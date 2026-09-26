//! windows.poolscanner.PoolScanner (python `plugins/windows/poolscanner.py`) and the pool
//! scanning framework every `*scan` plugin is built on: [`PoolConstraint`], [`pool_type`],
//! [`PoolHeaderScanner`], [`builtin_constraints`], [`gui_poolscanner_constraints`],
//! [`pool_scan`], [`generate_pool_scan`] / [`generate_pool_scan_extended`],
//! [`get_pool_header_table`], plus python `handles.Handles.get_type_map` / `find_cookie`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Everything per hit runs on the scan workers, in parallel: the tag search (AVX2 Teddy
//! prefilter), the `_POOL_HEADER` size / page-type / index checks, and (for
//! `generate_pool_scan*`) the object carving (`POOL_HEADER.get_object`, `is_valid()`) and the
//! object-type test. Results come back in python's order.
//!
//! ```ignore
//! use crate::plugins::windows::poolscanner::{self, builtin_constraints, generate_pool_scan_each};
//! let k = ctx.windows_kernel()?;
//! let cons = builtin_constraints(k.table.name(), &[b"Muta", b"Mut\xe1"]);   // tags_filter
//! generate_pool_scan_each(ctx, k, k.table, &cons, |hit| {
//!     let mutant = hit.object;              // `_KMUTANT` on the scan layer (native: kernel layer)
//!     let header = hit.header;              // its `_POOL_HEADER`
//!     let c = &cons[hit.constraint];        // the constraint that matched
//!     ...; Ok(true)                         // false = stop
//! })?;
//! ```

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::layers::scan::{MultiStringScanner, Scanner, scan_each};
use crate::objects::{Field, LayerRef, Obj, Space};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;
use crate::symbols::windows::pool::{ObjectCarver, PoolExt, PoolHeaderClass, TypeMap, pool_header_class, set_pool_header_class};
use crate::symbols::windows::pool::{pool_type_is_free, pool_type_is_nonpaged, pool_type_is_paged};
use crate::symbols::windows::versions;
use crate::symbols::{TableRef, Ty};
use crate::util::FxHashMap;
use std::sync::{Arc, Mutex};

/// python `PoolType` (an `IntFlag`; combine with `|`).
pub mod pool_type {
    pub const PAGED: u8 = 1;
    pub const NONPAGED: u8 = 2;
    pub const FREE: u8 = 4;
}

/// python `PoolConstraint`: tag / type / size / index / page-type information about a pool
/// allocation. Build with [`PoolConstraint::new`] and the builder methods.
#[derive(Clone, Debug, PartialEq)]
pub struct PoolConstraint {
    pub tag: Vec<u8>,
    /// `"table!type"` (python `symbol_table + constants.BANG + "_EPROCESS"`) or a type of the
    /// pool header table.
    pub type_name: String,
    /// Executive object type name (`"Process"`, `"File"` ...); `None` = plain structure.
    pub object_type: Option<String>,
    /// [`pool_type`] flags.
    pub page_type: Option<u8>,
    /// (min, max) of `alignment * BlockSize` (python ignores 0 / None bounds).
    pub size: Option<(Option<u64>, Option<u64>)>,
    /// (min, max) of `PoolIndex`.
    pub index: Option<(Option<u64>, Option<u64>)>,
    pub alignment: Option<u64>,
    pub skip_type_test: bool,
    pub additional_structures: Vec<String>,
}

impl PoolConstraint {
    pub fn new(tag: &[u8], type_name: impl Into<String>) -> PoolConstraint {
        PoolConstraint {
            tag: tag.to_vec(),
            type_name: type_name.into(),
            object_type: None,
            page_type: None,
            size: None,
            index: None,
            alignment: Some(1),
            skip_type_test: false,
            additional_structures: Vec::new(),
        }
    }
    pub fn object_type(mut self, t: &str) -> Self {
        self.object_type = Some(t.to_string());
        self
    }
    pub fn page_type(mut self, flags: u8) -> Self {
        self.page_type = Some(flags);
        self
    }
    pub fn size(mut self, min: Option<u64>, max: Option<u64>) -> Self {
        self.size = Some((min, max));
        self
    }
    pub fn index(mut self, min: Option<u64>, max: Option<u64>) -> Self {
        self.index = Some((min, max));
        self
    }
    pub fn skip_type_test(mut self) -> Self {
        self.skip_type_test = true;
        self
    }
    pub fn additional_structures(mut self, s: &[&str]) -> Self {
        self.additional_structures = s.iter().map(|x| x.to_string()).collect();
        self
    }
}

/// python `PoolScanner.builtin_constraints(symbol_table, tags_filter)`: the well-known
/// constraints (all of them when `tags_filter` is empty), in python's order.
pub fn builtin_constraints(symbol_table: &str, tags_filter: &[&[u8]]) -> Vec<PoolConstraint> {
    use pool_type::*;
    let t = |n: &str| format!("{symbol_table}!{n}");
    let all = vec![
        // atom tables
        PoolConstraint::new(b"AtmT", t("_RTL_ATOM_TABLE")).size(Some(200), None).page_type(PAGED | NONPAGED | FREE),
        // processes on windows before windows 8
        PoolConstraint::new(b"Pro\xe3", t("_EPROCESS")).object_type("Process").size(Some(600), None).skip_type_test().page_type(NONPAGED | FREE),
        // processes on windows starting with windows 8
        PoolConstraint::new(b"Proc", t("_EPROCESS")).object_type("Process").size(Some(600), None).skip_type_test().page_type(NONPAGED | FREE),
        // threads on windows before windows8
        PoolConstraint::new(b"Thr\xe5", t("_ETHREAD")).object_type("Thread").size(Some(600), None).skip_type_test().page_type(NONPAGED | FREE),
        // threads on windows starting with windows8
        PoolConstraint::new(b"Thre", t("_ETHREAD")).object_type("Thread").size(Some(600), None).page_type(NONPAGED | FREE),
        // files on windows before windows 8
        PoolConstraint::new(b"Fil\xe5", t("_FILE_OBJECT")).object_type("File").size(Some(150), None).page_type(NONPAGED | FREE),
        // files on windows starting with windows 8
        PoolConstraint::new(b"File", t("_FILE_OBJECT")).object_type("File").size(Some(150), None).page_type(NONPAGED | FREE),
        // mutants on windows before windows 8
        PoolConstraint::new(b"Mut\xe1", t("_KMUTANT")).object_type("Mutant").size(Some(64), None).page_type(NONPAGED | FREE),
        // mutants on windows starting with windows 8
        PoolConstraint::new(b"Muta", t("_KMUTANT")).object_type("Mutant").size(Some(64), None).page_type(NONPAGED | FREE),
        // drivers on windows before windows 8
        PoolConstraint::new(b"Dri\xf6", t("_DRIVER_OBJECT"))
            .object_type("Driver")
            .size(Some(248), None)
            .page_type(NONPAGED | FREE)
            .additional_structures(&["_DRIVER_EXTENSION"]),
        // drivers on windows starting with windows 8
        PoolConstraint::new(b"Driv", t("_DRIVER_OBJECT")).object_type("Driver").size(Some(248), None).page_type(NONPAGED | FREE),
        // kernel modules
        PoolConstraint::new(b"MmLd", t("_LDR_DATA_TABLE_ENTRY")).size(Some(76), None).page_type(NONPAGED | FREE),
        // symlinks on windows before windows 8
        PoolConstraint::new(b"Sym\xe2", t("_OBJECT_SYMBOLIC_LINK")).object_type("SymbolicLink").size(Some(72), None).page_type(PAGED | FREE),
        // symlinks on windows starting with windows 8
        PoolConstraint::new(b"Symb", t("_OBJECT_SYMBOLIC_LINK")).object_type("SymbolicLink").size(Some(72), None).page_type(PAGED | FREE),
        // registry hives
        PoolConstraint::new(b"CM10", t("_CMHIVE")).size(Some(800), None).page_type(PAGED | FREE).skip_type_test(),
    ];
    filter_tags(all, tags_filter)
}

/// python `PoolScanner.gui_poolscanner_constraints(gui_table, tags_filter)`.
pub fn gui_poolscanner_constraints(gui_table: &str, tags_filter: &[&[u8]]) -> Vec<PoolConstraint> {
    use pool_type::*;
    let all = vec![
        PoolConstraint::new(b"Wind", format!("{gui_table}!tagWINDOWSTATION"))
            .size(Some(0x90), None)
            .page_type(PAGED | NONPAGED)
            .object_type("WindowStation")
            .skip_type_test(),
        PoolConstraint::new(b"Desk", format!("{gui_table}!tagDESKTOP")).page_type(PAGED | NONPAGED).object_type("Desktop").skip_type_test(),
    ];
    filter_tags(all, tags_filter)
}

fn filter_tags(all: Vec<PoolConstraint>, tags_filter: &[&[u8]]) -> Vec<PoolConstraint> {
    if tags_filter.is_empty() {
        return all;
    }
    all.into_iter().filter(|c| tags_filter.contains(&c.tag.as_slice())).collect()
}

/// python `PoolScanner.get_pool_header_table(context, symbol_table)`: a table with a
/// `_POOL_HEADER` for `symbol_table` (the embedded `poolheader-*` ISF mapped onto it).
pub fn get_pool_header_table(ctx: &Context, symbol_table: TableRef) -> Result<TableRef> {
    let file = if symbol_table.is_64bit() {
        if versions::IS_WINDOWS_7.check(symbol_table) { "poolheader-x64-win7" } else { "poolheader-x64" }
    } else {
        "poolheader-x86"
    };
    let class = if versions::IS_VISTA_OR_LATER.check(symbol_table) { PoolHeaderClass::Vista } else { PoolHeaderClass::Legacy };
    let t = ctx.load_isf_with(&format!("windows/{file}"), None, &[("nt_symbols", symbol_table.name())])?;
    set_pool_header_class(t, class);
    Ok(t)
}

/// python `handles.Handles.get_type_map(context, kernel)`: executive object type index ->
/// name from `ObTypeIndexTable` (or `ObpObjectTypes`). Memoized per kernel.
pub fn get_type_map(k: &WinKernel) -> Result<Arc<TypeMap>> {
    static MAPS: Mutex<Option<FxHashMap<(usize, u64), Arc<TypeMap>>>> = Mutex::new(None);
    let key = (k.table as *const _ as *const u8 as usize, k.base);
    if let Some(m) = MAPS.lock().unwrap().as_ref().and_then(|m| m.get(&key).cloned()) {
        return Ok(m);
    }
    let mut type_map = TypeMap::default();
    let table_addr = match k.get_symbol("ObTypeIndexTable") {
        Ok(s) => s.address,
        Err(_) => k.get_symbol("ObpObjectTypes")?.address,
    };
    if k.vlayer.is_valid(k.base.wrapping_add(table_addr), 1) {
        let ptr_ty = k.get_type("pointer")?;
        let ptrs = k.object("pointer", table_addr)?.cast_array(100, ptr_ty);
        let objt_ty = k.get_type("_OBJECT_TYPE")?;
        for i in 0..100u64 {
            let ptr = ptrs.at(i)?;
            let v = ptr.u64()?;
            if i > 0 && v == 0 {
                break;
            }
            let name = (|| -> Result<String> {
                let objt = Obj::new(ptr.sp.native_space(), objt_ty, v);
                objt.m("Name")?.get_string()
            })();
            match name {
                Ok(n) => {
                    type_map.insert(i, n);
                }
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            }
        }
    }
    let m = Arc::new(type_map);
    MAPS.lock().unwrap().get_or_insert_with(Default::default).insert(key, m.clone());
    Ok(m)
}

/// python `handles.Handles.find_cookie(context, kernel)`: the `ObHeaderCookie` value (None
/// when the symbol does not exist; unreadable = error, like python's eager read).
pub fn find_cookie(k: &WinKernel) -> Result<Option<u64>> {
    let Ok(sym) = k.get_symbol("ObHeaderCookie") else { return Ok(None) };
    Ok(Some(k.object("unsigned int", sym.address)?.u64()?))
}

/// python `PoolHeaderScanner(module, constraint_lookup, alignment)`: finds the constraints'
/// tags and checks the `_POOL_HEADER` in front of each (size, page type, index; unreadable
/// headers are skipped). Every passing `(constraint index, header)` is handed to `post`, which
/// runs on the scan worker and pushes the scanner's hits.
pub struct PoolHeaderScanner<'a, H, P> {
    tags: MultiStringScanner,
    constraints: &'a [PoolConstraint],
    header_sp: &'static Space,
    header_ty: Ty,
    header_offset: u64,
    class: PoolHeaderClass,
    alignment: u64,
    block_size: Field,
    pool_type: Field,
    pool_index: Field,
    post: P,
    _h: std::marker::PhantomData<fn() -> H>,
}

impl<'a, H, P> PoolHeaderScanner<'a, H, P>
where
    P: Fn(usize, Obj, &mut Vec<H>) + Sync,
{
    /// `header_table` / `layer`: python's pool-header module (its table, bound to the scanned
    /// layer). Errors on duplicate tags (python `ValueError`).
    pub fn new(header_table: TableRef, layer: LayerRef, constraints: &'a [PoolConstraint], alignment: u64, post: P) -> Result<Self> {
        for (i, c) in constraints.iter().enumerate() {
            if constraints[..i].iter().any(|d| d.tag == c.tag) {
                return Err(Error::msg(format!("Constraint tag is used for more than one constraint: {:?}", String::from_utf8_lossy(&c.tag))));
            }
        }
        let header_ty = header_table.get_type("_POOL_HEADER")?;
        Ok(PoolHeaderScanner {
            tags: MultiStringScanner::new(&constraints.iter().map(|c| c.tag.clone()).collect::<Vec<_>>()),
            constraints,
            header_sp: Space::on(layer, header_table),
            header_ty,
            header_offset: header_table.offset_of("_POOL_HEADER", "PoolTag")?,
            class: pool_header_class(header_table),
            alignment,
            block_size: Field::new(header_table, "_POOL_HEADER", "BlockSize")?,
            pool_type: Field::new(header_table, "_POOL_HEADER", "PoolType")?,
            pool_index: Field::new(header_table, "_POOL_HEADER", "PoolIndex")?,
            post,
            _h: std::marker::PhantomData,
        })
    }

    /// python's per-hit checks (`Err` = unreadable header, skipped by the caller).
    fn passes(&self, c: &PoolConstraint, header: &Obj) -> Result<bool> {
        if let Some((lo, hi)) = c.size {
            if let Some(lo) = lo.filter(|v| *v != 0) {
                if (self.alignment as i128) * header.f(&self.block_size).int()? < lo as i128 {
                    return Ok(false);
                }
            }
            if let Some(hi) = hi.filter(|v| *v != 0) {
                if (self.alignment as i128) * header.f(&self.block_size).int()? > hi as i128 {
                    return Ok(false);
                }
            }
        }
        if let Some(pt) = c.page_type {
            let ok = (pt & pool_type::FREE != 0 && pool_type_is_free(header.f(&self.pool_type).int()?))
                || (pt & pool_type::NONPAGED != 0 && pool_type_is_nonpaged(self.class, header.f(&self.pool_type).int()?))
                || (pt & pool_type::PAGED != 0 && pool_type_is_paged(self.class, header.f(&self.pool_type).int()?));
            if !ok {
                return Ok(false);
            }
        }
        if let Some((lo, hi)) = c.index {
            if let Some(lo) = lo.filter(|v| *v != 0) {
                if header.f(&self.pool_index).int()? < lo as i128 {
                    return Ok(false);
                }
            }
            if let Some(hi) = hi.filter(|v| *v != 0) {
                if header.f(&self.pool_index).int()? > hi as i128 {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

impl<H: Send, P> Scanner for PoolHeaderScanner<'_, H, P>
where
    P: Fn(usize, Obj, &mut Vec<H>) + Sync,
{
    type Hit = H;
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<H>) {
        let mut found = Vec::new();
        self.tags.prescan(data, &mut found);
        self.finish(&found, data_offset, hits);
    }
    // the tag search depends only on the bytes: the executor runs it once per distinct range
    fn prescan(&self, data: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
        self.tags.prescan(data, out)
    }
    fn stream_window(&self) -> Option<usize> {
        self.tags.stream_window()
    }
    fn prescan_piece(&self, data: &[u8], base: u64, from: usize, limit: usize, out: &mut Vec<(u64, u32)>) -> usize {
        self.tags.prescan_piece(data, base, from, limit, out)
    }
    fn finish(&self, matches: &[(u64, u32)], data_offset: u64, hits: &mut Vec<H>) {
        for &(rel, pi) in matches {
            let ci = pi as usize;
            // a header before address 0 cannot be read (python raises -> skipped)
            let Some(at) = (data_offset + rel).checked_sub(self.header_offset) else { continue };
            let header = Obj::new(self.header_sp, self.header_ty, at);
            if let Ok(true) = self.passes(&self.constraints[ci], &header) {
                (self.post)(ci, header, hits);
            }
        }
    }
}

/// The `_POOL_HEADER` table python's `pool_scan` uses for `symbol_table`.
fn header_table_for(ctx: &Context, k: &WinKernel, symbol_table: TableRef) -> Result<TableRef> {
    if k.has_type("_POOL_HEADER") { Ok(k.table) } else { get_pool_header_table(ctx, symbol_table) }
}

/// python `PoolScanner.pool_scan(context, kernel, layer_name, symbol_table, constraints,
/// alignment)`: `(constraint index, _POOL_HEADER)` for every header passing its constraint,
/// in scan order.
pub fn pool_scan(ctx: &Context, k: &WinKernel, layer: LayerRef, symbol_table: TableRef, constraints: &[PoolConstraint], alignment: u64) -> Result<Vec<(usize, Obj)>> {
    let mut out = Vec::new();
    pool_scan_with(ctx, k, layer, symbol_table, constraints, alignment, |ci, h, hits: &mut Vec<(usize, Obj)>| hits.push((ci, h)), |h| {
        out.push(h);
        true
    })?;
    Ok(out)
}

/// [`pool_scan`] with a per-header post-processing step `post(constraint index, header, out)`
/// that runs on the scan workers (in parallel), and a streaming consumer `f` (in order; return
/// false to stop).
#[allow(clippy::too_many_arguments)]
pub fn pool_scan_with<H, P, F>(ctx: &Context, k: &WinKernel, layer: LayerRef, symbol_table: TableRef, constraints: &[PoolConstraint], alignment: u64, post: P, f: F) -> Result<()>
where
    H: Send,
    P: Fn(usize, Obj, &mut Vec<H>) + Sync,
    F: FnMut(H) -> bool,
{
    let header_table = header_table_for(ctx, k, symbol_table)?;
    let scanner = PoolHeaderScanner::new(header_table, layer, constraints, alignment, post)?;
    let _t = crate::util::trace::span("pool scan");
    scan_each(layer, &scanner, None, f);
    Ok(())
}

/// One result of [`generate_pool_scan`]: the constraint that matched, the carved object and
/// its pool header.
#[derive(Clone, Copy, Debug)]
pub struct PoolHit {
    pub constraint: usize,
    pub object: Obj,
    pub header: Obj,
}

/// The layer python's `generate_pool_scan_extended` scans: the kernel virtual layer on
/// Windows 10+, the physical layer before.
pub fn pool_scan_layer(k: &WinKernel) -> LayerRef {
    if versions::IS_WINDOWS_10.check(k.table) { k.vlayer } else { k.phys }
}

/// python `PoolScanner.generate_pool_scan_extended(context, kernel, object_symbol_table,
/// constraints)`, streaming: `f` gets every [`PoolHit`] in python's order (return `Ok(false)` to
/// stop). An `Err` from python's side (e.g. an unreadable type-map entry, or `get_object` raising
/// midway) is returned after the hits python would have produced before it.
pub fn generate_pool_scan_each(
    ctx: &Context,
    k: &WinKernel,
    object_table: TableRef,
    constraints: &[PoolConstraint],
    mut f: impl FnMut(PoolHit) -> Result<bool>,
) -> Result<()> {
    let type_map = get_type_map(k)?;
    let cookie = find_cookie(k)?;
    let is_windows_10 = versions::IS_WINDOWS_10.check(k.table);
    let is_windows_8_or_later = versions::IS_WINDOWS_8_OR_LATER.check(k.table);
    let scan_layer = if is_windows_10 { k.vlayer } else { k.phys };
    let alignment = if k.table.is_64bit() { 0x10 } else { 8 };
    let header_table = header_table_for(ctx, k, object_table)?;
    // per-constraint object carvers (python get_object's type lookups, done once)
    let carvers: Vec<Result<ObjectCarver>> = constraints
        .iter()
        .map(|c| {
            ObjectCarver::new(
                header_table,
                scan_layer,
                Some(k.vlayer),
                &c.type_name,
                c.object_type.is_some(),
                is_windows_8_or_later,
                Some(k.table),
                &c.additional_structures,
            )
        })
        .collect();
    let post = |ci: usize, header: Obj, out: &mut Vec<Result<PoolHit>>| {
        let c = &constraints[ci];
        let carver = match &carvers[ci] {
            Ok(cv) => cv,
            Err(e) => {
                out.push(Err(Error::Symbol(e.to_string())));
                return;
            }
        };
        let mut objs = Vec::new();
        let r = carver.carve(&header, &mut objs);
        for object in objs {
            if c.object_type.is_some() && !c.skip_type_test {
                let t = object.get_object_header(None).and_then(|h| h.get_object_type(&type_map, cookie));
                match t {
                    Ok(t) if t.as_deref() == c.object_type.as_deref() => {}
                    Ok(_) => continue,
                    Err(e) if e.is_invalid_address() => continue,
                    Err(e) => {
                        out.push(Err(e));
                        return;
                    }
                }
            }
            out.push(Ok(PoolHit { constraint: ci, object, header }));
        }
        if let Err(e) = r {
            out.push(Err(e));
        }
    };
    let mut err = None;
    pool_scan_with(ctx, k, scan_layer, object_table, constraints, alignment, post, |h| match h {
        Ok(hit) => match f(hit) {
            Ok(go) => go,
            Err(e) => {
                err = Some(e);
                false
            }
        },
        Err(e) => {
            err = Some(e);
            false
        }
    })?;
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// python `generate_pool_scan_extended` collected into a Vec.
pub fn generate_pool_scan_extended(ctx: &Context, k: &WinKernel, object_table: TableRef, constraints: &[PoolConstraint]) -> Result<Vec<PoolHit>> {
    let mut v = Vec::new();
    generate_pool_scan_each(ctx, k, object_table, constraints, |h| {
        v.push(h);
        Ok(true)
    })?;
    Ok(v)
}

/// python `PoolScanner.generate_pool_scan(context, kernel, constraints)` (objects from the
/// kernel's symbol table).
pub fn generate_pool_scan(ctx: &Context, k: &WinKernel, constraints: &[PoolConstraint]) -> Result<Vec<PoolHit>> {
    generate_pool_scan_extended(ctx, k, k.table, constraints)
}

pub struct PoolScanner;

impl Plugin for PoolScanner {
    fn name(&self) -> &'static str {
        "windows.poolscanner.PoolScanner"
    }
    fn description(&self) -> &'static str {
        "A generic pool scanner plugin."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Tag", ColType::Str),
            Column::new("Offset", ColType::Hex),
            Column::new("Layer", ColType::Str),
            Column::new("Name", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let constraints = builtin_constraints(k.table.name(), &[]);
        generate_pool_scan_each(ctx, k, k.table, &constraints, |hit| {
            let c = &constraints[hit.constraint];
            let name = match c.object_type.as_deref() {
                Some("Process") => Value::Str(hit.object.image_file_name_str()?),
                Some("File") => match hit.object.m("FileName").and_then(|n| n.get_string()) {
                    Ok(s) => Value::Str(s),
                    Err(e) if e.is_invalid_address() => return Ok(true),
                    Err(e) => return Err(e),
                },
                _ => Value::NotApplicable,
            };
            out.row(0, vec![Value::Str(c.type_name.clone()), Value::Int(hit.header.addr as i128), Value::str(hit.header.layer().name()), name])?;
            Ok(true)
        })
    }
}
