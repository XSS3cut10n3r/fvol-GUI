//! python `symbols/windows/extensions/pool.py`: `POOL_HEADER` / `POOL_HEADER_VISTA`
//! (page-type checks, `get_object` carving of the object behind a pool allocation header),
//! `POOL_TRACKER_BIG_PAGES`, the `ExecutiveObject` mixin (`get_object_header`, `get_name`) and
//! `OBJECT_HEADER` (`is_valid`, `get_object_type`, `NameInfo`, `get_name`), as the [`PoolExt`]
//! trait on [`Obj`] plus the pre-resolved [`ObjectCarver`] used by the pool scanners.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! use crate::symbols::windows::pool::{PoolExt, ObjectCarver};
//! let hdr = proc.get_object_header(None)?;              // ExecutiveObject.get_object_header()
//! let ty = hdr.get_object_type(&type_map, cookie)?;       // Some("Process")
//! let name = hdr.header_name()?;                          // OBJECT_HEADER.get_name()
//! ```

use crate::error::{Error, Result};
use crate::objects::{Field, LayerRef, Module, Obj, Space};
use crate::renderers::Value;
use crate::symbols::windows::WinExt;
use crate::symbols::{TableRef, Ty, resolve_ref};
use crate::util::FxHashMap;
use std::sync::Mutex;

/// python `handles.Handles.get_type_map()` result: object type index -> type name.
pub type TypeMap = FxHashMap<u64, String>;

/// Which python class a table binds to `_POOL_HEADER` (they differ in the paged / non-paged
/// tests).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolHeaderClass {
    /// `POOL_HEADER` (before Vista)
    Legacy,
    /// `POOL_HEADER_VISTA`
    Vista,
}

/// Classes chosen for explicitly loaded pool-header tables (python `get_pool_header_table`
/// passes `class_types={"_POOL_HEADER": ...}`); keyed by table address.
static HEADER_CLASSES: Mutex<Option<FxHashMap<usize, PoolHeaderClass>>> = Mutex::new(None);

/// Record the `_POOL_HEADER` class of a separately loaded pool-header table.
pub fn set_pool_header_class(t: TableRef, class: PoolHeaderClass) {
    HEADER_CLASSES.lock().unwrap().get_or_insert_with(Default::default).insert(t as *const _ as *const u8 as usize, class);
}

/// The `_POOL_HEADER` class of table `t`: the recorded one for loaded pool-header tables,
/// otherwise python `WindowsKernelIntermedSymbols`' choice (`POOL_HEADER_VISTA` when
/// `_POOL_TRACKER_BIG_PAGES` has `PoolType` or `SlushSize`).
pub fn pool_header_class(t: TableRef) -> PoolHeaderClass {
    if let Some(c) = HEADER_CLASSES.lock().unwrap().as_ref().and_then(|m| m.get(&(t as *const _ as *const u8 as usize)).copied()) {
        return c;
    }
    match t.user_type("_POOL_TRACKER_BIG_PAGES") {
        Some(ut) if t.member(ut, "PoolType").is_some() || t.member(ut, "SlushSize").is_some() => PoolHeaderClass::Vista,
        _ => PoolHeaderClass::Legacy,
    }
}

/// python `POOL_HEADER.is_free_pool()` for a `PoolType` value.
#[inline]
pub fn pool_type_is_free(pool_type: i128) -> bool {
    pool_type == 0
}

/// python `is_paged_pool()` for a `PoolType` value.
#[inline]
pub fn pool_type_is_paged(class: PoolHeaderClass, pool_type: i128) -> bool {
    match class {
        PoolHeaderClass::Legacy => pool_type.rem_euclid(2) == 0 && pool_type > 0,
        PoolHeaderClass::Vista => pool_type.rem_euclid(2) == 1,
    }
}

/// python `is_nonpaged_pool()` for a `PoolType` value.
#[inline]
pub fn pool_type_is_nonpaged(class: PoolHeaderClass, pool_type: i128) -> bool {
    match class {
        PoolHeaderClass::Legacy => pool_type.rem_euclid(2) == 1,
        PoolHeaderClass::Vista => pool_type.rem_euclid(2) == 0 && pool_type > 0,
    }
}

/// python `POOL_HEADER._calculate_optional_header_lengths(context, table)`: the optional
/// object headers present in `table`, in python's order, with their sizes.
pub fn optional_header_lengths(t: Option<TableRef>) -> (Vec<&'static str>, Vec<u64>) {
    const HEADERS: [&str; 9] = [
        "CREATOR_INFO",
        "NAME_INFO",
        "HANDLE_INFO",
        "QUOTA_INFO",
        "PROCESS_INFO",
        "AUDIT_INFO",
        "EXTENDED_INFO",
        "HANDLE_REVOCATION_INFO",
        "PADDING_INFO",
    ];
    let mut names = Vec::new();
    let mut sizes = Vec::new();
    // python formats f"{None}!_OBJECT_HEADER_..." when no table is given: nothing resolves
    let Some(t) = t else { return (names, sizes) };
    for h in HEADERS {
        if let Ok(ty) = t.get_type(&format!("_OBJECT_HEADER_{h}")) {
            names.push(h);
            sizes.push(t.size_of(ty));
        }
    }
    (names, sizes)
}

/// python `conversion.round(addr, align, up=True)`.
fn round_up(addr: u64, align: u64) -> u64 {
    if align == 0 || addr % align == 0 { addr } else { addr + (align - addr % align) }
}

/// python `POOL_HEADER.get_object(constraint, use_top_down, kernel_symbol_table,
/// native_layer_name)` with everything that does not depend on the header resolved once.
/// [`ObjectCarver::carve`] then does the per-header work (one padded read for the top-down
/// search over the optional headers, `is_valid()` on each candidate).
pub struct ObjectCarver {
    /// space of the carved objects: (header layer, native layer, object table)
    obj_sp: &'static Space,
    obj_ty: Ty,
    executive: bool,
    top_down: bool,
    pool_header_size: u64,
    /// python `alignment` inside `get_object` (16 / 8 by the object table's bitness)
    alignment: u64,
    block_size: Field,
    // top-down
    body_offset: u64,
    infomask_offset: u64,
    pointercount_offset: u64,
    pointercount_size: usize,
    opt_lengths: Vec<u64>,
    padding_index: Option<usize>,
    max_opt_len: u64,
    // bottom-up
    rounded_size: u64,
}

impl ObjectCarver {
    /// * `header_table` / `header_layer`: the `_POOL_HEADER` objects' table and layer.
    /// * `native`: python `native_layer_name` (None = the header layer).
    /// * `type_name`: python `constraint.type_name` (`"table!type"`, or a type of `header_table`).
    /// * `executive`: python `constraint.object_type is not None`.
    /// * `kernel_table`: python `kernel_symbol_table`.
    /// * `additional_structures`: python `constraint.additional_structures` (bottom-up sizes).
    pub fn new(
        header_table: TableRef,
        header_layer: LayerRef,
        native: Option<LayerRef>,
        type_name: &str,
        executive: bool,
        use_top_down: bool,
        kernel_table: Option<TableRef>,
        additional_structures: &[String],
    ) -> Result<ObjectCarver> {
        let (obj_table, obj_ty) = resolve_ref(header_table, type_name).ok_or_else(|| Error::Symbol(format!("Unknown symbol: {type_name}")))?;
        let obj_sp = Space::get(header_layer, native.unwrap_or(header_layer), obj_table);
        let header_ty = header_table.get_type("_POOL_HEADER")?;
        let pool_header_size = header_table.size_of(header_ty);
        let block_size = Field::new(header_table, "_POOL_HEADER", "BlockSize")?;
        let mut c = ObjectCarver {
            obj_sp,
            obj_ty,
            executive,
            top_down: use_top_down,
            pool_header_size,
            alignment: if obj_table.is_64bit() { 16 } else { 8 },
            block_size,
            body_offset: 0,
            infomask_offset: 0,
            pointercount_offset: 0,
            pointercount_size: 0,
            opt_lengths: Vec::new(),
            padding_index: None,
            max_opt_len: 0,
            rounded_size: 0,
        };
        if !executive {
            return Ok(c);
        }
        // python resolves the _OBJECT_HEADER type (kernel table if given) up front
        let oh_table = kernel_table.unwrap_or(obj_table);
        let oh = oh_table.user_type("_OBJECT_HEADER").ok_or_else(|| Error::Symbol(format!("Unknown symbol: {}!_OBJECT_HEADER", oh_table.name())))?;
        if use_top_down {
            let mem = |n: &str| oh_table.member(oh, n).ok_or_else(|| Error::Symbol(format!("Member not present in template: {n}")));
            c.body_offset = mem("Body")?.offset;
            c.infomask_offset = mem("InfoMask")?.offset;
            let pc = mem("PointerCount")?;
            c.pointercount_offset = pc.offset;
            c.pointercount_size = oh_table.size_of(pc.ty) as usize;
            let (names, sizes) = optional_header_lengths(kernel_table);
            c.padding_index = names.iter().position(|n| *n == "PADDING_INFO");
            c.max_opt_len = sizes.iter().sum();
            c.opt_lengths = sizes;
        } else {
            let mut size = obj_table.size_of(obj_ty);
            for extra in additional_structures {
                let (t, ty) = resolve_ref(obj_table, extra).ok_or_else(|| Error::Symbol(format!("Unknown symbol: {extra}")))?;
                size += t.size_of(ty);
            }
            c.rounded_size = round_up(size, c.alignment);
        }
        Ok(c)
    }

    /// The carved objects' space (layer, native layer, table).
    pub fn object_space(&self) -> &'static Space {
        self.obj_sp
    }

    /// Carve the object(s) behind `header` into `out` (python `get_object` generator: objects
    /// in python order; `Err` = python raised after yielding what is already in `out`).
    pub fn carve(&self, header: &Obj, out: &mut Vec<Obj>) -> Result<()> {
        if !self.executive {
            out.push(Obj::new(self.obj_sp, self.obj_ty, header.addr.wrapping_add(self.pool_header_size)));
            return Ok(());
        }
        let block_size = header.f(&self.block_size).int()? as u64;
        if !self.top_down {
            let end = header.addr as i128 + (block_size * self.alignment) as i128 - self.rounded_size as i128;
            if end < 0 {
                return Ok(());
            }
            let o = Obj::new(self.obj_sp, self.obj_ty, end as u64);
            if o.is_valid() {
                out.push(o);
            }
            return Ok(());
        }
        let start_offset = header.addr.wrapping_add(self.pool_header_size);
        let addr_limit = self.max_opt_len.min(block_size * self.alignment) as usize;
        let io = self.infomask_offset as usize;
        let mut buf = [0u8; 4096 + 64];
        let need = addr_limit + io;
        let mut heap;
        let data: &mut [u8] = if need <= buf.len() {
            &mut buf[..need]
        } else {
            heap = vec![0u8; need];
            &mut heap
        };
        header.layer().read_padded(start_offset, data);
        let pco = self.pointercount_offset as usize;
        let pcs = self.pointercount_size;
        let mut addr = 0usize;
        while addr < addr_limit {
            let a = addr;
            addr += self.alignment as usize;
            let Some(&infomask) = data.get(a + io) else { break };
            let pc_bytes = &data[(a + pco).min(data.len())..(a + pco + pcs).min(data.len())];
            let pointercount = le_signed(pc_bytes);
            if !(0 <= pointercount && pointercount < 0x1000000) {
                continue;
            }
            let mut padding_present = false;
            let mut ohl: i128 = 0;
            for (i, len) in self.opt_lengths.iter().enumerate() {
                if i < 8 && infomask & (1 << i) != 0 {
                    ohl += *len as i128;
                    if Some(i) == self.padding_index {
                        padding_present = true;
                    }
                }
            }
            let mut padding_length: i128 = 0;
            if padding_present {
                let p = a as i128 - ohl;
                if p < 0 {
                    continue;
                }
                let p = p as usize;
                // python: struct.unpack("<I", ...) of a short slice raises
                let b = data.get(p..p + 4).ok_or_else(|| Error::msg("struct.error: unpack requires a buffer of 4 bytes"))?;
                padding_length = u32::from_le_bytes(b.try_into().unwrap()) as i128;
                padding_length -= self.opt_lengths[self.padding_index.unwrap_or(0)] as i128;
            }
            if a as i128 - ohl >= padding_length && padding_length > a as i128 {
                continue;
            }
            let o = Obj::new(self.obj_sp, self.obj_ty, (a as u64).wrapping_add(self.body_offset).wrapping_add(start_offset));
            if o.is_valid() {
                out.push(o);
            }
        }
        Ok(())
    }
}

/// `int.from_bytes(b, "little", signed=True)`.
fn le_signed(b: &[u8]) -> i128 {
    if b.is_empty() {
        return 0;
    }
    let mut v: i128 = 0;
    for (i, &x) in b.iter().enumerate().take(16) {
        v |= (x as i128) << (8 * i);
    }
    let bits = 8 * b.len().min(16) as u32;
    if bits < 128 && v & (1i128 << (bits - 1)) != 0 {
        v -= 1i128 << bits;
    }
    v
}

/// python `POOL_HEADER.get_object(...)` (one-shot form of [`ObjectCarver`]).
#[allow(clippy::too_many_arguments)]
pub fn get_object(
    header: &Obj,
    type_name: &str,
    executive: bool,
    use_top_down: bool,
    kernel_table: Option<TableRef>,
    native: Option<LayerRef>,
    additional_structures: &[String],
) -> Result<Vec<Obj>> {
    let c = ObjectCarver::new(header.table(), header.layer(), native, type_name, executive, use_top_down, kernel_table, additional_structures)?;
    let mut out = Vec::new();
    c.carve(header, &mut out)?;
    Ok(out)
}

/// python `OBJECT_HEADER.is_valid()` (a free function: `WinExt::is_valid` does not dispatch
/// `_OBJECT_HEADER` yet).
pub fn object_header_is_valid(h: &Obj) -> bool {
    match h.m("PointerCount").and_then(|p| p.int()) {
        Ok(pc) => (0..=0x1000000).contains(&pc),
        Err(_) => false,
    }
}

/// Pool / object-header extensions on [`Obj`].
pub trait PoolExt {
    // ---- _POOL_HEADER
    /// python `POOL_HEADER.is_free_pool()`.
    fn is_free_pool(&self) -> Result<bool>;
    /// python `is_paged_pool()` (class-dependent, see [`pool_header_class`]).
    fn is_paged_pool(&self) -> Result<bool>;
    /// python `is_nonpaged_pool()`.
    fn is_nonpaged_pool(&self) -> Result<bool>;

    // ---- ExecutiveObject mixin (_EPROCESS, _FILE_OBJECT, _KMUTANT, _DRIVER_OBJECT ...)
    /// python `ExecutiveObject.get_object_header(symbol_table_name)`: the `_OBJECT_HEADER`
    /// in front of the object body (table: `table` or the object's own).
    fn get_object_header(&self, table: Option<TableRef>) -> Result<Obj>;
    /// python `ExecutiveObject.get_name(symbol_table_name)` (None on invalid addresses).
    fn executive_name(&self, table: Option<TableRef>) -> Result<Option<String>>;

    // ---- _OBJECT_HEADER
    /// python `OBJECT_HEADER.get_object_type(type_map, cookie)`.
    fn get_object_type(&self, type_map: &TypeMap, cookie: Option<u64>) -> Result<Option<String>>;
    /// python `OBJECT_HEADER.NameInfo` (`Err(Error::Msg)` for python's ValueError when the
    /// name-info offset is 0).
    fn name_info(&self) -> Result<Obj>;
    /// python `OBJECT_HEADER.get_name()`.
    fn header_name(&self) -> Result<Option<String>>;

    // ---- _POOL_TRACKER_BIG_PAGES
    /// python `POOL_TRACKER_BIG_PAGES.is_valid()` (`Key > 0`).
    fn big_page_is_valid(&self) -> Result<bool>;
    /// python `POOL_TRACKER_BIG_PAGES.is_free()` (`Va & 1 == 1`).
    fn is_free(&self) -> Result<bool>;
    /// python `get_key()`: the tag's printable characters.
    fn get_key(&self) -> Result<String>;
    /// python `get_pool_type()`: first `_POOL_TYPE` name for the value, `"Unknown choice N"`, or
    /// NotApplicable before Vista.
    fn get_pool_type(&self) -> Result<Value>;
    /// python `get_number_of_bytes()`.
    fn get_number_of_bytes(&self) -> Result<Value>;
}

/// python `POOL_TRACKER_BIG_PAGES.get_key()` of a `Key` value: its 4 little-endian bytes,
/// printable ones only.
pub fn big_page_key_str(key: u32) -> String {
    key.to_le_bytes().iter().filter(|&&x| 32 < x && x < 127).map(|&x| x as char).collect()
}

/// Error marking python's `ValueError` in `NameInfo`.
const NAME_INFO_ZERO: &str = "Could not find _OBJECT_HEADER_NAME_INFO";

impl PoolExt for Obj {
    fn is_free_pool(&self) -> Result<bool> {
        Ok(pool_type_is_free(self.m("PoolType")?.int()?))
    }
    fn is_paged_pool(&self) -> Result<bool> {
        Ok(pool_type_is_paged(pool_header_class(self.table()), self.m("PoolType")?.int()?))
    }
    fn is_nonpaged_pool(&self) -> Result<bool> {
        Ok(pool_type_is_nonpaged(pool_header_class(self.table()), self.m("PoolType")?.int()?))
    }

    fn get_object_header(&self, table: Option<TableRef>) -> Result<Obj> {
        let t = table.unwrap_or(self.table());
        let body = t.offset_of("_OBJECT_HEADER", "Body")?;
        let sp = Space::get(self.layer(), self.native(), t);
        Obj::named(sp, "_OBJECT_HEADER", self.addr.wrapping_sub(body))
    }

    fn executive_name(&self, table: Option<TableRef>) -> Result<Option<String>> {
        match self.get_object_header(table)?.header_name() {
            Ok(n) => Ok(n),
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_object_type(&self, type_map: &TypeMap, cookie: Option<u64>) -> Result<Option<String>> {
        if self.has_member("Type") {
            // vista and earlier: the Type pointer
            let name = self.m("Type")?.m("Name")?;
            let length = name.m("Length")?.int()?;
            if length == 0 || length > 128 {
                return Ok(None);
            }
            let s = name.get_string()?;
            let n = s.chars().count();
            return Ok(if n == 0 || n > 128 { None } else { Some(s) });
        }
        let ti = self.m("TypeIndex")?.int()? as u64;
        let index = match cookie {
            Some(c) => ((self.addr >> 8) ^ c ^ ti) & 0xff,
            None => ti,
        };
        Ok(type_map.get(&index).cloned())
    }

    fn name_info(&self) -> Result<Obj> {
        let t = self.table();
        let kvo = self
            .native()
            .as_intel()
            .and_then(|i| i.kernel_virtual_offset())
            .ok_or_else(|| Error::Symbol(format!("AttributeError: Could not find kernel_virtual_offset for layer: {}", self.layer().name())))?;
        let nt = Module { sp: Space::get(self.layer(), self.native(), t), offset: kvo };
        let header_offset: u64 = if self.has_member("NameInfoOffset") {
            self.m("NameInfoOffset")?.int()? as u64
        } else {
            let address = nt.get_symbol("ObpInfoMaskToOffset")?.address;
            let index = (self.m("InfoMask")?.int()? as u64) & 3;
            let sp = Space::get(self.native(), self.native(), t);
            Obj::named(sp, "unsigned char", kvo.wrapping_add(address).wrapping_add(index))?.int()? as u64
        };
        if header_offset == 0 {
            return Err(Error::msg(format!("{NAME_INFO_ZERO} for object at {} of layer {}", self.addr, self.layer().name())));
        }
        Obj::named(Space::get(self.layer(), self.native(), t), "_OBJECT_HEADER_NAME_INFO", self.addr.wrapping_sub(header_offset))
    }

    fn header_name(&self) -> Result<Option<String>> {
        let r = (|| -> Result<Option<String>> {
            let name = self.name_info()?.m("Name")?;
            let length = name.m("Length")?.int()?;
            let max = name.m("MaximumLength")?.int()?;
            if length == 0 || max == 0 || length > max {
                return Ok(None);
            }
            Ok(Some(name.get_string()?))
        })();
        match r {
            Ok(v) => Ok(v),
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(Error::Msg(m)) if m.starts_with(NAME_INFO_ZERO) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn big_page_is_valid(&self) -> Result<bool> {
        Ok(self.m("Key")?.int()? > 0)
    }

    fn is_free(&self) -> Result<bool> {
        Ok(self.m("Va")?.int()? & 1 == 1)
    }

    fn get_key(&self) -> Result<String> {
        Ok(big_page_key_str(self.m("Key")?.int()? as u32))
    }

    fn get_pool_type(&self) -> Result<Value> {
        if !self.has_member("PoolType") {
            return Ok(Value::NotApplicable);
        }
        let v = self.m("PoolType")?.int()?;
        let t = self.table();
        let name = t.enumeration("_POOL_TYPE").and_then(|e| t.enum_lookup(e, v));
        Ok(match name {
            Some(n) => Value::Str(n.to_string()),
            None => Value::Str(format!("Unknown choice {v}")),
        })
    }

    fn get_number_of_bytes(&self) -> Result<Value> {
        if !self.has_member("NumberOfBytes") {
            return Ok(Value::NotApplicable);
        }
        Ok(Value::Int(self.m("NumberOfBytes")?.int()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_type_classes() {
        use PoolHeaderClass::*;
        // python POOL_HEADER_VISTA: paged = odd, nonpaged = even and > 0, free = 0
        assert!(pool_type_is_paged(Vista, 1) && pool_type_is_paged(Vista, 3));
        assert!(pool_type_is_nonpaged(Vista, 2) && !pool_type_is_nonpaged(Vista, 0));
        assert!(pool_type_is_nonpaged(Legacy, 1) && pool_type_is_paged(Legacy, 2) && !pool_type_is_paged(Legacy, 0));
        assert!(pool_type_is_free(0) && !pool_type_is_free(2));
    }

    #[test]
    fn signed_le() {
        assert_eq!(le_signed(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), -1);
        assert_eq!(le_signed(&[0x01, 0, 0, 0, 0, 0, 0, 0]), 1);
        assert_eq!(le_signed(&[0x00, 0x80]), -32768);
        assert_eq!(round_up(0x51, 16), 0x60);
        assert_eq!(round_up(0x60, 16), 0x60);
    }
}
