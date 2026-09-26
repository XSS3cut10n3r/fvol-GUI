//! windows.handles.Handles (python `plugins/windows/handles.py`) and its reusable classmethods:
//! handle-table walking ([`handles`] / [`HandleItem`], python `Handles.handles`,
//! `_make_handle_array`, `_get_item`) and the per-handle object naming python's generator does
//! ([`handle_row`]). `get_type_map` / `find_cookie` live in
//! [`poolscanner`](crate::plugins::windows::poolscanner) (re-exported here).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! use crate::plugins::windows::handles::{self, HandleWalker};
//! let walker = HandleWalker::new(k)?;
//! let type_map = handles::get_type_map(k)?;
//! let cookie = handles::find_cookie(k)?;
//! for item in walker.handles(&proc.m("ObjectTable")?) {
//!     let item = item?;                      // Err = python raised (rare)
//!     let ty = item.header.get_object_type(&type_map, cookie)?;
//!     ...
//! }
//! ```

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::objects::util::array_to_string;
use crate::objects::{Field, LayerRef, Obj, Space};
use crate::plugins::windows::pslist::{list_processes, pid_filter};
use crate::plugins::windows::psscan::{create_offset_filter, scan_processes};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;
use crate::symbols::windows::objects::{ObjectsExt, is_name_info_value_error};
use crate::symbols::windows::pool::{PoolExt, TypeMap};
use crate::symbols::{StrEnc, StrErrors, Ty};

pub use crate::plugins::windows::poolscanner::{find_cookie, get_type_map};

pub struct Handles;

/// python `Handles.LEVEL_MASK`.
pub const LEVEL_MASK: u64 = 7;

/// One handle: python's `_OBJECT_HEADER` object with the `HandleValue` / `GrantedAccess`
/// attributes `_get_item` attaches.
#[derive(Clone, Copy, Debug)]
pub struct HandleItem {
    /// `_OBJECT_HEADER` on the kernel layer.
    pub header: Obj,
    /// python `HandleValue` (python computes it as a float; it is always integral here).
    pub handle_value: u64,
    /// python `GrantedAccess`.
    pub granted_access: u64,
}

/// Pre-resolved types / fields for walking handle tables of one kernel (python
/// `Handles.handles` / `_make_handle_array` / `_get_item`).
pub struct HandleWalker {
    layer: LayerRef,
    header_sp: &'static Space,
    header_ty: Ty,
    entry_ty: Ty,
    entry_size: u64,
    ptr_size: u64,
    is_64bit: bool,
    max_address: u64,
    table_code: Field,
    /// Windows 8+: the entry has no `Object` member
    object: Option<Field>,
    granted_access: Option<Field>,
    object_pointer_bits: Option<Field>,
    info_table: Option<Field>,
    granted_access_bits: Option<Field>,
    type_index: Option<Field>,
}

impl HandleWalker {
    pub fn new(k: &WinKernel) -> Result<HandleWalker> {
        let t = k.table;
        let f = |ty: &str, m: &str| Field::new(t, ty, m).ok();
        let entry_ty = t.get_type("_HANDLE_TABLE_ENTRY")?;
        Ok(HandleWalker {
            layer: k.vlayer,
            header_sp: Space::on(k.vlayer, t),
            header_ty: t.get_type("_OBJECT_HEADER")?,
            entry_ty,
            entry_size: t.size_of(entry_ty),
            ptr_size: t.size_of(t.get_type("pointer")?),
            is_64bit: t.is_64bit(),
            max_address: k.vlayer.max_address(),
            table_code: Field::new(t, "_HANDLE_TABLE", "TableCode")?,
            object: f("_HANDLE_TABLE_ENTRY", "Object"),
            granted_access: f("_HANDLE_TABLE_ENTRY", "GrantedAccess"),
            object_pointer_bits: f("_HANDLE_TABLE_ENTRY", "ObjectPointerBits"),
            info_table: f("_HANDLE_TABLE_ENTRY", "InfoTable"),
            granted_access_bits: f("_HANDLE_TABLE_ENTRY", "GrantedAccessBits"),
            type_index: f("_OBJECT_HEADER", "TypeIndex"),
        })
    }

    /// python `Handles.handles(context, kernel_module_name, handle_table)`: the object headers
    /// of the handle table (`_EPROCESS.ObjectTable`, a pointer or the `_HANDLE_TABLE`). A
    /// trailing `Err` = python raised there.
    pub fn handles(&self, handle_table: &Obj) -> Vec<Result<HandleItem>> {
        let mut out = Vec::new();
        let table = if handle_table.is_pointer() { handle_table.deref() } else { Ok(*handle_table) };
        let tc = match table.map(|t| t.f(&self.table_code)).and_then(|o| o.u64()) {
            Ok(v) => v,
            Err(e) if e.is_invalid_address() => return out,
            Err(e) => return vec![Err(e)],
        };
        if let Err(e) = self.make_handle_array(tc & !LEVEL_MASK, tc & LEVEL_MASK, 0, &mut out) {
            out.push(Err(e));
        }
        out
    }

    /// python `_make_handle_array(offset, level, depth)` (depth is passed by value, like python).
    fn make_handle_array(&self, offset: u64, level: u64, mut depth: u64, out: &mut Vec<Result<HandleItem>>) -> Result<()> {
        let (esize, count) = if level > 0 { (self.ptr_size, 0x1000 / self.ptr_size) } else { (self.entry_size, 0x1000 / self.entry_size) };
        if !self.layer.is_valid(offset, 1) {
            return Ok(());
        }
        let masked_offset = offset & self.max_address;
        let base = offset & self.layer.address_mask();
        let mut page = u64::MAX;
        let mut page_ok = false;
        for i in 0..count {
            let addr = base.wrapping_add(i * esize) & self.layer.address_mask();
            // python validates the element's first byte
            if addr >> 12 != page {
                page = addr >> 12;
                page_ok = self.layer.is_valid(addr, 1);
            }
            if level > 0 {
                // table[i] reads the pointer (caught), then the element address is checked
                let v = match self.read_ptr(addr) {
                    Ok(v) => v,
                    Err(e) if e.is_invalid_address() => continue,
                    Err(e) => return Err(e),
                };
                if !page_ok {
                    continue;
                }
                self.make_handle_array(v, level - 1, depth, out)?;
                depth += 1;
            } else {
                if !page_ok {
                    continue;
                }
                // python: ((entry.vol.offset - masked_offset) / (size / 4)) + depth * count * 4
                let hv = (addr.wrapping_sub(masked_offset) as f64) / (esize as f64 / 4.0) + (depth as f64) * (count as f64) * 4.0;
                let entry = Obj::new(self.header_sp, self.entry_ty, addr);
                let Some(item) = self.get_item(&entry, hv as u64)? else { continue };
                match self.type_nonzero(&item.header) {
                    Ok(true) => out.push(Ok(item)),
                    Ok(false) => {}
                    Err(e) if e.is_invalid_address() => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    /// A pointer element (masked like python's `Pointer`).
    fn read_ptr(&self, addr: u64) -> Result<u64> {
        let mut b = [0u8; 8];
        let n = self.ptr_size as usize;
        self.layer.read(addr, &mut b[..n])?;
        Ok(u64::from_le_bytes(b) & self.layer.address_mask())
    }

    /// python `item.TypeIndex != 0` (or `item.Type.Name` before Windows 7).
    fn type_nonzero(&self, header: &Obj) -> Result<bool> {
        match &self.type_index {
            Some(ti) => Ok(header.f(ti).int()? != 0),
            None => {
                let name = header.m("Type")?.m("Name")?;
                // python truthiness of the UNICODE_STRING struct: always True
                let _ = name;
                Ok(true)
            }
        }
    }

    /// python `Handles._get_item(context, kernel, handle_table_entry, handle_value)`.
    fn get_item(&self, entry: &Obj, handle_value: u64) -> Result<Option<HandleItem>> {
        if let Some(object) = &self.object {
            // before Windows 8
            let ptr = entry.f(object);
            if !self.layer.is_valid(ptr.u64()?, 1) {
                return Ok(None);
            }
            let fast_ref = ptr.cast("_EX_FAST_REF")?;
            // python's dereference() constructs (reads) a pointer at the header address
            let header = match fast_ref.fast_ref_dereference().and_then(|p| p.u64().map(|_| p)) {
                Ok(p) => Obj::new(p.sp, self.header_ty, p.addr),
                Err(e) if e.is_invalid_address() => return Ok(None),
                Err(e) => return Err(e),
            };
            let ga = match &self.granted_access {
                Some(g) => entry.f(g).u64()?,
                None => entry.m("GrantedAccess")?.u64()?,
            };
            return Ok(Some(HandleItem { header, handle_value, granted_access: ga }));
        }
        let offset = if self.is_64bit {
            let bits = match self.object_pointer_bits.as_ref().map(|f| entry.f(f).u64()) {
                Some(Ok(v)) => v,
                Some(Err(e)) if e.is_invalid_address() => return Ok(None),
                Some(Err(e)) => return Err(e),
                None => entry.m("ObjectPointerBits")?.u64()?,
            };
            if bits == 0 {
                return Ok(None);
            }
            bits << 4
        } else {
            let it = match self.info_table.as_ref().map(|f| entry.f(f).u64()) {
                Some(Ok(v)) => v,
                Some(Err(e)) if e.is_invalid_address() => return Ok(None),
                Some(Err(e)) => return Err(e),
                None => entry.m("InfoTable")?.u64()?,
            };
            if it == 0 {
                return Ok(None);
            }
            it & !7
        };
        let header = Obj::new(self.header_sp, self.header_ty, offset & self.layer.address_mask());
        let ga = match self.granted_access_bits.as_ref().map(|f| entry.f(f).u64()) {
            Some(Ok(v)) => v,
            Some(Err(e)) if e.is_invalid_address() => return Ok(None),
            Some(Err(e)) => return Err(e),
            None => return Err(Error::Symbol("AttributeError: _HANDLE_TABLE_ENTRY has no attribute: GrantedAccessBits".into())),
        };
        Ok(Some(HandleItem { header, handle_value, granted_access: ga }))
    }
}

/// python `CM_KEY_BODY.get_full_key_name()` (None where python returns None).
// TODO(dedupe): owned by A3 registry (symbols/windows/extensions/registry.py CM_KEY_BODY)
fn cm_key_body_full_name(body: &Obj) -> Result<Option<String>> {
    const KEY_HIVE_ENTRY: i128 = 0x04;
    let has_trans = body.has_member("Trans");
    let mut output: Vec<String> = Vec::new();
    let mut seen = crate::util::FxHashSet::default();
    let mut kcb = body.m("KeyControlBlock")?;
    loop {
        let parent = kcb.m("ParentKcb")?;
        if parent.u64()? == 0 {
            break;
        }
        if !seen.insert(parent.addr) {
            return Ok(None);
        }
        if output.len() > 128 {
            return Ok(None);
        }
        // `kcb.NameBlock.Name is None` is never true
        if has_trans && KEY_HIVE_ENTRY & kcb.m("Flags")?.int()? == KEY_HIVE_ENTRY {
            kcb = kcb.m("ParentKcb")?;
            if kcb.u64()? == 0 {
                break;
            }
        }
        let nb = kcb.m("NameBlock")?;
        let len = nb.m("NameLength")?.u64()?;
        output.push(nb.m("Name")?.cast_string(len, StrEnc::Utf8, StrErrors::Replace).string()?);
        kcb = kcb.m("ParentKcb")?;
    }
    output.reverse();
    Ok(Some(output.join("\\")))
}

/// python `_generator`'s per-handle part: (type name, object name) of one handle, `Ok(None)`
/// for handles python skips (unknown type or InvalidAddressException).
pub fn handle_object_info(item: &HandleItem, type_map: &TypeMap, cookie: Option<u64>) -> Result<Option<(String, Value)>> {
    let r = (|| -> Result<Option<(String, Value)>> {
        let Some(obj_type) = item.header.get_object_type(type_map, cookie)? else { return Ok(None) };
        let body = item.header.m("Body")?;
        let name = match obj_type.as_str() {
            "File" => body.cast("_FILE_OBJECT")?.file_name_with_device()?,
            "Process" => {
                let p = body.cast("_EPROCESS")?;
                Value::Str(format!("{} Pid {}", array_to_string(&p.m("ImageFileName")?, None)?, p.m("UniqueProcessId")?.int()?))
            }
            "Thread" => {
                let t = body.cast("_ETHREAD")?;
                let cid = t.m("Cid")?;
                Value::Str(format!("Tid {} Pid {}", cid.m("UniqueThread")?.int()?, cid.m("UniqueProcess")?.int()?))
            }
            "Key" => match cm_key_body_full_name(&body.cast("_CM_KEY_BODY")?)? {
                Some(s) => Value::Str(s),
                None => Value::NotAvailable,
            },
            _ => match item.header.name_info().and_then(|n| n.m("Name")).and_then(|n| n.get_string()) {
                Ok(s) => Value::Str(s),
                Err(e) if e.is_invalid_address() || is_name_info_value_error(&e) => Value::NotAvailable,
                Err(e) => return Err(e),
            },
        };
        // python: obj_name or NotAvailableValue()
        let name = match name {
            Value::Str(s) if s.is_empty() => Value::NotAvailable,
            v => v,
        };
        Ok(Some((obj_type, name)))
    })();
    match r {
        Err(e) if e.is_invalid_address() => Ok(None),
        r => r,
    }
}

/// The rows of one process (python `_generator` body for `proc`); a trailing `Err` = python
/// raised there.
fn proc_rows(walker: &HandleWalker, proc: &Obj, type_map: &TypeMap, cookie: Option<u64>) -> Vec<Result<Vec<Value>>> {
    let mut rows = Vec::new();
    let r = (|| -> Result<()> {
        let object_table = match proc.m("ObjectTable").and_then(|o| o.u64().map(|_| o)) {
            Ok(o) => o,
            Err(e) if e.is_invalid_address() => return Ok(()),
            Err(e) => return Err(e),
        };
        let process_name = array_to_string(&proc.m("ImageFileName")?, None)?;
        let mut pid: Option<i128> = None;
        for item in walker.handles(&object_table) {
            let item = item?;
            let Some((obj_type, name)) = handle_object_info(&item, type_map, cookie)? else { continue };
            let pid = match pid {
                Some(p) => p,
                None => *pid.insert(proc.m("UniqueProcessId")?.int()?),
            };
            let body_off = item.header.addr.wrapping_add(item.header.member_offset("Body")?);
            rows.push(Ok(vec![
                Value::Int(pid),
                Value::Str(process_name.clone()),
                Value::Int(body_off as i128),
                Value::Int(item.handle_value as i128),
                Value::Str(obj_type),
                Value::Int(item.granted_access as i128),
                name,
            ]));
        }
        Ok(())
    })();
    if let Err(e) = r {
        rows.push(Err(e));
    }
    rows
}

impl Plugin for Handles {
    fn name(&self) -> &'static str {
        "windows.handles.Handles"
    }
    fn description(&self) -> &'static str {
        "Lists process open handles."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Process IDs to include (all other processes are excluded)", ReqKind::ListInt).optional(),
            Requirement::new("offset", "Process offset in the physical address space", ReqKind::Int).optional(),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Offset", ColType::Hex),
            Column::new("HandleValue", ColType::Hex),
            Column::new("Type", ColType::Str),
            Column::new("GrantedAccess", ColType::Hex),
            Column::new("Name", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let pids = cfg.get_ints("pid");
        let offset = cfg.get_int("offset").filter(|o| *o != 0);
        let procs = match offset {
            Some(o) => scan_processes(ctx, k, &create_offset_filter(k, Some(o as u64), true, false)),
            None => list_processes(k, &pid_filter(&pids)),
        };
        let type_map = get_type_map(k)?;
        let cookie = find_cookie(k)?;
        let walker = HandleWalker::new(k)?;
        // processes are independent: walk them in parallel, emit in python order
        let per_proc = crate::util::par::par_map(procs.len(), |i| match &procs[i] {
            Ok(p) => proc_rows(&walker, p, &type_map, cookie),
            Err(_) => Vec::new(),
        });
        for (p, rows) in procs.into_iter().zip(per_proc) {
            p?;
            for r in rows {
                out.row(0, r?)?;
            }
        }
        Ok(())
    }
}
