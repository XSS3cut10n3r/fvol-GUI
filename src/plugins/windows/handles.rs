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
use crate::renderers::{ColType, Column, RowBlock, RowSink, Value};
use crate::symbols::table::{StrEnc, StrErrors};
use crate::symbols::windows::WinExt;
use crate::symbols::windows::objects::{ObjectsExt, is_name_info_value_error};
use crate::symbols::windows::pool::{PoolExt, TypeMap};
use crate::symbols::windows::registry::RegExt;
use crate::symbols::Ty;

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
    /// `layer.address_mask()` (the trait default takes an f64 log2 per call)
    mask: u64,
    /// the native layer's address mask (pointer values)
    native_mask: u64,
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
            mask: k.vlayer.address_mask(),
            native_mask: Space::on(k.vlayer, t).native_mask,
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
        let base = offset & self.mask;
        let mut page = u64::MAX;
        let mut page_ok = false;
        // level 0: the entries of a valid page, zero-copy when the image maps it whole
        let mut page_bytes: Option<&'static [u8]> = None;
        for i in 0..count {
            let addr = base.wrapping_add(i * esize) & self.mask;
            // python validates the element's first byte
            if addr >> 12 != page {
                page = addr >> 12;
                page_ok = self.layer.is_valid(addr, 1);
                page_bytes = if page_ok && level == 0 { crate::objects::page_bytes(self.layer, addr & !0xfff, 0x1000) } else { None };
                if let Some(pb) = page_bytes {
                    self.prefetch_headers(pb, (addr & 0xfff) as usize, esize as usize);
                }
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
                let o = (addr & 0xfff) as usize;
                let fast = page_bytes.and_then(|pb| pb.get(o..o + esize as usize)).and_then(|rec| self.get_item_from(rec, hv as u64));
                let item = match fast {
                    Some(it) => it,
                    None => {
                        let entry = Obj::new(self.header_sp, self.entry_ty, addr);
                        self.get_item(&entry, hv as u64)?
                    }
                };
                let Some(item) = item else { continue };
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
        crate::objects::read_into(self.layer, addr, &mut b[..n])?;
        Ok(u64::from_le_bytes(b) & self.mask)
    }

    /// Prefetch the `TypeIndex` of every object header the entries of a leaf page (from byte
    /// `from`) point to: the walk reads each right after decoding its entry, one cache miss
    /// per handle that would otherwise be paid one after the other.
    fn prefetch_headers(&self, page: &[u8], from: usize, esize: usize) {
        let Some(ti) = &self.type_index else { return };
        if esize == 0 {
            return;
        }
        let mut o = from;
        while o + esize <= page.len() {
            if let Some(Some(item)) = self.get_item_from(&page[o..o + esize], 0) {
                crate::objects::prefetch(self.layer, item.header.addr.wrapping_add(ti.offset));
            }
            o += esize;
        }
    }

    /// [`get_item`](Self::get_item) for an entry whose bytes `rec` are all readable (so no
    /// field read can fail), Windows 8+ layouts: `None` = take the generic path.
    #[inline]
    fn get_item_from(&self, rec: &[u8], handle_value: u64) -> Option<Option<HandleItem>> {
        if self.object.is_some() {
            return None;
        }
        let offset = if self.is_64bit {
            let bits = self.object_pointer_bits.as_ref()?.int_from(rec, self.native_mask)? as u64;
            if bits == 0 {
                return Some(None);
            }
            bits << 4
        } else {
            let it = self.info_table.as_ref()?.int_from(rec, self.native_mask)? as u64;
            if it == 0 {
                return Some(None);
            }
            it & !7
        };
        let granted_access = self.granted_access_bits.as_ref()?.int_from(rec, self.native_mask)? as u64;
        let header = Obj::new(self.header_sp, self.header_ty, offset & self.mask);
        Some(Some(HandleItem { header, handle_value, granted_access }))
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
        let header = Obj::new(self.header_sp, self.header_ty, offset & self.mask);
        let ga = match self.granted_access_bits.as_ref().map(|f| entry.f(f).u64()) {
            Some(Ok(v)) => v,
            Some(Err(e)) if e.is_invalid_address() => return Ok(None),
            Some(Err(e)) => return Err(e),
            None => return Err(Error::Symbol("AttributeError: _HANDLE_TABLE_ENTRY has no attribute: GrantedAccessBits".into())),
        };
        Ok(Some(HandleItem { header, handle_value, granted_access: ga }))
    }
}

/// python `_generator`'s per-handle part: (type name, object name) of one handle, `Ok(None)`
/// for handles python skips (unknown type or InvalidAddressException).
pub fn handle_object_info(item: &HandleItem, type_map: &TypeMap, cookie: Option<u64>) -> Result<Option<(String, Value)>> {
    let r = (|| -> Result<Option<(String, Value)>> {
        let Some(obj_type) = item.header.get_object_type(type_map, cookie)? else { return Ok(None) };
        let name = object_name(item, &obj_type, None)?;
        Ok(Some((obj_type, name)))
    })();
    match r {
        Err(e) if e.is_invalid_address() => Ok(None),
        r => r,
    }
}

/// The object name python's `_generator` shows for a handle of type `obj_type` (`obj_name or
/// NotAvailableValue()`); errors as python raises them (the caller skips invalid addresses).
fn object_name(item: &HandleItem, obj_type: &str, fast: Option<&Namer>) -> Result<Value> {
    let body = match fast {
        Some(n) => Obj::new(item.header.sp, n.body_ty, item.header.addr.wrapping_add(n.body_off)),
        None => item.header.m("Body")?,
    };
    let name = match obj_type {
        "File" => body.cast("_FILE_OBJECT")?.file_name_with_device()?,
        "Process" => {
            let p = body.cast("_EPROCESS")?;
            let mut s = array_to_string(&p.m("ImageFileName")?, None)?;
            s.push_str(" Pid ");
            push_int(&mut s, p.m("UniqueProcessId")?.int()?);
            Value::Str(s)
        }
        "Thread" => {
            let t = body.cast("_ETHREAD")?;
            let cid = t.m("Cid")?;
            let mut s = String::from("Tid ");
            push_int(&mut s, cid.m("UniqueThread")?.int()?);
            s.push_str(" Pid ");
            push_int(&mut s, cid.m("UniqueProcess")?.int()?);
            Value::Str(s)
        }
        "Key" => match body.cast("_CM_KEY_BODY")?.get_full_key_name()? {
            Some(s) => Value::Str(s),
            None => Value::NotAvailable,
        },
        _ => {
            let named = match fast.and_then(|n| n.name_info.as_ref()) {
                Some(ni) => ni.name(&item.header),
                None => item.header.name_info().and_then(|n| n.m("Name")).and_then(|n| n.get_string()).map(Some),
            };
            match named {
                Ok(Some(s)) => Value::Str(s),
                Ok(None) => Value::NotAvailable,
                Err(e) if e.is_invalid_address() || is_name_info_value_error(&e) => Value::NotAvailable,
                Err(e) => return Err(e),
            }
        }
    };
    // python: obj_name or NotAvailableValue()
    Ok(match name {
        Value::Str(s) if s.is_empty() => Value::NotAvailable,
        v => v,
    })
}

/// python's `str(int)` appended.
fn push_int(s: &mut String, v: i128) {
    use std::fmt::Write;
    let _ = write!(s, "{v}");
}

/// `OBJECT_HEADER.NameInfo.Name` (python `NameInfo` property + `.Name`, then `get_string()`),
/// with everything but the per-object reads resolved once: `Ok(None)` = python's ValueError
/// (no name info). Only built when the kernel layer has a kernel_virtual_offset (otherwise the
/// generic path raises python's AttributeError).
struct NameInfoFast {
    how: NameInfoHow,
    /// `_OBJECT_HEADER_NAME_INFO`
    ni_ty: Ty,
    /// offset of `Name` (a `_UNICODE_STRING`) in it
    name: Field,
    /// `_UNICODE_STRING.Buffer` / `.Length`
    buffer: Field,
    length: Field,
}

enum NameInfoHow {
    /// before Windows 7: `_OBJECT_HEADER.NameInfoOffset`
    Offset(Field),
    /// `ObpInfoMaskToOffset[InfoMask & 3]`: the header's `InfoMask`, the table's absolute address
    Mask { info_mask: Field, table: u64 },
}

impl NameInfoFast {
    fn new(k: &WinKernel) -> Option<NameInfoFast> {
        let t = k.table;
        let kvo = k.layer.kernel_virtual_offset()?;
        let how = match Field::new(t, "_OBJECT_HEADER", "NameInfoOffset") {
            Ok(f) => NameInfoHow::Offset(f),
            Err(_) => {
                let address = t.get_symbol("ObpInfoMaskToOffset").ok()?.address;
                NameInfoHow::Mask { info_mask: Field::new(t, "_OBJECT_HEADER", "InfoMask").ok()?, table: kvo.wrapping_add(address) }
            }
        };
        // python reads the table entry as an "unsigned char"
        if !matches!(t.get_type("unsigned char"), Ok(Ty::Int(p)) if p.size == 1 && !p.signed && !p.big_endian) {
            return None;
        }
        let ni_ty = t.get_type("_OBJECT_HEADER_NAME_INFO").ok()?;
        let name = Field::new(t, "_OBJECT_HEADER_NAME_INFO", "Name").ok()?;
        if !matches!(name.ty, Ty::Struct(u) if t.user_type_name(u) == "_UNICODE_STRING") {
            return None;
        }
        let buffer = Field::new(t, "_UNICODE_STRING", "Buffer").ok()?;
        let length = Field::new(t, "_UNICODE_STRING", "Length").ok()?;
        Some(NameInfoFast { how, ni_ty, name, buffer, length })
    }

    /// See the type docs. `header` is an `_OBJECT_HEADER` of the kernel table.
    fn name(&self, header: &Obj) -> Result<Option<String>> {
        let header_offset: u64 = match &self.how {
            NameInfoHow::Offset(f) => header.f(f).int()? as u64,
            NameInfoHow::Mask { info_mask, table } => {
                let index = (header.f(info_mask).int()? as u64) & 3;
                let nsp = header.sp.native_space();
                let mut b = [0u8; 1];
                crate::objects::read_into(nsp.layer, table.wrapping_add(index) & nsp.layer_mask, &mut b)?;
                b[0] as u64
            }
        };
        if header_offset == 0 {
            return Ok(None);
        }
        let ni = Obj::new(header.sp, self.ni_ty, header.addr.wrapping_sub(header_offset));
        let us = ni.f(&self.name);
        // python UNICODE_STRING.get_string()
        let length = us.f(&self.length).u64()?;
        let buffer = us.f(&self.buffer);
        let addr = buffer.u64()?;
        let sp = Space::get(buffer.sp.native, buffer.sp.native, us.sp.table);
        Obj::new(sp, Ty::Void, addr).cast_string(length, StrEnc::Utf16, StrErrors::Replace).string().map(Some)
    }
}

/// Per-run state of python's per-handle naming, resolved once (types, offsets, the name-info
/// lookup), for the Windows 7+ layouts (`_OBJECT_HEADER.TypeIndex`); older kernels use the
/// generic path.
pub struct Namer {
    /// python's `type_map`, indexed by the decoded type index (leaked: a few dozen short
    /// names per run, shared by every row)
    types: Vec<Option<&'static str>>,
    cookie: Option<u64>,
    type_index: Field,
    body_off: u64,
    body_ty: Ty,
    name_info: Option<NameInfoFast>,
}

impl Namer {
    /// None when the kernel's `_OBJECT_HEADER` has the pre-Windows 7 `Type` pointer.
    pub fn new(k: &WinKernel, type_map: &TypeMap, cookie: Option<u64>) -> Option<Namer> {
        let t = k.table;
        let hdr = t.user_type("_OBJECT_HEADER")?;
        if t.member(hdr, "Type").is_some() {
            return None;
        }
        let type_index = Field::new(t, "_OBJECT_HEADER", "TypeIndex").ok()?;
        let body = t.member(hdr, "Body")?;
        let mut types = vec![None; 256];
        for (&i, name) in type_map.iter() {
            if let Some(slot) = types.get_mut(i as usize) {
                *slot = Some(&*Box::leak(name.clone().into_boxed_str()));
            }
        }
        Some(Namer { types, cookie, type_index, body_off: body.offset, body_ty: body.ty, name_info: NameInfoFast::new(k) })
    }

    /// python `OBJECT_HEADER.get_object_type(type_map, cookie)` (Windows 7+).
    #[inline]
    fn object_type(&self, header: &Obj) -> Result<Option<&'static str>> {
        let ti = header.f(&self.type_index).int()? as u64;
        let index = match self.cookie {
            Some(c) => ((header.addr >> 8) ^ c ^ ti) & 0xff,
            None => ti,
        };
        Ok(self.types.get(index as usize).copied().flatten())
    }

    /// [`handle_object_info`] with the resolved state.
    fn info(&self, item: &HandleItem) -> Result<Option<(&'static str, Value)>> {
        let r = (|| -> Result<Option<(&'static str, Value)>> {
            let Some(obj_type) = self.object_type(&item.header)? else { return Ok(None) };
            let name = object_name(item, obj_type, Some(self))?;
            Ok(Some((obj_type, name)))
        })();
        match r {
            Err(e) if e.is_invalid_address() => Ok(None),
            r => r,
        }
    }
}

/// One process's part of the output, walked in parallel (python `_generator` up to the
/// handle loop).
struct ProcHandles {
    proc: Obj,
    /// python reads `ImageFileName` before walking (leaked: shared by all of its rows)
    name: &'static str,
    /// `UniqueProcessId`, read by python at the first row (an error surfaces there)
    pid: Option<i128>,
    /// the handles (up to where python raised while walking, see [`Walked`])
    items: Vec<HandleItem>,
}

/// Phase 1 result of one process: its handles, or where python raised before them (`pre`) or
/// while walking (`tail`, after the handles).
#[derive(Default)]
struct Walked {
    ph: Option<ProcHandles>,
    pre: Option<Error>,
    tail: Option<Error>,
}

/// Handles per work unit of the naming phase (the biggest tables are split across workers).
const UNIT: usize = 256;

/// How a unit of handles ended.
enum UnitEnd {
    Done,
    /// python raised (`Err` items, naming errors)
    Err(Error),
    /// the process's `UniqueProcessId` is unreadable at its first row: re-read on the output
    /// thread for python's error
    Pid,
}

/// The rows of one process (python `_generator` body for `proc`) on the generic path; a
/// trailing `Err` = python raised there.
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

/// Phase 1 of the fast path for one process (python `_generator` up to the handle loop, and
/// the handle-table walk).
fn walk_proc(walker: &HandleWalker, proc: &Obj) -> Walked {
    let object_table = match proc.m("ObjectTable").and_then(|o| o.u64().map(|_| o)) {
        Ok(o) => o,
        Err(e) if e.is_invalid_address() => return Walked::default(),
        Err(e) => return Walked { pre: Some(e), ..Default::default() },
    };
    let name = match proc.m("ImageFileName").and_then(|a| array_to_string(&a, None)) {
        Ok(n) => n,
        Err(e) => return Walked { pre: Some(e), ..Default::default() },
    };
    let name: &'static str = Box::leak(name.into_boxed_str());
    let pid = proc.m("UniqueProcessId").and_then(|p| p.int()).ok();
    let mut items = Vec::new();
    let mut tail = None;
    for r in walker.handles(&object_table) {
        match r {
            Ok(i) => items.push(i),
            Err(e) => {
                tail = Some(e);
                break;
            }
        }
    }
    Walked { ph: Some(ProcHandles { proc: *proc, name, pid, items }), pre: None, tail }
}

/// Phase 2: name and format handles `range` of one process into `block`.
fn unit_rows(namer: &Namer, ph: &ProcHandles, range: std::ops::Range<usize>, block: &mut RowBlock) -> UnitEnd {
    let mut row = [Value::Int(0), Value::SStr(ph.name), Value::Int(0), Value::Int(0), Value::SStr(""), Value::Int(0), Value::NotAvailable];
    for item in &ph.items[range] {
        let (obj_type, name) = match namer.info(item) {
            Ok(Some(x)) => x,
            Ok(None) => continue,
            Err(e) => return UnitEnd::Err(e),
        };
        let Some(pid) = ph.pid else { return UnitEnd::Pid };
        row[0] = Value::Int(pid);
        row[2] = Value::Int(item.header.addr.wrapping_add(namer.body_off) as i128);
        row[3] = Value::Int(item.handle_value as i128);
        row[4] = Value::SStr(obj_type);
        row[5] = Value::Int(item.granted_access as i128);
        row[6] = name;
        block.push_ref(&row);
    }
    UnitEnd::Done
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
        let _t = crate::util::trace::span("handles: setup");
        let type_map = get_type_map(k)?;
        let cookie = find_cookie(k)?;
        let walker = HandleWalker::new(k)?;
        drop(_t);
        let Some(namer) = Namer::new(k, &type_map, cookie) else {
            // pre-Windows 7 layouts: processes are independent, walk them in parallel
            return crate::plugins::emit_par_rows(out, procs, |p| proc_rows(&walker, p, &type_map, cookie));
        };
        // 1. walk every handle table (a process per task)
        let _t = crate::util::trace::span("handles: walk tables");
        let (mut perr, walked): (Vec<Option<Error>>, Vec<Walked>) = {
            let w = crate::util::par::par_map(procs.len(), |i| match &procs[i] {
                Ok(p) => walk_proc(&walker, p),
                Err(_) => Walked::default(),
            });
            (procs.into_iter().map(|p| p.err()).collect(), w)
        };
        let (phs, mut errs): (Vec<Option<ProcHandles>>, Vec<(Option<Error>, Option<Error>)>) = walked.into_iter().map(|w| (w.ph, (w.pre, w.tail))).unzip();
        drop(_t);
        let _t = crate::util::trace::span("handles: name + emit");
        // 2. name and format the handles in units of UNIT across all processes
        let mut units: Vec<(usize, std::ops::Range<usize>)> = Vec::new();
        for (pi, ph) in phs.iter().enumerate() {
            if let Some(ph) = ph {
                let n = ph.items.len();
                let mut s = 0;
                while s < n {
                    units.push((pi, s..(s + UNIT).min(n)));
                    s += UNIT;
                }
            }
        }
        // 3. emit in python's order: per process its errors before the handles, the handles'
        // units, the walk error after them
        let mut next = 0usize;
        let mut finish = |upto: usize, started: &mut Option<usize>| -> Result<()> {
            while next < upto {
                let pi = next;
                if *started != Some(pi) {
                    if let Some(e) = perr[pi].take() {
                        return Err(e);
                    }
                    if let Some(e) = errs[pi].0.take() {
                        return Err(e);
                    }
                }
                if let Some(e) = errs[pi].1.take() {
                    return Err(e);
                }
                next += 1;
            }
            Ok(())
        };
        let enc = out.encoder();
        let mut started: Option<usize> = None;
        crate::plugins::stream_blocks(
            enc.as_ref(),
            units.len(),
            |u, block| {
                let (pi, range) = &units[u];
                match &phs[*pi] {
                    Some(ph) => unit_rows(&namer, ph, range.clone(), block),
                    None => UnitEnd::Done,
                }
            },
            |u, block, end| {
                let pi = units[u].0;
                // every process before this one is complete; this one has no errors before its
                // handles (it has handles)
                finish(pi, &mut started)?;
                started = Some(pi);
                block.emit(&mut *out)?;
                match end {
                    // (None: the unit panicked after these rows; stream_blocks resumes it)
                    None | Some(UnitEnd::Done) => Ok(true),
                    Some(UnitEnd::Err(e)) => Err(e),
                    Some(UnitEnd::Pid) => {
                        phs[pi].as_ref().map(|ph| ph.proc).ok_or_else(|| Error::msg("handles: no process"))?.m("UniqueProcessId")?.int()?;
                        Err(Error::msg("UniqueProcessId became readable"))
                    }
                }
            },
        )?;
        finish(phs.len(), &mut started)?;
        Ok(())
    }
}
