//! python `symbols/windows/extensions/__init__.py` class extensions, as the [`WinExt`] trait on
//! [`Obj`]. Method names follow python; methods python defines on several classes
//! (`is_valid`, `get_create_time`, `get_exit_time`) dispatch on the object's type name like
//! python's per-class methods.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::error::{Error, Result};
use crate::layers::{Layer, LayerExt};
use crate::objects::util::array_to_string;
use crate::objects::{LayerRef, Module, Obj, Space, leak_layer};
use crate::renderers::Value;
use crate::symbols::{StrEnc, StrErrors, TableRef, Ty};
use crate::util::time::{current_year, wintime_to_datetime, year};
use crate::util::{FxHashMap, FxHashSet};
use std::sync::{Arc, Mutex};

/// python `constants.windows.MAX_PID`.
pub const MAX_PID: u64 = 0xFFFF_FFFC;

static PROC_LAYERS: Mutex<Option<FxHashMap<(usize, u64), LayerRef>>> = Mutex::new(None);

/// python `GenericIntelProcess._add_process_layer`: a translation layer like `parent` (an
/// Intel layer) with page table root `dtb`. Memoized per (parent, dtb).
pub fn process_layer(parent: LayerRef, dtb: u64, pid: u64) -> Result<LayerRef> {
    let intel = parent.as_intel().ok_or_else(|| Error::msg("Parent layer is not a translation layer, unable to construct process layer"))?;
    let key = (parent as *const dyn Layer as *const u8 as usize, dtb);
    let mut g = PROC_LAYERS.lock().unwrap();
    let map = g.get_or_insert_with(Default::default);
    if let Some(l) = map.get(&key) {
        return Ok(*l);
    }
    let name = format!("{}_Process{}", parent.name(), pid);
    let l = leak_layer(Arc::new(intel.process_layer(dtb, &name)));
    map.insert(key, l);
    Ok(l)
}

/// Lazy iterator over a `_LIST_ENTRY` list (python `LIST_ENTRY.to_list`). Yields
/// `Err` once (then stops) where python would raise mid-iteration.
pub struct ListIter {
    state: ListState,
}

enum ListState {
    Done,
    Failed(Error),
    Start { head: Obj, sym_sp: &'static Space, sym_ty: Ty, rel: u64, forward: bool, sentinel: bool },
    Walk { link: Obj, seen: FxHashSet<u64>, sym_sp: &'static Space, sym_ty: Ty, rel: u64, forward: bool },
}

impl ListIter {
    fn empty() -> ListIter {
        ListIter { state: ListState::Done }
    }
}

fn next_link(link: &Obj, forward: bool) -> Result<Option<Obj>> {
    let ptr = link.m(if forward { "Flink" } else { "Blink" })?;
    let v = ptr.u64()?;
    if v == 0 || !ptr.is_readable() {
        return Ok(None);
    }
    Ok(Some(ptr.deref()?))
}

impl Iterator for ListIter {
    type Item = Result<Obj>;
    fn next(&mut self) -> Option<Result<Obj>> {
        loop {
            match std::mem::replace(&mut self.state, ListState::Done) {
                ListState::Done => return None,
                ListState::Failed(e) => return Some(Err(e)),
                ListState::Start { head, sym_sp, sym_ty, rel, forward, sentinel } => {
                    let trans = sym_sp.layer;
                    if !trans.is_valid(head.addr, 1) {
                        return None;
                    }
                    let link = match next_link(&head, forward) {
                        Ok(Some(l)) => l,
                        Ok(None) => return None,
                        Err(e) => return Some(Err(e)),
                    };
                    let mut seen = FxHashSet::default();
                    seen.insert(head.addr);
                    self.state = ListState::Walk { link, seen, sym_sp, sym_ty, rel, forward };
                    if !sentinel {
                        let off = head.addr.wrapping_sub(rel);
                        if !trans.is_valid(off, 1) {
                            self.state = ListState::Done;
                            return None;
                        }
                        return Some(Ok(Obj::new(sym_sp, sym_ty, off)));
                    }
                }
                ListState::Walk { link, mut seen, sym_sp, sym_ty, rel, forward } => {
                    if seen.contains(&link.addr) {
                        return None;
                    }
                    let off = link.addr.wrapping_sub(rel);
                    if !sym_sp.layer.is_valid(off, 1) {
                        return None;
                    }
                    let item = Obj::new(sym_sp, sym_ty, off);
                    seen.insert(link.addr);
                    match next_link(&link, forward) {
                        Ok(Some(l)) => self.state = ListState::Walk { link: l, seen, sym_sp, sym_ty, rel, forward },
                        Ok(None) => self.state = ListState::Done,
                        Err(e) => {
                            // python raises when fetching the next link, after yielding `item`
                            self.state = ListState::Failed(e);
                        }
                    }
                    return Some(Ok(item));
                }
            }
        }
    }
}

/// Windows class extensions on [`Obj`].
pub trait WinExt {
    // ---- _UNICODE_STRING
    /// python `UNICODE_STRING.get_string()` / `.String`: `Length` bytes at `Buffer` (on the
    /// Buffer's native layer), utf-16 with errors="replace", cut at NUL.
    fn get_string(&self) -> Result<String>;

    // ---- _LIST_ENTRY
    /// python `LIST_ENTRY.to_list(symbol_type, member, forward, sentinel, layer)`.
    /// `symbol_type` is a type name of this object's table (or `table!type`).
    fn to_list(&self, symbol_type: &str, member: &str, forward: bool, sentinel: bool, layer: Option<LayerRef>) -> ListIter;
    /// `to_list(symbol_type, member)` with python defaults (forward, sentinel).
    fn list_of(&self, symbol_type: &str, member: &str) -> ListIter {
        self.to_list(symbol_type, member, true, true, None)
    }

    // ---- _KSYSTEM_TIME
    /// python `KSYSTEM_TIME.get_time()`.
    fn get_time(&self) -> Result<Value>;

    // ---- _EX_FAST_REF
    /// python `EX_FAST_REF.dereference()`: a `pointer` object at `Object & ~max_fast_ref`.
    fn fast_ref_dereference(&self) -> Result<Obj>;

    // ---- dispatching (python has these on several classes)
    /// python `is_valid()` of `_EPROCESS`, `_ETHREAD`, `_FILE_OBJECT`, `_DRIVER_OBJECT`,
    /// `_KMUTANT`, `_OBJECT_SYMBOLIC_LINK`, `_ERESOURCE`, `_CONTROL_AREA`, `_SHARED_CACHE_MAP`.
    fn is_valid(&self) -> bool;
    /// python `get_create_time()` (`_EPROCESS`, `_ETHREAD`, `_OBJECT_SYMBOLIC_LINK`).
    fn get_create_time(&self) -> Result<Value>;
    /// python `get_exit_time()` (`_EPROCESS`, `_ETHREAD`).
    fn get_exit_time(&self) -> Result<Value>;

    // ---- _EPROCESS
    /// python `EPROCESS.add_process_layer()`: the process address space.
    fn add_process_layer(&self) -> Result<LayerRef>;
    /// python `EPROCESS.get_peb()`.
    fn get_peb(&self) -> Result<Obj>;
    /// python `EPROCESS.get_peb32()` (None when not WoW64).
    fn get_peb32(&self) -> Result<Option<Obj>>;
    /// python `EPROCESS.load_order_modules()` (`_LDR_DATA_TABLE_ENTRY`s in the process layer).
    /// A trailing `Err` means python would have raised at that point (after the Ok items).
    fn load_order_modules(&self) -> Vec<Result<Obj>>;
    /// python `EPROCESS.init_order_modules()`.
    fn init_order_modules(&self) -> Vec<Result<Obj>>;
    /// python `EPROCESS.mem_order_modules()`.
    fn mem_order_modules(&self) -> Vec<Result<Obj>>;
    /// python `EPROCESS.get_handle_count()` (int or UnreadableValue).
    fn get_handle_count(&self) -> Value;
    /// python `EPROCESS.get_session_id()` (int, NotApplicable or Unreadable).
    fn get_session_id(&self) -> Result<Value>;
    /// python `EPROCESS.get_wow_64_process()`.
    fn get_wow_64_process(&self) -> Result<Obj>;
    /// python `EPROCESS.get_is_wow64()`.
    fn get_is_wow64(&self) -> Result<bool>;
    /// python `EPROCESS.get_vad_root()`.
    fn get_vad_root(&self) -> Result<Obj>;
    /// python `EPROCESS.environment_variables()`.
    fn environment_variables(&self) -> Vec<(String, String)>;
    /// python `utility.array_to_string(proc.ImageFileName)`.
    fn image_file_name(&self) -> Result<String>;
    /// `proc.ImageFileName.cast("string", max_length=count, errors="replace")` (pslist style).
    fn image_file_name_str(&self) -> Result<String>;

    // ---- _ETHREAD / _KTHREAD
    /// python `ETHREAD.owning_process()`.
    fn owning_process(&self) -> Result<Obj>;
    /// python `ETHREAD.get_cross_thread_flags()`.
    fn get_cross_thread_flags(&self) -> Result<String>;
    /// python `KTHREAD.get_state()`.
    fn get_state(&self) -> Result<Value>;
    /// python `KTHREAD.get_wait_reason()`.
    fn get_wait_reason(&self) -> Result<Value>;

    // ---- _LDR_DATA_TABLE_ENTRY
    /// python `LDR_DATA_TABLE_ENTRY.get_load_count()`.
    fn get_load_count(&self) -> Option<i128>;
}

/// `table!type` / `type` lookup on the object's table for list element types.
fn resolve_type(o: &Obj, symbol_type: &str) -> Result<(&'static Space, Ty)> {
    match crate::symbols::resolve_ref(o.sp.table, symbol_type) {
        Some((t, ty)) => Ok((o.sp.with_table(t), ty)),
        None => Err(Error::Symbol(format!("Unknown symbol: {symbol_type}"))),
    }
}

fn eproc_walk_ldr(p: &Obj, list_member: &str, link_member: &str) -> Vec<Result<Obj>> {
    let mut pebs = Vec::new();
    if let Ok(peb) = p.get_peb() {
        pebs.push(peb);
    }
    if let Ok(Some(peb32)) = p.get_peb32() {
        pebs.push(peb32);
    }
    let mut out = Vec::new();
    for peb in pebs {
        let Ok(ldr) = peb.m("Ldr") else { continue };
        if ldr.u64().is_err() {
            continue;
        }
        let (ldr_ptr, sym_table): (Obj, TableRef) = if ldr.type_name() == "unsigned long" {
            // WoW64 PEB: Ldr is a 32-bit value; recast as pointer to the 32-bit _PEB_LDR_DATA
            let t = peb.sp.table;
            match t.get_type("_PEB_LDR_DATA") {
                Ok(ldt) => match ldr.cast_pointer_to(ldt) {
                    Ok(pp) => (pp, t),
                    Err(_) => continue,
                },
                Err(_) => continue,
            }
        } else {
            (ldr, p.sp.table)
        };
        let Ok(head) = ldr_ptr.m(list_member) else { continue };
        let sp = Space::get(head.sp.layer, head.sp.native, sym_table);
        let head = Obj { sp, ..head };
        for ldr in head.to_list("_LDR_DATA_TABLE_ENTRY", link_member, true, true, None) {
            let ldr = match ldr {
                Ok(l) => l,
                Err(e) => {
                    out.push(Err(e));
                    return out;
                }
            };
            match ldr.m("DllBase").and_then(|d| d.u64()) {
                Ok(_) => out.push(Ok(ldr)),
                Err(_) => continue,
            }
        }
    }
    out
}

fn eproc_is_valid(p: &Obj) -> Result<bool> {
    let name = array_to_string(&p.m("ImageFileName")?, None)?;
    if name.is_empty() || name.starts_with('\0') {
        return Ok(false);
    }
    let pid = p.m("UniqueProcessId")?.u64()?;
    if !(name == "System" && pid == 4) {
        if p.path("CreateTime.QuadPart")?.int()? == 0 {
            return Ok(false);
        }
        let ctime = match p.get_create_time()? {
            Value::DateTime(d) => d,
            _ => return Ok(false),
        };
        let cy = current_year();
        let y = year(&ctime);
        if !(1998 < y && y < cy + 10) {
            return Ok(false);
        }
        if let Value::DateTime(etime) = p.get_exit_time()? {
            let ey = year(&etime);
            if !(1998 < ey && ey < cy + 10) {
                return Ok(false);
            }
            if ctime > etime {
                return Ok(false);
            }
        }
    }
    let pid = p.m("UniqueProcessId")?.int()?;
    if pid % 4 != 0 || pid == 0 || pid > MAX_PID as i128 {
        return Ok(false);
    }
    let dtb_o = p.path("Pcb.DirectoryTableBase")?;
    let dtb = if dtb_o.is_array() { dtb_o.cast("pointer")?.u64()? } else { dtb_o.u64()? };
    if dtb == 0 || dtb & !0xFFF == 0 {
        return Ok(false);
    }
    let kernel = 0x8000_0000u64;
    let lh = p.m("ThreadListHead")?;
    if lh.m("Flink")?.u64()? < kernel || lh.m("Blink")?.u64()? < kernel {
        return Ok(false);
    }
    Ok(true)
}

fn ethread_is_valid(t: &Obj) -> Result<bool> {
    let cid = t.m("Cid")?;
    if cid.m("UniqueThread")?.u64()? % 4 != 0 {
        return Ok(false);
    }
    let up = cid.m("UniqueProcess")?.u64()?;
    if up % 4 != 0 {
        return Ok(false);
    }
    if up != 4 {
        let ctime = match t.get_create_time()? {
            Value::DateTime(d) => d,
            _ => return Ok(false),
        };
        let y = year(&ctime);
        if !(1998 < y && y < current_year() + 10) {
            return Ok(false);
        }
    }
    Ok(true)
}

impl WinExt for Obj {
    fn get_string(&self) -> Result<String> {
        let buffer = self.m("Buffer")?;
        let length = self.m("Length")?.u64()?;
        let addr = buffer.u64()?;
        let sp = Space::get(buffer.sp.native, buffer.sp.native, self.sp.table);
        Obj::new(sp, Ty::Void, addr).cast_string(length, StrEnc::Utf16, StrErrors::Replace).string()
    }

    fn to_list(&self, symbol_type: &str, member: &str, forward: bool, sentinel: bool, layer: Option<LayerRef>) -> ListIter {
        let Ok((tsp, ty)) = resolve_type(self, symbol_type) else { return ListIter::empty() };
        let rel = match ty {
            Ty::Struct(ut) => match tsp.table.member(ut, member) {
                Some(m) => m.offset,
                None => return ListIter::empty(),
            },
            _ => return ListIter::empty(),
        };
        // python: native_layer_name = layer_name (layer or self's layer)
        let lay = layer.unwrap_or(self.sp.layer);
        let sym_sp = Space::get(lay, lay, tsp.table);
        let head = match layer {
            Some(l) => Obj::new(Space::get(l, self.sp.native, self.sp.table), self.ty, self.addr),
            None => *self,
        };
        ListIter { state: ListState::Start { head, sym_sp, sym_ty: ty, rel, forward, sentinel } }
    }

    fn get_time(&self) -> Result<Value> {
        let high = self.m("High1Time")?.int()?;
        let low = self.m("LowPart")?.int()?;
        Ok(wintime_to_datetime((high << 32) | low))
    }

    fn fast_ref_dereference(&self) -> Result<Obj> {
        let max_fast_ref: u64 = if self.sp.table.is_64bit() { 15 } else { 7 };
        let v = self.m("Object")?.u64()?;
        Obj::named(self.sp, "pointer", v & !max_fast_ref)
    }

    fn is_valid(&self) -> bool {
        match self.struct_name() {
            Some("_EPROCESS") => eproc_is_valid(self).unwrap_or(false),
            Some("_ETHREAD") => ethread_is_valid(self).unwrap_or(false),
            Some("_FILE_OBJECT") => (|| -> Result<bool> {
                let fname = self.m("FileName")?;
                if fname.m("Length")?.u64()? == 0 {
                    return Ok(false);
                }
                let buf = fname.m("Buffer")?;
                Ok(buf.sp.native.is_valid(buf.u64()?, 1))
            })()
            .unwrap_or(false),
            Some("_DRIVER_OBJECT") | Some("_KMUTANT") | Some("_OBJECT_SYMBOLIC_LINK") => true,
            Some("_CONTROL_AREA") => super::cache::control_area_is_valid(self),
            Some("_SHARED_CACHE_MAP") => super::cache::shared_cache_map_is_valid(self).unwrap_or(false),
            Some("_ERESOURCE") => super::cache::eresource_is_valid(self).unwrap_or(false),
            Some("_OBJECT_HEADER") => super::pool::object_header_is_valid(self),
            Some("_CMHIVE") => super::registry::cmhive_is_valid(self),
            Some("tagWINDOWSTATION") | Some("tagDESKTOP") | Some("tagWND") => super::gui::gui_is_valid(self).unwrap_or(true),
            Some("_POOL_TRACKER_BIG_PAGES") => {
                use super::pool::PoolExt;
                self.big_page_is_valid().unwrap_or(false)
            }
            _ => true,
        }
    }

    fn get_create_time(&self) -> Result<Value> {
        match self.struct_name() {
            Some("_ETHREAD") => {
                let q = self.path("CreateTime.QuadPart")?.int()?;
                if self.has_member("ThreadsProcess") { Ok(wintime_to_datetime(q >> 3)) } else { Ok(wintime_to_datetime(q)) }
            }
            Some("_OBJECT_SYMBOLIC_LINK") => Ok(wintime_to_datetime(self.path("CreationTime.QuadPart")?.int()?)),
            _ => Ok(wintime_to_datetime(self.path("CreateTime.QuadPart")?.int()?)),
        }
    }

    fn get_exit_time(&self) -> Result<Value> {
        Ok(wintime_to_datetime(self.path("ExitTime.QuadPart")?.int()?))
    }

    fn add_process_layer(&self) -> Result<LayerRef> {
        let parent = self.sp.layer;
        let intel = parent.as_intel().ok_or_else(|| Error::msg("Parent layer is not a translation layer, unable to construct process layer"))?;
        let d = self.path("Pcb.DirectoryTableBase")?;
        let dtb = if d.is_array() { d.cast("unsigned long long")?.u64()? } else { d.u64()? };
        let bits = intel.bits_per_register();
        let dtb = if bits >= 64 { dtb } else { dtb & ((1u64 << bits) - 1) };
        let pid = self.m("UniqueProcessId")?.u64()?;
        process_layer(parent, dtb, pid)
    }

    fn get_peb(&self) -> Result<Obj> {
        let pl = self.add_process_layer()?;
        let peb = self.m("Peb")?.u64()?;
        if !pl.is_valid(peb, 1) {
            return Err(Error::invalid(peb));
        }
        Obj::named(Space::on(pl, self.sp.table), "_PEB", peb)
    }

    fn get_peb32(&self) -> Result<Option<Obj>> {
        let pl = self.add_process_layer()?;
        if !self.get_is_wow64()? {
            return Ok(None);
        }
        let proc = self.get_wow_64_process()?;
        let pv = proc.u64()?;
        if !pl.is_valid(pv, 1) {
            return Err(Error::invalid(pv));
        }
        let wow = crate::symbols::load_isf("windows", "wow64", None, &[])?;
        let t = self.sp.table;
        let offset = if t.has_type("_EWOW64PROCESS") {
            proc.m("Peb")?.u64()?
        } else if t.has_type("_WOW64_PROCESS") {
            proc.m("Wow64")?.u64()?
        } else {
            pv
        };
        Ok(Some(Obj::named(Space::on(pl, wow), "_PEB32", offset)?))
    }

    fn load_order_modules(&self) -> Vec<Result<Obj>> {
        eproc_walk_ldr(self, "InLoadOrderModuleList", "InLoadOrderLinks")
    }
    fn init_order_modules(&self) -> Vec<Result<Obj>> {
        eproc_walk_ldr(self, "InInitializationOrderModuleList", "InInitializationOrderLinks")
    }
    fn mem_order_modules(&self) -> Vec<Result<Obj>> {
        eproc_walk_ldr(self, "InMemoryOrderModuleList", "InMemoryOrderLinks")
    }

    fn get_handle_count(&self) -> Value {
        if self.has_member("ObjectTable") {
            if let Ok(ot) = self.m("ObjectTable") {
                if ot.has_member("HandleCount") {
                    if let Ok(v) = ot.m("HandleCount").and_then(|h| h.int()) {
                        return Value::Int(v);
                    }
                }
            }
        }
        Value::Unreadable
    }

    fn get_session_id(&self) -> Result<Value> {
        if !self.has_member("Session") {
            return Ok(Value::Unreadable);
        }
        let session = match self.m("Session").and_then(|s| s.u64()) {
            Ok(s) => s,
            Err(e) if e.is_invalid_address() => return Ok(Value::Unreadable),
            Err(e) => return Err(e),
        };
        if session == 0 {
            return Ok(Value::NotApplicable);
        }
        let kvo = self
            .sp
            .native
            .as_intel()
            .and_then(|i| i.kernel_virtual_offset())
            .filter(|k| *k != 0)
            .ok_or_else(|| Error::msg("Intel layer does not have an associated kernel virtual offset, failing"))?;
        let nt = Module { sp: Space::on(self.sp.native, self.sp.table), offset: kvo };
        let r = if nt.has_type("_MM_SESSION_SPACE") {
            let s = nt.object_abs("_MM_SESSION_SPACE", session)?;
            if s.has_member("SessionId") {
                match s.m("SessionId").and_then(|x| x.int()) {
                    Ok(v) => Some(Ok(Value::Int(v))),
                    Err(e) => Some(Err(e)),
                }
            } else {
                None
            }
        } else {
            Some(nt.object_abs("unsigned long", session.wrapping_add(8)).and_then(|o| o.int()).map(Value::Int))
        };
        match r {
            Some(Ok(v)) => Ok(v),
            Some(Err(e)) if e.is_invalid_address() => Ok(Value::Unreadable),
            Some(Err(e)) => Err(e),
            None => Ok(Value::Unreadable),
        }
    }

    fn get_wow_64_process(&self) -> Result<Obj> {
        if self.has_member("Wow64Process") {
            self.m("Wow64Process")
        } else if self.has_member("WoW64Process") {
            self.m("WoW64Process")
        } else {
            Err(Error::Symbol("AttributeError: Unable to find Wow64Process".into()))
        }
    }

    fn get_is_wow64(&self) -> Result<bool> {
        match self.get_wow_64_process() {
            Ok(v) => Ok(v.int()? != 0),
            Err(_) => Ok(false),
        }
    }

    fn get_vad_root(&self) -> Result<Obj> {
        let vr = self.m("VadRoot")?;
        if vr.has_member("BalancedRoot") {
            vr.m("BalancedRoot")
        } else if vr.has_member("Root") {
            vr.m("Root")?.deref()
        } else {
            vr.deref()?.cast("_MMVAD")
        }
    }

    fn environment_variables(&self) -> Vec<(String, String)> {
        let r = (|| -> Result<Vec<(String, String)>> {
            let pl = self.add_process_layer()?;
            let pp = self.get_peb()?.m("ProcessParameters")?;
            let block = pp.m("Environment")?.u64()?;
            let size = if pp.has_member("EnvironmentSize") { pp.m("EnvironmentSize")?.u64()? } else { pp.m("Length")?.u64()? };
            let data = pl.read_vec(block, size as usize)?;
            let s = crate::objects::strings::decode(&data, StrEnc::Utf16Le, StrErrors::Replace)?;
            let mut parts: Vec<&str> = s.split('\0').collect();
            parts.pop();
            let mut out = Vec::new();
            for envar in parts {
                let (env, var) = match envar.find('=') {
                    Some(i) => (&envar[..i], &envar[i + 1..]),
                    // python: find() == -1 -> env = envar[:-1], var = envar
                    None => (&envar[..envar.char_indices().last().map(|(i, _)| i).unwrap_or(0)], envar),
                };
                if !env.is_empty() && !var.is_empty() {
                    out.push((env.to_string(), var.to_string()));
                }
            }
            Ok(out)
        })();
        r.unwrap_or_default()
    }

    fn image_file_name(&self) -> Result<String> {
        array_to_string(&self.m("ImageFileName")?, None)
    }

    fn image_file_name_str(&self) -> Result<String> {
        let a = self.m("ImageFileName")?;
        a.cast_string(a.count(), StrEnc::Utf8, StrErrors::Replace).string()
    }

    fn owning_process(&self) -> Result<Obj> {
        if self.has_member("ThreadsProcess") {
            self.m("ThreadsProcess")?.deref()?.cast("_EPROCESS")
        } else if self.has_member("Tcb") && self.m("Tcb")?.has_member("Process") {
            self.path("Tcb.Process")?.deref()?.cast("_EPROCESS")
        } else {
            Err(Error::Symbol("AttributeError: Unable to find the owning process of ethread".into()))
        }
    }

    fn get_cross_thread_flags(&self) -> Result<String> {
        const FLAGS: [&str; 9] = [
            "PS_CROSS_THREAD_FLAGS_TERMINATED",
            "PS_CROSS_THREAD_FLAGS_DEADTHREAD",
            "PS_CROSS_THREAD_FLAGS_HIDEFROMDBG",
            "PS_CROSS_THREAD_FLAGS_IMPERSONATING",
            "PS_CROSS_THREAD_FLAGS_SYSTEM",
            "PS_CROSS_THREAD_FLAGS_HARD_ERRORS_DISABLED",
            "PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION",
            "PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG",
            "PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG",
        ];
        let flags = self.m("CrossThreadFlags")?.int()?;
        let names: Vec<&str> = FLAGS.iter().enumerate().filter(|(i, _)| flags & (1 << i) != 0).map(|(_, n)| *n).collect();
        Ok(names.join(" "))
    }

    fn get_state(&self) -> Result<Value> {
        const S: [&str; 9] = ["Initialized", "Ready", "Running", "Standby", "Terminated", "Waiting", "Transition", "DeferredReady", "GateWait"];
        let v = self.m("State")?.int()?;
        Ok(if (0..9).contains(&v) { Value::SStr(S[v as usize]) } else { Value::NotApplicable })
    }

    fn get_wait_reason(&self) -> Result<Value> {
        const W: [&str; 38] = [
            "Executive", "FreePage", "PageIn", "PoolAllocation", "DelayExecution", "Suspended", "UserRequest", "WrExecutive", "WrFreePage",
            "WrPageIn", "WrPoolAllocation", "WrDelayExecution", "WrSuspended", "WrUserRequest", "WrEventPair", "WrQueue", "WrLpcReceive",
            "WrLpcReply", "WrVirtualMemory", "WrPageOut", "WrRendezvous", "Spare2", "Spare3", "Spare4", "Spare5", "Spare6", "WrKernel",
            "WrResource", "WrPushLock", "WrMutex", "WrQuantumEnd", "WrDispatchInt", "WrPreempted", "WrYieldExecution", "WrFastMutex",
            "WrGuardedMutex", "WrRundown", "MaximumWaitReason",
        ];
        let v = self.m("WaitReason")?.int()?;
        Ok(if (0..38).contains(&v) { Value::SStr(W[v as usize]) } else { Value::NotApplicable })
    }

    fn get_load_count(&self) -> Option<i128> {
        if let Ok(v) = self.m("LoadCount").and_then(|l| l.cast("short")).and_then(|s| s.int()) {
            return Some(v);
        }
        if let Ok(v) = self.m("ObsoleteLoadCount").and_then(|l| l.cast("short")).and_then(|s| s.int()) {
            return Some(v);
        }
        None
    }
}
