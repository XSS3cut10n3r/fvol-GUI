//! python `symbols/linux/extensions/__init__.py` class extensions, as the [`LinuxExt`] trait on
//! [`Obj`] (same style as `symbols::windows::WinExt`). Method names follow python; `is_valid`
//! dispatches on the struct name like python's per-class methods.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Implemented so far (what the automagic and `linux.pslist` need, plus cheap neighbours):
//!   * `list_head.to_list` ([`LinuxExt::to_list`], lazy [`ListIter`]), `hlist_head.to_list`
//!     ([`LinuxExt::hlist_to_list`]);
//!   * `task_struct`: `is_valid`, `add_process_layer`, `get_address_space_layer`,
//!     `is_kernel_thread`, `is_thread_group_leader`, `is_user_thread`, `get_threads`, `state`,
//!     `get_parent_pid`, `get_create_time`, `get_boottime`, `_get_boottime_raw`,
//!     `_get_task_start_time`, `get_time_namespace(_id)`, the time-namespace offsets;
//!   * `mm_struct.get_vma_iter` (mmap list and maple tree), `maple_tree.get_slot_iter`;
//!   * `vm_area_struct`: `is_valid`, `get_protection`, `get_flags`, `get_page_offset`;
//!   * `struct file`: `get_dentry`, `get_vfsmnt`, `get_inode`; `inode.is_valid`;
//!   * `cred`: `uid` / `gid` / `euid` / `egid` ([`LinuxExt::cred_value`]);
//!   * `timespec64` / `timespec`: [`LinuxExt::timespec`] (python `new_from_timespec`).
//!
//! Errors: where python raises, methods return `Err` (list-like results end with one `Err`);
//! where python returns None / False, they return `Ok(None)` / `Ok(false)`.

use super::timespec::{PyNum, Timespec, datetime_add_us};
use super::{PF_KTHREAD, vmlinux_of};
use crate::error::{Error, Result};
use crate::objects::{Field, LayerRef, Obj, Space};
use crate::renderers::DateTime;
use crate::symbols::Ty;
use crate::util::FxHashSet;

/// Lazy iterator over a `list_head` list (python `list_head.to_list`). Yields `Err` once
/// (then stops) where python would raise mid-iteration.
pub struct ListIter {
    state: ListState,
}

enum ListState {
    Done,
    Failed(Error),
    /// non-sentinel head: yield the head's container, then continue
    First(Obj, Box<ListState>),
    Walk { link: Obj, dir: Field, seen: FxHashSet<u64>, sym_sp: &'static Space, sym_ty: Ty, rel: u64, trans: LayerRef },
}

impl ListIter {
    /// An iterator that yields `e` once (python raised before yielding anything).
    pub fn failed(e: Error) -> ListIter {
        ListIter { state: ListState::Failed(e) }
    }
    /// An empty iterator.
    pub fn done() -> ListIter {
        ListIter { state: ListState::Done }
    }
}

/// `link_ptr = getattr(link, direction); if not (link_ptr and link_ptr.is_readable()): stop;
/// link = link_ptr.dereference()`.
#[inline]
fn follow(link: &Obj, dir: &Field) -> Result<Option<Obj>> {
    let ptr = link.f(dir);
    if ptr.u64()? == 0 || !ptr.is_readable() {
        return Ok(None);
    }
    Ok(Some(ptr.deref()?))
}

impl Iterator for ListIter {
    type Item = Result<Obj>;
    fn next(&mut self) -> Option<Result<Obj>> {
        match std::mem::replace(&mut self.state, ListState::Done) {
            ListState::Done => None,
            ListState::Failed(e) => Some(Err(e)),
            ListState::First(o, rest) => {
                self.state = *rest;
                Some(Ok(o))
            }
            ListState::Walk { link, dir, mut seen, sym_sp, sym_ty, rel, trans } => {
                if seen.contains(&link.addr) {
                    return None;
                }
                let off = link.addr.wrapping_sub(rel);
                if !trans.is_valid(off, 1) {
                    return None;
                }
                let item = Obj::new(sym_sp, sym_ty, off);
                seen.insert(link.addr);
                match follow(&link, &dir) {
                    Ok(Some(l)) => self.state = ListState::Walk { link: l, dir, seen, sym_sp, sym_ty, rel, trans },
                    Ok(None) => {}
                    // python raises when fetching the next link, after yielding `item`
                    Err(e) => self.state = ListState::Failed(e),
                }
                Some(Ok(item))
            }
        }
    }
}

/// Lazy iterator over an `hlist_head` list (python `hlist_head.to_list`): yields
/// `container_of(node)` for each readable node (`None` where python's `container_of` returns
/// None).
pub struct HListIter {
    cur: Option<Obj>,
    vmlinux: Option<crate::objects::Module>,
    symbol_type: String,
    member: String,
    failed: Option<Error>,
}

impl Iterator for HListIter {
    type Item = Result<Option<Obj>>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(e) = self.failed.take() {
            return Some(Err(e));
        }
        let cur = self.cur.take()?;
        let v = match cur.u64() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        if v == 0 || !cur.is_readable() {
            return None;
        }
        let vm = self.vmlinux?;
        let item = super::container_of(v, &self.symbol_type, &self.member, &vm);
        match cur.m("next") {
            Ok(n) => self.cur = Some(n),
            Err(e) => self.failed = Some(e),
        }
        Some(item)
    }
}

/// Linux class extensions on [`Obj`].
pub trait LinuxExt {
    // ---- list_head / hlist_head
    /// python `list_head.to_list(symbol_type, member, forward=True, sentinel=True, layer=None)`.
    /// `symbol_type` is `"task_struct"` or `"<table>!task_struct"`.
    fn to_list(&self, symbol_type: &str, member: &str, forward: bool, sentinel: bool, layer: Option<LayerRef>) -> ListIter;
    /// `to_list(symbol_type, member)` with python defaults (forward, sentinel).
    fn list_of(&self, symbol_type: &str, member: &str) -> ListIter {
        self.to_list(symbol_type, member, true, true, None)
    }
    /// python `hlist_head.to_list(symbol_type, member)`.
    fn hlist_to_list(&self, symbol_type: &str, member: &str) -> HListIter;

    // ---- dispatching
    /// python `is_valid()` of `task_struct`, `vm_area_struct` and `inode` (python exceptions ->
    /// false; use [`LinuxExt::vma_is_valid`] to keep them). Other types: `true` (not ported yet).
    fn is_valid(&self) -> bool;

    // ---- task_struct
    /// python `task_struct.add_process_layer()`: `Ok(None)` where python returns None.
    fn add_process_layer(&self) -> Result<Option<LayerRef>>;
    /// python `task_struct.get_address_space_layer()`.
    fn get_address_space_layer(&self) -> Result<Option<LayerRef>>;
    /// python `task_struct.is_kernel_thread` (`flags & PF_KTHREAD`).
    fn is_kernel_thread(&self) -> Result<bool>;
    /// python `task_struct.is_thread_group_leader` (`tgid == pid`).
    fn is_thread_group_leader(&self) -> Result<bool>;
    /// python `task_struct.is_user_thread`.
    fn is_user_thread(&self) -> Result<bool>;
    /// python `task_struct.get_threads()` (valid threads other than this task). A trailing
    /// `Err` means python would have raised at that point.
    fn get_threads(&self) -> Vec<Result<Obj>>;
    /// python `task_struct.state` (the `__state` or `state` member).
    fn state(&self) -> Result<Obj>;
    /// python `task_struct.get_parent_pid()`.
    fn get_parent_pid(&self) -> Result<i128>;
    /// python `task_struct._get_task_start_time()` (a timespec; `to_timedelta_us()` gives the
    /// python timedelta).
    fn get_task_start_time(&self) -> Result<Timespec>;
    /// python `task_struct._get_boottime_raw()`.
    fn get_boottime_raw(&self) -> Result<Timespec>;
    /// python `task_struct.get_boottime(root_time_namespace)`: `Ok(None)` where python returns
    /// an `UnparsableValue`.
    fn get_boottime(&self, root_time_namespace: bool) -> Result<Option<DateTime>>;
    /// python `task_struct.get_create_time()`. `Err` for every python exception (pslist
    /// renders those as N/A).
    fn get_create_time(&self) -> Result<DateTime>;
    /// python `task_struct.get_time_namespace()` (a `time_namespace *` pointer object), `None`
    /// on kernels without time namespaces or a NULL pointer.
    fn get_time_namespace(&self) -> Result<Option<Obj>>;
    /// python `task_struct.get_time_namespace_id()`.
    fn get_time_namespace_id(&self) -> Result<Option<i128>>;
    /// python `task_struct.get_time_namespace_monotonic_offset()` (a timespec64 object).
    fn get_time_namespace_monotonic_offset(&self) -> Result<Option<Obj>>;
    /// python `task_struct._get_time_namespace_boottime_offset()`.
    fn get_time_namespace_boottime_offset(&self) -> Result<Option<Obj>>;
    /// python `task_struct.get_process_memory_sections(heap_only)`: `(start, size)` of each
    /// valid VMA (only the heap VMA(s) with `heap_only`). `Err` where python raises.
    fn get_process_memory_sections(&self, heap_only: bool) -> Result<Vec<(u64, u64)>>;
    /// python `task_struct.is_being_ptraced` (`ptrace != 0`).
    fn is_being_ptraced(&self) -> Result<bool>;
    /// python `task_struct.is_ptracing` (the `ptraced` list is not empty).
    fn is_ptracing(&self) -> Result<bool>;
    /// python `task_struct.get_ptrace_tracer_tid()` (`parent.pid` when being traced).
    fn get_ptrace_tracer_tid(&self) -> Result<Option<i128>>;
    /// python `task_struct.get_ptrace_tracee_tids()` (pids on the `ptraced` list).
    fn get_ptrace_tracee_tids(&self) -> Result<Vec<i128>>;
    /// python `task_struct.get_ptrace_tracee_flags()` (`PT_FLAGS(ptrace).flags`, e.g.
    /// `"PT_PTRACED|PT_SEIZED"`; `Err` for bits outside PT_FLAGS like python's ValueError).
    fn get_ptrace_tracee_flags(&self) -> Result<Option<String>>;

    // ---- mm_struct / maple_tree / vm_area_struct / file
    /// python `mm_struct.get_vma_iter()`: the valid VMAs (`mmap` list on kernels < 6.1, the
    /// `mm_mt` maple tree after). A trailing `Err` means python would have raised there.
    fn get_vma_iter(&self) -> Vec<Result<Obj>>;
    /// python `maple_tree.get_slot_iter()`: every non-empty leaf slot value, in python order.
    /// A trailing `Err` means python would have raised there.
    fn get_slot_iter(&self) -> Vec<Result<u64>>;
    /// python `vm_area_struct.is_valid()` with python's exceptions kept (`Err`).
    fn vma_is_valid(&self) -> Result<bool>;
    /// python `vm_area_struct.get_protection()` (`"r-x"` style, the rwx bits of `vm_flags`).
    fn get_protection(&self) -> Result<String>;
    /// python `vm_area_struct.get_flags()` (all extended `VM_*` flag names).
    fn get_flags(&self) -> Result<String>;
    /// python `vm_area_struct.get_page_offset()`.
    fn get_page_offset(&self) -> Result<u64>;
    /// python `vm_area_struct.get_name(context, task)` (see [`super::utilities::vma_get_name`]).
    fn vma_get_name(&self, task: &Obj) -> Result<Option<String>>;
    /// python `vm_area_struct.get_malicious_pages(proclayer)`: executable (`r-x`), file-backed
    /// VMA pages that are dirty.
    fn get_malicious_pages(&self, proclayer: Option<LayerRef>) -> Result<Vec<u64>>;
    /// python `vm_area_struct.is_suspicious(proclayer)`.
    fn is_suspicious(&self, proclayer: Option<LayerRef>) -> Result<bool>;
    /// python `struct_file.get_dentry()` (a `dentry *` pointer object).
    fn get_dentry(&self) -> Result<Obj>;
    /// python `struct_file.get_vfsmnt()` (a `vfsmount *` pointer object).
    fn get_vfsmnt(&self) -> Result<Obj>;
    /// python `struct_file.get_inode()` / `dentry.get_inode()` (dispatch on the struct name;
    /// pointers are followed): the `inode` struct, `None` where python returns None.
    fn get_inode(&self) -> Result<Option<Obj>>;

    // ---- cred
    /// python `cred._get_cred_int_value(member)` (`cred.uid`, `.gid`, `.euid`, `.egid`).
    fn cred_value(&self, member: &str) -> Result<i128>;

    // ---- timespec64 / timespec
    /// python `Timespec64Abstract.new_from_timespec(self)`.
    fn timespec(&self) -> Result<Timespec>;
}

fn resolve_type(o: &Obj, symbol_type: &str) -> Result<(&'static Space, Ty)> {
    match crate::symbols::resolve_ref(o.sp.table, symbol_type) {
        Some((t, ty)) => Ok((o.sp.with_table(t), ty)),
        None => Err(Error::Symbol(format!("Unknown symbol: {symbol_type}"))),
    }
}

fn task_is_valid(t: &Obj) -> Result<bool> {
    if !t.sp.layer.is_valid(t.addr, t.size()) {
        return Ok(false);
    }
    if t.m("pid")?.int()? < 0 || t.m("tgid")?.int()? < 0 {
        return Ok(false);
    }
    // `if has_member(x) and not (x and x.is_readable())`
    for m in ["signal", "nsproxy", "real_parent"] {
        if t.has_member(m) {
            let p = t.m(m)?;
            if p.u64()? == 0 || !p.is_readable() {
                return Ok(false);
            }
        }
    }
    let active_mm = if t.has_member("active_mm") { Some(t.m("active_mm")?) } else { None };
    if let Some(am) = active_mm {
        if am.u64()? != 0 && !am.is_readable() {
            return Ok(false);
        }
    }
    let mm = t.m("mm")?;
    let mmv = mm.u64()?;
    if mmv != 0 {
        if !mm.is_readable() {
            return Ok(false);
        }
        // `self.mm != self.active_mm` (Pointer is an int: value comparison)
        let amv = t.m("active_mm")?.u64()?;
        if mmv != amv {
            return Ok(false);
        }
    }
    Ok(true)
}

impl LinuxExt for Obj {
    fn to_list(&self, symbol_type: &str, member: &str, forward: bool, sentinel: bool, layer: Option<LayerRef>) -> ListIter {
        let trans = layer.unwrap_or(self.sp.layer);
        if !trans.is_valid(self.addr, 1) {
            return ListIter::done();
        }
        let (tsp, ty) = match resolve_type(self, symbol_type) {
            Ok(x) => x,
            Err(e) => return ListIter::failed(e),
        };
        let rel = match ty {
            Ty::Struct(ut) => match tsp.table.member(ut, member) {
                Some(m) => m.offset,
                None => return ListIter::failed(Error::Symbol(format!("Member not present in template: {member}"))),
            },
            _ => return ListIter::failed(Error::Symbol(format!("{symbol_type} has no members"))),
        };
        let dir_name = if forward { "next" } else { "prev" };
        let dir = match self.struct_name().map(|n| Field::new(self.sp.table, n, dir_name)) {
            Some(Ok(f)) => f,
            Some(Err(e)) => return ListIter::failed(e),
            None => return ListIter::failed(Error::Symbol(format!("AttributeError: {} has no attribute: {dir_name}", self.type_name()))),
        };
        let link = match follow(self, &dir) {
            Ok(Some(l)) => l,
            Ok(None) => return ListIter::done(),
            Err(e) => return ListIter::failed(e),
        };
        let sym_sp = Space::get(trans, trans, tsp.table);
        let mut seen = FxHashSet::default();
        seen.insert(self.addr);
        if !sentinel {
            let off = self.addr.wrapping_sub(rel);
            if !trans.is_valid(off, 1) {
                return ListIter::done();
            }
            // yield the head's container first, then walk
            let walk = ListState::Walk { link, dir, seen, sym_sp, sym_ty: ty, rel, trans };
            return ListIter { state: ListState::First(Obj::new(sym_sp, ty, off), Box::new(walk)) };
        }
        ListIter { state: ListState::Walk { link, dir, seen, sym_sp, sym_ty: ty, rel, trans } }
    }

    fn hlist_to_list(&self, symbol_type: &str, member: &str) -> HListIter {
        let (vmlinux, cur, failed) = match vmlinux_of(self).and_then(|v| Ok((v, self.m("first")?))) {
            Ok((v, c)) => (Some(v), Some(c), None),
            Err(e) => (None, None, Some(e)),
        };
        HListIter { cur, vmlinux, symbol_type: symbol_type.to_string(), member: member.to_string(), failed }
    }

    fn is_valid(&self) -> bool {
        if self.is_pointer() {
            // python forwards `ptr.is_valid()` to the target
            return self.deref().is_ok_and(|t| t.is_valid());
        }
        match self.struct_name() {
            Some("task_struct") => task_is_valid(self).unwrap_or(false),
            Some("inode") => inode_is_valid(self).unwrap_or(false),
            Some("vm_area_struct") => self.vma_is_valid().unwrap_or(false),
            Some("vfsmount") => vfsmount_is_valid(self).unwrap_or(false),
            Some("page") => super::fs::FsExt::page_is_valid(self).unwrap_or(false),
            _ => true,
        }
    }

    fn add_process_layer(&self) -> Result<Option<LayerRef>> {
        let parent = self.sp.layer;
        let pgd = match self.m("mm").and_then(|mm| mm.deref()).and_then(|mm| mm.m("pgd")).and_then(|p| p.u64()) {
            Ok(p) => p,
            Err(e) if e.is_invalid_address() => return Ok(None),
            Err(e) => return Err(e),
        };
        let intel = parent.as_intel().ok_or_else(|| Error::msg("TypeError: Parent layer is not a translation layer, unable to construct process layer"))?;
        let Some((dtb, _)) = intel.translate_addr(pgd) else { return Ok(None) };
        let pid = self.m("pid")?.int()?;
        Ok(Some(crate::symbols::windows::ext::process_layer(parent, dtb, pid as u64)?))
    }

    fn get_address_space_layer(&self) -> Result<Option<LayerRef>> {
        if self.is_kernel_thread()? { Ok(Some(self.sp.layer)) } else { self.add_process_layer() }
    }

    fn is_kernel_thread(&self) -> Result<bool> {
        Ok(self.m("flags")?.int()? & PF_KTHREAD != 0)
    }

    fn is_thread_group_leader(&self) -> Result<bool> {
        Ok(self.m("tgid")?.int()? == self.m("pid")?.int()?)
    }

    fn is_user_thread(&self) -> Result<bool> {
        Ok(!self.is_kernel_thread()? && self.m("tgid")?.int()? != self.m("pid")?.int()?)
    }

    fn get_threads(&self) -> Vec<Result<Obj>> {
        let mut out = Vec::new();
        let iter = (|| -> Result<ListIter> {
            let vm = vmlinux_of(self)?;
            let t = vm.table();
            let sym = format!("{}!task_struct", t.name());
            let has = |ty: &str, m: &str| t.user_type(ty).is_some_and(|u| t.member(u, m).is_some());
            if has("task_struct", "signal") && has("signal_struct", "thread_head") {
                Ok(self.m("signal")?.m("thread_head")?.list_of(&sym, "thread_node"))
            } else if has("task_struct", "thread_group") {
                Ok(self.m("thread_group")?.list_of(&sym, "thread_group"))
            } else {
                Err(Error::msg("AttributeError: Unable to find the root dentry"))
            }
        })();
        let iter = match iter {
            Ok(i) => i,
            Err(e) => {
                out.push(Err(e));
                return out;
            }
        };
        let mut seen = FxHashSet::default();
        seen.insert(self.addr);
        for t in iter {
            match t {
                Ok(t) => {
                    if !t.is_valid() {
                        continue;
                    }
                    if seen.insert(t.addr) {
                        out.push(Ok(t));
                    }
                }
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            }
        }
        out
    }

    fn state(&self) -> Result<Obj> {
        if self.has_member("__state") {
            self.m("__state")
        } else if self.has_member("state") {
            self.m("state")
        } else {
            Err(Error::msg("AttributeError: Unsupported task_struct: Cannot find state"))
        }
    }

    fn get_parent_pid(&self) -> Result<i128> {
        let rp = self.m("real_parent")?;
        if rp.u64()? != 0 && rp.is_readable() { rp.m("tgid")?.int() } else { Ok(0) }
    }

    fn get_task_start_time(&self) -> Result<Timespec> {
        for name in ["start_boottime", "real_start_time", "start_time"] {
            if self.has_member(name) {
                let o = self.m(name)?;
                return match o.struct_name() {
                    Some("timespec") => o.timespec(),
                    Some(_) => Err(Error::msg("TypeError: '>' not supported between instances")),
                    None => Ok(Timespec::from_nsec(PyNum::I(o.int()?))),
                };
            }
        }
        Err(Error::msg("AttributeError: Unsupported task_struct start_time member"))
    }

    fn get_boottime_raw(&self) -> Result<Timespec> {
        let vm = vmlinux_of(self)?;
        let t = vm.table();
        if vm.has_symbol("tk_core") {
            let tk = vm.object_from_symbol("tk_core")?.m("timekeeper")?;
            let (real, boot) = (tk.m("offs_real")?, tk.m("offs_boot")?);
            let nsec = if !real.has_member("tv64") { real.int()? - boot.int()? } else { real.m("tv64")?.int()? - boot.m("tv64")?.int()? };
            return Ok(Timespec::from_nsec(PyNum::I(nsec)));
        }
        if vm.has_symbol("timekeeper") && t.user_type("timekeeper").is_some_and(|u| t.member(u, "wall_to_monotonic").is_some()) {
            let tk = vm.object_from_symbol("timekeeper")?;
            let b = tk.m("wall_to_monotonic")?.timespec()?;
            let b = b.add(&tk.m("total_sleep_time")?.timespec()?);
            return Ok(b.negate());
        }
        if vm.has_symbol("wall_to_monotonic") {
            let mut b = vm.object_from_symbol("wall_to_monotonic")?.timespec()?;
            if vm.has_symbol("total_sleep_time") {
                let tst = vm.object_from_symbol("total_sleep_time")?;
                if tst.struct_name() == Some("timespec") {
                    b = b.add(&tst.timespec()?);
                } else {
                    b.tv_sec = b.tv_sec.add(PyNum::I(tst.int()?));
                }
            }
            return Ok(b.negate());
        }
        Err(Error::msg("Unsupported"))
    }

    fn get_boottime(&self, root_time_namespace: bool) -> Result<Option<DateTime>> {
        let mut b = self.get_boottime_raw()?;
        if !root_time_namespace {
            if let Some(off) = self.get_time_namespace_boottime_offset()? {
                b = b.sub(&off.timespec()?);
            }
        }
        Ok(b.to_datetime())
    }

    fn get_create_time(&self) -> Result<DateTime> {
        let mut boottime = self.get_boottime(true)?.ok_or_else(|| Error::msg("AttributeError: 'UnparsableValue' object has no attribute 'replace'"))?;
        boottime.micros = 0;
        let us = self.get_task_start_time()?.to_timedelta_us()?;
        datetime_add_us(boottime, us)
    }

    fn get_time_namespace(&self) -> Result<Option<Obj>> {
        let vm = vmlinux_of(self)?;
        if !self.has_member("nsproxy") {
            return Ok(None);
        }
        let t = vm.table();
        if !t.user_type("nsproxy").is_some_and(|u| t.member(u, "time_ns").is_some()) {
            return Ok(None);
        }
        Ok(Some(self.m("nsproxy")?.m("time_ns")?))
    }

    fn get_time_namespace_id(&self) -> Result<Option<i128>> {
        match self.get_time_namespace()? {
            Some(ns) if ns.u64()? != 0 => Ok(Some(ns.m("ns")?.m("inum")?.int()?)),
            _ => Ok(None),
        }
    }

    fn get_time_namespace_monotonic_offset(&self) -> Result<Option<Obj>> {
        Ok(match time_ns_offsets(self)? {
            Some(o) => Some(o.m("monotonic")?),
            None => None,
        })
    }

    fn get_time_namespace_boottime_offset(&self) -> Result<Option<Obj>> {
        Ok(match time_ns_offsets(self)? {
            Some(o) => Some(o.m("boottime")?),
            None => None,
        })
    }

    fn get_process_memory_sections(&self, heap_only: bool) -> Result<Vec<(u64, u64)>> {
        let mm = self.m("mm")?;
        let mut out = Vec::new();
        for vma in mm.deref()?.get_vma_iter() {
            let vma = vma?;
            let start = vma.m("vm_start")?.u64()?;
            let end = vma.m("vm_end")?.u64()?;
            if heap_only && !(start <= mm.m("brk")?.u64()? && end >= mm.m("start_brk")?.u64()?) {
                continue;
            }
            if !heap_only {
                // python logs `self.mm.brk` / `self.mm.start_brk` here (reads them)
                mm.m("brk")?.u64()?;
                mm.m("start_brk")?.u64()?;
            }
            out.push((start, end.wrapping_sub(start)));
        }
        Ok(out)
    }

    fn is_being_ptraced(&self) -> Result<bool> {
        Ok(self.m("ptrace")?.int()? != 0)
    }

    fn is_ptracing(&self) -> Result<bool> {
        let ptraced = self.m("ptraced")?;
        let next = ptraced.m("next")?;
        Ok(next.is_readable() && next.deref()?.addr != ptraced.addr)
    }

    fn get_ptrace_tracer_tid(&self) -> Result<Option<i128>> {
        if self.is_being_ptraced()? { Ok(Some(self.m("parent")?.m("pid")?.int()?)) } else { Ok(None) }
    }

    fn get_ptrace_tracee_tids(&self) -> Result<Vec<i128>> {
        let sym = format!("{}!task_struct", self.table().name());
        let mut out = Vec::new();
        for t in self.m("ptraced")?.list_of(&sym, "ptrace_entry") {
            out.push(t?.m("pid")?.int()?);
        }
        Ok(out)
    }

    fn get_ptrace_tracee_flags(&self) -> Result<Option<String>> {
        if !self.is_being_ptraced()? {
            return Ok(None);
        }
        pt_flags(self.m("ptrace")?.int()?).map(Some)
    }

    fn get_vma_iter(&self) -> Vec<Result<Obj>> {
        let mut out = Vec::new();
        let raw = if self.has_member("mmap") {
            mmap_iter(self)
        } else if self.has_member("mm_mt") {
            maple_vma_iter(self)
        } else {
            vec![Err(Error::msg("AttributeError: Unable to find mmap or mm_mt in mm_struct"))]
        };
        for v in raw {
            match v.and_then(|vma| vma.vma_is_valid().map(|ok| (vma, ok))) {
                Ok((vma, true)) => out.push(Ok(vma)),
                Ok((_, false)) => {}
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            }
        }
        out
    }

    fn get_slot_iter(&self) -> Vec<Result<u64>> {
        let mut out = Vec::new();
        let r = (|| -> Result<()> {
            let tree_off = self.addr & !MAPLE_NODE_POINTER_MASK;
            let root = self.m("ma_root")?.u64()?;
            let mut seen = FxHashSet::default();
            parse_maple_node(self, root, tree_off, &mut seen, 1, &mut out)
        })();
        if let Err(e) = r {
            out.push(Err(e));
        }
        out
    }

    fn vma_is_valid(&self) -> Result<bool> {
        let r = (|| -> Result<(u64, u64)> {
            let s = self.m("vm_start")?.u64()?;
            let e = self.m("vm_end")?.u64()?;
            self.get_protection()?;
            Ok((s, e))
        })();
        let (start, end) = match r {
            Ok(v) => v,
            Err(e) if e.is_invalid_address() => return Ok(false),
            Err(e) => return Err(e),
        };
        let length = end.wrapping_sub(start);
        if start > end || (start == 0 && length == 0) || length % 0x1000 != 0 {
            return Ok(false);
        }
        let vm_file = self.m("vm_file")?;
        if vm_file.u64()? != 0 {
            let inode = match vm_file.deref().and_then(|f| f.get_inode()) {
                Ok(i) => i,
                Err(e) if e.is_invalid_address() => return Ok(false),
                Err(e) => return Err(e),
            };
            let inode = inode.ok_or_else(|| Error::msg("AttributeError: 'NoneType' object has no attribute 'i_size'"))?;
            let i_size = inode.m("i_size")?.int()?;
            if i_size > 0 && self.get_page_offset()? as i128 > i_size {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn get_protection(&self) -> Result<String> {
        let f = self.m("vm_flags")?.int()? & 0b1111;
        Ok([(1, 'r'), (2, 'w'), (4, 'x')].iter().map(|&(m, c)| if f & m == m { c } else { '-' }).collect())
    }

    fn get_flags(&self) -> Result<String> {
        let f = self.m("vm_flags")?.int()?;
        Ok(VM_FLAG_NAMES.iter().enumerate().map(|(i, n)| if f & (1 << i) != 0 { *n } else { "-" }).collect())
    }

    fn get_page_offset(&self) -> Result<u64> {
        if self.m("vm_file")?.u64()? == 0 {
            return Ok(0);
        }
        Ok(self.m("vm_pgoff")?.u64()?.wrapping_shl(12))
    }

    fn vma_get_name(&self, task: &Obj) -> Result<Option<String>> {
        super::utilities::vma_get_name(self, task)
    }

    fn get_malicious_pages(&self, proclayer: Option<LayerRef>) -> Result<Vec<u64>> {
        let mut out = Vec::new();
        let flags = self.get_protection()?;
        let Some(pl) = proclayer else { return Ok(out) };
        if !flags.contains("r-x") || self.m("vm_file")?.deref()?.addr == 0 {
            return Ok(out);
        }
        let start = self.m("vm_start")?.u64()?;
        let end = self.m("vm_end")?.u64()?;
        let intel = pl.as_intel();
        let mut a = start;
        while a < end {
            match intel.map(|i| i.is_dirty(a)) {
                Some(Ok(true)) => out.push(a),
                Some(Ok(false)) => {}
                // python: abort on the first translation failure (or a layer without is_dirty)
                _ => break,
            }
            a = match a.checked_add(0x1000) {
                Some(n) => n,
                None => break,
            };
        }
        Ok(out)
    }

    fn is_suspicious(&self, proclayer: Option<LayerRef>) -> Result<bool> {
        let flags = self.get_protection()?;
        if flags == "rwx" {
            return Ok(true);
        }
        if flags == "r-x" && self.m("vm_file")?.deref()?.addr == 0 {
            return Ok(true);
        }
        let Some(pl) = proclayer else { return Ok(false) };
        if !flags.contains('x') {
            return Ok(false);
        }
        let start = self.m("vm_start")?.u64()?;
        let end = self.m("vm_end")?.u64()?;
        let Some(intel) = pl.as_intel() else { return Err(Error::msg("AttributeError: layer has no attribute 'is_dirty'")) };
        let mut a = start;
        while a < end {
            match intel.is_dirty(a) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(e) if e.is_invalid_address() => return Ok(false),
                Err(e) => return Err(e),
            }
            a = match a.checked_add(0x1000) {
                Some(n) => n,
                None => break,
            };
        }
        Ok(false)
    }

    fn get_dentry(&self) -> Result<Obj> {
        if self.has_member("f_path") { self.m("f_path")?.m("dentry") } else { Err(Error::msg("AttributeError: Unable to find file -> dentry")) }
    }

    fn get_vfsmnt(&self) -> Result<Obj> {
        if self.has_member("f_path") { self.m("f_path")?.m("mnt") } else { Err(Error::msg("AttributeError: Unable to find file -> vfs mount")) }
    }

    fn get_inode(&self) -> Result<Option<Obj>> {
        if self.is_pointer() {
            return self.deref()?.get_inode();
        }
        if self.struct_name() == Some("dentry") {
            // python `dentry.get_inode()`
            let p = self.m("d_inode")?;
            if !(p.u64()? != 0 && p.is_readable() && inode_is_valid(&p.deref()?)?) {
                return Ok(None);
            }
            return Ok(Some(p.deref()?));
        }
        // `inode_ptr and inode_ptr.is_readable() and inode_ptr.is_valid()`
        let usable = |p: &Obj| -> Result<bool> { Ok(p.u64()? != 0 && p.is_readable() && inode_is_valid(&p.deref()?)?) };
        let mut inode_ptr = None;
        if self.has_member("f_inode") {
            let p = self.m("f_inode")?;
            if p.u64()? != 0 && p.is_readable() {
                inode_ptr = Some(p);
            }
        }
        let ok = match &inode_ptr {
            Some(p) => usable(p)?,
            None => false,
        };
        let p = if ok {
            inode_ptr.unwrap()
        } else {
            let d = self.get_dentry()?;
            if !(d.u64()? != 0 && d.is_readable()) {
                return Ok(None);
            }
            let p = d.m("d_inode")?;
            if !usable(&p)? {
                return Ok(None);
            }
            p
        };
        Ok(Some(p.deref()?))
    }

    fn cred_value(&self, member: &str) -> Result<i128> {
        if !self.has_member(member) {
            return Err(Error::msg(format!("AttributeError: struct cred doesn't have a '{member}' member")));
        }
        let v = self.m(member)?;
        if v.has_member("val") {
            v.m("val")?.int()
        } else if matches!(v.ty, Ty::Int(_)) {
            v.int()
        } else {
            Err(Error::msg("AttributeError: Kernel struct cred is not supported"))
        }
    }

    fn timespec(&self) -> Result<Timespec> {
        Ok(Timespec::from_ints(self.m("tv_sec")?.int()?, self.m("tv_nsec")?.int()?))
    }
}

/// python `linux_constants.PT_FLAGS` members in definition order (python's `enum.Flag` lists a
/// composite value's names in definition order).
pub const PT_FLAGS: [(i128, &str); 12] = [
    (0x00001, "PT_PTRACED"),
    (0x10000, "PT_SEIZED"),
    (1 << 3, "PT_TRACESYSGOOD"),
    (1 << (3 + 1), "PT_TRACE_FORK"),
    (1 << (3 + 2), "PT_TRACE_VFORK"),
    (1 << (3 + 3), "PT_TRACE_CLONE"),
    (1 << (3 + 4), "PT_TRACE_EXEC"),
    (1 << (3 + 5), "PT_TRACE_VFORK_DONE"),
    (1 << (3 + 6), "PT_TRACE_EXIT"),
    (1 << (3 + 7), "PT_TRACE_SECCOMP"),
    ((1 << 20) << 3, "PT_EXITKILL"),
    ((1 << 21) << 3, "PT_SUSPEND_SECCOMP"),
];

/// python `PT_FLAGS(value).flags` (`enum.Flag` with STRICT boundary: unknown bits raise
/// ValueError).
pub fn pt_flags(value: i128) -> Result<String> {
    let all: i128 = PT_FLAGS.iter().map(|f| f.0).fold(0, |a, b| a | b);
    if value & !all != 0 || value < 0 {
        return Err(Error::msg(format!("ValueError: <flag 'PT_FLAGS'> invalid value {value}")));
    }
    if value == 0 {
        return Ok("PT_FLAGS(0)".into());
    }
    Ok(PT_FLAGS.iter().filter(|f| value & f.0 != 0).map(|f| f.1).collect::<Vec<_>>().join("|"))
}

/// python `vfsmount.is_valid()`.
fn vfsmount_is_valid(v: &Obj) -> Result<bool> {
    use super::fs::FsExt;
    Ok(v.get_mnt_sb()?.u64()? != 0 && v.get_mnt_root()?.u64()? != 0 && v.get_mnt_parent()?.u64()? != 0)
}

/// python `inode.is_valid()` (exceptions kept).
fn inode_is_valid(i: &Obj) -> Result<bool> {
    Ok(i.m("i_ino")?.int()? > 0 && i.path("i_count.counter")?.int()? >= 0)
}

/// python `vm_area_struct.extended_flags` names by bit (insertion order = bit order).
const VM_FLAG_NAMES: [&str; 32] = [
    "VM_READ",
    "VM_WRITE",
    "VM_EXEC",
    "VM_SHARED",
    "VM_MAYREAD",
    "VM_MAYWRITE",
    "VM_MAYEXEC",
    "VM_MAYSHARE",
    "VM_GROWSDOWN",
    "VM_NOHUGEPAGE",
    "VM_PFNMAP",
    "VM_DENYWRITE",
    "VM_EXECUTABLE",
    "VM_LOCKED",
    "VM_IO",
    "VM_SEQ_READ",
    "VM_RAND_READ",
    "VM_DONTCOPY",
    "VM_DONTEXPAND",
    "VM_RESERVED",
    "VM_ACCOUNT",
    "VM_NORESERVE",
    "VM_HUGETLB",
    "VM_NONLINEAR",
    "VM_MAPPED_COP__VM_HUGEPAGE",
    "VM_INSERTPAGE",
    "VM_ALWAYSDUMP",
    "VM_CAN_NONLINEAR",
    "VM_MIXEDMAP",
    "VM_SAO",
    "VM_PFN_AT_MMAP",
    "VM_MERGEABLE",
];

/// python `mm_struct._get_mmap_iter()` (unfiltered).
fn mmap_iter(mm: &Obj) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let mut p = mm.m("mmap")?;
        let v = p.u64()?;
        if v == 0 || !p.is_readable() {
            return Ok(());
        }
        out.push(Ok(p.deref()?));
        let mut seen = FxHashSet::default();
        seen.insert(v);
        p = p.m("vm_next")?;
        loop {
            let v = p.u64()?;
            if v == 0 || !p.is_readable() || seen.contains(&v) {
                return Ok(());
            }
            out.push(Ok(p.deref()?));
            seen.insert(v);
            p = p.m("vm_next")?;
        }
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

/// python `mm_struct._get_maple_tree_iter()` (unfiltered).
fn maple_vma_iter(mm: &Obj) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    let tree = match mm.m("mm_mt") {
        Ok(t) => t,
        Err(e) => return vec![Err(e)],
    };
    // slots are `void *` values read on the tree's layer: dereference onto its native layer
    let sp = tree.sp.native_space();
    for slot in tree.get_slot_iter() {
        match slot.and_then(|s| Obj::named(sp, "vm_area_struct", s)) {
            Ok(vma) => {
                if vma.addr >= 0x1000 {
                    out.push(Ok(vma));
                }
            }
            Err(e) => {
                out.push(Err(e));
                break;
            }
        }
    }
    out
}

const MAPLE_NODE_POINTER_MASK: u64 = 0xFF;

/// python `maple_tree._parse_maple_tree_node` (recursive, python order).
fn parse_maple_node(tree: &Obj, entry: u64, parent: u64, seen: &mut FxHashSet<u64>, depth: u32, out: &mut Vec<Result<u64>>) -> Result<()> {
    if !seen.insert(entry) {
        return Ok(());
    }
    if depth > 900 {
        return Err(Error::msg("RecursionError: maximum recursion depth exceeded"));
    }
    let pointer = entry & !MAPLE_NODE_POINTER_MASK;
    let node_type = (entry >> 3) & 0x0F;
    // the node's parent pointer, read on the tree's native layer
    let parent_mte = Obj::named(tree.sp.native_space(), "pointer", pointer)?.u64()?;
    if parent_mte & !MAPLE_NODE_POINTER_MASK != parent {
        return Ok(());
    }
    let node = Obj::named(Space::on(tree.sp.layer, tree.sp.table), "maple_node", pointer)?;
    let (member, recurse) = match node_type {
        0 => ("alloc", false),
        1 => ("mr64", false),
        2 => ("mr64", true),
        3 => ("ma64", true),
        t => return Err(Error::msg(format!("AttributeError: Unknown Maple Tree node type {t} at offset {pointer:#x}."))),
    };
    let slots = node.m(member)?.m("slot")?;
    for i in 0..slots.count() {
        let v = slots.at(i)?.u64()?;
        if v & !0x0F == 0 {
            continue;
        }
        if recurse {
            parse_maple_node(tree, v, pointer, seen, depth + 1, out)?;
        } else {
            out.push(Ok(v));
        }
    }
    Ok(())
}

/// python `task_struct._get_time_namespace_offsets()`.
fn time_ns_offsets(t: &Obj) -> Result<Option<Obj>> {
    let Some(ns) = t.get_time_namespace()? else { return Ok(None) };
    if ns.u64()? == 0 || !ns.has_member("offsets") {
        return Ok(None);
    }
    Ok(Some(ns.m("offsets")?))
}
