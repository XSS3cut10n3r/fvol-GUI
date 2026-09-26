//! python `symbols/linux/extensions/__init__.py` class extensions, as the [`LinuxExt`] trait on
//! [`Obj`] (same style as `symbols::windows::WinExt`). Method names follow python; `is_valid`
//! dispatches on the struct name like python's per-class methods.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Implemented so far (what the automagic and `linux.pslist` need, plus cheap neighbours):
//!   * `list_head.to_list` ([`LinuxExt::to_list`], lazy [`ListIter`]), `hlist_head.to_list`
//!     ([`LinuxExt::hlist_to_list`]);
//!   * `task_struct`: `is_valid`, `add_process_layer`, `is_kernel_thread`,
//!     `is_thread_group_leader`, `is_user_thread`, `get_threads`, `state`, `get_parent_pid`,
//!     `get_create_time`, `get_boottime`, `get_time_namespace(_id)`, the time-namespace offsets;
//!   * `cred`: `uid` / `gid` / `euid` / `egid` ([`LinuxExt::cred_value`]);
//!   * `timespec64` / `timespec`: [`LinuxExt::timespec`] (python `new_from_timespec`);
//!   * `inode.is_valid`.

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
    fn failed(e: Error) -> ListIter {
        ListIter { state: ListState::Failed(e) }
    }
    fn done() -> ListIter {
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
    /// python `is_valid()` of `task_struct` and `inode`. Other types: `true` (not ported yet).
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
        let vmlinux = vmlinux_of(self).ok();
        let (cur, failed) = match self.m("first") {
            Ok(c) => (Some(c), None),
            Err(e) => (None, Some(e)),
        };
        HListIter { cur, vmlinux, symbol_type: symbol_type.to_string(), member: member.to_string(), failed }
    }

    fn is_valid(&self) -> bool {
        match self.struct_name() {
            Some("task_struct") => task_is_valid(self).unwrap_or(false),
            Some("inode") => (|| -> Result<bool> { Ok(self.m("i_ino")?.int()? > 0 && self.path("i_count.counter")?.int()? >= 0) })().unwrap_or(false),
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

/// python `task_struct._get_time_namespace_offsets()`.
fn time_ns_offsets(t: &Obj) -> Result<Option<Obj>> {
    let Some(ns) = t.get_time_namespace()? else { return Ok(None) };
    if ns.u64()? == 0 || !ns.has_member("offsets") {
        return Ok(None);
    }
    Ok(Some(ns.m("offsets")?))
}
