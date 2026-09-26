//! Mac helpers: python `symbols/mac/__init__.py` (`MacUtilities` list walkers) and
//! `symbols/mac/extensions/__init__.py` class extensions as the [`MacExt`] trait on [`Obj`],
//! plus the address helpers the Mac automagic uses.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! use crate::symbols::mac::MacExt;
//! let k = ctx.mac_kernel()?;
//! let head = k.object_from_symbol("tasks")?;
//! for task in head.walk_list(&head, "tasks", "task", 4096) { let task = task?; ... }
//! for p in hash_bucket.walk_list_head("p_hash", 4096) { let p = p?; /* a `proc *` */ }
//! ```
//!
//! Semantics follow python exactly, including where python reads memory: constructing a
//! pointer member reads its value (so that is where `InvalidAddressException` is raised and
//! suppressed), constructing a struct member reads nothing. List walkers return
//! `Vec<Result<Obj>>`; a trailing `Err` means python would have raised at that point (after
//! yielding the `Ok` items), e.g. an `AttributeError` for a wrong member name.

use crate::error::{Error, Result};
use crate::objects::{LayerRef, Obj};
use crate::renderers::DateTime;
use crate::util::FxHashSet;

/// python `MacIntelStacker.virtual_to_physical_address` (ignores KASLR), on u64 with
/// two's-complement wrap-around (python ints would go negative; the low 64 bits agree).
pub fn virtual_to_physical_address(addr: u64) -> u64 {
    if addr > 0xFFFF_FF80_0000_0000 { addr.wrapping_sub(0xFFFF_FF80_0000_0000) } else { addr.wrapping_sub(0xFF80_0000_0000) }
}

/// [`virtual_to_physical_address`] with python's unbounded-int arithmetic.
pub fn v2p(addr: i128) -> i128 {
    if addr > 0xFFFF_FF80_0000_0000 { addr - 0xFFFF_FF80_0000_0000 } else { addr - 0xFF80_0000_0000 }
}

/// Default `max_elements` / `max_size` of the python walkers.
pub const MAX_ELEMENTS: usize = 4096;

/// A pointer member's value, read where python constructs the `Pointer` object.
#[inline]
fn ptr_value(p: &Obj) -> Result<u64> {
    p.u64()
}

/// python `ptr.dereference().cast(type_name)` for a pointer whose value `v` was already read.
#[inline]
fn deref_cast(ptr: &Obj, v: u64, type_name: &str) -> Result<Obj> {
    Obj::named(ptr.sp.native_space(), type_name, v)
}

/// python `MacUtilities._walk_iterable(queue, list_head_member, list_next_member, next_member,
/// max_elements)`: yields the POINTER objects (python yields `current`, a pointer; member
/// access on it dereferences, `vol.offset` is where the pointer lives).
pub fn walk_iterable(queue: &Obj, list_head_member: &str, list_next_member: &str, next_member: &str, max_elements: usize) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    let mut seen: FxHashSet<u64> = FxHashSet::default();
    let mut current = match queue.m(list_head_member) {
        Ok(c) => c,
        Err(e) => {
            if !e.is_invalid_address() {
                out.push(Err(e));
            }
            return out;
        }
    };
    // python reads the pointer value when constructing it
    let mut value = match ptr_value(&current) {
        Ok(v) => v,
        Err(e) => {
            if !e.is_invalid_address() {
                out.push(Err(e));
            }
            return out;
        }
    };
    while value != 0 {
        if !seen.insert(current.addr) {
            break;
        }
        if seen.len() == max_elements {
            break;
        }
        if current.is_readable() {
            out.push(Ok(current));
        }
        let next = current.m(next_member).and_then(|n| n.m(list_next_member)).and_then(|n| ptr_value(&n).map(|v| (n, v)));
        match next {
            Ok((n, v)) => {
                current = n;
                value = v;
            }
            Err(e) => {
                if !e.is_invalid_address() {
                    out.push(Err(e));
                }
                break;
            }
        }
    }
    out
}

/// python `mac.MacUtilities.mask_mods_list` element: `(name, start, end)`.
pub type HandlerInfo = (String, u64, u64);

/// Mac class extensions on [`Obj`].
pub trait MacExt {
    // ---- queue_entry
    /// python `queue_entry.walk_list(list_head, member_name, type_name, max_size=4096)`:
    /// walks `next` then `prev`, each element cast to `type_name` (a type of this object's
    /// table), skipping duplicates, stopping at `list_head`.
    fn walk_list(&self, list_head: &Obj, member_name: &str, type_name: &str, max_size: usize) -> Vec<Result<Obj>>;

    // ---- MacUtilities walkers (this object is the queue / list head)
    /// python `MacUtilities.walk_tailq(queue, next_member, max_elements=4096)`.
    fn walk_tailq(&self, next_member: &str, max_elements: usize) -> Vec<Result<Obj>>;
    /// python `MacUtilities.walk_list_head(queue, next_member, max_elements=4096)`.
    fn walk_list_head(&self, next_member: &str, max_elements: usize) -> Vec<Result<Obj>>;
    /// python `MacUtilities.walk_slist(queue, next_member, max_elements=4096)`.
    fn walk_slist(&self, next_member: &str, max_elements: usize) -> Vec<Result<Obj>>;

    // ---- proc
    /// python `proc.get_task()`: `self.task.dereference().cast("task")`.
    fn get_task(&self) -> Result<Obj>;
    /// python `proc.add_process_layer()`: the process address space (DTB =
    /// `task.map.pmap.pm_cr3`), `None` when the DTB cannot be read.
    fn add_process_layer(&self) -> Result<Option<LayerRef>>;
    /// python `proc.get_map_iter()`: the task's `vm_map_entry` pointers. A trailing `Err`
    /// means python would have raised there.
    fn get_map_iter(&self) -> Vec<Result<Obj>>;

    // ---- fileglob
    /// python `fileglob.get_fg_type()`: `"VNODE"`, `"SOCKET"`, ... or None.
    fn get_fg_type(&self) -> Result<Option<String>>;

    // ---- vm_map_object
    /// python `vm_map_object.get_map_object()`.
    fn get_map_object(&self) -> Result<Obj>;

    // ---- vm_map_entry
    /// python `vm_map_entry.get_perms()` / `sysctl_oid.get_perms()` (dispatch on the type).
    fn get_perms(&self) -> Result<String>;
    /// python `vm_map_entry.get_range_alias()`.
    fn get_range_alias(&self) -> Result<i128>;
    /// python `vm_map_entry.get_special_path()`.
    fn get_special_path(&self) -> Result<&'static str>;
    /// python `vm_map_entry.get_object()`.
    fn get_object(&self) -> Result<Obj>;
    /// python `vm_map_entry.get_offset()`.
    fn get_offset(&self) -> Result<Obj>;

    // ---- sysctl_oid
    /// python `sysctl_oid.get_ctltype()`.
    fn get_ctltype(&self) -> Result<&'static str>;

    // ---- vnode
    /// python `vnode.full_path()`.
    fn full_path(&self) -> Result<String>;
}

fn attr_error(what: &str) -> Error {
    Error::Symbol(format!("AttributeError: {what}"))
}

impl MacExt for Obj {
    fn walk_list(&self, list_head: &Obj, member_name: &str, type_name: &str, max_size: usize) -> Vec<Result<Obj>> {
        let mut out = Vec::new();
        let mut yielded = 0usize;
        let mut seen: FxHashSet<u64> = FxHashSet::default();
        for attr in ["next", "prev"] {
            // with contextlib.suppress(InvalidAddressException)
            let r = (|| -> Result<bool> {
                let p = self.m(attr)?;
                let v = ptr_value(&p)?;
                let mut elem = deref_cast(&p, v, type_name)?;
                while elem.addr != list_head.addr {
                    if !seen.insert(elem.addr) {
                        break;
                    }
                    out.push(Ok(elem));
                    yielded += 1;
                    if yielded == max_size {
                        return Ok(true);
                    }
                    let p = elem.m(member_name)?.m(attr)?;
                    let v = ptr_value(&p)?;
                    elem = deref_cast(&p, v, type_name)?;
                }
                Ok(false)
            })();
            match r {
                Ok(true) => return out,
                Ok(false) => {}
                Err(e) if e.is_invalid_address() => {}
                Err(e) => {
                    out.push(Err(e));
                    return out;
                }
            }
        }
        out
    }

    fn walk_tailq(&self, next_member: &str, max_elements: usize) -> Vec<Result<Obj>> {
        walk_iterable(self, "tqh_first", "tqe_next", next_member, max_elements)
    }

    fn walk_list_head(&self, next_member: &str, max_elements: usize) -> Vec<Result<Obj>> {
        walk_iterable(self, "lh_first", "le_next", next_member, max_elements)
    }

    fn walk_slist(&self, next_member: &str, max_elements: usize) -> Vec<Result<Obj>> {
        walk_iterable(self, "slh_first", "sle_next", next_member, max_elements)
    }

    fn get_task(&self) -> Result<Obj> {
        let p = self.m("task")?;
        let v = ptr_value(&p)?;
        deref_cast(&p, v, "task")
    }

    fn add_process_layer(&self) -> Result<Option<LayerRef>> {
        let parent = self.layer();
        if parent.as_intel().is_none() {
            return Err(Error::msg("Parent layer is not a translation layer, unable to construct process layer"));
        }
        let dtb = match self.get_task().and_then(|t| t.m("map")).and_then(|m| m.m("pmap")).and_then(|p| p.m("pm_cr3")).and_then(|c| c.u64()) {
            Ok(d) => d,
            Err(e) if e.is_invalid_address() => return Ok(None),
            Err(e) => return Err(e),
        };
        let pid = self.m("p_pid")?.int()?;
        crate::symbols::windows::process_layer(parent, dtb, pid as u64).map(Some)
    }

    fn get_map_iter(&self) -> Vec<Result<Obj>> {
        let mut out = Vec::new();
        let start = (|| -> Result<(Obj, Obj, u64)> {
            let task = self.get_task()?;
            let links_next = task.m("map")?.m("hdr")?.m("links")?.m("next")?;
            let v = ptr_value(&links_next)?;
            Ok((task, links_next, v))
        })();
        let (task, mut current, mut value) = match start {
            Ok(s) => s,
            Err(e) if e.is_invalid_address() => return out,
            Err(e) => {
                out.push(Err(e));
                return out;
            }
        };
        let nentries = match task.m("map").and_then(|m| m.m("hdr")).and_then(|h| h.m("nentries")).and_then(|n| n.int()) {
            Ok(n) => n,
            Err(e) => {
                out.push(Err(e));
                return out;
            }
        };
        let native = task.native();
        let mut seen: FxHashSet<u64> = FxHashSet::default();
        let mut i: i128 = 0;
        while i < nentries {
            i += 1;
            // the break conditions (errors propagate like python)
            let ok = (|| -> Result<bool> {
                if value == 0 || seen.contains(&current.addr) {
                    return Ok(false);
                }
                let target = current.deref()?;
                if !native.is_valid(target.addr, target.size()) {
                    return Ok(false);
                }
                let links = current.m("links")?;
                Ok(links.m("start")?.u64()? != 0xDEAD_BEEF_DEAD_BEEF && links.m("end")?.u64()? != 0xDEAD_BEEF_DEAD_BEEF)
            })();
            match ok {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            }
            out.push(Ok(current));
            seen.insert(current.addr);
            match current.m("links").and_then(|l| l.m("next")).and_then(|n| ptr_value(&n).map(|v| (n, v))) {
                Ok((n, v)) => {
                    current = n;
                    value = v;
                }
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            }
        }
        out
    }

    fn get_fg_type(&self) -> Result<Option<String>> {
        let ret = if self.has_member("fg_type") {
            Some(self.m("fg_type")?)
        } else if self.m("fg_ops")?.u64()? != 0 {
            match self.m("fg_ops").and_then(|o| o.m("fo_type")) {
                Ok(t) => match t.int() {
                    Ok(_) => Some(t),
                    Err(e) if e.is_invalid_address() => None,
                    Err(e) => return Err(e),
                },
                Err(e) if e.is_invalid_address() => None,
                Err(e) => return Err(e),
            }
        } else {
            None
        };
        match ret {
            Some(t) if t.int()? != 0 => Ok(Some(t.description()?.replace("DTYPE_", ""))),
            _ => Ok(None),
        }
    }

    fn get_map_object(&self) -> Result<Obj> {
        if self.has_member("vm_object") {
            return self.m("vm_object");
        }
        if self.has_member("vmo_object") {
            return self.m("vmo_object");
        }
        Err(attr_error("vm_map_object -> get_object"))
    }

    fn get_perms(&self) -> Result<String> {
        if self.struct_name() == Some("sysctl_oid") {
            let kind = self.m("oid_kind")?.int()?;
            let mut ret = String::with_capacity(3);
            for (c, p) in [(0x8000_0000i128, 'R'), (0x4000_0000, 'W'), (0x0080_0000, 'L')] {
                ret.push(if c & kind != 0 { p } else { '-' });
            }
            return Ok(ret);
        }
        let prot = self.m("protection")?.int()?;
        let mut perms = String::with_capacity(3);
        for (ctr, i) in [1i128, 3, 5].into_iter().enumerate() {
            perms.push(if prot & i == i { b"rwx"[ctr] as char } else { '-' });
        }
        Ok(perms)
    }

    fn get_range_alias(&self) -> Result<i128> {
        if self.has_member("alias") { self.m("alias")?.int() } else { Ok(self.m("vme_offset")?.int()? & 0xFFF) }
    }

    fn get_special_path(&self) -> Result<&'static str> {
        let check = self.get_range_alias()?;
        Ok(if 0 < check && check < 10 {
            "[heap]"
        } else if check == 30 {
            "[stack]"
        } else {
            ""
        })
    }

    fn get_object(&self) -> Result<Obj> {
        if self.has_member("vme_object") {
            return self.m("vme_object");
        }
        if self.has_member("object") {
            return self.m("object");
        }
        Err(attr_error("vm_map_entry -> get_object: Unable to determine object"))
    }

    fn get_offset(&self) -> Result<Obj> {
        if self.has_member("vme_offset") {
            return self.m("vme_offset");
        }
        if self.has_member("offset") {
            return self.m("offset");
        }
        Err(attr_error("vm_map_entry -> get_offset: Unable to determine offset"))
    }

    fn get_ctltype(&self) -> Result<&'static str> {
        let t = self.m("oid_kind")?.int()? & 0xF;
        Ok(match t {
            1 => "CTLTYPE_NODE",
            2 => "CTLTYPE_INT",
            3 => "CTLTYPE_STRING",
            4 => "CTLTYPE_QUAD",
            5 => "CTLTYPE_OPAQUE",
            _ => "",
        })
    }

    fn full_path(&self) -> Result<String> {
        let v_flag = self.m("v_flag")?.int()?;
        let v_mount = self.m("v_mount")?;
        if v_flag & 1 != 0 && v_mount.u64()? != 0 && v_mount.m("mnt_flag")?.int()? & 0x4000 != 0 {
            return Ok("/".to_string());
        }
        let mut elements: Vec<String> = Vec::new();
        do_calc_path(&mut elements, Some(*self), Some(self.m("v_name")?))?;
        elements.reverse();
        let joined = elements.join("/");
        Ok(if joined.is_empty() { joined } else { format!("/{joined}") })
    }
}

/// python `vnode._do_calc_path(ret, vnodeobj, vname)` (recursive in python; iterative here
/// with the same visiting order and error behaviour).
fn do_calc_path(ret: &mut Vec<String>, vnodeobj: Option<Obj>, vname: Option<Obj>) -> Result<()> {
    let (mut node, mut name) = (vnodeobj, vname);
    // python recursion depth limit (~1000 frames) would raise RecursionError on a cycle; bound it
    for _ in 0..1000 {
        let Some(vn) = node else { return Ok(()) };
        if let Some(n) = name {
            if n.u64()? != 0 {
                match crate::objects::util::pointer_to_string(&n, 255) {
                    Ok(s) => ret.push(s),
                    Err(e) if e.is_invalid_address() => return Ok(()),
                    Err(e) => return Err(e),
                }
            }
        }
        let v_flag = vn.m("v_flag")?.int()?;
        let v_mount = vn.m("v_mount")?;
        if v_flag & 1 != 0 && v_mount.u64()? != 0 {
            let covered = v_mount.m("mnt_vnodecovered")?;
            if covered.u64()? != 0 {
                let cname = covered.m("v_name")?;
                node = Some(covered);
                name = Some(cname);
                continue;
            }
            return Ok(());
        }
        let parent = match vn.m("v_parent").and_then(|p| p.u64().map(|_| p)) {
            Ok(p) => p,
            Err(e) if e.is_invalid_address() => return Ok(()),
            Err(e) => return Err(e),
        };
        let pname = match parent.m("v_name").and_then(|n| n.u64().map(|_| n)) {
            Ok(n) => n,
            Err(e) if e.is_invalid_address() => return Ok(()),
            Err(e) => return Err(e),
        };
        node = Some(parent);
        name = Some(pname);
    }
    Err(Error::msg("RecursionError: maximum recursion depth exceeded"))
}

// ---------------------------------------------------------------------------------------------
// python `datetime.datetime.fromtimestamp(t)` (naive, local time zone)
// ---------------------------------------------------------------------------------------------

#[repr(C)]
struct Tm {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,
    tm_yday: i32,
    tm_isdst: i32,
    tm_gmtoff: i64,
    tm_zone: *const u8,
}

unsafe extern "C" {
    fn localtime_r(t: *const i64, out: *mut Tm) -> *mut Tm;
    fn tzset();
}

/// python `_PyTime_ObjectToTimeval(t, ROUND_HALF_EVEN)`: (seconds, microseconds).
/// `Err` = the python exception text.
pub fn float_to_timeval(t: f64) -> std::result::Result<(i64, u32), String> {
    if t.is_nan() {
        return Err("ValueError: Invalid value NaN (not a number)".into());
    }
    let mut intpart = t.trunc();
    let x = (t - intpart) * 1e6;
    let mut rounded = x.round();
    if (x - rounded).abs() == 0.5 {
        rounded = 2.0 * (x / 2.0).round();
    }
    let mut floatpart = rounded;
    if floatpart >= 1e6 {
        floatpart -= 1e6;
        intpart += 1.0;
    } else if floatpart < 0.0 {
        floatpart += 1e6;
        intpart -= 1.0;
    }
    if !(intpart >= -9.223_372_036_854_775_808e18 && intpart < 9.223_372_036_854_775_808e18) {
        return Err("OverflowError: timestamp out of range for platform time_t".into());
    }
    Ok((intpart as i64, floatpart as u32))
}

/// python `datetime.datetime.fromtimestamp(t)` without a tz: a NAIVE datetime in the process'
/// local time zone (libc `localtime_r`, like CPython). The returned [`DateTime`] holds the
/// local wall-clock time in `secs` (render-only; `utc = false`).
///
/// `Err` is the text of the python exception (`ValueError` for years outside 1..9999, ...),
/// which is NOT a volatility exception: python plugins crash with a traceback there (the
/// rsvol CLI's equivalent is a plugin panic, see `plugins::mac::pslist`).
pub fn fromtimestamp_local(t: f64) -> std::result::Result<DateTime, String> {
    static TZ: std::sync::Once = std::sync::Once::new();
    TZ.call_once(|| unsafe { tzset() });
    let (secs, us) = float_to_timeval(t)?;
    let mut tm = std::mem::MaybeUninit::<Tm>::zeroed();
    let r = unsafe { localtime_r(&secs, tm.as_mut_ptr()) };
    if r.is_null() {
        return Err("OSError: [Errno 75] Value too large for defined data type".into());
    }
    let tm = unsafe { tm.assume_init() };
    let year = tm.tm_year as i64 + 1900;
    if !(1..=9999).contains(&year) {
        return Err(format!("ValueError: year must be in 1..9999, not {year}"));
    }
    let days = crate::util::time::days_from_civil(year, tm.tm_mon as u32 + 1, tm.tm_mday as u32);
    // CPython clamps leap seconds to 59
    let sec = tm.tm_sec.min(59) as i64;
    let local = days * 86_400 + tm.tm_hour as i64 * 3600 + tm.tm_min as i64 * 60 + sec;
    Ok(DateTime { secs: local, micros: us, utc: false })
}

/// python `int(b)` for a bytes object (ASCII whitespace around, optional sign, digits with
/// single underscores between them). `None` = python raises `ValueError`. Values that do not
/// fit an i128 saturate (they can never compare equal to anything we read).
pub fn py_int_bytes(b: &[u8]) -> Option<i128> {
    let is_ws = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c | 0x1c..=0x1f);
    let start = b.iter().position(|c| !is_ws(c))?;
    let end = b.iter().rposition(|c| !is_ws(c))? + 1;
    let mut s = &b[start..end];
    let neg = match s.first() {
        Some(b'-') => {
            s = &s[1..];
            true
        }
        Some(b'+') => {
            s = &s[1..];
            false
        }
        _ => false,
    };
    if s.is_empty() || !s[0].is_ascii_digit() || !s[s.len() - 1].is_ascii_digit() {
        return None;
    }
    let mut v: i128 = 0;
    let mut prev_us = false;
    for &c in s {
        if c == b'_' {
            if prev_us {
                return None;
            }
            prev_us = true;
            continue;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        prev_us = false;
        v = v.saturating_mul(10).saturating_add((c - b'0') as i128);
    }
    Some(if neg { -v } else { v })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2p_matches_python() {
        assert_eq!(v2p(0xFFFF_FF80_0080_0000), 0x80_0000);
        assert_eq!(v2p(0xFF80_0080_0000), 0x80_0000);
        assert_eq!(v2p(0x1000), 0x1000 - 0xFF80_0000_0000);
        assert_eq!(virtual_to_physical_address(0xFFFF_FF80_0080_0000), 0x80_0000);
        // exactly the boundary goes to the else branch
        assert_eq!(v2p(0xFFFF_FF80_0000_0000), 0xFFFF_FF80_0000_0000 - 0xFF80_0000_0000);
    }

    #[test]
    fn py_int() {
        assert_eq!(py_int_bytes(b"13"), Some(13));
        assert_eq!(py_int_bytes(b" 13\n"), Some(13));
        assert_eq!(py_int_bytes(b"+1_3"), Some(13));
        assert_eq!(py_int_bytes(b"-7"), Some(-7));
        assert_eq!(py_int_bytes(b"1__3"), None);
        assert_eq!(py_int_bytes(b"_13"), None);
        assert_eq!(py_int_bytes(b""), None);
        assert_eq!(py_int_bytes(b"2: Thu"), None);
    }

    #[test]
    fn timeval_rounding() {
        assert_eq!(float_to_timeval(1.5).unwrap(), (1, 500_000));
        assert_eq!(float_to_timeval(1526946771.723834).unwrap(), (1526946771, 723_834));
        assert_eq!(float_to_timeval(-1.25).unwrap(), (-2, 750_000));
        // 0.0000005 rounds half-even at the microsecond
        assert_eq!(float_to_timeval(2.9999999).unwrap(), (3, 0));
    }
}
