//! python mac `vm_map_entry.get_vnode / get_path / is_suspicious` and
//! `proc.get_process_memory_sections` class extensions, as the [`MacVmExt`] trait on [`Obj`],
//! plus [`map_entries`] (a fast `proc.get_map_iter()` yielding the entries themselves).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! use crate::symbols::mac::vm::{MacVmExt, map_entries};
//! let k = ctx.mac_kernel()?;
//! for e in map_entries(&proc) {
//!     let e = e?;                                // a `vm_map_entry`
//!     let path = e.get_path(k.table.name())?;    // python get_path(context, kernel.symbol_table_name)
//! }
//! let sections = proc.get_process_memory_sections(k.table.name(), true)?;
//! ```
//!
//! `config_prefix` is what python passes as `config_prefix`: the NAME of the symbol table the
//! `vnode_pager` type is looked up in (`<config_prefix>!vnode_pager`). Most plugins pass the
//! kernel's symbol table name; mac.bash passes the kernel MODULE name ("kernel"), which python
//! cannot resolve (SymbolError) -- only reached when a vnode pager is actually found.
//!
//! Every method accepts the `vm_map_entry` struct or a pointer to it (python attribute access
//! on a pointer dereferences). Reads, and therefore which `InvalidAddressException`s are
//! caught or propagate, follow python exactly. Hot paths use members pre-resolved once per
//! kernel table ([`Field`]s) with the generic name-based lookups as the fallback.

use super::MacExt;
use crate::error::{Error, Result};
use crate::objects::util::pointer_to_string;
use crate::objects::{Field, Obj, Space};
use crate::symbols::{TableRef, Ty};
use crate::util::FxHashSet;
use std::sync::OnceLock;

/// python `vm_map_entry.get_vnode()` result.
#[derive(Clone, Copy, Debug)]
pub enum Vnode {
    /// The string `"sub_map"` (the entry maps a sub map).
    SubMap,
    /// `None`.
    None,
    /// `vnode_pager.vnode_handle`: a `vnode *` POINTER object (its value may be NULL; python's
    /// `get_path` tests its truthiness).
    Node(Obj),
}

/// Bound for python loops that would never terminate on cyclic garbage (python hangs there).
const HANG_GUARD: usize = 1 << 20;

/// ZP_POISON (python `get_map_iter` stops at entries with this start/end).
const ZP_POISON: u64 = 0xDEAD_BEEF_DEAD_BEEF;

/// Members of the hot paths resolved once per kernel table (python's `has_member` dispatch in
/// `get_object` / `get_map_object` / `get_range_alias` included).
struct VmFields {
    table: TableRef,
    /// `vm_map_entry` type
    entry_ty: Ty,
    entry_size: u64,
    start: Field,
    end: Field,
    next: Field,
    is_sub_map: Field,
    /// `entry.get_object().get_map_object()`: the `vm_object *` inside the union
    vm_object: Field,
    protection: Field,
    /// `alias`, or `vme_offset` (then `& 0xFFF`)
    alias: Field,
    alias_is_offset: bool,
    shadow: Field,
    pager: Field,
    mo_pager_ops: Field,
    /// addresses of `vnode_pager_ops` / `_vnode_pager_ops` (symbol_mask'ed, unslid)
    ops: [Option<u64>; 2],
}

impl VmFields {
    fn resolve(t: TableRef) -> Option<VmFields> {
        let member = |ty: Ty, name: &str| -> Option<(u64, Ty)> {
            match ty {
                Ty::Struct(ut) => t.member(ut, name).map(|m| (m.offset, m.ty)),
                _ => None,
            }
        };
        let field = |ty: Ty, name: &str| -> Option<Field> {
            match ty {
                Ty::Struct(ut) => Field::new(t, t.user_type_name(ut), name).ok(),
                _ => None,
            }
        };
        let entry_ty = t.get_type("vm_map_entry").ok()?;
        let links = member(entry_ty, "links")?;
        let (start, end, next) = (field(links.1, "start")?, field(links.1, "end")?, field(links.1, "next")?);
        let shift = |mut f: Field, by: u64| {
            f.offset += by;
            f
        };
        let (start, end, next) = (shift(start, links.0), shift(end, links.0), shift(next, links.0));
        // links.next must point to vm_map_entry
        if !matches!(next.ty, Ty::Pointer { target, .. } if t.node(target) == entry_ty) {
            return None;
        }
        let object = ["vme_object", "object"].iter().find_map(|n| member(entry_ty, n))?;
        let vm_object = ["vm_object", "vmo_object"].iter().find_map(|n| field(object.1, n))?;
        let vm_object = shift(vm_object, object.0);
        let vm_object_ty = match vm_object.ty {
            Ty::Pointer { target, .. } => t.node(target),
            _ => return None,
        };
        let shadow = field(vm_object_ty, "shadow")?;
        let pager = field(vm_object_ty, "pager")?;
        if !matches!(shadow.ty, Ty::Pointer { target, .. } if t.node(target) == vm_object_ty) {
            return None;
        }
        let memory_object_ty = match pager.ty {
            Ty::Pointer { target, .. } => t.node(target),
            _ => return None,
        };
        let mo_pager_ops = field(memory_object_ty, "mo_pager_ops")?;
        let (alias, alias_is_offset) = match field(entry_ty, "alias") {
            Some(f) => (f, false),
            None => (field(entry_ty, "vme_offset")?, true),
        };
        let ops = ["vnode_pager_ops", "_vnode_pager_ops"].map(|n| t.get_symbol(n).ok().map(|s| s.address));
        Some(VmFields {
            table: t,
            entry_ty,
            entry_size: t.size_of(entry_ty),
            start,
            end,
            next,
            is_sub_map: field(entry_ty, "is_sub_map")?,
            vm_object,
            protection: field(entry_ty, "protection")?,
            alias,
            alias_is_offset,
            shadow,
            pager,
            mo_pager_ops,
            ops,
        })
    }
}

/// The fields for `t` (one kernel table per run; other tables take the generic path).
fn vm_fields(t: TableRef) -> Option<&'static VmFields> {
    static F: OnceLock<Option<VmFields>> = OnceLock::new();
    F.get_or_init(|| VmFields::resolve(t)).as_ref().filter(|f| std::ptr::eq(f.table, t))
}

/// Member access for a `vm_map_entry` struct: pre-resolved fields or python-style lookups.
#[derive(Clone, Copy)]
enum Acc {
    Fast(&'static VmFields),
    Slow,
}

impl Acc {
    #[inline]
    fn of(e: &Obj) -> Acc {
        match vm_fields(e.table()) {
            Some(f) if e.ty == f.entry_ty => Acc::Fast(f),
            _ => Acc::Slow,
        }
    }
    #[inline]
    fn is_sub_map(self, e: &Obj) -> Result<i128> {
        match self {
            Acc::Fast(f) => e.f(&f.is_sub_map).int(),
            Acc::Slow => e.m("is_sub_map")?.int(),
        }
    }
    /// python `self.get_object().get_map_object()` (a `vm_object *` pointer)
    #[inline]
    fn vm_object(self, e: &Obj) -> Result<Obj> {
        match self {
            Acc::Fast(f) => Ok(e.f(&f.vm_object)),
            Acc::Slow => e.get_object()?.get_map_object(),
        }
    }
    /// `vm_object.shadow` of a vm_object struct
    #[inline]
    fn shadow(self, o: &Obj) -> Result<Obj> {
        match self {
            Acc::Fast(f) => Ok(o.f(&f.shadow)),
            Acc::Slow => o.m("shadow"),
        }
    }
    #[inline]
    fn pager(self, o: &Obj) -> Result<Obj> {
        match self {
            Acc::Fast(f) => Ok(o.f(&f.pager)),
            Acc::Slow => o.m("pager"),
        }
    }
    /// `pager.mo_pager_ops` for the `memory_object *` pointer `pager` whose value is `v`
    #[inline]
    fn mo_pager_ops(self, pager: &Obj, v: u64) -> Result<Obj> {
        match self {
            Acc::Fast(f) => Ok(deref_value(pager, v)?.f(&f.mo_pager_ops)),
            Acc::Slow => pager.m("mo_pager_ops"),
        }
    }
    /// python `get_symbols_by_location(addr)` contains `*!vnode_pager_ops` / `*!_vnode_pager_ops`
    #[inline]
    fn is_vnode_pager_ops(self, table: TableRef, addr: u64) -> bool {
        match self {
            Acc::Fast(f) => f.ops.contains(&Some(addr)),
            Acc::Slow => ["vnode_pager_ops", "_vnode_pager_ops"].iter().any(|n| table.get_symbol(n).is_ok_and(|s| s.address == addr)),
        }
    }
    /// python `vm_map_entry.get_perms()`
    #[inline]
    fn perms(self, e: &Obj) -> Result<&'static str> {
        match self {
            Acc::Fast(f) => Ok(perms_string(e.f(&f.protection).int()?)),
            Acc::Slow => Ok(perms_string(e.m("protection")?.int()?)),
        }
    }
    /// python `vm_map_entry.get_special_path()`
    #[inline]
    fn special_path(self, e: &Obj) -> Result<&'static str> {
        match self {
            Acc::Fast(f) => {
                let v = e.f(&f.alias).int()?;
                Ok(special_path_of(if f.alias_is_offset { v & 0xFFF } else { v }))
            }
            Acc::Slow => e.get_special_path(),
        }
    }
    /// `links.start` / `links.end`
    #[inline]
    fn start_end(self, e: &Obj) -> Result<(u64, u64)> {
        match self {
            Acc::Fast(f) => Ok((e.f(&f.start).u64()?, e.f(&f.end).u64()?)),
            Acc::Slow => {
                let links = e.m("links")?;
                Ok((links.m("start")?.u64()?, links.m("end")?.u64()?))
            }
        }
    }
}

/// python `vm_map_entry.get_perms()` from the `protection` value.
fn perms_string(prot: i128) -> &'static str {
    const PERMS: [&str; 8] = ["---", "r--", "-w-", "rw-", "--x", "r-x", "-wx", "rwx"];
    let bit = |i: i128, b: usize| if prot & i == i { b } else { 0 };
    PERMS[bit(1, 1) | bit(3, 2) | bit(5, 4)]
}

/// python `vm_map_entry.get_special_path()` from `get_range_alias()`.
fn special_path_of(check: i128) -> &'static str {
    if 0 < check && check < 10 {
        "[heap]"
    } else if check == 30 {
        "[stack]"
    } else {
        ""
    }
}

/// `p.dereference()` for a pointer whose value `v` was just read (python keeps the value: no
/// second read).
#[inline]
fn deref_value(p: &Obj, v: u64) -> Result<Obj> {
    match p.target_ty() {
        Some(ty @ Ty::Struct(_)) => Ok(Obj::new(p.sp.native_space(), ty, v)),
        _ => p.deref(),
    }
}

/// The struct behind `o` (python attribute access on a pointer dereferences).
#[inline]
fn entry(o: &Obj) -> Result<Obj> {
    if o.is_pointer() { o.deref() } else { Ok(*o) }
}

/// python `proc.get_map_iter()` with every yielded `vm_map_entry *` dereferenced (what python
/// code gets on member access): same entries, same stop conditions, same errors (a trailing
/// `Err` is where python raised), fewer reads than [`MacExt::get_map_iter`].
pub fn map_entries(proc: &Obj) -> Vec<Result<Obj>> {
    let Some(f) = vm_fields(proc.table()) else {
        return proc.get_map_iter().into_iter().map(|p| p.and_then(|p| p.deref())).collect();
    };
    let mut out = Vec::new();
    let start = (|| -> Result<(Obj, Obj, u64)> {
        let task = proc.get_task()?;
        let next = task.m("map")?.m("hdr")?.m("links")?.m("next")?;
        let v = next.u64()?;
        Ok((task, next, v))
    })();
    let (task, first, mut value) = match start {
        Ok(s) => s,
        Err(e) if e.is_invalid_address() => return out,
        Err(e) => {
            out.push(Err(e));
            return out;
        }
    };
    if !matches!(first.ty, Ty::Pointer { target, .. } if first.table().node(target) == f.entry_ty) || !std::ptr::eq(first.table(), f.table) {
        return proc.get_map_iter().into_iter().map(|p| p.and_then(|p| p.deref())).collect();
    }
    let nentries = match task.m("map").and_then(|m| m.m("hdr")).and_then(|h| h.m("nentries")).and_then(|n| n.int()) {
        Ok(n) => n,
        Err(e) => {
            out.push(Err(e));
            return out;
        }
    };
    let native = task.native();
    // `current_map.dereference()`: the entry at the pointer's value on its native layer
    let entry_sp = first.sp.native_space();
    let mut ptr_loc = first.addr;
    let mut seen: FxHashSet<u64> = FxHashSet::default();
    let mut i: i128 = 0;
    while i < nentries {
        i += 1;
        if value == 0 || seen.contains(&ptr_loc) {
            break;
        }
        let e = Obj::new(entry_sp, f.entry_ty, value);
        if !native.is_valid(e.addr, f.entry_size) {
            break;
        }
        let poisoned = (|| -> Result<bool> { Ok(e.f(&f.start).u64()? == ZP_POISON || e.f(&f.end).u64()? == ZP_POISON) })();
        match poisoned {
            Ok(false) => {}
            Ok(true) => break,
            Err(err) => {
                out.push(Err(err));
                break;
            }
        }
        out.push(Ok(e));
        seen.insert(ptr_loc);
        let next = e.f(&f.next);
        match next.u64() {
            Ok(v) => {
                value = v;
                ptr_loc = next.addr;
            }
            Err(err) => {
                out.push(Err(err));
                break;
            }
        }
    }
    out
}

/// Mac `vm_map_entry` / `proc` memory-map extensions (see the module docs).
pub trait MacVmExt {
    /// python `vm_map_entry.get_vnode(context, config_prefix)`: follows the entry's VM object
    /// shadow chain to its pager; when the pager's ops are the kernel's `vnode_pager_ops`
    /// (python looks the ABSOLUTE ops address up in the symbol tables, so with a KASLR slide
    /// this never matches -- mirrored), returns `<config_prefix>!vnode_pager.vnode_handle`.
    fn get_vnode(&self, config_prefix: &str) -> Result<Vnode>;
    /// python `vm_map_entry.get_path(context, config_prefix)`: `"sub_map"`, the vnode's path
    /// (`v_name`s up the `v_parent` chain), or `""`.
    fn get_path(&self, config_prefix: &str) -> Result<String>;
    /// python `vm_map_entry.is_suspicious(context, config_prefix)`: `rwx`, or `r-x` without a
    /// backing file.
    fn is_suspicious(&self, config_prefix: &str) -> Result<bool>;
    /// python `vm_map_entry.get_perms()` (= [`MacExt::get_perms`], faster).
    fn vma_perms(&self) -> Result<&'static str>;
    /// python `vm_map_entry.get_special_path()` (= [`MacExt::get_special_path`], faster).
    fn vma_special_path(&self) -> Result<&'static str>;
    /// python `vma.links.start, vma.links.end` (read in that order).
    fn vma_range(&self) -> Result<(u64, u64)>;
    /// python `proc.get_process_memory_sections(context, config_prefix, rw_no_file)`:
    /// `(start, size)` of every map entry. With `rw_no_file` python keeps an entry only if
    /// `get_perms() == "rw"` (never true: perms are 3 characters) and it has no path, or it is
    /// `[heap]` -- i.e. only the heap entries. The first `Err` is where python raised.
    /// Sizes are python ints (`end - start`, negative for garbage entries); turn the list into
    /// scan sections with [`scan_sections`].
    fn get_process_memory_sections(&self, config_prefix: &str, rw_no_file: bool) -> Result<Vec<(u64, i128)>>;
}

impl MacVmExt for Obj {
    fn get_vnode(&self, config_prefix: &str) -> Result<Vnode> {
        let e = entry(self)?;
        let acc = Acc::of(&e);
        if acc.is_sub_map(&e)? == 1 {
            return Ok(Vnode::SubMap);
        }
        // `vnode_object` starts as the `vm_object *` pointer (its vol.offset is where the
        // pointer lives), then becomes the shadow `vm_object` structs
        let ptr = acc.vm_object(&e)?;
        let v = ptr.u64()?;
        if v == 0 {
            return Ok(Vnode::None);
        }
        let mut vol_offset = ptr.addr;
        let mut obj = deref_value(&ptr, v)?;
        let mut guard = 0usize;
        loop {
            let tmp = match acc.shadow(&obj).and_then(|s| s.deref()) {
                Ok(t) => t,
                Err(e) if e.is_invalid_address() => break,
                Err(e) => return Err(e),
            };
            if tmp.addr == 0 {
                break;
            }
            vol_offset = tmp.addr;
            obj = tmp;
            guard += 1;
            if guard == HANG_GUARD {
                break;
            }
        }
        if vol_offset == 0 {
            return Ok(Vnode::None);
        }
        let ops = match (|| -> Result<Option<Obj>> {
            let pager = acc.pager(&obj)?;
            let v = pager.u64()?;
            if v == 0 {
                return Ok(None);
            }
            Ok(Some(acc.mo_pager_ops(&pager, v)?.deref()?))
        })() {
            Ok(Some(o)) => o,
            Ok(None) => return Ok(Vnode::None),
            Err(e) if e.is_invalid_address() => return Ok(Vnode::None),
            Err(e) => return Err(e),
        };
        // context.symbol_space.get_symbols_by_location(ops.vol.offset): exact address match of
        // a symbol named vnode_pager_ops / _vnode_pager_ops (table addresses are symbol_mask'ed
        // but not KASLR-shifted, like python's)
        if !acc.is_vnode_pager_ops(e.table(), ops.addr) {
            return Ok(Vnode::None);
        }
        let vtable = crate::symbols::table(config_prefix).ok_or_else(|| {
            Error::Symbol(format!("Type {config_prefix}!vnode_pager references missing Type/Symbol/Enum: '{config_prefix}'"))
        })?;
        let pager = acc.pager(&obj)?.u64()?;
        let vpager = Obj::named(Space::on(obj.native(), vtable), "vnode_pager", pager)?;
        let handle = vpager.m("vnode_handle")?;
        handle.u64()?;
        Ok(Vnode::Node(handle))
    }

    fn get_path(&self, config_prefix: &str) -> Result<String> {
        let mut node = match self.get_vnode(config_prefix)? {
            Vnode::SubMap => return Ok("sub_map".to_string()),
            Vnode::None => return Ok(String::new()),
            Vnode::Node(n) => n,
        };
        if node.u64()? == 0 {
            return Ok(String::new());
        }
        let mut path: Vec<String> = Vec::new();
        let mut seen: FxHashSet<u64> = FxHashSet::default();
        while node.u64()? != 0 && !seen.contains(&node.addr) {
            let v_name = match node.m("v_name").and_then(|n| pointer_to_string(&n, 255)) {
                Ok(s) => s,
                Err(e) if e.is_invalid_address() => break,
                Err(e) => return Err(e),
            };
            path.push(v_name);
            if path.len() > 1024 {
                break;
            }
            seen.insert(node.addr);
            node = node.m("v_parent")?;
            node.u64()?;
        }
        path.reverse();
        Ok(format!("/{}", path.join("/")))
    }

    fn is_suspicious(&self, config_prefix: &str) -> Result<bool> {
        let perms = self.vma_perms()?;
        Ok(if perms == "rwx" { true } else { perms == "r-x" && self.get_path(config_prefix)?.is_empty() })
    }

    fn vma_perms(&self) -> Result<&'static str> {
        let e = entry(self)?;
        Acc::of(&e).perms(&e)
    }

    fn vma_special_path(&self) -> Result<&'static str> {
        let e = entry(self)?;
        Acc::of(&e).special_path(&e)
    }

    fn vma_range(&self) -> Result<(u64, u64)> {
        let e = entry(self)?;
        Acc::of(&e).start_end(&e)
    }

    fn get_process_memory_sections(&self, config_prefix: &str, rw_no_file: bool) -> Result<Vec<(u64, i128)>> {
        let mut out = Vec::new();
        for e in map_entries(self) {
            let e = e?;
            let acc = Acc::of(&e);
            let (start, end) = acc.start_end(&e)?;
            if rw_no_file && (acc.perms(&e)? != "rw" || !e.get_path(config_prefix)?.is_empty()) && acc.special_path(&e)? != "[heap]" {
                continue;
            }
            out.push((start, end as i128 - start as i128));
        }
        Ok(out)
    }
}

/// `layer.scan(..., sections=<get_process_memory_sections(...)>)` sections: python's
/// `_coalesce_sections` merge step on python ints (a negative-size section still moves the
/// merge position, shrinking or splitting its neighbours), then the non-empty results. The
/// output is sorted and disjoint, so the scanner's own coalescing (and min/max clipping) of it
/// matches python's.
pub fn scan_sections(sections: &[(u64, i128)]) -> Vec<(u64, u64)> {
    let mut sorted = sections.to_vec();
    sorted.sort_unstable();
    let mut result: Vec<(u64, i128)> = Vec::with_capacity(sorted.len());
    let mut position: i128 = 0;
    for (start, length) in sorted {
        let s = start as i128;
        match result.last_mut() {
            Some(last) if s <= position => last.1 = (s + length) - last.0 as i128,
            _ => result.push((start, length)),
        }
        position = s + length;
    }
    result.into_iter().filter(|&(_, l)| l > 0).map(|(s, l)| (s, l as u64)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesce_like_python() {
        // python: (0,100),(10,-5) merge into (0,5); (20,10) stays separate
        assert_eq!(scan_sections(&[(20, 10), (0, 100), (10, -5)]), vec![(0, 5), (20, 10)]);
        // adjacent sections merge (start <= position)
        assert_eq!(scan_sections(&[(0, 0x1000), (0x1000, 0x1000)]), vec![(0, 0x2000)]);
        // a contained section shrinks the merged one (python quirk)
        assert_eq!(scan_sections(&[(0, 100), (10, 5)]), vec![(0, 15)]);
        // lone negative / empty sections vanish
        assert_eq!(scan_sections(&[(50, -10), (100, 0)]), vec![]);
    }

    #[test]
    fn perms_and_special_path() {
        assert_eq!(perms_string(7), "rwx");
        assert_eq!(perms_string(5), "r-x");
        assert_eq!(perms_string(2), "---");
        assert_eq!(perms_string(4), "---");
        assert_eq!(perms_string(3), "rw-");
        assert_eq!(special_path_of(1), "[heap]");
        assert_eq!(special_path_of(9), "[heap]");
        assert_eq!(special_path_of(10), "");
        assert_eq!(special_path_of(30), "[stack]");
        assert_eq!(special_path_of(0), "");
    }
}
