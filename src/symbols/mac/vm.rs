//! python mac `vm_map_entry.get_vnode / get_path / is_suspicious` and
//! `proc.get_process_memory_sections` class extensions, as the [`MacVmExt`] trait on [`Obj`].
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! use crate::symbols::mac::{MacExt, vm::MacVmExt};
//! let k = ctx.mac_kernel()?;
//! for vma in proc.get_map_iter() {
//!     let vma = vma?;                         // a `vm_map_entry *` (python yields pointers)
//!     let path = vma.get_path(k.table.name())?; // python get_path(context, kernel.symbol_table_name)
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
//! caught or propagate, follow python exactly.

use super::MacExt;
use crate::error::{Error, Result};
use crate::objects::util::pointer_to_string;
use crate::objects::{Obj, Space};
use crate::util::FxHashSet;

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

/// The struct behind `o` (python attribute access on a pointer dereferences).
#[inline]
fn entry(o: &Obj) -> Result<Obj> {
    if o.is_pointer() { o.deref() } else { Ok(*o) }
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
        if e.m("is_sub_map")?.int()? == 1 {
            return Ok(Vnode::SubMap);
        }
        // `vnode_object` starts as the `vm_object *` pointer (its vol.offset is where the
        // pointer lives), then becomes the shadow `vm_object` structs
        let ptr = e.get_object()?.get_map_object()?;
        if ptr.u64()? == 0 {
            return Ok(Vnode::None);
        }
        let mut vol_offset = ptr.addr;
        let mut obj = ptr.deref()?;
        let mut guard = 0usize;
        loop {
            let tmp = match obj.m("shadow").and_then(|s| s.deref()) {
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
            let pager = obj.m("pager")?;
            if pager.u64()? == 0 {
                return Ok(None);
            }
            Ok(Some(pager.m("mo_pager_ops")?.deref()?))
        })() {
            Ok(Some(o)) => o,
            Ok(None) => return Ok(Vnode::None),
            Err(e) if e.is_invalid_address() => return Ok(Vnode::None),
            Err(e) => return Err(e),
        };
        // context.symbol_space.get_symbols_by_location(ops.vol.offset): exact address match of
        // a symbol named vnode_pager_ops / _vnode_pager_ops (table addresses are symbol_mask'ed
        // but not KASLR-shifted, like python's)
        let table = e.table();
        let found = ["vnode_pager_ops", "_vnode_pager_ops"].iter().any(|n| table.get_symbol(n).is_ok_and(|s| s.address == ops.addr));
        if !found {
            return Ok(Vnode::None);
        }
        let vtable = crate::symbols::table(config_prefix).ok_or_else(|| {
            Error::Symbol(format!("Type {config_prefix}!vnode_pager references missing Type/Symbol/Enum: '{config_prefix}'"))
        })?;
        let pager = obj.m("pager")?.u64()?;
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
        let perms = self.get_perms()?;
        Ok(if perms == "rwx" { true } else { perms == "r-x" && self.get_path(config_prefix)?.is_empty() })
    }

    fn get_process_memory_sections(&self, config_prefix: &str, rw_no_file: bool) -> Result<Vec<(u64, i128)>> {
        let mut out = Vec::new();
        for vma in self.get_map_iter() {
            let vma = entry(&vma?)?;
            let links = vma.m("links")?;
            let start = links.m("start")?.u64()?;
            let end = links.m("end")?.u64()?;
            if rw_no_file && (vma.get_perms()? != "rw" || !vma.get_path(config_prefix)?.is_empty()) && vma.get_special_path()? != "[heap]" {
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
