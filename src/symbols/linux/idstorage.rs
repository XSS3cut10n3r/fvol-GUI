//! python `symbols/linux/__init__.py` `IDStorage` / `XArray` / `RadixTree` / `PageCache`, and the
//! tree-ish class extensions of `symbols/linux/extensions/__init__.py`: `IDR`, `rb_root`,
//! `scatterlist`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! * [`IdStorage::choose`] = python `IDStorage.choose_id_storage(context, "kernel")`; then
//!   [`IdStorage::get_entries`] walks an XArray / radix tree root (python `get_entries(root)`).
//! * [`PageCache`] = python `PageCache` (`get_cached_pages`).
//! * [`idr_get_entries`] = python `IDR.get_entries()` (`pid_namespace.idr` etc.).
//! * [`rb_get_nodes`] = python `rb_root.get_nodes()`.
//! * [`sg_for_each`] / [`sg_get_content`] = python `scatterlist.for_each_sg()` / `get_content()`.
//!
//! Every walker returns a `Vec<Result<..>>` whose trailing `Err` marks where python raised.

use super::fs::{FsExt, tgt};
use super::vmlinux_of;
use crate::error::{Error, Result};
use crate::layers::{Layer, LayerExt};
use crate::objects::{Module, Obj};
use crate::symbols::Ty;

/// Which tree implementation the kernel uses for the page cache / IDR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdKind {
    XArray,
    RadixTree,
}

/// python `IDStorage` (an `XArray` or a `RadixTree`), with its dynamically computed constants.
#[derive(Clone, Copy, Debug)]
pub struct IdStorage {
    pub vmlinux: Module,
    pub kind: IdKind,
    /// python `CHUNK_SHIFT` (from the node's `slots[]` size).
    pub chunk_shift: u32,
    /// python `CHUNK_SIZE`.
    pub chunk_size: u64,
    /// python `pointer_size`.
    pub pointer_size: u64,
    /// radix tree: `RADIX_TREE_INTERNAL_NODE` (1, or 2 when there is no `radix_tree_root`).
    pub radix_internal_node: u64,
    /// radix tree: `RADIX_TREE_HEIGHT_MASK`.
    pub radix_height_mask: u64,
    node_ty: Ty,
    slots_off: u64,
}

const XARRAY_TAG_MASK: u64 = 3;
const XARRAY_TAG_INTERNAL: u64 = 2;
const RADIX_TREE_EXCEPTIONAL_ENTRY: u64 = 2;
const RADIX_TREE_ENTRY_MASK: u64 = 3;

impl IdStorage {
    /// python `IDStorage.choose_id_storage(context, kernel_module_name)`.
    pub fn choose(vmlinux: Module) -> Result<IdStorage> {
        let t = vmlinux.table();
        let asp = t.user_type("address_space").ok_or_else(|| Error::Symbol("Unknown symbol: address_space".into()))?;
        let i_pages_ty = t.member(asp, "i_pages").map(|m| t.type_name(m.ty)).unwrap_or_default();
        let is_xarray = i_pages_ty == "xarray";
        let is_radix_root = i_pages_ty == "radix_tree_root" && t.user_type("radix_tree_root").is_some_and(|u| t.member(u, "xa_head").is_some());
        let kind = if is_xarray || is_radix_root { IdKind::XArray } else { IdKind::RadixTree };
        let node_name = match kind {
            IdKind::XArray => "xa_node",
            IdKind::RadixTree => "radix_tree_node",
        };
        let node_ty = vmlinux.get_type(node_name)?;
        let nut = match node_ty {
            Ty::Struct(u) => u,
            _ => return Err(Error::Symbol(format!("{node_name} is not a struct"))),
        };
        let slots = t.member(nut, "slots").ok_or_else(|| Error::Symbol(format!("AttributeError: {node_name} has no attribute: slots")))?;
        let count = match slots.ty {
            Ty::Array { count, .. } => count as u64,
            _ => 0,
        };
        // python: slots_array_size.bit_length() - 1
        let chunk_shift = (64 - count.leading_zeros()).saturating_sub(1);
        let pointer_size = t.size_of(t.get_type("pointer")?);
        let mut s = IdStorage {
            vmlinux,
            kind,
            chunk_shift,
            chunk_size: 1 << chunk_shift,
            pointer_size,
            radix_internal_node: 1,
            radix_height_mask: 0,
            node_ty,
            slots_off: slots.offset,
        };
        if kind == IdKind::RadixTree {
            let index_bits = 8 * pointer_size;
            let max_path = if chunk_shift == 0 { 0 } else { index_bits.div_ceil(chunk_shift as u64) };
            s.radix_height_mask = (1u64 << (max_path + 1).min(63)) - 1;
            if !vmlinux.has_type("radix_tree_root") {
                s.radix_internal_node = 2;
            }
        }
        Ok(s)
    }

    fn tag_internal_value(&self) -> u64 {
        match self.kind {
            IdKind::XArray => XARRAY_TAG_INTERNAL,
            IdKind::RadixTree => self.radix_internal_node,
        }
    }

    fn node_is_internal(&self, nodep: u64) -> bool {
        match self.kind {
            IdKind::XArray => nodep & XARRAY_TAG_MASK == XARRAY_TAG_INTERNAL,
            IdKind::RadixTree => nodep & self.radix_internal_node != 0,
        }
    }

    fn is_node_tagged(&self, nodep: u64) -> bool {
        match self.kind {
            IdKind::XArray => nodep & XARRAY_TAG_MASK != 0,
            IdKind::RadixTree => self.node_is_internal(nodep),
        }
    }

    fn untag_node(&self, nodep: u64) -> u64 {
        match self.kind {
            IdKind::XArray => nodep & !XARRAY_TAG_MASK,
            IdKind::RadixTree => nodep & !RADIX_TREE_ENTRY_MASK,
        }
    }

    /// python `is_valid_node(nodep)`.
    pub fn is_valid_node(&self, nodep: u64) -> bool {
        match self.kind {
            IdKind::XArray => !self.is_node_tagged(nodep),
            IdKind::RadixTree => !(self.vmlinux.has_type("radix_tree_root") && nodep & RADIX_TREE_ENTRY_MASK == RADIX_TREE_EXCEPTIONAL_ENTRY),
        }
    }

    fn node(&self, nodep: u64) -> Obj {
        Obj::new(self.vmlinux.sp, self.node_ty, nodep)
    }

    /// python `get_tree_height(treep)`.
    fn get_tree_height(&self, treep: u64) -> Result<u64> {
        if self.kind == IdKind::XArray {
            return Ok(0);
        }
        let t = self.vmlinux.table();
        if t.user_type("radix_tree_root").is_some_and(|u| t.member(u, "height").is_some()) {
            return self.vmlinux.object_abs("radix_tree_root", treep)?.m("height")?.u64();
        }
        Ok(0)
    }

    /// python `get_node_height(nodep)`.
    fn get_node_height(&self, nodep: u64) -> Result<u64> {
        let node = self.node(nodep);
        if self.kind == IdKind::XArray {
            return Ok(node.m("shift")?.u64()? / self.chunk_shift.max(1) as u64 + 1);
        }
        let height = if node.has_member("shift") {
            node.m("shift")?.u64()? / self.chunk_shift.max(1) as u64 + 1
        } else if node.has_member("path") {
            node.m("path")?.u64()? & self.radix_height_mask
        } else if node.has_member("height") {
            node.m("height")?.u64()?
        } else {
            return Err(Error::msg("VolatilityException: Cannot find radix-tree node height"));
        };
        let vm = &self.vmlinux;
        let arr = if vm.has_symbol("height_to_maxindex") {
            Some(vm.object_from_symbol("height_to_maxindex")?)
        } else if vm.has_symbol("height_to_maxnodes") {
            Some(vm.object_from_symbol("height_to_maxnodes")?)
        } else {
            None
        };
        if let Some(a) = arr {
            if a.count() > 0 && height >= a.count() {
                return Err(Error::msg(format!("LinuxPageCacheException: Radix Tree node {nodep:#x} height {height} exceeds max height of {}", a.count())));
            }
        }
        Ok(height)
    }

    /// python `get_head_node(tree)`: `xa_head` / `rnode` (None on InvalidAddressException).
    fn get_head_node(&self, tree: &Obj) -> Result<Option<Obj>> {
        let name = match self.kind {
            IdKind::XArray => "xa_head",
            IdKind::RadixTree => "rnode",
        };
        let p = tgt(tree)?.m(name)?;
        match p.u64() {
            Ok(_) => Ok(Some(p)),
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// python `_iter_node(nodep, height)` (reads the whole `slots[]` at once when possible).
    fn iter_node(&self, nodep: u64, height: u64, out: &mut Vec<Result<u64>>) {
        let layer = self.vmlinux.layer();
        let base = nodep.wrapping_add(self.slots_off) & self.vmlinux.sp.layer_mask;
        let ps = self.pointer_size as usize;
        let n = self.chunk_size as usize;
        let mask = self.vmlinux.sp.native_mask;
        let bulk = layer.read_vec(base, n * ps).ok();
        for off in 0..n {
            let slot = match &bulk {
                Some(b) => read_ptr(&b[off * ps..off * ps + ps]) & mask,
                None => {
                    let mut b = [0u8; 8];
                    // python: `try: slot = node_slots[off] except InvalidAddressException: continue`
                    if layer.read(base.wrapping_add((off * ps) as u64) & self.vmlinux.sp.layer_mask, &mut b[..ps]).is_err() {
                        continue;
                    }
                    read_ptr(&b[..ps]) & mask
                }
            };
            if slot == 0 {
                continue;
            }
            let child = if self.node_is_internal(slot) { slot & !self.tag_internal_value() } else { slot };
            if height == 1 {
                if self.is_valid_node(child) {
                    out.push(Ok(child));
                }
            } else {
                self.iter_node(child, height - 1, out);
            }
        }
    }

    /// python `IDStorage.get_entries(root)`: every leaf entry (pointer value) of the tree whose
    /// root object is `root` (an `xarray` / `radix_tree_root`).
    pub fn get_entries(&self, root: &Obj) -> Vec<Result<u64>> {
        let mut out = Vec::new();
        let r = (|| -> Result<()> {
            let root = tgt(root)?;
            let mut height = self.get_tree_height(root.addr)?;
            let Some(head) = self.get_head_node(&root)? else { return Ok(()) };
            let mut nodep = head.u64()?;
            if !(nodep != 0 && head.is_readable()) {
                return Ok(());
            }
            let is_internal = self.node_is_internal(nodep);
            if self.is_node_tagged(nodep) {
                nodep = self.untag_node(nodep);
            }
            if is_internal {
                height = self.get_node_height(nodep)?;
            }
            if height == 0 {
                if self.is_valid_node(nodep) {
                    out.push(Ok(nodep));
                }
            } else {
                self.iter_node(nodep, height, &mut out);
            }
            Ok(())
        })();
        if let Err(e) = r {
            out.push(Err(e));
        }
        out
    }
}

#[inline]
fn read_ptr(b: &[u8]) -> u64 {
    let mut x = [0u8; 8];
    x[..b.len()].copy_from_slice(b);
    u64::from_le_bytes(x)
}

/// python `PageCache` over an `address_space` object.
pub struct PageCache {
    pub vmlinux: Module,
    pub page_cache: Obj,
    pub idstorage: IdStorage,
}

impl PageCache {
    /// python `PageCache(context, "kernel", page_cache=address_space)`.
    pub fn new(vmlinux: Module, page_cache: Obj) -> Result<PageCache> {
        Ok(PageCache { vmlinux, page_cache, idstorage: IdStorage::choose(vmlinux)? })
    }

    /// python `get_cached_pages()`: `page` objects; a trailing `Err` where python raises
    /// (`LinuxPageCacheException` for an invalid page).
    pub fn get_cached_pages(&self) -> Vec<Result<Obj>> {
        let mut out = Vec::new();
        let root = match self.page_cache.i_pages() {
            Ok(r) => r,
            Err(e) => return vec![Err(e)],
        };
        let layer = self.vmlinux.layer();
        for e in self.idstorage.get_entries(&root) {
            let addr = match e {
                Ok(a) => a,
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            };
            if !layer.is_valid(addr, 1) {
                out.push(Err(Error::msg(format!("LinuxPageCacheException: Invalid cached page address at {addr:#x}, aborting"))));
                break;
            }
            let page = match self.vmlinux.object_abs("page", addr) {
                Ok(p) => p,
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            };
            match page.page_is_valid() {
                Ok(true) => out.push(Ok(page)),
                Ok(false) => {
                    out.push(Err(Error::msg(format!("LinuxPageCacheException: Invalid cached page at {addr:#x}, aborting"))));
                    break;
                }
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            }
        }
        out
    }
}

/// python `IDR.IDR_BITS` etc.
const IDR_BITS: u64 = 8;
const IDR_MASK: u64 = (1 << IDR_BITS) - 1;
const INT_SIZE: u64 = 4;
const MAX_IDR_SHIFT: u64 = INT_SIZE * 8 - 1;

/// python `IDR.idr_max(num_layers)` (python's `min([INT_SIZE, ...])` quirk kept).
pub fn idr_max(num_layers: i128) -> i128 {
    let bits = (INT_SIZE as i128).min(num_layers * IDR_BITS as i128).min(MAX_IDR_SHIFT as i128);
    if bits < 0 {
        return -1;
    }
    (1i128 << bits) - 1
}

/// python `IDR.idr_find(idr_id)` (kernels < 4.11): the `idr_layer` pointer object reached, or
/// None.
pub fn idr_find(idr: &Obj, idr_id: i128) -> Result<Option<Obj>> {
    let idr = tgt(idr)?;
    let vm = vmlinux_of(&idr)?;
    let t = vm.table();
    if !t.user_type("idr_layer").is_some_and(|u| t.member(u, "layer").is_some()) {
        return Ok(None);
    }
    if idr_id < 0 {
        return Ok(None);
    }
    let mut layer = idr.m("top")?;
    if layer.u64()? == 0 {
        return Ok(None);
    }
    let l = layer.m("layer")?.int()?;
    let mut n = (l + 1) * IDR_BITS as i128;
    if idr_id > idr_max(l + 1) {
        return Ok(None);
    }
    if n == 0 {
        return Err(Error::msg("AssertionError"));
    }
    while n > 0 && layer.u64()? != 0 {
        n -= IDR_BITS as i128;
        if n != layer.m("layer")?.int()? * IDR_BITS as i128 {
            return Err(Error::msg("AssertionError"));
        }
        let idx = (idr_id >> n) as u64 & IDR_MASK;
        layer = layer.m("ary")?.at(idx)?;
        layer.u64()?;
    }
    Ok(Some(layer))
}

/// python `IDR.get_entries()`: the pointer values stored in the IDR (`idr_rt` tree on kernels
/// >= 4.11, `idr_find` over `0..cur` before). A trailing `Err` = python raised.
pub fn idr_get_entries(idr: &Obj) -> Vec<Result<u64>> {
    let idr = match tgt(idr) {
        Ok(i) => i,
        Err(e) => return vec![Err(e)],
    };
    if idr.has_member("idr_rt") {
        let r = vmlinux_of(&idr).and_then(IdStorage::choose).and_then(|s| Ok((s, idr.m("idr_rt")?)));
        return match r {
            Ok((s, root)) => s.get_entries(&root),
            Err(e) => vec![Err(e)],
        };
    }
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let cur = idr.m("cur")?.int()?;
        let mut next_id = 0i128;
        while next_id < cur {
            if let Some(e) = idr_find(&idr, next_id)? {
                let v = e.u64()?;
                if v != 0 {
                    out.push(Ok(v));
                }
            }
            next_id += 1;
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

/// python `rb_root.get_nodes()`: every node pointer value, pre-order (node, left, right).
/// A trailing `Err` = python raised (incl. its RecursionError on absurdly deep trees).
pub fn rb_get_nodes(root: &Obj) -> Vec<Result<u64>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let root = tgt(root)?;
        let first = root.m("rb_node")?;
        // explicit stack of (pointer object, depth); python recursion depth ~ 1000 frames
        let mut stack = vec![(first, 1u32)];
        while let Some((p, depth)) = stack.pop() {
            if !(p.u64()? != 0 && p.is_readable()) {
                continue;
            }
            if depth > 980 {
                return Err(Error::msg("RecursionError: maximum recursion depth exceeded"));
            }
            out.push(Ok(p.u64()?));
            let n = p.deref()?;
            // python reads rb_left, walks it fully, then reads rb_right
            let left = n.m("rb_left")?;
            let right = n.m("rb_right")?;
            stack.push((right, depth + 1));
            stack.push((left, depth + 1));
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

const SG_CHAIN: u64 = 0x01;
const SG_END: u64 = 0x02;
const SG_PAGE_LINK_MASK: u64 = SG_CHAIN | SG_END;

fn sg_dma_len(sg: &Obj) -> Result<u64> {
    if sg.has_member("dma_length") { sg.m("dma_length")?.u64() } else { sg.m("length")?.u64() }
}

/// python `scatterlist._sg_next()`.
fn sg_next(sg: &Obj) -> Result<Option<Obj>> {
    let link = sg.m("page_link")?.u64()?;
    if link & SG_PAGE_LINK_MASK & SG_END != 0 {
        return Ok(None);
    }
    let next = if link & SG_PAGE_LINK_MASK & SG_CHAIN != 0 { link & !SG_PAGE_LINK_MASK } else { sg.addr.wrapping_add(sg.size()) };
    Ok(Some(sg.at_addr(next)))
}

/// python `scatterlist.for_each_sg()`. A trailing `Err` = python raised.
pub fn sg_for_each(sg: &Obj) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let sg0 = tgt(sg)?;
        let page_size = sg0.layer().as_intel().map_or(0x1000, |i| i.page_size());
        let size = sg0.size().max(1);
        let max_single = page_size / size;
        if sg0.m("page_link")?.u64()? == 0 && sg_dma_len(&sg0)? == 0 && sg0.m("dma_address")?.u64()? == 0 {
            return Ok(());
        }
        out.push(Ok(sg0));
        let mut cur = sg0;
        let mut count = 1u64;
        while count <= max_single {
            let Some(n) = sg_next(&cur)? else { break };
            cur = n;
            if cur.m("page_link")?.u64()? & SG_CHAIN != 0 {
                count = 0;
            } else {
                count += 1;
                out.push(Ok(cur));
            }
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

/// python `scatterlist.get_content()`: the concatenated bytes at each entry's `dma_address`
/// (read from the physical layer). `Err` where python raises (strict reads).
pub fn sg_get_content(sg: &Obj) -> Result<Vec<u8>> {
    let sg0 = tgt(sg)?;
    let phys: &dyn Layer = match sg0.layer().as_intel() {
        Some(i) => i.phys().as_ref(),
        None => sg0.layer(),
    };
    let mut out = Vec::new();
    for e in sg_for_each(&sg0) {
        let e = e?;
        let addr = e.m("dma_address")?.u64()?;
        let len = sg_dma_len(&e)? as usize;
        out.extend_from_slice(&phys.read_vec(addr, len)?);
    }
    Ok(out)
}

#[cfg(test)]
mod pagecache_tests {
    use super::*;
    use crate::context::{Context, GlobalOptions};
    use std::io::{Seek, SeekFrom, Write};

    /// Dumps an inode's page cache like python `linux.pagecache.InodePages --inode X --dump`
    /// (`write_inode_content_to_stream`) to check IDStorage / PageCache / page.get_content:
    /// `RSVOL_BENCH_IMAGE=<image> RSVOL_INODE=0x... RSVOL_TEST_OUT=<file> cargo test --profile fast
    /// inode_dump_like -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn inode_dump_like() {
        let image = std::env::var("RSVOL_BENCH_IMAGE").unwrap();
        let addr = u64::from_str_radix(std::env::var("RSVOL_INODE").unwrap().trim_start_matches("0x"), 16).unwrap();
        let out = std::env::var("RSVOL_TEST_OUT").unwrap();
        let opts = GlobalOptions { file: Some(image), symbol_dirs: vec!["/home/user/rs-vol/testdata/symbols".into()], ..Default::default() };
        let ctx = Context::new(opts).unwrap();
        let k = ctx.linux_kernel().unwrap();
        let inode = k.object_abs("inode", addr).unwrap();
        assert!(inode.is_reg().unwrap());
        let size = inode.m("i_size").unwrap().int().unwrap() as u64;
        let mut f = std::fs::File::create(&out).unwrap();
        let mut init = false;
        let mut n = 0;
        let t = std::time::Instant::now();
        for c in inode.get_contents() {
            let (idx, data) = c.unwrap();
            let fp = idx * 0x1000;
            let len = (size.saturating_sub(fp)).min(data.len() as u64);
            if fp >= size || fp + len > size {
                continue;
            }
            if !init {
                f.set_len(size).unwrap();
                init = true;
            }
            f.seek(SeekFrom::Start(fp)).unwrap();
            f.write_all(&data[..len as usize]).unwrap();
            n += 1;
        }
        eprintln!("pages written: {n} in {:?}", t.elapsed());
    }
}
