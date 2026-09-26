//! Intel x86 paging translation layers (python `framework/layers/intel.py`):
//! `Intel`, `IntelPAE`, `Intel32e` (+ 5-level `IntelLA57`), with the Windows
//! (`WindowsIntel*`: transition pages, pagefile/swap detection) and Linux (`LinuxIntel*`:
//! PROT_NONE / inverted PTEs) semantics.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Semantics mirrored exactly (output depends on them):
//!   * a page table whose entries are ALL identical is treated as not present (python
//!     `_get_valid_table`), at every level;
//!   * validity of an entry: Windows `present || (transition && !prototype)`, Linux
//!     `present || protnone`, otherwise `present`;
//!   * physical address bits: 32 (Intel), 40 (PAE), 52 (Intel32e), 45 (WindowsIntel32e),
//!     46 (LinuxIntel32e); large page frames are OR-ed with the offset like python;
//!   * a mapped chunk is only valid if the whole physical chunk is valid in the lower layer;
//!   * `mapping()` reproduces python's `_mapping` skip arithmetic and run coalescing.
//!
//! Speed: page-table validity is cached per table (shared by all process layers built from the
//! same kernel layer), PTEs are read straight from the mmapped file when the physical layer is
//! a raw file, and a small thread-local TLB caches 4 KiB translations.

use super::{Layer, Mapping, Metadata};
use crate::error::{Error, Result};
use std::cell::UnsafeCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Paging structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PagingMode {
    /// 32-bit, 2 levels, 4 byte entries (python `Intel`).
    Intel32,
    /// 32-bit PAE, 3 levels (python `IntelPAE`).
    Pae,
    /// 64-bit 4-level (python `Intel32e`).
    Intel32e,
    /// 64-bit 5-level (LA57; not in python volatility3 2.28).
    La57,
}

/// Page table entry interpretation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PteFlavor {
    /// Plain Intel (python `Intel`, `IntelPAE`, `Intel32e` -- also used for Mac).
    Generic,
    /// python `WindowsIntel*` (WindowsMixin).
    Windows,
    /// python `LinuxIntel*` (LinuxMixin).
    Linux,
}

#[derive(Clone, Copy, Debug)]
struct Params {
    entry_size: u32,
    index_shift: u32,
    bits_per_register: u32,
    maxphyaddr: u32,
    maxvirtaddr: u32,
    /// (index bits, large pages allowed) per level, top first
    levels: &'static [(u32, bool)],
}

const L_INTEL: &[(u32, bool)] = &[(10, true), (10, false)];
const L_PAE: &[(u32, bool)] = &[(2, false), (9, true), (9, false)];
const L_32E: &[(u32, bool)] = &[(9, false), (9, true), (9, true), (9, false)];
const L_LA57: &[(u32, bool)] = &[(9, false), (9, false), (9, true), (9, true), (9, false)];

fn params(mode: PagingMode, flavor: PteFlavor) -> Params {
    match mode {
        PagingMode::Intel32 => {
            Params { entry_size: 4, index_shift: 2, bits_per_register: 32, maxphyaddr: 32, maxvirtaddr: 32, levels: L_INTEL }
        }
        PagingMode::Pae => {
            Params { entry_size: 8, index_shift: 3, bits_per_register: 32, maxphyaddr: 40, maxvirtaddr: 32, levels: L_PAE }
        }
        PagingMode::Intel32e => Params {
            entry_size: 8,
            index_shift: 3,
            bits_per_register: 64,
            maxphyaddr: match flavor {
                PteFlavor::Windows => 45,
                PteFlavor::Linux => 46,
                PteFlavor::Generic => 52,
            },
            maxvirtaddr: 48,
            levels: L_32E,
        },
        PagingMode::La57 => Params {
            entry_size: 8,
            index_shift: 3,
            bits_per_register: 64,
            maxphyaddr: match flavor {
                PteFlavor::Windows => 45,
                PteFlavor::Linux => 46,
                PteFlavor::Generic => 52,
            },
            maxvirtaddr: 57,
            levels: L_LA57,
        },
    }
}

/// python `Intel._mask(value, high_bit, low_bit)`: bits `low..=high` of `value`.
#[inline(always)]
pub fn mask_bits(value: u64, high: u32, low: u32) -> u64 {
    let hi = if high >= 63 { u64::MAX } else { (1u64 << (high + 1)) - 1 };
    let lo = if low >= 64 { u64::MAX } else { (1u64 << low) - 1 };
    value & (hi ^ lo)
}

/// A page fault during translation (python `PagedInvalidAddressException`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    /// Number of low address bits covered by the faulting entry (skip granularity).
    pub invalid_bits: u32,
    /// The faulting entry.
    pub entry: u64,
    /// Set when the entry looks like a pagefile entry (python `SwappedInvalidAddressException`).
    pub swap_offset: Option<u64>,
}

/// Where a translated chunk lives: the physical layer or swap layer `n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Phys,
    Swap(u8),
}

/// Cache of "is this page table valid" answers keyed by physical table address, shared by the
/// kernel layer and all process layers derived from it.
pub struct TableCache {
    slots: Box<[AtomicU64]>,
}

const TABLE_CACHE_SLOTS: usize = 1 << 14;

impl TableCache {
    fn new() -> TableCache {
        TableCache { slots: (0..TABLE_CACHE_SLOTS).map(|_| AtomicU64::new(0)).collect() }
    }
    #[inline(always)]
    fn slot(base: u64) -> usize {
        (crate::util::fxhash::hash_u64(base) as usize) & (TABLE_CACHE_SLOTS - 1)
    }
    #[inline(always)]
    fn get(&self, base: u64) -> Option<bool> {
        let v = self.slots[Self::slot(base)].load(Ordering::Relaxed);
        if v & 1 != 0 && (v & !0x1f) == base { Some(v & 2 != 0) } else { None }
    }
    #[inline(always)]
    fn put(&self, base: u64, valid: bool) {
        self.slots[Self::slot(base)].store(base | 1 | if valid { 2 } else { 0 }, Ordering::Relaxed);
    }
}

static NEXT_LAYER_ID: AtomicU32 = AtomicU32::new(1);

const TLB_SIZE: usize = 1024;
const TLB_ID_SHIFT: u32 = 45;

thread_local! {
    /// (tag, physical page) pairs; tag = (layer id << 45 | vpn) + 1, 0 = empty.
    static TLB: UnsafeCell<[(u64, u64); TLB_SIZE]> = const { UnsafeCell::new([(0, 0); TLB_SIZE]) };
}

/// An Intel paging translation layer.
pub struct IntelLayer {
    name: String,
    phys: Arc<dyn Layer>,
    /// raw pointer/len of the mmapped file when `phys` is a raw file layer (kept alive by `phys`)
    phys_raw: Option<(usize, u64)>,
    swap: Vec<Arc<dyn Layer>>,
    dtb: u64,
    mode: PagingMode,
    flavor: PteFlavor,
    p: Params,
    initial_position: u32,
    initial_entry: u64,
    vmask: u64,
    register_mask: u64,
    table_cache: Arc<TableCache>,
    id: u32,
    os: Option<String>,
    kernel_virtual_offset: Option<u64>,
    kernel_banner: Option<String>,
}

impl IntelLayer {
    /// Create a translation layer named `name` over `phys` with page table root `dtb`
    /// (python `page_map_offset`).
    pub fn new(name: &str, phys: Arc<dyn Layer>, dtb: u64, mode: PagingMode, flavor: PteFlavor) -> IntelLayer {
        let p = params(mode, flavor);
        let initial_position = p.maxvirtaddr.min(p.bits_per_register) - 1;
        let initial_entry = mask_bits(dtb, initial_position, 0) | 1;
        let phys_raw = phys.as_file().map(|f| (f.data().as_ptr() as usize, f.len()));
        let id = NEXT_LAYER_ID.fetch_add(1, Ordering::Relaxed);
        IntelLayer {
            name: name.to_string(),
            phys,
            phys_raw,
            swap: Vec::new(),
            dtb,
            mode,
            flavor,
            p,
            initial_position,
            initial_entry,
            vmask: if p.maxvirtaddr >= 64 { u64::MAX } else { (1u64 << p.maxvirtaddr) - 1 },
            register_mask: if p.bits_per_register >= 64 { u64::MAX } else { (1u64 << p.bits_per_register) - 1 },
            table_cache: Arc::new(TableCache::new()),
            id,
            os: None,
            kernel_virtual_offset: None,
            kernel_banner: None,
        }
    }

    /// Set the `os` metadata ("Windows", "Linux", "mac"...).
    pub fn with_os(mut self, os: &str) -> Self {
        self.os = Some(os.to_string());
        self
    }
    /// Set python's `kernel_virtual_offset` config value.
    pub fn with_kernel_virtual_offset(mut self, kvo: Option<u64>) -> Self {
        self.kernel_virtual_offset = kvo;
        self
    }
    /// Set python's `kernel_banner` config value.
    pub fn with_kernel_banner(mut self, banner: Option<String>) -> Self {
        self.kernel_banner = banner;
        self
    }
    /// Attach swap (pagefile) layers; index n = python `swap_layers<n>`.
    pub fn with_swap(mut self, swap: Vec<Arc<dyn Layer>>) -> Self {
        self.swap = swap;
        self
    }

    /// A process address space: same class/config/physical layer, different DTB
    /// (python `_add_process_layer`). Shares the page-table cache.
    pub fn process_layer(&self, dtb: u64, name: &str) -> IntelLayer {
        let mut l = IntelLayer::new(name, self.phys.clone(), dtb, self.mode, self.flavor);
        l.swap = self.swap.clone();
        l.table_cache = self.table_cache.clone();
        l.os = self.os.clone();
        l.kernel_virtual_offset = self.kernel_virtual_offset;
        l.kernel_banner = self.kernel_banner.clone();
        l
    }

    pub fn mode(&self) -> PagingMode {
        self.mode
    }
    pub fn flavor(&self) -> PteFlavor {
        self.flavor
    }
    /// The physical layer (python `memory_layer`).
    pub fn phys(&self) -> &Arc<dyn Layer> {
        &self.phys
    }
    /// python `kernel_virtual_offset` config value.
    pub fn kernel_virtual_offset(&self) -> Option<u64> {
        self.kernel_virtual_offset
    }
    /// python `kernel_banner` config value.
    pub fn kernel_banner(&self) -> Option<&str> {
        self.kernel_banner.as_deref()
    }
    /// python `page_map_offset`.
    pub fn page_map_offset(&self) -> u64 {
        self.dtb
    }
    /// python `bits_per_register` (32 or 64).
    pub fn bits_per_register(&self) -> u32 {
        self.p.bits_per_register
    }
    /// python `_initial_entry` (DTB masked | 1).
    pub fn initial_entry(&self) -> u64 {
        self.initial_entry
    }
    /// 4096.
    pub fn page_size(&self) -> u64 {
        0x1000
    }
    /// Whether this is a PAE layer (python metadata "pae").
    pub fn is_pae(&self) -> bool {
        self.mode == PagingMode::Pae
    }
    /// python `canonicalize`: sign-extend a virtual address.
    pub fn canonicalize(&self, addr: u64) -> u64 {
        if self.p.bits_per_register <= self.p.maxvirtaddr {
            return addr & self.address_mask();
        }
        let half = 1u64 << (self.p.maxvirtaddr - 1);
        if addr < half {
            return addr;
        }
        let prefix = mask_bits(self.register_mask, self.p.bits_per_register, self.p.maxvirtaddr);
        mask_bits(addr, self.p.maxvirtaddr, 0).wrapping_add(prefix)
    }
    /// python `decanonicalize`.
    pub fn decanonicalize(&self, addr: u64) -> u64 {
        let half = 1u64 << (self.p.maxvirtaddr - 1);
        if addr < half {
            return addr;
        }
        let prefix = mask_bits(self.register_mask, self.p.bits_per_register, self.p.maxvirtaddr);
        addr ^ prefix
    }

    #[inline(always)]
    fn entry_valid(&self, e: u64) -> bool {
        match self.flavor {
            PteFlavor::Generic => e & 1 != 0,
            PteFlavor::Windows => (e & 1 != 0) || ((e & (1 << 11) != 0) && (e & (1 << 10) == 0)),
            PteFlavor::Linux => e & 0x101 != 0,
        }
    }

    #[inline(always)]
    fn pte_pfn(&self, e: u64) -> u64 {
        match self.flavor {
            PteFlavor::Linux => {
                let inv = if e != 0 && e & 1 == 0 { self.register_mask } else { 0 };
                let pfn_mask = !0xfffu64 & mask_bits(u64::MAX, self.p.maxphyaddr - 1, 0) & self.register_mask;
                ((e ^ inv) & pfn_mask) >> 12
            }
            _ => mask_bits(e, self.p.maxphyaddr - 1, 0) >> 12,
        }
    }

    /// Read one table entry from the physical layer.
    #[inline(always)]
    fn read_entry(&self, addr: u64) -> Option<u64> {
        if let Some((ptr, len)) = self.phys_raw {
            let es = self.p.entry_size as u64;
            if addr.checked_add(es)? > len {
                return None;
            }
            unsafe {
                let p = (ptr as *const u8).add(addr as usize);
                return Some(if es == 8 {
                    u64::from_le((p as *const u64).read_unaligned())
                } else {
                    u32::from_le((p as *const u32).read_unaligned()) as u64
                });
            }
        }
        if self.p.entry_size == 8 {
            let mut b = [0u8; 8];
            self.phys.read(addr, &mut b).ok()?;
            Some(u64::from_le_bytes(b))
        } else {
            let mut b = [0u8; 4];
            self.phys.read(addr, &mut b).ok()?;
            Some(u32::from_le_bytes(b) as u64)
        }
    }

    /// python `_get_valid_table(base) is not None` (cached).
    #[inline]
    fn table_valid(&self, base: u64) -> bool {
        if let Some(v) = self.table_cache.get(base) {
            return v;
        }
        let v = self.compute_table_valid(base);
        self.table_cache.put(base, v);
        v
    }

    fn compute_table_valid(&self, base: u64) -> bool {
        let raw;
        let buf: &[u8] = if let Some((ptr, len)) = self.phys_raw {
            match base.checked_add(0x1000) {
                Some(end) if end <= len => unsafe { std::slice::from_raw_parts((ptr as *const u8).add(base as usize), 0x1000) },
                _ => return false,
            }
        } else {
            let mut b = vec![0u8; 0x1000];
            if self.phys.read(base, &mut b).is_err() {
                return false;
            }
            raw = b;
            &raw
        };
        let es = self.p.entry_size as usize;
        let first = &buf[..es];
        // table == table[:entry_size] * entry_number  -> invalid
        !buf.chunks_exact(es).all(|c| c == first)
    }

    /// python `_translate_entry(page_address)`: walk the tables; returns (entry, position).
    #[inline]
    fn translate_entry(&self, addr: u64) -> std::result::Result<(u64, u32), Fault> {
        self.translate_entry_ex(addr).map(|(e, p, _)| (e, p))
    }

    /// `translate_entry` that also returns the base of the table the final entry came from.
    #[inline]
    fn translate_entry_ex(&self, addr: u64) -> std::result::Result<(u64, u32, u64), Fault> {
        let mut position = self.initial_position;
        let mut entry = self.initial_entry;
        let mut last_base = 0;
        for &(size, large) in self.p.levels {
            if !self.entry_valid(entry) {
                return Err(Fault { invalid_bits: position + 1, entry, swap_offset: None });
            }
            let base = mask_bits(entry, self.p.maxphyaddr - 1, size + self.p.index_shift);
            if !self.table_valid(base) {
                return Err(Fault { invalid_bits: position + 1, entry, swap_offset: None });
            }
            let start = position;
            position -= size;
            let index = mask_bits(addr, start, position + 1) >> (position + 1);
            let e = match self.read_entry(base + (index << self.p.index_shift)) {
                Some(e) => e,
                None => return Err(Fault { invalid_bits: start + 1, entry, swap_offset: None }),
            };
            entry = e;
            last_base = base;
            if large && entry & (1 << 7) != 0 {
                if entry & (1 << 12) != 0 {
                    entry -= 1 << 12;
                }
                break;
            }
        }
        Ok((entry, position, last_base))
    }

    /// `translate_raw` for sequential walks: `cur` remembers the last page table reached
    /// (region key, table base), so consecutive 4 KiB pages under the same table only read
    /// their PTE. Semantics are identical to `translate_raw` (invalid PTEs take the full path
    /// for python's fault / swap handling).
    #[inline]
    fn translate_cursor(&self, addr: u64, cur: &mut (u64, u64)) -> std::result::Result<(u64, u32, Target), Fault> {
        let last_bits = self.p.levels[self.p.levels.len() - 1].0;
        let key = ((addr & self.vmask) >> (12 + last_bits)) + 1;
        if cur.0 == key {
            let idx = (addr >> 12) & ((1u64 << last_bits) - 1);
            if let Some(e) = self.read_entry(cur.1 + (idx << self.p.index_shift)) {
                if self.entry_valid(e) {
                    return Ok(((self.pte_pfn(e) << 12) | (addr & 0xfff), 12, Target::Phys));
                }
                // exactly what the full walk returns for an invalid PTE (position 11)
                let f = Fault { invalid_bits: 12, entry: e, swap_offset: None };
                return if self.flavor == PteFlavor::Windows { self.translate_swap(f) } else { Err(f) };
            }
        }
        let r = self.translate_entry_ex(addr & !0xfff).and_then(|(entry, position, base)| {
            if position == 11 {
                *cur = (key, base);
            }
            if !self.entry_valid(entry) {
                return Err(Fault { invalid_bits: position + 1, entry, swap_offset: None });
            }
            let pfn = self.pte_pfn(entry);
            let page = (pfn << 12) | mask_bits(addr, position, 0);
            Ok((page, position + 1, Target::Phys))
        });
        match r {
            Ok(v) => Ok(v),
            Err(f) if self.flavor == PteFlavor::Windows => self.translate_swap(f),
            Err(f) => Err(f),
        }
    }

    /// python `_translate` (with the Windows swap handling): physical address, log2 of the
    /// page size, and the target layer.
    #[inline]
    pub fn translate_raw(&self, addr: u64) -> std::result::Result<(u64, u32, Target), Fault> {
        let r = self.translate_entry(addr & !0xfff).and_then(|(entry, position)| {
            if !self.entry_valid(entry) {
                return Err(Fault { invalid_bits: position + 1, entry, swap_offset: None });
            }
            let pfn = self.pte_pfn(entry);
            let page = (pfn << 12) | mask_bits(addr, position, 0);
            Ok((page, position + 1, Target::Phys))
        });
        match r {
            Ok(v) => Ok(v),
            Err(f) if self.flavor == PteFlavor::Windows => self.translate_swap(f),
            Err(f) => Err(f),
        }
    }

    #[cold]
    fn translate_swap(&self, f: Fault) -> std::result::Result<(u64, u32, Target), Fault> {
        let entry = f.entry;
        let tbit = entry & (1 << 11) != 0;
        let pbit = entry & (1 << 10) != 0;
        let unknown = entry & (1 << 7) != 0;
        let vbit = entry & 1 != 0;
        let n = ((entry >> 1) & 0xf) as u8;
        let bit_offset = match self.mode {
            PagingMode::Intel32 => 12,
            PagingMode::Pae => 32,
            _ => self.p.bits_per_register / 2,
        };
        if !tbit && !pbit && !vbit && unknown && (entry >> bit_offset) != 0 {
            let swap_offset = (entry >> bit_offset).checked_shl(f.invalid_bits).unwrap_or(0);
            if (n as usize) < self.swap.len() {
                return Ok((swap_offset, f.invalid_bits, Target::Swap(n)));
            }
            return Err(Fault { swap_offset: Some(swap_offset), ..f });
        }
        Err(f)
    }

    #[inline(always)]
    fn target_layer(&self, t: Target) -> &dyn Layer {
        match t {
            Target::Phys => self.phys.as_ref(),
            Target::Swap(n) => self.swap[n as usize].as_ref(),
        }
    }

    #[inline(always)]
    fn target_valid(&self, t: Target, addr: u64, len: u64) -> bool {
        if t == Target::Phys {
            if let Some((_, flen)) = self.phys_raw {
                return addr.checked_add(len).is_some_and(|e| e <= flen);
            }
        }
        self.target_layer(t).is_valid(addr, len)
    }

    #[inline(always)]
    fn tlb_tag(&self, addr: u64) -> Option<u64> {
        if self.id >= (1 << (64 - TLB_ID_SHIFT)) - 1 {
            return None;
        }
        let vpn = (addr & self.vmask) >> 12;
        Some(((self.id as u64) << TLB_ID_SHIFT | vpn).wrapping_add(1))
    }

    /// Translate the 4 KiB page containing `addr` to a physical page base, when the whole
    /// physical page is valid in the physical layer (TLB-cached).
    #[inline]
    fn page_fast(&self, addr: u64) -> Option<u64> {
        let tag = self.tlb_tag(addr)?;
        let slot = ((tag ^ (tag >> 13)) as usize) & (TLB_SIZE - 1);
        let hit = TLB.with(|t| unsafe {
            let e = (*t.get())[slot];
            if e.0 == tag { Some(e.1) } else { None }
        });
        if hit.is_some() {
            return hit;
        }
        let (phys, _bits, target) = self.translate_raw(addr & !0xfff).ok()?;
        if target != Target::Phys || !self.target_valid(target, phys, 0x1000) {
            return None;
        }
        TLB.with(|t| unsafe {
            (*t.get())[slot] = (tag, phys);
        });
        Some(phys)
    }

    /// python `_mapping(offset, length, ignore_errors)` (without coalescing). `f(offset, len,
    /// mapped, target)` returns false to stop. With `ignore_errors == false` the first fault is
    /// returned as an error.
    fn walk<F>(&self, mut offset: u64, length: u64, ignore_errors: bool, mut f: F) -> Result<()>
    where
        F: FnMut(u64, u64, u64, Target) -> bool,
    {
        if length == 0 {
            match self.translate_raw(offset) {
                Ok((mapped, _, t)) if self.target_valid(t, mapped, 1) => {
                    f(offset, 0, mapped, t);
                }
                Ok((mapped, _, _)) => {
                    if !ignore_errors {
                        return Err(Error::invalid(mapped));
                    }
                }
                Err(fault) => {
                    if !ignore_errors {
                        return Err(fault_error(offset, fault));
                    }
                }
            }
            return Ok(());
        }
        let mut length = length as u128;
        let mut cur = (0u64, 0u64);
        while length > 0 {
            let skip_mask: u64;
            match self.translate_cursor(offset, &mut cur) {
                Ok((chunk_offset, bits, t)) => {
                    let page_size = 1u128 << bits;
                    let chunk_size = (page_size - (offset as u128 & (page_size - 1))).min(length) as u64;
                    if self.target_valid(t, chunk_offset, chunk_size) {
                        if !f(offset, chunk_size, chunk_offset, t) {
                            return Ok(());
                        }
                        length -= chunk_size as u128;
                        match offset.checked_add(chunk_size) {
                            Some(o) => offset = o,
                            None => return Ok(()),
                        }
                        continue;
                    }
                    if !ignore_errors {
                        return Err(Error::invalid(offset));
                    }
                    skip_mask = chunk_size - 1;
                }
                Err(fault) => {
                    if !ignore_errors {
                        return Err(fault_error(offset, fault));
                    }
                    skip_mask = if fault.invalid_bits >= 64 { u64::MAX } else { (1u64 << fault.invalid_bits) - 1 };
                }
            }
            let length_diff = skip_mask as u128 + 1 - (offset & skip_mask) as u128;
            if length_diff >= length {
                return Ok(());
            }
            length -= length_diff;
            match offset.checked_add(length_diff as u64) {
                Some(o) => offset = o,
                None => return Ok(()),
            }
        }
        Ok(())
    }

    /// python `mapping()` including swap targets: coalesced runs `(offset, len, mapped, target)`.
    pub fn mapping_with_targets(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping, Target) -> bool) {
        let mut stash: Option<(Mapping, Target)> = None;
        let mut stopped = false;
        let _ = self.walk(addr, len, true, |off, size, mapped, t| {
            if let Some((ref mut m, st)) = stash {
                if m.offset.wrapping_add(m.len) == off && m.mapped.wrapping_add(m.len) == mapped && st == t {
                    m.len += size;
                    return true;
                }
                let prev = (*m, st);
                stash = Some((Mapping { offset: off, len: size, mapped }, t));
                if !f(prev.0, prev.1) {
                    stopped = true;
                    return false;
                }
                return true;
            }
            stash = Some((Mapping { offset: off, len: size, mapped }, t));
            true
        });
        if !stopped {
            if let Some((m, t)) = stash {
                f(m, t);
            }
        }
    }

    /// Translate a virtual address like python `layer.translate(offset)`:
    /// (physical offset, target) or None.
    pub fn translate_addr(&self, addr: u64) -> Option<(u64, Target)> {
        match self.translate_raw(addr) {
            Ok((mapped, _, t)) if self.target_valid(t, mapped, 1) => Some((mapped, t)),
            _ => None,
        }
    }

    /// Read with python semantics; `pad` zero-fills unmapped parts instead of failing.
    fn read_impl(&self, addr: u64, buf: &mut [u8], pad: bool) -> Result<()> {
        // fast path: within one 4K page
        let len = buf.len();
        if len > 0 && (addr & 0xfff) as usize + len <= 0x1000 {
            if let Some(page) = self.page_fast(addr) {
                let pa = page + (addr & 0xfff);
                if let Some((ptr, _)) = self.phys_raw {
                    unsafe {
                        std::ptr::copy_nonoverlapping((ptr as *const u8).add(pa as usize), buf.as_mut_ptr(), len);
                    }
                    return Ok(());
                }
                return self.phys.read(pa, buf).or_else(|e| {
                    if pad {
                        buf.fill(0);
                        Ok(())
                    } else {
                        Err(e)
                    }
                });
            }
        }
        if pad {
            buf.fill(0);
        }
        let mut err = None;
        self.walk(addr, len as u64, pad, |off, size, mapped, t| {
            let start = (off - addr) as usize;
            let dst = &mut buf[start..start + size as usize];
            let r = if t == Target::Phys {
                if let Some((ptr, _)) = self.phys_raw {
                    unsafe {
                        std::ptr::copy_nonoverlapping((ptr as *const u8).add(mapped as usize), dst.as_mut_ptr(), dst.len());
                    }
                    Ok(())
                } else if pad {
                    self.phys.read_padded(mapped, dst);
                    Ok(())
                } else {
                    self.phys.read(mapped, dst)
                }
            } else if pad {
                self.target_layer(t).read_padded(mapped, dst);
                Ok(())
            } else {
                self.target_layer(t).read(mapped, dst)
            };
            if let Err(e) = r {
                err = Some(e);
                return false;
            }
            true
        })?;
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

fn fault_error(offset: u64, fault: Fault) -> Error {
    if fault.swap_offset.is_some() { Error::Swapped { addr: offset } } else { Error::InvalidAddress { addr: offset } }
}

impl Layer for IntelLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_address(&self) -> u64 {
        self.vmask
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        self.read_impl(addr, buf, false)
    }

    fn read_padded(&self, addr: u64, buf: &mut [u8]) {
        let _ = self.read_impl(addr, buf, true);
    }

    fn is_valid(&self, addr: u64, len: u64) -> bool {
        if len > 0 && (addr & 0xfff) + len <= 0x1000 && self.page_fast(addr).is_some() {
            return true;
        }
        self.walk(addr, len, false, |_, _, _, _| true).is_ok()
    }

    fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
        // Runs mapped to swap layers are omitted (the trait's `mapped` refers to `lower()`).
        self.mapping_with_targets(addr, len, &mut |m, t| if t == Target::Phys { f(m) } else { true });
    }

    fn lower(&self) -> Option<&Arc<dyn Layer>> {
        Some(&self.phys)
    }

    #[inline]
    fn slice(&self, addr: u64, len: usize) -> Option<&[u8]> {
        if len == 0 || (addr & 0xfff) as usize + len > 0x1000 {
            return None;
        }
        let page = self.page_fast(addr)?;
        self.phys.slice(page + (addr & 0xfff), len)
    }

    fn dtb(&self) -> Option<u64> {
        Some(self.dtb)
    }

    fn translate(&self, addr: u64) -> Option<(u64, u64)> {
        match self.translate_raw(addr) {
            Ok((mapped, bits, Target::Phys)) if self.target_valid(Target::Phys, mapped, 1) => {
                let ps = 1u128 << bits;
                Some((mapped, (ps - (addr as u128 & (ps - 1))) as u64))
            }
            _ => None,
        }
    }

    fn class_name(&self) -> &'static str {
        match (self.flavor, self.mode) {
            (PteFlavor::Generic, PagingMode::Intel32) => "Intel",
            (PteFlavor::Generic, PagingMode::Pae) => "IntelPAE",
            (PteFlavor::Generic, PagingMode::Intel32e) => "Intel32e",
            (PteFlavor::Generic, PagingMode::La57) => "IntelLA57",
            (PteFlavor::Windows, PagingMode::Intel32) => "WindowsIntel",
            (PteFlavor::Windows, PagingMode::Pae) => "WindowsIntelPAE",
            (PteFlavor::Windows, PagingMode::Intel32e) => "WindowsIntel32e",
            (PteFlavor::Windows, PagingMode::La57) => "WindowsIntelLA57",
            (PteFlavor::Linux, PagingMode::Intel32) => "LinuxIntel",
            (PteFlavor::Linux, PagingMode::Pae) => "LinuxIntelPAE",
            (PteFlavor::Linux, PagingMode::Intel32e) => "LinuxIntel32e",
            (PteFlavor::Linux, PagingMode::La57) => "LinuxIntelLA57",
        }
    }

    fn own_metadata(&self) -> Metadata {
        Metadata {
            os: self.os.clone(),
            architecture: Some(if self.p.bits_per_register == 64 { "Intel64" } else { "Intel32" }.to_string()),
            pae: if self.mode == PagingMode::Pae { Some(true) } else { None },
            page_map_offset: None,
            mapped: Some(true),
        }
    }

    fn dependencies(&self) -> Vec<Arc<dyn Layer>> {
        let mut v = vec![self.phys.clone()];
        v.extend(self.swap.iter().cloned());
        v
    }

    fn as_intel(&self) -> Option<&IntelLayer> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::LayerExt;

    /// A physical layer backed by a Vec.
    struct Buf(Vec<u8>);
    impl Layer for Buf {
        fn name(&self) -> &str {
            "buf"
        }
        fn max_address(&self) -> u64 {
            self.0.len() as u64 - 1
        }
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let a = addr as usize;
            match self.0.get(a..a + buf.len()) {
                Some(s) => {
                    buf.copy_from_slice(s);
                    Ok(())
                }
                None => Err(Error::invalid(addr)),
            }
        }
        fn is_valid(&self, addr: u64, len: u64) -> bool {
            addr + len <= self.0.len() as u64
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
            f(Mapping { offset: addr, len, mapped: addr });
        }
    }

    fn put(v: &mut [u8], at: usize, e: u64) {
        v[at..at + 8].copy_from_slice(&e.to_le_bytes());
    }

    /// Build a tiny x64 page table: PML4 at 0x1000, PDPT 0x2000, PD 0x3000, PT 0x4000.
    fn make() -> Arc<dyn Layer> {
        let mut m = vec![0u8; 0x20000];
        // make tables non-uniform by adding a dummy second entry
        put(&mut m, 0x1000, 0x2000 | 1); // PML4[0]
        put(&mut m, 0x1008, 0x9000 | 1);
        put(&mut m, 0x2000, 0x3000 | 1); // PDPT[0]
        put(&mut m, 0x2008, 0x9000 | 1);
        put(&mut m, 0x3000, 0x4000 | 1); // PD[0] -> PT
        put(&mut m, 0x3008, 0x200000 | 0x81); // PD[1] large page 2MB at phys 0x200000 (out of range)
        put(&mut m, 0x4000, 0x5000 | 1); // PT[0] -> page 0x5000 (VA 0)
        put(&mut m, 0x4008, 0x6000 | 1); // PT[1] -> page 0x6000 (VA 0x1000)
        put(&mut m, 0x4010, 0x8000); // PT[2] not present (VA 0x2000)
        put(&mut m, 0x4018, 0x7000 | (1 << 11)); // PT[3] transition (Windows valid) (VA 0x3000)
        m[0x5000] = 0xAA;
        m[0x6000] = 0xBB;
        m[0x7000] = 0xCC;
        Arc::new(Buf(m))
    }

    #[test]
    fn translate_basic() {
        let phys = make();
        let l = IntelLayer::new("t", phys.clone(), 0x1000, PagingMode::Intel32e, PteFlavor::Generic);
        assert_eq!(l.translate_addr(0x10), Some((0x5010, Target::Phys)));
        assert_eq!(l.translate_addr(0x1010), Some((0x6010, Target::Phys)));
        assert!(l.translate_addr(0x2000).is_none());
        assert!(l.translate_addr(0x3000).is_none()); // transition is not valid for generic
        let w = IntelLayer::new("w", phys.clone(), 0x1000, PagingMode::Intel32e, PteFlavor::Windows);
        assert_eq!(w.translate_addr(0x3004), Some((0x7004, Target::Phys)));
        let mut b = [0u8; 2];
        w.read(0xfff, &mut b).unwrap();
        assert_eq!(b, [0, 0xBB]);
        assert!(w.read(0x2fff, &mut b).is_err());
        w.read_padded(0x2fff, &mut b);
        assert_eq!(b, [0, 0xCC]);
        let mut b = [0u8; 1];
        w.read(0x1000, &mut b).unwrap();
        assert_eq!(b[0], 0xBB);
        // mapping coalesces nothing here (phys pages not contiguous: 0x5000,0x6000 are!)
        let ms = w.mappings(0, 0x5000);
        assert_eq!(ms, vec![Mapping { offset: 0, len: 0x2000, mapped: 0x5000 }, Mapping { offset: 0x3000, len: 0x1000, mapped: 0x7000 }]);
        // canonical addresses translate like their 48-bit truncation
        assert_eq!(w.translate_addr(0xffff_0000_0000_0010), Some((0x5010, Target::Phys)));
        // large page beyond the physical end is invalid
        assert!(!w.is_valid(0x200000, 1));
    }

    #[test]
    fn duplicate_tables_invalid() {
        let mut m = vec![0u8; 0x10000];
        // PML4 whose entries are all identical -> invalid table
        for i in 0..512 {
            put(&mut m, 0x1000 + i * 8, 0x2000 | 1);
        }
        let l = IntelLayer::new("t", Arc::new(Buf(m)), 0x1000, PagingMode::Intel32e, PteFlavor::Generic);
        assert!(l.translate_addr(0).is_none());
        assert!(l.mappings(0, 1 << 47).is_empty());
    }
}
