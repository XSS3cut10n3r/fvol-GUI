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

/// Cap on the number of runs one `mapping_with_targets` call emits. A valid address space maps
/// far fewer (the busiest, the Windows kernel, is ~330k runs); a count above this means the page
/// tables are corrupt -- a garbage page read as a page table makes the walk enumerate a
/// practically unbounded set of scattered pages. python enumerates them lazily and so hangs
/// forever (confirmed: `windows.memmap`/`windows.driverscan` on such a mutant run past a 120 s
/// timeout emitting nothing); a consumer that collects the runs (memmap, the scanner) instead
/// runs out of memory. The walk stops here, turning an OOM into a bounded, partial result
/// (DESIGN "never OOM on malformed memory"). ~16M is ~48x any real layer, so no valid mapping is
/// ever truncated.
const MAX_MAPPING_RUNS: u64 = 16 << 20;

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
        IntelLayer::with_table_cache(name, phys, dtb, mode, flavor, Arc::new(TableCache::new()))
    }

    /// `new` sharing an existing page-table validity cache (process layers share their
    /// parent's: allocating and zeroing a fresh 128 KiB one per process is wasted work).
    fn with_table_cache(name: &str, phys: Arc<dyn Layer>, dtb: u64, mode: PagingMode, flavor: PteFlavor, table_cache: Arc<TableCache>) -> IntelLayer {
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
            table_cache,
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

    /// `is_valid` without the TLB fast path (python's exact `_mapping` walk), for tests.
    #[cfg(test)]
    pub(crate) fn is_valid_exact(&self, addr: u64, len: u64) -> bool {
        self.walk(addr, len, false, |_, _, _, _| true).is_ok()
    }

    /// A process address space: same class/config/physical layer, different DTB
    /// (python `_add_process_layer`). Shares the page-table cache.
    pub fn process_layer(&self, dtb: u64, name: &str) -> IntelLayer {
        let mut l = IntelLayer::with_table_cache(name, self.phys.clone(), dtb, self.mode, self.flavor, self.table_cache.clone());
        l.swap = self.swap.clone();
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
        // segmented physical layers (ELF cores, LiME): zero-copy when the entry is file-backed
        if let Some(b) = self.phys.slice(addr, self.p.entry_size as usize) {
            return Some(if b.len() == 8 {
                u64::from_le_bytes(b.try_into().ok()?)
            } else {
                u32::from_le_bytes(b.try_into().ok()?) as u64
            });
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
        } else if let Some(b) = self.phys.slice(base, 0x1000) {
            b
        } else {
            let mut b = [0u8; 0x1000];
            if self.phys.read(base, &mut b).is_err() {
                return false;
            }
            raw = b;
            &raw
        };
        let es = self.p.entry_size as usize;
        // table == table[:entry_size] * entry_number  -> invalid; i.e. every entry equals the
        // next one: one (vectorized) compare of the table with itself shifted by an entry
        buf[es..] != buf[..buf.len() - es]
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
    pub fn translate_cursor(&self, addr: u64, cur: &mut (u64, u64)) -> std::result::Result<(u64, u32, Target), Fault> {
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

    /// python `Intel.is_dirty(offset)`: the dirty bit (bit 6) of the final paging entry of the
    /// page containing `addr` (the entry itself need not be present, like python).
    /// `Err(InvalidAddress)` where python's `_translate_entry` raises.
    pub fn is_dirty(&self, addr: u64) -> Result<bool> {
        let page = addr & !0xfff;
        match self.translate_entry(page) {
            Ok((entry, _)) => Ok(entry & (1 << 6) != 0),
            Err(f) => Err(fault_error(page, f)),
        }
    }

    /// python `_translate(addr)[1]` and `is_dirty(addr)` with one page-table walk, for
    /// sequential page loops (linux malfind's `_get_dirty_pages`): `(page size, dirty bit of
    /// the final entry)`, or the fault where python's `_translate` raises (every address of the
    /// aligned `1 << fault.invalid_bits` block containing `addr` faults the same way, so a loop
    /// may skip it). `cur` caches the last page table reached (start with `(0, 0)`), so
    /// consecutive 4 KiB pages under one table only read their PTE.
    pub fn page_dirty_cursor(&self, addr: u64, cur: &mut (u64, u64)) -> std::result::Result<(u64, bool), Fault> {
        let last_bits = self.p.levels[self.p.levels.len() - 1].0;
        let key = ((addr & self.vmask) >> (12 + last_bits)) + 1;
        if cur.0 == key {
            let idx = (addr >> 12) & ((1u64 << last_bits) - 1);
            if let Some(e) = self.read_entry(cur.1 + (idx << self.p.index_shift)) {
                if self.entry_valid(e) {
                    return Ok((0x1000, e & (1 << 6) != 0));
                }
                // exactly what the full walk returns for an invalid PTE (position 11)
                let f = Fault { invalid_bits: 12, entry: e, swap_offset: None };
                if self.flavor == PteFlavor::Windows {
                    let (_, bits, _) = self.translate_swap(f)?;
                    return Ok((1u64.checked_shl(bits).unwrap_or(0), e & (1 << 6) != 0));
                }
                return Err(f);
            }
        }
        let (entry, position, base) = self.translate_entry_ex(addr & !0xfff)?;
        if position == 11 {
            *cur = (key, base);
        }
        let dirty = entry & (1 << 6) != 0;
        if !self.entry_valid(entry) {
            let f = Fault { invalid_bits: position + 1, entry, swap_offset: None };
            if self.flavor == PteFlavor::Windows {
                let (_, bits, _) = self.translate_swap(f)?;
                return Ok((1u64.checked_shl(bits).unwrap_or(0), dirty));
            }
            return Err(f);
        }
        Ok((1u64.checked_shl(position + 1).unwrap_or(0), dirty))
    }

    /// python `_translate(offset)[1]`: the size of the (possibly large) page mapping `addr`.
    /// `Err(InvalidAddress)` where python raises (PagedInvalidAddressException).
    pub fn page_size_at(&self, addr: u64) -> Result<u64> {
        match self.translate_raw(addr) {
            Ok((_, bits, _)) => Ok(1u64.checked_shl(bits).unwrap_or(0)),
            Err(f) => Err(fault_error(addr, f)),
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

    /// `walk(offset, length, ignore_errors = true, f)` -- the same chunks in the same order --
    /// but visiting the page tables level by level: every table is read once, a faulting or
    /// skipped entry drops its whole block, and each leaf entry fully inside the range is one
    /// chunk. Blocks that start before the current offset or end past the range end (the
    /// partial first page, a large page cut by the range end, ...) take `walk`'s per-address
    /// step instead, so its skip arithmetic applies to them unchanged.
    fn walk_ranges<F>(&self, offset: u64, length: u64, f: F)
    where
        F: FnMut(u64, u64, u64, Target) -> bool,
    {
        if length == 0 {
            let _ = self.walk(offset, 0, true, f);
            return;
        }
        let end = (offset as u128 + length as u128).min(1u128 << 64);
        let swap = self.flavor == PteFlavor::Windows && !self.swap.is_empty();
        RangeWalk { l: self, off: offset, end, f, cur: (0, 0), swap }.run();
    }

    /// `[addr, addr + len)` split at the top-level page-table entries, with the entry of each
    /// piece. `mapping_with_targets(addr, len)` is the pieces' runs concatenated, with runs
    /// that are contiguous across a seam merged. A piece's runs only depend on (entry, start,
    /// len), so equal pieces (the kernel half every process maps) need to be walked only once.
    /// None when the range is empty or leaves the translated address space, or when the
    /// top-level table itself is invalid (nothing is mapped then).
    pub fn top_level_pieces(&self, addr: u64, len: u64) -> Option<Vec<TopPiece>> {
        let bits = self.initial_position + 1;
        let end = addr.checked_add(len)?;
        if len == 0 || (bits < 64 && end > 1u64 << bits) {
            return None;
        }
        let (size, _) = self.p.levels[0];
        let base = mask_bits(self.initial_entry, self.p.maxphyaddr - 1, size + self.p.index_shift);
        if !self.table_valid(base) {
            return None;
        }
        let sub_bits = bits - size;
        let mut v = Vec::new();
        let mut a = addr;
        while a < end {
            let idx = a >> sub_bits;
            let piece_end = ((idx + 1) << sub_bits).min(end);
            let entry = self.read_entry(base + (idx << self.p.index_shift))?;
            v.push(TopPiece { entry, start: a, len: piece_end - a });
            a = piece_end;
        }
        Some(v)
    }

    /// The 4 KiB page table at physical `base` straight from the mmapped file / a zero-copy
    /// slice (None: read entries one by one).
    #[inline]
    fn table_slice(&self, base: u64) -> Option<&[u8]> {
        if let Some((ptr, len)) = self.phys_raw {
            return match base.checked_add(0x1000) {
                Some(end) if end <= len => Some(unsafe { std::slice::from_raw_parts((ptr as *const u8).add(base as usize), 0x1000) }),
                _ => None,
            };
        }
        self.phys.slice(base, 0x1000)
    }

    /// python `mapping()` including swap targets: coalesced runs `(offset, len, mapped, target)`.
    pub fn mapping_with_targets(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping, Target) -> bool) {
        let mut stash: Option<(Mapping, Target)> = None;
        let mut stopped = false;
        let mut emitted = 0u64;
        self.walk_ranges(addr, len, |off, size, mapped, t| {
            if let Some((ref mut m, st)) = stash {
                if m.offset.wrapping_add(m.len) == off && m.mapped.wrapping_add(m.len) == mapped && st == t {
                    m.len += size;
                    return true;
                }
                let prev = (*m, st);
                stash = Some((Mapping { offset: off, len: size, mapped }, t));
                emitted += 1;
                // corrupt page tables can enumerate an unbounded number of runs (see
                // MAX_MAPPING_RUNS): stop before a consumer that collects them exhausts memory.
                if emitted > MAX_MAPPING_RUNS || !f(prev.0, prev.1) {
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

/// A piece of a range under one top-level page-table entry ([`IntelLayer::top_level_pieces`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TopPiece {
    /// the top-level entry
    pub entry: u64,
    pub start: u64,
    pub len: u64,
}

/// Outcome of visiting (part of) a page-table block in [`RangeWalk`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Flow {
    /// the block is done; carry on with the next one
    Next,
    /// the range is done, or `f` asked to stop
    Stop,
    /// the block at the current offset can't be taken wholesale: one per-address step
    Partial,
}

/// State of one [`IntelLayer::walk_ranges`] walk.
struct RangeWalk<'a, F> {
    l: &'a IntelLayer,
    /// everything below `off` is done
    off: u64,
    /// exclusive end of the range (at most 2^64; 0 once the walk is over)
    end: u128,
    f: F,
    /// `translate_cursor` state for the per-address steps
    cur: (u64, u64),
    /// invalid entries may map to a swap layer (Windows flavour with swap layers attached)
    swap: bool,
}

impl<F: FnMut(u64, u64, u64, Target) -> bool> RangeWalk<'_, F> {
    fn run(&mut self) {
        while (self.off as u128) < self.end {
            if self.fast() == Flow::Stop || (self.off as u128) >= self.end {
                return;
            }
            if !self.step() {
                return;
            }
        }
    }

    /// Whole blocks from the root, epoch by epoch (addresses above the virtual address width
    /// alias the ones below it, like python's index masking).
    fn fast(&mut self) -> Flow {
        let l = self.l;
        let bits = l.initial_position + 1;
        loop {
            if (self.off as u128) >= self.end {
                return Flow::Stop;
            }
            let vbase = self.off & !((1u64 << bits) - 1);
            match self.table(l.initial_entry, 0, l.initial_position, vbase) {
                Flow::Next => {}
                other => return other,
            }
        }
    }

    /// Everything up to `to` (exclusive, <= 2^64) is done.
    #[inline(always)]
    fn advance(&mut self, to: u128) -> Flow {
        if to >= self.end {
            self.end = 0;
            return Flow::Stop;
        }
        self.off = to as u64;
        Flow::Next
    }

    /// One iteration of `walk`'s per-address loop at `off`. False when the walk is over.
    fn step(&mut self) -> bool {
        let l = self.l;
        let offset = self.off;
        let length = self.end - offset as u128;
        let skip_mask: u64 = match l.translate_cursor(offset, &mut self.cur) {
            Ok((chunk_offset, bits, t)) => {
                let page_size = 1u128 << bits;
                let chunk_size = (page_size - (offset as u128 & (page_size - 1))).min(length) as u64;
                if l.target_valid(t, chunk_offset, chunk_size) {
                    if !(self.f)(offset, chunk_size, chunk_offset, t) {
                        return false;
                    }
                    return self.advance(offset as u128 + chunk_size as u128) == Flow::Next;
                }
                chunk_size - 1
            }
            Err(fault) => {
                if fault.invalid_bits >= 64 {
                    u64::MAX
                } else {
                    (1u64 << fault.invalid_bits) - 1
                }
            }
        };
        let length_diff = skip_mask as u128 + 1 - (offset & skip_mask) as u128;
        self.advance(offset as u128 + length_diff) == Flow::Next
    }

    /// The table that `entry` points to, covering `[vbase, vbase + 2^(pos+1))`; `off` lies in
    /// that block.
    fn table(&mut self, entry: u64, level: usize, pos: u32, vbase: u64) -> Flow {
        let l = self.l;
        if !l.entry_valid(entry) {
            return self.fault(entry, pos + 1, vbase);
        }
        let (size, large) = l.p.levels[level];
        let base = mask_bits(entry, l.p.maxphyaddr - 1, size + l.p.index_shift);
        if !l.table_valid(base) {
            return self.fault(entry, pos + 1, vbase);
        }
        let raw = l.table_slice(base);
        let shift = l.p.index_shift;
        let npos = pos - size;
        let sub_bits = npos + 1;
        let last = level + 1 == l.p.levels.len();
        let first = ((self.off - vbase) >> sub_bits) as usize;
        for idx in first..(1usize << size) {
            let at = idx << shift;
            let e = match raw {
                Some(t) if shift == 3 => u64::from_le_bytes(t[at..at + 8].try_into().unwrap()),
                Some(t) => u32::from_le_bytes(t[at..at + 4].try_into().unwrap()) as u64,
                None => match l.read_entry(base + at as u64) {
                    Some(e) => e,
                    None => return self.fault(entry, pos + 1, vbase),
                },
            };
            let sub = vbase + ((idx as u64) << sub_bits);
            let flow = if last {
                self.leaf(e, sub_bits, sub)
            } else if large && e & (1 << 7) != 0 {
                self.leaf(if e & (1 << 12) != 0 { e - (1 << 12) } else { e }, sub_bits, sub)
            } else {
                self.table(e, level + 1, npos, sub)
            };
            if flow != Flow::Next {
                return flow;
            }
        }
        Flow::Next
    }

    /// A final entry (PTE or large page) mapping `[vbase, vbase + 2^bits)`.
    #[inline(always)]
    fn leaf(&mut self, e: u64, bits: u32, vbase: u64) -> Flow {
        let l = self.l;
        if !l.entry_valid(e) {
            return self.fault(e, bits, vbase);
        }
        let block_end = vbase as u128 + (1u128 << bits);
        if vbase < self.off || block_end > self.end {
            return Flow::Partial;
        }
        let phys = l.pte_pfn(e) << 12;
        let size = 1u64 << bits;
        if l.target_valid(Target::Phys, phys, size) && !(self.f)(vbase, size, phys, Target::Phys) {
            return Flow::Stop;
        }
        self.advance(block_end)
    }

    /// A faulting entry (`invalid_bits == bits`) for the block at `vbase`: skipped, or a swap
    /// chunk (python `_translate_swap`).
    #[inline(always)]
    fn fault(&mut self, entry: u64, bits: u32, vbase: u64) -> Flow {
        let block_end = vbase as u128 + (1u128 << bits);
        if self.swap
            && entry != 0
            && let Ok((swap_offset, _, t)) = self.l.translate_swap(Fault { invalid_bits: bits, entry, swap_offset: None })
        {
            if vbase < self.off || block_end > self.end {
                return Flow::Partial;
            }
            let size = 1u64 << bits;
            if self.l.target_valid(t, swap_offset, size) && !(self.f)(vbase, size, swap_offset, t) {
                return Flow::Stop;
            }
        }
        self.advance(block_end)
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
        // TLB fast path: every 4 KiB page translating to a fully valid physical page implies
        // python's answer (all mapped chunks valid); anything else takes the exact walk.
        if len > 0 && len <= 64 * 0x1000 {
            if let Some(end) = addr.checked_add(len - 1) {
                let mut page = addr & !0xfff;
                while self.page_fast(page).is_some() {
                    if page >= end & !0xfff {
                        return true;
                    }
                    page += 0x1000;
                }
            }
        }
        self.walk(addr, len, false, |_, _, _, _| true).is_ok()
    }

    fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
        // Runs mapped to swap layers are omitted (the trait's `mapped` refers to `lower()`);
        // `mapping_targets` includes them.
        self.mapping_with_targets(addr, len, &mut |m, t| if t == Target::Phys { f(m) } else { true });
    }

    fn mapping_targets(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping, &dyn Layer) -> bool) {
        self.mapping_with_targets(addr, len, &mut |m, t| f(m, self.target_layer(t)));
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

// Used by the dump writers (vadinfo / PE dumps, `PeView`): kept as a separate block so the
// layer internals above stay untouched.
impl IntelLayer {
    /// The chunks a padded read of `[addr, addr + len)` copies, in order: `f(offset, size,
    /// mapped, target layer)` -- read_impl's single-page fast path, else python's
    /// `_mapping(offset, length, ignore_errors=True)` walk of the whole range, fault skips
    /// included. Every other byte of the read is zero. This is exactly `read(addr, len,
    /// pad=True)`, which is NOT the same as reading the range page by page (a large page whose
    /// physical range is only partly valid is skipped as a whole by the long read), nor as
    /// [`Layer::mapping_targets`]. `f` returns false to stop.
    pub fn padded_read_chunks(&self, addr: u64, len: u64, f: &mut dyn FnMut(u64, u64, u64, &dyn Layer) -> bool) {
        if len > 0 && (addr & 0xfff) + len <= 0x1000 {
            if let Some(page) = self.page_fast(addr) {
                f(addr, len, page + (addr & 0xfff), self.phys.as_ref());
                return;
            }
        }
        let _ = self.walk(addr, len, true, |off, size, mapped, t| f(off, size, mapped, self.target_layer(t)));
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

    fn put32(v: &mut [u8], at: usize, e: u32) {
        v[at..at + 4].copy_from_slice(&e.to_le_bytes());
    }

    #[test]
    fn intel32_pse_and_4k() {
        // PD at 0x1000 (1024 x 4-byte entries), PT at 0x2000
        let mut m = vec![0u8; 0x800000];
        put32(&mut m, 0x1000, 0x2000 | 1); // PDE[0] -> PT
        put32(&mut m, 0x1004, 0x400000 | 0x81); // PDE[1]: 4 MiB page at phys 0x400000
        put32(&mut m, 0x2000, 0x3000 | 1); // PTE[0] -> 0x3000
        put32(&mut m, 0x2004, 0x5000 | 1);
        m[0x3000] = 0x11;
        m[0x400123] = 0x22;
        let l = IntelLayer::new("t", Arc::new(Buf(m)), 0x1000, PagingMode::Intel32, PteFlavor::Generic);
        assert_eq!(l.translate_addr(0x10), Some((0x3010, Target::Phys)));
        assert_eq!(l.translate_addr(0x400123), Some((0x400123, Target::Phys)));
        assert_eq!(l.read_u8(0x400123).unwrap(), 0x22);
        assert_eq!(l.max_address(), 0xFFFF_FFFF);
        // a 4 MiB page coalesces into one run
        let ms = l.mappings(0x400000, 0x400000);
        assert_eq!(ms, vec![Mapping { offset: 0x400000, len: 0x400000, mapped: 0x400000 }]);
    }

    /// `page_dirty_cursor` + fault-block skipping == python's `_translate` / `is_dirty` loop
    /// stepping 4 KiB on every fault (linux malfind `_get_dirty_pages`).
    #[test]
    fn page_dirty_cursor_matches_python_loop() {
        let mut m = vec![0u8; 0x20000];
        put(&mut m, 0x1000, 0x2000 | 1); // PML4[0]
        put(&mut m, 0x1008, 0x9000 | 1);
        put(&mut m, 0x2000, 0x3000 | 1); // PDPT[0]
        put(&mut m, 0x2008, 0x9000 | 1);
        put(&mut m, 0x3000, 0x4000 | 1); // PD[0] -> PT
        put(&mut m, 0x3008, 0x200000 | 0x81 | 0x40); // PD[1]: dirty 2 MiB page
        put(&mut m, 0x3018, 0xa000 | 1); // PD[3] -> PT at 0xa000 (all zero: invalid table)
        put(&mut m, 0x4000, 0x5000 | 1); // VA 0
        put(&mut m, 0x4008, 0x6000 | 1 | 0x40); // VA 0x1000 dirty
        put(&mut m, 0x4010, 0x8000 | 0x40); // VA 0x2000 not present (dirty bit set)
        put(&mut m, 0x4028, 0x7000 | 1 | 0x40); // VA 0x5000 dirty
        let l = IntelLayer::new("t", Arc::new(Buf(m)), 0x1000, PagingMode::Intel32e, PteFlavor::Linux);
        let python = |start: u64, end: u64| {
            let mut out = Vec::new();
            let mut a = start;
            while a < end {
                let step = match l.page_size_at(a) {
                    Ok(s) => {
                        if l.is_dirty(a).unwrap() {
                            out.push((a, s));
                        }
                        s
                    }
                    Err(_) => 0x1000,
                };
                a += step;
            }
            out
        };
        let fast = |start: u64, end: u64| {
            let mut out = Vec::new();
            let mut cur = (0u64, 0u64);
            let mut a = start;
            while a < end {
                let step = match l.page_dirty_cursor(a, &mut cur) {
                    Ok((s, d)) => {
                        if d {
                            out.push((a, s));
                        }
                        s
                    }
                    Err(f) => {
                        let block_end = (a | ((1u64 << f.invalid_bits) - 1)) + 1;
                        (block_end.min(end) - a).div_ceil(0x1000).max(1) * 0x1000
                    }
                };
                a += step;
            }
            out
        };
        for (s, e) in [(0, 0x1000000), (0x1000, 0x800000), (0x3000, 0x8000_0000), (0x201000, 0x402000)] {
            assert_eq!(fast(s, e), python(s, e), "{s:#x}-{e:#x}");
        }
        assert_eq!(fast(0, 0x400000), vec![(0x1000, 0x1000), (0x5000, 0x1000), (0x200000, 0x200000)]);
    }

    #[test]
    fn la57_five_levels() {
        let mut m = vec![0u8; 0x10000];
        // PML5 0x1000 -> PML4 0x2000 -> PDPT 0x3000 -> PD 0x4000 -> PT 0x5000 -> page 0x6000
        for (t, next) in [(0x1000usize, 0x2000u64), (0x2000, 0x3000), (0x3000, 0x4000), (0x4000, 0x5000), (0x5000, 0x6000)] {
            put(&mut m, t, next | 1);
            put(&mut m, t + 8, 0x9000 | 1);
        }
        m[0x6123] = 0x44;
        let l = IntelLayer::new("t", Arc::new(Buf(m)), 0x1000, PagingMode::La57, PteFlavor::Generic);
        assert_eq!(l.max_address(), (1 << 57) - 1);
        assert_eq!(l.translate_addr(0x123), Some((0x6123, Target::Phys)));
        assert_eq!(l.read_u8(0x123).unwrap(), 0x44);
        // bit 48 selects PML5 entry 1 (-> 0x9000, a zero table) -> invalid
        assert!(l.translate_addr(1 << 48).is_none());
    }

    #[test]
    fn pae_three_levels() {
        // PDPT at 0x1020 (32-byte aligned, not page aligned); the 4096-byte "table" read from
        // it must not be uniform
        let mut m = vec![0u8; 0x10000];
        put(&mut m, 0x1020, 0x2000 | 1); // PDPTE[0] -> PD
        put(&mut m, 0x1028, 0x8000 | 1);
        put(&mut m, 0x2000, 0x3000 | 1); // PDE[0] -> PT
        put(&mut m, 0x2008, 0x9000 | 1);
        put(&mut m, 0x3000, 0x4000 | 1); // PTE[0]
        put(&mut m, 0x3008, 0x6000 | 1);
        m[0x4abc] = 0x33;
        let l = IntelLayer::new("t", Arc::new(Buf(m)), 0x1020, PagingMode::Pae, PteFlavor::Generic);
        assert_eq!(l.translate_addr(0xabc), Some((0x4abc, Target::Phys)));
        assert_eq!(l.read_u8(0xabc).unwrap(), 0x33);
        assert!(l.is_pae());
        assert_eq!(crate::layers::metadata(&l).pae, Some(true));
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

    type Chunk = (u64, u64, u64, Target);

    /// Chunks of the per-address walk (python `_mapping`, the reference).
    pub(crate) fn chunks_per_address(l: &IntelLayer, off: u64, len: u64) -> Vec<Chunk> {
        let mut v = Vec::new();
        let _ = l.walk(off, len, true, |o, s, m, t| {
            v.push((o, s, m, t));
            true
        });
        v
    }

    /// Chunks of the level-by-level walk.
    pub(crate) fn chunks_ranges(l: &IntelLayer, off: u64, len: u64) -> Vec<Chunk> {
        let mut v = Vec::new();
        l.walk_ranges(off, len, |o, s, m, t| {
            v.push((o, s, m, t));
            true
        });
        v
    }

    /// `mapping_with_targets` runs.
    fn runs_whole(l: &IntelLayer, off: u64, len: u64) -> Vec<(Mapping, Target)> {
        let mut v = Vec::new();
        l.mapping_with_targets(off, len, &mut |m, t| {
            v.push((m, t));
            true
        });
        v
    }

    /// The same from `top_level_pieces`: per-piece runs, merged across the seams.
    fn runs_by_pieces(l: &IntelLayer, off: u64, len: u64) -> Vec<(Mapping, Target)> {
        let Some(pieces) = l.top_level_pieces(off, len) else { return runs_whole(l, off, len) };
        let mut v: Vec<(Mapping, Target)> = Vec::new();
        for p in pieces {
            for (m, t) in runs_whole(l, p.start, p.len) {
                if let Some((pm, pt)) = v.last_mut()
                    && pm.offset.wrapping_add(pm.len) == m.offset
                    && pm.mapped.wrapping_add(pm.len) == m.mapped
                    && *pt == t
                {
                    pm.len += m.len;
                    continue;
                }
                v.push((m, t));
            }
        }
        v
    }

    /// A physical layer with holes: `hole(addr)` bytes are unreadable / invalid; `slice` is
    /// offered or not (zero-copy table path vs entry-by-entry reads).
    struct Holey {
        m: Vec<u8>,
        holes: bool,
        slices: bool,
    }
    impl Holey {
        fn hole(&self, a: u64) -> bool {
            // the upper half of every 7th page, and all of every 11th page
            let p = a >> 12;
            self.holes && ((p % 7 == 3 && a & 0x800 != 0) || p % 11 == 5)
        }
    }
    impl Layer for Holey {
        fn name(&self) -> &str {
            "holey"
        }
        fn max_address(&self) -> u64 {
            self.m.len() as u64 - 1
        }
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            if !self.is_valid(addr, buf.len() as u64) {
                return Err(Error::invalid(addr));
            }
            buf.copy_from_slice(&self.m[addr as usize..addr as usize + buf.len()]);
            Ok(())
        }
        fn is_valid(&self, addr: u64, len: u64) -> bool {
            let Some(end) = addr.checked_add(len) else { return false };
            if end > self.m.len() as u64 {
                return false;
            }
            if !self.holes {
                return true;
            }
            let mut a = addr & !0x7ff;
            while a < end.max(addr + 1) {
                if self.hole(a.max(addr)) {
                    return false;
                }
                a += 0x800;
            }
            true
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
            f(Mapping { offset: addr, len, mapped: addr });
        }
        fn slice(&self, addr: u64, len: usize) -> Option<&[u8]> {
            if self.slices && self.is_valid(addr, len as u64) { Some(&self.m[addr as usize..addr as usize + len]) } else { None }
        }
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Random sparse page tables: `ntables` 4 KiB tables at pages 1.., a few entries each
    /// (pointers to other tables incl. themselves, 4 KiB / large frames in and out of range,
    /// transition / prototype / swap-looking / PROT_NONE entries), plus a uniform table.
    fn random_memory(rng: &mut Rng, es: usize, ntables: u64, npages: u64) -> Vec<u8> {
        let mut m = vec![0u8; (npages << 12) as usize];
        for p in npages - 16..npages {
            for b in 0..4096u64 {
                m[((p << 12) + b) as usize] = (p * 31 + b) as u8;
            }
        }
        let uniform = ntables; // page `ntables` is a uniform (invalid) table
        for i in 0..(4096 / es) {
            let at = ((uniform << 12) as usize) + i * es;
            m[at..at + es].copy_from_slice(&0x3003u64.to_le_bytes()[..es]);
        }
        for t in 1..ntables {
            let n = 1 + rng.below(6);
            for _ in 0..n {
                let idx = if rng.below(3) == 0 { rng.below(4) } else { rng.below((4096 / es) as u64) };
                let target_page = 1 + rng.below(ntables + 1);
                let frame = match rng.below(6) {
                    0 => npages - 16 + rng.below(16), // data pages
                    1 => rng.below(npages * 2),       // may be out of range
                    2 => rng.below(1 << 20),          // far away
                    3 => rng.below(2) << 9,           // 2 MiB aligned (large pages in range)
                    4 => rng.below(2) << 10,          // 4 MiB aligned
                    _ => target_page,
                };
                let e: u64 = match rng.below(12) {
                    0..=3 => (target_page << 12) | 1 | (rng.below(2) << 6),
                    4 => (frame << 12) | 0x81 | (rng.below(2) << 12),  // large (PAT maybe)
                    5 => (frame << 12) | 1,
                    6 => (frame << 12) | (1 << 11),                   // transition
                    7 => (frame << 12) | (1 << 11) | (1 << 10),       // prototype
                    8 => (rng.below(64) << 32) | 0x80 | (rng.below(5) << 1), // swap-looking (x64 / PAE)
                    9 => (rng.below(1024) << 12) | 0x80 | (rng.below(5) << 1), // swap-looking (32-bit)
                    10 => !((frame << 12) | 0xfff) | 0x100,          // PROT_NONE, inverted pfn
                    _ => rng.next(),
                };
                let at = ((t << 12) as usize) + (idx as usize) * es;
                m[at..at + es].copy_from_slice(&e.to_le_bytes()[..es]);
            }
        }
        m
    }

    /// The level-by-level walk yields exactly the per-address walk's chunks, for every paging
    /// mode / PTE flavour, holey and plain physical layers, swap layers, whole address spaces
    /// and random (unaligned, wrapping, huge) ranges.
    #[test]
    fn walk_ranges_matches_per_address_walk() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let (mut checked, mut swapped, mut large, mut partial) = (0usize, 0usize, 0usize, 0usize);
        for round in 0..48 {
            for mode in [PagingMode::Intel32, PagingMode::Pae, PagingMode::Intel32e, PagingMode::La57] {
                let es = if mode == PagingMode::Intel32 { 4 } else { 8 };
                let ntables = 24;
                let npages = 1100;
                let mem = random_memory(&mut rng, es, ntables, npages);
                let holes = round % 2 == 1;
                let slices = round % 3 != 0;
                let phys: Arc<dyn Layer> = Arc::new(Holey { m: mem, holes, slices });
                let swap: Arc<dyn Layer> = Arc::new(Holey { m: vec![0x5a; 1 << 22], holes: true, slices: true });
                let dtb = if mode == PagingMode::Pae { (1 << 12) + 32 * rng.below(4) } else { 1 << 12 };
                for flavor in [PteFlavor::Generic, PteFlavor::Windows, PteFlavor::Linux] {
                    let mut l = IntelLayer::new("t", phys.clone(), dtb, mode, flavor);
                    if flavor == PteFlavor::Windows && round % 4 < 2 {
                        l = l.with_swap(vec![swap.clone(), swap.clone(), swap.clone()]);
                    }
                    let max = l.max_address();
                    let mut ranges = vec![(0u64, max), (0, max.wrapping_add(1).max(max)), (1 << 12, 1 << 20)];
                    for _ in 0..24 {
                        let start = match rng.below(5) {
                            0 => rng.below(max),
                            1 => rng.below(max) & !0xfff,
                            2 => rng.next(),
                            3 => u64::MAX - rng.below(1 << 24),
                            _ => rng.below(1 << 24),
                        };
                        let len = match rng.below(5) {
                            0 => rng.below(1 << 14),
                            1 => rng.below(1 << 24),
                            2 => rng.next(),
                            3 => (rng.below(64) + 1) << 12,
                            _ => rng.below(max),
                        };
                        // at most ~3 laps of the (aliasing) address space
                        ranges.push((start, len.min(max.saturating_mul(3))));
                    }
                    // ranges starting / ending inside mapped chunks (partial pages, cut large pages)
                    let all = chunks_per_address(&l, 0, max);
                    for _ in 0..24 {
                        if all.is_empty() {
                            break;
                        }
                        let c = all[rng.below(all.len() as u64) as usize];
                        let s = c.0 + rng.below(c.1.max(1));
                        let n = match rng.below(3) {
                            0 => rng.below(c.1.max(1)),
                            1 => rng.below(1 << 22),
                            _ => all[rng.below(all.len() as u64) as usize].0.wrapping_sub(s).min(max),
                        };
                        ranges.push((s, n));
                    }
                    for (s, n) in ranges {
                        let want = chunks_per_address(&l, s, n);
                        let got = chunks_ranges(&l, s, n);
                        assert_eq!(got, want, "round {round} {mode:?} {flavor:?} holes={holes} range {s:#x}+{n:#x}");
                        checked += want.len();
                        swapped += want.iter().filter(|c| c.3 != Target::Phys).count();
                        large += want.iter().filter(|c| c.1 > 0x1000).count();
                        partial += want.iter().filter(|c| c.1 & 0xfff != 0 || c.0 & 0xfff != 0).count();
                        assert_eq!(runs_by_pieces(&l, s, n), runs_whole(&l, s, n), "pieces: round {round} {mode:?} {flavor:?} range {s:#x}+{n:#x}");
                    }
                }
            }
        }
        assert!(checked > 10_000 && swapped > 100 && large > 100 && partial > 100, "{checked} {swapped} {large} {partial}");
    }

    /// The kernel layer and every process layer of an image.
    fn image_layers(image: &str) -> (Vec<(String, &'static IntelLayer)>, &'static crate::context::Context) {
        use crate::context::{Context, GlobalOptions};
        let opts = GlobalOptions {
            file: Some(image.to_string()),
            symbol_dirs: vec!["/home/user/rs-vol/testdata/symbols".into()],
            ..Default::default()
        };
        let ctx: &'static Context = Box::leak(Box::new(Context::new(opts).unwrap()));
        let mut v: Vec<(String, &'static IntelLayer)> = Vec::new();
        if let Ok(k) = ctx.windows_kernel() {
            use crate::symbols::windows::WinExt;
            v.push(("kernel".into(), k.layer));
            let filter = crate::plugins::windows::pslist::pid_filter(&[]);
            for p in crate::plugins::windows::pslist::list_processes(k, &filter).into_iter().flatten() {
                if let (Ok(pid), Ok(l)) = (p.m("UniqueProcessId").and_then(|x| x.int()), p.add_process_layer()) {
                    v.push((format!("pid {pid}"), l.as_intel().unwrap()));
                }
            }
        } else if let Ok(k) = ctx.linux_kernel() {
            use crate::symbols::linux::ext::LinuxExt;
            v.push(("kernel".into(), k.layer));
            let _ = crate::plugins::linux::pslist::list_tasks(k, &|_| Ok(false), false, &mut |t| {
                if let (Ok(pid), Ok(Some(l))) = (t.m("pid").and_then(|x| x.int()), t.add_process_layer()) {
                    v.push((format!("pid {pid}"), l.as_intel().unwrap()));
                }
                Ok(true)
            });
        } else {
            use crate::symbols::mac::MacExt;
            let k = ctx.mac_kernel().unwrap();
            v.push(("kernel".into(), k.layer));
            for p in crate::plugins::mac::pslist::list_tasks_allproc(k, &|_| Ok(false)).into_iter().flatten() {
                if let (Ok(pid), Ok(Some(l))) = (p.m("p_pid").and_then(|x| x.int()), p.add_process_layer()) {
                    v.push((format!("pid {pid}"), l.as_intel().unwrap()));
                }
            }
        }
        // one layer per distinct page table root
        let mut seen = std::collections::HashSet::new();
        v.retain(|(_, l)| seen.insert(l.page_map_offset()));
        (v, ctx)
    }

    /// Whole-address-space (and random sub-range) equivalence of the level-by-level walk with
    /// the per-address walk on the real test images, for the kernel and every process:
    ///   bench/scripts/cargo.sh test --profile fast walk_ranges_images -- --ignored --nocapture
    #[test]
    #[ignore]
    fn walk_ranges_images() {
        let images = [
            "/home/user/cbc2/task2/memory-dirty.raw",
            "/home/user/rs-vol/testdata/images/windows/rsvol-win10-x64-17763-imagery.raw",
            "/home/user/rs-vol/testdata/images/linux/rsvol-noble-6.8.0-139.elf",
            "/home/user/rs-vol/testdata/images/linux/rsvol-noble-6.8.0-139.lime",
            "/home/user/rs-vol/testdata/images/linux/rsvol-jammy-5.15.0-191.elf",
            "/home/user/rs-vol/testdata/images/linux/rsvol-jammy-5.15.0-191.lime",
            "/home/user/rs-vol/testdata/images/mac/rsvol-mac-mavericks-10.9.2-13C64.dmp",
        ];
        for image in images {
            let t0 = std::time::Instant::now();
            let (layers, _ctx) = image_layers(image);
            let results = crate::util::par::par_map_bounded(layers.len(), 6, |i| {
                let (name, l) = &layers[i];
                let max = l.max_address();
                let mut rng = Rng(0x1234_5678 ^ (i as u64 + 1) * 0x9e37_79b9);
                // (count, hash) of the chunk stream + a reservoir sample of chunks
                let digest = |walk: &dyn Fn(&mut dyn FnMut(Chunk))| {
                    let (mut n, mut h) = (0usize, 0u64);
                    walk(&mut |c: Chunk| {
                        n += 1;
                        h = (h ^ crate::util::fxhash::hash_u64(c.0 ^ c.1.rotate_left(17) ^ c.2.rotate_left(34) ^ matches!(c.3, Target::Phys) as u64)).rotate_left(5).wrapping_mul(0x100000001b3);
                    });
                    (n, h)
                };
                let t = std::time::Instant::now();
                let mut sample: Vec<Chunk> = Vec::new();
                let mut seen = 0u64;
                let fast = digest(&|g| {
                    l.walk_ranges(0, max, |o, s, m, tg| {
                        g((o, s, m, tg));
                        true
                    })
                });
                let t1 = t.elapsed();
                l.walk_ranges(0, max, |o, s, m, tg| {
                    seen += 1;
                    if sample.len() < 256 {
                        sample.push((o, s, m, tg));
                    } else {
                        let j = rng.below(seen);
                        if j < 256 {
                            sample[j as usize] = (o, s, m, tg);
                        }
                    }
                    true
                });
                let t = std::time::Instant::now();
                let slow = digest(&|g| {
                    let _ = l.walk(0, max, true, |o, s, m, tg| {
                        g((o, s, m, tg));
                        true
                    });
                });
                let t2 = t.elapsed();
                let mut first_diff = if fast != slow { Some(format!("whole space: {fast:?} vs per-address {slow:?}")) } else { None };
                if first_diff.is_none() && runs_by_pieces(l, 0, max) != runs_whole(l, 0, max) {
                    first_diff = Some("top-level pieces".into());
                }
                // random sub-ranges starting / ending inside chunks
                for _ in 0..64 {
                    if sample.is_empty() || first_diff.is_some() {
                        break;
                    }
                    let c = sample[rng.below(sample.len() as u64) as usize];
                    let s = c.0 + rng.below(c.1.max(1));
                    let e = sample[rng.below(sample.len() as u64) as usize];
                    let n = match rng.below(3) {
                        0 => rng.below(1 << 24),
                        1 => e.0.wrapping_add(rng.below(e.1.max(1))).wrapping_sub(s).min(1 << 36),
                        _ => rng.below(1 << 40),
                    };
                    let (a, b) = (chunks_ranges(l, s, n), chunks_per_address(l, s, n));
                    if a != b {
                        first_diff = Some(format!("range {s:#x}+{n:#x}: {} vs {} chunks", a.len(), b.len()));
                    }
                }
                (name.clone(), fast.0, t1, t2, first_diff)
            });
            let total: usize = results.iter().map(|r| r.1).sum();
            let (fast, slow) = results.iter().fold((0.0, 0.0), |(a, b), r| (a + r.2.as_secs_f64(), b + r.3.as_secs_f64()));
            eprintln!(
                "{image}: {} layers, {total} chunks, walk_ranges {:.3}s vs per-address {:.3}s (cpu), {:.1}s",
                results.len(),
                fast,
                slow,
                t0.elapsed().as_secs_f64()
            );
            let bad: Vec<String> = results.iter().filter_map(|r| r.4.as_ref().map(|d| format!("{} {}", r.0, d))).collect();
            assert!(bad.is_empty(), "{image}: {}", bad.join("\n"));
        }
    }
}
