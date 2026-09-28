//! Windows automagic: DTB discovery (python `automagic/windows.py` WindowsIntelStacker +
//! PageMapScanner) and kernel PDB / base discovery (python `automagic/pdbscan.py`
//! KernelPDBScanner, `pdbutil.pdbname_scan`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::error::{Error, Result};
use crate::layers::scan::{BytesScanner, MultiStringScanner, Scanner, scan, scan_each};
use crate::layers::{IntelLayer, Layer, LayerExt, PagingMode, PteFlavor, metadata};
use crate::symbols::windows::pdb::{find_mz_before, guid_string, rsds_search};
use std::sync::Arc;

// ------------------------------------------------------------------------------------------
// DTB tests (python DtbSelfReferential & friends)
// ------------------------------------------------------------------------------------------

/// python `DtbSelfRef64bit` / `DtbSelfRefPae` / `DtbSelfRef32bit` / `DtbSelfRef64bitOldWindows`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DtbTest {
    SelfRef64,
    Pae,
    SelfRef32,
    SelfRef64Old,
}

impl DtbTest {
    fn ptr_size(self) -> usize {
        if self == DtbTest::SelfRef32 { 4 } else { 8 }
    }
    fn mask(self) -> u64 {
        if self == DtbTest::SelfRef32 { 0xFFFF_F000 } else { 0x3F_FFFF_FFFF_F000 }
    }
    fn reserved(self) -> u64 {
        match self {
            DtbTest::SelfRef64 | DtbTest::SelfRef64Old => 0x80,
            _ => 0,
        }
    }
    fn in_range(self, idx: u64) -> bool {
        match self {
            DtbTest::SelfRef64 => (0x100..0x1FF).contains(&idx),
            DtbTest::SelfRef64Old => idx == 0x1ED,
            DtbTest::Pae => idx == 3,
            DtbTest::SelfRef32 => idx == 0x300,
        }
    }
    /// The layer class python constructs for this test.
    pub fn mode(self) -> PagingMode {
        match self {
            DtbTest::SelfRef64 | DtbTest::SelfRef64Old => PagingMode::Intel32e,
            DtbTest::Pae => PagingMode::Pae,
            DtbTest::SelfRef32 => PagingMode::Intel32,
        }
    }
    fn layer_max(self) -> u64 {
        match self.mode() {
            PagingMode::Intel32e => (1 << 48) - 1,
            _ => (1 << 32) - 1,
        }
    }

    /// python `DtbSelfReferential.__call__` (+ the PAE override). `Err(())` = python would
    /// raise (a partial page makes `struct.unpack` fail, aborting the whole scan).
    fn test(self, data: &[u8], data_offset: u64, page_offset: usize) -> std::result::Result<Option<u64>, ()> {
        let page = &data[page_offset..(page_offset + 0x1000).min(data.len())];
        if page.is_empty() {
            return Ok(None);
        }
        let ps = self.ptr_size();
        let here = data_offset.wrapping_add(page_offset as u64);
        let mut ref_count = 0usize;
        let mut ref_page = 0usize;
        let mut r = 0usize;
        while r < 0x1000 {
            if r + ps > page.len() {
                return Err(());
            }
            let ptr = if ps == 8 { u64::from_le_bytes(page[r..r + 8].try_into().unwrap()) } else { u32::from_le_bytes(page[r..r + 4].try_into().unwrap()) as u64 };
            if ptr & self.reserved() != 0 && ptr & 1 != 0 {
                return Ok(None);
            }
            if (ptr & self.mask()) == here && here > 0 && ptr & 1 != 0 {
                // set semantics: each ref index counted once
                ref_count += 1;
                ref_page = r;
            }
            r += ps;
        }
        if ref_count != 1 || !self.in_range((ref_page / ps) as u64) {
            return Ok(None);
        }
        if self != DtbTest::Pae {
            return Ok(Some(here));
        }
        // PAE: the top page (dtb - 0x4000) must map the next four pages
        let top = here.wrapping_sub(0x4000);
        let start = top as i128 - data_offset as i128;
        let slice = py_slice(data, start, start + 32);
        let mut expected = Vec::with_capacity(32);
        for i in 1..5u64 {
            expected.extend_from_slice(&top.wrapping_add(i * 0x1000).to_le_bytes());
        }
        // _and_bytes(page_table, mask) pairs bytes from the END (zip of reversed sequences)
        let mask: Vec<u8> = [0x00, 0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff].repeat(4);
        let n = slice.len().min(mask.len());
        let anded: Vec<u8> = (0..n).map(|k| slice[slice.len() - n + k] & mask[mask.len() - n + k]).collect();
        if anded == expected { Ok(Some(top)) } else { Ok(None) }
    }
}

/// python `bytes[start:end]` slicing semantics with possibly negative indexes.
fn py_slice(data: &[u8], start: i128, end: i128) -> &[u8] {
    let len = data.len() as i128;
    let norm = |i: i128| -> i128 {
        if i < 0 { (len + i).max(0) } else { i.min(len) }
    };
    let (s, e) = (norm(start), norm(end));
    if s >= e { &[] } else { &data[s as usize..e as usize] }
}

#[derive(Clone, Copy, Debug)]
enum DtbHit {
    Hit(DtbTest, u64),
    Abort,
}

struct PageMapScanner {
    tests: &'static [DtbTest],
}

impl Scanner for PageMapScanner {
    type Hit = DtbHit;
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<DtbHit>) {
        let mut po = 0usize;
        while po < data.len() {
            for &t in self.tests {
                match t.test(data, data_offset, po) {
                    Ok(Some(dtb)) => hits.push(DtbHit::Hit(t, dtb)),
                    Ok(None) => {}
                    Err(()) => {
                        // python: the exception discards this chunk's results and ends the scan
                        hits.clear();
                        hits.push(DtbHit::Abort);
                        return;
                    }
                }
            }
            po += 0x1000;
        }
    }
}

/// python `WindowsIntelStacker.test_sets`.
const TEST_SETS: &[(&[DtbTest], &[(u64, u64)])] = &[
    (&[DtbTest::SelfRef64], &[(0x150000, 0x150000), (0x550000, 0x1A0000), (0x900000, 0x100000)]),
    (&[DtbTest::Pae, DtbTest::SelfRef32, DtbTest::SelfRef64Old], &[(0x30000, 0x1000000)]),
    (&[DtbTest::SelfRef64], &[(0xA00000, 0x5000000)]),
];

const KUSER_USER: u64 = 0x7FFE_0000;
const KUSER_NTMAJOR_OFF: u64 = 0x26C;

/// python `Intel32LayerCheck.check` / `Intel64LayerCheck.check`.
fn layer_check(layer: &IntelLayer) -> bool {
    let kuser_kernel: u64 = if layer.mode() == PagingMode::Intel32e || layer.mode() == PagingMode::La57 { 0xFFFF_F780_0000_0000 } else { 0xFFDF_0000 };
    let mut kaddr = None;
    if let Ok((k, _, _)) = layer.translate_raw(kuser_kernel) {
        kaddr = Some(k);
        if let Ok((u, _, _)) = layer.translate_raw(KUSER_USER) {
            if k != 0 && k == u {
                return true;
            }
        }
    }
    if kaddr.is_some() {
        let mut b = [0u8; 4];
        layer.read_padded(kuser_kernel + KUSER_NTMAJOR_OFF, &mut b);
        if [3u32, 4, 5, 6, 10].contains(&u32::from_le_bytes(b)) {
            return true;
        }
    }
    false
}

/// Result of the Windows stacker: DTB and paging mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DtbResult {
    pub dtb: u64,
    pub mode: PagingMode,
}

/// python `WindowsIntelStacker.stack(context, physical)`: find the DTB.
pub fn find_dtb(phys: &Arc<dyn Layer>) -> Result<Option<DtbResult>> {
    if phys.as_intel().is_some() {
        return Ok(None);
    }
    let md = metadata(phys.as_ref());
    let os = md.os.clone().unwrap_or_else(|| "Unknown".into());
    if os != "Windows" && os != "Unknown" {
        return Ok(None);
    }
    if os == "Windows" {
        if let Some(pmo) = md.page_map_offset.filter(|p| *p != 0) {
            let arch = md.architecture.clone().unwrap_or_default();
            let mode = match arch.as_str() {
                "Intel64" => PagingMode::Intel32e,
                "Intel32" => {
                    if md.pae.unwrap_or(false) {
                        PagingMode::Pae
                    } else {
                        PagingMode::Intel32
                    }
                }
                _ => return Ok(None),
            };
            return Ok(Some(DtbResult { dtb: pmo, mode }));
        }
    }
    let phys_max = phys.max_address();
    for (tests, sections) in TEST_SETS {
        let scanner = PageMapScanner { tests };
        let mut hits: Vec<(DtbTest, u64)> = Vec::new();
        scan_each(phys.as_ref(), &scanner, Some(sections), |h| match h {
            DtbHit::Hit(t, o) => {
                hits.push((t, o));
                true
            }
            DtbHit::Abort => false,
        });
        // sort by (test index, offset), stable
        hits.sort_by_key(|(t, o)| (tests.iter().position(|x| x == t).unwrap_or(0), *o));
        for (test, pmo) in hits {
            let table = phys.read_vec(pmo, 0x1000)?;
            let ps = test.ptr_size();
            let mut max_ptr: u64 = 0;
            for c in table.chunks_exact(ps) {
                let p = if ps == 8 { u64::from_le_bytes(c.try_into().unwrap()) } else { u32::from_le_bytes(c.try_into().unwrap()) as u64 };
                if p & 1 != 0 && p & 0x80 == 0 {
                    let v = (p ^ (p & 0xFFF)) % test.layer_max();
                    max_ptr = max_ptr.max(v);
                }
            }
            if max_ptr <= phys_max {
                let tmp = IntelLayer::new("IntelLayer", phys.clone(), pmo, test.mode(), PteFlavor::Windows);
                if !layer_check(&tmp) {
                    continue;
                }
                return Ok(Some(DtbResult { dtb: pmo, mode: test.mode() }));
            }
        }
    }
    Ok(None)
}

// ------------------------------------------------------------------------------------------
// PDB scanning (python pdbutil.PdbSignatureScanner / pdbname_scan, automagic/pdbscan.py)
// ------------------------------------------------------------------------------------------

/// python `constants.windows.KERNEL_MODULE_NAMES` + ".pdb".
pub const KERNEL_PDB_NAMES: [&[u8]; 4] = [b"ntkrnlmp.pdb", b"ntkrnlpa.pdb", b"ntkrpamp.pdb", b"ntoskrnl.pdb"];

/// A found RSDS record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdbSig {
    pub guid: String,
    pub age: u32,
    pub pdb_name: String,
    pub signature_offset: u64,
    pub mz_offset: Option<u64>,
}

/// python `PdbSignatureScanner.overlap`.
pub const PDB_SCANNER_OVERLAP: u64 = 0x4000;

/// python `PdbSignatureScanner`: `RSDS` + 20 bytes + one of `names` + NUL (regex finditer,
/// non-overlapping).
pub struct PdbSignatureScanner {
    pub names: Vec<Vec<u8>>,
}

impl Scanner for PdbSignatureScanner {
    type Hit = (String, u32, String, u64);
    fn overlap(&self) -> u64 {
        PDB_SCANNER_OVERLAP
    }
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<Self::Hit>) {
        let cs = (self.chunk_size() as usize).min(data.len());
        rsds_search(&self.names, data, 0, cs, |p, k| {
            let b = &data[p + 4..p + 24];
            let age = u32::from_le_bytes(b[16..20].try_into().unwrap());
            hits.push((guid_string(&b[..16]), age, String::from_utf8_lossy(&self.names[k as usize]).into_owned(), data_offset + p as u64));
        });
    }
}

/// [`PdbSignatureScanner`] in the executor's two-phase / streaming form: hits are
/// `(offset, name index)`; the GUID and age are read back from the layer (the same bytes the
/// chunk held). Lets the physical and virtual scans read small cache-resident pieces and
/// search aliased pages once.
pub struct RsdsScanner {
    pub names: Vec<Vec<u8>>,
}

impl Scanner for RsdsScanner {
    type Hit = (u64, u32);
    fn overlap(&self) -> u64 {
        PDB_SCANNER_OVERLAP
    }
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<(u64, u32)>) {
        let cs = (self.chunk_size() as usize).min(data.len());
        rsds_search(&self.names, data, 0, cs, |p, k| hits.push((data_offset + p as u64, k)));
    }
    fn prescan(&self, data: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
        self.scan(data, 0, out);
        true
    }
    fn finish(&self, matches: &[(u64, u32)], data_offset: u64, hits: &mut Vec<(u64, u32)>) {
        hits.extend(matches.iter().map(|&(o, k)| (data_offset + o, k)));
    }
    fn stream_window(&self) -> Option<usize> {
        Some(25 + self.names.iter().map(|n| n.len()).max().unwrap_or(0))
    }
    fn prescan_piece(&self, data: &[u8], base: u64, from: usize, limit: usize, out: &mut Vec<(u64, u32)>) -> usize {
        let cs_limit = self.chunk_size().saturating_sub(base).min(limit as u64) as usize;
        if from >= cs_limit {
            return limit;
        }
        rsds_search(&self.names, data, from, cs_limit, |p, k| out.push((base + p as u64, k))).max(limit)
    }
}

/// python `PDBUtility.pdbname_scan(layer, page_size, pdb_names, start, end)`. Stops early when
/// `f` returns false.
pub fn pdbname_scan(layer: &dyn Layer, names: &[&[u8]], start: Option<u64>, end: Option<u64>, mut f: impl FnMut(PdbSig) -> bool) {
    let start = start.unwrap_or(layer.min_address());
    let end = end.unwrap_or(layer.max_address());
    let scanner = RsdsScanner { names: names.iter().map(|n| n.to_vec()).collect() };
    let mut min_pfn: u64 = 0;
    let page_size = 0x1000u64;
    scan_each(layer, &scanner, Some(&[(start, end.wrapping_sub(start))]), |(sig_off, k)| {
        let mut rec = [0u8; 20];
        layer.read_padded(sig_off.wrapping_add(4), &mut rec);
        let guid = guid_string(&rec[..16]);
        let age = u32::from_le_bytes(rec[16..20].try_into().unwrap());
        let pdb_name = String::from_utf8_lossy(names[k as usize]).into_owned();
        let sig_pfn = sig_off / page_size;
        let mz = find_mz_before(layer, sig_off, page_size, min_pfn, 100);
        min_pfn = sig_pfn;
        f(PdbSig { guid, age, pdb_name, signature_offset: sig_off, mz_offset: mz })
    });
}

/// A found kernel: base (python kernel_virtual_offset) and PDB identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelFound {
    pub kvo: u64,
    pub pdb: PdbSig,
}

const MAX_PDB_SIZE: u64 = 0x400000;

/// python `KernelPDBScanner.check_kernel_offset`.
fn check_kernel_offset(vlayer: &IntelLayer, address: u64) -> Option<KernelFound> {
    let mut b = [0u8; 2];
    if vlayer.read(address, &mut b).is_err() || &b != b"MZ" {
        return None;
    }
    let mut first = None;
    pdbname_scan(vlayer, &KERNEL_PDB_NAMES, Some(address), Some(address + MAX_PDB_SIZE), |s| {
        if first.is_none() {
            first = Some(s);
        }
        // python lists all results; only the first is used
        true
    });
    first.map(|pdb| KernelFound { kvo: address, pdb })
}

/// python `method_low_stub_offset`.
fn method_low_stub(vlayer: &IntelLayer, phys: &dyn Layer) -> Option<KernelFound> {
    if vlayer.mode() != PagingMode::Intel32e {
        return None;
    }
    let mut kernel_hint = 0u64;
    let mut kernel_base = 0u64;
    let mut off = 0x1000u64;
    while off < 0x100000 {
        let r = (|| -> Result<Option<(u64, u64)>> {
            let v = phys.read_u64(off)?;
            if v & 0xFFFF_FFFF_FFFF_00FF != 0x0000_0001_0006_00E9 {
                return Ok(None);
            }
            let cr3 = phys.read_u64(off + 0xA0)?;
            if cr3.wrapping_add(1) != vlayer.initial_entry() {
                return Ok(None);
            }
            let hint = phys.read_u64(off + 0x70)?;
            if hint & 3 != 0 {
                return Ok(None);
            }
            let kh = hint & 0xFFFF_FFFF_FFFF;
            Ok(Some((kh, kh & !0x1F_FFFF & 0xFFFF_FFFF_FFFF)))
        })();
        if let Ok(Some((h, b))) = r {
            kernel_hint = h;
            kernel_base = b;
            break;
        }
        off += 0x1000;
    }
    if kernel_base != 0 {
        let mut kb = kernel_base as i128;
        while kb + 0x2000000 > kernel_hint as i128 {
            for i in (0..0x200000u64).step_by(0x1000) {
                let a = (kb as u64).wrapping_add(i);
                if let Some(k) = check_kernel_offset(vlayer, a) {
                    return Some(k);
                }
            }
            kb -= 0x200000;
        }
    }
    None
}

/// python `_method_offset` (kdbg / module list methods): scan the physical layer for `pattern`,
/// read a u64 at hit + `result_offset`, try it as a kernel base.
#[allow(dead_code)]
fn method_offset(vlayer: &IntelLayer, phys: &dyn Layer, pattern: &[u8], result_offset: i64) -> Result<Option<KernelFound>> {
    let mut seen = crate::util::FxHashSet::default();
    let mut found = None;
    let mut err = None;
    scan_each(phys, &BytesScanner::new(pattern), None, |hit| {
        let at = (hit as i128 + result_offset as i128) as u64;
        let ptr = match phys.read_u64(at) {
            Ok(p) => p,
            Err(e) => {
                err = Some(e);
                return false;
            }
        };
        let address = ptr & vlayer.address_mask();
        if !seen.insert(address) {
            return true;
        }
        if let Some(k) = check_kernel_offset(vlayer, address) {
            found = Some(k);
            return false;
        }
        true
    });
    if let Some(e) = err {
        return Err(e);
    }
    Ok(found)
}

/// The fused scan's [`MultiStringScanner`], also reporting module-list matches to `spot` as
/// the workers find them (out of order, before the in-order delivery reaches them).
struct Spotting<'s> {
    inner: MultiStringScanner,
    spot: &'s (dyn Fn(u64) + Sync),
}

impl Scanner for Spotting<'_> {
    type Hit = (u64, u32);
    fn chunk_size(&self) -> u64 {
        self.inner.chunk_size()
    }
    fn overlap(&self) -> u64 {
        self.inner.overlap()
    }
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<(u64, u32)>) {
        let n = hits.len();
        self.inner.scan(data, data_offset, hits);
        for &(o, pi) in &hits[n..] {
            if pi == 1 {
                (self.spot)(o);
            }
        }
    }
    fn prescan(&self, data: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
        self.inner.prescan(data, out)
    }
    fn finish(&self, matches: &[(u64, u32)], data_offset: u64, hits: &mut Vec<(u64, u32)>) {
        for &(o, pi) in matches {
            if pi == 1 {
                (self.spot)(data_offset + o);
            }
        }
        self.inner.finish(matches, data_offset, hits)
    }
    fn stream_window(&self) -> Option<usize> {
        self.inner.stream_window()
    }
    fn prescan_piece(&self, data: &[u8], base: u64, from: usize, limit: usize, out: &mut Vec<(u64, u32)>) -> usize {
        self.inner.prescan_piece(data, base, from, limit, out)
    }
    fn cache_query(&self) -> Option<crate::layers::scancache::CacheQuery<'_>> {
        self.inner.cache_query()
    }
}

/// Hits of the fused KDBG / module-list scan.
enum OffHit {
    Kdbg(u64),
    Module(u64),
}

/// python `method_kdbg_offset` followed by `method_module_offset`, in one physical pass:
/// KDBG hits are validated as they stream in (stopping at the first valid kernel, like
/// python). Module-list hits are validated as they stream in too, in order with python's
/// separate `seen` set, up to the first decisive one (a valid kernel, or a read error that
/// python would raise); that result is what python's module method returns if no KDBG hit
/// validates by the end of the scan. `candidate` sees it as soon as it is known (while the
/// scan continues), so the caller can start loading that kernel's symbols speculatively.
fn method_offsets_fused(vlayer: &IntelLayer, phys: &dyn Layer, candidate: &(dyn Fn(&KernelFound) + Sync)) -> Result<Option<KernelFound>> {
    let module_ro = -16 - (vlayer.bits_per_register() as i64 / 8);
    let mut seen = crate::util::FxHashSet::default();
    let mut found = None;
    let mut err = None;
    let mut module_hits = 0usize;
    let mut module_seen = crate::util::FxHashSet::default();
    // the module method's outcome once decided: Ok(kernel) or the error python raises
    let mut module_decision: Option<std::result::Result<KernelFound, Error>> = None;
    // Two BytesScanners (default chunking) in one pass. Neither needle can overlap itself or
    // the other, so the non-overlapping multi-string search yields exactly the union of both
    // needles' occurrences, in offset order.
    let inner = MultiStringScanner::new(&[&b"KDBG"[..], &b"\\SystemRoot\\system32\\nt"[..]]);
    // Speculation: a helper validates the first module-list matches the workers spot (any
    // order) and reports a valid kernel to `candidate` right away; the in-order evaluation
    // below decides the result as before.
    struct Spots {
        offs: Vec<u64>,
        done: bool,
    }
    let spots = std::sync::Mutex::new(Spots { offs: Vec::new(), done: false });
    let spotted = std::sync::Condvar::new();
    let spot = |o: u64| {
        let mut g = spots.lock().unwrap_or_else(|e| e.into_inner());
        if g.offs.len() < 8 && !g.done {
            g.offs.push(o);
            spotted.notify_one();
        }
    };
    let scanner = Spotting { inner, spot: &spot };
    let try_hit = |hit: u64, ro: i64, seen: &mut crate::util::FxHashSet<u64>| -> std::result::Result<Option<KernelFound>, Error> {
        let at = (hit as i128 + ro as i128) as u64;
        let ptr = phys.read_u64(at)?;
        let address = ptr & vlayer.address_mask();
        if !seen.insert(address) {
            return Ok(None);
        }
        Ok(check_kernel_offset(vlayer, address))
    };
    let helper = |_: ()| {
        let mut seen_h = crate::util::FxHashSet::default();
        let mut next = 0usize;
        loop {
            let o = {
                let mut g = spots.lock().unwrap_or_else(|e| e.into_inner());
                while next >= g.offs.len() && !g.done {
                    g = spotted.wait(g).unwrap_or_else(|e| e.into_inner());
                }
                if next >= g.offs.len() {
                    return;
                }
                next += 1;
                g.offs[next - 1]
            };
            if let Ok(Some(k)) = try_hit(o, module_ro, &mut seen_h) {
                crate::util::trace::note(|| format!("pdbscan: speculative kernel candidate from module-list hit at {o:#x}"));
                candidate(&k);
                spots.lock().unwrap_or_else(|e| e.into_inner()).done = true;
                return;
            }
        }
    };
    std::thread::scope(|sc| {
        let h = std::thread::Builder::new().name("fastvol-spot".into()).spawn_scoped(sc, || helper(())).ok();
        scan_each(phys, &scanner, None, |(o, pi)| match if pi == 0 { OffHit::Kdbg(o) } else { OffHit::Module(o) } {
            OffHit::Kdbg(o) => match try_hit(o, 8, &mut seen) {
                Ok(Some(k)) => {
                    crate::util::trace::note(|| format!("pdbscan: kernel from KDBG hit at {o:#x}"));
                    found = Some(k);
                    false
                }
                Ok(None) => true,
                Err(e) => {
                    err = Some(e);
                    false
                }
            },
            OffHit::Module(o) => {
                module_hits += 1;
                if module_decision.is_none() {
                    match try_hit(o, module_ro, &mut module_seen) {
                        Ok(Some(k)) => {
                            crate::util::trace::note(|| format!("pdbscan: kernel candidate from module-list hit at {o:#x}"));
                            candidate(&k);
                            module_decision = Some(Ok(k));
                        }
                        Ok(None) => {}
                        Err(e) => module_decision = Some(Err(e)),
                    }
                }
                true
            }
        });
        {
            let mut g = spots.lock().unwrap_or_else(|e| e.into_inner());
            g.done = true;
            spotted.notify_all();
        }
        if let Some(h) = h {
            let _ = h.join();
        }
    });
    if let Some(e) = err {
        return Err(e);
    }
    if found.is_some() {
        return Ok(found);
    }
    crate::util::trace::note(|| format!("pdbscan: no valid KDBG; {module_hits} module-list hits"));
    match module_decision {
        Some(Ok(k)) => Ok(Some(k)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// python `method_fixed_mapping`.
fn method_fixed_mapping(vlayer: &IntelLayer, phys: &dyn Layer) -> Option<KernelFound> {
    let mut found = None;
    pdbname_scan(phys, &KERNEL_PDB_NAMES, None, None, |k| {
        let Some(mz) = k.mz_offset else { return true };
        let kvo = if vlayer.bits_per_register() == 64 {
            let bits = ((vlayer.max_address() as f64 + 1.0).log2().ceil()) as u32;
            mz.wrapping_add(31u64 << (bits - 5))
        } else {
            mz.wrapping_add(1u64 << (vlayer.bits_per_register() - 1))
        };
        if let Some((p, crate::layers::intel::Target::Phys)) = vlayer.translate_addr(kvo) {
            if p == mz {
                found = Some(KernelFound { kvo, pdb: k });
                return false;
            }
        }
        true
    });
    found
}

/// python `method_slow_scan` (optimized virtual scan from 0x1f0 << 39, then full).
fn method_slow_scan(vlayer: &IntelLayer) -> Option<KernelFound> {
    let test = |k: PdbSig| k.mz_offset.map(|mz| KernelFound { kvo: mz, pdb: k });
    let mut found = None;
    let start = if vlayer.bits_per_register() == 64 { Some(0x1F0u64 << 39) } else { None };
    if start.is_some() {
        pdbname_scan(vlayer, &KERNEL_PDB_NAMES, start, None, |k| {
            found = test(k);
            found.is_none()
        });
        if found.is_some() {
            return found;
        }
    }
    pdbname_scan(vlayer, &KERNEL_PDB_NAMES, None, None, |k| {
        found = test(k);
        found.is_none()
    });
    found
}

/// python `KernelPDBScanner.determine_valid_kernel` on one Intel layer.
pub fn find_kernel(vlayer: &IntelLayer, phys: &dyn Layer) -> Result<Option<KernelFound>> {
    find_kernel_with(vlayer, phys, &|_| {})
}

/// [`find_kernel`], telling `candidate` about a kernel that will be the result unless a later
/// KDBG hit validates (see `method_offsets_fused`); for speculative symbol loading.
pub fn find_kernel_with(vlayer: &IntelLayer, phys: &dyn Layer, candidate: &(dyn Fn(&KernelFound) + Sync)) -> Result<Option<KernelFound>> {
    use crate::util::trace::span;
    {
        let _t = span("pdbscan: low stub");
        if let Some(k) = method_low_stub(vlayer, phys) {
            return Ok(Some(k));
        }
    }
    {
        // python runs method_kdbg_offset then method_module_offset, each a full physical scan;
        // one fused pass gives the same hits in the same order (see method_offsets_fused)
        let _t = span("pdbscan: kdbg + module offset (fused scan)");
        if let Some(k) = method_offsets_fused(vlayer, phys, candidate)? {
            return Ok(Some(k));
        }
    }
    {
        let _t = span("pdbscan: fixed mapping");
        if let Some(k) = method_fixed_mapping(vlayer, phys) {
            return Ok(Some(k));
        }
    }
    let _t = span("pdbscan: slow scan");
    Ok(method_slow_scan(vlayer))
}

/// The kernel symbol table, loaded on another thread while the kernel search still scans:
/// without a valid KDBG the whole image is scanned, and the module-list candidate (the result
/// unless a later KDBG hit validates) is known long before the scan ends.
///
/// The speculation loads exactly the ISF the final lookup will pick (python's identifier-cache
/// choice, else by name: `store::find_windows_isf_no_download`) and announces it before
/// loading, so the final lookup joins it only when it picked the same file and never waits for
/// the load of another one (with one GUID in two symbol directories, the copy python's
/// database lists last is the one loaded, once). With no ISF on disk the kernel's PDB is
/// downloaded meanwhile instead (not `--offline`), which the lookup's conversion then waits
/// for rather than downloading it again.
pub struct IsfSpeculation {
    job: std::sync::Mutex<Option<SpecJob>>,
}

struct SpecJob {
    /// (pdb name, GUID, age) of the candidate kernel
    key: (String, String, u32),
    /// the ISF the speculation loads (sent before it loads; `None`: none on disk)
    chosen: std::sync::mpsc::Receiver<Option<crate::symbols::IsfLocation>>,
    load: std::thread::JoinHandle<Option<crate::symbols::SymbolTable>>,
}

impl Default for IsfSpeculation {
    fn default() -> Self {
        Self::new()
    }
}

impl IsfSpeculation {
    pub fn new() -> IsfSpeculation {
        IsfSpeculation { job: std::sync::Mutex::new(None) }
    }

    /// Start the speculation for candidate `k` (the first candidate only), with the symbol
    /// search path `path`.
    ///
    /// `early`: the identifier index being built ([`EarlyIndex`]). When it has to read ISFs
    /// (python's cache lacks rows) python's choice would wait for that, so the ISF named by the
    /// PDB loads right away instead (joined only if it is the final choice, which it is unless
    /// one GUID has several copies); nothing is downloaded then.
    pub fn start(&self, path: &'static crate::symbols::SymbolPath, k: &KernelFound, offline: bool, early: Option<std::sync::Arc<EarlyState>>) {
        use crate::symbols::{self, BuildOptions};
        let mut g = self.job.lock().unwrap_or_else(|e| e.into_inner());
        if g.is_some() {
            return;
        }
        let key = (k.pdb.pdb_name.clone(), k.pdb.guid.clone(), k.pdb.age);
        let (pdb, guid, age) = key.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let job = move || {
            let _t = crate::util::trace::span("kernel isf load (speculative)");
            let cheap = early.is_none_or(|e| e.cheap());
            let loc = if cheap { symbols::store::find_windows_isf_no_download(path, &pdb, &guid, age) } else { symbols::store::find_windows_isf_local(path, &pdb, &guid, age) };
            let _ = tx.send(loc.clone());
            match loc {
                Some(loc) => symbols::store::load(&loc, "symbol_table_name", &BuildOptions::default()).ok(),
                None => {
                    if !offline && cheap {
                        symbols::windows::pdb::convert_ahead(pdb.trim_matches('\0'), &guid, age, true);
                    }
                    None
                }
            }
        };
        if let Ok(h) = std::thread::Builder::new().name("fastvol-spec".into()).spawn(job) {
            *g = Some(SpecJob { key, chosen: rx, load: h });
        }
    }

    /// A speculation running `job` (it announces its ISF through the sender) for kernel `key`.
    #[cfg(test)]
    fn with_job(
        key: (String, String, u32),
        job: impl FnOnce(std::sync::mpsc::Sender<Option<crate::symbols::IsfLocation>>) -> Option<crate::symbols::SymbolTable> + Send + 'static,
    ) -> IsfSpeculation {
        let (tx, rx) = std::sync::mpsc::channel();
        let load = std::thread::spawn(move || job(tx));
        IsfSpeculation { job: std::sync::Mutex::new(Some(SpecJob { key, chosen: rx, load })) }
    }

    /// The table the speculation loaded, when it was for kernel (`pdb_name`, `guid`, `age`)
    /// and loaded `loc` (the final lookup's answer); `None` otherwise, without waiting for a
    /// load of another file (that thread finishes, or dies with the process, on its own).
    pub fn take(self, pdb_name: &str, guid: &str, age: u32, loc: &crate::symbols::IsfLocation) -> Option<crate::symbols::SymbolTable> {
        let job = self.job.into_inner().unwrap_or_else(|e| e.into_inner())?;
        if (job.key.0.as_str(), job.key.1.as_str(), job.key.2) != (pdb_name, guid, age) {
            return None;
        }
        if job.chosen.recv().ok().flatten().as_ref() != Some(loc) {
            crate::util::trace::note(|| "kernel isf: the speculative load is not the final choice".to_string());
            return None;
        }
        let _t = crate::util::trace::span("kernel isf load (joining the speculative load)");
        job.load.join().ok().flatten()
    }
}

/// The identifier index, built while the kernel is searched for (the DTB scan and pdbscan
/// take 1-2 ms, reading python's identifier cache about as long). When the index has to read
/// ISFs (python's cache lacks rows) it waits for the kernel search to end
/// ([`EarlyIndex::kernel`]): decoding ISFs beside a whole-image KDBG scan only slows both
/// down, and with the kernel's identifier the index builds that ISF's table on the way, as
/// the lookup's own index build would. The kernel lookup then finds the index built (it is
/// memoized). Give the kernel (or `None`) before any ISF lookup: the lookup waits for this
/// index.
pub struct EarlyIndex {
    st: std::sync::Arc<EarlyState>,
}

/// What [`EarlyIndex`] shares with its thread and the speculative load.
pub struct EarlyState {
    m: std::sync::Mutex<EarlyPhase>,
    cv: std::sync::Condvar,
}

#[derive(Default)]
struct EarlyPhase {
    /// the kernel's identifier once the search ended (`Some(None)`: no kernel)
    kernel: Option<Option<Vec<u8>>>,
    /// the index reads ISFs (it waits for the kernel first)
    reading: bool,
    /// the index is built
    done: bool,
}

impl EarlyState {
    fn wait_until(&self, cond: impl Fn(&EarlyPhase) -> bool) -> std::sync::MutexGuard<'_, EarlyPhase> {
        let mut g = self.m.lock().unwrap_or_else(|e| e.into_inner());
        while !cond(&g) {
            g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
        g
    }

    fn update(&self, f: impl FnOnce(&mut EarlyPhase)) {
        let mut g = self.m.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut g);
        self.cv.notify_all();
    }

    /// Whether python's identifier-cache choice is at hand without reading ISFs: waits until
    /// the index is built (`true`) or turns out to need ISFs read (`false`).
    pub fn cheap(&self) -> bool {
        self.wait_until(|p| p.done || p.reading).done
    }
}

impl EarlyIndex {
    /// Start building the index of `path` on another thread.
    pub fn start(path: &'static crate::symbols::SymbolPath) -> EarlyIndex {
        let st = std::sync::Arc::new(EarlyState { m: Default::default(), cv: Default::default() });
        let s = st.clone();
        let spawned = std::thread::Builder::new().name("fastvol-index".into()).spawn(move || {
            let _t = crate::util::trace::span("identifier index (early)");
            crate::symbols::store::identifier_index_with(path, &|| {
                s.update(|p| p.reading = true);
                if let Some(Some(id)) = &s.wait_until(|p| p.kernel.is_some()).kernel {
                    crate::symbols::store::index_for(id.as_slice(), "windows");
                }
            });
            s.update(|p| p.done = true);
        });
        if spawned.is_err() {
            // (no thread: nothing is built early; nobody waits for it)
            st.update(|p| p.reading = true);
        }
        EarlyIndex { st }
    }

    /// The state the speculative kernel table load consults ([`EarlyState::cheap`]).
    pub fn state(&self) -> std::sync::Arc<EarlyState> {
        self.st.clone()
    }

    /// The kernel search ended with this kernel (`pdb`, `GUID`, `age`) or none; the first
    /// call counts.
    pub fn kernel(&self, pdb_name: Option<(&str, &str, u32)>) {
        self.st.update(|p| {
            if p.kernel.is_none() {
                p.kernel = Some(pdb_name.map(|(pdb, guid, age)| format!("{}|{}|{}", pdb.trim_matches('\0'), guid.to_uppercase(), age).into_bytes()));
            }
        });
    }
}

impl Drop for EarlyIndex {
    fn drop(&mut self) {
        self.kernel(None);
    }
}

/// Everything the Windows automagic determines for an image (cacheable).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WinAutomagic {
    pub dtb: u64,
    pub mode: PagingMode,
    pub kvo: u64,
    pub pdb_name: String,
    pub guid: String,
    pub age: u32,
}

/// Run the Windows automagic on the physical layer.
pub fn run(phys: &Arc<dyn Layer>) -> Result<WinAutomagic> {
    let d = {
        let _t = crate::util::trace::span("windows dtb scan");
        find_dtb(phys)?.ok_or_else(|| Error::Unsatisfied("Unable to validate the plugin requirements: no Windows DTB found".into()))?
    };
    let vl = IntelLayer::new("layer_name", phys.clone(), d.dtb, d.mode, PteFlavor::Windows);
    let k = {
        let _t = crate::util::trace::span("windows pdbscan");
        find_kernel(&vl, phys.as_ref())?.ok_or_else(|| Error::Unsatisfied("No suitable kernels found during pdbscan".into()))?
    };
    Ok(WinAutomagic { dtb: d.dtb, mode: d.mode, kvo: k.kvo, pdb_name: k.pdb.pdb_name, guid: k.pdb.guid, age: k.pdb.age })
}

#[allow(dead_code)]
fn _unused(l: &dyn Layer) -> Vec<u64> {
    scan(l, &BytesScanner::new(b"x"), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The speculative kernel table is used only when it is the file the final lookup chose;
    /// a speculation that chose another file is never waited for (it may still be loading).
    #[test]
    fn speculation_joins_only_the_final_choice() {
        use crate::symbols::IsfLocation;
        let key = || ("k.pdb".to_string(), "AB".to_string(), 1u32);
        let (a, b) = (IsfLocation::File("/syms/a.json".into()), IsfLocation::File("/syms/b.json".into()));
        let table = || crate::symbols::isf::load_table(crate::symbols::isf::tests::ISF.as_bytes(), "t", "file:///x", &Default::default()).ok();
        // chose b (python's copy), final lookup says a: not joined, although b's load hangs
        let (hold, wait) = std::sync::mpsc::channel::<()>();
        let bb = b.clone();
        let s = IsfSpeculation::with_job(key(), move |tx| {
            let _ = tx.send(Some(bb));
            let _ = wait.recv();
            None
        });
        let t0 = std::time::Instant::now();
        assert!(s.take("k.pdb", "AB", 1, &a).is_none());
        assert!(t0.elapsed() < std::time::Duration::from_secs(5));
        drop(hold);
        // the same file: joined, its table used
        let aa = a.clone();
        let s = IsfSpeculation::with_job(key(), move |tx| {
            let _ = tx.send(Some(aa));
            table()
        });
        assert!(s.take("k.pdb", "AB", 1, &a).is_some());
        // another kernel, or no ISF on disk (the PDB was fetched instead): not used
        let aa = a.clone();
        let s = IsfSpeculation::with_job(key(), move |tx| {
            let _ = tx.send(Some(aa));
            table()
        });
        assert!(s.take("k.pdb", "AB", 2, &a).is_none());
        let s = IsfSpeculation::with_job(key(), move |tx| {
            let _ = tx.send(None);
            None
        });
        assert!(s.take("k.pdb", "AB", 1, &a).is_none());
        assert!(IsfSpeculation::new().take("k.pdb", "AB", 1, &a).is_none());
    }

    /// The speculative load asks the early index whether python's choice is at hand: yes once
    /// the index is built, no as soon as it has to read ISFs (it then waits for the kernel).
    #[test]
    fn early_index_phases() {
        use std::sync::Arc;
        for reading in [false, true] {
            let st = Arc::new(EarlyState { m: Default::default(), cv: Default::default() });
            let s = st.clone();
            let h = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(20));
                s.update(|p| if reading { p.reading = true } else { p.done = true });
                if reading {
                    // the index waits for the kernel search to end, then finishes
                    let id = s.wait_until(|p| p.kernel.is_some()).kernel.clone();
                    s.update(|p| p.done = true);
                    return id;
                }
                None
            });
            assert_eq!(st.cheap(), !reading);
            let e = EarlyIndex { st: st.clone() };
            e.kernel(Some(("k.pdb\0", "ab", 3)));
            e.kernel(None); // the first call counts
            drop(e);
            let got = h.join().unwrap();
            assert_eq!(got, if reading { Some(Some(b"k.pdb|AB|3".to_vec())) } else { None });
            assert!(st.cheap());
        }
    }

    fn page_with(entries: &[(usize, u64)]) -> Vec<u8> {
        let mut p = vec![0u8; 0x1000];
        for &(i, v) in entries {
            p[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        p
    }

    #[test]
    fn selfref64() {
        // page at 0x1ae000 with a self reference at index 0x1ed
        let data = page_with(&[(0, 0x5000 | 1), (0x1ed, 0x1ae000 | 0x63)]);
        assert_eq!(DtbTest::SelfRef64.test(&data, 0x1ae000, 0), Ok(Some(0x1ae000)));
        assert_eq!(DtbTest::SelfRef64Old.test(&data, 0x1ae000, 0), Ok(Some(0x1ae000)));
        // two self references -> rejected
        let data = page_with(&[(0x1ed, 0x1ae000 | 1), (0x100, 0x1ae000 | 1)]);
        assert_eq!(DtbTest::SelfRef64.test(&data, 0x1ae000, 0), Ok(None));
        // a present entry with the reserved bit 7 -> page rejected
        let data = page_with(&[(0x1ed, 0x1ae000 | 1), (3, 0x9000 | 0x81)]);
        assert_eq!(DtbTest::SelfRef64.test(&data, 0x1ae000, 0), Ok(None));
        // index outside 0x100..0x1ff
        let data = page_with(&[(0x10, 0x1ae000 | 1)]);
        assert_eq!(DtbTest::SelfRef64.test(&data, 0x1ae000, 0), Ok(None));
        // partial page -> python's struct.error aborts the scan
        let data = page_with(&[(0x1ed, 0x1ae000 | 1)]);
        assert_eq!(DtbTest::SelfRef64.test(&data[..0x800], 0x1ae000, 0), Err(()));
    }

    #[test]
    fn python_slices() {
        let d = [1u8, 2, 3, 4, 5];
        assert_eq!(py_slice(&d, -2, 5), &[4, 5]);
        assert_eq!(py_slice(&d, -10, 2), &[1, 2]);
        assert_eq!(py_slice(&d, 3, 1), &[] as &[u8]);
        assert_eq!(py_slice(&d, 2, 100), &[3, 4, 5]);
    }

    #[test]
    fn rsds_scanner() {
        let mut data = vec![0u8; 256];
        data[10..14].copy_from_slice(b"RSDS");
        for (i, b) in data[14..30].iter_mut().enumerate() {
            *b = i as u8;
        }
        data[30..34].copy_from_slice(&7u32.to_le_bytes());
        data[34..46].copy_from_slice(b"ntkrnlmp.pdb");
        data[46] = 0;
        let s = PdbSignatureScanner { names: KERNEL_PDB_NAMES.iter().map(|n| n.to_vec()).collect() };
        let mut hits = Vec::new();
        s.scan(&data, 0x1000, &mut hits);
        assert_eq!(hits, vec![("030201000504070608090A0B0C0D0E0F".to_string(), 7, "ntkrnlmp.pdb".to_string(), 0x100a)]);
    }

    /// On real layers, the streaming `RsdsScanner` (pread pieces / aliased pages searched once)
    /// yields exactly the hits of the whole-chunk `PdbSignatureScanner` (mapped chunks):
    /// physical and kernel virtual layers of both Windows images.
    #[test]
    #[ignore]
    fn rsds_stream_on_images() {
        use crate::context::{Context, GlobalOptions};
        let names: Vec<Vec<u8>> = [&b"ntkrnlmp.pdb"[..], b"ntdll.pdb", b"tcpip.pdb", b"win32k.pdb", b"hal.pdb", b"kernel32.pdb"].iter().map(|n| n.to_vec()).collect();
        for img in &[crate::util::testdata::win_image(), crate::util::testdata::path("testdata/images/windows/rsvol-win10-x64-17763-imagery.raw")] {
            let ctx = Context::new(GlobalOptions { file: Some(img.into()), ..Default::default() }).unwrap();
            let k = ctx.windows_kernel().unwrap();
            for (lname, layer) in [("physical", k.phys), ("kernel", k.vlayer)] {
                let t = std::time::Instant::now();
                let mut a = Vec::new();
                scan_each(layer, &PdbSignatureScanner { names: names.clone() }, None, |h| {
                    a.push((h.3, h.2, h.0, h.1));
                    true
                });
                let ta = t.elapsed();
                let t = std::time::Instant::now();
                let mut b = Vec::new();
                scan_each(layer, &RsdsScanner { names: names.clone() }, None, |(o, n)| {
                    let mut rec = [0u8; 20];
                    layer.read_padded(o + 4, &mut rec);
                    b.push((o, String::from_utf8_lossy(&names[n as usize]).into_owned(), guid_string(&rec[..16]), u32::from_le_bytes(rec[16..20].try_into().unwrap())));
                    true
                });
                let tb = t.elapsed();
                assert_eq!(a, b, "{img} {lname}");
                println!("{img} {lname}: {} RSDS hits identical; whole-chunk {:.1} ms, streaming {:.1} ms", a.len(), ta.as_secs_f64() * 1e3, tb.as_secs_f64() * 1e3);
            }
        }
    }

    /// The piecewise RSDS search equals the whole-chunk search (python's finditer) for every
    /// piece size, chunk-size cut and a dense mix of partial / adjacent / overlapping records.
    #[test]
    fn rsds_stream_equals_whole_chunk() {
        let names: Vec<Vec<u8>> = [&b"ntkrnlmp.pdb"[..], b"nt.pdb", b"ntkrnlmp.pd"].iter().map(|n| n.to_vec()).collect();
        let mut x: u64 = 0x1234_5678_9abc_def1;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..300 {
            let mut data = Vec::new();
            while data.len() < 3000 {
                match next() % 6 {
                    0 => data.extend_from_slice(b"RSDS"),
                    1 => {
                        data.extend_from_slice(b"RSDS");
                        data.extend((0..20).map(|_| next() as u8));
                        let n = &names[(next() % 3) as usize];
                        data.extend_from_slice(n);
                        if next() % 4 != 0 {
                            data.push(0);
                        }
                    }
                    2 => data.extend_from_slice(b"RSDSRSDS"),
                    _ => data.extend((0..(next() % 40)).map(|_| if next() % 3 == 0 { b'R' } else { next() as u8 })),
                }
            }
            let sc = RsdsScanner { names: names.clone() };
            let whole = PdbSignatureScanner { names: names.clone() };
            let mut expect = Vec::new();
            rsds_search(&names, &data, 0, data.len(), |p, k| expect.push((p as u64, k)));
            let mut w = Vec::new();
            whole.scan(&data[..], 0, &mut w);
            assert_eq!(w.iter().map(|h| h.3).collect::<Vec<_>>(), expect.iter().map(|h| h.0).collect::<Vec<_>>(), "whole-chunk scanner");
            let mut pre = Vec::new();
            assert!(sc.prescan(&data, &mut pre));
            assert_eq!(pre, expect, "prescan");
            // the executor's piece loop (scan_pieces)
            let win = sc.stream_window().unwrap() as u64;
            let len = data.len() as u64;
            for piece in [1u64, 2, 7, 24, 31, 64, 999] {
                let mut got = Vec::new();
                let (mut next, mut p) = (0u64, 0u64);
                while p < len {
                    let limit = (p + piece).min(len);
                    let end = (limit + win - 1).min(len);
                    if next < limit {
                        let from = (next.max(p) - p) as usize;
                        next = p + sc.prescan_piece(&data[p as usize..end as usize], p, from, (limit - p) as usize, &mut got) as u64;
                    }
                    p = limit;
                }
                assert_eq!(got, expect, "round {round} piece {piece}");
            }
        }
    }
}
