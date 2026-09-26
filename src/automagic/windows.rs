//! Windows automagic: DTB discovery (python `automagic/windows.py` WindowsIntelStacker +
//! PageMapScanner) and kernel PDB / base discovery (python `automagic/pdbscan.py`
//! KernelPDBScanner, `pdbutil.pdbname_scan`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::error::{Error, Result};
use crate::layers::scan::{BytesScanner, Scanner, find, scan, scan_each};
use crate::layers::{IntelLayer, Layer, LayerExt, PagingMode, PteFlavor, metadata};
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

/// python `PdbSignatureScanner`: `RSDS` + 20 bytes + one of `names` + NUL (regex finditer,
/// non-overlapping).
pub struct PdbSignatureScanner {
    pub names: Vec<Vec<u8>>,
}

impl Scanner for PdbSignatureScanner {
    type Hit = (String, u32, String, u64);
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<Self::Hit>) {
        let cs = self.chunk_size() as usize;
        let mut pos = 0usize;
        while let Some(i) = find(&data[pos..], b"RSDS") {
            let s = pos + i;
            let name_at = s + 24;
            let mut matched = None;
            for n in &self.names {
                if data.len() >= name_at + n.len() + 1 && &data[name_at..name_at + n.len()] == n.as_slice() && data[name_at + n.len()] == 0 {
                    matched = Some(n);
                    break;
                }
            }
            match matched {
                Some(n) => {
                    if s < cs {
                        let b = &data[s + 4..s + 24];
                        let order = [3usize, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
                        let guid: String = order.iter().map(|&k| format!("{:02X}", b[k])).collect();
                        let age = u32::from_le_bytes(b[16..20].try_into().unwrap());
                        hits.push((guid, age, String::from_utf8_lossy(n).into_owned(), data_offset + s as u64));
                    }
                    pos = name_at + n.len() + 1;
                }
                None => pos = s + 1,
            }
        }
    }
}

/// python `PDBUtility.pdbname_scan(layer, page_size, pdb_names, start, end)`. Stops early when
/// `f` returns false.
pub fn pdbname_scan(layer: &dyn Layer, names: &[&[u8]], start: Option<u64>, end: Option<u64>, mut f: impl FnMut(PdbSig) -> bool) {
    let start = start.unwrap_or(layer.min_address());
    let end = end.unwrap_or(layer.max_address());
    let scanner = PdbSignatureScanner { names: names.iter().map(|n| n.to_vec()).collect() };
    let mut min_pfn: u64 = 0;
    let page_size = 0x1000u64;
    scan_each(layer, &scanner, Some(&[(start, end.wrapping_sub(start))]), |(guid, age, pdb_name, sig_off)| {
        let sig_pfn = sig_off / page_size;
        let mut mz = None;
        let mut invalid = 0;
        let mut i = sig_pfn;
        while i > min_pfn {
            if invalid > 100 {
                break;
            }
            if !layer.is_valid(i * page_size, 2) {
                invalid += 1;
                i -= 1;
                continue;
            }
            if let Ok(d) = layer.read_vec(i * page_size, 2) {
                if d == b"MZ" {
                    mz = Some(i * page_size);
                    break;
                }
            }
            i -= 1;
        }
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
    if let Some(k) = method_low_stub(vlayer, phys) {
        return Ok(Some(k));
    }
    if let Some(k) = method_offset(vlayer, phys, b"KDBG", 8)? {
        return Ok(Some(k));
    }
    let ro = -16 - (vlayer.bits_per_register() as i64 / 8);
    if let Some(k) = method_offset(vlayer, phys, b"\\SystemRoot\\system32\\nt", ro)? {
        return Ok(Some(k));
    }
    if let Some(k) = method_fixed_mapping(vlayer, phys) {
        return Ok(Some(k));
    }
    Ok(method_slow_scan(vlayer))
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
    let d = find_dtb(phys)?.ok_or_else(|| Error::Unsatisfied("Unable to validate the plugin requirements: no Windows DTB found".into()))?;
    let vl = IntelLayer::new("layer_name", phys.clone(), d.dtb, d.mode, PteFlavor::Windows);
    let k = find_kernel(&vl, phys.as_ref())?.ok_or_else(|| Error::Unsatisfied("No suitable kernels found during pdbscan".into()))?;
    Ok(WinAutomagic { dtb: d.dtb, mode: d.mode, kvo: k.kvo, pdb_name: k.pdb.pdb_name, guid: k.pdb.guid, age: k.pdb.age })
}

#[allow(dead_code)]
fn _unused(l: &dyn Layer) -> Vec<u64> {
    scan(l, &BytesScanner::new(b"x"), None)
}
