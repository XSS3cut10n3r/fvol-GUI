// Derived from Volatility 3 (Volatility Software License 1.0): framework/symbols/windows/pdbutil.py
//! PE debug-directory (CodeView RSDS) extraction and the `PdbSignatureScanner` matcher used
//! by `PDBUtility.pdbname_scan` (automagic/pdbscan.py, banners, pe_symbols, netstat...).

use crate::layers::Layer;

/// GUID / age / PDB file name of a CodeView RSDS record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeViewInfo {
    /// 32 uppercase hex digits (python `Signature_String[:32]`).
    pub guid: String,
    pub age: u32,
    /// File name component of the PDB path (python `PureWindowsPath(name).name`).
    pub pdb_name: String,
}

#[inline]
fn rd16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
fn rd32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// The GUID string of an RSDS record (`guid` = the 16 bytes after "RSDS"), in the mixed
/// endian order used by both pefile's `Signature_String` and `PdbSignatureScanner`.
fn guid_string(g: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(32);
    for i in [3usize, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15] {
        s.push(HEX[(g[i] >> 4) as usize] as char);
        s.push(HEX[(g[i] & 15) as usize] as char);
    }
    s
}

/// `SizeOfImage` from the headers of an image starting with "MZ" (python
/// `get_guid_from_mz` reads this many bytes, zero padded, before looking for the debug
/// directory). `header` needs to cover the optional header.
pub fn pe_image_size(header: &[u8]) -> Option<u32> {
    if header.get(..2)? != b"MZ" {
        return None;
    }
    let nt = rd32(header, 0x3c)? as usize;
    if header.get(nt..nt.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let opt = nt + 0x18;
    match rd16(header, opt)? {
        0x10b | 0x20b => rd32(header, opt + 56),
        _ => None,
    }
}

/// A read-only view of python's reconstructed "physical" PE:
/// `virtual[:SizeOfHeaders] + b"".join(virtual[VA:VA+SizeOfRawData] for each section)`,
/// where `virtual` is `SizeOfImage` bytes of the in-memory image, zero padded.
struct Physical<'a> {
    image: &'a [u8],
    size_of_image: usize,
    /// (physical start, virtual start, length)
    runs: Vec<(usize, usize, usize)>,
    len: usize,
}

impl<'a> Physical<'a> {
    fn byte(&self, virt: usize) -> u8 {
        if virt < self.size_of_image { self.image.get(virt).copied().unwrap_or(0) } else { 0 }
    }

    /// python `physical_data[start:end]` (clamped).
    fn slice(&self, start: usize, end: usize) -> Vec<u8> {
        let end = end.min(self.len);
        let mut out = Vec::with_capacity(end.saturating_sub(start));
        let mut pos = start;
        for &(ps, vs, l) in &self.runs {
            if pos >= end {
                break;
            }
            if pos >= ps + l {
                continue;
            }
            let take_end = end.min(ps + l);
            for p in pos.max(ps)..take_end {
                out.push(self.byte(vs + (p - ps)));
            }
            pos = take_end;
        }
        out
    }
}

struct Section {
    va: u32,
    vsize: u32,
    raw_size: u32,
    raw_ptr: u32,
}

/// python `PDBUtility.get_guid_from_mz` on the bytes of an in-memory PE image (`image[0]` is
/// the "MZ"; pass at least `SizeOfImage` bytes, see [`pe_image_size`] — missing bytes are
/// treated as zero, like `layer.read(..., pad=True)`). Returns None wherever python returns
/// None or raises.
pub fn pe_codeview_info(image: &[u8]) -> Option<CodeViewInfo> {
    if image.get(..2)? != b"MZ" {
        return None;
    }
    let nt = rd32(image, 0x3c)? as usize;
    if image.get(nt..nt.checked_add(2)?)? != b"PE" {
        return None;
    }
    // pefile requires the full signature and a known optional header
    if image.get(nt..nt + 4)? != b"PE\0\0" {
        return None;
    }
    let num_sections = rd16(image, nt + 6)? as usize;
    let opt_size = rd16(image, nt + 0x14)? as usize;
    let opt = nt + 0x18;
    let magic = rd16(image, opt)?;
    let (nrva_off, dd_off) = match magic {
        0x10b => (92, 96),
        0x20b => (108, 112),
        _ => return None,
    };
    let section_alignment = rd32(image, opt + 32)? as u64;
    let file_alignment = rd32(image, opt + 36)? as u64;
    let size_of_image = rd32(image, opt + 56)? as usize;
    let size_of_headers = rd32(image, opt + 60)? as usize;
    let nrva = rd32(image, opt + nrva_off)?.min(16);
    if nrva < 7 {
        return None;
    }
    let dbg_rva = rd32(image, opt + dd_off + 6 * 8)? as u64;
    let dbg_size = rd32(image, opt + dd_off + 6 * 8 + 4)? as u64;
    if dbg_rva == 0 {
        return None;
    }

    let sec_table = opt + opt_size;
    let mut sections = Vec::with_capacity(num_sections.min(96));
    for i in 0..num_sections {
        let o = sec_table + i * 40;
        let (Some(vsize), Some(va), Some(raw_size), Some(raw_ptr)) =
            (rd32(image, o + 8), rd32(image, o + 12), rd32(image, o + 16), rd32(image, o + 20))
        else {
            break;
        };
        sections.push(Section { va, vsize, raw_size, raw_ptr });
    }

    // physical_data = virtual_data[:SizeOfHeaders] + sections' raw data (python slicing clamps)
    let mut runs = Vec::with_capacity(sections.len() + 1);
    let hdr_len = size_of_headers.min(size_of_image);
    runs.push((0usize, 0usize, hdr_len));
    let mut len = hdr_len;
    for s in &sections {
        let start = (s.va as usize).min(size_of_image);
        let end = (s.va as usize).saturating_add(s.raw_size as usize).min(size_of_image);
        let l = end.saturating_sub(start);
        if l > 0 {
            runs.push((len, start, l));
            len += l;
        }
    }
    let phys = Physical { image, size_of_image, runs, len };

    // pefile RVA -> offset helpers
    let fa_adj = |v: u64| if file_alignment < 0x200 { v } else { (v / 0x200) * 0x200 };
    let sa = if section_alignment < 0x1000 { file_alignment } else { section_alignment };
    let va_adj = |v: u64| if sa != 0 && !v.is_multiple_of(sa) { sa * (v / sa) } else { v };
    let contains = |i: usize, rva: u64| -> bool {
        let s = &sections[i];
        let ptr_adj = fa_adj(s.raw_ptr as u64);
        let mut size = if (phys.len as u64).saturating_sub(ptr_adj) < s.raw_size as u64
            || (phys.len as u64) < ptr_adj
        {
            s.vsize as u64
        } else {
            (s.raw_size as u64).max(s.vsize as u64)
        };
        let vadj = va_adj(s.va as u64);
        if let Some(next) = sections.get(i + 1) {
            let nva = next.va as u64;
            if nva > s.va as u64 && vadj + size > nva {
                size = nva - vadj;
            }
        }
        vadj <= rva && rva < vadj + size
    };
    // pefile `get_data(rva, length)`
    let get_data = |rva: u64, length: u64| -> Vec<u8> {
        for (i, s) in sections.iter().enumerate() {
            if contains(i, rva) {
                let offset = rva.wrapping_sub(va_adj(s.va as u64)).wrapping_add(fa_adj(s.raw_ptr as u64));
                let mut end = offset.wrapping_add(length);
                let raw_end = s.raw_ptr as u64 + s.raw_size as u64;
                if end > raw_end && raw_end > offset {
                    end = raw_end;
                }
                if offset > phys.len as u64 {
                    return Vec::new();
                }
                return phys.slice(offset as usize, end.min(phys.len as u64) as usize);
            }
        }
        if rva < phys.len as u64 {
            return phys.slice(rva as usize, (rva + length).min(phys.len as u64) as usize);
        }
        Vec::new()
    };

    // parse_debug_directory
    let mut last_cv: Option<Option<CodeViewInfo>> = None;
    for idx in 0..dbg_size / 28 {
        let d = get_data(dbg_rva + 28 * idx, 28);
        if d.len() < 28 {
            // pefile: "Invalid debug information" -> no DIRECTORY_ENTRY_DEBUG at all
            return None;
        }
        let typ = rd32(&d, 12)?;
        if typ != 2 {
            continue;
        }
        let size_of_data = rd32(&d, 16)? as usize;
        let ptr = rd32(&d, 24)? as usize;
        let cv = phys.slice(ptr, ptr.saturating_add(size_of_data));
        last_cv = Some(parse_rsds(&cv, size_of_data));
    }
    last_cv?
}

/// pefile `CV_INFO_PDB70` parsing + the name handling of `get_guid_from_mz`.
fn parse_rsds(cv: &[u8], size_of_data: usize) -> Option<CodeViewInfo> {
    if cv.get(..4)? != b"RSDS" {
        return None;
    }
    // PdbFileName only exists (and unpacking only succeeds) with more than 24 bytes
    if size_of_data <= 24 || cv.len() < size_of_data {
        return None;
    }
    let guid = guid_string(&cv[4..20]);
    let age = rd32(cv, 20)?;
    let name = std::str::from_utf8(&cv[24..size_of_data]).ok()?;
    let name = name.trim_matches('\0');
    Some(CodeViewInfo { guid, age, pdb_name: windows_path_name(name).to_string() })
}

/// python `PureWindowsPath(path).name`.
fn windows_path_name(path: &str) -> &str {
    let is_sep = |c: char| c == '\\' || c == '/';
    let mut rest = path;
    // UNC drive: \\server\share
    let b = rest.as_bytes();
    if b.len() >= 2 && is_sep(b[0] as char) && is_sep(b[1] as char) {
        let after = &rest[2..];
        if let Some(i) = after.find(is_sep) {
            let share = &after[i + 1..];
            if !share.is_empty() && !share.starts_with(is_sep) {
                rest = match share.find(is_sep) {
                    Some(j) => &share[j..],
                    None => "",
                };
            }
        }
    } else if b.len() >= 2 && b[1] == b':' && (b[0] as char).is_ascii_alphabetic() {
        rest = &rest[2..];
    }
    rest.split(is_sep).rfind(|c| !c.is_empty() && *c != ".").unwrap_or("")
}

/// One `PdbSignatureScanner` hit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsdsMatch {
    /// Absolute offset of the "RSDS" (`data_offset + match.start()`).
    pub offset: u64,
    /// 32 uppercase hex digits.
    pub guid: String,
    pub age: u32,
    /// The matched name (one of `pdb_names`).
    pub pdb_name: Vec<u8>,
}

/// Finds the next "RSDS" at or after `from`.
#[inline]
fn find_rsds(data: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::*;
        // SAFETY: SSE2 is part of the x86_64 baseline; loads stay within `data` because
        // i + 3 + 16 <= data.len().
        unsafe {
            let r = _mm_set1_epi8(b'R' as i8);
            let s = _mm_set1_epi8(b'S' as i8);
            while i + 19 <= data.len() {
                let a = _mm_loadu_si128(data.as_ptr().add(i) as *const __m128i);
                let c = _mm_loadu_si128(data.as_ptr().add(i + 3) as *const __m128i);
                let mut m = _mm_movemask_epi8(_mm_and_si128(_mm_cmpeq_epi8(a, r), _mm_cmpeq_epi8(c, s))) as u32;
                while m != 0 {
                    let p = i + m.trailing_zeros() as usize;
                    if data[p + 1] == b'S' && data[p + 2] == b'D' {
                        return Some(p);
                    }
                    m &= m - 1;
                }
                i += 16;
            }
        }
    }
    while i + 4 <= data.len() {
        if &data[i..i + 4] == b"RSDS" {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// `PdbSignatureScanner(pdb_names)(data, data_offset)`: matches of
/// `RSDS.{20}(name1|name2|...)\x00` (non-overlapping, leftmost, alternatives tried in list
/// order) that start before `chunk_size` (pass `data.len()` to get all of them).
pub fn rsds_scan(data: &[u8], data_offset: u64, chunk_size: usize, pdb_names: &[&[u8]]) -> Vec<RsdsMatch> {
    let mut out = Vec::new();
    if pdb_names.is_empty() {
        return out; // python: the empty group matches but `b"" in []` is False
    }
    let mut pos = 0usize;
    while let Some(p) = find_rsds(data, pos) {
        if p >= chunk_size {
            break;
        }
        let name_at = p + 24;
        let hit = if name_at <= data.len() {
            let rest = &data[name_at..];
            pdb_names.iter().find(|n| rest.len() > n.len() && rest.starts_with(n) && rest[n.len()] == 0)
        } else {
            None
        };
        match hit {
            Some(n) => {
                let g = &data[p + 4..p + 20];
                out.push(RsdsMatch {
                    offset: data_offset + p as u64,
                    guid: guid_string(g),
                    age: u32::from_le_bytes([data[p + 20], data[p + 21], data[p + 22], data[p + 23]]),
                    pdb_name: n.to_vec(),
                });
                pos = name_at + n.len() + 1;
            }
            None => pos = p + 1,
        }
    }
    out
}

/// The backwards page walk of `PDBUtility.pdbname_scan` looking for the "MZ" of the image
/// holding the signature at `signature_offset` (pages `sig_pfn ..= min_pfn + 1`).
pub fn find_mz_before(
    layer: &dyn Layer,
    signature_offset: u64,
    page_size: u64,
    min_pfn: u64,
    maximum_invalid_count: u32,
) -> Option<u64> {
    if page_size == 0 {
        return None;
    }
    let sig_pfn = signature_offset / page_size;
    let mut invalid = 0u32;
    let mut i = sig_pfn;
    while i > min_pfn {
        if invalid > maximum_invalid_count {
            break;
        }
        let addr = i.wrapping_mul(page_size);
        if !layer.is_valid(addr, 2) {
            invalid += 1;
            i -= 1;
            continue;
        }
        let mut b = [0u8; 2];
        if layer.read(addr, &mut b).is_ok() && &b == b"MZ" {
            return Some(addr);
        }
        i -= 1;
    }
    None
}

/// One result of `PDBUtility.pdbname_scan`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdbScanResult {
    #[allow(non_snake_case)]
    pub GUID: String,
    pub age: u32,
    pub pdb_name: String,
    pub signature_offset: u64,
    pub mz_offset: Option<u64>,
}

/// The stateful part of `PDBUtility.pdbname_scan`: feed it the scanner hits in ascending
/// order; it performs the MZ back-search between the previous hit's page and this one.
pub struct PdbNameScan {
    page_size: u64,
    maximum_invalid_count: u32,
    min_pfn: u64,
}

impl PdbNameScan {
    pub fn new(page_size: u64, maximum_invalid_count: u32) -> PdbNameScan {
        PdbNameScan { page_size, maximum_invalid_count, min_pfn: 0 }
    }

    pub fn next(&mut self, layer: &dyn Layer, hit: &RsdsMatch) -> PdbScanResult {
        let mz = find_mz_before(layer, hit.offset, self.page_size, self.min_pfn, self.maximum_invalid_count);
        if let Some(pfn) = hit.offset.checked_div(self.page_size) {
            self.min_pfn = pfn;
        }
        PdbScanResult {
            GUID: hit.guid.clone(),
            age: hit.age,
            pdb_name: String::from_utf8_lossy(&hit.pdb_name).into_owned(),
            signature_offset: hit.offset,
            mz_offset: mz,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rsds(name: &[u8], age: u32) -> Vec<u8> {
        let mut v = b"RSDS".to_vec();
        v.extend_from_slice(&[0xd6, 0x73, 0x33, 0x8e, 0x4e, 0x12, 0x7f, 0x74, 0x0e, 0x72, 0xef, 0x8e, 0x02, 0xe6, 0x76, 0xb3]);
        v.extend_from_slice(&age.to_le_bytes());
        v.extend_from_slice(name);
        v.push(0);
        v
    }

    #[test]
    fn scan_matches_python_regex() {
        let mut data = vec![0u8; 100];
        data.extend(rsds(b"ntkrnlmp.pdb", 1));
        data.extend_from_slice(b"RSDSRSDS");
        data.extend(rsds(b"ntoskrnl.pdb", 2));
        data.extend(rsds(b"other.pdb", 3));
        data.extend(vec![0u8; 40]);
        let names: [&[u8]; 3] = [b"ntkrnlmp.pdb", b"ntoskrnl.pdb", b"ntkrnlpa.pdb"];
        let m = rsds_scan(&data, 0x1000, data.len(), &names);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].offset, 0x1000 + 100);
        assert_eq!(m[0].guid, "8E3373D6124E747F0E72EF8E02E676B3");
        assert_eq!(m[0].age, 1);
        assert_eq!(m[1].pdb_name, b"ntoskrnl.pdb");
        assert_eq!(m[1].age, 2);
        // chunk_size limits where matches may start
        assert_eq!(rsds_scan(&data, 0, 100, &names).len(), 0);
        assert_eq!(rsds_scan(&data, 0, 101, &names).len(), 1);
        // unaligned / short buffers
        for cut in 0..data.len() {
            let _ = rsds_scan(&data[cut..], 0, data.len(), &names);
        }
    }

    #[test]
    fn win_path_name() {
        assert_eq!(windows_path_name("d:\\a\\b\\ntkrnlmp.pdb"), "ntkrnlmp.pdb");
        assert_eq!(windows_path_name("ntkrnlmp.pdb"), "ntkrnlmp.pdb");
        assert_eq!(windows_path_name("C:foo.pdb"), "foo.pdb");
        assert_eq!(windows_path_name("a/b/c.pdb"), "c.pdb");
        assert_eq!(windows_path_name("\\\\srv\\share\\x.pdb"), "x.pdb");
        assert_eq!(windows_path_name("\\\\srv\\share"), "");
        assert_eq!(windows_path_name("a\\b\\"), "b");
        assert_eq!(windows_path_name(""), "");
    }

    /// Minimal PE32+ image with one section holding a debug directory + RSDS record.
    pub(crate) fn tiny_pe(name: &[u8]) -> Vec<u8> {
        let mut img = vec![0u8; 0x3000];
        img[0..2].copy_from_slice(b"MZ");
        img[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let nt = 0x80;
        img[nt..nt + 4].copy_from_slice(b"PE\0\0");
        img[nt + 6..nt + 8].copy_from_slice(&1u16.to_le_bytes());
        img[nt + 0x14..nt + 0x16].copy_from_slice(&240u16.to_le_bytes());
        let opt = nt + 0x18;
        img[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        img[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        img[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        img[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        img[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        img[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        let dd = opt + 112 + 6 * 8;
        img[dd..dd + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        img[dd + 4..dd + 8].copy_from_slice(&28u32.to_le_bytes());
        let sec = opt + 240;
        img[sec..sec + 5].copy_from_slice(b".rdat");
        img[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        img[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        img[sec + 16..sec + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        img[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes());
        // debug directory entry at RVA 0x1000
        let cv = rsds(name, 7);
        let d = 0x1000;
        img[d + 12..d + 16].copy_from_slice(&2u32.to_le_bytes());
        img[d + 16..d + 20].copy_from_slice(&(cv.len() as u32).to_le_bytes());
        img[d + 20..d + 24].copy_from_slice(&0x1040u32.to_le_bytes());
        img[d + 24..d + 28].copy_from_slice(&0x440u32.to_le_bytes()); // file offset
        img[0x1040..0x1040 + cv.len()].copy_from_slice(&cv);
        img
    }

    #[test]
    fn codeview_from_image() {
        let img = tiny_pe(b"d:\\build\\ntkrnlmp.pdb");
        assert_eq!(pe_image_size(&img), Some(0x3000));
        let cv = pe_codeview_info(&img).unwrap();
        assert_eq!(cv.guid, "8E3373D6124E747F0E72EF8E02E676B3");
        assert_eq!(cv.age, 7);
        assert_eq!(cv.pdb_name, "ntkrnlmp.pdb");
        // truncated images are zero padded, never panic
        for cut in (0..img.len()).step_by(7) {
            let _ = pe_codeview_info(&img[..cut]);
        }
        let mut bad = img.clone();
        bad[0x80] = b'X';
        assert!(pe_codeview_info(&bad).is_none());
    }
}
