//! banners.Banners (python `plugins/banners.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! python scans the physical layer twice: a `RegExScanner`
//! `(Linux version|Darwin Kernel Version) [0-9]+\.[0-9]+\.[0-9]+` (overlap 0x1000), then a
//! `PdbSignatureScanner` for the kernel PDB names (overlap 0x4000). Both searches only depend on
//! the bytes around each match, so we read the image ONCE: one parallel pass finds every
//! occurrence of the three literals (`Linux version `, `Darwin Kernel Version `, `RSDS`) and
//! records where the shortest possible match ends. Python's two chunk lists are then replayed
//! over those occurrences (hits must start in a chunk's first `chunk_size` bytes and end inside
//! the chunk's data; `RSDS` matches are non-overlapping per chunk; python's tail chunks can
//! overlap and report a hit twice) - the result is exactly python's two hit lists.
//!
//! A banner candidate whose match needs more than `WINDOW` bytes can never be printed (python's
//! 0xFFF-byte read of it contains no NUL), so the verification window is bounded.

use crate::context::Context;
use crate::error::Result;
use crate::layers::scan::{MultiStringScanner, Scanner, chunk_layout, scan};
use crate::layers::{Layer, LayerExt};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};

pub struct Banners;

/// python `ScannerInterface.chunk_size`.
const CHUNK: u64 = 0x1000000;
/// `RegExScanner` overlap (default) and `PdbSignatureScanner.overlap`.
const BANNER_OVERLAP: u64 = 0x1000;
const PDB_OVERLAP: u64 = 0x4000;
/// Bytes a candidate may examine (> the 0xFFF bytes python reads per banner).
const WINDOW: usize = 0x1100;
/// python `constants.windows.KERNEL_MODULE_NAMES` + ".pdb".
const KERNEL_PDBS: [&[u8]; 4] = [b"ntkrnlmp.pdb", b"ntkrnlpa.pdb", b"ntkrpamp.pdb", b"ntoskrnl.pdb"];

const KIND_BANNER: u32 = 0;
const KIND_RSDS: u32 = 1;

/// The single pass: every literal occurrence that can start a match, tagged with its kind and
/// `end - start` of the shortest match (banner) / the match (RSDS, low 2 bits of the tag = kind).
struct Occurrences {
    lits: MultiStringScanner,
}

impl Occurrences {
    fn new() -> Occurrences {
        Occurrences { lits: MultiStringScanner::new(&[b"Linux version ".as_ref(), b"Darwin Kernel Version ", b"RSDS"]) }
    }

    /// Verify a candidate at `data[p..]` (literal `idx`): the tag, or None.
    #[inline]
    fn verify(data: &[u8], p: usize, idx: u32) -> Option<u32> {
        let end = data.len().min(p + WINDOW);
        if idx == 2 {
            // RSDS + 16-byte GUID + age + one of the names + NUL
            let at = p + 24;
            for (ni, n) in KERNEL_PDBS.iter().enumerate() {
                if at + n.len() < end && &data[at..at + n.len()] == *n && data[at + n.len()] == 0 {
                    return Some(KIND_RSDS | (ni as u32) << 2);
                }
            }
            return None;
        }
        // [0-9]+ \. [0-9]+ \. [0-9]  (shortest match end)
        let mut i = p + if idx == 0 { 14 } else { 22 };
        for group in 0..3 {
            let s = i;
            while i < end && data[i].is_ascii_digit() {
                i += 1;
            }
            if i == s {
                return None;
            }
            if group == 2 {
                return Some(KIND_BANNER | ((s + 1 - p) as u32) << 2);
            }
            if i >= end || data[i] != b'.' {
                return None;
            }
            i += 1;
        }
        None
    }

    /// Occurrences starting in `data[from..limit)` (and before `cs_limit`), `data` extending
    /// past `limit` for verification.
    fn search(&self, data: &[u8], base: u64, from: usize, limit: usize, out: &mut Vec<(u64, u32)>) {
        if from >= limit {
            return;
        }
        let stop = (limit + 21).min(data.len());
        self.lits.search(&data[from..stop], |o, idx| {
            let p = from + o;
            if p >= limit {
                return false;
            }
            if let Some(tag) = Self::verify(data, p, idx) {
                out.push((base + p as u64, tag));
            }
            true
        });
    }
}

impl Scanner for Occurrences {
    type Hit = (u64, u32);
    fn chunk_size(&self) -> u64 {
        CHUNK
    }
    fn overlap(&self) -> u64 {
        PDB_OVERLAP
    }
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<(u64, u32)>) {
        let mut m = Vec::new();
        self.prescan(data, &mut m);
        self.finish(&m, data_offset, hits);
    }
    fn prescan(&self, data: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
        let limit = data.len().min(CHUNK as usize);
        self.search(data, 0, 0, limit, out);
        true
    }
    fn finish(&self, matches: &[(u64, u32)], data_offset: u64, hits: &mut Vec<(u64, u32)>) {
        hits.extend(matches.iter().map(|&(o, t)| (data_offset + o, t)));
    }
    fn stream_window(&self) -> Option<usize> {
        Some(WINDOW + 1)
    }
    fn prescan_piece(&self, data: &[u8], base: u64, from: usize, limit: usize, out: &mut Vec<(u64, u32)>) -> usize {
        let cs_limit = CHUNK.saturating_sub(base).min(limit as u64) as usize;
        self.search(data, base, from, cs_limit, out);
        limit
    }
}

/// Replay python's chunk list `(start, len)` over the sorted occurrences: the hits of one
/// python scan, in python order.
fn replay(chunks: &[(u64, u64)], occ: &[(u64, u32)], kind: u32) -> Vec<(u64, u32)> {
    let mut hits = Vec::new();
    for &(start, len) in chunks {
        let report_end = start.saturating_add(len.min(CHUNK));
        let data_end = start.saturating_add(len);
        let mut i = occ.partition_point(|o| o.0 < start);
        let mut last_end = 0u64;
        while i < occ.len() && occ[i].0 < report_end {
            let (addr, tag) = occ[i];
            i += 1;
            if tag & 3 != kind {
                continue;
            }
            let end = if kind == KIND_RSDS { addr + 24 + KERNEL_PDBS[(tag >> 2) as usize].len() as u64 + 1 } else { addr + (tag >> 2) as u64 };
            if end > data_end || addr < last_end {
                continue;
            }
            if kind == KIND_RSDS {
                last_end = end;
            }
            hits.push((addr, tag));
        }
    }
    hits
}

/// python `bytes.strip()` (ASCII whitespace).
fn py_strip(b: &[u8]) -> &[u8] {
    let ws = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let s = b.iter().position(|c| !ws(c)).unwrap_or(b.len());
    let e = b.iter().rposition(|c| !ws(c)).map_or(s, |e| e + 1);
    &b[s..e.max(s)]
}

fn allowed(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b" #()+,;/-.:@_~".contains(&c)
}

/// python `Banners.locate_banners(context, layer_name)`: (offset, banner) rows (Linux/Mac
/// banners, then the Windows kernel PDB signatures). A read error is python's uncaught
/// `InvalidAddressException` from `layer.read(offset, 0xFFF)`.
pub fn locate_banners(layer: &dyn Layer) -> Result<Vec<(u64, String)>> {
    let mut occ = scan(layer, &Occurrences::new(), None);
    occ.sort_unstable();
    occ.dedup();
    let mut rows = Vec::new();
    for (off, _) in replay(&chunk_layout(layer, CHUNK, BANNER_OVERLAP, None), &occ, KIND_BANNER) {
        let data = layer.read_vec(off, 0xFFF)?;
        let Some(idx) = data.iter().position(|&b| b == 0) else { continue };
        if idx == 0 {
            continue;
        }
        let s = py_strip(&data[..idx]);
        if s.iter().all(|&c| allowed(c)) {
            rows.push((off, s.iter().map(|&c| c as char).collect()));
        }
    }
    for (off, tag) in replay(&chunk_layout(layer, CHUNK, PDB_OVERLAP, None), &occ, KIND_RSDS) {
        let name = std::str::from_utf8(KERNEL_PDBS[(tag >> 2) as usize]).unwrap_or("");
        // python unpacks these from the chunk it just matched: always readable
        let b = layer.read_vec_padded(off + 4, 20);
        const ORDER: [usize; 16] = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut guid = String::with_capacity(32);
        for &k in &ORDER {
            guid.push_str(&format!("{:02X}", b[k]));
        }
        let age = u32::from_le_bytes([b[16], b[17], b[18], b[19]]);
        rows.push((off, format!("{name}|{guid}|{age}")));
    }
    Ok(rows)
}

impl Plugin for Banners {
    fn name(&self) -> &'static str {
        "banners.Banners"
    }
    fn description(&self) -> &'static str {
        "Attempts to identify potential linux banners in an image"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let layer = super::primary::physical(ctx, "Memory layer to scan")?;
        out.begin(vec![Column::new("Offset", ColType::Hex), Column::new("Banner", ColType::Str)])?;
        for (off, banner) in locate_banners(layer)? {
            out.row(0, vec![Value::Int(off as i128), Value::Str(banner)])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_banner_and_rsds() {
        let d = b"Linux version 5.15.0-191 xyz";
        assert_eq!(Occurrences::verify(d, 0, 0), Some(KIND_BANNER | (19 << 2)));
        assert_eq!(Occurrences::verify(b"Linux version 5.15-1", 0, 0), None);
        assert_eq!(Occurrences::verify(b"Linux version 5.15.", 0, 0), None);
        let mut r = b"RSDS".to_vec();
        r.extend_from_slice(&[0u8; 20]);
        r.extend_from_slice(b"ntoskrnl.pdb\0");
        assert_eq!(Occurrences::verify(&r, 0, 2), Some(KIND_RSDS | (3 << 2)));
        r.pop();
        assert_eq!(Occurrences::verify(&r, 0, 2), None);
        assert_eq!(py_strip(b"  a b\t\n"), b"a b");
        assert_eq!(py_strip(b" \t "), b"");
    }

    #[test]
    fn replay_quirks() {
        // RSDS non-overlap within a chunk, duplicate reports from overlapping tail chunks
        let occ = vec![(10u64, KIND_RSDS | (3 << 2)), (20, KIND_RSDS), (100, KIND_RSDS)];
        let chunks = vec![(0u64, 200u64), (50, 200)];
        let h = replay(&chunks, &occ, KIND_RSDS);
        assert_eq!(h.iter().map(|x| x.0).collect::<Vec<_>>(), vec![10, 100, 100]);
        // matches must end inside the chunk data
        let h = replay(&[(0, 30)], &occ, KIND_RSDS);
        assert!(h.is_empty());
    }
}
