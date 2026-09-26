//! Parallel layer scanning with python-identical chunking (python `DataLayerInterface.scan`,
//! `_scan_iterator`, `layers/scanners`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! How python chunks a scan -- and therefore which hits it reports -- is reproduced exactly:
//!   * sections default to `[(min_address, max_address - min_address)]` (so the very last byte
//!     of a layer is never scanned) and are coalesced like `_coalesce_sections`;
//!   * data layers (the file layer): fixed chunks of `chunk_size + overlap` stepping by
//!     `chunk_size`; a chunk that cannot be read entirely is skipped entirely;
//!   * translation layers (Intel, containers): chunks never cross a `mapping()` run, each run is
//!     cut into `chunk_size + overlap` pieces stepping by `chunk_size`, so matches spanning two
//!     physically discontiguous pages are not found (same as python);
//!   * every chunk is handed to the scanner independently (scanner state such as the
//!     non-overlapping match position restarts per chunk), and a scanner only reports hits that
//!     start before `chunk_size` in its chunk; results come back in chunk order.
//!
//! Chunks are processed on all cores; big file-backed chunks are mapped with a private
//! [`MapWindow`](crate::util::mmap::MapWindow) per chunk (parallel page-table setup/teardown).
//!
//! ```ignore
//! let hits: Vec<u64> = scan(layer, &BytesScanner::new(b"KDBG"), None);
//! scan_each(layer, &MultiStringScanner::new(&tags), None, |(off, idx)| { ...; true });
//! ```

use super::{FileLayer, Layer, Mapping};
use crate::util::par;
use std::cell::RefCell;

/// python default `ScannerInterface.chunk_size` (16 MiB).
pub const DEFAULT_CHUNK_SIZE: u64 = 0x1000000;
/// python default `ScannerInterface.overlap` (one page).
pub const DEFAULT_OVERLAP: u64 = 0x1000;

/// A scanner (python `ScannerInterface`). Implementations must be thread-safe: chunks are
/// scanned concurrently. `scan` must follow the python contract: only report hits that
/// start before `chunk_size()` within `data` (they will be reported by the next chunk
/// otherwise), in ascending order.
pub trait Scanner: Sync {
    type Hit: Send;
    fn chunk_size(&self) -> u64 {
        DEFAULT_CHUNK_SIZE
    }
    fn overlap(&self) -> u64 {
        DEFAULT_OVERLAP
    }
    /// Scan one chunk; `data_offset` is the layer address of `data[0]`.
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<Self::Hit>);
}

/// Where a chunk's bytes come from.
#[derive(Clone, Copy, Debug)]
enum Src {
    /// read from the scanned layer itself at the chunk address
    Layer,
    /// read from the scanned layer's lower layer at this address (one mapping run)
    Lower(u64),
}

/// One scan chunk: `[start, start+len)` in the scanned layer.
#[derive(Clone, Copy, Debug)]
struct Chunk {
    start: u64,
    len: u64,
    src: Src,
}

/// python `_coalesce_sections` (including its quirks).
pub fn coalesce_sections(layer: &dyn Layer, sections: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut sorted: Vec<(u64, u64)> = sections.to_vec();
    sorted.sort();
    let mut result: Vec<(u128, u128)> = Vec::new();
    let mut position: u128 = 0;
    for (start, length) in sorted {
        let (start, length) = (start as u128, length as u128);
        if !result.is_empty() && start <= position {
            let (initial_start, _) = result.pop().unwrap();
            result.push((initial_start, (start + length) - initial_start));
        } else {
            result.push((start, length));
        }
        position = start + length;
    }
    let min = layer.min_address() as u128;
    let max = layer.max_address() as u128;
    // while result and result[0] < (min, 0)
    while let Some(&(first_start, first_length)) = result.first() {
        if (first_start, first_length) >= (min, 0) {
            break;
        }
        if first_start + first_length < min {
            result.remove(0);
        } else if first_start < min {
            result[0] = (min, (first_start + first_length) - min);
        } else {
            break;
        }
    }
    // while result and result[-1] > (max, 0): only pops sections starting beyond max
    // (python's clipping branch writes result[1], a bug we mirror by only popping)
    while let Some(&(last_start, last_length)) = result.last() {
        if (last_start, last_length) <= (max, 0) {
            break;
        }
        if last_start > max {
            result.pop();
        } else {
            // last_start == max and length > 0: python would loop forever / mangle; keep it
            break;
        }
    }
    result.into_iter().map(|(s, l)| (s as u64, l.min(u64::MAX as u128) as u64)).collect()
}

fn default_sections(layer: &dyn Layer) -> Vec<(u64, u64)> {
    vec![(layer.min_address(), layer.max_address() - layer.min_address())]
}

/// Build python's chunk list.
fn build_chunks(layer: &dyn Layer, chunk: u64, overlap: u64, sections: &[(u64, u64)]) -> Vec<Chunk> {
    let mut out = Vec::new();
    if layer.lower().is_none() {
        // DataLayerInterface._scan_iterator
        for &(start, length) in sections {
            let mut offset = start;
            let mut length = length;
            while length > 0 {
                let mut cs = length.min(chunk + overlap);
                out.push(Chunk { start: offset, len: cs, src: Src::Layer });
                if cs > chunk {
                    cs -= overlap;
                }
                length -= cs;
                offset = offset.wrapping_add(cs);
            }
        }
    } else {
        // TranslationLayerInterface._scan_iterator (linear): per mapping run
        for &(start, length) in sections {
            layer.mapping(start, length, &mut |m: Mapping| {
                let run_end = m.offset + m.len;
                let mut piece = m.offset;
                while piece < run_end {
                    let len = (run_end - piece).min(chunk + overlap);
                    out.push(Chunk { start: piece, len, src: Src::Lower(m.mapped + (piece - m.offset)) });
                    piece = match piece.checked_add(chunk) {
                        Some(p) => p,
                        None => break,
                    };
                }
                true
            });
        }
    }
    out
}

/// Resolve `[addr, addr+len)` of `layer` to one contiguous span of the backing file.
fn file_span(layer: &dyn Layer, addr: u64, len: u64) -> Option<(&FileLayer, u64)> {
    if let Some(f) = layer.as_file() {
        return if addr.checked_add(len)? <= f.len() { Some((f, addr)) } else { None };
    }
    let lower = layer.lower()?;
    let mut runs = [Mapping { offset: 0, len: 0, mapped: 0 }; 2];
    let mut n = 0;
    layer.mapping(addr, len, &mut |m| {
        if n < 2 {
            runs[n] = m;
        }
        n += 1;
        n < 2
    });
    if n != 1 || runs[0].offset != addr || runs[0].len != len {
        return None;
    }
    file_span(lower.as_ref(), runs[0].mapped, len)
}

/// Chunks at least this big are mapped with a private window instead of the global mapping.
const WINDOW_MIN: u64 = 1 << 20;

thread_local! {
    static BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Run `f` on the bytes of chunk `c` (empty slice if unreadable, like python).
fn with_chunk_data<R>(layer: &dyn Layer, c: &Chunk, f: impl FnOnce(&[u8]) -> R) -> R {
    // find the file span if any
    let span = match c.src {
        Src::Layer => file_span(layer, c.start, c.len),
        Src::Lower(m) => layer.lower().and_then(|l| file_span(l.as_ref(), m, c.len)),
    };
    if let Some((file, off)) = span {
        if c.len >= WINDOW_MIN {
            if let Some(w) = file.window(off, c.len as usize) {
                return f(w.as_slice());
            }
        }
        if let Some(s) = file.slice(off, c.len as usize) {
            return f(s);
        }
    }
    // generic path: read into a per-thread buffer
    BUF.with(|b| {
        let mut buf = b.borrow_mut();
        buf.resize(c.len as usize, 0);
        let ok = match c.src {
            Src::Layer => layer.read(c.start, &mut buf).is_ok(),
            Src::Lower(m) => match layer.lower() {
                Some(l) => l.read(m, &mut buf).is_ok(),
                None => false,
            },
        };
        if ok { f(&buf) } else { f(&[]) }
    })
}

/// Scan `layer` (python `layer.scan(context, scanner, sections=sections)`) and return all hits
/// in python order.
pub fn scan<S: Scanner>(layer: &dyn Layer, scanner: &S, sections: Option<&[(u64, u64)]>) -> Vec<S::Hit> {
    let mut all = Vec::new();
    scan_each(layer, scanner, sections, |h| {
        all.push(h);
        true
    });
    all
}

/// Streaming scan: `f` receives hits in python order on the calling thread; return `false`
/// to stop (remaining chunks are abandoned). Chunks are scanned in parallel with bounded
/// look-ahead, so stopping early wastes little work.
pub fn scan_each<S, F>(layer: &dyn Layer, scanner: &S, sections: Option<&[(u64, u64)]>, mut f: F)
where
    S: Scanner,
    F: FnMut(S::Hit) -> bool,
{
    let secs = match sections {
        Some(s) => coalesce_sections(layer, s),
        None => coalesce_sections(layer, &default_sections(layer)),
    };
    let chunks = build_chunks(layer, scanner.chunk_size(), scanner.overlap(), &secs);
    if chunks.is_empty() {
        return;
    }
    let total: u64 = chunks.iter().map(|c| c.len).sum();
    let run_chunk = |i: usize| -> Vec<S::Hit> {
        let c = &chunks[i];
        let mut hits = Vec::new();
        with_chunk_data(layer, c, |data| {
            if !data.is_empty() {
                scanner.scan(data, c.start, &mut hits);
            }
        });
        hits
    };
    // small scans: no threads
    if chunks.len() == 1 || total < (4 << 20) {
        for i in 0..chunks.len() {
            for h in run_chunk(i) {
                if !f(h) {
                    return;
                }
            }
        }
        return;
    }
    let lookahead = par::threads() * 2;
    let mut stop = false;
    par::par_map_stream(chunks.len(), lookahead, run_chunk, |_, hits| {
        for h in hits {
            if !f(h) {
                stop = true;
                return false;
            }
        }
        !stop
    });
}

/// Scan several sections of `layer` and collect `(chunk start, hits)`; convenience for tests.
pub fn chunk_layout(layer: &dyn Layer, chunk: u64, overlap: u64, sections: Option<&[(u64, u64)]>) -> Vec<(u64, u64)> {
    let secs = match sections {
        Some(s) => coalesce_sections(layer, s),
        None => coalesce_sections(layer, &default_sections(layer)),
    };
    build_chunks(layer, chunk, overlap, &secs).iter().map(|c| (c.start, c.len)).collect()
}

// ---------------------------------------------------------------------------------------------
// Scanners
// ---------------------------------------------------------------------------------------------

unsafe extern "C" {
    fn memmem(haystack: *const u8, hlen: usize, needle: *const u8, nlen: usize) -> *const u8;
}

/// Find the first occurrence of `needle` in `hay` (glibc `memmem`, SIMD accelerated).
#[inline]
pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if hay.len() < needle.len() {
        return None;
    }
    let p = unsafe { memmem(hay.as_ptr(), hay.len(), needle.as_ptr(), needle.len()) };
    if p.is_null() { None } else { Some(p as usize - hay.as_ptr() as usize) }
}

/// python `scanners.BytesScanner(needle)`: every (overlapping) occurrence. Hit = address.
pub struct BytesScanner {
    needle: Vec<u8>,
    chunk_size: u64,
    overlap: u64,
}

impl BytesScanner {
    pub fn new(needle: &[u8]) -> BytesScanner {
        BytesScanner { needle: needle.to_vec(), chunk_size: DEFAULT_CHUNK_SIZE, overlap: DEFAULT_OVERLAP }
    }
}

impl Scanner for BytesScanner {
    type Hit = u64;
    fn chunk_size(&self) -> u64 {
        self.chunk_size
    }
    fn overlap(&self) -> u64 {
        self.overlap
    }
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<u64>) {
        let mut pos = 0usize;
        while let Some(i) = find(&data[pos..], &self.needle) {
            let at = pos + i;
            if (at as u64) < self.chunk_size {
                hits.push(data_offset + at as u64);
            } else {
                break;
            }
            pos = at + 1;
            if pos > data.len() {
                break;
            }
        }
    }
}

/// python `scanners.MultiStringScanner(patterns)`: leftmost-longest, non-overlapping matches
/// (python builds a trie regex and uses `re.finditer`). Hit = (address, pattern index).
pub struct MultiStringScanner {
    patterns: Vec<Vec<u8>>,
    /// trie: nodes[i] = sorted (byte, child) edges + terminal pattern index
    nodes: Vec<TrieNode>,
    /// first-byte filter
    first: [bool; 256],
    /// first-two-bytes filter (bitmap over u16), only when every pattern has >= 2 bytes
    pair: Option<Box<[u64; 1024]>>,
    min_len: usize,
    chunk_size: u64,
    overlap: u64,
}

#[derive(Default, Clone)]
struct TrieNode {
    edges: Vec<(u8, u32)>,
    terminal: Option<u32>,
}

impl MultiStringScanner {
    /// Build from patterns (duplicates collapse to the first index; empty patterns are ignored).
    pub fn new<P: AsRef<[u8]>>(patterns: &[P]) -> MultiStringScanner {
        let patterns: Vec<Vec<u8>> = patterns.iter().map(|p| p.as_ref().to_vec()).collect();
        let mut nodes = vec![TrieNode::default()];
        let mut first = [false; 256];
        let mut min_len = usize::MAX;
        for (pi, p) in patterns.iter().enumerate() {
            if p.is_empty() {
                continue;
            }
            min_len = min_len.min(p.len());
            first[p[0] as usize] = true;
            let mut n = 0usize;
            for &b in p {
                let next = match nodes[n].edges.binary_search_by_key(&b, |e| e.0) {
                    Ok(i) => nodes[n].edges[i].1 as usize,
                    Err(i) => {
                        let id = nodes.len();
                        nodes.push(TrieNode::default());
                        nodes[n].edges.insert(i, (b, id as u32));
                        id
                    }
                };
                n = next;
            }
            if nodes[n].terminal.is_none() {
                nodes[n].terminal = Some(pi as u32);
            }
        }
        let pair = if min_len >= 2 && min_len != usize::MAX {
            let mut bm = Box::new([0u64; 1024]);
            for p in patterns.iter().filter(|p| p.len() >= 2) {
                let k = u16::from_le_bytes([p[0], p[1]]) as usize;
                bm[k >> 6] |= 1 << (k & 63);
            }
            Some(bm)
        } else {
            None
        };
        MultiStringScanner {
            patterns,
            nodes,
            first,
            pair,
            min_len: if min_len == usize::MAX { 0 } else { min_len },
            chunk_size: DEFAULT_CHUNK_SIZE,
            overlap: DEFAULT_OVERLAP,
        }
    }

    /// Pattern by index (hits carry the index).
    pub fn pattern(&self, idx: usize) -> &[u8] {
        &self.patterns[idx]
    }

    /// Longest pattern matching at `data[i..]`: (pattern index, length).
    #[inline]
    fn longest_at(&self, data: &[u8], i: usize) -> Option<(u32, usize)> {
        let mut n = 0usize;
        let mut best = None;
        let mut j = i;
        while j < data.len() {
            let b = data[j];
            let edges = &self.nodes[n].edges;
            let next = if edges.len() <= 8 {
                edges.iter().find(|e| e.0 == b).map(|e| e.1)
            } else {
                edges.binary_search_by_key(&b, |e| e.0).ok().map(|k| edges[k].1)
            };
            match next {
                Some(c) => {
                    n = c as usize;
                    j += 1;
                    if let Some(t) = self.nodes[n].terminal {
                        best = Some((t, j - i));
                    }
                }
                None => break,
            }
        }
        best
    }

    /// python `search(haystack)`: all leftmost-longest non-overlapping matches (offset, index).
    pub fn search(&self, data: &[u8], mut f: impl FnMut(usize, u32) -> bool) {
        if self.min_len == 0 {
            return;
        }
        let n = data.len();
        if n < self.min_len {
            return;
        }
        let mut i = 0usize;
        let last = n - self.min_len;
        if let Some(pair) = &self.pair {
            while i <= last {
                // candidate filter on the first two bytes
                let k = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
                if pair[k >> 6] & (1 << (k & 63)) != 0 {
                    if let Some((pi, len)) = self.longest_at(data, i) {
                        if !f(i, pi) {
                            return;
                        }
                        i += len;
                        continue;
                    }
                }
                i += 1;
            }
        } else {
            while i <= last {
                if self.first[data[i] as usize] {
                    if let Some((pi, len)) = self.longest_at(data, i) {
                        if !f(i, pi) {
                            return;
                        }
                        i += len;
                        continue;
                    }
                }
                i += 1;
            }
        }
    }
}

impl Scanner for MultiStringScanner {
    type Hit = (u64, u32);
    fn chunk_size(&self) -> u64 {
        self.chunk_size
    }
    fn overlap(&self) -> u64 {
        self.overlap
    }
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<(u64, u32)>) {
        let cs = self.chunk_size;
        self.search(data, |off, pi| {
            if (off as u64) < cs {
                hits.push((data_offset + off as u64, pi));
                true
            } else {
                // matches are ascending: nothing further can be reported
                false
            }
        });
    }
}

/// An ad-hoc scanner from a closure `f(data, data_offset, hits)` (e.g. a regex from the yara
/// engine). The closure must apply the `chunk_size` filter itself.
pub struct FnScanner<H, F> {
    pub f: F,
    pub chunk_size: u64,
    pub overlap: u64,
    _h: std::marker::PhantomData<fn() -> H>,
}

impl<H, F> FnScanner<H, F>
where
    F: Fn(&[u8], u64, &mut Vec<H>) + Sync,
{
    pub fn new(f: F) -> Self {
        FnScanner { f, chunk_size: DEFAULT_CHUNK_SIZE, overlap: DEFAULT_OVERLAP, _h: std::marker::PhantomData }
    }
    pub fn with_chunking(mut self, chunk_size: u64, overlap: u64) -> Self {
        self.chunk_size = chunk_size;
        self.overlap = overlap;
        self
    }
}

impl<H: Send, F> Scanner for FnScanner<H, F>
where
    F: Fn(&[u8], u64, &mut Vec<H>) + Sync,
{
    type Hit = H;
    fn chunk_size(&self) -> u64 {
        self.chunk_size
    }
    fn overlap(&self) -> u64 {
        self.overlap
    }
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<H>) {
        (self.f)(data, data_offset, hits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result;
    use std::sync::Arc;

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
                None => Err(crate::error::Error::invalid(addr)),
            }
        }
        fn is_valid(&self, addr: u64, len: u64) -> bool {
            addr + len <= self.0.len() as u64
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
            f(Mapping { offset: addr, len, mapped: addr });
        }
    }

    #[test]
    fn multistring_semantics() {
        let s = MultiStringScanner::new(&[b"ab".as_ref(), b"abcd", b"bc", b"aaaa"]);
        let mut v = Vec::new();
        s.search(b"xabcx abcd aaaaaa bc", |o, p| {
            v.push((o, p));
            true
        });
        // "abc": longest at 1 is "ab" (abcd fails) -> then "c" no; "abcd" at 6; "aaaa" at 11, then "aa" no
        assert_eq!(v, vec![(1, 0), (6, 1), (11, 3), (18, 2)]);
    }

    #[test]
    fn bytes_scanner_chunks() {
        // python semantics: last byte of the layer is never scanned
        let mut data = vec![0u8; 100];
        data[10..14].copy_from_slice(b"KDBG");
        data[96..100].copy_from_slice(b"KDBG");
        let l = Buf(data);
        let hits = scan(&l, &BytesScanner::new(b"KDBG"), None);
        assert_eq!(hits, vec![10]);
        let hits = scan(&l, &BytesScanner::new(b"KDB"), None);
        assert_eq!(hits, vec![10, 96]);
    }

    #[test]
    fn data_layer_chunking_matches_python() {
        let l = Buf(vec![0u8; 100]);
        // chunk 10, overlap 4, section (0, 25): python yields 0:14, 10:14(->24), 20:5
        let c = chunk_layout(&l, 10, 4, Some(&[(0, 25)]));
        assert_eq!(c, vec![(0, 14), (10, 14), (20, 5)]);
        // section of length 12 (C < L < C+O): python chunks 0:12 then 8:4 (duplicated region)
        let c = chunk_layout(&l, 10, 4, Some(&[(0, 12)]));
        assert_eq!(c, vec![(0, 12), (8, 4)]);
        let _ = Arc::new(0);
    }
}
