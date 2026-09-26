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
            for m in collect_runs(layer, start, length) {
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
            }
        }
    }
    out
}

/// Granularity (log2) of the parallel mapping enumeration of Intel layers: no page (4 KiB up to
/// 1 GiB) crosses such a boundary.
const RUN_PIECE_BITS: u32 = 30;

/// python `layer.mapping(start, length, ignore_errors=True)` as a Vec (runs coalesced exactly
/// like python). Large ranges of Intel layers are enumerated in parallel: the range is cut at
/// 1 GiB boundaries (a cheap sequential pass drops pieces under invalid upper-level entries,
/// which python's walk skips as a whole too), pieces are walked concurrently and runs that
/// meet at a boundary contiguously in both spaces are merged again. The page-by-page walk
/// visits every piece boundary it does not skip over, so the result is identical.
fn collect_runs(layer: &dyn Layer, start: u64, length: u64) -> Vec<Mapping> {
    let mut out: Vec<Mapping> = Vec::new();
    let g = 1u128 << RUN_PIECE_BITS;
    let intel = layer.as_intel().filter(|_| length as u128 >= 8 * g && par::threads() > 1);
    let Some(intel) = intel else {
        layer.mapping(start, length, &mut |m| {
            out.push(m);
            true
        });
        return out;
    };
    let end = start as u128 + length as u128;
    let mut pieces: Vec<(u64, u64)> = Vec::new();
    let mut x = start as u128;
    while x < end {
        let pend = (((x >> RUN_PIECE_BITS) + 1) << RUN_PIECE_BITS).min(end);
        if let Err(f) = intel.translate_raw(x as u64) {
            if f.invalid_bits > RUN_PIECE_BITS && f.invalid_bits < 64 {
                let span = 1u128 << f.invalid_bits;
                x = (x / span + 1) * span;
                continue;
            }
        }
        pieces.push((x as u64, (pend - x) as u64));
        x = pend;
    }
    let parts: Vec<Vec<Mapping>> = par::par_map(pieces.len(), |i| {
        let (s, l) = pieces[i];
        let mut v = Vec::new();
        layer.mapping(s, l, &mut |m| {
            v.push(m);
            true
        });
        v
    });
    out.reserve(parts.iter().map(|p| p.len()).sum());
    for part in parts {
        let mut it = part.into_iter();
        if let Some(first) = it.next() {
            match out.last_mut() {
                Some(last) if last.offset.wrapping_add(last.len) == first.offset && last.mapped.wrapping_add(last.len) == first.mapped => {
                    last.len += first.len;
                }
                _ => out.push(first),
            }
        }
        out.extend(it);
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

// ---------------------------------------------------------------------------------------------
// Execution plan
//
// python's chunk list is fixed (see the module docs); how the chunks are *executed* is ours:
//   * big file-backed chunks (python's 16 MiB data-layer chunks) are one work item each, read
//     through a private `MapWindow` (map -> scan -> unmap on the worker: page-table setup and
//     teardown run in parallel and never pile up in the global mapping);
//   * small chunks (translation-layer runs, mostly single 4 KiB pages scattered over the file)
//     are batched into rounds of consecutive chunks; inside a round they are grouped by the
//     4 MiB file window they live in, and each window is one work item (one mmap, dense
//     sequential faults, one munmap). Hits are buffered per round and emitted in chunk order,
//     so results keep python's order and an early stop wastes at most one round;
//   * chunks that are not one contiguous span of the backing file are read through the layer.
// ---------------------------------------------------------------------------------------------

/// Tuning knob (temporary): env override of a constant.
fn knob(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Chunks at least this big are a work item of their own.
const BIG_CHUNK: u64 = 1 << 20;
/// Small chunks are grouped by file window of this size (log2).
const WIN_SHIFT: u32 = 22;
/// Bytes of small chunks per round (bounds the work wasted by an early stop).
const ROUND_BYTES: u64 = 256 << 20;
/// Generic (read-through-the-layer) items carry about this many bytes.
const GENERIC_ITEM_BYTES: u64 = 4 << 20;
/// Marker for chunks that are not one span of the backing file.
const NO_FILE: u64 = u64::MAX;

#[derive(Clone, Copy, Debug)]
enum Item {
    /// one chunk, file-backed at `off`
    Big { chunk: u32, off: u64 },
    /// chunks `idx[a..b]` (ascending), all file-backed inside the file range `[lo, hi)`
    Group { a: u32, b: u32, lo: u64, hi: u64 },
    /// chunks `idx[a..b]` (ascending), read through the layer
    Generic { a: u32, b: u32 },
}

struct Plan<'a> {
    chunks: Vec<Chunk>,
    /// file offset of each chunk (`NO_FILE` if not file-backed)
    offs: Vec<u64>,
    file: Option<&'a FileLayer>,
    /// chunk indices referenced by `Group` / `Generic` items
    idx: Vec<u32>,
    items: Vec<Item>,
    /// `round_end[i]`: item `i` is the last of its round
    round_end: Vec<bool>,
}

/// Hits of one work item: `hits` plus `(chunk, end)` spans (chunks ascending, chunks without
/// hits omitted; a span starts where the previous one ended).
struct ItemOut<H> {
    hits: Vec<H>,
    spans: Vec<(u32, u32)>,
}

fn chunk_source<'a>(layer: &'a dyn Layer, c: &Chunk) -> Option<(&'a FileLayer, u64)> {
    match c.src {
        Src::Layer => file_span(layer, c.start, c.len),
        Src::Lower(m) => layer.lower().and_then(|l| file_span(l.as_ref(), m, c.len)),
    }
}

fn make_plan(layer: &dyn Layer, chunks: Vec<Chunk>) -> Plan<'_> {
    let mut file: Option<&FileLayer> = None;
    let mut offs = Vec::with_capacity(chunks.len());
    for c in &chunks {
        let off = match chunk_source(layer, c) {
            Some((f, off)) => match file {
                None => {
                    file = Some(f);
                    off
                }
                Some(g) if std::ptr::eq(f, g) => off,
                Some(_) => NO_FILE,
            },
            None => NO_FILE,
        };
        offs.push(off);
    }
    let mut plan = Plan { chunks, offs, file, idx: Vec::new(), items: Vec::new(), round_end: Vec::new() };
    let n = plan.chunks.len();
    let mut round_start = 0usize;
    let mut round_bytes = 0u64;
    let mut i = 0usize;
    while i < n {
        let c = plan.chunks[i];
        if c.len >= BIG_CHUNK {
            close_round(&mut plan, round_start, i);
            if plan.offs[i] != NO_FILE {
                plan.items.push(Item::Big { chunk: i as u32, off: plan.offs[i] });
            } else {
                let a = plan.idx.len() as u32;
                plan.idx.push(i as u32);
                plan.items.push(Item::Generic { a, b: a + 1 });
            }
            plan.round_end.push(true);
            i += 1;
            round_start = i;
            round_bytes = 0;
            continue;
        }
        round_bytes += c.len;
        i += 1;
        if round_bytes >= knob("RSVOL_SCAN_ROUND", ROUND_BYTES >> 20) << 20 {
            close_round(&mut plan, round_start, i);
            round_start = i;
            round_bytes = 0;
        }
    }
    close_round(&mut plan, round_start, n);
    plan
}

/// Turn the small chunks `[start, end)` into window groups (+ generic items) forming one round.
fn close_round(plan: &mut Plan, start: usize, end: usize) {
    if start >= end {
        return;
    }
    let first_item = plan.items.len();
    // file-backed: group by window, ascending chunk index inside each group
    let mut keyed: Vec<(u64, u32)> = (start..end).filter(|&i| plan.offs[i] != NO_FILE).map(|i| (plan.offs[i] >> knob("RSVOL_SCAN_WIN", WIN_SHIFT as u64), i as u32)).collect();
    keyed.sort_unstable();
    let mut k = 0;
    while k < keyed.len() {
        let key = keyed[k].0;
        let a = plan.idx.len() as u32;
        let (mut lo, mut hi) = (u64::MAX, 0u64);
        while k < keyed.len() && keyed[k].0 == key {
            let ci = keyed[k].1 as usize;
            let off = plan.offs[ci];
            lo = lo.min(off);
            hi = hi.max(off + plan.chunks[ci].len);
            plan.idx.push(ci as u32);
            k += 1;
        }
        let b = plan.idx.len() as u32;
        plan.items.push(Item::Group { a, b, lo, hi });
    }
    // not file-backed: consecutive items of ~GENERIC_ITEM_BYTES
    let mut a = plan.idx.len() as u32;
    let mut bytes = 0u64;
    for i in start..end {
        if plan.offs[i] != NO_FILE {
            continue;
        }
        plan.idx.push(i as u32);
        bytes += plan.chunks[i].len;
        if bytes >= GENERIC_ITEM_BYTES {
            let b = plan.idx.len() as u32;
            plan.items.push(Item::Generic { a, b });
            a = b;
            bytes = 0;
        }
    }
    if (plan.idx.len() as u32) > a {
        plan.items.push(Item::Generic { a, b: plan.idx.len() as u32 });
    }
    let n_new = plan.items.len() - first_item;
    for j in 0..n_new {
        plan.round_end.push(j + 1 == n_new);
    }
}

thread_local! {
    static BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Read chunk `c` through the layer (python `_scan_chunk`: unreadable -> empty data).
fn read_chunk<R>(layer: &dyn Layer, c: &Chunk, f: impl FnOnce(&[u8]) -> R) -> R {
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

/// Map `[lo, hi)` of `file` privately and run `f` on it (falls back to the global mapping).
#[inline]
fn with_window<R>(file: &FileLayer, lo: u64, hi: u64, f: impl FnOnce(&[u8]) -> R) -> R {
    let len = (hi - lo) as usize;
    match crate::util::mmap::MapWindow::new(file.file(), lo, len, false) {
        Ok(w) => f(w.as_slice()),
        Err(_) => f(file.slice(lo, len).unwrap_or(&[])),
    }
}

fn run_item<S: Scanner>(layer: &dyn Layer, scanner: &S, plan: &Plan, item: Item) -> ItemOut<S::Hit> {
    let mut out = ItemOut { hits: Vec::new(), spans: Vec::new() };
    let push_span = |out: &mut ItemOut<S::Hit>, ci: u32| {
        let end = out.hits.len() as u32;
        let prev = out.spans.last().map(|s| s.1).unwrap_or(0);
        if end > prev {
            out.spans.push((ci, end));
        }
    };
    match item {
        Item::Big { chunk, off } => {
            let c = &plan.chunks[chunk as usize];
            let file = plan.file.expect("file-backed item without file");
            with_window(file, off, off + c.len, |data| {
                if !data.is_empty() {
                    scanner.scan(data, c.start, &mut out.hits);
                }
            });
            push_span(&mut out, chunk);
        }
        Item::Group { a, b, lo, hi } => {
            let file = plan.file.expect("file-backed item without file");
            with_window(file, lo, hi, |win| {
                for &ci in &plan.idx[a as usize..b as usize] {
                    let c = &plan.chunks[ci as usize];
                    let s = (plan.offs[ci as usize] - lo) as usize;
                    if let Some(data) = win.get(s..s + c.len as usize) {
                        scanner.scan(data, c.start, &mut out.hits);
                    }
                    push_span(&mut out, ci);
                }
            });
        }
        Item::Generic { a, b } => {
            for &ci in &plan.idx[a as usize..b as usize] {
                let c = &plan.chunks[ci as usize];
                read_chunk(layer, c, |data| {
                    if !data.is_empty() {
                        scanner.scan(data, c.start, &mut out.hits);
                    }
                });
                push_span(&mut out, ci);
            }
        }
    }
    out
}

/// Emit the hits of one round in chunk order; false if `f` asked to stop.
fn emit_round<H, F: FnMut(H) -> bool>(outs: &mut Vec<ItemOut<H>>, f: &mut F) -> bool {
    if outs.len() == 1 {
        let o = outs.pop().unwrap();
        for h in o.hits {
            if !f(h) {
                return false;
            }
        }
        return true;
    }
    // k-way merge by chunk index (each item's spans are ascending)
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    let mut iters: Vec<(std::vec::IntoIter<H>, Vec<(u32, u32)>, usize, u32)> = outs.drain(..).map(|o| (o.hits.into_iter(), o.spans, 0usize, 0u32)).collect();
    let mut heap: BinaryHeap<Reverse<(u32, u32)>> = BinaryHeap::new();
    for (k, it) in iters.iter().enumerate() {
        if let Some(&(ci, _)) = it.1.first() {
            heap.push(Reverse((ci, k as u32)));
        }
    }
    while let Some(Reverse((_, k))) = heap.pop() {
        let it = &mut iters[k as usize];
        let (_, end) = it.1[it.2];
        let n = end - it.3;
        for _ in 0..n {
            if let Some(h) = it.0.next() {
                if !f(h) {
                    return false;
                }
            }
        }
        it.3 = end;
        it.2 += 1;
        if let Some(&(ci, _)) = it.1.get(it.2) {
            heap.push(Reverse((ci, k)));
        }
    }
    true
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
/// to stop (remaining chunks are abandoned). Work items are scanned in parallel with bounded
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
    let chunks = {
        let _t = crate::util::trace::span("scan: build chunks");
        build_chunks(layer, scanner.chunk_size(), scanner.overlap(), &secs)
    };
    if chunks.is_empty() {
        return;
    }
    let total: u64 = chunks.iter().map(|c| c.len).sum();
    // small scans: no threads, no windows
    if total < (4 << 20) {
        let mut hits = Vec::new();
        for c in &chunks {
            match chunk_source(layer, c).and_then(|(file, off)| file.slice(off, c.len as usize)) {
                Some(data) => scanner.scan(data, c.start, &mut hits),
                None => read_chunk(layer, c, |data| {
                    if !data.is_empty() {
                        scanner.scan(data, c.start, &mut hits)
                    }
                }),
            }
            for h in hits.drain(..) {
                if !f(h) {
                    return;
                }
            }
        }
        return;
    }
    let plan = {
        let _t = crate::util::trace::span("scan: plan");
        make_plan(layer, chunks)
    };
    let _t = crate::util::trace::span("scan: execute");
    let lookahead = par::threads() * knob("RSVOL_SCAN_LA", 4) as usize;
    let mut round: Vec<ItemOut<S::Hit>> = Vec::new();
    par::par_map_stream(
        plan.items.len(),
        lookahead,
        |i| run_item(layer, scanner, &plan, plan.items[i]),
        |i, out| {
            round.push(out);
            if plan.round_end[i] { emit_round(&mut round, &mut f) } else { true }
        },
    );
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

/// Whether the AVX2 search kernels may be used (runtime detection; `RSVOL_NO_SIMD=1` forces the
/// scalar paths, for differential testing).
#[inline]
pub fn simd_enabled() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        static A: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *A.get_or_init(|| std::arch::is_x86_feature_detected!("avx2") && std::env::var_os("RSVOL_NO_SIMD").is_none_or(|v| v.is_empty() || v == "0"))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// python `scanners.MultiStringScanner(patterns)`: leftmost-longest, non-overlapping matches
/// (python builds a trie regex and uses `re.finditer`). Hit = (address, pattern index).
///
/// Search = a Teddy-style AVX2 prefilter (per-bucket nibble masks over the first `m <= 3`
/// bytes of every pattern, 64 input bytes per iteration: loads, `vpshufb`, `vpand`,
/// `vpmovmskb`) that yields candidate positions, each verified by walking the pattern trie.
/// Every position that starts a match passes the prefilter, so the result is exactly the
/// scalar leftmost-longest scan; the prefilter runs well above memory bandwidth per core.
pub struct MultiStringScanner {
    patterns: Vec<Vec<u8>>,
    /// trie: nodes[i] = sorted (byte, child) edges + terminal pattern index
    nodes: Vec<TrieNode>,
    /// first-byte filter (scalar path)
    first: [bool; 256],
    /// first-two-bytes filter (bitmap over u16), only when every pattern has >= 2 bytes
    pair: Option<Box<[u64; 1024]>>,
    teddy: Option<Teddy>,
    min_len: usize,
    chunk_size: u64,
    overlap: u64,
}

#[derive(Default, Clone)]
struct TrieNode {
    edges: Vec<(u8, u32)>,
    terminal: Option<u32>,
}

/// Teddy fingerprint tables: for fingerprint byte `j`, `lo[j][n]` / `hi[j][n]` hold the
/// buckets (bits) of the fingerprints whose byte `j` has low / high nibble `n` (each 16-entry
/// table is stored twice, once per 128-bit lane of a `vpshufb`).
#[derive(Clone)]
struct Teddy {
    m: usize,
    lo: [[u8; 32]; 3],
    hi: [[u8; 32]; 3],
}

impl Teddy {
    fn new(patterns: &[Vec<u8>], m: usize) -> Teddy {
        let mut fps: Vec<&[u8]> = patterns.iter().filter(|p| p.len() >= m).map(|p| &p[..m]).collect();
        fps.sort_unstable();
        fps.dedup();
        let n = fps.len();
        let mut t = Teddy { m, lo: [[0; 32]; 3], hi: [[0; 32]; 3] };
        for (i, fp) in fps.iter().enumerate() {
            // <= 8 fingerprints: one bucket each (exact); more: sorted runs share a bucket
            let bucket = if n <= 8 { i } else { i * 8 / n };
            let bit = 1u8 << bucket;
            for (j, &b) in fp.iter().enumerate() {
                for lane in [0, 16] {
                    t.lo[j][lane + (b & 0xf) as usize] |= bit;
                    t.hi[j][lane + (b >> 4) as usize] |= bit;
                }
            }
        }
        t
    }

    /// Scalar evaluation of the prefilter at `data[i..i + m]`.
    #[inline(always)]
    fn accepts(&self, data: &[u8], i: usize) -> bool {
        let mut r = 0xffu8;
        for j in 0..self.m {
            let b = data[i + j];
            r &= self.lo[j][(b & 0xf) as usize] & self.hi[j][(b >> 4) as usize];
        }
        r != 0
    }
}

/// Teddy search loop. Candidates `p < limit` (with `p + M <= data.len()`) are handed to
/// `verify`, which returns the next position a match may start at (`None` = stop).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn teddy_search<const M: usize>(t: &Teddy, data: &[u8], limit: usize, verify: &mut dyn FnMut(usize) -> Option<usize>) {
    use std::arch::x86_64::*;
    let n = data.len();
    let base = data.as_ptr();
    // SAFETY: the table loads read 32-byte arrays; block loads stay within `data` (checked by
    // the loop conditions: the last byte read is `i + 64 + M - 2 < n`).
    unsafe {
        let nib = _mm256_set1_epi8(0x0f);
        let zero = _mm256_setzero_si256();
        let lo0 = _mm256_loadu_si256(t.lo[0].as_ptr() as *const __m256i);
        let hi0 = _mm256_loadu_si256(t.hi[0].as_ptr() as *const __m256i);
        let lo1 = _mm256_loadu_si256(t.lo[1].as_ptr() as *const __m256i);
        let hi1 = _mm256_loadu_si256(t.hi[1].as_ptr() as *const __m256i);
        let lo2 = _mm256_loadu_si256(t.lo[2].as_ptr() as *const __m256i);
        let hi2 = _mm256_loadu_si256(t.hi[2].as_ptr() as *const __m256i);
        macro_rules! class {
            ($v:expr, $lo:expr, $hi:expr) => {
                _mm256_and_si256(
                    _mm256_shuffle_epi8($lo, _mm256_and_si256($v, nib)),
                    _mm256_shuffle_epi8($hi, _mm256_and_si256(_mm256_srli_epi16($v, 4), nib)),
                )
            };
        }
        macro_rules! block {
            ($p:expr) => {{
                let p = $p;
                let mut r = class!(_mm256_loadu_si256(p as *const __m256i), lo0, hi0);
                if M >= 2 {
                    r = _mm256_and_si256(r, class!(_mm256_loadu_si256(p.add(1) as *const __m256i), lo1, hi1));
                }
                if M >= 3 {
                    r = _mm256_and_si256(r, class!(_mm256_loadu_si256(p.add(2) as *const __m256i), lo2, hi2));
                }
                !(_mm256_movemask_epi8(_mm256_cmpeq_epi8(r, zero)) as u32)
            }};
        }
        let mut next = 0usize; // no match may start before this
        let mut i = 0usize;
        while i < limit && i + 64 + M - 1 <= n {
            let b0 = block!(base.add(i)) as u64;
            let b1 = block!(base.add(i + 32)) as u64;
            let mut bits = b0 | (b1 << 32);
            while bits != 0 {
                let p = i + bits.trailing_zeros() as usize;
                if p >= limit {
                    return;
                }
                match verify(p) {
                    Some(nx) => next = nx,
                    None => return,
                }
                let sh = next - i;
                bits = if sh >= 64 { 0 } else { bits & (!0u64 << sh) };
            }
            i = (i + 64).max(next);
        }
        while i < limit && i + 32 + M - 1 <= n {
            let mut bits = block!(base.add(i)) as u64;
            while bits != 0 {
                let p = i + bits.trailing_zeros() as usize;
                if p >= limit {
                    return;
                }
                match verify(p) {
                    Some(nx) => next = nx,
                    None => return,
                }
                let sh = next - i;
                bits = if sh >= 32 { 0 } else { bits & (!0u64 << sh) };
            }
            i = (i + 32).max(next);
        }
        while i < limit {
            if t.accepts(data, i) {
                match verify(i) {
                    Some(nx) => i = nx,
                    None => return,
                }
            } else {
                i += 1;
            }
        }
    }
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
        let min_len = if min_len == usize::MAX { 0 } else { min_len };
        let teddy = if min_len > 0 { Some(Teddy::new(&patterns, min_len.min(3))) } else { None };
        MultiStringScanner { patterns, nodes, first, pair, teddy, min_len, chunk_size: DEFAULT_CHUNK_SIZE, overlap: DEFAULT_OVERLAP }
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
    pub fn search(&self, data: &[u8], f: impl FnMut(usize, u32) -> bool) {
        self.search_limit(data, usize::MAX, simd_enabled(), f)
    }

    /// `search` restricted to matches starting before `max_start` (the matches found are
    /// exactly the prefix of the full result: the scan is left to right).
    fn search_limit(&self, data: &[u8], max_start: usize, simd: bool, mut f: impl FnMut(usize, u32) -> bool) {
        if self.min_len == 0 || data.len() < self.min_len {
            return;
        }
        let limit = (data.len() - self.min_len + 1).min(max_start);
        #[cfg(target_arch = "x86_64")]
        if simd {
            if let Some(t) = &self.teddy {
                let mut verify = |p: usize| -> Option<usize> {
                    match self.longest_at(data, p) {
                        Some((pi, len)) => {
                            if f(p, pi) {
                                Some(p + len)
                            } else {
                                None
                            }
                        }
                        None => Some(p + 1),
                    }
                };
                // SAFETY: AVX2 availability checked by `simd_enabled`.
                unsafe {
                    match t.m {
                        1 => teddy_search::<1>(t, data, limit, &mut verify),
                        2 => teddy_search::<2>(t, data, limit, &mut verify),
                        _ => teddy_search::<3>(t, data, limit, &mut verify),
                    }
                }
                return;
            }
        }
        let _ = simd;
        let mut i = 0usize;
        if let Some(pair) = &self.pair {
            while i < limit {
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
            while i < limit {
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
        let cs = usize::try_from(self.chunk_size).unwrap_or(usize::MAX);
        self.search_limit(data, cs, simd_enabled(), |off, pi| {
            hits.push((data_offset + off as u64, pi));
            true
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

    /// Tiny deterministic RNG for the differential tests.
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

    /// Brute-force leftmost-longest non-overlapping reference.
    fn naive_multi(patterns: &[Vec<u8>], data: &[u8], max_start: usize) -> Vec<(usize, u32)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < data.len() && i < max_start {
            let mut best: Option<(u32, usize)> = None;
            for (pi, p) in patterns.iter().enumerate() {
                if !p.is_empty() && data[i..].starts_with(p) && best.is_none_or(|(_, l)| p.len() > l) {
                    best = Some((pi as u32, p.len()));
                }
            }
            match best {
                Some((pi, l)) => {
                    out.push((i, pi));
                    i += l;
                }
                None => i += 1,
            }
        }
        out
    }

    #[test]
    fn multistring_simd_matches_naive() {
        let mut rng = Rng(0x9e3779b97f4a7c15);
        let alpha: [u8; 6] = [b'a', b'b', b'c', 0, 0xe3, b'P'];
        for trial in 0..3000 {
            let np = 1 + rng.below(12) as usize;
            let minl = 1 + rng.below(4) as usize;
            let patterns: Vec<Vec<u8>> = (0..np)
                .map(|_| {
                    let l = minl + rng.below(5) as usize;
                    (0..l).map(|_| if trial % 3 == 0 { rng.next() as u8 } else { alpha[rng.below(alpha.len() as u64) as usize] }).collect()
                })
                .collect();
            let n = rng.below(700) as usize;
            let data: Vec<u8> = (0..n).map(|_| alpha[rng.below(alpha.len() as u64) as usize]).collect();
            let s = MultiStringScanner::new(&patterns);
            for max_start in [usize::MAX, n / 2, 65, 64, 63, 1] {
                let want = naive_multi(&patterns, &data, max_start);
                for simd in [false, true] {
                    if simd && !simd_enabled() {
                        continue;
                    }
                    let mut got = Vec::new();
                    s.search_limit(&data, max_start, simd, |o, p| {
                        got.push((o, p));
                        true
                    });
                    assert_eq!(got, want, "trial {trial} simd {simd} max_start {max_start} patterns {patterns:?}");
                }
            }
        }
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

    /// Scan throughput on a real image:
    /// `RSVOL_BENCH_IMG=/path/img.raw cargo test --profile fast scan_bench -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn scan_bench() {
        use std::hint::black_box;
        use std::time::Instant;
        let Ok(path) = std::env::var("RSVOL_BENCH_IMG") else {
            eprintln!("set RSVOL_BENCH_IMG");
            return;
        };
        let reps: usize = std::env::var("RSVOL_BENCH_REPS").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
        let only = std::env::var("RSVOL_BENCH_ONLY").unwrap_or_default();
        let file = crate::layers::FileLayer::open(std::path::Path::new(&path)).unwrap();
        let mb = file.len() as f64 / 1e6;
        let run = |name: &str, f: &dyn Fn() -> usize| {
            if !only.is_empty() && !only.split(',').any(|o| name.starts_with(o)) {
                return;
            }
            let mut best = f64::MAX;
            let mut n = 0;
            for _ in 0..reps {
                let t = Instant::now();
                n = f();
                best = best.min(t.elapsed().as_secs_f64());
            }
            eprintln!("{name:<28} {:>8.1} ms  {:>8.0} MB/s  hits={n}", best * 1e3, mb / best);
        };
        let touch = FnScanner::new(|d: &[u8], _o: u64, h: &mut Vec<u64>| {
            let mut s = 0u64;
            let mut i = 0;
            while i < d.len() {
                s = s.wrapping_add(d[i] as u64);
                i += 4096;
            }
            if black_box(s) == 1 {
                h.push(s);
            }
        });
        run("touch-4k", &|| scan(&file, &touch, None).len());
        for mib in [1u64, 2, 4, 8, 32, 64] {
            let t2 = FnScanner::new(&touch.f).with_chunking(mib << 20, 0x1000);
            let name = format!("touch-4k item={mib}M");
            run(&name, &|| scan(&file, &t2, None).len());
        }
        let sum = FnScanner::new(|d: &[u8], _o: u64, h: &mut Vec<u64>| {
            let mut s = 0u64;
            for c in d.chunks_exact(8) {
                s = s.wrapping_add(u64::from_le_bytes(c.try_into().unwrap()));
            }
            if black_box(s) == 1 {
                h.push(s);
            }
        });
        run("sum-u64", &|| scan(&file, &sum, None).len());
        for mib in [1u64, 2, 4, 8, 32] {
            let t2 = FnScanner::new(&sum.f).with_chunking(mib << 20, 0x1000);
            let name = format!("sum-u64 item={mib}M");
            run(&name, &|| scan(&file, &t2, None).len());
        }
        // AVX2 streaming read (pure bandwidth)
        #[cfg(target_arch = "x86_64")]
        {
            let avx = FnScanner::new(|d: &[u8], _o: u64, h: &mut Vec<u64>| {
                #[target_feature(enable = "avx2")]
                unsafe fn or_all(d: &[u8]) -> u64 {
                    use std::arch::x86_64::*;
                    unsafe {
                        let mut a = _mm256_setzero_si256();
                        let mut b = _mm256_setzero_si256();
                        let mut i = 0;
                        while i + 64 <= d.len() {
                            a = _mm256_xor_si256(a, _mm256_loadu_si256(d.as_ptr().add(i) as *const __m256i));
                            b = _mm256_xor_si256(b, _mm256_loadu_si256(d.as_ptr().add(i + 32) as *const __m256i));
                            i += 64;
                        }
                        let x = _mm256_xor_si256(a, b);
                        _mm256_extract_epi64(x, 0) as u64
                    }
                }
                let s = unsafe { or_all(d) };
                if black_box(s) == 1 {
                    h.push(s);
                }
            });
            run("xor-avx2", &|| scan(&file, &avx, None).len());
            for mib in [2u64, 4, 8] {
                let t2 = FnScanner::new(&avx.f).with_chunking(mib << 20, 0x1000);
                let name = format!("xor-avx2 item={mib}M");
                run(&name, &|| scan(&file, &t2, None).len());
            }
        }
        run("bytes Proc", &|| scan(&file, &BytesScanner::new(b"Proc"), None).len());
        run("bytes KDBG", &|| scan(&file, &BytesScanner::new(b"KDBG"), None).len());
        let ps = MultiStringScanner::new(&[b"Pro\xe3".as_ref(), b"Proc"]);
        run("multi psscan(2)", &|| scan(&file, &ps, None).len());
        let tags: [&[u8]; 15] = [
            b"AtmT", b"Pro\xe3", b"Proc", b"Thr\xe5", b"Thre", b"Fil\xe5", b"File", b"Mut\xe1", b"Muta", b"Dri\xf6", b"Driv", b"MmLd", b"Sym\xe2",
            b"Symb", b"CM10",
        ];
        let all = MultiStringScanner::new(&tags);
        run("multi builtin(15)", &|| scan(&file, &all, None).len());
    }

    /// Single-thread search kernel throughput on cache-resident data:
    /// `cargo test --profile fast kernel_bench -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn kernel_bench() {
        use std::time::Instant;
        let mut rng = Rng(12345);
        let data: Vec<u8> = (0..(1 << 20)).map(|_| (rng.next() % 64) as u8 + if rng.below(4) == 0 { 0x40 } else { 0 }).collect();
        let tags: [&[u8]; 15] = [
            b"AtmT", b"Pro\xe3", b"Proc", b"Thr\xe5", b"Thre", b"Fil\xe5", b"File", b"Mut\xe1", b"Muta", b"Dri\xf6", b"Driv", b"MmLd", b"Sym\xe2",
            b"Symb", b"CM10",
        ];
        for (name, s) in [("psscan(2)", MultiStringScanner::new(&[b"Pro\xe3".as_ref(), b"Proc"])), ("builtin(15)", MultiStringScanner::new(&tags))] {
            for blk in [4096usize, 1 << 20] {
                for simd in [false, true] {
                    let reps = (256 << 20) / data.len();
                    let t = Instant::now();
                    let mut n = 0;
                    for _ in 0..reps {
                        for c in data.chunks(blk) {
                            s.search_limit(c, usize::MAX, simd, |_, _| {
                                n += 1;
                                true
                            });
                        }
                    }
                    let dt = t.elapsed().as_secs_f64();
                    eprintln!("{name:<12} block={blk:<8} simd={simd:<5} {:>8.0} MB/s  (hits {n})", (reps * data.len()) as f64 / dt / 1e6);
                }
            }
        }
        for simd in [false, true] {
            let _ = simd;
            let reps = (256 << 20) / data.len();
            let t = Instant::now();
            let mut n = 0;
            for _ in 0..reps {
                let mut pos = 0;
                while let Some(i) = find(&data[pos..], b"Proc") {
                    n += 1;
                    pos += i + 1;
                }
            }
            let dt = t.elapsed().as_secs_f64();
            eprintln!("memmem Proc {:>8.0} MB/s (hits {n})", (reps * data.len()) as f64 / dt / 1e6);
            break;
        }
    }

    /// Kernel virtual layer scan (what windows pool scanners do on Windows 10):
    /// `RSVOL_BENCH_IMG=... cargo test --profile fast vscan_bench -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn vscan_bench() {
        use std::time::Instant;
        let Ok(path) = std::env::var("RSVOL_BENCH_IMG") else {
            eprintln!("set RSVOL_BENCH_IMG");
            return;
        };
        let reps: usize = std::env::var("RSVOL_BENCH_REPS").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
        let ctx = crate::context::Context::new(crate::context::GlobalOptions { file: Some(path), ..Default::default() }).unwrap();
        let k = ctx.windows_kernel().unwrap();
        let l = k.vlayer;
        let secs = coalesce_sections(l, &default_sections(l));
        // parallel run enumeration == python's sequential walk
        let t = Instant::now();
        let mut seq = Vec::new();
        l.mapping(secs[0].0, secs[0].1, &mut |m| {
            seq.push(m);
            true
        });
        let t_seq = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let par_runs = collect_runs(l, secs[0].0, secs[0].1);
        let t_par = t.elapsed().as_secs_f64();
        assert!(seq == par_runs, "parallel runs differ: {} vs {}", seq.len(), par_runs.len());
        eprintln!("runs: {} sequential {:.1} ms, parallel {:.1} ms (identical)", seq.len(), t_seq * 1e3, t_par * 1e3);
        let mut best = f64::MAX;
        let mut chunks = Vec::new();
        for _ in 0..reps {
            let t = Instant::now();
            chunks = build_chunks(l, DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP, &secs);
            best = best.min(t.elapsed().as_secs_f64());
        }
        let total: u64 = chunks.iter().map(|c| c.len).sum();
        let small = chunks.iter().filter(|c| c.len <= 0x1000).count();
        eprintln!("build_chunks: {:.1} ms, {} chunks ({} <= 4K), {:.1} MB", best * 1e3, chunks.len(), small, total as f64 / 1e6);
        let ps = MultiStringScanner::new(&[b"Pro\xe3".as_ref(), b"Proc"]);
        let mut best = f64::MAX;
        let mut n = 0;
        for _ in 0..reps {
            let t = Instant::now();
            n = scan(l, &ps, None).len();
            best = best.min(t.elapsed().as_secs_f64());
        }
        eprintln!("vscan psscan(2): {:.1} ms, hits={n}", best * 1e3);
        let touch = FnScanner::new(|d: &[u8], _o: u64, h: &mut Vec<u64>| {
            let mut s = 0u64;
            let mut i = 0;
            while i < d.len() {
                s = s.wrapping_add(d[i] as u64);
                i += 4096;
            }
            if std::hint::black_box(s) == 1 {
                h.push(s);
            }
        });
        let mut best = f64::MAX;
        for _ in 0..reps {
            let t = Instant::now();
            n = scan(l, &touch, None).len();
            best = best.min(t.elapsed().as_secs_f64());
        }
        eprintln!("vscan touch: {:.1} ms, hits={n}", best * 1e3);
        let sum = FnScanner::new(|d: &[u8], _o: u64, h: &mut Vec<u64>| {
            let mut s = 0u64;
            for c in d.chunks_exact(8) {
                s = s.wrapping_add(u64::from_le_bytes(c.try_into().unwrap()));
            }
            if std::hint::black_box(s) == 1 {
                h.push(s);
            }
        });
        let mut best = f64::MAX;
        for _ in 0..reps {
            let t = Instant::now();
            n = scan(l, &sum, None).len();
            best = best.min(t.elapsed().as_secs_f64());
        }
        eprintln!("vscan sum: {:.1} ms, hits={n}", best * 1e3);
    }
}
