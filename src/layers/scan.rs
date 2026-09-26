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
//! Execution (all cores, python order, early stop) is described at "Execution plan" below.
//! Measured on a 5 GiB Windows 10 image (20 threads, warm page cache): a full physical-layer
//! `MultiStringScanner` scan ~150 ms (~35 GB/s, the machine's read bandwidth; python's trie
//! regex ~60 s), the kernel virtual layer (330k chunks, 1.8 GB of mapped pages, 0.7 GB
//! distinct) ~30 ms + 10 ms run enumeration.
//!
//! Search kernels: [`MultiStringScanner`] = AVX2 Teddy prefilter + trie verification (15-19
//! GB/s per core), [`BytesScanner`] = glibc `memmem`. Scanners may implement the two-phase
//! [`Scanner::prescan`] / [`Scanner::finish`] (pure byte search + per-chunk hits) and
//! [`Scanner::stream_window`] / [`Scanner::prescan_piece`] (piecewise reading); the pool
//! scanner does.
//!
//! ```ignore
//! let hits: Vec<u64> = scan(layer, &BytesScanner::new(b"KDBG"), None);
//! scan_each(layer, &MultiStringScanner::new(&tags), None, |(off, idx)| { ...; true });
//! ```

use super::{FileLayer, Layer, Mapping};
use crate::util::par;
use std::cell::RefCell;
use std::sync::Arc;

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
    /// Optional two-phase form for searches whose byte matching depends only on the chunk's
    /// bytes: `prescan` appends `(offset in data, tag)` matches (already filtered by the
    /// `chunk_size` rule) and returns true; `finish` turns one chunk's matches into hits (it
    /// may read memory, e.g. to validate a structure at the hit). Must satisfy
    /// `scan(d, o) == finish(prescan(d), o)`. The executor then scans identical file ranges
    /// (physical pages mapped at several virtual addresses) only once.
    fn prescan(&self, _data: &[u8], _out: &mut Vec<(u64, u32)>) -> bool {
        false
    }
    /// See [`Scanner::prescan`].
    fn finish(&self, _matches: &[(u64, u32)], _data_offset: u64, _hits: &mut Vec<Self::Hit>) {}
    /// Two-phase scanners whose matches examine at most `n` bytes from their start return
    /// `Some(n)`: big chunks are then read in small cache-resident pieces
    /// ([`Scanner::prescan_piece`]) instead of being mapped whole.
    fn stream_window(&self) -> Option<usize> {
        None
    }
    /// `prescan` of one piece of a chunk: `data` starts at offset `base` of the chunk and
    /// extends `stream_window() - 1` bytes past `limit` (or to the chunk's end). Append the
    /// matches starting in `[from, limit)` as `(base + position, tag)` and return where the
    /// next piece resumes (`>= limit`; beyond it when a match runs past `limit`, like the
    /// greedy non-overlapping search of one whole chunk).
    fn prescan_piece(&self, _data: &[u8], _base: u64, _from: usize, limit: usize, _out: &mut Vec<(u64, u32)>) -> usize {
        limit
    }
    /// Two-phase scanners: what their `prescan` computes, for the per-image scan cache
    /// ([`super::scancache`]): a full scan then records it, and later scans of the same layer,
    /// sections and chunking replay the cached matches through `finish` without reading the
    /// layer. `None` (the default) = never cached.
    fn cache_query(&self) -> Option<super::scancache::CacheQuery<'_>> {
        None
    }
}

/// Where a chunk's bytes come from.
#[derive(Clone, Copy, Debug)]
enum Src {
    /// read from the scanned layer itself at the chunk address
    Layer,
    /// read from the scanned layer's lower layer at this address (one mapping run)
    Lower(u64),
    /// read from dependency `.0` of the scanned layer (a Windows swap layer) at `.1`
    Dep(u8, u64),
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
    // while result and result[-1] > (max, 0) (tuple order: only sections starting at or beyond
    // max): pops those beyond max; python's clipping branch writes result[1] -- the last
    // section only when there are exactly two (one section: IndexError, more: endless loop;
    // we keep those)
    while let Some(&(last_start, last_length)) = result.last() {
        if (last_start, last_length) <= (max, 0) {
            break;
        }
        if last_start > max {
            result.pop();
        } else if last_start + last_length > max && result.len() == 2 {
            result[1] = (last_start, max - last_start);
        } else {
            break;
        }
    }
    result.into_iter().map(|(s, l)| (s as u64, l.min(u64::MAX as u128) as u64)).collect()
}

fn default_sections(layer: &dyn Layer) -> Vec<(u64, u64)> {
    vec![(layer.min_address(), layer.max_address() - layer.min_address())]
}

/// Build python's chunk list.
fn build_chunks(layer: &dyn Layer, deps: &[Arc<dyn Layer>], chunk: u64, overlap: u64, sections: &[(u64, u64)]) -> Vec<Chunk> {
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
            run_chunks(layer, deps, start, length, chunk, overlap, &mut out);
        }
    }
    out
}

/// A mapping run and the layer it maps into (0 = `lower()`, `i` = `dependencies()[i]`).
type Run = (Mapping, u8);

/// python `mapping()` runs of `[addr, addr+len)` with their target layer (python's scan also
/// reads runs that live in Windows swap layers); runs into unknown layers are skipped.
fn mapping_runs(layer: &dyn Layer, deps: &[Arc<dyn Layer>], addr: u64, len: u64, f: &mut dyn FnMut(Run)) {
    let lower = layer.lower().map(|l| Arc::as_ptr(l) as *const u8);
    layer.mapping_targets(addr, len, &mut |m, t| {
        let tp = t as *const dyn Layer as *const u8;
        if Some(tp) == lower {
            f((m, 0));
        } else if let Some(i) = deps.iter().position(|d| Arc::as_ptr(d) as *const u8 == tp).filter(|&i| i > 0 && i < 256) {
            f((m, i as u8));
        }
        true
    });
}

/// python's chunks of one mapping run: `chunk + overlap` pieces stepping by `chunk`.
#[inline]
fn cut_run((m, t): Run, chunk: u64, overlap: u64, out: &mut Vec<Chunk>) {
    let run_end = m.offset + m.len;
    let mut piece = m.offset;
    while piece < run_end {
        let len = (run_end - piece).min(chunk + overlap);
        let at = m.mapped + (piece - m.offset);
        out.push(Chunk { start: piece, len, src: if t == 0 { Src::Lower(at) } else { Src::Dep(t, at) } });
        piece = match piece.checked_add(chunk) {
            Some(p) => p,
            None => break,
        };
    }
}

/// Whether two runs are one python run (contiguous in both spaces, same target layer).
#[inline]
fn runs_join(a: &Run, b: &Run) -> bool {
    a.1 == b.1 && a.0.offset.wrapping_add(a.0.len) == b.0.offset && a.0.mapped.wrapping_add(a.0.len) == b.0.mapped
}

/// The chunks of `[start, start+length)` of a translation layer. Intel layers are walked in
/// parallel pieces (see [`run_pieces`]); each piece cuts its interior runs into chunks, and
/// only the runs at piece boundaries (which may continue in the neighbour) are joined and cut
/// sequentially.
fn run_chunks(layer: &dyn Layer, deps: &[Arc<dyn Layer>], start: u64, length: u64, chunk: u64, overlap: u64, out: &mut Vec<Chunk>) {
    if !layer.is_linear() {
        // python `_scan_iterator(linear=False)` (AVML, QEMU): every mapping() tuple is its own
        // block (nothing is coalesced) and is read through the layer itself, whose data is
        // decoded; the mapped offsets are compressed frames / fill bytes, not the data. Raw
        // spans still take the direct file path (`chunk_source` via `slice()`).
        mapping_runs(layer, deps, start, length, &mut |r| {
            let n = out.len();
            cut_run(r, chunk, overlap, out);
            for c in &mut out[n..] {
                c.src = Src::Layer;
            }
        });
        return;
    }
    let Some(pieces) = run_pieces(layer, start, length) else {
        let mut pending: Option<Run> = None;
        mapping_runs(layer, deps, start, length, &mut |r| match pending.as_mut() {
            Some(pr) if runs_join(pr, &r) => pr.0.len += r.0.len,
            _ => {
                if let Some(pr) = pending.replace(r) {
                    cut_run(pr, chunk, overlap, out);
                }
            }
        });
        if let Some(pr) = pending {
            cut_run(pr, chunk, overlap, out);
        }
        return;
    };
    struct PieceOut {
        first: Option<Run>,
        mid: Vec<Chunk>,
        last: Option<Run>,
    }
    let parts: Vec<PieceOut> = par::par_map(pieces.len(), |i| {
        let (s, l) = pieces[i];
        let mut p = PieceOut { first: None, mid: Vec::new(), last: None };
        mapping_runs(layer, deps, s, l, &mut |r| {
            // runs of one target come coalesced; a swap run between two runs of the same
            // target keeps them apart (python coalesces per target too)
            if let Some(l) = p.last.as_mut().filter(|l| runs_join(l, &r)) {
                l.0.len += r.0.len;
            } else if p.last.is_none() && p.first.as_ref().is_some_and(|f| runs_join(f, &r)) {
                p.first.as_mut().unwrap().0.len += r.0.len;
            } else if p.first.is_none() {
                p.first = Some(r);
            } else if let Some(prev) = p.last.replace(r) {
                cut_run(prev, chunk, overlap, &mut p.mid);
            }
        });
        p
    });
    out.reserve(parts.iter().map(|p| p.mid.len() + 2).sum());
    let mut pending: Option<Run> = None;
    for p in parts {
        if let Some(f) = p.first {
            match pending.as_mut() {
                Some(pm) if runs_join(pm, &f) => pm.0.len += f.0.len,
                _ => {
                    if let Some(pm) = pending.take() {
                        cut_run(pm, chunk, overlap, out);
                    }
                    pending = Some(f);
                }
            }
        }
        if p.last.is_some() {
            // the first run is complete: it is followed by more runs of this piece
            if let Some(pm) = pending.take() {
                cut_run(pm, chunk, overlap, out);
            }
            out.extend_from_slice(&p.mid);
            pending = p.last;
        }
    }
    if let Some(pm) = pending {
        cut_run(pm, chunk, overlap, out);
    }
}

/// Granularity (log2) of the parallel mapping enumeration of Intel layers: no page (4 KiB up to
/// 1 GiB) crosses such a boundary.
const RUN_PIECE_BITS: u32 = 30;
/// Finer split (log2) of 1 GiB pieces that are not a single 1 GiB page (pages <= 4 MiB).
const RUN_SUBPIECE_BITS: u32 = 24;

/// python `layer.mapping(start, length, ignore_errors=True)` runs, enumerated with
/// [`run_pieces`] (tests compare it with the sequential walk).
#[cfg(test)]
fn collect_runs(layer: &dyn Layer, start: u64, length: u64) -> Vec<Mapping> {
    let mut out: Vec<Mapping> = Vec::new();
    let Some(pieces) = run_pieces(layer, start, length) else {
        layer.mapping(start, length, &mut |m| {
            out.push(m);
            true
        });
        return out;
    };
    let parts: Vec<Vec<Mapping>> = par::par_map(pieces.len(), |i| {
        let (s, l) = pieces[i];
        let mut v = Vec::new();
        layer.mapping(s, l, &mut |m| {
            v.push(m);
            true
        });
        v
    });
    for part in parts {
        let mut it = part.into_iter();
        if let Some(first) = it.next() {
            match out.last_mut() {
                Some(last) if runs_join(&(*last, 0), &(first, 0)) => last.len += first.len,
                _ => out.push(first),
            }
        }
        out.extend(it);
    }
    out
}

/// The pieces a large range of an Intel layer is walked in, in parallel (None = walk it
/// sequentially): cut at 1 GiB boundaries, dropping ranges under invalid upper-level entries
/// (python's walk skips them as a whole too), and at 16 MiB boundaries where a page directory
/// (not a 1 GiB page) lies below. No page crosses a piece boundary, and the page-by-page walk
/// visits every boundary it does not skip over, so walking the pieces and re-joining runs that
/// meet at a boundary contiguously in both spaces gives exactly python's runs.
fn run_pieces(layer: &dyn Layer, start: u64, length: u64) -> Option<Vec<(u64, u64)>> {
    let g = 1u128 << RUN_PIECE_BITS;
    let intel = layer.as_intel().filter(|_| length as u128 >= 8 * g && par::threads() > 1)?;
    let end = start as u128 + length as u128;
    let mut pieces: Vec<(u64, u64)> = Vec::new();
    let mut x = start as u128;
    while x < end {
        let pend = (((x >> RUN_PIECE_BITS) + 1) << RUN_PIECE_BITS).min(end);
        let whole_page = match intel.translate_raw(x as u64) {
            // the entry covering 2^invalid_bits bytes is invalid: python's walk skips it all
            Err(f) if f.invalid_bits >= RUN_PIECE_BITS && f.invalid_bits < 64 => {
                let span = 1u128 << f.invalid_bits;
                x = (x / span + 1) * span;
                continue;
            }
            Ok((_, bits, _)) => bits >= RUN_PIECE_BITS,
            Err(_) => false,
        };
        if whole_page {
            // one 1 GiB page
            pieces.push((x as u64, (pend - x) as u64));
        } else {
            // a page directory below: no page crosses a 16 MiB boundary
            let mut y = x;
            while y < pend {
                let yend = (((y >> RUN_SUBPIECE_BITS) + 1) << RUN_SUBPIECE_BITS).min(pend);
                pieces.push((y as u64, (yend - y) as u64));
                y = yend;
            }
        }
        x = pend;
    }
    Some(pieces)
}

/// Locate `[addr, addr+len)` of `layer` as linear bytes of the backing file: the layer IS the
/// file layer, or it is a container whose `slice()` (which only succeeds for truly linear,
/// unencoded spans and never touches the bytes) points into the file's mapping. Encoded
/// container data (compressed frames, fill pages...) is never read from the file directly.
fn file_span(layer: &dyn Layer, addr: u64, len: u64) -> Option<(&FileLayer, u64)> {
    if let Some(f) = layer.as_file() {
        return if addr.checked_add(len)? <= f.len() { Some((f, addr)) } else { None };
    }
    let f = super::base_file(layer)?;
    let s = layer.slice(addr, usize::try_from(len).ok()?)?;
    let base = f.data().as_ptr() as usize;
    let p = s.as_ptr() as usize;
    if s.len() as u64 == len && p >= base && p + s.len() <= base + f.data().len() { Some((f, (p - base) as u64)) } else { None }
}

// ---------------------------------------------------------------------------------------------
// Execution plan
//
// python's chunk list is fixed (see the module docs); how the chunks are *executed* is ours:
//   * big file-backed chunks (python's 16 MiB data-layer chunks) are one work item each. Two-
//     phase streaming scanners read them with `pread` in 64 KiB pieces (+ the scanner's window)
//     into a buffer that stays in L1/L2 and search each piece, carrying the greedy match state
//     across pieces (exactly one whole-chunk search); other scanners get a private `MapWindow`
//     of the chunk (map -> scan -> unmap on the worker);
//   * small chunks (translation-layer runs, mostly single 4 KiB pages scattered over the file)
//     are batched into rounds of consecutive chunks (256 MiB). A round's chunks are sorted by
//     file range: ranges mapped at several virtual addresses (60% of a Windows kernel's pages)
//     are read once -- and searched once by two-phase scanners -- with a small `pread` each
//     (mapping scattered pages serializes on the mm locks). Work items take ~1 MiB of distinct
//     data. Hits are buffered per round and emitted in chunk order, so results keep python's
//     order and an early stop wastes at most one round;
//   * chunks that are not one contiguous span of the backing file are read through the layer.
// ---------------------------------------------------------------------------------------------

/// Chunks at least this big are a work item of their own.
const BIG_CHUNK: u64 = 1 << 20;
/// Big chunks of streaming scanners are read in pieces of this size.
const PIECE: u64 = 64 << 10;
/// Distinct bytes per group work item (about).
const GROUP_BYTES: u64 = 1 << 20;
/// Chunks per group work item (about).
const GROUP_CHUNKS: usize = 4096;
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
    /// chunks `idx[a..b]`, file-backed, sorted by file range
    Group { a: u32, b: u32 },
    /// chunks `idx[a..b]` (ascending), read through the layer
    Generic { a: u32, b: u32 },
}

struct Plan<'a> {
    /// `layer.dependencies()` (targets of `Src::Dep` chunks)
    deps: &'a [Arc<dyn Layer>],
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
    /// `(chunk, start, end)`: `hits[start..end]` belong to `chunk` (chunks without hits are
    /// omitted; ascending chunk order except for `Group` items)
    spans: Vec<(u32, u32, u32)>,
}

fn chunk_source<'a>(layer: &'a dyn Layer, deps: &'a [Arc<dyn Layer>], c: &Chunk) -> Option<(&'a FileLayer, u64)> {
    match c.src {
        Src::Layer => file_span(layer, c.start, c.len),
        Src::Lower(m) => layer.lower().and_then(|l| file_span(l.as_ref(), m, c.len)),
        Src::Dep(i, m) => deps.get(i as usize).and_then(|l| file_span(l.as_ref(), m, c.len)),
    }
}

fn make_plan<'a>(layer: &'a dyn Layer, deps: &'a [Arc<dyn Layer>], chunks: Vec<Chunk>) -> Plan<'a> {
    // file offsets (in parallel; every file-backed chunk lives in the layer stack's base file)
    let file = super::base_file(layer);
    const BLOCK: usize = 1 << 15;
    let blocks = par::par_map(chunks.len().div_ceil(BLOCK), |bi| {
        let cs = &chunks[bi * BLOCK..((bi + 1) * BLOCK).min(chunks.len())];
        cs.iter()
            .map(|c| match chunk_source(layer, deps, c) {
                Some((f, off)) if file.is_some_and(|g| std::ptr::eq(f, g)) => off,
                _ => NO_FILE,
            })
            .collect::<Vec<u64>>()
    });
    let offs: Vec<u64> = blocks.concat();
    let file = if offs.iter().any(|&o| o != NO_FILE) { file } else { None };
    // segments: big chunks alone, runs of small chunks cut into rounds
    enum Seg {
        Big(usize),
        Round(usize, usize),
    }
    let mut segs = Vec::new();
    let mut round_start = 0usize;
    let mut round_bytes = 0u64;
    for (i, c) in chunks.iter().enumerate() {
        if c.len >= BIG_CHUNK {
            if round_start < i {
                segs.push(Seg::Round(round_start, i));
            }
            segs.push(Seg::Big(i));
            round_start = i + 1;
            round_bytes = 0;
            continue;
        }
        round_bytes += c.len;
        if round_bytes >= ROUND_BYTES {
            segs.push(Seg::Round(round_start, i + 1));
            round_start = i + 1;
            round_bytes = 0;
        }
    }
    if round_start < chunks.len() {
        segs.push(Seg::Round(round_start, chunks.len()));
    }
    // rounds are planned in parallel (sorting by file range), then concatenated
    let rounds: Vec<(Vec<u32>, Vec<Item>)> = par::par_map(segs.len(), |k| match segs[k] {
        Seg::Round(a, b) => plan_round(&chunks, &offs, a, b),
        Seg::Big(i) => {
            if offs[i] != NO_FILE {
                (Vec::new(), vec![Item::Big { chunk: i as u32, off: offs[i] }])
            } else {
                (vec![i as u32], vec![Item::Generic { a: 0, b: 1 }])
            }
        }
    });
    let mut plan = Plan { deps, chunks, offs, file, idx: Vec::new(), items: Vec::new(), round_end: Vec::new() };
    for (idx, items) in rounds {
        let base = plan.idx.len() as u32;
        plan.idx.extend_from_slice(&idx);
        let n = items.len();
        for (j, it) in items.into_iter().enumerate() {
            plan.items.push(match it {
                Item::Group { a, b } => Item::Group { a: a + base, b: b + base },
                Item::Generic { a, b } => Item::Generic { a: a + base, b: b + base },
                big => big,
            });
            plan.round_end.push(j + 1 == n);
        }
    }
    plan
}

/// Work items of one round: the small chunks `[start, end)` (item ranges index the returned
/// chunk list).
fn plan_round(chunks: &[Chunk], offs: &[u64], start: usize, end: usize) -> (Vec<u32>, Vec<Item>) {
    let mut idx: Vec<u32> = Vec::new();
    let mut items = Vec::new();
    // file-backed: sorted by (file offset, length, chunk) so identical ranges (the same
    // physical pages mapped at several virtual addresses) are adjacent and read once; items
    // take up to GROUP_BYTES of distinct data (and GROUP_CHUNKS chunks)
    let mut keyed: Vec<(u64, u64, u32)> = (start..end).filter(|&i| offs[i] != NO_FILE).map(|i| (offs[i], chunks[i].len, i as u32)).collect();
    keyed.sort_unstable();
    let mut k = 0;
    while k < keyed.len() {
        let a = idx.len() as u32;
        let mut bytes = 0u64;
        let mut n = 0usize;
        while k < keyed.len() && bytes < GROUP_BYTES && n < GROUP_CHUNKS {
            let (off, len, _) = keyed[k];
            bytes += len;
            while k < keyed.len() && keyed[k].0 == off && keyed[k].1 == len {
                idx.push(keyed[k].2);
                k += 1;
                n += 1;
            }
        }
        items.push(Item::Group { a, b: idx.len() as u32 });
    }
    // not file-backed: consecutive items of ~GENERIC_ITEM_BYTES
    let mut a = idx.len() as u32;
    let mut bytes = 0u64;
    for i in start..end {
        if offs[i] != NO_FILE {
            continue;
        }
        idx.push(i as u32);
        bytes += chunks[i].len;
        if bytes >= GENERIC_ITEM_BYTES {
            let b = idx.len() as u32;
            items.push(Item::Generic { a, b });
            a = b;
            bytes = 0;
        }
    }
    if (idx.len() as u32) > a {
        items.push(Item::Generic { a, b: idx.len() as u32 });
    }
    (idx, items)
}

thread_local! {
    static BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Read chunk `c` through the layer (python `_scan_chunk`: unreadable -> empty data).
fn read_chunk<R>(layer: &dyn Layer, deps: &[Arc<dyn Layer>], c: &Chunk, f: impl FnOnce(&[u8]) -> R) -> R {
    BUF.with(|b| {
        let mut buf = b.borrow_mut();
        buf.resize(c.len as usize, 0);
        let ok = match c.src {
            Src::Layer => layer.read(c.start, &mut buf).is_ok(),
            Src::Lower(m) => match layer.lower() {
                Some(l) => l.read(m, &mut buf).is_ok(),
                None => false,
            },
            Src::Dep(i, m) => match deps.get(i as usize) {
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
        let prev = out.spans.last().map(|s| s.2).unwrap_or(0);
        if end > prev {
            out.spans.push((ci, prev, end));
        }
    };
    match item {
        Item::Big { chunk, off } if scanner.stream_window().is_some() => {
            let c = &plan.chunks[chunk as usize];
            let file = plan.file.expect("file-backed item without file");
            scan_pieces(scanner, file, off, c, PIECE, &mut out.hits);
            push_span(&mut out, chunk);
        }
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
        Item::Group { a, b } => {
            let file = plan.file.expect("file-backed item without file");
            let ids = &plan.idx[a as usize..b as usize];
            BUF.with(|buf| scan_group(scanner, plan, ids, file, &mut buf.borrow_mut(), &mut out, &push_span));
        }
        Item::Generic { a, b } => {
            for &ci in &plan.idx[a as usize..b as usize] {
                let c = &plan.chunks[ci as usize];
                read_chunk(layer, plan.deps, c, |data| {
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

/// A big chunk read in `piece`-byte pieces with `pread` into a cache-resident buffer (each
/// piece re-reads the `stream_window() - 1` bytes after it), scanned with
/// [`Scanner::prescan_piece`] and finished once: exactly `scan(whole chunk)`, but the bytes
/// never leave L1/L2 and no page tables are built (python: an unreadable chunk has no hits).
fn scan_pieces<S: Scanner>(scanner: &S, file: &FileLayer, off: u64, c: &Chunk, piece: u64, hits: &mut Vec<S::Hit>) {
    use std::os::unix::fs::FileExt;
    let w = scanner.stream_window().unwrap_or(1).max(1) as u64;
    BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        let cap = (piece + w - 1) as usize;
        if buf.len() < cap {
            buf.resize(cap, 0);
        }
        let mut rel: Vec<(u64, u32)> = Vec::new();
        let mut next = 0u64;
        let mut p = 0u64;
        while p < c.len {
            let limit = (p + piece).min(c.len);
            let end = (limit + w - 1).min(c.len);
            let n = (end - p) as usize;
            if file.file().read_exact_at(&mut buf[..n], off + p).is_err() {
                return;
            }
            if next < limit {
                let from = (next.max(p) - p) as usize;
                next = p + scanner.prescan_piece(&buf[..n], p, from, (limit - p) as usize, &mut rel) as u64;
            }
            p = limit;
        }
        if !rel.is_empty() {
            scanner.finish(&rel, c.start, hits);
        }
    });
}

/// `pread` the file bytes `[off, off+len)` into `buf` (None if unreadable). Small scattered
/// ranges are read, not mapped: mapping them serializes on the mm locks and pays page-table
/// setup + teardown per page; a small `pread` lands in L1/L2 right before the search.
#[inline]
fn pread<'b>(file: &FileLayer, buf: &'b mut Vec<u8>, off: u64, len: u64) -> Option<&'b [u8]> {
    use std::os::unix::fs::FileExt;
    let n = len as usize;
    if buf.len() < n {
        buf.resize(n, 0);
    }
    file.file().read_exact_at(&mut buf[..n], off).ok()?;
    Some(&buf[..n])
}

/// Scan the chunks `ids` (file-backed, sorted by file range): every distinct range is read
/// once; two-phase scanners also search it once and turn the matches into hits per chunk.
fn scan_group<S: Scanner>(
    scanner: &S,
    plan: &Plan,
    ids: &[u32],
    file: &FileLayer,
    buf: &mut Vec<u8>,
    out: &mut ItemOut<S::Hit>,
    push_span: &dyn Fn(&mut ItemOut<S::Hit>, u32),
) {
    // distinct ranges: (offset, len) and the ids[k..e] mapped to it
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut bounds: Vec<(usize, usize)> = Vec::new();
    let mut k = 0;
    while k < ids.len() {
        let c0 = ids[k] as usize;
        let (off, len) = (plan.offs[c0], plan.chunks[c0].len);
        let mut e = k + 1;
        while e < ids.len() && plan.offs[ids[e] as usize] == off && plan.chunks[ids[e] as usize].len == len {
            e += 1;
        }
        ranges.push((off, len));
        bounds.push((k, e));
        k = e;
    }
    let mut rel: Vec<(u64, u32)> = Vec::new();
    let two_phase = scanner.prescan(&[], &mut rel);
    for (r, &(off, len)) in ranges.iter().enumerate() {
        let (k, e) = bounds[r];
        let Some(data) = pread(file, buf, off, len) else { continue };
        if two_phase {
            rel.clear();
            scanner.prescan(data, &mut rel);
            if !rel.is_empty() {
                for &ci in &ids[k..e] {
                    scanner.finish(&rel, plan.chunks[ci as usize].start, &mut out.hits);
                    push_span(out, ci);
                }
            }
        } else {
            for &ci in &ids[k..e] {
                scanner.scan(data, plan.chunks[ci as usize].start, &mut out.hits);
                push_span(out, ci);
            }
        }
    }
}

/// Emit the hits of one round in chunk order; false if `f` asked to stop.
fn emit_round<H, F: FnMut(H) -> bool>(outs: &mut Vec<ItemOut<H>>, f: &mut F) -> bool {
    if outs.len() == 1 && outs[0].spans.windows(2).all(|w| w[0].0 < w[1].0) {
        let o = outs.pop().unwrap();
        for h in o.hits {
            if !f(h) {
                return false;
            }
        }
        return true;
    }
    // order all spans of the round by chunk (each chunk is in exactly one item)
    let mut recs: Vec<(u32, u32, u32, u32)> = Vec::new();
    for (k, o) in outs.iter().enumerate() {
        recs.extend(o.spans.iter().map(|&(ci, s, e)| (ci, k as u32, s, e)));
    }
    recs.sort_unstable();
    let mut hits: Vec<Vec<Option<H>>> = outs.drain(..).map(|o| o.hits.into_iter().map(Some).collect()).collect();
    for (_, k, s, e) in recs {
        for h in &mut hits[k as usize][s as usize..e as usize] {
            if let Some(h) = h.take() {
                if !f(h) {
                    return false;
                }
            }
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
pub fn scan_each<S, F>(layer: &dyn Layer, scanner: &S, sections: Option<&[(u64, u64)]>, f: F)
where
    S: Scanner,
    F: FnMut(S::Hit) -> bool,
{
    scan_sections(layer, scanner, sections, true, f)
}

/// [`scan_each`]; `cache` = whether the scan cache may answer / record it.
fn scan_sections<S, F>(layer: &dyn Layer, scanner: &S, sections: Option<&[(u64, u64)]>, cache: bool, f: F)
where
    S: Scanner,
    F: FnMut(S::Hit) -> bool,
{
    let secs = match sections {
        Some(s) => coalesce_sections(layer, s),
        None => coalesce_sections(layer, &default_sections(layer)),
    };
    if cache
        && let Some(q) = scanner.cache_query()
        && let Some(session) = super::scancache::Session::new(layer, &secs, sections.is_none(), scanner.chunk_size(), scanner.overlap())
    {
        return super::scancache::scan_each(&session, layer, scanner, q, &secs, f);
    }
    execute(layer, scanner, &secs, f)
}

/// Run python's chunk list of the (coalesced) sections `secs` of `layer` through `scanner` on
/// all cores; `f` gets the hits in python order and returns false to stop.
pub(crate) fn execute<S, F>(layer: &dyn Layer, scanner: &S, secs: &[(u64, u64)], mut f: F)
where
    S: Scanner,
    F: FnMut(S::Hit) -> bool,
{
    let deps = if layer.lower().is_some() { layer.dependencies() } else { Vec::new() };
    let chunks = {
        let _t = crate::util::trace::span("scan: build chunks");
        build_chunks(layer, &deps, scanner.chunk_size(), scanner.overlap(), secs)
    };
    if chunks.is_empty() {
        return;
    }
    let total: u64 = chunks.iter().map(|c| c.len).sum();
    // small scans: no threads, no windows
    if total < (4 << 20) {
        let mut hits = Vec::new();
        for c in &chunks {
            match chunk_source(layer, &deps, c).and_then(|(file, off)| file.slice(off, c.len as usize)) {
                Some(data) => scanner.scan(data, c.start, &mut hits),
                None => read_chunk(layer, &deps, c, |data| {
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
        make_plan(layer, &deps, chunks)
    };
    let _t = crate::util::trace::span("scan: execute");
    let lookahead = par::threads() * 4;
    let mut round: Vec<ItemOut<S::Hit>> = Vec::new();
    par::par_map_stream(
        plan.items.len(),
        lookahead,
        |i| {
            if !crate::util::trace::enabled() {
                return run_item(layer, scanner, &plan, plan.items[i]);
            }
            let t = std::time::Instant::now();
            let r = run_item(layer, scanner, &plan, plan.items[i]);
            let ns = t.elapsed().as_nanos() as u64;
            BUSY.fetch_add(ns, std::sync::atomic::Ordering::Relaxed);
            MAXI.fetch_max(ns, std::sync::atomic::Ordering::Relaxed);
            r
        },
        |i, out| {
            round.push(out);
            if plan.round_end[i] { emit_round(&mut round, &mut f) } else { true }
        },
    );
    if crate::util::trace::enabled() {
        eprintln!("[trace] scan: {} items, worker busy {:.1} ms total, slowest item {:.2} ms", plan.items.len(), BUSY.swap(0, std::sync::atomic::Ordering::Relaxed) as f64 / 1e6, MAXI.swap(0, std::sync::atomic::Ordering::Relaxed) as f64 / 1e6);
    }
}
/// [`scan_each`] over the whole layer (python default sections and chunking, hits in python
/// order, `f` returns false to stop) for scans that usually stop at an early hit, like banner
/// scans: the chunks are scanned in growing batches (2, 4, 8, ... up to 4x the thread count)
/// instead of with `scan_each`'s fixed look-ahead of 2x threads 16 MiB chunks. A banner in
/// chunk 4 then costs 6 chunks of work in 2 short rounds rather than a memory-bandwidth-bound
/// wave of ~40 chunks (4 chunks already saturate the memory bus); a full scan pays a handful
/// of batch barriers (a few percent).
///
/// Each batch is scanned with a section starting exactly at its first chunk, so the batch's
/// chunks are python's chunks; the section ends where python's last chunk of the batch ends,
/// which makes the layer produce one extra overlap-sized tail chunk whose hits (offset >= last
/// chunk start + chunk_size) belong to the next batch and are dropped via `offset_of`.
pub fn scan_each_progressive<S, F, O>(layer: &dyn Layer, scanner: &S, offset_of: O, mut f: F)
where
    S: Scanner,
    F: FnMut(S::Hit) -> bool,
    O: Fn(&S::Hit) -> u64,
{
    let cs = scanner.chunk_size();
    let chunks = chunk_layout(layer, cs, scanner.overlap(), None);
    let n = chunks.len();
    if n == 0 {
        return;
    }
    // python default section: (min_address, max_address - min_address)
    let section_end = layer.max_address();
    let max_batch = crate::util::par::threads() * 4;
    let (mut i0, mut batch) = (0usize, 2usize);
    while i0 < n {
        let i1 = (i0 + batch).min(n);
        let start = chunks[i0].0;
        let (end, limit) = if i1 == n {
            (section_end, u64::MAX)
        } else {
            let (ls, ll) = chunks[i1 - 1];
            (ls.saturating_add(ll), ls.saturating_add(cs))
        };
        let mut stopped = false;
        if end > start {
            // per-batch sections: nothing worth caching (these scans stop early)
            scan_sections(layer, scanner, Some(&[(start, end - start)]), false, |h| {
                if offset_of(&h) >= limit {
                    return true;
                }
                if f(h) {
                    true
                } else {
                    stopped = true;
                    false
                }
            });
        }
        if stopped {
            return;
        }
        i0 = i1;
        batch = (batch * 2).min(max_batch);
    }
}

/// Trace counters: total worker time and the slowest item of the last scan.
static BUSY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static MAXI: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Scan several sections of `layer` and collect `(chunk start, hits)`; convenience for tests.
pub fn chunk_layout(layer: &dyn Layer, chunk: u64, overlap: u64, sections: Option<&[(u64, u64)]>) -> Vec<(u64, u64)> {
    let secs = match sections {
        Some(s) => coalesce_sections(layer, s),
        None => coalesce_sections(layer, &default_sections(layer)),
    };
    let deps = layer.dependencies();
    build_chunks(layer, &deps, chunk, overlap, &secs).iter().map(|c| (c.start, c.len)).collect()
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
    fn prescan(&self, data: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
        let mut pos = 0usize;
        while let Some(i) = find(&data[pos..], &self.needle) {
            let at = pos + i;
            if (at as u64) >= self.chunk_size {
                break;
            }
            out.push((at as u64, 0));
            pos = at + 1;
            if pos > data.len() {
                break;
            }
        }
        true
    }
    fn finish(&self, matches: &[(u64, u32)], data_offset: u64, hits: &mut Vec<u64>) {
        hits.extend(matches.iter().map(|m| data_offset + m.0));
    }
    fn stream_window(&self) -> Option<usize> {
        if self.needle.is_empty() { None } else { Some(self.needle.len()) }
    }
    fn cache_query(&self) -> Option<super::scancache::CacheQuery<'_>> {
        if self.needle.is_empty() {
            return None;
        }
        Some(super::scancache::CacheQuery::Every { needle: &self.needle, limit: self.chunk_size })
    }
    fn prescan_piece(&self, data: &[u8], base: u64, from: usize, limit: usize, out: &mut Vec<(u64, u32)>) -> usize {
        // occurrences may overlap: every start in [from, limit) is independent
        let cs_limit = self.chunk_size.saturating_sub(base).min(limit as u64) as usize;
        let mut pos = from;
        while pos < cs_limit {
            match find(&data[pos..], &self.needle) {
                Some(i) if pos + i < cs_limit => {
                    out.push((base + (pos + i) as u64, 0));
                    pos += i + 1;
                }
                _ => break,
            }
        }
        limit
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
    max_len: usize,
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
        let max_len = patterns.iter().map(|p| p.len()).max().unwrap_or(0);
        MultiStringScanner { patterns, nodes, first, pair, teddy, min_len, max_len, chunk_size: DEFAULT_CHUNK_SIZE, overlap: DEFAULT_OVERLAP }
    }

    /// Pattern by index (hits carry the index).
    pub fn pattern(&self, idx: usize) -> &[u8] {
        &self.patterns[idx]
    }

    /// All patterns, in index order.
    pub fn patterns(&self) -> &[Vec<u8>] {
        &self.patterns
    }

    /// Every occurrence of every pattern (overlapping ones too, unlike [`Self::search`]) that
    /// starts in `data[from..limit)` and fits in `data`: `f(position, pattern index)` in
    /// ascending position order (several patterns at one position: shortest first). Same
    /// prefilter + trie walk as `search`, but every candidate position is verified.
    pub fn search_every(&self, data: &[u8], from: usize, limit: usize, f: impl FnMut(usize, u32)) {
        self.search_every_simd(data, from, limit, simd_enabled(), f)
    }

    fn search_every_simd(&self, data: &[u8], from: usize, limit: usize, simd: bool, mut f: impl FnMut(usize, u32)) {
        if self.min_len == 0 || data.len() < self.min_len {
            return;
        }
        let limit = limit.min(data.len() - self.min_len + 1);
        if from >= limit {
            return;
        }
        let d = &data[from..];
        let lim = limit - from;
        let mut every = |p: usize| {
            let mut n = 0usize;
            let mut j = p;
            while j < d.len() {
                let b = d[j];
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
                            f(from + p, t);
                        }
                    }
                    None => break,
                }
            }
        };
        #[cfg(target_arch = "x86_64")]
        if simd
            && let Some(t) = &self.teddy
        {
            let mut verify = |p: usize| -> Option<usize> {
                every(p);
                Some(p + 1)
            };
            // SAFETY: AVX2 availability checked by `simd_enabled`.
            unsafe {
                match t.m {
                    1 => teddy_search::<1>(t, d, lim, &mut verify),
                    2 => teddy_search::<2>(t, d, lim, &mut verify),
                    _ => teddy_search::<3>(t, d, lim, &mut verify),
                }
            }
            return;
        }
        let _ = simd;
        for i in 0..lim {
            let cand = match &self.pair {
                Some(pair) => {
                    let k = u16::from_le_bytes([d[i], d[i + 1]]) as usize;
                    pair[k >> 6] & (1 << (k & 63)) != 0
                }
                None => self.first[d[i] as usize],
            };
            if cand {
                every(i);
            }
        }
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
    fn prescan(&self, data: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
        self.scan(data, 0, out);
        true
    }
    fn finish(&self, matches: &[(u64, u32)], data_offset: u64, hits: &mut Vec<(u64, u32)>) {
        hits.extend(matches.iter().map(|&(o, p)| (data_offset + o, p)));
    }
    fn stream_window(&self) -> Option<usize> {
        Some(self.max_len.max(1))
    }
    fn cache_query(&self) -> Option<super::scancache::CacheQuery<'_>> {
        Some(super::scancache::CacheQuery::Greedy { patterns: &self.patterns, limit: self.chunk_size, cap: usize::MAX })
    }
    fn prescan_piece(&self, data: &[u8], base: u64, from: usize, limit: usize, out: &mut Vec<(u64, u32)>) -> usize {
        // the greedy search resumes at `from`; the scan of the whole chunk would be in the
        // same state there
        let cs_limit = self.chunk_size.saturating_sub(base).min(limit as u64) as usize;
        let mut next = limit;
        if from < cs_limit {
            self.search_limit(&data[from..], cs_limit - from, simd_enabled(), |o, pi| {
                out.push((base + (from + o) as u64, pi));
                let len = self.patterns[pi as usize].len();
                next = next.max(from + o + len);
                true
            });
        }
        next
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

    /// `search_every` (SIMD and scalar) == every (position, pattern) occurrence, overlapping.
    #[test]
    fn search_every_matches_naive() {
        let mut rng = Rng(0x5eed_0f_a11);
        let alpha: [u8; 6] = [b'a', b'b', b'c', 0, 0xe3, b'P'];
        for trial in 0..3000 {
            let np = 1 + rng.below(12) as usize;
            let minl = 1 + rng.below(4) as usize;
            let mut patterns: Vec<Vec<u8>> = (0..np)
                .map(|_| {
                    let l = minl + rng.below(5) as usize;
                    (0..l).map(|_| if trial % 3 == 0 { rng.next() as u8 } else { alpha[rng.below(alpha.len() as u64) as usize] }).collect()
                })
                .collect();
            patterns.sort();
            patterns.dedup();
            let n = rng.below(700) as usize;
            let data: Vec<u8> = (0..n).map(|_| alpha[rng.below(alpha.len() as u64) as usize]).collect();
            let s = MultiStringScanner::new(&patterns);
            for (from, limit) in [(0, usize::MAX), (0, n / 2), (3, 65), (n / 3, n), (64, 64)] {
                let mut want = Vec::new();
                for i in from..n.min(limit) {
                    let mut at: Vec<(usize, usize)> = patterns.iter().enumerate().filter(|(_, p)| data[i..].starts_with(p)).map(|(pi, p)| (p.len(), pi)).collect();
                    at.sort();
                    want.extend(at.into_iter().map(|(_, pi)| (i, pi as u32)));
                }
                for simd in [false, true] {
                    if simd && !simd_enabled() {
                        continue;
                    }
                    let mut got = Vec::new();
                    s.search_every_simd(&data, from, limit, simd, |p, i| got.push((p, i)));
                    assert_eq!(got, want, "trial {trial} simd {simd} from {from} limit {limit} patterns {patterns:?}");
                }
            }
        }
    }

    /// Reading a chunk in pieces ([`scan_pieces`]) == scanning it whole, for any piece size.
    #[test]
    fn streaming_pieces_match_whole_chunk() {
        let mut rng = Rng(0xdeadbeef12345);
        let alpha: [u8; 5] = [b'a', b'b', b'c', 0, b'P'];
        let n = 20000usize;
        let data: Vec<u8> = (0..n).map(|_| alpha[rng.below(alpha.len() as u64) as usize]).collect();
        let path = std::env::temp_dir().join(format!("rsvol-scan-pieces-{}.bin", std::process::id()));
        std::fs::write(&path, &data).unwrap();
        let file = FileLayer::open(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        for trial in 0..60 {
            let np = 1 + rng.below(6) as usize;
            let patterns: Vec<Vec<u8>> = (0..np)
                .map(|_| {
                    let l = 1 + rng.below(if trial % 2 == 0 { 3 } else { 7 }) as usize;
                    (0..l).map(|_| alpha[rng.below(alpha.len() as u64) as usize]).collect()
                })
                .collect();
            let start = rng.below(1000);
            let len = 1 + rng.below((n as u64 - start).min(12000));
            let cs = 1 + rng.below(len + 10);
            let c = Chunk { start: 0x1000_0000 + start, len, src: Src::Layer };
            let whole = &data[start as usize..(start + len) as usize];
            let mut m = MultiStringScanner::new(&patterns);
            m.chunk_size = cs;
            let bs = BytesScanner { needle: patterns[0].clone(), chunk_size: cs, overlap: 0 };
            let mut want_m = Vec::new();
            m.scan(whole, c.start, &mut want_m);
            let mut want_b = Vec::new();
            bs.scan(whole, c.start, &mut want_b);
            for piece in [1u64, 2, 3, 5, 64, 4096] {
                let mut got = Vec::new();
                scan_pieces(&m, &file, start, &c, piece, &mut got);
                assert_eq!(got, want_m, "multi trial {trial} piece {piece} patterns {patterns:?} cs {cs}");
                let mut got = Vec::new();
                scan_pieces(&bs, &file, start, &c, piece, &mut got);
                assert_eq!(got, want_b, "bytes trial {trial} piece {piece}");
            }
        }
    }

    #[test]
    fn coalesce_matches_python() {
        let l = Buf(vec![0u8; 100]); // max_address 99
        // adjacent / overlapping sections merge
        assert_eq!(coalesce_sections(&l, &[(10, 5), (15, 5), (30, 10), (35, 10)]), vec![(10, 10), (30, 15)]);
        // sections starting beyond max are dropped; one ending beyond it is kept (python
        // compares tuples: (90, 50) < (99, 0))
        assert_eq!(coalesce_sections(&l, &[(10, 5), (90, 50), (200, 5)]), vec![(10, 5), (90, 50)]);
        // starting at max: python's clip writes result[1] (right with exactly two sections)
        assert_eq!(coalesce_sections(&l, &[(10, 5), (99, 5)]), vec![(10, 5), (99, 0)]);
        // one section at max: python raises (IndexError); we keep it
        assert_eq!(coalesce_sections(&l, &[(99, 5)]), vec![(99, 5)]);
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
        run("bytes SystemRoot", &|| scan(&file, &BytesScanner::new(b"\\SystemRoot\\system32\\nt"), None).len());
        run("bytes RSDS", &|| scan(&file, &BytesScanner::new(b"RSDS"), None).len());
        run("bytes MZ", &|| scan(&file, &BytesScanner::new(b"MZ\x90\x00"), None).len());
        let ps = MultiStringScanner::new(&[b"Pro\xe3".as_ref(), b"Proc"]);
        run("multi psscan(2)", &|| scan(&file, &ps, None).len());
        let tags: [&[u8]; 15] = [
            b"AtmT", b"Pro\xe3", b"Proc", b"Thr\xe5", b"Thre", b"Fil\xe5", b"File", b"Mut\xe1", b"Muta", b"Dri\xf6", b"Driv", b"MmLd", b"Sym\xe2",
            b"Symb", b"CM10",
        ];
        let all = MultiStringScanner::new(&tags);
        run("multi builtin(15)", &|| scan(&file, &all, None).len());
    }

    /// Reference executor: python's chunks, each read through the layer (`read`, empty when
    /// unreadable), scanned sequentially.
    fn reference_scan<S: Scanner>(layer: &dyn Layer, scanner: &S) -> Vec<S::Hit> {
        let secs = coalesce_sections(layer, &default_sections(layer));
        let deps = layer.dependencies();
        let chunks = build_chunks(layer, &deps, scanner.chunk_size(), scanner.overlap(), &secs);
        let mut hits = Vec::new();
        for c in &chunks {
            read_chunk(layer, &deps, c, |d| {
                if !d.is_empty() {
                    scanner.scan(d, c.start, &mut hits)
                }
            });
        }
        hits
    }

    /// The parallel executor returns exactly what python's sequential chunk-by-chunk scan
    /// returns, on real images (raw, LiME, ELF core, kernel virtual layer):
    /// `RSVOL_BENCH_IMG=img cargo test --profile fast scan_exact -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn scan_exact() {
        let Ok(path) = std::env::var("RSVOL_BENCH_IMG") else {
            eprintln!("set RSVOL_BENCH_IMG");
            return;
        };
        let (phys, _) = crate::automagic::stack_physical(std::path::Path::new(&path), None, false, None).unwrap();
        let mut layers: Vec<(&str, &dyn Layer)> = vec![("physical", phys.as_ref())];
        let ctx;
        if std::env::var_os("RSVOL_BENCH_WIN").is_some() {
            ctx = crate::context::Context::new(crate::context::GlobalOptions { file: Some(path.clone()), ..Default::default() }).unwrap();
            layers.push(("kernel virtual", ctx.windows_kernel().unwrap().vlayer));
        }
        let tags: [&[u8]; 15] = [
            b"AtmT", b"Pro\xe3", b"Proc", b"Thr\xe5", b"Thre", b"Fil\xe5", b"File", b"Mut\xe1", b"Muta", b"Dri\xf6", b"Driv", b"MmLd", b"Sym\xe2",
            b"Symb", b"CM10",
        ];
        let multi = MultiStringScanner::new(&tags);
        let short = MultiStringScanner::new(&[b"Linux".as_ref(), b"Li", b"\x7fELF", b"MZ"]);
        let bytes = BytesScanner::new(b"Linux version");
        for (name, l) in layers {
            let t = std::time::Instant::now();
            let a = scan(l, &multi, None);
            let dt = t.elapsed().as_secs_f64();
            let b = reference_scan(l, &multi);
            assert!(a == b, "{name}: multi differs ({} vs {})", a.len(), b.len());
            let a2 = scan(l, &short, None);
            let b2 = reference_scan(l, &short);
            assert!(a2 == b2, "{name}: short multi differs ({} vs {})", a2.len(), b2.len());
            let a3 = scan(l, &bytes, None);
            let b3 = reference_scan(l, &bytes);
            assert!(a3 == b3, "{name}: bytes differs ({} vs {})", a3.len(), b3.len());
            eprintln!("{name}: identical ({} / {} / {} hits), multi {:.1} ms", a.len(), a2.len(), a3.len(), dt * 1e3);
        }
    }

    /// Hits in the format of the python oracle plugin (`scancheck.ScanCheck`, see the sub-scan
    /// report): `RSVOL_BENCH_IMG=img RSVOL_HITS_OUT=file [RSVOL_HITS_PHYS=1] cargo test
    /// --profile fast hits_dump -- --ignored`
    #[test]
    #[ignore]
    fn hits_dump() {
        use std::io::Write;
        let (Ok(path), Ok(outp)) = (std::env::var("RSVOL_BENCH_IMG"), std::env::var("RSVOL_HITS_OUT")) else {
            eprintln!("set RSVOL_BENCH_IMG and RSVOL_HITS_OUT");
            return;
        };
        let ctx = crate::context::Context::new(crate::context::GlobalOptions { file: Some(path), ..Default::default() }).unwrap();
        let k = ctx.windows_kernel().unwrap();
        let l = if std::env::var_os("RSVOL_HITS_PHYS").is_some() { k.phys } else { k.vlayer };
        let tags: [&[u8]; 15] = [
            b"AtmT", b"Pro\xe3", b"Proc", b"Thr\xe5", b"Thre", b"Fil\xe5", b"File", b"Mut\xe1", b"Muta", b"Dri\xf6", b"Driv", b"MmLd", b"Sym\xe2",
            b"Symb", b"CM10",
        ];
        let mut o = std::io::BufWriter::new(std::fs::File::create(outp).unwrap());
        writeln!(o, "Volatility 3 Framework 2.28.2\n\nKind\tOffset\tPattern\n").unwrap();
        for (off, pi) in scan(l, &MultiStringScanner::new(&tags), None) {
            let hex: String = tags[pi as usize].iter().map(|b| format!("{b:02x}")).collect();
            writeln!(o, "multi\t{off:#x}\t{hex}").unwrap();
        }
        for off in scan(l, &BytesScanner::new(b"RSDS"), None) {
            writeln!(o, "bytes\t{off:#x}\t52534453").unwrap();
        }
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
        {
            let mut seq_chunks = Vec::new();
            for m in &seq {
                cut_run((*m, 0), DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP, &mut seq_chunks);
            }
            let par_chunks = build_chunks(l, &l.dependencies(), DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP, &secs);
            let key = |c: &Chunk| {
                (c.start, c.len, match c.src {
                    Src::Lower(m) => m,
                    Src::Layer | Src::Dep(..) => u64::MAX,
                })
            };
            assert!(seq_chunks.len() == par_chunks.len() && seq_chunks.iter().zip(&par_chunks).all(|(a, b)| key(a) == key(b)), "parallel chunks differ");
        }
        eprintln!("runs: {} sequential {:.1} ms, parallel {:.1} ms (identical)", seq.len(), t_seq * 1e3, t_par * 1e3);
        let mut best = f64::MAX;
        let mut chunks = Vec::new();
        for _ in 0..reps {
            let t = Instant::now();
            chunks = build_chunks(l, &l.dependencies(), DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP, &secs);
            best = best.min(t.elapsed().as_secs_f64());
        }
        let total: u64 = chunks.iter().map(|c| c.len).sum();
        let small = chunks.iter().filter(|c| c.len <= 0x1000).count();
        eprintln!("build_chunks: {:.1} ms, {} chunks ({} <= 4K), {:.1} MB", best * 1e3, chunks.len(), small, total as f64 / 1e6);
        {
            let mut pages: Vec<u64> = Vec::new();
            for c in &chunks {
                if let Src::Lower(m) = c.src {
                    let mut p = m & !0xfff;
                    while p < m + c.len {
                        pages.push(p);
                        p += 0x1000;
                    }
                }
            }
            let n = pages.len();
            pages.sort_unstable();
            pages.dedup();
            eprintln!("physical pages touched: {n} ({} distinct, {:.1} MB)", pages.len(), pages.len() as f64 * 4096.0 / 1e6);
        }
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
