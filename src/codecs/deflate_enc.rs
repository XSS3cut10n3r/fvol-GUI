//! DEFLATE (RFC 1951) compressor with zlib (RFC 1950) and raw one-shot entry points.
//!
//! * [`deflate_compress`] — raw DEFLATE, [`zlib_compress`] — zlib container (PNG IDAT).
//! * [`Compressor`] — reusable per-thread state; [`Compressor::compress`] compresses one
//!   buffer (optionally primed with a preceding dictionary) and either finishes the stream
//!   (BFINAL) or ends it on a byte boundary so the next piece can be appended (pigz scheme).
//!   The streaming parallel gzip writer ([`super::gzip_enc::GzipEncoder`]) is built on it.
//!
//! Design (in the spirit of libdeflate's lazy compressors):
//! * LZ77 over the 32 KiB window: 4-byte hash chains (head table of absolute `u32`
//!   positions, 16-bit distance links indexed by `pos & 0x7fff`) plus a single-entry 3-byte
//!   hash table for length-3 matches. Greedy (levels 1-3), lazy (4-6) or double-lazy (7-9)
//!   parsing with a bounded chain depth and a "nice" length that ends the search early.
//! * Runs of one repeated byte (zero pages) take an RLE fast path: distance-1 matches of 258
//!   are emitted straight from a word-at-a-time run scan, without hashing the run interior.
//! * Blocks end on a token-statistics change heuristic or size caps; each block is written
//!   as dynamic Huffman, fixed Huffman or stored, whichever costs fewer bits (exact costs).
//!   Length-limited canonical Huffman codes (in-place Moffat-Katajainen + Kraft repair).
//! * Inputs larger than [`CHUNK`] are split into `CHUNK`-sized pieces compressed in parallel,
//!   each primed with the preceding 32 KiB as dictionary. The output depends only on the input
//!   and the level, never on the number of threads.

use super::huffman_enc::huffman_lengths;
use super::zlib::adler32;

/// Size of the independently (parallel) compressed pieces of large inputs.
pub const CHUNK: usize = 1 << 20;

const WSIZE: usize = 1 << 15;
const WMASK: usize = WSIZE - 1;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
/// Positions need this many bytes ahead to be hashed / searched.
const MIN_LOOKAHEAD: usize = 4;
/// Length-3 matches farther than this cost more than three literals.
const MAX_DIST3: u32 = 4096;
/// Empty hash slot: `pos - SENTINEL` (wrapping) is always outside the window.
const SENTINEL: u32 = 0u32.wrapping_sub(WSIZE as u32 + 1);
const HASH4_BITS: u32 = 16;
const HASH3_BITS: u32 = 14;

/// Block size limits (input bytes) and the block-split check interval.
const SOFT_MAX_BLOCK_LEN: usize = 300_000;
const MIN_BLOCK_LEN: usize = 10_000;
const CHECK_INTERVAL: usize = 512;
/// Observations (literals + matches) needed before a block-split evaluation.
const MIN_NEW_OBS: u64 = 512;
const NUM_OBS: usize = 10;

/// Search parameters of one compression level.
#[derive(Clone, Copy, Debug)]
struct Params {
    /// Maximum number of hash-chain candidates examined per search.
    depth: u32,
    /// A match at least this long ends the search (and the lazy evaluation).
    nice: usize,
    /// 0 = greedy, 1 = lazy (look one position ahead), 2 = double lazy.
    lazy: u8,
    /// When the current match is at least this long the lazy searches use depth / 4.
    good: usize,
    /// Matches longer than this only insert their first and last few positions.
    max_insert: usize,
    /// Level 1: one probe of a 4-byte hash table (no chains, no 3-byte table), greedy
    /// parsing (libdeflate's "fastest" scheme). About 1.3x the speed of a depth-4 chain
    /// search at a slightly lower ratio.
    fast: bool,
}

fn params(level: u32) -> Params {
    let (depth, nice, lazy, good, max_insert) = match level {
        1 => (4, 32, 0, 258, 16),
        2 => (8, 48, 0, 258, 32),
        3 => (16, 64, 0, 258, 64),
        4 => (16, 64, 1, 16, 258),
        5 => (24, 96, 1, 24, 258),
        6 => (40, 128, 1, 32, 258),
        7 => (64, 192, 2, 32, 258),
        8 => (128, 258, 2, 64, 258),
        _ => (256, 258, 2, 96, 258),
    };
    #[cfg(test)]
    if let Ok(s) = std::env::var("RSVOL_DEFLATE_PARAMS") {
        // Benchmark-only override: "depth,nice,lazy,good,max_insert".
        let v: Vec<usize> = s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
        if v.len() == 5 {
            return Params { depth: v[0] as u32, nice: v[1], lazy: v[2] as u8, good: v[3], max_insert: v[4], fast: false };
        }
    }
    Params { depth, nice, lazy, good, max_insert, fast: level == 1 }
}

// ---------------------------------------------------------------------------------------
// Static tables
// ---------------------------------------------------------------------------------------

const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const PRECODE_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Length (0..=258) -> length slot (0..=28).
static LEN_SLOT: [u8; 259] = {
    let mut t = [0u8; 259];
    let mut s = 0;
    let mut l = 3;
    while l <= 258 {
        while s + 1 < 29 && LEN_BASE[s + 1] as usize <= l {
            s += 1;
        }
        t[l] = s as u8;
        l += 1;
    }
    t
};

/// Distance slot of `d - 1` for d <= 256, and of `(d - 1) >> 7` (+ 256) for larger d.
static DIST_SLOT: [u8; 512] = {
    let mut t = [0u8; 512];
    let mut i = 0;
    while i < 512 {
        let d = if i < 256 { i + 1 } else { ((i - 256) << 7) + 1 };
        let mut s = 0;
        while s + 1 < 30 && DIST_BASE[s + 1] as usize <= d {
            s += 1;
        }
        t[i] = s as u8;
        i += 1;
    }
    t
};

#[inline(always)]
fn dist_slot(d: usize) -> usize {
    debug_assert!((1..=WSIZE).contains(&d));
    if d <= 256 { DIST_SLOT[d - 1] as usize } else { DIST_SLOT[256 + ((d - 1) >> 7)] as usize }
}

fn fixed_litlen_lens() -> [u8; 288] {
    let mut l = [0u8; 288];
    for (i, x) in l.iter_mut().enumerate() {
        *x = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    l
}

// ---------------------------------------------------------------------------------------
// Unchecked little-endian loads (hot loops; every call site states its bounds)
// ---------------------------------------------------------------------------------------

/// # Safety
/// `i + 4 <= b.len()`.
#[inline(always)]
unsafe fn ld32(b: &[u8], i: usize) -> u32 {
    debug_assert!(i + 4 <= b.len());
    // SAFETY: caller guarantees the 4 bytes are in bounds.
    u32::from_le(unsafe { (b.as_ptr().add(i) as *const u32).read_unaligned() })
}

/// # Safety
/// `i + 8 <= b.len()`.
#[inline(always)]
unsafe fn ld64(b: &[u8], i: usize) -> u64 {
    debug_assert!(i + 8 <= b.len());
    // SAFETY: caller guarantees the 8 bytes are in bounds.
    u64::from_le(unsafe { (b.as_ptr().add(i) as *const u64).read_unaligned() })
}

/// Length of the common prefix of `b[a..]` and `b[p..]`, starting the comparison at `i`
/// and capped at `max`.
///
/// # Safety
/// `a < p` and `p + max <= b.len()`.
#[inline(always)]
unsafe fn extend(b: &[u8], a: usize, p: usize, mut i: usize, max: usize) -> usize {
    debug_assert!(a < p && p + max <= b.len());
    // SAFETY (whole fn): every index read is below p + max <= b.len() (a < p).
    unsafe {
        while i + 8 <= max {
            let x = ld64(b, a + i) ^ ld64(b, p + i);
            if x != 0 {
                return i + (x.trailing_zeros() >> 3) as usize;
            }
            i += 8;
        }
        while i < max && *b.get_unchecked(a + i) == *b.get_unchecked(p + i) {
            i += 1;
        }
    }
    i
}

/// Match finder statistics (build with RUSTFLAGS="--cfg deflate_stats"): finds, chain
/// candidates, inserts, literals, matches, matched bytes, blocks.
#[cfg(deflate_stats)]
pub(crate) static STATS: [std::sync::atomic::AtomicU64; 8] = [const { std::sync::atomic::AtomicU64::new(0) }; 8];
#[inline(always)]
fn stat(_i: usize, _n: u64) {
    #[cfg(deflate_stats)]
    STATS[_i].fetch_add(_n, std::sync::atomic::Ordering::Relaxed);
}

// ---------------------------------------------------------------------------------------
// Huffman code construction
// ---------------------------------------------------------------------------------------

/// Canonical codes for `lens`, bit-reversed for LSB-first output.
fn canonical_codes(lens: &[u8], codes: &mut [u16]) {
    let mut bl = [0u16; 16];
    for &l in lens {
        bl[l as usize] += 1;
    }
    bl[0] = 0;
    let mut next = [0u16; 16];
    let mut code = 0u16;
    for b in 1..16 {
        code = (code + bl[b - 1]) << 1;
        next[b] = code;
    }
    for (s, &l) in lens.iter().enumerate() {
        if l != 0 {
            codes[s] = next[l as usize].reverse_bits() >> (16 - l as u32);
            next[l as usize] += 1;
        }
    }
}

// ---------------------------------------------------------------------------------------
// Bit writer
// ---------------------------------------------------------------------------------------

/// LSB-first bit writer. `buf.len() >= pos + 8` is kept by [`BitWriter::reserve`] so that
/// `flush` can always store a whole word.
struct BitWriter {
    buf: Vec<u8>,
    pos: usize,
    bits: u64,
    count: u32,
}

impl BitWriter {
    fn new(out: Vec<u8>) -> BitWriter {
        let pos = out.len();
        BitWriter { buf: out, pos, bits: 0, count: 0 }
    }

    /// Makes room for `n` more bytes (plus the word-store slack).
    #[inline]
    fn reserve(&mut self, n: usize) {
        let need = self.pos + n + 16;
        if self.buf.len() < need {
            let new_len = need.max(self.buf.len() + self.buf.len() / 2);
            self.buf.resize(new_len, 0);
        }
    }

    /// Adds `n` bits (the caller keeps `count + n <= 63` between flushes).
    #[inline(always)]
    fn put(&mut self, v: u64, n: u32) {
        self.bits |= v << self.count;
        self.count += n;
    }

    /// Stores the whole bytes of the bit buffer; afterwards `count < 8`.
    #[inline(always)]
    fn flush(&mut self) {
        assert!(self.pos + 8 <= self.buf.len() && self.count < 64);
        // SAFETY: checked above (the assert is almost free and never fails: reserve() keeps
        // 16 bytes of slack past every block's worst case).
        unsafe { (self.buf.as_mut_ptr().add(self.pos) as *mut u64).write_unaligned(self.bits.to_le()) };
        let nb = self.count >> 3;
        self.pos += nb as usize;
        self.bits >>= nb << 3;
        self.count &= 7;
    }

    /// Pads to a byte boundary.
    fn align(&mut self) {
        self.flush();
        if self.count > 0 {
            self.count = 8;
            self.flush();
        }
        self.bits = 0;
        self.count = 0;
    }

    /// Copies raw bytes (must be byte aligned).
    fn raw(&mut self, data: &[u8]) {
        debug_assert!(self.count == 0);
        self.reserve(data.len());
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
    }

    fn finish(mut self) -> Vec<u8> {
        self.reserve(0);
        self.align();
        self.buf.truncate(self.pos);
        self.buf
    }
}

// ---------------------------------------------------------------------------------------
// The compressor
// ---------------------------------------------------------------------------------------

/// Sequence budget per block: a block ends before it could overflow (one check interval
/// adds at most (CHECK_INTERVAL + MAX_MATCH) / 3 sequences; long runs are emitted within the
/// remaining room).
const MAX_BLOCK_SEQS: usize = 1 << 17;
const SEQ_HEADROOM: usize = (CHECK_INTERVAL + 2 * MAX_MATCH) / MIN_MATCH + 64;

/// A sequence is a literal run (bytes taken from the input) followed by a match:
/// `lit_run | len << 32 | dist << 48`.
#[inline(always)]
fn seq(lit_run: u32, len: usize, dist: usize) -> u64 {
    lit_run as u64 | ((len as u64) << 32) | ((dist as u64) << 48)
}

#[inline(always)]
fn unseq(s: u64) -> (usize, usize, usize) {
    (s as u32 as usize, (s >> 32) as u16 as usize, (s >> 48) as usize)
}

/// Reusable DEFLATE compressor state (hash tables, sequence buffer). One per thread; about
/// 1.5 MiB of memory. Create with [`Compressor::new`] and call [`Compressor::compress`] any
/// number of times.
pub struct Compressor {
    level: u32,
    p: Params,
    head4: Vec<u32>,
    head3: Vec<u32>,
    /// prev[p & WMASK] = the previous position with the same 4-byte hash as p.
    prev: Vec<u32>,
    /// Sequence buffer (MAX_BLOCK_SEQS entries).
    seqs: Vec<u64>,
}

/// The match finder's tables as raw pointers plus the hash shifts: a `Copy` handle that
/// lives in registers in the parse loop (LLVM cannot prove that stores into the tables do
/// not alias the fields of a `&mut Compressor`, so going through `self` reloads everything).
#[derive(Clone, Copy)]
struct Mf {
    h4: *mut u32,
    h3: *mut u32,
    prev: *mut u32,
    s4: u32,
    s3: u32,
}

impl Mf {
    #[inline(always)]
    fn hash4(&self, v: u32) -> usize {
        (v.wrapping_mul(0x1E35_A7BD) >> self.s4) as usize
    }

    #[inline(always)]
    fn hash3(&self, v: u32) -> usize {
        ((v << 8).wrapping_mul(0x9E37_79B1) >> self.s3) as usize
    }

    /// Inserts positions `p..to` (those with fewer than 4 bytes left are skipped).
    ///
    /// # Safety
    /// The tables are alive and sized for the shifts (see [`Compressor::reset`]).
    #[inline(always)]
    unsafe fn insert_range(self, buf: &[u8], mut p: usize, to: usize) {
        let to = to.min(buf.len().saturating_sub(MIN_LOOKAHEAD - 1));
        stat(2, to.saturating_sub(p) as u64);
        while p < to {
            // SAFETY: p + 4 <= buf.len(); hashes are < table lengths; p & WMASK < WSIZE.
            unsafe {
                let v = ld32(buf, p);
                let (h4, h3) = (self.hash4(v), self.hash3(v));
                *self.prev.add(p & WMASK) = *self.h4.add(h4);
                *self.h4.add(h4) = p as u32;
                *self.h3.add(h3) = p as u32;
            }
            p += 1;
        }
    }

    /// [`Mf::insert_range`] of the fast finder: the 4-byte hash table only.
    ///
    /// # Safety
    /// As [`Mf::insert_range`].
    #[inline(always)]
    unsafe fn insert_range_fast(self, buf: &[u8], mut p: usize, to: usize) {
        let to = to.min(buf.len().saturating_sub(MIN_LOOKAHEAD - 1));
        while p < to {
            // SAFETY: p + 4 <= buf.len(); the hash is < the table length.
            unsafe { *self.h4.add(self.hash4(ld32(buf, p))) = p as u32 };
            p += 1;
        }
    }

    /// The fast finder: inserts `pos` and checks the one candidate of its 4-byte hash bucket.
    /// Returns (len, dist), len 0 when it does not match.
    ///
    /// # Safety
    /// As [`Mf::find`].
    #[inline(always)]
    unsafe fn find_fast(self, buf: &[u8], pos: usize, max_len: usize) -> (usize, usize) {
        debug_assert!(max_len >= MIN_LOOKAHEAD && pos + max_len <= buf.len());
        // SAFETY: pos + 4 <= buf.len(); the hash is < the table length; a candidate that is
        // not the sentinel is < pos, so cand + 4 <= buf.len() (checked by the distance test).
        unsafe {
            let cur = ld32(buf, pos);
            let h = self.hash4(cur);
            let cand = *self.h4.add(h);
            *self.h4.add(h) = pos as u32;
            let dist = (pos as u32).wrapping_sub(cand);
            if dist.wrapping_sub(1) < WSIZE as u32 && ld32(buf, cand as usize) == cur {
                return (extend(buf, cand as usize, pos, 4, max_len), dist as usize);
            }
        }
        (0, 0)
    }

    /// Inserts `pos` and searches for the longest match longer than `best_len` (the hash-3
    /// candidate first when `best_len < 3`). Returns (len, dist); len <= best_len: none.
    ///
    /// # Safety
    /// As [`Mf::insert_range`]; `pos + max_len <= buf.len()`, `max_len >= MIN_LOOKAHEAD`,
    /// `nice <= max_len`.
    #[inline(always)]
    unsafe fn find(
        self,
        buf: &[u8],
        pos: usize,
        max_len: usize,
        nice: usize,
        mut depth: u32,
        best_len: usize,
    ) -> (usize, usize) {
        debug_assert!(max_len >= MIN_LOOKAHEAD && pos + max_len <= buf.len() && nice <= max_len);
        stat(0, 1);
        // SAFETY: pos + 4 <= buf.len().
        let cur = unsafe { ld32(buf, pos) };
        let (h4, h3) = (self.hash4(cur), self.hash3(cur));
        // SAFETY: hash values are < table lengths; pos & WMASK < WSIZE.
        let (mut cand, cand3) = unsafe {
            let c4 = *self.h4.add(h4);
            *self.h4.add(h4) = pos as u32;
            *self.prev.add(pos & WMASK) = c4;
            let c3 = *self.h3.add(h3);
            *self.h3.add(h3) = pos as u32;
            (c4, c3)
        };
        let mut best = best_len;
        let mut best_dist = 0usize;
        if best < MIN_MATCH {
            let d3 = (pos as u32).wrapping_sub(cand3);
            // SAFETY: cand3 < pos, so cand3 + 4 <= pos + 3 < buf.len().
            if d3.wrapping_sub(1) < MAX_DIST3 && (unsafe { ld32(buf, cand3 as usize) } ^ cur) & 0x00FF_FFFF == 0 {
                best = MIN_MATCH;
                best_dist = d3 as usize;
            }
        }
        // Chain candidates must beat `t` (>= 3: the chain finds 4-byte matches).
        let mut t = best.max(MIN_MATCH);
        if t >= max_len {
            return (best, best_dist);
        }
        // SAFETY: t < max_len, so pos + t + 1 <= buf.len().
        let mut tail = unsafe { ld32(buf, pos + t - 3) };
        loop {
            let dist = (pos as u32).wrapping_sub(cand);
            if dist.wrapping_sub(1) >= WSIZE as u32 {
                break;
            }
            let c = cand as usize;
            stat(1, 1);
            // SAFETY: c < pos and t < max_len, so c + t + 1 <= pos + max_len <= buf.len().
            unsafe {
                if ld32(buf, c + t - 3) == tail && ld32(buf, c) == cur {
                    let len = extend(buf, c, pos, 4, max_len);
                    if len > t {
                        best = len;
                        best_dist = dist as usize;
                        if len >= nice {
                            break;
                        }
                        t = len;
                        tail = ld32(buf, pos + t - 3);
                    }
                }
            }
            depth -= 1;
            if depth == 0 {
                break;
            }
            // SAFETY: c & WMASK < WSIZE.
            let next = unsafe { *self.prev.add(c & WMASK) };
            // Links only go backwards; a link overwritten by a newer position (at exactly
            // 32 KiB distance) or the sentinel ends the walk.
            if next >= cand {
                break;
            }
            cand = next;
        }
        (best, best_dist)
    }
}

/// Block-split statistics (8 literal classes by top 3 bits, 2 match-length classes) of the
/// block so far, updated every CHECK_INTERVAL input bytes.
struct SplitStats {
    obs: [u32; NUM_OBS],
    num_obs: u32,
    /// Observations not yet compared with the block (evaluated once there are enough).
    new: [u32; NUM_OBS],
    num_new: u32,
    /// Input before `obs_pos` has been observed; sequence `obs_seq` (the first not fully
    /// observed one) starts at `obs_seq_pos`.
    obs_seq: usize,
    obs_seq_pos: usize,
    obs_pos: usize,
    /// Position of the next check.
    next_check: usize,
}

impl SplitStats {
    fn new(pos: usize) -> SplitStats {
        SplitStats {
            obs: [0; NUM_OBS],
            num_obs: 0,
            new: [0; NUM_OBS],
            num_new: 0,
            obs_seq: 0,
            obs_seq_pos: pos,
            obs_pos: pos,
            next_check: pos + CHECK_INTERVAL,
        }
    }

    /// Should the block (`seqs` + a pending literal run, `block_start..pos`) end at `pos`?
    fn should_end(&mut self, buf: &[u8], seqs: &[u64], block_start: usize, pos: usize) -> bool {
        let block_len = pos - block_start;
        if block_len >= SOFT_MAX_BLOCK_LEN || seqs.len() >= MAX_BLOCK_SEQS - SEQ_HEADROOM {
            return true;
        }
        self.next_check = pos + CHECK_INTERVAL;
        // Observe the input since the last check.
        let mut new = self.new;
        let from = self.obs_pos;
        let count_lits = |new: &mut [u32; NUM_OBS], a: usize, b: usize| {
            let a = a.max(from);
            if a < b {
                for &x in &buf[a..b] {
                    new[(x >> 5) as usize] += 1;
                }
            }
        };
        let mut q = self.obs_seq_pos;
        for &s in &seqs[self.obs_seq..] {
            let (lr, len, _) = unseq(s);
            count_lits(&mut new, q, q + lr);
            q += lr;
            new[8 + (len >= 9) as usize] += 1;
            q += len;
        }
        count_lits(&mut new, q, pos);
        self.obs_seq = seqs.len();
        self.obs_seq_pos = q;
        self.obs_pos = pos;
        let n_new: u64 = new.iter().map(|&x| x as u64).sum();
        if n_new < MIN_NEW_OBS {
            self.new = new;
            self.num_new = n_new as u32;
            return false;
        }
        self.new = [0; NUM_OBS];
        self.num_new = 0;
        let n_old = self.num_obs as u64;
        if n_old > 0 && n_new > 0 && block_len >= MIN_BLOCK_LEN {
            // L1 distance between the observation distributions of the block so far and of
            // the latest interval; long blocks split more readily.
            let mut delta = 0u64;
            for i in 0..NUM_OBS {
                delta += (new[i] as u64 * n_old).abs_diff(self.obs[i] as u64 * n_new);
            }
            let cutoff = n_new * n_old * 200 / 512;
            if delta + (block_len as u64 / 4096) * n_old >= cutoff {
                return true;
            }
        }
        for i in 0..NUM_OBS {
            self.obs[i] += new[i];
        }
        self.num_obs += n_new as u32;
        false
    }
}

impl Compressor {
    /// A compressor for `level` (0 = stored only, 1 = fastest .. 9 = best; values above 9
    /// are treated as 9).
    pub fn new(level: u32) -> Compressor {
        let level = level.min(9);
        Compressor { level, p: params(level), head4: Vec::new(), head3: Vec::new(), prev: Vec::new(), seqs: Vec::new() }
    }

    /// The compression level.
    pub fn level(&self) -> u32 {
        self.level
    }

    /// Compresses `buf[start..]` as raw DEFLATE blocks appended to `out`; `buf[..start]` is
    /// a preset dictionary (only its last 32 KiB matter) that matches may refer to, i.e. the
    /// data that precedes this piece in the uncompressed stream.
    ///
    /// With `last`, the final block carries BFINAL (the stream is complete). Otherwise the
    /// output ends on a byte boundary (with an empty stored block if needed, like a zlib
    /// sync flush), so the compressed pieces of consecutive `buf`s can simply be concatenated.
    pub fn compress(&mut self, buf: &[u8], start: usize, last: bool, out: &mut Vec<u8>) {
        let start = start.min(buf.len());
        let dict = start.min(WSIZE);
        let buf = &buf[start - dict..];
        let mut bw = BitWriter::new(std::mem::take(out));
        // Positions are u32: process huge inputs in segments (each primed with the window).
        const SEG: usize = 1 << 30;
        let mut s = dict;
        loop {
            let e = (s + SEG).min(buf.len());
            let d = s.min(WSIZE);
            let is_last = e == buf.len();
            self.compress_segment(&buf[s - d..e], d, last && is_last, &mut bw);
            if is_last {
                break;
            }
            s = e;
        }
        if !last {
            // Byte-align with an empty stored block (sync flush) unless already aligned.
            bw.reserve(8);
            bw.flush();
            if bw.count != 0 {
                bw.put(0, 3);
                bw.align();
                bw.raw(&[0, 0, 0xFF, 0xFF]);
            }
        }
        *out = bw.finish();
    }

    /// Sizes and clears the tables for an input of `len` bytes; returns the table handle.
    fn reset(&mut self, len: usize) -> Mf {
        // Small inputs get small hash tables (cheap to clear).
        let need = (len.max(1) as u64 * 2).next_power_of_two().trailing_zeros();
        let b4 = need.clamp(10, HASH4_BITS);
        let b3 = need.clamp(10, HASH3_BITS);
        if self.head4.len() < 1 << b4 {
            self.head4.resize(1 << b4, SENTINEL);
        }
        if self.head3.len() < 1 << b3 {
            self.head3.resize(1 << b3, SENTINEL);
        }
        self.head4[..1 << b4].fill(SENTINEL);
        if !self.p.fast {
            self.head3[..1 << b3].fill(SENTINEL);
        }
        if self.prev.len() < WSIZE {
            self.prev.resize(WSIZE, SENTINEL);
        }
        let want = (len / MIN_MATCH + SEQ_HEADROOM + 64).min(MAX_BLOCK_SEQS);
        if self.seqs.len() < want {
            self.seqs.resize(want, 0);
        }
        Mf {
            h4: self.head4.as_mut_ptr(),
            h3: self.head3.as_mut_ptr(),
            prev: self.prev.as_mut_ptr(),
            s4: 32 - b4,
            s3: 32 - b3,
        }
    }

    fn compress_segment(&mut self, buf: &[u8], start: usize, last: bool, bw: &mut BitWriter) {
        if self.level == 0 {
            write_stored(bw, &buf[start..], last);
            return;
        }
        if self.p.fast {
            self.segment::<true>(buf, start, last, bw);
        } else {
            self.segment::<false>(buf, start, last, bw);
        }
    }

    /// The parse loop, specialized for the fast finder (`FAST`, level 1) or the chain search.
    fn segment<const FAST: bool>(&mut self, buf: &[u8], start: usize, last: bool, bw: &mut BitWriter) {
        let end = buf.len();
        let mf = self.reset(end - start);
        let p = self.p;
        let mut seqbuf = std::mem::take(&mut self.seqs);
        // A block needs at most (block bytes) / 3 sequences: shrink the budget for small inputs.
        let max_seqs = seqbuf.len();
        let seqs: &mut [u64] = &mut seqbuf;
        // SAFETY (all mf calls below): the tables stay allocated and unresized until the end
        // of this function, and `reset` sized them for mf's shifts.
        unsafe {
            if FAST {
                mf.insert_range_fast(buf, 0, start)
            } else {
                mf.insert_range(buf, 0, start)
            }
        };
        let mut pos = start;
        let mut block_start = start;
        let mut ns = 0usize;
        let mut lit_run = 0u32;
        let mut split = SplitStats::new(start);
        while pos < end {
            if pos >= split.next_check && split.should_end(buf, &seqs[..ns], block_start, pos) {
                write_block(bw, buf, block_start, pos, &seqs[..ns], lit_run, false);
                block_start = pos;
                ns = 0;
                lit_run = 0;
                split = SplitStats::new(pos);
            }
            // ---- one parse step: a literal, a (lazily chosen) match, or a long run ----
            let rem = end - pos;
            if rem < MIN_LOOKAHEAD {
                lit_run += 1;
                pos += 1;
                continue;
            }
            let max_len = rem.min(MAX_MATCH);
            // SAFETY: pos + max_len <= end, max_len >= 4.
            let (mut len, mut dist) = unsafe {
                if FAST {
                    mf.find_fast(buf, pos, max_len)
                } else {
                    mf.find(buf, pos, max_len, p.nice.min(max_len), p.depth, MIN_MATCH - 1)
                }
            };
            if len < MIN_MATCH {
                lit_run += 1;
                pos += 1;
                continue;
            }
            let mut cur = pos;
            pos += 1;
            if !FAST && p.lazy > 0 {
                loop {
                    if len >= p.nice || end - pos < MIN_LOOKAHEAD {
                        break;
                    }
                    let depth = if len >= p.good { (p.depth >> 2).max(1) } else { p.depth };
                    let ml = (end - pos).min(MAX_MATCH);
                    // SAFETY: pos + ml <= end, ml >= 4.
                    let (l2, d2) = unsafe { mf.find(buf, pos, ml, p.nice.min(ml), depth, len) };
                    if l2 > len && better(l2, d2, len, dist, 2) {
                        lit_run += 1;
                        cur = pos;
                        len = l2;
                        dist = d2;
                        pos += 1;
                        continue;
                    }
                    pos += 1;
                    if p.lazy > 1 && end - pos >= MIN_LOOKAHEAD && len < p.nice {
                        let ml = (end - pos).min(MAX_MATCH);
                        // SAFETY: as above.
                        let (l3, d3) = unsafe { mf.find(buf, pos, ml, p.nice.min(ml), depth, len) };
                        if l3 > len && better(l3, d3, len, dist, 6) {
                            lit_run += 2;
                            cur = pos;
                            len = l3;
                            dist = d3;
                            pos += 1;
                            continue;
                        }
                        pos += 1;
                    }
                    break;
                }
            }
            if len == MAX_MATCH {
                // Runs and long repeats: follow the same distance as far as it matches and
                // emit maximal matches without hashing the interior (zero pages!).
                // SAFETY: cur - dist < cur, cur + (end - cur) <= end; 258 bytes match already.
                let l = unsafe { extend(buf, cur - dist, cur, MAX_MATCH, end - cur) };
                let room = (max_seqs - SEQ_HEADROOM).saturating_sub(ns);
                let n = (l / MAX_MATCH).min(room);
                if n > 1 {
                    stat(3, lit_run as u64);
                    stat(4, n as u64);
                    stat(5, (n * MAX_MATCH) as u64);
                    seqs[ns] = seq(lit_run, MAX_MATCH, dist);
                    seqs[ns + 1..ns + n].fill(seq(0, MAX_MATCH, dist));
                    ns += n;
                    lit_run = 0;
                    let mend = cur + n * MAX_MATCH;
                    // SAFETY: see above.
                    unsafe {
                        if FAST {
                            mf.insert_range_fast(buf, mend - MIN_LOOKAHEAD, mend);
                        } else if dist < 16 || p.max_insert < MAX_MATCH {
                            // A run (short period): its interior hashes to a few chains.
                            mf.insert_range(buf, pos, (pos + 4).min(mend));
                            mf.insert_range(buf, mend - MIN_LOOKAHEAD, mend);
                        } else {
                            // Repeated content: keep it findable.
                            mf.insert_range(buf, pos, mend);
                        }
                    }
                    pos = mend;
                    continue;
                }
            }
            stat(3, lit_run as u64);
            stat(4, 1);
            stat(5, len as u64);
            seqs[ns] = seq(lit_run, len, dist);
            ns += 1;
            lit_run = 0;
            let mend = cur + len;
            // SAFETY: see above.
            unsafe {
                if FAST {
                    if len <= p.max_insert {
                        mf.insert_range_fast(buf, pos, mend);
                    } else {
                        mf.insert_range_fast(buf, pos, (pos + 4).min(mend));
                        mf.insert_range_fast(buf, (pos + 4).max(mend - 4), mend);
                    }
                } else if len <= p.max_insert {
                    mf.insert_range(buf, pos, mend);
                } else {
                    // Long match: only the first and last few positions.
                    mf.insert_range(buf, pos, (pos + 8).min(mend));
                    mf.insert_range(buf, (pos + 8).max(mend - 8), mend);
                }
            }
            pos = mend;
        }
        write_block(bw, buf, block_start, end, &seqs[..ns], lit_run, last);
        self.seqs = seqbuf;
    }
}

/// `better(new, old)`: is a match of `l2` at `d2` (starting one or two bytes later, after
/// literals) worth more than `l1` at `d1`? Length gains dominate; distance costs log2 bits.
#[inline(always)]
fn better(l2: usize, d2: usize, l1: usize, d1: usize, bias: i32) -> bool {
    let lg = |d: usize| 31 - (d as u32).leading_zeros() as i32;
    4 * (l2 as i32 - l1 as i32) + lg(d1) - lg(d2) > bias
}

/// Writes `buf[bstart..bend]` (= `seqs` followed by `tail_lits` literals) as the cheapest
/// block type.
fn write_block(bw: &mut BitWriter, buf: &[u8], bstart: usize, bend: usize, seqs: &[u64], tail_lits: u32, last: bool) {
    stat(6, 1);
    let mut lit_freq = [0u32; 288];
    let mut dist_freq = [0u32; 32];
    let mut q = bstart;
    for &s in seqs {
        let (lr, len, dist) = unseq(s);
        for &b in &buf[q..q + lr] {
            lit_freq[b as usize] += 1;
        }
        lit_freq[257 + LEN_SLOT[len] as usize] += 1;
        dist_freq[dist_slot(dist)] += 1;
        q += lr + len;
    }
    for &b in &buf[q..q + tail_lits as usize] {
        lit_freq[b as usize] += 1;
    }
    debug_assert_eq!(q + tail_lits as usize, bend);
    lit_freq[256] = 1;
    let mut llens = [0u8; 288];
    let mut dlens = [0u8; 32];
    huffman_lengths(&lit_freq[..286], 15, &mut llens);
    huffman_lengths(&dist_freq[..30], 15, &mut dlens);
    let hdr = DynHeader::new(&llens, &dlens);

    let mut extra = 0u64;
    for i in 0..29 {
        extra += lit_freq[257 + i] as u64 * LEN_EXTRA[i] as u64;
    }
    for i in 0..30 {
        extra += dist_freq[i] as u64 * DIST_EXTRA[i] as u64;
    }
    let fixed_l = fixed_litlen_lens();
    let mut dyn_cost = 3 + hdr.cost + extra;
    let mut fixed_cost = 3 + extra;
    for s in 0..286 {
        let f = lit_freq[s] as u64;
        dyn_cost += f * llens[s] as u64;
        fixed_cost += f * fixed_l[s] as u64;
    }
    for s in 0..30 {
        let f = dist_freq[s] as u64;
        dyn_cost += f * dlens[s] as u64;
        fixed_cost += f * 5;
    }
    let n = bend - bstart;
    // Stored: header + padding (<= 7) + LEN/NLEN per 65535-byte piece, then the bytes.
    let pieces = n.div_ceil(65535).max(1) as u64;
    let stored_cost = pieces * (3 + 7 + 32) + 8 * n as u64;

    if stored_cost <= dyn_cost.min(fixed_cost) {
        write_stored(bw, &buf[bstart..bend], last);
        return;
    }
    let mut lcodes = [0u16; 288];
    let mut dcodes = [0u16; 32];
    bw.reserve((dyn_cost.min(fixed_cost) / 8) as usize + 64);
    if dyn_cost < fixed_cost {
        canonical_codes(&llens, &mut lcodes);
        canonical_codes(&dlens, &mut dcodes);
        bw.put(last as u64 | (2 << 1), 3);
        hdr.write(bw);
        write_seqs(bw, buf, bstart, seqs, tail_lits, &llens, &lcodes, &dlens, &dcodes);
    } else {
        let dl = [5u8; 32];
        canonical_codes(&fixed_l, &mut lcodes);
        canonical_codes(&dl, &mut dcodes);
        bw.put(last as u64 | (1 << 1), 3);
        write_seqs(bw, buf, bstart, seqs, tail_lits, &fixed_l, &lcodes, &dl, &dcodes);
    }
}

/// Writes stored blocks for `data` (at least one block, even when empty).
fn write_stored(bw: &mut BitWriter, data: &[u8], last: bool) {
    let mut chunks = data.chunks(65535).peekable();
    if data.is_empty() {
        bw.reserve(16);
        bw.put(last as u64, 3);
        bw.align();
        bw.raw(&[0, 0, 0xFF, 0xFF]);
        return;
    }
    while let Some(c) = chunks.next() {
        let fin = last && chunks.peek().is_none();
        bw.reserve(16);
        bw.put(fin as u64, 3);
        bw.align();
        let l = c.len() as u16;
        bw.raw(&[l as u8, (l >> 8) as u8, !l as u8, (!l >> 8) as u8]);
        bw.raw(c);
    }
}

/// Emits the block's sequences and `tail_lits` trailing literals (literal bytes read from
/// `buf` starting at `bstart`) and the end-of-block code. The caller reserved room for the
/// block's exact bit cost.
#[allow(clippy::too_many_arguments)]
fn write_seqs(
    bw: &mut BitWriter,
    buf: &[u8],
    bstart: usize,
    seqs: &[u64],
    tail_lits: u32,
    llens: &[u8; 288],
    lcodes: &[u16; 288],
    dlens: &[u8; 32],
    dcodes: &[u16; 32],
) {
    // Length code + extra bits merged per length; literal code | bit length << 16; distance
    // slot code | bit length << 16 (+ extra bit count << 24).
    let mut lenc = [0u64; 259];
    for (len, e) in lenc.iter_mut().enumerate().skip(3) {
        let s = LEN_SLOT[len] as usize;
        let sym = 257 + s;
        let nb = llens[sym] as u64;
        *e = (lcodes[sym] as u64 | ((len as u64 - LEN_BASE[s] as u64) << nb)) | ((nb + LEN_EXTRA[s] as u64) << 32);
    }
    let mut lit = [0u32; 256];
    for (b, e) in lit.iter_mut().enumerate() {
        *e = lcodes[b] as u32 | ((llens[b] as u32) << 16);
    }
    let mut dsym = [0u32; 30];
    for (s, e) in dsym.iter_mut().enumerate() {
        *e = dcodes[s] as u32 | ((dlens[s] as u32) << 16) | ((DIST_EXTRA[s] as u32) << 24);
    }
    // The bit writer state lives in registers for the whole loop.
    let out = bw.buf.as_mut_ptr();
    let cap = bw.buf.len();
    let (mut bits, mut count, mut pos) = (bw.bits, bw.count, bw.pos);
    macro_rules! put {
        ($v:expr, $n:expr) => {{
            bits |= ($v as u64) << count;
            count += $n as u32;
        }};
    }
    macro_rules! flush {
        () => {{
            debug_assert!(pos + 8 <= cap && count < 64);
            // SAFETY: the caller reserved the block's exact size + 64 bytes, and pos only
            // advances by bits actually written, so pos + 8 <= cap.
            unsafe { (out.add(pos) as *mut u64).write_unaligned(bits.to_le()) };
            pos += (count >> 3) as usize;
            bits >>= count & !7;
            count &= 7;
        }};
    }
    let _ = cap;
    let emit_lits = |lits: &[u8], bits: &mut u64, count: &mut u32, pos: &mut usize| {
        let (mut b_, mut c_, mut p_) = (*bits, *count, *pos);
        let mut it = lits.chunks_exact(2);
        for two in &mut it {
            let (a, b) = (lit[two[0] as usize], lit[two[1] as usize]);
            b_ |= ((a & 0xFFFF) as u64) << c_;
            c_ += a >> 16;
            b_ |= ((b & 0xFFFF) as u64) << c_;
            c_ += b >> 16;
            // SAFETY: as in flush!.
            unsafe { (out.add(p_) as *mut u64).write_unaligned(b_.to_le()) };
            p_ += (c_ >> 3) as usize;
            b_ >>= c_ & !7;
            c_ &= 7;
        }
        if let [x] = it.remainder() {
            let a = lit[*x as usize];
            b_ |= ((a & 0xFFFF) as u64) << c_;
            c_ += a >> 16;
            // SAFETY: as in flush!.
            unsafe { (out.add(p_) as *mut u64).write_unaligned(b_.to_le()) };
            p_ += (c_ >> 3) as usize;
            b_ >>= c_ & !7;
            c_ &= 7;
        }
        (*bits, *count, *pos) = (b_, c_, p_);
    };
    let mut q = bstart;
    for &s in seqs {
        let (lr, len, dist) = unseq(s);
        if lr != 0 {
            emit_lits(&buf[q..q + lr], &mut bits, &mut count, &mut pos);
        }
        q += lr + len;
        let lc = lenc[len];
        put!(lc as u32, (lc >> 32) as u32);
        let ds = dist_slot(dist);
        let d = dsym[ds];
        let nb = (d >> 16) & 0xFF;
        put!((d & 0xFFFF) as u64 | (((dist - DIST_BASE[ds] as usize) as u64) << nb), nb + (d >> 24));
        flush!();
    }
    if tail_lits != 0 {
        emit_lits(&buf[q..q + tail_lits as usize], &mut bits, &mut count, &mut pos);
    }
    put!(lcodes[256], llens[256]);
    flush!();
    (bw.bits, bw.count, bw.pos) = (bits, count, pos);
}

/// A dynamic block header: HLIT/HDIST/HCLEN, the precode and the RLE-coded code lengths.
struct DynHeader {
    hlit: usize,
    hdist: usize,
    hclen: usize,
    pre_lens: [u8; 19],
    pre_codes: [u16; 19],
    /// (precode symbol, extra bits value)
    items: [(u8, u8); 320],
    nitems: usize,
    /// Header size in bits (excluding the 3-bit block header).
    cost: u64,
}

impl DynHeader {
    fn new(llens: &[u8; 288], dlens: &[u8; 32]) -> DynHeader {
        let mut hlit = 286;
        while hlit > 257 && llens[hlit - 1] == 0 {
            hlit -= 1;
        }
        let mut hdist = 30;
        while hdist > 1 && dlens[hdist - 1] == 0 {
            hdist -= 1;
        }
        let mut all = [0u8; 316];
        all[..hlit].copy_from_slice(&llens[..hlit]);
        all[hlit..hlit + hdist].copy_from_slice(&dlens[..hdist]);
        let all = &all[..hlit + hdist];
        let mut items = [(0u8, 0u8); 320];
        let mut ni = 0;
        let mut freq = [0u32; 19];
        let mut push = |s: u8, x: u8, items: &mut [(u8, u8); 320], ni: &mut usize| {
            items[*ni] = (s, x);
            *ni += 1;
            freq[s as usize] += 1;
        };
        let mut i = 0;
        while i < all.len() {
            let l = all[i];
            let mut run = 1;
            while i + run < all.len() && all[i + run] == l {
                run += 1;
            }
            i += run;
            if l == 0 {
                while run >= 11 {
                    let r = run.min(138);
                    push(18, (r - 11) as u8, &mut items, &mut ni);
                    run -= r;
                }
                if run >= 3 {
                    push(17, (run - 3) as u8, &mut items, &mut ni);
                    run = 0;
                }
            } else {
                push(l, 0, &mut items, &mut ni);
                run -= 1;
                while run >= 3 {
                    let r = run.min(6);
                    push(16, (r - 3) as u8, &mut items, &mut ni);
                    run -= r;
                }
            }
            for _ in 0..run {
                push(l, 0, &mut items, &mut ni);
            }
        }
        let mut pre_lens = [0u8; 19];
        huffman_lengths(&freq, 7, &mut pre_lens);
        let mut pre_codes = [0u16; 19];
        canonical_codes(&pre_lens, &mut pre_codes);
        let mut hclen = 19;
        while hclen > 4 && pre_lens[PRECODE_ORDER[hclen - 1]] == 0 {
            hclen -= 1;
        }
        let mut cost = 5 + 5 + 4 + 3 * hclen as u64;
        for s in 0..19 {
            let extra = match s {
                16 => 2,
                17 => 3,
                18 => 7,
                _ => 0,
            };
            cost += freq[s] as u64 * (pre_lens[s] as u64 + extra);
        }
        DynHeader { hlit, hdist, hclen, pre_lens, pre_codes, items, nitems: ni, cost }
    }

    fn write(&self, bw: &mut BitWriter) {
        bw.reserve((self.cost / 8) as usize + 16);
        bw.put((self.hlit - 257) as u64, 5);
        bw.put((self.hdist - 1) as u64, 5);
        bw.put((self.hclen - 4) as u64, 4);
        bw.flush();
        for &s in &PRECODE_ORDER[..self.hclen] {
            bw.put(self.pre_lens[s] as u64, 3);
            bw.flush();
        }
        for &(s, x) in &self.items[..self.nitems] {
            let s = s as usize;
            bw.put(self.pre_codes[s] as u64, self.pre_lens[s] as u32);
            match s {
                16 => bw.put(x as u64, 2),
                17 => bw.put(x as u64, 3),
                18 => bw.put(x as u64, 7),
                _ => {}
            }
            bw.flush();
        }
    }
}

// ---------------------------------------------------------------------------------------
// One-shot API (parallel for large inputs)
// ---------------------------------------------------------------------------------------

thread_local! {
    static TLS_COMPRESSOR: std::cell::RefCell<Option<Compressor>> = const { std::cell::RefCell::new(None) };
}

/// Runs `f` with this thread's cached compressor for `level`.
fn with_compressor<R>(level: u32, f: impl FnOnce(&mut Compressor) -> R) -> R {
    TLS_COMPRESSOR.with(|c| {
        let mut c = c.borrow_mut();
        let level = level.min(9);
        if c.as_ref().is_none_or(|x| x.level != level) {
            *c = Some(Compressor::new(level));
        }
        f(c.as_mut().unwrap())
    })
}

/// Compresses `data` as raw DEFLATE, appending to `out`. Inputs larger than [`CHUNK`] are
/// compressed in parallel (deterministic output, independent of the thread count).
pub fn deflate_compress_into(data: &[u8], level: u32, out: &mut Vec<u8>) {
    if data.len() <= CHUNK {
        with_compressor(level, |c| c.compress(data, 0, true, out));
        return;
    }
    let n = data.len().div_ceil(CHUNK);
    let parts = crate::util::par::par_map(n, |i| {
        let s = i * CHUNK;
        let e = (s + CHUNK).min(data.len());
        let d = s.min(WSIZE);
        let mut v = Vec::new();
        with_compressor(level, |c| c.compress(&data[s - d..e], d, i == n - 1, &mut v));
        v
    });
    out.reserve(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        out.extend_from_slice(&p);
    }
}

/// Compresses `data` as a raw DEFLATE stream (RFC 1951) at `level` (0 = stored,
/// 1 = fastest .. 9 = best; 6 is zlib's default).
pub fn deflate_compress(data: &[u8], level: u32) -> Vec<u8> {
    let mut out = Vec::new();
    deflate_compress_into(data, level, &mut out);
    out
}

/// Compresses `data` as a zlib stream (RFC 1950: 2-byte header, raw DEFLATE, big-endian
/// Adler-32), e.g. for PNG IDAT. The header's FLEVEL field follows zlib's convention for
/// `level`. Decompresses with any zlib (`zlib.decompress` in python).
pub fn zlib_compress(data: &[u8], level: u32) -> Vec<u8> {
    let level = level.min(9);
    let flevel: u16 = match level {
        0 | 1 => 0,
        2..=5 => 1,
        6 => 2,
        _ => 3,
    };
    let mut h: u16 = (0x78 << 8) | (flevel << 6);
    h += 31 - h % 31;
    let mut out = Vec::with_capacity(data.len() / 3 + 64);
    out.extend_from_slice(&h.to_be_bytes());
    let adler = if data.len() > CHUNK {
        // Large inputs: checksum on a helper thread while the chunks compress.
        std::thread::scope(|s| {
            let a = s.spawn(|| adler32(data));
            deflate_compress_into(data, level, &mut out);
            a.join().unwrap_or_else(|_| adler32(data))
        })
    } else {
        deflate_compress_into(data, level, &mut out);
        adler32(data)
    };
    out.extend_from_slice(&adler.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecs::testdata::gen_data;

    fn rng_bytes(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed | 1;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 32) as u8
            })
            .collect()
    }

    fn text(n: usize) -> Vec<u8> {
        let words = [&b"kernel "[..], b"process ", b"the ", b"memory ", b"_EPROCESS ", b"0x7ff6", b"\n", b"volatility "];
        let mut s = 12345u64;
        let mut v = Vec::new();
        while v.len() < n {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            v.extend_from_slice(words[(s >> 60) as usize % words.len()]);
        }
        v.truncate(n);
        v
    }

    fn roundtrip(data: &[u8], level: u32) -> usize {
        let c = deflate_compress(data, level);
        let d = crate::codecs::inflate::decompress(&c).expect("inflate failed");
        if d != data {
            let i = d.iter().zip(data.iter()).position(|(a, b)| a != b).unwrap_or(d.len().min(data.len()));
            panic!("level {level}: roundtrip mismatch (len {} vs {}), first diff at {i}", d.len(), data.len());
        }
        c.len()
    }

    #[test]
    fn codecs_deflate_enc_roundtrip_small() {
        for level in 0..=9 {
            roundtrip(b"", level);
            roundtrip(b"a", level);
            roundtrip(b"ab", level);
            roundtrip(b"abcabcabcabcabcabc", level);
            roundtrip(&[0u8; 5], level);
            roundtrip(&[7u8; 1000], level);
            for n in [3usize, 4, 5, 257, 258, 259, 260, 300, 1000] {
                roundtrip(&rng_bytes(n, n as u64), level);
                roundtrip(&text(n), level);
                roundtrip(&vec![0u8; n], level);
            }
        }
    }

    #[test]
    fn codecs_deflate_enc_roundtrip_mixed() {
        let mut data = gen_data(99, 300_000);
        data.extend_from_slice(&rng_bytes(70_000, 5));
        data.extend_from_slice(&vec![0u8; 100_000]);
        data.extend_from_slice(&text(150_000));
        for level in [1, 4, 6, 9] {
            let n = roundtrip(&data, level);
            assert!(n < data.len() / 2, "level {level}: {n}");
        }
        assert!(roundtrip(&rng_bytes(200_000, 3), 6) <= 200_000 + 200);
    }

    #[test]
    fn codecs_deflate_enc_chunked_parallel() {
        // Crosses the parallel CHUNK boundaries (dictionary priming, sync flushes).
        let mut data = gen_data(7, 2 * CHUNK + 12345);
        data[CHUNK - 100..CHUNK + 100].fill(0);
        let c = deflate_compress(&data, 6);
        assert!(crate::codecs::inflate::decompress(&c).unwrap() == data);
        let z = zlib_compress(&data, 9);
        assert!(crate::codecs::zlib::decompress(&z).unwrap() == data);
        // Exact multiple of CHUNK and long zero runs.
        let zeros = vec![0u8; 3 * CHUNK];
        let c = deflate_compress(&zeros, 9);
        assert!(c.len() < 12_000, "{}", c.len());
        assert!(crate::codecs::inflate::decompress(&c).unwrap() == zeros);
    }

    #[test]
    fn codecs_deflate_enc_dictionary_and_flush() {
        let data = text(200_000);
        let mut c = Compressor::new(6);
        let mut out = Vec::new();
        c.compress(&data[..70_000], 0, false, &mut out);
        c.compress(&data[..140_000], 70_000, false, &mut out);
        c.compress(&data, 140_000, true, &mut out);
        assert_eq!(crate::codecs::inflate::decompress(&out).unwrap(), data);
    }

    #[test]
    fn codecs_deflate_enc_zlib_header() {
        for (level, flg) in [(1u32, 0x01u8), (6, 0x9C), (9, 0xDA), (0, 0x01), (4, 0x5E)] {
            let z = zlib_compress(b"hello hello hello", level);
            assert_eq!(&z[..2], &[0x78, flg], "level {level}");
            assert_eq!(crate::codecs::zlib::decompress(&z).unwrap(), b"hello hello hello");
        }
    }
}
