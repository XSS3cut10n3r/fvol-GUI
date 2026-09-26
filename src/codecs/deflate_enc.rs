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

/// Block size limits (tokens / input bytes) and the statistics check interval.
const MAX_BLOCK_TOKENS: usize = 1 << 16;
const TOKEN_SLACK: usize = 4;
const SOFT_MAX_BLOCK_LEN: usize = 300_000;
const MIN_BLOCK_LEN: usize = 10_000;
const OBS_INTERVAL: usize = 512;
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
    Params { depth, nice, lazy, good, max_insert }
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

/// Number of bytes equal to `b[pos - 1]` starting at `pos` (up to `end`).
fn run_length(b: &[u8], pos: usize, end: usize) -> usize {
    let byte = b[pos - 1];
    let pat = u64::from_ne_bytes([byte; 8]);
    let mut i = pos;
    while i + 8 <= end {
        // SAFETY: i + 8 <= end <= b.len().
        let x = unsafe { ld64(b, i) } ^ pat;
        if x != 0 {
            return i - pos + (x.trailing_zeros() >> 3) as usize;
        }
        i += 8;
    }
    while i < end && b[i] == byte {
        i += 1;
    }
    i - pos
}

// ---------------------------------------------------------------------------------------
// Huffman code construction
// ---------------------------------------------------------------------------------------

/// In-place minimum-redundancy code lengths (Moffat & Katajainen): `a` holds the symbol
/// weights sorted ascending (n >= 2) and is overwritten with their code lengths.
fn minimum_redundancy(a: &mut [u32]) {
    let n = a.len();
    debug_assert!(n >= 2);
    // Phase 1: build the tree; internal node weights, then parent pointers.
    a[0] += a[1];
    let mut root = 0usize;
    let mut leaf = 2usize;
    for next in 1..n - 1 {
        if leaf >= n || a[root] < a[leaf] {
            a[next] = a[root];
            a[root] = next as u32;
            root += 1;
        } else {
            a[next] = a[leaf];
            leaf += 1;
        }
        if leaf >= n || (root < next && a[root] < a[leaf]) {
            a[next] += a[root];
            a[root] = next as u32;
            root += 1;
        } else {
            a[next] += a[leaf];
            leaf += 1;
        }
    }
    // Phase 2: internal node depths.
    a[n - 2] = 0;
    for next in (0..n - 2).rev() {
        a[next] = a[a[next] as usize] + 1;
    }
    // Phase 3: leaf depths.
    let mut avail = 1usize;
    let mut used = 0usize;
    let mut depth = 0u32;
    let mut root = n as isize - 2;
    let mut next = n as isize - 1;
    while avail > 0 {
        while root >= 0 && a[root as usize] == depth {
            used += 1;
            root -= 1;
        }
        while avail > used {
            a[next as usize] = depth;
            next -= 1;
            avail -= 1;
        }
        avail = 2 * used;
        depth += 1;
        used = 0;
    }
}

/// Length-limited (`max_len` <= 15) Huffman code lengths for `freqs` (unused symbols get 0).
/// The code is always complete with at least two symbols (a dummy symbol is added if fewer
/// are used), which every inflater accepts.
fn huffman_lengths(freqs: &[u32], max_len: u32, lens: &mut [u8]) {
    let n = freqs.len();
    debug_assert!(n <= 320 && lens.len() >= n && n >= 2);
    lens[..n].fill(0);
    let mut keys = [0u64; 320];
    let mut cnt = 0;
    for (s, &f) in freqs.iter().enumerate() {
        if f != 0 {
            keys[cnt] = ((f as u64) << 16) | s as u64;
            cnt += 1;
        }
    }
    if cnt < 2 {
        let s = if cnt == 1 { (keys[0] & 0xFFFF) as usize } else { 0 };
        lens[s] = 1;
        lens[if s == 0 { 1 } else { 0 }] = 1;
        return;
    }
    let keys = &mut keys[..cnt];
    keys.sort_unstable();
    let mut a = [0u32; 320];
    for (x, k) in a.iter_mut().zip(keys.iter()) {
        *x = (k >> 16) as u32;
    }
    minimum_redundancy(&mut a[..cnt]);
    // Count leaves per length, clamping over-long codes, then repair the Kraft sum.
    let mut bl = [0u32; 16];
    for &d in &a[..cnt] {
        bl[d.min(max_len) as usize] += 1;
    }
    let mut total: u32 = 0;
    for l in 1..=max_len {
        total += bl[l as usize] << (max_len - l);
    }
    while total > 1 << max_len {
        bl[max_len as usize] -= 1;
        for l in (1..max_len as usize).rev() {
            if bl[l] != 0 {
                bl[l] -= 1;
                bl[l + 1] += 2;
                break;
            }
        }
        total -= 1;
    }
    // Most frequent symbols (end of `keys`) get the shortest codes.
    let mut i = cnt;
    for l in 1..=max_len as usize {
        for _ in 0..bl[l] {
            i -= 1;
            lens[(keys[i] & 0xFFFF) as usize] = l as u8;
        }
    }
}

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
        debug_assert!(self.pos + 8 <= self.buf.len() && self.count < 64);
        self.buf[self.pos..self.pos + 8].copy_from_slice(&self.bits.to_le_bytes());
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

/// Reusable DEFLATE compressor state (hash tables, token buffer). One per thread; about
/// 1 MiB of memory. Create with [`Compressor::new`] and call [`Compressor::compress`] any
/// number of times.
pub struct Compressor {
    level: u32,
    p: Params,
    shift4: u32,
    shift3: u32,
    head4: Vec<u32>,
    head3: Vec<u32>,
    prev: Vec<u16>,
    toks: Vec<u32>,
    lit_freq: [u32; 288],
    dist_freq: [u32; 32],
    obs: [u32; NUM_OBS],
    new_obs: [u32; NUM_OBS],
    num_obs: u32,
    num_new: u32,
    next_check: usize,
}

/// A literal is `byte`; a match is `(len << 16) | dist` (len >= 3, so `tok >> 16 != 0`).
#[inline(always)]
fn match_tok(len: usize, dist: usize) -> u32 {
    ((len as u32) << 16) | dist as u32
}

impl Compressor {
    /// A compressor for `level` (0 = stored only, 1 = fastest .. 9 = best; values above 9
    /// are treated as 9).
    pub fn new(level: u32) -> Compressor {
        let level = level.min(9);
        Compressor {
            level,
            p: params(level),
            shift4: 32 - HASH4_BITS,
            shift3: 32 - HASH3_BITS,
            head4: Vec::new(),
            head3: Vec::new(),
            prev: Vec::new(),
            toks: Vec::new(),
            lit_freq: [0; 288],
            dist_freq: [0; 32],
            obs: [0; NUM_OBS],
            new_obs: [0; NUM_OBS],
            num_obs: 0,
            num_new: 0,
            next_check: 0,
        }
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

    fn compress_segment(&mut self, buf: &[u8], start: usize, last: bool, bw: &mut BitWriter) {
        if self.level == 0 {
            write_stored(bw, &buf[start..], last);
            return;
        }
        self.reset(buf.len() - start);
        let end = buf.len();
        // Prime the hash tables with the dictionary.
        let dict_end = start.min(end.saturating_sub(MIN_LOOKAHEAD - 1));
        for p in 0..dict_end {
            // SAFETY: p + 4 <= end.
            unsafe { self.insert(buf, p) };
        }
        let mut pos = start;
        let mut block_start = start;
        self.begin_block();
        while pos < end {
            if self.toks.len() >= self.next_check && self.end_block_check(pos - block_start) {
                self.flush_block(bw, buf, block_start, pos, false);
                block_start = pos;
                self.begin_block();
            }
            pos = self.parse_step(buf, pos, end);
        }
        self.flush_block(bw, buf, block_start, end, last);
    }

    fn reset(&mut self, len: usize) {
        // Small inputs get small hash tables (cheap to clear).
        let need = (len.max(1) as u64 * 2).next_power_of_two().trailing_zeros();
        let b4 = need.clamp(10, HASH4_BITS);
        let b3 = need.clamp(10, HASH3_BITS);
        self.shift4 = 32 - b4;
        self.shift3 = 32 - b3;
        if self.head4.len() < 1 << b4 {
            self.head4.resize(1 << b4, SENTINEL);
        }
        if self.head3.len() < 1 << b3 {
            self.head3.resize(1 << b3, SENTINEL);
        }
        self.head4[..1 << b4].fill(SENTINEL);
        self.head3[..1 << b3].fill(SENTINEL);
        if self.prev.len() < WSIZE {
            self.prev.resize(WSIZE, 0);
        }
        if self.toks.capacity() < MAX_BLOCK_TOKENS {
            self.toks.reserve_exact(MAX_BLOCK_TOKENS - self.toks.len());
        }
    }

    #[inline(always)]
    fn hash4(&self, v: u32) -> usize {
        (v.wrapping_mul(0x1E35_A7BD) >> self.shift4) as usize
    }

    #[inline(always)]
    fn hash3(&self, v: u32) -> usize {
        ((v << 8).wrapping_mul(0x9E37_79B1) >> self.shift3) as usize
    }

    /// Inserts position `p` into the hash tables.
    ///
    /// # Safety
    /// `p + 4 <= buf.len()`.
    #[inline(always)]
    unsafe fn insert(&mut self, buf: &[u8], p: usize) {
        // SAFETY: caller guarantees p + 4 <= buf.len().
        let v = unsafe { ld32(buf, p) };
        let h4 = self.hash4(v);
        let h3 = self.hash3(v);
        // SAFETY: hash values are < 1 << bits <= table length; p & WMASK < WSIZE.
        unsafe {
            let old = *self.head4.get_unchecked(h4);
            *self.head4.get_unchecked_mut(h4) = p as u32;
            let d = (p as u32).wrapping_sub(old);
            *self.prev.get_unchecked_mut(p & WMASK) = if d <= WSIZE as u32 { d as u16 } else { 0 };
            *self.head3.get_unchecked_mut(h3) = p as u32;
        }
    }

    /// Inserts `pos` and searches for the longest match longer than `best_len` (hash-3
    /// candidate first when `best_len < 3`). Returns (len, dist); len <= best_len means none.
    ///
    /// # Safety
    /// `pos + max_len <= buf.len()` and `max_len >= MIN_LOOKAHEAD`.
    #[inline(always)]
    unsafe fn find(&mut self, buf: &[u8], pos: usize, max_len: usize, depth: u32, best_len: usize) -> (usize, usize) {
        debug_assert!(max_len >= MIN_LOOKAHEAD && pos + max_len <= buf.len());
        // SAFETY: pos + 4 <= buf.len().
        let cur = unsafe { ld32(buf, pos) };
        let h4 = self.hash4(cur);
        let h3 = self.hash3(cur);
        // SAFETY: hash values are < table length.
        let (cand4, cand3) = unsafe {
            let c4 = *self.head4.get_unchecked(h4);
            *self.head4.get_unchecked_mut(h4) = pos as u32;
            let d = (pos as u32).wrapping_sub(c4);
            *self.prev.get_unchecked_mut(pos & WMASK) = if d <= WSIZE as u32 { d as u16 } else { 0 };
            let c3 = *self.head3.get_unchecked(h3);
            *self.head3.get_unchecked_mut(h3) = pos as u32;
            (c4, c3)
        };
        let mut best = best_len;
        let mut best_dist = 0usize;
        if best < MIN_MATCH {
            let d3 = (pos as u32).wrapping_sub(cand3);
            // SAFETY: cand3 < pos, so cand3 + 4 <= pos + 3 < buf.len().
            if d3 != 0 && d3 <= MAX_DIST3 && (unsafe { ld32(buf, cand3 as usize) } ^ cur) & 0x00FF_FFFF == 0 {
                best = MIN_MATCH;
                best_dist = d3 as usize;
            }
        }
        // Chain candidates must beat `t` (>= 3: the chain finds 4-byte matches).
        let mut t = best.max(MIN_MATCH);
        if t >= max_len {
            return (best, best_dist);
        }
        let nice = self.p.nice.min(max_len);
        // SAFETY: t < max_len, so pos + t + 1 <= buf.len().
        let mut tail = unsafe { ld32(buf, pos + t - 3) };
        let mut cand = cand4;
        let mut depth = depth;
        loop {
            let dist = (pos as u32).wrapping_sub(cand);
            if dist.wrapping_sub(1) >= WSIZE as u32 {
                break;
            }
            let c = cand as usize;
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
            let d = unsafe { *self.prev.get_unchecked(c & WMASK) };
            if d == 0 {
                break;
            }
            cand = cand.wrapping_sub(d as u32);
        }
        (best, best_dist)
    }

    #[inline(always)]
    fn lit(&mut self, b: u8) {
        self.toks.push(b as u32);
        self.lit_freq[b as usize] += 1;
        self.new_obs[(b >> 5) as usize] += 1;
        self.num_new += 1;
    }

    #[inline(always)]
    fn mat(&mut self, len: usize, dist: usize) {
        self.toks.push(match_tok(len, dist));
        self.lit_freq[257 + LEN_SLOT[len] as usize] += 1;
        self.dist_freq[dist_slot(dist)] += 1;
        self.new_obs[8 + (len >= 9) as usize] += 1;
        self.num_new += 1;
    }

    /// Emits the tokens for the input at `pos` (a literal, a match, or an RLE run) and
    /// returns the next position to process.
    #[inline(always)]
    fn parse_step(&mut self, buf: &[u8], pos: usize, end: usize) -> usize {
        let rem = end - pos;
        if rem < MIN_LOOKAHEAD {
            self.lit(buf[pos]);
            return pos + 1;
        }
        // RLE fast path: at least 258 more copies of the previous byte.
        if pos > 0 && rem >= MAX_MATCH && buf[pos] == buf[pos - 1] {
            let pat = u64::from_ne_bytes([buf[pos - 1]; 8]);
            // SAFETY: pos + 258 <= end.
            if unsafe { ld64(buf, pos) == pat && ld64(buf, pos + MAX_MATCH - 8) == pat } {
                let r = run_length(buf, pos, end);
                let room = MAX_BLOCK_TOKENS - TOKEN_SLACK - self.toks.len().min(MAX_BLOCK_TOKENS - TOKEN_SLACK);
                let n = (r / MAX_MATCH).min(room.max(1));
                if n == 0 {
                    return self.parse_match(buf, pos, end);
                }
                for _ in 0..n {
                    self.mat(MAX_MATCH, 1);
                }
                let run_end = pos + n * MAX_MATCH;
                // Only the last positions of the run need to be findable later.
                let from = run_end - MIN_LOOKAHEAD;
                for q in from..run_end.min(end - (MIN_LOOKAHEAD - 1)) {
                    // SAFETY: q + 4 <= end.
                    unsafe { self.insert(buf, q) };
                }
                return run_end;
            }
        }
        self.parse_match(buf, pos, end)
    }

    /// LZ77 step at `pos` (at least MIN_LOOKAHEAD bytes left): literal or (lazy) match.
    #[inline(always)]
    fn parse_match(&mut self, buf: &[u8], mut pos: usize, end: usize) -> usize {
        let rem = end - pos;
        let p = self.p;
        let max_len = rem.min(MAX_MATCH);
        // SAFETY: pos + max_len <= end, max_len >= 4.
        let (mut len, mut dist) = unsafe { self.find(buf, pos, max_len, p.depth, MIN_MATCH - 1) };
        if len < MIN_MATCH {
            self.lit(buf[pos]);
            return pos + 1;
        }
        let mut cur = pos;
        pos += 1;
        if p.lazy > 0 {
            loop {
                if len >= p.nice || end - pos < MIN_LOOKAHEAD {
                    break;
                }
                let depth = if len >= p.good { (p.depth >> 2).max(1) } else { p.depth };
                let ml = (end - pos).min(MAX_MATCH);
                // SAFETY: pos + ml <= end, ml >= 4.
                let (l2, d2) = unsafe { self.find(buf, pos, ml, depth, len) };
                if l2 > len && better(l2, d2, len, dist, 2) {
                    self.lit(buf[cur]);
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
                    let (l3, d3) = unsafe { self.find(buf, pos, ml, depth, len) };
                    if l3 > len && better(l3, d3, len, dist, 6) {
                        self.lit(buf[cur]);
                        self.lit(buf[cur + 1]);
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
        self.mat(len, dist);
        let mend = cur + len;
        let ins_end = mend.min(end - (MIN_LOOKAHEAD - 1));
        if len <= p.max_insert {
            while pos < ins_end {
                // SAFETY: pos + 4 <= end.
                unsafe { self.insert(buf, pos) };
                pos += 1;
            }
        } else {
            // Long match: only the first and last few positions.
            let a = (pos + 8).min(ins_end);
            while pos < a {
                // SAFETY: pos + 4 <= end.
                unsafe { self.insert(buf, pos) };
                pos += 1;
            }
            pos = pos.max(ins_end.saturating_sub(8));
            while pos < ins_end {
                // SAFETY: pos + 4 <= end.
                unsafe { self.insert(buf, pos) };
                pos += 1;
            }
        }
        mend
    }

    fn begin_block(&mut self) {
        self.toks.clear();
        self.lit_freq = [0; 288];
        self.dist_freq = [0; 32];
        self.obs = [0; NUM_OBS];
        self.new_obs = [0; NUM_OBS];
        self.num_obs = 0;
        self.num_new = 0;
        self.next_check = OBS_INTERVAL;
    }

    /// Called every OBS_INTERVAL tokens: should the block end here?
    fn end_block_check(&mut self, block_len: usize) -> bool {
        if self.toks.len() >= MAX_BLOCK_TOKENS - TOKEN_SLACK || block_len >= SOFT_MAX_BLOCK_LEN {
            return true;
        }
        self.next_check = (self.toks.len() + OBS_INTERVAL).min(MAX_BLOCK_TOKENS - TOKEN_SLACK);
        let (n_old, n_new) = (self.num_obs as u64, self.num_new as u64);
        if n_old > 0 && block_len >= MIN_BLOCK_LEN {
            // L1 distance between the token-class distributions of the block so far and of
            // the latest tokens; long blocks split more readily.
            let mut delta = 0u64;
            for i in 0..NUM_OBS {
                delta += (self.new_obs[i] as u64 * n_old).abs_diff(self.obs[i] as u64 * n_new);
            }
            let cutoff = n_new * n_old * 200 / 512;
            if delta + (block_len as u64 / 4096) * n_old >= cutoff {
                return true;
            }
        }
        for i in 0..NUM_OBS {
            self.obs[i] += self.new_obs[i];
            self.new_obs[i] = 0;
        }
        self.num_obs += self.num_new;
        self.num_new = 0;
        false
    }

    /// Writes the tokens of `buf[bstart..bend]` as the cheapest block type.
    fn flush_block(&mut self, bw: &mut BitWriter, buf: &[u8], bstart: usize, bend: usize, last: bool) {
        self.lit_freq[256] = 1;
        let mut llens = [0u8; 288];
        let mut dlens = [0u8; 32];
        huffman_lengths(&self.lit_freq[..286], 15, &mut llens);
        huffman_lengths(&self.dist_freq[..30], 15, &mut dlens);
        let hdr = DynHeader::new(&llens, &dlens);

        let mut extra = 0u64;
        for i in 0..29 {
            extra += self.lit_freq[257 + i] as u64 * LEN_EXTRA[i] as u64;
        }
        for i in 0..30 {
            extra += self.dist_freq[i] as u64 * DIST_EXTRA[i] as u64;
        }
        let fixed_l = fixed_litlen_lens();
        let mut dyn_cost = 3 + hdr.cost + extra;
        let mut fixed_cost = 3 + extra;
        for s in 0..286 {
            let f = self.lit_freq[s] as u64;
            dyn_cost += f * llens[s] as u64;
            fixed_cost += f * fixed_l[s] as u64;
        }
        for s in 0..30 {
            let f = self.dist_freq[s] as u64;
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
            write_tokens(bw, &self.toks, &llens, &lcodes, &dlens, &dcodes);
        } else {
            let dl = [5u8; 32];
            canonical_codes(&fixed_l, &mut lcodes);
            canonical_codes(&dl, &mut dcodes);
            bw.put(last as u64 | (1 << 1), 3);
            write_tokens(bw, &self.toks, &fixed_l, &lcodes, &dl, &dcodes);
        }
    }
}

/// `better(new, old)`: is a match of `l2` at `d2` (starting one or two bytes later, after
/// literals) worth more than `l1` at `d1`? Length gains dominate; distance costs log2 bits.
#[inline(always)]
fn better(l2: usize, d2: usize, l1: usize, d1: usize, bias: i32) -> bool {
    let lg = |d: usize| 31 - (d as u32).leading_zeros() as i32;
    4 * (l2 as i32 - l1 as i32) + lg(d1) - lg(d2) > bias
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

/// Emits the block's tokens and the end-of-block code.
fn write_tokens(bw: &mut BitWriter, toks: &[u32], llens: &[u8; 288], lcodes: &[u16; 288], dlens: &[u8; 32], dcodes: &[u16; 32]) {
    // Length code + extra bits, merged per length.
    let mut lenc = [(0u32, 0u32); 259];
    for (len, e) in lenc.iter_mut().enumerate().skip(3) {
        let s = LEN_SLOT[len] as usize;
        let sym = 257 + s;
        let nb = llens[sym] as u32;
        *e = (lcodes[sym] as u32 | ((len as u32 - LEN_BASE[s] as u32) << nb), nb + LEN_EXTRA[s] as u32);
    }
    let mut lit = [(0u32, 0u32); 256];
    for (b, e) in lit.iter_mut().enumerate() {
        *e = (lcodes[b] as u32, llens[b] as u32);
    }
    for &t in toks {
        if t < 256 {
            let (c, n) = lit[t as usize];
            bw.put(c as u64, n);
        } else {
            let len = (t >> 16) as usize;
            let dist = (t & 0xFFFF) as usize;
            let (c, n) = lenc[len];
            bw.put(c as u64, n);
            let s = dist_slot(dist);
            let nb = dlens[s] as u32;
            let v = dcodes[s] as u64 | (((dist - DIST_BASE[s] as usize) as u64) << nb);
            bw.put(v, nb + DIST_EXTRA[s] as u32);
        }
        bw.flush();
    }
    bw.put(lcodes[256] as u64, llens[256] as u32);
    bw.flush();
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
    fn codecs_deflate_enc_huffman_lengths() {
        // Skewed (Fibonacci) frequencies force the length limit.
        let mut f = [0u32; 40];
        let (mut a, mut b) = (1u32, 1u32);
        for x in f.iter_mut() {
            *x = a;
            let c = a.saturating_add(b);
            a = b;
            b = c;
        }
        for max in [7u32, 9, 15] {
            let mut lens = [0u8; 40];
            huffman_lengths(&f, max, &mut lens);
            let kraft: f64 = lens.iter().filter(|&&l| l > 0).map(|&l| 0.5f64.powi(l as i32)).sum();
            assert!((kraft - 1.0).abs() < 1e-12, "max {max}: kraft {kraft}");
            assert!(lens.iter().all(|&l| l >= 1 && l as u32 <= max));
        }
        let mut lens = [0u8; 4];
        huffman_lengths(&[0, 0, 5, 0], 15, &mut lens);
        assert_eq!(lens.iter().filter(|&&l| l == 1).count(), 2);
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
