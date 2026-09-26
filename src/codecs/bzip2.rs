//! bzip2 decoder (multiple streams, CRC verification).
//!
//! Semantics follow python's `bz2.decompress`: every concatenated stream is decoded, invalid
//! data after a complete stream is ignored, running out of data before an end-of-stream
//! marker is an error. Randomised blocks (a bzip2 0.9.0 feature no encoder has produced since
//! 0.9.5) are rejected.
//!
//! Per block:
//! 1. Entropy decoding: table-driven Huffman (MSB-first 64-bit bit buffer, 10-bit primary
//!    tables) and MTF / RUNA-RUNB decoding into `ll8`, the BWT's last column (one byte per
//!    symbol).
//! 2. Scatter: `tt[j] = (psi(j) << 8) | F[j]`, where F is the sorted (first) column and psi
//!    the inverse LF mapping. Storing F[j], which is just the bucket's byte, instead of L[j]
//!    turns libbz2's read-modify-write `tt[cftab[L[i]]++] |= i << 8` into a pure store; the
//!    output sequence F[orig], F[psi(orig)], F[psi(psi(orig))], ... is the same.
//! 3. Inverse BWT: following psi is a chain of dependent loads over up to 3.6 MB, i.e. purely
//!    latency-bound. The permutation is cut into segments at marked entries (bit 31) and
//!    `LANES` independent walkers follow different segments at the same time (memory-level
//!    parallelism), each writing into its own column; the segments are then stitched together
//!    in chain order. Periodic blocks (psi with several cycles) repeat the cycle through
//!    `orig`, exactly like following the chain n times.
//! 4. RLE1 decoding (SSE2 scan for 4-byte runs) straight into the output, then the block CRC.

use super::crc::crc32_bzip2;
use crate::error::{Error, Result};

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const END_MAGIC: u64 = 0x1772_4538_5090;
const MAX_GROUPS: usize = 6;
const MAX_ALPHA: usize = 258;
const MAX_SELECTORS: usize = 18002;
const MAX_CODE_LEN: u32 = 20;
const LOOKUP_BITS: u32 = 10;
/// Largest block (level 9): indices fit in 20 bits, so a `tt` entry is
/// `mark(1) | unused(3) | index(20) | byte(8)`.
const MAX_BLOCK: usize = 900_000;
/// Slack after buffers written with over-writing 16-byte stores.
const PAD: usize = 64;
/// Segment start marker in `tt` entries.
const MARK: u32 = 1 << 31;
/// Concurrent inverse-BWT walkers.
const LANES: usize = 16;
/// Column stride of the walkers' output (one column per lane).
const COL: usize = MAX_BLOCK + PAD;
/// Blocks shorter than this use a single walker.
const LANES_MIN: usize = 16 * 1024;
/// Average segment length (the permutation is cut into n / SEG_LEN segments).
const SEG_LEN: usize = 512;

fn corrupt(what: &str) -> Error {
    Error::Msg(format!("bzip2: corrupt data ({what})"))
}

fn alloc_error() -> Error {
    Error::Msg("bzip2: out of memory".into())
}

/// Why decoding a stream failed (python ignores corrupt data after the first stream but
/// reports truncation).
enum Fail {
    Truncated,
    Corrupt(Error),
}

impl From<Error> for Fail {
    fn from(e: Error) -> Fail {
        Fail::Corrupt(e)
    }
}

/// MSB-first bit reader.
#[derive(Clone, Copy)]
struct BitReader<'a> {
    data: &'a [u8],
    /// Valid bits are the top `count` bits of `buf`; bits below are the true next input bits
    /// or zero.
    buf: u64,
    count: u32,
    /// Next byte to load.
    ip: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8], ip: usize) -> Self {
        BitReader { data, buf: 0, count: 0, ip }
    }

    /// Tops the buffer up to at least 56 valid bits (zeros past the end of the input).
    #[inline(always)]
    fn refill(&mut self) {
        if self.ip + 8 <= self.data.len() {
            // SAFETY: ip + 8 <= len.
            let w = u64::from_be_bytes(unsafe { (self.data.as_ptr().add(self.ip) as *const [u8; 8]).read_unaligned() });
            self.buf |= w >> self.count;
            self.ip += ((63 - self.count) >> 3) as usize;
            self.count |= 56;
        } else {
            self.refill_tail();
        }
    }

    #[inline(never)]
    fn refill_tail(&mut self) {
        while self.count <= 56 {
            let b = self.data.get(self.ip).copied().unwrap_or(0);
            self.buf |= (b as u64) << (56 - self.count);
            self.ip += 1;
            self.count += 8;
        }
    }

    /// Bits consumed since the start of the input.
    #[inline(always)]
    fn position_bits(&self) -> usize {
        self.ip * 8 - self.count as usize
    }

    #[inline(always)]
    fn overrun(&self) -> bool {
        self.position_bits() > self.data.len() * 8
    }

    /// Classifies an error: anything detected after reading past the end of the input is
    /// truncation (libbz2 would still be waiting for more data).
    fn fail(&self, e: Error) -> Fail {
        if self.overrun() { Fail::Truncated } else { Fail::Corrupt(e) }
    }

    #[inline(always)]
    fn bits(&mut self, n: u32) -> u32 {
        debug_assert!(n > 0 && n <= 32);
        if self.count < n {
            self.refill();
        }
        let v = (self.buf >> (64 - n)) as u32;
        self.buf <<= n;
        self.count -= n;
        v
    }

    #[inline(always)]
    fn bit(&mut self) -> bool {
        self.bits(1) != 0
    }

    /// Skips to the next byte boundary; returns the byte offset.
    fn byte_align(&mut self) -> usize {
        let pos = self.position_bits().div_ceil(8);
        self.ip = pos;
        self.buf = 0;
        self.count = 0;
        pos
    }
}

/// Canonical Huffman decoder for one coding table.
struct HuffTable {
    /// Top LOOKUP_BITS bits -> (symbol << 5) | length; length 0 = longer code.
    lookup: [u16; 1 << LOOKUP_BITS],
    /// For lengths > LOOKUP_BITS: first code, count and offset into `sorted` per length.
    first: [u32; 21],
    count: [u32; 21],
    offset: [u32; 21],
    sorted: [u16; MAX_ALPHA],
    max_len: u32,
}

impl HuffTable {
    fn new() -> HuffTable {
        HuffTable {
            lookup: [0; 1 << LOOKUP_BITS],
            first: [0; 21],
            count: [0; 21],
            offset: [0; 21],
            sorted: [0; MAX_ALPHA],
            max_len: 0,
        }
    }

    fn build(&mut self, lens: &[u8]) -> Result<()> {
        self.count = [0; 21];
        for &l in lens {
            self.count[l as usize] += 1;
        }
        self.max_len = (1..=20).rev().find(|&l| self.count[l] != 0).unwrap_or(0) as u32;
        // Canonical codes: shorter first, then by symbol.
        let mut code = 0u32;
        let mut off = 0u32;
        for l in 1..=20 {
            self.first[l] = code;
            self.offset[l] = off;
            code = (code + self.count[l]) << 1;
            off += self.count[l];
        }
        let mut next = self.offset;
        for (sym, &l) in lens.iter().enumerate() {
            let l = l as usize;
            self.sorted[next[l] as usize] = sym as u16;
            next[l] += 1;
        }
        // Primary lookup table.
        self.lookup = [0; 1 << LOOKUP_BITS];
        for l in 1..=LOOKUP_BITS.min(self.max_len) as usize {
            for k in 0..self.count[l] {
                let c = self.first[l] + k;
                let sym = self.sorted[(self.offset[l] + k) as usize];
                let shift = LOOKUP_BITS - l as u32;
                let lo = (c << shift) as usize;
                let hi = ((c + 1) << shift) as usize;
                if hi > self.lookup.len() {
                    return Err(corrupt("over-subscribed Huffman code"));
                }
                let e = (sym << 5) | l as u16;
                self.lookup[lo..hi].fill(e);
            }
        }
        Ok(())
    }

    /// Decodes a code longer than LOOKUP_BITS (the buffer holds at least MAX_CODE_LEN bits).
    #[inline(never)]
    fn decode_long(&self, br: &mut BitReader) -> Option<u32> {
        for l in LOOKUP_BITS + 1..=self.max_len {
            let v = (br.buf >> (64 - l)) as u32;
            let d = v.wrapping_sub(self.first[l as usize]);
            if d < self.count[l as usize] {
                br.buf <<= l;
                br.count -= l;
                return Some(self.sorted[(self.offset[l as usize] + d) as usize] as u32);
            }
        }
        None
    }
}

/// Entropy-decoded block parameters (the symbols themselves are in `Scratch::ll8`).
struct BlockInfo {
    n: usize,
    orig_ptr: usize,
    crc: u32,
    counts: [u32; 256],
    /// Symbols produced by RUNA/RUNB runs (repeats of the preceding byte).
    run_total: usize,
}

/// Segment bookkeeping of the multi-lane inverse BWT.
struct Segs {
    /// Per segment: lane, first and end round in that lane's column, following segment.
    lane: Vec<u8>,
    r0: Vec<u32>,
    r1: Vec<u32>,
    next: Vec<u32>,
    /// Original `tt` entry at each segment start (the slot holds `MARK | segment`).
    first: Vec<u32>,
    /// Segment each lane is walking.
    cur: [u32; LANES],
    nseg: usize,
    step: usize,
    orig: usize,
    n: usize,
    /// Rounds of the last walk (statistics).
    rounds: usize,
}

impl Segs {
    /// Index of the first entry of segment `j`.
    #[inline(always)]
    fn start(&self, j: usize) -> usize {
        let s = self.orig + j * self.step;
        if s >= self.n { s - self.n } else { s }
    }
}

/// Reusable per-decoder buffers.
struct Scratch {
    tables: Vec<HuffTable>,
    selectors: Vec<u8>,
    /// MTF output (BWT last column); capacity MAX_BLOCK + PAD.
    ll8: Vec<u8>,
    /// Inverse BWT vector (+1 sentinel entry); capacity MAX_BLOCK + 1.
    tt: HugeBuf<u32>,
    /// Lane columns; capacity LANES * COL (only the walked prefix is ever touched).
    cols: Vec<u8>,
    /// Pre-RLE1 bytes in output order; capacity MAX_BLOCK + PAD.
    pre: Vec<u8>,
    segs: Segs,
    /// Histogram snapshots of `ll8[..snap_pos[k]]`, taken during entropy decoding every
    /// max_block / SNAPS symbols (they let the scatter run several independent streams).
    snap_pos: Vec<usize>,
    snap_counts: Vec<[u32; 256]>,
}

/// Histogram snapshots per (full) block.
const SNAPS: usize = 32;
/// Independent scatter streams.
const STREAMS: usize = 4;

/// Uninitialised scratch memory, 2 MiB aligned and advised for transparent huge pages (the
/// inverse BWT makes random accesses over `tt`; with 4 KiB pages most of them miss the TLB).
struct HugeBuf<T> {
    ptr: *mut T,
    layout: std::alloc::Layout,
}

// SAFETY: plain owned memory.
unsafe impl<T: Send> Send for HugeBuf<T> {}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn madvise(addr: *mut u8, len: usize, advice: i32) -> i32;
}

impl<T> HugeBuf<T> {
    const ALIGN: usize = 2 << 20;

    fn new(len: usize) -> Result<Self> {
        let size = (len.max(1) * std::mem::size_of::<T>()).next_multiple_of(Self::ALIGN);
        let layout = std::alloc::Layout::from_size_align(size, Self::ALIGN).map_err(|_| alloc_error())?;
        // SAFETY: non-zero size.
        let ptr = unsafe { std::alloc::alloc(layout) } as *mut T;
        if ptr.is_null() {
            return Err(alloc_error());
        }
        #[cfg(target_os = "linux")]
        // SAFETY: advisory only, on our own allocation (MADV_HUGEPAGE = 14).
        unsafe {
            madvise(ptr as *mut u8, size, 14);
        }
        Ok(HugeBuf { ptr, layout })
    }

    fn as_ptr(&self) -> *const T {
        self.ptr
    }

    fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr
    }
}

impl<T> Drop for HugeBuf<T> {
    fn drop(&mut self) {
        // SAFETY: allocated in `new` with this layout.
        unsafe { std::alloc::dealloc(self.ptr as *mut u8, self.layout) };
    }
}

fn try_vec<T>(cap: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(cap).map_err(|_| alloc_error())?;
    Ok(v)
}

impl Scratch {
    fn new() -> Result<Scratch> {
        Ok(Scratch {
            tables: (0..MAX_GROUPS).map(|_| HuffTable::new()).collect(),
            selectors: Vec::with_capacity(MAX_SELECTORS),
            ll8: try_vec(MAX_BLOCK + PAD)?,
            tt: HugeBuf::new(MAX_BLOCK + 1)?,
            cols: Vec::new(),
            pre: try_vec(MAX_BLOCK + PAD)?,
            segs: Segs {
                lane: Vec::new(),
                r0: Vec::new(),
                r1: Vec::new(),
                next: Vec::new(),
                first: Vec::new(),
                cur: [0; LANES],
                nseg: 0,
                step: 1,
                orig: 0,
                n: 0,
                rounds: 0,
            },
            snap_pos: Vec::with_capacity(SNAPS + 1),
            snap_counts: Vec::with_capacity(SNAPS + 1),
        })
    }

    /// Decodes one block (after its magic), appending its output to `out`; returns the
    /// block CRC.
    fn block(&mut self, br: &mut BitReader, max_block: usize, out: &mut Vec<u8>) -> std::result::Result<u32, Fail> {
        let info = self.entropy(br, max_block)?;
        self.finish(&info, out)?;
        Ok(info.crc)
    }

    /// Huffman + MTF/RUNA-RUNB decoding of one block into `ll8`.
    fn entropy(&mut self, br: &mut BitReader, max_block: usize) -> std::result::Result<BlockInfo, Fail> {
        let crc = br.bits(32);
        if br.bit() {
            return Err(br.fail(Error::Msg("bzip2: randomised blocks are not supported".into())));
        }
        let orig_ptr = br.bits(24) as usize;
        // Symbol map.
        let used16 = br.bits(16);
        let mut seq_to_unseq = [0u8; 256];
        let mut n_in_use = 0usize;
        for i in 0..16 {
            if used16 & (0x8000 >> i) != 0 {
                let bits = br.bits(16);
                for j in 0..16 {
                    if bits & (0x8000 >> j) != 0 {
                        seq_to_unseq[n_in_use] = (i * 16 + j) as u8;
                        n_in_use += 1;
                    }
                }
            }
        }
        if n_in_use == 0 {
            return Err(br.fail(corrupt("no symbols in use")));
        }
        let alpha = n_in_use + 2;
        let n_groups = br.bits(3) as usize;
        if !(2..=MAX_GROUPS).contains(&n_groups) {
            return Err(br.fail(corrupt("number of Huffman groups")));
        }
        let n_selectors = br.bits(15) as usize;
        if n_selectors == 0 {
            return Err(br.fail(corrupt("no selectors")));
        }
        // Selectors (MTF coded, unary). Values at MTF positions < n_groups stay < n_groups.
        let mut mtf_groups = [0u8, 1, 2, 3, 4, 5];
        self.selectors.clear();
        for i in 0..n_selectors {
            let mut j = 0usize;
            while br.bit() {
                j += 1;
                if j >= n_groups {
                    return Err(br.fail(corrupt("selector out of range")));
                }
            }
            if i < MAX_SELECTORS {
                let v = mtf_groups[j];
                mtf_groups.copy_within(0..j, 1);
                mtf_groups[0] = v;
                self.selectors.push(v);
            }
        }
        if br.overrun() {
            return Err(Fail::Truncated);
        }
        // Coding tables (delta-coded lengths).
        let mut lens = [0u8; MAX_ALPHA];
        for t in 0..n_groups {
            let mut curr = br.bits(5) as i32;
            for l in lens.iter_mut().take(alpha) {
                loop {
                    if !(1..=MAX_CODE_LEN as i32).contains(&curr) {
                        return Err(br.fail(corrupt("code length")));
                    }
                    if !br.bit() {
                        break;
                    }
                    if br.bit() {
                        curr -= 1;
                    } else {
                        curr += 1;
                    }
                }
                *l = curr as u8;
            }
            if br.overrun() {
                return Err(Fail::Truncated);
            }
            if let Err(e) = self.tables[t].build(&lens[..alpha]) {
                return Err(br.fail(e));
            }
        }

        // MTF / RUNA-RUNB decoding. The MTF list holds the byte values themselves.
        let eob = (n_in_use + 1) as u32;
        let mut mtf = MtfList([0u8; 256]);
        mtf.0[..n_in_use].copy_from_slice(&seq_to_unseq[..n_in_use]);
        let mut counts = [0u32; 256];
        let ll = self.ll8.as_mut_ptr();
        debug_assert!(self.ll8.capacity() >= MAX_BLOCK + PAD && max_block <= MAX_BLOCK);
        let mut pos = 0usize;
        let mut sel = 0usize;
        let mut run = 0usize;
        let mut run_bit = 0u32;
        let mut run_total = 0usize;
        let mut b = *br;
        self.snap_pos.clear();
        self.snap_counts.clear();
        let snap_every = (max_block / SNAPS).max(1);
        let mut snap_next = snap_every;
        macro_rules! snapshot {
            () => {
                if pos >= snap_next {
                    self.snap_pos.push(pos);
                    self.snap_counts.push(counts);
                    snap_next = pos + snap_every;
                }
            };
        }
        macro_rules! bail {
            ($what:expr) => {{
                *br = b;
                return Err(br.fail(corrupt($what)));
            }};
        }
        'block: loop {
            let Some(&s) = self.selectors.get(sel) else { bail!("ran out of selectors") };
            sel += 1;
            let tbl = &self.tables[s as usize];
            for _ in 0..50 {
                if b.count < MAX_CODE_LEN {
                    b.refill();
                }
                let e = tbl.lookup[(b.buf >> (64 - LOOKUP_BITS)) as usize];
                let l = (e & 31) as u32;
                let sym = if l != 0 {
                    b.buf <<= l;
                    b.count -= l;
                    (e >> 5) as u32
                } else {
                    match tbl.decode_long(&mut b) {
                        Some(s) => s,
                        None => bail!("invalid Huffman code"),
                    }
                };
                if sym <= 1 {
                    // RUNA / RUNB: bijective base-2 run length of the front symbol.
                    if run_bit > 21 {
                        bail!("run too long");
                    }
                    run += ((sym + 1) as usize) << run_bit;
                    run_bit += 1;
                    continue;
                }
                if run > 0 {
                    if pos + run > max_block {
                        bail!("block overflow");
                    }
                    let v = mtf.0[0];
                    counts[v as usize] += run as u32;
                    // SAFETY: pos + run <= MAX_BLOCK; the fill over-writes < 16 bytes into PAD.
                    unsafe { fill16(ll.add(pos), v, run) };
                    pos += run;
                    run_total += run;
                    run = 0;
                    run_bit = 0;
                    snapshot!();
                }
                if sym == eob {
                    break 'block;
                }
                // sym < eob: MTF index 1..n_in_use-1.
                let v = mtf_move(&mut mtf, (sym - 1) as usize);
                if pos >= max_block {
                    bail!("block overflow");
                }
                counts[v as usize] += 1;
                // SAFETY: pos < max_block <= capacity.
                unsafe { *ll.add(pos) = v };
                pos += 1;
                snapshot!();
            }
        }
        *br = b;
        if br.overrun() {
            return Err(Fail::Truncated);
        }
        if orig_ptr >= pos {
            return Err(corrupt("original pointer out of range").into());
        }
        Ok(BlockInfo { n: pos, orig_ptr, crc, counts, run_total })
    }

    /// Inverse BWT + RLE1 of the block in `ll8`, appended to `out`; checks the block CRC.
    fn finish(&mut self, info: &BlockInfo, out: &mut Vec<u8>) -> Result<()> {
        let n = info.n;
        debug_assert!(n >= 1 && n <= MAX_BLOCK && info.orig_ptr < n);
        // SAFETY: ll8 holds n decoded bytes whose histogram is `counts` (so every tt slot
        // below n is written exactly once with an index < n); buffer capacities are fixed at
        // construction (tt: MAX_BLOCK + 1, pre: MAX_BLOCK + PAD).
        unsafe {
            scatter(self.ll8.as_ptr(), n, info, &self.snap_pos, &self.snap_counts, self.tt.as_mut_ptr());
            if n < LANES_MIN {
                walk_single(self.tt.as_ptr(), n, info.orig_ptr, self.pre.as_mut_ptr());
            } else {
                if self.cols.capacity() < LANES * COL {
                    self.cols.try_reserve_exact(LANES * COL).map_err(|_| alloc_error())?;
                }
                walk_lanes(self.tt.as_mut_ptr(), n, info.orig_ptr, self.cols.as_mut_ptr(), self.pre.as_mut_ptr(), &mut self.segs)?;
            }
            let start = out.len();
            unrle(std::slice::from_raw_parts(self.pre.as_ptr(), n), out)?;
            if crc32_bzip2(&out[start..]) != info.crc {
                return Err(corrupt("block CRC mismatch"));
            }
        }
        Ok(())
    }
}

/// The MTF list, 32-byte aligned for the vector moves.
#[repr(C, align(32))]
struct MtfList([u8; 256]);

/// Moves `mtf[idx]` (idx >= 1) to the front; returns it.
///
/// AVX2: every 32-byte chunk at or below `idx` becomes the chunk shifted up by one byte
/// (carrying in the previous chunk's last byte, or `v` for chunk 0), blended with the
/// original above `idx`. Indices below 32 touch one chunk; larger ones process all eight
/// chunks without branches (random data has uniformly spread indices, so a data-dependent
/// loop length would mispredict on nearly every symbol).
#[cfg(target_feature = "avx2")]
#[inline(always)]
fn mtf_move(mtf: &mut MtfList, idx: usize) -> u8 {
    use std::arch::x86_64::*;
    let idx = idx & 255;
    let v = mtf.0[idx];
    // SAFETY: AVX2 is enabled at compile time; all accesses are within the aligned 256 bytes.
    unsafe {
        let p = mtf.0.as_mut_ptr() as *mut __m256i;
        // Byte j of chunk c is position 32c + j; biased by 0x80 for a signed compare.
        let pos0 = _mm256_setr_epi8(
            -128, -127, -126, -125, -124, -123, -122, -121, -120, -119, -118, -117, -116, -115, -114, -113, -112,
            -111, -110, -109, -108, -107, -106, -105, -104, -103, -102, -101, -100, -99, -98, -97,
        );
        let lim = _mm256_set1_epi8((idx as u8 ^ 0x80) as i8);
        let mut prev = _mm256_set1_epi8(v as i8);
        macro_rules! chunk {
            ($c:expr) => {{
                let old = _mm256_load_si256(p.add($c));
                let t = _mm256_permute2x128_si256(old, prev, 0x03);
                let shifted = _mm256_alignr_epi8(old, t, 15);
                let pos = _mm256_add_epi8(pos0, _mm256_set1_epi8((32 * $c) as i8));
                // keep = position > idx
                let keep = _mm256_cmpgt_epi8(pos, lim);
                _mm256_store_si256(p.add($c), _mm256_blendv_epi8(shifted, old, keep));
                #[allow(unused_assignments)]
                {
                    prev = old;
                }
            }};
        }
        chunk!(0);
        if idx >= 32 {
            chunk!(1);
            chunk!(2);
            chunk!(3);
            chunk!(4);
            chunk!(5);
            chunk!(6);
            chunk!(7);
        }
    }
    v
}

/// Moves `mtf[idx]` (idx >= 1) to the front; returns it.
#[cfg(not(target_feature = "avx2"))]
#[inline(always)]
fn mtf_move(mtf: &mut MtfList, idx: usize) -> u8 {
    let mtf = &mut mtf.0;
    let v = mtf[idx & 255];
    if idx < 16 {
        let w = u128::from_le_bytes(mtf[..16].try_into().unwrap());
        let below = (1u128 << (8 * idx)) - 1; // bytes < idx
        let above = !((below << 8) | 0xFF); // bytes > idx
        let nw = (w & above) | ((w & below) << 8) | v as u128;
        mtf[..16].copy_from_slice(&nw.to_le_bytes());
    } else {
        let idx = idx & 255;
        mtf.copy_within(0..idx, 1);
        mtf[0] = v;
    }
    v
}

/// Writes `c` copies of `x` at `p`, possibly over-writing up to 15 bytes past `p + c`.
///
/// # Safety
/// `p .. p + c + 15` must be writable.
#[inline(always)]
unsafe fn fill16(p: *mut u8, x: u8, c: usize) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        use std::arch::x86_64::*;
        let v = _mm_set1_epi8(x as i8);
        let mut k = 0;
        while k < c {
            _mm_storeu_si128(p.add(k) as *mut __m128i, v);
            k += 16;
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    unsafe {
        std::ptr::write_bytes(p, x, c);
    }
}

/// `tt[cf[L[i]]++] = (i << 8) | L[i]` for i in 0..n, where cf starts at the bucket starts.
///
/// A single pass is bound by store-to-load forwarding on `cf[b]` whenever bytes repeat
/// (runs are common in BWT output of text), so run-heavy blocks are cut into STREAMS pieces
/// at histogram snapshots and the pieces are scattered in lock-step, each with its own `cf`
/// table. Run-poor blocks use one stream: several streams multiply the number of write
/// positions (256 per stream, each in its own cache line) and thrash L1.
///
/// # Safety
/// `ll8[..n]` readable with histogram `counts`; `snaps` are exact histograms of
/// `ll8[..pos]` at increasing positions; `tt[..n]` writable.
unsafe fn scatter(ll8: *const u8, n: usize, info: &BlockInfo, snap_pos: &[usize], snap_counts: &[[u32; 256]], tt: *mut u32) {
    unsafe {
        if info.run_total * 4 >= n {
            scatter_n::<STREAMS>(ll8, n, &info.counts, snap_pos, snap_counts, tt)
        } else {
            scatter_n::<1>(ll8, n, &info.counts, snap_pos, snap_counts, tt)
        }
    }
}

unsafe fn scatter_n<const S: usize>(
    ll8: *const u8,
    n: usize,
    counts: &[u32; 256],
    snap_pos: &[usize],
    snap_counts: &[[u32; 256]],
    tt: *mut u32,
) {
    let mut cf = [[0u32; 256]; S];
    let mut sum = 0u32;
    for (c, &k) in cf[0].iter_mut().zip(counts.iter()) {
        *c = sum;
        sum += k;
    }
    debug_assert_eq!(sum as usize, n);
    // Stream boundaries: the snapshots closest to n * k / S.
    let mut bounds = [0usize; 5];
    bounds[S] = n;
    for k in 1..S {
        let want = n * k / S;
        let best = snap_pos
            .iter()
            .enumerate()
            .filter(|&(_, &p)| p > bounds[k - 1] && p < n)
            .min_by_key(|&(_, &p)| p.abs_diff(want));
        match best {
            Some((j, &p)) if p > bounds[k - 1] && p < n => {
                bounds[k] = p;
                for b in 0..256 {
                    cf[k][b] = cf[0][b] + snap_counts[j][b];
                }
            }
            // No usable snapshot: an empty stream.
            _ => {
                bounds[k] = bounds[k - 1];
                cf[k] = cf[k - 1];
            }
        }
    }
    // Lock-step over the shortest stream (0 if any stream is empty), then the tails.
    let mut len = usize::MAX;
    for k in 0..S {
        len = len.min(bounds[k + 1] - bounds[k]);
    }
    #[inline(always)]
    unsafe fn one(ll8: *const u8, tt: *mut u32, cf: &mut [u32; 256], i: usize) {
        unsafe {
            let b = *ll8.add(i);
            let d = *cf.get_unchecked(b as usize);
            *tt.add(d as usize) = ((i as u32) << 8) | b as u32;
            *cf.get_unchecked_mut(b as usize) = d + 1;
        }
    }
    unsafe {
        if S > 1 {
            for i in 0..len {
                for k in 0..S {
                    one(ll8, tt, &mut cf[k], bounds[k] + i);
                }
            }
        } else {
            len = 0;
        }
        for (k, c) in cf.iter_mut().enumerate() {
            for i in bounds[k] + len..bounds[k + 1] {
                one(ll8, tt, c, i);
            }
        }
    }
}

/// Single-walker inverse BWT (short blocks).
///
/// # Safety
/// `tt[..n]` is the scatter output (indices < n); `pre[..n]` writable.
unsafe fn walk_single(tt: *const u32, n: usize, orig: usize, pre: *mut u8) {
    let mut t = orig;
    for k in 0..n {
        unsafe {
            let e = *tt.add(t);
            *pre.add(k) = e as u8;
            t = (e >> 8) as usize;
        }
    }
}

/// Multi-lane inverse BWT into `pre[..n]`.
///
/// Segment `j` starts at index `start(j)`; its `tt` entry is replaced by `MARK | j` (the
/// original is kept in `s.first[j]`), so a lane that loads a marked entry knows which
/// segment follows its own. Lanes OR their loads into `any` and marks are handled after the
/// round, which keeps the unrolled round free of calls (all lanes stay in registers).
///
/// # Safety
/// `tt[..n]` is the scatter output (indices < n) with room for `tt[n]`; `cols` has
/// capacity LANES * COL; `pre[..n]` writable; n >= LANES_MIN.
unsafe fn walk_lanes(tt: *mut u32, n: usize, orig: usize, cols: *mut u8, pre: *mut u8, s: &mut Segs) -> Result<()> {
    let nseg = (n / SEG_LEN).max(16 * LANES).min(n / 64);
    s.nseg = nseg;
    s.step = n / nseg;
    s.orig = orig;
    s.n = n;
    for v in [&mut s.r0, &mut s.r1, &mut s.next, &mut s.first] {
        v.clear();
        v.resize(nseg, 0);
    }
    s.lane.clear();
    s.lane.resize(nseg, 0);
    unsafe {
        // Segment starts are distinct: j * step < n for j < nseg.
        for j in 0..nseg {
            let p = tt.add(s.start(j));
            s.first[j] = *p;
            *p = MARK | j as u32;
        }
        // Parked lanes loop on this entry forever.
        *tt.add(n) = (n as u32) << 8;
        let mut e = [0u32; LANES];
        for (w, x) in e.iter_mut().enumerate() {
            *x = s.first[w];
            s.cur[w] = w as u32;
            s.lane[w] = w as u8;
        }
        let mut unassigned = LANES;
        let mut active = LANES;
        let mut r = 0usize;
        loop {
            // Rounds <= total steps <= n < COL, but never trust that with raw writes.
            if r >= COL {
                return Err(corrupt("inverse BWT"));
            }
            let p = cols.add(r);
            let mut any = 0u32;
            for (w, x) in e.iter_mut().enumerate() {
                *p.add(w * COL) = *x as u8;
                let ne = *tt.add((*x >> 8) as usize);
                *x = ne;
                any |= ne;
            }
            r += 1;
            if any & MARK != 0 {
                // Close the segments of the lanes that reached a start and hand them the
                // next unassigned segment (or park them).
                for (w, x) in e.iter_mut().enumerate() {
                    if *x & MARK != 0 {
                        let k = s.cur[w] as usize;
                        s.r1[k] = r as u32;
                        s.next[k] = *x & !MARK;
                        if unassigned < nseg {
                            let j = unassigned;
                            unassigned += 1;
                            s.cur[w] = j as u32;
                            s.lane[j] = w as u8;
                            s.r0[j] = r as u32;
                            *x = s.first[j];
                        } else {
                            active -= 1;
                            *x = (n as u32) << 8;
                        }
                    }
                }
                if active == 0 {
                    break;
                }
            }
        }
        s.rounds = r;
        // Stitch the segments in chain order, starting with the one at `orig`.
        let mut k = 0usize;
        let mut total = 0usize;
        while total < n {
            let r0 = s.r0[k] as usize;
            let len = (s.r1[k] as usize - r0).min(n - total);
            std::ptr::copy_nonoverlapping(cols.add(s.lane[k] as usize * COL + r0), pre.add(total), len);
            total += len;
            k = s.next[k] as usize;
        }
    }
    Ok(())
}

/// Grows `out` so that `extra` more bytes fit.
fn reserve(out: &mut Vec<u8>, extra: usize) -> Result<()> {
    out.try_reserve(extra).map_err(|_| alloc_error())
}

/// Undoes the initial run-length encoding (4 equal bytes + count byte) of `src`, appending
/// to `out`.
fn unrle(src: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let n = src.len();
    reserve(out, n + PAD)?;
    let s = src.as_ptr();
    // SAFETY: `room` tracks the spare capacity after `op`; the invariant
    // room >= (n - i) + PAD holds at the top of each iteration, so the 16-byte stores and
    // fills (which over-write < 16 bytes) stay inside the allocation. Reads stay below n.
    unsafe {
        let mut op = out.as_mut_ptr().add(out.len());
        let mut room = out.capacity() - out.len();
        let mut i = 0usize;
        loop {
            // Find the next run start j >= i (src[j..j+4] all equal), copying src[i..j].
            let j = loop {
                #[cfg(target_arch = "x86_64")]
                if i + 19 <= n {
                    use std::arch::x86_64::*;
                    let a = _mm_loadu_si128(s.add(i) as *const __m128i);
                    let b = _mm_loadu_si128(s.add(i + 1) as *const __m128i);
                    let c = _mm_loadu_si128(s.add(i + 2) as *const __m128i);
                    let d = _mm_loadu_si128(s.add(i + 3) as *const __m128i);
                    _mm_storeu_si128(op as *mut __m128i, a);
                    let m = _mm_movemask_epi8(_mm_and_si128(
                        _mm_and_si128(_mm_cmpeq_epi8(a, b), _mm_cmpeq_epi8(a, c)),
                        _mm_cmpeq_epi8(a, d),
                    )) as u32;
                    if m == 0 {
                        i += 16;
                        op = op.add(16);
                        room -= 16;
                        continue;
                    }
                    let z = m.trailing_zeros() as usize;
                    op = op.add(z);
                    room -= z;
                    break i + z;
                }
                if i + 4 > n {
                    let rest = n - i;
                    std::ptr::copy_nonoverlapping(s.add(i), op, rest);
                    let len = out.capacity() - room + rest;
                    out.set_len(len);
                    return Ok(());
                }
                let x = *s.add(i);
                if *s.add(i + 1) == x && *s.add(i + 2) == x && *s.add(i + 3) == x {
                    break i;
                }
                *op = x;
                op = op.add(1);
                room -= 1;
                i += 1;
            };
            let x = *s.add(j);
            (op as *mut [u8; 4]).write_unaligned([x; 4]);
            op = op.add(4);
            room -= 4;
            if j + 4 >= n {
                // A run at the very end of the block has no count byte.
                let len = out.capacity() - room;
                out.set_len(len);
                return Ok(());
            }
            let c = *s.add(j + 4) as usize;
            let rest = n - (j + 5);
            if room < c + rest + PAD {
                let len = out.capacity() - room;
                out.set_len(len);
                reserve(out, c + rest + PAD)?;
                op = out.as_mut_ptr().add(len);
                room = out.capacity() - len;
            }
            fill16(op, x, c);
            op = op.add(c);
            room -= c;
            i = j + 5;
        }
    }
}

/// Decodes one stream starting at byte `off`; returns the byte offset after it.
fn decode_stream(data: &[u8], off: usize, sc: &mut Scratch, out: &mut Vec<u8>) -> std::result::Result<usize, Fail> {
    // Header "BZh1".."BZh9"; a mismatch in the available bytes is corrupt, a short but
    // matching prefix is truncation (libbz2 checks byte by byte).
    let avail = &data[off.min(data.len())..];
    for (k, &b) in avail.iter().take(4).enumerate() {
        let ok = if k < 3 { b == b"BZh"[k] } else { (b'1'..=b'9').contains(&b) };
        if !ok {
            return Err(corrupt("bad stream header").into());
        }
    }
    if avail.len() < 4 {
        return Err(Fail::Truncated);
    }
    let max_block = (avail[3] - b'0') as usize * 100_000;
    let mut br = BitReader::new(data, off + 4);
    let mut combined = 0u32;
    loop {
        let hi = br.bits(24) as u64;
        let magic = (hi << 24) | br.bits(24) as u64;
        if magic == END_MAGIC {
            let crc = br.bits(32);
            if br.overrun() {
                return Err(Fail::Truncated);
            }
            if crc != combined {
                return Err(corrupt("stream CRC mismatch").into());
            }
            return Ok(br.byte_align());
        }
        if magic != BLOCK_MAGIC {
            return Err(br.fail(corrupt("bad block magic")));
        }
        let crc = sc.block(&mut br, max_block, out)?;
        combined = combined.rotate_left(1) ^ crc;
    }
}

/// Decompresses a bzip2 file (all concatenated streams). Like python's `bz2.decompress`,
/// invalid data after the first complete stream is ignored.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    // Size hint only (a failed reservation just means growing later).
    let _ = out.try_reserve(data.len().saturating_mul(5).min(1 << 30));
    let mut sc = Scratch::new()?;
    let mut off = 0usize;
    let mut streams = 0;
    while off < data.len() {
        let mark = out.len();
        match decode_stream(data, off, &mut sc, &mut out) {
            Ok(next) => {
                off = next;
                streams += 1;
            }
            Err(Fail::Corrupt(e)) => {
                if streams > 0 {
                    out.truncate(mark);
                    break;
                }
                return Err(e);
            }
            Err(Fail::Truncated) => {
                return Err(Error::Msg(
                    "bzip2: compressed data ended before the end-of-stream marker was reached".into(),
                ));
            }
        }
    }
    if streams == 0 {
        return Err(Error::Msg("bzip2: empty input".into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // printf 'hello hello hello hello\n' | bzip2 -9
    const BZ: &[u8] = &[
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x6f, 0x4f, 0x10, 0xf3, 0x00, 0x00,
        0x05, 0xd1, 0x00, 0x00, 0x10, 0x40, 0x00, 0x02, 0x44, 0xa0, 0x00, 0x30, 0xc0, 0x02, 0xa8, 0x34,
        0x71, 0x0d, 0xad, 0x87, 0x0f, 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0x6f, 0x4f, 0x10, 0xf3,
    ];

    #[test]
    fn codecs_bzip2_small_multistream() {
        assert_eq!(decompress(BZ).unwrap(), b"hello hello hello hello\n");
        let mut two = BZ.to_vec();
        two.extend_from_slice(BZ);
        assert_eq!(decompress(&two).unwrap(), b"hello hello hello hello\nhello hello hello hello\n");
        // Garbage after a complete stream is ignored (python semantics)...
        let mut g = BZ.to_vec();
        g.extend_from_slice(b"garbage");
        assert_eq!(decompress(&g).unwrap(), b"hello hello hello hello\n");
        // ...but truncation is an error.
        for n in 0..BZ.len() {
            assert!(decompress(&BZ[..n]).is_err(), "truncated at {n}");
        }
    }

    /// Per-phase cost of CODECS_BENCH_FILE (single stream), in user-mode cycles per BWT symbol.
    #[cfg(target_arch = "x86_64")]
    #[test]
    #[ignore]
    fn codecs_bzip2_phases() {
        let Ok(file) = std::env::var("CODECS_BENCH_FILE") else { return };
        let data = std::fs::read(file).unwrap();
        // User-mode cycles of this thread (perf_event_open), falling back to the TSC.
        use std::os::raw::{c_int, c_long, c_ulong};
        unsafe extern "C" {
            fn syscall(num: c_long, ...) -> c_long;
            fn ioctl(fd: c_int, req: c_ulong, ...) -> c_int;
            fn read(fd: c_int, buf: *mut std::ffi::c_void, n: usize) -> isize;
        }
        let pmu = std::fs::read_to_string("/sys/bus/event_source/devices/cpu_core/type")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let mut attr = [0u64; 8];
        attr[0] = 64u64 << 32;
        attr[1] = pmu << 32;
        attr[5] = (1 << 5) | (1 << 6);
        let fd = unsafe { syscall(298, attr.as_ptr(), 0 as c_int, -1 as c_int, -1 as c_int, 0 as c_ulong) } as c_int;
        if fd >= 0 {
            unsafe { ioctl(fd, 0x2400, 0 as c_ulong) };
        }
        let tsc = || {
            if fd >= 0 {
                let mut v = 0u64;
                unsafe { read(fd, &mut v as *mut u64 as *mut std::ffi::c_void, 8) };
                v
            } else {
                unsafe { std::arch::x86_64::_rdtsc() }
            }
        };
        let mut best = [u64::MAX; 5];
        let mut total_n = 0usize;
        let mut total_out = 0usize;
        let mut total_runs = 0usize;
        let mut total_rounds = 0usize;
        for _ in 0..5 {
            let mut t = [0u64; 5];
            let mut sc = Scratch::new().unwrap();
            let mut out = Vec::with_capacity(1 << 27);
            let max_block = (data[3] - b'0') as usize * 100_000;
            let mut br = BitReader::new(&data, 4);
            total_n = 0;
            total_runs = 0;
            total_rounds = 0;
            loop {
                let hi = br.bits(24) as u64;
                let magic = (hi << 24) | br.bits(24) as u64;
                if magic != BLOCK_MAGIC {
                    break;
                }
                let t0 = tsc();
                let Ok(info) = sc.entropy(&mut br, max_block) else { panic!("entropy") };
                let t1 = tsc();
                let n = info.n;
                total_n += n;
                total_runs += info.run_total;
                unsafe {
                    scatter(sc.ll8.as_ptr(), n, &info, &sc.snap_pos, &sc.snap_counts, sc.tt.as_mut_ptr());
                    let t2 = tsc();
                    if n < LANES_MIN {
                        walk_single(sc.tt.as_ptr(), n, info.orig_ptr, sc.pre.as_mut_ptr());
                    } else {
                        if sc.cols.capacity() < LANES * COL {
                            sc.cols.reserve_exact(LANES * COL);
                        }
                        walk_lanes(sc.tt.as_mut_ptr(), n, info.orig_ptr, sc.cols.as_mut_ptr(), sc.pre.as_mut_ptr(), &mut sc.segs)
                            .unwrap();
                        total_rounds += sc.segs.rounds;
                    }
                    let t3 = tsc();
                    let start = out.len();
                    unrle(std::slice::from_raw_parts(sc.pre.as_ptr(), n), &mut out).unwrap();
                    let t4 = tsc();
                    assert_eq!(crc32_bzip2(&out[start..]), info.crc);
                    let t5 = tsc();
                    for (k, d) in [t1 - t0, t2 - t1, t3 - t2, t4 - t3, t5 - t4].into_iter().enumerate() {
                        t[k] += d;
                    }
                }
            }
            total_out = out.len();
            for k in 0..5 {
                best[k] = best[k].min(t[k]);
            }
        }
        if let Ok(r) = std::fs::read_to_string("/proc/self/smaps_rollup") {
            for l in r.lines().filter(|l| l.starts_with("AnonHuge")) {
                println!("{l}");
            }
        }
        let names = ["entropy", "scatter", "walk", "unrle", "crc"];
        let sum: u64 = best.iter().sum();
        let line: Vec<String> = names
            .iter()
            .zip(best.iter())
            .map(|(nm, &c)| format!("{nm} {:.2}", c as f64 / total_n as f64))
            .collect();
        println!(
            "phases (cycles per BWT symbol, n={total_n}, out={total_out}, runs {:.2}, lane use {:.2}): {} | total {:.1} Mticks",
            total_runs as f64 / total_n as f64,
            total_n as f64 / (total_rounds * LANES) as f64,
            line.join("  "),
            sum as f64 / 1e6
        );
    }

    /// Walk micro-benchmark on a random single-cycle permutation (Sattolo), warm caches.
    #[cfg(target_arch = "x86_64")]
    #[test]
    #[ignore]
    fn codecs_bzip2_walk_bench() {
        for n in [100_000usize, 400_000, 900_000] {
            let mut s = 0x9E37_79B9_7F4A_7C15u64;
            let mut rnd = || {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                s
            };
            let mut perm: Vec<u32> = (0..n as u32).collect();
            for i in (1..n).rev() {
                let j = (rnd() % i as u64) as usize;
                perm.swap(i, j);
            }
            let orig: Vec<u32> = (0..n).map(|i| (perm[i] << 8) | (rnd() as u32 & 0xFF)).collect();
            let mut tt = HugeBuf::<u32>::new(MAX_BLOCK + 1).unwrap();
            let mut cols: Vec<u8> = Vec::with_capacity(LANES * COL);
            let mut pre: Vec<u8> = Vec::with_capacity(MAX_BLOCK + PAD);
            let mut sc = Scratch::new().unwrap();
            let mut best = u64::MAX;
            for _ in 0..20 {
                unsafe {
                    std::ptr::copy_nonoverlapping(orig.as_ptr(), tt.as_mut_ptr(), n);
                    let t0 = std::arch::x86_64::_rdtsc();
                    walk_lanes(tt.as_mut_ptr(), n, 0, cols.as_mut_ptr(), pre.as_mut_ptr(), &mut sc.segs).unwrap();
                    best = best.min(std::arch::x86_64::_rdtsc() - t0);
                }
            }
            println!("walk n={n} lanes={LANES}: {:.2} TSC ticks/step", best as f64 / n as f64);
        }
    }

    #[test]
    fn codecs_bzip2_garbage_never_panics() {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..3000 {
            let mut v = BZ.to_vec();
            for _ in 0..3 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                let i = 4 + (s as usize) % (v.len() - 4);
                v[i] ^= 1 << ((s >> 40) & 7);
            }
            let _ = decompress(&v);
        }
    }
}
