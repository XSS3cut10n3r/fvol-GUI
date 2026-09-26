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
/// Concurrent inverse-BWT walkers. More lanes keep more cache misses in flight (up to the
/// core's ~16 L1 miss buffers), but beyond 12 the lane state no longer fits in registers;
/// 16 lanes kept on the stack measured within +-4% (better on 900k random-access blocks,
/// worse on small or cache-friendly ones).
const LANES: usize = 12;

/// Invokes `$m!(w)` for every lane index (literals, so lane state stays in registers).
macro_rules! for_each_lane {
    ($m:ident) => {
        $m!(0);
        $m!(1);
        $m!(2);
        $m!(3);
        $m!(4);
        $m!(5);
        $m!(6);
        $m!(7);
        $m!(8);
        $m!(9);
        $m!(10);
        $m!(11);
    };
}
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

    /// A reader positioned at bit `pos` of `data`.
    fn at_bit(data: &'a [u8], pos: usize) -> Self {
        let mut br = BitReader::new(data, pos / 8);
        if !pos.is_multiple_of(8) {
            br.bits((pos % 8) as u32);
        }
        br
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
    /// block CRC and its BWT length.
    fn decode_block(
        &mut self,
        br: &mut BitReader,
        max_block: usize,
        out: &mut Vec<u8>,
    ) -> std::result::Result<(u32, usize), Fail> {
        let info = self.entropy(br, max_block)?;
        self.finish(&info, out)?;
        Ok((info.crc, info.n))
    }

    /// Huffman + MTF/RUNA-RUNB decoding of one block into `ll8`: the AVX2 build of
    /// [`Scratch::entropy_impl`] when the CPU has AVX2 (detected at run time, so portable
    /// builds keep it), the scalar one otherwise.
    fn entropy(&mut self, br: &mut BitReader, max_block: usize) -> std::result::Result<BlockInfo, Fail> {
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 is available.
            return unsafe { self.entropy_avx2(br, max_block) };
        }
        self.entropy_impl::<false>(br, max_block)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn entropy_avx2(&mut self, br: &mut BitReader, max_block: usize) -> std::result::Result<BlockInfo, Fail> {
        self.entropy_impl::<true>(br, max_block)
    }

    /// [`Scratch::entropy`]; `AVX2`: move-to-front with [`mtf_move_avx2`] (only instantiated
    /// inside [`Scratch::entropy_avx2`]).
    #[inline(always)]
    fn entropy_impl<const AVX2: bool>(&mut self, br: &mut BitReader, max_block: usize) -> std::result::Result<BlockInfo, Fail> {
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
        for table in self.tables.iter_mut().take(n_groups) {
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
            if let Err(e) = table.build(&lens[..alpha]) {
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
                let v = mtf_move::<AVX2>(&mut mtf, (sym - 1) as usize);
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
        debug_assert!((1..=MAX_BLOCK).contains(&n) && info.orig_ptr < n);
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
                walk(self.tt.as_mut_ptr(), n, info.orig_ptr, self.cols.as_mut_ptr(), self.pre.as_mut_ptr(), &mut self.segs)?;
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

/// Moves `mtf[idx]` (idx >= 1) to the front; returns it. `AVX2` selects [`mtf_move_avx2`]
/// (true only inside `Scratch::entropy_avx2`, i.e. on a CPU with AVX2).
#[inline(always)]
fn mtf_move<const AVX2: bool>(mtf: &mut MtfList, idx: usize) -> u8 {
    #[cfg(target_arch = "x86_64")]
    if AVX2 {
        // SAFETY: AVX2 was detected before entering the AVX2 build of the decoder.
        return unsafe { mtf_move_avx2(mtf, idx) };
    }
    mtf_move_scalar(mtf, idx)
}

/// [`mtf_move`] with AVX2: every 32-byte chunk at or below `idx` becomes the chunk shifted
/// up by one byte (carrying in the previous chunk's last byte, or `v` for chunk 0), blended
/// with the original above `idx`. Indices below 32 touch one chunk; larger ones process all
/// eight chunks without branches (random data has uniformly spread indices, so a
/// data-dependent loop length would mispredict on nearly every symbol).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn mtf_move_avx2(mtf: &mut MtfList, idx: usize) -> u8 {
    use std::arch::x86_64::*;
    let idx = idx & 255;
    let v = mtf.0[idx];
    // SAFETY: the caller checked AVX2; all accesses are within the aligned 256 bytes.
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
#[inline(always)]
fn mtf_move_scalar(mtf: &mut MtfList, idx: usize) -> u8 {
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
/// round, which keeps the round free of calls.
///
/// # Safety
/// `tt[..n]` is the scatter output (indices < n) with room for `tt[n]`; `cols` has
/// capacity LANES * COL; `pre[..n]` writable; n >= LANES_MIN.
unsafe fn walk(tt: *mut u32, n: usize, orig: usize, cols: *mut u8, pre: *mut u8, s: &mut Segs) -> Result<()> {
    debug_assert!(n >= LANES_MIN);
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
            macro_rules! step {
                ($w:literal) => {{
                    *p.add($w * COL) = e[$w] as u8;
                    let ne = *tt.add((e[$w] >> 8) as usize);
                    e[$w] = ne;
                    any |= ne;
                }};
            }
            for_each_lane!(step);
            r += 1;
            if any & MARK != 0 {
                // Close the segments of the lanes that reached a start and hand them the
                // next unassigned segment (or park them).
                macro_rules! handle {
                    ($w:literal) => {{
                        let x = &mut e[$w];
                        if *x & MARK != 0 {
                            let k = s.cur[$w] as usize;
                            s.r1[k] = r as u32;
                            s.next[k] = *x & !MARK;
                            if unassigned < nseg {
                                let j = unassigned;
                                unassigned += 1;
                                s.cur[$w] = j as u32;
                                s.lane[j] = $w as u8;
                                s.r0[j] = r as u32;
                                *x = s.first[j];
                            } else {
                                active -= 1;
                                *x = (n as u32) << 8;
                            }
                        }
                    }};
                }
                for_each_lane!(handle);
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

/// Where the stream walker gets its blocks from.
trait BlockSource {
    /// Decodes the block whose header starts at `br` (just after the block magic), appending
    /// its output to `out` and leaving `br` after the block; returns the block CRC.
    fn block(&mut self, br: &mut BitReader, max_block: usize, out: &mut Vec<u8>) -> std::result::Result<u32, Fail>;
}

impl BlockSource for Scratch {
    fn block(&mut self, br: &mut BitReader, max_block: usize, out: &mut Vec<u8>) -> std::result::Result<u32, Fail> {
        self.decode_block(br, max_block, out).map(|(crc, _)| crc)
    }
}

/// Decodes one stream starting at byte `off`; returns the byte offset after it.
fn decode_stream<S: BlockSource>(data: &[u8], off: usize, src: &mut S, out: &mut Vec<u8>) -> std::result::Result<usize, Fail> {
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
        let crc = src.block(&mut br, max_block, out)?;
        combined = combined.rotate_left(1) ^ crc;
    }
}

/// Decodes all streams of `data` (python `bz2.decompress` semantics).
fn decode_all<S: BlockSource>(data: &[u8], src: &mut S) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    // Size hint only (a failed reservation just means growing later).
    let _ = out.try_reserve(data.len().saturating_mul(5).min(1 << 30));
    let mut off = 0usize;
    let mut streams = 0;
    while off < data.len() {
        let mark = out.len();
        match decode_stream(data, off, src, &mut out) {
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
    // No streams at all only happens for empty input, which python decodes to b"".
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// Parallel decoding
//
// Blocks are not byte aligned and there is no index, but every block starts with the 48-bit
// magic 0x314159265359. The input is scanned (in parallel) for the magic at every bit
// offset; worker threads then decode whole blocks (entropy decoding, inverse BWT, RLE1, CRC)
// at those candidate positions, in order, at most WINDOW candidates / BUDGET output bytes
// ahead of the consumer. The calling thread runs the ordinary sequential stream walker and,
// for each block, takes the result computed for exactly that bit position (helping with
// jobs while it waits). A speculative failure, or a block longer than its stream's level
// allows (workers decode with the level-9 limit), is simply decoded again inline, so errors
// and python semantics are exactly those of the sequential decoder. A magic that occurs by
// chance inside compressed data (probability ~2^-48 per bit) only costs wasted work.
// ---------------------------------------------------------------------------------------

/// Inputs shorter than this are decoded on the calling thread only (a bzip2 block is at
/// least ~40 bytes, and highly compressible blocks are a few hundred bytes).
const PAR_MIN: usize = 1024;
/// Upper bound on decoding threads.
const MAX_THREADS: usize = 16;
/// Upper bound on finished-but-unconsumed output held by the workers.
const BUDGET: usize = 64 << 20;
/// Output buffers larger than this are not recycled.
const POOL_MAX_CAP: usize = 4 << 20;

/// Bit positions just after each occurrence of the block magic (any bit offset), ascending.
fn scan_magics(data: &[u8], threads: usize) -> Vec<usize> {
    // TBL[b] has bit s set if byte 2 of a magic starting at bit offset s of byte 0 is b.
    let mut tbl = [0u8; 256];
    for sh in 0..8 {
        tbl[((BLOCK_MAGIC >> (24 + sh)) & 0xFF) as usize] |= 1 << sh;
    }
    let scan = |from: usize, to: usize| -> Vec<usize> {
        let mut v = Vec::new();
        let end = to.min(data.len().saturating_sub(8));
        for i in from..end {
            let mut m = tbl[data[i + 2] as usize];
            if m == 0 {
                continue;
            }
            let w = u64::from_be_bytes(data[i..i + 8].try_into().unwrap());
            while m != 0 {
                let sh = m.trailing_zeros();
                m &= m - 1;
                if (w >> (16 - sh)) & 0xFFFF_FFFF_FFFF == BLOCK_MAGIC {
                    v.push(i * 8 + sh as usize + 48);
                }
            }
        }
        v
    };
    let chunk = data.len().div_ceil(threads.max(1)).max(1 << 16);
    if chunk >= data.len() {
        return scan(0, data.len());
    }
    std::thread::scope(|sc| {
        let hs: Vec<_> = (0..data.len().div_ceil(chunk))
            .map(|t| {
                let scan = &scan;
                sc.spawn(move || scan(t * chunk, (t + 1) * chunk))
            })
            .collect();
        let mut all = Vec::new();
        for h in hs {
            // The scan cannot panic; if it did, fewer candidates only mean more inline
            // decoding.
            if let Ok(v) = h.join() {
                all.extend(v);
            }
        }
        all
    })
}

/// A block decoded ahead of time.
struct Ahead {
    /// Bit position after the block.
    end_bit: usize,
    crc: u32,
    /// BWT length (checked against the stream's level).
    n: usize,
    out: Vec<u8>,
}

/// State shared by the workers and the walker.
struct Shared {
    /// Next candidate to hand out.
    next_job: usize,
    /// Candidates below this are no longer needed by the walker.
    need: usize,
    /// Per candidate: None = pending, Some(None) = failed, Some(Some(..)) = decoded.
    results: Vec<Option<Option<Ahead>>>,
    /// Output bytes held in `results`.
    held: usize,
    pool: Vec<Vec<u8>>,
    stop: bool,
}

struct Par<'a> {
    data: &'a [u8],
    cands: &'a [usize],
    window: usize,
    st: &'a std::sync::Mutex<Shared>,
    cv: &'a std::sync::Condvar,
}

impl Par<'_> {
    fn lock(&self) -> std::sync::MutexGuard<'_, Shared> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn wait<'g>(&self, g: std::sync::MutexGuard<'g, Shared>) -> std::sync::MutexGuard<'g, Shared> {
        self.cv.wait(g).unwrap_or_else(|e| e.into_inner())
    }

    /// Hands out the next job allowed by the window and the byte budget.
    fn take_job(&self, g: &mut Shared) -> Option<(usize, Vec<u8>)> {
        g.next_job = g.next_job.max(g.need);
        let i = g.next_job;
        if i >= self.cands.len() || i >= g.need + self.window || (i > g.need && g.held >= BUDGET) {
            return None;
        }
        g.next_job += 1;
        Some((i, g.pool.pop().unwrap_or_default()))
    }

    fn recycle(g: &mut Shared, mut buf: Vec<u8>) {
        if buf.capacity() <= POOL_MAX_CAP && g.pool.len() < 64 {
            buf.clear();
            g.pool.push(buf);
        }
    }

    /// Decodes candidate `i` (never panics into the caller: a panic counts as a failure,
    /// and the walker then decodes the block inline).
    fn run_job(&self, i: usize, sc: &mut Option<Scratch>, mut buf: Vec<u8>) -> Option<Ahead> {
        if sc.is_none() {
            *sc = Scratch::new().ok();
        }
        let scr = sc.as_mut()?;
        let pos = self.cands[i];
        let data = self.data;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            buf.clear();
            let mut br = BitReader::at_bit(data, pos);
            match scr.decode_block(&mut br, MAX_BLOCK, &mut buf) {
                Ok((crc, n)) => Some(Ahead { end_bit: br.position_bits(), crc, n, out: buf }),
                Err(_) => None,
            }
        }));
        match r {
            Ok(a) => a,
            Err(_) => {
                *sc = None;
                None
            }
        }
    }

    fn store(&self, g: &mut Shared, i: usize, r: Option<Ahead>) {
        if i < g.need {
            if let Some(a) = r {
                Self::recycle(g, a.out);
            }
            return;
        }
        if let Some(a) = &r {
            g.held += a.out.len();
        }
        g.results[i] = Some(r);
    }

    /// Drops the results below `need` (the walker has moved past them).
    fn advance(&self, g: &mut Shared, need: usize) {
        while g.need < need {
            let i = g.need;
            if let Some(Some(a)) = g.results[i].take() {
                g.held -= a.out.len();
                Self::recycle(g, a.out);
            }
            g.need += 1;
        }
    }

    fn worker(&self) {
        let mut sc: Option<Scratch> = None;
        let mut g = self.lock();
        loop {
            if g.stop {
                return;
            }
            match self.take_job(&mut g) {
                Some((i, buf)) => {
                    drop(g);
                    let r = self.run_job(i, &mut sc, buf);
                    g = self.lock();
                    self.store(&mut g, i, r);
                    self.cv.notify_all();
                }
                None => {
                    if g.next_job >= self.cands.len() {
                        return;
                    }
                    g = self.wait(g);
                }
            }
        }
    }
}

/// The walker's block source: precomputed results, inline decoding as the fallback.
struct ParWalker<'a> {
    par: Par<'a>,
    sc: Option<Scratch>,
}

impl BlockSource for ParWalker<'_> {
    fn block(&mut self, br: &mut BitReader, max_block: usize, out: &mut Vec<u8>) -> std::result::Result<u32, Fail> {
        let pos = br.position_bits();
        let idx = self.par.cands.partition_point(|&c| c < pos);
        let mut g = self.par.lock();
        self.par.advance(&mut g, idx);
        if self.par.cands.get(idx) == Some(&pos) {
            let r = loop {
                if let Some(r) = g.results[idx].take() {
                    break r;
                }
                match self.par.take_job(&mut g) {
                    Some((i, buf)) => {
                        drop(g);
                        let r = self.par.run_job(i, &mut self.sc, buf);
                        g = self.par.lock();
                        self.par.store(&mut g, i, r);
                        self.par.cv.notify_all();
                    }
                    None => g = self.par.wait(g),
                }
            };
            if let Some(a) = &r {
                g.held -= a.out.len();
            }
            self.par.advance(&mut g, idx + 1);
            drop(g);
            self.par.cv.notify_all();
            if let Some(a) = r {
                let ok = a.n <= max_block;
                if ok {
                    reserve(out, a.out.len())?;
                    out.extend_from_slice(&a.out);
                    *br = BitReader::at_bit(br.data, a.end_bit);
                }
                let crc = a.crc;
                Par::recycle(&mut self.par.lock(), a.out);
                if ok {
                    return Ok(crc);
                }
            }
        } else {
            drop(g);
        }
        // Not a candidate, failed, or too long for this stream's level: decode inline.
        if self.sc.is_none() {
            self.sc = Some(Scratch::new()?);
        }
        let sc = self.sc.as_mut().ok_or_else(alloc_error)?;
        sc.block(br, max_block, out)
    }
}

/// Decodes with up to `threads` threads (the calling thread included).
fn decompress_par(data: &[u8], cands: &[usize], threads: usize) -> Result<Vec<u8>> {
    let st = std::sync::Mutex::new(Shared {
        next_job: 0,
        need: 0,
        results: (0..cands.len()).map(|_| None).collect(),
        held: 0,
        pool: Vec::new(),
        stop: false,
    });
    let cv = std::sync::Condvar::new();
    let window = 2 * threads + 2;
    let mk = || Par { data, cands, window, st: &st, cv: &cv };
    std::thread::scope(|scope| {
        for _ in 1..threads {
            let p = mk();
            scope.spawn(move || p.worker());
        }
        let mut walker = ParWalker { par: mk(), sc: None };
        let r = decode_all(data, &mut walker);
        let mut g = walker.par.lock();
        g.stop = true;
        drop(g);
        cv.notify_all();
        r
    })
}

/// Number of threads for decoding `data` (1 when pinned to one CPU).
///
/// The inverse BWT makes random accesses over 4 bytes per block symbol; once the blocks being
/// decoded concurrently no longer fit in the last-level cache the walk turns DRAM-latency
/// bound and every thread slows down several times (level-9 text: 6 threads 40 ms, 16
/// threads 58 ms). So the thread count is capped at L3 size / ~4.5 bytes per block symbol,
/// using the first stream's level.
fn default_threads(data: &[u8]) -> usize {
    if data.len() < PAR_MIN {
        return 1;
    }
    let avail = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(MAX_THREADS);
    if avail <= 1 {
        return 1;
    }
    let level = match data.get(..4) {
        Some([b'B', b'Z', b'h', l @ b'1'..=b'9']) => (l - b'0') as usize,
        _ => 9,
    };
    let per_thread = level * 100_000 * 9 / 2;
    avail.min((l3_cache_bytes() / per_thread).max(2))
}

/// Last-level cache size (Linux sysfs; 32 MiB if unknown).
fn l3_cache_bytes() -> usize {
    static L3: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *L3.get_or_init(|| {
        let mut best = 0usize;
        for i in 0..8 {
            let dir = format!("/sys/devices/system/cpu/cpu0/cache/index{i}");
            let Ok(size) = std::fs::read_to_string(format!("{dir}/size")) else { break };
            let size = size.trim();
            let (num, mul) = match size.strip_suffix('K') {
                Some(k) => (k, 1 << 10),
                None => match size.strip_suffix('M') {
                    Some(m) => (m, 1 << 20),
                    None => (size, 1),
                },
            };
            if let Ok(v) = num.parse::<usize>() {
                best = best.max(v.saturating_mul(mul));
            }
        }
        if best >= 1 << 20 { best } else { 32 << 20 }
    })
}

/// Decompresses a bzip2 file (all concatenated streams). Like python's `bz2.decompress`,
/// invalid data after the first complete stream is ignored. Multi-block inputs are decoded
/// on up to `available_parallelism()` threads.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    decompress_threads(data, default_threads(data))
}

/// As [`decompress`] with an explicit thread count (1 = single-threaded).
pub fn decompress_threads(data: &[u8], threads: usize) -> Result<Vec<u8>> {
    if threads > 1 {
        let cands = scan_magics(data, threads);
        if cands.len() >= 2 {
            return decompress_par(data, &cands, threads.min(cands.len()));
        }
    }
    decode_all(data, &mut Scratch::new()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AVX2 move-to-front (when the CPU has it) equals the scalar one.
    #[test]
    fn mtf_avx2_equals_scalar() {
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("avx2") {
            let (mut a, mut b) = (MtfList([0u8; 256]), MtfList([0u8; 256]));
            for i in 0..256 {
                a.0[i] = (i as u8).wrapping_mul(97);
                b.0[i] = a.0[i];
            }
            let mut x: u32 = 12345;
            for n in 0..20000 {
                x = x.wrapping_mul(1103515245).wrapping_add(12345);
                // mostly small indices, like real data, and every value up to 255
                let idx = 1 + if n % 3 == 0 { (x >> 16) as usize % 255 } else { (x >> 16) as usize % 20 };
                // SAFETY: AVX2 checked above
                let va = unsafe { mtf_move_avx2(&mut a, idx) };
                let vb = mtf_move_scalar(&mut b, idx);
                assert_eq!((va, a.0), (vb, b.0), "step {n} idx {idx}");
            }
        }
        let mut m = MtfList([0u8; 256]);
        m.0[..4].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(mtf_move::<false>(&mut m, 2), 3);
        assert_eq!(&m.0[..4], &[3, 1, 2, 4]);
    }

    // ---------------------------------------------------------------------------------
    // Minimal bzip2 encoder (tests only): RLE1, BWT by prefix doubling, MTF + RUNA/RUNB,
    // fixed-length Huffman codes (two identical tables, every selector 0). The output is a
    // valid bzip2 stream with freely chosen block sizes, so multi-block, periodic-block and
    // multi-threaded paths can be tested on arbitrary data.
    // ---------------------------------------------------------------------------------

    struct BitW {
        out: Vec<u8>,
        acc: u8,
        n: u32,
    }

    impl BitW {
        fn put(&mut self, v: u64, bits: u32) {
            for i in (0..bits).rev() {
                self.acc = (self.acc << 1) | ((v >> i) & 1) as u8;
                self.n += 1;
                if self.n == 8 {
                    self.out.push(self.acc);
                    self.acc = 0;
                    self.n = 0;
                }
            }
        }

        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.out.push(self.acc << (8 - self.n));
            }
            self.out
        }
    }

    /// Splits `data` into blocks whose RLE1 encoding has at most `limit` bytes; returns
    /// (original bytes, RLE1 encoding) per block.
    fn rle1_blocks(data: &[u8], limit: usize) -> Vec<(&[u8], Vec<u8>)> {
        let mut blocks = Vec::new();
        let mut start = 0;
        let mut enc = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let b = data[i];
            let mut j = i;
            while j < data.len() && data[j] == b && j - i < 259 {
                j += 1;
            }
            let run = j - i;
            let size = if run >= 4 { 5 } else { run };
            if enc.len() + size > limit {
                blocks.push((&data[start..i], std::mem::take(&mut enc)));
                start = i;
            }
            if run >= 4 {
                enc.extend_from_slice(&[b; 4]);
                enc.push((run - 4) as u8);
            } else {
                enc.extend(std::iter::repeat_n(b, run));
            }
            i = j;
        }
        if start < data.len() {
            blocks.push((&data[start..], enc));
        }
        blocks
    }

    /// Burrows-Wheeler transform (sorted rotations): last column and row of rotation 0.
    fn bwt(s: &[u8]) -> (Vec<u8>, usize) {
        let n = s.len();
        let mut rank: Vec<u32> = s.iter().map(|&b| b as u32).collect();
        let mut sa: Vec<u32> = (0..n as u32).collect();
        let mut k = 1;
        loop {
            let r = &rank;
            let key = |i: u32| (r[i as usize], r[(i as usize + k) % n]);
            sa.sort_unstable_by_key(|&i| key(i));
            let mut nr = vec![0u32; n];
            for w in 1..n {
                nr[sa[w] as usize] = nr[sa[w - 1] as usize] + (key(sa[w]) != key(sa[w - 1])) as u32;
            }
            let distinct = nr[sa[n - 1] as usize] as usize == n - 1;
            rank = nr;
            if distinct || k >= n {
                break;
            }
            k *= 2;
        }
        let l = sa.iter().map(|&i| s[(i as usize + n - 1) % n]).collect();
        let orig = sa.iter().position(|&i| i == 0).unwrap();
        (l, orig)
    }

    fn encode_block(w: &mut BitW, block: &[u8], crc: u32) {
        let (l, orig) = bwt(block);
        let mut used = [false; 256];
        for &b in &l {
            used[b as usize] = true;
        }
        let mut list: Vec<u8> = (0..=255u8).filter(|&b| used[b as usize]).collect();
        let alpha = list.len() + 2;
        let mut syms: Vec<u16> = Vec::new();
        let mut run = 0usize;
        fn flush(run: &mut usize, syms: &mut Vec<u16>) {
            let mut r = *run;
            while r > 0 {
                if r & 1 == 1 {
                    syms.push(0);
                    r = (r - 1) / 2;
                } else {
                    syms.push(1);
                    r = (r - 2) / 2;
                }
            }
            *run = 0;
        }
        for &b in &l {
            let j = list.iter().position(|&x| x == b).unwrap();
            if j == 0 {
                run += 1;
                continue;
            }
            flush(&mut run, &mut syms);
            list.remove(j);
            list.insert(0, b);
            syms.push(j as u16 + 1);
        }
        flush(&mut run, &mut syms);
        syms.push(alpha as u16 - 1);
        let len = usize::BITS - (alpha - 1).leading_zeros();
        w.put(BLOCK_MAGIC, 48);
        w.put(crc as u64, 32);
        w.put(0, 1);
        w.put(orig as u64, 24);
        let mut used16 = 0u64;
        for i in 0..16 {
            if used[i * 16..i * 16 + 16].iter().any(|&u| u) {
                used16 |= 1 << (15 - i);
            }
        }
        w.put(used16, 16);
        for i in 0..16 {
            if used16 & (1 << (15 - i)) != 0 {
                let mut bits = 0u64;
                for j in 0..16 {
                    if used[i * 16 + j] {
                        bits |= 1 << (15 - j);
                    }
                }
                w.put(bits, 16);
            }
        }
        w.put(2, 3);
        let nsel = syms.len().div_ceil(50);
        w.put(nsel as u64, 15);
        for _ in 0..nsel {
            w.put(0, 1);
        }
        for _ in 0..2 {
            w.put(len as u64, 5);
            for _ in 0..alpha {
                w.put(0, 1);
            }
        }
        for &s in &syms {
            w.put(s as u64, len);
        }
    }

    /// bzip2 stream of `data` with level digit `level` and RLE1 blocks of <= `limit` bytes.
    fn bz_encode(data: &[u8], level: u8, limit: usize) -> Vec<u8> {
        let mut w = BitW { out: vec![b'B', b'Z', b'h', b'0' + level], acc: 0, n: 0 };
        let mut combined = 0u32;
        for (orig, enc) in rle1_blocks(data, limit) {
            let crc = crc32_bzip2(orig);
            combined = combined.rotate_left(1) ^ crc;
            encode_block(&mut w, &enc, crc);
        }
        w.put(END_MAGIC, 48);
        w.put(combined as u64, 32);
        w.finish()
    }

    fn xorshift(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    /// Deterministic test data: 0 random, 1 text-like, 2 runs of 1..600, 3 periodic,
    /// 4 zero pages with some noise.
    fn sample(kind: u32, len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed | 1;
        let mut v = Vec::with_capacity(len);
        match kind {
            0 => v.extend((0..len).map(|_| xorshift(&mut s) as u8)),
            1 => {
                const WORDS: [&str; 12] =
                    ["the", "kernel", "struct", "_EPROCESS", "offset", "0x", "type", "pointer", "{", "}", ",", "\n    "];
                while v.len() < len {
                    v.extend_from_slice(WORDS[(xorshift(&mut s) % 12) as usize].as_bytes());
                    v.push(b' ');
                }
            }
            2 => {
                while v.len() < len {
                    let b = xorshift(&mut s) as u8;
                    let n = (xorshift(&mut s) % 600) as usize + 1;
                    v.extend(std::iter::repeat_n(b, n));
                }
            }
            3 => {
                let p = (seed % 7 + 2) as usize;
                let pat: Vec<u8> = (0..p).map(|i| b'a' + i as u8).collect();
                while v.len() < len {
                    v.extend_from_slice(&pat);
                }
            }
            _ => {
                while v.len() < len {
                    if xorshift(&mut s).is_multiple_of(4) {
                        v.extend((0..4096).map(|_| xorshift(&mut s) as u8 & 7));
                    } else {
                        v.extend(std::iter::repeat_n(0, 4096));
                    }
                }
            }
        }
        v.truncate(len);
        v
    }

    fn assert_same(bz: &[u8], want: &[u8]) {
        assert_eq!(decompress_threads(bz, 1).unwrap(), want, "single-threaded");
        assert_eq!(decompress_threads(bz, 4).unwrap(), want, "4 threads");
        assert_eq!(decompress(bz).unwrap(), want, "default threads");
    }

    // ---------------------------------------------------------------------------------
    // Vectors from the real bzip2 1.0.8 (see scratch gen script; python bz2 agrees).
    // ---------------------------------------------------------------------------------

    // printf 'hello hello hello hello\n' | bzip2 -9
    const BZ: &[u8] = &[
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x6f, 0x4f, 0x10, 0xf3, 0x00, 0x00,
        0x05, 0xd1, 0x00, 0x00, 0x10, 0x40, 0x00, 0x02, 0x44, 0xa0, 0x00, 0x30, 0xc0, 0x02, 0xa8, 0x34,
        0x71, 0x0d, 0xad, 0x87, 0x0f, 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0x6f, 0x4f, 0x10, 0xf3,
    ];
    const HELLO: &[u8] = b"hello hello hello hello\n";

    const LEVEL_TEXT_LEN: usize = 1910;
    // bzip2 -9 of 40 numbered lines; -1..-8 differ only in byte 3 (verified)
    const LEVEL9: &[u8] = &[
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xb8, 0x72, 0x18, 0x73, 0x00, 0x00, 0xc8, 0xd9, 0x80, 0x00,
        0x10, 0x40, 0x00, 0x7f, 0xf0, 0x3f, 0xff, 0xff, 0xf0, 0x30, 0x00, 0xfa, 0x40, 0x69, 0x1f, 0xaa, 0xa3, 0xf5, 0x47, 0xfa,
        0xa8, 0x68, 0x0f, 0x50, 0x0c, 0x80, 0x03, 0x06, 0x9a, 0x34, 0xd3, 0x09, 0x89, 0x93, 0x01, 0x03, 0x4c, 0x0a, 0x55, 0x26,
        0xa0, 0x00, 0x01, 0xa0, 0xd0, 0xda, 0x9b, 0x6a, 0x4f, 0x31, 0x36, 0x89, 0x81, 0x3e, 0x84, 0xc0, 0x9e, 0xc2, 0x68, 0x26,
        0x42, 0x68, 0x4a, 0x15, 0x92, 0x50, 0xb4, 0x66, 0xbb, 0x4d, 0x54, 0x20, 0xa9, 0x45, 0x08, 0x02, 0x21, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x52, 0x81, 0x65, 0xa8, 0x31, 0xeb, 0xd9, 0xb7, 0x75, 0xb2, 0xba, 0x36, 0xdb, 0x6d, 0xe4, 0x6e, 0xad,
        0xb6, 0xdb, 0x99, 0x99, 0x99, 0xe6, 0xfb, 0x13, 0xd4, 0x4d, 0xc2, 0x64, 0x26, 0xe0, 0x9a, 0x89, 0xb0, 0x4d, 0xe2, 0x70,
        0x09, 0xa8, 0x99, 0x89, 0xf8, 0x26, 0x42, 0x6c, 0x13, 0x02, 0x6f, 0x13, 0x31, 0x36, 0x89, 0xa0, 0x9c, 0x04, 0xcc, 0x4f,
        0x91, 0x3f, 0x84, 0xd4, 0x4c, 0xc2, 0x60, 0x4c, 0x09, 0xdc, 0x2a, 0xe2, 0x27, 0x11, 0x3f, 0xc5, 0xdc, 0x91, 0x4e, 0x14,
        0x24, 0x2e, 0x1c, 0x86, 0x1c, 0xc0,
    ];
    // bzip2 -9 of an empty file
    const EMPTY: &[u8] = &[
        0x42, 0x5a, 0x68, 0x39, 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0x00, 0x00, 0x00, 0x00,
    ];
    const RUNS_LEN: usize = 45450;
    // bzip2 -9 of runs of 1..=300 identical bytes separated by 'x'
    const RUNS: &[u8] = &[
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xa6, 0xbd, 0x78, 0x29, 0x00, 0x00, 0x05, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x50, 0x04, 0x5e, 0x00, 0x3c, 0x18, 0x73, 0xc0, 0x0c,
        0x4b, 0xf5, 0x4f, 0xd5, 0x03, 0xff, 0xd5, 0x52, 0x7e, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x69, 0xef, 0xfd, 0x55, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x6f, 0xf5, 0x25, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x06, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xef, 0xf5, 0x53, 0xfd, 0x55, 0x41, 0x31, 0xff, 0xea, 0xaa, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0xff, 0xd5, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x34, 0x25, 0xff, 0xea, 0xa7, 0xfa, 0xaa, 0x8d, 0x1e, 0xff, 0x55, 0x51, 0xa0, 0x0d, 0x1a, 0x68, 0x03,
        0x43, 0x46, 0x9a, 0x0c, 0x8c, 0x20, 0x00, 0x1a, 0x01, 0xa0, 0x64, 0xc8, 0x01, 0xa0, 0x31, 0x1a, 0x68, 0x00, 0xd0, 0xd0,
        0x18, 0x83, 0x40, 0x32, 0x06, 0x26, 0x99, 0x01, 0x88, 0x19, 0x18, 0x9a, 0x00, 0x19, 0x34, 0xd0, 0x00, 0x1a, 0x64, 0x06,
        0x08, 0x00, 0x1a, 0x01, 0x29, 0x4f, 0xd5, 0x4d, 0xfa, 0xaa, 0xa1, 0xe7, 0xa7, 0xea, 0xa7, 0xfa, 0xaa, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x37, 0xfb, 0x4c, 0x5a, 0xe5, 0x7b, 0x15, 0x2c, 0xc1, 0xbf, 0x7a,
        0xf6, 0x0d, 0x96, 0x17, 0xe5, 0x5e, 0x24, 0x2e, 0xc2, 0x53, 0x16, 0x96, 0x17, 0xe9, 0x61, 0x45, 0xa5, 0x87, 0xfd, 0x38,
        0xc5, 0xea, 0x86, 0x58, 0xec, 0x27, 0x19, 0x55, 0x0c, 0x68, 0x27, 0x1a, 0x54, 0x45, 0xac, 0x44, 0xe3, 0x6a, 0x88, 0x6c,
        0x44, 0xe3, 0x8a, 0x88, 0x6c, 0x44, 0xe3, 0xaa, 0x88, 0x6c, 0x44, 0xe3, 0xca, 0x88, 0x6c, 0x44, 0xe3, 0xea, 0x88, 0x6c,
        0x44, 0xe4, 0x0a, 0x88, 0x6c, 0x44, 0xe4, 0x2a, 0x88, 0x6c, 0x44, 0xe4, 0x4a, 0x88, 0x6c, 0x44, 0xe4, 0x6a, 0x88, 0x6c,
        0x44, 0xe4, 0x8a, 0x88, 0x6c, 0x44, 0xe4, 0xaa, 0x88, 0x6c, 0x44, 0xe4, 0xca, 0x88, 0x6c, 0x44, 0xe4, 0xea, 0x88, 0x6c,
        0x44, 0xe5, 0x0a, 0x88, 0x6c, 0x44, 0xe5, 0x2a, 0x88, 0x6c, 0x44, 0xe5, 0x4a, 0x88, 0x6c, 0x44, 0xe5, 0x6a, 0x88, 0x6c,
        0x44, 0xe5, 0x8a, 0x88, 0x6c, 0x44, 0xe5, 0xaa, 0x88, 0x6c, 0x44, 0xe5, 0xca, 0x88, 0x6c, 0x44, 0xe5, 0xea, 0x88, 0x6c,
        0x44, 0xe6, 0x0a, 0x88, 0x6c, 0x44, 0xe6, 0x2a, 0x88, 0x6c, 0x44, 0xe6, 0x4a, 0x88, 0x6c, 0x44, 0xe6, 0x6a, 0x88, 0x6c,
        0x44, 0xe6, 0x8a, 0x88, 0x6c, 0x44, 0xe6, 0xaa, 0x88, 0x6c, 0x44, 0xe6, 0xca, 0x88, 0x6c, 0x44, 0xe6, 0xea, 0x88, 0x6c,
        0x44, 0xe7, 0x0a, 0x88, 0x6c, 0x44, 0xe7, 0x2a, 0x88, 0x6c, 0x44, 0xe7, 0x4a, 0x88, 0x6c, 0x46, 0x77, 0x84, 0xa8, 0x86,
        0xc4, 0x4d, 0x98, 0x44, 0x5b, 0x68, 0x8b, 0xf6, 0x49, 0x16, 0xda, 0x22, 0xeb, 0x2f, 0x91, 0x6d, 0xa2, 0x2e, 0xb2, 0xe2,
        0x2d, 0xb4, 0x46, 0x79, 0x65, 0xc4, 0x5b, 0x68, 0x8c, 0xf6, 0xcb, 0x88, 0xb6, 0xd1, 0x19, 0xf5, 0x97, 0x11, 0x6d, 0xa2,
        0x33, 0xfb, 0x2e, 0x22, 0xdb, 0x44, 0x68, 0x16, 0x5d, 0x17, 0xb4, 0x1b, 0xa1, 0x68, 0x57, 0x42, 0xd0, 0xee, 0x85, 0xa2,
        0x60, 0xc2, 0xd1, 0x70, 0x21, 0x68, 0xd8, 0x00, 0xdc, 0xd0, 0x37, 0x44, 0x0d, 0xd5, 0x03, 0x76, 0x40, 0xdd, 0xd0, 0x37,
        0x84, 0x0d, 0xe5, 0x03, 0x7a, 0x40, 0xb9, 0xa0, 0x6f, 0x68, 0x1b, 0xe2, 0x06, 0xfa, 0x81, 0xbf, 0x20, 0x6f, 0xe8, 0x1c,
        0x02, 0x07, 0x02, 0x81, 0x74, 0x40, 0xe0, 0x90, 0x38, 0x34, 0x0e, 0x11, 0x03, 0x85, 0x40, 0xe1, 0x90, 0x2e, 0xa8, 0x17,
        0x64, 0x0e, 0x1d, 0x02, 0xee, 0x81, 0x78, 0x40, 0xe2, 0x10, 0x38, 0x94, 0x0e, 0x29, 0x03, 0x8b, 0x40, 0xe3, 0x10, 0x38,
        0xd4, 0x0e, 0x39, 0x03, 0x8f, 0x40, 0xe4, 0x10, 0x2f, 0x28, 0x1c, 0x8a, 0x07, 0x24, 0x81, 0xc9, 0xa0, 0x72, 0x88, 0x1c,
        0xaa, 0x07, 0x2c, 0x81, 0x7a, 0x40, 0xbd, 0xa0, 0x5f, 0x10, 0x39, 0x74, 0x0e, 0x61, 0x02, 0xfa, 0x81, 0xcc, 0xa0, 0x5f,
        0x90, 0x39, 0xa4, 0x0e, 0x6d, 0x03, 0x9c, 0x40, 0xe7, 0x50, 0x39, 0xe4, 0x0e, 0x7d, 0x03, 0xa0, 0x40, 0xb1, 0x0c, 0x34,
        0x2c, 0x41, 0xd1, 0x30, 0x62, 0x18, 0x68, 0xd8, 0x83, 0x87, 0x86, 0x6b, 0x03, 0xf8, 0x88, 0x30, 0xb0, 0xbf, 0xe2, 0xbe,
        0x40, 0x50, 0x14, 0x08, 0x44, 0x24, 0x92, 0x48, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42, 0x10,
        0x84, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0x0a, 0x6e, 0x84, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x81, 0x07, 0x61, 0xc6, 0x28, 0x81, 0x89, 0x85, 0x89, 0x80, 0x42, 0x62,
        0xf1, 0x98, 0xdc, 0x76, 0x3f, 0x21, 0x91, 0xc9, 0x64, 0xf2, 0x99, 0x5c, 0xb6, 0x5f, 0x31, 0x99, 0xcd, 0x4b, 0xcc, 0x4c,
        0xcd, 0x4d, 0xce, 0x4e, 0xcf, 0x4f, 0xd0, 0x50, 0xd1, 0x51, 0xd2, 0x52, 0xd3, 0x53, 0xd4, 0x54, 0xd5, 0x55, 0xd6, 0x56,
        0xd7, 0x57, 0xd8, 0x58, 0xd9, 0x59, 0xda, 0x5a, 0xdb, 0x5b, 0xdc, 0x5c, 0xdd, 0x5d, 0xde, 0x5e, 0xdf, 0x5f, 0xe0, 0x60,
        0xe1, 0x61, 0xe2, 0x62, 0xe3, 0x63, 0xe4, 0x64, 0xe5, 0x65, 0xe6, 0x66, 0xe7, 0x67, 0xe8, 0x68, 0xe9, 0x69, 0xea, 0x6a,
        0xeb, 0x6b, 0xec, 0x6c, 0xed, 0x6d, 0xee, 0x6e, 0xef, 0x6f, 0xf0, 0x70, 0xf1, 0x71, 0xf2, 0x72, 0xf3, 0x73, 0xf4, 0x74,
        0xf5, 0x75, 0xf6, 0x76, 0xf7, 0x77, 0xf8, 0x78, 0xf9, 0x79, 0xfa, 0x7a, 0xfb, 0x7b, 0xfc, 0x7c, 0xfd, 0x7e, 0xff, 0x90,
        0x9f, 0xdc, 0x05, 0xf2, 0x0c, 0x0c, 0x1e, 0x06, 0xfd, 0x06, 0x03, 0x78, 0x08, 0x30, 0x0b, 0xc0, 0xc1, 0x80, 0x5b, 0x83,
        0x00, 0xb8, 0x88, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02,
        0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d,
        0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0,
        0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02,
        0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d,
        0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0,
        0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02,
        0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d,
        0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x2d, 0x02, 0xd0, 0x30, 0x88, 0x18, 0x44, 0x0c, 0x22,
        0x0e, 0xc1, 0x79, 0xc7, 0x60, 0xbc, 0xe3, 0xb0, 0x5e, 0x71, 0xd7, 0xde, 0x71, 0xd7, 0xde, 0x71, 0xd7, 0xde, 0x71, 0xd7,
        0xde, 0x71, 0xd6, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x86, 0xfe,
        0xff, 0x3f, 0x6c, 0xcc, 0xcc, 0xcc, 0xcc, 0xcf, 0xd0, 0x9c, 0x9c, 0xff, 0xc5, 0xdc, 0x91, 0x4e, 0x14, 0x24, 0x29, 0xaf,
        0x5e, 0x0a, 0x40,
    ];
    // all 256 byte values, each three times (shuffled)
    const ALL_BYTES_SRC: &[u8] = &[
        0x40, 0xee, 0x95, 0xf7, 0xc4, 0xd1, 0xe2, 0x37, 0xa2, 0xa5, 0x54, 0x22, 0x13, 0xf6, 0x93, 0x4a, 0x5d, 0xf7, 0x8c, 0x2c,
        0x2b, 0xc9, 0x97, 0x68, 0x35, 0x5a, 0x75, 0xc5, 0x0d, 0x1e, 0xdb, 0xce, 0x6a, 0x5a, 0x4b, 0x63, 0x32, 0x1b, 0x5e, 0x68,
        0xb2, 0xd8, 0xde, 0x11, 0x04, 0x71, 0xf3, 0xf9, 0xcb, 0x4d, 0xe1, 0x1b, 0x81, 0x1d, 0xab, 0x6c, 0xfe, 0x21, 0x91, 0xed,
        0x54, 0x25, 0x8a, 0xa9, 0x9a, 0xc5, 0x43, 0xfe, 0x50, 0xef, 0xa8, 0x0f, 0x24, 0x73, 0xd8, 0x0b, 0x61, 0x93, 0x6b, 0x7f,
        0x34, 0xe7, 0x73, 0x8e, 0x7f, 0xdf, 0x48, 0x00, 0xb3, 0x43, 0x3d, 0x45, 0xca, 0x5c, 0x7e, 0xc9, 0x4a, 0x41, 0x0a, 0x43,
        0x9f, 0x5c, 0x14, 0x7d, 0x1f, 0x6a, 0x90, 0xce, 0xf5, 0x79, 0x03, 0x0b, 0xd9, 0x67, 0x41, 0x77, 0x8f, 0xcf, 0x49, 0xe3,
        0xb4, 0x0f, 0xc9, 0xf9, 0xea, 0xbd, 0x20, 0xea, 0xb8, 0xbf, 0xa3, 0xd0, 0x38, 0x44, 0x4c, 0xa2, 0xd4, 0x42, 0x3e, 0xa5,
        0x12, 0x9e, 0x51, 0x95, 0xa1, 0x6f, 0xc7, 0x3f, 0xbd, 0xc4, 0x9a, 0xe7, 0xb5, 0xc5, 0xa4, 0x52, 0xfd, 0x42, 0x6c, 0x53,
        0xb2, 0x66, 0x72, 0x61, 0xf3, 0x71, 0xe2, 0x58, 0xb8, 0xfd, 0xe9, 0x19, 0xa6, 0x41, 0xab, 0x86, 0x47, 0x8b, 0x01, 0x42,
        0x62, 0x59, 0xf1, 0x64, 0xad, 0xd3, 0x17, 0x64, 0x91, 0xad, 0xe4, 0x06, 0x71, 0xfb, 0x9f, 0x92, 0x83, 0x78, 0x09, 0xa6,
        0x98, 0x76, 0xdc, 0x7a, 0xb3, 0x2a, 0x55, 0xdf, 0x85, 0xb2, 0x4b, 0x4f, 0xd2, 0xb1, 0xc4, 0xdb, 0x28, 0x5e, 0x4e, 0xf9,
        0xc3, 0x38, 0x0c, 0x38, 0xa5, 0x6b, 0xbf, 0xd6, 0x2e, 0x76, 0xe8, 0x23, 0x4a, 0xef, 0x92, 0xf2, 0x1c, 0x1e, 0x3d, 0x74,
        0xbb, 0x0d, 0x1a, 0xd5, 0x2e, 0xef, 0xa6, 0x8d, 0x27, 0xa1, 0x87, 0x9f, 0xa0, 0x46, 0x99, 0xd4, 0x76, 0xe6, 0xcb, 0xde,
        0x0e, 0x9c, 0x2a, 0x46, 0x6d, 0x30, 0xe0, 0xd5, 0x97, 0xf1, 0x6b, 0x57, 0x01, 0xca, 0x3e, 0x98, 0x60, 0xd1, 0x8e, 0x80,
        0xdc, 0x32, 0x78, 0x8c, 0x65, 0x4c, 0x50, 0x4e, 0xdd, 0x99, 0x32, 0x5a, 0x1b, 0x79, 0x10, 0x53, 0x30, 0x69, 0xc2, 0x8e,
        0x07, 0x36, 0x9c, 0x7e, 0x26, 0x4c, 0x5b, 0xc1, 0x04, 0xe6, 0x56, 0x00, 0x03, 0x25, 0xd3, 0xfc, 0xb7, 0x94, 0x82, 0x0b,
        0x8b, 0x3b, 0xce, 0xf8, 0xcc, 0x87, 0x7c, 0x0a, 0xe8, 0x51, 0x2f, 0xaf, 0x72, 0x74, 0x16, 0x88, 0x58, 0x7d, 0x9b, 0x62,
        0xb1, 0x5f, 0xa9, 0x40, 0x67, 0xc7, 0x4d, 0xdb, 0x9e, 0x26, 0xdf, 0xa4, 0xe5, 0x2d, 0x8f, 0xb6, 0xb8, 0x7e, 0x14, 0x9d,
        0x87, 0x70, 0x69, 0x86, 0xb6, 0x52, 0xf0, 0xb9, 0xf6, 0x3c, 0xaa, 0xe1, 0x81, 0xe9, 0xa3, 0x85, 0x79, 0x20, 0x7c, 0xbb,
        0xc8, 0x98, 0x57, 0x23, 0x80, 0xa9, 0x89, 0x0d, 0xa0, 0x22, 0x19, 0x0f, 0x33, 0xa1, 0xf4, 0x6c, 0x81, 0xb9, 0x96, 0x15,
        0x8d, 0x55, 0x34, 0x7c, 0x51, 0xc6, 0x5c, 0xe7, 0x3f, 0x3b, 0x52, 0xd7, 0xbe, 0xf4, 0x7a, 0xf4, 0xca, 0x2f, 0xc3, 0xd3,
        0x2e, 0x07, 0x57, 0xbf, 0x06, 0xb3, 0x7a, 0x17, 0xac, 0x37, 0x8d, 0xe9, 0xd8, 0xf2, 0xc2, 0x97, 0xba, 0xfe, 0x29, 0x21,
        0x72, 0x19, 0x24, 0x27, 0xc1, 0x90, 0x2c, 0x3a, 0xd9, 0xda, 0xfd, 0x77, 0x4b, 0x9d, 0x12, 0xfa, 0x25, 0xd0, 0xb7, 0x3a,
        0x35, 0x8a, 0x1a, 0xcf, 0x45, 0xfa, 0xc6, 0x6e, 0xcb, 0x35, 0xbc, 0xee, 0x3c, 0x3a, 0xf7, 0xad, 0xbc, 0x82, 0xae, 0x44,
        0x33, 0xaa, 0xf6, 0xff, 0x6d, 0x5e, 0xd2, 0x64, 0x56, 0x44, 0x2b, 0x14, 0x73, 0x70, 0xfb, 0xeb, 0x89, 0xb6, 0x11, 0x49,
        0xd7, 0xc3, 0xd4, 0xb0, 0x18, 0xdd, 0xc0, 0xac, 0x31, 0x59, 0x88, 0xda, 0xb7, 0x5b, 0x8a, 0x4f, 0x16, 0xa0, 0xed, 0x20,
        0x9b, 0x4d, 0x63, 0xbc, 0x7b, 0xc7, 0xf1, 0x6a, 0xf8, 0xc6, 0xf0, 0x83, 0x65, 0x63, 0xcd, 0x83, 0x1d, 0x09, 0xaf, 0xd7,
        0xde, 0x26, 0x08, 0x85, 0x02, 0xcd, 0xa2, 0x2b, 0x3d, 0x4e, 0x65, 0x39, 0x30, 0xd9, 0x80, 0x31, 0x3c, 0x7d, 0x48, 0x94,
        0xe5, 0x18, 0xe4, 0xcd, 0x10, 0xe1, 0x2d, 0x82, 0x06, 0xec, 0xa4, 0x24, 0x95, 0x96, 0x12, 0xe6, 0x15, 0xba, 0xf5, 0x0a,
        0x03, 0x6f, 0x08, 0xc0, 0xaf, 0x5f, 0x8b, 0x3f, 0x18, 0x74, 0xe5, 0xfc, 0x49, 0xd1, 0x2d, 0x17, 0x9a, 0xda, 0x67, 0xa3,
        0xab, 0x47, 0x29, 0x90, 0xbd, 0x70, 0x8c, 0xff, 0x1f, 0x0e, 0xcf, 0x11, 0x55, 0x48, 0x21, 0xfc, 0x34, 0x5d, 0xb9, 0x56,
        0x33, 0xb5, 0xeb, 0x1c, 0x66, 0xd5, 0x53, 0x29, 0x27, 0x01, 0x62, 0xb4, 0x6d, 0xf0, 0xa7, 0x04, 0x9c, 0x37, 0x47, 0x75,
        0xec, 0x39, 0xb4, 0xd2, 0x3e, 0x13, 0x84, 0x0c, 0x88, 0x05, 0x6f, 0x94, 0x13, 0xd0, 0x69, 0x4f, 0x60, 0x0e, 0x9e, 0xed,
        0xb0, 0x28, 0xcc, 0x0c, 0xe8, 0x02, 0xac, 0xae, 0x96, 0x93, 0x50, 0x5f, 0x75, 0x3b, 0x2c, 0xe0, 0x1e, 0xf5, 0x7b, 0xba,
        0x15, 0xa7, 0x6e, 0x08, 0xa7, 0xc1, 0x58, 0x7f, 0x31, 0x77, 0xb1, 0xa8, 0xa8, 0x9d, 0xf8, 0xeb, 0x23, 0x5b, 0x92, 0x05,
        0xff, 0x59, 0x22, 0x36, 0xc2, 0xae, 0x07, 0xdc, 0x00, 0x54, 0x7b, 0x2f, 0x84, 0xbe, 0x66, 0x91, 0x39, 0xaa, 0xe4, 0x28,
        0xd6, 0xe0, 0xb5, 0xec, 0x61, 0xee, 0x36, 0xfa, 0xc0, 0xe3, 0x1c, 0xf2, 0xb0, 0xdd, 0xbe, 0x86, 0x09, 0x2a, 0x99, 0x1a,
        0x16, 0x1f, 0x45, 0x68, 0x5d, 0xea, 0xe2, 0x10, 0xc8, 0xc8, 0x02, 0x6e, 0xbb, 0x8f, 0x1d, 0xf3, 0x60, 0xd6, 0x84, 0x9b,
        0xe3, 0xcc, 0xfb, 0x78, 0x05, 0x40, 0x46, 0x89,
    ];
    // bzip2 -9 of ALL_BYTES_SRC
    const ALL_BYTES: &[u8] = &[
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xb4, 0x8c, 0x81, 0x4f, 0x00, 0x00, 0x61, 0x7f, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x02, 0x1b, 0x36, 0xdb, 0xa6, 0xb4, 0x24, 0x1a,
        0x32, 0x03, 0x6a, 0x0d, 0x06, 0xd4, 0x0c, 0x9e, 0xa1, 0xa0, 0xc8, 0x3d, 0x46, 0x4f, 0x50, 0xd3, 0x13, 0xd4, 0xd0, 0xc9,
        0xe9, 0x07, 0xa9, 0xea, 0x32, 0x7a, 0x9a, 0x1f, 0xaa, 0x34, 0x00, 0x1a, 0x34, 0x68, 0xc3, 0x53, 0x69, 0x1a, 0x19, 0x0d,
        0x3d, 0x40, 0x0f, 0x53, 0xd4, 0x66, 0x88, 0xd3, 0x4c, 0x46, 0x98, 0x86, 0x99, 0x00, 0xfd, 0x53, 0xd4, 0xf5, 0x33, 0x53,
        0xf5, 0x13, 0xd4, 0x78, 0x50, 0xda, 0x4f, 0x53, 0x68, 0x9e, 0xa6, 0xf5, 0x31, 0x1b, 0x4c, 0xa9, 0xfa, 0x46, 0x8d, 0x3d,
        0x35, 0x10, 0x04, 0xcd, 0x09, 0x93, 0x00, 0x68, 0x10, 0xc0, 0x13, 0x06, 0xa6, 0x13, 0x4d, 0x30, 0x21, 0x93, 0x13, 0x09,
        0x80, 0x9e, 0x40, 0x02, 0x60, 0x09, 0x81, 0x0c, 0x09, 0x80, 0x02, 0x18, 0x35, 0x01, 0x9a, 0x26, 0x00, 0x27, 0xa1, 0xa0,
        0x0d, 0x01, 0x3f, 0x50, 0x00, 0x0d, 0x32, 0x26, 0x4d, 0x0c, 0x0d, 0x4f, 0xd2, 0x0d, 0x13, 0x4c, 0x13, 0x46, 0x88, 0x00,
        0x98, 0x26, 0x46, 0x00, 0x4c, 0x13, 0x26, 0x02, 0x18, 0x1a, 0x00, 0x01, 0x30, 0x4c, 0x00, 0x09, 0x91, 0xe8, 0x00, 0x00,
        0x00, 0x0c, 0x80, 0x06, 0x91, 0x86, 0xa6, 0x4f, 0x43, 0x40, 0x00, 0x00, 0x00, 0x00, 0x68, 0x34, 0x01, 0x18, 0x1a, 0x9e,
        0x88, 0xf4, 0x8f, 0x48, 0x0c, 0x00, 0x00, 0x10, 0x4d, 0xa0, 0x00, 0xd0, 0x00, 0x00, 0x09, 0x93, 0x4c, 0x00, 0x00, 0x00,
        0x02, 0x63, 0x53, 0x13, 0x20, 0xc0, 0x02, 0x33, 0x40, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x02, 0x34, 0x64, 0x32, 0x30, 0x04,
        0x61, 0x18, 0x98, 0x99, 0x32, 0x66, 0x81, 0xa0, 0xd2, 0x36, 0x80, 0x0d, 0x00, 0x0f, 0x50, 0x0d, 0x03, 0x30, 0xb5, 0xb0,
        0x88, 0x2d, 0x22, 0x7f, 0x72, 0x71, 0x44, 0xc5, 0xa6, 0x95, 0x82, 0x01, 0xfb, 0xe7, 0x06, 0x88, 0x96, 0x9b, 0x52, 0xb6,
        0x4d, 0x8a, 0x05, 0x32, 0x50, 0x03, 0x91, 0xa0, 0x20, 0xbf, 0x09, 0xd3, 0x10, 0x5d, 0x11, 0x19, 0x81, 0x86, 0x44, 0x2b,
        0x5b, 0xa9, 0xe1, 0x1d, 0x8d, 0x1c, 0x10, 0x01, 0xf6, 0xd5, 0x76, 0x0f, 0x35, 0x6c, 0xe1, 0xe3, 0xc5, 0x17, 0xe1, 0x91,
        0x67, 0xf7, 0xc5, 0x68, 0xba, 0x50, 0xc1, 0x00, 0x47, 0xa5, 0x40, 0x0d, 0x95, 0x63, 0x4b, 0xff, 0xa0, 0x8f, 0xeb, 0x6c,
        0x90, 0xb1, 0x63, 0x1e, 0x8c, 0x49, 0x73, 0xbc, 0xd7, 0x26, 0x13, 0x1f, 0x0d, 0xce, 0x23, 0xd8, 0x07, 0xc0, 0x39, 0xcb,
        0x6a, 0xab, 0xe6, 0x10, 0x4e, 0x65, 0xde, 0xc8, 0x6b, 0xf3, 0x51, 0xb1, 0x3b, 0x7d, 0x60, 0xe7, 0x42, 0x84, 0xe0, 0x0e,
        0x82, 0x13, 0x89, 0x27, 0x79, 0x7b, 0x3b, 0xb0, 0xa0, 0xaa, 0xae, 0x08, 0x37, 0xb4, 0xfa, 0xe7, 0x1e, 0xd1, 0xa0, 0x0e,
        0xbf, 0xa5, 0x82, 0x91, 0xca, 0xe2, 0x4f, 0x38, 0xa2, 0x74, 0xf6, 0x4d, 0x87, 0x2a, 0x68, 0x72, 0xc5, 0x00, 0x5e, 0xc7,
        0xa5, 0xee, 0xaa, 0x1d, 0x76, 0x52, 0x80, 0x28, 0x89, 0x77, 0x59, 0xdb, 0x8a, 0x3d, 0xcc, 0xd5, 0xa3, 0xd5, 0x25, 0xf4,
        0x7b, 0x34, 0x2b, 0x63, 0xa9, 0xd3, 0x2d, 0x13, 0xbb, 0xdc, 0xa8, 0x1a, 0x2f, 0xd1, 0x31, 0x21, 0x19, 0x76, 0x0a, 0xd2,
        0xf0, 0x08, 0xcb, 0xd9, 0xae, 0x44, 0xb7, 0x54, 0xda, 0x12, 0x7d, 0xf1, 0x57, 0x1f, 0xa8, 0x51, 0x40, 0x03, 0xab, 0x7d,
        0xcf, 0x55, 0x0c, 0x44, 0xe7, 0x03, 0xd2, 0xc9, 0x13, 0xe3, 0x6e, 0x7f, 0x76, 0x0e, 0x04, 0x2b, 0xf3, 0x65, 0x91, 0x01,
        0x31, 0x35, 0xb0, 0x28, 0x69, 0x93, 0x40, 0xe7, 0x67, 0xfd, 0xdb, 0x45, 0xd7, 0x08, 0x93, 0xf0, 0x10, 0x9a, 0xd0, 0xc6,
        0x10, 0x19, 0x0f, 0x51, 0x98, 0x9e, 0x43, 0xc3, 0x26, 0x2e, 0x17, 0x8d, 0x40, 0x8f, 0xe4, 0x51, 0xf7, 0x28, 0x0f, 0x02,
        0x9c, 0x15, 0xda, 0xfb, 0x03, 0xd7, 0x00, 0x0a, 0xe3, 0xf5, 0xcc, 0x47, 0x0a, 0x24, 0xcb, 0x5b, 0x5d, 0x83, 0x05, 0x90,
        0xbc, 0x75, 0xf5, 0x8d, 0x40, 0xc1, 0xdd, 0xa1, 0x8c, 0x95, 0x6e, 0x07, 0xf0, 0xc5, 0x38, 0x49, 0xf3, 0x73, 0x31, 0x96,
        0x8c, 0xa7, 0x98, 0xbd, 0xa9, 0x54, 0xb5, 0x86, 0x76, 0xb4, 0xf4, 0xe1, 0x78, 0xa1, 0x42, 0xfd, 0x95, 0x2a, 0x10, 0xc2,
        0x21, 0xf1, 0x42, 0x77, 0x25, 0x84, 0xc7, 0x5d, 0x13, 0x17, 0x46, 0x83, 0x62, 0x3e, 0x01, 0xd3, 0x2e, 0x99, 0xa4, 0xe0,
        0xb0, 0x29, 0x3f, 0xa0, 0x9c, 0x7f, 0xcb, 0x3e, 0xa1, 0xc2, 0xc0, 0xb5, 0x9f, 0xcc, 0x42, 0xac, 0x61, 0x82, 0xb5, 0x6c,
        0x36, 0x35, 0x06, 0x40, 0x72, 0x0e, 0x51, 0x5d, 0x64, 0x0f, 0x89, 0x35, 0x42, 0x33, 0x55, 0x1c, 0x5b, 0x3b, 0x2c, 0xfe,
        0xf9, 0xfc, 0x8a, 0xfd, 0x8f, 0x7d, 0x84, 0xc3, 0x6d, 0x58, 0x35, 0xd9, 0x34, 0x5c, 0xb4, 0xdc, 0xa3, 0x7c, 0xe3, 0x98,
        0x79, 0x32, 0x28, 0x96, 0x8b, 0x63, 0x2a, 0xa4, 0xea, 0x5a, 0x51, 0xfa, 0x94, 0x33, 0xa5, 0x51, 0x31, 0xb0, 0x78, 0xed,
        0xdc, 0xbd, 0xbe, 0x4a, 0x37, 0x37, 0x42, 0x1b, 0x3e, 0x08, 0xb2, 0xf1, 0x16, 0x5f, 0x96, 0x8e, 0x60, 0xee, 0xb6, 0x8b,
        0x9e, 0xa0, 0xb1, 0xcd, 0x05, 0xd6, 0x98, 0x46, 0x18, 0x22, 0xa2, 0x04, 0xd9, 0x65, 0x80, 0xd7, 0xbf, 0x69, 0x37, 0xaf,
        0x07, 0x2d, 0x42, 0xf8, 0xb1, 0x0f, 0xb8, 0x7f, 0x20, 0x15, 0xc0, 0x9c, 0x47, 0xf0, 0x34, 0xcb, 0x53, 0x0e, 0x5a, 0xc1,
        0x31, 0xc1, 0x3c, 0x41, 0x63, 0xed, 0x89, 0x0c, 0x6c, 0xa8, 0x8e, 0xd2, 0x19, 0xb4, 0x36, 0x73, 0x68, 0xc1, 0x02, 0x71,
        0x04, 0x1c, 0xcc, 0x92, 0x55, 0x1e, 0x44, 0xe9, 0x48, 0x96, 0xb5, 0x66, 0x5d, 0x7e, 0x72, 0x90, 0x41, 0xea, 0xec, 0x5b,
        0x9e, 0xc0, 0xb1, 0x5c, 0x74, 0x02, 0x05, 0x43, 0xda, 0x72, 0x32, 0x2c, 0x6d, 0x19, 0xce, 0x8e, 0x6b, 0x6c, 0x4b, 0xf6,
        0x0b, 0xcb, 0x01, 0x09, 0xfe, 0xb9, 0x71, 0x1a, 0x50, 0x99, 0x03, 0xb9, 0x17, 0xd8, 0xec, 0xd0, 0x36, 0xb8, 0x2a, 0xc3,
        0xe0, 0x78, 0x8c, 0x04, 0x88, 0x06, 0xad, 0xc8, 0x86, 0xcc, 0x1b, 0xc6, 0x28, 0x37, 0x3a, 0xaf, 0xa7, 0xe1, 0x45, 0xd7,
        0xd5, 0x13, 0xfb, 0x0f, 0x98, 0xa5, 0xc2, 0x42, 0x14, 0x00, 0x44, 0xf3, 0xec, 0x8f, 0xc4, 0xc6, 0x63, 0x01, 0xdf, 0xfb,
        0x72, 0xa3, 0xe6, 0xd4, 0x0e, 0xfa, 0xba, 0x99, 0xdd, 0x60, 0xd6, 0x11, 0xce, 0x3f, 0x76, 0xf5, 0x6c, 0x88, 0xd3, 0x36,
        0x18, 0x5b, 0x6f, 0x6b, 0xb1, 0x48, 0x12, 0x62, 0x7c, 0xc4, 0x9e, 0x78, 0x0d, 0xf1, 0xcf, 0x0a, 0x90, 0x4d, 0xc4, 0xc4,
        0xd1, 0x5f, 0xa5, 0x51, 0x6f, 0x7b, 0x93, 0x65, 0x71, 0x6d, 0x27, 0x8d, 0x46, 0x44, 0xc3, 0x4e, 0x6c, 0xef, 0x47, 0xed,
        0x90, 0x0d, 0x4c, 0x13, 0x01, 0x2b, 0x59, 0xaf, 0x10, 0xc8, 0x4d, 0x4f, 0xa8, 0x66, 0x61, 0x1b, 0xae, 0x61, 0x3a, 0x9e,
        0xb9, 0x22, 0x41, 0xa4, 0xd9, 0x17, 0x79, 0xd4, 0x79, 0xc2, 0x74, 0x55, 0x08, 0x1a, 0x57, 0xd3, 0xf1, 0x6a, 0xdd, 0x94,
        0x27, 0x20, 0x87, 0x94, 0x28, 0x16, 0x3b, 0xa4, 0x19, 0x92, 0xab, 0xa1, 0x77, 0x24, 0x53, 0x85, 0x09, 0x0b, 0x48, 0xc8,
        0x14, 0xf0,
    ];
    // bzip2 -1 of 330000 bytes of 'abc..z' repeated (4 blocks)
    const MULTI: &[u8] = &[
        0x42, 0x5a, 0x68, 0x31, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xce, 0x71, 0x4a, 0x19, 0x00, 0x07, 0x82, 0x81, 0x80, 0x3f,
        0xff, 0xff, 0xf0, 0x30, 0x00, 0xf8, 0x02, 0x80, 0x00, 0x03, 0x26, 0x41, 0x40, 0x00, 0x01, 0x93, 0x20, 0x29, 0x55, 0x0d,
        0x03, 0x26, 0x80, 0x34, 0x69, 0xac, 0x81, 0x56, 0x5b, 0x54, 0x0a, 0xb7, 0x28, 0x15, 0x60, 0xa0, 0x55, 0xbd, 0x40, 0xab,
        0x82, 0x81, 0x57, 0x15, 0x02, 0xae, 0x4a, 0x05, 0x5c, 0xd4, 0x0a, 0xb1, 0x50, 0x2a, 0xc9, 0x40, 0xab, 0x19, 0x02, 0xae,
        0x92, 0x05, 0x59, 0xc8, 0x15, 0x75, 0x90, 0x2a, 0xed, 0x20, 0x55, 0xde, 0x40, 0xab, 0xc4, 0x81, 0x57, 0x99, 0x02, 0xaf,
        0x52, 0x05, 0x5e, 0xe4, 0x0a, 0xbe, 0x48, 0x15, 0x69, 0x20, 0x55, 0xf6, 0x40, 0xab, 0xf4, 0x81, 0x56, 0xb2, 0x05, 0x5f,
        0xcc, 0x50, 0x56, 0x49, 0x94, 0xd6, 0x6b, 0xc5, 0x1b, 0xf0, 0xc0, 0x16, 0x87, 0x80, 0x60, 0x0f, 0xff, 0xff, 0xfc, 0x0c,
        0x00, 0x3e, 0x00, 0xa0, 0x00, 0x00, 0xc9, 0x90, 0x50, 0x00, 0x00, 0x64, 0xc8, 0x0a, 0x55, 0x43, 0x40, 0xc9, 0xa0, 0x0d,
        0x1a, 0x6b, 0x20, 0x55, 0xb2, 0x40, 0xab, 0x6c, 0x81, 0x56, 0xe9, 0x02, 0xac, 0x24, 0x0a, 0xb7, 0xc8, 0x15, 0x70, 0x90,
        0x2a, 0xe3, 0x20, 0x55, 0xca, 0x40, 0xab, 0x9c, 0x81, 0x56, 0x32, 0x05, 0x59, 0x48, 0x15, 0x69, 0x9a, 0x81, 0x57, 0x55,
        0x02, 0xae, 0xca, 0x05, 0x5d, 0xd4, 0x0a, 0xbc, 0x28, 0x15, 0x79, 0x50, 0x2a, 0xf4, 0xa0, 0x55, 0xed, 0x40, 0xab, 0xe2,
        0x81, 0x56, 0x8a, 0x05, 0x58, 0xc8, 0x15, 0x7d, 0x90, 0x2a, 0xfd, 0x20, 0x55, 0xac, 0x81, 0x57, 0xf3, 0x14, 0x15, 0x92,
        0x65, 0x35, 0x93, 0x1d, 0xc5, 0x62, 0x40, 0x0a, 0x53, 0xa8, 0x18, 0x03, 0xff, 0xff, 0xff, 0x03, 0x00, 0x0f, 0x80, 0x28,
        0x00, 0x00, 0x32, 0x64, 0x14, 0x00, 0x00, 0x19, 0x32, 0x02, 0x95, 0x51, 0xa0, 0xd0, 0x34, 0xc8, 0x06, 0x9a, 0xa8, 0x15,
        0x6c, 0x50, 0x2a, 0xda, 0xa0, 0x55, 0x82, 0x81, 0x56, 0xe5, 0x02, 0xad, 0xea, 0x05, 0x5c, 0x14, 0x0a, 0xb8, 0xc8, 0x15,
        0x63, 0x20, 0x55, 0xca, 0x40, 0xab, 0x9c, 0x81, 0x57, 0x49, 0x02, 0xae, 0xb2, 0x05, 0x5d, 0xa4, 0x0a, 0xb2, 0x90, 0x2a,
        0xef, 0x20, 0x55, 0x9c, 0x81, 0x56, 0x92, 0x05, 0x5e, 0x24, 0x0a, 0xbc, 0xc8, 0x15, 0x7a, 0x90, 0x2a, 0xf7, 0x20, 0x55,
        0x97, 0xc9, 0x02, 0xaf, 0xaa, 0x05, 0x5f, 0x94, 0x0a, 0xb5, 0x50, 0x2a, 0xfe, 0x62, 0x82, 0xb2, 0x4c, 0xa6, 0xb3, 0xd5,
        0xfc, 0x60, 0x94, 0x00, 0x24, 0x20, 0x03, 0x00, 0x7f, 0xff, 0xff, 0xe0, 0x60, 0x01, 0xb0, 0x0a, 0x00, 0x00, 0x0c, 0x99,
        0x05, 0x00, 0x00, 0x06, 0x4c, 0x80, 0xa5, 0x54, 0x0d, 0x06, 0x99, 0x00, 0xd1, 0xa6, 0xa4, 0x11, 0xb0, 0x82, 0x36, 0x90,
        0x46, 0xe2, 0x08, 0xde, 0x41, 0x1c, 0x08, 0x23, 0x02, 0x08, 0xe2, 0x41, 0x1c, 0xa4, 0x11, 0xcc, 0x82, 0x3a, 0x10, 0x46,
        0x24, 0x11, 0xd4, 0x82, 0x32, 0x20, 0x8c, 0xc8, 0x23, 0xb1, 0x04, 0x77, 0x20, 0x8f, 0x04, 0x11, 0xe4, 0x82, 0x3d, 0x10,
        0x47, 0xb2, 0x08, 0xf8, 0x41, 0x1a, 0x10, 0x47, 0xd2, 0x08, 0xfc, 0x41, 0x1a, 0x90, 0x47, 0xf1, 0x77, 0x24, 0x53, 0x85,
        0x09, 0x04, 0x69, 0xd7, 0x3c, 0x20,
    ];

    fn level_text() -> Vec<u8> {
        (0..40).flat_map(|i| format!("{i}: the quick brown fox jumps over the lazy dog\n").into_bytes()).collect()
    }

    #[test]
    fn codecs_bzip2_levels() {
        let text = level_text();
        assert_eq!(text.len(), LEVEL_TEXT_LEN);
        for level in b'1'..=b'9' {
            let mut v = LEVEL9.to_vec();
            v[3] = level;
            assert_same(&v, &text);
        }
        // Level digits outside 1..9 are not bzip2.
        for bad in *b"0:a" {
            let mut v = LEVEL9.to_vec();
            v[3] = bad;
            assert!(decompress(&v).is_err());
        }
    }

    #[test]
    fn codecs_bzip2_empty() {
        // bzip2 of an empty file: header + end-of-stream marker only.
        assert_eq!(decompress(EMPTY).unwrap(), b"");
        // python: bz2.decompress(b"") == b"".
        assert_eq!(decompress(b"").unwrap(), b"");
        let mut two = EMPTY.to_vec();
        two.extend_from_slice(BZ);
        assert_eq!(decompress(&two).unwrap(), HELLO);
    }

    #[test]
    fn codecs_bzip2_rle1_runs() {
        let want: Vec<u8> =
            (1..=300usize).flat_map(|n| std::iter::repeat_n((n % 251 + 1) as u8, n).chain(std::iter::once(b'x'))).collect();
        assert_eq!(want.len(), RUNS_LEN);
        assert_same(RUNS, &want);
    }

    #[test]
    fn codecs_bzip2_all_byte_values() {
        assert_same(ALL_BYTES, ALL_BYTES_SRC);
        let mut seen = [0u32; 256];
        for &b in ALL_BYTES_SRC {
            seen[b as usize] += 1;
        }
        assert!(seen.iter().all(|&c| c == 3));
    }

    #[test]
    fn codecs_bzip2_real_multiblock() {
        let want: Vec<u8> = b"abcdefghijklmnopqrstuvwxyz".iter().copied().cycle().take(330_000).collect();
        assert_same(MULTI, &want);
        let cands = scan_magics(MULTI, 4);
        assert_eq!(cands.len(), 4, "4 blocks of 100k");
    }

    #[test]
    fn codecs_bzip2_small_multistream() {
        assert_same(BZ, HELLO);
        let mut two = BZ.to_vec();
        two.extend_from_slice(BZ);
        assert_eq!(decompress(&two).unwrap(), b"hello hello hello hello\nhello hello hello hello\n");
        // Truncation anywhere is an error.
        for n in 1..BZ.len() {
            assert!(decompress(&BZ[..n]).is_err(), "truncated at {n}");
        }
    }

    /// python bz2.decompress: data after a complete stream is ignored if libbz2 rejects it,
    /// but a (possibly partial) valid stream prefix means truncation.
    #[test]
    fn codecs_bzip2_trailing_data_semantics() {
        let ignored: [&[u8]; 6] = [b"x", b"\x00", b"\x00\x00\x00", b"garbage", b"BZh0", b"BZx"];
        for tail in ignored {
            let mut v = BZ.to_vec();
            v.extend_from_slice(tail);
            assert_eq!(decompress(&v).unwrap(), HELLO, "tail {tail:?}");
        }
        let truncated: [&[u8]; 6] = [b"B", b"BZ", b"BZh", b"BZh9", b"BZh91AY", &BZ[..BZ.len() - 1]];
        for tail in truncated {
            let mut v = BZ.to_vec();
            v.extend_from_slice(tail);
            assert!(decompress(&v).is_err(), "tail {tail:?}");
        }
        // Garbage first is an error.
        assert!(decompress(b"x").is_err());
        assert!(decompress(b"BZh9").is_err());
        // A second stream with a corrupt block CRC is ignored (python: OSError after the
        // first stream), a bad first stream is an error.
        let mut v = BZ.to_vec();
        let mut bad = BZ.to_vec();
        bad[10] ^= 1; // block CRC
        v.extend_from_slice(&bad);
        assert_eq!(decompress(&v).unwrap(), HELLO);
        assert!(decompress(&bad).is_err());
        let mut bad_stream_crc = BZ.to_vec();
        let k = bad_stream_crc.len() - 2;
        bad_stream_crc[k] ^= 0x10;
        assert!(decompress(&bad_stream_crc).is_err());
    }

    #[test]
    fn codecs_bzip2_corrupt_crc() {
        // Every single-bit flip of the block CRC or the stream CRC is detected.
        for byte in (10..14).chain(BZ.len() - 5..BZ.len()) {
            for bit in 0..8 {
                let mut v = BZ.to_vec();
                v[byte] ^= 1 << bit;
                if let Ok(out) = decompress(&v) {
                    // Only possible if the flip hit padding bits after the stream CRC.
                    assert_eq!(out, HELLO, "byte {byte} bit {bit}");
                    assert_eq!(byte, BZ.len() - 1);
                }
            }
        }
    }

    #[test]
    fn codecs_bzip2_encoder_roundtrip() {
        // (kind, len, level, RLE1 block limit): lane walk (>= LANES_MIN) and single walk,
        // periodic blocks (the BWT permutation has many cycles), big RLE1 expansions.
        let cases = [
            (0u32, 70_000usize, 9u8, 30_000usize),
            (0, 3000, 1, 1000),
            (1, 150_000, 2, 50_000),
            (2, 200_000, 1, 40_000),
            (3, 120_000, 9, 30_000),
            (3, 64_000, 9, 20_000),
            (4, 1 << 20, 9, 100_000),
            (1, 90_000, 9, 900_000),
            (2, 5000, 9, 64),
        ];
        for (i, &(kind, len, level, limit)) in cases.iter().enumerate() {
            let data = sample(kind, len, i as u64 * 7919 + 1);
            let bz = bz_encode(&data, level, limit);
            assert_same(&bz, &data);
        }
        // Exactly periodic lane-sized blocks: 'ab' * 15000 and 'abc' * 10000 per block.
        for pat in [&b"ab"[..], b"abc", b"abcd"] {
            let data: Vec<u8> = pat.iter().copied().cycle().take(60_000 * pat.len()).collect();
            let bz = bz_encode(&data, 9, 30_000 - 30_000 % pat.len());
            assert_same(&bz, &data);
        }
        // Each run length 1..=600 of a single byte value (RLE1 boundaries 4, 259, 263, ...).
        for n in (1..=40).chain([255, 258, 259, 260, 262, 263, 264, 517, 518, 519, 600]) {
            let data = vec![0xA5u8; n];
            assert_same(&bz_encode(&data, 9, 900_000), &data);
        }
    }

    #[test]
    fn codecs_bzip2_parallel_false_candidates() {
        let data = sample(1, 200_000, 5);
        let bz = bz_encode(&data, 9, 25_000);
        let real = scan_magics(&bz, 4);
        assert!(real.len() >= 8);
        assert_eq!(scan_magics(&bz, 1), real);
        // Bogus candidates (as if the magic occurred inside compressed data) and a missing
        // real one (decoded inline) must not change anything.
        let mut cands = real.clone();
        cands.remove(3);
        let mut s = 99u64;
        for _ in 0..40 {
            cands.push((xorshift(&mut s) as usize) % (bz.len() * 8));
        }
        cands.sort_unstable();
        cands.dedup();
        for threads in [2, 3, 8] {
            assert_eq!(decompress_par(&bz, &cands, threads).unwrap(), data);
            assert_eq!(decompress_par(&bz, &real, threads).unwrap(), data);
        }
    }

    #[test]
    fn codecs_bzip2_parallel_matches_sequential() {
        // Multi-stream input: 3 streams of several blocks each, then garbage.
        let parts: Vec<Vec<u8>> = (0..3).map(|k| sample(k, 60_000, k as u64 + 3)).collect();
        let streams: Vec<Vec<u8>> = parts.iter().map(|p| bz_encode(p, 9, 20_000)).collect();
        let mut all = streams.concat();
        let want = parts.concat();
        assert_same(&all, &want);
        all.extend_from_slice(b"trailing garbage");
        assert_same(&all, &want);
        // Corruption in stream 2 (a block CRC mismatch, detected after the inverse BWT):
        // python keeps stream 1 and ignores the rest; any thread count must agree.
        let mut s = 1234u64;
        for trial in 0..60 {
            let mut v = streams.concat();
            let lo = streams[0].len() + if trial % 2 == 0 { 10 } else { 0 };
            let span = if trial % 3 == 0 { streams[1].len() } else { v.len() - lo };
            let at = lo + (xorshift(&mut s) as usize) % span;
            v[at] ^= 1 << (xorshift(&mut s) % 8);
            let r1 = decompress_threads(&v, 1);
            for t in [2, 5] {
                let rt = decompress_threads(&v, t);
                match (&r1, &rt) {
                    (Ok(a), Ok(b)) => assert!(a == b, "trial {trial} threads {t}"),
                    (Err(_), Err(_)) => {}
                    _ => panic!("trial {trial} threads {t}: {:?} vs {:?}", r1.is_ok(), rt.is_ok()),
                }
            }
            if let Ok(out) = r1 {
                assert!(out.len() >= parts[0].len());
            }
        }
        // Truncation inside stream 2 is an error for every thread count.
        let v = streams.concat();
        for cut in [streams[0].len() + 3, streams[0].len() + 500, v.len() - 1] {
            assert!(decompress_threads(&v[..cut], 1).is_err());
            assert!(decompress_threads(&v[..cut], 4).is_err());
        }
    }

    #[test]
    fn codecs_bzip2_garbage_never_panics() {
        // Bit flips in real and synthetic streams (single- and multi-threaded paths),
        // truncations, and random bytes behind a valid header.
        let multi = bz_encode(&sample(2, 60_000, 11), 1, 20_000);
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        for round in 0..1500 {
            let src: &[u8] = if round % 3 == 0 { &multi } else { BZ };
            let mut v = src.to_vec();
            for _ in 0..1 + round % 4 {
                let i = 4 + (xorshift(&mut s) as usize) % (v.len() - 4);
                v[i] ^= 1 << (xorshift(&mut s) & 7);
            }
            if round % 5 == 0 {
                v.truncate(4 + (xorshift(&mut s) as usize) % (v.len() - 4));
            }
            let threads = if round % 3 == 0 { 1 + round % 4 } else { 1 };
            let _ = decompress_threads(&v, threads);
        }
        for _ in 0..300 {
            let mut v = b"BZh91AY&SY".to_vec();
            let n = (xorshift(&mut s) % 400) as usize;
            v.extend((0..n).map(|_| xorshift(&mut s) as u8));
            let _ = decompress(&v);
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
                        walk(sc.tt.as_mut_ptr(), n, info.orig_ptr, sc.cols.as_mut_ptr(), sc.pre.as_mut_ptr(), &mut sc.segs)
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
                    walk(tt.as_mut_ptr(), n, 0, cols.as_mut_ptr(), pre.as_mut_ptr(), &mut sc.segs).unwrap();
                    best = best.min(std::arch::x86_64::_rdtsc() - t0);
                }
            }
            println!("walk n={n}: {:.2} TSC ticks/step", best as f64 / n as f64);
        }
    }

    /// Thread scaling on CODECS_BENCH_FILE: best wall time per thread count.
    #[test]
    #[ignore]
    fn codecs_bzip2_threads() {
        let Ok(file) = std::env::var("CODECS_BENCH_FILE") else { return };
        let data = std::fs::read(&file).unwrap();
        let reference = decompress_threads(&data, 1).unwrap();
        let counts: Vec<usize> = std::env::var("CODECS_THREADS")
            .unwrap_or_else(|_| "1,2,4,6,8,10,12,16,20".into())
            .split(',')
            .filter_map(|x| x.parse().ok())
            .collect();
        for t in counts {
            let mut best = f64::MAX;
            for _ in 0..5 {
                let t0 = std::time::Instant::now();
                let out = decompress_threads(&data, t).unwrap();
                best = best.min(t0.elapsed().as_secs_f64());
                assert!(out == reference);
            }
            println!(
                "threads {t:2}: {:8.2} ms {:8.1} MB/s",
                best * 1e3,
                reference.len() as f64 / best / 1e6
            );
        }
    }

}
