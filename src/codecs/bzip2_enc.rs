//! bzip2 encoder: streaming, block-parallel [`Bzip2Encoder`] and one-shot [`bzip2_compress`].
//!
//! The output is a single ordinary bzip2 stream ("BZh" + level, blocks, end marker with the
//! combined CRC) that `bzip2 -d`, python's `bz2` and [`super::bzip2::decompress`] read. Block
//! boundaries follow libbz2 (a block holds at most `100000 * level - 19` bytes after the
//! initial run-length encoding), so the ratio matches `bzip2 -<level>`.
//!
//! Pipeline:
//! * Producer (the thread calling `write`): RLE1 (runs of 4..255 equal bytes -> 4 bytes + a
//!   count; an SSE2 scan finds run starts, so run-free data is block-copied), block CRC over
//!   the original bytes. Full blocks go to worker threads ([`super::enc_pipeline`]).
//! * Workers (blocks are independent): cyclic BWT by SA-IS on the least rotation
//!   ([`super::sais::bwt`], linear time on any input), MTF + RUNA/RUNB zero-run coding, 2-6
//!   Huffman tables fitted by 4 rounds of per-50-symbol table selection (like libbz2, plus a
//!   final re-selection with the final tables), selector MTF, MSB-first bit packing.
//! * Collector: blocks are concatenated at bit granularity (bzip2 blocks are not byte
//!   aligned), in order; combined CRC = rotl(crc, 1) ^ block CRC.
//!
//! Memory: about 10 MB of scratch per worker thread plus ~1 MB per block in flight.

use std::io::{self, Write};

use super::crc::crc32_bzip2_update;
use super::enc_pipeline::Pipeline;
use super::huffman_enc::huffman_lengths;
use super::sais::{BwtScratch, bwt};

const BLOCK_MAGIC_HI: u32 = 0x31_4159;
const BLOCK_MAGIC_LO: u32 = 0x26_5359;
const END_MAGIC_HI: u32 = 0x17_7245;
const END_MAGIC_LO: u32 = 0x38_5090;
const MAX_GROUPS: usize = 6;
const MAX_ALPHA: usize = 258;
const GROUP_SIZE: usize = 50;
const MAX_CODE_LEN: u32 = 17;
const ITERS: usize = 4;
const RUNA: u32 = 0;
const RUNB: u32 = 1;

// ---------------------------------------------------------------------------------------
// MSB-first bit writer
// ---------------------------------------------------------------------------------------

/// MSB-first bit accumulator over a byte vector.
struct MsbWriter {
    buf: Vec<u8>,
    acc: u64,
    /// Valid bits in `acc` (< 32 between calls).
    n: u32,
}

impl MsbWriter {
    fn new(buf: Vec<u8>) -> MsbWriter {
        MsbWriter { buf, acc: 0, n: 0 }
    }

    /// Appends the low `nb` (<= 32) bits of `v`.
    #[inline(always)]
    fn put(&mut self, v: u32, nb: u32) {
        debug_assert!(nb <= 32 && (nb == 32 || v >> nb == 0));
        self.acc = (self.acc << nb) | v as u64;
        self.n += nb;
        if self.n >= 32 {
            self.n -= 32;
            self.buf.extend_from_slice(&((self.acc >> self.n) as u32).to_be_bytes());
        }
    }

    /// Total bits written.
    fn bits(&self) -> u64 {
        self.buf.len() as u64 * 8 + self.n as u64
    }

    /// Appends `nbits` bits stored MSB-first in `bytes` (the last byte may be partial).
    fn append_bits(&mut self, bytes: &[u8], nbits: u64) {
        let full = (nbits / 8) as usize;
        let rem = (nbits % 8) as u32;
        let mut i = 0;
        if self.n.is_multiple_of(8) {
            // Byte aligned: flush the accumulator's whole bytes and copy.
            while self.n > 0 {
                self.n -= 8;
                self.buf.push((self.acc >> self.n) as u8);
            }
            self.buf.extend_from_slice(&bytes[..full]);
            i = full;
        } else {
            while i + 4 <= full {
                self.put(u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]), 32);
                i += 4;
            }
        }
        while i < full {
            self.put(bytes[i] as u32, 8);
            i += 1;
        }
        if rem > 0 {
            self.put((bytes[full] >> (8 - rem)) as u32, rem);
        }
    }

    /// Moves the complete bytes written so far out (keeping the partial one).
    fn take_bytes(&mut self) -> Vec<u8> {
        while self.n >= 8 {
            self.n -= 8;
            self.buf.push((self.acc >> self.n) as u8);
        }
        std::mem::take(&mut self.buf)
    }

    /// Pads the last byte with zero bits; returns (bytes, bit length before padding).
    fn finish(mut self) -> (Vec<u8>, u64) {
        let bits = self.bits();
        let pad = (8 - self.n % 8) % 8;
        self.put(0, pad);
        while self.n >= 8 {
            self.n -= 8;
            self.buf.push((self.acc >> self.n) as u8);
        }
        (self.buf, bits)
    }
}

// ---------------------------------------------------------------------------------------
// Block encoder (worker side)
// ---------------------------------------------------------------------------------------

/// Per-thread scratch for [`encode_block`] (reused across blocks).
#[derive(Default)]
pub(crate) struct BlockScratch {
    bwt: BwtScratch,
    last: Vec<u8>,
    selectors: Vec<u8>,
}

/// Encodes one block (`block` = RLE1 output, 1..=900000 bytes; `crc` = CRC of the original
/// bytes) as a bit string appended to `out`; returns its length in bits.
pub(crate) fn encode_block(block: &[u8], crc: u32, sc: &mut BlockScratch, out: Vec<u8>) -> (Vec<u8>, u64) {
    debug_assert!(!block.is_empty() && block.len() <= 900_000);
    let mut w = MsbWriter::new(out);

    // Symbols in use.
    let mut hist = [0u32; 256];
    for &b in block {
        hist[b as usize] += 1;
    }
    let mut seq_of = [0u8; 256];
    let mut n_in_use = 0usize;
    for (c, &h) in hist.iter().enumerate() {
        if h != 0 {
            seq_of[c] = n_in_use as u8;
            n_in_use += 1;
        }
    }

    // BWT.
    let orig = bwt(block, &mut sc.last, &mut sc.bwt);

    // MTF + RUNA/RUNB.
    let alpha = n_in_use + 2;
    let eob = (n_in_use + 1) as u32;
    let mut freq = [0u32; MAX_ALPHA];
    // The MTF symbols reuse the suffix array's memory (free once the BWT is done).
    let mut mtf_buf = sc.bwt.take_sa();
    mtf_buf.clear();
    mtf_buf.reserve(block.len() + 1);
    let mtf = &mut mtf_buf;
    {
        let mut yy = [0u8; 256];
        for (i, y) in yy.iter_mut().enumerate() {
            *y = i as u8;
        }
        let mut zpend = 0u32;
        let flush_run = |zpend: &mut u32, mtf: &mut Vec<u32>, freq: &mut [u32; MAX_ALPHA]| {
            let mut z = *zpend - 1;
            loop {
                let s = if z & 1 != 0 { RUNB } else { RUNA };
                mtf.push(s);
                freq[s as usize] += 1;
                if z < 2 {
                    break;
                }
                z = (z - 2) / 2;
            }
            *zpend = 0;
        };
        for &c in sc.last.iter() {
            let s = seq_of[c as usize];
            if yy[0] == s {
                zpend += 1;
                continue;
            }
            if zpend > 0 {
                flush_run(&mut zpend, mtf, &mut freq);
            }
            // Rank of s (>= 1), then move it to the front.
            let j = mtf_rank(&yy, s);
            if j < 8 {
                for k in (1..=j).rev() {
                    yy[k] = yy[k - 1];
                }
            } else {
                yy.copy_within(0..j, 1);
            }
            yy[0] = s;
            let sym = (j + 1) as u32;
            mtf.push(sym);
            freq[sym as usize] += 1;
        }
        if zpend > 0 {
            flush_run(&mut zpend, mtf, &mut freq);
        }
        mtf.push(eob);
        freq[eob as usize] += 1;
    }
    let n_mtf = mtf.len();

    // Huffman tables and selectors.
    let n_groups = match n_mtf {
        0..200 => 2,
        200..600 => 3,
        600..1200 => 4,
        1200..2400 => 5,
        _ => 6,
    };
    let mut lens = [[0u8; MAX_ALPHA]; MAX_GROUPS];
    {
        // Initial tables: contiguous symbol ranges of about equal total frequency.
        let mut n_part = n_groups;
        let mut rem_f = n_mtf as u32;
        let mut gs = 0usize;
        while n_part > 0 {
            let t_freq = rem_f / n_part as u32;
            let mut ge = gs as isize - 1;
            let mut a_freq = 0u32;
            while a_freq < t_freq && ge < alpha as isize - 1 {
                ge += 1;
                a_freq += freq[ge as usize];
            }
            if ge > gs as isize && n_part != n_groups && n_part != 1 && (n_groups - n_part) % 2 == 1 {
                a_freq -= freq[ge as usize];
                ge -= 1;
            }
            for v in 0..alpha {
                lens[n_part - 1][v] = if v as isize >= gs as isize && v as isize <= ge { 0 } else { 15 };
            }
            n_part -= 1;
            gs = (ge + 1) as usize;
            rem_f = rem_f.saturating_sub(a_freq);
        }
    }
    let n_sel = n_mtf.div_ceil(GROUP_SIZE);
    let sels = &mut sc.selectors;
    sels.clear();
    sels.resize(n_sel, 0);
    // Packed per-symbol costs: 10 bits per table (a group costs at most 50 * 20 < 1024).
    let pack = |lens: &[[u8; MAX_ALPHA]; MAX_GROUPS], packed: &mut [u64; MAX_ALPHA]| {
        for v in 0..alpha {
            let mut x = 0u64;
            for (t, l) in lens.iter().enumerate().take(n_groups) {
                x |= (l[v] as u64) << (10 * t);
            }
            packed[v] = x;
        }
    };
    let select = |packed: &[u64; MAX_ALPHA], sels: &mut [u8], mtf: &[u32]| {
        for (g, chunk) in mtf.chunks(GROUP_SIZE).enumerate() {
            let mut c = 0u64;
            for &s in chunk {
                c += packed[s as usize];
            }
            let mut bt = 0;
            let mut bc = u64::MAX;
            for t in 0..n_groups {
                let ct = (c >> (10 * t)) & 1023;
                if ct < bc {
                    bc = ct;
                    bt = t;
                }
            }
            sels[g] = bt as u8;
        }
    };
    let mut packed = [0u64; MAX_ALPHA];
    for _ in 0..ITERS {
        pack(&lens, &mut packed);
        select(&packed, sels, mtf);
        let mut rfreq = [[0u32; MAX_ALPHA]; MAX_GROUPS];
        for (g, chunk) in mtf.chunks(GROUP_SIZE).enumerate() {
            let f = &mut rfreq[sels[g] as usize];
            for &s in chunk {
                f[s as usize] += 1;
            }
        }
        for t in 0..n_groups {
            // Every symbol needs a code (bzip2 has no zero-length codes).
            let mut f = [0u32; MAX_ALPHA];
            for v in 0..alpha {
                f[v] = rfreq[t][v].max(1);
            }
            huffman_lengths(&f[..alpha], MAX_CODE_LEN, &mut lens[t][..alpha]);
        }
    }
    // Final selection with the final tables.
    pack(&lens, &mut packed);
    select(&packed, sels, mtf);

    // Canonical codes (by length, then symbol).
    let mut codes = [[0u32; MAX_ALPHA]; MAX_GROUPS];
    for t in 0..n_groups {
        let mut code = 0u32;
        for l in 1..=MAX_CODE_LEN as u8 {
            for v in 0..alpha {
                if lens[t][v] == l {
                    codes[t][v] = code;
                    code += 1;
                }
            }
            code <<= 1;
        }
    }

    // ---- Write the block ----
    w.put(BLOCK_MAGIC_HI, 24);
    w.put(BLOCK_MAGIC_LO, 24);
    w.put(crc, 32);
    w.put(0, 1); // not randomised
    w.put(orig as u32, 24);
    let mut in_use16 = 0u32;
    for i in 0..16 {
        if hist[i * 16..i * 16 + 16].iter().any(|&h| h != 0) {
            in_use16 |= 1 << (15 - i);
        }
    }
    w.put(in_use16, 16);
    for i in 0..16 {
        if in_use16 & (1 << (15 - i)) != 0 {
            let mut bits = 0u32;
            for j in 0..16 {
                if hist[i * 16 + j] != 0 {
                    bits |= 1 << (15 - j);
                }
            }
            w.put(bits, 16);
        }
    }
    w.put(n_groups as u32, 3);
    w.put(n_sel as u32, 15);
    {
        // Selectors, MTF coded, unary.
        let mut pos = [0u8, 1, 2, 3, 4, 5];
        for &s in sels.iter() {
            let mut j = 0;
            while pos[j] != s {
                j += 1;
            }
            let v = pos[j];
            for k in (1..=j).rev() {
                pos[k] = pos[k - 1];
            }
            pos[0] = v;
            w.put(((1u32 << (j + 1)) - 2) as u32, j as u32 + 1);
        }
    }
    for t in 0..n_groups {
        let mut cur = lens[t][0] as i32;
        w.put(cur as u32, 5);
        for v in 0..alpha {
            let l = lens[t][v] as i32;
            while cur < l {
                w.put(2, 2);
                cur += 1;
            }
            while cur > l {
                w.put(3, 2);
                cur -= 1;
            }
            w.put(0, 1);
        }
    }
    for (g, chunk) in mtf.chunks(GROUP_SIZE).enumerate() {
        let t = sels[g] as usize;
        let (c, l) = (&codes[t], &lens[t]);
        for &s in chunk {
            w.put(c[s as usize], l[s as usize] as u32);
        }
    }
    sc.bwt.put_sa(mtf_buf);
    let bits = w.bits();
    // Complete bytes plus the partial last byte (zero padded); `bits` is the true length.
    let (bytes, _) = w.finish();
    (bytes, bits)
}

/// Index of `s` in the MTF list `yy` (it is present).
#[inline(always)]
fn mtf_rank(yy: &[u8; 256], s: u8) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::*;
        // SAFETY: 16 loads of 16 bytes cover exactly yy[0..256]; SSE2 is baseline on x86-64.
        unsafe {
            let needle = _mm_set1_epi8(s as i8);
            let mut k = 0;
            while k < 256 {
                let v = _mm_loadu_si128(yy.as_ptr().add(k) as *const __m128i);
                let m = _mm_movemask_epi8(_mm_cmpeq_epi8(v, needle)) as u32;
                if m != 0 {
                    return k + m.trailing_zeros() as usize;
                }
                k += 16;
            }
        }
        0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        yy.iter().position(|&x| x == s).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------------------
// RLE1 helpers (producer side)
// ---------------------------------------------------------------------------------------

/// First `j >= i` with `d[j..j + 4]` four equal bytes, or `d.len()`.
fn find_run4(d: &[u8], mut i: usize) -> usize {
    let n = d.len();
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::*;
        while i + 19 <= n {
            // SAFETY: the four 16-byte loads end at i + 19 <= n; SSE2 is baseline on x86-64.
            let mask = unsafe {
                let p = d.as_ptr().add(i);
                let a = _mm_loadu_si128(p as *const __m128i);
                let b = _mm_loadu_si128(p.add(1) as *const __m128i);
                let c = _mm_loadu_si128(p.add(2) as *const __m128i);
                let e = _mm_loadu_si128(p.add(3) as *const __m128i);
                let m = _mm_and_si128(_mm_and_si128(_mm_cmpeq_epi8(a, b), _mm_cmpeq_epi8(a, c)), _mm_cmpeq_epi8(a, e));
                _mm_movemask_epi8(m) as u32
            };
            if mask != 0 {
                return i + mask.trailing_zeros() as usize;
            }
            i += 16;
        }
    }
    while i + 4 <= n {
        if d[i] == d[i + 1] && d[i] == d[i + 2] && d[i] == d[i + 3] {
            return i;
        }
        i += 1;
    }
    n
}

/// Number of bytes equal to `ch` at the start of `d`.
fn eq_run(d: &[u8], ch: u8) -> usize {
    let pat = u64::from_ne_bytes([ch; 8]);
    let mut i = 0;
    while i + 8 <= d.len() {
        let x = u64::from_ne_bytes(d[i..i + 8].try_into().unwrap()) ^ pat;
        if x != 0 {
            return i + (x.to_le().trailing_zeros() / 8) as usize;
        }
        i += 8;
    }
    while i < d.len() && d[i] == ch {
        i += 1;
    }
    i
}

// ---------------------------------------------------------------------------------------
// Streaming encoder
// ---------------------------------------------------------------------------------------

struct Job {
    block: Vec<u8>,
    crc: u32,
    out: Vec<u8>,
}

struct Done {
    bytes: Vec<u8>,
    bits: u64,
    crc: u32,
    block: Vec<u8>,
}

fn encode_job(sc: &mut BlockScratch, j: Job) -> Done {
    let mut out = j.out;
    out.clear();
    let (bytes, bits) = encode_block(&j.block, j.crc, sc, out);
    Done { bytes, bits, crc: j.crc, block: j.block }
}

/// Streaming, block-parallel bzip2 writer (see the module documentation). Create with
/// [`Bzip2Encoder::new`], feed it through [`std::io::Write`], and call
/// [`Bzip2Encoder::finish`] (dropping it without `finish` leaves the output truncated).
pub struct Bzip2Encoder<W: Write + Send> {
    w: W,
    level: u32,
    /// Maximum RLE1 bytes per block.
    limit: usize,
    blk: Vec<u8>,
    blk_crc: u32,
    /// Pending run of `run_ch` (may continue in the next `write`).
    run_ch: u8,
    run_len: usize,
    pipe: Pipeline<BlockScratch, Job, Done>,
    max_in_flight: usize,
    out: MsbWriter,
    combined: u32,
    free: Vec<Vec<u8>>,
}

impl<W: Write + Send> Bzip2Encoder<W> {
    /// A bzip2 writer onto `w` with block size `level` x 100k (1..=9; python's
    /// `bz2.BZ2File(compresslevel=9)` / `tarfile` "w:bz2" use 9), on all logical CPUs.
    pub fn new(w: W, level: u32) -> Bzip2Encoder<W> {
        Bzip2Encoder::with_threads(w, level, 0)
    }

    /// As [`Bzip2Encoder::new`] with at most `threads` worker threads (0 = all logical CPUs).
    pub fn with_threads(w: W, level: u32, threads: usize) -> Bzip2Encoder<W> {
        let level = level.clamp(1, 9);
        let threads = if threads == 0 { crate::util::par::threads() } else { threads };
        let mut out = MsbWriter::new(Vec::with_capacity(1 << 16));
        for &b in b"BZh" {
            out.put(b as u32, 8);
        }
        out.put(b'0' as u32 + level, 8);
        Bzip2Encoder {
            w,
            level,
            limit: 100_000 * level as usize - 19,
            blk: Vec::new(),
            blk_crc: 0,
            run_ch: 0,
            run_len: 0,
            pipe: Pipeline::new(threads, BlockScratch::default, encode_job),
            max_in_flight: if threads <= 1 { 1 } else { threads + 2 },
            out,
            combined: 0,
            free: Vec::new(),
        }
    }

    /// The block size level (1..=9).
    pub fn level(&self) -> u32 {
        self.level
    }

    fn ensure_block(&mut self) {
        if self.blk.capacity() == 0 {
            let mut b = self.free.pop().unwrap_or_default();
            b.clear();
            b.reserve(self.limit);
            self.blk = b;
        }
    }

    /// Hands the current block to the workers.
    fn submit(&mut self, last: bool) -> io::Result<()> {
        if self.blk.is_empty() {
            return Ok(());
        }
        let block = std::mem::take(&mut self.blk);
        let out = self.free.pop().unwrap_or_default();
        let job = Job { block, crc: self.blk_crc, out };
        self.blk_crc = 0;
        if last && self.pipe.submitted() == 0 {
            self.pipe.run_inline(job);
        } else {
            self.pipe.submit(job);
        }
        self.collect(false)?;
        while self.pipe.in_flight() >= self.max_in_flight {
            self.collect_one(true)?;
        }
        Ok(())
    }

    fn collect(&mut self, block: bool) -> io::Result<()> {
        while self.collect_one(block)? {}
        Ok(())
    }

    fn collect_one(&mut self, block: bool) -> io::Result<bool> {
        let Some(r) = self.pipe.next(block) else { return Ok(false) };
        let d = r?;
        self.out.append_bits(&d.bytes, d.bits);
        self.combined = self.combined.rotate_left(1) ^ d.crc;
        if self.out.buf.len() >= 1 << 16 {
            let bytes = self.out.take_bytes();
            self.w.write_all(&bytes)?;
            self.out.buf = bytes;
            self.out.buf.clear();
        }
        self.free.push(d.bytes);
        self.free.push(d.block);
        Ok(true)
    }

    /// Appends run-free bytes to the block(s).
    fn emit_verbatim(&mut self, mut d: &[u8]) -> io::Result<()> {
        while !d.is_empty() {
            self.ensure_block();
            let take = (self.limit - self.blk.len()).min(d.len());
            self.blk.extend_from_slice(&d[..take]);
            self.blk_crc = crc32_bzip2_update(self.blk_crc, &d[..take]);
            d = &d[take..];
            if self.blk.len() >= self.limit {
                self.submit(false)?;
            }
        }
        Ok(())
    }

    /// Emits the pending run (`run_ch` x `run_len`) in RLE1 form.
    fn emit_run(&mut self) -> io::Result<()> {
        let ch = self.run_ch;
        let copies = [ch; 255];
        while self.run_len > 0 {
            let piece = self.run_len.min(255);
            let need = if piece >= 4 { 5 } else { piece };
            self.ensure_block();
            if self.blk.len() + need > self.limit {
                self.submit(false)?;
                self.ensure_block();
            }
            if piece >= 4 {
                self.blk.extend_from_slice(&[ch, ch, ch, ch, (piece - 4) as u8]);
            } else {
                self.blk.extend_from_slice(&copies[..piece]);
            }
            self.blk_crc = crc32_bzip2_update(self.blk_crc, &copies[..piece]);
            self.run_len -= piece;
        }
        Ok(())
    }

    /// Compresses the remaining input, writes the end-of-stream marker and combined CRC,
    /// flushes and returns the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.emit_run()?;
        self.submit(true)?;
        self.collect(true)?;
        self.out.put(END_MAGIC_HI, 24);
        self.out.put(END_MAGIC_LO, 24);
        self.out.put(self.combined, 32);
        let out = std::mem::replace(&mut self.out, MsbWriter::new(Vec::new()));
        let (bytes, _) = out.finish();
        self.w.write_all(&bytes)?;
        self.w.flush()?;
        let Bzip2Encoder { w, .. } = self;
        Ok(w)
    }
}

impl<W: Write + Send> Write for Bzip2Encoder<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len();
        let mut i = 0;
        if self.run_len > 0 {
            let r = eq_run(data, self.run_ch);
            self.run_len += r;
            i = r;
            if i == n {
                return Ok(n);
            }
            self.emit_run()?;
        }
        while i < n {
            let j = find_run4(data, i);
            if j == n {
                // No run of 4 left; up to 3 trailing equal bytes may start one.
                let last = data[n - 1];
                let t = eq_run_rev(&data[i..], last).min(3);
                self.emit_verbatim(&data[i..n - t])?;
                self.run_ch = last;
                self.run_len = t;
                return Ok(n);
            }
            self.emit_verbatim(&data[i..j])?;
            let ch = data[j];
            let r = eq_run(&data[j..], ch);
            self.run_ch = ch;
            self.run_len = r;
            if j + r == n {
                return Ok(n); // the run may continue
            }
            self.emit_run()?;
            i = j + r;
        }
        Ok(n)
    }

    /// Writes out the blocks that are already compressed and flushes the inner writer (the
    /// block being filled stays buffered).
    fn flush(&mut self) -> io::Result<()> {
        self.collect(false)?;
        let bytes = self.out.take_bytes();
        self.w.write_all(&bytes)?;
        self.out.buf = bytes;
        self.out.buf.clear();
        self.w.flush()
    }
}

/// Number of bytes equal to `ch` at the end of `d`.
fn eq_run_rev(d: &[u8], ch: u8) -> usize {
    d.iter().rev().take_while(|&&b| b == ch).count()
}

/// Compresses `data` into a bzip2 stream with block size `level` x 100k (1..=9), using all
/// cores for inputs of more than one block.
pub fn bzip2_compress(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = Bzip2Encoder::new(Vec::with_capacity(data.len() / 4 + 64), level);
    // Writing into a Vec cannot fail.
    let _ = e.write_all(data);
    e.finish().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecs::testdata::gen_data;

    fn rng(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    fn roundtrip(data: &[u8], level: u32, threads: usize, write: usize) -> Vec<u8> {
        let mut e = Bzip2Encoder::with_threads(Vec::new(), level, threads);
        for c in data.chunks(write.max(1)) {
            e.write_all(c).unwrap();
        }
        let z = e.finish().unwrap();
        let d = crate::codecs::bzip2::decompress(&z).expect("our decoder rejected the stream");
        assert!(d == data, "roundtrip mismatch: len {} level {level} threads {threads} write {write}", data.len());
        z
    }

    #[test]
    fn codecs_bzip2_enc_small() {
        assert_eq!(bzip2_compress(b"", 9), b"BZh9\x17rE8P\x90\x00\x00\x00\x00");
        for d in [&b"a"[..], b"ab", b"aaaa", b"aaaaa", b"hello hello hello", &[0u8; 1000], &[1u8; 255], &[2u8; 256]] {
            roundtrip(d, 9, 1, 1 << 20);
            roundtrip(d, 1, 1, 1);
        }
        let mut runs = Vec::new();
        for i in 0..600usize {
            runs.extend(std::iter::repeat_n((i % 7) as u8, i % 300));
        }
        roundtrip(&runs, 9, 1, 1 << 20);
        roundtrip(&runs, 9, 2, 13);
        roundtrip(&rng(10_000, 1), 9, 1, 777);
        roundtrip(&gen_data(3, 50_000), 9, 1, 4096);
    }

    #[test]
    fn codecs_bzip2_enc_multiblock() {
        // level 1: 99981-byte blocks; runs straddling block and write boundaries.
        let mut d = gen_data(5, 250_000);
        d.extend(std::iter::repeat_n(0u8, 300_000));
        d.extend_from_slice(&rng(120_000, 9));
        d.extend(std::iter::repeat_n(b'x', 1000));
        let a = roundtrip(&d, 1, 1, 1 << 20);
        let b = roundtrip(&d, 1, 4, 999);
        assert!(a == b, "output depends on threads / write sizes");
        assert!(a.len() < d.len() / 3);
    }
}
