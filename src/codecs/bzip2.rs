//! bzip2 decoder (multiple streams, CRC verification).
//!
//! Per block: Huffman + MTF/RUNA-RUNB decoding into the BWT vector (`tt`, the byte in the
//! low 8 bits), inverse BWT through the `tt` linked list (index in the high 24 bits), then
//! the initial run-length decoding. Randomised blocks (a bzip2 0.9.0 feature no encoder has
//! produced since 0.9.5) are rejected.
//!
//! Throughput: Huffman decoding is table-driven (MSB-first 64-bit bit buffer, 10-bit
//! primary tables). The inverse BWT is a chain of dependent loads over up to 3.6 MB, so it is
//! latency-bound; multi-block streams therefore hand finished blocks to worker threads for
//! the inverse BWT / RLE / CRC while the calling thread keeps entropy-decoding.

use super::crc::crc32_bzip2;
use crate::error::{Error, Result};

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const END_MAGIC: u64 = 0x1772_4538_5090;
const MAX_GROUPS: usize = 6;
const MAX_ALPHA: usize = 258;
const MAX_SELECTORS: usize = 18002;
const MAX_CODE_LEN: u32 = 20;
const LOOKUP_BITS: u32 = 10;

fn corrupt(what: &str) -> Error {
    Error::Msg(format!("bzip2: corrupt data ({what})"))
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

    #[inline(always)]
    fn refill(&mut self) {
        if self.ip + 8 <= self.data.len() {
            let w = u64::from_be_bytes(self.data[self.ip..self.ip + 8].try_into().unwrap());
            self.buf |= w >> self.count;
            self.ip += ((63 - self.count) >> 3) as usize;
            self.count |= 56;
        } else {
            while self.count <= 56 {
                let b = self.data.get(self.ip).copied().unwrap_or(0);
                self.buf |= (b as u64) << (56 - self.count);
                self.ip += 1;
                self.count += 8;
            }
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
    fn new() -> Box<HuffTable> {
        Box::new(HuffTable {
            lookup: [0; 1 << LOOKUP_BITS],
            first: [0; 21],
            count: [0; 21],
            offset: [0; 21],
            sorted: [0; MAX_ALPHA],
            max_len: 0,
        })
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

    #[inline(always)]
    fn decode(&self, br: &mut BitReader) -> Result<u32> {
        if br.count < 32 {
            br.refill();
        }
        let e = self.lookup[(br.buf >> (64 - LOOKUP_BITS)) as usize];
        let l = (e & 31) as u32;
        if l != 0 {
            br.buf <<= l;
            br.count -= l;
            return Ok((e >> 5) as u32);
        }
        for l in LOOKUP_BITS + 1..=self.max_len {
            let v = (br.buf >> (64 - l)) as u32;
            let d = v.wrapping_sub(self.first[l as usize]);
            if d < self.count[l as usize] {
                br.buf <<= l;
                br.count -= l;
                return Ok(self.sorted[(self.offset[l as usize] + d) as usize] as u32);
            }
        }
        Err(corrupt("invalid Huffman code"))
    }
}

/// A block after entropy decoding: the pre-BWT byte vector and its parameters.
struct RawBlock {
    tt: Vec<u32>,
    orig_ptr: usize,
    counts: [u32; 256],
    crc: u32,
}

/// Reusable decoder state for entropy decoding.
struct BlockDecoder {
    tables: Vec<Box<HuffTable>>,
    selectors: Vec<u8>,
}

impl BlockDecoder {
    fn new() -> Self {
        BlockDecoder { tables: (0..MAX_GROUPS).map(|_| HuffTable::new()).collect(), selectors: Vec::new() }
    }

    /// Decodes one block (after its magic) into `tt`.
    fn decode(&mut self, br: &mut BitReader, max_block: usize, mut tt: Vec<u32>) -> std::result::Result<RawBlock, Fail> {
        let crc = br.bits(32);
        if br.bit() {
            return Err(Fail::Corrupt(Error::Msg("bzip2: randomised blocks are not supported".into())));
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
        if br.overrun() {
            return Err(Fail::Truncated);
        }
        if n_in_use == 0 {
            return Err(corrupt("no symbols in use").into());
        }
        let alpha = n_in_use + 2;
        let n_groups = br.bits(3) as usize;
        if !(2..=MAX_GROUPS).contains(&n_groups) {
            return Err(corrupt("number of Huffman groups").into());
        }
        let n_selectors = br.bits(15) as usize;
        if n_selectors == 0 {
            return Err(corrupt("no selectors").into());
        }
        // Selectors (MTF coded, unary).
        let mut mtf_groups = [0u8, 1, 2, 3, 4, 5];
        self.selectors.clear();
        for i in 0..n_selectors {
            let mut j = 0usize;
            while br.bit() {
                j += 1;
                if j >= n_groups {
                    return Err(corrupt("selector out of range").into());
                }
            }
            if br.overrun() {
                return Err(Fail::Truncated);
            }
            if i < MAX_SELECTORS {
                let v = mtf_groups[j];
                mtf_groups.copy_within(0..j, 1);
                mtf_groups[0] = v;
                self.selectors.push(v);
            }
        }
        // Coding tables (delta-coded lengths).
        let mut lens = [0u8; MAX_ALPHA];
        for t in 0..n_groups {
            let mut curr = br.bits(5) as i32;
            for l in lens.iter_mut().take(alpha) {
                loop {
                    if !(1..=MAX_CODE_LEN as i32).contains(&curr) {
                        return Err(corrupt("code length").into());
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
            self.tables[t].build(&lens[..alpha])?;
        }

        // MTF / RUNA-RUNB decoding.
        let eob = (n_in_use + 1) as u32;
        let mut mtf = [0u8; 256];
        for (i, m) in mtf.iter_mut().enumerate() {
            *m = i as u8;
        }
        let mut counts = [0u32; 256];
        tt.clear();
        tt.reserve(max_block);
        let mut group_left = 0usize;
        let mut sel = 0usize;
        let mut table: &HuffTable = &self.tables[0];
        let mut run = 0usize;
        let mut run_bit = 0u32;
        loop {
            if group_left == 0 {
                let s = *self.selectors.get(sel).ok_or_else(|| corrupt("ran out of selectors"))?;
                if s as usize >= n_groups {
                    return Err(corrupt("selector").into());
                }
                table = &self.tables[s as usize];
                sel += 1;
                group_left = 50;
            }
            group_left -= 1;
            let sym = table.decode(br)?;
            if sym <= 1 {
                // RUNA / RUNB: bijective base-2 run length of the front symbol.
                if run_bit > 21 {
                    return Err(corrupt("run too long").into());
                }
                run += ((sym + 1) as usize) << run_bit;
                run_bit += 1;
                continue;
            }
            if run > 0 {
                if tt.len() + run > max_block {
                    return Err(corrupt("block overflow").into());
                }
                let b = seq_to_unseq[mtf[0] as usize];
                counts[b as usize] += run as u32;
                tt.resize(tt.len() + run, b as u32);
                run = 0;
                run_bit = 0;
            }
            if sym == eob {
                break;
            }
            if br.overrun() {
                return Err(Fail::Truncated);
            }
            let idx = (sym - 1) as usize;
            if idx >= n_in_use {
                return Err(corrupt("MTF index").into());
            }
            let v = mtf[idx];
            mtf.copy_within(0..idx, 1);
            mtf[0] = v;
            let b = seq_to_unseq[v as usize];
            if tt.len() >= max_block {
                return Err(corrupt("block overflow").into());
            }
            counts[b as usize] += 1;
            tt.push(b as u32);
        }
        if br.overrun() {
            return Err(Fail::Truncated);
        }
        if orig_ptr >= tt.len() {
            return Err(corrupt("original pointer out of range").into());
        }
        Ok(RawBlock { tt, orig_ptr, counts, crc })
    }
}

/// Inverse BWT + run-length decoding of one block, appended to `out`. Returns the CRC.
fn finish_block(blk: &mut RawBlock, out: &mut Vec<u8>) -> Result<()> {
    let n = blk.tt.len();
    let tt = &mut blk.tt[..];
    // cftab: start of each byte value's bucket.
    let mut cf = [0u32; 256];
    let mut sum = 0u32;
    for (c, &k) in cf.iter_mut().zip(blk.counts.iter()) {
        *c = sum;
        sum += k;
    }
    for i in 0..n {
        let b = (tt[i] & 0xFF) as usize;
        let d = cf[b] as usize;
        // SAFETY-free: d < n because the counts sum to n.
        tt[d] |= (i as u32) << 8;
        cf[b] += 1;
    }
    let start = out.len();
    out.reserve(n + 256);
    let mut t = tt[blk.orig_ptr] >> 8;
    let mut prev: u32 = 256; // not a byte
    let mut same = 0u32;
    let mut k = 0usize;
    while k < n {
        let e = tt[(t as usize).min(n - 1)];
        t = e >> 8;
        let ch = e & 0xFF;
        k += 1;
        if same == 4 {
            // Run-length byte: `ch` more copies of `prev`.
            out.resize(out.len() + ch as usize, prev as u8);
            same = 0;
            prev = 256;
            continue;
        }
        if ch == prev {
            same += 1;
        } else {
            prev = ch;
            same = 1;
        }
        if out.len() == out.capacity() {
            out.reserve(n - k + 256);
        }
        out.push(ch as u8);
    }
    if crc32_bzip2(&out[start..]) != blk.crc {
        return Err(corrupt("block CRC mismatch"));
    }
    Ok(())
}

/// Decodes one stream starting at byte `off`; returns the byte offset after it.
fn decode_stream(data: &[u8], off: usize, out: &mut Vec<u8>) -> std::result::Result<usize, Fail> {
    let h = data.get(off..off + 4).ok_or(Fail::Truncated)?;
    if &h[..3] != b"BZh" || !(b'1'..=b'9').contains(&h[3]) {
        return Err(corrupt("bad stream header").into());
    }
    let max_block = (h[3] - b'0') as usize * 100_000;
    let mut br = BitReader::new(data, off + 4);
    let mut dec = BlockDecoder::new();
    let mut combined = 0u32;
    let mut tt: Vec<u32> = Vec::new();
    loop {
        let hi = br.bits(24) as u64;
        let magic = (hi << 24) | br.bits(24) as u64;
        if br.overrun() {
            return Err(Fail::Truncated);
        }
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
            return Err(corrupt("bad block magic").into());
        }
        let mut blk = dec.decode(&mut br, max_block, std::mem::take(&mut tt))?;
        combined = combined.rotate_left(1) ^ blk.crc;
        finish_block(&mut blk, out)?;
        tt = blk.tt;
    }
}

/// Decompresses a bzip2 file (all concatenated streams). Like python's `bz2.decompress`,
/// invalid data after the first complete stream is ignored.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len().saturating_mul(5).min(1 << 30));
    let mut off = 0usize;
    let mut streams = 0;
    while off < data.len() {
        let mark = out.len();
        match decode_stream(data, off, &mut out) {
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
