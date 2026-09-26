//! Raw DEFLATE (RFC 1951) decoder.
//!
//! * 64-bit bit buffer with a branchless 8-byte refill (bits above `bitcount` always hold the
//!   true next input bits, so OR-ing a fresh load on top is harmless).
//! * Table-driven Huffman decoding (libdeflate style): one u32 entry per lookup carries the
//!   decoded value and the *total* number of bits to consume (code + extra bits), so a
//!   length or distance and its extra bits leave the bit buffer with a single shift; the
//!   extra bits are then extracted from the saved buffer. Codes longer than the primary table
//!   width go through a second-level subtable.
//! * The fast loop needs no bounds checks: it runs while at least `FAST_IN` input bytes and
//!   `FAST_OUT` output bytes of capacity remain; one refill covers up to three literals or a
//!   whole length/distance pair, the next literal/length entry is looked up right after the
//!   refill (its latency overlaps the match copy), and copies may over-write in 16/32-byte
//!   chunks.
//! * Output goes straight into the spare capacity of the caller's `Vec` (no zero fill); the
//!   window is simply everything this stream has produced so far. Allocation failures are
//!   errors, never aborts.

use crate::error::{Error, Result};
use std::sync::OnceLock;

const LIT_BITS: u32 = 11;
const DIST_BITS: u32 = 8;
const PRE_BITS: u32 = 7;

// Entry layout: bits 0..7 = bits to consume (code length + extra bits; the primary width for
// subtable pointers), bits 8..11 = code length (shift of the extra bits within the saved bit
// buffer; subtable width for pointers), flags in bits 12..15 and 31, value in bits 16..30.
const F_BAD: u32 = 1 << 12;
const F_EOB: u32 = 1 << 13;
const F_SUB: u32 = 1 << 14;
/// Anything but a literal or a length / distance: subtable pointer, end of block, bad code.
const F_EXC: u32 = 1 << 15;
const F_LIT: u32 = 1 << 31;
const BAD: u32 = F_EXC | F_BAD;

const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const PRECODE_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Input bytes that must remain for the fast loop (each iteration refills once, reading 8
/// bytes).
const FAST_IN: usize = 16;
/// Output capacity that must remain for the fast loop: longest match + copy over-run.
const FAST_OUT: usize = 258 + 64;
/// Largest possible expansion of DEFLATE data (a 258-byte match in 2 bits).
const MAX_RATIO: usize = 1032;

fn corrupt(what: &str) -> Error {
    Error::Msg(format!("inflate: corrupt data ({what})"))
}

fn alloc_error() -> Error {
    Error::Msg("inflate: out of memory".into())
}

/// Entry for literal/length symbol `sym` whose code has `l` bits (beyond the table index
/// consumed so far).
fn litlen_entry(sym: usize, l: u32) -> u32 {
    match sym {
        0..=255 => F_LIT | ((sym as u32) << 16) | l,
        256 => F_EXC | F_EOB | l,
        257..=285 => {
            let x = LEN_EXTRA[sym - 257] as u32;
            ((LEN_BASE[sym - 257] as u32) << 16) | (l << 8) | (l + x)
        }
        _ => BAD,
    }
}

fn dist_entry(sym: usize, l: u32) -> u32 {
    if sym < 30 {
        let x = DIST_EXTRA[sym] as u32;
        ((DIST_BASE[sym] as u32) << 16) | (l << 8) | (l + x)
    } else {
        BAD
    }
}

fn pre_entry(sym: usize, l: u32) -> u32 {
    ((sym as u32) << 16) | l
}

/// Kind of code being built (zlib's rules for incomplete codes differ).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Pre,
    Lit,
    Dist,
}

/// Builds a two-level decode table for canonical Huffman code `lens` into `table`.
fn build_table(lens: &[u8], bits: u32, kind: Kind, table: &mut Vec<u32>) -> Result<()> {
    let entry: fn(usize, u32) -> u32 = match kind {
        Kind::Pre => pre_entry,
        Kind::Lit => litlen_entry,
        Kind::Dist => dist_entry,
    };
    let mut count = [0u16; 16];
    for &l in lens {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let max_len = (1..16).rev().find(|&l| count[l] != 0).unwrap_or(0);
    table.clear();
    table.resize(1 << bits, BAD);
    if max_len == 0 {
        // No codes at all: every lookup is invalid (legal for a distance code that is never
        // used; the literal/length code is rejected by the caller since EOB is missing).
        return if kind == Kind::Pre { Err(corrupt("empty code length code")) } else { Ok(()) };
    }
    let mut left: i32 = 1;
    for &c in &count[1..16] {
        left <<= 1;
        left -= c as i32;
        if left < 0 {
            return Err(corrupt("over-subscribed Huffman code"));
        }
    }
    if left > 0 && (kind == Kind::Pre || max_len != 1) {
        return Err(corrupt("incomplete Huffman code"));
    }
    // Canonical codes.
    let mut next = [0u32; 16];
    let mut code = 0u32;
    for l in 1..16 {
        code = (code + count[l - 1] as u32) << 1;
        next[l] = code;
    }
    let mask = (1u32 << bits) - 1;
    // Pass 1: bit-reversed codes and the longest code per primary-table prefix.
    let mut sub_len = [0u8; 1 << LIT_BITS];
    let mut codes = [0u32; 320];
    for (sym, &l) in lens.iter().enumerate() {
        if l == 0 {
            continue;
        }
        let c = next[l as usize];
        next[l as usize] += 1;
        let rev = c.reverse_bits() >> (32 - l as u32);
        codes[sym] = rev;
        if l as u32 > bits {
            let p = (rev & mask) as usize;
            sub_len[p] = sub_len[p].max(l);
        }
    }
    // Pass 2: fill.
    let mut sub_start = [0u32; 1 << LIT_BITS];
    for (sym, &l) in lens.iter().enumerate() {
        if l == 0 {
            continue;
        }
        let l = l as u32;
        let rev = codes[sym];
        if l <= bits {
            let v = entry(sym, l);
            let mut i = rev as usize;
            while i < (1 << bits) {
                table[i] = v;
                i += 1 << l;
            }
        } else {
            let p = (rev & mask) as usize;
            let sbits = sub_len[p] as u32 - bits;
            if sub_start[p] == 0 {
                let start = table.len() as u32;
                sub_start[p] = start;
                table.try_reserve(1 << sbits).map_err(|_| alloc_error())?;
                table.resize(table.len() + (1 << sbits), BAD);
                table[p] = F_EXC | F_SUB | (start << 16) | (sbits << 8) | bits;
            }
            let start = sub_start[p] as usize;
            let v = entry(sym, l - bits);
            let mut i = (rev >> bits) as usize;
            while i < (1 << sbits) {
                table[start + i] = v;
                i += 1 << (l - bits);
            }
        }
    }
    Ok(())
}

struct Tables {
    lit: Vec<u32>,
    dist: Vec<u32>,
}

fn fixed_tables() -> &'static Tables {
    static FIXED: OnceLock<Tables> = OnceLock::new();
    FIXED.get_or_init(|| {
        let mut lens = [0u8; 288];
        lens[..144].fill(8);
        lens[144..256].fill(9);
        lens[256..280].fill(7);
        lens[280..].fill(8);
        let mut lit = Vec::new();
        build_table(&lens, LIT_BITS, Kind::Lit, &mut lit).expect("fixed litlen table");
        let mut dist = Vec::new();
        build_table(&[5u8; 32], DIST_BITS, Kind::Dist, &mut dist).expect("fixed dist table");
        Tables { lit, dist }
    })
}

/// Bit reader state (the input slice is passed around separately).
struct Bits {
    buf: u64,
    count: u32,
    ip: usize,
}

impl Bits {
    /// Safe refill: top up to >= 56 bits, reading zeros past the end of the input.
    #[inline(always)]
    fn refill_slow(&mut self, input: &[u8]) {
        while self.count <= 56 {
            let b = input.get(self.ip).copied().unwrap_or(0);
            self.buf |= (b as u64) << self.count;
            self.ip += 1;
            self.count += 8;
        }
    }
    /// Input bits consumed so far.
    #[inline(always)]
    fn consumed_bits(&self) -> usize {
        self.ip * 8 - self.count as usize
    }
    #[inline(always)]
    fn take(&mut self, input: &[u8], n: u32) -> u32 {
        if self.count < n {
            self.refill_slow(input);
        }
        let v = (self.buf & ((1u64 << n) - 1)) as u32;
        self.buf >>= n;
        self.count -= n;
        v
    }
    fn check(&self, input: &[u8]) -> Result<()> {
        if self.consumed_bits() > input.len() * 8 { Err(corrupt("truncated input")) } else { Ok(()) }
    }
    /// Drops bits up to the next byte boundary and un-reads buffered whole bytes.
    fn align(&mut self) {
        let drop = self.count & 7;
        self.count -= drop;
        self.ip -= (self.count / 8) as usize;
        self.buf = 0;
        self.count = 0;
    }
}

/// Decodes a raw DEFLATE stream from `input`, appending to `out`. Back-references may only
/// reach bytes produced by this stream. Returns the number of input bytes consumed (the
/// stream end rounded up to a byte boundary).
pub fn inflate_into(input: &[u8], out: &mut Vec<u8>) -> Result<usize> {
    let start = out.len();
    let mut bits = Bits { buf: 0, count: 0, ip: 0 };
    let mut dynamic = Tables { lit: Vec::with_capacity(4096), dist: Vec::with_capacity(1024) };
    let mut pre = Vec::with_capacity(1 << PRE_BITS);
    let mut lens = [0u8; 320];
    loop {
        let hdr = bits.take(input, 3);
        bits.check(input)?;
        let last = hdr & 1 != 0;
        match hdr >> 1 {
            0 => {
                bits.align();
                let h = input.get(bits.ip..bits.ip + 4).ok_or_else(|| corrupt("truncated stored block"))?;
                let len = u16::from_le_bytes([h[0], h[1]]) as usize;
                let nlen = u16::from_le_bytes([h[2], h[3]]) as usize;
                if len != !nlen & 0xFFFF {
                    return Err(corrupt("stored block length check"));
                }
                bits.ip += 4;
                let src = input.get(bits.ip..bits.ip + len).ok_or_else(|| corrupt("truncated stored block"))?;
                out.try_reserve(len).map_err(|_| alloc_error())?;
                out.extend_from_slice(src);
                bits.ip += len;
            }
            1 => {
                let t = fixed_tables();
                decode_block(input, &mut bits, out, start, &t.lit, &t.dist)?;
            }
            2 => {
                let hlit = bits.take(input, 5) as usize + 257;
                let hdist = bits.take(input, 5) as usize + 1;
                let hclen = bits.take(input, 4) as usize + 4;
                if hlit > 286 || hdist > 30 {
                    return Err(corrupt("too many length or distance symbols"));
                }
                let mut plens = [0u8; 19];
                for &i in &PRECODE_ORDER[..hclen] {
                    plens[i] = bits.take(input, 3) as u8;
                }
                bits.check(input)?;
                build_table(&plens, PRE_BITS, Kind::Pre, &mut pre)?;
                let n = hlit + hdist;
                let mut i = 0;
                while i < n {
                    if bits.count < 16 {
                        bits.refill_slow(input);
                    }
                    let e = pre[(bits.buf & ((1 << PRE_BITS) - 1)) as usize];
                    if e & F_BAD != 0 {
                        return Err(corrupt("invalid code length code"));
                    }
                    let l = e & 0xFF;
                    bits.buf >>= l;
                    bits.count -= l;
                    let sym = (e >> 16) as u8;
                    match sym {
                        0..=15 => {
                            lens[i] = sym;
                            i += 1;
                        }
                        16 => {
                            if i == 0 {
                                return Err(corrupt("repeat with no previous length"));
                            }
                            let prev = lens[i - 1];
                            let r = 3 + bits.take(input, 2) as usize;
                            if i + r > n {
                                return Err(corrupt("too many code lengths"));
                            }
                            lens[i..i + r].fill(prev);
                            i += r;
                        }
                        _ => {
                            let r = if sym == 17 { 3 + bits.take(input, 3) } else { 11 + bits.take(input, 7) } as usize;
                            if i + r > n {
                                return Err(corrupt("too many code lengths"));
                            }
                            lens[i..i + r].fill(0);
                            i += r;
                        }
                    }
                }
                bits.check(input)?;
                if lens[256] == 0 {
                    return Err(corrupt("missing end-of-block code"));
                }
                build_table(&lens[..hlit], LIT_BITS, Kind::Lit, &mut dynamic.lit)?;
                build_table(&lens[hlit..n], DIST_BITS, Kind::Dist, &mut dynamic.dist)?;
                decode_block(input, &mut bits, out, start, &dynamic.lit, &dynamic.dist)?;
            }
            _ => return Err(corrupt("invalid block type")),
        }
        if last {
            break;
        }
    }
    bits.check(input)?;
    // Round the consumed bit count up to whole bytes.
    Ok(bits.consumed_bits().div_ceil(8))
}

/// Decodes one Huffman-coded block (until end-of-block).
fn decode_block(input: &[u8], bits: &mut Bits, out: &mut Vec<u8>, start: usize, lt: &[u32], dt: &[u32]) -> Result<()> {
    const LMASK: u64 = (1 << LIT_BITS) - 1;
    const DMASK: u64 = (1 << DIST_BITS) - 1;
    let in_len = input.len();
    let inp = input.as_ptr();
    let mut buf = bits.buf;
    let mut cnt = bits.count;
    let mut ip = bits.ip;
    let mut pos = out.len();
    let mut cap = out.capacity();
    let mut base = out.as_mut_ptr();

    // Drops the bits of entry `e` (code + extra bits).
    macro_rules! consume {
        ($e:expr) => {{
            let n = $e & 0xFF;
            buf >>= n;
            cnt -= n;
        }};
    }
    // Extra-bits value of entry `e`, from the bit buffer as it was before consuming `e`.
    macro_rules! extra {
        ($saved:expr, $e:expr) => {{
            let e = $e;
            (($saved & ((1u64 << (e & 0xFF)) - 1)) >> ((e >> 8) & 0xF)) as usize
        }};
    }
    // Subtable lookup for pointer entry `e` (its primary bits are already consumed).
    macro_rules! sub {
        ($t:expr, $e:expr) => {{
            let e = $e;
            // SAFETY: build_table allocated 2^((e >> 8) & 15) entries at e >> 16.
            unsafe { *$t.get_unchecked((e >> 16) as usize + (buf & ((1u64 << ((e >> 8) & 0xF)) - 1)) as usize) }
        }};
    }
    // Grows the output so at least FAST_OUT bytes of capacity follow `pos`.
    macro_rules! grow {
        ($need:expr) => {{
            // SAFETY: bytes [0, pos) have been written.
            unsafe { out.set_len(pos) };
            let want = ((pos - start).max(1 << 16)).max($need) + FAST_OUT;
            out.try_reserve(want).map_err(|_| alloc_error())?;
            cap = out.capacity();
            base = out.as_mut_ptr();
        }};
    }
    macro_rules! done {
        () => {{
            bits.buf = buf;
            bits.count = cnt;
            bits.ip = ip;
            // SAFETY: bytes [0, pos) have been written.
            unsafe { out.set_len(pos) };
            return Ok(());
        }};
    }

    loop {
        // ---------------- fast loop ----------------
        if ip + FAST_IN <= in_len && pos + FAST_OUT <= cap {
            let in_end = in_len - FAST_IN;
            let out_end = cap - FAST_OUT;
            // Branchless refill to >= 56 bits (ip <= in_end, so 8 bytes are readable).
            macro_rules! refill {
                () => {{
                    // SAFETY: ip + 8 <= in_len (see FAST_IN).
                    let w = u64::from_le(unsafe { (inp.add(ip) as *const u64).read_unaligned() });
                    buf |= w << cnt;
                    ip += ((63 - cnt) >> 3) as usize;
                    cnt |= 56;
                }};
            }
            // SAFETY (all table lookups below): masked indices < primary table size.
            macro_rules! lit_lookup {
                () => {
                    unsafe { *lt.get_unchecked((buf & LMASK) as usize) }
                };
            }
            refill!();
            let mut e = lit_lookup!();
            // Invariant at the top: >= 56 valid bits and `e` is the entry for them.
            while ip <= in_end && pos <= out_end {
                let mut saved = buf;
                consume!(e);
                if e & F_LIT != 0 {
                    // Up to three literals per refill (<= 45 bits).
                    // SAFETY: pos < out_end; three literals fit in FAST_OUT.
                    unsafe { *base.add(pos) = (e >> 16) as u8 };
                    pos += 1;
                    e = lit_lookup!();
                    if e & F_LIT != 0 {
                        consume!(e);
                        unsafe { *base.add(pos) = (e >> 16) as u8 };
                        pos += 1;
                        e = lit_lookup!();
                        if e & F_LIT != 0 {
                            consume!(e);
                            unsafe { *base.add(pos) = (e >> 16) as u8 };
                            pos += 1;
                            e = lit_lookup!();
                        }
                    }
                    // >= 11 valid bits remain, so `e` is valid; top up for the next symbol.
                    refill!();
                    continue;
                }
                if e & F_EXC != 0 {
                    if e & F_SUB != 0 {
                        e = sub!(lt, e);
                        saved = buf;
                        consume!(e);
                        if e & F_LIT != 0 {
                            unsafe { *base.add(pos) = (e >> 16) as u8 };
                            pos += 1;
                            refill!();
                            e = lit_lookup!();
                            continue;
                        }
                    }
                    if e & F_EXC != 0 {
                        if e & F_EOB != 0 {
                            done!();
                        }
                        return Err(corrupt("invalid literal/length code"));
                    }
                }
                // Length (<= 20 bits) + distance (<= 28 bits) fit in the >= 56 bits.
                let len = (e >> 16) as usize + extra!(saved, e);
                let mut d = unsafe { *dt.get_unchecked((buf & DMASK) as usize) };
                saved = buf;
                consume!(d);
                if d & F_EXC != 0 {
                    if d & F_SUB != 0 {
                        d = sub!(dt, d);
                        saved = buf;
                        consume!(d);
                    }
                    if d & F_EXC != 0 {
                        return Err(corrupt("invalid distance code"));
                    }
                }
                let dist = (d >> 16) as usize + extra!(saved, d);
                refill!();
                e = lit_lookup!();
                if dist > pos - start {
                    return Err(corrupt("distance too far back"));
                }
                // SAFETY: dist <= pos - start, pos + len + 64 <= cap.
                unsafe { copy_fast(base, pos - dist, pos, len) };
                pos += len;
            }
            if ip <= in_end {
                // Output space ran low.
                grow!(0);
                continue;
            }
        }

        // ---------------- careful single step ----------------
        if pos + FAST_OUT > cap && ip + FAST_IN <= in_len {
            grow!(0);
            continue;
        }
        if cnt < 48 {
            let mut b = Bits { buf, count: cnt, ip };
            b.refill_slow(input);
            buf = b.buf;
            cnt = b.count;
            ip = b.ip;
        }
        let mut saved = buf;
        let mut e = lt[(buf & LMASK) as usize];
        consume!(e);
        if e & F_SUB != 0 {
            e = sub!(lt, e);
            saved = buf;
            consume!(e);
        }
        if ip * 8 - cnt as usize > in_len * 8 {
            return Err(corrupt("truncated input"));
        }
        if e & F_LIT != 0 {
            if pos >= cap {
                grow!(1);
            }
            // SAFETY: pos < cap.
            unsafe { *base.add(pos) = (e >> 16) as u8 };
            pos += 1;
            continue;
        }
        if e & F_EXC != 0 {
            if e & F_EOB != 0 {
                done!();
            }
            return Err(corrupt("invalid literal/length code"));
        }
        let len = (e >> 16) as usize + extra!(saved, e);
        let mut d = dt[(buf & DMASK) as usize];
        saved = buf;
        consume!(d);
        if d & F_SUB != 0 {
            d = sub!(dt, d);
            saved = buf;
            consume!(d);
        }
        if d & F_EXC != 0 {
            return Err(corrupt("invalid distance code"));
        }
        let dist = (d >> 16) as usize + extra!(saved, d);
        if ip * 8 - cnt as usize > in_len * 8 {
            return Err(corrupt("truncated input"));
        }
        if dist > pos - start {
            return Err(corrupt("distance too far back"));
        }
        if pos + len > cap {
            grow!(len);
        }
        for i in 0..len {
            // SAFETY: pos + len <= cap, dist <= pos - start.
            unsafe { *base.add(pos + i) = *base.add(pos + i - dist) };
        }
        pos += len;
    }
}

/// LZ77 copy with over-write of up to 63 bytes past `dst + len`.
///
/// # Safety
/// `src < dst`, `dst + len + 64` within the allocation, bytes `[src, dst)` initialised.
#[inline(always)]
unsafe fn copy_fast(base: *mut u8, src: usize, dst: usize, len: usize) {
    use std::ptr::copy_nonoverlapping as cp;
    let dist = dst - src;
    unsafe {
        let s = base.add(src);
        let d = base.add(dst);
        if dist >= 32 {
            cp(s, d, 32);
            if len > 32 {
                let mut i = 32;
                while i < len {
                    cp(s.add(i), d.add(i), 32);
                    i += 32;
                }
            }
        } else if dist >= 16 {
            let mut i = 0;
            while i < len {
                cp(s.add(i), d.add(i), 16);
                i += 16;
            }
        } else if dist == 1 {
            std::ptr::write_bytes(d, *s, len);
        } else {
            // Short period: replicate the pattern until it is >= 8 bytes, then copy 8 at a
            // time (each chunk reads bytes at least 8 back).
            let mut i = 0;
            while i < dist.min(len) {
                *d.add(i) = *s.add(i);
                i += 1;
            }
            let period = dist * 8_usize.div_ceil(dist);
            while i < period.min(len) {
                *d.add(i) = *d.add(i - dist);
                i += 1;
            }
            while i < len {
                cp(d.add(i - period), d.add(i), 8);
                i += 8;
            }
        }
    }
}

/// Decompresses a raw DEFLATE stream.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    // Size hint only; a failed reservation just means growing later.
    let _ = out.try_reserve(data.len().saturating_mul(4).clamp(1 << 12, 1 << 28));
    inflate_into(data, &mut out)?;
    Ok(out)
}

/// Decompresses a raw DEFLATE stream whose uncompressed size is known (e.g. from a ZIP
/// directory); fails if the output size differs. An impossible `size` (more than DEFLATE
/// can expand `data` to) fails without allocating.
pub fn decompress_sized(data: &[u8], size: usize) -> Result<Vec<u8>> {
    if size > data.len().saturating_mul(MAX_RATIO).saturating_add(MAX_RATIO) {
        return Err(corrupt("uncompressed size mismatch"));
    }
    let mut out = Vec::new();
    out.try_reserve_exact(size.saturating_add(FAST_OUT)).map_err(|_| alloc_error())?;
    inflate_into(data, &mut out)?;
    if out.len() != size {
        return Err(corrupt("uncompressed size mismatch"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codecs_inflate_stored_fixed_dynamic() {
        // Stored block "abc".
        assert_eq!(decompress(&[0x01, 0x03, 0x00, 0xfc, 0xff, b'a', b'b', b'c']).unwrap(), b"abc");
        // Fixed Huffman: python zlib.compress(b"hello hello hello", wbits=-15) with level 1.
        let fixed = [0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x90, 0x00];
        assert_eq!(decompress(&fixed).unwrap(), b"hello hello hello");
        // Empty fixed block.
        assert_eq!(decompress(&[0x03, 0x00]).unwrap(), b"");
    }

    #[test]
    fn codecs_inflate_rejects_garbage() {
        assert!(decompress(&[0x07]).is_err()); // reserved block type
        assert!(decompress(&[0x01, 0x03, 0x00, 0xfc, 0xfe, b'a']).is_err()); // bad NLEN
        assert!(decompress(&[0xcb, 0x48]).is_err()); // truncated
        let mut s = 0x2545_F491_4F6C_DD1Du64;
        for n in 0..2000usize {
            let mut v = vec![0u8; n % 97 + 1];
            for b in v.iter_mut() {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                *b = s as u8;
            }
            let _ = decompress(&v);
        }
    }
}
