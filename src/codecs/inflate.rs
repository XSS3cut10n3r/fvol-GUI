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

/// Checksum of the produced output, updated chunk by chunk while the bytes are still in
/// cache (a separate pass afterwards would re-read the whole output from memory).
pub(crate) struct Check {
    kind: CheckKind,
    /// Current checksum value (CRC-32 or Adler-32, standard initial values).
    pub(crate) value: u32,
    /// Output position up to which `value` is computed.
    done: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CheckKind {
    None,
    Crc32,
    Adler32,
}

/// Output bytes between checksum updates (the chunk stays in L2).
const CHECK_CHUNK: usize = 64 << 10;

impl Check {
    pub(crate) fn none() -> Check {
        Check { kind: CheckKind::None, value: 0, done: 0 }
    }
    pub(crate) fn crc32() -> Check {
        Check { kind: CheckKind::Crc32, value: 0, done: 0 }
    }
    pub(crate) fn adler32() -> Check {
        Check { kind: CheckKind::Adler32, value: 1, done: 0 }
    }

    /// Output position at which the fast loop should pause for an update.
    #[inline]
    fn limit(&self) -> usize {
        if self.kind == CheckKind::None { usize::MAX } else { self.done + CHECK_CHUNK }
    }

    /// Folds `base[done..upto]` (written output) into the checksum.
    ///
    /// # Safety
    /// `base[..upto]` initialised.
    unsafe fn update(&mut self, base: *const u8, upto: usize) {
        if upto <= self.done {
            return;
        }
        // SAFETY: caller guarantees initialised bytes below `upto`.
        let chunk = unsafe { std::slice::from_raw_parts(base.add(self.done), upto - self.done) };
        self.value = match self.kind {
            CheckKind::None => 0,
            CheckKind::Crc32 => super::crc::crc32_update(self.value, chunk),
            CheckKind::Adler32 => super::zlib::adler32_update(self.value, chunk),
        };
        self.done = upto;
    }
}

/// Decodes a raw DEFLATE stream from `input`, appending to `out`. Back-references may only
/// reach bytes produced by this stream. Returns the number of input bytes consumed (the
/// stream end rounded up to a byte boundary).
pub fn inflate_into(input: &[u8], out: &mut Vec<u8>) -> Result<usize> {
    inflate_into_check(input, out, &mut Check::none())
}

/// As [`inflate_into`], also computing `check` over the bytes this stream appends.
pub(crate) fn inflate_into_check(input: &[u8], out: &mut Vec<u8>, check: &mut Check) -> Result<usize> {
    let start = out.len();
    check.done = start;
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
                // SAFETY: out[..len] initialised.
                unsafe { check.update(out.as_ptr(), out.len()) };
                bits.ip += len;
            }
            1 => {
                let t = fixed_tables();
                decode_block(input, &mut bits, out, start, &t.lit, &t.dist, check)?;
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
                decode_block(input, &mut bits, out, start, &dynamic.lit, &dynamic.dist, check)?;
            }
            _ => return Err(corrupt("invalid block type")),
        }
        if last {
            break;
        }
    }
    bits.check(input)?;
    // SAFETY: out[..len] initialised.
    unsafe { check.update(out.as_ptr(), out.len()) };
    // Round the consumed bit count up to whole bytes.
    Ok(bits.consumed_bits().div_ceil(8))
}

/// Decodes one Huffman-coded block (until end-of-block).
fn decode_block(
    input: &[u8],
    bits: &mut Bits,
    out: &mut Vec<u8>,
    start: usize,
    lt: &[u32],
    dt: &[u32],
    check: &mut Check,
) -> Result<()> {
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
            // The fast loop also pauses at checksum chunk boundaries.
            let out_end = (cap - FAST_OUT).min(check.limit());
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
                if pos + FAST_OUT > cap {
                    // Output space ran low.
                    grow!(0);
                } else {
                    // Checksum chunk boundary.
                    // SAFETY: base[..pos] written.
                    unsafe { check.update(base, pos) };
                }
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

/// Test data and a small raw-DEFLATE writer shared by the inflate, zlib and gzip tests.
#[cfg(test)]
pub(crate) mod test_util {
    use super::{DIST_BASE, DIST_EXTRA, LEN_BASE, LEN_EXTRA, PRECODE_ORDER};

    /// 1000 bytes of random words (python `random.Random(7)`), used for the real
    /// zlib / GNU gzip vectors.
    pub(crate) const TEXT: &[u8] = b"0x struct type the kernel { kernel 0x } the { _EPROCESS the kernel type type kernel \
        _EPROCESS kernel { type the } kernel _EPROCESS } the } } type the _EPROCESS the { \
        struct offset type struct { kernel } offset { struct kernel } } _EPROCESS 0x kernel { \
        kernel } the } _EPROCESS pointer { type 0x pointer } pointer 0x offset _EPROCESS struct \
        _EPROCESS kernel } offset { pointer 0x pointer offset } kernel kernel { type struct 0x \
        struct pointer type the kernel { } 0x 0x 0x } pointer } pointer kernel kernel offset \
        pointer kernel the offset } pointer offset type 0x the pointer 0x struct } kernel \
        pointer the _EPROCESS offset struct _EPROCESS type type pointer kernel struct pointer \
        type { offset struct type { offset type 0x type _EPROCESS struct kernel struct struct \
        _EPROCESS _EPROCESS the pointer } struct offset offset the struct type { 0x } } 0x \
        struct { } the pointer { type type type type kernel pointer type the _EPROCESS kernel \
        _EPROCESS pointer struct kernel 0x } the kernel the } struct { ke";

    /// LSB-first bit writer (DEFLATE bit order).
    pub(crate) struct BitW {
        pub(crate) out: Vec<u8>,
        acc: u64,
        n: u32,
    }

    impl BitW {
        pub(crate) fn new() -> BitW {
            BitW { out: Vec::new(), acc: 0, n: 0 }
        }

        pub(crate) fn bits(&mut self, v: u32, n: u32) {
            self.acc |= (v as u64 & ((1u64 << n) - 1)) << self.n;
            self.n += n;
            while self.n >= 8 {
                self.out.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
        }

        /// A Huffman code (sent most significant bit first).
        pub(crate) fn code(&mut self, code: u32, len: u32) {
            self.bits(code.reverse_bits() >> (32 - len), len);
        }

        pub(crate) fn align(&mut self) {
            if !self.n.is_multiple_of(8) {
                self.bits(0, 8 - self.n % 8);
            }
        }

        pub(crate) fn finish(mut self) -> Vec<u8> {
            self.align();
            self.out
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Tok {
        Lit(u8),
        /// (length, distance)
        Match(usize, usize),
    }

    /// Reference LZ77 expansion.
    pub(crate) fn expand(toks: &[Tok]) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        for &t in toks {
            match t {
                Tok::Lit(b) => v.push(b),
                Tok::Match(len, dist) => {
                    for _ in 0..len {
                        v.push(v[v.len() - dist]);
                    }
                }
            }
        }
        v
    }

    /// Canonical Huffman codes for `lens`.
    pub(crate) fn canonical(lens: &[u8]) -> Vec<u32> {
        let mut count = [0u32; 16];
        for &l in lens {
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut next = [0u32; 16];
        let mut code = 0;
        for l in 1..16 {
            code = (code + count[l - 1]) << 1;
            next[l] = code;
        }
        lens.iter()
            .map(|&l| {
                if l == 0 {
                    0
                } else {
                    let c = next[l as usize];
                    next[l as usize] += 1;
                    c
                }
            })
            .collect()
    }

    /// (symbol index from 0, extra bit count, extra value) for a match length / distance.
    pub(crate) fn len_code(len: usize) -> (usize, u32, u32) {
        let i = LEN_BASE.iter().rposition(|&b| b as usize <= len).unwrap();
        (i, LEN_EXTRA[i] as u32, (len - LEN_BASE[i] as usize) as u32)
    }

    pub(crate) fn dist_code(dist: usize) -> (usize, u32, u32) {
        let i = DIST_BASE.iter().rposition(|&b| b as usize <= dist).unwrap();
        (i, DIST_EXTRA[i] as u32, (dist - DIST_BASE[i] as usize) as u32)
    }

    /// Fixed-code lengths (288 literal/length, 32 distance).
    pub(crate) fn fixed_lens() -> (Vec<u8>, Vec<u8>) {
        let mut ll = vec![8u8; 288];
        ll[144..256].fill(9);
        ll[256..280].fill(7);
        (ll, vec![5u8; 32])
    }

    /// Complete codes over all 286 literal/length and 30 distance symbols.
    pub(crate) fn full_lens() -> (Vec<u8>, Vec<u8>) {
        // 226 * 2^-8 + 60 * 2^-9 = 1 and 2 * 2^-4 + 28 * 2^-5 = 1.
        let mut ll = vec![8u8; 286];
        ll[226..].fill(9);
        let mut dl = vec![5u8; 30];
        dl[..2].fill(4);
        (ll, dl)
    }

    /// Writes `toks` + end-of-block with the codes `ll` / `dl`.
    pub(crate) fn put_tokens(w: &mut BitW, toks: &[Tok], ll: &[u8], dl: &[u8]) {
        let lc = canonical(ll);
        let dc = canonical(dl);
        for &t in toks {
            match t {
                Tok::Lit(b) => w.code(lc[b as usize], ll[b as usize] as u32),
                Tok::Match(len, dist) => {
                    let (s, eb, ev) = len_code(len);
                    w.code(lc[257 + s], ll[257 + s] as u32);
                    w.bits(ev, eb);
                    let (d, deb, dev) = dist_code(dist);
                    w.code(dc[d], dl[d] as u32);
                    w.bits(dev, deb);
                }
            }
        }
        w.code(lc[256], ll[256] as u32);
    }

    pub(crate) fn stored_block(w: &mut BitW, data: &[u8], last: bool) {
        assert!(data.len() <= 0xFFFF);
        w.bits(last as u32, 1);
        w.bits(0, 2);
        w.align();
        w.bits(data.len() as u32, 16);
        w.bits(!data.len() as u32 & 0xFFFF, 16);
        w.out.extend_from_slice(data);
    }

    pub(crate) fn fixed_block(w: &mut BitW, toks: &[Tok], last: bool) {
        w.bits(last as u32, 1);
        w.bits(1, 2);
        let (ll, dl) = fixed_lens();
        put_tokens(w, toks, &ll, &dl);
    }

    /// Dynamic block header: HLIT/HDIST/HCLEN, the code-length code (symbols 0..15, 4 bits
    /// each, complete) and the code lengths `ll` ++ `dl`, one symbol per length.
    pub(crate) fn dynamic_header(w: &mut BitW, ll: &[u8], dl: &[u8], last: bool) {
        w.bits(last as u32, 1);
        w.bits(2, 2);
        w.bits((ll.len() - 257) as u32, 5);
        w.bits((dl.len() - 1) as u32, 5);
        w.bits(19 - 4, 4);
        for &sym in &PRECODE_ORDER {
            w.bits(if sym < 16 { 4 } else { 0 }, 3);
        }
        for &l in ll.iter().chain(dl) {
            w.code(l as u32, 4);
        }
    }

    pub(crate) fn dynamic_block(w: &mut BitW, toks: &[Tok], ll: &[u8], dl: &[u8], last: bool) {
        dynamic_header(w, ll, dl, last);
        put_tokens(w, toks, ll, dl);
    }

    pub(crate) fn xorshift(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    /// Random literals and matches (distances within the output so far and <= 32768).
    pub(crate) fn random_tokens(n: usize, seed: u64, pos0: usize) -> Vec<Tok> {
        let mut s = seed | 1;
        let mut pos = pos0;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let r = xorshift(&mut s);
            if pos == 0 || r.is_multiple_of(3) {
                v.push(Tok::Lit((r >> 8) as u8));
                pos += 1;
            } else {
                let len = match r % 7 {
                    0 => 258,
                    1 => 3 + (r >> 20) as usize % 30,
                    _ => 3 + (r >> 20) as usize % 256,
                };
                let far = pos.min(32768);
                let dist = match (r >> 40) % 4 {
                    0 => 1 + (r >> 44) as usize % far.min(16),
                    1 => far,
                    _ => 1 + (r >> 44) as usize % far,
                };
                v.push(Tok::Match(len, dist));
                pos += len;
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::*;
    use super::*;

    // raw deflate (python zlib) of TEXT: level 1 Z_FIXED (fixed block), levels 6, 9 (dynamic)
    const RAW_TEXT: [&[u8]; 3] = [
        &[
            0x33, 0xa8, 0x50, 0x28, 0x2e, 0x29, 0x2a, 0x4d, 0x2e, 0x51, 0x28, 0xa9, 0x2c, 0x48, 0x55, 0x28, 0xc9, 0x48, 0x55, 0xc8,
            0x4e, 0x2d, 0xca, 0x4b, 0xcd, 0x51, 0xa8, 0x86, 0x31, 0x0c, 0x2a, 0x14, 0x6a, 0xc1, 0x12, 0xd5, 0x0a, 0xf1, 0xae, 0x01,
            0x41, 0xfe, 0xce, 0xae, 0xc1, 0xc1, 0xc8, 0x0a, 0x21, 0x1a, 0x41, 0xba, 0xa1, 0x3a, 0x11, 0xaa, 0xe0, 0x46, 0xc1, 0x0d,
            0xaf, 0xc5, 0x54, 0x04, 0x31, 0xbc, 0x16, 0x64, 0x09, 0xcc, 0x09, 0x08, 0x13, 0x40, 0x0e, 0xaa, 0x86, 0x39, 0x31, 0x3f,
            0x2d, 0xad, 0x38, 0x15, 0xea, 0x52, 0xa8, 0xab, 0xe1, 0xae, 0xac, 0x55, 0x80, 0xca, 0xc2, 0x55, 0x43, 0x2d, 0x07, 0x19,
            0x8c, 0x30, 0x0f, 0xe8, 0x19, 0xb8, 0xa3, 0xe0, 0x0a, 0x40, 0x96, 0x20, 0x2b, 0x2a, 0xc8, 0xcf, 0xcc, 0x2b, 0x49, 0x2d,
            0x02, 0x5a, 0x0c, 0x76, 0x11, 0x50, 0x0f, 0x4c, 0xa4, 0x16, 0xce, 0x02, 0x0a, 0x42, 0x2d, 0x44, 0x18, 0x0e, 0x75, 0x13,
            0x42, 0x00, 0x6e, 0x03, 0xdc, 0x6d, 0x30, 0x83, 0x90, 0xcc, 0x84, 0xca, 0xc1, 0x43, 0x06, 0xee, 0x3e, 0xb0, 0xe5, 0x50,
            0x33, 0x81, 0xea, 0xa1, 0x2c, 0x98, 0x09, 0xf0, 0xc0, 0x82, 0xab, 0xaf, 0x55, 0x00, 0xaa, 0x82, 0x20, 0x84, 0x3b, 0x11,
            0x2c, 0xa8, 0x3a, 0x28, 0x05, 0xb5, 0x15, 0x66, 0x1a, 0x54, 0x14, 0x14, 0x12, 0x70, 0xf7, 0xc0, 0xe4, 0xa0, 0x02, 0xb0,
            0xb0, 0x00, 0xa9, 0x81, 0x49, 0x21, 0x9c, 0x05, 0x77, 0x3e, 0x4c, 0x0a, 0xa4, 0x0c, 0x11, 0x12, 0x50, 0x33, 0x30, 0x42,
            0x08, 0xe2, 0x0b, 0x50, 0xbc, 0xc3, 0xf4, 0x41, 0x5d, 0x82, 0xcd, 0xb7, 0xd5, 0x30, 0xb7, 0x41, 0x25, 0xc1, 0x9a, 0xe1,
            0x82, 0x70, 0xf7, 0x81, 0x4c, 0x43, 0xd8, 0x0c, 0x55, 0x8b, 0x6a, 0x2c, 0x86, 0x3b, 0x10, 0xea, 0x91, 0xbd, 0x57, 0x0b,
            0x0b, 0x74, 0xa8, 0xf3, 0x61, 0x21, 0x01, 0xf4, 0x1a, 0xaa, 0x13, 0x80, 0xe1, 0x00, 0x4a, 0x67, 0x88, 0xe0, 0xa8, 0x06,
            0xf2, 0x90, 0x4d, 0x82, 0x26, 0x25, 0x84, 0x77, 0xc1, 0x2c, 0xa8, 0xa3, 0x60, 0x5e, 0x87, 0xc8, 0xa2, 0x84, 0x1b, 0x54,
            0x05, 0xc2, 0x79, 0x30, 0xb5, 0xa8, 0xde, 0x02, 0xdb, 0x0f, 0xb2, 0x0f, 0xaa, 0x1e, 0xc4, 0x84, 0x3b, 0x1e, 0x94, 0x47,
            0x00,
        ],
        &[
            0x6d, 0x53, 0x6d, 0x0a, 0x83, 0x30, 0x0c, 0xbd, 0x4a, 0x8f, 0xe0, 0x1d, 0x86, 0xbf, 0x37, 0xb6, 0x03, 0xec, 0xc7, 0xa8,
            0x38, 0x36, 0xa6, 0x68, 0x07, 0x8e, 0x92, 0xbb, 0xcf, 0x6a, 0x92, 0xe6, 0x43, 0x90, 0x5a, 0x92, 0x97, 0x97, 0x97, 0x8f,
            0x36, 0x4b, 0x98, 0xd3, 0xf4, 0x7d, 0xa4, 0x90, 0x7e, 0x63, 0x0c, 0xa9, 0x8f, 0xe1, 0x15, 0xa7, 0x4f, 0x7c, 0x87, 0x4c,
            0x97, 0x66, 0x09, 0xb0, 0x39, 0x72, 0xb8, 0xb7, 0x97, 0xeb, 0xf9, 0xd4, 0xde, 0x6e, 0x12, 0xb8, 0x07, 0x96, 0x03, 0x0d,
            0x15, 0xc5, 0x54, 0x4c, 0x0e, 0x1e, 0x04, 0xe8, 0x80, 0x8a, 0xd2, 0x79, 0x32, 0x49, 0x1c, 0xba, 0x6e, 0x8e, 0xa8, 0x14,
            0x4d, 0xac, 0x12, 0xc8, 0xcb, 0x68, 0x76, 0x80, 0xe0, 0x5b, 0x8b, 0xb1, 0xf5, 0x51, 0xfe, 0x0a, 0x1a, 0x87, 0xe7, 0x27,
            0xc5, 0x89, 0x74, 0xaf, 0x31, 0x64, 0x01, 0xbe, 0xad, 0x46, 0x4c, 0x58, 0xe3, 0x30, 0xb1, 0xab, 0x5f, 0x68, 0x13, 0xe1,
            0x74, 0x45, 0x1f, 0x77, 0x46, 0x37, 0x0d, 0x39, 0x1b, 0x9e, 0x13, 0x85, 0xf9, 0x79, 0x41, 0x41, 0xed, 0x1f, 0x1c, 0x28,
            0xd6, 0xf4, 0x98, 0xd5, 0x38, 0x0b, 0x1f, 0xeb, 0x31, 0x02, 0xa9, 0x17, 0x05, 0x23, 0xca, 0x40, 0x59, 0x2c, 0x9f, 0xf5,
            0xa9, 0x39, 0x22, 0x87, 0xeb, 0x50, 0x5d, 0x1e, 0xa3, 0xe4, 0xa8, 0xda, 0x6c, 0x68, 0xb4, 0x91, 0xf5, 0x95, 0xbf, 0x1b,
            0x8a, 0xa6, 0x75, 0x3a, 0xf4, 0xc6, 0xd5, 0xe6, 0xe9, 0xcd, 0xa3, 0x4c, 0x7d, 0x34, 0x12, 0xb6, 0x96, 0x83, 0x68, 0x47,
            0xc6, 0xb5, 0x32, 0xab, 0x64, 0x0e, 0xdb, 0x32, 0xbf, 0xff, 0xee, 0xb5, 0x10, 0x56, 0x97, 0xc5, 0x6f, 0x54, 0xcc, 0x11,
            0xe4, 0x1b, 0xf9, 0x03,
        ],
        &[
            0x6d, 0x53, 0x6d, 0x0a, 0x83, 0x30, 0x0c, 0xbd, 0x4a, 0x8f, 0xe0, 0x1d, 0x86, 0xbf, 0x37, 0xb6, 0x03, 0xec, 0xc7, 0xa8,
            0x38, 0x36, 0xa6, 0x68, 0x07, 0x8e, 0x92, 0xbb, 0xcf, 0x6a, 0x92, 0xe6, 0x43, 0x90, 0x5a, 0x92, 0x97, 0x97, 0x97, 0x8f,
            0x36, 0x4b, 0x98, 0xd3, 0xf4, 0x7d, 0xa4, 0x90, 0x7e, 0x63, 0x0c, 0xa9, 0x8f, 0xe1, 0x15, 0xa7, 0x4f, 0x7c, 0x87, 0x4c,
            0x97, 0x66, 0x09, 0xb0, 0x39, 0x72, 0xb8, 0xb7, 0x97, 0xeb, 0xf9, 0xd4, 0xde, 0x6e, 0x12, 0xb8, 0x07, 0x96, 0x03, 0x0d,
            0x15, 0xc5, 0x54, 0x4c, 0x0e, 0x1e, 0x04, 0xe8, 0x80, 0x8a, 0xd2, 0x79, 0x32, 0x49, 0x1c, 0xba, 0x6e, 0x8e, 0xa8, 0x14,
            0x4d, 0xac, 0x12, 0xc8, 0xcb, 0x68, 0x76, 0x80, 0xe0, 0x5b, 0x8b, 0xb1, 0xf5, 0x51, 0xfe, 0x0a, 0x1a, 0x87, 0xe7, 0x27,
            0xc5, 0x89, 0x74, 0xaf, 0x31, 0x64, 0x01, 0xbe, 0xad, 0x46, 0x4c, 0x58, 0xe3, 0x30, 0xb1, 0xab, 0x5f, 0x68, 0x13, 0xe1,
            0x74, 0x45, 0x1f, 0x77, 0x46, 0x37, 0x0d, 0x39, 0x1b, 0x9e, 0x13, 0x85, 0xf9, 0x79, 0x41, 0x41, 0xed, 0x1f, 0x1c, 0x28,
            0xd6, 0xf4, 0x98, 0xd5, 0x38, 0x0b, 0x1f, 0xeb, 0x31, 0x02, 0xa9, 0x17, 0x05, 0x23, 0xca, 0x40, 0x59, 0x2c, 0x9f, 0xf5,
            0xa9, 0x39, 0x22, 0x87, 0xeb, 0x50, 0x5d, 0x1e, 0xa3, 0xe4, 0xa8, 0xda, 0x6c, 0x68, 0xb4, 0x91, 0xf5, 0x95, 0xbf, 0x1b,
            0x8a, 0xa6, 0x75, 0x3a, 0xf4, 0xc6, 0xd5, 0xe6, 0xe9, 0xcd, 0xa3, 0x4c, 0x7d, 0x34, 0x12, 0xb6, 0x96, 0x83, 0x68, 0x47,
            0xc6, 0xb5, 0x32, 0xab, 0x64, 0x0e, 0xdb, 0x32, 0xbf, 0xff, 0xee, 0xb5, 0x10, 0x56, 0x97, 0xc5, 0x6f, 0x54, 0xcc, 0x11,
            0xe4, 0x1b, 0xf9, 0x03,
        ],
    ];

    #[test]
    fn codecs_inflate_stored_fixed_dynamic() {
        // Stored block "abc".
        assert_eq!(decompress(&[0x01, 0x03, 0x00, 0xfc, 0xff, b'a', b'b', b'c']).unwrap(), b"abc");
        // Fixed Huffman: python zlib.compress(b"hello hello hello", wbits=-15) with level 1.
        let fixed = [0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x90, 0x00];
        assert_eq!(decompress(&fixed).unwrap(), b"hello hello hello");
        // Empty fixed block.
        assert_eq!(decompress(&[0x03, 0x00]).unwrap(), b"");
        // Real zlib output: a fixed block (Z_FIXED) and dynamic blocks.
        assert_eq!(RAW_TEXT[0][0] >> 1 & 3, 1);
        assert_eq!(RAW_TEXT[1][0] >> 1 & 3, 2);
        for raw in RAW_TEXT {
            assert_eq!(decompress(raw).unwrap(), TEXT);
            assert_eq!(decompress_sized(raw, TEXT.len()).unwrap(), TEXT);
        }
        // All three block types in one stream (a stored block after a Huffman block starts
        // at the next byte boundary).
        let toks = random_tokens(3000, 1, 0);
        let mut want = expand(&toks);
        let mut w = BitW::new();
        fixed_block(&mut w, &toks, false);
        stored_block(&mut w, b"stored after fixed", false);
        want.extend_from_slice(b"stored after fixed");
        let more = random_tokens(3000, 2, want.len());
        let (ll, dl) = full_lens();
        dynamic_block(&mut w, &more, &ll, &dl, false);
        let mut all: Vec<Tok> = want.iter().map(|&b| Tok::Lit(b)).collect();
        all.extend_from_slice(&more);
        want = expand(&all);
        stored_block(&mut w, b"", false);
        fixed_block(&mut w, &[], true);
        let stream = w.finish();
        assert_eq!(decompress(&stream).unwrap(), want);
        // The consumed length is reported exactly (trailing data is left alone).
        let mut v = Vec::new();
        let mut padded = stream.clone();
        padded.extend_from_slice(b"TRAILER");
        assert_eq!(inflate_into(&padded, &mut v).unwrap(), stream.len());
        assert_eq!(v, want);
    }

    #[test]
    fn codecs_inflate_stored_over_64k() {
        let mut s = 5u64;
        let data: Vec<u8> = (0..200_000).map(|_| xorshift(&mut s) as u8).collect();
        let mut w = BitW::new();
        let chunks: Vec<&[u8]> = data.chunks(0xFFFF).collect();
        for (i, c) in chunks.iter().enumerate() {
            stored_block(&mut w, c, i + 1 == chunks.len());
        }
        let stream = w.finish();
        assert_eq!(decompress(&stream).unwrap(), data);
        assert_eq!(decompress_sized(&stream, data.len()).unwrap(), data);
        // A single 65535-byte stored block is the maximum; LEN/NLEN must agree.
        let mut bad = stream.clone();
        bad[3] ^= 1; // NLEN of the first block
        assert!(decompress(&bad).is_err());
    }

    #[test]
    fn codecs_inflate_all_byte_values() {
        let lits: Vec<Tok> = (0..=255u8).chain((0..=255u8).rev()).map(Tok::Lit).collect();
        let want = expand(&lits);
        let (ll, dl) = full_lens();
        for kind in 0..3 {
            let mut w = BitW::new();
            match kind {
                0 => fixed_block(&mut w, &lits, true),
                1 => dynamic_block(&mut w, &lits, &ll, &dl, true),
                _ => stored_block(&mut w, &want, true),
            }
            assert_eq!(decompress(&w.finish()).unwrap(), want, "block kind {kind}");
        }
    }

    #[test]
    fn codecs_inflate_max_distance() {
        let mut s = 77u64;
        let mut toks: Vec<Tok> = (0..32768).map(|_| Tok::Lit(xorshift(&mut s) as u8)).collect();
        toks.extend([Tok::Match(258, 32768), Tok::Match(3, 32768), Tok::Match(258, 1), Tok::Match(100, 32768)]);
        let want = expand(&toks);
        let (ll, dl) = full_lens();
        let mut w = BitW::new();
        fixed_block(&mut w, &toks, false);
        dynamic_block(&mut w, &[Tok::Match(258, 32768), Tok::Match(77, 32767)], &ll, &dl, true);
        let mut all = toks.clone();
        all.extend([Tok::Match(258, 32768), Tok::Match(77, 32767)]);
        let stream = w.finish();
        assert_eq!(decompress(&stream).unwrap(), expand(&all));
        assert_eq!(&decompress(&stream).unwrap()[..want.len()], &want[..]);
        // One byte short of the window: distance 32768 reaches before the stream start.
        let mut w = BitW::new();
        let mut short = toks[..32767].to_vec();
        short.push(Tok::Match(3, 32768));
        fixed_block(&mut w, &short, true);
        assert!(decompress(&w.finish()).is_err());
        // Back-references never reach bytes that were already in the output vector.
        let mut w = BitW::new();
        fixed_block(&mut w, &[Tok::Lit(b'a'), Tok::Match(3, 2)], true);
        let mut v = b"prefix".to_vec();
        assert!(inflate_into(&w.finish(), &mut v).is_err());
    }

    #[test]
    fn codecs_inflate_long_codes() {
        // Complete codes with lengths 1..=15 (16 symbols each): the longest literal/length
        // and distance codes go through the second-level tables.
        let lit_syms = [b'a' as usize, 256, b'b' as usize, 257, b'c' as usize, 265, 285, b'd' as usize, 270, b'e' as usize,
            275, b'f' as usize, 280, b'g' as usize, 284, b'h' as usize];
        let dist_syms = [0usize, 3, 4, 10, 15, 20, 25, 29, 1, 2, 5, 6, 7, 8, 9, 11];
        let lens: Vec<u8> = (1..=15).chain([15]).collect();
        let mut ll = vec![0u8; 286];
        let mut dl = vec![0u8; 30];
        for i in 0..16 {
            ll[lit_syms[i]] = lens[i];
            dl[dist_syms[i]] = lens[i];
        }
        // Tokens using every symbol, in particular the 15-bit ones.
        let lit_bytes = *b"abcdefgh";
        let len_of = |sym: usize| LEN_BASE[sym - 257] as usize;
        let dist_of = |sym: usize| DIST_BASE[sym] as usize;
        let mut toks: Vec<Tok> = Vec::new();
        let mut pos = 0usize;
        let mut s = 3u64;
        while pos < 40_000 {
            let r = xorshift(&mut s);
            if pos < 30_000 || r.is_multiple_of(2) {
                toks.push(Tok::Lit(lit_bytes[(r % 8) as usize]));
                pos += 1;
            } else {
                let lsym = [257usize, 265, 270, 275, 280, 284, 285][(r >> 8) as usize % 7];
                let d = dist_syms[(r >> 16) as usize % 16];
                let dist = dist_of(d);
                if dist > pos {
                    continue;
                }
                let len = len_of(lsym);
                toks.push(Tok::Match(len, dist));
                pos += len;
            }
        }
        let want = expand(&toks);
        let mut w = BitW::new();
        dynamic_block(&mut w, &toks, &ll, &dl, true);
        let stream = w.finish();
        assert_eq!(decompress(&stream).unwrap(), want);
        assert_eq!(decompress_sized(&stream, want.len()).unwrap(), want);
    }

    #[test]
    fn codecs_inflate_random_streams() {
        // Long streams through the fast loop (output growth, 64 KiB checksum chunks) and
        // the careful tail, in fixed, dynamic and stored blocks.
        for seed in 1..6u64 {
            let (ll, dl) = full_lens();
            let mut w = BitW::new();
            let mut all: Vec<Tok> = Vec::new();
            for b in 0..4 {
                let prev = expand(&all).len();
                let toks = random_tokens(20_000, seed * 10 + b, prev);
                match (seed + b) % 3 {
                    0 => fixed_block(&mut w, &toks, b == 3),
                    1 => dynamic_block(&mut w, &toks, &ll, &dl, b == 3),
                    _ => {
                        // The matches may reach into earlier blocks.
                        let mut full = all.clone();
                        full.extend_from_slice(&toks);
                        let bytes = expand(&full).split_off(prev);
                        for c in bytes.chunks(0xFFFF) {
                            stored_block(&mut w, c, false);
                        }
                        if b == 3 {
                            fixed_block(&mut w, &[], true);
                        }
                    }
                }
                all.extend_from_slice(&toks);
            }
            let want = expand(&all);
            let stream = w.finish();
            assert_eq!(decompress(&stream).unwrap(), want, "seed {seed}");
            assert_eq!(decompress_sized(&stream, want.len()).unwrap(), want, "seed {seed}");
        }
    }

    /// Streams with invalid codes or headers; each must fail (and not panic).
    #[test]
    fn codecs_inflate_invalid_codes() {
        // (expected error, stream)
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        let (ll, dl) = full_lens();
        let hdr = |f: &dyn Fn(&mut BitW)| {
            let mut w = BitW::new();
            f(&mut w);
            // Enough zero bits so a decoder never runs out while parsing.
            w.bits(0, 32);
            w.finish()
        };
        // Code-length code: over-subscribed (19 codes of length 1) and incomplete (one code).
        cases.push((
            "over-subscribed",
            hdr(&|w| {
                w.bits(1, 1);
                w.bits(2, 2);
                w.bits(0, 5);
                w.bits(0, 5);
                w.bits(15, 4);
                for _ in 0..19 {
                    w.bits(1, 3);
                }
            }),
        ));
        cases.push((
            "incomplete",
            hdr(&|w| {
                w.bits(1, 1);
                w.bits(2, 2);
                w.bits(0, 5);
                w.bits(0, 5);
                w.bits(0, 4);
                for i in 0..4 {
                    w.bits(if i == 3 { 1 } else { 0 }, 3);
                }
            }),
        ));
        // Literal/length code over-subscribed (three codes of length 1).
        let mut over = vec![0u8; 257];
        over[0] = 1;
        over[1] = 1;
        over[256] = 1;
        cases.push(("over-subscribed", hdr(&|w| dynamic_header(w, &over, &[1], true))));
        // Incomplete (two codes of length 2).
        let mut inc = vec![0u8; 257];
        inc[0] = 2;
        inc[256] = 2;
        cases.push(("incomplete", hdr(&|w| dynamic_header(w, &inc, &[1], true))));
        // No end-of-block code.
        let mut no_eob = ll.clone();
        no_eob[256] = 0;
        no_eob[255] = 7; // keep it complete otherwise irrelevant
        cases.push(("missing end-of-block", hdr(&|w| dynamic_header(w, &no_eob, &dl, true))));
        // Distance code over-subscribed / incomplete.
        cases.push(("over-subscribed", hdr(&|w| dynamic_header(w, &ll, &[1, 1, 1], true))));
        cases.push(("incomplete", hdr(&|w| dynamic_header(w, &ll, &[2, 2], true))));
        // HLIT 287 / 288 and HDIST 31 / 32 are out of range.
        cases.push((
            "too many length or distance symbols",
            hdr(&|w| {
                w.bits(1, 1);
                w.bits(2, 2);
                w.bits(30, 5);
                w.bits(0, 5);
            }),
        ));
        cases.push((
            "too many length or distance symbols",
            hdr(&|w| {
                w.bits(1, 1);
                w.bits(2, 2);
                w.bits(0, 5);
                w.bits(30, 5);
            }),
        ));
        // Repeat code 16 as the first length, and a repeat running past HLIT + HDIST.
        cases.push((
            "repeat with no previous length",
            hdr(&|w| {
                w.bits(1, 1);
                w.bits(2, 2);
                w.bits(0, 5);
                w.bits(0, 5);
                w.bits(15, 4);
                // Code-length code: 16 and 17 of length 1.
                for &sym in &PRECODE_ORDER {
                    w.bits(if sym == 16 || sym == 17 { 1 } else { 0 }, 3);
                }
                w.code(0, 1); // symbol 16
            }),
        ));
        cases.push((
            "too many code lengths",
            hdr(&|w| {
                w.bits(1, 1);
                w.bits(2, 2);
                w.bits(0, 5);
                w.bits(0, 5);
                w.bits(15, 4);
                // Code-length code: 18 (length 1) and 8 (length 1).
                for &sym in &PRECODE_ORDER {
                    w.bits(if sym == 18 || sym == 8 { 1 } else { 0 }, 3);
                }
                for _ in 0..3 {
                    w.code(1, 1); // symbol 18
                    w.bits(127, 7); // 138 zeros
                }
            }),
        ));
        // Fixed block: literal/length symbols 286/287 and distance symbols 30/31 are invalid.
        {
            let (fl, fd) = fixed_lens();
            let lc = canonical(&fl);
            let dc = canonical(&fd);
            for sym in [286usize, 287] {
                let mut w = BitW::new();
                w.bits(1, 1);
                w.bits(1, 2);
                w.code(lc[sym], fl[sym] as u32);
                cases.push(("invalid literal/length code", w.finish()));
            }
            for sym in [30usize, 31] {
                // Three literals, then a match whose distance symbol is 30/31.
                let mut w2 = BitW::new();
                w2.bits(1, 1);
                w2.bits(1, 2);
                for b in 1..=3u32 {
                    w2.code(lc[b as usize], 8);
                }
                w2.code(lc[257], fl[257] as u32);
                w2.code(dc[sym], 5);
                w2.bits(0, 16);
                cases.push(("invalid distance code", w2.finish()));
            }
        }
        // Reserved block type.
        cases.push(("invalid block type", vec![0x07, 0, 0, 0]));
        // Each fails at the intended check (not by running out of input).
        for (what, v) in &cases {
            match decompress(v) {
                Ok(_) => panic!("{what}: accepted"),
                Err(e) => assert!(e.to_string().contains(what), "{what}: got {e}"),
            }
        }
        // Allowed incomplete codes: a single literal/length or distance code of length 1.
        let mut one = vec![0u8; 257];
        one[256] = 1;
        let mut w = BitW::new();
        dynamic_block(&mut w, &[], &one, &[1], true);
        assert_eq!(decompress(&w.finish()).unwrap(), b"");
        // ... and a distance code with no codes at all when no match is used.
        let mut w = BitW::new();
        dynamic_block(&mut w, &[Tok::Lit(b'x')], &ll, &[0], true);
        assert_eq!(decompress(&w.finish()).unwrap(), b"x");
    }

    #[test]
    fn codecs_inflate_truncation() {
        let (ll, dl) = full_lens();
        let toks = random_tokens(400, 9, 0);
        let mut w = BitW::new();
        fixed_block(&mut w, &toks[..200], false);
        stored_block(&mut w, b"0123456789", false);
        dynamic_block(&mut w, &toks[200..], &ll, &dl, true);
        let stream = w.finish();
        assert!(decompress(&stream).is_ok());
        for n in 0..stream.len() {
            assert!(decompress(&stream[..n]).is_err(), "truncated at {n}");
        }
        for raw in RAW_TEXT {
            for n in 0..raw.len() {
                assert!(decompress(&raw[..n]).is_err(), "truncated at {n}");
            }
        }
    }

    #[test]
    fn codecs_inflate_sized() {
        let raw = RAW_TEXT[2];
        assert_eq!(decompress_sized(raw, TEXT.len()).unwrap(), TEXT);
        assert!(decompress_sized(raw, TEXT.len() - 1).is_err());
        assert!(decompress_sized(raw, TEXT.len() + 1).is_err());
        // Absurd sizes (e.g. from a corrupt ZIP directory) fail without allocating.
        assert!(decompress_sized(raw, 1 << 50).is_err());
        assert!(decompress_sized(raw, usize::MAX).is_err());
        assert!(decompress_sized(&[], 0).is_err());
    }

    #[test]
    fn codecs_inflate_rejects_garbage() {
        assert!(decompress(&[0x07]).is_err()); // reserved block type
        assert!(decompress(&[0x01, 0x03, 0x00, 0xfc, 0xfe, b'a']).is_err()); // bad NLEN
        assert!(decompress(&[0xcb, 0x48]).is_err()); // truncated
        assert!(decompress(&[]).is_err());
        let mut s = 0x2545_F491_4F6C_DD1Du64;
        for n in 0..2000usize {
            let v: Vec<u8> = (0..n % 97 + 1).map(|_| xorshift(&mut s) as u8).collect();
            let _ = decompress(&v);
        }
        // Bit flips and truncations of valid streams (all code paths), no panics.
        let (ll, dl) = full_lens();
        let mut w = BitW::new();
        let toks = random_tokens(3000, 4, 0);
        dynamic_block(&mut w, &toks, &ll, &dl, false);
        fixed_block(&mut w, &random_tokens(2000, 5, expand(&toks).len()), true);
        let streams = [w.finish(), RAW_TEXT[0].to_vec(), RAW_TEXT[2].to_vec()];
        for round in 0..3000 {
            let mut v = streams[round % 3].clone();
            for _ in 0..1 + round % 3 {
                let i = (xorshift(&mut s) as usize) % v.len();
                v[i] ^= 1 << (xorshift(&mut s) % 8);
            }
            if round % 7 == 0 {
                v.truncate((xorshift(&mut s) as usize) % v.len());
            }
            let _ = decompress(&v);
            let _ = decompress_sized(&v, (xorshift(&mut s) % 100_000) as usize);
        }
    }
}
