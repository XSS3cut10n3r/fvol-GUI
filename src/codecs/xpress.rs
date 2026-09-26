//! Microsoft Xpress decompression ([MS-XCA]): "Plain LZ77" (COMPRESSION_FORMAT_XPRESS) and
//! "LZ77+Huffman" (COMPRESSION_FORMAT_XPRESS_HUFF), the formats of the memory-manager store,
//! prefetch (MAM) files and WIM/WOF (Windows hibernation files use them too, but rsvol, like
//! volatility3 2.28.2, has no hibernation layer).
//!
//! Part of rsvol, a port of Volatility 3 (Volatility Software License 1.0).
//!
//! Both decoders write into a caller-provided buffer whose length is the expected
//! decompressed size (Windows always knows it). They stop when the buffer is full or the
//! input ends and return the number of bytes produced. Malformed input returns an error; no
//! input can make them panic or loop forever (every iteration produces output or consumes
//! input).

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XpressError {
    /// Input ended in the middle of an element.
    Truncated,
    /// A match refers to data before the start of the output.
    BadOffset,
    /// Invalid extended match length.
    BadLength,
    /// LZ77+Huffman: the code-length table does not describe a complete prefix code.
    BadTable,
}

impl fmt::Display for XpressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            XpressError::Truncated => "xpress: truncated input",
            XpressError::BadOffset => "xpress: bad match offset",
            XpressError::BadLength => "xpress: bad match length",
            XpressError::BadTable => "xpress: bad huffman table",
        };
        f.write_str(s)
    }
}

impl std::error::Error for XpressError {}

impl From<XpressError> for crate::error::Error {
    fn from(e: XpressError) -> Self {
        crate::error::Error::Msg(e.to_string())
    }
}

/// Copy `len` bytes from `op - off` to `op` with LZ77 (byte-by-byte forward) semantics,
/// truncated at the end of `out`. Returns the new output position.
#[inline(always)]
fn copy_match(out: &mut [u8], op: usize, off: usize, len: usize) -> Result<usize, XpressError> {
    if off == 0 || off > op {
        return Err(XpressError::BadOffset);
    }
    let room = out.len() - op;
    if off >= 8 && len <= 24 && room >= 24 {
        // the common short match: exactly three unconditional word copies, no loop
        // SAFETY: src [op-off, op-off+24) and dst [op, op+24) are inside `out` (room >= 24);
        // off >= 8 makes word-wise forward copying equal to byte-wise LZ77 copying.
        unsafe {
            let p = out.as_mut_ptr();
            let s = p.add(op - off);
            let d = p.add(op);
            (d as *mut u64).write_unaligned((s as *const u64).read_unaligned());
            (d.add(8) as *mut u64).write_unaligned((s.add(8) as *const u64).read_unaligned());
            (d.add(16) as *mut u64).write_unaligned((s.add(16) as *const u64).read_unaligned());
        }
        return Ok(op + len);
    }
    if off >= 8 && room >= len + 8 {
        // 8-byte word copies (may write up to 7 bytes past op+len, inside `out`, overwritten
        // later). Equivalent to a forward byte copy: every word read ends at or before the
        // first byte the same word writes because off >= 8.
        // SAFETY: src [op-off, op-off+len+7] and dst [op, op+len+7] are inside `out`
        // (room >= len + 8).
        unsafe {
            let p = out.as_mut_ptr();
            let mut k = 0;
            while k < len {
                let w = (p.add(op - off + k) as *const u64).read_unaligned();
                (p.add(op + k) as *mut u64).write_unaligned(w);
                k += 8;
            }
        }
        return Ok(op + len);
    }
    if off == 1 && room >= len + 8 {
        // run of one byte: 8-byte stores of the repeated byte
        let v = u64::from_ne_bytes([out[op - 1]; 8]);
        // SAFETY: writes stay below op + len + 8 <= out.len()
        unsafe {
            let p = out.as_mut_ptr();
            let mut k = 0;
            while k < len {
                (p.add(op + k) as *mut u64).write_unaligned(v);
                k += 8;
            }
        }
        return Ok(op + len);
    }
    let len = len.min(room);
    let src = op - off;
    if len <= 32 {
        // short (overlapping) matches: a plain forward byte loop beats memmove calls
        for k in 0..len {
            out[op + k] = out[src + k];
        }
    } else if off >= len {
        out.copy_within(src..src + len, op);
    } else {
        // periodic pattern: doubling non-overlapping copies (see snappy.rs)
        let mut copied = 0usize;
        while copied < len {
            let chunk = (len - copied).min(copied + off);
            out.copy_within(src..src + chunk, op + copied);
            copied += chunk;
        }
    }
    Ok(op + len)
}

// ---------------------------------------------------------------------------------------------
// Plain LZ77 ([MS-XCA] 2.4)
// ---------------------------------------------------------------------------------------------

/// Decompress Xpress "Plain LZ77" data into `out`; returns the number of bytes produced.
pub fn lz77_decompress_into(input: &[u8], out: &mut [u8]) -> Result<usize, XpressError> {
    lz77_impl::<true>(input, out)
}

/// Plain LZ77 decoder state (shared by the fast and the checked loop).
#[derive(Clone, Copy)]
struct Lz77State {
    ip: usize,
    op: usize,
    /// Flag bits not yet used: the low `flag_count` bits of `flags`, MSB first.
    flags: u32,
    flag_count: u32,
    /// Input position of the shared length nibble byte (0 = none; position 0 always holds
    /// flags).
    last_half: usize,
}

/// `FAST = false`: the checked loop alone (the differential oracle of the tests).
fn lz77_impl<const FAST: bool>(input: &[u8], out: &mut [u8]) -> Result<usize, XpressError> {
    let mut st = Lz77State { ip: 0, op: 0, flags: 0, flag_count: 0, last_half: 0 };
    if FAST {
        lz77_fast(input, out, &mut st)?;
    }
    lz77_checked(input, out, st)
}

/// Match length after the 3-bit field 7 ([MS-XCA] 2.4.4: shared nibbles, then 1, 2 or 4
/// extra bytes), without the minimum length 3. `ip` must be past the match word.
#[inline(always)]
fn lz77_long_len(input: &[u8], ip: &mut usize, last_half: &mut usize) -> Result<usize, XpressError> {
    let n = input.len();
    let mut len;
    if *last_half == 0 {
        if *ip >= n {
            return Err(XpressError::Truncated);
        }
        len = (input[*ip] & 0xf) as usize;
        *last_half = *ip;
        *ip += 1;
    } else {
        len = (input[*last_half] >> 4) as usize;
        *last_half = 0;
    }
    if len == 15 {
        if *ip >= n {
            return Err(XpressError::Truncated);
        }
        len = input[*ip] as usize;
        *ip += 1;
        if len == 255 {
            if n - *ip < 2 {
                return Err(XpressError::Truncated);
            }
            len = u16::from_le_bytes([input[*ip], input[*ip + 1]]) as usize;
            *ip += 2;
            if len == 0 {
                if n - *ip < 4 {
                    return Err(XpressError::Truncated);
                }
                len = u32::from_le_bytes([input[*ip], input[*ip + 1], input[*ip + 2], input[*ip + 3]]) as usize;
                *ip += 4;
            }
            if len < 15 + 7 {
                return Err(XpressError::BadLength);
            }
            len -= 15 + 7;
        }
        len += 15;
    }
    Ok(len + 7)
}

/// The bulk loop while the input has 64 and the output 64 bytes of slack: a whole run of
/// literal flags and a short non-overlapping match are one fixed 32-byte move each, and the
/// flag word is kept left-aligned above a sentinel bit. Everything else goes through the
/// same helpers as the checked loop, so results and errors are identical.
#[inline(never)]
fn lz77_fast(input: &[u8], out: &mut [u8], st: &mut Lz77State) -> Result<(), XpressError> {
    // per iteration at most: flags 4 + literals 32 + match 2 + length bytes 8
    const IN_SLACK: usize = 64;
    const SENTINEL: u64 = 1 << 63;
    if input.len() < IN_SLACK || out.len() < 64 {
        return Ok(());
    }
    let ip_end = input.len() - IN_SLACK; // ip <= ip_end at the top of an iteration
    let op_end = out.len() - 64; // op <= op_end: 32 literal bytes, then a 32-byte match
    let sp = input.as_ptr();
    let dp = out.as_mut_ptr();
    let (mut ip, mut op, mut last_half) = (st.ip, st.op, st.last_half);
    // the remaining flags in the top bits, then a one
    let mut fw: u64 = match st.flag_count {
        0 => SENTINEL,
        k => ((st.flags as u64) << (64 - k)) | (1 << (63 - k)),
    };
    while ip <= ip_end && op <= op_end {
        if fw == SENTINEL {
            // SAFETY: ip + 4 <= input.len()
            let f = u32::from_le(unsafe { (sp.add(ip) as *const u32).read_unaligned() });
            fw = ((f as u64) << 32) | (1 << 31);
            ip += 4;
        }
        // literal run: up to 32 zero flags
        let lits = fw.leading_zeros() as usize;
        // SAFETY: ip + 32 <= input.len() and op + 32 <= out.len() (slack above)
        unsafe {
            let v = (sp.add(ip) as *const [u8; 32]).read_unaligned();
            (dp.add(op) as *mut [u8; 32]).write_unaligned(v);
        }
        ip += lits;
        op += lits;
        fw <<= lits;
        if fw == SENTINEL {
            continue;
        }
        fw <<= 1;
        // match
        // SAFETY: ip + 2 <= input.len()
        let mb = u16::from_le(unsafe { (sp.add(ip) as *const u16).read_unaligned() }) as usize;
        ip += 2;
        let off = (mb >> 3) + 1;
        let mut len = mb & 7;
        if len == 7 {
            len = lz77_long_len(input, &mut ip, &mut last_half)?;
        }
        len += 3;
        if len <= off && off <= op && len <= 32 {
            // SAFETY: op + 32 <= out.len(); one 32-byte load before the store equals the
            // forward byte copy because len <= off
            unsafe {
                let v = (dp.add(op - off) as *const [u8; 32]).read_unaligned();
                (dp.add(op) as *mut [u8; 32]).write_unaligned(v);
            }
            op += len;
        } else {
            op = copy_match(out, op, off, len)?;
        }
    }
    let k = 63 - fw.trailing_zeros();
    let flags = if k == 0 { 0 } else { (fw >> (64 - k)) as u32 };
    *st = Lz77State { ip, op, flags, flag_count: k, last_half };
    Ok(())
}

/// The checked loop (every bounds check, stream ends and errors), from `st`.
fn lz77_checked(input: &[u8], out: &mut [u8], st: Lz77State) -> Result<usize, XpressError> {
    let n = input.len();
    let Lz77State { mut ip, mut op, mut flags, mut flag_count, mut last_half } = st;
    while op < out.len() {
        if flag_count == 0 {
            if n - ip < 4 {
                // no more flags: end of stream
                return Ok(op);
            }
            flags = u32::from_le_bytes([input[ip], input[ip + 1], input[ip + 2], input[ip + 3]]);
            ip += 4;
            flag_count = 32;
        }
        // run of literal flags (zero bits from bit flag_count-1 downwards): one memcpy
        let window = ((flags as u64) << (64 - flag_count)) | ((1u64 << (64 - flag_count)) - 1);
        let lits = window.leading_zeros();
        if lits > 0 {
            let k = (lits as usize).min(n - ip).min(out.len() - op);
            out[op..op + k].copy_from_slice(&input[ip..ip + k]);
            op += k;
            ip += k;
            if k < lits as usize {
                // input or output exhausted inside the run
                return Ok(op);
            }
            flag_count -= lits;
            continue;
        }
        flag_count -= 1;
        // match flag
        if ip == n {
            // regular end of stream
            return Ok(op);
        }
        if n - ip < 2 {
            return Err(XpressError::Truncated);
        }
        let mb = u16::from_le_bytes([input[ip], input[ip + 1]]) as usize;
        ip += 2;
        let mut len = mb & 7;
        let off = (mb >> 3) + 1;
        if len == 7 {
            len = lz77_long_len(input, &mut ip, &mut last_half)?;
        }
        len += 3;
        op = copy_match(out, op, off, len)?;
    }
    Ok(op)
}

/// Decompress Plain LZ77 data expected to expand to `out_len` bytes (the result is shorter if
/// the stream ends early).
pub fn lz77_decompress(input: &[u8], out_len: usize) -> Result<Vec<u8>, XpressError> {
    let mut out = vec![0u8; out_len];
    let n = lz77_decompress_into(input, &mut out)?;
    out.truncate(n);
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// LZ77+Huffman ([MS-XCA] 2.2)
// ---------------------------------------------------------------------------------------------

const HUFF_SYMBOLS: usize = 512;
const HUFF_MAX_LEN: usize = 15;
const HUFF_BLOCK: usize = 65536;
/// Primary lookup table bits: 2048 entries * 8 bytes (16 KiB) stay in L1 and cover 99.9% of
/// literal and ~97% of match symbols of real memory; longer codes (up to 15 bits) go through
/// a second table indexed by the top 15 bits, covering only the long end of the code space.
const TABLE_BITS: u32 = 11;

// Decode table entry layout (u64), everything the fast loop needs for a symbol with few
// instructions:
//   bits  0..5   bits to consume for the whole symbol: code length + match offset bits
//                (<= 30, so bit 5 is clear and the entry itself works as a shift count)
//   bits  6..11  output length: 1 for a literal, 3..=17 for a match, 0 for SLOW entries
//   bit  12      literal
//   bits 16..25  symbol
//   bits 25..29  code length (0 in the primary table for codes longer than TABLE_BITS)
//   bits 33..64  K: the "offset" is (top `nbits` bits of the stream) ^ K. For a match that
//                is its offset (the offset bits with the implicit leading one); for a
//                literal it is 256 - byte, so `LIT_SRC + 256 - offset` points at the byte.
//                SLOW entries (length code 15, long codes) set K bit 30: an offset >= 2^30
//                is never valid in the fast loop (it stops before 2^30 bytes of output).
const E_LIT: u64 = 1 << 12;
const E_K_SHIFT: u32 = 33;
const E_SLOW_K: u64 = 1 << 30;
/// Code length field of an entry.
const E_CODE_LEN: u64 = 15 << 25;
/// Entry for codes longer than the table (nbits 1 keeps the shifts in range).
const E_LONG: u64 = (E_SLOW_K << E_K_SHIFT) | 1;

/// Table entry of symbol `sym` with canonical code `code` of length `l`.
#[inline(always)]
const fn entry(sym: usize, l: usize, code: u64) -> u64 {
    if sym < 256 {
        let k = code ^ (256 - sym as u64);
        (l | 1 << 6 | (sym << 16) | (l << 25)) as u64 | E_LIT | (k << E_K_SHIFT)
    } else {
        let s = sym - 256;
        let (len_code, obits) = (s & 15, s >> 4);
        let base = ((l + obits) | (sym << 16) | (l << 25)) as u64;
        if len_code == 15 {
            base | ((E_SLOW_K | (code << obits)) << E_K_SHIFT)
        } else {
            base | (((len_code + 3) << 6) as u64) | (((code << obits) ^ (1 << obits)) << E_K_SHIFT)
        }
    }
}

/// Canonical Huffman decoder for one block. The spec's 2^15 direct table assigns code space
/// in (length, symbol) order, i.e. standard canonical codes.
struct HuffTable {
    fast: [u64; 1 << TABLE_BITS],
    /// Entries for the 15-bit codes `long_base..2^15` (the prefixes of the primary table's
    /// `E_LONG` slots), one per 15-bit value.
    long: Vec<u64>,
    long_base: usize,
    first_code: [u32; HUFF_MAX_LEN + 1],
    count: [u32; HUFF_MAX_LEN + 1],
    offset: [u16; HUFF_MAX_LEN + 1],
    sorted: [u16; HUFF_SYMBOLS],
}

impl HuffTable {
    fn new() -> HuffTable {
        HuffTable {
            fast: [0; 1 << TABLE_BITS],
            long: Vec::new(),
            long_base: 1 << HUFF_MAX_LEN,
            first_code: [0; HUFF_MAX_LEN + 1],
            count: [0; HUFF_MAX_LEN + 1],
            offset: [0; HUFF_MAX_LEN + 1],
            sorted: [0; HUFF_SYMBOLS],
        }
    }

    /// Build from the 256-byte table of 4-bit lengths. The spec requires the lengths to fill
    /// the code space exactly.
    fn build(&mut self, table: &[u8]) -> Result<(), XpressError> {
        let mut count = [0u32; HUFF_MAX_LEN + 1];
        for &b in table {
            count[(b & 0xf) as usize] += 1;
            count[(b >> 4) as usize] += 1;
        }
        count[0] = 0;
        let mut code = 0u32;
        let mut off = 0u16;
        for l in 1..=HUFF_MAX_LEN {
            self.first_code[l] = code;
            self.offset[l] = off;
            if code + count[l] > 1 << l {
                return Err(XpressError::BadTable);
            }
            code = (code + count[l]) << 1;
            off += count[l] as u16;
        }
        if code != 1 << (HUFF_MAX_LEN + 1) {
            return Err(XpressError::BadTable);
        }
        self.count = count;
        let mut next = self.offset;
        for (i, &b) in table.iter().enumerate() {
            for (sym, l) in [(2 * i, (b & 0xf) as usize), (2 * i + 1, (b >> 4) as usize)] {
                if l != 0 {
                    self.sorted[next[l] as usize] = sym as u16;
                    next[l] += 1;
                }
            }
        }
        let mut pos = 0usize;
        for l in 1..=TABLE_BITS as usize {
            let span = 1usize << (TABLE_BITS as usize - l);
            let o = self.offset[l] as usize;
            let mut code = self.first_code[l] as u64;
            for &sym in &self.sorted[o..o + count[l] as usize] {
                self.fast[pos..pos + span].fill(entry(sym as usize, l, code));
                pos += span;
                code += 1;
            }
        }
        self.fast[pos..].fill(E_LONG);
        // the long codes fill the rest of the code space in canonical order
        const SUB: usize = HUFF_MAX_LEN - TABLE_BITS as usize;
        self.long_base = pos << SUB;
        self.long.clear();
        self.long.resize((1 << HUFF_MAX_LEN) - self.long_base, E_LONG);
        let mut at = 0usize;
        for l in TABLE_BITS as usize + 1..=HUFF_MAX_LEN {
            let span = 1usize << (HUFF_MAX_LEN - l);
            let o = self.offset[l] as usize;
            let mut code = self.first_code[l] as u64;
            for &sym in &self.sorted[o..o + count[l] as usize] {
                self.long[at..at + span].fill(entry(sym as usize, l, code));
                at += span;
                code += 1;
            }
        }
        Ok(())
    }

    /// Entry of a code longer than TABLE_BITS from the top 15 bits of the stream (E_LONG if
    /// the bits are not a long code).
    #[inline(always)]
    fn long_entry(&self, top15: usize) -> u64 {
        self.long.get(top15.wrapping_sub(self.long_base)).copied().unwrap_or(E_LONG)
    }

    /// Decode the symbol at the top of `bits`: (symbol, code length).
    #[inline(always)]
    fn decode(&self, bits: u32) -> (usize, u32) {
        let mut e = self.fast[(bits >> (32 - TABLE_BITS)) as usize];
        if e & E_CODE_LEN == 0 {
            e = self.long_entry((bits >> (32 - HUFF_MAX_LEN)) as usize);
        }
        let l = ((e >> 25) & 15) as u32;
        if l != 0 {
            return (((e >> 16) & 511) as usize, l);
        }
        self.decode_slow(bits)
    }

    #[cold]
    fn decode_slow(&self, bits: u32) -> (usize, u32) {
        for l in TABLE_BITS as usize + 1..=HUFF_MAX_LEN {
            let c = bits >> (32 - l);
            let i = c.wrapping_sub(self.first_code[l]);
            if i < self.count[l] {
                return (self.sorted[self.offset[l] as usize + i as usize] as usize, l as u32);
            }
        }
        // unreachable for a complete code
        (0, HUFF_MAX_LEN as u32)
    }
}

/// 64-bit bit reader equivalent to the 32-bit reader of [MS-XCA] 2.2.4.
///
/// The spec keeps 16..32 bits buffered and reads the next 16-bit word at the current input
/// position whenever fewer than 16 remain; match-length extension bytes are read at that same
/// position, interleaved with the words. After consuming C bits the spec has read
/// R(C) = max(2, ceil(C/16) + 1) words, so its input position is a function of C and of the
/// length bytes read so far.
///
/// This reader instead refills branchlessly to 48..63 bits (four words loaded at once, the
/// standard "OR in the lookahead, count only whole words" trick), which is enough for a whole
/// symbol (code + offset bits, <= 30) per refill, keeping the refill off the per-symbol
/// dependency chain. When length bytes show up it recomputes the spec position, reads them
/// there and drops the words it had prefetched from beyond them.
struct BitReader {
    /// Unconsumed bits, MSB first; bits below `cnt` are either zero or the upcoming data.
    buf: u64,
    cnt: u32,
    /// `ptr - 2 * (whole words counted into buf since the start of the block)`: keeps the
    /// word count off the refill path.
    base: usize,
    /// Input position of the next word to count.
    ptr: usize,
}

/// Four 16-bit words (little-endian) as one big-endian bit string: w0 in the top bits.
#[inline(always)]
fn word_lanes(x: u64) -> u64 {
    let y = x.rotate_left(32);
    ((y & 0x0000_FFFF_0000_FFFF) << 16) | ((y >> 16) & 0x0000_FFFF_0000_FFFF)
}

impl BitReader {
    /// Four 16-bit words at `p` as one big-endian bit string (w0 in the top bits). Bytes past
    /// the end of the input read as zero: the reader prefetches beyond the last used symbol.
    #[inline(always)]
    fn lanes<const FAST: bool>(input: &[u8], p: usize) -> u64 {
        let x = if FAST {
            // SAFETY: FAST callers guarantee p + 8 <= input.len()
            u64::from_le_bytes(unsafe { *(input.as_ptr().add(p) as *const [u8; 8]) })
        } else {
            let mut b = [0u8; 8];
            if let Some(s) = input.get(p..) {
                let k = s.len().min(8);
                b[..k].copy_from_slice(&s[..k]);
            }
            u64::from_le_bytes(b)
        };
        word_lanes(x)
    }

    #[inline(always)]
    fn byte<const FAST: bool>(input: &[u8], p: usize) -> Result<usize, XpressError> {
        if FAST {
            // SAFETY: FAST steps start with ptr + 16 <= len (before their refill) and length
            // bytes lie below that ptr + 12
            Ok(unsafe { *input.get_unchecked(p) } as usize)
        } else {
            input.get(p).map(|&b| b as usize).ok_or(XpressError::Truncated)
        }
    }

    /// Top up to 48..63 valid bits.
    #[inline(always)]
    fn refill<const FAST: bool>(&mut self, input: &[u8]) {
        self.buf |= Self::lanes::<FAST>(input, self.ptr) >> self.cnt;
        let k = (63 - self.cnt) >> 4;
        self.ptr += 2 * k as usize;
        self.cnt += 16 * k;
    }

    #[inline(always)]
    fn consume(&mut self, n: u32) {
        self.buf <<= n;
        self.cnt -= n;
    }

    /// Words counted into `buf` since the start of the block.
    #[inline(always)]
    fn words(&self) -> usize {
        (self.ptr - self.base) >> 1
    }

    /// Words the spec decoder has read at this point.
    #[inline(always)]
    fn spec_words(&self) -> usize {
        let consumed = 16 * self.words() - self.cnt as usize;
        (consumed.div_ceil(16) + 1).max(2)
    }

    /// Spec input position (after the words the spec has read).
    #[inline(always)]
    fn spec_ip(&self) -> usize {
        self.base + 2 * self.spec_words()
    }

    /// Continue counting words at `p` (after length bytes), keeping only the unconsumed bits
    /// of the words the spec has read.
    #[inline(always)]
    fn resync(&mut self, p: usize) {
        let r = self.spec_words();
        let keep = (16 * r - (16 * self.words() - self.cnt as usize)) as u32; // 16..=31
        self.buf &= !(u64::MAX >> keep);
        self.cnt = keep;
        self.ptr = p;
        self.base = p - 2 * r;
    }
}

/// The match part of a symbol (>= 256), with at least 30 bits buffered for symbol + offset.
#[inline(always)]
fn huff_match<const FAST: bool>(input: &[u8], out: &mut [u8], rd: &mut BitReader, op: &mut usize, sym: usize) -> Result<(), XpressError> {
    let s = sym - 256;
    let mut len = s & 15;
    let obits = (s >> 4) as u32;
    if len == 15 {
        let mut p = rd.spec_ip();
        len = BitReader::byte::<FAST>(input, p)?;
        p += 1;
        if len == 255 {
            len = BitReader::byte::<FAST>(input, p)? | BitReader::byte::<FAST>(input, p + 1)? << 8;
            p += 2;
            if len == 0 {
                len = 0;
                for k in 0..4 {
                    len |= BitReader::byte::<FAST>(input, p + k)? << (8 * k);
                }
                p += 4;
            }
            if len < 15 {
                return Err(XpressError::BadLength);
            }
            len -= 15;
        }
        len += 15;
        rd.resync(p);
    }
    len += 3;
    let off = ((rd.buf >> 1 >> (63 - obits)) as usize) + (1usize << obits);
    rd.consume(obits);
    *op = copy_match(out, *op, off, len)?;
    Ok(())
}

/// Decode symbols of one block until `block_end` with every check (the tail of the input
/// and of the output, and rare symbols).
fn huff_run_checked(input: &[u8], out: &mut [u8], table: &HuffTable, rd: &mut BitReader, op: &mut usize, block_end: usize) -> Result<(), XpressError> {
    while *op < block_end {
        rd.refill::<false>(input);
        huff_symbol::<false>(input, out, table, rd, op)?;
    }
    Ok(())
}

/// One symbol with >= 48 bits buffered.
#[inline(always)]
fn huff_symbol<const FAST: bool>(input: &[u8], out: &mut [u8], table: &HuffTable, rd: &mut BitReader, op: &mut usize) -> Result<(), XpressError> {
    let (sym, bl) = table.decode((rd.buf >> 32) as u32);
    rd.consume(bl);
    if sym >= 256 {
        return huff_match::<FAST>(input, out, rd, op, sym);
    }
    // SAFETY: callers only decode while *op < block_end <= out.len()
    unsafe { *out.get_unchecked_mut(*op) = sym as u8 };
    *op += 1;
    Ok(())
}

/// [`huff_symbol`] out of line, keeping the fast loop's registers free.
#[cold]
#[inline(never)]
fn huff_symbol_cold(input: &[u8], out: &mut [u8], table: &HuffTable, rd: &mut BitReader, op: &mut usize) -> Result<(), XpressError> {
    huff_symbol::<true>(input, out, table, rd, op)
}

/// Identity bytes: a literal is "copied" from `LIT_SRC[sym..]` like a match from the output,
/// which makes literals and matches one branch-free code path.
static LIT_SRC: [u8; 256 + 32] = {
    let mut t = [0u8; 256 + 32];
    let mut i = 0;
    while i < 256 {
        t[i] = i as u8;
        i += 1;
    }
    t
};

/// `PATTERN[off][k][i] = (16k + i) % off`: pshufb masks replicating an `off`-byte period.
#[cfg(all(target_arch = "x86_64", target_feature = "ssse3"))]
static PATTERN: [[[u8; 16]; 2]; 17] = {
    let mut t = [[[0u8; 16]; 2]; 17];
    let mut off = 1;
    while off <= 16 {
        let mut k = 0;
        while k < 32 {
            t[off][k / 16][k % 16] = (k % off) as u8;
            k += 1;
        }
        off += 1;
    }
    t
};

/// Write 32 bytes at `d` continuing the `off`-periodic pattern that ends at `d`
/// (`1 <= off <= 16`): an overlapping match of length <= 32 plus slop.
#[inline(always)]
unsafe fn pattern32(d: *mut u8, off: usize) {
    // SAFETY (whole body): caller guarantees off valid bytes before d and 32 writable at d
    unsafe {
        #[cfg(all(target_arch = "x86_64", target_feature = "ssse3"))]
        {
            use std::arch::x86_64::*;
            let v = _mm_loadu_si128(d.sub(off) as *const __m128i);
            let m = &PATTERN[off];
            let a = _mm_shuffle_epi8(v, _mm_loadu_si128(m[0].as_ptr() as *const __m128i));
            let b = _mm_shuffle_epi8(v, _mm_loadu_si128(m[1].as_ptr() as *const __m128i));
            _mm_storeu_si128(d as *mut __m128i, a);
            _mm_storeu_si128(d.add(16) as *mut __m128i, b);
        }
        #[cfg(not(all(target_arch = "x86_64", target_feature = "ssse3")))]
        {
            for i in 0..32 {
                *d.add(i) = *d.add(i).sub(off);
            }
        }
    }
}

/// Refill load: four 16-bit words at `p` as one big-endian bit string (w0 in the top bits).
///
/// # Safety
/// 8 bytes must be readable at `p`.
#[inline(always)]
unsafe fn load_lanes(p: *const u8) -> u64 {
    #[cfg(all(target_arch = "x86_64", target_feature = "ssse3"))]
    // SAFETY: caller guarantees 8 readable bytes
    unsafe {
        use std::arch::x86_64::*;
        let v = _mm_loadl_epi64(p as *const __m128i);
        let m = _mm_set_epi8(-1, -1, -1, -1, -1, -1, -1, -1, 1, 0, 3, 2, 5, 4, 7, 6);
        _mm_cvtsi128_si64(_mm_shuffle_epi8(v, m)) as u64
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "ssse3")))]
    // SAFETY: caller guarantees 8 readable bytes
    unsafe {
        word_lanes(u64::from_le((p as *const u64).read_unaligned()))
    }
}

/// The bulk decoder. Every symbol takes the same branch-free path: the table entry gives the
/// bits to consume, the output length and the source offset (a literal is "copied" from
/// `LIT_SRC`), and 32 bytes are moved. One refill (>= 48 bits) serves up to three symbols
/// (the second and third while they fit in the bits left). Runs while the input has 24 bytes
/// and the output 32 bytes of slack and at least 256 bytes have been produced; length
/// extensions, long codes, overlapping and invalid matches leave the common path, and errors
/// are produced by the same code as the checked loop.
#[inline(never)]
fn huff_run_fast(input: &[u8], out: &mut [u8], table: &HuffTable, rd: &mut BitReader, op: &mut usize, block_end: usize) -> Result<(), XpressError> {
    if input.len() < 24 || out.len() < 32 || *op < 256 {
        return Ok(());
    }
    let ip_end = input.len() - 24; // ptr <= ip_end at the top of an iteration
    // o < o_end: 32 bytes writable at o, and o < E_SLOW_K
    let o_end = block_end.min(out.len() - 31).min(E_SLOW_K as usize);
    let sp = input.as_ptr();
    let dp = out.as_mut_ptr();
    let t = &table.fast;
    // SAFETY: one past the 256 identity bytes, inside LIT_SRC
    let lit_end = unsafe { LIT_SRC.as_ptr().add(256) };
    // `cnt` keeps garbage above bit 5 (entries are subtracted whole); only cnt & 63 counts
    let (mut buf, mut cnt, mut ptr, mut base) = (rd.buf, rd.cnt as u64, rd.ptr, rd.base);
    let mut o = *op;

    // One common-case symbol: move 32 bytes from the literal table or the output.
    macro_rules! emit {
        ($e:expr, $off:expr, $len:expr) => {{
            let (e, off, len) = ($e, $off, $len);
            buf = buf.wrapping_shl(e as u32);
            cnt = cnt.wrapping_sub(e);
            // SAFETY: literal: lit_end - off = LIT_SRC + byte, with 32 readable bytes; match:
            // 1 <= off <= o, and one 32-byte load before the store equals the forward byte
            // copy because len <= off; 32 bytes are writable at o (o < o_end).
            unsafe {
                let base = std::hint::select_unpredictable(e & E_LIT != 0, lit_end, dp.add(o) as *const u8);
                let v = (base.sub(off) as *const [u8; 32]).read_unaligned();
                (dp.add(o) as *mut [u8; 32]).write_unaligned(v);
            }
            o += len;
        }};
    }
    // Table entry, source offset and length of the symbol at the top of `buf`.
    macro_rules! lookup {
        () => {{
            // SAFETY: the index has TABLE_BITS bits
            let e = unsafe { *t.get_unchecked((buf >> (64 - TABLE_BITS)) as usize) };
            // top nbits bits: the shift count (64 - nbits) & 63 is -e & 63
            let off = (buf.wrapping_shr((e as u32).wrapping_neg()) ^ (e >> E_K_SHIFT)) as usize;
            (e, off, ((e >> 6) & 31) as usize)
        }};
    }

    // Top up to 48..63 counted bits (cnt | 48 adds whole words); the bits already at the top
    // of `buf` do not change.
    macro_rules! refill {
        () => {{
            // SAFETY: ptr + 8 <= input.len(): ptr <= ip_end at the top of an iteration and
            // at most three refills (<= 18 bytes) happen before the next check
            buf |= unsafe { load_lanes(sp.add(ptr)) }.wrapping_shr(cnt as u32);
            let c2 = cnt | 48;
            ptr += ((c2 ^ cnt) >> 3) as usize;
            cnt = c2;
        }};
    }
    // Any symbol that is not the common case, with >= 48 bits buffered; always ends the
    // iteration (`continue`).
    macro_rules! special {
        ($next:lifetime, $e:expr, $off:expr, $len:expr) => {{
            let (mut e, mut off, mut len) = ($e, $off, $len);
            if e & E_CODE_LEN == 0 {
                // code longer than the table: the second-level entry of the top 15 bits
                e = table.long_entry((buf >> (64 - HUFF_MAX_LEN)) as usize);
                off = (buf.wrapping_shr((e as u32).wrapping_neg()) ^ (e >> E_K_SHIFT)) as usize;
                len = ((e >> 6) & 31) as usize;
            }
            if off.wrapping_sub(len) <= o - len {
                emit!(e, off, len);
                continue $next;
            }
            if off < E_SLOW_K as usize {
                if off <= o {
                    // overlapping match (off < len <= 17)
                    buf = buf.wrapping_shl(e as u32);
                    cnt = cnt.wrapping_sub(e);
                    // SAFETY: off <= o valid bytes before o, 32 writable at o (o < o_end)
                    unsafe { pattern32(dp.add(o), off) };
                    o += len;
                    continue $next;
                }
            } else if e & E_CODE_LEN != 0 {
                // length code 15: one extension byte at the spec input position (as
                // huff_match: consume the code, read the byte, resync, then the offset bits)
                let cl = ((e >> 25) & 15) as u32;
                let obits = (e & 31) as u32 - cl;
                let consumed = 8 * (ptr - base) - ((cnt & 63) as usize - cl as usize);
                let r = (consumed.div_ceil(16) + 1).max(2);
                let p = base + 2 * r;
                // SAFETY: the spec position is at most ptr - 2 < input.len()
                let b = unsafe { *sp.add(p) } as usize;
                if b != 255 {
                    let keep = (16 * r - consumed) as u32; // 16..=31
                    buf = (buf << cl) & !(u64::MAX >> keep);
                    let off = ((buf >> 1 >> (63 - obits)) as usize) + (1usize << obits);
                    buf <<= obits;
                    cnt = (keep - obits) as u64;
                    ptr = p + 1;
                    base = p + 1 - 2 * r;
                    let len = b + 18;
                    if off >= 32 && off <= o && len + 64 <= out.len() - o {
                        // SAFETY: chunks read final bytes (off >= 32) inside out and write
                        // below o + max(len, 64) + 32 <= out.len()
                        unsafe {
                            // lengths 18..=64 (80% of them): two fixed moves, no loop exit
                            // to mispredict
                            for k in [0, 32] {
                                let v = (dp.add(o + k - off) as *const [u8; 32]).read_unaligned();
                                (dp.add(o + k) as *mut [u8; 32]).write_unaligned(v);
                            }
                            let mut k = 64;
                            while k < len {
                                let v = (dp.add(o + k - off) as *const [u8; 32]).read_unaligned();
                                (dp.add(o + k) as *mut [u8; 32]).write_unaligned(v);
                                k += 32;
                            }
                        }
                        o += len;
                    } else {
                        o = copy_match(out, o, off, len)?;
                    }
                    continue $next;
                }
            }
            // long length, long code or bad offset: the checked code, one symbol
            rd.buf = buf;
            rd.cnt = (cnt & 63) as u32;
            rd.ptr = ptr;
            rd.base = base;
            *op = o;
            huff_symbol_cold(input, out, table, rd, op)?;
            (buf, cnt, ptr, base, o) = (rd.buf, rd.cnt as u64, rd.ptr, rd.base, *op);
            continue $next;
        }};
    }

    'next: while o < o_end && ptr <= ip_end {
        refill!();
        // ---- symbol A (>= 48 bits buffered)
        let (e, off, len) = lookup!();
        // common case: len <= off <= o (o >= 256 > len, so o - len does not wrap)
        if off.wrapping_sub(len) > o - len {
            special!('next, e, off, len);
        }
        emit!(e, off, len);
        // ---- symbols B and C: common case with the bits left, else refill and as A
        for _ in 0..2 {
            if o >= o_end {
                break;
            }
            let (e, off, len) = lookup!();
            if (off.wrapping_sub(len) > o - len) | ((e & 31) > (cnt & 63)) {
                refill!();
                let off = (buf.wrapping_shr((e as u32).wrapping_neg()) ^ (e >> E_K_SHIFT)) as usize;
                special!('next, e, off, len);
            }
            emit!(e, off, len);
        }
    }
    rd.buf = buf;
    rd.cnt = (cnt & 63) as u32;
    rd.ptr = ptr;
    rd.base = base;
    *op = o;
    Ok(())
}

/// Decompress Xpress "LZ77+Huffman" data into `out`; returns the number of bytes produced
/// (always `out.len()` on success: the format has no in-band end of stream before that).
pub fn huffman_decompress_into(input: &[u8], out: &mut [u8]) -> Result<usize, XpressError> {
    huffman_impl::<true>(input, out)
}

/// `FAST = false`: the checked loop alone (the differential oracle of the tests).
fn huffman_impl<const FAST: bool>(input: &[u8], out: &mut [u8]) -> Result<usize, XpressError> {
    let n = input.len();
    let mut table = HuffTable::new();
    let mut ip = 0usize;
    let mut op = 0usize;
    while op < out.len() {
        if n.saturating_sub(ip) < 256 {
            return Err(XpressError::Truncated);
        }
        table.build(&input[ip..ip + 256])?;
        let mut rd = BitReader { buf: 0, cnt: 0, base: ip + 256, ptr: ip + 256 };
        let block_end = op.saturating_add(HUFF_BLOCK).min(out.len());
        if FAST {
            if op < 256 {
                // the fast loop needs 256 bytes of history
                huff_run_checked(input, out, &table, &mut rd, &mut op, block_end.min(256))?;
            }
            huff_run_fast(input, out, &table, &mut rd, &mut op, block_end)?;
        }
        huff_run_checked(input, out, &table, &mut rd, &mut op, block_end)?;
        ip = rd.spec_ip();
    }
    Ok(op)
}

/// Decompress LZ77+Huffman data that expands to `out_len` bytes.
pub fn huffman_decompress(input: &[u8], out_len: usize) -> Result<Vec<u8>, XpressError> {
    let mut out = vec![0u8; out_len];
    let n = huffman_decompress_into(input, &mut out)?;
    out.truncate(n);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|h| u8::from_str_radix(h, 16).unwrap()).collect()
    }

    /// [MS-XCA] 3.1 examples.
    #[test]
    fn lz77_spec_examples() {
        let enc = hex("3f 00 00 00 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a");
        assert_eq!(lz77_decompress(&enc, 26).unwrap(), b"abcdefghijklmnopqrstuvwxyz");
        let enc = hex("ff ff ff 1f 61 62 63 17 00 0f ff 26 01");
        assert_eq!(lz77_decompress(&enc, 300).unwrap(), b"abc".repeat(100));
        // larger output buffer than the data: stops at end of stream
        assert_eq!(lz77_decompress(&enc, 1000).unwrap(), b"abc".repeat(100));
    }

    #[test]
    fn malformed_never_panics() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..3000 {
            let len = (next() % 700) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if round % 3 == 0 && buf.len() >= 256 {
                // plausible huffman table: every symbol length 9 = complete code
                for b in buf[..256].iter_mut() {
                    *b = 0x99;
                }
            }
            let _ = lz77_decompress(&buf, 5000);
            let _ = huffman_decompress(&buf, 70000);
        }
        assert_eq!(huffman_decompress(&[0u8; 300], 10), Err(XpressError::BadTable));
        assert_eq!(huffman_decompress(&[0x99u8; 10], 10), Err(XpressError::Truncated));
        // first element is a match: offset before start of output
        assert_eq!(lz77_decompress(&hex("00 00 00 80 00 00"), 10), Err(XpressError::BadOffset));
    }

    #[test]
    fn huffman_all_literals_fixed_code() {
        // Every symbol has length 9: symbol s has code s (canonical order). Encode literals
        // "hello" followed by zero padding.
        let mut enc = vec![0x99u8; 256];
        let msg = b"hello, world";
        let mut bitbuf: Vec<bool> = Vec::new();
        for &c in msg {
            for k in (0..9).rev() {
                bitbuf.push((c as u32 >> k) & 1 == 1);
            }
        }
        while bitbuf.len() % 16 != 0 {
            bitbuf.push(false);
        }
        for w in bitbuf.chunks(16) {
            let mut v = 0u16;
            for &b in w {
                v = (v << 1) | b as u16;
            }
            enc.extend_from_slice(&v.to_le_bytes());
        }
        enc.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(huffman_decompress(&enc, msg.len()).unwrap(), msg);
    }
}

#[cfg(test)]
mod fixture_tests {
    //! Vectors in tests/fixtures/codecs: `gen_xpress.py` (independent python reference
    //! encoders) and a real Windows 10 prefetch file page (MAM\x04 = Xpress Huffman) carved
    //! from the test memory image.
    use super::*;

    use crate::codecs::testdata::{fixture, gen_data};

    fn vector(name: &str) -> Vec<u8> {
        match name {
            "small" => gen_data(1, 3000),
            "medium" => gen_data(2, 40000),
            "multiblock" => gen_data(3, 200000),
            "zeros_runs" => {
                let d = gen_data(4, 70000);
                let mut v = vec![0u8; 30000];
                v.extend_from_slice(&d[..10000]);
                v.resize(v.len() + 30000, 0);
                v
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn reference_encoder_vectors() {
        for name in ["small", "medium", "multiblock", "zeros_runs"] {
            let want = vector(name);
            let c = fixture(&format!("xpress_lz77_{name}.bin"));
            assert_eq!(lz77_decompress(&c, want.len()).unwrap(), want, "lz77 {name}");
            let c = fixture(&format!("xpress_huff_{name}.bin"));
            assert_eq!(huffman_decompress(&c, want.len()).unwrap(), want, "huffman {name}");
        }
    }

    /// Plain LZ77: the fast loop against the checked loop alone.
    #[test]
    fn lz77_fast_loop_matches_checked_loop() {
        let mut x: u64 = 0x1f83_d9ab_fb41_bd6b;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let check = |c: &[u8], n: usize| {
            let mut a = vec![0u8; n];
            let mut b = vec![0u8; n];
            let ra = lz77_impl::<true>(c, &mut a);
            let rb = lz77_impl::<false>(c, &mut b);
            assert_eq!(ra, rb);
            if let Ok(k) = ra {
                assert!(a[..k] == b[..k], "outputs differ");
            }
        };
        for name in ["small", "medium", "multiblock", "zeros_runs"] {
            let c = fixture(&format!("xpress_lz77_{name}.bin"));
            let n = vector(name).len();
            check(&c, n);
            check(&c, n / 3);
            check(&c, n + 999);
            for _ in 0..300 {
                let mut m = c.clone();
                for _ in 0..1 + next() % 3 {
                    let at = (next() as usize) % m.len();
                    m[at] ^= 1 << (next() % 8);
                }
                if next() % 4 == 0 {
                    m.truncate((next() as usize) % m.len());
                }
                check(&m, n);
            }
        }
        for _ in 0..500 {
            let len = (next() % 3000) as usize;
            let m: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            check(&m, 1 + (next() % 20000) as usize);
        }
    }

    /// The fast loop against the checked loop alone: identical output and errors on valid,
    /// mutated and truncated streams.
    #[test]
    fn huffman_fast_loop_matches_checked_loop() {
        let mut x: u64 = 0x853c_49e6_748f_ea9b;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let check = |c: &[u8], n: usize| {
            let mut a = vec![0u8; n];
            let mut b = vec![0u8; n];
            let ra = huffman_impl::<true>(c, &mut a);
            let rb = huffman_impl::<false>(c, &mut b);
            assert_eq!(ra, rb);
            if let Ok(k) = ra {
                assert!(a[..k] == b[..k], "outputs differ");
            }
        };
        let mut inputs = Vec::new();
        for name in ["small", "medium", "multiblock", "zeros_runs"] {
            inputs.push((fixture(&format!("xpress_huff_{name}.bin")), vector(name).len()));
        }
        inputs.push((fixture("mam_svchost_13980.bin"), 0x2400));
        for (c, n) in &inputs {
            check(c, *n);
            check(c, n / 2);
            check(c, n + 1000);
            for _ in 0..300 {
                let mut m = c.clone();
                for _ in 0..1 + next() % 3 {
                    // mostly the bitstream, sometimes the length table
                    let at = if next() % 8 == 0 { (next() as usize) % 256.min(m.len()) } else { (next() as usize) % m.len() };
                    m[at] ^= 1 << (next() % 8);
                }
                if next() % 4 == 0 {
                    m.truncate((next() as usize) % m.len());
                }
                check(&m, *n);
            }
        }
        // plausible table (all lengths 9) followed by garbage: every kind of match
        for _ in 0..500 {
            let len = 256 + (next() % 3000) as usize;
            let mut m: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            m[..256].fill(0x99);
            check(&m, 1 + (next() % 20000) as usize);
        }
    }

    #[test]
    fn real_windows_prefetch_page() {
        // First physical page of a compressed prefetch file: "MAM\x04" + u32 size + data.
        let data = fixture("mam_svchost_13980.bin");
        let mut out = vec![0u8; 0x2400];
        huffman_decompress_into(&data, &mut out).unwrap();
        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), 30); // version
        assert_eq!(&out[4..8], b"SCCA");
        assert_eq!(u32::from_le_bytes(out[12..16].try_into().unwrap()), 13980); // file size
        let utf16 = |b: &[u8]| -> String { b.chunks(2).map(|c| c[0] as char).take_while(|&c| c != '\0').collect() };
        assert_eq!(utf16(&out[0x10..0x4c]), "SVCHOST.EXE");
        let strings = u32::from_le_bytes(out[0x64..0x68].try_into().unwrap()) as usize;
        assert_eq!(strings, 0x22d8);
        assert_eq!(
            utf16(&out[strings..strings + 200]),
            "\\VOLUME{01dd38fe2004ea92-f6200eb0}\\WINDOWS\\SYSTEM32\\MAPSBTSVC.DLL"
        );
    }
}

#[cfg(test)]
pub(crate) fn bench_build_table(t: &[u8]) -> bool {
    let mut h = HuffTable::new();
    h.build(t).is_ok() && std::hint::black_box(&h).fast[0] != 0xffff
}
