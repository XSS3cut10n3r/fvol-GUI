//! LZMA / LZMA2 decoding.
//!
//! * [`decompress`] — legacy `.lzma` files ("LZMA_Alone": 13-byte header + LZMA1 stream).
//! * [`decompress_lzma2`] — a raw LZMA2 stream (as stored inside `.xz` blocks).
//! * [`decompress_lzma1_raw`] — a raw LZMA1 stream with explicit properties (ZIP method 14).
//!
//! Design: the whole output lives in one flat buffer, so the "dictionary" is simply the
//! output produced since the last dictionary reset. No circular window, no wrap checks.
//! The hot loop keeps the range coder, state and reps in locals and decodes bits through
//! macros so nothing is a function call.

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------------------
// Probability array layout (one flat u16 array, like the reference decoder)
// ---------------------------------------------------------------------------------------

const NUM_STATES: usize = 12;
const POS_STATES_MAX: usize = 16;
const IS_MATCH: usize = 0;
const IS_REP: usize = IS_MATCH + NUM_STATES * POS_STATES_MAX; // 192
const IS_REP0: usize = IS_REP + NUM_STATES; // 204
const IS_REP1: usize = IS_REP0 + NUM_STATES; // 216
const IS_REP2: usize = IS_REP1 + NUM_STATES; // 228
const IS_REP0_LONG: usize = IS_REP2 + NUM_STATES; // 240
const DIST_SLOT: usize = IS_REP0_LONG + NUM_STATES * POS_STATES_MAX; // 432
const DIST_SPECIAL: usize = DIST_SLOT + 4 * 64; // 688
const ALIGN: usize = DIST_SPECIAL + 114; // 802
const LEN_CODER: usize = ALIGN + 16; // 818
const LEN_PROBS: usize = 2 + 2 * POS_STATES_MAX * 8 + 256; // 514
const REP_LEN_CODER: usize = LEN_CODER + LEN_PROBS; // 1332
const LITERAL: usize = REP_LEN_CODER + LEN_PROBS; // 1846

// Offsets inside a length coder.
const LEN_CHOICE: usize = 0;
const LEN_CHOICE2: usize = 1;
const LEN_LOW: usize = 2;
const LEN_MID: usize = LEN_LOW + POS_STATES_MAX * 8; // 130
const LEN_HIGH: usize = LEN_MID + POS_STATES_MAX * 8; // 258

const PROB_INIT: u16 = 1024;
/// Input bytes that must remain readable past the position checked at a symbol boundary.
const INPUT_MARGIN: usize = 64;
const TOP: u32 = 1 << 24;
const END_MARKER: u32 = 0xFFFF_FFFF;

/// Next state after a literal.
const LIT_NEXT_STATE: [u8; 16] = [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 4, 5, 0, 0, 0, 0];

/// Largest `.lzma` output we pre-allocate before seeing data (grows beyond on demand).
const PREALLOC_CAP: usize = 256 << 20;

#[inline(always)]
fn corrupt(what: &str) -> Error {
    Error::Msg(format!("lzma: corrupt data ({what})"))
}

#[cfg(lzma_stats)]
pub(crate) static STATS: [std::sync::atomic::AtomicU64; 16] = [const { std::sync::atomic::AtomicU64::new(0) }; 16];
macro_rules! stat {
    ($i:expr, $v:expr) => {
        #[cfg(lzma_stats)]
        STATS[$i].fetch_add($v as u64, std::sync::atomic::Ordering::Relaxed);
    };
}

/// Why [`LzmaDecoder::decode`] stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// `pos` reached `limit` (a match may have been cut; see `pending_len`).
    Limit,
    /// The end-of-payload marker was decoded.
    EndMarker,
    /// The input ran out (more bytes were needed than available).
    InputExhausted,
}

/// Range decoder position/state. The input slice is passed separately to every call.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RangeDecoder {
    pub range: u32,
    pub code: u32,
    /// Next input byte. May exceed the input length: missing bytes read as zero and the
    /// caller detects the overrun.
    pub ip: usize,
}

impl RangeDecoder {
    /// Initialises from the 5 range coder bytes at `input[start..]`.
    pub fn new(input: &[u8], start: usize) -> Result<RangeDecoder> {
        let b = input.get(start..start + 5).ok_or_else(|| corrupt("truncated range coder init"))?;
        if b[0] != 0 {
            return Err(corrupt("range coder init byte"));
        }
        let code = u32::from_be_bytes([b[1], b[2], b[3], b[4]]);
        Ok(RangeDecoder { range: 0xFFFF_FFFF, code, ip: start + 5 })
    }

    #[inline(always)]
    fn normalize(&mut self, input: &[u8]) {
        if self.range < TOP {
            self.range <<= 8;
            let b = input.get(self.ip).copied().unwrap_or(0);
            self.ip += 1;
            self.code = (self.code << 8) | b as u32;
        }
    }

    /// The reference decoders normalise once more after the last symbol of a stream.
    pub fn finish(&mut self, input: &[u8]) {
        self.normalize(input);
    }

    #[inline]
    pub fn is_finished_ok(&self) -> bool {
        self.code == 0
    }
}

/// LZMA properties (literal context bits, literal position bits, position bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Props {
    pub lc: u32,
    pub lp: u32,
    pub pb: u32,
}

impl Props {
    /// Decodes the classic properties byte `(pb * 5 + lp) * 9 + lc`.
    pub fn from_byte(b: u8) -> Result<Props> {
        if b >= 9 * 5 * 5 {
            return Err(corrupt("properties byte"));
        }
        let b = b as u32;
        Ok(Props { lc: b % 9, lp: (b / 9) % 5, pb: b / 45 })
    }
}

/// LZMA decoder state: probabilities, state machine, rep distances.
pub(crate) struct LzmaDecoder {
    probs: Vec<u16>,
    props: Props,
    state: usize,
    /// Rep distances, stored as distance - 1.
    reps: [usize; 4],
    /// Remaining length of a match that was cut at the output limit.
    pub pending_len: usize,
}

impl LzmaDecoder {
    pub fn new(props: Props) -> LzmaDecoder {
        let mut d = LzmaDecoder { probs: Vec::new(), props, state: 0, reps: [0; 4], pending_len: 0 };
        d.set_props(props);
        d
    }

    /// Changes lc/lp/pb and resets the state.
    pub fn set_props(&mut self, props: Props) {
        self.props = props;
        let n = LITERAL + (0x300usize << (props.lc + props.lp));
        self.probs.clear();
        self.probs.resize(n, PROB_INIT);
        self.state = 0;
        self.reps = [0; 4];
        self.pending_len = 0;
    }

    /// State reset (probabilities, state, reps) keeping the properties.
    pub fn reset_state(&mut self) {
        self.probs.fill(PROB_INIT);
        self.state = 0;
        self.reps = [0; 4];
        self.pending_len = 0;
    }

    /// Decodes into `out` starting at `*pos` until `*pos == limit`, an end marker, or the
    /// input is exhausted. `out[..*pos]` is the dictionary (everything since the last
    /// dictionary reset); nothing at or beyond `out.len()` is ever touched, bytes in
    /// `[limit, out.len())` may be scribbled on (fast match copies over-write a little).
    ///
    /// A match that crosses `limit` is cut there and its remainder is kept in
    /// `pending_len` (it is flushed first on the next call).
    pub fn decode(
        &mut self,
        rc: &mut RangeDecoder,
        input: &[u8],
        out: &mut [u8],
        pos: &mut usize,
        limit: usize,
    ) -> Result<Stop> {
        assert!(limit <= out.len() && *pos <= limit);
        // Flush a match cut by the previous call.
        if self.pending_len > 0 {
            let p = *pos;
            let dist = self.reps[0];
            if dist >= p {
                return Err(corrupt("distance"));
            }
            let n = self.pending_len.min(limit - p);
            // SAFETY: dist < p, p + n <= limit <= out.len().
            unsafe { copy_match(out.as_mut_ptr(), out.len(), p - dist - 1, p, n) };
            *pos = p + n;
            self.pending_len -= n;
            if self.pending_len > 0 {
                return Ok(Stop::Limit);
            }
        }
        let fixed = self.props == Props { lc: 3, lp: 0, pb: 2 };
        // Main part: read the input in place while at least INPUT_MARGIN bytes remain (a
        // single symbol never reads more than ~50 bytes), so reads need no bounds checks.
        if input.len() >= INPUT_MARGIN && rc.ip <= input.len() - INPUT_MARGIN {
            let ip_limit = input.len() - INPUT_MARGIN;
            // SAFETY: the loop stops once ip > ip_limit; one symbol reads < INPUT_MARGIN bytes.
            let stop = unsafe {
                if fixed {
                    self.decode_inner::<true>(rc, input.as_ptr(), ip_limit, out, pos, limit)?
                } else {
                    self.decode_inner::<false>(rc, input.as_ptr(), ip_limit, out, pos, limit)?
                }
            };
            if stop != Stop::InputExhausted {
                return Ok(stop);
            }
        }
        // Tail: decode the last bytes from a zero-padded copy.
        if rc.ip > input.len() {
            return Ok(Stop::InputExhausted);
        }
        let rem = input.len() - rc.ip;
        let mut tail = [0u8; 4 * INPUT_MARGIN];
        tail[..rem].copy_from_slice(&input[rc.ip..]);
        let base = rc.ip;
        rc.ip = 0;
        // SAFETY: rem < 2 * INPUT_MARGIN, reads stay below rem + INPUT_MARGIN < tail.len().
        let stop = unsafe {
            if fixed {
                self.decode_inner::<true>(rc, tail.as_ptr(), rem, out, pos, limit)
            } else {
                self.decode_inner::<false>(rc, tail.as_ptr(), rem, out, pos, limit)
            }
        };
        rc.ip += base;
        stop
    }

    /// The decoding loop. Reads `inp[ip]` without bounds checks; stops with
    /// `Stop::InputExhausted` at a symbol boundary once `ip > ip_limit`.
    ///
    /// # Safety
    /// `inp` must be readable up to `ip_limit + INPUT_MARGIN`.
    /// `FIXED` = the properties are lc=3 lp=0 pb=2 (compile-time constants).
    #[inline(never)]
    unsafe fn decode_inner<const FIXED: bool>(
        &mut self,
        rc: &mut RangeDecoder,
        inp: *const u8,
        ip_limit: usize,
        out: &mut [u8],
        pos: &mut usize,
        limit: usize,
    ) -> Result<Stop> {
        let out_len = out.len();
        let outp = out.as_mut_ptr();
        let mut p = *pos;

        let probs = self.probs.as_mut_ptr();
        let (lc, lp_mask, pb_mask) = if FIXED {
            (3usize, 0usize, 3usize)
        } else {
            (self.props.lc as usize, (1usize << self.props.lp) - 1, (1usize << self.props.pb) - 1)
        };

        let mut ip = rc.ip;
        let mut range = rc.range;
        let mut code = rc.code;
        let mut state = self.state;
        let [mut rep0, mut rep1, mut rep2, mut rep3] = self.reps;
        // The previous output byte, kept in a register (avoids a store->load round trip in
        // front of every literal).
        // SAFETY: p <= out_len; p - 1 valid when p > 0.
        let mut prev: usize = if p > 0 { (unsafe { *outp.add(p - 1) }) as usize } else { 0 };
        let stop;

        macro_rules! normalize {
            () => {
                if range < TOP {
                    range <<= 8;
                    // SAFETY: ip <= ip_limit + INPUT_MARGIN (see decode_inner).
                    let b = unsafe { *inp.add(ip) };
                    ip += 1;
                    code = (code << 8) | b as u32;
                }
            };
        }
        // Decodes one bit with the probability at `probs[$i]`; evaluates to 0 or 1 (usize).
        macro_rules! bit {
            ($i:expr) => {{
                // SAFETY: every index is below LITERAL + 0x300 << (lc + lp) by construction
                // (fixed layout offsets plus bounded tree indices).
                let pp = unsafe { probs.add($i) };
                let pr = unsafe { *pp } as u32;
                normalize!();
                let bound = (range >> 11) * pr;
                if code < bound {
                    range = bound;
                    unsafe { *pp = (pr + ((2048 - pr) >> 5)) as u16 };
                    0usize
                } else {
                    range -= bound;
                    code -= bound;
                    unsafe { *pp = (pr - (pr >> 5)) as u16 };
                    1usize
                }
            }};
        }
        // Branchless bit with an already-loaded probability `$pr` stored at `$pp`: range/code
        // are selected with cmov and the probability update is a single subtraction
        // (p -= (p - adj) >> 5 with adj = 0 for a 1 bit and 2048 - 31 for a 0 bit).
        // Evaluates to the bit as a bool.
        macro_rules! bitnb_loaded {
            ($pp:expr, $pr:expr) => {{
                let pr = $pr;
                normalize!();
                let bound = (range >> 11) * pr;
                // One subtraction yields both the bit (no borrow = 1) and the new code.
                let (c2, borrow) = code.overflowing_sub(bound);
                let r2 = range.wrapping_sub(bound);
                code = std::hint::select_unpredictable(borrow, code, c2);
                range = std::hint::select_unpredictable(borrow, bound, r2);
                let adj = std::hint::select_unpredictable(borrow, 2048 - 31, 0u32);
                // SAFETY: caller guarantees $pp is inside the probability array.
                unsafe { *$pp = (pr as i32 - ((pr as i32 - adj as i32) >> 5)) as u16 };
                !borrow
            }};
        }
        // Bit-tree walk of $n bits rooted at probs[$base + 1]. Both children of the current
        // node are loaded before the bit is known, so the probability load is off the
        // critical path. (Child indices < 2^($n+1) stay inside the probability array for
        // every tree of the layout.) Evaluates to (final node m in [2^n, 2^(n+1)), the bits
        // in reverse order).
        macro_rules! walk {
            ($base:expr, $n:expr) => {{
                // SAFETY: see above; all indices are bounded by the tree size.
                let tp = unsafe { probs.add($base) };
                let mut m = 1usize;
                let mut pr = unsafe { *tp.add(1) } as u32;
                let mut rev = 0usize;
                for _i in 0..$n {
                    let p0 = unsafe { *tp.add(2 * m) } as u32;
                    let p1 = unsafe { *tp.add(2 * m + 1) } as u32;
                    let b = bitnb_loaded!(tp.add(m), pr);
                    rev |= (b as usize) << _i;
                    m = 2 * m + b as usize;
                    pr = std::hint::select_unpredictable(b, p1, p0);
                }
                (m, rev)
            }};
        }
        macro_rules! tree {
            ($base:expr, $n:expr) => {{ walk!($base, $n).0 - (1usize << $n) }};
        }
        macro_rules! rev_tree {
            ($base:expr, $n:expr) => {{ walk!($base, $n).1 }};
        }
        macro_rules! len {
            ($coder:expr, $ps:expr) => {{
                let c = $coder;
                if bit!(c + LEN_CHOICE) == 0 {
                    tree!(c + LEN_LOW + ($ps << 3), 3) + 2
                } else if bit!(c + LEN_CHOICE2) == 0 {
                    tree!(c + LEN_MID + ($ps << 3), 3) + 10
                } else {
                    tree!(c + LEN_HIGH, 8) + 18
                }
            }};
        }

        loop {
            if p >= limit {
                stop = Stop::Limit;
                break;
            }
            if ip > ip_limit {
                stop = Stop::InputExhausted;
                break;
            }
            let pos_state = p & pb_mask;
            if bit!(IS_MATCH + (state << 4) + pos_state) == 0 {
                // ---- literal ----
                // SAFETY: p < limit <= out_len; p - 1 valid when p > 0.
                let lit = LITERAL + 0x300 * (((p & lp_mask) << lc) + (prev >> (8 - lc)));
                let mut sym = 1usize;
                if state < 7 {
                    stat!(0, 1);
                    sym = walk!(lit, 8).0;
                } else {
                    stat!(1, 1);
                    if rep0 >= p {
                        return Err(corrupt("distance"));
                    }
                    // SAFETY: rep0 < p.
                    let mut match_byte = ((unsafe { *outp.add(p - rep0 - 1) }) as usize) << 1;
                    let mut offs = 0x100usize;
                    // SAFETY: offs + match_bit + sym < 0x300 for every visited node.
                    let lp = unsafe { probs.add(lit) };
                    let mut match_bit = match_byte & offs;
                    let mut pp = unsafe { lp.add(offs + match_bit + sym) };
                    let mut pr = unsafe { *pp } as u32;
                    for _ in 0..8 {
                        // Candidate next nodes for a 0 bit and a 1 bit.
                        let nmb = match_byte << 1;
                        let offs0 = offs & !match_bit;
                        let offs1 = offs & match_bit;
                        let mb0 = nmb & offs0;
                        let mb1 = nmb & offs1;
                        let pp0 = unsafe { lp.add(offs0 + mb0 + 2 * sym) };
                        let pp1 = unsafe { lp.add(offs1 + mb1 + 2 * sym + 1) };
                        let p0 = unsafe { *pp0 } as u32;
                        let p1 = unsafe { *pp1 } as u32;
                        let b = bitnb_loaded!(pp, pr);
                        sym = 2 * sym + b as usize;
                        offs = std::hint::select_unpredictable(b, offs1, offs0);
                        match_bit = std::hint::select_unpredictable(b, mb1, mb0);
                        pp = std::hint::select_unpredictable(b, pp1, pp0);
                        pr = std::hint::select_unpredictable(b, p1, p0);
                        match_byte = nmb;
                    }
                }
                // SAFETY: p < limit <= out_len.
                unsafe { *outp.add(p) = sym as u8 };
                prev = sym & 0xFF;
                p += 1;
                // 0..3 -> 0, 4..9 -> state - 3, 10..11 -> state - 6
                state = state.saturating_sub(std::hint::select_unpredictable(state >= 10, 6, 3));
                continue;
            }

            let len;
            if bit!(IS_REP + state) == 0 {
                // ---- simple match ----
                len = len!(LEN_CODER, pos_state);
                state = if state < 7 { 7 } else { 10 };
                let len_state = if len < 6 { len - 2 } else { 3 };
                let slot = tree!(DIST_SLOT + (len_state << 6), 6);
                let dist: u32 = if slot < 4 {
                    slot as u32
                } else {
                    let nbits = (slot >> 1) - 1;
                    let base = (2 | (slot & 1)) << nbits;
                    if slot < 14 {
                        (base + rev_tree!(DIST_SPECIAL + base - slot - 1, nbits)) as u32
                    } else {
                        let mut d = (2 | (slot & 1)) as u32;
                        for _ in 0..nbits - 4 {
                            normalize!();
                            range >>= 1;
                            code = code.wrapping_sub(range);
                            let t = 0u32.wrapping_sub(code >> 31);
                            code = code.wrapping_add(range & t);
                            d = (d << 1).wrapping_add(t.wrapping_add(1));
                        }
                        (d << 4).wrapping_add(rev_tree!(ALIGN, 4) as u32)
                    }
                };
                if dist == END_MARKER {
                    stop = Stop::EndMarker;
                    break;
                }
                rep3 = rep2;
                rep2 = rep1;
                rep1 = rep0;
                rep0 = dist as usize;
                stat!(2, 1);
                stat!(10, (slot >= 14) as u64);
            } else {
                // ---- rep match ----
                if bit!(IS_REP0 + state) == 0 {
                    if bit!(IS_REP0_LONG + (state << 4) + pos_state) == 0 {
                        // short rep: one byte at distance rep0
                        stat!(4, 1);
                        if rep0 >= p {
                            return Err(corrupt("distance"));
                        }
                        state = if state < 7 { 9 } else { 11 };
                        // SAFETY: rep0 < p < limit <= out_len.
                        prev = (unsafe { *outp.add(p - rep0 - 1) }) as usize;
                        unsafe { *outp.add(p) = prev as u8 };
                        p += 1;
                        continue;
                    }
                } else {
                    let d;
                    if bit!(IS_REP1 + state) == 0 {
                        d = rep1;
                    } else {
                        if bit!(IS_REP2 + state) == 0 {
                            d = rep2;
                        } else {
                            d = rep3;
                            rep3 = rep2;
                        }
                        rep2 = rep1;
                    }
                    rep1 = rep0;
                    rep0 = d;
                }
                len = len!(REP_LEN_CODER, pos_state);
                stat!(3, 1);
                state = if state < 7 { 8 } else { 11 };
            }

            if rep0 >= p {
                return Err(corrupt("distance"));
            }
            stat!(8, len);
            stat!(9, (rep0 < 15) as u64);
            stat!(11, (len >= 18) as u64);
            let avail = limit - p;
            let n = if len <= avail { len } else { avail };
            // SAFETY: rep0 < p, p + n <= limit <= out_len.
            unsafe { copy_match(outp, out_len, p - rep0 - 1, p, n) };
            p += n;
            // SAFETY: n >= 1 (len >= 2 and p < limit), so p - 1 was just written.
            prev = (unsafe { *outp.add(p - 1) }) as usize;
            if n < len {
                self.pending_len = len - n;
                stop = Stop::Limit;
                break;
            }
        }

        rc.ip = ip;
        rc.range = range;
        rc.code = code;
        self.state = state;
        self.reps = [rep0, rep1, rep2, rep3];
        *pos = p;
        Ok(stop)
    }
}

/// Copies `len` bytes from `out[src..]` to `out[dst..]` (src < dst, LZ77 overlap semantics).
/// May write up to 15 bytes past `dst + len` but never at or beyond `out_len`.
///
/// # Safety
/// `src < dst` and `dst + len <= out_len`, `out` valid for `out_len` bytes.
#[inline(always)]
pub(crate) unsafe fn copy_match(out: *mut u8, out_len: usize, src: usize, dst: usize, len: usize) {
    use std::ptr::copy_nonoverlapping as cp;
    let dist = dst - src;
    unsafe {
        if len <= 16 && dist >= 16 && dst + 16 <= out_len {
            cp(out.add(src), out.add(dst), 16);
        } else if dist >= 32 && dst + len + 64 <= out_len {
            // Copy 64 bytes unconditionally (most matches are shorter), then 32 at a time.
            // Chunks of C bytes are correct for any overlap as long as dist >= C.
            let s = out.add(src);
            let d = out.add(dst);
            cp(s, d, 32);
            cp(s.add(32), d.add(32), 32);
            if len > 64 {
                let mut i = 64;
                while i < len {
                    cp(s.add(i), d.add(i), 32);
                    i += 32;
                }
            }
        } else if dist >= 16 && dst + len + 16 <= out_len {
            let mut s = out.add(src);
            let mut d = out.add(dst);
            let end = out.add(dst + len);
            loop {
                cp(s, d, 16);
                s = s.add(16);
                d = d.add(16);
                if d >= end {
                    break;
                }
            }
        } else if dist == 1 {
            std::ptr::write_bytes(out.add(dst), *out.add(src), len);
        } else if dist >= 8 && dst + len + 8 <= out_len {
            let mut s = out.add(src);
            let mut d = out.add(dst);
            let end = out.add(dst + len);
            loop {
                cp(s, d, 8);
                s = s.add(8);
                d = d.add(8);
                if d >= end {
                    break;
                }
            }
        } else {
            for i in 0..len {
                *out.add(dst + i) = *out.add(src + i);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// LZMA2
// ---------------------------------------------------------------------------------------

/// Walks the chunk headers of a raw LZMA2 stream without decoding anything.
/// Returns (bytes up to and including the end-of-stream control byte, uncompressed size).
pub(crate) fn lzma2_scan(input: &[u8]) -> Result<(usize, u64)> {
    let mut ip = 0usize;
    let mut total = 0u64;
    loop {
        let c = *input.get(ip).ok_or_else(|| corrupt("truncated lzma2 stream"))?;
        if c == 0 {
            return Ok((ip + 1, total));
        }
        if c == 1 || c == 2 {
            let h = input.get(ip..ip + 3).ok_or_else(|| corrupt("truncated lzma2 chunk header"))?;
            let size = u16::from_be_bytes([h[1], h[2]]) as usize + 1;
            ip += 3 + size;
            total += size as u64;
        } else if c >= 0x80 {
            let hlen = if c >= 0xC0 { 6 } else { 5 };
            let h = input.get(ip..ip + hlen).ok_or_else(|| corrupt("truncated lzma2 chunk header"))?;
            let unpacked = (((c & 0x1F) as usize) << 16) + u16::from_be_bytes([h[1], h[2]]) as usize + 1;
            let packed = u16::from_be_bytes([h[3], h[4]]) as usize + 1;
            ip += hlen + packed;
            total += unpacked as u64;
        } else {
            return Err(corrupt("lzma2 control byte"));
        }
        if ip > input.len() {
            return Err(corrupt("truncated lzma2 chunk"));
        }
    }
}

/// Decodes a raw LZMA2 stream into `out`, which must be exactly the uncompressed size
/// (see [`lzma2_scan`]). Returns the number of input bytes consumed.
pub(crate) fn lzma2_decode_into(input: &[u8], out: &mut [u8]) -> Result<usize> {
    let mut ip = 0usize;
    let mut pos = 0usize;
    let mut dict_start = 0usize;
    let mut need_dict_reset = true;
    let mut need_props = true;
    let mut dec: Option<LzmaDecoder> = None;
    loop {
        let c = *input.get(ip).ok_or_else(|| corrupt("truncated lzma2 stream"))?;
        ip += 1;
        if c == 0 {
            break;
        }
        if c >= 0xE0 || c == 1 {
            need_props = true;
            need_dict_reset = false;
            dict_start = pos;
        } else if need_dict_reset {
            return Err(corrupt("lzma2 missing dictionary reset"));
        }
        if c >= 0x80 {
            let hlen = if c >= 0xC0 { 5 } else { 4 };
            let h = input.get(ip..ip + hlen).ok_or_else(|| corrupt("truncated lzma2 chunk header"))?;
            let unpacked = (((c & 0x1F) as usize) << 16) + u16::from_be_bytes([h[0], h[1]]) as usize + 1;
            let packed = u16::from_be_bytes([h[2], h[3]]) as usize + 1;
            if c >= 0xC0 {
                let props = Props::from_byte(h[4])?;
                if props.lc + props.lp > 4 {
                    return Err(corrupt("lzma2 lc + lp > 4"));
                }
                match dec.as_mut() {
                    Some(d) if d.props == props => d.reset_state(),
                    Some(d) => d.set_props(props),
                    None => dec = Some(LzmaDecoder::new(props)),
                }
                need_props = false;
            } else if need_props {
                return Err(corrupt("lzma2 missing properties"));
            } else if c >= 0xA0 {
                if let Some(d) = dec.as_mut() {
                    d.reset_state();
                }
            }
            ip += hlen;
            let chunk = input.get(ip..ip + packed).ok_or_else(|| corrupt("truncated lzma2 chunk"))?;
            let limit = pos + unpacked;
            if limit > out.len() {
                return Err(corrupt("lzma2 uncompressed size mismatch"));
            }
            let d = dec.as_mut().ok_or_else(|| corrupt("lzma2 missing properties"))?;
            let mut rc = RangeDecoder::new(chunk, 0)?;
            let window = &mut out[dict_start..];
            let mut wpos = pos - dict_start;
            let stop = d.decode(&mut rc, chunk, window, &mut wpos, limit - dict_start)?;
            rc.finish(chunk);
            if stop != Stop::Limit || d.pending_len != 0 || rc.ip != packed || !rc.is_finished_ok() {
                return Err(corrupt("lzma2 chunk"));
            }
            pos = limit;
            ip += packed;
        } else if c == 1 || c == 2 {
            let h = input.get(ip..ip + 2).ok_or_else(|| corrupt("truncated lzma2 chunk header"))?;
            let size = u16::from_be_bytes([h[0], h[1]]) as usize + 1;
            ip += 2;
            let src = input.get(ip..ip + size).ok_or_else(|| corrupt("truncated lzma2 chunk"))?;
            let dst = out.get_mut(pos..pos + size).ok_or_else(|| corrupt("lzma2 uncompressed size mismatch"))?;
            dst.copy_from_slice(src);
            pos += size;
            ip += size;
        } else {
            return Err(corrupt("lzma2 control byte"));
        }
    }
    if pos != out.len() {
        return Err(corrupt("lzma2 uncompressed size mismatch"));
    }
    Ok(ip)
}

/// Decompresses a raw LZMA2 stream (terminated by a 0x00 control byte).
pub fn decompress_lzma2(data: &[u8]) -> Result<Vec<u8>> {
    let (_, size) = lzma2_scan(data)?;
    let size = usize::try_from(size).map_err(|_| corrupt("lzma2 size"))?;
    let mut out = vec![0u8; size];
    lzma2_decode_into(data, &mut out)?;
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// LZMA1 (".lzma" / LZMA_Alone, raw)
// ---------------------------------------------------------------------------------------

/// Decodes a raw LZMA1 range-coded stream. `size` is the uncompressed size if known (the
/// stream may then end without an end marker). Returns (output, input bytes consumed).
pub(crate) fn decode_lzma1(input: &[u8], props: Props, size: Option<u64>) -> Result<(Vec<u8>, usize)> {
    let mut rc = RangeDecoder::new(input, 0)?;
    let mut dec = LzmaDecoder::new(props);
    // Initial allocation: the declared size if sane, else a guess from the input size.
    let guess = input.len().saturating_mul(8).saturating_add(4096).min(PREALLOC_CAP);
    let target = match size {
        Some(s) => usize::try_from(s).map_err(|_| corrupt("uncompressed size"))?,
        None => usize::MAX,
    };
    let mut out = vec![0u8; target.min(guess.max(1 << 16))];
    let mut pos = 0usize;
    loop {
        let limit = out.len().min(target);
        let stop = dec.decode(&mut rc, input, &mut out, &mut pos, limit)?;
        match stop {
            Stop::EndMarker => {
                if size.is_some() && pos as u64 != size.unwrap_or(0) {
                    return Err(corrupt("end marker before declared size"));
                }
                rc.finish(input);
                break;
            }
            Stop::InputExhausted => return Err(corrupt("truncated input")),
            Stop::Limit => {
                if pos == target {
                    break;
                }
                // Grow the output buffer.
                let new_len = out.len().saturating_mul(2).min(target).max(out.len() + 1);
                out.resize(new_len, 0);
            }
        }
        if rc.ip > input.len() {
            return Err(corrupt("truncated input"));
        }
    }
    if rc.ip > input.len() {
        return Err(corrupt("truncated input"));
    }
    out.truncate(pos);
    Ok((out, rc.ip))
}

/// Decompresses a raw LZMA1 stream with explicit properties.
pub fn decompress_lzma1_raw(data: &[u8], props_byte: u8, uncompressed_size: Option<u64>) -> Result<Vec<u8>> {
    let props = Props::from_byte(props_byte)?;
    Ok(decode_lzma1(data, props, uncompressed_size)?.0)
}

/// Decompresses a legacy `.lzma` ("LZMA_Alone") file: props byte, u32 dictionary size,
/// u64 uncompressed size (all ones = unknown, end marker required), LZMA1 data.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 13 {
        return Err(corrupt("truncated .lzma header"));
    }
    let props = Props::from_byte(data[0])?;
    let size = u64::from_le_bytes(data[5..13].try_into().unwrap());
    let size = if size == u64::MAX { None } else { Some(size) };
    Ok(decode_lzma1(&data[13..], props, size)?.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `printf 'hello hello hello hello\n' | xz --format=lzma -c | xxd -i`
    const HELLO_LZMA: &[u8] = &[
        0x5d, 0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x34, 0x19,
        0x49, 0xee, 0x8d, 0xe9, 0x56, 0x0a, 0xc1, 0xb6, 0x20, 0xb7, 0xff, 0xff, 0xba, 0x34, 0x00, 0x00,
    ];

    #[test]
    fn codecs_lzma_alone_small() {
        assert_eq!(decompress(HELLO_LZMA).unwrap(), b"hello hello hello hello\n");
    }

    #[test]
    fn codecs_lzma_garbage_never_panics() {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        for n in 0..400usize {
            let mut v = HELLO_LZMA.to_vec();
            for _ in 0..(n % 5 + 1) {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                let i = (s as usize) % v.len();
                v[i] ^= (s >> 32) as u8;
            }
            v.truncate(13 + (s as usize >> 40) % (v.len() - 12));
            let _ = decompress(&v);
            let _ = decompress_lzma2(&v[13..]);
        }
    }
}
