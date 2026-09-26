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


/// Largest `.lzma` output we pre-allocate before seeing data (grows beyond on demand).
const PREALLOC_CAP: usize = 1 << 30;

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

// ---------------------------------------------------------------------------------------
// x86-64 range coder steps (asm templates)
// ---------------------------------------------------------------------------------------
//
// Operands shared by the templates: {range} {code} (u32), {inp} (input pointer), {base}
// (probability node array), {sym} (node index), {t0} {t1} scratch, {p0} {p1} the current and
// next probability (the two alternate between steps so no moves are needed).
//
// A bit is decoded as: bound = (range >> 11) * prob is left in {range}, {t0} = range - bound,
// {t1} = code, code -= bound; the carry of that subtraction is the negated bit and cmov picks
// the right range/code (the reference decoder's x86-64 scheme). The chain per bit is
// shr, imul, sub, cmov: 6 cycles; everything else hangs off it. The node index advances with
// `sbb sym, -1` one cycle after the flags so the children of the next node are loaded (with a
// scaled index) in time for the next-but-one bit.

/// Normalization: shift in one input byte when range < 2^24.
#[cfg(target_arch = "x86_64")]
macro_rules! norm {
    () => {
        concat!(
            "cmp {range:e}, 0x1000000\n",
            "jae 2f\n",
            "shl {code:e}, 8\n",
            "mov {code:l}, byte ptr [{inp}]\n",
            "shl {range:e}, 8\n",
            "inc {inp}\n",
            "2:\n",
        )
    };
}

/// bound in {range}, range - bound in {t0}, old code in {t1}, code - bound in {code} (CF = !bit).
#[cfg(target_arch = "x86_64")]
macro_rules! calc {
    ($p:literal) => {
        concat!(
            "mov {t0:e}, {range:e}\n",
            "shr {range:e}, 11\n",
            "imul {range:e}, {",
            $p,
            ":e}\n",
            "sub {t0:e}, {range:e}\n",
            "mov {t1:e}, {code:e}\n",
            "sub {code:e}, {range:e}\n",
        )
    };
}

/// Probability update from CF (= !bit): p -= (p + (bit ? 0 : 31 - 2048)) >> 5, stored at
/// byte offset {t1} of {base} (upper bits of the register are garbage afterwards).
#[cfg(target_arch = "x86_64")]
macro_rules! upd_store {
    ($p:literal, $addr:literal) => {
        concat!(
            "shr {t0:e}, 5\n",
            "sub {",
            $p,
            ":e}, {t0:e}\n",
            "mov word ptr [",
            $addr,
            "], {",
            $p,
            ":x}\n",
        )
    };
}

/// First bit of a bit tree: node 1, children 2 and 3 loaded up front.
#[cfg(target_arch = "x86_64")]
macro_rules! tree_first {
    ($a:literal, $b:literal) => {
        concat!(
            "movzx {", $a, ":e}, word ptr [{base} + 2]\n",
            "mov {sym:e}, 2\n",
            "movzx {", $b, ":e}, word ptr [{base} + 4]\n",
            norm!(),
            calc!($a),
            "cmovae {range:e}, {t0:e}\n",
            "movzx {t0:e}, word ptr [{base} + 6]\n",
            "cmovae {", $b, ":e}, {t0:e}\n",
            "lea {t0:e}, [{", $a, "} - 2017]\n",
            "cmovb {code:e}, {t1:e}\n",
            "mov {t1:e}, {sym:e}\n",
            "cmovae {t0:e}, {", $a, ":e}\n",
            "sbb {sym:e}, -1\n",
            upd_store!($a, "{base} + {t1}"),
        )
    };
}

/// Middle bit: node {sym} (prob in $a); children loaded into $b.
#[cfg(target_arch = "x86_64")]
macro_rules! tree_mid {
    ($a:literal, $b:literal) => {
        concat!(
            "movzx {", $b, ":e}, word ptr [{base} + {sym}*4]\n",
            norm!(),
            calc!($a),
            "cmovae {range:e}, {t0:e}\n",
            "movzx {t0:e}, word ptr [{base} + {sym}*4 + 2]\n",
            "lea {sym:e}, [{sym} + {sym}]\n",
            "cmovae {", $b, ":e}, {t0:e}\n",
            "lea {t0:e}, [{", $a, "} - 2017]\n",
            "cmovb {code:e}, {t1:e}\n",
            "mov {t1:e}, {sym:e}\n",
            "cmovae {t0:e}, {", $a, ":e}\n",
            "sbb {sym:e}, -1\n",
            upd_store!($a, "{base} + {t1}"),
        )
    };
}

/// Last bit; {sym} = final node + {last} + 1 (the const operand folds in the offset).
#[cfg(target_arch = "x86_64")]
macro_rules! tree_last {
    ($a:literal) => {
        concat!(
            "add {sym:e}, {sym:e}\n",
            norm!(),
            calc!($a),
            "cmovae {range:e}, {t0:e}\n",
            "lea {t0:e}, [{", $a, "} - 2017]\n",
            "cmovb {code:e}, {t1:e}\n",
            "mov {t1:e}, {sym:e}\n",
            "cmovae {t0:e}, {", $a, ":e}\n",
            "sbb {sym:e}, {last}\n",
            upd_store!($a, "{base} + {t1}"),
        )
    };
}

/// Reverse tree, first bit: node 1, next candidates 2 and 3; {sym} = bits so far.
#[cfg(target_arch = "x86_64")]
macro_rules! rev_first {
    ($a:literal, $b:literal) => {
        concat!(
            "movzx {", $a, ":e}, word ptr [{base} + 2]\n",
            "xor {sym:e}, {sym:e}\n",
            "movzx {", $b, ":e}, word ptr [{base} + 4]\n",
            norm!(),
            calc!($a),
            "cmovae {range:e}, {t0:e}\n",
            "movzx {t0:e}, word ptr [{base} + 6]\n",
            "cmovae {", $b, ":e}, {t0:e}\n",
            "lea {t0:e}, [{sym} + 1]\n",
            "cmovb {code:e}, {t1:e}\n",
            "cmovae {sym:e}, {t0:e}\n",
            "lea {t0:e}, [{", $a, "} - 2017]\n",
            "cmovae {t0:e}, {", $a, ":e}\n",
            "shr {t0:e}, 5\n",
            "sub {", $a, ":e}, {t0:e}\n",
            "mov word ptr [{base} + 2], {", $a, ":x}\n",
        )
    };
}

/// Reverse tree, middle bit of weight $add: current node $dcur/2 + sym, next candidates
/// $n0/2 + sym (bit 0) and $n1/2 + sym (bit 1).
#[cfg(target_arch = "x86_64")]
macro_rules! rev_mid {
    ($a:literal, $b:literal, $add:literal, $dcur:literal, $n0:literal, $n1:literal) => {
        concat!(
            "movzx {", $b, ":e}, word ptr [{base} + {sym}*2 + ", $n0, "]\n",
            norm!(),
            calc!($a),
            "cmovae {range:e}, {t0:e}\n",
            "movzx {t0:e}, word ptr [{base} + {sym}*2 + ", $n1, "]\n",
            "cmovae {", $b, ":e}, {t0:e}\n",
            "lea {t0:e}, [{sym} + ", $add, "]\n",
            "cmovb {code:e}, {t1:e}\n",
            "mov {t1:e}, {sym:e}\n",
            "cmovae {sym:e}, {t0:e}\n",
            "lea {t0:e}, [{", $a, "} - 2017]\n",
            "cmovae {t0:e}, {", $a, ":e}\n",
            "shr {t0:e}, 5\n",
            "sub {", $a, ":e}, {t0:e}\n",
            "mov word ptr [{base} + {t1}*2 + ", $dcur, "], {", $a, ":x}\n",
        )
    };
}

/// Reverse tree, last bit of weight $add at node $dcur/2 + sym.
#[cfg(target_arch = "x86_64")]
macro_rules! rev_last {
    ($a:literal, $add:literal, $dcur:literal) => {
        concat!(
            norm!(),
            calc!($a),
            "cmovae {range:e}, {t0:e}\n",
            "lea {t0:e}, [{sym} + ", $add, "]\n",
            "cmovb {code:e}, {t1:e}\n",
            "mov {t1:e}, {sym:e}\n",
            "cmovae {sym:e}, {t0:e}\n",
            "lea {t0:e}, [{", $a, "} - 2017]\n",
            "cmovae {t0:e}, {", $a, ":e}\n",
            "shr {t0:e}, 5\n",
            "sub {", $a, ":e}, {t0:e}\n",
            "mov word ptr [{base} + {t1}*2 + ", $dcur, "], {", $a, ":x}\n",
        )
    };
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
        inp0: *const u8,
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

        // SAFETY: rc.ip <= ip_limit + INPUT_MARGIN (callers), inside the readable input.
        let mut inp = unsafe { inp0.add(rc.ip) };
        let in_limit = inp0.wrapping_add(ip_limit);
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
                stat!(12, 1);
                if range < TOP {
                    stat!(13, 1);
                    range <<= 8;
                    // SAFETY: inp <= in_limit + INPUT_MARGIN (see decode_inner).
                    code = (code << 8) | unsafe { *inp } as u32;
                    inp = unsafe { inp.add(1) };
                }
            };
        }
        // Decodes one bit with the probability at `$pp`; evaluates to true for a 0 bit.
        // (Branchy, like the reference decoder: the caller branches on the bit anyway.)
        macro_rules! is0 {
            ($pp:expr) => {{
                let pp: *mut u16 = $pp;
                // SAFETY: every index is below LITERAL + 0x300 << (lc + lp) by construction.
                let pr = unsafe { *pp } as u32;
                normalize!();
                let bound = (range >> 11) * pr;
                if code < bound {
                    range = bound;
                    unsafe { *pp = (pr + ((2048 - pr) >> 5)) as u16 };
                    true
                } else {
                    range -= bound;
                    code -= bound;
                    unsafe { *pp = (pr - (pr >> 5)) as u16 };
                    false
                }
            }};
        }
        // Bit trees: 3, 6 or 8 bits MSB first under the node array at `$base` (node 1 is the
        // root), result = final node + $fa. x86-64: the reference decoder's branchless asm
        // (both children loaded before the bit is known, node index advanced with sbb).
        #[cfg(target_arch = "x86_64")]
        macro_rules! tree {
            ($base:expr, $fa:expr, $($steps:expr),+) => {{
                let base: *mut u16 = $base;
                let sym: usize;
                // SAFETY: tree nodes lie inside the probability array; input reads stay
                // within the INPUT_MARGIN slack.
                unsafe {
                    core::arch::asm!(
                        $($steps),+,
                        range = inout(reg) range,
                        code = inout(reg) code,
                        inp = inout(reg) inp,
                        base = in(reg) base,
                        sym = out(reg) sym,
                        t0 = out(reg) _,
                        t1 = out(reg) _,
                        p0 = out(reg) _,
                        p1 = out(reg) _,
                        last = const -1 - ($fa),
                        options(nostack),
                    )
                };
                sym
            }};
        }
        #[cfg(target_arch = "x86_64")]
        macro_rules! tree3 {
            ($base:expr, $fa:expr) => {
                tree!($base, $fa, tree_first!("p0", "p1"), tree_mid!("p1", "p0"), tree_last!("p0"))
            };
        }
        #[cfg(target_arch = "x86_64")]
        macro_rules! tree6 {
            ($base:expr, $fa:expr) => {
                tree!(
                    $base,
                    $fa,
                    tree_first!("p0", "p1"),
                    tree_mid!("p1", "p0"),
                    tree_mid!("p0", "p1"),
                    tree_mid!("p1", "p0"),
                    tree_mid!("p0", "p1"),
                    tree_last!("p1")
                )
            };
        }
        #[cfg(target_arch = "x86_64")]
        macro_rules! tree8 {
            ($base:expr, $fa:expr) => {
                tree!(
                    $base,
                    $fa,
                    tree_first!("p0", "p1"),
                    tree_mid!("p1", "p0"),
                    tree_mid!("p0", "p1"),
                    tree_mid!("p1", "p0"),
                    tree_mid!("p0", "p1"),
                    tree_mid!("p1", "p0"),
                    tree_mid!("p0", "p1"),
                    tree_last!("p1")
                )
            };
        }
        // Portable bit trees: same node walk in plain Rust.
        #[cfg(not(target_arch = "x86_64"))]
        macro_rules! tree_n {
            ($base:expr, $fa:expr, $n:expr) => {{
                let tp: *mut u16 = $base;
                let mut m = 1usize;
                for _ in 0..$n {
                    m = 2 * m + (!is0!(unsafe { tp.add(m) })) as usize;
                }
                (m as isize + ($fa) as isize) as usize
            }};
        }
        #[cfg(not(target_arch = "x86_64"))]
        macro_rules! tree3 {
            ($base:expr, $fa:expr) => {
                tree_n!($base, $fa, 3)
            };
        }
        #[cfg(not(target_arch = "x86_64"))]
        macro_rules! tree6 {
            ($base:expr, $fa:expr) => {
                tree_n!($base, $fa, 6)
            };
        }
        #[cfg(not(target_arch = "x86_64"))]
        macro_rules! tree8 {
            ($base:expr, $fa:expr) => {
                tree_n!($base, $fa, 8)
            };
        }
        // 4-bit reverse tree (align bits), LSB first; nodes are numbered 2^depth + (bits so
        // far), the reference decoder's layout (any per-prefix layout is equivalent).
        #[cfg(target_arch = "x86_64")]
        macro_rules! rev4 {
            ($base:expr) => {{
                let base: *mut u16 = $base;
                let sym: usize;
                // SAFETY: nodes 1..16 of the align array; input within the margin.
                unsafe {
                    core::arch::asm!(
                        rev_first!("p0", "p1"),
                        rev_mid!("p1", "p0", "2", "4", "8", "12"),
                        rev_mid!("p0", "p1", "4", "8", "16", "24"),
                        rev_last!("p1", "8", "16"),
                        range = inout(reg) range,
                        code = inout(reg) code,
                        inp = inout(reg) inp,
                        base = in(reg) base,
                        sym = out(reg) sym,
                        t0 = out(reg) _,
                        t1 = out(reg) _,
                        p0 = out(reg) _,
                        p1 = out(reg) _,
                        options(nostack),
                    )
                };
                sym
            }};
        }
        // Reverse tree of $n (1..=5) bits, LSB first, same node layout as rev4.
        macro_rules! rev_n {
            ($base:expr, $n:expr) => {{
                let tp: *mut u16 = $base;
                let mut sym = 0usize;
                for i in 0..$n {
                    // SAFETY: node (1 << i) + sym < 2^n, inside this slot's range.
                    if !is0!(unsafe { tp.add((1 << i) + sym) }) {
                        sym += 1 << i;
                    }
                }
                sym
            }};
        }
        #[cfg(not(target_arch = "x86_64"))]
        macro_rules! rev4 {
            ($base:expr) => {
                rev_n!($base, 4)
            };
        }
        // $n (>= 1) direct bits appended to $d.
        #[cfg(target_arch = "x86_64")]
        macro_rules! direct {
            ($d:expr, $n:expr) => {{
                let mut d: u32 = $d;
                let mut cnt: u32 = $n;
                // SAFETY: input within the margin.
                unsafe {
                    core::arch::asm!(
                        "3:",
                        "add {d:e}, {d:e}",
                        "lea {t1:e}, [{d:r} + 1]",
                        norm!(),
                        "shr {range:e}, 1",
                        "mov {t0:e}, {code:e}",
                        "sub {code:e}, {range:e}",
                        "cmovns {d:e}, {t1:e}",
                        "cmovs {code:e}, {t0:e}",
                        "dec {cnt:e}",
                        "jnz 3b",
                        range = inout(reg) range,
                        code = inout(reg) code,
                        inp = inout(reg) inp,
                        d = inout(reg) d,
                        cnt = inout(reg) cnt,
                        t0 = out(reg) _,
                        t1 = out(reg) _,
                        options(nostack),
                    )
                };
                let _ = cnt;
                d
            }};
        }
        #[cfg(not(target_arch = "x86_64"))]
        macro_rules! direct {
            ($d:expr, $n:expr) => {{
                let mut d: u32 = $d;
                for _ in 0..$n {
                    normalize!();
                    range >>= 1;
                    code = code.wrapping_sub(range);
                    let t = 0u32.wrapping_sub(code >> 31);
                    code = code.wrapping_add(range & t);
                    d = (d << 1).wrapping_add(t.wrapping_add(1));
                }
                d
            }};
        }
        // Branchless bit with an already-loaded probability `$pr` stored at `$pp` (used by
        // the matched literal): evaluates to the bit as a bool.
        macro_rules! bitnb_loaded {
            ($pp:expr, $pr:expr) => {{
                let pr = $pr;
                normalize!();
                let bound = (range >> 11) * pr;
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
        macro_rules! len {
            ($coder:expr, $ps:expr) => {{
                // SAFETY: fixed layout offsets.
                let c = unsafe { probs.add($coder) };
                if is0!(unsafe { c.add(LEN_CHOICE) }) {
                    tree3!(unsafe { c.add(LEN_LOW + ($ps << 3)) }, 2 - 8)
                } else if is0!(unsafe { c.add(LEN_CHOICE2) }) {
                    tree3!(unsafe { c.add(LEN_MID + ($ps << 3)) }, 10 - 8)
                } else {
                    tree8!(unsafe { c.add(LEN_HIGH) }, 18 - 256)
                }
            }};
        }

        loop {
            if p >= limit {
                stop = Stop::Limit;
                break;
            }
            if inp > in_limit {
                stop = Stop::InputExhausted;
                break;
            }
            let pos_state = p & pb_mask;
            // SAFETY: fixed layout offsets (state < 12, pos_state < 16).
            if is0!(unsafe { probs.add(IS_MATCH + (state << 4) + pos_state) }) {
                // ---- literal ----
                let lit = LITERAL + 0x300 * (((p & lp_mask) << lc) + (prev >> (8 - lc)));
                // SAFETY: lit + 0x300 <= probs.len().
                let lp = unsafe { probs.add(lit) };
                let sym;
                if state < 7 {
                    stat!(0, 1);
                    sym = tree8!(lp, -0x100);
                } else {
                    stat!(1, 1);
                    if rep0 >= p {
                        return Err(corrupt("distance"));
                    }
                    // SAFETY: rep0 < p.
                    let mb = (unsafe { *outp.add(p - rep0 - 1) }) as usize;
                    // While the decoded bits equal the match byte's bits ("matching"), node
                    // `s` of bit i lives at 0x100 + (match bit i) * 0x100 + s, otherwise
                    // at s. Candidate children only need `matching` (an all-ones/zero mask)
                    // and per-position offsets known from the match byte up front.
                    // SAFETY: every index is < 2 * 0x100 + 0x100 = 0x300 (the literal coder).
                    let mut s = 1usize;
                    let mut matching = !0usize;
                    let mut idx = 0x100 + (((mb >> 7) & 1) << 8) + 1;
                    let mut pr = unsafe { *lp.add(idx) } as u32;
                    for i in 0..8 {
                        let mbit = (mb >> (7 - i)) & 1;
                        let mo_next = if i < 7 { 0x100 + (((mb >> (6 - i)) & 1) << 8) } else { 0 };
                        let mo0 = mo_next & mbit.wrapping_sub(1);
                        let mo1 = mo_next & 0usize.wrapping_sub(mbit);
                        let idx0 = 2 * s + (matching & mo0);
                        let idx1 = 2 * s + 1 + (matching & mo1);
                        let p0 = unsafe { *lp.add(idx0) } as u32;
                        let p1 = unsafe { *lp.add(idx1) } as u32;
                        let b = bitnb_loaded!(lp.add(idx), pr);
                        s = 2 * s + b as usize;
                        let keep = std::hint::select_unpredictable(b, 0usize.wrapping_sub(mbit), mbit.wrapping_sub(1));
                        matching &= keep;
                        idx = std::hint::select_unpredictable(b, idx1, idx0);
                        pr = std::hint::select_unpredictable(b, p1, p0);
                    }
                    sym = s & 0xFF;
                }
                // SAFETY: p < limit <= out_len.
                unsafe { *outp.add(p) = sym as u8 };
                prev = sym;
                p += 1;
                // 0..3 -> 0, 4..9 -> state - 3, 10..11 -> state - 6
                state = state.saturating_sub(std::hint::select_unpredictable(state >= 10, 6, 3));
                continue;
            }

            let len;
            if is0!(unsafe { probs.add(IS_REP + state) }) {
                // ---- simple match ----
                len = len!(LEN_CODER, pos_state);
                state = if state < 7 { 7 } else { 10 };
                let len_state = if len < 6 { len - 2 } else { 3 };
                let slot = tree6!(unsafe { probs.add(DIST_SLOT + (len_state << 6)) }, -64);
                let dist: u32 = if slot < 4 {
                    slot as u32
                } else {
                    let nbits = (slot >> 1) - 1;
                    let base = (2 | (slot & 1)) << nbits;
                    if slot < 14 {
                        // SAFETY: DIST_SPECIAL + base - slot - 1 + node < DIST_SPECIAL + 114.
                        (base + rev_n!(unsafe { probs.add(DIST_SPECIAL + base - slot - 1) }, nbits)) as u32
                    } else {
                        let d = direct!((2 | (slot & 1)) as u32, (nbits - 4) as u32);
                        (d << 4).wrapping_add(rev4!(unsafe { probs.add(ALIGN) }) as u32)
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
                if is0!(unsafe { probs.add(IS_REP0 + state) }) {
                    if is0!(unsafe { probs.add(IS_REP0_LONG + (state << 4) + pos_state) }) {
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
                    if is0!(unsafe { probs.add(IS_REP1 + state) }) {
                        d = rep1;
                    } else {
                        if is0!(unsafe { probs.add(IS_REP2 + state) }) {
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

        rc.ip = inp as usize - inp0 as usize;
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
    let mut out = super::try_zeroed(size)?;
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
    // calloc memory costs nothing until written, so guess generously (then shrink).
    let guess = input.len().saturating_mul(32).saturating_add(4096).min(PREALLOC_CAP);
    let target = match size {
        Some(s) => usize::try_from(s).map_err(|_| corrupt("uncompressed size"))?,
        None => usize::MAX,
    };
    let mut out = super::try_zeroed(target.min(guess.max(1 << 16)))?;
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
                out.try_reserve_exact(new_len - out.len()).map_err(|_| corrupt("output too large"))?;
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
    out.shrink_to_fit();
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
    fn codecs_lzma_huge_claimed_sizes_are_errors() {
        assert!(crate::codecs::try_zeroed(usize::MAX).is_err());
        // .lzma header claiming 2^60 bytes with a short body.
        let mut h = HELLO_LZMA.to_vec();
        h[5..13].copy_from_slice(&(1u64 << 60).to_le_bytes());
        assert!(decompress(&h).is_err());
        // LZMA2 chunks each claiming 2 MiB of output from a 1-byte body.
        let mut v = Vec::new();
        for _ in 0..100 {
            v.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x5d, 0x00]);
        }
        v.push(0);
        assert!(decompress_lzma2(&v).is_err());
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
