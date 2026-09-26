//! LZMA / LZMA2 decoding.
//!
//! * [`decompress`] — legacy `.lzma` files ("LZMA_Alone": 13-byte header + LZMA1 stream).
//! * [`decompress_lzma2`] — a raw LZMA2 stream (as stored inside `.xz` blocks).
//! * [`decompress_lzma1_raw`] — a raw LZMA1 stream with explicit properties (ZIP method 14).
//!
//! Design: the whole output lives in one flat buffer, so the "dictionary" is simply the
//! output produced since the last dictionary reset. No circular window, no wrap checks.
//!
//! Speed is set by the range coder's dependency chain (shr, imul, sub, cmov: ~6 cycles per
//! decoded bit) plus mispredicted branches. On x86-64 the symbol loop is one asm block
//! (`decode_asm`) with a fixed register plan, which is what beats liblzma (1.10-1.2x on
//! JSON, 1.1x on binaries, `bench/refbench/codec_xz_micro.sh`):
//! * bit trees load both children before the bit is known and advance the node with sbb;
//!   probability updates are loads from a (p, bit) table kept in front of the
//!   probabilities, leaving ports 0/6 to the chain;
//! * a literal with match byte walks the match byte's nodes with addresses that do not
//!   depend on the decoding, and joins the plain literal tree at the first differing bit;
//! * the next literal's coder (from the previous byte) and match byte are known before the
//!   symbol starts: from three bits in the middle of a literal, or from the match source;
//! * the distance slot tree of long matches is set up before their length is decoded, match
//!   sources are prefetched once the distance is known to within 16 bytes, and matches copy
//!   64 bytes at a time.
//!
//! The Rust loop (`decode_inner`) is the portable implementation (other targets) and, in
//! tests, the independent reference the asm loop is checked against.

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
/// The probability array is preceded by PROB_UPD (the asm loop addresses the update
/// table relative to the probabilities).
const PROBS_OFF: usize = 4096;
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
// A bit is decoded as in the reference decoder's x86-64 asm: bound = (range >> 11) * prob is
// left in {range}, {t0} = range - bound, {t1} = code, code -= bound; the carry of that
// subtraction is the negated bit and cmov picks the right range/code. The chain per bit is
// shr, imul, sub, cmov (6 cycles); everything else hangs off it. Bit trees load both
// children of the current node before the bit is known and advance the node index with
// `sbb sym, -1` one cycle after the flags, so the next probability is ready in time.
//
// Ports 0 and 6 (shifts, cmov, sbb, branches) are the bottleneck around that chain, so
// probability updates are table loads (PROB_UPD, stored right in front of the probability
// array and addressed relative to {probs}) instead of shift/cmov arithmetic.

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

/// Probability update table: PROB_UPD[2p + bit] = p after decoding `bit` with probability p
/// (p + ((2048 - p) >> 5) for 0, p - (p >> 5) for 1). Copied in front of every decoder's
/// probabilities (entry 2p + bit at byte offset 4p + 2bit - 8192 from them).
static PROB_UPD: [u16; 4096] = {
    let mut t = [0u16; 4096];
    let mut p = 0;
    while p < 2048 {
        t[2 * p] = (p + ((2048 - p) >> 5)) as u16;
        t[2 * p + 1] = (p - (p >> 5)) as u16;
        p += 1;
    }
    t
};

// ---------------------------------------------------------------------------------------
// x86-64: the whole symbol loop in one asm block (lc=3 lp=0 pb=2)
// ---------------------------------------------------------------------------------------
//
// The compiler cannot keep the decoder in registers around bit-tree asm blocks that need
// a dozen registers each: it spilled the range coder to the stack on every symbol and grew
// ~10 induction variables. Here the loop is written out with a fixed register plan:
// range, code, inp, op (output pointer), probs, ctx live in registers throughout; the
// rest of the state (state, reps, limits, length, literal context) sits in `AsmCtx`,
// read and written only where a symbol needs it. The probability update table lives
// right in front of the probabilities: entry 2p + bit at probs - 8192 + 4p + 2bit.
//
// Probability byte offsets (2 * index) used in the templates:
//   IS_MATCH 0, IS_REP 384, IS_REP0 408, IS_REP1 432, IS_REP2 456, IS_REP0_LONG 480,
//   DIST_SLOT 864, DIST_SPECIAL 1376, ALIGN 1604, LEN_CODER 1636, REP_LEN_CODER 2664,
//   LITERAL 3692; in a length coder: CHOICE 0, CHOICE2 2, LOW 4, MID 260, HIGH 516.

/// Profiling marker (`--cfg lzma_marks`): a nop with displacement 0x7700 + $n that tools
/// use to split the asm loop into regions.
#[cfg(all(target_arch = "x86_64", lzma_marks))]
macro_rules! mark {
    ($n:literal) => {
        concat!("nop dword ptr [rax + 0x77", $n, "]\n")
    };
}
#[cfg(all(target_arch = "x86_64", not(lzma_marks)))]
macro_rules! mark {
    ($n:literal) => {
        ""
    };
}

/// Branchy bit with the probability at [$addr]: falls through on 0 (range and the
/// probability already updated), jumps to $one on 1, where `bit1!($addr)` must follow.
/// Leaves the bound in {t0} and the old probability in {a} for `bit1!`.
#[cfg(target_arch = "x86_64")]
macro_rules! bit {
    ($addr:expr, $one:expr) => {
        concat!(
            "movzx {a:e}, word ptr [", $addr, "]\n",
            norm!(),
            "mov {t0:e}, {range:e}\n",
            "shr {t0:e}, 11\n",
            "imul {t0:e}, {a:e}\n",
            "cmp {code:e}, {t0:e}\n",
            "jae ", $one, "\n",
            "mov {range:e}, {t0:e}\n",
            "movzx {a:e}, word ptr [{probs} + {a}*4 - 8192]\n",
            "mov word ptr [", $addr, "], {a:x}\n",
        )
    };
}

/// Bit-1 side of `bit!`.
#[cfg(target_arch = "x86_64")]
macro_rules! bit1 {
    ($addr:expr) => {
        concat!(
            "sub {range:e}, {t0:e}\n",
            "sub {code:e}, {t0:e}\n",
            "movzx {a:e}, word ptr [{probs} + {a}*4 - 8190]\n",
            "mov word ptr [", $addr, "], {a:x}\n",
        )
    };
}

/// Bit-tree step at node {sym} of the tree at $base (an address expression), current
/// probability in $a, the taken child's probability ends up in $b. $pre/$post: extra code.
/// Chain: shr, imul, sub, cmov. {sym} advances with sbb; the probability update is a table
/// load indexed by (p, bit) (no port-0/6 work).
#[cfg(target_arch = "x86_64")]
macro_rules! tstep {
    ($base:expr, $a:literal, $b:literal) => {
        concat!(
            "movzx {", $b, ":e}, word ptr [", $base, " + {sym}*4]\n",
            norm!(),
            "mov {t0:e}, {range:e}\n",
            "shr {range:e}, 11\n",
            "imul {range:e}, {", $a, ":e}\n",
            "sub {t0:e}, {range:e}\n",
            "mov {t1:e}, {code:e}\n",
            "sub {code:e}, {range:e}\n",
            "cmovae {range:e}, {t0:e}\n",
            "movzx {t0:e}, word ptr [", $base, " + {sym}*4 + 2]\n",
            "lea {sym:e}, [{sym} + {sym}]\n",
            "cmovae {", $b, ":e}, {t0:e}\n",
            "cmovb {code:e}, {t1:e}\n",
            "mov {t1:e}, {sym:e}\n",
            "sbb {sym:e}, -1\n",
            "mov {t0:e}, {sym:e}\n",
            "and {t0:e}, 1\n",
            "lea {t0:e}, [{t0} + {", $a, "}*2]\n",
            "movzx {t0:e}, word ptr [{probs} + {t0}*2 - 8192]\n",
            "mov word ptr [", $base, " + {t1}], {t0:x}\n",
        )
    };
}

/// Last bit-tree step: {sym} = final node + $fa ($fa even, as a literal expression).
#[cfg(target_arch = "x86_64")]
macro_rules! tlast {
    ($base:expr, $a:literal, $sbb:literal) => {
        concat!(
            "add {sym:e}, {sym:e}\n",
            norm!(),
            "mov {t0:e}, {range:e}\n",
            "shr {range:e}, 11\n",
            "imul {range:e}, {", $a, ":e}\n",
            "sub {t0:e}, {range:e}\n",
            "mov {t1:e}, {code:e}\n",
            "sub {code:e}, {range:e}\n",
            "cmovae {range:e}, {t0:e}\n",
            "cmovb {code:e}, {t1:e}\n",
            "mov {t1:e}, {sym:e}\n",
            "sbb {sym:e}, ", $sbb, "\n",
            "mov {t0:e}, {sym:e}\n",
            "and {t0:e}, 1\n",
            "lea {t0:e}, [{t0} + {", $a, "}*2]\n",
            "movzx {t0:e}, word ptr [{probs} + {t0}*2 - 8192]\n",
            "mov word ptr [", $base, " + {t1}], {t0:x}\n",
        )
    };
}

/// Start of a bit tree: node 1.
#[cfg(target_arch = "x86_64")]
macro_rules! tfirst {
    ($base:expr) => {
        concat!("mov {sym:e}, 1\n", "movzx {a:e}, word ptr [", $base, " + 2]\n")
    };
}

/// 3-bit tree; $sbb = -1 - final_add.
#[cfg(target_arch = "x86_64")]
macro_rules! tree3a {
    ($base:expr, $sbb:literal) => {
        concat!(tfirst!($base), tstep!($base, "a", "b"), tstep!($base, "b", "a"), tlast!($base, "a", $sbb))
    };
}

/// 6-bit tree.
#[cfg(target_arch = "x86_64")]
macro_rules! tree6a {
    ($base:expr, $sbb:literal) => {
        concat!(
            tfirst!($base),
            tstep!($base, "a", "b"),
            tstep!($base, "b", "a"),
            tstep!($base, "a", "b"),
            tstep!($base, "b", "a"),
            tstep!($base, "a", "b"),
            tlast!($base, "b", $sbb),
        )
    };
}

/// 8-bit tree; $mid is inserted after the third bit (literal context capture).
#[cfg(target_arch = "x86_64")]
macro_rules! tree8a {
    ($base:expr, $sbb:literal, $mid:expr) => {
        concat!(
            tfirst!($base),
            tstep!($base, "a", "b"),
            tstep!($base, "b", "a"),
            tstep!($base, "a", "b"),
            $mid,
            tstep!($base, "b", "a"),
            tstep!($base, "a", "b"),
            tstep!($base, "b", "a"),
            tstep!($base, "a", "b"),
            tlast!($base, "b", $sbb),
        )
    };
}

/// Literal-with-match-byte step while all earlier bits equalled the match byte's ({t2}):
/// node {sym} = the match byte's prefix, probability at 0x100 + match bit * 0x100 + node.
/// $sh: 7 - bit position. The next node assumes the bit matches (so no address depends on
/// the decoding); on a mismatch the plain-tree node is {sym} ^ 1 and the code jumps to $miss.
#[cfg(target_arch = "x86_64")]
macro_rules! mlit {
    ($sh:literal, $miss:literal) => {
        concat!(
            "mov {t3:e}, {t2:e}\n",
            "shr {t3:e}, ", $sh, "\n",
            "and {t3:e}, 1\n",
            "mov {t1:e}, {t3:e}\n",
            "shl {t1:e}, 8\n",
            "lea {t1:e}, [{t1} + {sym} + 0x100]\n",
            "movzx {a:e}, word ptr [{base} + {t1}*2]\n",
            norm!(),
            "mov {t0:e}, {range:e}\n",
            "shr {range:e}, 11\n",
            "imul {range:e}, {a:e}\n",
            "sub {t0:e}, {range:e}\n",
            "mov {b:e}, {code:e}\n",
            "sub {code:e}, {range:e}\n",
            "cmovae {range:e}, {t0:e}\n",
            "cmovb {code:e}, {b:e}\n",
            "sbb {b:e}, {b:e}\n",
            "inc {b:e}\n",
            "lea {t0:e}, [{b} + {a}*2]\n",
            "movzx {t0:e}, word ptr [{probs} + {t0}*2 - 8192]\n",
            "mov word ptr [{base} + {t1}*2], {t0:x}\n",
            "lea {sym:e}, [{t3} + {sym}*2]\n",
            "cmp {b:e}, {t3:e}\n",
            "jne ", $miss, "f\n",
        )
    };
}

/// Last bit of a literal with match byte (still matching so far): {sym} = 0x100 + byte.
#[cfg(target_arch = "x86_64")]
macro_rules! mlit_last {
    () => {
        concat!(
            "mov {t3:e}, {t2:e}\n",
            "and {t3:e}, 1\n",
            "mov {t1:e}, {t3:e}\n",
            "shl {t1:e}, 8\n",
            "lea {t1:e}, [{t1} + {sym} + 0x100]\n",
            "movzx {a:e}, word ptr [{base} + {t1}*2]\n",
            norm!(),
            "mov {t0:e}, {range:e}\n",
            "shr {range:e}, 11\n",
            "imul {range:e}, {a:e}\n",
            "sub {t0:e}, {range:e}\n",
            "mov {b:e}, {code:e}\n",
            "sub {code:e}, {range:e}\n",
            "cmovae {range:e}, {t0:e}\n",
            "cmovb {code:e}, {b:e}\n",
            "sbb {b:e}, {b:e}\n",
            "inc {b:e}\n",
            "lea {t0:e}, [{b} + {a}*2]\n",
            "movzx {t0:e}, word ptr [{probs} + {t0}*2 - 8192]\n",
            "mov word ptr [{base} + {t1}*2], {t0:x}\n",
            "lea {sym:e}, [{b} + {sym}*2]\n",
        )
    };
}

/// Length decoder of the length coder at byte offset $c; result in {sym}. $l1..$l3: labels.
/// The low and mid trees use {t2} as their base. $low: code run after a low-tree length
/// (2..9); $hi: code run as soon as the length is known to be >= 10 (the match coder uses
/// them to set up the distance slot tree, whose choice depends only on min(len - 2, 3)).
#[cfg(target_arch = "x86_64")]
macro_rules! len_dec {
    ($pm:expr, $c:literal, $l1:literal, $l2:literal, $l3:literal, $low:expr, $hi:expr) => {
        concat!(
            bit!(concat!("{probs} + ", $c), concat!($l1, "f")),
            // low: base = probs + c + 4 + pos_state * 16
            "mov {t1}, {op}\n",
            "sub {t1}, qword ptr [{ctx} + 16]\n",
            $pm,
            "\n",
            "shl {t1:e}, 4\n",
            "lea {t2}, [{probs} + {t1} + ", $c, " + 4]\n",
            tree3a!("{t2}", "5"),
            $low,
            "jmp ", $l3, "f\n",
            $l1, ":\n",
            $hi,
            bit1!(concat!("{probs} + ", $c)),
            bit!(concat!("{probs} + ", $c, " + 2"), concat!($l2, "f")),
            "mov {t1}, {op}\n",
            "sub {t1}, qword ptr [{ctx} + 16]\n",
            $pm,
            "\n",
            "shl {t1:e}, 4\n",
            "lea {t2}, [{probs} + {t1} + ", $c, " + 260]\n",
            tree3a!("{t2}", "-3"),
            "jmp ", $l3, "f\n",
            $l2, ":\n",
            bit1!(concat!("{probs} + ", $c, " + 2")),
            tree8a!(concat!("{probs} + ", $c, " + 516"), "237", ""),
            $l3, ":\n",
        )
    };
}

/// 4-bit reverse tree (align bits) at $base, LSB first, node = 2^depth + bits so far (the
/// reference decoder's layout). Result in {sym}.
#[cfg(target_arch = "x86_64")]
macro_rules! rev4a {
    ($base:expr) => {
        concat!(
            "movzx {a:e}, word ptr [", $base, " + 2]\n",
            "xor {sym:e}, {sym:e}\n",
            "movzx {b:e}, word ptr [", $base, " + 4]\n",
            norm!(),
            "mov {t0:e}, {range:e}\n",
            "shr {range:e}, 11\n",
            "imul {range:e}, {a:e}\n",
            "sub {t0:e}, {range:e}\n",
            "mov {t1:e}, {code:e}\n",
            "sub {code:e}, {range:e}\n",
            "cmovae {range:e}, {t0:e}\n",
            "movzx {t0:e}, word ptr [", $base, " + 6]\n",
            "cmovae {b:e}, {t0:e}\n",
            "lea {t0:e}, [{sym} + 1]\n",
            "cmovb {code:e}, {t1:e}\n",
            "cmovae {sym:e}, {t0:e}\n",
            "lea {t0:e}, [{a} - 2017]\n",
            "cmovae {t0:e}, {a:e}\n",
            "shr {t0:e}, 5\n",
            "sub {a:e}, {t0:e}\n",
            "mov word ptr [", $base, " + 2], {a:x}\n",
            rev_stepa!($base, "b", "a", "2", "4", "8", "12"),
            rev_stepa!($base, "a", "b", "4", "8", "16", "24"),
            rev_lasta!($base, "b", "8", "16"),
        )
    };
}

#[cfg(target_arch = "x86_64")]
macro_rules! rev_stepa {
    ($base:expr, $a:literal, $b:literal, $add:literal, $dcur:literal, $n0:literal, $n1:literal) => {
        concat!(
            "movzx {", $b, ":e}, word ptr [", $base, " + {sym}*2 + ", $n0, "]\n",
            norm!(),
            "mov {t0:e}, {range:e}\n",
            "shr {range:e}, 11\n",
            "imul {range:e}, {", $a, ":e}\n",
            "sub {t0:e}, {range:e}\n",
            "mov {t1:e}, {code:e}\n",
            "sub {code:e}, {range:e}\n",
            "cmovae {range:e}, {t0:e}\n",
            "movzx {t0:e}, word ptr [", $base, " + {sym}*2 + ", $n1, "]\n",
            "cmovae {", $b, ":e}, {t0:e}\n",
            "lea {t0:e}, [{sym} + ", $add, "]\n",
            "cmovb {code:e}, {t1:e}\n",
            "mov {t1:e}, {sym:e}\n",
            "cmovae {sym:e}, {t0:e}\n",
            "lea {t0:e}, [{", $a, "} - 2017]\n",
            "cmovae {t0:e}, {", $a, ":e}\n",
            "shr {t0:e}, 5\n",
            "sub {", $a, ":e}, {t0:e}\n",
            "mov word ptr [", $base, " + {t1}*2 + ", $dcur, "], {", $a, ":x}\n",
        )
    };
}

#[cfg(target_arch = "x86_64")]
macro_rules! rev_lasta {
    ($base:expr, $a:literal, $add:literal, $dcur:literal) => {
        concat!(
            norm!(),
            "mov {t0:e}, {range:e}\n",
            "shr {range:e}, 11\n",
            "imul {range:e}, {", $a, ":e}\n",
            "sub {t0:e}, {range:e}\n",
            "mov {t1:e}, {code:e}\n",
            "sub {code:e}, {range:e}\n",
            "cmovae {range:e}, {t0:e}\n",
            "lea {t0:e}, [{sym} + ", $add, "]\n",
            "cmovb {code:e}, {t1:e}\n",
            "mov {t1:e}, {sym:e}\n",
            "cmovae {sym:e}, {t0:e}\n",
            "lea {t0:e}, [{", $a, "} - 2017]\n",
            "cmovae {t0:e}, {", $a, ":e}\n",
            "shr {t0:e}, 5\n",
            "sub {", $a, ":e}, {t0:e}\n",
            "mov word ptr [", $base, " + {t1}*2 + ", $dcur, "], {", $a, ":x}\n",
        )
    };
}

/// Picks the template text of mode `fixed` (lc=3 lp=0 pb=2) or `generic`.
#[cfg(target_arch = "x86_64")]
macro_rules! sel {
    (fixed, $a:expr, $b:expr) => {
        $a
    };
    (generic, $a:expr, $b:expr) => {
        $b
    };
}

/// Generic mode: {base} = literal coder of the next literal from the previous byte ({t3})
/// and the position: hioff[byte] + looff[p & 15] (byte offsets, see `AsmCtx`).
#[cfg(target_arch = "x86_64")]
macro_rules! litbase {
    () => {
        concat!(
            "mov {t3:e}, dword ptr [{ctx} + {t3}*4 + 184]\n",
            "mov {t1}, {op}\n",
            "sub {t1}, qword ptr [{ctx} + 16]\n",
            "and {t1:e}, 15\n",
            "add {t3:e}, dword ptr [{ctx} + {t1}*4 + 1208]\n",
            "lea {base}, [{probs} + {t3} + 3692]\n",
        )
    };
}

/// Per-decoder scratch for the asm loop (field offsets are hard-coded in the template).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct AsmCtx {
    in_limit: *const u8,  // 0
    out_limit: *mut u8,   // 8
    out_start: *mut u8,   // 16
    out_end: *mut u8,     // 24
    reps: [u64; 4],       // 32, 40, 48, 56
    state: u64,           // 64
    _unused: u64,         // 72
    pending: u64,         // 80
    status: u64,          // 88
    len: u64,             // 96
    next: [u8; 48],       // 104: state after literal / match / rep / short rep (12 each)
    dbase: [u8; 16],      // 152: distance base of slots 4..13
    scratch: u64,         // 168
    pbmask: u64,          // 176: (1 << pb) - 1
    hioff: [u32; 256],    // 184: (byte >> (8 - lc)) * 0x600, literal coder offset of a byte
    looff: [u32; 16],     // 1208: ((p & lp_mask) << lc) * 0x600 for p & 15
}

// The asm template addresses these fields by offset.
#[cfg(target_arch = "x86_64")]
const _: () = {
    use std::mem::offset_of;
    assert!(offset_of!(AsmCtx, in_limit) == 0 && offset_of!(AsmCtx, out_limit) == 8);
    assert!(offset_of!(AsmCtx, out_start) == 16 && offset_of!(AsmCtx, out_end) == 24);
    assert!(offset_of!(AsmCtx, reps) == 32 && offset_of!(AsmCtx, state) == 64);
    assert!(offset_of!(AsmCtx, pending) == 80 && offset_of!(AsmCtx, status) == 88);
    assert!(offset_of!(AsmCtx, len) == 96 && offset_of!(AsmCtx, next) == 104);
    assert!(offset_of!(AsmCtx, dbase) == 152 && offset_of!(AsmCtx, scratch) == 168);
    assert!(offset_of!(AsmCtx, pbmask) == 176 && offset_of!(AsmCtx, hioff) == 184);
    assert!(offset_of!(AsmCtx, looff) == 1208);
};

#[cfg(target_arch = "x86_64")]
const ASM_NEXT: [u8; 48] = [
    0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 4, 5, // literal
    7, 7, 7, 7, 7, 7, 7, 10, 10, 10, 10, 10, // match
    8, 8, 8, 8, 8, 8, 8, 11, 11, 11, 11, 11, // rep
    9, 9, 9, 9, 9, 9, 9, 11, 11, 11, 11, 11, // short rep
];
#[cfg(target_arch = "x86_64")]
const ASM_DBASE: [u8; 16] = [4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 0, 0, 0, 0, 0, 0];

#[cfg(test)]
thread_local! {
    /// Tests: decode with the portable Rust loop instead of the x86-64 asm loop.
    static FORCE_PORTABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Use the portable loop on x86-64 too (tests; statistics builds count in the Rust loop).
#[inline(always)]
fn force_portable() -> bool {
    #[cfg(test)]
    return FORCE_PORTABLE.with(|f| f.get()) || cfg!(lzma_stats);
    #[cfg(not(test))]
    cfg!(lzma_stats)
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
        let n = PROBS_OFF + LITERAL + (0x300usize << (props.lc + props.lp));
        self.probs.clear();
        self.probs.extend_from_slice(&PROB_UPD);
        self.probs.resize(n, PROB_INIT);
        self.state = 0;
        self.reps = [0; 4];
        self.pending_len = 0;
    }

    /// State reset (probabilities, state, reps) keeping the properties.
    pub fn reset_state(&mut self) {
        self.probs[PROBS_OFF..].fill(PROB_INIT);
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
    /// On x86-64 this is the asm loop (`decode_asm`); the Rust loop below is the portable
    /// implementation and, in tests, the independent reference the asm is checked against.
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
        #[cfg(target_arch = "x86_64")]
        if !force_portable() {
            // SAFETY: same contract.
            return unsafe { self.decode_asm::<FIXED>(rc, inp, ip_limit, out, pos, limit) };
        }
        let out_len = out.len();
        let outp = out.as_mut_ptr();
        let mut p = *pos;

        // SAFETY: the update table occupies the first PROBS_OFF entries.
        let probs = unsafe { self.probs.as_mut_ptr().add(PROBS_OFF) };
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
                stat!(12, 1);
                if range < TOP {
                    stat!(13, 1);
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
                    let mb = (unsafe { *outp.add(p - rep0 - 1) }) as usize;
                    // While the decoded bits equal the match byte's bits ("matching"), node
                    // `sym` of bit i lives at 0x100 + (match bit i) * 0x100 + sym, otherwise
                    // at sym. Candidate children only need `matching` (an all-ones/zero mask)
                    // and per-position offsets known from the match byte up front.
                    // SAFETY: every index is < 2 * 0x100 + 0x100 = 0x300 (the literal coder).
                    let lp = unsafe { probs.add(lit) };
                    let mut matching = !0usize;
                    let mut idx = 0x100 + (((mb >> 7) & 1) << 8) + 1;
                    let mut pr = unsafe { *lp.add(idx) } as u32;
                    for i in 0..8 {
                        let mbit = (mb >> (7 - i)) & 1;
                        let mo_next = if i < 7 { 0x100 + (((mb >> (6 - i)) & 1) << 8) } else { 0 };
                        // Offset of the child if the decoded bit is 0 / 1 and we still match.
                        let mo0 = mo_next & mbit.wrapping_sub(1);
                        let mo1 = mo_next & 0usize.wrapping_sub(mbit);
                        let idx0 = 2 * sym + (matching & mo0);
                        let idx1 = 2 * sym + 1 + (matching & mo1);
                        let p0 = unsafe { *lp.add(idx0) } as u32;
                        let p1 = unsafe { *lp.add(idx1) } as u32;
                        let b = bitnb_loaded!(lp.add(idx), pr);
                        sym = 2 * sym + b as usize;
                        let keep = std::hint::select_unpredictable(b, 0usize.wrapping_sub(mbit), mbit.wrapping_sub(1));
                        matching &= keep;
                        idx = std::hint::select_unpredictable(b, idx1, idx0);
                        pr = std::hint::select_unpredictable(b, p1, p0);
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
            stat!(5, (len <= 32) as u64);
            stat!(6, (len > 32 && len <= 64) as u64);
            stat!(7, (len > 64) as u64);
            stat!(14, if rep0 < 15 { len } else { 0 });
            stat!(15, (rep0 == 0) as u64);
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

impl LzmaDecoder {
    /// `decode_inner` on x86-64: the symbol loop as one asm block. `FIXED`: lc=3 lp=0 pb=2
    /// (the next literal's coder is taken from three bits in the middle of the previous
    /// literal); otherwise the literal coder comes from two small tables in `AsmCtx`.
    ///
    /// # Safety
    /// As `decode_inner`.
    #[cfg(target_arch = "x86_64")]
    #[inline(never)]
    unsafe fn decode_asm<const FIXED: bool>(
        &mut self,
        rc: &mut RangeDecoder,
        inp0: *const u8,
        ip_limit: usize,
        out: &mut [u8],
        pos: &mut usize,
        limit: usize,
    ) -> Result<Stop> {
        let outp = out.as_mut_ptr();
        let p = *pos;
        let mut ctx = AsmCtx {
            in_limit: inp0.wrapping_add(ip_limit),
            out_limit: outp.wrapping_add(limit),
            out_start: outp,
            out_end: outp.wrapping_add(out.len()),
            reps: self.reps.map(|r| r as u64),
            state: self.state as u64,
            _unused: 0,
            pending: 0,
            status: 0,
            len: 0,
            next: ASM_NEXT,
            dbase: ASM_DBASE,
            scratch: 0,
            pbmask: (1u64 << self.props.pb) - 1,
            hioff: [0; 256],
            looff: [0; 16],
        };
        let (lc, lp_mask) = (self.props.lc, (1usize << self.props.lp) - 1);
        if !FIXED {
            for (b, v) in ctx.hioff.iter_mut().enumerate() {
                *v = ((b >> (8 - lc)) * 0x600) as u32;
            }
            for (k, v) in ctx.looff.iter_mut().enumerate() {
                *v = (((k & lp_mask) << lc) * 0x600) as u32;
            }
        }
        let mut range = rc.range;
        let mut code = rc.code;
        // SAFETY: rc.ip <= ip_limit + INPUT_MARGIN; p <= limit <= out.len().
        let mut inp = unsafe { inp0.add(rc.ip) };
        let mut op = unsafe { outp.add(p) };
        // SAFETY: the update table occupies the first PROBS_OFF entries.
        let probs = unsafe { self.probs.as_mut_ptr().add(PROBS_OFF) };
        let ctxp: *mut AsmCtx = &mut ctx;
        // Carried in registers across symbols: the literal coder of the next literal (from
        // the previous byte and the position) and the match byte of a literal after a match
        // (state >= 7).
        let prev = if p > 0 { out[p - 1] as usize } else { 0 };
        let lit = ((p & lp_mask) << lc) + (prev >> (8 - lc));
        // SAFETY: lit < 2^(lc + lp): the probability array holds 0x300 << (lc + lp) literals.
        let lit_base = unsafe { probs.add(LITERAL + 0x300 * lit) };
        let rep0 = self.reps[0];
        let match_byte: usize = if self.state >= 7 && rep0 < p { out[p - rep0 - 1] as usize } else { 0 };
        // SAFETY: probability indices are bounded by the layout (literal contexts < 8, pos
        // states < 4, states < 12, tree nodes inside their trees); input reads stay within
        // INPUT_MARGIN of in_limit (checked at every symbol); output writes are checked
        // against out_limit (symbol starts, match cut) and out_end (copy over-write);
        // match sources are checked against the dictionary start (rep0 < p).
        macro_rules! asm_loop {
            ($mode:ident) => {
                    core::arch::asm!(
                        // ---- symbol loop ----
                        "20:",
                        mark!("01"),
                        "cmp {op}, qword ptr [{ctx} + 8]",
                        "jae 90f",
                        "cmp {inp}, qword ptr [{ctx}]",
                        "ja 91f",
                        "mov {t1}, {op}",
                        "sub {t1}, qword ptr [{ctx} + 16]",
                        sel!($mode, "and {t1:e}, 3", "and {t1:e}, dword ptr [{ctx} + 176]"),
                        "mov {t2}, qword ptr [{ctx} + 64]",
                        "shl {t2:e}, 4",
                        "add {t1:e}, {t2:e}",
                        bit!("{probs} + {t1}*2", "40f"),
                        // ---- literal ----
                        mark!("02"),
                        "mov {t2}, qword ptr [{ctx} + 64]",
                        "cmp {t2:e}, 7",
                        "jae 30f",
                        // 8-bit tree; labels 31..37: entry at depth 1..7 (node in {sym}, its
                        // probability in {b} for odd depths, {a} for even ones), used by the
                        // literal with match byte once a bit differs from the match byte.
                        tfirst!("{base}"),
                        tstep!("{base}", "a", "b"),
                        "31:",
                        tstep!("{base}", "b", "a"),
                        "32:",
                        tstep!("{base}", "a", "b"),
                        "33:",
                        // the next literal's context: this byte's top three bits
                        "mov {t3:e}, {sym:e}",
                        "and {t3:e}, 7",
                        tstep!("{base}", "b", "a"),
                        "34:",
                        tstep!("{base}", "a", "b"),
                        "35:",
                        tstep!("{base}", "b", "a"),
                        "36:",
                        tstep!("{base}", "a", "b"),
                        "37:",
                        tlast!("{base}", "b", "255"),
                        "38:",
                        "mov byte ptr [{op}], {sym:l}",
                        "inc {op}",
                        sel!(
                            $mode,
                            concat!("imul {t3:e}, {t3:e}, 0x600\n", "lea {base}, [{probs} + {t3} + 3692]\n"),
                            concat!("movzx {t3:e}, {sym:l}\n", litbase!())
                        ),
                        "mov {t2}, qword ptr [{ctx} + 64]",
                        "movzx {t2:e}, byte ptr [{ctx} + {t2} + 104]",
                        "mov qword ptr [{ctx} + 64], {t2}",
                        "jmp 20b",
                        // ---- literal with match byte ----
                        "30:",
                        mark!("03"),
                        "mov {t0}, qword ptr [{ctx} + 32]",
                        "mov {t1}, {op}",
                        "sub {t1}, qword ptr [{ctx} + 16]",
                        "cmp {t0}, {t1}",
                        "jae 95f",
                        // the match byte was read by the previous symbol (in {b})
                        "mov {t2:e}, {b:e}",
                        // While the decoded bits equal the match byte's, the nodes follow the match
                        // byte: their addresses do not depend on the decoding, so the loads run
                        // ahead. The top three bits usually match (context of the next literal).
                        "mov {sym:e}, 1",
                        mlit!("7", "80"),
                        mlit!("6", "81"),
                        mlit!("5", "82"),
                        mlit!("4", "83"),
                        mlit!("3", "84"),
                        mlit!("2", "85"),
                        mlit!("1", "86"),
                        mlit_last!(),
                        "mov {t3:e}, {t2:e}",
                        "shr {t3:e}, 5",
                        "jmp 38b",
                        // first differing bit at position i: continue the plain tree at depth i + 1
                        "80:",
                        "xor {sym:e}, 1",
                        "movzx {b:e}, word ptr [{base} + {sym}*2]",
                        "jmp 31b",
                        "81:",
                        "xor {sym:e}, 1",
                        "movzx {a:e}, word ptr [{base} + {sym}*2]",
                        "jmp 32b",
                        "82:",
                        "xor {sym:e}, 1",
                        "movzx {b:e}, word ptr [{base} + {sym}*2]",
                        "jmp 33b",
                        "83:",
                        "xor {sym:e}, 1",
                        "movzx {a:e}, word ptr [{base} + {sym}*2]",
                        "mov {t3:e}, {t2:e}",
                        "shr {t3:e}, 5",
                        "jmp 34b",
                        "84:",
                        "xor {sym:e}, 1",
                        "movzx {b:e}, word ptr [{base} + {sym}*2]",
                        "mov {t3:e}, {t2:e}",
                        "shr {t3:e}, 5",
                        "jmp 35b",
                        "85:",
                        "xor {sym:e}, 1",
                        "movzx {a:e}, word ptr [{base} + {sym}*2]",
                        "mov {t3:e}, {t2:e}",
                        "shr {t3:e}, 5",
                        "jmp 36b",
                        "86:",
                        "xor {sym:e}, 1",
                        "movzx {b:e}, word ptr [{base} + {sym}*2]",
                        "mov {t3:e}, {t2:e}",
                        "shr {t3:e}, 5",
                        "jmp 37b",
                        // ---- match ----
                        "40:",
                        mark!("04"),
                        bit1!("{probs} + {t1}*2"),
                        "mov {t2}, qword ptr [{ctx} + 64]",
                        bit!("{probs} + {t2}*2 + 384", "50f"),
                        "movzx {t0:e}, byte ptr [{ctx} + {t2} + 116]",
                        "mov qword ptr [{ctx} + 64], {t0}",
                        // distance slot tree at DIST_SLOT + min(len - 2, 3) * 64 (bytes: 864 + 128 *
                        // min(len - 2, 3)); fixed for lengths >= 10, set up before their length tree
                        len_dec!(
                            sel!($mode, "and {t1:e}, 3", "and {t1:e}, dword ptr [{ctx} + 176]"),
                            "1636",
                            "41",
                            "42",
                            "43",
                            concat!(
                                "mov {t0:e}, 5\n",
                                "cmp {sym:e}, 5\n",
                                "cmovb {t0:e}, {sym:e}\n",
                                "shl {t0:e}, 7\n",
                                "lea {base}, [{probs} + {t0} + 608]\n",
                            ),
                            "lea {base}, [{probs} + 1248]\n"
                        ),
                        "mov qword ptr [{ctx} + 96], {sym}",
                        mark!("05"),
                        tree6a!("{base}", "63"),
                        "cmp {sym:e}, 4",
                        "jb 48f",
                        "cmp {sym:e}, 14",
                        "jb 46f",
                        // slot >= 14: (slot >> 1) - 5 direct bits, then 4 align bits
                        "mov {t2:e}, {sym:e}",
                        "shr {t2:e}, 1",
                        "sub {t2:e}, 5",
                        "mov {t3:e}, {sym:e}",
                        "and {t3:e}, 1",
                        "or {t3:e}, 2",
                        mark!("06"),
                        "44:",
                        "add {t3:e}, {t3:e}",
                        "lea {t1:e}, [{t3} + 1]",
                        norm!(),
                        "shr {range:e}, 1",
                        "mov {t0:e}, {code:e}",
                        "sub {code:e}, {range:e}",
                        "cmovns {t3:e}, {t1:e}",
                        "cmovs {code:e}, {t0:e}",
                        "dec {t2:e}",
                        "jnz 44b",
                        "shl {t3:e}, 4",
                        // the match source is known to within 16 bytes: prefetch it during the
                        // align bits (far matches miss L1/L2 and the next literal waits on them)
                        "mov {t0}, {op}",
                        "sub {t0}, {t3}",
                        "prefetcht0 byte ptr [{t0} - 16]",
                        "prefetcht0 byte ptr [{t0} + 48]",
                        mark!("07"),
                        rev4a!("{probs} + 1604"),
                        "add {sym:e}, {t3:e}",
                        "cmp {sym:e}, -1",
                        "je 92f",
                        "jmp 48f",
                        // slot 4..13: reverse tree of (slot >> 1) - 1 bits
                        "46:",
                        mark!("08"),
                        "mov {t2:e}, {sym:e}",
                        "shr {t2:e}, 1",
                        "dec {t2:e}",
                        "movzx {t3:e}, byte ptr [{ctx} + {sym} + 148]",
                        "mov qword ptr [{ctx} + 168], {t3}",
                        "sub {t3:e}, {sym:e}",
                        "lea {base}, [{probs} + {t3}*2 + 1374]",
                        "xor {sym:e}, {sym:e}",
                        "mov {t3:e}, 1",
                        "47:",
                        "lea {b:e}, [{sym} + {t3}]",
                        "movzx {a:e}, word ptr [{base} + {b}*2]",
                        norm!(),
                        "mov {t0:e}, {range:e}",
                        "shr {range:e}, 11",
                        "imul {range:e}, {a:e}",
                        "sub {t0:e}, {range:e}",
                        "mov {t1:e}, {code:e}",
                        "sub {code:e}, {range:e}",
                        "cmovae {range:e}, {t0:e}",
                        "cmovb {code:e}, {t1:e}",
                        "lea {t0:e}, [{sym} + {t3}]",
                        "cmovae {sym:e}, {t0:e}",
                        "lea {t0:e}, [{a} - 2017]",
                        "cmovae {t0:e}, {a:e}",
                        "shr {t0:e}, 5",
                        "sub {a:e}, {t0:e}",
                        "mov word ptr [{base} + {b}*2], {a:x}",
                        "add {t3:e}, {t3:e}",
                        "dec {t2:e}",
                        "jnz 47b",
                        "add {sym:e}, dword ptr [{ctx} + 168]",
                        // rep3..rep1 shift, rep0 = distance
                        "48:",
                        mark!("09"),
                        "mov {t0}, qword ptr [{ctx} + 48]",
                        "mov qword ptr [{ctx} + 56], {t0}",
                        "mov {t0}, qword ptr [{ctx} + 40]",
                        "mov qword ptr [{ctx} + 48], {t0}",
                        "mov {t0}, qword ptr [{ctx} + 32]",
                        "mov qword ptr [{ctx} + 40], {t0}",
                        "mov {t0:e}, {sym:e}",
                        "mov qword ptr [{ctx} + 32], {t0}",
                        "jmp 60f",
                        // ---- rep match ----
                        "50:",
                        mark!("10"),
                        bit1!("{probs} + {t2}*2 + 384"),
                        bit!("{probs} + {t2}*2 + 408", "52f"),
                        "mov {t1}, {op}",
                        "sub {t1}, qword ptr [{ctx} + 16]",
                        sel!($mode, "and {t1:e}, 3", "and {t1:e}, dword ptr [{ctx} + 176]"),
                        "mov {t0:e}, {t2:e}",
                        "shl {t0:e}, 4",
                        "add {t1:e}, {t0:e}",
                        bit!("{probs} + {t1}*2 + 480", "51f"),
                        // short rep: one byte at distance rep0
                        "movzx {t0:e}, byte ptr [{ctx} + {t2} + 140]",
                        "mov qword ptr [{ctx} + 64], {t0}",
                        "mov {t0}, qword ptr [{ctx} + 32]",
                        "mov {t1}, {op}",
                        "sub {t1}, qword ptr [{ctx} + 16]",
                        "cmp {t0}, {t1}",
                        "jae 95f",
                        "neg {t0}",
                        "movzx {t3:e}, byte ptr [{op} + {t0} - 1]",
                        "mov byte ptr [{op}], {t3:l}",
                        "movzx {b:e}, byte ptr [{op} + {t0}]",
                        "inc {op}",
                        sel!(
                            $mode,
                            concat!(
                                "shr {t3:e}, 5\n",
                                "imul {t3:e}, {t3:e}, 0x600\n",
                                "lea {base}, [{probs} + {t3} + 3692]\n"
                            ),
                            litbase!()
                        ),
                        "jmp 20b",
                        "51:",
                        bit1!("{probs} + {t1}*2 + 480"),
                        "jmp 55f",
                        "52:",
                        bit1!("{probs} + {t2}*2 + 408"),
                        bit!("{probs} + {t2}*2 + 432", "53f"),
                        "mov {t0}, qword ptr [{ctx} + 40]",
                        "mov {t1}, qword ptr [{ctx} + 32]",
                        "mov qword ptr [{ctx} + 32], {t0}",
                        "mov qword ptr [{ctx} + 40], {t1}",
                        "jmp 55f",
                        "53:",
                        bit1!("{probs} + {t2}*2 + 432"),
                        bit!("{probs} + {t2}*2 + 456", "54f"),
                        "mov {t0}, qword ptr [{ctx} + 48]",
                        "jmp 56f",
                        "54:",
                        bit1!("{probs} + {t2}*2 + 456"),
                        "mov {t0}, qword ptr [{ctx} + 56]",
                        "mov {t1}, qword ptr [{ctx} + 48]",
                        "mov qword ptr [{ctx} + 56], {t1}",
                        "56:",
                        "mov {t1}, qword ptr [{ctx} + 40]",
                        "mov qword ptr [{ctx} + 48], {t1}",
                        "mov {t1}, qword ptr [{ctx} + 32]",
                        "mov qword ptr [{ctx} + 40], {t1}",
                        "mov qword ptr [{ctx} + 32], {t0}",
                        "55:",
                        "mov {t0}, {op}",
                        "sub {t0}, qword ptr [{ctx} + 32]",
                        "prefetcht0 byte ptr [{t0} - 1]",
                        "prefetcht0 byte ptr [{t0} + 63]",
                        "movzx {t0:e}, byte ptr [{ctx} + {t2} + 128]",
                        "mov qword ptr [{ctx} + 64], {t0}",
                        mark!("11"),
                        len_dec!(sel!($mode, "and {t1:e}, 3", "and {t1:e}, dword ptr [{ctx} + 176]"), "2664", "57", "58", "59", "", ""),
                        "mov qword ptr [{ctx} + 96], {sym}",
                        // ---- copy len ([ctx + 96]) bytes from distance rep0 + 1 ----
                        "60:",
                        mark!("12"),
                        "mov {t0}, qword ptr [{ctx} + 32]",
                        "mov {t1}, {op}",
                        "sub {t1}, qword ptr [{ctx} + 16]",
                        "cmp {t0}, {t1}",
                        "jae 95f",
                        "mov {t2}, qword ptr [{ctx} + 96]",
                        "mov {t1}, qword ptr [{ctx} + 8]",
                        "sub {t1}, {op}",
                        "cmp {t2}, {t1}",
                        "ja 70f",
                        "mov {sym}, {op}",
                        "sub {sym}, {t0}",
                        // the next literal's context byte and match byte: from the source (old
                        // data, loads issue now) unless the match overlaps itself
                        "cmp {t2}, {t0}",
                        "ja 65f",
                        "movzx {t3:e}, byte ptr [{sym} + {t2} - 2]",
                        "movzx {b:e}, byte ptr [{sym} + {t2} - 1]",
                        "65:",
                        "lea {t1}, [{op} + {t2} + 64]",
                        "cmp {t1}, qword ptr [{ctx} + 24]",
                        "ja 75f",
                        "cmp {t0}, 15",
                        "jb 75f",
                        // distance >= 16: 16-byte chunks (each chunk's source is complete); 64
                        // bytes unconditionally (~85% of the matches in text are shorter)
                        "movdqu xmm0, xmmword ptr [{sym} - 1]",
                        "movdqu xmmword ptr [{op}], xmm0",
                        "movdqu xmm1, xmmword ptr [{sym} + 15]",
                        "movdqu xmmword ptr [{op} + 16], xmm1",
                        "movdqu xmm0, xmmword ptr [{sym} + 31]",
                        "movdqu xmmword ptr [{op} + 32], xmm0",
                        "movdqu xmm1, xmmword ptr [{sym} + 47]",
                        "movdqu xmmword ptr [{op} + 48], xmm1",
                        "cmp {t2}, 64",
                        "jbe 63f",
                        "mov {t1}, 64",
                        "62:",
                        "movdqu xmm0, xmmword ptr [{sym} + {t1} - 1]",
                        "movdqu xmmword ptr [{op} + {t1}], xmm0",
                        "movdqu xmm1, xmmword ptr [{sym} + {t1} + 15]",
                        "movdqu xmmword ptr [{op} + {t1} + 16], xmm1",
                        "add {t1}, 32",
                        "cmp {t1}, {t2}",
                        "jb 62b",
                        "63:",
                        "add {op}, {t2}",
                        "cmp {t2}, {t0}",
                        "jbe 66f",
                        "movzx {t3:e}, byte ptr [{op} - 1]",
                        "mov {b}, {op}",
                        "sub {b}, {t0}",
                        "movzx {b:e}, byte ptr [{b} - 1]",
                        "66:",
                        sel!(
                            $mode,
                            concat!(
                                "shr {t3:e}, 5\n",
                                "imul {t3:e}, {t3:e}, 0x600\n",
                                "lea {base}, [{probs} + {t3} + 3692]\n"
                            ),
                            litbase!()
                        ),
                        "jmp 20b",
                        // short distance or near the end of the buffer: byte by byte
                        "75:",
                        "movzx {t1:e}, byte ptr [{sym} - 1]",
                        "mov byte ptr [{op}], {t1:l}",
                        "inc {sym}",
                        "inc {op}",
                        "dec {t2}",
                        "jnz 75b",
                        "movzx {t3:e}, byte ptr [{op} - 1]",
                        "mov {b}, {op}",
                        "sub {b}, {t0}",
                        "movzx {b:e}, byte ptr [{b} - 1]",
                        sel!(
                            $mode,
                            concat!(
                                "shr {t3:e}, 5\n",
                                "imul {t3:e}, {t3:e}, 0x600\n",
                                "lea {base}, [{probs} + {t3} + 3692]\n"
                            ),
                            litbase!()
                        ),
                        "jmp 20b",
                        // the match crosses the output limit: copy up to it, keep the rest pending
                        "70:",
                        "sub {t2}, {t1}",
                        "mov qword ptr [{ctx} + 80], {t2}",
                        "mov {t2}, {t1}",
                        "mov {sym}, {op}",
                        "sub {sym}, {t0}",
                        "76:",
                        "movzx {t1:e}, byte ptr [{sym} - 1]",
                        "mov byte ptr [{op}], {t1:l}",
                        "inc {sym}",
                        "inc {op}",
                        "dec {t2}",
                        "jnz 76b",
                        // ---- exits: status 0 limit, 1 input, 2 end marker, 3 bad distance ----
                        "90:",
                        mark!("13"),
                        "xor {t0:e}, {t0:e}",
                        "jmp 99f",
                        "91:",
                        "mov {t0:e}, 1",
                        "jmp 99f",
                        "92:",
                        "mov {t0:e}, 2",
                        "jmp 99f",
                        "95:",
                        "mov {t0:e}, 3",
                        "99:",
                        "mov qword ptr [{ctx} + 88], {t0}",
                        range = inout(reg) range,
                        code = inout(reg) code,
                        inp = inout(reg) inp,
                        op = inout(reg) op,
                        probs = in(reg) probs,
                        ctx = in(reg) ctxp,
                        base = inout(reg) lit_base => _,
                        sym = out(reg) _,
                        a = out(reg) _,
                        b = inout(reg) match_byte => _,
                        t0 = out(reg) _,
                        t1 = out(reg) _,
                        t2 = out(reg) _,
                        t3 = out(reg) _,
                        out("xmm0") _,
                        out("xmm1") _,
                        options(nostack),
                    )
            };
        }
        unsafe {
            if FIXED {
                asm_loop!(fixed)
            } else {
                asm_loop!(generic)
            }
        };
        rc.range = range;
        rc.code = code;
        rc.ip = inp as usize - inp0 as usize;
        *pos = op as usize - outp as usize;
        self.state = ctx.state as usize;
        self.reps = ctx.reps.map(|r| r as usize);
        match ctx.status {
            0 => {
                self.pending_len = ctx.pending as usize;
                Ok(Stop::Limit)
            }
            1 => Ok(Stop::InputExhausted),
            2 => Ok(Stop::EndMarker),
            _ => Err(corrupt("distance")),
        }
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

    /// Decodes with the lc=3 lp=0 pb=2 fast path and with the generic loop.
    fn both<T: PartialEq + std::fmt::Debug>(f: impl Fn() -> T) -> (T, T) {
        let fast = f();
        FORCE_PORTABLE.with(|g| g.set(true));
        let generic = f();
        FORCE_PORTABLE.with(|g| g.set(false));
        (fast, generic)
    }

    fn xorshift(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    /// Outcome of a decode as a comparable value (error messages included).
    fn outcome(r: Result<Vec<u8>>) -> std::result::Result<Vec<u8>, String> {
        r.map_err(|e| format!("{e:?}"))
    }

    /// The x86-64 asm loop and the portable Rust loop (an independent implementation) must
    /// agree on every input: valid streams from our encoder over varied data (text, binary,
    /// runs, short and long distances, chunk and output-limit crossings) and thousands of
    /// mutated and truncated versions of them (same output, or the same error), raw LZMA1
    /// with every properties byte, and the xz fixtures (lc1 lp3 pb1, BCJ, delta, multi-block).
    #[test]
    fn codecs_lzma_fast_path_matches_generic() {
        use crate::codecs::lzma_enc::{Lzma2Encoder, LzmaParams};
        use crate::codecs::testdata::gen_data;
        let mut s = 0x5EED_1234_ABCD_0001u64;
        let mut inputs: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"a".to_vec(),
            b"abababababababababababababababababab".to_vec(),
            vec![0u8; 70_000],
            include_bytes!("testdata/text.json").to_vec(),
            include_bytes!("testdata/x86.bin").to_vec(),
        ];
        for (i, n) in [100usize, 1000, 5000, 30_000, 70_000, 200_000, 600_000].into_iter().enumerate() {
            inputs.push(gen_data(i as u64 + 1, n));
            // short-period patterns (distances 1..20) mixed with random bytes
            let mut v = Vec::with_capacity(n);
            while v.len() < n {
                let r = xorshift(&mut s);
                let period = (r % 20 + 1) as usize;
                let reps = (r >> 8) % 300;
                let start = v.len();
                for _ in 0..period {
                    v.push((xorshift(&mut s) % 7) as u8 + b'a');
                }
                for k in 0..reps as usize {
                    let b = v[start + k % period];
                    v.push(b);
                }
            }
            v.truncate(n);
            inputs.push(v);
        }
        let mut streams = Vec::new();
        for (i, data) in inputs.iter().enumerate() {
            let mut e = Lzma2Encoder::new(LzmaParams::preset([0, 6, 9][i % 3]));
            let mut out = Vec::new();
            e.encode_block(data, &mut out);
            let (fast, generic) = both(|| outcome(decompress_lzma2(&out)));
            assert_eq!(fast.as_deref().ok(), Some(&data[..]), "input {i}: fast path");
            assert!(fast == generic, "input {i}: paths differ");
            streams.push(out);
        }
        streams.push(include_bytes!("testdata/text.lzma2").to_vec());
        // Mutations: bytes, bit flips, truncations, splices.
        let mut n_ok = 0;
        for round in 0..6000 {
            let base = &streams[round % streams.len()];
            if base.len() < 8 {
                continue;
            }
            let mut v = base.clone();
            let r = xorshift(&mut s);
            match r % 4 {
                0 => {
                    for _ in 0..(r >> 8) % 3 + 1 {
                        let i = 6 + (xorshift(&mut s) as usize) % (v.len() - 6);
                        v[i] = xorshift(&mut s) as u8;
                    }
                }
                1 => {
                    let i = 6 + (xorshift(&mut s) as usize) % (v.len() - 6);
                    v[i] ^= 1 << (xorshift(&mut s) % 8);
                }
                2 => v.truncate((xorshift(&mut s) as usize) % v.len()),
                _ => {
                    let other = &streams[(xorshift(&mut s) as usize) % streams.len()];
                    let a = (xorshift(&mut s) as usize) % v.len();
                    let b = (xorshift(&mut s) as usize) % other.len();
                    let n = ((xorshift(&mut s) % 64) as usize).min(v.len() - a).min(other.len() - b);
                    v[a..a + n].copy_from_slice(&other[b..b + n]);
                }
            }
            let (fast, generic) = both(|| outcome(decompress_lzma2(&v)));
            assert!(fast == generic, "mutation {round}: paths differ");
            n_ok += fast.is_ok() as usize;
            // Raw LZMA1 on the payload of the first chunk: garbage symbols, end markers,
            // output growth (no size) and a declared size.
            if v.len() > 6 {
                let size = xorshift(&mut s) % 100_000;
                let (f1, g1) = both(|| outcome(decompress_lzma1_raw(&v[6..], 93, None)));
                assert!(f1 == g1, "mutation {round}: lzma1 paths differ");
                let (f2, g2) = both(|| outcome(decompress_lzma1_raw(&v[6..], 93, Some(size))));
                assert!(f2 == g2, "mutation {round}: sized lzma1 paths differ");
                // any lc/lp/pb (the asm loop's generic mode)
                let props = (xorshift(&mut s) % 225) as u8;
                let (f3, g3) = both(|| outcome(decompress_lzma1_raw(&v[6..], props, Some(size))));
                assert!(f3 == g3, "mutation {round}: lzma1 props {props} paths differ");
            }
        }
        assert!(n_ok > 20, "{n_ok}");
        // xz fixtures, whole and mutated
        let fixtures: [&[u8]; 8] = [
            include_bytes!("testdata/text.xz"),
            include_bytes!("testdata/text.e9.xz"),
            include_bytes!("testdata/text.props.xz"),
            include_bytes!("testdata/text.blocks.xz"),
            include_bytes!("testdata/noise.xz"),
            include_bytes!("testdata/x86.bin.xz"),
            include_bytes!("testdata/samples.bin.xz"),
            include_bytes!("testdata/multi.xz"),
        ];
        for (i, f) in fixtures.iter().enumerate() {
            let (fast, generic) = both(|| outcome(crate::codecs::xz::decompress(f)));
            assert!(fast.is_ok() && fast == generic, "xz fixture {i}");
        }
        for round in 0..3000 {
            let mut v = fixtures[round % fixtures.len()].to_vec();
            for _ in 0..(round % 3) + 1 {
                let i = (xorshift(&mut s) as usize) % v.len();
                v[i] ^= 1 << (xorshift(&mut s) % 8);
            }
            let (fast, generic) = both(|| outcome(crate::codecs::xz::decompress(&v)));
            assert!(fast == generic, "xz mutation {round}: paths differ");
            // the lc1 lp3 pb1 fixture's LZMA2 payload with its checks out of the way
            let (f1, g1) = both(|| outcome(decompress_lzma2(&v[24..])));
            assert!(f1 == g1, "xz mutation {round}: raw lzma2 paths differ");
        }
    }
}
