//! Structural-index JSON parsing, simdjson style.
//!
//! **Stage 1** ([`Index::build`]) finds, 64 bytes at a time with AVX2 + PCLMULQDQ (runtime
//! detected; portable fallback), every unescaped quote (string open and close), every
//! structural character outside strings (`{ } [ ] : ,`) and the first byte of every scalar
//! (number / `true` / `false` / `null` / garbage), and flattens them into one sorted `u32`
//! position array. Backslashes inside strings are recorded separately (strings without one are
//! borrowed as is). Raw control characters inside strings and unterminated strings are errors
//! (python's `json.loads` is strict about both).
//!
//! **Stage 2** ([`Walker`]) walks the index: a string is two consecutive entries (open, close
//! quote), a scalar starts at its entry, so no whitespace is ever scanned byte by byte.
//! [`Pull`] is the pull-parser interface shared with [`crate::util::json::Parser`], so the same
//! consumer code (the ISF loader) runs on either.
//!
//! Large inputs are indexed on several threads: chunks begin right after a `'\n'`, which valid
//! JSON never has inside a string (raw control characters must be escaped), so every chunk
//! starts outside a string; each chunk checks that it also ends outside one, which by induction
//! validates the assumption. Each chunk's bracket depth change comes out of stage 1, giving
//! every chunk its absolute start depth for parallel stage-2 walks ([`Index::chunks`]).

use super::json::{Json, Kind, dict_dedupe};
use crate::error::{Error, Result};
use std::borrow::Cow;

/// Minimum input size before stage 1 runs on several threads.
const PAR_MIN: usize = 1 << 20;
/// Target chunk size for parallel stage 1.
const CHUNK: usize = 512 << 10;

/// A stage-1 chunk of the index: entries `[first, first + len)` cover input bytes
/// `[start, end)`; `depth` is the absolute bracket depth at `start`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Chunk {
    pub start: u32,
    pub end: u32,
    pub first: u32,
    pub len: u32,
    pub depth: i32,
}

/// The structural index of a JSON document.
pub struct Index {
    /// Sorted byte positions of quotes, structurals and scalar starts.
    pub pos: Vec<u32>,
    /// Sorted positions of backslashes inside strings.
    pub esc: Vec<u32>,
    /// The stage-1 chunks (one for small inputs), in order.
    pub chunks: Vec<Chunk>,
    /// The whole input is valid UTF-8 (string slices need no per-string check).
    pub utf8: bool,
}

// ---------------------------------------------------------------------------------------------
// stage 1
// ---------------------------------------------------------------------------------------------

/// Per-64-byte-block character class masks (bit i = byte i).
#[derive(Clone, Copy, Default)]
struct Masks {
    quote: u64,
    bs: u64,
    /// `{ } [ ] : ,`
    op: u64,
    /// `{ [`
    open: u64,
    /// `} ]`
    close: u64,
    /// space, \t, \n, \r
    ws: u64,
    /// bytes < 0x20
    ctrl: u64,
}

/// Carried state between blocks.
#[derive(Clone, Copy, Default)]
struct State {
    prev_escaped: u64,
    prev_in_string: u64,
    prev_scalar: u64,
    depth: i64,
    bad: bool,
}

const C_QUOTE: u8 = 1;
const C_BS: u8 = 2;
const C_OP: u8 = 4;
const C_OPEN: u8 = 8;
const C_CLOSE: u8 = 16;
const C_WS: u8 = 32;
const C_CTRL: u8 = 64;

const fn class_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 0x20 {
        t[i] = C_CTRL;
        i += 1;
    }
    t[b'"' as usize] = C_QUOTE;
    t[b'\\' as usize] = C_BS;
    t[b'{' as usize] = C_OP | C_OPEN;
    t[b'[' as usize] = C_OP | C_OPEN;
    t[b'}' as usize] = C_OP | C_CLOSE;
    t[b']' as usize] = C_OP | C_CLOSE;
    t[b':' as usize] = C_OP;
    t[b',' as usize] = C_OP;
    t[b' ' as usize] = C_WS;
    t[b'\t' as usize] = C_WS | C_CTRL;
    t[b'\n' as usize] = C_WS | C_CTRL;
    t[b'\r' as usize] = C_WS | C_CTRL;
    t
}
static CLASS: [u8; 256] = class_table();

/// Portable mask computation (fallback and tests).
#[inline]
fn masks_scalar(b: &[u8; 64]) -> Masks {
    let mut m = Masks::default();
    for (i, &c) in b.iter().enumerate() {
        let k = CLASS[c as usize];
        let bit = 1u64 << i;
        if k & C_QUOTE != 0 {
            m.quote |= bit;
        }
        if k & C_BS != 0 {
            m.bs |= bit;
        }
        if k & C_OP != 0 {
            m.op |= bit;
        }
        if k & C_OPEN != 0 {
            m.open |= bit;
        }
        if k & C_CLOSE != 0 {
            m.close |= bit;
        }
        if k & C_WS != 0 {
            m.ws |= bit;
        }
        if k & C_CTRL != 0 {
            m.ctrl |= bit;
        }
    }
    m
}

#[inline(always)]
fn prefix_xor_portable(mut x: u64) -> u64 {
    x ^= x << 1;
    x ^= x << 2;
    x ^= x << 4;
    x ^= x << 8;
    x ^= x << 16;
    x ^= x << 32;
    x
}

/// Where stage 1 puts a block's index bits.
trait Sink {
    fn put(&mut self, bits: u64, base: u32);
}

impl Sink for Vec<u32> {
    #[inline(always)]
    fn put(&mut self, bits: u64, base: u32) {
        flatten(self, bits, base)
    }
}

/// Counting pass of the parallel stage 1: only how many entries a chunk has.
struct Count(usize);

impl Sink for Count {
    #[inline(always)]
    fn put(&mut self, bits: u64, _base: u32) {
        self.0 += bits.count_ones() as usize;
    }
}

/// The bit logic shared by the SIMD and portable paths: escapes, string mask, index bits,
/// depth; appends the index entries of this block.
#[inline(always)]
fn block<K: Sink>(m: &Masks, in_str_xor: u64, base: u32, st: &mut State, out: &mut K, esc: &mut Vec<u32>) {
    // backslash runs: odd-length runs escape the next character (simdjson find_escaped)
    let escaped = if m.bs == 0 && st.prev_escaped == 0 {
        0
    } else {
        const EVEN: u64 = 0x5555_5555_5555_5555;
        let bs = m.bs & !st.prev_escaped;
        let follows = (bs << 1) | st.prev_escaped;
        let odd_starts = bs & !EVEN & !follows;
        let (seq_even, ovf) = odd_starts.overflowing_add(bs);
        st.prev_escaped = ovf as u64;
        (EVEN ^ (seq_even << 1)) & follows
    };
    let quote = m.quote & !escaped;
    // `in_str_xor` = prefix_xor(quote) (computed by the caller: PCLMUL or portable)
    let _ = quote;
    let in_string = in_str_xor ^ st.prev_in_string;
    st.prev_in_string = ((in_string as i64) >> 63) as u64;
    if m.ctrl & in_string != 0 {
        st.bad = true;
    }
    let bs_in = m.bs & in_string;
    if bs_in != 0 {
        let mut b = bs_in;
        while b != 0 {
            esc.push(base + b.trailing_zeros());
            b &= b - 1;
        }
    }
    let outside = !in_string;
    let scalar = !(m.op | m.ws | quote | in_string);
    let starts = scalar & !((scalar << 1) | st.prev_scalar);
    st.prev_scalar = scalar >> 63;
    st.depth += (m.open & outside).count_ones() as i64 - (m.close & outside).count_ones() as i64;
    out.put((m.op & outside) | quote | starts, base);
}

/// Append the positions of the set bits of `bits` (+ `base`). Unconditionally writes 8 (then
/// 16) slots so the common case has no data-dependent loop exit.
#[inline(always)]
fn flatten(out: &mut Vec<u32>, bits: u64, base: u32) {
    if bits == 0 {
        return;
    }
    let cnt = bits.count_ones() as usize;
    if out.capacity() - out.len() < 64 {
        out.reserve(out.len().max(1 << 16));
    }
    let len = out.len();
    // SAFETY: capacity >= len + 64 >= len + cnt, and every slot below len + cnt is written
    unsafe {
        let p = out.as_mut_ptr().add(len);
        let mut b = bits;
        for k in 0..8 {
            *p.add(k) = base.wrapping_add(b.trailing_zeros());
            b &= b.wrapping_sub(1);
        }
        if cnt > 8 {
            for k in 8..16 {
                *p.add(k) = base.wrapping_add(b.trailing_zeros());
                b &= b.wrapping_sub(1);
            }
            let mut k = 16;
            while b != 0 {
                *p.add(k) = base.wrapping_add(b.trailing_zeros());
                b &= b.wrapping_sub(1);
                k += 1;
            }
        }
        out.set_len(len + cnt);
    }
}

/// Index `buf[start..end]` (absolute positions), assuming `start` is outside any string and
/// not escaped. Returns the state after `end`.
fn index_range<K: Sink>(buf: &[u8], start: usize, end: usize, out: &mut K, esc: &mut Vec<u32>) -> State {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") && std::arch::is_x86_feature_detected!("pclmulqdq") {
            // SAFETY: the features were detected at run time
            return unsafe { x86::index_range_avx2(buf, start, end, out, esc) };
        }
    }
    index_range_portable(buf, start, end, out, esc)
}

fn index_range_portable<K: Sink>(buf: &[u8], start: usize, end: usize, out: &mut K, esc: &mut Vec<u32>) -> State {
    let mut st = State::default();
    let mut i = start;
    let mut blk = [b' '; 64];
    while i < end {
        let n = (end - i).min(64);
        blk[..n].copy_from_slice(&buf[i..i + n]);
        blk[n..].fill(b' ');
        let m = masks_scalar(&blk);
        let escaped_q = quote_after_escapes(&m, &st);
        block(&m, prefix_xor_portable(escaped_q), i as u32, &mut st, out, esc);
        i += 64;
    }
    st
}

/// The unescaped quote bits (what `block` computes; needed first for the prefix xor).
#[inline(always)]
fn quote_after_escapes(m: &Masks, st: &State) -> u64 {
    if m.bs == 0 && st.prev_escaped == 0 {
        return m.quote;
    }
    const EVEN: u64 = 0x5555_5555_5555_5555;
    let bs = m.bs & !st.prev_escaped;
    let follows = (bs << 1) | st.prev_escaped;
    let odd_starts = bs & !EVEN & !follows;
    let seq_even = odd_starts.wrapping_add(bs);
    m.quote & !((EVEN ^ (seq_even << 1)) & follows)
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::*;
    use std::arch::x86_64::*;

    #[target_feature(enable = "avx2,pclmulqdq,popcnt,bmi1")]
    pub(super) unsafe fn ident_marks_avx2(buf: &[u8]) -> Option<IdentMarks> {
        let q = _mm256_set1_epi8(b'"' as i8);
        let bsl = _mm256_set1_epi8(b'\\' as i8);
        let ob = _mm256_set1_epi8(b'{' as i8);
        let os = _mm256_set1_epi8(b'[' as i8);
        let cb = _mm256_set1_epi8(b'}' as i8);
        let cs = _mm256_set1_epi8(b']' as i8);
        let vv = _mm256_set1_epi8(b'v' as i8);
        let ll = _mm256_set1_epi8(b'l' as i8);
        let ones = _mm_set1_epi8(-1);
        let mut out = IdentMarks::default();
        let (mut prev_escaped, mut prev_in, mut depth) = (0u64, 0u64, 0i64);
        let mut any_bs = 0u64;
        // blocks read 64 + 13 bytes: the last ones go through a padded copy
        let mut pad = [b' '; 64 + 64];
        let mut i = 0usize;
        while i < buf.len() {
            let p: *const u8 = if buf.len() - i >= 64 + 16 {
                unsafe { buf.as_ptr().add(i) }
            } else {
                let n = (buf.len() - i).min(128);
                pad[..n].copy_from_slice(&buf[i..i + n]);
                pad[n..].fill(b' ');
                pad.as_ptr()
            };
            // SAFETY: `p` has at least 64 + 13 readable bytes (input or padded copy)
            let (qm, bs, o, c, pre) = unsafe {
                let half = |k: usize| -> (u32, u32, u32, u32, u32) {
                    let v = _mm256_loadu_si256(p.add(k) as *const __m256i);
                    let v1 = _mm256_loadu_si256(p.add(k + 1) as *const __m256i);
                    let v8 = _mm256_loadu_si256(p.add(k + 8) as *const __m256i);
                    let v13 = _mm256_loadu_si256(p.add(k + 13) as *const __m256i);
                    let isq = _mm256_cmpeq_epi8(v, q);
                    let cand = _mm256_and_si256(
                        isq,
                        _mm256_or_si256(
                            _mm256_and_si256(_mm256_cmpeq_epi8(v1, vv), _mm256_cmpeq_epi8(v8, q)),
                            _mm256_and_si256(_mm256_cmpeq_epi8(v1, ll), _mm256_cmpeq_epi8(v13, q)),
                        ),
                    );
                    (
                        _mm256_movemask_epi8(isq) as u32,
                        _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, bsl)) as u32,
                        _mm256_movemask_epi8(_mm256_or_si256(_mm256_cmpeq_epi8(v, ob), _mm256_cmpeq_epi8(v, os))) as u32,
                        _mm256_movemask_epi8(_mm256_or_si256(_mm256_cmpeq_epi8(v, cb), _mm256_cmpeq_epi8(v, cs))) as u32,
                        _mm256_movemask_epi8(cand) as u32,
                    )
                };
                let a = half(0);
                let b = half(32);
                let j = |x: u32, y: u32| x as u64 | (y as u64) << 32;
                (j(a.0, b.0), j(a.1, b.1), j(a.2, b.2), j(a.3, b.3), j(a.4, b.4))
            };
            // the padded tail: bytes past the end are spaces, masks beyond it are empty
            any_bs |= bs;
            let escaped = if bs == 0 && prev_escaped == 0 {
                0
            } else {
                const EVEN: u64 = 0x5555_5555_5555_5555;
                let bs = bs & !prev_escaped;
                let follows = (bs << 1) | prev_escaped;
                let odd_starts = bs & !EVEN & !follows;
                let (seq_even, ovf) = odd_starts.overflowing_add(bs);
                prev_escaped = ovf as u64;
                (EVEN ^ (seq_even << 1)) & follows
            };
            let qu = qm & !escaped;
            let in_string = _mm_cvtsi128_si64(_mm_clmulepi64_si128(_mm_set_epi64x(0, qu as i64), ones, 0)) as u64 ^ prev_in;
            prev_in = ((in_string as i64) >> 63) as u64;
            let outside = !in_string;
            let (op, cl) = (o & outside, c & outside);
            let opening = qu & in_string;
            // verified candidates among the opening quotes
            let mut cmask = 0u64;
            let mut pc = pre & opening;
            while pc != 0 {
                let t = pc.trailing_zeros() as usize;
                if i + t < buf.len() && ident_cand_at(buf, i + t) {
                    cmask |= 1u64 << t;
                }
                pc &= pc - 1;
            }
            let ccl = cl.count_ones() as i64;
            if (opening != 0 && (depth - ccl <= 1 || cmask != 0)) || depth - ccl < 0 {
                let mut ev = op | cl | opening;
                let mut d = depth;
                while ev != 0 {
                    let t = ev.trailing_zeros();
                    let bit = 1u64 << t;
                    if op & bit != 0 {
                        d += 1;
                    } else if cl & bit != 0 {
                        d -= 1;
                        if d < 0 {
                            return None;
                        }
                    } else if d == 1 {
                        out.d1.push(i + t as usize);
                    } else if d == 2 && cmask & bit != 0 {
                        out.d2.push(i + t as usize);
                    }
                    ev &= ev - 1;
                }
            }
            depth += op.count_ones() as i64 - ccl;
            i += 64;
        }
        out.backslash = any_bs != 0;
        (depth == 0 && prev_in == 0).then_some(out)
    }

    #[target_feature(enable = "avx2,pclmulqdq,popcnt,bmi1")]
    pub(super) unsafe fn depth_marks_avx2(buf: &[u8], cands: &[usize]) -> Option<(Vec<usize>, Vec<usize>)> {
        let q = _mm256_set1_epi8(b'"' as i8);
        let bsl = _mm256_set1_epi8(b'\\' as i8);
        let ob = _mm256_set1_epi8(b'{' as i8);
        let os = _mm256_set1_epi8(b'[' as i8);
        let cb = _mm256_set1_epi8(b'}' as i8);
        let cs = _mm256_set1_epi8(b']' as i8);
        let ones = _mm_set1_epi8(-1);
        let masks = |b: &[u8; 64]| -> (u64, u64, u64, u64) {
            // SAFETY: 64 readable bytes; AVX2 detected by the caller
            unsafe {
                let m = |v: __m256i| -> (u32, u32, u32, u32) {
                    (
                        _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, q)) as u32,
                        _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, bsl)) as u32,
                        _mm256_movemask_epi8(_mm256_or_si256(_mm256_cmpeq_epi8(v, ob), _mm256_cmpeq_epi8(v, os))) as u32,
                        _mm256_movemask_epi8(_mm256_or_si256(_mm256_cmpeq_epi8(v, cb), _mm256_cmpeq_epi8(v, cs))) as u32,
                    )
                };
                let a = m(_mm256_loadu_si256(b.as_ptr() as *const __m256i));
                let c = m(_mm256_loadu_si256(b.as_ptr().add(32) as *const __m256i));
                let j = |x: u32, y: u32| x as u64 | (y as u64) << 32;
                (j(a.0, c.0), j(a.1, c.1), j(a.2, c.2), j(a.3, c.3))
            }
        };
        let pxor = |x: u64| -> u64 { _mm_cvtsi128_si64(_mm_clmulepi64_si128(_mm_set_epi64x(0, x as i64), ones, 0)) as u64 };
        depth_marks_with(buf, cands, masks, pxor)
    }

    #[target_feature(enable = "avx2,pclmulqdq,popcnt,bmi1")]
    pub(super) unsafe fn index_range_avx2<K: Sink>(buf: &[u8], start: usize, end: usize, out: &mut K, esc: &mut Vec<u32>) -> State {
        // nibble classifier (see the module docs of simdjson): class bits
        //   b0 ','  b1 ':'  b2 '[' '{'  b3 ']' '}'  b4 ' '  b5 '\t' '\n' '\r'
        let lo_tab = _mm256_setr_epi8(
            0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x22, 0x04, 0x01, 0x28, 0, 0, //
            0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x22, 0x04, 0x01, 0x28, 0, 0,
        );
        let hi_tab = _mm256_setr_epi8(
            0x20, 0, 0x11, 0x02, 0, 0x0C, 0, 0x0C, 0, 0, 0, 0, 0, 0, 0, 0, //
            0x20, 0, 0x11, 0x02, 0, 0x0C, 0, 0x0C, 0, 0, 0, 0, 0, 0, 0, 0,
        );
        let nib = _mm256_set1_epi8(0x0F);
        let zero = _mm256_setzero_si256();
        let q = _mm256_set1_epi8(b'"' as i8);
        let bsl = _mm256_set1_epi8(b'\\' as i8);
        let c1f = _mm256_set1_epi8(0x1F);
        let op_bits = _mm256_set1_epi8(0x0F);
        let ws_bits = _mm256_set1_epi8(0x30);
        let ones = _mm_set1_epi8(-1);

        macro_rules! half {
            ($v:expr) => {{
                let v = $v;
                let lo = _mm256_shuffle_epi8(lo_tab, _mm256_and_si256(v, nib));
                let hi = _mm256_shuffle_epi8(hi_tab, _mm256_and_si256(_mm256_srli_epi16(v, 4), nib));
                let cls = _mm256_and_si256(lo, hi);
                let op = !(_mm256_movemask_epi8(_mm256_cmpeq_epi8(_mm256_and_si256(cls, op_bits), zero)) as u32);
                let ws = !(_mm256_movemask_epi8(_mm256_cmpeq_epi8(_mm256_and_si256(cls, ws_bits), zero)) as u32);
                // class bit 2 / bit 3 -> each byte's bit 7 (epi16 shifts by < 8 never carry a
                // neighbour byte's bits into bit 7)
                let open = _mm256_movemask_epi8(_mm256_slli_epi16(cls, 5)) as u32;
                let close = _mm256_movemask_epi8(_mm256_slli_epi16(cls, 4)) as u32;
                let quote = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, q)) as u32;
                let bs = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, bsl)) as u32;
                let ctrl = _mm256_movemask_epi8(_mm256_cmpeq_epi8(_mm256_max_epu8(v, c1f), c1f)) as u32;
                [quote, bs, op, open, close, ws, ctrl]
            }};
        }

        let mut st = State::default();
        let mut i = start;
        let mut tail = [b' '; 64];
        while i < end {
            let p: *const u8 = if end - i >= 64 {
                unsafe { buf.as_ptr().add(i) }
            } else {
                let n = end - i;
                tail[..n].copy_from_slice(&buf[i..end]);
                tail[n..].fill(b' ');
                tail.as_ptr()
            };
            // SAFETY: `p` points at 64 readable bytes (the input or the padded tail copy)
            let (a, b) = unsafe { (half!(_mm256_loadu_si256(p as *const __m256i)), half!(_mm256_loadu_si256(p.add(32) as *const __m256i))) };
            let j = |k: usize| a[k] as u64 | (b[k] as u64) << 32;
            let m = Masks { quote: j(0), bs: j(1), op: j(2), open: j(3), close: j(4), ws: j(5), ctrl: j(6) };
            let qu = quote_after_escapes(&m, &st);
            let px = _mm_cvtsi128_si64(_mm_clmulepi64_si128(_mm_set_epi64x(0, qu as i64), ones, 0)) as u64;
            block(&m, px, i as u32, &mut st, out, esc);
            i += 64;
        }
        st
    }
}

impl Index {
    /// Stage 1 over the whole document (parallel for large inputs).
    pub fn build(buf: &[u8]) -> Result<Index> {
        Self::build_with(buf, true)
    }

    /// Stage 1; `parallel = false` keeps it on the calling thread (callers that already run one
    /// document per core).
    pub fn build_with(buf: &[u8], parallel: bool) -> Result<Index> {
        if buf.len() >= u32::MAX as usize - 64 {
            return Err(Error::msg("JSON document too large"));
        }
        let threads = if parallel && buf.len() >= PAR_MIN { crate::util::par::threads() } else { 1 };
        // chunk boundaries: just after a '\n' near every CHUNK bytes
        let mut bounds = vec![0usize];
        if threads > 1 {
            let target = CHUNK.max(buf.len() / (threads * 2)).max(64 << 10);
            let mut at = target;
            while at < buf.len() {
                match memchr_nl(&buf[at..(at + (64 << 10)).min(buf.len())]) {
                    Some(k) if at + k + 1 < buf.len() => {
                        bounds.push(at + k + 1);
                        at = at + k + 1 + target;
                    }
                    _ => break,
                }
            }
        }
        bounds.push(buf.len());
        let n = bounds.len() - 1;
        if n == 1 {
            let mut pos = Vec::with_capacity(buf.len() / 6 + 64);
            let mut esc = Vec::new();
            let st = index_range(buf, 0, buf.len(), &mut pos, &mut esc);
            if st.bad {
                return Err(Error::msg("JSON parse error: invalid control character in string"));
            }
            if st.prev_in_string != 0 {
                return Err(Error::msg("JSON parse error: unterminated string"));
            }
            let chunks = vec![Chunk { start: 0, end: buf.len() as u32, first: 0, len: pos.len() as u32, depth: 0 }];
            return Ok(Index { pos, esc, chunks, utf8: std::str::from_utf8(buf).is_ok() });
        }
        // two passes over the chunks: count each chunk's entries (and its end state), then
        // index each chunk straight into its slot of the final array (no per-chunk vectors to
        // allocate, fault in and concatenate)
        let counted: Vec<(usize, State, bool)> = {
            let _t = crate::util::trace::span("stage1: count pass");
            crate::util::pool::map(n, |c| {
                let (s, e) = (bounds[c], bounds[c + 1]);
                let mut cnt = Count(0);
                let st = index_range(buf, s, e, &mut cnt, &mut Vec::new());
                (cnt.0, st, std::str::from_utf8(&buf[s..e]).is_ok())
            })
        };
        let mut chunks = Vec::with_capacity(n);
        let mut depth: i64 = 0;
        let mut total = 0usize;
        let mut utf8 = true;
        for (c, (cnt, st, u)) in counted.iter().enumerate() {
            if st.bad {
                return Err(Error::msg("JSON parse error: invalid control character in string"));
            }
            if st.prev_in_string != 0 {
                return Err(Error::msg("JSON parse error: unterminated string"));
            }
            utf8 &= u;
            chunks.push(Chunk { start: bounds[c] as u32, end: bounds[c + 1] as u32, first: total as u32, len: *cnt as u32, depth: depth.clamp(i32::MIN as i64, i32::MAX as i64) as i32 });
            depth += st.depth;
            total += cnt;
        }
        let _t = crate::util::trace::span("stage1: index pass");
        let mut pos: Vec<u32> = Vec::with_capacity(total + 8);
        struct Dst(*mut u32);
        // SAFETY: each chunk writes exactly its own range [first, first + len) (checked)
        unsafe impl Sync for Dst {}
        let dst = Dst(pos.as_mut_ptr());
        let dst = &dst;
        let chunks_ref = &chunks;
        thread_local! {
            static SCRATCH: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
        }
        let escs: Vec<Option<Vec<u32>>> = crate::util::pool::map(n, |c| {
            let (s, e) = (bounds[c], bounds[c + 1]);
            let ch = chunks_ref[c];
            SCRATCH.with(|sc| {
                let mut sc = sc.borrow_mut();
                sc.clear();
                let mut esc = Vec::new();
                index_range(buf, s, e, &mut *sc, &mut esc);
                if sc.len() != ch.len as usize {
                    return None; // cannot happen: the same pass as the count
                }
                // SAFETY: disjoint destination ranges, total capacity reserved above
                unsafe { std::ptr::copy_nonoverlapping(sc.as_ptr(), dst.0.add(ch.first as usize), sc.len()) };
                Some(esc)
            })
        });
        if escs.iter().any(|e| e.is_none()) {
            return Err(Error::msg("JSON structural index: inconsistent passes"));
        }
        // SAFETY: every chunk wrote its full range, which tile [0, total)
        unsafe { pos.set_len(total) };
        let esc: Vec<u32> = escs.into_iter().flatten().flatten().collect();
        Ok(Index { pos, esc, chunks, utf8 })
    }

    /// Serial stage 1 into a recycled position vector (see [`Index::recycle`]): a worker
    /// indexing many documents faults its index memory in once.
    pub fn build_serial_reusing(buf: &[u8], mut pos: Vec<u32>) -> Result<Index> {
        if buf.len() >= u32::MAX as usize - 64 {
            return Err(Error::msg("JSON document too large"));
        }
        pos.clear();
        let mut esc = Vec::new();
        let st = index_range(buf, 0, buf.len(), &mut pos, &mut esc);
        if st.bad {
            return Err(Error::msg("JSON parse error: invalid control character in string"));
        }
        if st.prev_in_string != 0 {
            return Err(Error::msg("JSON parse error: unterminated string"));
        }
        let chunks = vec![Chunk { start: 0, end: buf.len() as u32, first: 0, len: pos.len() as u32, depth: 0 }];
        Ok(Index { pos, esc, chunks, utf8: std::str::from_utf8(buf).is_ok() })
    }

    /// The position vector, for [`Index::build_serial_reusing`].
    pub fn recycle(self) -> Vec<u32> {
        self.pos
    }

    /// A walker over the whole document.
    pub fn walker<'d, 'a>(&'d self, buf: &'a [u8]) -> Walker<'d, 'a> {
        Walker { buf, pos: &self.pos, esc: &self.esc, i: 0, utf8: self.utf8, depth: 0 }
    }

    /// The top two levels of a document shaped `{"key": value, ...}`, found on all cores
    /// (each stage-1 chunk walks its own entries from its known start depth), in document
    /// order: every key of the root object ([`Ev::TopKey`]), every bracket opening / closing a
    /// top-level value ([`Ev::Open1`] / [`Ev::Close1`]) and every string at depth 2 that
    /// follows `{` or `,` ([`Ev::Key2`]: the member keys of top-level objects; also strings in
    /// top-level arrays, which consumers ignore). Enough to split the members of each
    /// top-level object into ranges that parse independently. Not a validation: consumers
    /// check the grammar while parsing.
    pub fn top_events(&self, buf: &[u8]) -> Vec<(u32, Ev)> {
        let byte = |p: u32| buf.get(p as usize).copied().unwrap_or(0);
        let walk = |c: usize| -> Vec<(u32, Ev)> {
            let ch = self.chunks[c];
            let (first, end) = (ch.first as usize, (ch.first + ch.len) as usize);
            let mut out = Vec::new();
            let mut d = ch.depth as i64;
            let mut prev = if first > 0 { byte(self.pos[first - 1]) } else { 0 };
            let mut e = first;
            while e < end {
                let c = byte(self.pos[e]);
                match c {
                    b'{' | b'[' => {
                        if d == 1 {
                            out.push((e as u32, Ev::Open1));
                        }
                        d += 1;
                    }
                    b'}' | b']' => {
                        d -= 1;
                        if d == 1 {
                            out.push((e as u32, Ev::Close1));
                        }
                    }
                    b'"' => {
                        if prev == b'{' || prev == b',' {
                            if d == 1 {
                                out.push((e as u32, Ev::TopKey));
                            } else if d == 2 {
                                out.push((e as u32, Ev::Key2));
                            }
                        }
                        e += 1; // the closing quote (same chunk: chunks never split a string)
                    }
                    _ => {}
                }
                prev = c;
                e += 1;
            }
            out
        };
        let n = self.chunks.len();
        if n == 1 {
            return walk(0);
        }
        crate::util::pool::map(n, walk).into_iter().flatten().collect()
    }
}

/// See [`Index::top_events`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ev {
    TopKey,
    Open1,
    Close1,
    Key2,
}

#[inline]
fn memchr_nl(b: &[u8]) -> Option<usize> {
    b.iter().position(|&c| c == b'\n')
}

// ---------------------------------------------------------------------------------------------
// depth marks: one SIMD pass tracking bracket depth, no index
// ---------------------------------------------------------------------------------------------

/// Quote / backslash / open / close masks of a 64-byte block (portable).
#[inline]
fn qbo_scalar(b: &[u8; 64]) -> (u64, u64, u64, u64) {
    let (mut q, mut bs, mut o, mut c) = (0u64, 0u64, 0u64, 0u64);
    for (i, &x) in b.iter().enumerate() {
        let bit = 1u64 << i;
        match x {
            b'"' => q |= bit,
            b'\\' => bs |= bit,
            b'{' | b'[' => o |= bit,
            b'}' | b']' => c |= bit,
            _ => {}
        }
    }
    (q, bs, o, c)
}

/// One pass over a JSON document tracking the bracket depth outside strings, for callers that
/// need a few keys of a huge document without parsing it (the identifier index): returns the
/// opening-quote positions of every string at depth 1 (the root object's keys and string
/// values) and those of `cands` (sorted opening-quote positions, e.g. from a substring search)
/// that are string starts at depth 2. `None` if a bracket closes below depth 0, the brackets do
/// not balance, or a string is unterminated. No grammar check beyond that (like a byte-level
/// skip).
pub fn depth_marks(buf: &[u8], cands: &[usize]) -> Option<(Vec<usize>, Vec<usize>)> {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") && std::arch::is_x86_feature_detected!("pclmulqdq") {
            // SAFETY: the features were detected at run time
            return unsafe { x86::depth_marks_avx2(buf, cands) };
        }
    }
    depth_marks_with(buf, cands, |blk| qbo_scalar(blk), prefix_xor_portable)
}

/// What the identifier extraction needs from an ISF, from ONE pass (see [`ident_marks`]).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct IdentMarks {
    /// opening quotes of the strings at depth 1
    pub d1: Vec<usize>,
    /// opening quotes of the strings `"version"` / `"linux_banner"` at depth 2
    pub d2: Vec<usize>,
    /// the document contains a backslash
    pub backslash: bool,
}

/// [`depth_marks`] fused with the search for the strings `"version"` and `"linux_banner"` and
/// a backslash check: one read of the document instead of four (the identifier index runs this
/// on every core right after decompressing, where memory bandwidth is the limit).
pub fn ident_marks(buf: &[u8]) -> Option<IdentMarks> {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") && std::arch::is_x86_feature_detected!("pclmulqdq") {
            // SAFETY: the features were detected at run time
            return unsafe { x86::ident_marks_avx2(buf) };
        }
    }
    let mut cands = Vec::new();
    for pat in [&b"\"linux_banner\""[..], b"\"version\""] {
        let mut i = 0;
        while let Some(k) = buf[i..].windows(pat.len()).position(|w| w == pat) {
            cands.push(i + k);
            i += k + 1;
        }
    }
    cands.sort_unstable();
    let (d1, d2) = depth_marks(buf, &cands)?;
    Some(IdentMarks { d1, d2, backslash: buf.contains(&b'\\') })
}

/// The exact test behind the candidate prefilter of [`ident_marks`].
#[inline]
fn ident_cand_at(buf: &[u8], p: usize) -> bool {
    let r = &buf[p..];
    r.starts_with(b"\"version\"") || r.starts_with(b"\"linux_banner\"")
}

/// The depth-marks loop over any mask source.
#[inline(always)]
fn depth_marks_with(buf: &[u8], cands: &[usize], masks: impl Fn(&[u8; 64]) -> (u64, u64, u64, u64), pxor: impl Fn(u64) -> u64) -> Option<(Vec<usize>, Vec<usize>)> {
    let mut d1 = Vec::new();
    let mut d2 = Vec::new();
    let (mut prev_escaped, mut prev_in, mut depth) = (0u64, 0u64, 0i64);
    let mut ci = 0usize;
    let mut blk = [b' '; 64];
    let mut i = 0usize;
    while i < buf.len() {
        let b: &[u8; 64] = if buf.len() - i >= 64 {
            buf[i..i + 64].try_into().unwrap()
        } else {
            let n = buf.len() - i;
            blk[..n].copy_from_slice(&buf[i..]);
            blk[n..].fill(b' ');
            &blk
        };
        let (q, bs, o, c) = masks(b);
        let escaped = if bs == 0 && prev_escaped == 0 {
            0
        } else {
            const EVEN: u64 = 0x5555_5555_5555_5555;
            let bs = bs & !prev_escaped;
            let follows = (bs << 1) | prev_escaped;
            let odd_starts = bs & !EVEN & !follows;
            let (seq_even, ovf) = odd_starts.overflowing_add(bs);
            prev_escaped = ovf as u64;
            (EVEN ^ (seq_even << 1)) & follows
        };
        let qu = q & !escaped;
        let in_string = pxor(qu) ^ prev_in;
        prev_in = ((in_string as i64) >> 63) as u64;
        let outside = !in_string;
        let (op, cl) = (o & outside, c & outside);
        let opening = qu & in_string;
        let ccl = cl.count_ones() as i64;
        // candidates in this block
        let mut cmask = 0u64;
        while ci < cands.len() && cands[ci] < i + 64 {
            if cands[ci] >= i {
                cmask |= 1u64 << (cands[ci] - i);
            }
            ci += 1;
        }
        let low = depth - ccl <= 1;
        if (opening != 0 && (low || cmask & opening != 0)) || depth - ccl < 0 {
            // exact depths inside the block
            let mut ev = op | cl | opening;
            let mut d = depth;
            while ev != 0 {
                let t = ev.trailing_zeros();
                let bit = 1u64 << t;
                if op & bit != 0 {
                    d += 1;
                } else if cl & bit != 0 {
                    d -= 1;
                    if d < 0 {
                        return None;
                    }
                } else {
                    if d == 1 {
                        d1.push(i + t as usize);
                    } else if d == 2 && cmask & bit != 0 {
                        d2.push(i + t as usize);
                    }
                }
                ev &= ev - 1;
            }
        }
        depth += op.count_ones() as i64 - ccl;
        i += 64;
    }
    (depth == 0 && prev_in == 0).then_some((d1, d2))
}

// ---------------------------------------------------------------------------------------------
// the pull interface
// ---------------------------------------------------------------------------------------------

/// Pull-parser operations shared by the byte parser ([`crate::util::json::Parser`]) and the
/// index walker ([`Walker`]). Consumers written against it run on either.
pub trait Pull<'a> {
    /// Iterate an object's members; `f` must consume each value.
    fn object<F>(&mut self, f: F) -> Result<()>
    where
        F: FnMut(&mut Self, Cow<'a, str>) -> Result<()>;
    fn str(&mut self) -> Result<Cow<'a, str>>;
    fn int(&mut self) -> Result<i128>;
    fn bool(&mut self) -> Result<bool>;
    fn skip(&mut self) -> Result<()>;
    fn value(&mut self) -> Result<Json<'a>>;
    fn peek_kind(&mut self) -> Result<Kind>;
}

impl<'a> Pull<'a> for super::json::Parser<'a> {
    #[inline(always)]
    fn object<F>(&mut self, f: F) -> Result<()>
    where
        F: FnMut(&mut Self, Cow<'a, str>) -> Result<()>,
    {
        super::json::Parser::object(self, f)
    }
    #[inline(always)]
    fn str(&mut self) -> Result<Cow<'a, str>> {
        super::json::Parser::str(self)
    }
    #[inline(always)]
    fn int(&mut self) -> Result<i128> {
        super::json::Parser::int(self)
    }
    #[inline(always)]
    fn bool(&mut self) -> Result<bool> {
        super::json::Parser::bool(self)
    }
    #[inline(always)]
    fn skip(&mut self) -> Result<()> {
        super::json::Parser::skip(self)
    }
    #[inline(always)]
    fn value(&mut self) -> Result<Json<'a>> {
        super::json::Parser::value(self)
    }
    #[inline(always)]
    fn peek_kind(&mut self) -> Result<Kind> {
        super::json::Parser::peek_kind(self)
    }
}

// ---------------------------------------------------------------------------------------------
// stage 2
// ---------------------------------------------------------------------------------------------

/// Cursor over an [`Index`]. Cheap to create at any entry (parallel walks of ranges).
#[derive(Clone)]
pub struct Walker<'d, 'a> {
    buf: &'a [u8],
    pos: &'d [u32],
    esc: &'d [u32],
    i: usize,
    utf8: bool,
    depth: u32,
}

/// Bytes that may directly follow a scalar (whitespace, structural, quote) or end the input.
#[inline(always)]
fn is_delim(c: Option<&u8>) -> bool {
    match c {
        None => true,
        Some(&c) => CLASS[c as usize] & (C_WS | C_OP | C_QUOTE) != 0,
    }
}

impl<'d, 'a> Walker<'d, 'a> {
    /// Current entry index.
    #[inline(always)]
    pub fn entry(&self) -> usize {
        self.i
    }
    /// Move to entry `i`.
    #[inline(always)]
    pub fn seek(&mut self, i: usize) {
        self.i = i;
    }
    /// Byte position of entry `i` (`buf.len()` past the end).
    #[inline(always)]
    pub fn pos_of(&self, i: usize) -> usize {
        match self.pos.get(i) {
            Some(&p) => p as usize,
            None => self.buf.len(),
        }
    }
    /// The byte at entry `i` (0 past the end).
    #[inline(always)]
    pub fn ch(&self, i: usize) -> u8 {
        match self.pos.get(i) {
            Some(&p) => self.buf.get(p as usize).copied().unwrap_or(0),
            None => 0,
        }
    }

    #[cold]
    #[inline(never)]
    fn err(&self, what: &str) -> Error {
        Error::Msg(format!("JSON parse error at byte {}: {what}", self.pos_of(self.i)))
    }

    /// The string whose opening quote is entry `i` (closing quote = entry `i + 1`).
    #[inline(always)]
    pub fn string_at(&self, i: usize) -> Result<Cow<'a, str>> {
        let (Some(&o), Some(&c)) = (self.pos.get(i), self.pos.get(i + 1)) else { return Err(self.err("unterminated string")) };
        let (o, c) = (o as usize + 1, c as usize);
        if c < o || self.buf.get(c) != Some(&b'"') {
            return Err(self.err("unterminated string"));
        }
        let s = &self.buf[o..c];
        if !self.esc.is_empty() {
            let k = self.esc.partition_point(|&e| (e as usize) < o);
            if self.esc.get(k).is_some_and(|&e| (e as usize) < c) {
                return unescape(s).map(Cow::Owned).map_err(|e| self.err(e));
            }
        }
        if self.utf8 {
            // SAFETY: the whole buffer is valid UTF-8 and `s` is delimited by ASCII quotes
            Ok(Cow::Borrowed(unsafe { std::str::from_utf8_unchecked(s) }))
        } else {
            Ok(match std::str::from_utf8(s) {
                Ok(s) => Cow::Borrowed(s),
                Err(_) => Cow::Owned(String::from_utf8_lossy(s).into_owned()),
            })
        }
    }

    /// Parse the scalar number at the current entry.
    #[inline]
    fn number(&mut self) -> Result<Json<'static>> {
        let start = self.pos_of(self.i);
        let buf = self.buf;
        let mut i = start;
        let neg = buf.get(i) == Some(&b'-');
        if neg {
            i += 1;
        }
        let dstart = i;
        let mut v64: u64 = 0;
        while i < buf.len() && i - dstart < 19 && buf[i].is_ascii_digit() {
            v64 = v64 * 10 + (buf[i] - b'0') as u64;
            i += 1;
        }
        let mut v: u128 = v64 as u128;
        let mut overflow = false;
        while i < buf.len() && buf[i].is_ascii_digit() {
            match v.checked_mul(10).and_then(|x| x.checked_add((buf[i] - b'0') as u128)) {
                Some(x) => v = x,
                None => overflow = true,
            }
            i += 1;
        }
        if i == dstart {
            return Err(self.err("invalid number"));
        }
        let is_float = i < buf.len() && matches!(buf[i], b'.' | b'e' | b'E');
        if !is_float && !overflow && v <= i128::MAX as u128 {
            if !is_delim(buf.get(i)) {
                return Err(self.err("invalid number"));
            }
            self.i += 1;
            let v = v as i128;
            return Ok(Json::Int(if neg { -v } else { v }));
        }
        while i < buf.len() && matches!(buf[i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
            i += 1;
        }
        if !is_delim(buf.get(i)) {
            return Err(self.err("invalid number"));
        }
        let s = std::str::from_utf8(&buf[start..i]).map_err(|_| self.err("invalid number"))?;
        let f: f64 = s.parse().map_err(|_| self.err("invalid number"))?;
        self.i += 1;
        Ok(Json::Float(f))
    }

    /// `true` / `false` / `null` at the current entry.
    #[inline]
    fn literal(&mut self, lit: &[u8]) -> bool {
        let p = self.pos_of(self.i);
        if self.buf.get(p..p + lit.len()) == Some(lit) && is_delim(self.buf.get(p + lit.len())) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    /// Skip a string / array / object / scalar at the current entry.
    fn skip_value(&mut self) -> Result<()> {
        match self.ch(self.i) {
            b'"' => {
                if self.ch(self.i + 1) != b'"' {
                    return Err(self.err("unterminated string"));
                }
                self.i += 2;
                Ok(())
            }
            b'{' | b'[' => {
                // bracket matching over the index (the bracket kinds must pair up)
                let mut stack: u64 = 0; // bit per level: 1 = '{'
                let mut deep: Vec<bool> = Vec::new();
                let mut depth = 0usize;
                let mut i = self.i;
                loop {
                    let c = self.ch(i);
                    match c {
                        b'{' | b'[' => {
                            if depth < 64 {
                                stack = (stack << 1) | (c == b'{') as u64;
                            } else {
                                deep.push(c == b'{');
                            }
                            depth += 1;
                            i += 1;
                        }
                        b'}' | b']' => {
                            if depth == 0 {
                                return Err(self.err("unbalanced brackets"));
                            }
                            let was_obj = if depth > 64 {
                                deep.pop().unwrap_or(false)
                            } else {
                                let b = stack & 1 != 0;
                                stack >>= 1;
                                b
                            };
                            if was_obj != (c == b'}') {
                                self.i = i;
                                return Err(self.err("mismatched brackets"));
                            }
                            depth -= 1;
                            i += 1;
                            if depth == 0 {
                                self.i = i;
                                return Ok(());
                            }
                        }
                        b'"' => i += 2,
                        0 if i >= self.pos.len() => {
                            self.i = i;
                            return Err(self.err("unterminated structure"));
                        }
                        _ => i += 1,
                    }
                }
            }
            b't' => self.literal(b"true").then_some(()).ok_or_else(|| self.err("expected boolean")),
            b'f' => self.literal(b"false").then_some(()).ok_or_else(|| self.err("expected boolean")),
            b'n' => self.literal(b"null").then_some(()).ok_or_else(|| self.err("expected null")),
            _ => self.number().map(|_| ()),
        }
    }

    /// Skip the rest of an object whose members are being iterated (cursor on a member's value):
    /// used by consumers that stop early.
    pub fn at_end(&self) -> bool {
        self.i >= self.pos.len()
    }
}

impl<'d, 'a> Pull<'a> for Walker<'d, 'a> {
    #[inline(always)]
    fn object<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(&mut Self, Cow<'a, str>) -> Result<()>,
    {
        if self.ch(self.i) != b'{' {
            return Err(self.err("expected '{'"));
        }
        self.i += 1;
        if self.ch(self.i) == b'}' {
            self.i += 1;
            return Ok(());
        }
        loop {
            if self.ch(self.i) != b'"' || self.ch(self.i + 2) != b':' {
                return Err(self.err("expected object key"));
            }
            let k = self.string_at(self.i)?;
            self.i += 3;
            f(self, k)?;
            match self.ch(self.i) {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    #[inline(always)]
    fn str(&mut self) -> Result<Cow<'a, str>> {
        if self.ch(self.i) != b'"' {
            return Err(self.err("expected string"));
        }
        let s = self.string_at(self.i)?;
        self.i += 2;
        Ok(s)
    }

    #[inline(always)]
    fn int(&mut self) -> Result<i128> {
        match self.ch(self.i) {
            b'-' | b'0'..=b'9' => match self.number()? {
                Json::Int(i) => Ok(i),
                _ => Err(self.err("expected integer")),
            },
            _ => Err(self.err("invalid number")),
        }
    }

    fn bool(&mut self) -> Result<bool> {
        if self.literal(b"true") {
            Ok(true)
        } else if self.literal(b"false") {
            Ok(false)
        } else {
            Err(self.err("expected boolean"))
        }
    }

    #[inline(always)]
    fn skip(&mut self) -> Result<()> {
        self.skip_value()
    }

    fn value(&mut self) -> Result<Json<'a>> {
        Ok(match self.peek_kind()? {
            Kind::Null => {
                if !self.literal(b"null") {
                    return Err(self.err("expected null"));
                }
                Json::Null
            }
            Kind::Bool => Json::Bool(self.bool()?),
            Kind::Number => self.number()?,
            Kind::Str => Json::Str(self.str()?),
            Kind::Arr => {
                self.depth += 1;
                if self.depth > 1000 {
                    return Err(self.err("nesting too deep"));
                }
                self.i += 1;
                let mut v = Vec::new();
                if self.ch(self.i) == b']' {
                    self.i += 1;
                } else {
                    loop {
                        v.push(self.value()?);
                        match self.ch(self.i) {
                            b',' => self.i += 1,
                            b']' => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err(self.err("expected ',' or ']'")),
                        }
                    }
                }
                self.depth -= 1;
                Json::Arr(v)
            }
            Kind::Obj => {
                self.depth += 1;
                if self.depth > 1000 {
                    return Err(self.err("nesting too deep"));
                }
                let mut v = Vec::new();
                self.object(|p, k| {
                    let val = p.value()?;
                    v.push((k, val));
                    Ok(())
                })?;
                dict_dedupe(&mut v, |e| &e.0);
                self.depth -= 1;
                Json::Obj(v)
            }
        })
    }

    #[inline(always)]
    fn peek_kind(&mut self) -> Result<Kind> {
        Ok(match self.ch(self.i) {
            b'n' => Kind::Null,
            b't' | b'f' => Kind::Bool,
            b'"' => Kind::Str,
            b'[' => Kind::Arr,
            b'{' => Kind::Obj,
            b'-' | b'0'..=b'9' => Kind::Number,
            _ => return Err(self.err(if self.i >= self.pos.len() { "unexpected end of input" } else { "unexpected character" })),
        })
    }
}

/// Decode a JSON string body with escapes (same results as `json::Parser::str`).
fn unescape(s: &[u8]) -> std::result::Result<String, &'static str> {
    let hex4 = |at: usize| -> std::result::Result<u32, &'static str> {
        let h = s.get(at..at + 4).ok_or("bad \\u escape")?;
        let mut v = 0u32;
        for &c in h {
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err("bad \\u escape"),
            };
            v = v * 16 + d as u32;
        }
        Ok(v)
    };
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        let e = *s.get(i + 1).ok_or("bad escape")?;
        i += 2;
        match e {
            b'"' => out.push(b'"'),
            b'\\' => out.push(b'\\'),
            b'/' => out.push(b'/'),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'u' => {
                let cp = hex4(i)?;
                i += 4;
                let ch = if (0xD800..0xDC00).contains(&cp) {
                    if s.get(i) == Some(&b'\\') && s.get(i + 1) == Some(&b'u') {
                        let lo = hex4(i + 2)?;
                        if (0xDC00..0xE000).contains(&lo) {
                            i += 6;
                            char::from_u32(0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    char::from_u32(cp)
                };
                let ch = ch.unwrap_or('\u{FFFD}');
                let mut tmp = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
            }
            _ => return Err("bad escape"),
        }
    }
    Ok(match String::from_utf8(out) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::json::Parser;

    fn dom_both(doc: &[u8]) -> (Result<Json<'_>>, Result<Json<'static>>) {
        let old = Json::parse(doc);
        let new = (|| {
            let idx = Index::build(doc)?;
            let mut w = idx.walker(doc);
            let v = w.value()?.into_owned();
            if !w.at_end() {
                return Err(Error::msg("trailing data"));
            }
            Ok(v)
        })();
        (old, new)
    }

    #[test]
    fn stage1_positions() {
        let doc = br#"{"a": [1, true, "x\"y"], "b\\": {"c": null}}"#;
        let idx = Index::build(doc).unwrap();
        let chars: String = idx.pos.iter().map(|&p| doc[p as usize] as char).collect();
        assert_eq!(chars, r#"{"":[1,t,""],"":{"":n}}"#);
        assert_eq!(idx.esc.len(), 3);
        assert!(Index::build(b"{\"a\": \"x\ny\"}").is_err());
        assert!(Index::build(b"{\"a\": \"xy}").is_err());
    }

    /// The SIMD path and the portable path produce identical indexes, for every alignment and
    /// many random documents with escapes, long strings and backslash runs across blocks.
    #[test]
    fn simd_equals_portable() {
        let mut x: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let alphabet: &[u8] = b"{}[]:, \n\t\"\\\\\\aZ09-.eE+tfnul\x01\xc3\xa9";
        for round in 0..3000 {
            let len = (next() % 400) as usize;
            let doc: Vec<u8> = (0..len).map(|_| alphabet[(next() % alphabet.len() as u64) as usize]).collect();
            let off = round % 7;
            let mut padded = vec![b' '; off];
            padded.extend_from_slice(&doc);
            let d = &padded[off..];
            let (mut a, mut ea) = (Vec::new(), Vec::new());
            let (mut b, mut eb) = (Vec::new(), Vec::new());
            let sa = index_range(d, 0, d.len(), &mut a, &mut ea);
            let sb = index_range_portable(d, 0, d.len(), &mut b, &mut eb);
            assert_eq!(a, b, "round {round}");
            assert_eq!(ea, eb);
            assert_eq!((sa.prev_in_string, sa.depth, sa.bad), (sb.prev_in_string, sb.depth, sb.bad));
        }
    }

    #[test]
    fn dom_matches_byte_parser() {
        let u = |h: &str| format!("{}{}{}", '\\', 'u', h);
        let docs = [
            format!(r#" {{"a": [1, -2, 3.5, true, null, "x\"y{}{}{}"], "b": {{"c": 18446744073709551615}}}} "#, u("00e9"), u("d83d"), u("de00")),
            r#"{"k": 1, "k": 2, "z": {"q": [[], {}, [1e5, -0.25]]}}"#.to_string(),
            r#"[1, 2, 170141183460469231731687303715884105728, -170141183460469231731687303715884105727]"#.to_string(),
            "\"just a string\"".to_string(),
            "  42  ".to_string(),
        ];
        for d in &docs {
            let (old, new) = dom_both(d.as_bytes());
            assert_eq!(old.unwrap().into_owned(), new.unwrap(), "{d}");
        }
    }

    #[test]
    fn errors_and_garbage() {
        for bad in [&b"{"[..], b"[1,]", b"\"abc", b"{} x", b"{\"a\" 1}", b"{\"a\":1 2}", b"[tru]", b"[1x]", b"{\"a\":}", b"]", b"{\"a\":1,}"] {
            assert!(dom_both(bad).1.is_err(), "{}", String::from_utf8_lossy(bad));
        }
        // no panic on random mutations; valid prefixes agree with the byte parser
        let doc = br#"{"a": {"b": [1, 2.5e3, -7, "xA\n", true, false, null, {"c": "d\\\"e"}]}, "f": 18446744073709551616}"#;
        let mut x: u64 = 0x9e3779b97f4a7c15;
        for i in 0..doc.len() {
            let _ = dom_both(&doc[..i]);
            for _ in 0..8 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let mut d = doc.to_vec();
                d[i] = x as u8;
                let (old, new) = dom_both(&d);
                if let (Ok(o), Ok(n)) = (&old, &new) {
                    assert_eq!(&o.clone().into_owned(), n);
                }
            }
        }
        let deep = "[".repeat(5000);
        assert!(dom_both(deep.as_bytes()).1.is_err());
    }

    #[test]
    fn pull_skip() {
        let data = br#"{"skipme": {"x": [1, {"y": "}]"}], "z": "a\\\"b"}, "keep": 42, "e": {}, "f": []}"#;
        let idx = Index::build(data).unwrap();
        let mut w = idx.walker(data);
        let mut keep = 0;
        w.object(|p, k| {
            match k.as_ref() {
                "keep" => keep = p.int()?,
                _ => p.skip()?,
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(keep, 42);
        let mut p = Parser::new(data);
        let mut keep2 = 0;
        Pull::object(&mut p, |p, k| {
            match k.as_ref() {
                "keep" => keep2 = Pull::int(p)?,
                _ => Pull::skip(p)?,
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(keep2, 42);
    }

    /// xz decode of an ISF into a fresh buffer vs a pre-faulted one (page-fault share).
    /// `RSVOL_BENCH_XZ=file.json.xz cargo test --release xz_fault_share -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn xz_fault_share() {
        let raw = std::fs::read(std::env::var("RSVOL_BENCH_XZ").unwrap()).unwrap();
        let mut reuse = Vec::new();
        crate::codecs::xz::decompress_reuse(&raw, &mut reuse, false).unwrap();
        for _ in 0..3 {
            let t = std::time::Instant::now();
            let v = crate::codecs::xz::decompress(&raw).unwrap();
            let fresh = t.elapsed();
            drop(v);
            let t = std::time::Instant::now();
            crate::codecs::xz::decompress_reuse(&raw, &mut reuse, false).unwrap();
            let warm = t.elapsed();
            println!("fresh buffer {:.2} ms, pre-faulted {:.2} ms", fresh.as_secs_f64() * 1e3, warm.as_secs_f64() * 1e3);
        }
    }

    /// The fused one-pass identifier marks equal the portable composition (substring search +
    /// depth marks), for every alignment and random documents with escapes and near-misses.
    #[test]
    fn ident_marks_equal_portable() {
        let mut x: u64 = 0x0123_4567_89ab_cdef;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let parts: &[&[u8]] = &[b"{", b"}", b"[", b"]", b",", b":", b" ", b"\n", b"\"version\"", b"\"linux_banner\"", b"\"versio\"", b"\"x\"", b"\"linux_banne\"", b"\"a\\\"b\"", b"\\", b"\"version\": ", b"{\"symbols\": {", b"}}", b"\"l\"", b"\"v\"", b"12"];
        for round in 0..3000 {
            let mut doc = Vec::new();
            for _ in 0..(next() % 60) {
                doc.extend_from_slice(parts[(next() % parts.len() as u64) as usize]);
            }
            let off = round % 9;
            let mut padded = vec![b'x'; off];
            padded.extend_from_slice(&doc);
            let d = &padded[off..];
            let fused = ident_marks(d);
            let mut cands = Vec::new();
            for pat in [&b"\"linux_banner\""[..], b"\"version\""] {
                let mut i = 0;
                while let Some(k) = d.get(i..).and_then(|r| r.windows(pat.len()).position(|w| w == pat)) {
                    cands.push(i + k);
                    i += k + 1;
                }
            }
            cands.sort_unstable();
            let portable = depth_marks_with(d, &cands, |b| qbo_scalar(b), prefix_xor_portable).map(|(d1, d2)| IdentMarks { d1, d2, backslash: d.contains(&b'\\') });
            assert_eq!(fused, portable, "round {round}: {}", String::from_utf8_lossy(d));
        }
    }

    /// Cost of one `par_for` round (thread spawn + join) on this machine.
    #[test]
    #[ignore]
    fn spawn_round_cost() {
        for n in [1usize, 4, 20] {
            let t = std::time::Instant::now();
            for _ in 0..50 {
                crate::util::par::par_for(n, |i| {
                    std::hint::black_box(i);
                });
            }
            println!("par_for({n}) round: {:.1} us", t.elapsed().as_secs_f64() * 1e6 / 50.0);
        }
    }

    /// Parallel stage 1 (newline-aligned chunks) equals the single-chunk index.
    #[test]
    fn parallel_stage1_equals_serial() {
        let mut doc = String::from("{\n");
        for i in 0..60000 {
            doc.push_str(&format!("  \"k{i}\": {{\n    \"offset\": {i},\n    \"s\": \"a\\\"b\\\\\",\n    \"t\": [true, null, -1.5e3]\n  }},\n"));
        }
        doc.push_str("  \"end\": 0\n}\n");
        let d = doc.as_bytes();
        assert!(d.len() > PAR_MIN);
        let a = Index::build_with(d, false).unwrap();
        let b = Index::build_with(d, true).unwrap();
        assert!(b.chunks.len() > 1 || crate::util::par::threads() == 1);
        assert_eq!(a.pos, b.pos);
        assert_eq!(a.esc, b.esc);
        // chunk depths: every chunk starts at depth 1 (inside the top object) except the first
        for c in &b.chunks[1..] {
            assert!(c.depth >= 1, "{c:?}");
        }
        let mut w = b.walker(d);
        let v = w.value().unwrap();
        assert_eq!(v, Json::parse(d).unwrap());
    }
}
