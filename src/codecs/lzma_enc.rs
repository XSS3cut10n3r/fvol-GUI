//! LZMA / LZMA2 encoder (the compressor behind [`super::xz_enc`]).
//!
//! [`Lzma2Encoder::encode_block`] compresses one buffer into a complete raw LZMA2 stream
//! (dictionary reset at the start, 0x00 end marker), with lc=3 lp=0 pb=2 (xz's defaults).
//!
//! * Range coder and probability models exactly as in the LZMA SDK / liblzma (the layout
//!   mirrors [`super::lzma`]'s decoder): literals (plain and "matched" against the byte at
//!   rep0), matches (length coder, 6-bit distance slot tree, reverse-tree / direct / align
//!   distance footers), the four rep distances and short reps, 12-state machine.
//! * Match finder: hash chains over 4-byte hashes (depth-limited, "nice" length early exit)
//!   plus direct 2-byte and hashed 3-byte heads for short matches; the whole block is the
//!   dictionary.
//! * Parser: liblzma-style "fast" mode — the longest rep match vs the longest match (with a
//!   preference for much closer shorter matches), one-position lookahead (lazy evaluation).
//!   Runs and long repeats (a maximal 273-byte match) are extended at the same distance and
//!   emitted as rep0 matches without hashing their interior.
//! * LZMA2 chunking: chunks end before 2 MiB uncompressed / 64 KiB compressed; a chunk that
//!   does not shrink is stored uncompressed (followed by a state reset).

use super::crc::crc64;

// ---------------------------------------------------------------------------------------
// Model layout (same as the decoder)
// ---------------------------------------------------------------------------------------

const NUM_STATES: usize = 12;
const POS_STATES_MAX: usize = 16;
const IS_MATCH: usize = 0;
const IS_REP: usize = IS_MATCH + NUM_STATES * POS_STATES_MAX;
const IS_REP0: usize = IS_REP + NUM_STATES;
const IS_REP1: usize = IS_REP0 + NUM_STATES;
const IS_REP2: usize = IS_REP1 + NUM_STATES;
const IS_REP0_LONG: usize = IS_REP2 + NUM_STATES;
const DIST_SLOT: usize = IS_REP0_LONG + NUM_STATES * POS_STATES_MAX;
const DIST_SPECIAL: usize = DIST_SLOT + 4 * 64;
const ALIGN: usize = DIST_SPECIAL + 114;
const LEN_CODER: usize = ALIGN + 16;
const LEN_PROBS: usize = 2 + 2 * POS_STATES_MAX * 8 + 256;
const REP_LEN_CODER: usize = LEN_CODER + LEN_PROBS;
const LITERAL: usize = REP_LEN_CODER + LEN_PROBS;
const LEN_CHOICE: usize = 0;
const LEN_CHOICE2: usize = 1;
const LEN_LOW: usize = 2;
const LEN_MID: usize = LEN_LOW + POS_STATES_MAX * 8;
const LEN_HIGH: usize = LEN_MID + POS_STATES_MAX * 8;
const PROB_INIT: u16 = 1024;
const TOP: u32 = 1 << 24;

/// lc=3, lp=0, pb=2.
const LC: usize = 3;
const PB_MASK: usize = 3;
/// The LZMA properties byte `(pb * 5 + lp) * 9 + lc`.
pub(crate) const PROPS_BYTE: u8 = 0x5D;

const MATCH_LEN_MIN: usize = 2;
const MATCH_LEN_MAX: usize = 273;
const REPS: usize = 4;

/// LZMA2 chunk limits.
const CHUNK_UNCOMPRESSED_MAX: usize = 1 << 21;
const CHUNK_COMPRESSED_MAX: usize = 1 << 16;
/// Upper bound of the range coder bytes one symbol (plus the final flush) can add.
const SYMBOL_MARGIN: usize = 64;
/// Literals in a row after which the parser only searches every 4th position.
const MISS_LIMIT: usize = 64;

// ---------------------------------------------------------------------------------------
// Range encoder
// ---------------------------------------------------------------------------------------

struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    out: Vec<u8>,
}

impl RangeEncoder {
    fn new(mut out: Vec<u8>) -> RangeEncoder {
        out.clear();
        RangeEncoder { low: 0, range: 0xFFFF_FFFF, cache: 0, cache_size: 1, out }
    }

    #[inline(always)]
    fn shift_low(&mut self) {
        if (self.low as u32) < 0xFF00_0000 || (self.low >> 32) != 0 {
            let carry = (self.low >> 32) as u8;
            let mut temp = self.cache;
            loop {
                self.out.push(temp.wrapping_add(carry));
                temp = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = (self.low >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low & 0x00FF_FFFF) << 8;
    }

    #[inline(always)]
    fn bit(&mut self, p: &mut u16, bit: u32) {
        let pr = *p as u32;
        let bound = (self.range >> 11) * pr;
        if bit == 0 {
            self.range = bound;
            *p = (pr + ((2048 - pr) >> 5)) as u16;
        } else {
            self.low += bound as u64;
            self.range -= bound;
            *p = (pr - (pr >> 5)) as u16;
        }
        while self.range < TOP {
            self.range <<= 8;
            self.shift_low();
        }
    }

    /// `n` bits of `v`, most significant first, with probability 1/2.
    fn direct(&mut self, v: u32, n: u32) {
        for i in (0..n).rev() {
            self.range >>= 1;
            if (v >> i) & 1 != 0 {
                self.low += self.range as u64;
            }
            if self.range < TOP {
                self.range <<= 8;
                self.shift_low();
            }
        }
    }

    /// Bytes the stream will have after [`RangeEncoder::flush`] (upper bound).
    #[inline(always)]
    fn pending(&self) -> usize {
        self.out.len() + self.cache_size as usize + 5
    }

    fn flush(&mut self) {
        for _ in 0..5 {
            self.shift_low();
        }
    }
}

// ---------------------------------------------------------------------------------------
// Match finder (hash chains over the whole block)
// ---------------------------------------------------------------------------------------

const EMPTY: u32 = u32::MAX;
const HASH2_BITS: u32 = 16;
const HASH3_BITS: u32 = 16;
/// The hash chains link positions within the last CHAIN_WINDOW bytes (a ring buffer: 4 MB
/// whatever the block size); older candidates are still found through the hash heads.
const CHAIN_WINDOW: usize = 1 << 20;

/// A match: length and distance - 1 (LZMA's convention).
#[derive(Clone, Copy, Default, Debug)]
struct Match {
    len: u32,
    dist: u32,
}

struct MatchFinder {
    head2: Vec<u32>,
    head3: Vec<u32>,
    head4: Vec<u32>,
    /// chain[p & cmask] = previous position with the same 4-byte hash as p.
    chain: Vec<u32>,
    cmask: usize,
    shift4: u32,
    depth: u32,
    nice: usize,
}

#[inline(always)]
fn ld32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}

/// Common prefix length of `b[a..]` and `b[p..]` from `i`, capped at `max` (a < p,
/// p + max <= b.len()).
#[inline(always)]
fn extend(b: &[u8], a: usize, p: usize, mut i: usize, max: usize) -> usize {
    while i + 8 <= max {
        let x = u64::from_le_bytes(b[a + i..a + i + 8].try_into().unwrap())
            ^ u64::from_le_bytes(b[p + i..p + i + 8].try_into().unwrap());
        if x != 0 {
            return i + (x.trailing_zeros() >> 3) as usize;
        }
        i += 8;
    }
    while i < max && b[a + i] == b[p + i] {
        i += 1;
    }
    i
}

impl MatchFinder {
    fn new() -> MatchFinder {
        MatchFinder {
            head2: Vec::new(),
            head3: Vec::new(),
            head4: Vec::new(),
            chain: Vec::new(),
            cmask: 0,
            shift4: 0,
            depth: 16,
            nice: 64,
        }
    }

    fn reset(&mut self, n: usize, depth: u32, nice: usize) {
        let bits4 = ((n.max(1) as u64).next_power_of_two().trailing_zeros()).clamp(12, 18);
        self.shift4 = 32 - bits4;
        for (v, bits) in [(&mut self.head2, HASH2_BITS), (&mut self.head3, HASH3_BITS), (&mut self.head4, bits4)] {
            v.clear();
            v.resize(1 << bits, EMPTY);
        }
        #[allow(unused_mut)]
        let mut window = CHAIN_WINDOW;
        #[cfg(test)]
        if let Some(w) = std::env::var("RSVOL_LZMA_WINDOW").ok().and_then(|v| v.parse::<usize>().ok()) {
            window = w.next_power_of_two();
        }
        let size = n.max(1).next_power_of_two().min(window);
        self.cmask = size - 1;
        self.chain.clear();
        self.chain.resize(size, EMPTY);
        self.depth = depth.max(1);
        self.nice = nice.clamp(MATCH_LEN_MIN + 1, MATCH_LEN_MAX);
    }

    #[inline(always)]
    fn hashes(&self, v: u32) -> (usize, usize, usize) {
        let h2 = (v & 0xFFFF) as usize;
        let h3 = ((v & 0xFF_FFFF).wrapping_mul(0x9E37_79B1) >> (32 - HASH3_BITS)) as usize;
        let h4 = (v.wrapping_mul(0x1E35_A7BD) >> self.shift4) as usize;
        (h2, h3, h4)
    }

    /// Inserts `pos` (needs 4 bytes).
    #[inline(always)]
    fn insert(&mut self, b: &[u8], pos: usize) {
        let (h2, h3, h4) = self.hashes(ld32(b, pos));
        self.head2[h2] = pos as u32;
        self.head3[h3] = pos as u32;
        self.chain[pos & self.cmask] = self.head4[h4];
        self.head4[h4] = pos as u32;
    }

    /// Inserts positions `from..to` (those with fewer than 4 bytes left are skipped).
    fn skip(&mut self, b: &[u8], from: usize, to: usize) {
        for p in from..to.min(b.len().saturating_sub(3)) {
            self.insert(b, p);
        }
    }

    /// Finds matches at `pos` (inserting it) into `out` with strictly increasing lengths;
    /// returns their number.
    fn find(&mut self, b: &[u8], pos: usize, out: &mut [Match; MATCH_LEN_MAX + 1]) -> usize {
        let avail = (b.len() - pos).min(MATCH_LEN_MAX);
        if avail < 4 {
            return 0;
        }
        let cur = ld32(b, pos);
        let (h2, h3, h4) = self.hashes(cur);
        let (c2, c3, mut c) = (self.head2[h2], self.head3[h3], self.head4[h4]);
        self.head2[h2] = pos as u32;
        self.head3[h3] = pos as u32;
        self.chain[pos & self.cmask] = c;
        self.head4[h4] = pos as u32;
        let nice = self.nice.min(avail);
        let mut n = 0;
        let mut best = 1usize;
        let p32 = pos as u32;
        if c2 < p32 && b[c2 as usize] == b[pos] && b[c2 as usize + 1] == b[pos + 1] {
            let len = extend(b, c2 as usize, pos, 2, avail);
            out[n] = Match { len: len as u32, dist: p32 - c2 - 1 };
            n += 1;
            best = len;
            if len >= nice {
                return n;
            }
        }
        if c3 < p32 && c3 != c2 && (ld32(b, c3 as usize) ^ cur) & 0xFF_FFFF == 0 {
            let len = extend(b, c3 as usize, pos, 3, avail);
            if len > best {
                out[n] = Match { len: len as u32, dist: p32 - c3 - 1 };
                n += 1;
                best = len;
                if len >= nice {
                    return n;
                }
            }
        }
        let mut depth = self.depth;
        while c < p32 {
            let cu = c as usize;
            if b[cu + best.min(avail - 1)] == b[pos + best.min(avail - 1)] && ld32(b, cu) == cur {
                let len = extend(b, cu, pos, 4, avail);
                if len > best {
                    out[n] = Match { len: len as u32, dist: p32 - c - 1 };
                    n += 1;
                    best = len;
                    if len >= nice {
                        break;
                    }
                }
            }
            depth -= 1;
            // A candidate beyond the ring may have had its link overwritten: stop there.
            if depth == 0 || pos - cu > self.cmask {
                break;
            }
            c = self.chain[cu & self.cmask];
        }
        n
    }
}

// ---------------------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------------------

/// Parser / match finder settings for an xz preset (0..=9).
#[derive(Clone, Copy, Debug)]
pub(crate) struct LzmaParams {
    pub depth: u32,
    pub nice: usize,
}

impl LzmaParams {
    /// Settings for `preset` (0 = fastest .. 9; python's default is 6).
    pub(crate) fn preset(preset: u32) -> LzmaParams {
        let (depth, nice) = match preset {
            0 => (4, 32),
            1 => (8, 48),
            2 => (12, 64),
            3 => (16, 96),
            4 => (24, 128),
            5 => (32, 192),
            6 => (48, 273),
            7 => (64, 273),
            8 => (128, 273),
            _ => (256, 273),
        };
        #[cfg(test)]
        if let Ok(s) = std::env::var("RSVOL_LZMA_PARAMS") {
            // Benchmark-only override: "depth,nice".
            let v: Vec<usize> = s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
            if v.len() == 2 {
                return LzmaParams { depth: v[0] as u32, nice: v[1] };
            }
        }
        LzmaParams { depth, nice }
    }
}

/// Reusable LZMA2 block compressor (models, match finder, buffers): one per thread.
pub(crate) struct Lzma2Encoder {
    probs: Vec<u16>,
    state: usize,
    reps: [u32; REPS],
    mf: MatchFinder,
    params: LzmaParams,
    matches: Box<[Match; MATCH_LEN_MAX + 1]>,
    next_matches: Box<[Match; MATCH_LEN_MAX + 1]>,
    chunk_buf: Vec<u8>,
}

#[inline(always)]
fn change_pair(small_dist: u32, big_dist: u32) -> bool {
    (big_dist >> 7) > small_dist
}

#[inline(always)]
fn dist_slot(d: u32) -> u32 {
    if d < 4 {
        d
    } else {
        let n = 31 - d.leading_zeros();
        (n << 1) | ((d >> (n - 1)) & 1)
    }
}

/// A parse decision: a literal, a rep match (index 0..4), or a normal match.
#[derive(Clone, Copy, Debug)]
enum Op {
    Literal,
    Rep(usize, usize),
    Match(usize, u32),
}

impl Lzma2Encoder {
    pub(crate) fn new(params: LzmaParams) -> Lzma2Encoder {
        Lzma2Encoder {
            probs: vec![PROB_INIT; LITERAL + (0x300 << LC)],
            state: 0,
            reps: [0; REPS],
            mf: MatchFinder::new(),
            params,
            matches: Box::new([Match::default(); MATCH_LEN_MAX + 1]),
            next_matches: Box::new([Match::default(); MATCH_LEN_MAX + 1]),
            chunk_buf: Vec::new(),
        }
    }

    fn reset_state(&mut self) {
        self.probs.fill(PROB_INIT);
        self.state = 0;
        self.reps = [0; REPS];
    }

    // ---- symbol encoders ----

    #[inline(always)]
    fn tree(&mut self, rc: &mut RangeEncoder, base: usize, nbits: u32, v: u32) {
        let mut m = 1usize;
        for i in (0..nbits).rev() {
            let bit = (v >> i) & 1;
            rc.bit(&mut self.probs[base + m], bit);
            m = 2 * m + bit as usize;
        }
    }

    #[inline(always)]
    fn rev_tree(&mut self, rc: &mut RangeEncoder, base: usize, nbits: u32, v: u32) {
        let mut m = 1usize;
        for i in 0..nbits {
            let bit = (v >> i) & 1;
            rc.bit(&mut self.probs[base + m], bit);
            m = 2 * m + bit as usize;
        }
    }

    fn len(&mut self, rc: &mut RangeEncoder, coder: usize, len: usize, ps: usize) {
        let l = (len - MATCH_LEN_MIN) as u32;
        if l < 8 {
            rc.bit(&mut self.probs[coder + LEN_CHOICE], 0);
            self.tree(rc, coder + LEN_LOW + (ps << 3), 3, l);
        } else if l < 16 {
            rc.bit(&mut self.probs[coder + LEN_CHOICE], 1);
            rc.bit(&mut self.probs[coder + LEN_CHOICE2], 0);
            self.tree(rc, coder + LEN_MID + (ps << 3), 3, l - 8);
        } else {
            rc.bit(&mut self.probs[coder + LEN_CHOICE], 1);
            rc.bit(&mut self.probs[coder + LEN_CHOICE2], 1);
            self.tree(rc, coder + LEN_HIGH, 8, l - 16);
        }
    }

    fn literal(&mut self, rc: &mut RangeEncoder, b: &[u8], pos: usize) {
        let ps = pos & PB_MASK;
        rc.bit(&mut self.probs[IS_MATCH + (self.state << 4) + ps], 0);
        let prev = if pos > 0 { b[pos - 1] as usize } else { 0 };
        let base = LITERAL + 0x300 * (prev >> (8 - LC));
        let sym = b[pos] as u32;
        if self.state < 7 {
            self.tree(rc, base, 8, sym);
        } else {
            let mb = b[pos - self.reps[0] as usize - 1] as u32;
            let mut m = 1usize;
            let mut matching = true;
            for i in (0..8).rev() {
                let bit = (sym >> i) & 1;
                let idx = if matching {
                    let mbit = (mb >> i) & 1;
                    matching = mbit == bit;
                    ((1 + mbit as usize) << 8) + m
                } else {
                    m
                };
                rc.bit(&mut self.probs[base + idx], bit);
                m = 2 * m + bit as usize;
            }
        }
        self.state = if self.state < 4 {
            0
        } else if self.state < 10 {
            self.state - 3
        } else {
            self.state - 6
        };
    }

    fn short_rep(&mut self, rc: &mut RangeEncoder, pos: usize) {
        let ps = pos & PB_MASK;
        let s = self.state;
        rc.bit(&mut self.probs[IS_MATCH + (s << 4) + ps], 1);
        rc.bit(&mut self.probs[IS_REP + s], 1);
        rc.bit(&mut self.probs[IS_REP0 + s], 0);
        rc.bit(&mut self.probs[IS_REP0_LONG + (s << 4) + ps], 0);
        self.state = if s < 7 { 9 } else { 11 };
    }

    fn rep_match(&mut self, rc: &mut RangeEncoder, pos: usize, rep: usize, len: usize) {
        let ps = pos & PB_MASK;
        let s = self.state;
        rc.bit(&mut self.probs[IS_MATCH + (s << 4) + ps], 1);
        rc.bit(&mut self.probs[IS_REP + s], 1);
        if rep == 0 {
            rc.bit(&mut self.probs[IS_REP0 + s], 0);
            rc.bit(&mut self.probs[IS_REP0_LONG + (s << 4) + ps], 1);
        } else {
            rc.bit(&mut self.probs[IS_REP0 + s], 1);
            if rep == 1 {
                rc.bit(&mut self.probs[IS_REP1 + s], 0);
            } else {
                rc.bit(&mut self.probs[IS_REP1 + s], 1);
                rc.bit(&mut self.probs[IS_REP2 + s], (rep - 2) as u32);
            }
            let d = self.reps[rep];
            for i in (1..=rep).rev() {
                self.reps[i] = self.reps[i - 1];
            }
            self.reps[0] = d;
        }
        self.len(rc, REP_LEN_CODER, len, ps);
        self.state = if s < 7 { 8 } else { 11 };
    }

    fn normal_match(&mut self, rc: &mut RangeEncoder, pos: usize, dist: u32, len: usize) {
        let ps = pos & PB_MASK;
        let s = self.state;
        rc.bit(&mut self.probs[IS_MATCH + (s << 4) + ps], 1);
        rc.bit(&mut self.probs[IS_REP + s], 0);
        self.len(rc, LEN_CODER, len, ps);
        let len_state = (len - MATCH_LEN_MIN).min(3);
        let slot = dist_slot(dist);
        self.tree(rc, DIST_SLOT + (len_state << 6), 6, slot);
        if slot >= 4 {
            let nbits = (slot >> 1) - 1;
            let base = (2 | (slot & 1)) << nbits;
            let reduced = dist - base;
            if slot < 14 {
                self.rev_tree(rc, DIST_SPECIAL + base as usize - slot as usize - 1, nbits, reduced);
            } else {
                rc.direct(reduced >> 4, nbits - 4);
                self.rev_tree(rc, ALIGN, 4, reduced & 15);
            }
        }
        self.reps = [dist, self.reps[0], self.reps[1], self.reps[2]];
        self.state = if s < 7 { 7 } else { 10 };
    }

    // ---- parser ----

    /// Longest rep match at `pos`: (rep index, length) with length 0 if none.
    #[inline(always)]
    fn best_rep(&self, b: &[u8], pos: usize, avail: usize) -> (usize, usize) {
        let (mut bi, mut bl) = (0, 0);
        for i in 0..REPS {
            let d = self.reps[i] as usize + 1;
            if d > pos {
                continue;
            }
            let s = pos - d;
            if b[s] != b[pos] || b[s + 1] != b[pos + 1] {
                continue;
            }
            let l = extend(b, s, pos, 2, avail);
            if l > bl {
                bi = i;
                bl = l;
            }
        }
        (bi, bl)
    }

    /// Chooses the operation at `pos`. `la` holds the match count of a lookahead search
    /// already done at `pos` (its matches are in `self.matches`), if any; on return it holds
    /// the lookahead done at `pos + 1` (matches in `self.matches`) if this op is a literal.
    /// The flag tells whether `pos + 1` has been inserted into the match finder.
    fn decide(&mut self, b: &[u8], pos: usize, la: &mut Option<usize>) -> (Op, bool) {
        let avail = (b.len() - pos).min(MATCH_LEN_MAX);
        let nice = self.params.nice.min(avail);
        let count = match la.take() {
            Some(c) => c,
            None => self.mf.find(b, pos, &mut self.matches),
        };
        if avail < 2 {
            return (Op::Literal, false);
        }
        let (rep_i, rep_len) = self.best_rep(b, pos, avail);
        if rep_len >= nice {
            return (Op::Rep(rep_i, rep_len), false);
        }
        let (mut main_len, mut main_dist) = (0usize, 0u32);
        if count > 0 {
            let mut k = count - 1;
            main_len = self.matches[k].len as usize;
            main_dist = self.matches[k].dist;
            if main_len >= nice {
                return (Op::Match(main_len, main_dist), false);
            }
            // Prefer a match one shorter at a much smaller distance.
            while k > 0 && main_len == self.matches[k - 1].len as usize + 1 {
                if !change_pair(self.matches[k - 1].dist, main_dist) {
                    break;
                }
                k -= 1;
                main_len = self.matches[k].len as usize;
                main_dist = self.matches[k].dist;
            }
            // Short matches far away cost more than literals.
            if (main_len == 2 && main_dist >= 0x80) || (main_len == 3 && main_dist >= 0x8000) {
                main_len = 0;
            }
        }
        if rep_len >= 2
            && (rep_len + 1 >= main_len
                || (rep_len + 2 >= main_len && main_dist > (1 << 9))
                || (rep_len + 3 >= main_len && main_dist > (1 << 15)))
        {
            return (Op::Rep(rep_i, rep_len), false);
        }
        if main_len < 2 || avail <= 2 {
            return (Op::Literal, false);
        }
        // Lazy evaluation: the matches at pos + 1.
        let nc = self.mf.find(b, pos + 1, &mut self.next_matches);
        if nc > 0 {
            let nm = self.next_matches[nc - 1];
            let (nl, nd) = (nm.len as usize, nm.dist);
            if (nl >= main_len && nd < main_dist)
                || (nl == main_len + 1 && !change_pair(main_dist, nd))
                || nl > main_len + 1
                || (nl + 1 >= main_len && main_len >= 3 && change_pair(nd, main_dist))
            {
                std::mem::swap(&mut self.matches, &mut self.next_matches);
                *la = Some(nc);
                return (Op::Literal, true);
            }
        }
        // A rep match at pos + 1 almost as long: take the literal now.
        let limit = (main_len - 1).max(2);
        let p1 = pos + 1;
        if p1 + limit <= b.len() {
            for i in 0..REPS {
                let d = self.reps[i] as usize + 1;
                if d <= p1 && b[p1 - d..p1 - d + limit] == b[p1..p1 + limit] {
                    std::mem::swap(&mut self.matches, &mut self.next_matches);
                    *la = Some(nc);
                    return (Op::Literal, true);
                }
            }
        }
        (Op::Match(main_len, main_dist), true)
    }

    /// Compresses `data` into a complete raw LZMA2 stream appended to `out` (the whole of
    /// `data` is the dictionary; nothing before it is referenced).
    #[allow(unused_assignments)] // (the end_chunk! macro's last expansion)
    pub(crate) fn encode_block(&mut self, data: &[u8], out: &mut Vec<u8>) {
        let n = data.len();
        self.mf.reset(n, self.params.depth, self.params.nice);
        self.reset_state();
        let mut need_dict_reset = true;
        let mut need_props = true;
        let mut need_state_reset = false;
        let mut rc = RangeEncoder::new(std::mem::take(&mut self.chunk_buf));
        let mut chunk_start = 0usize;
        let mut pos = 0usize;
        let mut la: Option<usize> = None;
        let mut misses = 0usize;

        // Ends the current chunk at `pos` (LZMA or stored).
        macro_rules! end_chunk {
            () => {{
                rc.flush();
                let unpacked = pos - chunk_start;
                let packed = rc.out.len();
                if unpacked > 0 {
                    if packed + 6 < unpacked + 3 * unpacked.div_ceil(1 << 16) && packed <= CHUNK_COMPRESSED_MAX {
                        let reset = if need_dict_reset {
                            3
                        } else if need_props {
                            2
                        } else if need_state_reset {
                            1
                        } else {
                            0
                        };
                        let u = unpacked - 1;
                        let p = packed - 1;
                        out.push(0x80 | (reset << 5) | (u >> 16) as u8);
                        out.extend_from_slice(&[(u >> 8) as u8, u as u8, (p >> 8) as u8, p as u8]);
                        if reset >= 2 {
                            out.push(PROPS_BYTE);
                        }
                        out.extend_from_slice(&rc.out);
                        need_dict_reset = false;
                        need_props = false;
                        need_state_reset = false;
                    } else {
                        // Stored: the decoder resets the LZMA state before the next chunk.
                        for piece in data[chunk_start..pos].chunks(1 << 16) {
                            let s = piece.len() - 1;
                            out.extend_from_slice(&[if need_dict_reset { 1 } else { 2 }, (s >> 8) as u8, s as u8]);
                            out.extend_from_slice(piece);
                            if need_dict_reset {
                                // (control 1 also makes the next LZMA chunk carry properties)
                                need_dict_reset = false;
                                need_props = true;
                            }
                        }
                        need_state_reset = true;
                    }
                }
                rc = RangeEncoder::new(std::mem::take(&mut rc.out));
                chunk_start = pos;
                if need_state_reset || need_props {
                    // The next LZMA chunk starts from fresh models (its control byte
                    // carries a state reset).
                    self.reset_state();
                }
            }};
        }

        while pos < n {
            if pos - chunk_start > CHUNK_UNCOMPRESSED_MAX - MATCH_LEN_MAX
                || rc.pending() + SYMBOL_MARGIN > CHUNK_COMPRESSED_MAX
            {
                end_chunk!();
            }
            // Incompressible stretch: after MISS_LIMIT literals in a row, search (and hash)
            // only every 4th position until something matches again.
            if misses >= MISS_LIMIT && la.is_none() && pos & 3 != 0 {
                self.literal(&mut rc, data, pos);
                pos += 1;
                continue;
            }
            let (op, ahead) = self.decide(data, pos, &mut la);
            // First position not yet inserted into the match finder after this op's start.
            let next_ins = pos + 1 + ahead as usize;
            misses = if matches!(op, Op::Literal) { misses + 1 } else { 0 };
            match op {
                Op::Literal => {
                    // A byte equal to the one at rep0 right after a match: short rep.
                    if self.state >= 7
                        && (self.reps[0] as usize) < pos
                        && data[pos - self.reps[0] as usize - 1] == data[pos]
                    {
                        self.short_rep(&mut rc, pos);
                    } else {
                        self.literal(&mut rc, data, pos);
                    }
                    pos += 1;
                }
                Op::Rep(i, len) => {
                    self.rep_match(&mut rc, pos, i, len);
                    pos = self.after_match(&mut rc, data, pos, len, next_ins, chunk_start);
                }
                Op::Match(len, dist) => {
                    self.normal_match(&mut rc, pos, dist, len);
                    pos = self.after_match(&mut rc, data, pos, len, next_ins, chunk_start);
                }
            }
        }
        end_chunk!();
        out.push(0x00);
        self.chunk_buf = rc.out;
    }

    /// Finishes a match of `len` at `start` (already encoded): inserts the covered positions
    /// from `next_ins` on and returns the next position. After a maximal match, keeps
    /// emitting maximal rep0 matches while the data repeats at that distance (zero runs cost
    /// almost nothing), within the current chunk's limits, hashing only the edges.
    fn after_match(
        &mut self,
        rc: &mut RangeEncoder,
        b: &[u8],
        start: usize,
        len: usize,
        next_ins: usize,
        chunk_start: usize,
    ) -> usize {
        let mut end = start + len;
        if len < MATCH_LEN_MAX {
            self.mf.skip(b, next_ins, end);
            return end;
        }
        let d = self.reps[0] as usize + 1;
        let total = extend(b, start - d, start, MATCH_LEN_MAX, b.len() - start);
        let mut n_more = (total - MATCH_LEN_MAX) / MATCH_LEN_MAX;
        while n_more > 0
            && rc.pending() + SYMBOL_MARGIN <= CHUNK_COMPRESSED_MAX
            && end + MATCH_LEN_MAX - chunk_start <= CHUNK_UNCOMPRESSED_MAX
        {
            self.rep_match(rc, end, 0, MATCH_LEN_MAX);
            end += MATCH_LEN_MAX;
            n_more -= 1;
        }
        self.mf.skip(b, next_ins, (start + 8).min(end));
        self.mf.skip(b, (end - 8).max(start + 8).max(next_ins), end);
        end
    }
}

/// Worst-case size of the LZMA2 stream of `n` input bytes (stored chunks + headers).
pub(crate) fn lzma2_bound(n: usize) -> usize {
    n + 3 * n.div_ceil(1 << 16) + 16
}

/// CRC-64 helper re-exported for the xz writer.
pub(crate) fn check(data: &[u8]) -> u64 {
    crc64(data)
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

    fn roundtrip(data: &[u8], preset: u32) -> usize {
        let mut e = Lzma2Encoder::new(LzmaParams::preset(preset));
        let mut out = Vec::new();
        e.encode_block(data, &mut out);
        let d = crate::codecs::lzma::decompress_lzma2(&out).expect("our LZMA2 decoder rejected the stream");
        assert!(d == data, "roundtrip mismatch (len {}, preset {preset})", data.len());
        out.len()
    }

    #[test]
    fn codecs_lzma_enc_roundtrip() {
        for p in [0, 6, 9] {
            roundtrip(b"", p);
            roundtrip(b"a", p);
            roundtrip(b"ab", p);
            roundtrip(b"abcabcabcabcabcabcabc", p);
            roundtrip(&[0u8; 5000], p);
            roundtrip(&rng(3000, 1), p);
            let n = roundtrip(&gen_data(4, 300_000), p);
            assert!(n < 300_000 / 3, "{n}");
        }
        // Incompressible data -> stored chunks; zero runs across chunk limits.
        let r = rng(200_000, 7);
        assert!(roundtrip(&r, 6) <= lzma2_bound(r.len()));
        let mut z = vec![0u8; 5 << 20];
        z[3 << 20] = 1;
        assert!(roundtrip(&z, 6) < 10_000);
        let mut mixed = gen_data(9, 1 << 20);
        mixed.extend_from_slice(&rng(100_000, 3));
        mixed.extend_from_slice(&gen_data(10, 1 << 20));
        roundtrip(&mixed, 3);
    }
}
