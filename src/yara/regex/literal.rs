//! Literal / byte-set sequence extraction and the SIMD prefilter built from it.
//!
//! `positions(h)` computes a sequence of byte sets S0..Sk-1 such that every match of
//! `h` starts with bytes b0..bk-1, bi in Si. This covers plain literals, case
//! insensitive literals (`(?i)passw` -> [pP][aA][sS]...), alternations of literals
//! (`FILE0|FILE\*|BAAD` -> [FB][IA][LA][ED]) and fixed class prefixes. A `SeqFinder`
//! scans for the two rarest positions with SIMD and verifies all positions.

use super::hir::{ByteSet, Hir};
use crate::yara::memchr::{self, ByteSetFinder, Memmem, SetDesc};

/// Approximate byte frequencies (parts per 2^20) measured on a Windows memory image.
pub const BYTE_FREQ: [u32; 256] = [
    559442, 13435, 7360, 3913, 4234, 3263, 2149, 2001, 5072, 1729, 1804, 1499, 7719, 1825, 1221, 5686, 4362, 1612,
    1258, 1139, 1329, 2964, 934, 1031, 2338, 908, 777, 764, 916, 712, 819, 1243, 5456, 1104, 1197, 918, 6537, 942,
    775, 687, 2738, 1133, 731, 838, 1014, 1499, 1912, 913, 4045, 2245, 1419, 2843, 1479, 1229, 1327, 1015, 3338, 1736,
    1247, 1445, 905, 938, 800, 1095, 3606, 4416, 1330, 1989, 3995, 2819, 1452, 1155, 19554, 3437, 710, 832, 4594, 2235,
    1149, 1002, 3577, 874, 959, 1688, 1644, 1434, 1431, 1694, 1326, 619, 766, 902, 1730, 862, 1132, 1896, 1695, 3111,
    1089, 2176, 2242, 4780, 2348, 1197, 1592, 3133, 635, 940, 2357, 1584, 3071, 3393, 2985, 929, 3091, 3093, 5441,
    2552, 1185, 1199, 1675, 1376, 539, 577, 903, 691, 808, 3436, 3801, 1234, 780, 3545, 1902, 3441, 634, 631, 1355,
    7136, 907, 10980, 869, 4515, 600, 718, 1870, 516, 516, 550, 756, 638, 594, 558, 917, 1069, 589, 534, 731, 592,
    647, 627, 1674, 767, 724, 753, 796, 711, 643, 680, 1030, 648, 783, 610, 794, 617, 654, 666, 1365, 791, 660, 660,
    816, 693, 1445, 929, 1587, 1231, 1682, 840, 1051, 877, 889, 911, 3995, 1864, 1028, 1776, 1698, 860, 1005, 1549,
    1409, 1294, 755, 963, 9658, 751, 1162, 997, 1923, 928, 1116, 1039, 869, 871, 1092, 1202, 1516, 1060, 1088, 991,
    695, 1706, 626, 604, 2148, 893, 744, 581, 1192, 481, 543, 504, 4694, 1658, 621, 1219, 1353, 633, 650, 732, 2175,
    958, 888, 1897, 774, 650, 1178, 941, 1659, 1252, 1163, 3579, 1115, 1208, 2303, 32775,
];

/// Estimated probability (parts per 2^20) that a random memory byte is in `s`.
pub fn set_freq(s: &ByteSet) -> u64 {
    // 32 table lookups, one per byte of the 256-bit set
    let mut t = 0u64;
    for (w, &word) in s.0.iter().enumerate() {
        for k in 0..8 {
            t += FREQ_BY_MASK[w * 8 + k][(word >> (8 * k)) as u8 as usize] as u64;
        }
    }
    t
}

/// `FREQ_BY_MASK[g][m]`: summed `BYTE_FREQ` of the bytes `8 g + i` for the bits `i` set
/// in `m` (byte group `g` of a 256-bit set).
static FREQ_BY_MASK: [[u32; 256]; 32] = {
    let mut t = [[0u32; 256]; 32];
    let mut g = 0;
    while g < 32 {
        let mut m = 0;
        while m < 256 {
            let mut sum = 0u32;
            let mut i = 0;
            while i < 8 {
                if m >> i & 1 != 0 {
                    sum += BYTE_FREQ[g * 8 + i];
                }
                i += 1;
            }
            t[g][m] = sum;
            m += 1;
        }
        g += 1;
    }
    t
};

const MAX_POSITIONS: usize = 32;

/// Required leading byte-set sequence; `complete` = every match of `h` has exactly
/// this length (so a following concat element may extend it).
pub fn positions(h: &Hir) -> (Vec<ByteSet>, bool) {
    let mut out = Vec::with_capacity(16);
    let complete = pos_into(h, &mut out, 0);
    if out.len() > MAX_POSITIONS {
        out.truncate(MAX_POSITIONS);
        return (out, false);
    }
    (out, complete)
}

/// `positions(&Hir::Concat(v.to_vec()))` without building the concatenation.
pub fn positions_concat(v: &[Hir]) -> (Vec<ByteSet>, bool) {
    let mut out = Vec::new();
    let mut complete = true;
    for x in v {
        if !pos_into(x, &mut out, 1) {
            complete = false;
            break;
        }
    }
    if out.len() > MAX_POSITIONS {
        out.truncate(MAX_POSITIONS);
        return (out, false);
    }
    (out, complete)
}

fn pos_into(h: &Hir, out: &mut Vec<ByteSet>, depth: usize) -> bool {
    if out.len() >= MAX_POSITIONS || depth > 200 {
        return false;
    }
    match h {
        Hir::Empty | Hir::Look(_) => true,
        Hir::Fail => true,
        Hir::Class(s) => {
            out.push(*s);
            true
        }
        Hir::Concat(v) => {
            for x in v {
                if !pos_into(x, out, depth + 1) {
                    return false;
                }
            }
            true
        }
        Hir::Alt(v) => {
            let mut seqs = Vec::with_capacity(v.len());
            let mut all_complete = true;
            for x in v {
                let mut s = Vec::new();
                all_complete &= pos_into(x, &mut s, depth + 1);
                seqs.push(s);
            }
            let min = seqs.iter().map(|s| s.len()).min().unwrap_or(0);
            let max = seqs.iter().map(|s| s.len()).max().unwrap_or(0);
            for i in 0..min {
                let mut u = ByteSet::EMPTY;
                for s in &seqs {
                    u.union(&s[i]);
                }
                out.push(u);
            }
            all_complete && min == max
        }
        Hir::Repeat { min, max, sub, .. } => {
            if *min == 0 {
                return *max == Some(0);
            }
            for _ in 0..*min {
                let before = out.len();
                if !pos_into(sub, out, depth + 1) {
                    return false;
                }
                if out.len() == before || out.len() >= MAX_POSITIONS {
                    // zero-width body or enough positions
                    return *max == Some(*min) && out.len() < MAX_POSITIONS;
                }
            }
            *max == Some(*min)
        }
        Hir::Capture { sub, .. } => pos_into(sub, out, depth + 1),
        _ => false,
    }
}

/// Union of all bytes any consuming part of `h` can match.
pub fn bytes_of(h: &Hir) -> ByteSet {
    let mut s = ByteSet::EMPTY;
    bytes_into(h, &mut s, 0);
    s
}

/// `bytes_of` for a node found at nesting `depth` of a larger tree (same depth limit).
pub fn bytes_of_nested(h: &Hir, depth: usize) -> ByteSet {
    let mut s = ByteSet::EMPTY;
    bytes_into(h, &mut s, depth);
    s
}

fn bytes_into(h: &Hir, s: &mut ByteSet, depth: usize) {
    if depth > 3000 {
        *s = ByteSet::FULL;
        return;
    }
    match h {
        Hir::Class(c) => s.union(c),
        Hir::Concat(v) | Hir::Alt(v) => v.iter().for_each(|x| bytes_into(x, s, depth + 1)),
        Hir::Repeat { sub, .. } | Hir::Capture { sub, .. } | Hir::Atomic(sub) | Hir::LookAround { sub, .. } => {
            bytes_into(sub, s, depth + 1)
        }
        Hir::Cond { yes, no, .. } => {
            bytes_into(yes, s, depth + 1);
            bytes_into(no, s, depth + 1);
        }
        Hir::Backref { .. } | Hir::UClass(_) => *s = ByteSet::FULL,
        _ => {}
    }
}

/// Estimated candidate rate (parts per 2^20) of a position sequence using its two
/// rarest positions.
pub fn seq_rate(seq: &[ByteSet]) -> u64 {
    // the two smallest frequencies
    let (mut a, mut b) = (u64::MAX, u64::MAX);
    for s in seq {
        let f = set_freq(s);
        if f < a {
            b = a;
            a = f;
        } else if f < b {
            b = f;
        }
    }
    match seq.len() {
        0 => 1 << 20,
        1 => a,
        _ => ((a * b) >> 20).max(1),
    }
}

/// Whether `alt_seqs` can find more than one top-level alternative (an alternation at
/// the top, under captures or at the head of a concatenation).
fn top_alt(h: &Hir, depth: usize) -> bool {
    if depth > 50 {
        return false;
    }
    match h {
        Hir::Alt(_) => true,
        Hir::Capture { sub, .. } => top_alt(sub, depth + 1),
        Hir::Concat(v) => match v.iter().find(|x| !matches!(x, Hir::Look(_) | Hir::Empty)) {
            Some(Hir::Capture { sub, .. }) => matches!(**sub, Hir::Alt(_)),
            Some(x) => matches!(x, Hir::Alt(_)),
            None => false,
        },
        _ => false,
    }
}

/// Leading byte-set sequences per top-level alternative (every match starts with one
/// of them). None when some alternative can start with anything / match empty.
pub fn alt_seqs(h: &Hir) -> Option<Vec<Vec<ByteSet>>> {
    let mut out = Vec::new();
    alt_seqs_into(h, &mut out, 0)?;
    if out.is_empty() || out.iter().any(|s| s.is_empty()) {
        return None;
    }
    Some(out)
}

fn alt_seqs_into(h: &Hir, out: &mut Vec<Vec<ByteSet>>, depth: usize) -> Option<()> {
    if depth > 50 || out.len() > 64 {
        return None;
    }
    match h {
        Hir::Alt(v) => {
            for x in v {
                alt_seqs_into(x, out, depth + 1)?;
            }
        }
        Hir::Capture { sub, .. } => alt_seqs_into(sub, out, depth + 1)?,
        Hir::Concat(v) => {
            let k = v.iter().position(|x| !matches!(x, Hir::Look(_) | Hir::Empty)).unwrap_or(v.len());
            let head = match v.get(k) {
                Some(Hir::Capture { sub, .. }) => &**sub,
                Some(x) => x,
                None => return None,
            };
            if let Hir::Alt(alts) = head {
                for a in alts {
                    let mut c = vec![a.clone()];
                    c.extend_from_slice(&v[k + 1..]);
                    alt_seqs_into(&Hir::Concat(c), out, depth + 1)?;
                }
            } else {
                out.push(positions(h).0);
            }
        }
        _ => out.push(positions(h).0),
    }
    if out.len() > 64 { None } else { Some(()) }
}

/// A prefilter reporting candidate match starts.
#[derive(Clone, Debug)]
pub enum Prefilter {
    Seq(SeqFinder),
    Teddy(crate::yara::teddy::Teddy),
}

impl Prefilter {
    #[inline]
    pub fn find(&self, hay: &[u8], from: usize) -> Option<usize> {
        match self {
            Prefilter::Seq(s) => s.find(hay, from),
            Prefilter::Teddy(t) => t.find(hay, from),
        }
    }

    /// Choose the best prefix prefilter for `h` (None when not selective enough).
    pub fn for_hir(h: &Hir) -> Option<(Prefilter, u64)> {
        const MAX_RATE: u64 = (1 << 20) / 12;
        let alts = if top_alt(h, 0) { alt_seqs(h) } else { None };
        // For a plain top-level alternation the per-alternative sequences are what
        // `positions` would compute again: take their union directly.
        let pseq = match (&alts, h) {
            (Some(a), Hir::Alt(v)) if a.len() == v.len() => {
                let min = a.iter().map(|x| x.len()).min().unwrap_or(0);
                (0..min)
                    .map(|i| {
                        let mut u = ByteSet::EMPTY;
                        for x in a {
                            u.union(&x[i]);
                        }
                        u
                    })
                    .collect()
            }
            _ => positions(h).0,
        };
        let seq_rate_v = if pseq.is_empty() { u64::MAX } else { seq_rate(&pseq) };
        let mut best: Option<(Prefilter, u64)> = None;
        if seq_rate_v < MAX_RATE {
            if let Some(f) = SeqFinder::new(&pseq) {
                best = Some((Prefilter::Seq(f), seq_rate_v));
            }
        }
        if let Some(alts) = alts {
            if alts.len() > 1 {
                let m = alts.iter().map(|s| s.len()).min().unwrap_or(0).min(3);
                if m >= 1 {
                    let rate: u64 = alts
                        .iter()
                        .map(|s| s[..m].iter().fold(1u64 << 20, |acc, x| (acc * set_freq(x)) >> 20).max(1))
                        .sum::<u64>()
                        .saturating_mul(2);
                    let better = best.as_ref().map_or(true, |b| rate * 2 < b.1);
                    if rate < MAX_RATE && better {
                        if let Some(t) = crate::yara::teddy::Teddy::from_vec(alts) {
                            best = Some((Prefilter::Teddy(t), rate));
                        }
                    }
                }
            }
        }
        best
    }
}

// ---------------------------------------------------------------------------------------
// SeqFinder
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Kind {
    /// Single exact literal.
    Lit(Memmem),
    /// Single byte set position (first byte).
    Set(ByteSetFinder),
    /// Pair of positions + full verification.
    Pair { i1: usize, i2: usize },
}

/// Finds the leftmost position where a byte-set sequence occurs.
#[derive(Clone, Debug)]
pub struct SeqFinder {
    seq: Vec<ByteSet>,
    kind: Kind,
    s1: SetDesc,
    s2: SetDesc,
}

impl SeqFinder {
    pub fn new(seq: &[ByteSet]) -> Option<SeqFinder> {
        if seq.is_empty() || seq.iter().any(|s| s.is_empty()) {
            return None;
        }
        let seq: Vec<ByteSet> = seq.to_vec();
        if seq.iter().all(|s| s.len() == 1) && seq.len() >= 2 {
            let lit: Vec<u8> = seq.iter().filter_map(|s| s.as_single()).collect();
            return Some(SeqFinder { kind: Kind::Lit(Memmem::new(&lit)), s1: SetDesc::new(&seq[0]), s2: SetDesc::new(&seq[0]), seq });
        }
        if seq.len() == 1 {
            return Some(SeqFinder { kind: Kind::Set(ByteSetFinder::new(&seq[0].to_bools())), s1: SetDesc::new(&seq[0]), s2: SetDesc::new(&seq[0]), seq });
        }
        // Two rarest positions.
        let (mut i1, mut i2) = (usize::MAX, usize::MAX);
        let (mut f1, mut f2) = (u64::MAX, u64::MAX);
        for (i, s) in seq.iter().enumerate() {
            let f = set_freq(s);
            if f < f1 {
                (i2, f2) = (i1, f1);
                (i1, f1) = (i, f);
            } else if f < f2 {
                (i2, f2) = (i, f);
            }
        }
        Some(SeqFinder { kind: Kind::Pair { i1, i2 }, s1: SetDesc::new(&seq[i1]), s2: SetDesc::new(&seq[i2]), seq })
    }

    pub fn len(&self) -> usize {
        self.seq.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seq.is_empty()
    }

    pub fn rate(&self) -> u64 {
        seq_rate(&self.seq)
    }

    #[inline]
    fn verify(&self, hay: &[u8], p: usize) -> bool {
        if p + self.seq.len() > hay.len() {
            return false;
        }
        self.seq.iter().zip(&hay[p..p + self.seq.len()]).all(|(s, &b)| s.contains(b))
    }

    /// Leftmost p >= from where the sequence matches.
    pub fn find(&self, hay: &[u8], from: usize) -> Option<usize> {
        let k = self.seq.len();
        if from > hay.len() || hay.len() - from < k {
            return None;
        }
        match &self.kind {
            Kind::Lit(m) => m.find_at(hay, from),
            Kind::Set(f) => f.find(&hay[..hay.len() - k + 1], from),
            Kind::Pair { i1, i2 } => {
                let last = hay.len() - k;
                memchr::pair_set_find(hay, from, last, *i1, &self.s1, *i2, &self.s2, &mut |q| self.verify(hay, q))
            }
        }
    }
}
