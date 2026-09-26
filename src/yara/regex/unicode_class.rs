//! Codepoint sets and helpers for python str-pattern semantics: Unicode `\w \d \s`,
//! sre's IGNORECASE folding (`lower(ch)` membership plus `_EXTRA_CASES`), and UTF-8
//! decoding of haystack characters.

use super::unicode::{EXTRA, LOWER};

pub const MAX_CP: u32 = 0x10ffff;

#[inline]
pub fn in_table(t: &[(u32, u32)], c: u32) -> bool {
    let mut lo = 0usize;
    let mut hi = t.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let (a, b) = t[mid];
        if c < a {
            hi = mid;
        } else if c > b {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    false
}

/// sre `unicode_tolower` (simple lowercase mapping).
#[inline]
pub fn lower(c: u32) -> u32 {
    match LOWER.binary_search_by_key(&c, |&(k, _)| k) {
        Ok(i) => LOWER[i].1,
        Err(_) => c,
    }
}

/// Sorted, merged codepoint ranges (surrogates never included).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CpSet {
    pub ranges: Vec<(u32, u32)>,
}

impl CpSet {
    pub fn single(c: u32) -> CpSet {
        let mut s = CpSet::default();
        s.add(c);
        s
    }

    pub fn from_table(t: &[(u32, u32)]) -> CpSet {
        CpSet { ranges: t.to_vec() }
    }

    pub fn add(&mut self, c: u32) {
        self.add_range(c, c);
    }

    pub fn add_range(&mut self, a: u32, b: u32) {
        if a > b {
            return;
        }
        self.ranges.push((a, b));
    }

    pub fn union(&mut self, o: &CpSet) {
        self.ranges.extend_from_slice(&o.ranges);
    }

    /// Sort, merge and drop surrogates.
    pub fn normalize(&mut self) {
        let mut v: Vec<(u32, u32)> = Vec::with_capacity(self.ranges.len() + 1);
        for &(a, b) in &self.ranges {
            let b = b.min(MAX_CP);
            if a > b {
                continue;
            }
            // split out surrogates
            if a <= 0xdfff && b >= 0xd800 {
                if a < 0xd800 {
                    v.push((a, 0xd7ff));
                }
                if b > 0xdfff {
                    v.push((0xe000, b));
                }
            } else {
                v.push((a, b));
            }
        }
        v.sort_unstable();
        let mut out: Vec<(u32, u32)> = Vec::with_capacity(v.len());
        for (a, b) in v {
            if let Some(last) = out.last_mut() {
                if a <= last.1.saturating_add(1) {
                    last.1 = last.1.max(b);
                    continue;
                }
            }
            out.push((a, b));
        }
        self.ranges = out;
    }

    pub fn contains(&self, c: u32) -> bool {
        in_table(&self.ranges, c)
    }

    /// Complement over all scalar values.
    pub fn negate(&self) -> CpSet {
        let mut s = self.clone();
        s.normalize();
        let mut out = Vec::new();
        let mut next = 0u32;
        for &(a, b) in &s.ranges {
            if a > next {
                out.push((next, a - 1));
            }
            next = b.saturating_add(1);
        }
        if next <= MAX_CP {
            out.push((next, MAX_CP));
        }
        let mut r = CpSet { ranges: out };
        r.normalize();
        r
    }

    /// sre Unicode IGNORECASE: {ch : lower(ch) in T} where
    /// T = {lower(x) : x in self} plus `_EXTRA_CASES` of those.
    pub fn fold_unicode(&self) -> CpSet {
        let mut s = self.clone();
        s.normalize();
        let mut u = CpSet { ranges: LOWER.iter().map(|&(x, _)| (x, x)).collect() };
        u.normalize();
        // T = (S \ U) ∪ {lower(x) : x ∈ S ∩ U} ∪ extras
        let mut t = s.minus(&u);
        for &(x, lx) in LOWER {
            if s.contains(x) {
                t.add(lx);
            }
        }
        t.normalize();
        let mut extra = Vec::new();
        for &(k, vals) in EXTRA {
            if t.contains(k) {
                extra.extend_from_slice(vals);
            }
        }
        for e in extra {
            t.add(e);
        }
        t.normalize();
        // R = (T \ U) ∪ {x ∈ U : lower(x) ∈ T}
        let mut r = t.minus(&u);
        for &(x, lx) in LOWER {
            if t.contains(lx) {
                r.add(x);
            }
        }
        r.normalize();
        r
    }

    /// ASCII-only IGNORECASE (python `re.ASCII | re.IGNORECASE` on str patterns).
    pub fn fold_ascii(&self) -> CpSet {
        let mut src = self.clone();
        src.normalize();
        let mut s = src.clone();
        for c in (b'a' as u32)..=(b'z' as u32) {
            if src.contains(c) || src.contains(c - 32) {
                s.add(c);
                s.add(c - 32);
            }
        }
        s.normalize();
        s
    }

    pub fn minus(&self, o: &CpSet) -> CpSet {
        // self ∩ ¬o
        let n = o.negate();
        self.intersect(&n)
    }

    pub fn intersect(&self, o: &CpSet) -> CpSet {
        let mut a = self.clone();
        a.normalize();
        let mut b = o.clone();
        b.normalize();
        let (mut i, mut j) = (0, 0);
        let mut out = Vec::new();
        while i < a.ranges.len() && j < b.ranges.len() {
            let (a0, a1) = a.ranges[i];
            let (b0, b1) = b.ranges[j];
            let lo = a0.max(b0);
            let hi = a1.min(b1);
            if lo <= hi {
                out.push((lo, hi));
            }
            if a1 < b1 {
                i += 1;
            } else {
                j += 1;
            }
        }
        CpSet { ranges: out }
    }
}

/// Decode the UTF-8 character at `i` (invalid bytes decode as U+FFFD, length 1).
#[inline]
pub fn decode(b: &[u8], i: usize) -> Option<(u32, usize)> {
    let c0 = *b.get(i)?;
    if c0 < 0x80 {
        return Some((c0 as u32, 1));
    }
    let (n, init) = if c0 & 0xe0 == 0xc0 {
        (2, (c0 & 0x1f) as u32)
    } else if c0 & 0xf0 == 0xe0 {
        (3, (c0 & 0x0f) as u32)
    } else if c0 & 0xf8 == 0xf0 {
        (4, (c0 & 0x07) as u32)
    } else {
        return Some((0xfffd, 1));
    };
    if i + n > b.len() {
        return Some((0xfffd, 1));
    }
    let mut cp = init;
    for k in 1..n {
        let c = b[i + k];
        if c & 0xc0 != 0x80 {
            return Some((0xfffd, 1));
        }
        cp = cp << 6 | (c & 0x3f) as u32;
    }
    Some((cp, n))
}

/// Decode the character ending right before `i`.
#[inline]
pub fn decode_prev(b: &[u8], i: usize) -> Option<(u32, usize)> {
    if i == 0 || i > b.len() {
        return None;
    }
    let mut j = i - 1;
    let stop = i.saturating_sub(4);
    while j > stop && b[j] & 0xc0 == 0x80 {
        j -= 1;
    }
    match decode(b, j) {
        Some((cp, n)) if j + n == i => Some((cp, n)),
        _ => Some((0xfffd, 1)),
    }
}

#[inline]
pub fn is_word(c: u32) -> bool {
    if c < 128 {
        (c as u8).is_ascii_alphanumeric() || c == 0x5f
    } else {
        in_table(super::unicode::WORD, c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yara_unicode_fold() {
        let s = CpSet::single('k' as u32).fold_unicode();
        assert!(s.contains('K' as u32) && s.contains('k' as u32) && s.contains(0x212a));
        let s = CpSet::single('i' as u32).fold_unicode();
        assert!(s.contains('I' as u32) && s.contains(0x131) && s.contains(0x130));
        let n = CpSet::single('a' as u32).negate();
        assert!(!n.contains('a' as u32) && n.contains('b' as u32) && !n.contains(0xd800));
    }
}
