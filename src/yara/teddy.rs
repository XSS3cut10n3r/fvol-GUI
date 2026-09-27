//! Teddy-style SIMD multi-pattern prefilter (the idea from Hyperscan): each pattern is a
//! sequence of byte sets; its first `m <= 3` positions are fingerprinted into 8 buckets
//! with low/high nibble shuffle tables. One AVX2 iteration classifies 32 candidate
//! start positions with 6 `vpshufb`; candidates are verified against the full
//! sequences of the patterns in the matching buckets.

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::yara::regex::hir::ByteSet;

#[derive(Clone, Debug)]
pub struct Teddy {
    pats: Vec<Vec<ByteSet>>,
    /// Pattern indices per bucket.
    buckets: [Vec<u32>; 8],
    /// Fingerprint length (1..=3).
    m: usize,
    lo: [[u8; 16]; 3],
    hi: [[u8; 16]; 3],
    min_len: usize,
    /// No fingerprinted byte is >= 0x80: `vpshufb` on the raw byte already yields the
    /// low-nibble entry for ASCII bytes and 0 for the others (whose high-nibble entry is
    /// 0 anyway), so the low-nibble mask can be skipped.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    ascii: bool,
}

impl Teddy {
    /// Build for 1..=64 non-empty patterns.
    pub fn new(pats: &[Vec<ByteSet>]) -> Option<Teddy> {
        Self::from_vec(pats.to_vec())
    }

    /// [`Teddy::new`] taking ownership of the patterns (no copy).
    pub fn from_vec(pats: Vec<Vec<ByteSet>>) -> Option<Teddy> {
        if pats.is_empty() || pats.len() > 64 || pats.iter().any(|p| p.is_empty() || p.iter().any(|s| s.is_empty())) {
            return None;
        }
        let min_len = pats.iter().map(|p| p.len()).min()?;
        let m = min_len.min(3);
        // Assign patterns to buckets: group patterns with identical fingerprints,
        // then spread groups round-robin by estimated weight.
        let mut order: Vec<usize> = (0..pats.len()).collect();
        order.sort_by(|&a, &b| pats[a][..m].iter().map(|s| s.0).cmp(pats[b][..m].iter().map(|s| s.0)));
        let mut buckets: [Vec<u32>; 8] = Default::default();
        let mut bi = 0usize;
        let mut prev: Option<&[ByteSet]> = None;
        for &i in &order {
            let fp = &pats[i][..m];
            if let Some(p) = prev {
                if p != fp {
                    bi = (bi + 1) % 8;
                }
            }
            buckets[bi].push(i as u32);
            prev = Some(fp);
        }
        let mut lo = [[0u8; 16]; 3];
        let mut hi = [[0u8; 16]; 3];
        for (b, list) in buckets.iter().enumerate() {
            for &pi in list {
                for j in 0..m {
                    for c in pats[pi as usize][j].iter() {
                        lo[j][(c & 15) as usize] |= 1 << b;
                        hi[j][(c >> 4) as usize] |= 1 << b;
                    }
                }
            }
        }
        let ascii = pats.iter().all(|p| p[..m].iter().all(|s| s.0[2] == 0 && s.0[3] == 0));
        Some(Teddy { pats, buckets, m, lo, hi, min_len, ascii })
    }

    #[inline]
    fn verify_bucket(&self, hay: &[u8], p: usize, bits: u32) -> bool {
        let mut bits = bits;
        while bits != 0 {
            let b = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            for &pi in &self.buckets[b] {
                let pat = &self.pats[pi as usize];
                if p + pat.len() <= hay.len() && pat.iter().zip(&hay[p..p + pat.len()]).all(|(s, &x)| s.contains(x)) {
                    return true;
                }
            }
        }
        false
    }

    #[inline]
    fn scalar_bits(&self, hay: &[u8], p: usize) -> u32 {
        let mut r = 0xffu32;
        for j in 0..self.m {
            let x = hay[p + j];
            r &= (self.lo[j][(x & 15) as usize] & self.hi[j][(x >> 4) as usize]) as u32;
        }
        r
    }

    /// Leftmost position >= `from` where some pattern matches.
    pub fn find(&self, hay: &[u8], from: usize) -> Option<usize> {
        if from > hay.len() || hay.len() - from < self.min_len {
            return None;
        }
        // Last start position with room for the fingerprint.
        let last = hay.len() - self.min_len;
        #[cfg(target_arch = "x86_64")]
        {
            if last - from >= 64 && has_avx2() {
                // SAFETY: AVX2 checked; loads stay within hay (see find_avx2).
                return unsafe {
                    match (self.m, self.ascii) {
                        (1, false) => self.find_avx2::<1, false>(hay, from, last),
                        (2, false) => self.find_avx2::<2, false>(hay, from, last),
                        (_, false) => self.find_avx2::<3, false>(hay, from, last),
                        (1, true) => self.find_avx2::<1, true>(hay, from, last),
                        (2, true) => self.find_avx2::<2, true>(hay, from, last),
                        (_, true) => self.find_avx2::<3, true>(hay, from, last),
                    }
                };
            }
        }
        (from..=last).find(|&p| {
            let bits = self.scalar_bits(hay, p);
            bits != 0 && self.verify_bucket(hay, p, bits)
        })
    }

    /// 64 candidate starts per branch (two 32-byte classifications OR-tested), the line
    /// one page ahead touched per step (see `memchr`'s block loops).
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn find_avx2<const M: usize, const ASCII: bool>(&self, hay: &[u8], from: usize, last: usize) -> Option<usize> {
        unsafe {
            let ptr = hay.as_ptr();
            let n = hay.len();
            let nib = _mm256_set1_epi8(0x0f);
            let t = |a: &[u8; 16]| _mm256_broadcastsi128_si256(_mm_loadu_si128(a.as_ptr() as *const __m128i));
            let lo = [t(&self.lo[0]), t(&self.lo[1]), t(&self.lo[2])];
            let hi = [t(&self.hi[0]), t(&self.hi[1]), t(&self.hi[2])];
            // Positions q..q+31 need bytes up to q+31+(M-1) <= last + M - 1 < hay.len().
            macro_rules! classify {
                ($q:expr) => {{
                    let mut r = _mm256_set1_epi8(-1);
                    for j in 0..M {
                        let v = _mm256_loadu_si256(ptr.add($q + j) as *const __m256i);
                        let l = _mm256_shuffle_epi8(lo[j], if ASCII { v } else { _mm256_and_si256(v, nib) });
                        let h = _mm256_shuffle_epi8(hi[j], _mm256_and_si256(_mm256_srli_epi16(v, 4), nib));
                        r = _mm256_and_si256(r, _mm256_and_si256(l, h));
                    }
                    r
                }};
            }
            let zero = _mm256_setzero_si256();
            let emit = |q: usize, r: __m256i| -> Option<usize> {
                let mut mask = !(_mm256_movemask_epi8(_mm256_cmpeq_epi8(r, zero)) as u32);
                if mask != 0 {
                    let mut bytes = [0u8; 32];
                    _mm256_storeu_si256(bytes.as_mut_ptr() as *mut __m256i, r);
                    while mask != 0 {
                        let k = mask.trailing_zeros() as usize;
                        mask &= mask - 1;
                        if self.verify_bucket(hay, q + k, bytes[k] as u32) {
                            return Some(q + k);
                        }
                    }
                }
                None
            };
            let mut p = from;
            while p + 63 <= last {
                if p + 4096 < n {
                    _mm_prefetch::<_MM_HINT_T0>(ptr.add(p + 4096) as *const i8);
                }
                let a = classify!(p);
                let b = classify!(p + 32);
                let any = _mm256_or_si256(a, b);
                if _mm256_testz_si256(any, any) == 0 {
                    if let Some(x) = emit(p, a) {
                        return Some(x);
                    }
                    if let Some(x) = emit(p + 32, b) {
                        return Some(x);
                    }
                }
                p += 64;
            }
            while p + 31 <= last {
                if let Some(x) = emit(p, classify!(p)) {
                    return Some(x);
                }
                p += 32;
            }
            (p..=last).find(|&q| {
                let bits = self.scalar_bits(hay, q);
                bits != 0 && self.verify_bucket(hay, q, bits)
            })
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn has_avx2() -> bool {
    if cfg!(target_feature = "avx2") {
        return true;
    }
    use std::sync::atomic::{AtomicU8, Ordering};
    static STATE: AtomicU8 = AtomicU8::new(0);
    match STATE.load(Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => {
            let yes = std::is_x86_feature_detected!("avx2");
            STATE.store(if yes { 2 } else { 1 }, Ordering::Relaxed);
            yes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(s: &[u8]) -> Vec<ByteSet> {
        s.iter().map(|&b| ByteSet::single(b)).collect()
    }

    #[test]
    fn yara_teddy_random() {
        let mut seed = 0x1234_5678u64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..500 {
            let npat = 1 + (rnd() % 20) as usize;
            let pats: Vec<Vec<u8>> = (0..npat)
                .map(|_| (0..1 + rnd() % 5).map(|_| b"abcd"[(rnd() % 4) as usize]).collect())
                .collect();
            let t = Teddy::new(&pats.iter().map(|p| lit(p)).collect::<Vec<_>>()).unwrap();
            let hay: Vec<u8> = (0..(rnd() % 300)).map(|_| b"abcde"[(rnd() % 5) as usize]).collect();
            let from = (rnd() as usize) % (hay.len() + 1);
            let want = (from..=hay.len()).find(|&p| pats.iter().any(|q| hay[p..].starts_with(q)));
            assert_eq!(t.find(&hay, from), want, "{pats:?} {hay:?}");
        }
    }
}
