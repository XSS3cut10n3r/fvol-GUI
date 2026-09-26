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
}

impl Teddy {
    /// Build for 1..=64 non-empty patterns.
    pub fn new(pats: &[Vec<ByteSet>]) -> Option<Teddy> {
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
        Some(Teddy { pats: pats.to_vec(), buckets, m, lo, hi, min_len })
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
            if last - from >= 64 && std::is_x86_feature_detected!("avx2") {
                // SAFETY: AVX2 checked; loads stay within hay (see find_avx2).
                return unsafe { self.find_avx2(hay, from, last) };
            }
        }
        (from..=last).find(|&p| {
            let bits = self.scalar_bits(hay, p);
            bits != 0 && self.verify_bucket(hay, p, bits)
        })
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn find_avx2(&self, hay: &[u8], from: usize, last: usize) -> Option<usize> {
        unsafe {
            let ptr = hay.as_ptr();
            let nib = _mm256_set1_epi8(0x0f);
            let t = |a: &[u8; 16]| _mm256_broadcastsi128_si256(_mm_loadu_si128(a.as_ptr() as *const __m128i));
            let (lo0, hi0) = (t(&self.lo[0]), t(&self.hi[0]));
            let (lo1, hi1) = (t(&self.lo[1]), t(&self.hi[1]));
            let (lo2, hi2) = (t(&self.lo[2]), t(&self.hi[2]));
            let m = self.m;
            let classify = |v: __m256i, lo: __m256i, hi: __m256i| -> __m256i {
                let l = _mm256_shuffle_epi8(lo, _mm256_and_si256(v, nib));
                let h = _mm256_shuffle_epi8(hi, _mm256_and_si256(_mm256_srli_epi16(v, 4), nib));
                _mm256_and_si256(l, h)
            };
            let zero = _mm256_setzero_si256();
            // Positions p..p+31 need bytes up to p+31+(m-1) <= last + m - 1 < hay.len().
            let mut p = from;
            while p + 31 <= last {
                let v0 = _mm256_loadu_si256(ptr.add(p) as *const __m256i);
                let mut r = classify(v0, lo0, hi0);
                if m > 1 {
                    let v1 = _mm256_loadu_si256(ptr.add(p + 1) as *const __m256i);
                    r = _mm256_and_si256(r, classify(v1, lo1, hi1));
                }
                if m > 2 {
                    let v2 = _mm256_loadu_si256(ptr.add(p + 2) as *const __m256i);
                    r = _mm256_and_si256(r, classify(v2, lo2, hi2));
                }
                let mut mask = !(_mm256_movemask_epi8(_mm256_cmpeq_epi8(r, zero)) as u32);
                if mask != 0 {
                    let mut bytes = [0u8; 32];
                    _mm256_storeu_si256(bytes.as_mut_ptr() as *mut __m256i, r);
                    while mask != 0 {
                        let k = mask.trailing_zeros() as usize;
                        mask &= mask - 1;
                        if self.verify_bucket(hay, p + k, bytes[k] as u32) {
                            return Some(p + k);
                        }
                    }
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
