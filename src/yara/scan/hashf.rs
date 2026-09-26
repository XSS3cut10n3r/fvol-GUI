//! Candidate search for large sets of 4-byte windows (hundreds to thousands), where
//! Teddy's buckets get too crowded and an Aho-Corasick DFA is bound by its serial
//! load-to-load dependency (one state transition per byte).
//!
//! Every haystack position is tested independently, so the CPU overlaps many
//! positions. Stage 1 is a Bloom-style bit table over the hashed 4-byte words of all
//! windows (2^19 bits = 64 KiB): with AVX2, eight overlapping words are built with one
//! byte shuffle, hashed with one multiply and looked up with one gather. Stage 2
//! hashes the word into a small bucket table of exact windows.

#[derive(Clone, Debug)]
pub struct HashFilter {
    /// Stage-1 bit table (u32 words), indexed by `hash(word) >> (32 - BLOOM_BITS)`.
    bloom: Vec<u32>,
    shift: u32,
    heads: Vec<u32>,
    /// (window as little-endian u32, id), grouped by bucket.
    entries: Vec<(u32, u32)>,
}

const BLOOM_BITS: u32 = 19;
const MUL: u32 = 0x9E37_79B1;

#[inline(always)]
fn hash(x: u32, shift: u32) -> usize {
    (x.wrapping_mul(MUL) >> shift) as usize
}

#[inline(always)]
fn ld32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

impl HashFilter {
    /// `windows[k]` (exact bytes) belongs to pattern `ids[k]`.
    pub fn new(windows: &[[u8; 4]], ids: &[u32]) -> HashFilter {
        let mut bloom = vec![0u32; 1 << (BLOOM_BITS - 5)];
        for w in windows {
            let h = hash(u32::from_le_bytes(*w), 32 - BLOOM_BITS);
            bloom[h >> 5] |= 1 << (h & 31);
        }
        let n = windows.len().max(1);
        let bits = (usize::BITS - (n * 4 - 1).leading_zeros()).clamp(4, 24);
        let shift = 32 - bits;
        let nb = 1usize << bits;
        let mut counts = vec![0u32; nb + 1];
        for w in windows {
            counts[hash(u32::from_le_bytes(*w), shift) + 1] += 1;
        }
        for b in 0..nb {
            counts[b + 1] += counts[b];
        }
        let heads = counts.clone();
        let mut fill = counts;
        let mut entries = vec![(0u32, 0u32); windows.len()];
        for (w, &id) in windows.iter().zip(ids) {
            let x = u32::from_le_bytes(*w);
            let h = hash(x, shift);
            entries[fill[h] as usize] = (x, id);
            fill[h] += 1;
        }
        HashFilter { bloom, shift, heads, entries }
    }

    #[inline(always)]
    fn stage1(&self, x: u32) -> bool {
        let h = hash(x, 32 - BLOOM_BITS);
        self.bloom.get(h >> 5).is_some_and(|w| w >> (h & 31) & 1 != 0)
    }

    #[inline(always)]
    fn stage2<F: FnMut(usize, u32)>(&self, q: usize, x: u32, f: &mut F) {
        let h = hash(x, self.shift);
        let (a, b) = (self.heads[h] as usize, self.heads[h + 1] as usize);
        for &(w, id) in &self.entries[a..b] {
            if w == x {
                f(q, id);
            }
        }
    }

    /// Calls `f(q, id)` for every `q` in `[from, to)` where the window of `id` occurs.
    #[inline]
    pub fn find<F: FnMut(usize, u32)>(&self, hay: &[u8], from: usize, to: usize, mut f: F) {
        let end = to.min(hay.len().saturating_sub(3));
        let mut q = from;
        #[cfg(target_arch = "x86_64")]
        {
            if has_avx2() && !super::teddy::force_scalar() && self.bloom.len() == 1 << (BLOOM_BITS - 5) {
                let mut cands = [0u64; 256];
                loop {
                    // SAFETY: AVX2 checked; the core bounds-checks its loads and the
                    // table size is checked above.
                    let (next, k) = unsafe { stage1_avx2(&self.bloom, hay, q, end, &mut cands) };
                    for &c in &cands[..k.min(cands.len())] {
                        let p = c as usize;
                        if p + 4 <= hay.len() {
                            self.stage2(p, ld32(hay, p), &mut f);
                        }
                    }
                    if next == q {
                        break;
                    }
                    q = next;
                }
            }
        }
        while q < end {
            let x = ld32(hay, q);
            if self.stage1(x) {
                self.stage2(q, x, &mut f);
            }
            q += 1;
        }
    }
}

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

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

/// Stage 1 with AVX2: 16 positions per step. The words at `q..q+8` come from one
/// 16-byte load broadcast to both lanes and one byte shuffle; one multiply hashes
/// them, one gather reads the bit-table words. Writes candidate positions to `out`;
/// returns (next position, count). Loads stay inside `hay`; positions stay below
/// `end`. `bloom` must hold `1 << (BLOOM_BITS - 5)` words.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline(never)]
unsafe fn stage1_avx2(bloom: &[u32], hay: &[u8], mut q: usize, end: usize, out: &mut [u64; 256]) -> (usize, usize) {
    let n = hay.len();
    let ptr = hay.as_ptr();
    let tp = bloom.as_ptr() as *const i32;
    let idx = _mm256_setr_epi8(
        0, 1, 2, 3, 1, 2, 3, 4, 2, 3, 4, 5, 3, 4, 5, 6, 4, 5, 6, 7, 5, 6, 7, 8, 6, 7, 8, 9, 7, 8, 9, 10,
    );
    let mul = _mm256_set1_epi32(MUL as i32);
    let low5 = _mm256_set1_epi32(31);
    let one = _mm256_set1_epi32(1);
    let zero = _mm256_setzero_si256();
    // The caller guarantees p + 16 <= n; hash indices are < 2^BLOOM_BITS so word
    // indices are < bloom.len().
    let group = |p: usize| -> u32 {
        // SAFETY: see above.
        let x = unsafe { _mm256_broadcastsi128_si256(_mm_loadu_si128(ptr.add(p) as *const __m128i)) };
        let w = _mm256_shuffle_epi8(x, idx);
        let h = _mm256_srli_epi32(_mm256_mullo_epi32(w, mul), (32 - BLOOM_BITS) as i32);
        // SAFETY: see above.
        let g = unsafe { _mm256_i32gather_epi32::<4>(tp, _mm256_srli_epi32(h, 5)) };
        let bit = _mm256_and_si256(_mm256_srlv_epi32(g, _mm256_and_si256(h, low5)), one);
        (!_mm256_movemask_ps(_mm256_castsi256_ps(_mm256_cmpeq_epi32(bit, zero))) & 0xff) as u32
    };
    let mut k = 0usize;
    while q + 16 <= end && q + 24 <= n && k + 16 <= out.len() {
        let mut bits = group(q) | group(q + 8) << 8;
        while bits != 0 {
            let i = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            out[k] = (q + i) as u64;
            k += 1;
        }
        q += 16;
    }
    (q, k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yara_hashf_exact() {
        let mut x = 0x5555_1234_abcd_0001u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..3 {
            let wins: Vec<[u8; 4]> = (0..500)
                .map(|_| {
                    let mut w = [b"ab\x00c"[(rnd() % 4) as usize], rnd() as u8, b'x', (rnd() % 3) as u8];
                    w.rotate_left(round);
                    w
                })
                .collect();
            let ids: Vec<u32> = (0..wins.len() as u32).collect();
            let hf = HashFilter::new(&wins, &ids);
            let mut hay: Vec<u8> = (0..5000).map(|_| rnd() as u8).collect();
            for w in wins.iter().step_by(7) {
                let p = (rnd() % 4996) as usize;
                hay[p..p + 4].copy_from_slice(w);
            }
            hay[4996..].copy_from_slice(&wins[3]);
            let mut got = Vec::new();
            hf.find(&hay, 0, hay.len(), |q, id| got.push((q, id)));
            let mut exp = Vec::new();
            for q in 0..hay.len() - 3 {
                for (i, w) in wins.iter().enumerate() {
                    if hay[q..q + 4] == *w {
                        exp.push((q, i as u32));
                    }
                }
            }
            got.sort();
            exp.sort();
            assert_eq!(got, exp, "round {round}");
        }
    }
}
