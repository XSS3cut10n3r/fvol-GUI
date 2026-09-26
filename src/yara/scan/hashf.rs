//! Candidate search for large sets of 4-byte windows (hundreds to thousands), where
//! Teddy's buckets get too crowded and an Aho-Corasick DFA is bound by its serial
//! load-to-load dependency (one state transition per byte).
//!
//! Every haystack position is tested independently (so the CPU overlaps many
//! positions): stage 1 looks up two bytes of the 4-byte word at the position in a
//! 64 Kbit bitmap (the byte pair is chosen at build time to minimise the expected hit
//! rate on memory images); stage 2 hashes the whole word into a small bucket table of
//! exact windows.

use crate::yara::regex::literal::BYTE_FREQ;

#[derive(Clone, Debug)]
pub struct HashFilter {
    /// Stage-1 byte positions inside the window (i < j < 4), as bit shifts.
    si: u32,
    sj: u32,
    bitmap: Vec<u64>,
    shift: u32,
    heads: Vec<u32>,
    /// (window as little-endian u32, id), grouped by bucket.
    entries: Vec<(u32, u32)>,
}

#[inline(always)]
fn hash(x: u32, shift: u32) -> usize {
    (x.wrapping_mul(0x9E37_79B1) >> shift) as usize
}

impl HashFilter {
    /// `windows[k]` (exact bytes) belongs to pattern `ids[k]`.
    pub fn new(windows: &[[u8; 4]], ids: &[u32]) -> HashFilter {
        // Stage-1 byte pair: minimise the summed frequency of the distinct pair keys.
        let mut best = (0u32, 1u32);
        let mut best_cost = f64::MAX;
        for i in 0..4usize {
            for j in i + 1..4 {
                let mut keys: Vec<u16> = windows.iter().map(|w| w[i] as u16 | (w[j] as u16) << 8).collect();
                keys.sort_unstable();
                keys.dedup();
                let cost: f64 = keys
                    .iter()
                    .map(|&k| BYTE_FREQ[(k & 0xff) as usize] as f64 * BYTE_FREQ[(k >> 8) as usize] as f64)
                    .sum();
                if cost < best_cost {
                    best_cost = cost;
                    best = (i as u32, j as u32);
                }
            }
        }
        let (si, sj) = (best.0 * 8, best.1 * 8);
        let mut bitmap = vec![0u64; 1024];
        for w in windows {
            let x = u32::from_le_bytes(*w);
            let k = ((x >> si) & 0xff | ((x >> sj) & 0xff) << 8) as usize;
            bitmap[k >> 6] |= 1 << (k & 63);
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
        HashFilter { si, sj, bitmap, shift, heads, entries }
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
        let (si, sj) = (self.si, self.sj);
        let bm: &[u64; 1024] = match self.bitmap.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return,
        };
        let mut q = from;
        while q + 8 <= end {
            let c: &[u8; 11] = match hay[q..q + 11].try_into() {
                Ok(c) => c,
                Err(_) => return,
            };
            for k in 0..8 {
                let x = u32::from_le_bytes([c[k], c[k + 1], c[k + 2], c[k + 3]]);
                let key = ((x >> si) & 0xff | ((x >> sj) & 0xff) << 8) as usize;
                if bm[key >> 6] >> (key & 63) & 1 != 0 {
                    self.stage2(q + k, x, &mut f);
                }
            }
            q += 8;
        }
        while q < end {
            let x = u32::from_le_bytes([hay[q], hay[q + 1], hay[q + 2], hay[q + 3]]);
            let key = ((x >> si) & 0xff | ((x >> sj) & 0xff) << 8) as usize;
            if bm[key >> 6] >> (key & 63) & 1 != 0 {
                self.stage2(q, x, &mut f);
            }
            q += 1;
        }
    }
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
        let wins: Vec<[u8; 4]> = (0..500).map(|_| [b"ab\x00c"[(rnd() % 4) as usize], rnd() as u8, b'x', (rnd() % 3) as u8]).collect();
        let ids: Vec<u32> = (0..wins.len() as u32).collect();
        let hf = HashFilter::new(&wins, &ids);
        let mut hay: Vec<u8> = (0..5000).map(|_| rnd() as u8).collect();
        for w in wins.iter().step_by(7) {
            let p = (rnd() % 4990) as usize;
            hay[p..p + 4].copy_from_slice(w);
        }
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
        assert_eq!(got, exp);
    }
}
