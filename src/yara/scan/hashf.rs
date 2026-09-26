//! Candidate search for large sets of 4-byte windows (hundreds to thousands), where
//! Teddy's buckets get too crowded and an Aho-Corasick DFA is bound by its serial
//! load-to-load dependency (one state transition per byte).
//!
//! Every haystack position is tested independently, so the CPU overlaps many
//! positions: stage 1 reads the 16-bit word at `q + I` (the adjacent byte pair of the
//! windows chosen at build time to minimise the expected hit rate on memory images)
//! and looks it up in a 64 KiB byte table; the 8 results of an unrolled group are
//! folded into one bit mask so the common "nothing here" case costs a single branch.
//! Stage 2 hashes the whole 4-byte word into a small bucket table of exact windows.

use super::freq::pair_bits;

#[derive(Clone, Debug)]
pub struct HashFilter {
    /// Stage-1 pair offset inside the window (0..=2).
    pair: usize,
    /// 0xff for 16-bit keys (little-endian pair) present in some window.
    table: Vec<u8>,
    shift: u32,
    heads: Vec<u32>,
    /// (window as little-endian u32, id), grouped by bucket.
    entries: Vec<(u32, u32)>,
}

#[inline(always)]
fn hash(x: u32, shift: u32) -> usize {
    (x.wrapping_mul(0x9E37_79B1) >> shift) as usize
}

#[inline(always)]
fn ld16(b: &[u8], i: usize) -> usize {
    u16::from_le_bytes([b[i], b[i + 1]]) as usize
}

#[inline(always)]
fn ld32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

impl HashFilter {
    /// `windows[k]` (exact bytes) belongs to pattern `ids[k]`.
    pub fn new(windows: &[[u8; 4]], ids: &[u32]) -> HashFilter {
        // Stage-1 pair: minimise the summed frequency of the distinct pair keys.
        let mut pair = 0;
        let mut best_cost = f64::MAX;
        for i in 0..3usize {
            let mut keys: Vec<u16> = windows.iter().map(|w| u16::from_le_bytes([w[i], w[i + 1]])).collect();
            keys.sort_unstable();
            keys.dedup();
            let cost: f64 = keys.iter().map(|&k| (-pair_bits(k as u8, (k >> 8) as u8)).exp2()).sum();
            if cost < best_cost {
                best_cost = cost;
                pair = i;
            }
        }
        let mut table = vec![0u8; 1 << 16];
        for w in windows {
            table[u16::from_le_bytes([w[pair], w[pair + 1]]) as usize] = 0xff;
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
        HashFilter { pair, table, shift, heads, entries }
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
        match self.pair {
            0 => self.find_pair::<0, F>(hay, from, to, &mut f),
            1 => self.find_pair::<1, F>(hay, from, to, &mut f),
            _ => self.find_pair::<2, F>(hay, from, to, &mut f),
        }
    }

    #[inline(always)]
    fn find_pair<const P: usize, F: FnMut(usize, u32)>(&self, hay: &[u8], from: usize, to: usize, f: &mut F) {
        let end = to.min(hay.len().saturating_sub(3));
        let t: &[u8; 1 << 16] = match self.table.as_slice().try_into() {
            Ok(t) => t,
            Err(_) => return,
        };
        let mut q = from;
        while q + 8 <= end {
            let c: &[u8; 11] = match hay[q..q + 11].try_into() {
                Ok(c) => c,
                Err(_) => return,
            };
            let mut bits = 0u32;
            for k in 0..8 {
                bits |= (t[ld16(c, k + P)] as u32) & (1 << k);
            }
            while bits != 0 {
                let k = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                self.stage2(q + k, ld32(c, k), f);
            }
            q += 8;
        }
        while q < end {
            if t[ld16(hay, q + P)] != 0 {
                self.stage2(q, ld32(hay, q), f);
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
