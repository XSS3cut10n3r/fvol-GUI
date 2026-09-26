//! Teddy: SIMD multi-literal candidate search (the Hyperscan idea, built from scratch).
//!
//! Every pattern contributes a *window* of 1..=4 byte sets (usually its rarest 4-byte
//! substring; nocase letters are 2-byte sets). Patterns are grouped into 8 buckets; for
//! window position `j` two 16-entry tables map the low / high nibble of a haystack byte
//! to the set of buckets that accept it. For 32 haystack positions at once:
//!
//! ```text
//! acc = AND_j ( pshufb(LO[j], hay[q+j] & 15) & pshufb(HI[j], hay[q+j] >> 4) )
//! ```
//!
//! A non-zero byte of `acc` means "some pattern of these buckets may have its window at
//! q". The caller verifies. Buckets are filled greedily so the nibble cross products
//! (the false positives) stay small, weighting bytes with their frequency in memory.

use crate::yara::regex::hir::ByteSet;
use crate::yara::regex::literal::BYTE_FREQ;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// Maximum window length.
pub const MAX_WINDOW: usize = 4;
/// Buckets.
const NB: usize = 8;

/// Candidate search over windows.
#[derive(Clone, Debug)]
pub struct Teddy {
    /// Number of window positions in use (1..=4).
    m: usize,
    lo: [[u8; 16]; MAX_WINDOW],
    hi: [[u8; 16]; MAX_WINDOW],
    /// `members[bucket_off[b]..bucket_off[b+1]]` are the ids of bucket `b`.
    bucket_off: [u32; NB + 1],
    members: Vec<u32>,
}

/// Nibble projection of a bucket position: (low nibbles, high nibbles) as bitmasks.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Nib {
    lo: u16,
    hi: u16,
}

impl Nib {
    fn of(s: &ByteSet) -> Nib {
        let mut n = Nib::default();
        for b in s.iter() {
            n.lo |= 1 << (b & 15);
            n.hi |= 1 << (b >> 4);
        }
        n
    }
    fn union(self, o: Nib) -> Nib {
        Nib { lo: self.lo | o.lo, hi: self.hi | o.hi }
    }
    /// Estimated probability that a memory byte falls in the accepted product set.
    fn freq(self, table: &[[f64; 16]; 16]) -> f64 {
        if self.lo == 0xffff && self.hi == 0xffff {
            return 1.0;
        }
        let mut f = 0.0;
        for h in 0..16 {
            if self.hi >> h & 1 != 0 {
                for l in 0..16 {
                    if self.lo >> l & 1 != 0 {
                        f += table[h][l];
                    }
                }
            }
        }
        f
    }
}

const ALL: Nib = Nib { lo: 0xffff, hi: 0xffff };

fn bucket_cost(b: &[Nib; MAX_WINDOW], m: usize, table: &[[f64; 16]; 16]) -> f64 {
    let mut c = 1.0;
    for n in b.iter().take(m) {
        c *= n.freq(table);
    }
    c
}

impl Teddy {
    /// `windows[i]` is the window of pattern id `ids[i]` (1..=4 non-empty byte sets).
    pub fn new(windows: &[Vec<ByteSet>], ids: &[u32]) -> Teddy {
        let mut table = [[0.0f64; 16]; 16];
        for b in 0..256 {
            table[b >> 4][b & 15] = BYTE_FREQ[b] as f64 / (1u64 << 20) as f64;
        }
        let m = windows.iter().map(|w| w.len().clamp(1, MAX_WINDOW)).max().unwrap_or(1);
        let nibs: Vec<[Nib; MAX_WINDOW]> = windows
            .iter()
            .map(|w| {
                let mut a = [ALL; MAX_WINDOW];
                for (j, s) in w.iter().take(MAX_WINDOW).enumerate() {
                    a[j] = Nib::of(s);
                }
                a
            })
            .collect();
        let own: Vec<f64> = nibs.iter().map(|n| bucket_cost(n, m, &table)).collect();
        // Greedy assignment, most expensive (least selective) windows first.
        let mut order: Vec<usize> = (0..windows.len()).collect();
        order.sort_by(|&a, &b| own[b].partial_cmp(&own[a]).unwrap_or(std::cmp::Ordering::Equal).then(a.cmp(&b)));
        let mut bk: [Option<[Nib; MAX_WINDOW]>; NB] = [None; NB];
        let mut assign: Vec<Vec<u32>> = vec![Vec::new(); NB];
        for &i in &order {
            let mut best = 0usize;
            let mut best_delta = f64::INFINITY;
            for (b, slot) in bk.iter().enumerate() {
                let delta = match slot {
                    None => own[i],
                    Some(cur) => {
                        let mut u = *cur;
                        for j in 0..MAX_WINDOW {
                            u[j] = u[j].union(nibs[i][j]);
                        }
                        // Scale by the number of patterns sharing the bucket: every
                        // candidate costs one verification per member.
                        let k = assign[b].len() as f64;
                        bucket_cost(&u, m, &table) * (k + 1.0) - bucket_cost(cur, m, &table) * k
                    }
                };
                if delta < best_delta {
                    best_delta = delta;
                    best = b;
                }
            }
            bk[best] = Some(match bk[best] {
                None => nibs[i],
                Some(cur) => {
                    let mut u = cur;
                    for j in 0..MAX_WINDOW {
                        u[j] = u[j].union(nibs[i][j]);
                    }
                    u
                }
            });
            assign[best].push(ids[i]);
        }
        let mut lo = [[0u8; 16]; MAX_WINDOW];
        let mut hi = [[0u8; 16]; MAX_WINDOW];
        for (b, slot) in bk.iter().enumerate() {
            if let Some(n) = slot {
                for j in 0..MAX_WINDOW {
                    for x in 0..16 {
                        if n[j].lo >> x & 1 != 0 {
                            lo[j][x] |= 1 << b;
                        }
                        if n[j].hi >> x & 1 != 0 {
                            hi[j][x] |= 1 << b;
                        }
                    }
                }
            }
        }
        let mut bucket_off = [0u32; NB + 1];
        let mut members = Vec::new();
        for b in 0..NB {
            bucket_off[b] = members.len() as u32;
            members.extend_from_slice(&assign[b]);
        }
        bucket_off[NB] = members.len() as u32;
        Teddy { m, lo, hi, bucket_off, members }
    }

    /// Estimated fraction of haystack positions that produce a candidate.
    pub fn estimated_rate(&self) -> f64 {
        let mut table = [[0.0f64; 16]; 16];
        for b in 0..256 {
            table[b >> 4][b & 15] = BYTE_FREQ[b] as f64 / (1u64 << 20) as f64;
        }
        let mut total = 0.0;
        for b in 0..NB {
            let mut n = [ALL; MAX_WINDOW];
            let mut any = false;
            for (j, nj) in n.iter_mut().enumerate() {
                let mut lo = 0u16;
                let mut hi = 0u16;
                for x in 0..16 {
                    if self.lo[j][x] >> b & 1 != 0 {
                        lo |= 1 << x;
                    }
                    if self.hi[j][x] >> b & 1 != 0 {
                        hi |= 1 << x;
                    }
                }
                any |= lo != 0;
                *nj = Nib { lo, hi };
            }
            if any {
                total += bucket_cost(&n, self.m, &table) * (self.bucket_off[b + 1] - self.bucket_off[b]) as f64;
            }
        }
        total
    }

    #[inline(always)]
    fn bucket(&self, b: usize) -> &[u32] {
        &self.members[self.bucket_off[b] as usize..self.bucket_off[b + 1] as usize]
    }

    #[inline(always)]
    fn emit<F: FnMut(usize, u32)>(&self, q: usize, mut bits: u8, f: &mut F) {
        while bits != 0 {
            let b = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            for &id in self.bucket(b) {
                f(q, id);
            }
        }
    }

    #[inline(always)]
    fn scalar_bits(&self, hay: &[u8], q: usize) -> u8 {
        let mut acc = 0xffu8;
        for j in 0..self.m {
            // Past the end: any byte (the caller's bounds check rejects the candidate).
            let b = hay.get(q + j).copied().unwrap_or(0) as usize;
            acc &= self.lo[j][b & 15] & self.hi[j][b >> 4];
        }
        acc
    }

    /// Calls `f(q, id)` for every position `q` in `[from, to)` whose window matches the
    /// buckets of pattern `id` (a superset of the true window matches).
    #[inline]
    pub fn find<F: FnMut(usize, u32)>(&self, hay: &[u8], from: usize, to: usize, mut f: F) {
        let to = to.min(hay.len());
        let mut q = from;
        #[cfg(target_arch = "x86_64")]
        {
            if has_avx2() {
                let mut cands = [0u64; CAND_CAP];
                loop {
                    // SAFETY: AVX2 availability checked at runtime.
                    let (next, k) = unsafe {
                        match self.m {
                            1 => core_avx2::<1>(&self.lo, &self.hi, hay, q, to, &mut cands),
                            2 => core_avx2::<2>(&self.lo, &self.hi, hay, q, to, &mut cands),
                            3 => core_avx2::<3>(&self.lo, &self.hi, hay, q, to, &mut cands),
                            _ => core_avx2::<4>(&self.lo, &self.hi, hay, q, to, &mut cands),
                        }
                    };
                    for &c in &cands[..k.min(CAND_CAP)] {
                        self.emit((c >> 8) as usize, c as u8, &mut f);
                    }
                    if next == q {
                        break;
                    }
                    q = next;
                }
            }
        }
        while q < to {
            let bits = self.scalar_bits(hay, q);
            if bits != 0 {
                self.emit(q, bits, &mut f);
            }
            q += 1;
        }
    }
}

/// Candidate buffer of the SIMD core: `position << 8 | bucket bits`.
const CAND_CAP: usize = 256;

/// The SIMD loop, kept out of line so the eight nibble tables stay in registers:
/// processes 64 positions per step from `q` while all loads stay inside `hay` and
/// the candidate buffer has room. Returns (next position, candidates written).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline(never)]
unsafe fn core_avx2<const M: usize>(
    lo_t: &[[u8; 16]; MAX_WINDOW],
    hi_t: &[[u8; 16]; MAX_WINDOW],
    hay: &[u8],
    mut q: usize,
    to: usize,
    out: &mut [u64; CAND_CAP],
) -> (usize, usize) {
    let n = hay.len();
    let ptr = hay.as_ptr();
    let nib = _mm256_set1_epi8(0x0f);
    let zero = _mm256_setzero_si256();
    let mut lo = [zero; MAX_WINDOW];
    let mut hi = [zero; MAX_WINDOW];
    for j in 0..M {
        // SAFETY: 16-byte arrays; unaligned loads.
        unsafe {
            lo[j] = _mm256_broadcastsi128_si256(_mm_loadu_si128(lo_t[j].as_ptr() as *const __m128i));
            hi[j] = _mm256_broadcastsi128_si256(_mm_loadu_si128(hi_t[j].as_ptr() as *const __m128i));
        }
    }
    let classify = |p: usize| -> __m256i {
        // SAFETY: the caller guarantees p + 32 + M - 1 <= n.
        unsafe {
            let v = _mm256_loadu_si256(ptr.add(p) as *const __m256i);
            let mut acc = _mm256_and_si256(
                _mm256_shuffle_epi8(lo[0], _mm256_and_si256(v, nib)),
                _mm256_shuffle_epi8(hi[0], _mm256_and_si256(_mm256_srli_epi16(v, 4), nib)),
            );
            let mut j = 1;
            while j < M {
                let v = _mm256_loadu_si256(ptr.add(p + j) as *const __m256i);
                let r = _mm256_and_si256(
                    _mm256_shuffle_epi8(lo[j], _mm256_and_si256(v, nib)),
                    _mm256_shuffle_epi8(hi[j], _mm256_and_si256(_mm256_srli_epi16(v, 4), nib)),
                );
                acc = _mm256_and_si256(acc, r);
                j += 1;
            }
            acc
        }
    };
    let mut k = 0usize;
    let mut buf = [0u8; 64];
    // Loads touch [q, q + 64 + M - 1).
    while q + 64 <= to && q + 64 + M - 1 <= n && k + 64 <= CAND_CAP {
        let a = classify(q);
        let b = classify(q + 32);
        let ma = !(_mm256_movemask_epi8(_mm256_cmpeq_epi8(a, zero)) as u32) as u64;
        let mb = !(_mm256_movemask_epi8(_mm256_cmpeq_epi8(b, zero)) as u32) as u64;
        let mut mask = ma | mb << 32;
        if mask != 0 {
            // SAFETY: 64-byte buffer.
            unsafe {
                _mm256_storeu_si256(buf.as_mut_ptr() as *mut __m256i, a);
                _mm256_storeu_si256(buf.as_mut_ptr().add(32) as *mut __m256i, b);
            }
            while mask != 0 {
                let i = mask.trailing_zeros() as usize;
                mask &= mask - 1;
                out[k] = ((q + i) as u64) << 8 | buf[i] as u64;
                k += 1;
            }
        }
        q += 64;
    }
    while q + 32 <= to && q + 32 + M - 1 <= n && k + 32 <= CAND_CAP {
        let a = classify(q);
        let mut mask = !(_mm256_movemask_epi8(_mm256_cmpeq_epi8(a, zero)) as u32);
        if mask != 0 {
            // SAFETY: 64-byte buffer.
            unsafe { _mm256_storeu_si256(buf.as_mut_ptr() as *mut __m256i, a) };
            while mask != 0 {
                let i = mask.trailing_zeros() as usize;
                mask &= mask - 1;
                out[k] = ((q + i) as u64) << 8 | buf[i] as u64;
                k += 1;
            }
        }
        q += 32;
    }
    (q, k)
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

    fn win(p: &[u8]) -> Vec<ByteSet> {
        p.iter().take(MAX_WINDOW).map(|&b| ByteSet::single(b)).collect()
    }

    #[test]
    fn yara_teddy_superset() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..100 {
            let np = 1 + (rnd() % 40) as usize;
            let pats: Vec<Vec<u8>> = (0..np)
                .map(|_| (0..1 + rnd() % 4).map(|_| b"ab\x00c"[(rnd() % 4) as usize]).collect())
                .collect();
            let wins: Vec<Vec<ByteSet>> = pats.iter().map(|p| win(p)).collect();
            let ids: Vec<u32> = (0..np as u32).collect();
            let t = Teddy::new(&wins, &ids);
            let hay: Vec<u8> = (0..200 + round).map(|_| b"ab\x00cd"[(rnd() % 5) as usize]).collect();
            let mut got = std::collections::HashSet::new();
            t.find(&hay, 0, hay.len(), |q, id| {
                got.insert((q, id));
            });
            for (i, p) in pats.iter().enumerate() {
                for q in 0..hay.len() {
                    if hay[q..].starts_with(p) {
                        assert!(got.contains(&(q, i as u32)), "round {round} pat {i} at {q}");
                    }
                }
            }
            // With few patterns (one per bucket) and full windows the candidates are exact.
            if np <= 8 && pats.iter().all(|p| p.len() == 4) {
                for &(q, id) in &got {
                    assert!(hay[q..].starts_with(&pats[id as usize]));
                }
            }
        }
    }

    /// Core throughput on an in-cache-ish 32 MiB buffer with no candidates.
    #[test]
    #[ignore]
    fn yara_teddy_core_speed() {
        let hay: Vec<u8> = (0..std::env::var("TEDDY_MB").ok().and_then(|v| v.parse::<usize>().ok()).unwrap_or(32) << 20).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8 & 0x7f).collect();
        let t4 = Teddy::new(&[win(b"\xf1\xf2\xf3\xf4")], &[0]);
        let t3 = Teddy::new(&[win(b"\xf1\xf2\xf3")], &[0]);
        let t2 = Teddy::new(&[win(b"\xf1\xf2")], &[0]);
        for i in 0..9 {
            let t = [&t4, &t3, &t2][i % 3];
            let reps = (512usize << 20) / hay.len();
            let t0 = std::time::Instant::now();
            let mut n = 0usize;
            for _ in 0..reps {
                t.find(&hay, 0, hay.len(), |_, _| n += 1);
            }
            let dt = t0.elapsed().as_secs_f64();
            eprintln!("teddy core m={}: {:.1} GB/s ({n})", t.m, (hay.len() * reps) as f64 / dt / 1e9);
        }
    }
}
