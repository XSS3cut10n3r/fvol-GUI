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
    /// `members[bucket_off[b]..bucket_off[b+1]]` are the patterns of bucket `b`.
    bucket_off: [u32; NB + 1],
    members: Vec<Member>,
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
}

const ALL: Nib = Nib { lo: 0xffff, hi: 0xffff };


/// Fast weighted sum over a nibble-product set: `A[h][lo & 0xff] + B[h][lo >> 8]`.
struct NibTable {
    a: Vec<[f64; 256]>,
    b: Vec<[f64; 256]>,
}

impl NibTable {
    fn new() -> NibTable {
        let mut a = vec![[0.0; 256]; 16];
        let mut b = vec![[0.0; 256]; 16];
        for h in 0..16 {
            for m in 0..256usize {
                for l in 0..8 {
                    if m >> l & 1 != 0 {
                        a[h][m] += BYTE_FREQ[h << 4 | l] as f64 / (1u64 << 20) as f64;
                        b[h][m] += BYTE_FREQ[h << 4 | (l + 8)] as f64 / (1u64 << 20) as f64;
                    }
                }
            }
        }
        NibTable { a, b }
    }

    fn freq(&self, n: Nib) -> f64 {
        if n.lo == 0xffff && n.hi == 0xffff {
            return 1.0;
        }
        let (la, lb) = ((n.lo & 0xff) as usize, (n.lo >> 8) as usize);
        let mut f = 0.0;
        let mut hs = n.hi;
        while hs != 0 {
            let h = hs.trailing_zeros() as usize;
            hs &= hs - 1;
            f += self.a[h][la] + self.b[h][lb];
        }
        f
    }

    fn prob(&self, w: &[Nib; MAX_WINDOW], m: usize) -> f64 {
        w.iter().take(m).map(|&n| self.freq(n)).product()
    }
}

fn union(a: &[Nib; MAX_WINDOW], b: &[Nib; MAX_WINDOW]) -> [Nib; MAX_WINDOW] {
    let mut u = *a;
    for j in 0..MAX_WINDOW {
        u[j] = u[j].union(b[j]);
    }
    u
}

type Cluster = ([Nib; MAX_WINDOW], Vec<usize>);

/// Merges clusters until `NB` remain, always the pair whose union adds the least
/// cost. Each active cluster caches its best partner, so a merge only rescans the
/// rows that pointed at the merged pair (about O(n^2) cost evaluations overall).
fn cluster(mut cl: Vec<Cluster>, cost: &dyn Fn(&[Nib; MAX_WINDOW], usize) -> f64) -> Vec<Cluster> {
    let n = cl.len();
    let mut active = vec![true; n];
    let mut own: Vec<f64> = cl.iter().map(|c| cost(&c.0, c.1.len())).collect();
    let delta = |cl: &[Cluster], own: &[f64], a: usize, b: usize| {
        cost(&union(&cl[a].0, &cl[b].0), cl[a].1.len() + cl[b].1.len()) - own[a] - own[b]
    };
    let mut best: Vec<(f64, usize)> = vec![(f64::INFINITY, usize::MAX); n];
    let rescan = |cl: &[Cluster], own: &[f64], active: &[bool], a: usize| -> (f64, usize) {
        let mut r = (f64::INFINITY, usize::MAX);
        for b in 0..cl.len() {
            if b != a && active[b] {
                let d = delta(cl, own, a, b);
                if d < r.0 {
                    r = (d, b);
                }
            }
        }
        r
    };
    for a in 0..n {
        best[a] = rescan(&cl, &own, &active, a);
    }
    let mut left = n;
    while left > NB {
        let mut a = usize::MAX;
        for x in 0..n {
            if active[x] && best[x].1 != usize::MAX && (a == usize::MAX || best[x].0 < best[a].0) {
                a = x;
            }
        }
        if a == usize::MAX {
            break;
        }
        let b = best[a].1;
        let taken = std::mem::take(&mut cl[b].1);
        let nb = cl[b].0;
        cl[a].0 = union(&cl[a].0, &nb);
        cl[a].1.extend(taken);
        active[b] = false;
        own[a] = cost(&cl[a].0, cl[a].1.len());
        left -= 1;
        best[a] = rescan(&cl, &own, &active, a);
        for x in 0..n {
            if !active[x] || x == a {
                continue;
            }
            if best[x].1 == a || best[x].1 == b {
                best[x] = rescan(&cl, &own, &active, x);
            } else {
                let d = delta(&cl, &own, x, a);
                if d < best[x].0 {
                    best[x] = (d, a);
                }
            }
        }
    }
    cl.into_iter().zip(active).filter(|(_, act)| *act).map(|(c, _)| c).collect()
}

/// Exact window test run on each bucket member before reporting it:
/// `(word | fold) & mask == val` on the 4 bytes at the candidate position.
#[derive(Clone, Copy, Debug, Default)]
struct Member {
    id: u32,
    val: u32,
    fold: u32,
    mask: u32,
}

impl Member {
    fn new(id: u32, w: &[ByteSet]) -> Member {
        let (mut val, mut fold, mut mask) = (0u32, 0u32, 0u32);
        for (j, s) in w.iter().take(MAX_WINDOW).enumerate() {
            let v: Vec<u8> = s.iter().collect();
            let sh = 8 * j;
            match v.len() {
                1 => {
                    val |= (v[0] as u32) << sh;
                    mask |= 0xff << sh;
                }
                2 if v[0] ^ v[1] == 0x20 => {
                    val |= ((v[0] | 0x20) as u32) << sh;
                    fold |= 0x20 << sh;
                    mask |= 0xff << sh;
                }
                _ => {}
            }
        }
        Member { id, val, fold, mask }
    }
}

/// Relative cost of a bucket hit per member (inline window test) vs the hit itself.
const MEMBER_COST: f64 = 0.5;

impl Teddy {
    /// `windows[i]` is the window of pattern id `ids[i]` (1..=4 non-empty byte sets).
    pub fn new(windows: &[Vec<ByteSet>], ids: &[u32]) -> Teddy {
        let nt = NibTable::new();
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
        // Agglomerative clustering into NB buckets: repeatedly merge the two clusters
        // whose union adds the least expected work (hit probability x member count).
        let cost = |n: &[Nib; MAX_WINDOW], k: usize| nt.prob(n, m) * (1.0 + MEMBER_COST * k as f64);
        let mut clusters: Vec<([Nib; MAX_WINDOW], Vec<usize>)> = Vec::new();
        for (i, n) in nibs.iter().enumerate() {
            match clusters.iter_mut().find(|c| c.0 == *n) {
                Some(c) => c.1.push(i),
                None => clusters.push((*n, vec![i])),
            }
        }
        if clusters.len() > NB {
            clusters = cluster(clusters, &cost);
        }
        let mut lo = [[0u8; 16]; MAX_WINDOW];
        let mut hi = [[0u8; 16]; MAX_WINDOW];
        for (b, (n, _)) in clusters.iter().enumerate() {
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
        let mut bucket_off = [0u32; NB + 1];
        let mut members = Vec::new();
        for (b, off) in bucket_off.iter_mut().enumerate().take(NB) {
            *off = members.len() as u32;
            if let Some((_, list)) = clusters.get(b) {
                for &i in list {
                    members.push(Member::new(ids[i], &windows[i]));
                }
            }
        }
        bucket_off[NB] = members.len() as u32;
        Teddy { m, lo, hi, bucket_off, members }
    }

    /// Estimated fraction of haystack positions that produce a bucket hit.
    pub fn estimated_rate(&self) -> f64 {
        let nt = NibTable::new();
        let mut total = 0.0;
        for b in 0..NB {
            if self.bucket_off[b + 1] == self.bucket_off[b] {
                continue;
            }
            let mut n = [ALL; MAX_WINDOW];
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
                *nj = Nib { lo, hi };
            }
            total += nt.prob(&n, self.m);
        }
        total
    }

    #[inline(always)]
    fn bucket(&self, b: usize) -> &[Member] {
        &self.members[self.bucket_off[b] as usize..self.bucket_off[b + 1] as usize]
    }

    #[inline(always)]
    fn emit<const DIFF: bool, F: FnMut(usize, u32)>(&self, hay: &[u8], q: usize, mut bits: u8, f: &mut F) {
        let x = match hay.get(q..q + 5) {
            Some(b) if DIFF => u32::from_le_bytes([b[0] ^ b[1], b[1] ^ b[2], b[2] ^ b[3], b[3] ^ b[4]]),
            Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            None => {
                let mut w = [0u8; 4];
                for (j, v) in w.iter_mut().enumerate() {
                    *v = dbyte::<DIFF>(hay, q + j);
                }
                u32::from_le_bytes(w)
            }
        };
        while bits != 0 {
            let b = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            for mb in self.bucket(b) {
                if (x | mb.fold) & mb.mask == mb.val {
                    f(q, mb.id);
                }
            }
        }
    }

    #[inline(always)]
    fn scalar_bits<const DIFF: bool>(&self, hay: &[u8], q: usize) -> u8 {
        let mut acc = 0xffu8;
        for j in 0..self.m {
            // Past the end: any byte (the caller's bounds check rejects the candidate).
            let b = dbyte::<DIFF>(hay, q + j) as usize;
            acc &= self.lo[j][b & 15] & self.hi[j][b >> 4];
        }
        acc
    }

    /// Calls `f(q, id)` for every position `q` in `[from, to)` whose window matches the
    /// buckets of pattern `id` (a superset of the true window matches).
    #[inline]
    pub fn find<F: FnMut(usize, u32)>(&self, hay: &[u8], from: usize, to: usize, f: F) {
        self.find_live(hay, from, to, 0xff, f)
    }

    /// Ids of the patterns in each bucket.
    pub fn buckets(&self) -> Vec<Vec<u32>> {
        (0..NB).map(|b| self.bucket(b).iter().map(|m| m.id).collect()).collect()
    }

    /// [`Teddy::find`] restricted to the buckets set in `live` (bit b = bucket b).
    #[inline]
    pub fn find_live<F: FnMut(usize, u32)>(&self, hay: &[u8], from: usize, to: usize, live: u8, f: F) {
        self.find_impl::<false, F>(hay, from, to, live, f)
    }

    /// Search the difference stream `D[i] = hay[i] ^ hay[i + 1]` (computed on the fly;
    /// positions are D positions, `D` has `hay.len() - 1` bytes).
    #[inline]
    pub fn find_diff<F: FnMut(usize, u32)>(&self, hay: &[u8], from: usize, to: usize, live: u8, f: F) {
        let to = to.min(hay.len().saturating_sub(1));
        self.find_impl::<true, F>(hay, from, to, live, f)
    }

    #[inline]
    fn find_impl<const DIFF: bool, F: FnMut(usize, u32)>(&self, hay: &[u8], from: usize, to: usize, live: u8, mut f: F) {
        if live == 0 {
            return;
        }
        let to = to.min(hay.len());
        let mut q = from;
        #[cfg(target_arch = "x86_64")]
        {
            if has_avx2() && !force_scalar() {
                let mut cands = [0u64; CAND_CAP];
                loop {
                    // SAFETY: AVX2 availability checked at runtime.
                    let (next, k) = unsafe {
                        match self.m {
                            1 => core_avx2::<1, DIFF>(&self.lo, &self.hi, live, hay, q, to, &mut cands),
                            2 => core_avx2::<2, DIFF>(&self.lo, &self.hi, live, hay, q, to, &mut cands),
                            3 => core_avx2::<3, DIFF>(&self.lo, &self.hi, live, hay, q, to, &mut cands),
                            _ => core_avx2::<4, DIFF>(&self.lo, &self.hi, live, hay, q, to, &mut cands),
                        }
                    };
                    for &c in &cands[..k.min(CAND_CAP)] {
                        self.emit::<DIFF, F>(hay, (c >> 8) as usize, c as u8, &mut f);
                    }
                    if next == q {
                        break;
                    }
                    q = next;
                }
            }
        }
        while q < to {
            let bits = self.scalar_bits::<DIFF>(hay, q) & live;
            if bits != 0 {
                self.emit::<DIFF, F>(hay, q, bits, &mut f);
            }
            q += 1;
        }
    }
}

/// Byte `i` of the raw (`DIFF = false`) or difference stream; 0 past the end.
#[inline(always)]
fn dbyte<const DIFF: bool>(hay: &[u8], i: usize) -> u8 {
    if DIFF {
        match (hay.get(i), hay.get(i + 1)) {
            (Some(a), Some(b)) => a ^ b,
            _ => 0,
        }
    } else {
        hay.get(i).copied().unwrap_or(0)
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
unsafe fn core_avx2<const M: usize, const DIFF: bool>(
    lo_t: &[[u8; 16]; MAX_WINDOW],
    hi_t: &[[u8; 16]; MAX_WINDOW],
    live: u8,
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
    // Dead buckets never match: clear them from the first table.
    lo[0] = _mm256_and_si256(lo[0], _mm256_set1_epi8(live as i8));
    // Byte vector of the searched stream at `p` (D = hay[p..] ^ hay[p+1..] when DIFF).
    let load = |p: usize| -> __m256i {
        // SAFETY: the caller guarantees p + 32 + DIFF <= n.
        unsafe {
            let v = _mm256_loadu_si256(ptr.add(p) as *const __m256i);
            if DIFF { _mm256_xor_si256(v, _mm256_loadu_si256(ptr.add(p + 1) as *const __m256i)) } else { v }
        }
    };
    // The caller guarantees p + 32 + M - 1 + DIFF <= n.
    let classify = |p: usize| -> __m256i {
        let v = load(p);
        let mut acc = _mm256_and_si256(
            _mm256_shuffle_epi8(lo[0], _mm256_and_si256(v, nib)),
            _mm256_shuffle_epi8(hi[0], _mm256_and_si256(_mm256_srli_epi16(v, 4), nib)),
        );
        let mut j = 1;
        while j < M {
            let v = load(p + j);
            let r = _mm256_and_si256(
                _mm256_shuffle_epi8(lo[j], _mm256_and_si256(v, nib)),
                _mm256_shuffle_epi8(hi[j], _mm256_and_si256(_mm256_srli_epi16(v, 4), nib)),
            );
            acc = _mm256_and_si256(acc, r);
            j += 1;
        }
        acc
    };
    let mut k = 0usize;
    let mut buf = [0u8; 64];
    // Loads touch [q, q + 64 + M - 1).
    let extra = M - 1 + DIFF as usize;
    while q + 64 <= to && q + 64 + extra <= n && k + 64 <= CAND_CAP {
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
    while q + 32 <= to && q + 32 + extra <= n && k + 32 <= CAND_CAP {
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

/// Tests can force the portable paths (results are identical by design).
#[cfg(test)]
pub(crate) static FORCE_SCALAR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[inline(always)]
pub(crate) fn force_scalar() -> bool {
    #[cfg(test)]
    {
        FORCE_SCALAR.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(not(test))]
    {
        false
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
