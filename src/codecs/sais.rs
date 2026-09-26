//! Linear-time suffix array construction (SA-IS: Nong, Zhang & Chan, "Two efficient
//! algorithms for linear time suffix array construction", 2009) and the cyclic Burrows-Wheeler
//! transform that bzip2 needs.
//!
//! [`bwt`]: bzip2 sorts the *rotations* of a block. Rotating the block to its lexicographically
//! least rotation T (a necklace, so T = u^k with u a Lyndon word) makes the rotation order of
//! u equal to its suffix order (a property of Lyndon words), so one SA-IS pass over u gives
//! the BWT of the block: each row of u's sorted rotations stands for k identical rows. SA-IS
//! is O(n) whatever the input (no quadratic blowup on repetitive blocks, unlike comparison
//! sorts).

const EMPTY: u32 = u32::MAX;

trait Sym: Copy + PartialEq {
    fn idx(self) -> usize;
}
impl Sym for u8 {
    #[inline(always)]
    fn idx(self) -> usize {
        self as usize
    }
}
impl Sym for u32 {
    #[inline(always)]
    fn idx(self) -> usize {
        self as usize
    }
}

/// S/L suffix types as a bit vector (1 = S-type): 1/8 of the text size, so the random type
/// lookups of the induce loops stay in cache.
#[derive(Default)]
struct Types(Vec<u64>);

impl Types {
    fn reset(&mut self, n: usize) {
        self.0.clear();
        self.0.resize(n.div_ceil(64), 0);
    }
    #[inline(always)]
    fn get(&self, i: usize) -> bool {
        (self.0[i >> 6] >> (i & 63)) & 1 != 0
    }
    /// Calls `f(i)` for every LMS position (S-type, preceded by an L-type) in increasing
    /// order.
    #[inline(always)]
    fn for_each_lms(&self, mut f: impl FnMut(usize)) {
        let mut carry = 1u64; // position -1 counts as S-type: 0 is never LMS
        for (wi, &w) in self.0.iter().enumerate() {
            let mut lms = w & !((w << 1) | carry);
            carry = w >> 63;
            while lms != 0 {
                f(wi * 64 + lms.trailing_zeros() as usize);
                lms &= lms - 1;
            }
        }
    }
}

/// Hints the CPU to fetch the cache line at `p` (never faults).
#[inline(always)]
fn prefetch<T>(p: *const T) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: prefetching is a hint and never faults, whatever the address.
    unsafe {
        std::arch::x86_64::_mm_prefetch::<{ std::arch::x86_64::_MM_HINT_T0 }>(p as *const i8)
    };
    #[cfg(not(target_arch = "x86_64"))]
    let _ = p;
}

/// Prefetch distance (SA entries) in the induce scans.
const PF: usize = 24;

/// Scratch buffers, reused across calls.
#[derive(Default)]
pub(crate) struct SaisScratch {
    stype: Types,
    bkt: Vec<u32>,
    b: Vec<u32>,
    /// Scratch of the recursion level below.
    sub: Option<Box<SaisScratch>>,
}

/// Suffix array of `t` (suffixes compared as if followed by a unique smallest sentinel) into
/// `sa` (`sa.len() == t.len()`; `t.len() < 2^32 - 1`).
pub(crate) fn suffix_array(t: &[u8], sa: &mut [u32], scratch: &mut SaisScratch) {
    assert_eq!(t.len(), sa.len());
    assert!(t.len() < EMPTY as usize);
    if !t.is_empty() {
        sais(t, sa, 256, scratch);
    }
}

fn bucket_starts(bkt: &[u32], b: &mut [u32]) {
    let mut s = 0;
    for (x, &c) in b.iter_mut().zip(bkt) {
        *x = s;
        s += c;
    }
}

fn bucket_ends(bkt: &[u32], b: &mut [u32]) {
    let mut s = 0;
    for (x, &c) in b.iter_mut().zip(bkt) {
        s += c;
        *x = s;
    }
}

/// Induced sorting of the L-type then S-type suffixes from the LMS suffixes in `sa`.
/// (`p - 1` wraps EMPTY and 0 to values >= n, so one comparison skips both.)
fn induce<T: Sym>(t: &[T], sa: &mut [u32], stype: &Types, bkt: &[u32], b: &mut [u32]) {
    let n = t.len();
    bucket_starts(bkt, b);
    // The virtual sentinel induces suffix n-1 (always L-type).
    let c = t[n - 1].idx();
    sa[b[c] as usize] = (n - 1) as u32;
    b[c] += 1;
    for j in 0..n {
        if j + PF < n {
            let f = sa[j + PF].wrapping_sub(1) as usize;
            prefetch(t.as_ptr().wrapping_add(f));
        }
        let q = sa[j].wrapping_sub(1) as usize;
        if q < n && !stype.get(q) {
            let c = t[q].idx();
            sa[b[c] as usize] = q as u32;
            b[c] += 1;
        }
    }
    bucket_ends(bkt, b);
    for j in (0..n).rev() {
        if j >= PF {
            let f = sa[j - PF].wrapping_sub(1) as usize;
            prefetch(t.as_ptr().wrapping_add(f));
        }
        let q = sa[j].wrapping_sub(1) as usize;
        if q < n && stype.get(q) {
            let c = t[q].idx();
            b[c] -= 1;
            sa[b[c] as usize] = q as u32;
        }
    }
}

#[inline(always)]
fn is_lms(stype: &Types, i: usize) -> bool {
    i > 0 && stype.get(i) && !stype.get(i - 1)
}

fn sais<T: Sym>(t: &[T], sa: &mut [u32], k: usize, scratch: &mut SaisScratch) {
    let n = t.len();
    if n == 1 {
        sa[0] = 0;
        return;
    }
    // Classify: S-type if smaller than the next suffix (the last suffix is L-type).
    let mut stype = std::mem::take(&mut scratch.stype);
    stype.reset(n);
    {
        // Branchless right-to-left scan, one bit-vector word at a time.
        let words = &mut stype.0;
        let mut next_s = false;
        let mut i = n - 1;
        while i > 0 {
            i -= 1;
            let (a, b) = (t[i].idx(), t[i + 1].idx());
            next_s = (a < b) | ((a == b) & next_s);
            words[i >> 6] |= (next_s as u64) << (i & 63);
        }
    }
    let mut bkt = std::mem::take(&mut scratch.bkt);
    let mut b = std::mem::take(&mut scratch.b);
    bkt.clear();
    bkt.resize(k, 0);
    b.clear();
    b.resize(k, 0);
    for &c in t {
        bkt[c.idx()] += 1;
    }

    // 1. Sort the LMS substrings: LMS positions at their bucket ends, then induce.
    sa.fill(EMPTY);
    bucket_ends(&bkt, &mut b);
    stype.for_each_lms(|i| {
        let c = t[i].idx();
        b[c] -= 1;
        sa[b[c] as usize] = i as u32;
    });
    induce(t, sa, &stype, &bkt, &mut b);

    // 2. Name them: compact the sorted LMS positions to sa[..m], names into sa[m..] by
    //    position / 2 (LMS positions are at least 2 apart), then gather to sa[n-m..].
    let mut m = 0;
    for j in 0..n {
        let p = sa[j];
        if p != EMPTY && is_lms(&stype, p as usize) {
            sa[m] = p;
            m += 1;
        }
    }
    sa[m..].fill(EMPTY);
    // LMS substring lengths (to the next LMS position, inclusive) into the name slots; the
    // last one reaches the unique sentinel. Equal length + equal characters implies equal
    // types (both end on an S-type), so substrings compare with a plain slice compare.
    const UNIQUE: u32 = u32::MAX - 1;
    {
        let mut last = usize::MAX;
        stype.for_each_lms(|i| {
            if last != usize::MAX {
                sa[m + last / 2] = (i - last + 1) as u32;
            }
            last = i;
        });
        if last != usize::MAX {
            sa[m + last / 2] = UNIQUE;
        }
    }
    let mut names = 0u32;
    let (mut prev, mut prev_len) = (0usize, UNIQUE);
    for j in 0..m {
        let p = sa[j] as usize;
        let len = sa[m + p / 2];
        let same = len == prev_len && len != UNIQUE && t[p..p + len as usize] == t[prev..prev + len as usize];
        if !same {
            names += 1;
        }
        prev = p;
        prev_len = len;
        sa[m + p / 2] = names - 1;
    }
    let mut w = n;
    for i in (m..n).rev() {
        if sa[i] != EMPTY {
            w -= 1;
            sa[w] = sa[i];
        }
    }

    // 3. Sort the LMS suffixes: recurse on the reduced string if names are not unique.
    {
        let (sa1, rest) = sa.split_at_mut(m);
        let s1 = &mut rest[n - 2 * m..];
        if (names as usize) < m {
            let sub = scratch.sub.get_or_insert_with(Default::default);
            sais(&*s1, sa1, names as usize, sub);
        } else {
            for (i, &c) in s1.iter().enumerate() {
                sa1[c as usize] = i as u32;
            }
        }
        // Map ranks back to text positions (s1 := LMS positions in text order).
        let mut j = 0;
        stype.for_each_lms(|i| {
            s1[j] = i as u32;
            j += 1;
        });
        for x in sa1.iter_mut() {
            *x = s1[*x as usize];
        }
    }

    // 4. Induce the full suffix array from the sorted LMS suffixes (placed at their bucket
    //    ends, largest first).
    sa[m..].fill(EMPTY);
    bucket_ends(&bkt, &mut b);
    for i in (0..m).rev() {
        let p = sa[i];
        sa[i] = EMPTY;
        let c = t[p as usize].idx();
        b[c] -= 1;
        sa[b[c] as usize] = p;
    }
    induce(t, sa, &stype, &bkt, &mut b);

    scratch.stype = stype;
    scratch.bkt = bkt;
    scratch.b = b;
}

/// Start of the lexicographically least rotation of `s` (Duval / Lyndon factorisation).
fn least_rotation(s: &[u8]) -> usize {
    let n = s.len();
    let at = |i: usize| if i < n { s[i] } else { s[i - n] };
    let (mut i, mut ans) = (0usize, 0usize);
    while i < n {
        ans = i;
        let (mut j, mut k) = (i + 1, i);
        while j < 2 * n && at(k) <= at(j) {
            if at(k) < at(j) {
                k = i;
            } else {
                k += 1;
            }
            j += 1;
        }
        while i <= k {
            i += j - k;
        }
    }
    ans
}

/// Smallest period `p` of the necklace `t` (t = u^(n/p), u a Lyndon word).
fn necklace_period(t: &[u8]) -> usize {
    let n = t.len();
    let (mut j, mut k) = (1usize, 0usize);
    while j < n && t[k] <= t[j] {
        if t[k] < t[j] {
            k = 0;
        } else {
            k += 1;
        }
        j += 1;
    }
    let p = j - k;
    if n % p == 0 { p } else { n }
}

/// Buffers for [`bwt`], reused across blocks.
#[derive(Default)]
pub(crate) struct BwtScratch {
    rot: Vec<u8>,
    sa: Vec<u32>,
    sais: SaisScratch,
}

impl BwtScratch {
    /// Lends the suffix-array buffer (scratch between [`bwt`] calls) to the caller.
    pub(crate) fn take_sa(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.sa)
    }

    /// Returns a buffer obtained from [`BwtScratch::take_sa`].
    pub(crate) fn put_sa(&mut self, v: Vec<u32>) {
        self.sa = v;
    }
}

/// Cyclic Burrows-Wheeler transform of `s` (as bzip2 defines it: the last column of the
/// sorted rotations) into `out` (resized to `s.len()`); returns the row of `s` itself
/// (bzip2's origPtr). Identical rotations (periodic blocks) are adjacent and interchangeable.
pub(crate) fn bwt(s: &[u8], out: &mut Vec<u8>, scratch: &mut BwtScratch) -> usize {
    let n = s.len();
    out.clear();
    if n == 0 {
        return 0;
    }
    let r = least_rotation(s);
    let rot = &mut scratch.rot;
    rot.clear();
    rot.extend_from_slice(&s[r..]);
    rot.extend_from_slice(&s[..r]);
    let p = necklace_period(rot);
    let reps = n / p;
    let u = &rot[..p];
    let sa = &mut scratch.sa;
    sa.clear();
    sa.resize(p, 0);
    suffix_array(u, sa, &mut scratch.sais);
    // s = rotation of T starting at (n - r) % n, i.e. rotation (n - r) % p of u.
    let s_rot = ((n - r) % n) % p;
    out.reserve(n);
    let mut orig = 0;
    for (row, &a) in sa.iter().enumerate() {
        let a = a as usize;
        if a == s_rot {
            orig = row * reps;
        }
        let c = u[if a == 0 { p - 1 } else { a - 1 }];
        for _ in 0..reps {
            out.push(c);
        }
    }
    orig
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive_sa(t: &[u8]) -> Vec<u32> {
        let mut v: Vec<u32> = (0..t.len() as u32).collect();
        v.sort_by(|&a, &b| t[a as usize..].cmp(&t[b as usize..]));
        v
    }

    fn naive_bwt(s: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // returns (last column, original rotation) of the stably sorted rotations
        let n = s.len();
        let mut rows: Vec<usize> = (0..n).collect();
        let rot = |i: usize| -> Vec<u8> { s[i..].iter().chain(&s[..i]).copied().collect() };
        rows.sort_by_key(|&i| rot(i));
        (rows.iter().map(|&i| s[(i + n - 1) % n]).collect(), s.to_vec())
    }

    fn rng(n: usize, seed: u64, alpha: u8) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x % alpha as u64) as u8
            })
            .collect()
    }

    #[test]
    fn codecs_sais_matches_naive() {
        let mut sc = SaisScratch::default();
        let mut cases: Vec<Vec<u8>> = vec![
            b"a".to_vec(),
            b"banana".to_vec(),
            b"mississippi".to_vec(),
            vec![0; 100],
            b"abababababab".to_vec(),
            b"aabaabaabaab".to_vec(),
        ];
        for (i, alpha) in [2u8, 3, 4, 26, 255].iter().enumerate() {
            for n in [2usize, 3, 10, 100, 1000, 5000] {
                cases.push(rng(n, (i * 1000 + n) as u64, *alpha));
            }
        }
        for t in &cases {
            let mut sa = vec![0u32; t.len()];
            suffix_array(t, &mut sa, &mut sc);
            assert_eq!(sa, naive_sa(t), "{:?}", &t[..t.len().min(20)]);
        }
    }

    #[test]
    fn codecs_sais_bwt_matches_rotation_sort() {
        let mut sc = BwtScratch::default();
        let mut cases: Vec<Vec<u8>> = vec![
            b"a".to_vec(),
            b"ab".to_vec(),
            b"ba".to_vec(),
            b"banana".to_vec(),
            b"abab".to_vec(),
            b"baba".to_vec(),
            vec![7; 50],
            b"abcabcabc".to_vec(),
            b"cabcabcab".to_vec(),
            b"aabaab".to_vec(),
        ];
        for (i, alpha) in [2u8, 3, 26].iter().enumerate() {
            for n in [2usize, 5, 17, 200, 700] {
                cases.push(rng(n, (i * 77 + n) as u64, *alpha));
            }
        }
        for s in &cases {
            let mut out = Vec::new();
            let orig = bwt(s, &mut out, &mut sc);
            let (want, _) = naive_bwt(s);
            assert_eq!(out, want, "{s:?}");
            // origPtr row really is the original string
            let n = s.len();
            let mut rows: Vec<usize> = (0..n).collect();
            let rot = |i: usize| -> Vec<u8> { s[i..].iter().chain(&s[..i]).copied().collect() };
            rows.sort_by_key(|&i| rot(i));
            assert_eq!(rot(rows[orig]), *s, "orig for {s:?}");
        }
    }
}
