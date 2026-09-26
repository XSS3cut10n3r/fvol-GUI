//! Fast byte / substring search primitives (memchr, memchr2, memchr3, memrchr, memmem,
//! byte-set search) used by the regex and YARA engines.
//!
//! x86_64: AVX2 when available at runtime (or statically enabled), SSE2 otherwise.
//! Other targets: a portable SWAR implementation. Substring search uses a SIMD
//! "rare byte pair" prefilter (ranked with byte frequencies measured on real memory
//! images) and falls back to Two-Way when the prefilter degenerates, so worst-case
//! time stays linear.

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

// ---------------------------------------------------------------------------------------
// CPU feature detection
// ---------------------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------------------
// Byte frequency ranks (0 = rarest, 255 = most common), measured on a Windows 10 memory
// image. Used to pick the rarest bytes of a needle for the substring prefilter.
// ---------------------------------------------------------------------------------------

pub(crate) const BYTE_RANK: [u8; 256] = [
    255, 252, 248, 231, 235, 220, 199, 197, 242, 183, 187, 165, 249, 188, 139, 245, 236, 171,
    146, 125, 150, 213, 95, 111, 206, 86, 59, 54, 89, 43, 68, 143, 244, 120, 133, 91, 246, 99,
    58, 37, 210, 124, 46, 70, 107, 164, 194, 88, 234, 204, 157, 212, 163, 140, 149, 108, 221,
    185, 144, 160, 84, 96, 65, 119, 229, 237, 151, 196, 233, 211, 162, 127, 253, 224, 41, 69,
    239, 202, 126, 105, 227, 77, 101, 178, 172, 159, 158, 179, 148, 18, 55, 82, 184, 73, 123,
    191, 180, 218, 117, 201, 203, 241, 207, 134, 170, 219, 25, 97, 208, 168, 215, 222, 214, 93,
    216, 217, 243, 209, 131, 135, 176, 155, 5, 9, 83, 38, 66, 223, 230, 142, 60, 226, 193, 225,
    24, 22, 153, 247, 85, 251, 75, 238, 14, 44, 190, 3, 2, 7, 53, 26, 13, 8, 90, 115, 11, 4, 47,
    12, 28, 21, 175, 56, 45, 51, 64, 42, 27, 36, 110, 29, 61, 16, 63, 17, 32, 35, 154, 62, 33,
    34, 67, 39, 161, 94, 169, 141, 177, 71, 113, 78, 80, 87, 232, 189, 109, 186, 181, 72, 106,
    167, 156, 147, 52, 102, 250, 50, 128, 104, 195, 92, 122, 112, 74, 76, 118, 136, 166, 114,
    116, 103, 40, 182, 20, 15, 198, 81, 49, 10, 132, 0, 6, 1, 240, 173, 19, 138, 152, 23, 30, 48,
    200, 100, 79, 192, 57, 31, 130, 98, 174, 145, 129, 228, 121, 137, 205, 254,
];

// ---------------------------------------------------------------------------------------
// memchr family
// ---------------------------------------------------------------------------------------

/// Index of the first occurrence of `n1` in `hay`.
#[inline]
pub fn memchr(n1: u8, hay: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if hay.len() >= 32 && has_avx2() {
            // SAFETY: AVX2 availability checked above.
            return unsafe { avx2::memchr(n1, hay) };
        }
        if hay.len() >= 16 {
            // SAFETY: SSE2 is part of the x86_64 baseline.
            return unsafe { sse2::memchr(n1, hay) };
        }
    }
    fallback::memchr(n1, hay)
}

/// Index of the first occurrence of `n1` or `n2` in `hay`.
#[inline]
pub fn memchr2(n1: u8, n2: u8, hay: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if hay.len() >= 32 && has_avx2() {
            // SAFETY: AVX2 availability checked above.
            return unsafe { avx2::memchr2(n1, n2, hay) };
        }
    }
    hay.iter().position(|&b| b == n1 || b == n2)
}

/// Index of the first occurrence of `n1`, `n2` or `n3` in `hay`.
#[inline]
pub fn memchr3(n1: u8, n2: u8, n3: u8, hay: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if hay.len() >= 32 && has_avx2() {
            // SAFETY: AVX2 availability checked above.
            return unsafe { avx2::memchr3(n1, n2, n3, hay) };
        }
    }
    hay.iter().position(|&b| b == n1 || b == n2 || b == n3)
}

/// Index of the last occurrence of `n1` in `hay`.
#[inline]
pub fn memrchr(n1: u8, hay: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if hay.len() >= 32 && has_avx2() {
            // SAFETY: AVX2 availability checked above.
            return unsafe { avx2::memrchr(n1, hay) };
        }
    }
    hay.iter().rposition(|&b| b == n1)
}

mod fallback {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;

    #[inline(always)]
    fn has_zero(x: u64) -> bool {
        x.wrapping_sub(LO) & !x & HI != 0
    }

    pub fn memchr(n1: u8, hay: &[u8]) -> Option<usize> {
        let rep = LO.wrapping_mul(n1 as u64);
        let mut i = 0;
        while i + 8 <= hay.len() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&hay[i..i + 8]);
            let x = u64::from_le_bytes(w) ^ rep;
            if has_zero(x) {
                break;
            }
            i += 8;
        }
        hay[i..].iter().position(|&b| b == n1).map(|p| p + i)
    }
}

#[cfg(target_arch = "x86_64")]
mod sse2 {
    use super::*;

    #[target_feature(enable = "sse2")]
    pub unsafe fn memchr(n1: u8, hay: &[u8]) -> Option<usize> {
        let len = hay.len();
        let ptr = hay.as_ptr();
        let v = _mm_set1_epi8(n1 as i8);
        let mut i = 0usize;
        unsafe {
            while i + 16 <= len {
                let m = _mm_movemask_epi8(_mm_cmpeq_epi8(
                    _mm_loadu_si128(ptr.add(i) as *const __m128i),
                    v,
                )) as u32;
                if m != 0 {
                    return Some(i + m.trailing_zeros() as usize);
                }
                i += 16;
            }
            if i < len {
                // Overlapping final load (len >= 16 guaranteed by caller).
                let j = len - 16;
                let m = _mm_movemask_epi8(_mm_cmpeq_epi8(
                    _mm_loadu_si128(ptr.add(j) as *const __m128i),
                    v,
                )) as u32;
                let m = m >> (i - j);
                if m != 0 {
                    return Some(i + m.trailing_zeros() as usize);
                }
            }
        }
        None
    }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use super::vset::{Any, Masked, One, Three, Two, VSet, build};
    use super::*;

    /// Streaming loops touch the line `PF_DIST` bytes ahead once per coarse block: the next
    /// page's TLB walk and the hardware streamer's restart (it stops at every 4 KiB page
    /// boundary) then overlap the scan of the current page. Measured on the 1 GiB window of
    /// refbench (i7-12700K, DDR5): 256-byte blocks + this prefetch run a byte-pair search at
    /// ~28 GB/s vs ~21 GB/s for 64-byte blocks without it (a plain AVX2 read loop: ~26 GB/s).
    const PF_DIST: usize = 4096;
    /// Coarse block: 8 vectors tested with a single branch.
    const BLOCK: usize = 256;

    #[inline(always)]
    unsafe fn load(p: *const u8) -> __m256i {
        unsafe { _mm256_loadu_si256(p as *const __m256i) }
    }

    #[inline(always)]
    unsafe fn prefetch(ptr: *const u8, p: usize, len: usize) {
        if p + PF_DIST < len {
            // SAFETY: in bounds of the haystack (prefetches never fault anyway).
            unsafe { _mm_prefetch::<_MM_HINT_T0>(ptr.add(p + PF_DIST) as *const i8) };
        }
    }

    #[inline(always)]
    unsafe fn nonzero(x: __m256i) -> bool {
        unsafe { _mm256_testz_si256(x, x) == 0 }
    }

    /// First index >= `from` whose byte is in the set `a` (`hay.len() >= 32`).
    #[inline(always)]
    unsafe fn set_scan<A: VSet>(hay: &[u8], from: usize, a: &A) -> Option<usize> {
        let len = hay.len();
        let ptr = hay.as_ptr();
        let mut i = from;
        unsafe {
            macro_rules! t {
                ($o:expr) => {
                    a.test(load(ptr.add(i + $o)))
                };
            }
            while i + BLOCK <= len {
                prefetch(ptr, i, len);
                let x = _mm256_or_si256(
                    _mm256_or_si256(_mm256_or_si256(t!(0), t!(32)), _mm256_or_si256(t!(64), t!(96))),
                    _mm256_or_si256(_mm256_or_si256(t!(128), t!(160)), _mm256_or_si256(t!(192), t!(224))),
                );
                if nonzero(x) {
                    // Hit block: the first non-empty 64-byte quarter.
                    let mut k = 0;
                    while k < BLOCK {
                        let lo = _mm256_movemask_epi8(t!(k)) as u32 as u64;
                        let hi = _mm256_movemask_epi8(t!(k + 32)) as u32 as u64;
                        let m = lo | (hi << 32);
                        if m != 0 {
                            return Some(i + k + m.trailing_zeros() as usize);
                        }
                        k += 64;
                    }
                }
                i += BLOCK;
            }
            while i + 32 <= len {
                let m = _mm256_movemask_epi8(t!(0)) as u32;
                if m != 0 {
                    return Some(i + m.trailing_zeros() as usize);
                }
                i += 32;
            }
            if i < len {
                // Overlapping final load (len >= 32 guaranteed by the callers).
                let j = len - 32;
                let m = (_mm256_movemask_epi8(a.test(load(ptr.add(j)))) as u32) >> (i - j);
                if m != 0 {
                    return Some(i + m.trailing_zeros() as usize);
                }
            }
        }
        None
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn memchr(n1: u8, hay: &[u8]) -> Option<usize> {
        unsafe { set_scan(hay, 0, &One(_mm256_set1_epi8(n1 as i8))) }
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn memchr2(n1: u8, n2: u8, hay: &[u8]) -> Option<usize> {
        let d = n1 ^ n2;
        unsafe {
            if d.count_ones() == 1 {
                // {x, x|bit}: one and + compare
                set_scan(hay, 0, &Masked(_mm256_set1_epi8(!d as i8), _mm256_set1_epi8((n1 & !d) as i8)))
            } else {
                set_scan(hay, 0, &Two(_mm256_set1_epi8(n1 as i8), _mm256_set1_epi8(n2 as i8)))
            }
        }
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn memchr3(n1: u8, n2: u8, n3: u8, hay: &[u8]) -> Option<usize> {
        unsafe {
            set_scan(hay, 0, &Three(_mm256_set1_epi8(n1 as i8), _mm256_set1_epi8(n2 as i8), _mm256_set1_epi8(n3 as i8)))
        }
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn memrchr(n1: u8, hay: &[u8]) -> Option<usize> {
        let len = hay.len();
        let ptr = hay.as_ptr();
        let v = _mm256_set1_epi8(n1 as i8);
        let mut end = len;
        unsafe {
            while end >= 32 {
                let j = end - 32;
                let m = _mm256_movemask_epi8(_mm256_cmpeq_epi8(load(ptr.add(j)), v)) as u32;
                if m != 0 {
                    return Some(j + 31 - m.leading_zeros() as usize);
                }
                end = j;
            }
        }
        hay[..end].iter().rposition(|&b| b == n1)
    }

    /// Byte-set search (Truffle-style): `lo` / `hi` are nibble tables for bytes < 0x80
    /// and >= 0x80 respectively. Returns the first index in `hay[from..]` whose byte
    /// is in the set.
    #[target_feature(enable = "avx2")]
    pub unsafe fn find_in_set(lo: &[u8; 16], hi: &[u8; 16], hay: &[u8], from: usize) -> Option<usize> {
        let len = hay.len();
        if len < 32 {
            // scalar
            for (k, &b) in hay.get(from..)?.iter().enumerate() {
                let t = if b < 0x80 { lo[(b & 15) as usize] } else { hi[(b & 15) as usize] };
                if t & (1u8 << ((b >> 4) & 7)) != 0 {
                    return Some(from + k);
                }
            }
            return None;
        }
        unsafe {
            let t = super::vset::Truffle {
                lo: _mm256_broadcastsi128_si256(_mm_loadu_si128(lo.as_ptr() as *const __m128i)),
                hi: _mm256_broadcastsi128_si256(_mm_loadu_si128(hi.as_ptr() as *const __m128i)),
                bits: super::vset::truffle_bits(),
            };
            set_scan(hay, from, &t)
        }
    }

    /// Leftmost p in [from, last] with a hit of `a` at p + i1 and of `b` at p + i2 for
    /// which `f(p)` returns true (`f` must fully verify: positions of the scalar tail are
    /// passed unfiltered). Requires `last + max(i1, i2) < hay.len()`.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    unsafe fn pair_scan<A: VSet, B: VSet, F: FnMut(usize) -> bool>(
        hay: &[u8],
        from: usize,
        last: usize,
        i1: usize,
        a: &A,
        i2: usize,
        b: &B,
        f: &mut F,
    ) -> Option<usize> {
        let ptr = hay.as_ptr();
        let len = hay.len();
        let mut p = from;
        unsafe {
            macro_rules! c {
                ($q:expr) => {
                    _mm256_and_si256(a.test(load(ptr.add($q + i1))), b.test(load(ptr.add($q + i2))))
                };
            }
            loop {
                // Coarse: 256 candidate starts per branch.
                while p + BLOCK - 1 <= last {
                    prefetch(ptr, p, len);
                    let x = _mm256_or_si256(
                        _mm256_or_si256(_mm256_or_si256(c!(p), c!(p + 32)), _mm256_or_si256(c!(p + 64), c!(p + 96))),
                        _mm256_or_si256(
                            _mm256_or_si256(c!(p + 128), c!(p + 160)),
                            _mm256_or_si256(c!(p + 192), c!(p + 224)),
                        ),
                    );
                    if nonzero(x) {
                        break;
                    }
                    p += BLOCK;
                }
                // Fine: the hit block (or what is left) 32 starts at a time.
                let stop = if p + BLOCK - 1 <= last { p + BLOCK } else { last + 1 };
                while p + 32 <= stop {
                    let mut m = _mm256_movemask_epi8(c!(p)) as u32;
                    while m != 0 {
                        let q = p + m.trailing_zeros() as usize;
                        if f(q) {
                            return Some(q);
                        }
                        m &= m - 1;
                    }
                    p += 32;
                }
                if stop == last + 1 {
                    break;
                }
            }
            if p <= last {
                if last >= 31 {
                    // Overlapping tail.
                    let j = last - 31;
                    let mut m = (_mm256_movemask_epi8(c!(j)) as u32) >> (p - j);
                    while m != 0 {
                        let q = p + m.trailing_zeros() as usize;
                        if f(q) {
                            return Some(q);
                        }
                        m &= m - 1;
                    }
                } else {
                    for q in p..=last {
                        if f(q) {
                            return Some(q);
                        }
                    }
                }
            }
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    #[target_feature(enable = "avx2")]
    pub unsafe fn pair_set_dispatch<F: FnMut(usize) -> bool>(
        hay: &[u8],
        from: usize,
        last: usize,
        i1: usize,
        s1: &super::SetDesc,
        i2: usize,
        s2: &super::SetDesc,
        verify: &mut F,
    ) -> Option<usize> {
        unsafe {
            let a = build(s1);
            let b = build(s2);
            macro_rules! go {
                ($x:expr) => {
                    match &b {
                        Any::One(y) => pair_scan(hay, from, last, i1, $x, i2, y, verify),
                        Any::Two(y) => pair_scan(hay, from, last, i1, $x, i2, y, verify),
                        Any::Three(y) => pair_scan(hay, from, last, i1, $x, i2, y, verify),
                        Any::Masked(y) => pair_scan(hay, from, last, i1, $x, i2, y, verify),
                        Any::Truffle(y) => pair_scan(hay, from, last, i1, $x, i2, y, verify),
                    }
                };
            }
            match &a {
                Any::One(x) => go!(x),
                Any::Two(x) => go!(x),
                Any::Three(x) => go!(x),
                Any::Masked(x) => go!(x),
                Any::Truffle(x) => go!(x),
            }
        }
    }

    /// Packed-pair candidate search: returns the first p in [from, last] (inclusive)
    /// such that hay[p+i1]==b1 && hay[p+i2]==b2 (and verified by `verify`).
    /// `last + max(i1,i2) < hay.len()` must hold. Returns Err(resume) when false
    /// candidates are too frequent (caller switches to a worst-case-linear search).
    #[allow(clippy::too_many_arguments)]
    #[target_feature(enable = "avx2")]
    pub unsafe fn pair_find<F: FnMut(usize) -> bool>(
        hay: &[u8],
        from: usize,
        last: usize,
        i1: usize,
        b1: u8,
        i2: usize,
        b2: u8,
        mut verify: F,
    ) -> Result<Option<usize>, usize> {
        let a = One(_mm256_set1_epi8(b1 as i8));
        let b = One(_mm256_set1_epi8(b2 as i8));
        let mut fails: usize = 0;
        let mut abort = false;
        let mut f = |q: usize| {
            if verify(q) {
                return true;
            }
            fails += 1;
            if fails > 64 + ((q - from) >> 4) {
                abort = true;
                return true;
            }
            false
        };
        match unsafe { pair_scan(hay, from, last, i1, &a, i2, &b, &mut f) } {
            None => Ok(None),
            Some(q) if abort => Err(q + 1),
            Some(q) => Ok(Some(q)),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Pair-of-byte-sets search (generalized packed pair)
// ---------------------------------------------------------------------------------------

use super::regex::hir::ByteSet;

/// Precomputed SIMD-friendly description of a byte set (built once, reused per call).
#[derive(Clone, Debug)]
pub struct SetDesc {
    pub set: ByteSet,
    kind: DescKind,
}

#[derive(Clone, Debug)]
enum DescKind {
    One(u8),
    Two(u8, u8),
    Three(u8, u8, u8),
    Masked(u8, u8),
    Truffle([u8; 16], [u8; 16]),
}

impl SetDesc {
    pub fn new(s: &ByteSet) -> SetDesc {
        let v: Vec<u8> = s.iter().collect();
        let kind = match v.len() {
            1 => DescKind::One(v[0]),
            2 => {
                let d = v[0] ^ v[1];
                if d.count_ones() == 1 { DescKind::Masked(!d, v[0] & !d) } else { DescKind::Two(v[0], v[1]) }
            }
            3 => DescKind::Three(v[0], v[1], v[2]),
            _ => {
                let mut lo = [0u8; 16];
                let mut hi = [0u8; 16];
                for &b in &v {
                    let bit = 1u8 << ((b >> 4) & 7);
                    if b < 0x80 {
                        lo[(b & 15) as usize] |= bit;
                    } else {
                        hi[(b & 15) as usize] |= bit;
                    }
                }
                DescKind::Truffle(lo, hi)
            }
        };
        SetDesc { set: *s, kind }
    }
}

/// Leftmost p in [from, last] with hay[p+i1] in s1, hay[p+i2] in s2 and `verify(p)`.
/// Requires last + max(i1, i2) < hay.len().
pub fn pair_set_find<F: FnMut(usize) -> bool>(
    hay: &[u8],
    from: usize,
    last: usize,
    i1: usize,
    s1: &SetDesc,
    i2: usize,
    s2: &SetDesc,
    verify: &mut F,
) -> Option<usize> {
    if from > last || last + i1.max(i2) >= hay.len() {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        if last - from >= 32 && has_avx2() {
            // SAFETY: AVX2 checked; bounds checked above.
            return unsafe { avx2::pair_set_dispatch(hay, from, last, i1, s1, i2, s2, verify) };
        }
    }
    (from..=last).find(|&p| s1.set.contains(hay[p + i1]) && s2.set.contains(hay[p + i2]) && verify(p))
}

#[cfg(target_arch = "x86_64")]
mod vset {
    use super::*;

    pub trait VSet {
        unsafe fn test(&self, v: __m256i) -> __m256i;
    }
    pub struct One(pub __m256i);
    pub struct Two(pub __m256i, pub __m256i);
    pub struct Three(pub __m256i, pub __m256i, pub __m256i);
    pub struct Masked(pub __m256i, pub __m256i);
    pub struct Truffle {
        pub lo: __m256i,
        pub hi: __m256i,
        pub bits: __m256i,
    }
    impl VSet for One {
        #[inline(always)]
        unsafe fn test(&self, v: __m256i) -> __m256i {
            unsafe { _mm256_cmpeq_epi8(v, self.0) }
        }
    }
    impl VSet for Two {
        #[inline(always)]
        unsafe fn test(&self, v: __m256i) -> __m256i {
            unsafe { _mm256_or_si256(_mm256_cmpeq_epi8(v, self.0), _mm256_cmpeq_epi8(v, self.1)) }
        }
    }
    impl VSet for Three {
        #[inline(always)]
        unsafe fn test(&self, v: __m256i) -> __m256i {
            unsafe {
                _mm256_or_si256(
                    _mm256_or_si256(_mm256_cmpeq_epi8(v, self.0), _mm256_cmpeq_epi8(v, self.1)),
                    _mm256_cmpeq_epi8(v, self.2),
                )
            }
        }
    }
    impl VSet for Masked {
        #[inline(always)]
        unsafe fn test(&self, v: __m256i) -> __m256i {
            unsafe { _mm256_cmpeq_epi8(_mm256_and_si256(v, self.0), self.1) }
        }
    }
    impl VSet for Truffle {
        #[inline(always)]
        unsafe fn test(&self, x: __m256i) -> __m256i {
            unsafe {
                let a = _mm256_shuffle_epi8(self.lo, x);
                let b = _mm256_shuffle_epi8(self.hi, _mm256_xor_si256(x, _mm256_set1_epi8(-128)));
                let t = _mm256_or_si256(a, b);
                let h = _mm256_and_si256(_mm256_srli_epi16(x, 4), _mm256_set1_epi8(7));
                let m = _mm256_shuffle_epi8(self.bits, h);
                let r = _mm256_and_si256(t, m);
                _mm256_xor_si256(_mm256_cmpeq_epi8(r, _mm256_setzero_si256()), _mm256_set1_epi8(-1))
            }
        }
    }

    /// Bit `1 << (high nibble & 7)` per lane (Truffle membership bit).
    #[inline(always)]
    pub unsafe fn truffle_bits() -> __m256i {
        unsafe {
            _mm256_setr_epi8(
                1, 2, 4, 8, 16, 32, 64, -128, 1, 2, 4, 8, 16, 32, 64, -128, 1, 2, 4, 8, 16, 32, 64, -128, 1, 2, 4, 8,
                16, 32, 64, -128,
            )
        }
    }

    pub enum Any {
        One(One),
        Two(Two),
        Three(Three),
        Masked(Masked),
        Truffle(Truffle),
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn build(d: &SetDesc) -> Any {
        unsafe {
            match &d.kind {
                DescKind::One(a) => Any::One(One(_mm256_set1_epi8(*a as i8))),
                DescKind::Two(a, b) => Any::Two(Two(_mm256_set1_epi8(*a as i8), _mm256_set1_epi8(*b as i8))),
                DescKind::Three(a, b, c) => Any::Three(Three(
                    _mm256_set1_epi8(*a as i8),
                    _mm256_set1_epi8(*b as i8),
                    _mm256_set1_epi8(*c as i8),
                )),
                DescKind::Masked(m, v) => Any::Masked(Masked(_mm256_set1_epi8(*m as i8), _mm256_set1_epi8(*v as i8))),
                DescKind::Truffle(lo, hi) => Any::Truffle(Truffle {
                    lo: _mm256_broadcastsi128_si256(_mm_loadu_si128(lo.as_ptr() as *const __m128i)),
                    hi: _mm256_broadcastsi128_si256(_mm_loadu_si128(hi.as_ptr() as *const __m128i)),
                    bits: truffle_bits(),
                }),
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Byte set search
// ---------------------------------------------------------------------------------------

/// A set of bytes with a fast SIMD "find first byte in set" search.
#[derive(Clone, Debug)]
pub struct ByteSetFinder {
    set: [bool; 256],
    lo: [u8; 16],
    hi: [u8; 16],
    count: usize,
    bytes: [u8; 3],
}

impl ByteSetFinder {
    pub fn new(set: &[bool; 256]) -> ByteSetFinder {
        let mut lo = [0u8; 16];
        let mut hi = [0u8; 16];
        let mut count = 0;
        let mut bytes = [0u8; 3];
        for b in 0..256usize {
            if set[b] {
                if count < 3 {
                    bytes[count] = b as u8;
                }
                count += 1;
                let bit = 1u8 << ((b >> 4) & 7);
                if b < 0x80 {
                    lo[b & 15] |= bit;
                } else {
                    hi[b & 15] |= bit;
                }
            }
        }
        ByteSetFinder { set: *set, lo, hi, count, bytes }
    }

    #[inline]
    pub fn contains(&self, b: u8) -> bool {
        self.set[b as usize]
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// First index >= `from` whose byte is in the set.
    #[inline]
    pub fn find(&self, hay: &[u8], from: usize) -> Option<usize> {
        if from >= hay.len() {
            return None;
        }
        match self.count {
            0 => None,
            1 => memchr(self.bytes[0], &hay[from..]).map(|p| p + from),
            2 => memchr2(self.bytes[0], self.bytes[1], &hay[from..]).map(|p| p + from),
            3 => memchr3(self.bytes[0], self.bytes[1], self.bytes[2], &hay[from..]).map(|p| p + from),
            256 => Some(from),
            _ => {
                #[cfg(target_arch = "x86_64")]
                {
                    if hay.len() >= 32 && has_avx2() {
                        // SAFETY: AVX2 availability checked above.
                        return unsafe { avx2::find_in_set(&self.lo, &self.hi, hay, from) };
                    }
                }
                hay[from..].iter().position(|&b| self.set[b as usize]).map(|p| p + from)
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Substring search
// ---------------------------------------------------------------------------------------

/// Bytes searched with Two-Way before the SIMD prefilter is retried.
const FALLBACK_WINDOW: usize = 64 << 10;

/// Precompiled substring searcher.
#[derive(Clone, Debug)]
pub struct Memmem {
    needle: Box<[u8]>,
    i1: usize,
    i2: usize,
    tw: TwoWay,
}

impl Memmem {
    pub fn new(needle: &[u8]) -> Memmem {
        let (i1, i2) = rare_pair(needle);
        Memmem { needle: needle.into(), i1, i2, tw: TwoWay::new(needle) }
    }

    pub fn needle(&self) -> &[u8] {
        &self.needle
    }

    /// First occurrence of the needle in `hay`.
    #[inline]
    pub fn find(&self, hay: &[u8]) -> Option<usize> {
        self.find_at(hay, 0)
    }

    /// First occurrence of the needle starting at or after `from`.
    pub fn find_at(&self, hay: &[u8], from: usize) -> Option<usize> {
        let n = &self.needle[..];
        let m = n.len();
        if from > hay.len() || hay.len() - from < m {
            return None;
        }
        if m == 0 {
            return Some(from);
        }
        if m == 1 {
            return memchr(n[0], &hay[from..]).map(|p| p + from);
        }
        let last = hay.len() - m; // last valid start
        #[cfg(target_arch = "x86_64")]
        {
            if last - from >= 32 && has_avx2() {
                let (b2, i2) = (n[self.i2], self.i2);
                let mut start = from;
                loop {
                    let verify = |q: usize| hay[q..q + m] == *n;
                    // SAFETY: AVX2 checked; last + max(i1, i2) < hay.len() since i1,i2 < m.
                    let r = unsafe { avx2::pair_find(hay, start, last, self.i1, n[self.i1], i2, b2, verify) };
                    match r {
                        Ok(x) => return x,
                        Err(resume) => {
                            // Dense false candidates: Two-Way over a bounded window, then
                            // retry the SIMD scan (worst case stays linear).
                            let wend = resume.saturating_add(FALLBACK_WINDOW).min(hay.len());
                            let wlim = (wend + m - 1).min(hay.len());
                            if let Some(x) = self.tw.find(&hay[..wlim], resume, n) {
                                return Some(x);
                            }
                            if wend >= hay.len() || wend > last {
                                return None;
                            }
                            start = wend;
                            if last - start < 32 {
                                return self.tw.find(hay, start, n);
                            }
                        }
                    }
                }
            }
        }
        // Scalar: memchr on the rarest byte, verify, with Two-Way fallback.
        let b1 = n[self.i1];
        let mut p = from;
        let mut budget: isize = 64;
        while p <= last {
            let lim = last + self.i1 + 1;
            match memchr(b1, &hay[p + self.i1..lim]) {
                None => return None,
                Some(k) => {
                    let q = p + k;
                    if hay[q..q + m] == *n {
                        return Some(q);
                    }
                    budget -= 1;
                    if budget < 0 {
                        let wend = (q + 1).saturating_add(FALLBACK_WINDOW).min(hay.len());
                        let wlim = (wend + m - 1).min(hay.len());
                        if let Some(x) = self.tw.find(&hay[..wlim], q + 1, n) {
                            return Some(x);
                        }
                        if wend > last {
                            return None;
                        }
                        p = wend;
                        budget = 64;
                        continue;
                    }
                    budget += (k / 16) as isize;
                    p = q + 1;
                }
            }
        }
        None
    }

    /// Iterator over (possibly overlapping) occurrences.
    pub fn find_iter<'a>(&'a self, hay: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
        let mut pos = 0usize;
        std::iter::from_fn(move || {
            let r = self.find_at(hay, pos)?;
            pos = r + 1;
            Some(r)
        })
    }
}

/// Picks two distinct positions of the rarest bytes in the needle.
fn rare_pair(n: &[u8]) -> (usize, usize) {
    if n.len() < 2 {
        return (0, 0);
    }
    let mut i1 = 0usize;
    for i in 1..n.len() {
        if BYTE_RANK[n[i] as usize] < BYTE_RANK[n[i1] as usize] {
            i1 = i;
        }
    }
    let mut i2 = if i1 == 0 { 1 } else { 0 };
    for i in 0..n.len() {
        if i != i1 && BYTE_RANK[n[i] as usize] < BYTE_RANK[n[i2] as usize] {
            i2 = i;
        }
    }
    (i1, i2)
}

/// Two-Way string matching (Crochemore–Perrin), linear worst case.
#[derive(Clone, Debug)]
struct TwoWay {
    crit: usize,
    period: usize,
    memory: bool,
}

impl TwoWay {
    fn new(n: &[u8]) -> TwoWay {
        if n.is_empty() {
            return TwoWay { crit: 0, period: 1, memory: false };
        }
        let (l1, p1) = max_suffix(n, false);
        let (l2, p2) = max_suffix(n, true);
        let (crit, period) = if l1 > l2 { (l1, p1) } else { (l2, p2) };
        if period + crit <= n.len() && n[..crit] == n[period..period + crit] {
            TwoWay { crit, period, memory: true }
        } else {
            let period = crit.max(n.len() - crit) + 1;
            TwoWay { crit, period, memory: false }
        }
    }

    fn find(&self, hay: &[u8], from: usize, n: &[u8]) -> Option<usize> {
        let m = n.len();
        if m == 0 {
            return if from <= hay.len() { Some(from) } else { None };
        }
        let crit = self.crit;
        let mut pos = from;
        if self.memory {
            let mut memory = 0usize;
            while pos + m <= hay.len() {
                let mut i = crit.max(memory);
                while i < m && n[i] == hay[pos + i] {
                    i += 1;
                }
                if i < m {
                    pos += i - crit + 1;
                    memory = 0;
                    continue;
                }
                let mut j = crit;
                while j > memory && n[j - 1] == hay[pos + j - 1] {
                    j -= 1;
                }
                if j <= memory {
                    return Some(pos);
                }
                pos += self.period;
                memory = m - self.period;
            }
        } else {
            while pos + m <= hay.len() {
                let mut i = crit;
                while i < m && n[i] == hay[pos + i] {
                    i += 1;
                }
                if i < m {
                    pos += i - crit + 1;
                    continue;
                }
                let mut j = crit;
                while j > 0 && n[j - 1] == hay[pos + j - 1] {
                    j -= 1;
                }
                if j == 0 {
                    return Some(pos);
                }
                pos += self.period;
            }
        }
        None
    }
}

fn max_suffix(n: &[u8], rev: bool) -> (usize, usize) {
    let mut left = 0usize;
    let mut right = 1usize;
    let mut offset = 0usize;
    let mut period = 1usize;
    while right + offset < n.len() {
        let a = n[right + offset];
        let b = n[left + offset];
        let less = if rev { a > b } else { a < b };
        if less {
            right += offset + 1;
            offset = 0;
            period = right - left;
        } else if a == b {
            if offset + 1 == period {
                right += offset + 1;
                offset = 0;
            } else {
                offset += 1;
            }
        } else {
            left = right;
            right += 1;
            offset = 0;
            period = 1;
        }
    }
    (left, period)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive(h: &[u8], n: &[u8], from: usize) -> Option<usize> {
        if n.is_empty() {
            return if from <= h.len() { Some(from) } else { None };
        }
        (from..h.len().saturating_sub(n.len() - 1)).find(|&i| i + n.len() <= h.len() && &h[i..i + n.len()] == n)
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn yara_memchr_random() {
        let mut r = Rng(0x1234_5678_9abc_def1);
        for _ in 0..3000 {
            let len = (r.next() % 300) as usize;
            let alpha = 1 + (r.next() % 6) as u8;
            let h: Vec<u8> = (0..len).map(|_| b'a' + (r.next() % alpha as u64) as u8).collect();
            let c = b'a' + (r.next() % (alpha as u64 + 1)) as u8;
            assert_eq!(memchr(c, &h), h.iter().position(|&b| b == c));
            assert_eq!(memrchr(c, &h), h.iter().rposition(|&b| b == c));
            let d = b'a' + (r.next() % (alpha as u64 + 1)) as u8;
            let e = b'a' + (r.next() % (alpha as u64 + 1)) as u8;
            assert_eq!(memchr2(c, d, &h), h.iter().position(|&b| b == c || b == d));
            assert_eq!(memchr3(c, d, e, &h), h.iter().position(|&b| b == c || b == d || b == e));
            let mut set = [false; 256];
            for _ in 0..(r.next() % 8) {
                set[(b'a' + (r.next() % 8) as u8) as usize] = true;
                set[(r.next() % 256) as usize] = true;
            }
            let f = ByteSetFinder::new(&set);
            let from = if len > 0 { (r.next() as usize) % (len + 1) } else { 0 };
            assert_eq!(f.find(&h, from), h.iter().enumerate().skip(from).find(|(_, b)| set[**b as usize]).map(|x| x.0));
        }
    }

    #[test]
    fn yara_memmem_random() {
        let mut r = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..4000 {
            let len = (r.next() % 400) as usize;
            let alpha = 1 + (r.next() % 3) as u8;
            let h: Vec<u8> = (0..len).map(|_| b'a' + (r.next() % alpha as u64) as u8).collect();
            let nl = (r.next() % 9) as usize;
            let n: Vec<u8> = if nl > 0 && len > nl && r.next() % 2 == 0 {
                let s = (r.next() as usize) % (len - nl);
                h[s..s + nl].to_vec()
            } else {
                (0..nl).map(|_| b'a' + (r.next() % alpha as u64) as u8).collect()
            };
            let mm = Memmem::new(&n);
            let from = (r.next() as usize) % (len + 2);
            assert_eq!(mm.find_at(&h, from), naive(&h, &n, from), "h={:?} n={:?}", h, n);

            let tw = TwoWay::new(&n);
            if from <= h.len() {
                assert_eq!(tw.find(&h, from, &n), naive(&h, &n, from));
            }
        }
    }

    /// Long haystacks with a few planted hits: exercises the 256-byte block loops, their
    /// hit blocks, the 32-byte fine passes and the overlapping tails at every alignment.
    #[test]
    fn yara_memchr_blocks_sparse() {
        let mut r = Rng(0x2545_f491_4f6c_dd1d);
        for it in 0..2500 {
            let len = (r.next() % 9000) as usize;
            let mut h: Vec<u8> = (0..len).map(|_| b'a' + (r.next() % 20) as u8).collect();
            let plant = |h: &mut Vec<u8>, r: &mut Rng, what: &[u8]| {
                if h.len() > what.len() {
                    let at = (r.next() as usize) % (h.len() - what.len() + 1);
                    h[at..at + what.len()].copy_from_slice(what);
                }
            };
            for _ in 0..(r.next() % 4) {
                let k = (r.next() % 4) as usize;
                plant(&mut h, &mut r, [&b"X"[..], b"Y", b"xY", b"XYZ"][k]);
            }
            for _ in 0..(r.next() % 3) {
                plant(&mut h, &mut r, b"Ab\x00cD");
                plant(&mut h, &mut r, b"aB\x00Cd");
            }
            let from = if len > 0 { (r.next() as usize) % (len + 1) } else { 0 };
            let naive_set = |set: &dyn Fn(u8) -> bool| h[from..].iter().position(|&b| set(b)).map(|p| p + from);
            assert_eq!(memchr(b'X', &h[from..]).map(|p| p + from), naive_set(&|b| b == b'X'), "it {it}");
            assert_eq!(memchr2(b'X', b'Y', &h[from..]).map(|p| p + from), naive_set(&|b| b == b'X' || b == b'Y'));
            assert_eq!(memchr2(b'X', b'x', &h[from..]).map(|p| p + from), naive_set(&|b| b == b'X' || b == b'x'));
            assert_eq!(
                memchr3(b'X', b'Y', b'Z', &h[from..]).map(|p| p + from),
                naive_set(&|b| b == b'X' || b == b'Y' || b == b'Z')
            );
            let mut set = [false; 256];
            for b in [b'X', b'Z', 0u8, 0xf0] {
                set[b as usize] = true;
            }
            assert_eq!(ByteSetFinder::new(&set).find(&h, from), naive_set(&|b| set[b as usize]));
            for n in [&b"XY"[..], b"Ab\x00cD", b"xYa", b"Y"] {
                assert_eq!(Memmem::new(n).find_at(&h, from), naive(&h, n, from), "it {it} n={n:?}");
            }
            // Byte-set pairs (case-insensitive "ab\0cd" at offsets 0 and 4, and 1 and 3).
            let sets: Vec<ByteSet> = b"ab\x00cd"
                .iter()
                .map(|&c| {
                    let mut s = ByteSet::single(c);
                    s.insert(c.to_ascii_uppercase());
                    s
                })
                .collect();
            if len >= 5 {
                let last = len - 5;
                for (i1, i2) in [(0usize, 4usize), (1, 3), (2, 0)] {
                    let (d1, d2) = (SetDesc::new(&sets[i1]), SetDesc::new(&sets[i2]));
                    let ok = |q: usize| sets.iter().enumerate().all(|(k, s)| s.contains(h[q + k]));
                    let want = (from..=last).find(|&q| q <= last && ok(q));
                    let got = pair_set_find(&h, from, last, i1, &d1, i2, &d2, &mut |q| ok(q));
                    assert_eq!(got, if from <= last { want } else { None }, "it {it} pair {i1},{i2}");
                }
            }
        }
    }
}
