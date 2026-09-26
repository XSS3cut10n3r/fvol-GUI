//! Fast exact substring search for the Linux automagic scans (VMCOREINFO magic, banners,
//! `swapper`): a two-byte SIMD pre-filter (Muła's "generic SIMD" algorithm: compare the
//! needle's first byte at `i` and a second, rarely-zero byte at `i + k` for 32 positions at
//! once) followed by an exact compare. Memory images are full of zero pages and text, where
//! glibc `memmem` runs at ~4 GB/s per core for a 12-byte needle; this runs at memory speed.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0) (search semantics of python's
//! `BytesScanner`: every, possibly overlapping, occurrence in ascending order).

/// A prepared needle.
pub struct Needle<'a> {
    pub needle: &'a [u8],
    /// Offset of the second filter byte.
    k: usize,
}

impl<'a> Needle<'a> {
    pub fn new(needle: &'a [u8]) -> Needle<'a> {
        // the second filter byte: the last byte that is neither 0 nor the first byte (zeros
        // dominate memory images); falls back to the last byte
        let n = needle.len();
        let k = if n < 2 {
            0
        } else {
            (1..n).rev().find(|&i| needle[i] != 0 && needle[i] != needle[0]).unwrap_or(n - 1)
        };
        Needle { needle, k }
    }

    /// Call `f(offset)` for every occurrence in `hay` in ascending order; `f` returns false to
    /// stop.
    #[inline]
    pub fn for_each(&self, hay: &[u8], mut f: impl FnMut(usize) -> bool) {
        let (nd, n) = (self.needle, self.needle.len());
        if n == 0 || hay.len() < n {
            return;
        }
        let last = hay.len() - n; // last valid start
        let mut i = 0usize;
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        if n >= 2 {
            // SAFETY: loads stay within `hay`: i + k + 32 <= i + n - 1 + 32 <= last + n + 31 ...
            // guarded by `i + self.k + 32 <= hay.len()` and `i + 32 <= hay.len()`.
            unsafe {
                use std::arch::x86_64::*;
                let first = _mm256_set1_epi8(nd[0] as i8);
                let second = _mm256_set1_epi8(nd[self.k] as i8);
                let p = hay.as_ptr();
                while i + self.k + 32 <= hay.len() && i <= last {
                    let a = _mm256_loadu_si256(p.add(i) as *const __m256i);
                    let b = _mm256_loadu_si256(p.add(i + self.k) as *const __m256i);
                    let mut m = _mm256_movemask_epi8(_mm256_and_si256(_mm256_cmpeq_epi8(a, first), _mm256_cmpeq_epi8(b, second))) as u32;
                    while m != 0 {
                        let pos = i + m.trailing_zeros() as usize;
                        if pos <= last && hay[pos..pos + n] == *nd && !f(pos) {
                            return;
                        }
                        m &= m - 1;
                    }
                    i += 32;
                }
            }
        }
        while i <= last {
            match crate::layers::scan::find(&hay[i..], nd) {
                Some(j) => {
                    if !f(i + j) {
                        return;
                    }
                    i += j + 1;
                }
                None => return,
            }
        }
    }
}

/// python `scanners.BytesScanner(needle)` on the fast search: a [`Scanner`] reporting every
/// occurrence starting in the first `chunk_size` bytes of each chunk. Hit = address.
///
/// [`Scanner`]: crate::layers::scan::Scanner
pub struct FastBytesScanner {
    needle: Vec<u8>,
}

impl FastBytesScanner {
    pub fn new(needle: &[u8]) -> FastBytesScanner {
        FastBytesScanner { needle: needle.to_vec() }
    }
}

impl crate::layers::scan::Scanner for FastBytesScanner {
    type Hit = u64;
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<u64>) {
        let cs = self.chunk_size();
        Needle::new(&self.needle).for_each(data, |i| {
            if (i as u64) < cs {
                hits.push(data_offset + i as u64);
                true
            } else {
                false
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive(h: &[u8], n: &[u8]) -> Vec<usize> {
        (0..h.len().saturating_sub(n.len()) + 1).filter(|&i| i + n.len() <= h.len() && &h[i..i + n.len()] == n).collect()
    }

    #[test]
    fn matches_naive() {
        let mut h = vec![0u8; 300];
        for (i, b) in h.iter_mut().enumerate() {
            *b = if i % 7 == 0 { b'V' } else if i % 11 == 0 { b'M' } else { 0 };
        }
        h[100..112].copy_from_slice(b"VMCOREINFO\0\0");
        h[288..300].copy_from_slice(b"VMCOREINFO\0\0");
        h[40..42].copy_from_slice(b"aa");
        for nd in [b"VMCOREINFO\0\0".as_slice(), b"V", b"aa", b"a", b"\0\0", b"VM", b"swapper"] {
            let mut v = Vec::new();
            Needle::new(nd).for_each(&h, |o| {
                v.push(o);
                true
            });
            assert_eq!(v, naive(&h, nd), "needle {nd:?}");
        }
        // overlapping occurrences
        let h = vec![b'a'; 100];
        let mut v = Vec::new();
        Needle::new(b"aaa").for_each(&h, |o| {
            v.push(o);
            true
        });
        assert_eq!(v, (0..98).collect::<Vec<_>>());
    }
}
