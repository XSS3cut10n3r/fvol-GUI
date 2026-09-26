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
    // two-phase form: identical physical ranges mapped at several virtual addresses (the
    // kernel direct map, vmalloc aliases) are searched once, big chunks are streamed
    fn prescan(&self, data: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
        let cs = self.chunk_size();
        Needle::new(&self.needle).for_each(data, |i| {
            if (i as u64) < cs {
                out.push((i as u64, 0));
                true
            } else {
                false
            }
        });
        true
    }
    fn finish(&self, matches: &[(u64, u32)], data_offset: u64, hits: &mut Vec<u64>) {
        hits.extend(matches.iter().map(|m| data_offset + m.0));
    }
    fn stream_window(&self) -> Option<usize> {
        if self.needle.is_empty() { None } else { Some(self.needle.len()) }
    }
    fn prescan_piece(&self, data: &[u8], base: u64, from: usize, limit: usize, out: &mut Vec<(u64, u32)>) -> usize {
        // occurrences may overlap: every start in [from, limit) is independent
        let cs_limit = self.chunk_size().saturating_sub(base).min(limit as u64) as usize;
        if from < cs_limit {
            let end = (cs_limit + self.needle.len() - 1).min(data.len());
            Needle::new(&self.needle).for_each(&data[from..end], |i| {
                out.push((base + (from + i) as u64, 0));
                true
            });
        }
        limit
    }
}

/// python `scanners.MultiStringScanner(patterns)` (leftmost-longest, non-overlapping) with the
/// fast search on the patterns' longest common prefix (all Linux banners start with
/// `"Linux version "`): candidates come from [`Needle`], the trie decides at each candidate.
/// Falls back to the plain trie scan when the common prefix is shorter than 2 bytes.
/// Hit = (address, pattern index).
pub struct FastMultiStringScanner {
    mss: crate::layers::scan::MultiStringScanner,
    lcp: Vec<u8>,
    maxlen: usize,
}

impl FastMultiStringScanner {
    pub fn new<P: AsRef<[u8]>>(patterns: &[P]) -> FastMultiStringScanner {
        let pats: Vec<&[u8]> = patterns.iter().map(|p| p.as_ref()).filter(|p| !p.is_empty()).collect();
        let mut lcp: Vec<u8> = pats.first().map(|p| p.to_vec()).unwrap_or_default();
        for p in &pats {
            let n = lcp.iter().zip(p.iter()).take_while(|(a, b)| a == b).count();
            lcp.truncate(n);
        }
        let maxlen = pats.iter().map(|p| p.len()).max().unwrap_or(0);
        FastMultiStringScanner { mss: crate::layers::scan::MultiStringScanner::new(patterns), lcp, maxlen }
    }

    /// Pattern by index (hits carry the index).
    pub fn pattern(&self, idx: usize) -> &[u8] {
        self.mss.pattern(idx)
    }
}

impl crate::layers::scan::Scanner for FastMultiStringScanner {
    type Hit = (u64, u32);
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<(u64, u32)>) {
        if self.lcp.len() < 2 {
            return self.mss.scan(data, data_offset, hits);
        }
        let cs = self.chunk_size();
        let mut next_allowed = 0usize;
        Needle::new(&self.lcp).for_each(data, |i| {
            if i < next_allowed {
                return true;
            }
            if i as u64 >= cs {
                return false;
            }
            // the longest pattern matching exactly at i (leftmost-longest => reported first)
            let end = (i + self.maxlen).min(data.len());
            let mut m = None;
            self.mss.search(&data[i..end], |o, pi| {
                if o == 0 {
                    m = Some(pi);
                }
                false
            });
            if let Some(pi) = m {
                hits.push((data_offset + i as u64, pi));
                next_allowed = i + self.mss.pattern(pi as usize).len();
            }
            true
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

    #[test]
    fn multi_matches_trie_scanner() {
        use crate::layers::scan::{MultiStringScanner, Scanner};
        let pats: Vec<&[u8]> = vec![b"Linux version 5.1 (a)\n\0", b"Linux version 5.1 (a)\n\0xx", b"Linux version 6.8 (b)\n\0", b"Linux version"];
        let mut h = vec![0u8; 5000];
        let put = |h: &mut Vec<u8>, at: usize, s: &[u8]| h[at..at + s.len()].copy_from_slice(s);
        put(&mut h, 10, b"Linux version 5.1 (a)\n\0xx");
        put(&mut h, 100, b"Linux version 6.8 (b)\n\0");
        put(&mut h, 200, b"Linux version 7");
        put(&mut h, 300, b"Linux versioLinux version 5.1 (a)\n\0");
        put(&mut h, 4990, b"Linux vers");
        let (mut a, mut b) = (Vec::new(), Vec::new());
        MultiStringScanner::new(&pats).scan(&h, 0, &mut a);
        FastMultiStringScanner::new(&pats).scan(&h, 0, &mut b);
        assert_eq!(a, b);
        assert_eq!(a.len(), 4);
    }
}
