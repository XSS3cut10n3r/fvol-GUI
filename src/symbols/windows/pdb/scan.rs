//! Byte scanners used on the hot paths of the PDB converter (SSE2 on x86_64, which is part of
//! the baseline; scalar code for short inputs and other targets).

#[cfg(target_arch = "x86_64")]
mod sse {
    use std::arch::x86_64::*;

    /// Bitmask (bit k = byte k) of the bytes of `s[at..at + 16]` selected by `pred`.
    /// SAFETY (callers): `at + 16 <= s.len()`.
    #[inline(always)]
    pub unsafe fn mask(s: &[u8], at: usize, pred: impl Fn(__m128i) -> __m128i) -> u32 {
        unsafe {
            let v = _mm_loadu_si128(s.as_ptr().add(at) as *const __m128i);
            _mm_movemask_epi8(pred(v)) as u32
        }
    }

    /// First index whose byte is selected by `pred`, scanning 16 bytes at a time and
    /// finishing with one overlapping load. Requires `s.len() >= 16`.
    #[inline(always)]
    pub fn find(s: &[u8], pred: impl Fn(__m128i) -> __m128i + Copy) -> Option<usize> {
        debug_assert!(s.len() >= 16);
        let mut i = 0usize;
        // SAFETY: SSE2 is baseline on x86_64 and every load is in bounds.
        unsafe {
            while i + 16 <= s.len() {
                let m = mask(s, i, pred);
                if m != 0 {
                    return Some(i + m.trailing_zeros() as usize);
                }
                i += 16;
            }
            if i < s.len() {
                let j = s.len() - 16;
                let m = mask(s, j, pred) >> (i - j);
                if m != 0 {
                    return Some(i + m.trailing_zeros() as usize);
                }
            }
        }
        None
    }
}

/// Index of the first byte in `s` equal to `needle`.
#[inline]
pub(crate) fn find_byte(s: &[u8], needle: u8) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    if s.len() >= 16 {
        use std::arch::x86_64::*;
        // SAFETY: SSE2 is baseline on x86_64.
        let n = unsafe { _mm_set1_epi8(needle as i8) };
        return sse::find(s, move |v| unsafe { _mm_cmpeq_epi8(v, n) });
    }
    s.iter().position(|&c| c == needle)
}

#[inline(always)]
fn escaped(c: u8) -> bool {
    !(0x20..0x7f).contains(&c) || c == b'"' || c == b'\\'
}

/// Index of the first byte that python's `json.dumps(ensure_ascii=True)` would not copy
/// verbatim: controls, `"`, `\`, DEL and everything >= 0x80.
#[inline]
pub(crate) fn find_json_escape(s: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    if s.len() >= 16 {
        use std::arch::x86_64::*;
        // SAFETY: SSE2 is baseline on x86_64.
        let (sp, quote, bslash, del) = unsafe {
            (_mm_set1_epi8(0x20), _mm_set1_epi8(b'"' as i8), _mm_set1_epi8(b'\\' as i8), _mm_set1_epi8(0x7f))
        };
        return sse::find(s, move |v| unsafe {
            // signed compare: bytes >= 0x80 are negative, so `< 0x20` catches them too
            _mm_or_si128(
                _mm_or_si128(_mm_cmplt_epi8(v, sp), _mm_cmpeq_epi8(v, del)),
                _mm_or_si128(_mm_cmpeq_epi8(v, quote), _mm_cmpeq_epi8(v, bslash)),
            )
        });
    }
    if s.len() >= 8 {
        // two overlapping words: exact "any byte needs escaping" test (SWAR)
        let w = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap());
        let any = |x: u64| {
            const L: u64 = 0x0101_0101_0101_0101;
            const H: u64 = 0x8080_8080_8080_8080;
            let zero = |y: u64| y.wrapping_sub(L) & !y & H;
            (x.wrapping_sub(0x20 * L) & !x & H) | (x & H) | zero(x ^ (b'"' as u64 * L)) | zero(x ^ (b'\\' as u64 * L)) | zero(x ^ (0x7f * L))
        };
        if s.len() <= 16 {
            if any(w(&s[..8])) | any(w(&s[s.len() - 8..])) == 0 {
                return None;
            }
        } else {
            // longer strings (no SSE path on this architecture): word by word, then the exact
            // position from the first word that has one
            let mut i = 0;
            while i + 8 <= s.len() && any(w(&s[i..i + 8])) == 0 {
                i += 8;
            }
            return s[i..].iter().position(|&c| escaped(c)).map(|p| p + i);
        }
    }
    s.iter().position(|&c| escaped(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanners_match_scalar() {
        let mut rng = 0x2545_f491_4f6c_dd1du64;
        for len in 0..80 {
            for _ in 0..200 {
                let v: Vec<u8> = (0..len)
                    .map(|_| {
                        rng ^= rng << 13;
                        rng ^= rng >> 7;
                        rng ^= rng << 17;
                        // mostly printable, sometimes special
                        match rng % 97 {
                            0 => 0,
                            1 => b'"',
                            2 => b'\\',
                            3 => 0x7f,
                            4 => 0x80 | (rng >> 8) as u8,
                            5 => (rng >> 8) as u8 & 0x1f,
                            6..=8 => b'@',
                            9 => 0x20,
                            10 => 0x7e,
                            _ => 0x20 + ((rng >> 8) % 95) as u8,
                        }
                    })
                    .collect();
                for needle in [0u8, b'@'] {
                    assert_eq!(find_byte(&v, needle), v.iter().position(|&c| c == needle));
                }
                assert_eq!(find_json_escape(&v), v.iter().position(|&c| escaped(c)), "{v:?}");
            }
        }
    }
}
