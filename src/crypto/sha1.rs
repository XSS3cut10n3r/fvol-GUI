// Derived from Volatility 3 (Volatility Software License 1.0); see LICENSE.txt.
//! SHA-1 (FIPS 180-4). Used by volatility3 for Windows service SID derivation
//! (`hashlib.sha1` in `windows/getservicesids.py`) and as the underlying hash for
//! HMAC-SHA1 where needed elsewhere in the framework.

const H0: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

/// Runs the compression function over every 64-byte block of `blocks`
/// (`blocks.len()` must be a multiple of 64): SHA-NI when the CPU has it, else
/// the portable implementation.
#[inline]
fn compress(state: &mut [u32; 5], blocks: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    if sha_ni::available() {
        // Safety: available() checked the target features.
        unsafe { sha_ni::compress(state, blocks) };
        return;
    }
    compress_portable(state, blocks);
}

/// FIPS 180-4 compression, plain Rust (the non-SHA-NI path, and the reference
/// the SHA-NI path is tested against).
fn compress_portable(state: &mut [u32; 5], blocks: &[u8]) {
    for block in blocks.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = *state;

        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for (s, v) in state.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(v);
        }
    }
}

/// Incremental SHA-1 hasher.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    len: u64,
    buf: [u8; 64],
    buf_len: usize,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    pub fn new() -> Self {
        Sha1 {
            state: H0,
            len: 0,
            buf: [0; 64],
            buf_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);

        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 64 {
                return;
            }
            compress(&mut self.state, &self.buf);
            self.buf_len = 0;
        }

        let whole = data.len() & !63;
        if whole > 0 {
            compress(&mut self.state, &data[..whole]);
        }
        let rest = &data[whole..];
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    pub fn finalize(mut self) -> [u8; 20] {
        // Pad in place: 0x80, zeros, then the 64-bit big-endian bit length,
        // spilling into a second block when fewer than 8 bytes remain.
        let n = self.buf_len;
        let mut tail = [0u8; 128];
        tail[..n].copy_from_slice(&self.buf[..n]);
        tail[n] = 0x80;
        let total = if n < 56 { 64 } else { 128 };
        tail[total - 8..total].copy_from_slice(&self.len.wrapping_mul(8).to_be_bytes());
        compress(&mut self.state, &tail[..total]);

        let mut out = [0u8; 20];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

// --- SHA-NI hardware path (x86_64 only, runtime-detected). `sha1rnds4` does 4
// rounds of the compression function per call (choosing one of the 4 round
// functions via its immediate), `sha1nexte`/`sha1msg1`/`sha1msg2` compute the
// message schedule 4 words at a time (Intel's published instruction sequence).
// The 20 `sha1rnds4` of a block are one serial chain; the state stays in
// registers across all blocks of one call instead of being unpacked and
// re-packed around every block.
#[cfg(target_arch = "x86_64")]
mod sha_ni {
    use std::arch::x86_64::*;

    #[inline]
    pub fn available() -> bool {
        is_x86_feature_detected!("sha")
            && is_x86_feature_detected!("sse2")
            && is_x86_feature_detected!("ssse3")
            && is_x86_feature_detected!("sse4.1")
    }

    /// Safety: the CPU must support sha, sse2, ssse3 and sse4.1.
    ///
    /// Never inlined, and it clears the upper YMM halves on entry: see
    /// `sha256::sha_ni::compress` (SHA-NI after AVX code is 150x slower otherwise).
    #[inline(never)]
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub unsafe fn compress(state: &mut [u32; 5], blocks: &[u8]) {
        unsafe {
            #[cfg(target_feature = "avx")]
            _mm256_zeroupper();
            let mask = _mm_set_epi64x(0x0001020304050607u64 as i64, 0x08090a0b0c0d0e0fu64 as i64);
            // ABCD with A in the top lane; E in the top lane of its own register
            // (the low three lanes must stay zero: they are added to W1..W3).
            let mut abcd = _mm_shuffle_epi32(_mm_loadu_si128(state.as_ptr().cast()), 0x1B);
            let mut e0 = _mm_set_epi32(state[4] as i32, 0, 0, 0);
            let mut e1;

            // Group g (rounds 4g..4g+4) on schedule vector `$cur`: E (nexte of the
            // ABCD saved one group earlier, plus W) goes in, and the current ABCD
            // is saved into `$e_next` for the group after.
            macro_rules! group {
                ($e:ident, $e_next:ident, $cur:expr, $f:literal) => {
                    $e = _mm_sha1nexte_epu32($e, $cur);
                    $e_next = abcd;
                    abcd = _mm_sha1rnds4_epu32(abcd, $e, $f);
                };
            }

            for block in blocks.chunks_exact(64) {
                let abcd_save = abcd;
                let e_save = e0;
                let p = block.as_ptr();
                // Message schedule, 4 words per vector v[g] = W[4g..4g+4] (W[4g]
                // in the top lane). Groups 4-7 use sha1msg1/sha1msg2; groups 8-19
                // use W[i] = rotl2(W[i-6] ^ W[i-16] ^ W[i-28] ^ W[i-32]) (valid for
                // i >= 32, and free of dependencies inside a 4-word group) in
                // plain SSE. The 20 sha1rnds4 are the serial chain (4-cycle
                // latency, but the SHA unit is busy 3 of those cycles), and
                // sha1msg2 holds that same unit for ~2 cycles each: with Intel's
                // all-sha1msg sequence the loop ran at ~118 cycles/block
                // (OpenSSL: ~117); with 12 of the 16 msg2 moved to SSE and each
                // v[g+2] computed right after group g (so the schedule never
                // queues ahead of the rounds in program order): ~106.
                let mut v = [_mm_setzero_si128(); 20];
                for g in 0..4 {
                    v[g] = _mm_shuffle_epi8(_mm_loadu_si128(p.add(16 * g).cast()), mask);
                }
                macro_rules! sch {
                    (msg, $g:literal) => {
                        let t = _mm_xor_si128(_mm_sha1msg1_epu32(v[$g - 4], v[$g - 3]), v[$g - 2]);
                        v[$g] = _mm_sha1msg2_epu32(t, v[$g - 1]);
                    };
                    (id, $g:literal) => {
                        // [W(i-6), W(i-5), W(i-4), W(i-3)] = low half of v[g-2] :
                        // high half of v[g-1].
                        let x = _mm_xor_si128(_mm_alignr_epi8(v[$g - 2], v[$g - 1], 8), v[$g - 4]);
                        let x = _mm_xor_si128(x, _mm_xor_si128(v[$g - 7], v[$g - 8]));
                        v[$g] = _mm_or_si128(_mm_slli_epi32(x, 2), _mm_srli_epi32(x, 30));
                    };
                }
                // Rounds 0-3: E is added directly (no previous A to rotate in).
                e0 = _mm_add_epi32(e0, v[0]);
                e1 = abcd;
                abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
                group!(e1, e0, v[1], 0);
                group!(e0, e1, v[2], 0);
                sch!(msg, 4);
                group!(e1, e0, v[3], 0);
                sch!(msg, 5);
                group!(e0, e1, v[4], 0);
                sch!(msg, 6);
                group!(e1, e0, v[5], 1);
                sch!(msg, 7);
                group!(e0, e1, v[6], 1);
                sch!(id, 8);
                group!(e1, e0, v[7], 1);
                sch!(id, 9);
                group!(e0, e1, v[8], 1);
                sch!(id, 10);
                group!(e1, e0, v[9], 1);
                sch!(id, 11);
                group!(e0, e1, v[10], 2);
                sch!(id, 12);
                group!(e1, e0, v[11], 2);
                sch!(id, 13);
                group!(e0, e1, v[12], 2);
                sch!(id, 14);
                group!(e1, e0, v[13], 2);
                sch!(id, 15);
                group!(e0, e1, v[14], 2);
                sch!(id, 16);
                group!(e1, e0, v[15], 3);
                sch!(id, 17);
                group!(e0, e1, v[16], 3);
                sch!(id, 18);
                group!(e1, e0, v[17], 3);
                sch!(id, 19);
                group!(e0, e1, v[18], 3);
                group!(e1, e0, v[19], 3);

                // Fold in the saved state: E via nexte (rotl(A_79, 30) + E_save;
                // its low lanes come from e_save, i.e. stay zero).
                e0 = _mm_sha1nexte_epu32(e0, e_save);
                abcd = _mm_add_epi32(abcd, abcd_save);
            }

            _mm_storeu_si128(state.as_mut_ptr().cast(), _mm_shuffle_epi32(abcd, 0x1B));
            state[4] = _mm_extract_epi32(e0, 3) as u32;
        }
    }
}

/// One-shot SHA-1 digest.
pub fn digest(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // FIPS 180-4 / RFC 3174 test vectors.
    #[test]
    fn known_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
            ),
        ];
        for (input, expect) in cases {
            assert_eq!(hex(&digest(input)), *expect, "input={input:?}");
        }
    }

    #[test]
    fn million_a() {
        let data = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&digest(&data)),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let whole = digest(&data);
        for chunk_size in [1usize, 3, 7, 55, 56, 63, 64, 65, 200] {
            let mut h = Sha1::new();
            for chunk in data.chunks(chunk_size) {
                h.update(chunk);
            }
            assert_eq!(h.finalize(), whole, "chunk_size={chunk_size}");
        }
    }

    /// Best of 9 timings (ns) of `dirty()` followed by SHA-NI over `data`.
    #[cfg(target_arch = "x86_64")]
    fn ni_time(data: &[u8], dirty: impl Fn()) -> u64 {
        let mut best = u64::MAX;
        for _ in 0..9 {
            let t0 = std::time::Instant::now();
            dirty();
            let mut st = H0;
            // Safety: the callers checked sha_ni::available()
            unsafe { sha_ni::compress(&mut st, data) };
            std::hint::black_box(st);
            best = best.min(t0.elapsed().as_nanos() as u64);
        }
        best
    }

    /// See `sha256::tests::ni_fast_after_avx_code`: SHA-NI after AVX code must not pay the
    /// SSE/AVX transition on every instruction.
    #[test]
    fn ni_fast_after_avx_code() {
        #[cfg(target_arch = "x86_64")]
        {
            if !sha_ni::available() || !is_x86_feature_detected!("avx") {
                return;
            }
            let data = vec![0xa5u8; 64 << 10];
            let clean = ni_time(&data, || {});
            // Two shapes of caller: all 16 YMM registers written by visible AVX code, and one
            // register written in a loop. Where LLVM puts vzeroupper differs with the shape
            // (measured on the fast test build: without the vzeroupper on entry the SHA-1
            // run of one of them takes 190x the clean one), so both must stay fast.
            let seen = ni_time(&data, || unsafe { crate::crypto::dirty_upper_ymm() });
            let run = |dirty: bool| -> u64 {
                let mut best = u64::MAX;
                for _ in 0..9 {
                    let t0 = std::time::Instant::now();
                    if dirty {
                        unsafe { std::arch::asm!("vpcmpeqb {0}, {0}, {0}", out(ymm_reg) _, options(nomem, nostack, preserves_flags)) };
                    }
                    let mut st = H0;
                    // Safety: available() checked the target features
                    unsafe { sha_ni::compress(&mut st, &data) };
                    std::hint::black_box(st);
                    best = best.min(t0.elapsed().as_nanos() as u64);
                }
                best
            };
            let unseen = run(true);
            for (case, dirty) in [("all-register", seen), ("loop", unseen)] {
                assert!(dirty < clean * 4 + 20_000, "SHA-1 NI after {case} AVX code: {dirty} ns vs {clean} ns clean");
            }
        }
    }

    // Cross-checks the SHA-NI multi-block path against the portable path on any
    // CPU that actually has SHA-NI, for single blocks and multi-block runs.
    #[test]
    fn ni_matches_portable_if_available() {
        #[cfg(target_arch = "x86_64")]
        {
            if !sha_ni::available() {
                return;
            }
            let mut rng: u64 = 0xBEEF_BEEF;
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            for nblocks in [1usize, 2, 5, 33] {
                let data: Vec<u8> = (0..nblocks * 64).map(|_| next() as u8).collect();
                let mut ni_state = H0;
                unsafe { sha_ni::compress(&mut ni_state, &data) };
                let mut sw_state = H0;
                compress_portable(&mut sw_state, &data);
                assert_eq!(ni_state, sw_state, "nblocks={nblocks}");
            }
        }
    }
}
