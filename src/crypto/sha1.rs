// Derived from Volatility 3 (Volatility Software License 1.0); see LICENSE.txt.
//! SHA-1 (FIPS 180-4). Used by volatility3 for Windows service SID derivation
//! (`hashlib.sha1` in `windows/getservicesids.py`) and as the underlying hash for
//! HMAC-SHA1 where needed elsewhere in the framework.

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
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            len: 0,
            buf: [0; 64],
            buf_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);

        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.process_block(&block);
                self.buf_len = 0;
            }
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.process_block(&block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.len.wrapping_mul(8);
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let pad_len = if self.buf_len < 56 {
            56 - self.buf_len
        } else {
            120 - self.buf_len
        };
        self.append_no_len(&pad[..pad_len]);
        self.append_no_len(&bit_len.to_be_bytes());

        let mut out = [0u8; 20];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn append_no_len(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.process_block(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.process_block(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        #[cfg(target_arch = "x86_64")]
        if sha_ni::available() {
            sha_ni::process_block(&mut self.state, block);
            return;
        }
        self.process_block_scalar(block);
    }

    fn process_block_scalar(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.state;

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

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

// --- SHA-NI hardware path (x86_64 only, runtime-detected). Same family of
// intrinsics as SHA-256's (see that module's doc comment): `sha1rnds4` does 4
// rounds of the compression function per call (choosing one of the 4 round
// functions via its immediate), `sha1nexte`/`sha1msg1`/`sha1msg2` compute the
// message schedule 4 words at a time. Correctness is pinned down by the same
// FIPS 180-4 / differential tests the scalar path uses.
#[cfg(target_arch = "x86_64")]
mod sha_ni {
    use std::arch::x86_64::*;
    use std::sync::OnceLock;

    pub fn available() -> bool {
        static AVAILABLE: OnceLock<bool> = OnceLock::new();
        *AVAILABLE.get_or_init(|| {
            is_x86_feature_detected!("sha")
                && is_x86_feature_detected!("sse4.1")
                && is_x86_feature_detected!("ssse3")
                && is_x86_feature_detected!("sse2")
        })
    }

    pub fn process_block(state: &mut [u32; 5], block: &[u8; 64]) {
        unsafe { process_block_unchecked(state, block) }
    }

    #[target_feature(enable = "sha,sse4.1,ssse3,sse2")]
    unsafe fn process_block_unchecked(state: &mut [u32; 5], block: &[u8; 64]) {
        unsafe {
            let mask = _mm_set_epi64x(0x0001020304050607u64 as i64, 0x08090a0b0c0d0e0fu64 as i64);

            let mut abcd = _mm_loadu_si128(state.as_ptr() as *const __m128i);
            let mut e0 = _mm_set_epi32(state[4] as i32, 0, 0, 0);
            abcd = _mm_shuffle_epi32(abcd, 0x1B);

            let abcd_save = abcd;
            let e0_save = e0;

            let p = block.as_ptr();
            let mut msg0 = _mm_shuffle_epi8(_mm_loadu_si128(p as *const __m128i), mask);
            let mut msg1 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(16) as *const __m128i), mask);
            let mut msg2 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(32) as *const __m128i), mask);
            let mut msg3 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(48) as *const __m128i), mask);

            let mut e1;

            // Rounds 0-3 (func 0: Ch)
            e0 = _mm_add_epi32(e0, msg0);
            e1 = abcd;
            abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);

            // Rounds 4-7 (func 0)
            e1 = _mm_sha1nexte_epu32(e1, msg1);
            e0 = abcd;
            abcd = _mm_sha1rnds4_epu32(abcd, e1, 0);
            msg0 = _mm_sha1msg1_epu32(msg0, msg1);

            // Rounds 8-11 (func 0)
            e0 = _mm_sha1nexte_epu32(e0, msg2);
            e1 = abcd;
            abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
            msg1 = _mm_sha1msg1_epu32(msg1, msg2);
            msg0 = _mm_xor_si128(msg0, msg2);

            // Rounds 12-15 (func 0)
            e1 = _mm_sha1nexte_epu32(e1, msg3);
            e0 = abcd;
            msg0 = _mm_sha1msg2_epu32(msg0, msg3);
            abcd = _mm_sha1rnds4_epu32(abcd, e1, 0);
            msg2 = _mm_sha1msg1_epu32(msg2, msg3);
            msg1 = _mm_xor_si128(msg1, msg3);

            // Rounds 16-19 (func 0, last group of func 0)
            e0 = _mm_sha1nexte_epu32(e0, msg0);
            e1 = abcd;
            msg1 = _mm_sha1msg2_epu32(msg1, msg0);
            abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
            msg3 = _mm_sha1msg1_epu32(msg3, msg0);
            msg2 = _mm_xor_si128(msg2, msg0);

            // Rounds 20-39 (func 1: Parity), 5 groups of 4, e0/e1 ping-ponging
            // roles each group exactly as rounds 0-19 did above.

            // Rounds 20-23 (func 1)
            e1 = _mm_sha1nexte_epu32(e1, msg1);
            e0 = abcd;
            msg2 = _mm_sha1msg2_epu32(msg2, msg1);
            abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
            msg0 = _mm_sha1msg1_epu32(msg0, msg1);
            msg3 = _mm_xor_si128(msg3, msg1);

            // Rounds 24-27 (func 1)
            e0 = _mm_sha1nexte_epu32(e0, msg2);
            e1 = abcd;
            msg3 = _mm_sha1msg2_epu32(msg3, msg2);
            abcd = _mm_sha1rnds4_epu32(abcd, e0, 1);
            msg1 = _mm_sha1msg1_epu32(msg1, msg2);
            msg0 = _mm_xor_si128(msg0, msg2);

            // Rounds 28-31 (func 1)
            e1 = _mm_sha1nexte_epu32(e1, msg3);
            e0 = abcd;
            msg0 = _mm_sha1msg2_epu32(msg0, msg3);
            abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
            msg2 = _mm_sha1msg1_epu32(msg2, msg3);
            msg1 = _mm_xor_si128(msg1, msg3);

            // Rounds 32-35 (func 1)
            e0 = _mm_sha1nexte_epu32(e0, msg0);
            e1 = abcd;
            msg1 = _mm_sha1msg2_epu32(msg1, msg0);
            abcd = _mm_sha1rnds4_epu32(abcd, e0, 1);
            msg3 = _mm_sha1msg1_epu32(msg3, msg0);
            msg2 = _mm_xor_si128(msg2, msg0);

            // Rounds 36-39 (func 1, last of func 1)
            e1 = _mm_sha1nexte_epu32(e1, msg1);
            e0 = abcd;
            msg2 = _mm_sha1msg2_epu32(msg2, msg1);
            abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
            msg0 = _mm_sha1msg1_epu32(msg0, msg1);
            msg3 = _mm_xor_si128(msg3, msg1);

            // Rounds 40-59 (func 2: Maj), 5 groups of 4.
            // Rounds 40-43
            e0 = _mm_sha1nexte_epu32(e0, msg2);
            e1 = abcd;
            msg3 = _mm_sha1msg2_epu32(msg3, msg2);
            abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
            msg1 = _mm_sha1msg1_epu32(msg1, msg2);
            msg0 = _mm_xor_si128(msg0, msg2);

            // Rounds 44-47
            e1 = _mm_sha1nexte_epu32(e1, msg3);
            e0 = abcd;
            msg0 = _mm_sha1msg2_epu32(msg0, msg3);
            abcd = _mm_sha1rnds4_epu32(abcd, e1, 2);
            msg2 = _mm_sha1msg1_epu32(msg2, msg3);
            msg1 = _mm_xor_si128(msg1, msg3);

            // Rounds 48-51
            e0 = _mm_sha1nexte_epu32(e0, msg0);
            e1 = abcd;
            msg1 = _mm_sha1msg2_epu32(msg1, msg0);
            abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
            msg3 = _mm_sha1msg1_epu32(msg3, msg0);
            msg2 = _mm_xor_si128(msg2, msg0);

            // Rounds 52-55
            e1 = _mm_sha1nexte_epu32(e1, msg1);
            e0 = abcd;
            msg2 = _mm_sha1msg2_epu32(msg2, msg1);
            abcd = _mm_sha1rnds4_epu32(abcd, e1, 2);
            msg0 = _mm_sha1msg1_epu32(msg0, msg1);
            msg3 = _mm_xor_si128(msg3, msg1);

            // Rounds 56-59 (last of func 2)
            e0 = _mm_sha1nexte_epu32(e0, msg2);
            e1 = abcd;
            msg3 = _mm_sha1msg2_epu32(msg3, msg2);
            abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
            msg1 = _mm_sha1msg1_epu32(msg1, msg2);
            msg0 = _mm_xor_si128(msg0, msg2);

            // Rounds 60-79 (func 3: Parity), 5 groups of 4; no more msg1 needed
            // after round 63's schedule word, and no more xor-prep after 71.
            // Rounds 60-63
            e1 = _mm_sha1nexte_epu32(e1, msg3);
            e0 = abcd;
            msg0 = _mm_sha1msg2_epu32(msg0, msg3);
            abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);
            msg2 = _mm_sha1msg1_epu32(msg2, msg3);
            msg1 = _mm_xor_si128(msg1, msg3);

            // Rounds 64-67
            e0 = _mm_sha1nexte_epu32(e0, msg0);
            e1 = abcd;
            msg1 = _mm_sha1msg2_epu32(msg1, msg0);
            abcd = _mm_sha1rnds4_epu32(abcd, e0, 3);
            msg3 = _mm_sha1msg1_epu32(msg3, msg0);
            msg2 = _mm_xor_si128(msg2, msg0);

            // Rounds 68-71
            e1 = _mm_sha1nexte_epu32(e1, msg1);
            e0 = abcd;
            msg2 = _mm_sha1msg2_epu32(msg2, msg1);
            abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);
            msg3 = _mm_xor_si128(msg3, msg1);

            // Rounds 72-75
            e0 = _mm_sha1nexte_epu32(e0, msg2);
            e1 = abcd;
            msg3 = _mm_sha1msg2_epu32(msg3, msg2);
            abcd = _mm_sha1rnds4_epu32(abcd, e0, 3);

            // Rounds 76-79
            e1 = _mm_sha1nexte_epu32(e1, msg3);
            e0 = abcd;
            abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);

            // Combine state.
            e0 = _mm_sha1nexte_epu32(e0, e0_save);
            abcd = _mm_add_epi32(abcd, abcd_save);

            abcd = _mm_shuffle_epi32(abcd, 0x1B);
            _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, abcd);
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

    // Cross-checks the SHA-NI path against the scalar path on any CPU that
    // actually has SHA-NI.
    #[test]
    fn ni_matches_scalar_if_available() {
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
            for nblocks in [1usize, 2, 5] {
                let block: Vec<u8> = (0..nblocks * 64).map(|_| next() as u8).collect();
                let mut ni_state = [0x67452301u32, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
                for chunk in block.chunks_exact(64) {
                    let b: &[u8; 64] = chunk.try_into().unwrap();
                    sha_ni::process_block(&mut ni_state, b);
                }
                let mut scalar = Sha1::new();
                scalar.update(&block);
                assert_eq!(ni_state, scalar.state, "nblocks={nblocks}");
            }
        }
    }
}
