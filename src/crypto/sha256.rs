// Derived from Volatility 3 (Volatility Software License 1.0); see LICENSE.txt.
//! SHA-256 (FIPS 180-4). Used by volatility3 to derive the LSA key on Vista+
//! systems: `windows/registry/lsadump.py` runs a 1000-iteration SHA-256 loop
//! (`hashlib.sha256`) over the bootkey and part of the encrypted `PolEKList`
//! value before AES-CBC-decrypting the LSA key material.

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

/// Incremental SHA-256 hasher.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    len: u64,
    buf: [u8; 64],
    buf_len: usize,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            state: H0,
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

    pub fn finalize(mut self) -> [u8; 32] {
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

        let mut out = [0u8; 32];
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
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

// --- SHA-NI hardware path (x86_64 only, runtime-detected). Intel's published
// algorithm (see e.g. "Fast SHA-256 Implementations on Intel Architecture
// Processors" / the widely-mirrored `noloader/SHA-Intrinsics` reference): four
// rounds of the compression function per `sha256rnds2` call, with `sha256msg1`/
// `sha256msg2` computing four words of message schedule at a time. State is kept
// packed as two `__m128i` (`{A,B,E,F}` and `{C,D,G,H}`) between calls rather than
// unpacked to a `[u32;8]` every block, since the packing/unpacking shuffles are
// themselves not free. Correctness is pinned down by the same FIPS 180-4 /
// differential tests the scalar path uses -- both paths produce identical output
// on this CPU per `tests::ni_matches_scalar`.
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

    pub fn process_block(state: &mut [u32; 8], block: &[u8; 64]) {
        unsafe { process_block_unchecked(state, block) }
    }

    #[target_feature(enable = "sha,sse4.1,ssse3,sse2")]
    #[allow(unused_assignments)] // msg0's final round4! write (round 52-55) primes
    // no further round, since rounds 56-63 only ever need msg2/msg3 again.
    unsafe fn process_block_unchecked(state: &mut [u32; 8], block: &[u8; 64]) {
        unsafe {
            let k = &super::K;
            // Byte-swap mask: SHA-NI wants each 32-bit message word big-endian
            // *within* the 128-bit lane the way `_mm_shuffle_epi8` reorders bytes.
            let mask = _mm_set_epi64x(0x0c0d0e0f08090a0bu64 as i64, 0x0405060700010203u64 as i64);

            // state[] is A,B,C,D,E,F,G,H (FIPS order). Load as {D,C,B,A} / {H,G,F,E}
            // (loadu reads state[0..4] into lane order [state0,state1,state2,state3]
            // interpreted low-to-high, then we shuffle into the {C,D,A,B}/{G,H,E,F}
            // working order sha256rnds2 expects).
            let mut tmp = _mm_loadu_si128(state.as_ptr() as *const __m128i); // A B C D
            let mut state1 = _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i); // E F G H

            tmp = _mm_shuffle_epi32(tmp, 0xB1); // CDAB
            state1 = _mm_shuffle_epi32(state1, 0x1B); // GHEF
            let mut state0 = _mm_alignr_epi8(tmp, state1, 8); // ABEF
            state1 = _mm_blend_epi16(state1, tmp, 0xF0); // CDGH

            let abef_save = state0;
            let cdgh_save = state1;

            macro_rules! kmsg {
                ($msg:expr, $k0:expr, $k1:expr) => {
                    _mm_add_epi32($msg, _mm_set_epi64x($k1 as i64, $k0 as i64))
                };
            }

            let p = block.as_ptr();
            let mut msg0 = _mm_shuffle_epi8(_mm_loadu_si128(p as *const __m128i), mask);
            let mut msg1 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(16) as *const __m128i), mask);
            let mut msg2 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(32) as *const __m128i), mask);
            let mut msg3 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(48) as *const __m128i), mask);

            // Rounds 0-3
            let mut msg = kmsg!(
                msg0,
                (k[0] as u64) | ((k[1] as u64) << 32),
                (k[2] as u64) | ((k[3] as u64) << 32)
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

            // Rounds 4-63, four at a time, msgN cycling through the schedule.
            macro_rules! round4 {
                ($msg_new:expr, $msg_prev1:expr, $msg_prev2:expr, $msg_prev3:expr, $kidx:expr) => {{
                    let mut m = kmsg!(
                        $msg_new,
                        (k[$kidx] as u64) | ((k[$kidx + 1] as u64) << 32),
                        (k[$kidx + 2] as u64) | ((k[$kidx + 3] as u64) << 32)
                    );
                    state1 = _mm_sha256rnds2_epu32(state1, state0, m);
                    let tmp2 = _mm_alignr_epi8($msg_new, $msg_prev1, 4);
                    $msg_prev2 = _mm_add_epi32($msg_prev2, tmp2);
                    $msg_prev2 = _mm_sha256msg2_epu32($msg_prev2, $msg_new);
                    m = _mm_shuffle_epi32(m, 0x0E);
                    state0 = _mm_sha256rnds2_epu32(state0, state1, m);
                    $msg_prev3 = _mm_sha256msg1_epu32($msg_prev3, $msg_new);
                }};
            }

            // Rounds 4-7 (special-case: msg0's msg1 step, no add/msg2 yet)
            let mut msg_k = kmsg!(
                msg1,
                (k[4] as u64) | ((k[5] as u64) << 32),
                (k[6] as u64) | ((k[7] as u64) << 32)
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg_k);
            msg_k = _mm_shuffle_epi32(msg_k, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg_k);
            msg0 = _mm_sha256msg1_epu32(msg0, msg1);

            // Rounds 8-11
            msg_k = kmsg!(
                msg2,
                (k[8] as u64) | ((k[9] as u64) << 32),
                (k[10] as u64) | ((k[11] as u64) << 32)
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg_k);
            msg_k = _mm_shuffle_epi32(msg_k, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg_k);
            msg1 = _mm_sha256msg1_epu32(msg1, msg2);

            // Rounds 12-15
            msg_k = kmsg!(
                msg3,
                (k[12] as u64) | ((k[13] as u64) << 32),
                (k[14] as u64) | ((k[15] as u64) << 32)
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg_k);
            let mut tmp3 = _mm_alignr_epi8(msg3, msg2, 4);
            msg0 = _mm_add_epi32(msg0, tmp3);
            msg0 = _mm_sha256msg2_epu32(msg0, msg3);
            msg_k = _mm_shuffle_epi32(msg_k, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg_k);
            msg2 = _mm_sha256msg1_epu32(msg2, msg3);

            // Rounds 16-19..60-63: 12 more round4! groups cycling msg0..msg3.
            round4!(msg0, msg3, msg1, msg3, 16);
            round4!(msg1, msg0, msg2, msg0, 20);
            round4!(msg2, msg1, msg3, msg1, 24);
            round4!(msg3, msg2, msg0, msg2, 28);
            round4!(msg0, msg3, msg1, msg3, 32);
            round4!(msg1, msg0, msg2, msg0, 36);
            round4!(msg2, msg1, msg3, msg1, 40);
            round4!(msg3, msg2, msg0, msg2, 44);
            round4!(msg0, msg3, msg1, msg3, 48);
            round4!(msg1, msg0, msg2, msg0, 52);

            // Rounds 56-59 (no further msg1 needed after this)
            tmp3 = _mm_alignr_epi8(msg2, msg1, 4);
            msg3 = _mm_add_epi32(msg3, tmp3);
            msg3 = _mm_sha256msg2_epu32(msg3, msg2);
            msg_k = kmsg!(
                msg2,
                (k[56] as u64) | ((k[57] as u64) << 32),
                (k[58] as u64) | ((k[59] as u64) << 32)
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg_k);
            msg_k = _mm_shuffle_epi32(msg_k, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg_k);

            // Rounds 60-63
            msg_k = kmsg!(
                msg3,
                (k[60] as u64) | ((k[61] as u64) << 32),
                (k[62] as u64) | ((k[63] as u64) << 32)
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg_k);
            msg_k = _mm_shuffle_epi32(msg_k, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg_k);

            state0 = _mm_add_epi32(state0, abef_save);
            state1 = _mm_add_epi32(state1, cdgh_save);

            tmp = _mm_shuffle_epi32(state0, 0x1B); // FEBA
            state1 = _mm_shuffle_epi32(state1, 0xB1); // DCHG
            let out0 = _mm_blend_epi16(tmp, state1, 0xF0); // DCBA
            let out1 = _mm_alignr_epi8(state1, tmp, 8); // HGFE

            _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, out0);
            _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, out1);
        }
    }
}

/// One-shot SHA-256 digest.
pub fn digest(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // FIPS 180-4 test vectors.
    #[test]
    fn known_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
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
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let whole = digest(&data);
        for chunk_size in [1usize, 3, 7, 55, 56, 63, 64, 65, 200] {
            let mut h = Sha256::new();
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
            let mut rng: u64 = 0x5A5A_5A5A;
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            for nblocks in [1usize, 2, 5] {
                let block: Vec<u8> = (0..nblocks * 64).map(|_| next() as u8).collect();
                let mut ni_state = H0;
                for chunk in block.chunks_exact(64) {
                    let b: &[u8; 64] = chunk.try_into().unwrap();
                    sha_ni::process_block(&mut ni_state, b);
                }
                let mut scalar = Sha256::new();
                scalar.update(&block);
                // Compare mid-state directly: scalar's `state` matches ni_state
                // exactly after whole 64-byte blocks (no padding involved yet).
                assert_eq!(ni_state, scalar.state, "nblocks={nblocks}");
            }
        }
    }
}
