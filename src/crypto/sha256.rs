// Derived from Volatility 3 (Volatility Software License 1.0); see LICENSE.txt.
//! SHA-256 (FIPS 180-4). Used by volatility3 to derive the LSA key on Vista+
//! systems: `windows/registry/lsadump.py` runs a 1000-iteration SHA-256 loop
//! (`hashlib.sha256`) over the bootkey and part of the encrypted `PolEKList`
//! value before AES-CBC-decrypting the LSA key material.

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Runs the compression function over every 64-byte block of `blocks`
/// (`blocks.len()` must be a multiple of 64): SHA-NI when the CPU has it, else
/// the portable implementation.
#[inline]
fn compress(state: &mut [u32; 8], blocks: &[u8]) {
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
fn compress_portable(state: &mut [u32; 8], blocks: &[u8]) {
    for block in blocks.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

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

        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

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

    pub fn finalize(mut self) -> [u8; 32] {
        // Pad in place: 0x80, zeros, then the 64-bit big-endian bit length,
        // spilling into a second block when fewer than 8 bytes remain.
        let n = self.buf_len;
        let mut tail = [0u8; 128];
        tail[..n].copy_from_slice(&self.buf[..n]);
        tail[n] = 0x80;
        let total = if n < 56 { 64 } else { 128 };
        tail[total - 8..total].copy_from_slice(&self.len.wrapping_mul(8).to_be_bytes());
        compress(&mut self.state, &tail[..total]);

        let mut out = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

// --- SHA-NI hardware path (x86_64 only, runtime-detected). Intel's published
// algorithm (see e.g. "Fast SHA-256 Implementations on Intel Architecture
// Processors"): four rounds of the compression function per pair of
// `sha256rnds2` calls, with `sha256msg1`/`sha256msg2` computing four words of
// message schedule at a time. The two `sha256rnds2` of every round pair are one
// serial chain (4-cycle latency each on Golden Cove), so a block costs at least
// 32 x 4 = 128 cycles; everything else (schedule, K adds, byte swaps, loads) is
// off that chain. The state stays packed as `{A,B,E,F}` / `{C,D,G,H}` registers
// across all blocks of one call -- the pack/unpack shuffles and the call are paid
// once per `update`, not once per block.
#[cfg(target_arch = "x86_64")]
mod sha_ni {
    use super::K;
    use std::arch::x86_64::*;

    #[inline]
    pub fn available() -> bool {
        is_x86_feature_detected!("sha")
            && is_x86_feature_detected!("sse2")
            && is_x86_feature_detected!("ssse3")
            && is_x86_feature_detected!("sse4.1")
    }

    /// Safety: the CPU must support sha, sse2, ssse3 and sse4.1.
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub unsafe fn compress(state: &mut [u32; 8], blocks: &[u8]) {
        unsafe {
            // Byte-swap mask: SHA-NI wants each 32-bit message word big-endian.
            let mask = _mm_set_epi64x(0x0c0d0e0f08090a0bu64 as i64, 0x0405060700010203u64 as i64);
            // state[] is A..H; sha256rnds2 works on {A,B,E,F} / {C,D,G,H}
            // (lanes high to low).
            let tmp = _mm_shuffle_epi32(_mm_loadu_si128(state.as_ptr().cast()), 0xB1); // CDAB
            let efgh = _mm_shuffle_epi32(_mm_loadu_si128(state.as_ptr().add(4).cast()), 0x1B); // GHEF
            let mut state0 = _mm_alignr_epi8(tmp, efgh, 8); // ABEF
            let mut state1 = _mm_blend_epi16(efgh, tmp, 0xF0); // CDGH

            // Four rounds on schedule words `$m` = W[i..i+4].
            macro_rules! rounds4 {
                ($m:expr, $i:expr) => {
                    let wk = _mm_add_epi32($m, _mm_loadu_si128(K.as_ptr().add($i).cast()));
                    state1 = _mm_sha256rnds2_epu32(state1, state0, wk);
                    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(wk, 0x0E));
                };
            }
            // `$next` (msg1 half already applied) := the schedule words for the
            // group after the current one, from the current group's words `$cur`
            // and the previous group's `$prev` (read before its own msg1 update).
            macro_rules! sched {
                ($next:ident, $cur:ident, $prev:ident) => {
                    $next = _mm_sha256msg2_epu32(
                        _mm_add_epi32($next, _mm_alignr_epi8($cur, $prev, 4)),
                        $cur,
                    );
                };
            }
            macro_rules! msg1 {
                ($a:ident, $b:ident) => {
                    $a = _mm_sha256msg1_epu32($a, $b);
                };
            }

            for block in blocks.chunks_exact(64) {
                let abef_save = state0;
                let cdgh_save = state1;
                let p = block.as_ptr();
                let mut m0 = _mm_shuffle_epi8(_mm_loadu_si128(p.cast()), mask);
                let mut m1 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(16).cast()), mask);
                let mut m2 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(32).cast()), mask);
                let mut m3 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(48).cast()), mask);

                rounds4!(m0, 0);
                rounds4!(m1, 4);
                msg1!(m0, m1);
                rounds4!(m2, 8);
                msg1!(m1, m2);
                rounds4!(m3, 12);
                sched!(m0, m3, m2);
                msg1!(m2, m3);
                rounds4!(m0, 16);
                sched!(m1, m0, m3);
                msg1!(m3, m0);
                rounds4!(m1, 20);
                sched!(m2, m1, m0);
                msg1!(m0, m1);
                rounds4!(m2, 24);
                sched!(m3, m2, m1);
                msg1!(m1, m2);
                rounds4!(m3, 28);
                sched!(m0, m3, m2);
                msg1!(m2, m3);
                rounds4!(m0, 32);
                sched!(m1, m0, m3);
                msg1!(m3, m0);
                rounds4!(m1, 36);
                sched!(m2, m1, m0);
                msg1!(m0, m1);
                rounds4!(m2, 40);
                sched!(m3, m2, m1);
                msg1!(m1, m2);
                rounds4!(m3, 44);
                sched!(m0, m3, m2);
                msg1!(m2, m3);
                rounds4!(m0, 48);
                sched!(m1, m0, m3);
                msg1!(m3, m0);
                rounds4!(m1, 52);
                sched!(m2, m1, m0);
                rounds4!(m2, 56);
                sched!(m3, m2, m1);
                rounds4!(m3, 60);

                state0 = _mm_add_epi32(state0, abef_save);
                state1 = _mm_add_epi32(state1, cdgh_save);
            }

            let feba = _mm_shuffle_epi32(state0, 0x1B);
            let dchg = _mm_shuffle_epi32(state1, 0xB1);
            _mm_storeu_si128(state.as_mut_ptr().cast(), _mm_blend_epi16(feba, dchg, 0xF0)); // DCBA
            _mm_storeu_si128(
                state.as_mut_ptr().add(4).cast(),
                _mm_alignr_epi8(dchg, feba, 8),
            ); // HGFE
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

    // Cross-checks the SHA-NI multi-block path against the portable path on any
    // CPU that actually has SHA-NI, for single blocks and multi-block runs.
    #[test]
    fn ni_matches_portable_if_available() {
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
