// Derived from Volatility 3 (Volatility Software License 1.0); see LICENSE.txt.
//! MD5 (RFC 1321). Used by volatility3 for SAM/LSA key material derivation
//! (`hashlib.md5` in `windows/registry/hashdump.py`, `windows/registry/lsadump.py`),
//! content hashing (`windows/mbrscan.py`), and cache-key hashing
//! (`framework/contexts/__init__.py`).

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

// K[i] = floor(2^32 * abs(sin(i + 1))), precomputed as in RFC 1321.
const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
    0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
    0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
    0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
    0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
    0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
    0xeb86d391,
];

/// Incremental MD5 hasher.
#[derive(Clone)]
pub struct Md5 {
    state: [u32; 4],
    len: u64,
    buf: [u8; 64],
    buf_len: usize,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    pub fn new() -> Self {
        Md5 {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
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

    pub fn finalize(mut self) -> [u8; 16] {
        let bit_len = self.len.wrapping_mul(8);
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let pad_len = if self.buf_len < 56 {
            56 - self.buf_len
        } else {
            120 - self.buf_len
        };
        self.append_no_len(&pad[..pad_len]);
        self.append_no_len(&bit_len.to_le_bytes());

        let mut out = [0u8; 16];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    // Like update, but does not touch self.len (used for the length-padding suffix,
    // whose own length must not be counted in the message length field).
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

    // Split into four fixed-trip-count loops (one per round function) instead of
    // one 64-iteration loop with a `match` on `i` to pick F and the message-word
    // index every round: the round function is now a single hardcoded expression
    // per loop (no per-iteration branch to predict), `S`/`K`/`m` indices are
    // either the loop counter directly or a cheap fixed formula, and each F/G
    // uses the standard 3-operation bitwise-identity form (one AND/OR fewer than
    // the textbook `(b&c)|(!b&d)`/`(b&d)|(c&!d)`) instead of the direct
    // definition:
    //   F(b,c,d) = (b&c)|(!b&d)  ==  d ^ (b & (c^d))
    //   G(b,c,d) = (b&d)|(c&!d)  ==  c ^ (d & (b^c))
    // (both verified by case-splitting on the free variable that disappears:
    // b for F, d for G -- see the module's differential/KAT tests, which cover
    // this rewrite the same as everything else here).
    fn process_block(&mut self, block: &[u8; 64]) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let [mut a, mut b, mut c, mut d] = self.state;

        for i in 0..16 {
            let f = d ^ (b & (c ^ d));
            let tmp = a
                .wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(m[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(tmp.rotate_left(S[i]));
        }
        for i in 16..32 {
            let g = (5 * i + 1) % 16;
            let f = c ^ (d & (b ^ c));
            let tmp = a
                .wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(unsafe { *m.get_unchecked(g) }); // g < 16 always (mod 16)
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(tmp.rotate_left(S[i]));
        }
        for i in 32..48 {
            let g = (3 * i + 5) % 16;
            let f = b ^ c ^ d;
            let tmp = a
                .wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(unsafe { *m.get_unchecked(g) }); // g < 16 always (mod 16)
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(tmp.rotate_left(S[i]));
        }
        for i in 48..64 {
            let g = (7 * i) % 16;
            let f = c ^ (b | !d);
            let tmp = a
                .wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(unsafe { *m.get_unchecked(g) }); // g < 16 always (mod 16)
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(tmp.rotate_left(S[i]));
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

/// One-shot MD5 digest.
pub fn digest(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // RFC 1321 section A.5 test suite.
    #[test]
    fn rfc1321_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", "d41d8cd98f00b204e9800998ecf8427e"),
            (b"a", "0cc175b9c0f1b6a831c399e269772661"),
            (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
            (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (input, expect) in cases {
            assert_eq!(hex(&digest(input)), *expect, "input={input:?}");
        }
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let whole = digest(&data);
        for chunk_size in [1usize, 3, 7, 55, 56, 63, 64, 65, 200] {
            let mut h = Md5::new();
            for chunk in data.chunks(chunk_size) {
                h.update(chunk);
            }
            assert_eq!(h.finalize(), whole, "chunk_size={chunk_size}");
        }
    }
}
