// Derived from Volatility 3 (Volatility Software License 1.0); see LICENSE.txt.
//! MD5 (RFC 1321). Used by volatility3 for SAM/LSA key material derivation
//! (`hashlib.md5` in `windows/registry/hashdump.py`, `windows/registry/lsadump.py`),
//! content hashing (`windows/mbrscan.py`), and cache-key hashing
//! (`framework/contexts/__init__.py`).
//!
//! ## Speed
//!
//! MD5 is one serial dependency chain through `b`: every step is
//! `b' = b + rotl(a + K + M + F(b, c, d), s)`, so for a single message its speed is
//! the latency of that chain, 64 times per block. The steps are arranged so the
//! only work on the chain is what depends on the newest value `b`:
//! - `a + K + M` (and `c ^ d`, `c & !d`, `!d`) only involve older values and are
//!   computed while the previous step is still in flight;
//! - F = `d ^ (b & (c ^ d))`: 2 ops on the chain; G = `(b & d) + (c & !d)` (the two
//!   terms are bitwise disjoint, so `|` is `+`, and the `c & !d` half joins the
//!   off-chain sum): 1 op; H = `b ^ (c ^ d)`: 1 op; I = `c ^ (b | !d)`: 2 ops.
//!
//! That is 5/4/4/5 cycles per step (op(s), add, rotate, add) = 288 cycles per
//! 64-byte block, 4.5 cycles/byte: the floor for a single message on any core with
//! 1-cycle ALU ops. The block's closing `state += (a, b, c, d)` would add one more
//! cycle to the chain; the last step instead adds its rotated sum to the
//! precomputed `state.b + c`. Measured: 288.3 cycles/block (OpenSSL's hand-written
//! asm: 289.4).
//!
//! Getting there needs exact instruction selection, which LLVM does not give: it
//! reassociates `(a + K + M) + f` into `(a + M + f) + K` (one more add on the
//! chain) and spends ~3% more on the scheduling of what remains. So on x86_64 the
//! chain part of each step is a 6-7 instruction `asm!` block (everything off the
//! chain -- message loads, `a + K + M` -- is still left to the compiler), and other
//! targets use the same steps in plain Rust ([`compress_portable`], which the tests
//! also run on x86_64). The block loop is fully unrolled, reads each message word
//! straight from the input and keeps the state in registers across blocks.

use super::gpr;

// K[i] = floor(2^32 * abs(sin(i + 1))), precomputed as in RFC 1321.
const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

const INIT: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

/// Expands to a whole block-loop compression function whose 64 steps are
/// `$step!(F|G|H|I, a, b, c, d, t, s, bb)` invocations computing
/// `a = bb + rotl(t + f(b, c, d), s)`, where `t` = `a + K[i] + M[g]` is the
/// off-chain part and `bb` is normally `b` (the last step passes `sb + b`).
macro_rules! md5_compress_fn {
    ($(#[$attr:meta])* $name:ident, $step:ident) => {
        $(#[$attr])*
        fn $name(state: &mut [u32; 4], blocks: &[u8]) {
            debug_assert!(blocks.len().is_multiple_of(64));
            let [mut sa, mut sb, mut sc, mut sd] = *state;
            for block in blocks.chunks_exact(64) {
                let m = |i: usize| u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
                let (mut a, mut b, mut c, mut d) = (sa, sb, sc, sd);
                // Four steps rotate the roles of a,b,c,d back to where they started.
                macro_rules! round {
                    ($f:ident, $i0:expr, [$g0:expr, $g1:expr, $g2:expr, $g3:expr], [$s0:expr, $s1:expr, $s2:expr, $s3:expr]) => {
                        #[allow(unused_mut)]
                        let mut t = a.wrapping_add(K[$i0]).wrapping_add(m($g0));
                        $step!($f, a, b, c, d, t, $s0, b);
                        #[allow(unused_mut)]
                        let mut t = d.wrapping_add(K[$i0 + 1]).wrapping_add(m($g1));
                        $step!($f, d, a, b, c, t, $s1, a);
                        #[allow(unused_mut)]
                        let mut t = c.wrapping_add(K[$i0 + 2]).wrapping_add(m($g2));
                        $step!($f, c, d, a, b, t, $s2, d);
                        #[allow(unused_mut)]
                        let mut t = b.wrapping_add(K[$i0 + 3]).wrapping_add(m($g3));
                        $step!($f, b, c, d, a, t, $s3, c);
                    };
                }
                round!(F, 0, [0, 1, 2, 3], [7, 12, 17, 22]);
                round!(F, 4, [4, 5, 6, 7], [7, 12, 17, 22]);
                round!(F, 8, [8, 9, 10, 11], [7, 12, 17, 22]);
                round!(F, 12, [12, 13, 14, 15], [7, 12, 17, 22]);
                round!(G, 16, [1, 6, 11, 0], [5, 9, 14, 20]);
                round!(G, 20, [5, 10, 15, 4], [5, 9, 14, 20]);
                round!(G, 24, [9, 14, 3, 8], [5, 9, 14, 20]);
                round!(G, 28, [13, 2, 7, 12], [5, 9, 14, 20]);
                round!(H, 32, [5, 8, 11, 14], [4, 11, 16, 23]);
                round!(H, 36, [1, 4, 7, 10], [4, 11, 16, 23]);
                round!(H, 40, [13, 0, 3, 6], [4, 11, 16, 23]);
                round!(H, 44, [9, 12, 15, 2], [4, 11, 16, 23]);
                round!(I, 48, [0, 7, 14, 5], [6, 10, 15, 21]);
                round!(I, 52, [12, 3, 10, 1], [6, 10, 15, 21]);
                round!(I, 56, [8, 15, 6, 13], [6, 10, 15, 21]);
                // Last round by hand: its final step writes b = c + rotl(..), and
                // sb + b is folded in as (sb + c) + rotl(..), off the chain.
                #[allow(unused_mut)]
                let mut t = a.wrapping_add(K[60]).wrapping_add(m(4));
                $step!(I, a, b, c, d, t, 6, b);
                #[allow(unused_mut)]
                let mut t = d.wrapping_add(K[61]).wrapping_add(m(11));
                $step!(I, d, a, b, c, t, 10, a);
                #[allow(unused_mut)]
                let mut t = c.wrapping_add(K[62]).wrapping_add(m(2));
                $step!(I, c, d, a, b, t, 15, d);
                #[allow(unused_mut)]
                let mut t = b.wrapping_add(K[63]).wrapping_add(m(9));
                let sb_c = sb.wrapping_add(c);
                $step!(I, b, c, d, a, t, 21, sb_c);
                sa = sa.wrapping_add(a);
                sb = b;
                sc = sc.wrapping_add(c);
                sd = sd.wrapping_add(d);
            }
            *state = [sa, sb, sc, sd];
        }
    };
}

/// Portable step: `$a = $b + rotl($t + f, s)`. `gpr` pins the off-chain sum so
/// LLVM cannot move the constant add behind `f`; G's `b & d` is `andn(!d, b)` on a
/// pinned `!d` so no register copy of `b` lands on the chain.
macro_rules! step_rust {
    (F, $a:ident, $b:ident, $c:ident, $d:ident, $t:ident, $s:expr, $bb:expr) => {
        $a = $bb.wrapping_add(gpr($t).wrapping_add($d ^ ($b & ($c ^ $d))).rotate_left($s));
    };
    (G, $a:ident, $b:ident, $c:ident, $d:ident, $t:ident, $s:expr, $bb:expr) => {
        let nd = gpr(!$d);
        $a = $bb.wrapping_add(
            gpr($t.wrapping_add($c & nd))
                .wrapping_add($b & !nd)
                .rotate_left($s),
        );
    };
    (H, $a:ident, $b:ident, $c:ident, $d:ident, $t:ident, $s:expr, $bb:expr) => {
        $a = $bb.wrapping_add(gpr($t).wrapping_add($b ^ ($c ^ $d)).rotate_left($s));
    };
    (I, $a:ident, $b:ident, $c:ident, $d:ident, $t:ident, $s:expr, $bb:expr) => {
        $a = $bb.wrapping_add(gpr($t).wrapping_add($c ^ ($b | !$d)).rotate_left($s));
    };
}

/// x86_64 step: the same operations, instruction for instruction. Only baseline
/// x86_64 instructions (`rol`, not BMI2 `rorx`; measured equal).
#[cfg(target_arch = "x86_64")]
macro_rules! step_asm {
    ($f:ident, $a:ident, $b:ident, $c:ident, $d:ident, $t:ident, $s:expr, $bb:expr) => {
        // Safety: pure register arithmetic, no memory or stack access.
        unsafe {
            std::arch::asm!(
                step_asm!(@ops $f),
                "add {t:e}, {x:e}", "rol {t:e}, {s}", "add {t:e}, {bb:e}",
                t = inout(reg) $t, b = in(reg) $b, c = in(reg) $c, d = in(reg) $d,
                bb = in(reg) $bb, x = out(reg) _, s = const $s, options(pure, nomem, nostack),
            )
        };
        $a = $t;
    };
    // x = f(b, c, d); G also folds its off-chain `c & !d` into t first.
    (@ops F) => { "mov {x:e}, {c:e}\n xor {x:e}, {d:e}\n and {x:e}, {b:e}\n xor {x:e}, {d:e}" };
    (@ops G) => { "mov {x:e}, {d:e}\n not {x:e}\n and {x:e}, {c:e}\n add {t:e}, {x:e}\n mov {x:e}, {d:e}\n and {x:e}, {b:e}" };
    (@ops H) => { "mov {x:e}, {c:e}\n xor {x:e}, {d:e}\n xor {x:e}, {b:e}" };
    (@ops I) => { "mov {x:e}, {d:e}\n not {x:e}\n or {x:e}, {b:e}\n xor {x:e}, {c:e}" };
}

md5_compress_fn!(
    /// Plain-Rust compression over every 64-byte block of `blocks`: the
    /// implementation off x86_64, and the cross-check for `compress_asm`.
    #[cfg_attr(target_arch = "x86_64", allow(dead_code))]
    compress_portable,
    step_rust
);

#[cfg(target_arch = "x86_64")]
md5_compress_fn!(
    /// x86_64 compression over every 64-byte block of `blocks`.
    compress_asm,
    step_asm
);

/// Runs the compression function over every 64-byte block of `blocks`
/// (`blocks.len()` must be a multiple of 64).
#[inline]
fn compress(state: &mut [u32; 4], blocks: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    compress_asm(state, blocks);
    #[cfg(not(target_arch = "x86_64"))]
    compress_portable(state, blocks);
}

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
            state: INIT,
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

    pub fn finalize(mut self) -> [u8; 16] {
        // Pad in place: 0x80, zeros, then the 64-bit little-endian bit length,
        // spilling into a second block when fewer than 8 bytes remain.
        let n = self.buf_len;
        let mut tail = [0u8; 128];
        tail[..n].copy_from_slice(&self.buf[..n]);
        tail[n] = 0x80;
        let total = if n < 56 { 64 } else { 128 };
        tail[total - 8..total].copy_from_slice(&self.len.wrapping_mul(8).to_le_bytes());
        compress(&mut self.state, &tail[..total]);

        let mut out = [0u8; 16];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
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

    /// Textbook RFC 1321 block function (one loop, the round function and message
    /// index picked per step) -- the reference for the scheduled `compress`.
    fn reference_block(state: &mut [u32; 4], block: &[u8]) {
        const S: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
        let m: Vec<u32> = block
            .chunks_exact(4)
            .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
            .collect();
        let [mut a, mut b, mut c, mut d] = *state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((b & d) | (c & !d), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let t = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            (a, d, c) = (d, c, b);
            b = b.wrapping_add(t.rotate_left(S[4 * (i / 16) + i % 4]));
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d]) {
            *s = s.wrapping_add(v);
        }
    }

    #[test]
    fn compress_matches_reference_on_random_blocks() {
        let mut x: u64 = 0x0123_4567_89AB_CDEF;
        let data: Vec<u8> = (0..64 * 40)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        for nblocks in [1usize, 2, 3, 40] {
            let mut slow = INIT;
            for block in data[..64 * nblocks].chunks_exact(64) {
                reference_block(&mut slow, block);
            }
            let mut fast = INIT;
            compress(&mut fast, &data[..64 * nblocks]);
            assert_eq!(fast, slow, "nblocks={nblocks}");
            let mut portable = INIT;
            compress_portable(&mut portable, &data[..64 * nblocks]);
            assert_eq!(portable, slow, "portable, nblocks={nblocks}");
        }
    }
}
