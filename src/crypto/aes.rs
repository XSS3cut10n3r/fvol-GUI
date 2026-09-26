// Derived from Volatility 3 (Volatility Software License 1.0); see LICENSE.txt.
//! AES (FIPS-197), 128/192/256-bit keys. volatility3 uses `Crypto.Cipher.AES` in
//! `windows/registry/hashdump.py`, `lsadump.py` and `cachedump.py` for the
//! "revision 3" / Vista-and-later SAM/LSA secret formats:
//! - `Hashdump.get_hbootkey` (revision 3): `AES.new(bootkey, AES.MODE_CBC, iv)`,
//!   a single `decrypt()` call over 2 chained 16-byte blocks -> use
//!   [`Aes::cbc_decrypt`].
//! - `Hashdump.decrypt_single_salted_hash`: `AES.new(hbootkey[:16], AES.MODE_CBC,
//!   salt)` over exactly one 16-byte block -> [`Aes::cbc_decrypt`] (a single
//!   block makes CBC and ECB-with-that-IV equivalent, but callers should still
//!   use `cbc_decrypt` for clarity/consistency).
//! - `Lsadump.decrypt_aes` (1000-iteration SHA-256 LSA key derivation): *re-creates*
//!   a fresh `AES.new(key, AES.MODE_CBC, b"\x00" * 16)` cipher object **inside** the
//!   loop, once per 16-byte chunk. Because the object (and therefore pycryptodome's
//!   internal chaining state) is discarded every iteration, the IV never advances --
//!   this is mathematically plain ECB (the zero IV is a no-op either way). Use
//!   [`Aes::ecb_decrypt`] (or [`Aes::ecb_decrypt_with_iv`] for the general fixed,
//!   non-advancing-IV form) for this. **Do not use `cbc_decrypt` here.**
//! - `Cachedump.decrypt_hash` (non-XP cached credentials): creates **one**
//!   `AES.new(key, AES.MODE_CBC, ch)` object *before* the loop and calls
//!   `.decrypt()` repeatedly on that *same* object, once per chunk. pycryptodome
//!   keeps CBC chaining state across repeated calls on one cipher object, so this
//!   *is* real chained CBC over the whole buffer -- byte-identical to a single
//!   [`Aes::cbc_decrypt`] call on the concatenated data. **Do not use
//!   `ecb_decrypt_with_iv` here** -- that would (incorrectly) reset the chain every
//!   block. This distinction was verified empirically against pycryptodome (see
//!   `gen_vectors.py`'s `AES_CACHEDUMP_REUSED_CIPHER_VECTORS`, which reproduces
//!   cachedump.py's exact object-reuse loop and asserts it equals one-shot CBC).
//!
//! In both cases a short final chunk is zero-padded on the right before
//! decryption, matching the plugins' own manual zero-padding.
//!
//! ## Implementation
//!
//! Three paths, chosen once per process (`hw_level`) and recorded in each `Aes`:
//! - **VAES** (x86_64 with VAES+AVX2): the buffer calls run 16 blocks (eight 256-bit
//!   registers, two blocks each) through the rounds together. One `vaesdec` has a
//!   3-cycle latency but the core issues two per cycle, so it takes >= 6 independent
//!   chains to keep both AES units busy; 8 chains of 2 blocks do, and reach twice
//!   what OpenSSL's 8-way xmm AES-NI loop can (it is port-bound at 1 block per 5
//!   cycles for AES-128). The CBC XOR with the previous ciphertext block is fused
//!   into the same pass (a load of the input at offset -16), so there is exactly one
//!   read and one write of the data, and output buffers are never zero-filled first.
//! - **AES-NI** (x86_64 without VAES): the same kernels with 8 xmm registers.
//! - **portable** byte-oriented reference implementation (everything else); also
//!   the ground truth every hardware path is cross-checked against in the tests.
//!
//! Key expansion on the hardware paths runs entirely in registers with
//! `aesenclast`: broadcasting `RotWord(w3)` to all four columns makes ShiftRows a
//! no-op, so `aesenclast(x, rcon)` computes `SubWord(RotWord(w3)) ^ rcon` in 4
//! cycles (`aeskeygenassist` takes ~15 on this core). The decryption schedule
//! (`aesimc` of every middle round key) is built in the same pass, so `Aes::new`
//! for AES-128 costs a few dozen cycles. AES-192 (unused by volatility3) expands
//! with the portable code and then derives the same hardware schedules.

use crate::error::{Error, Result};
use std::sync::OnceLock;

// --- S-box construction (GF(2^8) multiplicative inverse + affine transform),
// computed once at first use instead of transcribing a 256-entry literal table.
// Only the portable path (and AES-192 key expansion) touches these. ---

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

fn build_sbox() -> ([u8; 256], [u8; 256]) {
    // Multiplicative inverse in GF(2^8), with inv[0] = 0 by AES convention.
    let mut inv = [0u8; 256];
    for a in 1..256u16 {
        for b in 1..256u16 {
            if gf_mul(a as u8, b as u8) == 1 {
                inv[a as usize] = b as u8;
                break;
            }
        }
    }

    let mut sbox = [0u8; 256];
    for (x, &y) in inv.iter().enumerate() {
        let r1 = y.rotate_left(1);
        let r2 = y.rotate_left(2);
        let r3 = y.rotate_left(3);
        let r4 = y.rotate_left(4);
        sbox[x] = y ^ r1 ^ r2 ^ r3 ^ r4 ^ 0x63;
    }

    let mut inv_sbox = [0u8; 256];
    for (x, &s) in sbox.iter().enumerate() {
        inv_sbox[s as usize] = x as u8;
    }

    (sbox, inv_sbox)
}

fn sboxes() -> &'static ([u8; 256], [u8; 256]) {
    static SBOX: OnceLock<([u8; 256], [u8; 256])> = OnceLock::new();
    SBOX.get_or_init(build_sbox)
}

fn sbox() -> &'static [u8; 256] {
    &sboxes().0
}

fn inv_sbox() -> &'static [u8; 256] {
    &sboxes().1
}

fn rcon(i: u32) -> u8 {
    // i is 1-indexed; rcon(i) = x^(i-1) in GF(2^8).
    let mut v: u8 = 1;
    for _ in 1..i {
        let hi = v & 0x80;
        v <<= 1;
        if hi != 0 {
            v ^= 0x1B;
        }
    }
    v
}

/// Round keys as 16-byte blocks: up to Nr+1 = 15 of them (AES-256).
type Keys = [[u8; 16]; 15];

/// FIPS-197 key expansion, byte-oriented. The only expansion on non-AES-NI
/// machines, the AES-192 expansion everywhere, and the reference the AES-NI
/// expansion is tested against. `key.len()` must be 16, 24 or 32.
fn expand_portable(key: &[u8], out: &mut Keys) {
    let nk = key.len() / 4;
    let nr = nk + 6;
    let total_words = 4 * (nr + 1);
    let sb = sbox();
    let mut w = [[0u8; 4]; 60];
    for i in 0..nk {
        w[i].copy_from_slice(&key[i * 4..i * 4 + 4]);
    }
    for i in nk..total_words {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = [temp[1], temp[2], temp[3], temp[0]]; // RotWord
            for b in temp.iter_mut() {
                *b = sb[*b as usize]; // SubWord
            }
            temp[0] ^= rcon((i / nk) as u32);
        } else if nk > 6 && i % nk == 4 {
            for b in temp.iter_mut() {
                *b = sb[*b as usize];
            }
        }
        for j in 0..4 {
            w[i][j] = w[i - nk][j] ^ temp[j];
        }
    }
    for (r, rk) in out.iter_mut().enumerate().take(nr + 1) {
        for c in 0..4 {
            rk[c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c]);
        }
    }
}

/// Which implementation an `Aes` uses. Ordered: each level implies the ones below.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Hw {
    Portable = 0,
    Ni = 1,
    Vaes = 2,
}

/// Best implementation this CPU supports, detected once per process (the feature
/// checks fold to constants when compiled with the features enabled).
fn hw_level() -> Hw {
    #[cfg(target_arch = "x86_64")]
    {
        use std::sync::atomic::{AtomicU8, Ordering};
        static LEVEL: AtomicU8 = AtomicU8::new(u8::MAX);
        match LEVEL.load(Ordering::Relaxed) {
            0 => return Hw::Portable,
            1 => return Hw::Ni,
            2 => return Hw::Vaes,
            _ => {}
        }
        let lvl = if is_x86_feature_detected!("aes")
            && is_x86_feature_detected!("sse2")
            && is_x86_feature_detected!("ssse3")
        {
            if is_x86_feature_detected!("vaes") && is_x86_feature_detected!("avx2") {
                Hw::Vaes
            } else {
                Hw::Ni
            }
        } else {
            Hw::Portable
        };
        LEVEL.store(lvl as u8, Ordering::Relaxed);
        lvl
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Hw::Portable
    }
}

/// What the bulk decrypt kernels XOR into each decrypted block.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Chain {
    /// Nothing (plain ECB).
    None,
    /// The same fixed IV into every block (lsadump's fresh-cipher-per-chunk pattern).
    FixedIv,
    /// The previous ciphertext block (true CBC).
    Cbc,
}

// --- x86_64 hardware kernels. Every function here is `unsafe` + `target_feature`:
// callers must have checked `hw_level()` (recorded in `Aes::hw`). Round keys are read
// straight from the `Aes` arrays (a broadcast load per round, shared by all blocks in
// flight -- far cheaper than keeping 11-15 keys pinned in registers). ---
#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::{Chain, Keys};
    use std::arch::x86_64::*;

    macro_rules! k128 {
        ($keys:expr, $r:expr) => {
            _mm_loadu_si128(($keys).as_ptr().add($r).cast::<__m128i>())
        };
    }
    macro_rules! k256 {
        ($keys:expr, $r:expr) => {
            _mm256_broadcastsi128_si256(k128!($keys, $r))
        };
    }

    /// AES-128/AES-256 key expansion (`key.len()` 16 or 32) into `enc`, plus the
    /// equivalent-inverse-cipher schedule for `aesdec` into `dec`: `dec[0] = enc[nr]`,
    /// `dec[i] = InvMixColumns(enc[nr - i])`, `dec[nr] = enc[0]`.
    #[target_feature(enable = "aes,sse2,ssse3")]
    pub unsafe fn expand(key: &[u8], enc: &mut Keys, dec: &mut Keys) {
        unsafe {
            // RotWord(w3) / w3 broadcast to all four columns (ShiftRows then is a no-op,
            // so aesenclast(x, rcon) = SubWord(x) ^ rcon in every column).
            let rot = _mm_setr_epi8(13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12);
            let bcast = _mm_setr_epi8(12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15);
            macro_rules! prefix_xor {
                ($k:expr) => {{
                    let k = $k;
                    let k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
                    _mm_xor_si128(k, _mm_slli_si128::<8>(k))
                }};
            }
            let mut ks = [_mm_setzero_si128(); 15];
            let nr;
            if key.len() == 16 {
                nr = 10;
                let mut k = _mm_loadu_si128(key.as_ptr().cast());
                ks[0] = k;
                macro_rules! step {
                    ($i:expr, $rc:expr) => {
                        let t = _mm_aesenclast_si128(_mm_shuffle_epi8(k, rot), _mm_set1_epi32($rc));
                        k = _mm_xor_si128(prefix_xor!(k), t);
                        ks[$i] = k;
                    };
                }
                step!(1, 0x01);
                step!(2, 0x02);
                step!(3, 0x04);
                step!(4, 0x08);
                step!(5, 0x10);
                step!(6, 0x20);
                step!(7, 0x40);
                step!(8, 0x80);
                step!(9, 0x1b);
                step!(10, 0x36);
            } else {
                debug_assert_eq!(key.len(), 32);
                nr = 14;
                let mut a = _mm_loadu_si128(key.as_ptr().cast());
                let mut b = _mm_loadu_si128(key.as_ptr().add(16).cast());
                ks[0] = a;
                ks[1] = b;
                macro_rules! even {
                    ($i:expr, $rc:expr) => {
                        let t = _mm_aesenclast_si128(_mm_shuffle_epi8(b, rot), _mm_set1_epi32($rc));
                        a = _mm_xor_si128(prefix_xor!(a), t);
                        ks[$i] = a;
                    };
                }
                macro_rules! odd {
                    ($i:expr) => {
                        let t = _mm_aesenclast_si128(_mm_shuffle_epi8(a, bcast), _mm_setzero_si128());
                        b = _mm_xor_si128(prefix_xor!(b), t);
                        ks[$i] = b;
                    };
                }
                even!(2, 0x01);
                odd!(3);
                even!(4, 0x02);
                odd!(5);
                even!(6, 0x04);
                odd!(7);
                even!(8, 0x08);
                odd!(9);
                even!(10, 0x10);
                odd!(11);
                even!(12, 0x20);
                odd!(13);
                even!(14, 0x40);
            }
            for i in 0..=nr {
                _mm_storeu_si128(enc[i].as_mut_ptr().cast(), ks[i]);
            }
            _mm_storeu_si128(dec[0].as_mut_ptr().cast(), ks[nr]);
            for i in 1..nr {
                _mm_storeu_si128(dec[i].as_mut_ptr().cast(), _mm_aesimc_si128(ks[nr - i]));
            }
            _mm_storeu_si128(dec[nr].as_mut_ptr().cast(), ks[0]);
        }
    }

    /// Builds the `aesdec` schedule from an already-expanded `enc` (AES-192 path).
    #[target_feature(enable = "aes,sse2")]
    pub unsafe fn invert(enc: &Keys, dec: &mut Keys, nr: usize) {
        unsafe {
            dec[0] = enc[nr];
            for i in 1..nr {
                _mm_storeu_si128(dec[i].as_mut_ptr().cast(), _mm_aesimc_si128(k128!(enc, nr - i)));
            }
            dec[nr] = enc[0];
        }
    }

    #[target_feature(enable = "aes,sse2")]
    pub unsafe fn encrypt1(enc: &Keys, nr: usize, block: &mut [u8; 16]) {
        unsafe {
            let mut b = _mm_xor_si128(_mm_loadu_si128(block.as_ptr().cast()), k128!(enc, 0));
            for r in 1..nr {
                b = _mm_aesenc_si128(b, k128!(enc, r));
            }
            b = _mm_aesenclast_si128(b, k128!(enc, nr));
            _mm_storeu_si128(block.as_mut_ptr().cast(), b);
        }
    }

    #[target_feature(enable = "aes,sse2")]
    pub unsafe fn decrypt1(dec: &Keys, nr: usize, block: &mut [u8; 16]) {
        unsafe {
            let mut b = _mm_xor_si128(_mm_loadu_si128(block.as_ptr().cast()), k128!(dec, 0));
            for r in 1..nr {
                b = _mm_aesdec_si128(b, k128!(dec, r));
            }
            b = _mm_aesdeclast_si128(b, k128!(dec, nr));
            _mm_storeu_si128(block.as_mut_ptr().cast(), b);
        }
    }

    /// Decrypts `n` 16-byte blocks from `inp` to `out` and XORs in `chain` (see
    /// [`Chain`]); `iv` is the CBC IV / the fixed IV. `inp == out` (in place) is
    /// allowed: every input a group needs (including the previous-ciphertext blocks
    /// CBC XORs in) is loaded before that group's outputs are stored. Tail blocks
    /// that don't fill a 16-block group go 2 at a time, then 1.
    #[target_feature(enable = "vaes,avx2,aes,sse2")]
    pub unsafe fn decrypt_vaes(
        dec: &Keys,
        nr: usize,
        chain: Chain,
        iv: &[u8; 16],
        mut inp: *const u8,
        mut out: *mut u8,
        mut n: usize,
    ) {
        unsafe {
            let mut prev = _mm_loadu_si128(iv.as_ptr().cast());
            let ivv = _mm256_broadcastsi128_si256(prev);
            macro_rules! ld {
                ($off:expr) => {
                    _mm256_loadu_si256(inp.add($off).cast::<__m256i>())
                };
            }
            macro_rules! st {
                ($off:expr, $v:expr) => {
                    _mm256_storeu_si256(out.add($off).cast::<__m256i>(), $v)
                };
            }
            while n >= 16 {
                let k = k256!(dec, 0);
                let mut b0 = _mm256_xor_si256(ld!(0), k);
                let mut b1 = _mm256_xor_si256(ld!(32), k);
                let mut b2 = _mm256_xor_si256(ld!(64), k);
                let mut b3 = _mm256_xor_si256(ld!(96), k);
                let mut b4 = _mm256_xor_si256(ld!(128), k);
                let mut b5 = _mm256_xor_si256(ld!(160), k);
                let mut b6 = _mm256_xor_si256(ld!(192), k);
                let mut b7 = _mm256_xor_si256(ld!(224), k);
                for r in 1..nr {
                    let k = k256!(dec, r);
                    b0 = _mm256_aesdec_epi128(b0, k);
                    b1 = _mm256_aesdec_epi128(b1, k);
                    b2 = _mm256_aesdec_epi128(b2, k);
                    b3 = _mm256_aesdec_epi128(b3, k);
                    b4 = _mm256_aesdec_epi128(b4, k);
                    b5 = _mm256_aesdec_epi128(b5, k);
                    b6 = _mm256_aesdec_epi128(b6, k);
                    b7 = _mm256_aesdec_epi128(b7, k);
                }
                let k = k256!(dec, nr);
                b0 = _mm256_aesdeclast_epi128(b0, k);
                b1 = _mm256_aesdeclast_epi128(b1, k);
                b2 = _mm256_aesdeclast_epi128(b2, k);
                b3 = _mm256_aesdeclast_epi128(b3, k);
                b4 = _mm256_aesdeclast_epi128(b4, k);
                b5 = _mm256_aesdeclast_epi128(b5, k);
                b6 = _mm256_aesdeclast_epi128(b6, k);
                b7 = _mm256_aesdeclast_epi128(b7, k);
                match chain {
                    Chain::Cbc => {
                        // Register r holds blocks 2r, 2r+1; their chaining values are
                        // ciphertext blocks 2r-1, 2r = the input at byte offset 32r-16.
                        let x0 = _mm256_inserti128_si256::<1>(
                            _mm256_castsi128_si256(prev),
                            _mm_loadu_si128(inp.cast()),
                        );
                        b0 = _mm256_xor_si256(b0, x0);
                        b1 = _mm256_xor_si256(b1, ld!(16));
                        b2 = _mm256_xor_si256(b2, ld!(48));
                        b3 = _mm256_xor_si256(b3, ld!(80));
                        b4 = _mm256_xor_si256(b4, ld!(112));
                        b5 = _mm256_xor_si256(b5, ld!(144));
                        b6 = _mm256_xor_si256(b6, ld!(176));
                        b7 = _mm256_xor_si256(b7, ld!(208));
                        prev = _mm_loadu_si128(inp.add(240).cast());
                    }
                    Chain::FixedIv => {
                        b0 = _mm256_xor_si256(b0, ivv);
                        b1 = _mm256_xor_si256(b1, ivv);
                        b2 = _mm256_xor_si256(b2, ivv);
                        b3 = _mm256_xor_si256(b3, ivv);
                        b4 = _mm256_xor_si256(b4, ivv);
                        b5 = _mm256_xor_si256(b5, ivv);
                        b6 = _mm256_xor_si256(b6, ivv);
                        b7 = _mm256_xor_si256(b7, ivv);
                    }
                    Chain::None => {}
                }
                st!(0, b0);
                st!(32, b1);
                st!(64, b2);
                st!(96, b3);
                st!(128, b4);
                st!(160, b5);
                st!(192, b6);
                st!(224, b7);
                inp = inp.add(256);
                out = out.add(256);
                n -= 16;
            }
            while n >= 2 {
                let mut b = _mm256_xor_si256(ld!(0), k256!(dec, 0));
                for r in 1..nr {
                    b = _mm256_aesdec_epi128(b, k256!(dec, r));
                }
                b = _mm256_aesdeclast_epi128(b, k256!(dec, nr));
                match chain {
                    Chain::Cbc => {
                        let x = _mm256_inserti128_si256::<1>(
                            _mm256_castsi128_si256(prev),
                            _mm_loadu_si128(inp.cast()),
                        );
                        b = _mm256_xor_si256(b, x);
                        prev = _mm_loadu_si128(inp.add(16).cast());
                    }
                    Chain::FixedIv => b = _mm256_xor_si256(b, ivv),
                    Chain::None => {}
                }
                st!(0, b);
                inp = inp.add(32);
                out = out.add(32);
                n -= 2;
            }
            if n == 1 {
                let c = _mm_loadu_si128(inp.cast());
                let mut b = _mm_xor_si128(c, k128!(dec, 0));
                for r in 1..nr {
                    b = _mm_aesdec_si128(b, k128!(dec, r));
                }
                b = _mm_aesdeclast_si128(b, k128!(dec, nr));
                if chain != Chain::None {
                    b = _mm_xor_si128(b, prev); // prev == iv for FixedIv
                }
                _mm_storeu_si128(out.cast(), b);
            }
        }
    }

    /// [`decrypt_vaes`] for CPUs with AES-NI but no VAES: 8 xmm blocks in flight.
    #[target_feature(enable = "aes,sse2")]
    pub unsafe fn decrypt_ni(
        dec: &Keys,
        nr: usize,
        chain: Chain,
        iv: &[u8; 16],
        mut inp: *const u8,
        mut out: *mut u8,
        mut n: usize,
    ) {
        unsafe {
            let ivx = _mm_loadu_si128(iv.as_ptr().cast());
            let mut prev = ivx;
            macro_rules! ld {
                ($off:expr) => {
                    _mm_loadu_si128(inp.add($off).cast::<__m128i>())
                };
            }
            macro_rules! st {
                ($off:expr, $v:expr) => {
                    _mm_storeu_si128(out.add($off).cast::<__m128i>(), $v)
                };
            }
            while n >= 8 {
                let k = k128!(dec, 0);
                let mut b0 = _mm_xor_si128(ld!(0), k);
                let mut b1 = _mm_xor_si128(ld!(16), k);
                let mut b2 = _mm_xor_si128(ld!(32), k);
                let mut b3 = _mm_xor_si128(ld!(48), k);
                let mut b4 = _mm_xor_si128(ld!(64), k);
                let mut b5 = _mm_xor_si128(ld!(80), k);
                let mut b6 = _mm_xor_si128(ld!(96), k);
                let mut b7 = _mm_xor_si128(ld!(112), k);
                for r in 1..nr {
                    let k = k128!(dec, r);
                    b0 = _mm_aesdec_si128(b0, k);
                    b1 = _mm_aesdec_si128(b1, k);
                    b2 = _mm_aesdec_si128(b2, k);
                    b3 = _mm_aesdec_si128(b3, k);
                    b4 = _mm_aesdec_si128(b4, k);
                    b5 = _mm_aesdec_si128(b5, k);
                    b6 = _mm_aesdec_si128(b6, k);
                    b7 = _mm_aesdec_si128(b7, k);
                }
                let k = k128!(dec, nr);
                b0 = _mm_aesdeclast_si128(b0, k);
                b1 = _mm_aesdeclast_si128(b1, k);
                b2 = _mm_aesdeclast_si128(b2, k);
                b3 = _mm_aesdeclast_si128(b3, k);
                b4 = _mm_aesdeclast_si128(b4, k);
                b5 = _mm_aesdeclast_si128(b5, k);
                b6 = _mm_aesdeclast_si128(b6, k);
                b7 = _mm_aesdeclast_si128(b7, k);
                match chain {
                    Chain::Cbc => {
                        b0 = _mm_xor_si128(b0, prev);
                        b1 = _mm_xor_si128(b1, ld!(0));
                        b2 = _mm_xor_si128(b2, ld!(16));
                        b3 = _mm_xor_si128(b3, ld!(32));
                        b4 = _mm_xor_si128(b4, ld!(48));
                        b5 = _mm_xor_si128(b5, ld!(64));
                        b6 = _mm_xor_si128(b6, ld!(80));
                        b7 = _mm_xor_si128(b7, ld!(96));
                        prev = ld!(112);
                    }
                    Chain::FixedIv => {
                        b0 = _mm_xor_si128(b0, ivx);
                        b1 = _mm_xor_si128(b1, ivx);
                        b2 = _mm_xor_si128(b2, ivx);
                        b3 = _mm_xor_si128(b3, ivx);
                        b4 = _mm_xor_si128(b4, ivx);
                        b5 = _mm_xor_si128(b5, ivx);
                        b6 = _mm_xor_si128(b6, ivx);
                        b7 = _mm_xor_si128(b7, ivx);
                    }
                    Chain::None => {}
                }
                st!(0, b0);
                st!(16, b1);
                st!(32, b2);
                st!(48, b3);
                st!(64, b4);
                st!(80, b5);
                st!(96, b6);
                st!(112, b7);
                inp = inp.add(128);
                out = out.add(128);
                n -= 8;
            }
            while n > 0 {
                let c = ld!(0);
                let mut b = _mm_xor_si128(c, k128!(dec, 0));
                for r in 1..nr {
                    b = _mm_aesdec_si128(b, k128!(dec, r));
                }
                b = _mm_aesdeclast_si128(b, k128!(dec, nr));
                match chain {
                    Chain::Cbc => {
                        b = _mm_xor_si128(b, prev);
                        prev = c;
                    }
                    Chain::FixedIv => b = _mm_xor_si128(b, ivx),
                    Chain::None => {}
                }
                st!(0, b);
                inp = inp.add(16);
                out = out.add(16);
                n -= 1;
            }
        }
    }

    /// ECB-encrypts `n` blocks from `inp` to `out` (may alias), 16 at a time.
    #[target_feature(enable = "vaes,avx2,aes,sse2")]
    pub unsafe fn ecb_encrypt_vaes(enc: &Keys, nr: usize, mut inp: *const u8, mut out: *mut u8, mut n: usize) {
        unsafe {
            while n >= 16 {
                let p = inp.cast::<__m256i>();
                let k = k256!(enc, 0);
                let mut b0 = _mm256_xor_si256(_mm256_loadu_si256(p), k);
                let mut b1 = _mm256_xor_si256(_mm256_loadu_si256(p.add(1)), k);
                let mut b2 = _mm256_xor_si256(_mm256_loadu_si256(p.add(2)), k);
                let mut b3 = _mm256_xor_si256(_mm256_loadu_si256(p.add(3)), k);
                let mut b4 = _mm256_xor_si256(_mm256_loadu_si256(p.add(4)), k);
                let mut b5 = _mm256_xor_si256(_mm256_loadu_si256(p.add(5)), k);
                let mut b6 = _mm256_xor_si256(_mm256_loadu_si256(p.add(6)), k);
                let mut b7 = _mm256_xor_si256(_mm256_loadu_si256(p.add(7)), k);
                for r in 1..nr {
                    let k = k256!(enc, r);
                    b0 = _mm256_aesenc_epi128(b0, k);
                    b1 = _mm256_aesenc_epi128(b1, k);
                    b2 = _mm256_aesenc_epi128(b2, k);
                    b3 = _mm256_aesenc_epi128(b3, k);
                    b4 = _mm256_aesenc_epi128(b4, k);
                    b5 = _mm256_aesenc_epi128(b5, k);
                    b6 = _mm256_aesenc_epi128(b6, k);
                    b7 = _mm256_aesenc_epi128(b7, k);
                }
                let k = k256!(enc, nr);
                let o = out.cast::<__m256i>();
                _mm256_storeu_si256(o, _mm256_aesenclast_epi128(b0, k));
                _mm256_storeu_si256(o.add(1), _mm256_aesenclast_epi128(b1, k));
                _mm256_storeu_si256(o.add(2), _mm256_aesenclast_epi128(b2, k));
                _mm256_storeu_si256(o.add(3), _mm256_aesenclast_epi128(b3, k));
                _mm256_storeu_si256(o.add(4), _mm256_aesenclast_epi128(b4, k));
                _mm256_storeu_si256(o.add(5), _mm256_aesenclast_epi128(b5, k));
                _mm256_storeu_si256(o.add(6), _mm256_aesenclast_epi128(b6, k));
                _mm256_storeu_si256(o.add(7), _mm256_aesenclast_epi128(b7, k));
                inp = inp.add(256);
                out = out.add(256);
                n -= 16;
            }
            ecb_encrypt_ni(enc, nr, inp, out, n);
        }
    }

    /// ECB-encrypts `n` blocks from `inp` to `out` (may alias), 4 xmm blocks at a time.
    #[target_feature(enable = "aes,sse2")]
    pub unsafe fn ecb_encrypt_ni(enc: &Keys, nr: usize, mut inp: *const u8, mut out: *mut u8, mut n: usize) {
        unsafe {
            while n >= 4 {
                let p = inp.cast::<__m128i>();
                let k = k128!(enc, 0);
                let mut b0 = _mm_xor_si128(_mm_loadu_si128(p), k);
                let mut b1 = _mm_xor_si128(_mm_loadu_si128(p.add(1)), k);
                let mut b2 = _mm_xor_si128(_mm_loadu_si128(p.add(2)), k);
                let mut b3 = _mm_xor_si128(_mm_loadu_si128(p.add(3)), k);
                for r in 1..nr {
                    let k = k128!(enc, r);
                    b0 = _mm_aesenc_si128(b0, k);
                    b1 = _mm_aesenc_si128(b1, k);
                    b2 = _mm_aesenc_si128(b2, k);
                    b3 = _mm_aesenc_si128(b3, k);
                }
                let k = k128!(enc, nr);
                let o = out.cast::<__m128i>();
                _mm_storeu_si128(o, _mm_aesenclast_si128(b0, k));
                _mm_storeu_si128(o.add(1), _mm_aesenclast_si128(b1, k));
                _mm_storeu_si128(o.add(2), _mm_aesenclast_si128(b2, k));
                _mm_storeu_si128(o.add(3), _mm_aesenclast_si128(b3, k));
                inp = inp.add(64);
                out = out.add(64);
                n -= 4;
            }
            while n > 0 {
                let mut b = _mm_xor_si128(_mm_loadu_si128(inp.cast()), k128!(enc, 0));
                for r in 1..nr {
                    b = _mm_aesenc_si128(b, k128!(enc, r));
                }
                _mm_storeu_si128(out.cast(), _mm_aesenclast_si128(b, k128!(enc, nr)));
                inp = inp.add(16);
                out = out.add(16);
                n -= 1;
            }
        }
    }

    /// CBC-encrypts `n` blocks from `inp` to `out` (may alias). Inherently serial.
    #[target_feature(enable = "aes,sse2")]
    pub unsafe fn cbc_encrypt_ni(enc: &Keys, nr: usize, iv: &[u8; 16], mut inp: *const u8, mut out: *mut u8, n: usize) {
        unsafe {
            let mut prev = _mm_loadu_si128(iv.as_ptr().cast());
            for _ in 0..n {
                let mut b = _mm_xor_si128(_mm_loadu_si128(inp.cast()), prev);
                b = _mm_xor_si128(b, k128!(enc, 0));
                for r in 1..nr {
                    b = _mm_aesenc_si128(b, k128!(enc, r));
                }
                prev = _mm_aesenclast_si128(b, k128!(enc, nr));
                _mm_storeu_si128(out.cast(), prev);
                inp = inp.add(16);
                out = out.add(16);
            }
        }
    }
}

/// An expanded AES key (128/192/256-bit), ready to encrypt/decrypt 16-byte blocks.
/// The implementation (VAES / AES-NI / portable, see the module doc comment) is
/// chosen once per process; all of them share the FIPS-197 round keys in `enc`.
#[derive(Clone)]
#[repr(C, align(32))]
pub struct Aes {
    /// FIPS-197 round keys, `enc[r]` = words `w[4r..4r+4]` as bytes.
    enc: Keys,
    /// Hardware paths only: the `aesdec` (equivalent inverse cipher) schedule.
    dec: Keys,
    nr: usize, // number of rounds: 10, 12, or 14
    hw: Hw,
}

impl Aes {
    /// Builds the key schedule. `key` must be 16, 24 or 32 bytes (AES-128/192/256);
    /// any other length returns an error rather than panicking.
    #[inline]
    pub fn new(key: &[u8]) -> Result<Self> {
        Self::with_hw(key, hw_level())
    }

    fn with_hw(key: &[u8], hw: Hw) -> Result<Self> {
        let nr = match key.len() {
            16 => 10,
            24 => 12,
            32 => 14,
            n => {
                return Err(Error::msg(format!(
                    "AES key must be 16, 24 or 32 bytes, got {n}"
                )));
            }
        };
        let mut aes = Aes {
            enc: [[0; 16]; 15],
            dec: [[0; 16]; 15],
            nr,
            hw,
        };
        #[cfg(target_arch = "x86_64")]
        if hw >= Hw::Ni {
            // Safety: hw >= Ni means hw_level() saw aes+sse2+ssse3 on this CPU.
            unsafe {
                if nr == 12 {
                    expand_portable(key, &mut aes.enc);
                    x86::invert(&aes.enc, &mut aes.dec, nr);
                } else {
                    x86::expand(key, &mut aes.enc, &mut aes.dec);
                }
            }
            return Ok(aes);
        }
        expand_portable(key, &mut aes.enc);
        Ok(aes)
    }

    /// True if the 16-blocks-at-a-time VAES path is active on this CPU (used by the
    /// bulk buffer-oriented calls, and by tests to know whether to exercise it).
    /// Always `false` off x86_64 or on a CPU without VAES.
    #[allow(dead_code)]
    pub(crate) fn has_vaes(&self) -> bool {
        self.hw == Hw::Vaes
    }

    /// Encrypts one 16-byte block in place. Dispatches to AES-NI when this CPU
    /// supports it (checked once per process), otherwise the portable path.
    #[inline]
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        #[cfg(target_arch = "x86_64")]
        if self.hw >= Hw::Ni {
            // Safety: hw >= Ni was verified by hw_level().
            unsafe { x86::encrypt1(&self.enc, self.nr, block) };
            return;
        }
        self.encrypt_block_portable(block);
    }

    /// Decrypts one 16-byte block in place. Dispatches to AES-NI when available.
    #[inline]
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        #[cfg(target_arch = "x86_64")]
        if self.hw >= Hw::Ni {
            // Safety: hw >= Ni was verified by hw_level().
            unsafe { x86::decrypt1(&self.dec, self.nr, block) };
            return;
        }
        self.decrypt_block_portable(block);
    }

    /// The portable (no hardware acceleration) block encrypt, exposed for
    /// testing the two paths against each other; prefer [`Aes::encrypt_block`].
    pub fn encrypt_block_portable(&self, block: &mut [u8; 16]) {
        let sb = sbox();
        add_round_key(block, &self.enc[0]);
        for round in 1..self.nr {
            sub_bytes(block, sb);
            shift_rows(block);
            mix_columns(block);
            add_round_key(block, &self.enc[round]);
        }
        sub_bytes(block, sb);
        shift_rows(block);
        add_round_key(block, &self.enc[self.nr]);
    }

    /// The portable (no hardware acceleration) block decrypt, exposed for
    /// testing the two paths against each other; prefer [`Aes::decrypt_block`].
    pub fn decrypt_block_portable(&self, block: &mut [u8; 16]) {
        let isb = inv_sbox();
        add_round_key(block, &self.enc[self.nr]);
        for round in (1..self.nr).rev() {
            inv_shift_rows(block);
            inv_sub_bytes(block, isb);
            add_round_key(block, &self.enc[round]);
            inv_mix_columns(block);
        }
        inv_shift_rows(block);
        inv_sub_bytes(block, isb);
        add_round_key(block, &self.enc[0]);
    }

    /// Decrypts `n` whole blocks from `inp` into `out` (which may be the same
    /// memory) with the given chaining. The one entry point every decrypt API uses.
    ///
    /// Safety: `inp` must be readable and `out` writable for `16 * n` bytes; they
    /// either don't overlap or are exactly equal.
    #[inline]
    unsafe fn decrypt_raw(&self, chain: Chain, iv: &[u8; 16], inp: *const u8, out: *mut u8, n: usize) {
        #[cfg(target_arch = "x86_64")]
        {
            // Safety: hw was verified by hw_level(); pointer contract forwarded.
            if self.hw == Hw::Vaes {
                unsafe { x86::decrypt_vaes(&self.dec, self.nr, chain, iv, inp, out, n) };
                return;
            }
            if self.hw == Hw::Ni {
                unsafe { x86::decrypt_ni(&self.dec, self.nr, chain, iv, inp, out, n) };
                return;
            }
        }
        let mut prev = *iv;
        for i in 0..n {
            let mut block = [0u8; 16];
            // Safety: i < n, caller guarantees 16*n readable/writable bytes.
            unsafe { std::ptr::copy_nonoverlapping(inp.add(16 * i), block.as_mut_ptr(), 16) };
            let ct = block;
            self.decrypt_block_portable(&mut block);
            match chain {
                Chain::None => {}
                Chain::FixedIv => (0..16).for_each(|k| block[k] ^= iv[k]),
                Chain::Cbc => {
                    (0..16).for_each(|k| block[k] ^= prev[k]);
                    prev = ct;
                }
            }
            unsafe { std::ptr::copy_nonoverlapping(block.as_ptr(), out.add(16 * i), 16) };
        }
    }

    /// Decrypts `data` (whole blocks) into a new, never zero-filled `Vec`.
    fn decrypt_to_vec(&self, chain: Chain, iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
        debug_assert!(data.len().is_multiple_of(16));
        let mut out = Vec::with_capacity(data.len());
        // Safety: `out` has capacity for data.len() bytes, all of which
        // decrypt_raw writes before set_len exposes them.
        unsafe {
            self.decrypt_raw(chain, iv, data.as_ptr(), out.as_mut_ptr(), data.len() / 16);
            out.set_len(data.len());
        }
        out
    }

    /// True CBC decryption (IV chained across blocks within this single call),
    /// matching `AES.new(key, AES.MODE_CBC, iv).decrypt(data)` in pycryptodome.
    /// `data.len()` must be a multiple of 16; a short final block is
    /// never produced by pycryptodome (it raises), so this returns an error
    /// instead of guessing at padding.
    pub fn cbc_decrypt(&self, iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(16) {
            return Err(unaligned("AES CBC decrypt", data.len()));
        }
        Ok(self.decrypt_to_vec(Chain::Cbc, iv, data))
    }

    /// [`Aes::cbc_decrypt`] in place, without allocating: `buf` (a multiple of 16
    /// bytes, else an error and `buf` untouched) is replaced by its plaintext.
    pub fn cbc_decrypt_in_place(&self, iv: &[u8; 16], buf: &mut [u8]) -> Result<()> {
        if !buf.len().is_multiple_of(16) {
            return Err(unaligned("AES CBC decrypt", buf.len()));
        }
        let p = buf.as_mut_ptr();
        // Safety: in == out exactly, buf.len() bytes, whole blocks.
        unsafe { self.decrypt_raw(Chain::Cbc, iv, p, p, buf.len() / 16) };
        Ok(())
    }

    /// True CBC encryption, the inverse of [`Aes::cbc_decrypt`].
    pub fn cbc_encrypt(&self, iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(16) {
            return Err(unaligned("AES CBC encrypt", data.len()));
        }
        let mut out = data.to_vec();
        #[cfg(target_arch = "x86_64")]
        if self.hw >= Hw::Ni {
            let p = out.as_mut_ptr();
            // Safety: hw verified; in == out, whole blocks.
            unsafe { x86::cbc_encrypt_ni(&self.enc, self.nr, iv, p, p, out.len() / 16) };
            return Ok(out);
        }
        let mut prev = *iv;
        for chunk in out.chunks_exact_mut(16) {
            let block: &mut [u8; 16] = chunk.try_into().unwrap();
            for i in 0..16 {
                block[i] ^= prev[i];
            }
            self.encrypt_block_portable(block);
            prev = *block;
        }
        Ok(out)
    }

    /// Decrypts each 16-byte chunk of `data` independently, XORing the same
    /// fixed `iv` into every chunk's decrypted output (never chaining). This is
    /// what `lsadump.py`'s `decrypt_aes` actually computes, by re-constructing an
    /// `AES.new(key, MODE_CBC, iv)` object for every chunk instead of reusing one
    /// cipher object across the whole buffer -- see the module-level doc comment.
    /// **This is not what `cachedump.py` does** -- its non-XP path reuses a single
    /// cipher object across chunks, which is real chained CBC; use
    /// [`Aes::cbc_decrypt`] for that instead. A short final chunk is zero-padded
    /// on the right (matching the plugins' own manual padding) rather than
    /// rejected. As in the Python (each chunk is decrypted as a full 16-byte
    /// block), the output for a short final chunk is a full 16 bytes too -- it is
    /// *not* truncated back down to `data.len()` -- so the returned buffer's
    /// length is `data.len()` rounded up to the next multiple of 16.
    pub fn ecb_decrypt_with_iv(&self, iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
        let chain = if *iv == [0u8; 16] { Chain::None } else { Chain::FixedIv };
        let whole = data.len() & !15;
        if whole == data.len() {
            // Common case (block-aligned input, which is every real plugin call).
            return self.decrypt_to_vec(chain, iv, data);
        }
        let mut out = Vec::with_capacity(whole + 16);
        let mut last = [0u8; 16];
        last[..data.len() - whole].copy_from_slice(&data[whole..]);
        // Safety: capacity whole+16; the first `whole` bytes are written by the
        // first call, the final block by the second, before set_len.
        unsafe {
            self.decrypt_raw(chain, iv, data.as_ptr(), out.as_mut_ptr(), whole / 16);
            self.decrypt_raw(chain, iv, last.as_ptr(), out.as_mut_ptr().add(whole), 1);
            out.set_len(whole + 16);
        }
        out
    }

    /// Plain ECB decryption (each 16-byte block decrypted independently, no
    /// IV). Equivalent to `ecb_decrypt_with_iv` with an all-zero IV, which is
    /// exactly the pattern `lsadump.py`'s `decrypt_aes` uses (**not**
    /// `cachedump.py` -- see the module-level doc comment).
    pub fn ecb_decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.ecb_decrypt_with_iv(&[0u8; 16], data)
    }

    /// Plain ECB decryption in place, without allocating. Unlike
    /// [`Aes::ecb_decrypt`] there is no room to zero-pad a short final chunk, so
    /// `buf.len()` must be a multiple of 16 (else an error and `buf` untouched).
    pub fn ecb_decrypt_in_place(&self, buf: &mut [u8]) -> Result<()> {
        if !buf.len().is_multiple_of(16) {
            return Err(unaligned("AES ECB decrypt", buf.len()));
        }
        let p = buf.as_mut_ptr();
        // Safety: in == out exactly, buf.len() bytes, whole blocks.
        unsafe { self.decrypt_raw(Chain::None, &[0; 16], p, p, buf.len() / 16) };
        Ok(())
    }

    /// Plain ECB encryption (each 16-byte block encrypted independently). Not
    /// used by any current plugin (they only ever decrypt), but ECB encrypt is
    /// exactly as parallel as ECB decrypt, so it gets the same wide kernels.
    /// `data.len()` must be a multiple of 16.
    pub fn ecb_encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(16) {
            return Err(unaligned("AES ECB encrypt", data.len()));
        }
        let mut out = data.to_vec();
        let p = out.as_mut_ptr();
        let n = out.len() / 16;
        #[cfg(target_arch = "x86_64")]
        {
            // Safety: hw verified by hw_level(); in == out, whole blocks.
            if self.hw == Hw::Vaes {
                unsafe { x86::ecb_encrypt_vaes(&self.enc, self.nr, p, p, n) };
                return Ok(out);
            }
            if self.hw == Hw::Ni {
                unsafe { x86::ecb_encrypt_ni(&self.enc, self.nr, p, p, n) };
                return Ok(out);
            }
        }
        let _ = (p, n);
        for chunk in out.chunks_exact_mut(16) {
            self.encrypt_block_portable(chunk.try_into().unwrap());
        }
        Ok(out)
    }
}

#[cold]
fn unaligned(what: &str, len: usize) -> Error {
    Error::msg(format!(
        "{what}: data length {len} is not a multiple of the 16-byte block size"
    ))
}

fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= rk[i];
    }
}

fn sub_bytes(state: &mut [u8; 16], sb: &[u8; 256]) {
    for b in state.iter_mut() {
        *b = sb[*b as usize];
    }
}

fn inv_sub_bytes(state: &mut [u8; 16], isb: &[u8; 256]) {
    for b in state.iter_mut() {
        *b = isb[*b as usize];
    }
}

// State byte layout: state[r + 4*c] is row r, column c (AES/FIPS-197 convention).

fn shift_rows(state: &mut [u8; 16]) {
    let s = *state;
    for r in 1..4 {
        for c in 0..4 {
            state[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
        }
    }
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    let s = *state;
    for r in 1..4 {
        for c in 0..4 {
            state[r + 4 * c] = s[r + 4 * ((c + 4 - r) % 4)];
        }
    }
}

fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let s0 = state[4 * c];
        let s1 = state[1 + 4 * c];
        let s2 = state[2 + 4 * c];
        let s3 = state[3 + 4 * c];
        state[4 * c] = gf_mul(s0, 2) ^ gf_mul(s1, 3) ^ s2 ^ s3;
        state[1 + 4 * c] = s0 ^ gf_mul(s1, 2) ^ gf_mul(s2, 3) ^ s3;
        state[2 + 4 * c] = s0 ^ s1 ^ gf_mul(s2, 2) ^ gf_mul(s3, 3);
        state[3 + 4 * c] = gf_mul(s0, 3) ^ s1 ^ s2 ^ gf_mul(s3, 2);
    }
}

fn inv_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let s0 = state[4 * c];
        let s1 = state[1 + 4 * c];
        let s2 = state[2 + 4 * c];
        let s3 = state[3 + 4 * c];
        state[4 * c] = gf_mul(s0, 0x0e) ^ gf_mul(s1, 0x0b) ^ gf_mul(s2, 0x0d) ^ gf_mul(s3, 0x09);
        state[1 + 4 * c] =
            gf_mul(s0, 0x09) ^ gf_mul(s1, 0x0e) ^ gf_mul(s2, 0x0b) ^ gf_mul(s3, 0x0d);
        state[2 + 4 * c] =
            gf_mul(s0, 0x0d) ^ gf_mul(s1, 0x09) ^ gf_mul(s2, 0x0e) ^ gf_mul(s3, 0x0b);
        state[3 + 4 * c] =
            gf_mul(s0, 0x0b) ^ gf_mul(s1, 0x0d) ^ gf_mul(s2, 0x09) ^ gf_mul(s3, 0x0e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn unhex16(s: &str) -> [u8; 16] {
        unhex(s).try_into().unwrap()
    }
    fn rng(seed: u64) -> impl FnMut() -> u8 {
        let mut s = seed;
        move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        }
    }
    /// Every implementation level this CPU can run, lowest first.
    fn levels() -> Vec<Hw> {
        [Hw::Portable, Hw::Ni, Hw::Vaes].into_iter().filter(|&l| l <= hw_level()).collect()
    }

    // FIPS-197 Appendix B/C known-answer vectors.
    #[test]
    fn fips197_aes128() {
        let key = unhex16("000102030405060708090a0b0c0d0e0f");
        let pt = unhex16("00112233445566778899aabbccddeeff");
        let aes = Aes::new(&key).unwrap();
        let mut block = pt;
        aes.encrypt_block(&mut block);
        assert_eq!(hex(&block), "69c4e0d86a7b0430d8cdb78070b4c55a");
        aes.decrypt_block(&mut block);
        assert_eq!(block, pt);
    }

    #[test]
    fn fips197_aes192() {
        let key: Vec<u8> = unhex("000102030405060708090a0b0c0d0e0f1011121314151617");
        let pt = unhex16("00112233445566778899aabbccddeeff");
        let aes = Aes::new(&key).unwrap();
        let mut block = pt;
        aes.encrypt_block(&mut block);
        assert_eq!(hex(&block), "dda97ca4864cdfe06eaf70a0ec0d7191");
        aes.decrypt_block(&mut block);
        assert_eq!(block, pt);
    }

    #[test]
    fn fips197_aes256() {
        let key: Vec<u8> =
            unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt = unhex16("00112233445566778899aabbccddeeff");
        let aes = Aes::new(&key).unwrap();
        let mut block = pt;
        aes.encrypt_block(&mut block);
        assert_eq!(hex(&block), "8ea2b7ca516745bfeafc49904b496089");
        aes.decrypt_block(&mut block);
        assert_eq!(block, pt);
    }

    #[test]
    fn rejects_bad_key_length() {
        assert!(Aes::new(&[0u8; 15]).is_err());
        assert!(Aes::new(&[0u8; 20]).is_err());
    }

    #[test]
    fn cbc_roundtrip_and_rejects_unaligned() {
        let aes = Aes::new(&[0x2bu8; 16]).unwrap();
        let iv = [0x11u8; 16];
        let data: Vec<u8> = (0..64u32).map(|i| i as u8).collect();
        let ct = aes.cbc_encrypt(&iv, &data).unwrap();
        let pt = aes.cbc_decrypt(&iv, &ct).unwrap();
        assert_eq!(pt, data);
        assert!(aes.cbc_decrypt(&iv, &data[..17]).is_err());
        let mut odd = data[..17].to_vec();
        assert!(aes.cbc_decrypt_in_place(&iv, &mut odd).is_err());
        assert_eq!(odd, &data[..17]);
        assert!(aes.ecb_decrypt_in_place(&mut odd).is_err());
        assert!(aes.cbc_decrypt(&iv, &[]).unwrap().is_empty());
    }

    #[test]
    fn ecb_decrypt_with_iv_handles_short_final_chunk() {
        let aes = Aes::new(&[0x5au8; 16]).unwrap();
        // 20 bytes: one full block + a 4-byte tail that must be zero-padded
        // (not panic), producing a full extra 16-byte block of output --
        // matching the Python plugins, which never truncate back down.
        let data = vec![7u8; 20];
        let out = aes.ecb_decrypt_with_iv(&[0u8; 16], &data);
        assert_eq!(out.len(), 32);
        let mut padded = [0u8; 32];
        padded[..20].copy_from_slice(&data);
        assert_eq!(out, aes.ecb_decrypt(&padded));
        let iv = [0x33u8; 16];
        let out_iv = aes.ecb_decrypt_with_iv(&iv, &data);
        let expect: Vec<u8> = out.iter().enumerate().map(|(i, b)| b ^ iv[i % 16]).collect();
        assert_eq!(out_iv, expect);
    }

    // The AES-NI key expansion (enc and dec schedules) must match the FIPS-197
    // byte-oriented expansion for every key size, on random keys.
    #[test]
    fn hw_key_expansion_matches_portable() {
        if hw_level() < Hw::Ni {
            return;
        }
        let mut next = rng(0xC0FFEE);
        for klen in [16usize, 24, 32] {
            for _ in 0..100 {
                let key: Vec<u8> = (0..klen).map(|_| next()).collect();
                let hw = Aes::with_hw(&key, Hw::Ni).unwrap();
                let sw = Aes::with_hw(&key, Hw::Portable).unwrap();
                assert_eq!(hw.enc, sw.enc, "enc schedule, key_len={klen}");
                assert_eq!(hw.nr, sw.nr);
                // dec[i] is InvMixColumns(enc[nr-i]) for the middle rounds.
                assert_eq!(hw.dec[0], sw.enc[sw.nr]);
                assert_eq!(hw.dec[hw.nr], sw.enc[0]);
                for i in 1..hw.nr {
                    let mut s = sw.enc[sw.nr - i];
                    inv_mix_columns(&mut s);
                    assert_eq!(hw.dec[i], s, "dec[{i}], key_len={klen}");
                }
            }
        }
    }

    // Single-block encrypt/decrypt agree across every available implementation.
    #[test]
    fn block_paths_agree() {
        let mut next = rng(0xBADC0DE);
        for klen in [16usize, 24, 32] {
            let key: Vec<u8> = (0..klen).map(|_| next()).collect();
            let sw = Aes::with_hw(&key, Hw::Portable).unwrap();
            for lvl in levels() {
                let aes = Aes::with_hw(&key, lvl).unwrap();
                for _ in 0..100 {
                    let pt: [u8; 16] = std::array::from_fn(|_| next());
                    let mut ct = pt;
                    aes.encrypt_block(&mut ct);
                    let mut sw_ct = pt;
                    sw.encrypt_block_portable(&mut sw_ct);
                    assert_eq!(ct, sw_ct, "encrypt {lvl:?} key_len={klen}");
                    aes.decrypt_block(&mut ct);
                    assert_eq!(ct, pt, "decrypt {lvl:?} key_len={klen}");
                }
            }
        }
    }

    // Every buffer API, on every implementation level, for block counts that
    // cover the 16-block VAES groups, the 2-block and 1-block tails, and the
    // 8-block AES-NI groups -- checked against a block-by-block portable model.
    #[test]
    fn buffer_paths_agree_with_portable_model() {
        let mut next = rng(0x5EED_5EED);
        for klen in [16usize, 24, 32] {
            let key: Vec<u8> = (0..klen).map(|_| next()).collect();
            let iv: [u8; 16] = std::array::from_fn(|_| next());
            let sw = Aes::with_hw(&key, Hw::Portable).unwrap();
            for nblocks in [0usize, 1, 2, 3, 7, 8, 9, 15, 16, 17, 18, 31, 32, 33, 47, 50] {
                let data: Vec<u8> = (0..nblocks * 16).map(|_| next()).collect();
                // Portable model of each mode.
                let mut ecb = Vec::new();
                let mut cbc = Vec::new();
                let mut ecb_iv = Vec::new();
                let mut prev = iv;
                for c in data.chunks_exact(16) {
                    let mut b: [u8; 16] = c.try_into().unwrap();
                    sw.decrypt_block_portable(&mut b);
                    ecb.extend_from_slice(&b);
                    ecb_iv.extend((0..16).map(|k| b[k] ^ iv[k]));
                    cbc.extend((0..16).map(|k| b[k] ^ prev[k]));
                    prev = c.try_into().unwrap();
                }
                let mut ecb_enc = Vec::new();
                for c in data.chunks_exact(16) {
                    let mut b: [u8; 16] = c.try_into().unwrap();
                    sw.encrypt_block_portable(&mut b);
                    ecb_enc.extend_from_slice(&b);
                }
                for lvl in levels() {
                    let aes = Aes::with_hw(&key, lvl).unwrap();
                    let tag = format!("{lvl:?} key_len={klen} nblocks={nblocks}");
                    assert_eq!(aes.ecb_decrypt(&data), ecb, "ecb {tag}");
                    assert_eq!(aes.ecb_decrypt_with_iv(&iv, &data), ecb_iv, "ecb_iv {tag}");
                    assert_eq!(aes.cbc_decrypt(&iv, &data).unwrap(), cbc, "cbc {tag}");
                    let mut buf = data.clone();
                    aes.cbc_decrypt_in_place(&iv, &mut buf).unwrap();
                    assert_eq!(buf, cbc, "cbc in place {tag}");
                    let mut buf = data.clone();
                    aes.ecb_decrypt_in_place(&mut buf).unwrap();
                    assert_eq!(buf, ecb, "ecb in place {tag}");
                    assert_eq!(aes.ecb_encrypt(&data).unwrap(), ecb_enc, "ecb enc {tag}");
                    let ct = aes.cbc_encrypt(&iv, &data).unwrap();
                    assert_eq!(sw.cbc_decrypt(&iv, &ct).unwrap(), data, "cbc enc {tag}");
                }
            }
        }
    }
}
