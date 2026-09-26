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
//! `encrypt_block`/`decrypt_block` use the AES-NI hardware instructions
//! (`aesenc`/`aesdec` via `std::arch::x86_64`) when this is an x86_64 CPU that has
//! them, detected once at [`Aes::new`] time with `is_x86_feature_detected!`; every
//! other target, and older x86_64 CPUs, fall back to the portable table-driven
//! implementation below. The buffer-oriented decrypt calls additionally use an
//! 8-blocks-at-a-time VAES path (`vaes` module) when available, since a single
//! `aesdec` has multi-cycle latency that a one-block-at-a-time loop can't hide --
//! see that module's doc comment, and `bench/refbench` for the measurement that
//! motivated it. All paths share one key schedule and are cross-checked against
//! each other in `tests::ni_matches_portable_if_available` and
//! `tests::vaes_matches_portable_if_available`.

use crate::error::{Error, Result};
use std::sync::OnceLock;

// --- S-box construction (GF(2^8) multiplicative inverse + affine transform),
// computed once at first use instead of transcribing a 256-entry literal table. ---

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

fn sbox() -> &'static [u8; 256] {
    static SBOX: OnceLock<([u8; 256], [u8; 256])> = OnceLock::new();
    &SBOX.get_or_init(build_sbox).0
}

fn inv_sbox() -> &'static [u8; 256] {
    static SBOX: OnceLock<([u8; 256], [u8; 256])> = OnceLock::new();
    &SBOX.get_or_init(build_sbox).1
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

const MAX_ROUND_KEYS_WORDS: usize = 4 * 15; // Nr up to 14 -> 15 round keys * 4 words.

// --- AES-NI fast path (x86_64 only, runtime-detected). The portable byte-oriented
// implementation above is always compiled and is the fallback on any CPU/arch
// without hardware AES support; correctness of both paths is cross-checked in the
// test module below on machines that do have AES-NI. ---
#[cfg(target_arch = "x86_64")]
mod ni {
    use std::arch::x86_64::*;

    /// Round keys loaded into SSE registers, plus the decrypt-side "equivalent
    /// inverse cipher" keys AES-NI's `aesdec`/`aesdeclast` require (every middle
    /// round key run through `aesimc`; first/last round keys unchanged).
    #[derive(Clone, Copy)]
    pub struct Keys {
        enc: [__m128i; 15],
        dec: [__m128i; 15],
        nr: usize,
    }

    /// Checks both CPUID feature bits this needs. sse2 is part of the x86_64
    /// baseline, but we still check it explicitly rather than assume.
    pub fn available() -> bool {
        is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2")
    }

    /// Builds the AES-NI key schedule from the same round-key bytes the portable
    /// path uses (`Aes::round_key_bytes`), so there is exactly one source of
    /// truth for key expansion.
    #[target_feature(enable = "aes,sse2")]
    unsafe fn expand(round_key_bytes: &[[u8; 16]], nr: usize) -> Keys {
        unsafe {
            let mut enc = [_mm_setzero_si128(); 15];
            for i in 0..=nr {
                enc[i] = _mm_loadu_si128(round_key_bytes[i].as_ptr() as *const __m128i);
            }
            let mut dec = [_mm_setzero_si128(); 15];
            dec[0] = enc[nr];
            for i in 1..nr {
                dec[i] = _mm_aesimc_si128(enc[nr - i]);
            }
            dec[nr] = enc[0];
            Keys { enc, dec, nr }
        }
    }

    /// Safe wrapper: `available()` must be checked by the caller before calling
    /// this (it is, in `Aes::new`), but building the key schedule itself never
    /// touches unverified feature-gated instructions unsafely from safe code.
    pub fn build(round_key_bytes: &[[u8; 16]], nr: usize) -> Keys {
        // Safety: only called after `available()` returned true.
        unsafe { expand(round_key_bytes, nr) }
    }

    #[target_feature(enable = "aes,sse2")]
    unsafe fn encrypt_block_unchecked(keys: &Keys, block: &mut [u8; 16]) {
        unsafe {
            let mut b = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            b = _mm_xor_si128(b, keys.enc[0]);
            for &rk in &keys.enc[1..keys.nr] {
                b = _mm_aesenc_si128(b, rk);
            }
            b = _mm_aesenclast_si128(b, keys.enc[keys.nr]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, b);
        }
    }

    #[target_feature(enable = "aes,sse2")]
    unsafe fn decrypt_block_unchecked(keys: &Keys, block: &mut [u8; 16]) {
        unsafe {
            let mut b = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            b = _mm_xor_si128(b, keys.dec[0]);
            for &rk in &keys.dec[1..keys.nr] {
                b = _mm_aesdec_si128(b, rk);
            }
            b = _mm_aesdeclast_si128(b, keys.dec[keys.nr]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, b);
        }
    }

    /// Safety: caller must have already confirmed `available()`.
    pub fn encrypt_block(keys: &Keys, block: &mut [u8; 16]) {
        unsafe { encrypt_block_unchecked(keys, block) }
    }

    /// Safety: caller must have already confirmed `available()`.
    pub fn decrypt_block(keys: &Keys, block: &mut [u8; 16]) {
        unsafe { decrypt_block_unchecked(keys, block) }
    }
}

// --- VAES fast path: 8 blocks (four 256-bit lanes) of AES-NI interleaved per call.
// Single-block `aesenc`/`aesdec` has ~4 cycle latency but 1/cycle throughput, so a
// loop over one block at a time (the `ni` module above) stalls on that latency
// instead of saturating the execution port -- confirmed against OpenSSL's ~15 GB/s
// EVP AES throughput on this CPU (bench/refbench), which is 6-7x what a naive
// single-block AES-NI loop achieves. VAES runs the same `aesenc`/`aesdec` state
// machine two 128-bit lanes at a time inside one 256-bit register; interleaving
// four independent __m256i registers (8 blocks total) gives the reorder buffer
// enough independent work in flight to hide that latency. Only used for buffers of
// 8+ blocks; shorter runs (the common case for a single SAM/LSA secret) fall back
// to the `ni`/portable single-block path, where the fixed cost of setting up 4
// interleaved lanes isn't worth it.
#[cfg(target_arch = "x86_64")]
mod vaes {
    use std::arch::x86_64::*;

    pub const BLOCKS_PER_CALL: usize = 8;

    #[derive(Clone, Copy)]
    pub struct Keys {
        enc: [__m256i; 15], // each round key broadcast into both 128-bit lanes
        dec: [__m256i; 15],
        nr: usize,
    }

    pub fn available() -> bool {
        is_x86_feature_detected!("vaes")
            && is_x86_feature_detected!("avx2")
            && is_x86_feature_detected!("aes")
    }

    #[target_feature(enable = "vaes,avx2,aes")]
    unsafe fn expand(round_key_bytes: &[[u8; 16]], nr: usize) -> Keys {
        unsafe {
            let mut enc128 = [_mm_setzero_si128(); 15];
            for i in 0..=nr {
                enc128[i] = _mm_loadu_si128(round_key_bytes[i].as_ptr() as *const __m128i);
            }
            let mut dec128 = [_mm_setzero_si128(); 15];
            dec128[0] = enc128[nr];
            for i in 1..nr {
                dec128[i] = _mm_aesimc_si128(enc128[nr - i]);
            }
            dec128[nr] = enc128[0];

            let mut enc = [_mm256_setzero_si256(); 15];
            let mut dec = [_mm256_setzero_si256(); 15];
            for i in 0..=nr {
                enc[i] = _mm256_broadcastsi128_si256(enc128[i]);
                dec[i] = _mm256_broadcastsi128_si256(dec128[i]);
            }
            Keys { enc, dec, nr }
        }
    }

    /// Safety: only called after `available()` returned true.
    pub fn build(round_key_bytes: &[[u8; 16]], nr: usize) -> Keys {
        unsafe { expand(round_key_bytes, nr) }
    }

    /// Decrypts `BLOCKS_PER_CALL` (8) independent 16-byte blocks in place -- i.e.
    /// plain ECB decrypt of a 128-byte chunk. CBC/`ecb_decrypt_with_iv` build on
    /// this by XORing in the right previous-ciphertext/IV value afterward, since
    /// that XOR has no dependency on the AES computation itself.
    ///
    /// Only used by tests/benchmarks (`decrypt8_from_to` below is the one the
    /// production `decrypt_blocks` path uses, since it avoids a redundant copy);
    /// kept as a convenience for the in-place case rather than deleted.
    #[cfg(test)]
    #[target_feature(enable = "vaes,avx2,aes")]
    unsafe fn decrypt8_unchecked(keys: &Keys, blocks: &mut [u8; 128]) {
        unsafe {
            let p = blocks.as_ptr() as *const __m256i;
            let mut b0 = _mm256_loadu_si256(p);
            let mut b1 = _mm256_loadu_si256(p.add(1));
            let mut b2 = _mm256_loadu_si256(p.add(2));
            let mut b3 = _mm256_loadu_si256(p.add(3));

            b0 = _mm256_xor_si256(b0, keys.dec[0]);
            b1 = _mm256_xor_si256(b1, keys.dec[0]);
            b2 = _mm256_xor_si256(b2, keys.dec[0]);
            b3 = _mm256_xor_si256(b3, keys.dec[0]);

            for &rk in &keys.dec[1..keys.nr] {
                b0 = _mm256_aesdec_epi128(b0, rk);
                b1 = _mm256_aesdec_epi128(b1, rk);
                b2 = _mm256_aesdec_epi128(b2, rk);
                b3 = _mm256_aesdec_epi128(b3, rk);
            }
            let last = keys.dec[keys.nr];
            b0 = _mm256_aesdeclast_epi128(b0, last);
            b1 = _mm256_aesdeclast_epi128(b1, last);
            b2 = _mm256_aesdeclast_epi128(b2, last);
            b3 = _mm256_aesdeclast_epi128(b3, last);

            let out = blocks.as_mut_ptr() as *mut __m256i;
            _mm256_storeu_si256(out, b0);
            _mm256_storeu_si256(out.add(1), b1);
            _mm256_storeu_si256(out.add(2), b2);
            _mm256_storeu_si256(out.add(3), b3);
        }
    }

    /// Safety: caller must have already confirmed `available()`. Test/bench-only,
    /// see `decrypt8_unchecked`.
    #[cfg(test)]
    pub fn decrypt8(keys: &Keys, blocks: &mut [u8; 128]) {
        unsafe { decrypt8_unchecked(keys, blocks) }
    }

    #[target_feature(enable = "vaes,avx2,aes")]
    unsafe fn decrypt8_from_to_unchecked(keys: &Keys, input: &[u8; 128], output: &mut [u8; 128]) {
        unsafe {
            let p = input.as_ptr() as *const __m256i;
            let mut b0 = _mm256_loadu_si256(p);
            let mut b1 = _mm256_loadu_si256(p.add(1));
            let mut b2 = _mm256_loadu_si256(p.add(2));
            let mut b3 = _mm256_loadu_si256(p.add(3));

            b0 = _mm256_xor_si256(b0, keys.dec[0]);
            b1 = _mm256_xor_si256(b1, keys.dec[0]);
            b2 = _mm256_xor_si256(b2, keys.dec[0]);
            b3 = _mm256_xor_si256(b3, keys.dec[0]);

            for &rk in &keys.dec[1..keys.nr] {
                b0 = _mm256_aesdec_epi128(b0, rk);
                b1 = _mm256_aesdec_epi128(b1, rk);
                b2 = _mm256_aesdec_epi128(b2, rk);
                b3 = _mm256_aesdec_epi128(b3, rk);
            }
            let last = keys.dec[keys.nr];
            b0 = _mm256_aesdeclast_epi128(b0, last);
            b1 = _mm256_aesdeclast_epi128(b1, last);
            b2 = _mm256_aesdeclast_epi128(b2, last);
            b3 = _mm256_aesdeclast_epi128(b3, last);

            let out = output.as_mut_ptr() as *mut __m256i;
            _mm256_storeu_si256(out, b0);
            _mm256_storeu_si256(out.add(1), b1);
            _mm256_storeu_si256(out.add(2), b2);
            _mm256_storeu_si256(out.add(3), b3);
        }
    }

    /// Safety: caller must have already confirmed `available()`.
    pub fn decrypt8_from_to(keys: &Keys, input: &[u8; 128], output: &mut [u8; 128]) {
        unsafe { decrypt8_from_to_unchecked(keys, input, output) }
    }

    #[target_feature(enable = "vaes,avx2,aes")]
    unsafe fn encrypt8_unchecked(keys: &Keys, blocks: &mut [u8; 128]) {
        unsafe {
            let p = blocks.as_ptr() as *const __m256i;
            let mut b0 = _mm256_loadu_si256(p);
            let mut b1 = _mm256_loadu_si256(p.add(1));
            let mut b2 = _mm256_loadu_si256(p.add(2));
            let mut b3 = _mm256_loadu_si256(p.add(3));

            b0 = _mm256_xor_si256(b0, keys.enc[0]);
            b1 = _mm256_xor_si256(b1, keys.enc[0]);
            b2 = _mm256_xor_si256(b2, keys.enc[0]);
            b3 = _mm256_xor_si256(b3, keys.enc[0]);

            for &rk in &keys.enc[1..keys.nr] {
                b0 = _mm256_aesenc_epi128(b0, rk);
                b1 = _mm256_aesenc_epi128(b1, rk);
                b2 = _mm256_aesenc_epi128(b2, rk);
                b3 = _mm256_aesenc_epi128(b3, rk);
            }
            let last = keys.enc[keys.nr];
            b0 = _mm256_aesenclast_epi128(b0, last);
            b1 = _mm256_aesenclast_epi128(b1, last);
            b2 = _mm256_aesenclast_epi128(b2, last);
            b3 = _mm256_aesenclast_epi128(b3, last);

            let out = blocks.as_mut_ptr() as *mut __m256i;
            _mm256_storeu_si256(out, b0);
            _mm256_storeu_si256(out.add(1), b1);
            _mm256_storeu_si256(out.add(2), b2);
            _mm256_storeu_si256(out.add(3), b3);
        }
    }

    /// Safety: caller must have already confirmed `available()`.
    pub fn encrypt8(keys: &Keys, blocks: &mut [u8; 128]) {
        unsafe { encrypt8_unchecked(keys, blocks) }
    }
}

/// An expanded AES key (128/192/256-bit), ready to encrypt/decrypt 16-byte blocks.
/// On x86_64 with a CPU that supports AES-NI (checked once, at construction time),
/// `encrypt_block`/`decrypt_block` use the hardware `aesenc`/`aesdec` instructions;
/// buffer-oriented calls ([`Aes::cbc_decrypt`], [`Aes::ecb_decrypt_with_iv`],
/// [`Aes::cbc_encrypt`]) additionally use the 8-blocks-at-a-time VAES path
/// ([`vaes`]) when the CPU has it and there's enough data, since AES decrypt has no
/// inter-block dependency and that's where the real throughput win is. Every other
/// target (and older x86_64 CPUs) uses the portable table-driven implementation.
/// All three paths share one key schedule.
pub struct Aes {
    round_keys: [[u8; 4]; MAX_ROUND_KEYS_WORDS],
    nr: usize, // number of rounds: 10, 12, or 14
    #[cfg(target_arch = "x86_64")]
    ni: Option<ni::Keys>,
    #[cfg(target_arch = "x86_64")]
    vaes: Option<vaes::Keys>,
}

impl Aes {
    /// Builds the key schedule. `key` must be 16, 24 or 32 bytes (AES-128/192/256);
    /// any other length returns an error rather than panicking.
    pub fn new(key: &[u8]) -> Result<Self> {
        let nk = match key.len() {
            16 => 4,
            24 => 6,
            32 => 8,
            n => {
                return Err(Error::msg(format!(
                    "AES key must be 16, 24 or 32 bytes, got {n}"
                )));
            }
        };
        let nr = nk + 6;
        let total_words = 4 * (nr + 1);

        let sb = sbox();
        let mut w = [[0u8; 4]; MAX_ROUND_KEYS_WORDS];
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

        #[cfg(target_arch = "x86_64")]
        let rkb = {
            let mut rkb = [[0u8; 16]; 15];
            for (i, slot) in rkb.iter_mut().enumerate().take(nr + 1) {
                for c in 0..4 {
                    slot[c * 4..c * 4 + 4].copy_from_slice(&w[i * 4 + c]);
                }
            }
            rkb
        };
        #[cfg(target_arch = "x86_64")]
        let ni = ni::available().then(|| ni::build(&rkb, nr));
        #[cfg(target_arch = "x86_64")]
        let vaes = vaes::available().then(|| vaes::build(&rkb, nr));

        Ok(Aes {
            round_keys: w,
            nr,
            #[cfg(target_arch = "x86_64")]
            ni,
            #[cfg(target_arch = "x86_64")]
            vaes,
        })
    }

    /// True if the 8-blocks-at-a-time VAES path is active on this CPU (used by the
    /// bulk buffer-oriented calls below, and by tests to know whether to exercise
    /// it). Always `false` off x86_64 or on a CPU without VAES.
    #[allow(dead_code)]
    pub(crate) fn has_vaes(&self) -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            self.vaes.is_some()
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }

    /// Raw single-call VAES 8-block decrypt, bypassing all Vec/slice/XOR overhead
    /// in [`Aes::ecb_decrypt`]/[`Aes::cbc_decrypt`]. `bench.rs`-only: exists purely
    /// to isolate the hardware loop's own throughput from everything around it.
    /// Panics if VAES isn't available -- callers must check [`Aes::has_vaes`] first.
    #[cfg(all(test, target_arch = "x86_64"))]
    pub(crate) fn decrypt8_raw_for_bench(&self, buf: &mut [u8; 128]) {
        vaes::decrypt8(self.vaes.as_ref().expect("VAES not available"), buf);
    }

    fn round_key_bytes(&self, round: usize) -> [u8; 16] {
        let mut out = [0u8; 16];
        for c in 0..4 {
            out[c * 4..c * 4 + 4].copy_from_slice(&self.round_keys[round * 4 + c]);
        }
        out
    }

    /// Encrypts one 16-byte block in place. Dispatches to AES-NI when this CPU
    /// supports it (checked once in [`Aes::new`]), otherwise the portable path.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        #[cfg(target_arch = "x86_64")]
        if let Some(keys) = &self.ni {
            ni::encrypt_block(keys, block);
            return;
        }
        self.encrypt_block_portable(block);
    }

    /// Decrypts one 16-byte block in place. Dispatches to AES-NI when available.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        #[cfg(target_arch = "x86_64")]
        if let Some(keys) = &self.ni {
            ni::decrypt_block(keys, block);
            return;
        }
        self.decrypt_block_portable(block);
    }

    /// The portable (no hardware acceleration) block encrypt, exposed for
    /// testing the two paths against each other; prefer [`Aes::encrypt_block`].
    pub fn encrypt_block_portable(&self, block: &mut [u8; 16]) {
        let sb = sbox();
        add_round_key(block, &self.round_key_bytes(0));
        for round in 1..self.nr {
            sub_bytes(block, sb);
            shift_rows(block);
            mix_columns(block);
            add_round_key(block, &self.round_key_bytes(round));
        }
        sub_bytes(block, sb);
        shift_rows(block);
        add_round_key(block, &self.round_key_bytes(self.nr));
    }

    /// The portable (no hardware acceleration) block decrypt, exposed for
    /// testing the two paths against each other; prefer [`Aes::decrypt_block`].
    pub fn decrypt_block_portable(&self, block: &mut [u8; 16]) {
        let isb = inv_sbox();
        add_round_key(block, &self.round_key_bytes(self.nr));
        for round in (1..self.nr).rev() {
            inv_shift_rows(block);
            inv_sub_bytes(block, isb);
            add_round_key(block, &self.round_key_bytes(round));
            inv_mix_columns(block);
        }
        inv_shift_rows(block);
        inv_sub_bytes(block, isb);
        add_round_key(block, &self.round_key_bytes(0));
    }

    /// Decrypts every 16-byte block of `input` into `output` with **no** chaining
    /// -- i.e. `output[i] = AES_decrypt(input[i])` for each block independently,
    /// reading straight from `input` rather than requiring a separate copy pass
    /// first. This is the shared fast path behind [`Aes::cbc_decrypt`] and
    /// [`Aes::ecb_decrypt_with_iv`]: AES-CBC decryption's only serial dependency
    /// is the final XOR-with-previous-ciphertext step (plain data movement, not an
    /// AES operation), so the decrypt step itself is embarrassingly parallel
    /// regardless of chaining mode. `input` and `output` must be the same length,
    /// a multiple of 16.
    fn decrypt_blocks(&self, input: &[u8], output: &mut [u8]) {
        debug_assert_eq!(input.len(), output.len());
        let mut i = 0;
        #[cfg(target_arch = "x86_64")]
        if let Some(keys) = &self.vaes {
            while input.len() - i >= vaes::BLOCKS_PER_CALL * 16 {
                let chunk_in: &[u8; 128] = (&input[i..i + 128]).try_into().unwrap();
                let chunk_out: &mut [u8; 128] = (&mut output[i..i + 128]).try_into().unwrap();
                vaes::decrypt8_from_to(keys, chunk_in, chunk_out);
                i += 128;
            }
        }
        while i < input.len() {
            let mut block = [0u8; 16];
            block.copy_from_slice(&input[i..i + 16]);
            self.decrypt_block(&mut block);
            output[i..i + 16].copy_from_slice(&block);
            i += 16;
        }
    }

    /// True CBC decryption (IV chained across blocks within this single call),
    /// matching `AES.new(key, AES.MODE_CBC, iv).decrypt(data)` in pycryptodome.
    /// `data.len()` must be a non-zero multiple of 16; a short final block is
    /// never produced by pycryptodome (it raises), so this returns an error
    /// instead of guessing at padding.
    pub fn cbc_decrypt(&self, iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(16) {
            return Err(Error::msg(format!(
                "AES CBC decrypt: data length {} is not a multiple of the 16-byte block size",
                data.len()
            )));
        }
        let mut out = vec![0u8; data.len()];
        self.decrypt_blocks(data, &mut out);
        // XOR each decrypted block with its previous ciphertext block. Written so
        // `prev` is read straight from `data`/`iv` rather than carried through a
        // mutable loop variable: with a loop-carried `prev`, LLVM has to treat each
        // iteration as depending on the last one and can't vectorize this; with
        // `prev` derived directly from `data[off-16..off]`, every iteration is
        // independent (this is literally `out[16..] ^= data[..len-16]`, plus
        // `out[..16] ^= iv`) and the auto-vectorizer can treat it as one wide XOR
        // over the whole buffer.
        for (o, v) in out[..16].iter_mut().zip(iv.iter()) {
            *o ^= *v;
        }
        if out.len() > 16 {
            let n = out.len() - 16;
            for (o, d) in out[16..].iter_mut().zip(data[..n].iter()) {
                *o ^= *d;
            }
        }
        Ok(out)
    }

    /// True CBC encryption, the inverse of [`Aes::cbc_decrypt`].
    pub fn cbc_encrypt(&self, iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(16) {
            return Err(Error::msg(format!(
                "AES CBC encrypt: data length {} is not a multiple of the 16-byte block size",
                data.len()
            )));
        }
        let mut out = Vec::with_capacity(data.len());
        let mut prev = *iv;
        for chunk in data.chunks_exact(16) {
            let mut block = [0u8; 16];
            for i in 0..16 {
                block[i] = chunk[i] ^ prev[i];
            }
            self.encrypt_block(&mut block);
            out.extend_from_slice(&block);
            prev = block;
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
        let n_blocks = data.len().div_ceil(16);
        let padded_len = n_blocks * 16;
        let mut out = vec![0u8; padded_len];
        if data.len() == padded_len {
            // Common case (block-aligned input, which is every real plugin call):
            // decrypt straight from `data`, no padding copy needed.
            self.decrypt_blocks(data, &mut out);
        } else {
            let mut padded_in = vec![0u8; padded_len];
            padded_in[..data.len()].copy_from_slice(data);
            self.decrypt_blocks(&padded_in, &mut out);
        }
        for block in out.chunks_exact_mut(16) {
            for k in 0..16 {
                block[k] ^= iv[k];
            }
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

    /// Plain ECB encryption (each 16-byte block encrypted independently). Not
    /// used by any current plugin (they only ever decrypt), but ECB encrypt is
    /// exactly as parallel as ECB decrypt, so it gets the same 8-blocks-at-a-time
    /// VAES fast path for symmetry and for `bench/refbench` comparisons.
    /// `data.len()` must be a multiple of 16.
    pub fn ecb_encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(16) {
            return Err(Error::msg(format!(
                "AES ECB encrypt: data length {} is not a multiple of the 16-byte block size",
                data.len()
            )));
        }
        let mut out = data.to_vec();
        let mut i = 0;
        #[cfg(target_arch = "x86_64")]
        if let Some(keys) = &self.vaes {
            while out.len() - i >= vaes::BLOCKS_PER_CALL * 16 {
                let chunk: &mut [u8; 128] = (&mut out[i..i + 128]).try_into().unwrap();
                vaes::encrypt8(keys, chunk);
                i += 128;
            }
        }
        while i < out.len() {
            let block: &mut [u8; 16] = (&mut out[i..i + 16]).try_into().unwrap();
            self.encrypt_block(block);
            i += 16;
        }
        Ok(out)
    }
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
    }

    // Cross-checks the AES-NI fast path against the portable path on any CPU that
    // actually has AES-NI (this is a no-op assertion-wise, but a useful signal,
    // on CPUs without it -- `encrypt_block`/`decrypt_block` just always take the
    // portable branch there, which the tests above already cover).
    #[test]
    fn ni_matches_portable_if_available() {
        #[cfg(target_arch = "x86_64")]
        {
            if !ni::available() {
                return;
            }
            let mut rng_state: u64 = 0xC0FFEE;
            let mut next = || {
                rng_state ^= rng_state << 13;
                rng_state ^= rng_state >> 7;
                rng_state ^= rng_state << 17;
                rng_state
            };
            for klen in [16usize, 24, 32] {
                let key: Vec<u8> = (0..klen).map(|_| next() as u8).collect();
                let aes = Aes::new(&key).unwrap();
                assert!(aes.ni.is_some(), "AES-NI should be active on this CPU");
                for _ in 0..200 {
                    let pt: [u8; 16] = {
                        let mut b = [0u8; 16];
                        for x in b.iter_mut() {
                            *x = next() as u8;
                        }
                        b
                    };
                    let mut ni_ct = pt;
                    ni::encrypt_block(aes.ni.as_ref().unwrap(), &mut ni_ct);
                    let mut sw_ct = pt;
                    aes.encrypt_block_portable(&mut sw_ct);
                    assert_eq!(ni_ct, sw_ct, "encrypt mismatch key_len={klen}");

                    let mut ni_pt = ni_ct;
                    ni::decrypt_block(aes.ni.as_ref().unwrap(), &mut ni_pt);
                    assert_eq!(ni_pt, pt, "NI decrypt did not invert NI encrypt");

                    let mut sw_pt = sw_ct;
                    aes.decrypt_block_portable(&mut sw_pt);
                    assert_eq!(sw_pt, pt, "portable decrypt did not invert portable encrypt");
                }
            }
        }
    }

    // Cross-checks the 8-blocks-at-a-time VAES path against the portable
    // single-block path, on any CPU that actually has VAES.
    #[test]
    fn vaes_matches_portable_if_available() {
        #[cfg(target_arch = "x86_64")]
        {
            if !vaes::available() {
                return;
            }
            let mut rng_state: u64 = 0x5EED_5EED;
            let mut next = || {
                rng_state ^= rng_state << 13;
                rng_state ^= rng_state >> 7;
                rng_state ^= rng_state << 17;
                rng_state
            };
            for klen in [16usize, 24, 32] {
                let key: Vec<u8> = (0..klen).map(|_| next() as u8).collect();
                let aes = Aes::new(&key).unwrap();
                assert!(aes.vaes.is_some(), "VAES should be active on this CPU");

                // Exactly one 8-block chunk, and a couple of multiples, so the
                // batched path in decrypt_blocks_inplace is actually exercised.
                for nblocks in [8usize, 16, 24] {
                    let ct: Vec<u8> = (0..nblocks * 16).map(|_| next() as u8).collect();

                    let mut vaes_buf = ct.clone();
                    for chunk in vaes_buf.chunks_exact_mut(128) {
                        let block: &mut [u8; 128] = chunk.try_into().unwrap();
                        vaes::decrypt8(aes.vaes.as_ref().unwrap(), block);
                    }

                    let mut portable_buf = ct.clone();
                    for block in portable_buf.chunks_exact_mut(16) {
                        let b: &mut [u8; 16] = block.try_into().unwrap();
                        aes.decrypt_block_portable(b);
                    }

                    assert_eq!(
                        vaes_buf, portable_buf,
                        "VAES 8-block decrypt mismatch, key_len={klen} nblocks={nblocks}"
                    );

                    // And the public API path (which dispatches through VAES for
                    // buffers this size) must agree too.
                    let via_api = aes.ecb_decrypt(&ct);
                    assert_eq!(via_api, portable_buf);
                }
            }
        }
    }
}
