// Derived from Volatility 3 (Volatility Software License 1.0); see LICENSE.txt.
//! DES, ECB mode only (FIPS 46-3). volatility3 uses single-DES (not 3DES) with
//! 8-byte keys derived from a RID or from LSA secret key material, always in
//! ECB mode operating on independent 8-byte blocks:
//! - `windows/registry/hashdump.py` (`decrypt_single_hash`,
//!   `decrypt_single_salted_hash`): decrypts the final 16 bytes of obfuscated
//!   LM/NT hash material with two DES keys derived from the user's RID
//!   (`sid_to_key`/`sidbytes_to_key` in the plugin), one key per 8-byte half.
//! - `windows/registry/lsadump.py` (`decrypt_secret`, a.k.a. `SystemFunction005`):
//!   decrypts an LSA secret 8 bytes at a time, cycling through 7-byte chunks of
//!   the LSA key, each expanded to a DES key with [`key_from_7_bytes`].
//!
//! Both call sites use `DES.new(key, DES.MODE_ECB)` from pycryptodome, i.e.
//! independent per-block decryption with no chaining and no padding.
//!
//! ## Implementation
//!
//! Every DES permutation only *selects* bits, so each is applied with lookup
//! tables built (at compile time, `const fn`) from the FIPS 46-3 bit tables by the
//! original bit-at-a-time [`permute_slow`] -- the one source of truth, which the
//! tests cross-check every fast path against. The per-round work is arranged so a
//! round is 2 XORs, 1 rotate, 2 ANDs and 8 byte-indexed loads from 2 KB of tables:
//!
//! - **E expansion for free.** S-box `i`'s 6 input bits are the cyclically
//!   contiguous run of R starting at bit `27-4i` (LSB numbering). With R kept
//!   rotated right by 21 (`r' = rotr(R, 21)`), S-boxes 1,7,5,3 (0-based) sit in bits
//!   2..7 of bytes 0..3 of `r'`, and S-boxes 0,6,4,2 in bits 2..7 of bytes 0..3 of
//!   `rotr(r', 4)`. The key schedule emits each 48-bit round key pre-split into
//!   those two layouts, so `(r' ^ ka) & 0xfcfcfcfc` yields four S-box inputs at
//!   once, each already multiplied by 4 -- i.e. a byte offset into a `u32` table.
//! - **S-box + P fused.** Each of the 8 64-entry "SP" tables holds P applied to that
//!   S-box's output nibble (P's per-box output bits are disjoint, so XOR-combining
//!   the 8 lookups is exactly concatenate-then-permute), pre-rotated by 21 so L
//!   and R stay in the rotated domain for all 16 rounds.
//! - **IP / FP with one 256-entry table each.** Both are 8x8 bit-matrix
//!   transposes with a row/column relabelling: input byte `b` contributes the same
//!   bit pattern for every `b`, shifted right by a per-byte column offset. So
//!   `IP(x) = OR_b T[byte_b(x)] >> (7-b)`, and similarly for FP (2 KB each instead
//!   of 8 tables x 2 KB).
//! - **Key schedule** in the same style: PC1 via 16 nibble lookups, and PC2 plus
//!   the round-key layout via 8 lookups of 7-bit chunks of the rotating C and D
//!   registers (C only feeds S-boxes 0-3, D only 4-7).
//! - **ECB interleaving.** Blocks are independent, so bulk ECB runs 4 blocks
//!   through each round together; the 4 dependency chains (xor -> mask -> load ->
//!   xor, ~10 cycles) overlap and the loop becomes throughput-bound.

use super::gpr;
use crate::error::{Error, Result};

// --- Standard FIPS 46-3 permutation / selection tables (1-indexed bit positions,
// counting from the most-significant bit of the relevant value). Used only to
// build the fast lookup tables below -- never on the per-block hot path. ---

const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

#[cfg(test)]
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

#[rustfmt::skip]
const SBOX: [[u8; 64]; 8] = [
    [
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,
    ],
    [
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9,
    ],
    [
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,
    ],
    [
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,
    ],
    [
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3,
    ],
    [
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,
    ],
    [
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,
    ],
    [
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11,
    ],
];

/// The original bit-at-a-time permutation: output bit i (MSB-first) is input bit
/// `table[i]` (1-indexed, MSB-first within `in_bits`). Only used to *build* the
/// fast tables (at compile time) and in the cross-check tests.
const fn permute_slow(input: u64, table: &[u8], in_bits: u32) -> u64 {
    let mut out: u64 = 0;
    let mut i = 0;
    while i < table.len() {
        let bit = (input >> (in_bits - table[i] as u32)) & 1;
        out = (out << 1) | bit;
        i += 1;
    }
    out
}

/// Byte slots of the two masked round words (see the module doc): S-box index
/// feeding byte 0..3 of `(r' ^ ka)` (slots 0-3) and of `(rotr(r',4) ^ kb)` (4-7).
const SLOT_SBOX: [usize; 8] = [1, 7, 5, 3, 0, 6, 4, 2];
/// Rotation of the L/R halves' working representation.
const ROT: u32 = 21;

/// Splits a 48-bit round key (MSB-first groups g0..g7, 6 bits each) into the
/// `ka | kb << 32` layout the round function XORs in: group `SLOT_SBOX[s]` goes to
/// bits 2..7 of byte `s % 4` of word `s / 4`.
const fn key_layout(k48: u64) -> u64 {
    let mut out = 0u64;
    let mut s = 0;
    while s < 8 {
        let g = (k48 >> (42 - 6 * SLOT_SBOX[s])) & 63;
        out |= g << (2 + 8 * (s % 4) + 32 * (s / 4));
        s += 1;
    }
    out
}

struct Tables {
    /// `sp[slot][g]`: rotr(P(S-box SLOT_SBOX[slot] applied to g), ROT).
    sp: [[u32; 64]; 8],
    /// IP of an input whose only nonzero byte is the last one (see `ip`).
    ip: [u64; 256],
    /// FP of an input whose only nonzero byte is byte 4 (see `fp`).
    fp: [u64; 256],
    /// `pc1[n][v]`: PC1 of nibble `n` (MSB-first) having value `v`.
    pc1: [[u64; 16]; 16],
    /// `pc2[j][v]`: key_layout(PC2(...)) contribution of 7-bit chunk `j` of the
    /// 56-bit C||D register (chunks 0-3 are C, 4-7 are D, MSB-first).
    pc2: [[u64; 128]; 8],
}

const fn build_tables() -> Tables {
    let mut t = Tables {
        sp: [[0; 64]; 8],
        ip: [0; 256],
        fp: [0; 256],
        pc1: [[0; 16]; 16],
        pc2: [[0; 128]; 8],
    };
    let mut slot = 0;
    while slot < 8 {
        let i = SLOT_SBOX[slot];
        let mut g = 0;
        while g < 64 {
            let row = ((g & 0x20) >> 4) | (g & 0x01);
            let col = (g >> 1) & 0x0F;
            // Box i's 4-bit output occupies bits (31-4i)..(28-4i) of the 32-bit
            // S-box output concatenation.
            let placed = (SBOX[i][row * 16 + col] as u64) << (28 - 4 * i);
            t.sp[slot][g] = (permute_slow(placed, &P, 32) as u32).rotate_right(ROT);
            g += 1;
        }
        slot += 1;
    }
    let mut v = 0;
    while v < 256 {
        t.ip[v] = permute_slow(v as u64, &IP, 64);
        t.fp[v] = permute_slow((v as u64) << 24, &FP, 64);
        v += 1;
    }
    let mut n = 0;
    while n < 16 {
        let mut v = 0;
        while v < 16 {
            t.pc1[n][v] = permute_slow((v as u64) << (60 - 4 * n), &PC1, 64);
            v += 1;
        }
        n += 1;
    }
    let mut j = 0;
    while j < 8 {
        let mut v = 0;
        while v < 128 {
            t.pc2[j][v] = key_layout(permute_slow((v as u64) << (49 - 7 * j), &PC2, 56));
            v += 1;
        }
        j += 1;
    }
    t
}

static TABLES: Tables = build_tables();

/// For FP: the right shift applied to input byte b's contribution.
const FP_SHIFT: [u32; 8] = [1, 3, 5, 7, 0, 2, 4, 6];

#[inline(always)]
fn ip(x: u64) -> u64 {
    let t = &TABLES.ip;
    let mut out = 0;
    for b in 0..8 {
        out |= gpr(t[((x >> (56 - 8 * b)) & 0xff) as usize]) >> (7 - b);
    }
    out
}

#[inline(always)]
fn fp(x: u64) -> u64 {
    let t = &TABLES.fp;
    let mut out = 0;
    for b in 0..8 {
        out |= gpr(t[((x >> (56 - 8 * b)) & 0xff) as usize]) >> FP_SHIFT[b];
    }
    out
}

/// The 16 round keys in `ka | kb << 32` layout (see the module doc comment).
fn key_schedule(key: &[u8; 8]) -> [u64; 16] {
    let t = &TABLES;
    let k = u64::from_be_bytes(*key);
    let mut cd = 0u64;
    for n in 0..16 {
        cd |= t.pc1[n][((k >> (60 - 4 * n)) & 15) as usize];
    }
    let mut c = (cd >> 28) as u32;
    let mut d = (cd & 0x0FFF_FFFF) as u32;
    let mut rk = [0u64; 16];
    for (i, &s) in SHIFTS.iter().enumerate() {
        c = ((c << s) | (c >> (28 - s))) & 0x0FFF_FFFF;
        d = ((d << s) | (d >> (28 - s))) & 0x0FFF_FFFF;
        rk[i] = t.pc2[0][(c >> 21) as usize]
            | t.pc2[1][((c >> 14) & 127) as usize]
            | t.pc2[2][((c >> 7) & 127) as usize]
            | t.pc2[3][(c & 127) as usize]
            | t.pc2[4][(d >> 21) as usize]
            | t.pc2[5][((d >> 14) & 127) as usize]
            | t.pc2[6][((d >> 7) & 127) as usize]
            | t.pc2[7][(d & 127) as usize];
    }
    rk
}

/// The Feistel function in the rotated domain: `rotr(P(S(E(R) ^ K)), ROT)` given
/// `r = rotr(R, ROT)` and the round key in `ka | kb << 32` layout.
#[inline(always)]
fn f(r: u32, k: u64) -> u32 {
    let sp = &TABLES.sp;
    let u = (r ^ k as u32) & 0xFCFC_FCFC;
    let t = (r.rotate_right(4) ^ (k >> 32) as u32) & 0xFCFC_FCFC;
    // Each masked byte is (6-bit S-box input) << 2: shift it back to an index
    // (LLVM folds the >>2 into the x4 addressing). Two XOR chains, each link
    // pinned (see `gpr`) so every lookup stays a fused `xor reg, [table + idx]`.
    let mut a = sp[0][(u & 0xFF) as usize >> 2];
    let mut b = sp[4][(t & 0xFF) as usize >> 2];
    a = gpr(a ^ sp[1][((u >> 8) & 0xFF) as usize >> 2]);
    b = gpr(b ^ sp[5][((t >> 8) & 0xFF) as usize >> 2]);
    a = gpr(a ^ sp[2][((u >> 16) & 0xFF) as usize >> 2]);
    b = gpr(b ^ sp[6][((t >> 16) & 0xFF) as usize >> 2]);
    a = gpr(a ^ sp[3][(u >> 24) as usize >> 2]);
    b = gpr(b ^ sp[7][(t >> 24) as usize >> 2]);
    a ^ b
}

/// Encrypts (`DEC = false`) or decrypts `N` independent blocks together, one
/// round at a time across all of them so their dependency chains overlap.
#[inline(always)]
fn crypt<const N: usize, const DEC: bool>(rk: &[u64; 16], blocks: [u64; N]) -> [u64; N] {
    let mut l = [0u32; N];
    let mut r = [0u32; N];
    for i in 0..N {
        let x = ip(blocks[i]);
        l[i] = ((x >> 32) as u32).rotate_right(ROT);
        r[i] = (x as u32).rotate_right(ROT);
    }
    for round in 0..8 {
        let (k0, k1) = if DEC {
            (rk[15 - 2 * round], rk[14 - 2 * round])
        } else {
            (rk[2 * round], rk[2 * round + 1])
        };
        for i in 0..N {
            l[i] ^= f(r[i], k0);
        }
        for i in 0..N {
            r[i] ^= f(l[i], k1);
        }
    }
    let mut out = [0u64; N];
    for i in 0..N {
        // Pre-output is R16 || L16 (the last round's swap is undone).
        out[i] = fp(((r[i].rotate_left(ROT) as u64) << 32) | l[i].rotate_left(ROT) as u64);
    }
    out
}

/// ECB over whole 8-byte blocks from `inp` to `out` (equal lengths, may be the
/// same buffer via the in-place wrappers): 4 blocks at a time, then singles.
#[inline(always)]
fn ecb<const DEC: bool>(rk: &[u64; 16], inp: &[u8], out: &mut [u8]) {
    debug_assert_eq!(inp.len(), out.len());
    let mut ic = inp.chunks_exact(32);
    let mut oc = out.chunks_exact_mut(32);
    for (i, o) in (&mut ic).zip(&mut oc) {
        let b =
            std::array::from_fn(|k| u64::from_be_bytes(i[8 * k..8 * k + 8].try_into().unwrap()));
        let r = crypt::<4, DEC>(rk, b);
        for k in 0..4 {
            o[8 * k..8 * k + 8].copy_from_slice(&r[k].to_be_bytes());
        }
    }
    for (i, o) in ic
        .remainder()
        .chunks_exact(8)
        .zip(oc.into_remainder().chunks_exact_mut(8))
    {
        let [r] = crypt::<1, DEC>(rk, [u64::from_be_bytes(i.try_into().unwrap())]);
        o.copy_from_slice(&r.to_be_bytes());
    }
}

/// In-place variant of [`ecb`] (a separate loop so the borrow checker sees one
/// buffer; same kernel).
#[inline(always)]
fn ecb_in_place<const DEC: bool>(rk: &[u64; 16], buf: &mut [u8]) {
    let mut chunks = buf.chunks_exact_mut(32);
    for c in &mut chunks {
        let b =
            std::array::from_fn(|k| u64::from_be_bytes(c[8 * k..8 * k + 8].try_into().unwrap()));
        let r = crypt::<4, DEC>(rk, b);
        for k in 0..4 {
            c[8 * k..8 * k + 8].copy_from_slice(&r[k].to_be_bytes());
        }
    }
    for c in chunks.into_remainder().chunks_exact_mut(8) {
        let [r] = crypt::<1, DEC>(rk, [u64::from_be_bytes((&*c).try_into().unwrap())]);
        c.copy_from_slice(&r.to_be_bytes());
    }
}

/// A single DES key, expanded into its 16 round keys.
#[derive(Clone)]
pub struct Des {
    round_keys: [u64; 16],
}

impl Des {
    pub fn new(key: &[u8; 8]) -> Self {
        Des {
            round_keys: key_schedule(key),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 8]) {
        let [r] = crypt::<1, false>(&self.round_keys, [u64::from_be_bytes(*block)]);
        *block = r.to_be_bytes();
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        let [r] = crypt::<1, true>(&self.round_keys, [u64::from_be_bytes(*block)]);
        *block = r.to_be_bytes();
    }

    /// Decrypts `data` as independent 8-byte ECB blocks (`DES.new(key,
    /// DES.MODE_ECB).decrypt(data)` in pycryptodome). Returns an error rather
    /// than panicking if `data` is not a whole number of blocks.
    pub fn ecb_decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(8) {
            return Err(unaligned("DES ECB decrypt", data.len()));
        }
        let mut out = vec![0u8; data.len()];
        ecb::<true>(&self.round_keys, data, &mut out);
        Ok(out)
    }

    /// Encrypts `data` as independent 8-byte ECB blocks.
    pub fn ecb_encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(8) {
            return Err(unaligned("DES ECB encrypt", data.len()));
        }
        let mut out = vec![0u8; data.len()];
        ecb::<false>(&self.round_keys, data, &mut out);
        Ok(out)
    }

    /// [`Des::ecb_decrypt`] in place, without allocating (error, and `buf`
    /// untouched, if it is not a whole number of blocks).
    pub fn ecb_decrypt_in_place(&self, buf: &mut [u8]) -> Result<()> {
        if !buf.len().is_multiple_of(8) {
            return Err(unaligned("DES ECB decrypt", buf.len()));
        }
        ecb_in_place::<true>(&self.round_keys, buf);
        Ok(())
    }

    /// [`Des::ecb_encrypt`] in place, without allocating.
    pub fn ecb_encrypt_in_place(&self, buf: &mut [u8]) -> Result<()> {
        if !buf.len().is_multiple_of(8) {
            return Err(unaligned("DES ECB encrypt", buf.len()));
        }
        ecb_in_place::<false>(&self.round_keys, buf);
        Ok(())
    }
}

#[cold]
fn unaligned(what: &str, len: usize) -> Error {
    Error::msg(format!(
        "{what}: data length {len} is not a multiple of the 8-byte block size"
    ))
}

/// Odd-parity adjustment used by the DES key schedule: given a byte whose low
/// bit is 0, set that bit so the byte's total population count is odd. volatility3's
/// `odd_parity` lookup table (in `windows/registry/hashdump.py`) implements exactly
/// this function; deriving it algebraically avoids reproducing a 256-entry table.
fn odd_parity(b: u8) -> u8 {
    if (b >> 1).count_ones() % 2 == 0 {
        b | 1
    } else {
        b & !1
    }
}

/// Expands 7 bytes (56 bits) of key material into an 8-byte DES key with an
/// odd-parity bit in the low bit of each byte, as used throughout the SAM/LSA
/// secret-decryption routines (`Hashdump.sidbytes_to_key` /
/// `SystemFunction005` in volatility3's `windows/registry/hashdump.py` and
/// `lsadump.py`). Splitting a RID or an LSA key into the 7-byte chunks this
/// takes as input is plugin-specific logic and is not part of this module.
pub fn key_from_7_bytes(s: &[u8; 7]) -> [u8; 8] {
    let key7 = [
        s[0] >> 1,
        ((s[0] & 0x01) << 6) | (s[1] >> 2),
        ((s[1] & 0x03) << 5) | (s[2] >> 3),
        ((s[2] & 0x07) << 4) | (s[3] >> 4),
        ((s[3] & 0x0F) << 3) | (s[4] >> 5),
        ((s[4] & 0x1F) << 2) | (s[5] >> 6),
        ((s[5] & 0x3F) << 1) | (s[6] >> 7),
        s[6] & 0x7F,
    ];
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = odd_parity(key7[i] << 1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    fn unhex8(s: &str) -> [u8; 8] {
        let v: Vec<u8> = (0..16)
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }
    fn rng(seed: u64) -> impl FnMut() -> u64 {
        let mut s = seed;
        move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        }
    }

    // Textbook DES straight from the FIPS 46-3 tables, bit at a time -- the
    // reference every table-driven path is checked against.
    fn reference_round_keys(key: &[u8; 8]) -> [u64; 16] {
        let pc1 = permute_slow(u64::from_be_bytes(*key), &PC1, 64);
        let (mut c, mut d) = (pc1 >> 28, pc1 & 0x0FFF_FFFF);
        let mut rk = [0u64; 16];
        for (i, &s) in SHIFTS.iter().enumerate() {
            c = ((c << s) | (c >> (28 - s))) & 0x0FFF_FFFF;
            d = ((d << s) | (d >> (28 - s))) & 0x0FFF_FFFF;
            rk[i] = permute_slow((c << 28) | d, &PC2, 56);
        }
        rk
    }
    fn reference_crypt(key: &[u8; 8], block: u64, decrypt: bool) -> u64 {
        let mut rk = reference_round_keys(key);
        if decrypt {
            rk.reverse();
        }
        let x = permute_slow(block, &IP, 64);
        let (mut l, mut r) = ((x >> 32) as u32, x as u32);
        for k in rk {
            let e = permute_slow(r as u64, &E, 32) ^ k;
            let mut s = 0u64;
            for i in 0..8 {
                let g = ((e >> (42 - 6 * i)) & 63) as usize;
                let row = ((g & 0x20) >> 4) | (g & 1);
                s = (s << 4) | SBOX[i][row * 16 + ((g >> 1) & 15)] as u64;
            }
            let f = permute_slow(s, &P, 32) as u32;
            (l, r) = (r, l ^ f);
        }
        permute_slow(((r as u64) << 32) | l as u64, &FP, 64)
    }

    // The canonical single DES test vector (FIPS 46-3 / many textbooks).
    #[test]
    fn classic_known_answer() {
        let key = unhex8("133457799BBCDFF1");
        let pt = unhex8("0123456789ABCDEF");
        let des = Des::new(&key);
        let mut block = pt;
        des.encrypt_block(&mut block);
        assert_eq!(hex(&block), "85e813540f0ab405");
        des.decrypt_block(&mut block);
        assert_eq!(block, pt);
    }

    // NIST SP 800-17 variable-plaintext known-answer subset (encryption of the
    // all-zero block with a single 1-bit key, first few entries).
    #[test]
    fn nist_variable_plaintext_subset() {
        let key = unhex8("8000000000000000");
        let des = Des::new(&key);
        let mut block = [0u8; 8];
        des.encrypt_block(&mut block);
        assert_eq!(hex(&block), "95a8d72813daa94d");
    }

    #[test]
    fn odd_parity_matches_hashdump_table_formula() {
        // Spot-check a handful of values against volatility3's hard-coded
        // odd_parity table (windows/registry/hashdump.py): odd_parity[x] for
        // even x in [0, 2, 4, 6, 8] is [1, 2, 4, 7, 8].
        assert_eq!(odd_parity(0), 1);
        assert_eq!(odd_parity(2), 2);
        assert_eq!(odd_parity(4), 4);
        assert_eq!(odd_parity(6), 7);
        assert_eq!(odd_parity(8), 8);
    }

    #[test]
    fn ecb_rejects_unaligned_length() {
        let des = Des::new(&[0u8; 8]);
        assert!(des.ecb_decrypt(&[0u8; 7]).is_err());
        assert!(des.ecb_decrypt(&[0u8; 9]).is_err());
        assert!(des.ecb_decrypt(&[]).unwrap().is_empty());
        let mut odd = [5u8; 9];
        assert!(des.ecb_decrypt_in_place(&mut odd).is_err());
        assert!(des.ecb_encrypt_in_place(&mut odd).is_err());
        assert_eq!(odd, [5u8; 9]);
    }

    #[test]
    fn ecb_roundtrip() {
        let des = Des::new(&unhex8("0123456789ABCDEF"));
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let ct = des.ecb_encrypt(&data).unwrap();
        let pt = des.ecb_decrypt(&ct).unwrap();
        assert_eq!(pt, data);
    }

    // The single-table IP/FP and the nibble/7-bit key-schedule tables compute
    // exactly the FIPS permutations.
    #[test]
    fn fast_permutations_match_slow() {
        let mut next = rng(0x1234_5678_9ABC_DEF0);
        for _ in 0..2000 {
            let x = next();
            assert_eq!(ip(x), permute_slow(x, &IP, 64), "IP {x:#x}");
            assert_eq!(fp(x), permute_slow(x, &FP, 64), "FP {x:#x}");
            assert_eq!(fp(ip(x)), x, "FP inverts IP");
            let key = x.to_be_bytes();
            let fast = key_schedule(&key);
            let slow = reference_round_keys(&key);
            for i in 0..16 {
                assert_eq!(fast[i], key_layout(slow[i]), "round key {i} of {x:#x}");
            }
        }
    }

    // SP tables == S-box then P, in the rotated domain.
    #[test]
    fn sp_tables_match_sbox_then_p() {
        for slot in 0..8 {
            let i = SLOT_SBOX[slot];
            for g in 0..64usize {
                let row = ((g & 0x20) >> 4) | (g & 0x01);
                let col = (g >> 1) & 0x0F;
                let placed = (SBOX[i][row * 16 + col] as u64) << (28 - 4 * i);
                let expect = (permute_slow(placed, &P, 32) as u32).rotate_right(ROT);
                assert_eq!(TABLES.sp[slot][g], expect, "slot={slot} g={g}");
            }
        }
    }

    // Every block path (single, 4-way interleaved, Vec, in place; encrypt and
    // decrypt) against the bit-at-a-time textbook DES, on random keys and block
    // counts covering the 4-block groups and the 1-3 block tails.
    #[test]
    fn all_paths_match_reference_des() {
        let mut next = rng(0xDE5_DE5);
        for _ in 0..40 {
            let key = next().to_be_bytes();
            let des = Des::new(&key);
            for nblocks in [0usize, 1, 2, 3, 4, 5, 7, 8, 9, 13] {
                let data: Vec<u8> = (0..nblocks).flat_map(|_| next().to_be_bytes()).collect();
                let enc: Vec<u8> = data
                    .chunks_exact(8)
                    .flat_map(|c| {
                        reference_crypt(&key, u64::from_be_bytes(c.try_into().unwrap()), false)
                            .to_be_bytes()
                    })
                    .collect();
                let dec: Vec<u8> = data
                    .chunks_exact(8)
                    .flat_map(|c| {
                        reference_crypt(&key, u64::from_be_bytes(c.try_into().unwrap()), true)
                            .to_be_bytes()
                    })
                    .collect();
                assert_eq!(des.ecb_encrypt(&data).unwrap(), enc);
                assert_eq!(des.ecb_decrypt(&data).unwrap(), dec);
                let mut buf = data.clone();
                des.ecb_encrypt_in_place(&mut buf).unwrap();
                assert_eq!(buf, enc);
                let mut buf = data.clone();
                des.ecb_decrypt_in_place(&mut buf).unwrap();
                assert_eq!(buf, dec);
                for (i, c) in data.chunks_exact(8).enumerate() {
                    let mut b: [u8; 8] = c.try_into().unwrap();
                    des.encrypt_block(&mut b);
                    assert_eq!(b[..], enc[8 * i..8 * i + 8]);
                    let mut b: [u8; 8] = c.try_into().unwrap();
                    des.decrypt_block(&mut b);
                    assert_eq!(b[..], dec[8 * i..8 * i + 8]);
                }
            }
        }
    }
}
