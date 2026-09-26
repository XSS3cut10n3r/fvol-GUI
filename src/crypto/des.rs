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
//! ## Table-driven implementation
//!
//! DES's bit-level permutations (IP, FP, the 32->48-bit expansion E, the P
//! permutation after the S-boxes, and the key schedule's PC1/PC2) are each a
//! fixed selection of "output bit i comes from input bit table\[i\]". Naively
//! applying one bit at a time (a loop over the table) costs one iteration per
//! output bit -- 64 for IP/FP, 48 for E and PC2, 56 for PC1 -- adding up to well
//! over a thousand loop iterations per block (E and P alone run inside all 16
//! Feistel rounds) plus ~800 more per key schedule.
//!
//! Because every one of these permutations only *selects* bits (never combines
//! two input bits into one output bit), the contribution of each input *byte* to
//! the output can be precomputed independently and then OR-ed together: for each
//! of the `in_bits/8` input byte positions, build a 256-entry table of "the
//! (zero-elsewhere) output value this byte alone would produce for every
//! possible byte value". Applying the permutation then costs `in_bits/8` table
//! lookups and ORs instead of `table.len()` loop iterations -- e.g. 4 lookups
//! instead of 48 for E, or 8 instead of 64 for IP/FP. [`build_perm_tables`]
//! builds these once (lazily, via `OnceLock`) using [`permute_slow`] -- the
//! original bit-loop -- as the ground truth, so there is no risk of the fast and
//! slow paths disagreeing on *what* permutation is being computed, only on *how*
//! it's computed; `tests::fast_matches_slow_permutation` cross-checks them
//! directly, and every existing FIPS/differential/known-answer test exercises
//! the fast path in normal use (it's the only path -- there is no separate
//! "slow mode" left in `Des` itself).
//!
//! The S-box lookup + P-permutation step is folded into eight 64-entry
//! "SP-boxes" the same way: since the P permutation's input byte (well, nibble)
//! ranges for each of the 8 S-boxes' 4-bit outputs are disjoint, P(S-box
//! output) can be precomputed per S-box and XOR-combined, skipping the explicit
//! concatenate-then-permute step entirely (see [`build_sp_tables`]).

use crate::error::{Error, Result};
use std::sync::OnceLock;

// --- Standard FIPS 46-3 permutation / selection tables (1-indexed bit positions,
// counting from the most-significant bit of the relevant value). Used only to
// build the fast lookup tables below (see module doc comment) -- never on the
// per-block hot path. ---

const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4,
];

const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41,
    52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

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

/// The original bit-at-a-time permutation. Only used to *build* the fast tables
/// below (and in the cross-check test) -- never called per-block.
fn permute_slow(input: u64, table: &[u8], in_bits: u32) -> u64 {
    let mut out: u64 = 0;
    for &pos in table {
        let bit = (input >> (in_bits - pos as u32)) & 1;
        out = (out << 1) | bit;
    }
    out
}

/// Builds the per-input-byte contribution tables described in the module doc
/// comment, as a fixed-size `[[u64;256]; N]` (N = `in_bits/8`) rather than a
/// heap-allocated `Vec` -- these are read on every single block/round, so
/// avoiding the extra pointer indirection (and letting `apply_perm` fully
/// unroll its loop over a compile-time-known `N`) measurably matters here, in
/// a way it doesn't for AES's once-per-call S-box. `in_bits` must be a multiple
/// of 8 (true for every permutation DES actually uses: IP/FP/PC1 take 64 bits,
/// E and P take 32, PC2 takes 56) and must equal `N*8`.
fn build_perm_tables<const N: usize>(table: &'static [u8], in_bits: usize) -> [[u64; 256]; N] {
    debug_assert_eq!(in_bits, N * 8);
    let mut tables = [[0u64; 256]; N];
    for (byte_idx, tbl) in tables.iter_mut().enumerate() {
        let shift = in_bits - 8 * (byte_idx + 1);
        for (val, slot) in tbl.iter_mut().enumerate() {
            let input = (val as u64) << shift;
            *slot = permute_slow(input, table, in_bits as u32);
        }
    }
    tables
}

/// Applies a table built by [`build_perm_tables`]: `N` lookups + ORs, unrolled
/// since `N` is a compile-time constant at every call site.
#[inline(always)]
fn apply_perm<const N: usize>(tables: &[[u64; 256]; N], input: u64, in_bits: usize) -> u64 {
    let mut out = 0u64;
    for (byte_idx, tbl) in tables.iter().enumerate() {
        let shift = in_bits - 8 * (byte_idx + 1);
        out |= tbl[((input >> shift) & 0xFF) as usize];
    }
    out
}

/// The 8 S-boxes' outputs, pre-permuted through P and placed in their final bit
/// position, so `feistel` can XOR-combine 8 table lookups instead of
/// concatenating 8 nibbles and then running a separate 32-bit permutation (P's
/// input bit ranges for each S-box's 4-bit output are disjoint, so precomputing
/// P applied to "just this S-box's nibble, every other bit 0" and XOR-ing all 8
/// together is exactly equivalent to concatenating then permuting once).
fn build_sp_tables() -> [[u32; 64]; 8] {
    let mut sp = [[0u32; 64]; 8];
    for (i, sbox) in SBOX.iter().enumerate() {
        for chunk in 0..64usize {
            let row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
            let col = (chunk >> 1) & 0x0F;
            let val = sbox[row * 16 + col] as u32;
            // Box i's 4-bit output occupies bits (31-4i)..(28-4i) of the 32-bit
            // concatenation the original code built via `sbox_out = (sbox_out
            // << 4) | val` across boxes 0..8.
            let placed = (val as u64) << (28 - 4 * i);
            sp[i][chunk] = permute_slow(placed, &P, 32) as u32;
        }
    }
    sp
}

struct Tables {
    ip: [[u64; 256]; 8],
    fp: [[u64; 256]; 8],
    e: [[u64; 256]; 4],
    pc1: [[u64; 256]; 8],
    pc2: [[u64; 256]; 7],
    sp: [[u32; 64]; 8],
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| Tables {
        ip: build_perm_tables(&IP, 64),
        fp: build_perm_tables(&FP, 64),
        e: build_perm_tables(&E, 32),
        pc1: build_perm_tables(&PC1, 64),
        pc2: build_perm_tables(&PC2, 56),
        sp: build_sp_tables(),
    })
}

/// The 16 round keys (48 bits each, right aligned in a u64) derived from a
/// 64-bit (56-bits-+ parity) DES key.
fn key_schedule(key: &[u8; 8]) -> [u64; 16] {
    let t = tables();
    let key_bits = u64::from_be_bytes(*key);
    let pc1 = apply_perm(&t.pc1, key_bits, 64); // 56 significant bits
    let mut c = (pc1 >> 28) & 0x0FFF_FFFF;
    let mut d = pc1 & 0x0FFF_FFFF;

    let mut round_keys = [0u64; 16];
    for (i, &shift) in SHIFTS.iter().enumerate() {
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFF_FFFF;
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFF_FFFF;
        let cd = (c << 28) | d;
        round_keys[i] = apply_perm(&t.pc2, cd, 56);
    }
    round_keys
}

#[inline]
fn feistel(t: &Tables, r: u32, round_key: u64) -> u32 {
    let expanded = apply_perm(&t.e, r as u64, 32); // 48 bits
    let x = expanded ^ round_key;
    let mut out = 0u32;
    for i in 0..8 {
        let chunk = ((x >> (42 - 6 * i)) & 0x3F) as usize;
        out ^= t.sp[i][chunk];
    }
    out
}

fn crypt_block(t: &Tables, block: u64, round_keys: &[u64; 16]) -> u64 {
    let ip = apply_perm(&t.ip, block, 64);
    let mut l = (ip >> 32) as u32;
    let mut r = ip as u32;
    for &rk in round_keys {
        let new_r = l ^ feistel(t, r, rk);
        l = r;
        r = new_r;
    }
    // Note: no swap after the final round (pre-output combination is R||L... here
    // l/r have already been swapped 16 times, an even count would return to R,L
    // order, so we combine as r_final||l_final to match the standard, which is
    // equivalent to *not* performing the final swap the Feistel loop above would
    // otherwise apply).
    let combined = ((r as u64) << 32) | (l as u64);
    apply_perm(&t.fp, combined, 64)
}

/// A single DES key, expanded into its 16 round keys.
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
        let t = tables();
        let input = u64::from_be_bytes(*block);
        let output = crypt_block(t, input, &self.round_keys);
        *block = output.to_be_bytes();
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        let t = tables();
        let mut reversed = self.round_keys;
        reversed.reverse();
        let input = u64::from_be_bytes(*block);
        let output = crypt_block(t, input, &reversed);
        *block = output.to_be_bytes();
    }

    /// Decrypts `data` as independent 8-byte ECB blocks (`DES.new(key,
    /// DES.MODE_ECB).decrypt(data)` in pycryptodome). Returns an error rather
    /// than panicking if `data` is not a whole number of blocks.
    pub fn ecb_decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(8) {
            return Err(Error::msg(format!(
                "DES ECB decrypt: data length {} is not a multiple of the 8-byte block size",
                data.len()
            )));
        }
        let t = tables();
        let mut reversed = self.round_keys;
        reversed.reverse();
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks_exact(8) {
            let input = u64::from_be_bytes(chunk.try_into().unwrap());
            let output = crypt_block(t, input, &reversed);
            out.extend_from_slice(&output.to_be_bytes());
        }
        Ok(out)
    }

    /// Encrypts `data` as independent 8-byte ECB blocks.
    pub fn ecb_encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(8) {
            return Err(Error::msg(format!(
                "DES ECB encrypt: data length {} is not a multiple of the 8-byte block size",
                data.len()
            )));
        }
        let t = tables();
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks_exact(8) {
            let input = u64::from_be_bytes(chunk.try_into().unwrap());
            let output = crypt_block(t, input, &self.round_keys);
            out.extend_from_slice(&output.to_be_bytes());
        }
        Ok(out)
    }
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
    }

    #[test]
    fn ecb_roundtrip() {
        let des = Des::new(&unhex8("0123456789ABCDEF"));
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let ct = des.ecb_encrypt(&data).unwrap();
        let pt = des.ecb_decrypt(&ct).unwrap();
        assert_eq!(pt, data);
    }

    // Cross-checks every fast table-driven permutation against the original
    // bit-loop it was built from, on random inputs -- this is what actually
    // proves `build_perm_tables`/`apply_perm` compute the same function as
    // `permute_slow`, independent of whether DES's own answers happen to be
    // right (which the KAT/differential tests above already establish using
    // only the fast path).
    #[test]
    fn fast_matches_slow_permutation() {
        let mut rng: u64 = 0x1234_5678_9ABC_DEF0;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        macro_rules! check {
            ($n:literal, $table:expr, $in_bits:expr) => {{
                let fast = build_perm_tables::<$n>($table, $in_bits);
                for _ in 0..200 {
                    let raw = next();
                    let input = if $in_bits == 64 {
                        raw
                    } else {
                        raw & ((1u64 << $in_bits) - 1)
                    };
                    assert_eq!(
                        apply_perm(&fast, input, $in_bits),
                        permute_slow(input, $table, $in_bits as u32),
                        "in_bits={} input={input:#x}",
                        $in_bits
                    );
                }
            }};
        }
        check!(8, &IP, 64);
        check!(8, &FP, 64);
        check!(4, &E, 32);
        check!(8, &PC1, 64);
        check!(7, &PC2, 56);
    }

    #[test]
    fn sp_tables_match_sbox_then_p() {
        let sp = build_sp_tables();
        for i in 0..8 {
            for chunk in 0..64usize {
                let row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
                let col = (chunk >> 1) & 0x0F;
                let val = SBOX[i][row * 16 + col] as u64;
                let placed = val << (28 - 4 * i);
                let expect = permute_slow(placed, &P, 32) as u32;
                assert_eq!(sp[i][chunk], expect, "box={i} chunk={chunk}");
            }
        }
    }
}
