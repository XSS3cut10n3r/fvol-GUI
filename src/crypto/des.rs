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

use crate::error::{Error, Result};

// --- Standard FIPS 46-3 permutation / selection tables (1-indexed bit positions,
// counting from the most-significant bit of the relevant value). ---

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

/// Gathers bits from `input` (which holds `in_bits` significant bits, right
/// aligned) according to a 1-indexed-from-the-MSB permutation/selection table,
/// producing a value with `table.len()` significant bits, right aligned.
fn permute(input: u64, table: &[u8], in_bits: u32) -> u64 {
    let mut out: u64 = 0;
    for &pos in table {
        let bit = (input >> (in_bits - pos as u32)) & 1;
        out = (out << 1) | bit;
    }
    out
}

/// The 16 round keys (48 bits each, right aligned in a u64) derived from a
/// 64-bit (56-bits-+ parity) DES key.
fn key_schedule(key: &[u8; 8]) -> [u64; 16] {
    let key_bits = u64::from_be_bytes(*key);
    let pc1 = permute(key_bits, &PC1, 64); // 56 significant bits
    let mut c = (pc1 >> 28) & 0x0FFF_FFFF;
    let mut d = pc1 & 0x0FFF_FFFF;

    let mut round_keys = [0u64; 16];
    for (i, &shift) in SHIFTS.iter().enumerate() {
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFF_FFFF;
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFF_FFFF;
        let cd = (c << 28) | d;
        round_keys[i] = permute(cd, &PC2, 56);
    }
    round_keys
}

fn feistel(r: u32, round_key: u64) -> u32 {
    let expanded = permute(r as u64, &E, 32); // 48 bits
    let x = expanded ^ round_key;
    let mut sbox_out: u32 = 0;
    for (i, sbox) in SBOX.iter().enumerate() {
        let chunk = ((x >> (42 - 6 * i)) & 0x3F) as usize;
        let row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
        let col = (chunk >> 1) & 0x0F;
        let val = sbox[row * 16 + col] as u32;
        sbox_out = (sbox_out << 4) | val;
    }
    permute(sbox_out as u64, &P, 32) as u32
}

fn crypt_block(block: u64, round_keys: &[u64; 16]) -> u64 {
    let ip = permute(block, &IP, 64);
    let mut l = (ip >> 32) as u32;
    let mut r = ip as u32;
    for &rk in round_keys {
        let new_r = l ^ feistel(r, rk);
        l = r;
        r = new_r;
    }
    // Note: no swap after the final round (pre-output combination is R||L... here
    // l/r have already been swapped 16 times, an even count would return to R,L
    // order, so we combine as r_final||l_final to match the standard, which is
    // equivalent to *not* performing the final swap the Feistel loop above would
    // otherwise apply).
    let combined = ((r as u64) << 32) | (l as u64);
    permute(combined, &FP, 64)
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
        let input = u64::from_be_bytes(*block);
        let output = crypt_block(input, &self.round_keys);
        *block = output.to_be_bytes();
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        let mut reversed = self.round_keys;
        reversed.reverse();
        let input = u64::from_be_bytes(*block);
        let output = crypt_block(input, &reversed);
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
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks_exact(8) {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);
            self.decrypt_block(&mut block);
            out.extend_from_slice(&block);
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
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks_exact(8) {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);
            self.encrypt_block(&mut block);
            out.extend_from_slice(&block);
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
}
