// Derived from Volatility 3 (Volatility Software License 1.0); see LICENSE.txt.
//! RC4 (ARC4). Used throughout the Windows registry-secrets plugins wherever
//! volatility3 calls `Crypto.Cipher.ARC4`:
//! - `windows/registry/hashdump.py`: decrypts the SAM `hbootkey` (pre-Win2k/XP
//!   "revision 2" format) and the per-user LM/NT hash obfuscation key.
//! - `windows/registry/lsadump.py`: decrypts the pre-Vista LSA key
//!   (`PolSecretEncryptionKey`).
//! - `windows/registry/cachedump.py`: decrypts cached domain credentials on
//!   pre-Vista systems, keyed by `HMAC-MD5(NL$KM, challenge)`.
//!
//! RC4 is a symmetric stream cipher: encryption and decryption are the same
//! operation (XOR with the keystream), matching pycryptodome's
//! `ARC4.new(key).encrypt(...)` / `.decrypt(...)` (both call the same C code).

/// Streaming RC4 keystream generator / XOR-applier.
///
/// Call [`Rc4::apply`] repeatedly to keep consuming keystream bytes across
/// multiple buffers (matching a pycryptodome cipher object's `encrypt`/`decrypt`
/// being called more than once), or use the one-shot [`rc4`] function.
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Builds the RC4 state (KSA) from `key`. An empty key leaves the identity
    /// permutation in place (keystream is not attacker-controlled input here;
    /// this just avoids a modulo-by-zero panic rather than trying to be
    /// cryptographically meaningful).
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        if !key.is_empty() {
            let mut j: u8 = 0;
            for i in 0..256usize {
                j = j
                    .wrapping_add(s[i])
                    .wrapping_add(key[i % key.len()]);
                s.swap(i, j as usize);
            }
        }
        Rc4 { s, i: 0, j: 0 }
    }

    /// XORs `data` in place with the next `data.len()` keystream bytes,
    /// advancing internal state (so consecutive calls continue the same
    /// keystream, as with a pycryptodome cipher object).
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

/// One-shot RC4: returns `data` XORed with the keystream generated from `key`.
pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    Rc4::new(key).apply(&mut out);
    out
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

    // RFC 6229 test vectors (first 16 bytes of keystream, applied to a
    // zero-filled plaintext so the ciphertext equals the keystream).
    #[test]
    fn rfc6229_keystream_prefixes() {
        let cases: &[(&str, &str)] = &[
            ("0102030405", "b2396305f03dc027ccc3524a0a1118a8"),
            (
                "0102030405060708090a0b0c0d0e0f10",
                "9ac7cc9a609d1ef7b2932899cde41b97",
            ),
            ("833222772a", "80ad97bdc973df8a2e879e92a497efda"),
        ];
        for (key_hex, ks_hex) in cases {
            let key = unhex(key_hex);
            let n = ks_hex.len() / 2;
            let zeros = vec![0u8; n];
            let out = rc4(&key, &zeros);
            assert_eq!(hex(&out), *ks_hex, "key={key_hex}");
        }
    }

    #[test]
    fn roundtrip_and_streaming_continuation() {
        let key = b"some key material";
        let msg = b"the quick brown fox jumps over the lazy dog, 0123456789";
        let ct = rc4(key, msg);
        let pt = rc4(key, &ct); // RC4 is an involution given the same keystream
        assert_eq!(pt, msg);

        // Splitting the call in two must produce the same output as one call,
        // since a pycryptodome cipher object keeps generating keystream across
        // calls to encrypt()/decrypt().
        let mut cipher = Rc4::new(key);
        let mut buf = msg.to_vec();
        let (a, b) = buf.split_at_mut(10);
        cipher.apply(a);
        cipher.apply(b);
        assert_eq!(buf, ct);
    }

    #[test]
    fn empty_key_does_not_panic() {
        let mut data = [1u8, 2, 3];
        Rc4::new(&[]).apply(&mut data);
    }
}
