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
///
/// ## Speed
///
/// RC4 is a chain of dependent loads and stores into one 256-entry table, so its
/// speed is set by memory ordering, not arithmetic:
/// - The table is `u32`s, not bytes (as OpenSSL does on x86_64): byte-sized
///   table stores feeding later loads measured ~1.5x slower.
/// - Each step needs `S[i+1]` for the next step, and the only store that can
///   change it before then is this step's `S[j] = S[i]` (when `j == i+1`). So
///   `S[i+1]` is loaded *before* this step's two stores and patched when
///   `j == i+1`, instead of being loaded after them (a load the core would
///   otherwise hold behind the store, or replay when its guess is wrong).
/// - In `apply` the patch is a cold branch, not a select: predicted not-taken,
///   the next `j = j + S[i+1]` does not wait for the `j == i+1` compare (a cmov
///   put it on the chain: 5.0 vs 3.5 cycles/byte). In the key schedule, where
///   the loop is short and the mispredict per key costs relatively more, a
///   select of the two candidate next-`j` sums measured steadier. The key index
///   advances by a counter, not a `%` per byte.
///
/// Together: ~3.5 cycles/byte (OpenSSL's asm: ~7), and the key schedule ~1200
/// cycles (the textbook loop: ~2300).
pub struct Rc4 {
    s: [u32; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Builds the RC4 state (KSA) from `key`. An empty key leaves the identity
    /// permutation in place (keystream is not attacker-controlled input here;
    /// this just avoids a modulo-by-zero panic rather than trying to be
    /// cryptographically meaningful).
    pub fn new(key: &[u8]) -> Self {
        let mut s: [u32; 256] = std::array::from_fn(|i| i as u32);
        if !key.is_empty() {
            // j = j + S[i] + key[i % len]; swap(S[i], S[j]) -- with S[i+1] loaded
            // ahead and the next j selected from the two candidate sums (see the
            // type's doc comment).
            let mut k = 0usize;
            let mut si = s[0];
            let mut j = (si as u8).wrapping_add(key[0]);
            for i in 0..256usize {
                k += 1;
                if k == key.len() {
                    k = 0;
                }
                let kn = key[k];
                let sj = s[j as usize];
                let next = s[(i + 1) & 255];
                s[i] = sj;
                s[j as usize] = si;
                let hit = j as usize == (i + 1) & 255;
                let jn = std::hint::select_unpredictable(hit, j.wrapping_add(si as u8), j.wrapping_add(next as u8));
                si = std::hint::select_unpredictable(hit, si, next);
                j = jn.wrapping_add(kn);
            }
        }
        Rc4 { s, i: 0, j: 0 }
    }

    /// XORs `data` in place with the next `data.len()` keystream bytes,
    /// advancing internal state (so consecutive calls continue the same
    /// keystream, as with a pycryptodome cipher object).
    pub fn apply(&mut self, data: &mut [u8]) {
        let s = &mut self.s;
        let (mut i, mut j) = (self.i, self.j);
        let mut si = s[i.wrapping_add(1) as usize];
        macro_rules! step {
            ($b:expr) => {
                i = i.wrapping_add(1);
                j = j.wrapping_add(si as u8);
                let sj = s[j as usize];
                let next = s[i.wrapping_add(1) as usize];
                s[i as usize] = sj;
                s[j as usize] = si;
                $b ^= s[(si as u8).wrapping_add(sj as u8) as usize] as u8;
                // A (predicted, almost never taken) branch, not a select: a cmov
                // would make the next j wait for this compare; the branch lets the
                // core run ahead with `next` speculatively (1 in 256 mispredicts).
                if j == i.wrapping_add(1) {
                    std::hint::cold_path(); // S[i+1] just became si
                } else {
                    si = next;
                }
            };
        }
        let mut chunks = data.chunks_exact_mut(8);
        for c in &mut chunks {
            for k in 0..8 {
                step!(c[k]);
            }
        }
        for b in chunks.into_remainder() {
            step!(*b);
        }
        self.i = i;
        self.j = j;
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


    // Textbook RC4 (byte table, `%` key index, load-after-store) -- the reference
    // for the scheduled KSA/PRGA above, over many keys, lengths and call splits.
    fn reference(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut s: Vec<u8> = (0..=255).collect();
        let mut j: u8 = 0;
        if !key.is_empty() {
            for i in 0..256 {
                j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
                s.swap(i, j as usize);
            }
        }
        let (mut i, mut j) = (0u8, 0u8);
        data.iter()
            .map(|b| {
                i = i.wrapping_add(1);
                j = j.wrapping_add(s[i as usize]);
                s.swap(i as usize, j as usize);
                b ^ s[s[i as usize].wrapping_add(s[j as usize]) as usize]
            })
            .collect()
    }

    #[test]
    fn matches_textbook_reference() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        };
        for klen in [1usize, 2, 5, 7, 13, 16, 32, 64, 255, 256, 300] {
            let key: Vec<u8> = (0..klen).map(|_| next()).collect();
            let data: Vec<u8> = (0..3000).map(|_| next()).collect();
            let expect = reference(&key, &data);
            assert_eq!(rc4(&key, &data), expect, "klen={klen}");
            // Arbitrary call splits continue the same keystream.
            let mut c = Rc4::new(&key);
            let mut buf = data.clone();
            let mut off = 0;
            for step in [1usize, 7, 8, 9, 255, 256, 257, 1000] {
                let end = (off + step).min(buf.len());
                c.apply(&mut buf[off..end]);
                off = end;
            }
            c.apply(&mut buf[off..]);
            assert_eq!(buf, expect, "split klen={klen}");
        }
        // Keys that force j == i+1 collisions early (all-zero / all-0xff keys).
        for key in [[0u8; 16], [0xffu8; 16], [1u8; 16]] {
            let data = vec![0u8; 5000];
            assert_eq!(rc4(&key, &data), reference(&key, &data));
        }
    }

    #[test]
    fn empty_key_does_not_panic() {
        let mut data = [1u8, 2, 3];
        Rc4::new(&[]).apply(&mut data);
    }
}
