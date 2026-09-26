// Derived from Volatility 3 (Volatility Software License 1.0); see LICENSE.txt.
//! HMAC (RFC 2104 / FIPS 198-1), over MD5, SHA-1 and SHA-256.
//!
//! volatility3 uses `Crypto.Hash.HMAC.new(key, msg)` in
//! `windows/registry/cachedump.py` to derive the RC4 key for cached domain
//! credentials on pre-Vista systems; pycryptodome's `HMAC.new` defaults to MD5
//! when no `digestmod` is given, so that call is HMAC-MD5. HMAC-SHA1/SHA256 are
//! provided here as general-purpose primitives for the rest of the framework
//! (e.g. any future NTLM/Kerberos support), built the same way.

use super::md5::Md5;
use super::sha1::Sha1;
use super::sha256::Sha256;

const BLOCK_SIZE: usize = 64; // MD5, SHA-1 and SHA-256 all use 64-byte blocks.

/// Computes `HMAC(key, msg)` given hasher constructors, mirroring RFC 2104.
/// `N` is the output size in bytes of the underlying hash.
fn hmac<const N: usize>(
    key: &[u8],
    msg: &[u8],
    new: impl Fn() -> HasherKind,
    update: impl Fn(&mut HasherKind, &[u8]),
    finalize: impl Fn(HasherKind) -> [u8; N],
) -> [u8; N] {
    // Normalize the key to exactly BLOCK_SIZE bytes.
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let mut h = new();
        update(&mut h, key);
        let hashed = finalize(h);
        key_block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    let mut inner = new();
    update(&mut inner, &ipad);
    update(&mut inner, msg);
    let inner_digest = finalize(inner);

    let mut outer = new();
    update(&mut outer, &opad);
    update(&mut outer, &inner_digest);
    finalize(outer)
}

// A tiny closed enum lets the three call sites below share the generic `hmac`
// helper above without needing a hashing trait object or associated-type plumbing.
enum HasherKind {
    Md5(Md5),
    Sha1(Sha1),
    Sha256(Sha256),
}

/// HMAC-MD5 (RFC 2202). Used for cached-domain-credential key derivation
/// (`windows/registry/cachedump.py`, pre-Vista path).
pub fn hmac_md5(key: &[u8], msg: &[u8]) -> [u8; 16] {
    hmac::<16>(
        key,
        msg,
        || HasherKind::Md5(Md5::new()),
        |h, d| {
            if let HasherKind::Md5(h) = h {
                h.update(d)
            }
        },
        |h| match h {
            HasherKind::Md5(h) => h.finalize(),
            _ => unreachable!(),
        },
    )
}

/// HMAC-SHA1 (RFC 2202).
pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    hmac::<20>(
        key,
        msg,
        || HasherKind::Sha1(Sha1::new()),
        |h, d| {
            if let HasherKind::Sha1(h) = h {
                h.update(d)
            }
        },
        |h| match h {
            HasherKind::Sha1(h) => h.finalize(),
            _ => unreachable!(),
        },
    )
}

/// HMAC-SHA256 (RFC 4231).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    hmac::<32>(
        key,
        msg,
        || HasherKind::Sha256(Sha256::new()),
        |h, d| {
            if let HasherKind::Sha256(h) = h {
                h.update(d)
            }
        },
        |h| match h {
            HasherKind::Sha256(h) => h.finalize(),
            _ => unreachable!(),
        },
    )
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

    // RFC 2202 HMAC-MD5 test cases 1-4 (key <= block size; cases 5-7 involve
    // truncated output / repeated data and are covered by the differential
    // tests instead).
    #[test]
    fn rfc2202_hmac_md5() {
        let cases: &[(&[u8], &[u8], &str)] = &[
            (
                &[0x0b; 16],
                b"Hi There",
                "9294727a3638bb1c13f48ef8158bfc9d",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "750c783e6ab0b503eaa86e310a5db738",
            ),
            (&[0xaa; 16], &[0xdd; 50], "56be34521d144c88dbb8c733f0e8b3f6"),
        ];
        for (key, msg, expect) in cases {
            assert_eq!(hex(&hmac_md5(key, msg)), *expect);
        }
    }

    // RFC 2202 HMAC-SHA1 test cases 1-3.
    #[test]
    fn rfc2202_hmac_sha1() {
        let cases: &[(&[u8], &[u8], &str)] = &[
            (
                &[0x0b; 20],
                b"Hi There",
                "b617318655057264e28bc0b6fb378c8ef146be00",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            ),
            (
                &[0xaa; 20],
                &[0xdd; 50],
                "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
            ),
        ];
        for (key, msg, expect) in cases {
            assert_eq!(hex(&hmac_sha1(key, msg)), *expect);
        }
    }

    // RFC 4231 HMAC-SHA256 test cases 1-2.
    #[test]
    fn rfc4231_hmac_sha256() {
        let key1 = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        assert_eq!(
            hex(&hmac_sha256(&key1, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(
                b"Jefe",
                b"what do ya want for nothing?"
            )),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
