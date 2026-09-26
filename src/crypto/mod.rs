//! Cryptographic primitives used by volatility3 plugins.
//!
//! Zero-dependency (std only) implementations of the hash functions, MAC, and block
//! ciphers that volatility3's registry-secrets plugins (`hashdump`, `lsadump`,
//! `cachedump`) and a handful of other plugins pull in from `hashlib` / pycryptodome
//! (`Crypto.Cipher`, `Crypto.Hash`). See each submodule's doc comment for exactly
//! which plugin(s) use it and how.
//!
//! None of these functions panic on malformed input: buffer-oriented APIs that can
//! fail (wrong block alignment) return `crate::error::Result` rather than panicking,
//! per the project's robustness rule.

pub mod aes;
pub mod des;
pub mod hmac;
pub mod md5;
pub mod rc4;
pub mod sha1;
pub mod sha256;

// Differential tests against Python hashlib/pycryptodome; the embedded vectors
// (~36 KB) are test-only and excluded from non-test builds.
#[cfg(test)]
mod differential;
#[cfg(test)]
mod vectors;

// Manual throughput measurements (`cargo test --profile fast crypto::bench --
// --ignored --nocapture`); see bench.rs for why there's no bench-harness crate.
#[cfg(test)]
mod bench;
