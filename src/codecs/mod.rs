//! Decompression codecs (std only).
//!
//! Every codec exposes `decompress(data: &[u8]) -> Result<Vec<u8>>` (plus format specific
//! helpers). Malformed input never panics; it returns [`crate::error::Error`].

#![allow(dead_code, unexpected_cfgs)]

pub mod crc;
pub mod lzma;
pub mod xz;
#[cfg(test)]
mod bench;
