//! LZNT1 decompression (NTFS / RtlDecompressBuffer COMPRESSION_FORMAT_LZNT1).
//!
//! Placeholder: the implementation is being written on the `feat/codecs-lznt1` branch.

use crate::error::{Error, Result};

/// Decompresses an LZNT1 buffer (sequence of chunks, terminated by a zero chunk header or
/// the end of the input).
pub fn decompress(_data: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Msg("lznt1: not implemented yet".into()))
}
