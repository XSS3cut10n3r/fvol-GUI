//! bzip2 decompression.
// STUB (core agent): shells out to `bzip2 -dc`; replaced by the codecs agent's native decoder.

/// Decompress a complete .bz2 stream.
pub fn decompress(data: &[u8]) -> crate::error::Result<Vec<u8>> {
    super::pipe("bzip2", &["-dc"], data)
}
