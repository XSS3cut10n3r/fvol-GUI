//! xz / lzma decompression.
// STUB (core agent): shells out to `xz -dc`; replaced by the codecs agent's native decoder.

/// Decompress a complete .xz stream.
pub fn decompress(data: &[u8]) -> crate::error::Result<Vec<u8>> {
    super::pipe("xz", &["-dc"], data)
}
