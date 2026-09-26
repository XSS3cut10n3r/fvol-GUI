//! gzip decompression.
// STUB (core agent): shells out to `gzip -dc`; replaced by the codecs agent's native decoder.

/// Decompress a complete .gz stream.
pub fn decompress(data: &[u8]) -> crate::error::Result<Vec<u8>> {
    super::pipe("gzip", &["-dc"], data)
}
