//! Raw DEFLATE (zip method 8) decompression.
// STUB (core agent): wraps the raw deflate data in a gzip container and shells out to
// `gzip -dc`; replaced by the codecs agent's native inflate.

/// Inflate raw DEFLATE data. `crc32` / `size` come from the zip directory entry.
pub fn inflate(raw: &[u8], crc32: u32, size: u32) -> crate::error::Result<Vec<u8>> {
    let mut g = Vec::with_capacity(raw.len() + 18);
    g.extend_from_slice(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff]);
    g.extend_from_slice(raw);
    g.extend_from_slice(&crc32.to_le_bytes());
    g.extend_from_slice(&size.to_le_bytes());
    super::pipe("gzip", &["-dc"], &g)
}
