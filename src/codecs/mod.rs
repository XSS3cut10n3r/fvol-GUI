//! Decompression codecs (std only).
//!
//! Every codec exposes `decompress(data: &[u8]) -> Result<Vec<u8>>` (plus format specific
//! helpers). Malformed input never panics; it returns [`crate::error::Error`].

#![allow(dead_code, unexpected_cfgs)]

pub mod bzip2;
pub mod crc;
pub mod gzip;
pub mod inflate;
pub mod lzma;
pub mod lznt1;
pub mod xz;
pub mod zip;
pub mod zlib;
#[cfg(test)]
mod bench;

/// A zero-filled buffer of `n` bytes, or an error if it cannot be allocated. Sizes taken from
/// (possibly malicious) headers must go through this instead of `vec![0; n]`, which aborts the
/// process on failure. Uses calloc, so large buffers are lazily zeroed fresh pages.
pub(crate) fn try_zeroed(n: usize) -> crate::error::Result<Vec<u8>> {
    if n == 0 {
        return Ok(Vec::new());
    }
    let layout = std::alloc::Layout::array::<u8>(n)
        .map_err(|_| crate::error::Error::Msg(format!("cannot allocate {n} bytes")))?;
    // SAFETY: layout has non-zero size; on success the block holds n initialised (zero) bytes
    // allocated by the global allocator with alignment 1, as Vec<u8> requires.
    unsafe {
        let p = std::alloc::alloc_zeroed(layout);
        if p.is_null() {
            return Err(crate::error::Error::Msg(format!("cannot allocate {n} bytes")));
        }
        Ok(Vec::from_raw_parts(p, n, n))
    }
}
