//! Decompression codecs (std only).
//!
//! Every codec exposes `decompress(data: &[u8]) -> Result<Vec<u8>>` (plus format specific
//! helpers). Malformed input never panics; it returns [`crate::error::Error`].
//!
//! * [`xz::decompress`] — `.xz` (all streams/blocks, LZMA2 + x86 BCJ / delta, CRC32/CRC64
//!   verified; multi-block files decode in parallel). ISF symbol files are `.json.xz`.
//! * [`lzma::decompress`] (`.lzma` / LZMA_Alone), [`lzma::decompress_lzma2`] (raw LZMA2),
//!   [`lzma::decompress_lzma1_raw`] (raw LZMA1 with a properties byte, ZIP method 14).
//! * [`inflate::decompress`] (raw DEFLATE), [`zlib::decompress`], [`gzip::decompress`]
//!   (multi-member).
//! * [`bzip2::decompress`] (multi-stream).
//! * [`zip::ZipArchive`] — `parse`, `entries`, `find(name)`, `read(&entry)`.
//! * [`lznt1::decompress`] — NTFS / RtlDecompressBuffer LZNT1.
//! * [`snappy`], [`xpress`] — owned by the formats agent (memory image containers).
//! * [`crc`] — CRC-32, CRC-64/XZ, CRC-32/BZIP2 (PCLMULQDQ folding).
//!
//! Benchmarks against liblzma / zlib / libbz2: `bench/refbench/codecs_run.sh`.

#![allow(dead_code, unexpected_cfgs)]

pub mod bzip2;
pub mod crc;
pub mod gzip;
pub mod inflate;
pub mod lzma;
pub mod lznt1;
pub mod snappy;
#[cfg(test)]
mod testdata;
pub mod xpress;
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
