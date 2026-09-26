//! Compression codecs (std only).
//!
//! Decoders: every codec exposes `decompress(data: &[u8]) -> Result<Vec<u8>>` (plus format
//! specific helpers). Malformed input never panics; it returns [`crate::error::Error`].
//!
//! * [`xz::decompress`] — `.xz` (all streams/blocks, LZMA2 + x86 BCJ / delta, CRC32/CRC64
//!   verified; multi-block files decode in parallel). ISF symbol files are `.json.xz`.
//! * [`lzma::decompress`] (`.lzma` / LZMA_Alone), [`lzma::decompress_lzma2`] (raw LZMA2),
//!   [`lzma::decompress_lzma1_raw`] (raw LZMA1 with a properties byte, ZIP method 14).
//! * [`inflate::decompress`] (raw DEFLATE), [`zlib::decompress`], [`gzip::decompress`]
//!   (multi-member).
//! * [`bzip2::decompress`] (multi-stream).
//! * Streaming, for whole memory images: [`gzip::decompress_to`] and
//!   [`bzip2::decompress_to`] emit into a [`sink::Sink`] (e.g. [`sink::FileSink`], a writer
//!   thread) with bounded memory; [`xz::decompress_to_file`] decodes blocks in parallel and
//!   writes each at its offset.
//! * [`zip::ZipArchive`] — `parse`, `entries`, `find(name)`, `read(&entry)`.
//! * [`lznt1::decompress`] — NTFS / RtlDecompressBuffer LZNT1.
//! * [`snappy`], [`xpress`] — owned by the formats agent (memory image containers).
//! * [`crc`] — CRC-32, CRC-64/XZ, CRC-32/BZIP2 (PCLMULQDQ folding).
//! * [`zlib_exact`] — byte-exact zlib 1.3.2 compressor ([`zlib_exact::Deflater`],
//!   [`zlib_exact::compress`]) for reproducing files python writes through zlib.
//! * [`png::png_rgba_pillow`] — Pillow 12.3.0's PNG file for an RGBA image, byte for byte.
//!
//! Encoders (streaming ones are `std::io::Write` + `finish() -> io::Result<W>`, compress on
//! worker threads with bounded memory, and produce output independent of the thread count):
//! * [`deflate_enc::deflate_compress`], [`deflate_enc::zlib_compress`] (e.g. PNG IDAT),
//!   [`deflate_enc::Compressor`] — DEFLATE levels 0-9 (lazy hash chains, block splitting).
//! * [`gzip_enc::GzipEncoder`] / [`gzip_enc::gzip_compress`] — gzip with python's header
//!   ([`gzip_enc::GzipOptions::python`]), pigz-style parallel; [`gzip_enc::crc32_combine`].
//! * [`bzip2_enc::Bzip2Encoder`] / [`bzip2_enc::bzip2_compress`] — bzip2, block-parallel
//!   (SA-IS BWT).
//! * [`xz_enc::XzEncoder`] / [`xz_enc::xz_compress`] — `.xz` (LZMA2, CRC-64),
//!   block-parallel.
//!
//! Benchmarks against liblzma / zlib / libbz2: `bench/refbench/codecs_run.sh` (decoders),
//! `bench/refbench/codecs_enc_run.sh` (encoders), `bench/refbench/zlib_exact_run.sh`
//! (zlib_exact / png); system-tool / python round trips: `bench/refbench/codecs_enc_verify.sh`.

#![allow(dead_code, unexpected_cfgs)]

pub mod bzip2;
pub mod bzip2_enc;
pub mod crc;
pub mod deflate_enc;
mod enc_pipeline;
pub(crate) mod huffman_enc;
pub(crate) mod sais;
pub mod gzip;
pub mod gzip_enc;
pub mod inflate;
pub mod lzma;
pub(crate) mod lzma_enc;
pub mod lznt1;
pub mod png;
pub mod sink;
pub mod snappy;
#[cfg(test)]
mod testdata;
pub mod xpress;
pub mod xz;
pub mod xz_enc;
pub mod zip;
pub mod zlib;
pub mod zlib_exact;
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
        advise_huge(p, n);
        Ok(Vec::from_raw_parts(p, n, n))
    }
}

/// Ask for transparent huge pages on a big fresh output buffer before it is first written (a
/// 64 MB decompressed ISF is 16k page faults otherwise, ~30 with 2 MiB pages; systems whose THP
/// mode is `madvise` only use them on request). Advisory only.
pub(crate) fn advise_huge(p: *mut u8, n: usize) {
    #[cfg(target_os = "linux")]
    {
        unsafe extern "C" {
            fn madvise(addr: *mut u8, len: usize, advice: i32) -> i32;
        }
        const PAGE: usize = 4096;
        const MADV_HUGEPAGE: i32 = 14;
        if n < 8 << 20 {
            return;
        }
        let start = (p as usize).next_multiple_of(PAGE);
        let end = (p as usize + n) & !(PAGE - 1);
        if end > start {
            // SAFETY: the page-aligned inside of an allocation this process owns; advisory
            unsafe { madvise(start as *mut u8, end - start, MADV_HUGEPAGE) };
        }
    }
}
