//! `.xz` writers: the streaming, block-parallel [`XzEncoder`] and the one-shot
//! [`xz_compress`].
//!
//! Output: one xz stream (CRC-64 check, like python's `lzma.LZMAFile(mode="w")` /
//! `tarfile` "w:xz") made of independent blocks of [`XzOptions::block_size`] bytes, each an
//! LZMA2 stream ([`super::lzma_enc`]) whose dictionary is the block itself. Blocks are
//! compressed on worker threads ([`super::enc_pipeline`]) and written in order; block
//! headers carry both sizes (like `xz -T`), followed by the index and footer. `xz -d`,
//! python's `lzma` and [`super::xz::decompress`] read it.
//!
//! Memory: per worker thread about 6 MB of match finder tables plus an LZMA2 scratch
//! buffer, and one input block per job in flight (at most threads + 1 jobs): roughly
//! 25 MB per worker with the default 8 MiB blocks (12 workers by default: ~300 MB; lower
//! [`XzOptions::threads`] to trade speed for memory).

use std::io::{self, Write};

use super::crc::{crc32, crc64};
use super::enc_pipeline::Pipeline;
use super::lzma_enc::{Lzma2Encoder, LzmaParams};

const HEADER_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];
/// Stream flags: check type 4 = CRC-64.
const STREAM_FLAGS: [u8; 2] = [0x00, 0x04];
const FILTER_LZMA2: u64 = 0x21;
const CHECK_SIZE: usize = 8;

/// xz writer settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XzOptions {
    /// Compression preset 0..=9 (python's default is 6): match finder depth / nice length.
    pub preset: u32,
    /// Worker threads (0 = min(all logical CPUs, 12)).
    pub threads: usize,
    /// Uncompressed bytes per xz block (each block is compressed independently, with the
    /// block as its dictionary). Default 8 MiB (the dictionary size of preset 6).
    pub block_size: usize,
}

impl XzOptions {
    /// Default settings for `preset`.
    pub fn preset(preset: u32) -> XzOptions {
        XzOptions { preset: preset.min(9), threads: 0, block_size: 8 << 20 }
    }
}

impl Default for XzOptions {
    /// `XzOptions::preset(6)`.
    fn default() -> XzOptions {
        XzOptions::preset(6)
    }
}

/// Appends an xz variable-length integer.
fn put_vli(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Smallest LZMA2 dictionary-size byte whose size is at least `n`.
fn dict_size_byte(n: usize) -> u8 {
    for b in 0u8..40 {
        let size = (2u64 | (b as u64 & 1)) << (b / 2 + 11);
        if size >= n as u64 {
            return b;
        }
    }
    40
}

fn stream_header() -> [u8; 12] {
    let mut h = [0u8; 12];
    h[..6].copy_from_slice(&HEADER_MAGIC);
    h[6..8].copy_from_slice(&STREAM_FLAGS);
    h[8..12].copy_from_slice(&crc32(&STREAM_FLAGS).to_le_bytes());
    h
}

/// Block header with compressed and uncompressed sizes and the LZMA2 filter.
fn block_header(compressed: u64, uncompressed: u64, dict_byte: u8) -> Vec<u8> {
    let mut h = vec![0u8, 0xC0];
    put_vli(&mut h, compressed);
    put_vli(&mut h, uncompressed);
    put_vli(&mut h, FILTER_LZMA2);
    put_vli(&mut h, 1);
    h.push(dict_byte);
    while !(h.len() + 4).is_multiple_of(4) {
        h.push(0);
    }
    h[0] = ((h.len() + 4) / 4 - 1) as u8;
    let c = crc32(&h);
    h.extend_from_slice(&c.to_le_bytes());
    h
}

/// Index + stream footer for the given (unpadded size, uncompressed size) records.
fn index_and_footer(records: &[(u64, u64)]) -> Vec<u8> {
    let mut idx = vec![0u8];
    put_vli(&mut idx, records.len() as u64);
    for &(unpadded, uncompressed) in records {
        put_vli(&mut idx, unpadded);
        put_vli(&mut idx, uncompressed);
    }
    while !idx.len().is_multiple_of(4) {
        idx.push(0);
    }
    let c = crc32(&idx);
    idx.extend_from_slice(&c.to_le_bytes());
    let backward = (idx.len() / 4 - 1) as u32;
    let mut f = [0u8; 10];
    f[..4].copy_from_slice(&backward.to_le_bytes());
    f[4..6].copy_from_slice(&STREAM_FLAGS);
    let fc = crc32(&f[..6]);
    idx.extend_from_slice(&fc.to_le_bytes());
    idx.extend_from_slice(&f[..6]);
    idx.extend_from_slice(b"YZ");
    idx
}

struct Job {
    data: Vec<u8>,
}

struct Done {
    /// Complete block: header, LZMA2 data, padding, check.
    block: Vec<u8>,
    unpadded: u64,
    uncompressed: u64,
    data: Vec<u8>,
}

/// Per-thread worker state: the compressor, the dictionary-size byte and an LZMA2 scratch
/// buffer.
type Worker = (Lzma2Encoder, u8, Vec<u8>);

fn encode_job(enc: &mut Worker, j: Job) -> Done {
    let (lz, dict_byte, lzma2) = enc;
    lzma2.clear();
    lz.encode_block(&j.data, lzma2);
    let check = crc64(&j.data);
    let header = block_header(lzma2.len() as u64, j.data.len() as u64, *dict_byte);
    let mut block = Vec::with_capacity(header.len() + lzma2.len() + 3 + CHECK_SIZE);
    block.extend_from_slice(&header);
    block.extend_from_slice(lzma2);
    // Block padding: the header is a multiple of 4 bytes, so pad header + data.
    while !block.len().is_multiple_of(4) {
        block.push(0);
    }
    block.extend_from_slice(&check.to_le_bytes());
    let unpadded = (header.len() + lzma2.len() + CHECK_SIZE) as u64;
    Done { block, unpadded, uncompressed: j.data.len() as u64, data: j.data }
}

/// Streaming, block-parallel xz writer (see the module documentation). Create with
/// [`XzEncoder::new`] or [`XzEncoder::with_options`], feed it through [`std::io::Write`],
/// and call [`XzEncoder::finish`] to write the index and footer (dropping it without
/// `finish` leaves the output truncated).
pub struct XzEncoder<W: Write + Send> {
    w: W,
    header_written: bool,
    block_size: usize,
    cur: Vec<u8>,
    pipe: Pipeline<Worker, Job, Done>,
    max_in_flight: usize,
    records: Vec<(u64, u64)>,
    /// Recycled input buffers (block_size capacity).
    free: Vec<Vec<u8>>,
}

impl<W: Write + Send> XzEncoder<W> {
    /// An xz writer onto `w` with compression `preset` (0..=9; python's `lzma.LZMAFile` /
    /// `tarfile` "w:xz" use 6), default block size and threads.
    pub fn new(w: W, preset: u32) -> XzEncoder<W> {
        XzEncoder::with_options(w, XzOptions::preset(preset))
    }

    /// An xz writer with explicit [`XzOptions`].
    pub fn with_options(w: W, opts: XzOptions) -> XzEncoder<W> {
        let threads = if opts.threads == 0 { crate::util::par::threads().min(12) } else { opts.threads };
        let block_size = opts.block_size.clamp(4096, 1 << 30);
        let params = LzmaParams::preset(opts.preset);
        let dict_byte = dict_size_byte(block_size);
        let pipe = Pipeline::new(threads, move || (Lzma2Encoder::new(params), dict_byte, Vec::new()), encode_job);
        XzEncoder {
            w,
            header_written: false,
            block_size,
            cur: Vec::new(),
            pipe,
            max_in_flight: if threads <= 1 { 1 } else { threads + 1 },
            records: Vec::new(),
            free: Vec::new(),
        }
    }

    fn write_header(&mut self) -> io::Result<()> {
        if !self.header_written {
            self.w.write_all(&stream_header())?;
            self.header_written = true;
        }
        Ok(())
    }

    fn submit(&mut self, last: bool) -> io::Result<()> {
        if self.cur.is_empty() {
            return Ok(());
        }
        let data = std::mem::take(&mut self.cur);
        let job = Job { data };
        if last && self.pipe.submitted() == 0 {
            self.pipe.run_inline(job);
        } else {
            self.pipe.submit(job);
        }
        self.collect(false)?;
        while self.pipe.in_flight() >= self.max_in_flight {
            self.collect_one(true)?;
        }
        Ok(())
    }

    fn collect(&mut self, block: bool) -> io::Result<()> {
        while self.collect_one(block)? {}
        Ok(())
    }

    fn collect_one(&mut self, block: bool) -> io::Result<bool> {
        let Some(r) = self.pipe.next(block) else { return Ok(false) };
        let d = r?;
        self.write_header()?;
        self.w.write_all(&d.block)?;
        self.records.push((d.unpadded, d.uncompressed));
        if self.free.len() < 2 {
            self.free.push(d.data);
        }
        Ok(true)
    }

    /// Compresses the remaining input, writes the index and stream footer, flushes and
    /// returns the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.submit(true)?;
        self.collect(true)?;
        self.write_header()?;
        let tail = index_and_footer(&self.records);
        self.w.write_all(&tail)?;
        self.w.flush()?;
        let XzEncoder { w, .. } = self;
        Ok(w)
    }
}

impl<W: Write + Send> Write for XzEncoder<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut rest = data;
        while !rest.is_empty() {
            if self.cur.len() == self.block_size {
                self.submit(false)?;
            }
            if self.cur.capacity() == 0 {
                let mut b = self.free.pop().unwrap_or_default();
                b.clear();
                b.reserve(self.block_size);
                self.cur = b;
            }
            let n = (self.block_size - self.cur.len()).min(rest.len());
            self.cur.extend_from_slice(&rest[..n]);
            rest = &rest[n..];
        }
        Ok(data.len())
    }

    /// Writes out the blocks that are already compressed and flushes the inner writer (the
    /// block being filled stays buffered).
    fn flush(&mut self) -> io::Result<()> {
        self.collect(false)?;
        self.w.flush()
    }
}

/// Compresses `data` into an `.xz` stream at `preset` (0..=9), with the default block size
/// and threads.
pub fn xz_compress(data: &[u8], preset: u32) -> Vec<u8> {
    let mut e = XzEncoder::new(Vec::with_capacity(data.len() / 4 + 64), preset);
    // Writing into a Vec cannot fail.
    let _ = e.write_all(data);
    e.finish().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecs::testdata::gen_data;

    #[test]
    fn codecs_xz_enc_empty_matches_python() {
        // python: lzma.compress(b"")
        let want: [u8; 32] = [
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x00, 0x00, 0x00, 0x00, 0x1c, 0xdf,
            0x44, 0x21, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a,
        ];
        assert_eq!(xz_compress(b"", 6), want);
    }

    #[test]
    fn codecs_xz_enc_roundtrip() {
        let mut big = gen_data(21, 700_000);
        big.extend(std::iter::repeat_n(0u8, 300_000));
        for (data, bs, threads, ws) in [
            (b"hello".to_vec(), 4096, 1, 1),
            (gen_data(1, 10_000), 4096, 2, 333),
            (big.clone(), 65_536, 3, 50_000),
            (big.clone(), 1 << 20, 1, 1 << 20),
        ] {
            let mut e = XzEncoder::with_options(Vec::new(), XzOptions { preset: 6, threads, block_size: bs });
            for c in data.chunks(ws) {
                e.write_all(c).unwrap();
            }
            let z = e.finish().unwrap();
            let d = crate::codecs::xz::decompress(&z).expect("our xz decoder rejected the stream");
            assert!(d == data, "roundtrip mismatch len {} bs {bs}", data.len());
        }
        // Deterministic: independent of threads and write sizes.
        let a = {
            let mut e = XzEncoder::with_options(Vec::new(), XzOptions { preset: 3, threads: 1, block_size: 100_000 });
            e.write_all(&big).unwrap();
            e.finish().unwrap()
        };
        let b = {
            let mut e = XzEncoder::with_options(Vec::new(), XzOptions { preset: 3, threads: 4, block_size: 100_000 });
            for c in big.chunks(7777) {
                e.write_all(c).unwrap();
            }
            e.finish().unwrap()
        };
        assert!(a == b);
    }
}
