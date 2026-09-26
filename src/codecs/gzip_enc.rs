//! gzip (RFC 1952) writers: the streaming parallel [`GzipEncoder`] (pigz scheme) and the
//! one-shot [`gzip_compress`]. Also [`crc32_combine`].
//!
//! [`GzipEncoder`] splits the stream into [`CHUNK`]-sized pieces that worker threads compress
//! with [`Compressor`], each primed with the preceding 32 KiB as dictionary and ended on a
//! byte boundary (only the last one carries BFINAL), so the pieces concatenate into one
//! ordinary single-member gzip stream that any inflater (gzip -d, python gzip/tarfile, our
//! [`super::gzip::decompress`]) reads. CRC-32s are computed per piece on the workers and
//! combined. Memory is bounded: at most ~1.5 x threads pieces are in flight (about 2 MiB
//! each); `write` blocks when the budget is used up. The compressed bytes depend only on the
//! input and the level, not on the thread count or on how the input was split into `write`s.

use std::io::{self, Write};

use super::crc::crc32;
use super::deflate_enc::{CHUNK, Compressor, deflate_compress_into};
use super::enc_pipeline::Pipeline;

const WSIZE: usize = 1 << 15;

/// gzip header fields and compression settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GzipOptions {
    /// MTIME header field (python: `int(time.time())` unless given).
    pub mtime: u32,
    /// XFL header field (python: 2 for level 9, 4 for level 1, else 0).
    pub xfl: u8,
    /// OS header field (python always writes 255 = unknown).
    pub os: u8,
    /// Compression level 0-9 (python's tarfile/gzip default is 9).
    pub level: u32,
    /// Worker threads for [`GzipEncoder`] (0 = all logical CPUs, `crate::util::par::threads()`).
    pub threads: usize,
}

impl GzipOptions {
    /// The header python writes for `gzip.GzipFile(fileobj=<BytesIO or other nameless
    /// object>, mode="wb", compresslevel=level, mtime=mtime)` (`tarfile.open(fileobj=...,
    /// mode="w:gz")` uses level 9): `1f 8b 08 00 MTIME XFL ff`, no file name.
    pub fn python(level: u32, mtime: u32) -> GzipOptions {
        let xfl = match level {
            9 => 2,
            1 => 4,
            _ => 0,
        };
        GzipOptions { mtime, xfl, os: 255, level, threads: 0 }
    }

    /// The 10-byte member header (FLG = 0: no name, comment, extra or header CRC).
    pub fn header(&self) -> [u8; 10] {
        let m = self.mtime.to_le_bytes();
        [0x1f, 0x8b, 8, 0, m[0], m[1], m[2], m[3], self.xfl, self.os]
    }
}

impl Default for GzipOptions {
    /// `GzipOptions::python(9, 0)`.
    fn default() -> GzipOptions {
        GzipOptions::python(9, 0)
    }
}

// ---------------------------------------------------------------------------------------
// CRC-32 combination (GF(2) polynomial arithmetic modulo the reflected CRC-32 polynomial)
// ---------------------------------------------------------------------------------------

const POLY: u32 = 0xEDB8_8320;

/// a * b mod P (reflected: bit 31 is the x^0 coefficient).
fn multmodp(a: u32, mut b: u32) -> u32 {
    let mut m = 1u32 << 31;
    let mut p = 0u32;
    loop {
        if a & m != 0 {
            p ^= b;
            if a & (m - 1) == 0 {
                break;
            }
        }
        m >>= 1;
        b = if b & 1 != 0 { (b >> 1) ^ POLY } else { b >> 1 };
    }
    p
}

/// X2N[k] = x^(2^k) mod P.
static X2N: [u32; 32] = {
    let mut t = [0u32; 32];
    let mut p = 1u32 << 30; // x^1
    t[0] = p;
    let mut k = 1;
    while k < 32 {
        // p = p * p mod P (const version of multmodp)
        let (a, mut b) = (p, p);
        let mut m = 1u32 << 31;
        let mut r = 0u32;
        loop {
            if a & m != 0 {
                r ^= b;
                if a & (m - 1) == 0 {
                    break;
                }
            }
            m >>= 1;
            b = if b & 1 != 0 { (b >> 1) ^ POLY } else { b >> 1 };
        }
        p = r;
        t[k] = p;
        k += 1;
    }
    t
};

/// x^(n * 2^k) mod P.
fn x2nmodp(mut n: u64, mut k: u32) -> u32 {
    let mut p = 1u32 << 31; // x^0
    while n != 0 {
        if n & 1 != 0 {
            p = multmodp(X2N[(k & 31) as usize], p);
        }
        n >>= 1;
        k += 1;
    }
    p
}

/// CRC-32 of `A ++ B` from `crc1 = crc32(A)`, `crc2 = crc32(B)` and `len2 = B.len()`
/// (zlib's `crc32_combine`).
pub fn crc32_combine(crc1: u32, crc2: u32, len2: u64) -> u32 {
    multmodp(x2nmodp(len2, 3), crc1) ^ crc2
}

// ---------------------------------------------------------------------------------------
// One-shot
// ---------------------------------------------------------------------------------------

/// Compresses `data` into a single-member gzip file with `opts`' header (large inputs are
/// compressed in parallel on all cores; `opts.threads` is ignored).
pub fn gzip_compress(data: &[u8], opts: &GzipOptions) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 3 + 64);
    out.extend_from_slice(&opts.header());
    let crc = if data.len() > CHUNK {
        std::thread::scope(|s| {
            let c = s.spawn(|| crc32(data));
            deflate_compress_into(data, opts.level, &mut out);
            c.join().unwrap_or_else(|_| crc32(data))
        })
    } else {
        deflate_compress_into(data, opts.level, &mut out);
        crc32(data)
    };
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

// ---------------------------------------------------------------------------------------
// Streaming parallel encoder
// ---------------------------------------------------------------------------------------

struct Job {
    /// `[dictionary (<= 32 KiB) | piece]`
    buf: Vec<u8>,
    dict: usize,
    last: bool,
    /// Recycled output buffer.
    out: Vec<u8>,
}

struct Done {
    out: Vec<u8>,
    crc: u32,
    len: usize,
    buf: Vec<u8>,
}

fn compress_job(c: &mut Compressor, mut j: Job) -> Done {
    let piece = &j.buf[j.dict..];
    let crc = crc32(piece);
    let len = piece.len();
    j.out.clear();
    c.compress(&j.buf, j.dict, j.last, &mut j.out);
    Done { out: j.out, crc, len, buf: j.buf }
}

/// Streaming, parallel gzip writer (see the module documentation). Create with
/// [`GzipEncoder::new`], feed it through [`std::io::Write`], and call
/// [`GzipEncoder::finish`] to write the final block and the CRC-32/ISIZE trailer (dropping
/// the encoder without `finish` leaves the output truncated).
pub struct GzipEncoder<W: Write + Send> {
    w: W,
    header: [u8; 10],
    header_written: bool,
    pipe: Pipeline<Compressor, Job, Done>,
    max_in_flight: usize,
    /// Current piece being filled: `[dictionary | data]`.
    cur: Vec<u8>,
    dict: usize,
    crc: u32,
    size: u64,
    free: Vec<Vec<u8>>,
}

impl<W: Write + Send> GzipEncoder<W> {
    /// A gzip writer onto `w` with `opts`' header fields, level and thread count. Nothing is
    /// written to `w` until the first piece is compressed (or [`GzipEncoder::finish`]).
    pub fn new(w: W, opts: GzipOptions) -> GzipEncoder<W> {
        let threads = if opts.threads == 0 { crate::util::par::threads() } else { opts.threads };
        let level = opts.level.min(9);
        let pipe = Pipeline::new(threads, move || Compressor::new(level), compress_job);
        GzipEncoder {
            w,
            header: opts.header(),
            header_written: false,
            pipe,
            max_in_flight: if threads <= 1 { 1 } else { threads + threads / 2 + 1 },
            cur: Vec::new(),
            dict: 0,
            crc: 0,
            size: 0,
            free: Vec::new(),
        }
    }

    /// Uncompressed bytes accepted so far.
    pub fn total_in(&self) -> u64 {
        self.size + (self.cur.len() - self.dict) as u64
    }

    /// Hands the current piece to the pipeline and starts the next one with its last 32 KiB
    /// as dictionary.
    fn submit(&mut self, last: bool) -> io::Result<()> {
        let keep = self.cur.len().min(WSIZE);
        let mut next = self.free.pop().unwrap_or_default();
        next.clear();
        next.reserve(WSIZE + CHUNK);
        next.extend_from_slice(&self.cur[self.cur.len() - keep..]);
        let buf = std::mem::replace(&mut self.cur, next);
        let out = self.free.pop().unwrap_or_default();
        let job = Job { buf, dict: self.dict, last, out };
        self.dict = keep;
        if last && self.pipe.submitted() == 0 {
            // Small stream: no threads.
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

    /// Writes every result that is ready (blocking: every result in flight).
    fn collect(&mut self, block: bool) -> io::Result<()> {
        while self.collect_one(block)? {}
        Ok(())
    }

    fn collect_one(&mut self, block: bool) -> io::Result<bool> {
        let Some(r) = self.pipe.next(block) else { return Ok(false) };
        let d = r?;
        if !self.header_written {
            self.w.write_all(&self.header)?;
            self.header_written = true;
        }
        self.w.write_all(&d.out)?;
        self.crc = crc32_combine(self.crc, d.crc, d.len as u64);
        self.size += d.len as u64;
        self.free.push(d.out);
        self.free.push(d.buf);
        Ok(true)
    }

    /// Compresses the remaining input, writes the final block and the trailer (CRC-32 and
    /// ISIZE = total length mod 2^32), flushes and returns the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.submit(true)?;
        self.collect(true)?;
        if !self.header_written {
            self.w.write_all(&self.header)?;
        }
        let mut t = [0u8; 8];
        t[..4].copy_from_slice(&self.crc.to_le_bytes());
        t[4..].copy_from_slice(&(self.size as u32).to_le_bytes());
        self.w.write_all(&t)?;
        self.w.flush()?;
        let GzipEncoder { w, .. } = self;
        Ok(w)
    }
}

impl<W: Write + Send> Write for GzipEncoder<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut rest = data;
        while !rest.is_empty() {
            if self.cur.len() == self.dict + CHUNK {
                // Full: only now (more data follows) is it known not to be the last piece.
                self.submit(false)?;
            }
            if self.cur.capacity() == 0 {
                self.cur.reserve(WSIZE + CHUNK);
            }
            let n = (self.dict + CHUNK - self.cur.len()).min(rest.len());
            self.cur.extend_from_slice(&rest[..n]);
            rest = &rest[n..];
        }
        Ok(data.len())
    }

    /// Writes out the pieces that are already compressed and flushes the inner writer (the
    /// piece being filled stays buffered: a gzip stream cannot be flushed mid-piece without
    /// changing the output).
    fn flush(&mut self) -> io::Result<()> {
        self.collect(false)?;
        self.w.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecs::testdata::gen_data;

    #[test]
    fn codecs_gzip_enc_crc32_combine() {
        let data = gen_data(3, 100_000);
        for split in [0usize, 1, 7, 4096, 65_536, 99_999, 100_000] {
            let (a, b) = data.split_at(split);
            assert_eq!(crc32_combine(crc32(a), crc32(b), b.len() as u64), crc32(&data), "split {split}");
        }
        assert_eq!(crc32_combine(0, 0, 0), 0);
    }

    #[test]
    fn codecs_gzip_enc_header_python() {
        let o = GzipOptions::python(9, 0x6ab70963);
        assert_eq!(o.header(), [0x1f, 0x8b, 8, 0, 0x63, 0x09, 0xb7, 0x6a, 2, 0xff]);
        assert_eq!(GzipOptions::python(6, 0).xfl, 0);
        assert_eq!(GzipOptions::python(1, 0).xfl, 4);
    }

    fn stream(data: &[u8], opts: GzipOptions, write_size: usize) -> Vec<u8> {
        let mut e = GzipEncoder::new(Vec::new(), opts);
        for c in data.chunks(write_size.max(1)) {
            e.write_all(c).unwrap();
        }
        if data.is_empty() {
            e.write_all(&[]).unwrap();
        }
        e.finish().unwrap()
    }

    #[test]
    fn codecs_gzip_enc_roundtrip() {
        let mut big = gen_data(11, 2 * CHUNK + 777);
        big[CHUNK - 5000..CHUNK + 300_000].fill(0);
        let cases: Vec<Vec<u8>> =
            vec![Vec::new(), b"x".to_vec(), gen_data(1, 1000), gen_data(2, CHUNK), big.clone(), vec![0u8; CHUNK * 3]];
        for data in &cases {
            let mut prev: Option<Vec<u8>> = None;
            for (threads, ws) in [(1usize, 1 << 20), (4, 1000), (3, 65_536), (2, CHUNK + 1)] {
                let opts = GzipOptions { threads, ..GzipOptions::python(9, 1234) };
                let gz = stream(data, opts, ws);
                assert_eq!(&gz[..10], &opts.header());
                assert!(crate::codecs::gzip::decompress(&gz).unwrap() == *data, "len {} threads {threads}", data.len());
                // Same bytes regardless of thread count and write sizes.
                if let Some(p) = &prev {
                    assert!(p == &gz, "output depends on threads/write size (len {})", data.len());
                }
                prev = Some(gz);
            }
            // One-shot writer produces the same stream.
            assert!(gzip_compress(data, &GzipOptions::python(9, 1234)) == prev.unwrap(), "one-shot differs");
        }
    }
}
