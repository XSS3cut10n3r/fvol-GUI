//! PNG writer reproducing Pillow 12.3.0's `Image.save(fp, "PNG")` byte for byte for a plain
//! RGBA image (`Image.new("RGBA", size)` + `putpixel`, default save options), as used by
//! `linux.graphics.fbdev --dump`.
//!
//! What Pillow writes (PngImagePlugin._save + ImageFile._save + libImaging/ZipEncode.c,
//! verified empirically against the installed Pillow, see the ignored test
//! `png_pillow_corpus`):
//! * signature, `IHDR` (width, height, bit depth 8, colour type 6, 0, 0, 0), `IDAT`s, `IEND`
//!   — no other chunk for an image without info / encoder options;
//! * the image data: one filter byte + the filtered scanline per row, compressed as a single
//!   zlib stream with `deflateInit2(Z_DEFAULT_COMPRESSION = 6, Z_DEFLATED, 15, 9, Z_FILTERED)`,
//!   one `deflate(Z_NO_FLUSH)` call per filtered row, then `Z_FINISH` (zlib 1.3.2, reproduced
//!   by [`super::zlib_exact`]);
//! * per-row adaptive filter: None, then Up, Sub, Paeth (Average only with `optimize=True`),
//!   each tried only while the best "sum of distances from zero" (`v < 128 ? v : 256 - v`) is
//!   still > 0, and taken only if strictly smaller (ties keep the earlier filter); the
//!   previous row starts as zeros;
//! * the encoder output buffer is `max(65536, 4 * width)` bytes and each buffer becomes one
//!   IDAT chunk, so the zlib stream is split into IDATs of exactly that size (the last one
//!   shorter; a stream that is an exact multiple does not produce an empty IDAT).

use super::crc::crc32_update;
use super::zlib_exact::{Deflater, Z_FILTERED, Z_FINISH, Z_NO_FLUSH};

const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];

/// `ImageFile.MAXBLOCK`.
const MAXBLOCK: usize = 65536;

/// The PNG file Pillow 12.3.0 writes for a `width` x `height` RGBA image whose pixels are
/// `rgba` (row-major, 4 bytes per pixel). Missing trailing bytes count as 0 (the value of
/// pixels `Image.new` leaves unset). Pillow refuses to save an empty image ("cannot write
/// empty image"): for `width == 0 || height == 0` this returns an empty Vec.
pub fn png_rgba_pillow(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
    if width == 0 || height == 0 {
        return Vec::new();
    }
    let w = width as usize;
    let h = height as usize;
    let stride = w * 4;
    let z = idat_stream(w, h, rgba);

    let bufsize = MAXBLOCK.max(stride);
    let nchunks = z.len().div_ceil(bufsize);
    let mut out = Vec::with_capacity(8 + 25 + z.len() + 12 * nchunks + 12);
    out.extend_from_slice(&SIGNATURE);
    let mut ihdr = [0u8; 13];
    ihdr[0..4].copy_from_slice(&width.to_be_bytes());
    ihdr[4..8].copy_from_slice(&height.to_be_bytes());
    ihdr[8] = 8; // bit depth
    ihdr[9] = 6; // colour type RGBA
    put_chunk(&mut out, b"IHDR", &ihdr);
    for c in z.chunks(bufsize) {
        put_chunk(&mut out, b"IDAT", c);
    }
    put_chunk(&mut out, b"IEND", &[]);
    out
}

fn put_chunk(out: &mut Vec<u8>, cid: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(cid);
    out.extend_from_slice(data);
    let crc = crc32_update(crc32_update(0, cid), data);
    out.extend_from_slice(&crc.to_be_bytes());
}

/// The zlib stream of the IDAT chunks (ZipEncode.c in PNG mode).
fn idat_stream(w: usize, h: usize, rgba: &[u8]) -> Vec<u8> {
    let stride = w * 4;
    let mut d = Deflater::new(6, 15, 9, Z_FILTERED).expect("valid zlib parameters");
    // Filtered image data is typically well compressible; start with a quarter.
    let mut z = Vec::with_capacity((stride + 1) * h / 4 + 1024);
    // Rows are read in place. A short `rgba` is padded with zeros (unset pixels): the row
    // holding its tail is copied, rows after it are all zero like the initial previous row.
    let zero = vec![0u8; stride];
    let full = (rgba.len() / stride).min(h);
    let mut tail_row = Vec::new();
    if full < h {
        tail_row = zero.clone();
        let tail = &rgba[full * stride..];
        tail_row[..tail.len()].copy_from_slice(tail);
    }
    let row = |y: usize| -> &[u8] {
        if y < full {
            &rgba[y * stride..(y + 1) * stride]
        } else if y == full {
            &tail_row
        } else {
            &zero
        }
    };
    let mut filtered = vec![0u8; stride + 1];
    for y in 0..h {
        let prev = if y == 0 { &zero[..] } else { row(y - 1) };
        filter_row(row(y), prev, &mut filtered);
        d.deflate_vec(&filtered, &mut z, Z_NO_FLUSH);
    }
    d.deflate_vec(&[], &mut z, Z_FINISH);
    z
}

/// Distance of a filtered byte from zero: `v < 128 ? v : 256 - v`.
#[inline(always)]
fn dist(v: u8) -> u32 {
    (v as i8).unsigned_abs() as u32
}

/// Paeth predictor residual for byte `x` with left `a`, up `b`, up-left `c` (PNG spec order
/// of the tie rules: a, then b, then c).
#[inline(always)]
fn paeth(x: u8, a: u8, b: u8, c: u8) -> u8 {
    let (ai, bi, ci) = (a as i16, b as i16, c as i16);
    let pa = (bi - ci).abs();
    let pb = (ai - ci).abs();
    let pc = (ai + bi - 2 * ci).abs();
    let p = if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    };
    x.wrapping_sub(p)
}

const BPP: usize = 4;

/// Sums of distances from zero of the None, Up and Sub filtered row, in one pass.
fn sums_none_up_sub(row: &[u8], prev: &[u8]) -> (u64, u64, u64) {
    let n = row.len();
    let prev = &prev[..n];
    let head = n.min(BPP);
    let (mut s_none, mut s_up, mut s_sub) = (0u64, 0u64, 0u64);
    for i in 0..head {
        s_none += dist(row[i]) as u64;
        s_up += dist(row[i].wrapping_sub(prev[i])) as u64;
        s_sub += dist(row[i]) as u64;
    }
    // Blocks of at most 2^16 bytes keep the u32 lane sums from overflowing (2^16 * 128).
    let mut i = head;
    while i < n {
        let end = (i + (1 << 16)).min(n);
        let (mut a0, mut a1, mut a2) = (0u32, 0u32, 0u32);
        let (x, a, b) = (&row[i..end], &row[i - BPP..end - BPP], &prev[i..end]);
        for j in 0..x.len() {
            a0 += dist(x[j]);
            a1 += dist(x[j].wrapping_sub(b[j]));
            a2 += dist(x[j].wrapping_sub(a[j]));
        }
        s_none += a0 as u64;
        s_up += a1 as u64;
        s_sub += a2 as u64;
        i = end;
    }
    (s_none, s_up, s_sub)
}

/// Writes the Paeth-filtered row to `o` and returns its sum of distances from zero.
fn paeth_into(row: &[u8], prev: &[u8], o: &mut [u8]) -> u64 {
    let n = row.len();
    let (prev, o) = (&prev[..n], &mut o[..n]);
    let head = n.min(BPP);
    let mut s = 0u64;
    for i in 0..head {
        // a = c = 0: the predictor is b
        o[i] = row[i].wrapping_sub(prev[i]);
        s += dist(o[i]) as u64;
    }
    let mut i = head;
    while i < n {
        let end = (i + (1 << 16)).min(n);
        let mut acc = 0u32;
        let (x, a, b, c) = (&row[i..end], &row[i - BPP..end - BPP], &prev[i..end], &prev[i - BPP..end - BPP]);
        let o = &mut o[i..end];
        for j in 0..x.len() {
            let v = paeth(x[j], a[j], b[j], c[j]);
            o[j] = v;
            acc += dist(v);
        }
        s += acc as u64;
        i = end;
    }
    s
}

/// Pillow's adaptive filter choice for one scanline; writes filter byte + filtered data to
/// `out` (len = row.len() + 1). Pixels are 4 bytes (bpp = 4).
fn filter_row(row: &[u8], prev: &[u8], out: &mut [u8]) {
    let n = row.len();
    let (row, prev) = (&row[..n], &prev[..n]);
    let (s_none, s_up, s_sub) = sums_none_up_sub(row, prev);
    let mut best = 0u8;
    let mut sum = s_none;
    if sum > 0 && s_up < sum {
        best = 2;
        sum = s_up;
    }
    if sum > 0 && s_sub < sum {
        best = 1;
        sum = s_sub;
    }
    let (f, o) = out.split_at_mut(1);
    let o = &mut o[..n];
    // Paeth is tried last and only while the best sum is still > 0.
    if sum > 0 && paeth_into(row, prev, o) < sum {
        f[0] = 4;
        return;
    }
    f[0] = best;
    let head = n.min(BPP);
    match best {
        0 => o.copy_from_slice(row),
        2 => {
            for i in 0..n {
                o[i] = row[i].wrapping_sub(prev[i]);
            }
        }
        _ => {
            o[..head].copy_from_slice(&row[..head]);
            for i in head..n {
                o[i] = row[i].wrapping_sub(row[i - BPP]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic test pixels, shared with bench/refbench/png_pillow_oracle.py (`lcg`).
    pub(crate) fn lcg_bytes(n: usize, seed: u32) -> Vec<u8> {
        let mut s = seed;
        (0..n)
            .map(|_| {
                s = s.wrapping_mul(1103515245).wrapping_add(12345);
                (s >> 16) as u8
            })
            .collect()
    }

    /// Mirrors `pattern` in tests/fixtures/codecs/gen_png.py.
    fn pattern(w: usize, h: usize) -> Vec<u8> {
        let mut out = vec![0u8; w * h * 4];
        for y in 0..h {
            for x in 0..w {
                let o = (y * w + x) * 4;
                let v = if (x / 3 + y / 5) % 7 == 0 { 255 } else { 0 };
                out[o..o + 4].copy_from_slice(&[(x * 5 + y) as u8, v, (x * y) as u8, 255 - (y & 15) as u8]);
            }
        }
        out
    }

    /// Pillow's own output (tests/fixtures/codecs/gen_png.py).
    #[test]
    fn golden_files() {
        use super::super::testdata::fixture;
        for (w, h, seed) in [(1usize, 1usize, 1u32), (3, 7, 2), (17, 5, 3)] {
            let want = fixture(&format!("png_lcg_{w}x{h}_s{seed}.png"));
            assert!(png_rgba_pillow(w as u32, h as u32, &lcg_bytes(w * h * 4, seed)) == want, "lcg {w}x{h}");
        }
        assert!(png_rgba_pillow(16, 16, &pattern(16, 16)) == fixture("png_pattern_16x16.png"));
    }

    /// Larger Pillow outputs (several IDAT chunks), checked by length + CRC-32.
    #[test]
    fn golden_len_crc() {
        let a = png_rgba_pillow(300, 200, &lcg_bytes(300 * 200 * 4, 4));
        assert_eq!((a.len(), super::super::crc::crc32(&a)), (240550, 0x8b3eb454));
        let b = png_rgba_pillow(333, 250, &pattern(333, 250));
        assert_eq!((b.len(), super::super::crc::crc32(&b)), (43449, 0xb436b3d2));
    }

    /// Byte-exact comparison against a Pillow corpus made by
    /// `bench/refbench/png_pillow_oracle.py DIR` (NAME_WxH.rgba + NAME_WxH.png pairs):
    ///
    /// ```text
    /// PNG_CORPUS=DIR cargo test --profile fast png_pillow_corpus -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn png_pillow_corpus() {
        let dir = std::env::var("PNG_CORPUS")
            .unwrap_or_else(|_| format!("{}/testdata/png_corpus", env!("CARGO_MANIFEST_DIR")));
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "rgba"))
            .collect();
        names.sort();
        let mut bad = 0;
        for p in &names {
            let stem = p.file_stem().unwrap().to_string_lossy().to_string();
            let dims = stem.rsplit('_').next().unwrap();
            let (w, h) = dims.split_once('x').unwrap();
            let (w, h): (u32, u32) = (w.parse().unwrap(), h.parse().unwrap());
            let rgba = std::fs::read(p).unwrap();
            let want = std::fs::read(p.with_extension("png")).unwrap();
            let t = std::time::Instant::now();
            let got = png_rgba_pillow(w, h, &rgba);
            let ms = t.elapsed().as_secs_f64() * 1e3;
            let ok = got == want;
            if !ok {
                bad += 1;
            }
            println!("{:32} {:>9} bytes {:8.2} ms {}", stem, want.len(), ms, if ok { "ok" } else { "MISMATCH" });
        }
        println!("png_pillow_corpus: {} images, {} mismatches", names.len(), bad);
        assert!(!names.is_empty() && bad == 0);
    }

    /// PNG_BENCH=DIR/NAME_WxH.rgba [PNG_RUNS=N]: best-of-N time of png_rgba_pillow. Prints
    /// "rust png NAME BYTES BEST_MS".
    #[test]
    #[ignore]
    fn png_bench() {
        let Ok(path) = std::env::var("PNG_BENCH") else {
            eprintln!("set PNG_BENCH");
            return;
        };
        let runs: usize = std::env::var("PNG_RUNS").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
        let p = std::path::Path::new(&path);
        let stem = p.file_stem().unwrap().to_string_lossy().to_string();
        let (w, h) = stem.rsplit('_').next().unwrap().split_once('x').unwrap();
        let (w, h): (u32, u32) = (w.parse().unwrap(), h.parse().unwrap());
        let rgba = std::fs::read(p).unwrap();
        let mut best = f64::MAX;
        let mut n = 0;
        for _ in 0..runs {
            let t = std::time::Instant::now();
            let png = png_rgba_pillow(w, h, &rgba);
            best = best.min(t.elapsed().as_secs_f64());
            n = png.len();
        }
        println!("rust png {stem} {n} {:.3}", best * 1e3);
    }

    #[test]
    fn short_buffer_is_zero_padded() {
        let (w, h) = (13usize, 9usize);
        let px = lcg_bytes(w * h * 4, 3);
        for cut in [0, 1, 52, 53, w * 4 * 3 + 7, w * h * 4 - 1] {
            let mut padded = px[..cut].to_vec();
            padded.resize(w * h * 4, 0);
            assert!(png_rgba_pillow(w as u32, h as u32, &px[..cut]) == png_rgba_pillow(w as u32, h as u32, &padded), "cut {cut}");
        }
    }

    #[test]
    fn empty_image() {
        assert!(png_rgba_pillow(0, 5, &[]).is_empty());
        assert!(png_rgba_pillow(5, 0, &[]).is_empty());
    }

    #[test]
    fn roundtrip_through_inflate() {
        let (w, h) = (37usize, 23usize);
        let px = lcg_bytes(w * h * 4, 9);
        let png = png_rgba_pillow(w as u32, h as u32, &px);
        assert_eq!(&png[..8], &SIGNATURE);
        // gather IDATs
        let mut i = 8;
        let mut z = Vec::new();
        while i < png.len() {
            let n = u32::from_be_bytes(png[i..i + 4].try_into().unwrap()) as usize;
            if &png[i + 4..i + 8] == b"IDAT" {
                z.extend_from_slice(&png[i + 8..i + 8 + n]);
            }
            i += 12 + n;
        }
        let raw = super::super::zlib::decompress(&z).unwrap();
        assert_eq!(raw.len(), h * (w * 4 + 1));
        // unfilter and compare
        let stride = w * 4;
        let mut prev = vec![0u8; stride];
        for y in 0..h {
            let f = raw[y * (stride + 1)];
            let d = &raw[y * (stride + 1) + 1..(y + 1) * (stride + 1)];
            let mut cur = vec![0u8; stride];
            for x in 0..stride {
                let a = if x >= 4 { cur[x - 4] } else { 0 };
                let b = prev[x];
                let c = if x >= 4 { prev[x - 4] } else { 0 };
                cur[x] = match f {
                    0 => d[x],
                    1 => d[x].wrapping_add(a),
                    2 => d[x].wrapping_add(b),
                    // paeth(0, a, b, c) = -predictor
                    4 => d[x].wrapping_sub(paeth(0, a, b, c)),
                    _ => panic!("filter {f}"),
                };
            }
            assert_eq!(&cur[..], &px[y * stride..(y + 1) * stride], "row {y}");
            prev = cur;
        }
    }
}
