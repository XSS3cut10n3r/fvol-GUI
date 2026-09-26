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
    let mut prev = vec![0u8; stride];
    let mut pad = Vec::new();
    let mut filtered = vec![0u8; stride + 1];
    for y in 0..h {
        let start = y * stride;
        let row: &[u8] = if start + stride <= rgba.len() {
            &rgba[start..start + stride]
        } else {
            pad.clear();
            pad.extend_from_slice(rgba.get(start..).unwrap_or(&[]));
            pad.resize(stride, 0);
            &pad
        };
        filter_row(row, &prev, &mut filtered);
        d.deflate_vec(&filtered, &mut z, Z_NO_FLUSH);
        prev.copy_from_slice(row);
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

/// Pillow's adaptive filter choice for one scanline; writes filter byte + filtered data to
/// `out` (len = row.len() + 1). Pixels are 4 bytes (bpp = 4).
fn filter_row(row: &[u8], prev: &[u8], out: &mut [u8]) {
    const BPP: usize = 4;
    let n = row.len();
    let (row, prev) = (&row[..n], &prev[..n]);
    // All four sums in one pass over the row (the C code computes each candidate filter only
    // while the best sum is > 0; computing all of them does not change the decision below).
    let (mut s_none, mut s_up, mut s_sub, mut s_paeth) = (0u64, 0u64, 0u64, 0u64);
    let head = n.min(BPP);
    for i in 0..head {
        let x = row[i];
        s_none += dist(x) as u64;
        let up = x.wrapping_sub(prev[i]);
        s_up += dist(up) as u64;
        s_sub += dist(x) as u64;
        s_paeth += dist(up) as u64;
    }
    if n > BPP {
        // Chunked so the u32 lane sums cannot overflow (4096 * 128 < 2^32).
        let mut i = BPP;
        while i < n {
            let end = (i + 4096).min(n);
            let (mut a0, mut a1, mut a2, mut a3) = (0u32, 0u32, 0u32, 0u32);
            for j in i..end {
                let x = row[j];
                let a = row[j - BPP];
                let b = prev[j];
                let c = prev[j - BPP];
                a0 += dist(x);
                a1 += dist(x.wrapping_sub(b));
                a2 += dist(x.wrapping_sub(a));
                a3 += dist(paeth(x, a, b, c));
            }
            s_none += a0 as u64;
            s_up += a1 as u64;
            s_sub += a2 as u64;
            s_paeth += a3 as u64;
            i = end;
        }
    }
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
    if sum > 0 && s_paeth < sum {
        best = 4;
    }
    out[0] = best;
    let o = &mut out[1..n + 1];
    match best {
        0 => o.copy_from_slice(row),
        2 => {
            for i in 0..n {
                o[i] = row[i].wrapping_sub(prev[i]);
            }
        }
        1 => {
            o[..head].copy_from_slice(&row[..head]);
            for i in head..n {
                o[i] = row[i].wrapping_sub(row[i - BPP]);
            }
        }
        _ => {
            for i in 0..head {
                o[i] = row[i].wrapping_sub(prev[i]);
            }
            for i in head..n {
                o[i] = paeth(row[i], row[i - BPP], prev[i], prev[i - BPP]);
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
