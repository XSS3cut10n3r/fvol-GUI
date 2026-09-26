//! zlib (RFC 1950) container: 2-byte header, raw DEFLATE, big-endian Adler-32 trailer.

use super::inflate::{Check, inflate_into_check};
use crate::error::{Error, Result};

fn err(what: &str) -> Error {
    Error::Msg(format!("zlib: {what}"))
}

/// Decompresses a zlib stream (trailing data after the Adler-32 is ignored, like python's
/// `zlib.decompress`). Preset dictionaries are not supported.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    decompress_with_capacity(data, data.len().saturating_mul(4).clamp(1 << 12, 1 << 28))
}

/// As [`decompress`], pre-allocating `capacity` bytes of output (a hint: if that much memory
/// is not available the output simply grows as needed; the hint is also capped at what
/// DEFLATE can expand `data` to).
pub fn decompress_with_capacity(data: &[u8], capacity: usize) -> Result<Vec<u8>> {
    if data.len() < 2 {
        return Err(err("truncated header"));
    }
    let (cmf, flg) = (data[0], data[1]);
    if cmf & 0x0F != 8 || cmf >> 4 > 7 {
        return Err(err("unknown compression method"));
    }
    if (cmf as u16 * 256 + flg as u16) % 31 != 0 {
        return Err(err("incorrect header check"));
    }
    if flg & 0x20 != 0 {
        return Err(err("preset dictionary not supported"));
    }
    let mut out = Vec::new();
    let _ = out.try_reserve(capacity.min(data.len().saturating_mul(1032).saturating_add(1032)));
    let mut check = Check::adler32();
    let used = inflate_into_check(&data[2..], &mut out, &mut check)?;
    let t = data.get(2 + used..2 + used + 4).ok_or_else(|| err("truncated Adler-32 trailer"))?;
    if check.value != u32::from_be_bytes([t[0], t[1], t[2], t[3]]) {
        return Err(err("incorrect data check"));
    }
    Ok(out)
}

/// Adler-32 of `data`.
pub fn adler32(data: &[u8]) -> u32 {
    adler32_update(1, data)
}

/// Continues an Adler-32 checksum.
pub fn adler32_update(adler: u32, data: &[u8]) -> u32 {
    const MOD: u64 = 65521;
    // Largest multiple of 32 keeping the per-lane sums below 2^32 (zlib's NMAX is 5552).
    const BLOCK: usize = 5536;
    let mut s1 = (adler & 0xFFFF) as u64;
    let mut s2 = (adler >> 16) as u64;
    let mut rest = data;
    // Any multiple of 32 bytes (up to BLOCK) goes through the vector loop, so short and
    // unaligned updates (inflate updates the checksum in 64 KiB chunks) stay fast.
    while rest.len() >= 32 {
        let n = rest.len().min(BLOCK) & !31;
        let (blk, tail) = rest.split_at(n);
        rest = tail;
        // Lane j sums bytes j, j+32, ... (a) and the running prefix sums (b); a plain loop
        // over fixed-size arrays that LLVM vectorises.
        let mut a = [0u32; 32];
        let mut b = [0u32; 32];
        for chunk in blk.chunks_exact(32) {
            for j in 0..32 {
                b[j] += a[j];
                a[j] += chunk[j] as u32;
            }
        }
        let mut sa = 0u64;
        let mut sb = 0u64;
        let mut sj = 0u64;
        for j in 0..32 {
            sa += a[j] as u64;
            sb += b[j] as u64;
            sj += j as u64 * a[j] as u64;
        }
        // With k = n / 32 rows, byte (c, j) at t = 32c + j contributes (n - t) to s2:
        // sum_j sum_c (32 (k - c) - j) x = 32 (b_j + a_j) - j a_j summed over the lanes.
        s2 = (s2 + n as u64 * s1 + 32 * (sb + sa) - sj) % MOD;
        s1 = (s1 + sa) % MOD;
    }
    for &byte in rest {
        s1 += byte as u64;
        s2 += s1;
    }
    ((s2 % MOD) << 16 | (s1 % MOD)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adler_ref(data: &[u8]) -> u32 {
        let (mut a, mut b) = (1u32, 0u32);
        for &x in data {
            a = (a + x as u32) % 65521;
            b = (b + a) % 65521;
        }
        (b << 16) | a
    }

    #[test]
    fn codecs_zlib_adler32() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        let mut v = vec![0u8; 5536 * 3 + 1000];
        let mut s = 7u32;
        for x in v.iter_mut() {
            s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
            *x = (s >> 16) as u8;
        }
        for n in [0, 1, 31, 32, 5535, 5536, 5537, 11072, v.len()] {
            assert_eq!(adler32(&v[..n]), adler_ref(&v[..n]), "len {n}");
        }
        let all_ff = vec![0xFFu8; 20000];
        assert_eq!(adler32(&all_ff), adler_ref(&all_ff));
    }

    #[test]
    fn codecs_zlib_small() {
        // python3: zlib.compress(b"hello hello hello hello\n")
        const Z: &[u8] = &[
            0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x27, 0xb9, 0x00, 0x70, 0xbe, 0x08, 0xbb,
        ];
        assert_eq!(decompress(Z).unwrap(), b"hello hello hello hello\n");
        let mut bad = Z.to_vec();
        *bad.last_mut().unwrap() ^= 1;
        assert!(decompress(&bad).is_err());
        assert!(decompress(&Z[..Z.len() - 1]).is_err());
    }
}
