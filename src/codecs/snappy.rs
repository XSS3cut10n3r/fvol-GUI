//! Snappy decompression: the raw block format and the framing format
//! (<https://github.com/google/snappy/blob/main/format_description.txt>,
//! <https://github.com/google/snappy/blob/main/framing_format.txt>).
//!
//! Used by the AVML container layer (derived from Volatility 3's avml.py, Volatility Software
//! License 1.0), which in python calls libsnappy's `snappy_uncompress` per frame.
//!
//! Hot path: [`decompress_into`] writes into a caller-provided buffer (no allocation); every
//! length/offset is bounds-checked, so malformed input returns an error instead of panicking.

use std::fmt;

/// Maximum uncompressed size of one chunk in the framing format.
pub const MAX_FRAME_UNCOMPRESSED: usize = 65536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnappyError {
    /// The varint length preamble is missing or malformed.
    BadHeader,
    /// Input ended in the middle of an element.
    Truncated,
    /// A copy refers to data before the start of the output (or offset 0).
    BadOffset,
    /// The output does not match the length announced in the preamble.
    BadLength,
    /// The destination buffer is too small.
    OutputTooSmall,
    /// Framing format: bad stream identifier, reserved unskippable chunk, or oversize chunk.
    BadFrame,
    /// Framing format: CRC mismatch.
    BadChecksum,
}

impl fmt::Display for SnappyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SnappyError::BadHeader => "snappy: bad length preamble",
            SnappyError::Truncated => "snappy: truncated input",
            SnappyError::BadOffset => "snappy: bad copy offset",
            SnappyError::BadLength => "snappy: length mismatch",
            SnappyError::OutputTooSmall => "snappy: output buffer too small",
            SnappyError::BadFrame => "snappy: bad frame",
            SnappyError::BadChecksum => "snappy: checksum mismatch",
        };
        f.write_str(s)
    }
}

impl std::error::Error for SnappyError {}

impl From<SnappyError> for crate::error::Error {
    fn from(e: SnappyError) -> Self {
        crate::error::Error::Msg(e.to_string())
    }
}

/// Parse the varint uncompressed-length preamble of a raw snappy block.
/// Returns (uncompressed length, number of preamble bytes).
#[inline]
pub fn uncompressed_len(src: &[u8]) -> Result<(usize, usize), SnappyError> {
    let mut v: u64 = 0;
    for (i, &b) in src.iter().enumerate().take(5) {
        v |= ((b & 0x7f) as u64) << (7 * i);
        if b & 0x80 == 0 {
            // snappy lengths are 32-bit
            if v > u32::MAX as u64 {
                return Err(SnappyError::BadHeader);
            }
            return Ok((v as usize, i + 1));
        }
    }
    Err(SnappyError::BadHeader)
}

/// Decompress a raw snappy block into `dst`, returning the number of bytes written
/// (== the preamble length). `dst` must be at least that large.
pub fn decompress_into(src: &[u8], dst: &mut [u8]) -> Result<usize, SnappyError> {
    let mut st = Partial::start(src)?;
    decompress_continue(src, dst, &mut st, usize::MAX)?;
    Ok(st.ulen)
}

/// Resumable decoding state of one raw snappy block: lets a reader decode only the prefix it
/// needs and continue later (random reads into large compressed frames).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Partial {
    /// Next input position.
    pub ip: usize,
    /// Bytes of output produced so far.
    pub op: usize,
    /// Total uncompressed length (from the preamble).
    pub ulen: usize,
}

impl Partial {
    /// Parse the length preamble.
    pub fn start(src: &[u8]) -> Result<Partial, SnappyError> {
        let (ulen, ip) = uncompressed_len(src)?;
        Ok(Partial { ip, op: 0, ulen })
    }

    pub fn is_complete(&self) -> bool {
        self.op >= self.ulen
    }
}

/// Continue decoding `src` into `dst` (which holds the `st.op` bytes produced so far) until
/// at least `want` bytes are available (`want >= ulen`: decode and validate the whole block).
///
/// Fast paths (like libsnappy): short literals and copies are done with fixed 16-byte
/// unaligned moves when both buffers have slack, instead of variable-length memcpy calls.
/// Every fast path is guarded by explicit bounds checks; the slow path handles buffer ends.
pub fn decompress_continue(src: &[u8], dst: &mut [u8], st: &mut Partial, want: usize) -> Result<(), SnappyError> {
    let ulen = st.ulen;
    if dst.len() < ulen || st.op > ulen {
        return Err(SnappyError::OutputTooSmall);
    }
    let out = &mut dst[..ulen];
    let limit = if want >= ulen { usize::MAX } else { want };
    let (mut ip, mut op) = (st.ip, st.op);
    let n = src.len();
    let sp = src.as_ptr();
    let dp = out.as_mut_ptr();
    while ip < n && op < limit {
        // SAFETY: ip < n
        let tag = unsafe { *sp.add(ip) };
        ip += 1;
        match tag & 3 {
            0 => {
                let mut len = (tag >> 2) as usize;
                if len < 16 && n - ip >= 16 && ulen - op >= 16 {
                    // SAFETY: 16 readable bytes at ip, 16 writable bytes at op (checked above)
                    unsafe { std::ptr::copy_nonoverlapping(sp.add(ip), dp.add(op), 16) };
                    ip += len + 1;
                    op += len + 1;
                    continue;
                }
                if len >= 60 {
                    let nb = len - 59;
                    if n - ip < nb {
                        return Err(SnappyError::Truncated);
                    }
                    let mut v = 0usize;
                    for k in 0..nb {
                        v |= (src[ip + k] as usize) << (8 * k);
                    }
                    ip += nb;
                    len = v;
                }
                len += 1;
                if n - ip < len {
                    return Err(SnappyError::Truncated);
                }
                if ulen - op < len {
                    return Err(SnappyError::BadLength);
                }
                out[op..op + len].copy_from_slice(&src[ip..ip + len]);
                ip += len;
                op += len;
            }
            1 => {
                if ip >= n {
                    return Err(SnappyError::Truncated);
                }
                let len = 4 + ((tag >> 2) & 7) as usize;
                let off = (((tag as usize) >> 5) << 8) | src[ip] as usize;
                ip += 1;
                op = copy_back(out, op, off, len)?;
            }
            2 => {
                if n - ip < 2 {
                    return Err(SnappyError::Truncated);
                }
                let len = 1 + (tag >> 2) as usize;
                let off = u16::from_le_bytes([src[ip], src[ip + 1]]) as usize;
                ip += 2;
                op = copy_back(out, op, off, len)?;
            }
            _ => {
                if n - ip < 4 {
                    return Err(SnappyError::Truncated);
                }
                let len = 1 + (tag >> 2) as usize;
                let off = u32::from_le_bytes([src[ip], src[ip + 1], src[ip + 2], src[ip + 3]]) as usize;
                ip += 4;
                op = copy_back(out, op, off, len)?;
            }
        }
    }
    st.ip = ip;
    st.op = op;
    if ip >= n && op != ulen {
        // the stream ended before (or produced more than) the announced length
        return Err(SnappyError::BadLength);
    }
    Ok(())
}

/// LZ77-style back reference: copy `len` (<= 64) bytes from `op - off` to `op` (may overlap).
#[inline(always)]
fn copy_back(out: &mut [u8], op: usize, off: usize, len: usize) -> Result<usize, SnappyError> {
    if off == 0 || off > op {
        return Err(SnappyError::BadOffset);
    }
    let room = out.len() - op;
    if room < len {
        return Err(SnappyError::BadLength);
    }
    let p = out.as_mut_ptr();
    // Fast paths: fixed-size chunk moves that may write up to 15 bytes past `op + len`
    // (still inside `out`, and overwritten by later elements).
    if off >= 16 && room >= len + 16 {
        let mut k = 0;
        while k < len {
            // SAFETY: src chunk [op-off+k, +16) and dst chunk [op+k, +16) are in bounds
            // (op+k+16 <= op+len+16 <= out.len()) and do not overlap (off >= 16).
            unsafe { std::ptr::copy_nonoverlapping(p.add(op - off + k), p.add(op + k), 16) };
            k += 16;
        }
        return Ok(op + len);
    }
    if off >= 8 && room >= len + 8 {
        let mut k = 0;
        while k < len {
            // SAFETY: as above with 8-byte chunks and off >= 8.
            unsafe { std::ptr::copy_nonoverlapping(p.add(op - off + k), p.add(op + k), 8) };
            k += 8;
        }
        return Ok(op + len);
    }
    let src = op - off;
    if off >= len {
        out.copy_within(src..src + len, op);
    } else {
        // Overlapping: the pattern of period `off` is replicated with doubling copies. Each
        // copy_within is non-overlapping because the copied amount stays a multiple of `off`
        // (except the last chunk) and the chunk never exceeds `copied + off`.
        let mut copied = 0usize;
        while copied < len {
            let chunk = (len - copied).min(copied + off);
            out.copy_within(src..src + chunk, op + copied);
            copied += chunk;
        }
    }
    Ok(op + len)
}

/// Decompress a raw snappy block into a new vector.
pub fn decompress(src: &[u8]) -> Result<Vec<u8>, SnappyError> {
    let (ulen, _) = uncompressed_len(src)?;
    let mut out = vec![0u8; ulen];
    decompress_into(src, &mut out)?;
    Ok(out)
}

/// Decompress a snappy framing-format stream (`sNaPpY` stream identifier, compressed and
/// uncompressed chunks, padding/skippable chunks). CRCs are verified.
pub fn decompress_framed(src: &[u8]) -> Result<Vec<u8>, SnappyError> {
    let mut out = Vec::new();
    let mut ip = 0usize;
    let mut seen_ident = false;
    while ip < src.len() {
        if src.len() - ip < 4 {
            return Err(SnappyError::Truncated);
        }
        let ty = src[ip];
        let len = u32::from_le_bytes([src[ip + 1], src[ip + 2], src[ip + 3], 0]) as usize;
        ip += 4;
        if src.len() - ip < len {
            return Err(SnappyError::Truncated);
        }
        let body = &src[ip..ip + len];
        ip += len;
        match ty {
            0xff => {
                if body != b"sNaPpY" {
                    return Err(SnappyError::BadFrame);
                }
                seen_ident = true;
            }
            0x00 | 0x01 => {
                if !seen_ident || body.len() < 4 {
                    return Err(SnappyError::BadFrame);
                }
                let want = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                let start = out.len();
                if ty == 0x00 {
                    let (ulen, _) = uncompressed_len(&body[4..])?;
                    if ulen > MAX_FRAME_UNCOMPRESSED {
                        return Err(SnappyError::BadFrame);
                    }
                    out.resize(start + ulen, 0);
                    decompress_into(&body[4..], &mut out[start..])?;
                } else {
                    if body.len() - 4 > MAX_FRAME_UNCOMPRESSED {
                        return Err(SnappyError::BadFrame);
                    }
                    out.extend_from_slice(&body[4..]);
                }
                if masked_crc32c(&out[start..]) != want {
                    return Err(SnappyError::BadChecksum);
                }
            }
            0x02..=0x7f => return Err(SnappyError::BadFrame),
            _ => {} // padding (0xfe) and reserved skippable chunks
        }
    }
    Ok(out)
}

/// The framing format's masked CRC-32C.
#[inline]
pub fn masked_crc32c(data: &[u8]) -> u32 {
    let c = crc32c(data);
    (c.rotate_right(15)).wrapping_add(0xa282_ead8)
}

/// CRC-32C (Castagnoli), hardware accelerated when SSE4.2 is available.
pub fn crc32c(data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("sse4.2") {
            // SAFETY: feature checked at runtime.
            return unsafe { crc32c_sse42(data) };
        }
    }
    crc32c_sw(data)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn crc32c_sse42(data: &[u8]) -> u32 {
    use std::arch::x86_64::{_mm_crc32_u64, _mm_crc32_u8};
    let mut c: u64 = 0xffff_ffff;
    let mut chunks = data.chunks_exact(8);
    for ch in &mut chunks {
        let v = u64::from_le_bytes([ch[0], ch[1], ch[2], ch[3], ch[4], ch[5], ch[6], ch[7]]);
        c = _mm_crc32_u64(c, v);
    }
    let mut c32 = c as u32;
    for &b in chunks.remainder() {
        c32 = _mm_crc32_u8(c32, b);
    }
    !c32
}

fn crc32c_table() -> &'static [[u32; 256]; 8] {
    static TABLE: std::sync::OnceLock<Box<[[u32; 256]; 8]>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = Box::new([[0u32; 256]; 8]);
        for i in 0..256u32 {
            let mut c = i;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ 0x82f6_3b78 } else { c >> 1 };
            }
            t[0][i as usize] = c;
        }
        for i in 0..256 {
            for k in 1..8 {
                let prev = t[k - 1][i];
                t[k][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            }
        }
        t
    })
}

fn crc32c_sw(data: &[u8]) -> u32 {
    let t = crc32c_table();
    let mut c: u32 = 0xffff_ffff;
    let mut chunks = data.chunks_exact(8);
    for ch in &mut chunks {
        let lo = c ^ u32::from_le_bytes([ch[0], ch[1], ch[2], ch[3]]);
        let hi = u32::from_le_bytes([ch[4], ch[5], ch[6], ch[7]]);
        c = t[7][(lo & 0xff) as usize]
            ^ t[6][((lo >> 8) & 0xff) as usize]
            ^ t[5][((lo >> 16) & 0xff) as usize]
            ^ t[4][(lo >> 24) as usize]
            ^ t[3][(hi & 0xff) as usize]
            ^ t[2][((hi >> 8) & 0xff) as usize]
            ^ t[1][((hi >> 16) & 0xff) as usize]
            ^ t[0][(hi >> 24) as usize];
    }
    for &b in chunks.remainder() {
        c = (c >> 8) ^ t[0][((c ^ b as u32) & 0xff) as usize];
    }
    !c
}

/// A simple (greedy, hash based) raw snappy compressor. Only used to build test data.
#[cfg(test)]
pub(crate) fn compress(input: &[u8]) -> Vec<u8> {
    fn emit_literal(out: &mut Vec<u8>, lit: &[u8]) {
        let mut rest = lit;
        while !rest.is_empty() {
            let n = rest.len().min(1 << 16);
            let v = n - 1;
            if v < 60 {
                out.push((v as u8) << 2);
            } else if v < 256 {
                out.push(60 << 2);
                out.push(v as u8);
            } else {
                out.push(61 << 2);
                out.extend_from_slice(&(v as u16).to_le_bytes());
            }
            out.extend_from_slice(&rest[..n]);
            rest = &rest[n..];
        }
    }
    fn emit_copy(out: &mut Vec<u8>, off: usize, mut len: usize) {
        while len > 0 {
            let n = if len > 64 { if len - 64 < 4 { 60 } else { 64 } } else { len };
            if (4..12).contains(&n) && off < 2048 {
                out.push(1 | (((n - 4) as u8) << 2) | (((off >> 8) as u8) << 5));
                out.push(off as u8);
            } else if off < 65536 {
                out.push(2 | (((n - 1) as u8) << 2));
                out.extend_from_slice(&(off as u16).to_le_bytes());
            } else {
                out.push(3 | (((n - 1) as u8) << 2));
                out.extend_from_slice(&(off as u32).to_le_bytes());
            }
            len -= n;
        }
    }
    let mut out = Vec::with_capacity(input.len() + input.len() / 6 + 8);
    let mut v = input.len() as u64;
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
    const HBITS: u32 = 14;
    let mut table = vec![usize::MAX; 1 << HBITS];
    let mut lit_start = 0usize;
    let mut i = 0usize;
    while i + 4 <= input.len() {
        let key = u32::from_le_bytes([input[i], input[i + 1], input[i + 2], input[i + 3]]);
        let h = (key.wrapping_mul(0x1e35_a7bd) >> (32 - HBITS)) as usize;
        let cand = table[h];
        table[h] = i;
        if cand != usize::MAX && i - cand <= u32::MAX as usize && input[cand..cand + 4] == input[i..i + 4] {
            let mut len = 4;
            while i + len < input.len() && input[cand + len] == input[i + len] {
                len += 1;
            }
            emit_literal(&mut out, &input[lit_start..i]);
            emit_copy(&mut out, i - cand, len);
            i += len;
            lit_start = i;
        } else {
            i += 1;
        }
    }
    emit_literal(&mut out, &input[lit_start..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_vectors() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c_sw(b"123456789"), 0xe306_9283);
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        assert_eq!(crc32c(&data), crc32c_sw(&data));
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn literal_and_copies() {
        // "abcd" literal + copy-1 (len 8, off 4) -> "abcdabcdabcd"
        let enc = [12u8, 3 << 2, b'a', b'b', b'c', b'd', 1 | (4 << 2), 4];
        assert_eq!(decompress(&enc).unwrap(), b"abcdabcdabcd");
        // copy-2 and copy-4 elements
        let enc = [10u8, 1 << 2, b'x', b'y', 2 | (7 << 2), 2, 0];
        assert_eq!(decompress(&enc).unwrap(), b"xyxyxyxyxy");
        let enc = [5u8, 0, b'z', 3 | (3 << 2), 1, 0, 0, 0];
        assert_eq!(decompress(&enc).unwrap(), b"zzzzz");
    }

    #[test]
    fn malformed_never_panics() {
        assert_eq!(decompress(&[]), Err(SnappyError::BadHeader));
        assert_eq!(decompress(&[0x80, 0x80, 0x80, 0x80, 0x80]), Err(SnappyError::BadHeader));
        assert_eq!(decompress(&[4, 1 | (0 << 2), 1]), Err(SnappyError::BadOffset));
        assert_eq!(decompress(&[4, 0, b'a']), Err(SnappyError::BadLength));
        assert_eq!(decompress(&[1, 0]), Err(SnappyError::Truncated));
        assert_eq!(decompress(&[1, 63 << 2, 0xff, 0xff]), Err(SnappyError::Truncated));
        // pseudo random garbage
        let mut x: u64 = 0x1234_5678_9abc_def0;
        for _ in 0..20000 {
            let mut buf = [0u8; 40];
            for b in buf.iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = x as u8;
            }
            buf[0] &= 0x7f;
            let _ = decompress(&buf);
            let _ = decompress_framed(&buf);
        }
    }

    #[test]
    fn roundtrip_compressor() {
        let mut data = Vec::new();
        for i in 0..200_000u32 {
            data.push(match i % 1000 {
                0..=399 => 0,
                400..=699 => (i % 7) as u8,
                _ => (i.wrapping_mul(2_654_435_761) >> 13) as u8,
            });
        }
        let c = compress(&data);
        assert!(c.len() < data.len());
        assert_eq!(decompress(&c).unwrap(), data);
    }

    #[test]
    fn framed() {
        let data: Vec<u8> = (0..150_000u32).map(|i| (i / 300) as u8).collect();
        let mut s = vec![0xff, 6, 0, 0];
        s.extend_from_slice(b"sNaPpY");
        for (k, chunk) in data.chunks(65536).enumerate() {
            let crc = masked_crc32c(chunk).to_le_bytes();
            if k % 2 == 0 {
                let c = compress(chunk);
                let l = (c.len() + 4) as u32;
                s.extend_from_slice(&[0, l as u8, (l >> 8) as u8, (l >> 16) as u8]);
                s.extend_from_slice(&crc);
                s.extend_from_slice(&c);
            } else {
                let l = (chunk.len() + 4) as u32;
                s.extend_from_slice(&[1, l as u8, (l >> 8) as u8, (l >> 16) as u8]);
                s.extend_from_slice(&crc);
                s.extend_from_slice(chunk);
            }
            s.extend_from_slice(&[0xfe, 2, 0, 0, 0, 0]); // padding
        }
        assert_eq!(decompress_framed(&s).unwrap(), data);
        let mut bad = s.clone();
        bad[14] ^= 1; // first chunk's CRC
        assert_eq!(decompress_framed(&bad), Err(SnappyError::BadChecksum));
        let mut bad = s.clone();
        bad[4] = b'X'; // stream identifier
        assert_eq!(decompress_framed(&bad), Err(SnappyError::BadFrame));
    }

    #[test]
    fn libsnappy_vectors() {
        use crate::codecs::testdata::{fixture, gen_data};
        for (name, seed, n) in [("small", 5, 1000), ("block64k", 6, 65536), ("large", 7, 300000)] {
            let c = fixture(&format!("snappy_{name}.bin"));
            assert_eq!(decompress(&c).unwrap(), gen_data(seed, n), "{name}");
            // truncated input must fail cleanly
            assert!(decompress(&c[..c.len() - 1]).is_err());
        }
    }

    #[test]
    fn resumable_prefix_decoding() {
        use crate::codecs::testdata::{fixture, gen_data};
        let c = fixture("snappy_block64k.bin");
        let want = gen_data(6, 65536);
        let mut out = vec![0u8; 65536];
        let mut st = Partial::start(&c).unwrap();
        for need in [1usize, 100, 5000, 5001, 40000, 65536] {
            decompress_continue(&c, &mut out, &mut st, need).unwrap();
            assert!(st.op >= need);
            assert_eq!(&out[..need], &want[..need]);
        }
        assert!(st.is_complete());
        // a truncated stream fails once the decoder reaches the end
        let mut st = Partial::start(&c[..c.len() / 2]).unwrap();
        assert!(decompress_continue(&c[..c.len() / 2], &mut out, &mut st, 10).is_ok());
        assert!(decompress_continue(&c[..c.len() / 2], &mut out, &mut st, 65536).is_err());
    }
}
