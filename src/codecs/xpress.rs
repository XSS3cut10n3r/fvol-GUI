//! Microsoft Xpress decompression ([MS-XCA]): "Plain LZ77" (COMPRESSION_FORMAT_XPRESS) and
//! "LZ77+Huffman" (COMPRESSION_FORMAT_XPRESS_HUFF), as used by Windows hibernation files,
//! the memory-manager store, prefetch (MAM) files, WIM/WOF, ...
//!
//! Part of rsvol, a port of Volatility 3 (Volatility Software License 1.0).
//!
//! Both decoders write into a caller-provided buffer whose length is the expected
//! decompressed size (Windows always knows it). They stop when the buffer is full or the
//! input ends and return the number of bytes produced. Malformed input returns an error; no
//! input can make them panic or loop forever (every iteration produces output or consumes
//! input).

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XpressError {
    /// Input ended in the middle of an element.
    Truncated,
    /// A match refers to data before the start of the output.
    BadOffset,
    /// Invalid extended match length.
    BadLength,
    /// LZ77+Huffman: the code-length table does not describe a complete prefix code.
    BadTable,
}

impl fmt::Display for XpressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            XpressError::Truncated => "xpress: truncated input",
            XpressError::BadOffset => "xpress: bad match offset",
            XpressError::BadLength => "xpress: bad match length",
            XpressError::BadTable => "xpress: bad huffman table",
        };
        f.write_str(s)
    }
}

impl std::error::Error for XpressError {}

impl From<XpressError> for crate::error::Error {
    fn from(e: XpressError) -> Self {
        crate::error::Error::Msg(e.to_string())
    }
}

/// Copy `len` bytes from `op - off` to `op` with LZ77 (byte-by-byte forward) semantics,
/// truncated at the end of `out`. Returns the new output position.
#[inline(always)]
fn copy_match(out: &mut [u8], op: usize, off: usize, len: usize) -> Result<usize, XpressError> {
    if off == 0 || off > op {
        return Err(XpressError::BadOffset);
    }
    let len = len.min(out.len() - op);
    let src = op - off;
    if off >= len {
        out.copy_within(src..src + len, op);
    } else {
        // periodic pattern: doubling non-overlapping copies (see snappy.rs)
        let mut copied = 0usize;
        while copied < len {
            let chunk = (len - copied).min(copied + off);
            out.copy_within(src..src + chunk, op + copied);
            copied += chunk;
        }
    }
    Ok(op + len)
}

// ---------------------------------------------------------------------------------------------
// Plain LZ77 ([MS-XCA] 2.4)
// ---------------------------------------------------------------------------------------------

/// Decompress Xpress "Plain LZ77" data into `out`; returns the number of bytes produced.
pub fn lz77_decompress_into(input: &[u8], out: &mut [u8]) -> Result<usize, XpressError> {
    let n = input.len();
    let mut ip = 0usize;
    let mut op = 0usize;
    let mut flags: u32 = 0;
    let mut flag_count: u32 = 0;
    // input position of the shared length nibble byte (0 = none; position 0 always holds flags)
    let mut last_half = 0usize;
    while op < out.len() {
        if flag_count == 0 {
            if n - ip < 4 {
                // no more flags: end of stream
                return Ok(op);
            }
            flags = u32::from_le_bytes([input[ip], input[ip + 1], input[ip + 2], input[ip + 3]]);
            ip += 4;
            flag_count = 32;
        }
        flag_count -= 1;
        if flags & (1u32 << flag_count) == 0 {
            if ip >= n {
                return Ok(op);
            }
            out[op] = input[ip];
            op += 1;
            ip += 1;
        } else {
            if ip == n {
                // regular end of stream
                return Ok(op);
            }
            if n - ip < 2 {
                return Err(XpressError::Truncated);
            }
            let mb = u16::from_le_bytes([input[ip], input[ip + 1]]) as usize;
            ip += 2;
            let mut len = mb & 7;
            let off = (mb >> 3) + 1;
            if len == 7 {
                if last_half == 0 {
                    if ip >= n {
                        return Err(XpressError::Truncated);
                    }
                    len = (input[ip] & 0xf) as usize;
                    last_half = ip;
                    ip += 1;
                } else {
                    len = (input[last_half] >> 4) as usize;
                    last_half = 0;
                }
                if len == 15 {
                    if ip >= n {
                        return Err(XpressError::Truncated);
                    }
                    len = input[ip] as usize;
                    ip += 1;
                    if len == 255 {
                        if n - ip < 2 {
                            return Err(XpressError::Truncated);
                        }
                        len = u16::from_le_bytes([input[ip], input[ip + 1]]) as usize;
                        ip += 2;
                        if len == 0 {
                            if n - ip < 4 {
                                return Err(XpressError::Truncated);
                            }
                            len = u32::from_le_bytes([input[ip], input[ip + 1], input[ip + 2], input[ip + 3]]) as usize;
                            ip += 4;
                        }
                        if len < 15 + 7 {
                            return Err(XpressError::BadLength);
                        }
                        len -= 15 + 7;
                    }
                    len += 15;
                }
                len += 7;
            }
            len += 3;
            op = copy_match(out, op, off, len)?;
        }
    }
    Ok(op)
}

/// Decompress Plain LZ77 data expected to expand to `out_len` bytes (the result is shorter if
/// the stream ends early).
pub fn lz77_decompress(input: &[u8], out_len: usize) -> Result<Vec<u8>, XpressError> {
    let mut out = vec![0u8; out_len];
    let n = lz77_decompress_into(input, &mut out)?;
    out.truncate(n);
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// LZ77+Huffman ([MS-XCA] 2.2)
// ---------------------------------------------------------------------------------------------

const HUFF_SYMBOLS: usize = 512;
const HUFF_BITS: u32 = 15;
const HUFF_BLOCK: usize = 65536;

/// Build the 2^15-entry direct decoding table from the 256-byte code length table.
fn build_table(lengths: &[u8; HUFF_SYMBOLS], table: &mut [u16]) -> Result<(), XpressError> {
    let mut pos = 0usize;
    for bl in 1..=HUFF_BITS as u8 {
        let entries = 1usize << (HUFF_BITS - bl as u32);
        for (sym, &l) in lengths.iter().enumerate() {
            if l == bl {
                if pos + entries > table.len() {
                    return Err(XpressError::BadTable);
                }
                table[pos..pos + entries].fill(sym as u16);
                pos += entries;
            }
        }
    }
    if pos != table.len() {
        return Err(XpressError::BadTable);
    }
    Ok(())
}

/// Decompress Xpress "LZ77+Huffman" data into `out`; returns the number of bytes produced
/// (always `out.len()` on success: the format has no in-band end of stream before that).
pub fn huffman_decompress_into(input: &[u8], out: &mut [u8]) -> Result<usize, XpressError> {
    let n = input.len();
    // Reads past the end of input yield zero bits: the bit reader prefetches up to 4 bytes
    // beyond the last used symbol.
    let rd16 = |p: usize| -> u32 {
        if p + 1 < n {
            u16::from_le_bytes([input[p], input[p + 1]]) as u32
        } else if p < n {
            input[p] as u32
        } else {
            0
        }
    };
    let mut table = vec![0u16; 1 << HUFF_BITS];
    let mut lengths = [0u8; HUFF_SYMBOLS];
    let mut ip = 0usize;
    let mut op = 0usize;
    while op < out.len() {
        if n.saturating_sub(ip) < 256 {
            return Err(XpressError::Truncated);
        }
        for (i, &b) in input[ip..ip + 256].iter().enumerate() {
            lengths[2 * i] = b & 0xf;
            lengths[2 * i + 1] = b >> 4;
        }
        build_table(&lengths, &mut table)?;
        ip += 256;
        let mut bits: u32 = (rd16(ip) << 16) | rd16(ip + 2);
        ip += 4;
        let mut extra: i32 = 16;
        let block_end = op.saturating_add(HUFF_BLOCK).min(out.len());
        while op < block_end {
            let sym = table[(bits >> (32 - HUFF_BITS)) as usize] as usize;
            let bl = lengths[sym] as u32;
            bits <<= bl;
            extra -= bl as i32;
            if extra < 0 {
                bits |= rd16(ip) << (-extra) as u32;
                extra += 16;
                ip += 2;
            }
            if sym < 256 {
                out[op] = sym as u8;
                op += 1;
                continue;
            }
            // match (symbol 256 is only an end marker once all output is produced, which the
            // loop condition already handles)
            let s = sym - 256;
            let mut len = s & 15;
            let obits = (s >> 4) as u32;
            if len == 15 {
                if ip >= n {
                    return Err(XpressError::Truncated);
                }
                len = input[ip] as usize;
                ip += 1;
                if len == 255 {
                    if n - ip < 2 {
                        return Err(XpressError::Truncated);
                    }
                    len = u16::from_le_bytes([input[ip], input[ip + 1]]) as usize;
                    ip += 2;
                    if len == 0 {
                        if n - ip < 4 {
                            return Err(XpressError::Truncated);
                        }
                        len = u32::from_le_bytes([input[ip], input[ip + 1], input[ip + 2], input[ip + 3]]) as usize;
                        ip += 4;
                    }
                    if len < 15 {
                        return Err(XpressError::BadLength);
                    }
                    len -= 15;
                }
                len += 15;
            }
            len += 3;
            let off = if obits == 0 { 1 } else { ((bits >> (32 - obits)) as usize) + (1usize << obits) };
            bits = if obits == 0 { bits } else { bits << obits };
            extra -= obits as i32;
            if extra < 0 {
                bits |= rd16(ip) << (-extra) as u32;
                extra += 16;
                ip += 2;
            }
            op = copy_match(out, op, off, len)?;
        }
    }
    Ok(op)
}

/// Decompress LZ77+Huffman data that expands to `out_len` bytes.
pub fn huffman_decompress(input: &[u8], out_len: usize) -> Result<Vec<u8>, XpressError> {
    let mut out = vec![0u8; out_len];
    let n = huffman_decompress_into(input, &mut out)?;
    out.truncate(n);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|h| u8::from_str_radix(h, 16).unwrap()).collect()
    }

    /// [MS-XCA] 3.1 examples.
    #[test]
    fn lz77_spec_examples() {
        let enc = hex("3f 00 00 00 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a");
        assert_eq!(lz77_decompress(&enc, 26).unwrap(), b"abcdefghijklmnopqrstuvwxyz");
        let enc = hex("ff ff ff 1f 61 62 63 17 00 0f ff 26 01");
        assert_eq!(lz77_decompress(&enc, 300).unwrap(), b"abc".repeat(100));
        // larger output buffer than the data: stops at end of stream
        assert_eq!(lz77_decompress(&enc, 1000).unwrap(), b"abc".repeat(100));
    }

    #[test]
    fn malformed_never_panics() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..3000 {
            let len = (next() % 700) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if round % 3 == 0 && buf.len() >= 256 {
                // plausible huffman table: every symbol length 9 = complete code
                for b in buf[..256].iter_mut() {
                    *b = 0x99;
                }
            }
            let _ = lz77_decompress(&buf, 5000);
            let _ = huffman_decompress(&buf, 70000);
        }
        assert_eq!(huffman_decompress(&[0u8; 300], 10), Err(XpressError::BadTable));
        assert_eq!(huffman_decompress(&[0x99u8; 10], 10), Err(XpressError::Truncated));
        // first element is a match: offset before start of output
        assert_eq!(lz77_decompress(&hex("00 00 00 80 00 00"), 10), Err(XpressError::BadOffset));
    }

    #[test]
    fn huffman_all_literals_fixed_code() {
        // Every symbol has length 9: symbol s has code s (canonical order). Encode literals
        // "hello" followed by zero padding.
        let mut enc = vec![0x99u8; 256];
        let msg = b"hello, world";
        let mut bitbuf: Vec<bool> = Vec::new();
        for &c in msg {
            for k in (0..9).rev() {
                bitbuf.push((c as u32 >> k) & 1 == 1);
            }
        }
        while bitbuf.len() % 16 != 0 {
            bitbuf.push(false);
        }
        for w in bitbuf.chunks(16) {
            let mut v = 0u16;
            for &b in w {
                v = (v << 1) | b as u16;
            }
            enc.extend_from_slice(&v.to_le_bytes());
        }
        enc.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(huffman_decompress(&enc, msg.len()).unwrap(), msg);
    }
}

#[cfg(test)]
mod fixture_tests {
    //! Vectors in tests/fixtures/codecs: `gen_xpress.py` (independent python reference
    //! encoders) and a real Windows 10 prefetch file page (MAM\x04 = Xpress Huffman) carved
    //! from the test memory image.
    use super::*;

    use crate::codecs::testdata::{fixture, gen_data};

    fn vector(name: &str) -> Vec<u8> {
        match name {
            "small" => gen_data(1, 3000),
            "medium" => gen_data(2, 40000),
            "multiblock" => gen_data(3, 200000),
            "zeros_runs" => {
                let d = gen_data(4, 70000);
                let mut v = vec![0u8; 30000];
                v.extend_from_slice(&d[..10000]);
                v.resize(v.len() + 30000, 0);
                v
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn reference_encoder_vectors() {
        for name in ["small", "medium", "multiblock", "zeros_runs"] {
            let want = vector(name);
            let c = fixture(&format!("xpress_lz77_{name}.bin"));
            assert_eq!(lz77_decompress(&c, want.len()).unwrap(), want, "lz77 {name}");
            let c = fixture(&format!("xpress_huff_{name}.bin"));
            assert_eq!(huffman_decompress(&c, want.len()).unwrap(), want, "huffman {name}");
        }
    }

    #[test]
    fn real_windows_prefetch_page() {
        // First physical page of a compressed prefetch file: "MAM\x04" + u32 size + data.
        let data = fixture("mam_svchost_13980.bin");
        let mut out = vec![0u8; 0x2400];
        huffman_decompress_into(&data, &mut out).unwrap();
        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), 30); // version
        assert_eq!(&out[4..8], b"SCCA");
        assert_eq!(u32::from_le_bytes(out[12..16].try_into().unwrap()), 13980); // file size
        let utf16 = |b: &[u8]| -> String { b.chunks(2).map(|c| c[0] as char).take_while(|&c| c != '\0').collect() };
        assert_eq!(utf16(&out[0x10..0x4c]), "SVCHOST.EXE");
        let strings = u32::from_le_bytes(out[0x64..0x68].try_into().unwrap()) as usize;
        assert_eq!(strings, 0x22d8);
        assert_eq!(
            utf16(&out[strings..strings + 200]),
            "\\VOLUME{01dd38fe2004ea92-f6200eb0}\\WINDOWS\\SYSTEM32\\MAPSBTSVC.DLL"
        );
    }
}
