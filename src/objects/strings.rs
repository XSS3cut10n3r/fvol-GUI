//! Byte-string decoding with python `bytes.decode(encoding, errors)` semantics for the codecs
//! volatility3 uses: utf-8, utf-16 (BOM sniffing, default little endian), utf-16-le/be,
//! latin-1, ascii; errors = strict / replace / ignore / backslashreplace.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::error::{Error, Result};
use crate::symbols::table::{StrEnc, StrErrors};

/// Parse a python encoding name.
pub fn parse_encoding(name: &str) -> StrEnc {
    match name.to_ascii_lowercase().replace('_', "-").as_str() {
        "utf-16" | "utf16" => StrEnc::Utf16,
        "utf-16-le" | "utf-16le" | "utf16le" | "utf16-le" => StrEnc::Utf16Le,
        "utf-16-be" | "utf-16be" | "utf16be" | "utf16-be" => StrEnc::Utf16Be,
        "latin-1" | "latin1" | "iso-8859-1" | "iso8859-1" | "l1" => StrEnc::Latin1,
        "ascii" | "us-ascii" => StrEnc::Ascii,
        _ => StrEnc::Utf8,
    }
}

/// Parse a python `errors=` value.
pub fn parse_errors(name: &str) -> StrErrors {
    match name {
        "replace" => StrErrors::Replace,
        "ignore" => StrErrors::Ignore,
        "backslashreplace" => StrErrors::BackslashReplace,
        _ => StrErrors::Strict,
    }
}

fn handle_err(out: &mut String, bad: &[u8], errors: StrErrors, what: &str) -> Result<()> {
    match errors {
        StrErrors::Strict => Err(Error::msg(format!("UnicodeDecodeError: {what}"))),
        StrErrors::Replace => {
            out.push('\u{FFFD}');
            Ok(())
        }
        StrErrors::Ignore => Ok(()),
        StrErrors::BackslashReplace => {
            for b in bad {
                out.push_str(&format!("\\x{b:02x}"));
            }
            Ok(())
        }
    }
}

/// python `data.decode("utf-8", errors)`.
pub fn decode_utf8(data: &[u8], errors: StrErrors) -> Result<String> {
    match std::str::from_utf8(data) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => {
            let mut out = String::with_capacity(data.len());
            let mut rest = data;
            loop {
                match std::str::from_utf8(rest) {
                    Ok(s) => {
                        out.push_str(s);
                        return Ok(out);
                    }
                    Err(e) => {
                        let good = e.valid_up_to();
                        out.push_str(unsafe { std::str::from_utf8_unchecked(&rest[..good]) });
                        // maximal invalid subpart (same rule as CPython)
                        let bad_len = e.error_len().unwrap_or(rest.len() - good);
                        handle_err(&mut out, &rest[good..good + bad_len], errors, "invalid utf-8")?;
                        rest = &rest[good + bad_len..];
                    }
                }
            }
        }
    }
}

/// python `data.decode("utf-16-le"/"utf-16-be", errors)`.
pub fn decode_utf16(data: &[u8], big_endian: bool, errors: StrErrors) -> Result<String> {
    let mut out = String::with_capacity(data.len() / 2);
    let n = data.len() / 2;
    let unit = |i: usize| -> u16 {
        let (a, b) = (data[2 * i], data[2 * i + 1]);
        if big_endian { u16::from_be_bytes([a, b]) } else { u16::from_le_bytes([a, b]) }
    };
    let mut i = 0;
    // ASCII run (most names): the low bytes straight into the string
    {
        let (lo, hi) = if big_endian { (1, 0) } else { (0, 1) };
        // SAFETY: only bytes < 0x80 are pushed, so the string stays valid UTF-8
        let v = unsafe { out.as_mut_vec() };
        while i < n && data[2 * i + hi] == 0 && data[2 * i + lo] < 0x80 {
            v.push(data[2 * i + lo]);
            i += 1;
        }
    }
    while i < n {
        let u = unit(i);
        if !(0xD800..0xE000).contains(&u) {
            out.push(char::from_u32(u as u32).unwrap_or('\u{FFFD}'));
            i += 1;
        } else if u < 0xDC00 {
            // high surrogate
            if i + 1 < n {
                let lo = unit(i + 1);
                if (0xDC00..0xE000).contains(&lo) {
                    let c = 0x10000 + (((u as u32) - 0xD800) << 10) + ((lo as u32) - 0xDC00);
                    out.push(char::from_u32(c).unwrap_or('\u{FFFD}'));
                    i += 2;
                    continue;
                }
                handle_err(&mut out, &data[2 * i..2 * i + 2], errors, "illegal UTF-16 surrogate")?;
                i += 1;
            } else {
                // high surrogate at the end: python reports "unexpected end of data" covering
                // the rest of the input (including an odd trailing byte)
                handle_err(&mut out, &data[2 * i..], errors, "unexpected end of data")?;
                return Ok(out);
            }
        } else {
            handle_err(&mut out, &data[2 * i..2 * i + 2], errors, "illegal encoding")?;
            i += 1;
        }
    }
    if data.len() % 2 == 1 {
        handle_err(&mut out, &data[data.len() - 1..], errors, "truncated data")?;
    }
    Ok(out)
}

/// python `data.decode(encoding, errors)`.
pub fn decode(data: &[u8], enc: StrEnc, errors: StrErrors) -> Result<String> {
    match enc {
        StrEnc::Utf8 => decode_utf8(data, errors),
        StrEnc::Utf16Le => decode_utf16(data, false, errors),
        StrEnc::Utf16Be => decode_utf16(data, true, errors),
        StrEnc::Utf16 => {
            // BOM sniffing; default little endian (python on little-endian hosts)
            if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFE {
                decode_utf16(&data[2..], false, errors)
            } else if data.len() >= 2 && data[0] == 0xFE && data[1] == 0xFF {
                decode_utf16(&data[2..], true, errors)
            } else {
                decode_utf16(data, false, errors)
            }
        }
        StrEnc::Latin1 => Ok(data.iter().map(|&b| b as char).collect()),
        StrEnc::Ascii => {
            let mut out = String::with_capacity(data.len());
            for (i, &b) in data.iter().enumerate() {
                if b < 0x80 {
                    out.push(b as char);
                } else {
                    handle_err(&mut out, &data[i..i + 1], errors, "ordinal not in range(128)")?;
                }
            }
            Ok(out)
        }
    }
}

/// Index of the first NUL code unit of `data` in the encoding (a zero byte for the 8-bit
/// encodings, a zero u16 at an even offset for UTF-16), or `data.len()`.
fn first_nul_unit(data: &[u8], enc: StrEnc) -> usize {
    match enc {
        StrEnc::Utf16 | StrEnc::Utf16Le | StrEnc::Utf16Be => data.chunks_exact(2).position(|u| u[0] == 0 && u[1] == 0).map_or(data.len(), |i| 2 * i),
        _ => data.iter().position(|&b| b == 0).unwrap_or(data.len()),
    }
}

/// python `objects.String` value: decode then cut at the first NUL character.
pub fn decode_cstring(data: &[u8], enc: StrEnc, errors: StrErrors) -> Result<String> {
    // Only the text before the first NUL survives. With a non-strict error handler nothing at
    // or after the first NUL code unit can change that text: a NUL unit always decodes to
    // U+0000 on its own (it is never part of a multi-byte UTF-8 sequence or a surrogate pair),
    // and an error just before it covers the same bytes whether the NUL follows or the data
    // ends there (UTF-8: the maximal invalid subpart; UTF-16: the lone surrogate unit). So
    // decode only up to it: a `max_length=512` UTF-16 cast of a 10-character name decodes 10
    // units, not 256. Strict decoding must see every byte (python raises for an error after
    // the NUL). UTF-16 with a BOM: the BOM is sniffed first, then the rest is cut.
    if errors != StrErrors::Strict {
        let (body, enc2) = match enc {
            StrEnc::Utf16 if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFE => (&data[2..], StrEnc::Utf16Le),
            StrEnc::Utf16 if data.len() >= 2 && data[0] == 0xFE && data[1] == 0xFF => (&data[2..], StrEnc::Utf16Be),
            StrEnc::Utf16 => (data, StrEnc::Utf16Le),
            e => (data, e),
        };
        return decode(&body[..first_nul_unit(body, enc2)], enc2, errors);
    }
    let mut s = decode(data, enc, errors)?;
    if let Some(i) = s.find('\0') {
        s.truncate(i);
    }
    Ok(s)
}

/// python `str.encode(encoding)` for the encodings above (strict: unencodable -> error).
pub fn encode(s: &str, enc: StrEnc) -> Result<Vec<u8>> {
    Ok(match enc {
        StrEnc::Utf8 => s.as_bytes().to_vec(),
        StrEnc::Utf16Le => s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect(),
        StrEnc::Utf16Be => s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect(),
        StrEnc::Utf16 => {
            let mut v = vec![0xFF, 0xFE];
            v.extend(s.encode_utf16().flat_map(|u| u.to_le_bytes()));
            v
        }
        StrEnc::Latin1 => {
            let mut v = Vec::with_capacity(s.len());
            for c in s.chars() {
                if (c as u32) < 256 {
                    v.push(c as u32 as u8);
                } else {
                    return Err(Error::msg("UnicodeEncodeError"));
                }
            }
            v
        }
        StrEnc::Ascii => {
            if !s.is_ascii() {
                return Err(Error::msg("UnicodeEncodeError"));
            }
            s.as_bytes().to_vec()
        }
    })
}

/// python `utility.bytes_to_decoded_string(data, encoding, errors)`: decode with replace, cut
/// at the first U+FFFD or NUL, re-encode, decode again with `errors`.
pub fn bytes_to_decoded_string(data: &[u8], enc: StrEnc, errors: StrErrors) -> Result<String> {
    let full = decode(data, enc, StrErrors::Replace)?;
    let idx = full.find(['\u{FFFD}', '\0']).unwrap_or(full.len());
    let prefix = &full[..idx];
    let bytes = encode(prefix, enc)?;
    decode(&bytes, enc, errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utf16() {
        let d = [b'a', 0, 0x3d, 0xd8, 0x00, 0xde, b'b', 0, 0x00, 0xd8, b'c', 0, b'x'];
        let s = decode(&d, StrEnc::Utf16Le, StrErrors::Replace).unwrap();
        assert_eq!(s, "a\u{1F600}b\u{FFFD}c\u{FFFD}");
        assert!(decode(&d, StrEnc::Utf16Le, StrErrors::Strict).is_err());
        let bom = [0xFF, 0xFE, b'h', 0, b'i', 0];
        assert_eq!(decode(&bom, StrEnc::Utf16, StrErrors::Strict).unwrap(), "hi");
        let be = [0, b'h', 0, b'i', 0xd8, 0x3d, 0xde, 0x00];
        assert_eq!(decode(&be, StrEnc::Utf16Be, StrErrors::Strict).unwrap(), "hi\u{1F600}");
    }

    /// Cutting at the first NUL unit before decoding gives what decode-then-cut gives, for
    /// every non-strict handler, encoding and error placement (errors right before, at and
    /// after the NUL, odd lengths, BOMs).
    #[test]
    fn cstring_cut_matches_full_decode() {
        let reference = |data: &[u8], enc: StrEnc, errors: StrErrors| -> String {
            let mut s = decode(data, enc, errors).unwrap();
            if let Some(i) = s.find('\0') {
                s.truncate(i);
            }
            s
        };
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let pool: [u8; 10] = [0, 0, b'a', 0x80, 0xd8, 0xdc, 0xff, 0xfe, 0xe2, 0x82];
        for _ in 0..20000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x % 9) as usize;
            let data: Vec<u8> = (0..len).map(|k| pool[((x >> (8 + 4 * k)) % 10) as usize]).collect();
            for enc in [StrEnc::Utf8, StrEnc::Utf16Le, StrEnc::Utf16Be, StrEnc::Utf16, StrEnc::Latin1, StrEnc::Ascii] {
                for errors in [StrErrors::Replace, StrErrors::Ignore, StrErrors::BackslashReplace] {
                    assert_eq!(decode_cstring(&data, enc, errors).unwrap(), reference(&data, enc, errors), "{data:x?} {enc:?} {errors:?}");
                }
                match (decode(&data, enc, StrErrors::Strict), decode_cstring(&data, enc, StrErrors::Strict)) {
                    (Ok(_), Ok(s)) => assert_eq!(s, reference(&data, enc, StrErrors::Strict)),
                    (Err(_), Err(_)) => {}
                    (a, b) => panic!("strict mismatch {data:x?} {enc:?}: {a:?} {b:?}"),
                }
            }
        }
    }
    #[test]
    fn utf8_replace() {
        assert_eq!(decode_utf8(b"a\xffb\xe2\x82", StrErrors::Replace).unwrap(), "a\u{FFFD}b\u{FFFD}");
        assert_eq!(decode_cstring(b"abc\0def", StrEnc::Utf8, StrErrors::Strict).unwrap(), "abc");
        assert_eq!(bytes_to_decoded_string(b"ab\xffcd", StrEnc::Utf8, StrErrors::Replace).unwrap(), "ab");
    }
}
