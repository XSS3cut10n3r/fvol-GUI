//! Python value formatting helpers (derived from Volatility 3 / CPython semantics; Volatility
//! Software License 1.0). Everything here writes straight into a byte buffer so the renderer hot
//! paths do not allocate.

use super::DateTime;

/// Append the decimal representation of `v` (python `str(int)`).
#[inline]
pub fn push_u64(out: &mut Vec<u8>, mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out.extend_from_slice(&buf[i..]);
}

/// Append the decimal representation of `v` (python `str(int)`).
#[inline]
pub fn push_i128(out: &mut Vec<u8>, v: i128) {
    if v >= 0 && v <= u64::MAX as i128 {
        return push_u64(out, v as u64);
    }
    if v < 0 {
        out.push(b'-');
    }
    let mut u = v.unsigned_abs();
    let mut buf = [0u8; 40];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (u % 10) as u8;
        u /= 10;
        if u == 0 {
            break;
        }
    }
    out.extend_from_slice(&buf[i..]);
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Append python `f"{v:x}"` (lower case, `-` sign for negatives, no prefix).
#[inline]
pub fn push_hex(out: &mut Vec<u8>, v: i128) {
    if v < 0 {
        out.push(b'-');
    }
    let u = v.unsigned_abs();
    let mut buf = [0u8; 32];
    let mut i = buf.len();
    let mut x = u;
    loop {
        i -= 1;
        buf[i] = HEX[(x & 0xf) as usize];
        x >>= 4;
        if x == 0 {
            break;
        }
    }
    out.extend_from_slice(&buf[i..]);
}

/// Append python `f"{v:b}"`.
pub fn push_bin(out: &mut Vec<u8>, v: i128) {
    if v < 0 {
        out.push(b'-');
    }
    let u = v.unsigned_abs();
    if u == 0 {
        out.push(b'0');
        return;
    }
    let bits = 128 - u.leading_zeros();
    for b in (0..bits).rev() {
        out.push(if (u >> b) & 1 == 1 { b'1' } else { b'0' });
    }
}

/// Append a byte as two lower-case hex digits.
#[inline]
pub fn push_hex_byte(out: &mut Vec<u8>, b: u8) {
    out.push(HEX[(b >> 4) as usize]);
    out.push(HEX[(b & 0xf) as usize]);
}

/// python `repr(float)` / `str(float)` (shortest round-trip, exponent form when the decimal
/// exponent is < -4 or >= 16, `.0` appended to integral values).
pub fn push_float(out: &mut Vec<u8>, f: f64) {
    if f.is_nan() {
        out.extend_from_slice(b"nan");
        return;
    }
    if f.is_infinite() {
        out.extend_from_slice(if f > 0.0 { b"inf" } else { b"-inf" });
        return;
    }
    // Rust's `{:e}` gives the shortest round-trip digits: "-1.2345e-7"
    let s = format!("{:e}", f);
    let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let (neg, mant) = match mant.strip_prefix('-') {
        Some(m) => (true, m),
        None => (false, mant),
    };
    let digits: Vec<u8> = mant.bytes().filter(|c| *c != b'.').collect();
    let decpt = exp + 1; // value = 0.d1d2d3... * 10^decpt
    if neg {
        out.push(b'-');
    }
    if decpt <= -4 || decpt > 16 {
        out.push(digits[0]);
        if digits.len() > 1 {
            out.push(b'.');
            out.extend_from_slice(&digits[1..]);
        }
        out.push(b'e');
        let e = decpt - 1;
        out.push(if e < 0 { b'-' } else { b'+' });
        let ea = e.unsigned_abs();
        if ea < 10 {
            out.push(b'0');
        }
        push_u64(out, ea as u64);
    } else if decpt <= 0 {
        out.extend_from_slice(b"0.");
        for _ in 0..(-decpt) {
            out.push(b'0');
        }
        out.extend_from_slice(&digits);
    } else {
        let d = decpt as usize;
        if digits.len() <= d {
            out.extend_from_slice(&digits);
            for _ in digits.len()..d {
                out.push(b'0');
            }
            out.extend_from_slice(b".0");
        } else {
            out.extend_from_slice(&digits[..d]);
            out.push(b'.');
            out.extend_from_slice(&digits[d..]);
        }
    }
}

/// python `repr(bytes)`: `b'...'`.
pub fn push_bytes_repr(out: &mut Vec<u8>, data: &[u8]) {
    let quote = if data.contains(&b'\'') && !data.contains(&b'"') { b'"' } else { b'\'' };
    out.push(b'b');
    out.push(quote);
    for &c in data {
        match c {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\t' => out.extend_from_slice(b"\\t"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            c if c == quote => {
                out.push(b'\\');
                out.push(c);
            }
            0x20..=0x7e => out.push(c),
            _ => {
                out.extend_from_slice(b"\\x");
                push_hex_byte(out, c);
            }
        }
    }
    out.push(quote);
}

/// Approximation of python `str.isprintable()` for a single character.
fn is_printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    !matches!(c as u32,
        0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x180e | 0x200b..=0x200f | 0x202a..=0x202e
        | 0x2060..=0x206f | 0xd800..=0xf8ff | 0xfeff | 0xfff9..=0xfffb | 0xe0001 | 0xe0020..=0xe007f
        | 0xf0000..=0x10ffff)
}

/// python `repr(str)`.
pub fn str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if is_printable(c) => out.push(c),
            c => {
                let v = c as u32;
                if v < 0x100 {
                    out.push_str(&format!("\\x{v:02x}"));
                } else if v < 0x10000 {
                    out.push_str(&format!("\\u{v:04x}"));
                } else {
                    out.push_str(&format!("\\U{v:08x}"));
                }
            }
        }
    }
    out.push(quote);
    out
}

/// Append a JSON string literal the way python's `json.dumps(ensure_ascii=True)` writes it.
pub fn push_json_str(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    let bytes = s.as_bytes();
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\' {
            continue;
        }
        if b >= 0x80 && (b & 0xc0) == 0x80 {
            // continuation byte, handled with its lead byte
            continue;
        }
        out.extend_from_slice(&bytes[start..i]);
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            _ if b < 0x80 => push_u_escape(out, b as u32),
            _ => {
                let c = s[i..].chars().next().unwrap_or('\u{fffd}');
                let v = c as u32;
                if v >= 0x10000 {
                    let v2 = v - 0x10000;
                    push_u_escape(out, 0xd800 | (v2 >> 10));
                    push_u_escape(out, 0xdc00 | (v2 & 0x3ff));
                } else {
                    push_u_escape(out, v);
                }
                start = i + c.len_utf8();
                continue;
            }
        }
        start = i + 1;
    }
    out.extend_from_slice(&bytes[start..]);
    out.push(b'"');
}

#[inline]
fn push_u_escape(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(b"\\u");
    push_hex_byte(out, (v >> 8) as u8);
    push_hex_byte(out, v as u8);
}

/// python `int(s, 0)`. Returns `None` where python raises `ValueError`.
pub fn parse_int0(s: &str) -> Option<i128> {
    let s = s.trim();
    let (neg, s) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let b = s.as_bytes();
    if b.is_empty() {
        return None;
    }
    let (radix, digits, after_prefix) = if b.len() >= 2 && b[0] == b'0' {
        match b[1] {
            b'x' | b'X' => (16, &s[2..], true),
            b'o' | b'O' => (8, &s[2..], true),
            b'b' | b'B' => (2, &s[2..], true),
            _ => (10, s, false),
        }
    } else {
        (10, s, false)
    };
    let d = digits.as_bytes();
    if d.is_empty() {
        return None;
    }
    // underscore rules: single underscores between digits; one allowed right after a prefix
    let mut prev_us = !after_prefix; // leading underscore invalid unless after a base prefix
    let mut value: i128 = 0;
    let mut ndigits = 0;
    let mut nonzero_seen = false;
    for &c in d {
        if c == b'_' {
            if prev_us {
                return None;
            }
            prev_us = true;
            continue;
        }
        prev_us = false;
        let v = (c as char).to_digit(radix)? as i128;
        if v != 0 {
            nonzero_seen = true;
        }
        value = value.checked_mul(radix as i128)?.checked_add(v)?;
        ndigits += 1;
    }
    if prev_us || ndigits == 0 {
        return None;
    }
    // "0123" is invalid in base 0 (leading zeros only allowed for zero itself)
    if radix == 10 && !after_prefix && d[0] == b'0' && nonzero_seen {
        return None;
    }
    Some(if neg { -value } else { value })
}

/// Civil date from days since 1970-01-01 (proleptic Gregorian).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + (m <= 2) as i64, m, d)
}

#[inline]
fn push_2(out: &mut Vec<u8>, v: u32) {
    out.push(b'0' + (v / 10 % 10) as u8);
    out.push(b'0' + (v % 10) as u8);
}

/// Append `YYYY-MM-DD{sep}HH:MM:SS` for the timestamp.
fn push_date_time(out: &mut Vec<u8>, dt: &DateTime, sep: u8) {
    let days = dt.secs.div_euclid(86_400);
    let sod = dt.secs.rem_euclid(86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    if (0..10_000).contains(&y) {
        let y = y as u32;
        push_2(out, y / 100);
        push_2(out, y % 100);
    } else {
        push_i128(out, y as i128);
    }
    out.push(b'-');
    push_2(out, m);
    out.push(b'-');
    push_2(out, d);
    out.push(sep);
    push_2(out, sod / 3600);
    out.push(b':');
    push_2(out, sod / 60 % 60);
    out.push(b':');
    push_2(out, sod % 60);
}

fn push_micros(out: &mut Vec<u8>, micros: u32) {
    let m = micros.min(999_999);
    push_2(out, m / 10_000);
    push_2(out, m / 100 % 100);
    push_2(out, m % 100);
}

/// `dt.strftime("%Y-%m-%d %H:%M:%S.%f %Z")` (`%Z` is `UTC` for aware values, empty for naive).
pub fn push_datetime_cli(out: &mut Vec<u8>, dt: &DateTime) {
    // small memo: sorted outputs (timeliner: 2.8M rows x 4 date columns) repeat the same
    // values in consecutive rows
    type Memo = ([Option<DateTime>; 4], [[u8; 48]; 4], [u8; 4], usize);
    thread_local! {
        static MEMO: std::cell::RefCell<Memo> = const { std::cell::RefCell::new(([None; 4], [[0; 48]; 4], [0; 4], 0)) };
    }
    MEMO.with(|m| {
        let mut m = m.borrow_mut();
        if let Some(i) = m.0.iter().position(|x| *x == Some(*dt)) {
            let n = m.2[i] as usize;
            out.extend_from_slice(&m.1[i][..n]);
            return;
        }
        let start = out.len();
        push_date_time(out, dt, b' ');
        out.push(b'.');
        push_micros(out, dt.micros);
        out.push(b' ');
        if dt.utc {
            out.extend_from_slice(b"UTC");
        }
        let n = out.len() - start;
        if n <= 48 {
            let i = m.3;
            m.3 = (i + 1) % 4;
            m.1[i][..n].copy_from_slice(&out[start..]);
            m.2[i] = n as u8;
            m.0[i] = Some(*dt);
        }
    })
}

/// python `str(dt)` (`sep=b' '`) or `dt.isoformat()` (`sep=b'T'`).
pub fn push_datetime_iso(out: &mut Vec<u8>, dt: &DateTime, sep: u8) {
    push_date_time(out, dt, sep);
    if dt.micros != 0 {
        out.push(b'.');
        push_micros(out, dt.micros);
    }
    if dt.utc {
        out.extend_from_slice(b"+00:00");
    }
}

/// Decode like python `bytes.decode("utf-16-le", errors="replace")`.
pub fn decode_utf16le_replace(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() / 2);
    let n = data.len();
    let even = n & !1;
    let mut i = 0;
    let unit = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]) as u32;
    while i < even {
        let u = unit(i);
        i += 2;
        if !(0xd800..0xe000).contains(&u) {
            s.push(char::from_u32(u).unwrap_or('\u{fffd}'));
        } else if u >= 0xdc00 {
            s.push('\u{fffd}');
        } else if i >= even {
            // "unexpected end of data": swallows the rest (incl. an odd trailing byte)
            s.push('\u{fffd}');
            return s;
        } else {
            let u2 = unit(i);
            if (0xdc00..0xe000).contains(&u2) {
                i += 2;
                s.push(char::from_u32(0x10000 + ((u - 0xd800) << 10) + (u2 - 0xdc00)).unwrap_or('\u{fffd}'));
            } else {
                s.push('\u{fffd}');
            }
        }
    }
    if i < n {
        s.push('\u{fffd}');
    }
    s
}

/// Number of characters (python `len(str)`) of a UTF-8 string.
#[inline]
pub fn char_len(s: &str) -> usize {
    if s.is_ascii() { s.len() } else { s.chars().count() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(x: f64) -> String {
        let mut v = Vec::new();
        push_float(&mut v, x);
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn floats() {
        assert_eq!(f(1.0), "1.0");
        assert_eq!(f(0.1), "0.1");
        assert_eq!(f(1e16), "1e+16");
        assert_eq!(f(1e15), "1000000000000000.0");
        assert_eq!(f(123456789012345678.0), "1.2345678901234568e+17");
        assert_eq!(f(1e-5), "1e-05");
        assert_eq!(f(0.0001), "0.0001");
        assert_eq!(f(-0.0), "-0.0");
        assert_eq!(f(1.5e300), "1.5e+300");
        assert_eq!(f(2.5e-7), "2.5e-07");
        assert_eq!(f(12345.678), "12345.678");
        assert_eq!(f(f64::NAN), "nan");
    }

    #[test]
    fn ints() {
        assert_eq!(parse_int0("0x10"), Some(16));
        assert_eq!(parse_int0(" -0b101 "), Some(-5));
        assert_eq!(parse_int0("0o17"), Some(15));
        assert_eq!(parse_int0("1_000"), Some(1000));
        assert_eq!(parse_int0("0x_ff"), Some(255));
        assert_eq!(parse_int0("00"), Some(0));
        assert_eq!(parse_int0("0_0"), Some(0));
        assert_eq!(parse_int0("01"), None);
        assert_eq!(parse_int0("1__0"), None);
        assert_eq!(parse_int0("_1"), None);
        assert_eq!(parse_int0("1_"), None);
        assert_eq!(parse_int0("0x"), None);
        assert_eq!(parse_int0(""), None);
        assert_eq!(parse_int0("x"), None);
        assert_eq!(parse_int0("+7"), Some(7));
    }

    #[test]
    fn utf16() {
        assert_eq!(decode_utf16le_replace(b"\x00\xd8\x41"), "\u{fffd}");
        assert_eq!(decode_utf16le_replace(b"\x00\xd8A\x00"), "\u{fffd}A");
        assert_eq!(decode_utf16le_replace(b"A"), "\u{fffd}");
        assert_eq!(decode_utf16le_replace(b"\x00\xd8\x00\xd8\x00\xdc"), "\u{fffd}\u{10000}");
        assert_eq!(decode_utf16le_replace(b"A\x00\x00\xd8\x00\xdcB"), "A\u{10000}\u{fffd}");
    }

    #[test]
    fn json_str() {
        let mut v = Vec::new();
        let input: String = ['\u{e9}', '\x7f', '\x1f', '\u{2028}', '\u{1f600}', '"', '\\', '/'].iter().collect();
        push_json_str(&mut v, &input);
        let bs = '\\';
        let want = format!("\"{bs}u00e9{bs}u007f{bs}u001f{bs}u2028{bs}ud83d{bs}ude00{bs}\"{bs}{bs}/\"");
        assert_eq!(String::from_utf8(v).unwrap(), want);
    }

    #[test]
    fn dates() {
        let mut v = Vec::new();
        push_datetime_cli(&mut v, &DateTime { secs: -11644473600 + 86400 + 3 * 3600 + 4 * 60 + 5, micros: 6, utc: true });
        assert_eq!(String::from_utf8(v).unwrap(), "1601-01-02 03:04:05.000006 UTC");
        let mut v = Vec::new();
        push_datetime_iso(&mut v, &DateTime { secs: 1577934245, micros: 0, utc: true }, b'T');
        assert_eq!(String::from_utf8(v).unwrap(), "2020-01-02T03:04:05+00:00");
    }
}
