//! Python value formatting helpers (derived from Volatility 3 / CPython semantics; Volatility
//! Software License 1.0). Everything here writes straight into a byte buffer so the renderer hot
//! paths do not allocate.

use super::DateTime;

/// "00" "01" ... "99"
static DEC2: [[u8; 2]; 100] = {
    let mut t = [[0u8; 2]; 100];
    let mut i = 0;
    while i < 100 {
        t[i] = [b'0' + (i / 10) as u8, b'0' + (i % 10) as u8];
        i += 1;
    }
    t
};

/// "00" "01" ... "ff"
static HEX2: [[u8; 2]; 256] = {
    let h = b"0123456789abcdef";
    let mut t = [[0u8; 2]; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = [h[i >> 4], h[i & 15]];
        i += 1;
    }
    t
};

/// Digits are formatted right-aligned to `END` in a `[u8; 48]` scratch buffer.
const END: usize = 24;

/// Append `buf[start..END]` (at most 24 bytes) with one fixed-size 24-byte copy into the
/// spare capacity instead of a variable-length memcpy call.
#[inline(always)]
fn push_tail(out: &mut Vec<u8>, buf: &[u8; 48], start: usize) {
    out.reserve(24);
    unsafe {
        let len = out.len();
        std::ptr::copy_nonoverlapping(buf.as_ptr().add(start), out.as_mut_ptr().add(len), 24);
        out.set_len(len + (END - start));
    }
}

/// Append the decimal representation of `v` (python `str(int)`), two digits per step.
#[inline]
pub fn push_u64(out: &mut Vec<u8>, mut v: u64) {
    if v < 10 {
        out.push(b'0' + v as u8);
        return;
    }
    let mut buf = [0u8; 48];
    let mut i = END;
    while v >= 100 {
        i -= 2;
        buf[i..i + 2].copy_from_slice(&DEC2[(v % 100) as usize]);
        v /= 100;
    }
    if v >= 10 {
        i -= 2;
        buf[i..i + 2].copy_from_slice(&DEC2[v as usize]);
    } else {
        i -= 1;
        buf[i] = b'0' + v as u8;
    }
    push_tail(out, &buf, i);
}

/// Append python `f"{v:x}"` for a u64 (lower case, no prefix), a byte per step.
#[inline]
pub fn push_hex_u64(out: &mut Vec<u8>, mut v: u64) {
    let mut buf = [0u8; 48];
    let mut i = END;
    loop {
        i -= 2;
        buf[i..i + 2].copy_from_slice(&HEX2[(v & 0xff) as usize]);
        v >>= 8;
        if v == 0 {
            break;
        }
    }
    if buf[i] == b'0' {
        i += 1;
    }
    push_tail(out, &buf, i);
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
    if v >= 0 && v <= u64::MAX as i128 {
        return push_hex_u64(out, v as u64);
    }
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
    out.extend_from_slice(&DEC2[(v % 100) as usize]);
}

/// `YYYY-MM-DD` of day `days` since 1970, for years 0..=9999 (None otherwise).
#[inline]
fn date_bytes(days: i64) -> Option<[u8; 10]> {
    // one-entry per-thread cache: sorted / clustered timestamps share their day
    thread_local! {
        static DAY: std::cell::Cell<(i64, [u8; 10])> = const { std::cell::Cell::new((i64::MIN, [0; 10])) };
    }
    let (cd, cb) = DAY.with(|c| c.get());
    if cd == days {
        return Some(cb);
    }
    let (y, m, d) = civil_from_days(days);
    if !(0..10_000).contains(&y) {
        return None;
    }
    let y = y as usize;
    let mut b = [0u8; 10];
    b[0..2].copy_from_slice(&DEC2[y / 100]);
    b[2..4].copy_from_slice(&DEC2[y % 100]);
    b[4] = b'-';
    b[5..7].copy_from_slice(&DEC2[m as usize]);
    b[7] = b'-';
    b[8..10].copy_from_slice(&DEC2[d as usize]);
    DAY.with(|c| c.set((days, b)));
    Some(b)
}

/// `HH:MM:SS` for a second of the day into `b[..8]`.
#[inline(always)]
fn time_bytes(sod: u32, b: &mut [u8]) {
    b[0..2].copy_from_slice(&DEC2[(sod / 3600) as usize]);
    b[2] = b':';
    b[3..5].copy_from_slice(&DEC2[(sod / 60 % 60) as usize]);
    b[5] = b':';
    b[6..8].copy_from_slice(&DEC2[(sod % 60) as usize]);
}

/// `ffffff` into `b[..6]`.
#[inline(always)]
fn micros_bytes(micros: u32, b: &mut [u8]) {
    let m = micros.min(999_999);
    b[0..2].copy_from_slice(&DEC2[(m / 10_000) as usize]);
    b[2..4].copy_from_slice(&DEC2[(m / 100 % 100) as usize]);
    b[4..6].copy_from_slice(&DEC2[(m % 100) as usize]);
}

/// Append `YYYY-MM-DD{sep}HH:MM:SS` for the timestamp.
fn push_date_time(out: &mut Vec<u8>, dt: &DateTime, sep: u8) {
    let days = dt.secs.div_euclid(86_400);
    let sod = dt.secs.rem_euclid(86_400) as u32;
    let mut b = [0u8; 19];
    match date_bytes(days) {
        Some(d) => b[..10].copy_from_slice(&d),
        None => {
            let (y, m, d) = civil_from_days(days);
            push_i128(out, y as i128);
            out.push(b'-');
            push_2(out, m);
            out.push(b'-');
            push_2(out, d);
            out.push(sep);
            time_bytes(sod, &mut b[11..]);
            out.extend_from_slice(&b[11..]);
            return;
        }
    }
    b[10] = sep;
    time_bytes(sod, &mut b[11..]);
    out.extend_from_slice(&b);
}

/// `dt.strftime("%Y-%m-%d %H:%M:%S.%f %Z")` (`%Z` is `UTC` for aware values, empty for naive).
#[inline]
pub fn push_datetime_cli(out: &mut Vec<u8>, dt: &DateTime) {
    let days = dt.secs.div_euclid(86_400);
    let sod = dt.secs.rem_euclid(86_400) as u32;
    let Some(date) = date_bytes(days) else {
        push_date_time(out, dt, b' ');
        let mut b = [0u8; 8];
        b[0] = b'.';
        micros_bytes(dt.micros, &mut b[1..7]);
        b[7] = b' ';
        out.extend_from_slice(&b);
        if dt.utc {
            out.extend_from_slice(b"UTC");
        }
        return;
    };
    // "YYYY-MM-DD HH:MM:SS.ffffff UTC", one fixed 32-byte store
    let mut b = [0u8; 32];
    b[..10].copy_from_slice(&date);
    b[10] = b' ';
    time_bytes(sod, &mut b[11..19]);
    b[19] = b'.';
    micros_bytes(dt.micros, &mut b[20..26]);
    b[26] = b' ';
    b[27..30].copy_from_slice(b"UTC");
    let n = if dt.utc { 30 } else { 27 };
    out.reserve(32);
    unsafe {
        let len = out.len();
        std::ptr::copy_nonoverlapping(b.as_ptr(), out.as_mut_ptr().add(len), 32);
        out.set_len(len + n);
    }
}

/// python `str(dt)` (`sep=b' '`) or `dt.isoformat()` (`sep=b'T'`).
pub fn push_datetime_iso(out: &mut Vec<u8>, dt: &DateTime, sep: u8) {
    push_date_time(out, dt, sep);
    if dt.micros != 0 {
        let mut b = [0u8; 7];
        b[0] = b'.';
        micros_bytes(dt.micros, &mut b[1..]);
        out.extend_from_slice(&b);
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
    fn ints_and_hex_like_format() {
        let mut vals: Vec<u64> = vec![0, 1, 9, 10, 15, 16, 99, 100, 255, 256, 999, 1000, u64::MAX, u64::MAX - 1, 1 << 63];
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..20000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            vals.push(x >> (x % 64));
            vals.push(10u64.pow((x % 20) as u32));
            vals.push(10u64.pow((x % 20) as u32) - 1);
            vals.push(1u64 << (x % 64));
        }
        for v in vals {
            let mut o = b"x".to_vec();
            push_u64(&mut o, v);
            push_hex_u64(&mut o, v);
            push_i128(&mut o, -(v as i128));
            push_hex(&mut o, -(v as i128));
            push_hex(&mut o, v as i128 + (1 << 70));
            let want = format!("x{v}{v:x}{}{}{:x}", -(v as i128), if v == 0 { "0".to_string() } else { format!("-{v:x}") }, v as i128 + (1 << 70));
            assert_eq!(String::from_utf8(o).unwrap(), want);
        }
    }

    #[test]
    fn datetimes_like_chrono_math() {
        // against a straightforward formatter over a wide range of seconds / micros
        let slow = |dt: &DateTime, cli: bool| -> String {
            let days = dt.secs.div_euclid(86_400);
            let sod = dt.secs.rem_euclid(86_400);
            let (y, m, d) = civil_from_days(days);
            let ys = if (0..10_000).contains(&y) { format!("{y:04}") } else { format!("{y}") };
            let base = format!("{ys}-{m:02}-{d:02} {:02}:{:02}:{:02}", sod / 3600, sod / 60 % 60, sod % 60);
            if cli {
                format!("{base}.{:06} {}", dt.micros.min(999_999), if dt.utc { "UTC" } else { "" })
            } else {
                let mut s = base;
                if dt.micros != 0 {
                    s += &format!(".{:06}", dt.micros.min(999_999));
                }
                if dt.utc {
                    s += "+00:00";
                }
                s
            }
        };
        let mut x = 0x2545_f491_4f6c_dd1du64;
        for i in 0..200_000i64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let secs = match i % 4 {
                0 => (x % 400_000_000_000) as i64 - 100_000_000_000,
                1 => 1_700_000_000 + (i % 1000),
                2 => -11_644_473_600 + (x % 100_000) as i64,
                _ => (x as i64) >> (x % 30),
            };
            let dt = DateTime { secs, micros: (x >> 40) as u32 % 1_000_000, utc: i % 3 != 0 };
            let mut o = Vec::new();
            push_datetime_cli(&mut o, &dt);
            assert_eq!(String::from_utf8(o).unwrap(), slow(&dt, true), "{dt:?}");
            let mut o = Vec::new();
            push_datetime_iso(&mut o, &dt, b' ');
            assert_eq!(String::from_utf8(o).unwrap(), slow(&dt, false), "{dt:?}");
        }
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
