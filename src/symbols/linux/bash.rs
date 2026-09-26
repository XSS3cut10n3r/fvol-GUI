//! python `symbols/linux/bash.py` (`BashIntermedSymbols`) and `symbols/linux/extensions/bash.py`
//! (the `hist_entry` class). Shared by `linux.bash` and `mac.bash` (both use the linux ISFs).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! let table = bash::bash_table(ctx, k.table.is_64bit())?;          // linux/bash64 | bash32
//! let hist = Obj::named(Space::on(proc_layer, table), "hist_entry", addr)?;
//! if let Some(h) = bash::HistEntry::parse(&hist)? { h.time; h.time_int; h.command; }
//! ```

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::renderers::Value;
use crate::symbols::TableRef;
use std::cmp::Ordering;

/// python `BashIntermedSymbols.create(ctx, path, "linux", "bash64" | "bash32")`.
pub fn bash_table(ctx: &Context, is_64bit: bool) -> Result<TableRef> {
    ctx.load_isf(if is_64bit { "linux/bash64" } else { "linux/bash32" })
}

/// A `hist_entry` that passed python's `hist_entry.is_valid()`, with the values python's
/// `get_time_as_integer()`, `get_time_object()` and `get_command()` return.
#[derive(Clone, Debug)]
pub struct HistEntry {
    /// python `get_time_as_integer()` (saturated to i128 for absurdly long digit strings).
    pub time: i128,
    /// python `get_time_as_integer()` exactly (arbitrary precision; sort key of python's
    /// `sorted(..., key=get_time_as_integer)`).
    pub time_int: PyInt,
    /// python `get_command()`.
    pub command: String,
}

impl HistEntry {
    /// python `hist_entry.get_time_object()` (`conversion.unixtime_to_datetime`).
    pub fn time_object(&self) -> Value {
        crate::util::time::unixtime_to_datetime(self.time)
    }

    /// python `hist_entry.is_valid()` on `hist` (a `hist_entry` object); `Some` with the
    /// parsed values when valid. `Err` only for non-address errors (python would crash).
    pub fn parse(hist: &Obj) -> Result<Option<HistEntry>> {
        // try: cmd = get_command(); ts = array_to_string(timestamp.dereference())
        let read = || -> Result<(String, String)> {
            let cmd = get_command(hist)?;
            let ts = array_to_string(&hist.m("timestamp")?.deref()?, None)?;
            Ok((cmd, ts))
        };
        let (cmd, ts) = match read() {
            Ok(v) => v,
            Err(e) if e.is_invalid_address() => return Ok(None),
            Err(e) => return Err(e),
        };
        if cmd.is_empty() || ts.is_empty() {
            return Ok(None);
        }
        // len(ts) < 10 (characters) or ts[0] != "#"
        if ts.chars().count() < 10 || !ts.starts_with('#') {
            return Ok(None);
        }
        let Some(time_int) = PyInt::parse(&ts[1..]) else { return Ok(None) };
        Ok(Some(HistEntry { time: time_int.saturating_i128(), time_int, command: cmd }))
    }
}

/// python `hist_entry.get_command()`: `array_to_string(self.line.dereference())`.
pub fn get_command(hist: &Obj) -> Result<String> {
    array_to_string(&hist.m("line")?.deref()?, None)
}

/// python `int(s)` for a `str` (base 10), saturated to i128; `None` = python's ValueError.
/// See [`PyInt::parse`].
pub fn py_int(s: &str) -> Option<i128> {
    PyInt::parse(s).map(|v| v.saturating_i128())
}

/// An arbitrary-precision python int as parsed by `int(str)` (base 10), ordered like python.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PyInt {
    neg: bool,
    /// ASCII decimal digits without leading zeros (empty = 0)
    digits: Vec<u8>,
}

/// Zero code points of the Unicode decimal digit runs (`unicodedata.decimal`, Unicode 16.0 as
/// in python 3.14): python `int()` accepts any of them as digits.
const DECIMAL_ZEROS: [u32; 76] = [
    0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66, 0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0,
    0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0, 0xff10, 0x104a0,
    0x10d30, 0x10d40, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0, 0x11650, 0x116c0, 0x116d0, 0x116da, 0x11730, 0x118e0, 0x11950,
    0x11bf0, 0x11c50, 0x11d50, 0x11da0, 0x11f50, 0x16130, 0x16a60, 0x16ac0, 0x16b50, 0x16d70, 0x1ccf0, 0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6,
    0x1e140, 0x1e2f0, 0x1e4f0, 0x1e5f1, 0x1e950, 0x1fbf0,
];

/// Non-ASCII characters python's `str.isspace()` accepts.
const UNICODE_SPACES: [u32; 19] =
    [0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000];

impl PyInt {
    /// python `int(s)` for a str (CPython `_PyUnicode_TransformDecimalAndSpaceToASCII` then
    /// `PyLong_FromString(base=10)`): surrounding whitespace, an optional sign, digits (any
    /// Unicode decimal digit) with single underscores between them. `None` = ValueError.
    pub fn parse(s: &str) -> Option<PyInt> {
        let mut ascii: Vec<u8> = Vec::with_capacity(s.len());
        for c in s.chars() {
            let u = c as u32;
            if u < 127 {
                ascii.push(u as u8);
            } else if UNICODE_SPACES.contains(&u) {
                ascii.push(b' ');
            } else {
                let i = DECIMAL_ZEROS.partition_point(|&z| z <= u);
                match i.checked_sub(1).map(|i| DECIMAL_ZEROS[i]) {
                    Some(z) if u - z < 10 => ascii.push(b'0' + (u - z) as u8),
                    _ => return None,
                }
            }
        }
        let is_ws = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
        let start = ascii.iter().position(|c| !is_ws(c))?;
        let end = ascii.iter().rposition(|c| !is_ws(c))? + 1;
        let mut t = &ascii[start..end];
        let neg = match t.first() {
            Some(b'-') => {
                t = &t[1..];
                true
            }
            Some(b'+') => {
                t = &t[1..];
                false
            }
            _ => false,
        };
        if t.is_empty() || !t[0].is_ascii_digit() || !t[t.len() - 1].is_ascii_digit() {
            return None;
        }
        let mut digits = Vec::with_capacity(t.len());
        let mut prev_us = false;
        for &c in t {
            if c == b'_' {
                if prev_us {
                    return None;
                }
                prev_us = true;
                continue;
            }
            if !c.is_ascii_digit() {
                return None;
            }
            prev_us = false;
            if !(digits.is_empty() && c == b'0') {
                digits.push(c);
            }
        }
        Some(PyInt { neg: neg && !digits.is_empty(), digits })
    }

    /// The value, saturated to the i128 range.
    pub fn saturating_i128(&self) -> i128 {
        let mut v: i128 = 0;
        for &d in &self.digits {
            v = v.saturating_mul(10).saturating_add((d - b'0') as i128);
        }
        if self.neg { -v } else { v }
    }
}

impl Ord for PyInt {
    fn cmp(&self, other: &Self) -> Ordering {
        let mag = || self.digits.len().cmp(&other.digits.len()).then_with(|| self.digits.cmp(&other.digits));
        match (self.neg, other.neg) {
            (false, false) => mag(),
            (true, true) => mag().reverse(),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
        }
    }
}

impl PartialOrd for PyInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::{PyInt, py_int};

    #[test]
    fn python_int() {
        assert_eq!(py_int("1758843627"), Some(1758843627));
        assert_eq!(py_int(" 12 "), Some(12));
        assert_eq!(py_int("1_000"), Some(1000));
        assert_eq!(py_int("-5"), Some(-5));
        assert_eq!(py_int("+5"), Some(5));
        assert_eq!(py_int("1__0"), None);
        assert_eq!(py_int("_1"), None);
        assert_eq!(py_int("1_"), None);
        assert_eq!(py_int("12a"), None);
        assert_eq!(py_int(""), None);
        assert_eq!(py_int("-"), None);
        assert_eq!(py_int("1 2"), None);
    }

    #[test]
    fn py_int_like_python() {
        let p = py_int;
        assert_eq!(p("1234567890"), Some(1234567890));
        assert_eq!(p(" 12 "), Some(12));
        assert_eq!(p("13\u{85}"), Some(13));
        assert_eq!(p("13\x0b"), Some(13));
        assert_eq!(p("13\x1c"), None);
        assert_eq!(p("\u{661}\u{662}"), Some(12));
        assert_eq!(p("\u{661}_\u{662}"), Some(12));
        assert_eq!(p("+_1"), None);
        assert_eq!(p("1__2"), None);
        assert_eq!(p("1_"), None);
        assert_eq!(p("0x10"), None);
        assert_eq!(p("00012"), Some(12));
        assert_eq!(p("-0"), Some(0));
        assert_eq!(p(" - 1"), None);
        assert_eq!(p("1\x00"), None);
        assert_eq!(p(""), None);
        assert_eq!(p("-"), None);
    }

    #[test]
    fn py_int_order() {
        let mut v: Vec<PyInt> = ["5", "-3", "0", "-0", "100000000000000000000000000000000000000000000", "-100000000000000000000000000000000000000000000", "-4", "99"]
            .iter()
            .map(|s| PyInt::parse(s).unwrap())
            .collect();
        v.sort();
        let got: Vec<String> = v.iter().map(|x| format!("{}{}", if x.neg { "-" } else { "" }, String::from_utf8_lossy(&x.digits))).collect();
        assert_eq!(got, ["-100000000000000000000000000000000000000000000", "-4", "-3", "", "", "5", "99", "100000000000000000000000000000000000000000000"]);
    }
}
