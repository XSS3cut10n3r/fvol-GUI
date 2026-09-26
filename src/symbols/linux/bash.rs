//! python `symbols/linux/bash.py` (`BashIntermedSymbols`) and `symbols/linux/extensions/bash.py`
//! (the `hist_entry` class).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! let table = bash::bash_table(ctx, k.table.is_64bit())?;          // linux/bash64 | bash32
//! let hist = Obj::named(Space::on(proc_layer, table), "hist_entry", addr)?;
//! if let Some(h) = bash::HistEntry::parse(&hist)? { h.time; h.command; }
//! ```

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::renderers::Value;
use crate::symbols::TableRef;

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
        let Some(time) = py_int(&ts[1..]) else { return Ok(None) };
        Ok(Some(HistEntry { time, command: cmd }))
    }
}

/// python `hist_entry.get_command()`: `array_to_string(self.line.dereference())`.
pub fn get_command(hist: &Obj) -> Result<String> {
    array_to_string(&hist.m("line")?.deref()?, None)
}

/// python `int(s)` for a `str` (base 10): surrounding whitespace, an optional sign, digits
/// with single underscores between them. `None` = python's ValueError. Only ASCII digits are
/// accepted (python also takes other Unicode decimal digits; never seen in bash history).
/// Values beyond i128 saturate.
pub fn py_int(s: &str) -> Option<i128> {
    let t = s.trim_matches(py_isspace);
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let b = digits.as_bytes();
    if b.is_empty() || !b[0].is_ascii_digit() || !b[b.len() - 1].is_ascii_digit() {
        return None;
    }
    let mut v: i128 = 0;
    let mut prev_us = false;
    for &c in b {
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
        v = v.saturating_mul(10).saturating_add((c - b'0') as i128);
    }
    Some(if neg { -v } else { v })
}

/// python `str.isspace()` for one character.
fn py_isspace(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\x0b' | '\x0c' | '\r' | '\x1c'..='\x1f' | ' ' | '\u{85}') || (c as u32 > 0x7f && c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::py_int;

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
}
