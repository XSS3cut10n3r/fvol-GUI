//! python `symbols/linux/__init__.py` `VMCoreInfo`: find and parse the kernel's VMCOREINFO ELF
//! note in a (physical) layer.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::error::{Error, Result};
use crate::layers::Layer;
use crate::layers::scan::{BytesScanner, scan_each};

/// python `linux_constants.VMCOREINFO_MAGIC`.
pub const VMCOREINFO_MAGIC: &[u8] = b"VMCOREINFO\x00";
/// python `linux_constants.VMCOREINFO_MAGIC_ALIGNED`.
pub const VMCOREINFO_MAGIC_ALIGNED: &[u8] = b"VMCOREINFO\x00\x00";
/// python `linux_constants.OSRELEASE_TAG`.
pub const OSRELEASE_TAG: &[u8] = b"OSRELEASE=";
/// `Elf64_Note` size (elf.json).
const ELF_NOTE_SIZE: u64 = 12;

/// A parsed VMCOREINFO value (python `_parse_value`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmValue {
    Int(i128),
    Str(String),
}

/// A VMCOREINFO table (python dict: insertion order of first occurrence, last value wins).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VmCoreInfo {
    pub entries: Vec<(String, VmValue)>,
}

impl VmCoreInfo {
    /// python `vmcoreinfo.get(key)`.
    pub fn get(&self, key: &str) -> Option<&VmValue> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    /// Integer value of `key` (None if missing or a string).
    pub fn int(&self, key: &str) -> Option<i128> {
        match self.get(key) {
            Some(VmValue::Int(i)) => Some(*i),
            _ => None,
        }
    }
    /// String value of `key` (None if missing or an int).
    pub fn str(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(VmValue::Str(s)) => Some(s),
            _ => None,
        }
    }
    fn insert(&mut self, key: &str, v: VmValue) {
        match self.entries.iter_mut().find(|(k, _)| k == key) {
            Some(e) => e.1 = v,
            None => self.entries.push((key.to_string(), v)),
        }
    }
}

/// python `string.printable` membership.
#[inline]
pub fn is_printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// python whitespace for `str.strip()` / `int()` on ASCII.
#[inline]
fn is_py_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\x1f' | '\u{85}' | '\u{a0}')
}

/// python `int(s, base)` for base 0 or 2..=36 (None = ValueError, or beyond i128).
pub fn py_int(s: &str, base: u32) -> Option<i128> {
    let base0 = base == 0;
    let s = s.trim_matches(is_py_space);
    let (neg, s) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let b = s.as_bytes();
    let has_prefix = |c: u8| b.len() >= 2 && b[0] == b'0' && (b[1] | 0x20) == c;
    let (base, digits, prefixed) = match base {
        0 => {
            if has_prefix(b'x') {
                (16, &s[2..], true)
            } else if has_prefix(b'o') {
                (8, &s[2..], true)
            } else if has_prefix(b'b') {
                (2, &s[2..], true)
            } else {
                (10, s, false)
            }
        }
        16 if has_prefix(b'x') => (16, &s[2..], true),
        8 if has_prefix(b'o') => (8, &s[2..], true),
        2 if has_prefix(b'b') => (2, &s[2..], true),
        b if (2..=36).contains(&b) => (b, s, false),
        _ => return None,
    };
    let digits = if prefixed { digits.strip_prefix('_').unwrap_or(digits) } else { digits };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let mut v: i128 = 0;
    let mut nonzero = false;
    for c in digits.chars() {
        if c == '_' {
            continue;
        }
        let d = c.to_digit(36)?;
        if d >= base {
            return None;
        }
        nonzero |= d != 0;
        v = v.checked_mul(base as i128)?.checked_add(d as i128)?;
    }
    // base 0: a decimal literal may not have leading zeros (except zero itself)
    if base0 && !prefixed && digits.starts_with('0') && nonzero {
        return None;
    }
    Some(if neg { -v } else { v })
}

/// python `VMCoreInfo._parse_value(key, value)` (`Err` = python raises ValueError).
pub fn parse_value(key: &str, value: &str) -> Result<VmValue> {
    let bad = || Error::msg(format!("ValueError: invalid literal for int(): {value:?}"));
    if key.starts_with("SYMBOL(") || key == "KERNELOFFSET" {
        return py_int(value, 16).map(VmValue::Int).ok_or_else(bad);
    }
    if ["NUMBER(", "LENGTH(", "SIZE(", "OFFSET("].iter().any(|p| key.starts_with(p)) || key == "PAGESIZE" {
        return py_int(value, 0).map(VmValue::Int).ok_or_else(bad);
    }
    Ok(VmValue::Str(value.to_string()))
}

/// python `VMCoreInfo._vmcoreinfo_data_to_dict(data)`: `Ok(None)` when not every byte is
/// printable, `Err` where python raises (a line without '=', a bad integer).
pub fn data_to_dict(data: &[u8]) -> Result<Option<VmCoreInfo>> {
    if !data.iter().all(|&b| is_printable(b)) {
        return Ok(None);
    }
    let text = std::str::from_utf8(data).map_err(|_| Error::msg("decode error"))?;
    let mut out = VmCoreInfo::default();
    for line in splitlines(text) {
        if line.is_empty() {
            break;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| Error::msg("ValueError: not enough values to unpack (expected 2, got 1)"))?;
        out.insert(key, parse_value(key, value)?);
    }
    Ok(Some(out))
}

/// python `str.splitlines()` restricted to the ASCII printable set (`\n`, `\r`, `\r\n`,
/// `\x0b`, `\x0c`).
fn splitlines(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let (mut start, mut i) = (0usize, 0usize);
    while i < b.len() {
        match b[i] {
            b'\n' | 0x0b | 0x0c => {
                out.push(&s[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                out.push(&s[start..i]);
                i += if b.get(i + 1) == Some(&b'\n') { 2 } else { 1 };
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < b.len() {
        out.push(&s[start..]);
    }
    out
}

/// python `layer.read(offset, length)` for a possibly large `length`: reads in pieces (so a
/// garbage length cannot exhaust memory) and keeps the bytes only while they could still form
/// a valid note (start with `OSRELEASE=` and are all printable). `Err` where python's read
/// would raise.
fn read_note_data(layer: &dyn Layer, off: u64, len: u64) -> Result<Option<Vec<u8>>> {
    const PIECE: u64 = 1 << 20;
    let mut keep = Some(Vec::with_capacity(len.min(PIECE) as usize));
    let mut buf = vec![0u8; len.min(PIECE) as usize];
    let mut done = 0u64;
    while done < len {
        let n = (len - done).min(PIECE) as usize;
        layer.read(off.wrapping_add(done), &mut buf[..n])?;
        if let Some(k) = keep.as_mut() {
            let piece = &buf[..n];
            let starts_ok = done > 0 || piece.starts_with(OSRELEASE_TAG);
            if starts_ok && piece.iter().all(|&b| is_printable(b)) {
                k.extend_from_slice(piece);
            } else {
                // cannot be a valid table; python still reads (and may fail on) the rest
                keep = None;
            }
        }
        done += n as u64;
    }
    Ok(keep)
}

/// python `VMCoreInfo.search_vmcoreinfo_elf_note(context, layer_name)`: calls `f(note
/// offset, table)` for each valid VMCOREINFO note in python order until `f` returns false.
/// `Err` where python's generator raises (which aborts the caller's iteration).
pub fn search_vmcoreinfo_elf_note(layer: &dyn Layer, mut f: impl FnMut(u64, &VmCoreInfo) -> bool) -> Result<()> {
    let mask = layer.address_mask();
    let rd32 = |addr: u64| -> Result<u32> {
        let mut b = [0u8; 4];
        layer.read(addr & mask, &mut b)?;
        Ok(u32::from_le_bytes(b))
    };
    let mut err = None;
    scan_each(layer, &BytesScanner::new(VMCOREINFO_MAGIC_ALIGNED), None, |magic_off| {
        let r = (|| -> Result<Option<(u64, VmCoreInfo)>> {
            let note = magic_off.wrapping_sub(ELF_NOTE_SIZE);
            if rd32(note)? as usize != VMCOREINFO_MAGIC.len() || rd32(note.wrapping_add(8))? != 0 {
                return Ok(None);
            }
            let descsz = rd32(note.wrapping_add(4))?;
            if descsz == 0 {
                return Ok(None);
            }
            let data_off = magic_off.wrapping_add(VMCOREINFO_MAGIC_ALIGNED.len() as u64);
            let Some(data) = read_note_data(layer, data_off, descsz as u64)? else { return Ok(None) };
            if !data.starts_with(OSRELEASE_TAG) {
                return Ok(None);
            }
            Ok(data_to_dict(&data)?.map(|t| (note & mask, t)))
        })();
        match r {
            Ok(Some((off, t))) => f(off, &t),
            Ok(None) => true,
            Err(e) => {
                err = Some(e);
                false
            }
        }
    });
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_int_parsing() {
        assert_eq!(py_int("ffffffff9d63c000", 16), Some(0xffffffff9d63c000));
        assert_eq!(py_int("0x10", 16), Some(16));
        assert_eq!(py_int("  -12 ", 0), Some(-12));
        assert_eq!(py_int("0x1_0", 0), Some(16));
        assert_eq!(py_int("010", 0), None);
        assert_eq!(py_int("00", 0), Some(0));
        assert_eq!(py_int("", 0), None);
        assert_eq!(py_int("1__0", 0), None);
        assert_eq!(py_int("4096", 0), Some(4096));
    }

    #[test]
    fn parse_table() {
        let t = data_to_dict(b"OSRELEASE=6.8.0-139-generic\nPAGESIZE=4096\nSYMBOL(swapper_pg_dir)=ffffffff9d63c000\nKERNELOFFSET=1ca00000\nNUMBER(phys_base)=1470103552\n\nIGNORED=x\n")
            .unwrap()
            .unwrap();
        assert_eq!(t.str("OSRELEASE"), Some("6.8.0-139-generic"));
        assert_eq!(t.int("PAGESIZE"), Some(4096));
        assert_eq!(t.int("SYMBOL(swapper_pg_dir)"), Some(0xffffffff9d63c000));
        assert_eq!(t.int("KERNELOFFSET"), Some(0x1ca00000));
        assert_eq!(t.get("IGNORED"), None);
        assert!(data_to_dict(b"OSRELEASE=x\nNOEQUALS\n").is_err());
        assert_eq!(data_to_dict(b"OSRELEASE=x\x00").unwrap(), None);
    }
}
