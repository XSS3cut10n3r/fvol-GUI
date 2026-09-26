//! Fast JSON: a zero-copy pull parser ([`Parser`]) plus a small DOM ([`Json`]) built on it.
//!
//! The pull parser is what the ISF loader uses (no DOM allocation for 50 MB+ Linux ISFs):
//!
//! ```ignore
//! let mut p = Parser::new(bytes);
//! p.object(|p, key| {
//!     match key.as_ref() {
//!         "size" => size = p.u64()?,
//!         _ => p.skip()?,
//!     }
//!     Ok(())
//! })?;
//! ```
//!
//! Object key order is preserved everywhere (python dicts are insertion ordered, and several
//! volatility3 behaviours depend on that order). Strings without escapes are borrowed.
//! Numbers: integers up to 128 bits are kept exactly (python ints), others become f64.

use crate::error::{Error, Result};
use std::borrow::Cow;
use std::fmt::Write as _;

/// A parsed JSON value. Objects keep their key order (python dict semantics).
#[derive(Clone, Debug, PartialEq)]
pub enum Json<'a> {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(Cow<'a, str>),
    Arr(Vec<Json<'a>>),
    Obj(Vec<(Cow<'a, str>, Json<'a>)>),
}

impl<'a> Json<'a> {
    /// Parse a complete document.
    pub fn parse(buf: &'a [u8]) -> Result<Json<'a>> {
        let mut p = Parser::new(buf);
        let v = p.value()?;
        p.ws();
        if p.pos != p.buf.len() {
            return Err(p.err("trailing data"));
        }
        Ok(v)
    }

    /// Object member lookup (linear; fine for small objects). `None` for non-objects.
    pub fn get(&self, key: &str) -> Option<&Json<'a>> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    /// Nested lookup: `j.path(&["metadata", "windows", "pdb"])`.
    pub fn path(&self, keys: &[&str]) -> Option<&Json<'a>> {
        let mut cur = self;
        for k in keys {
            cur = cur.get(k)?;
        }
        Some(cur)
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Json::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Int(i) => u64::try_from(*i).ok(),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(i) => i64::try_from(*i).ok(),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Int(i) => Some(*i as f64),
            Json::Float(f) => Some(*f),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Json<'a>]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&[(Cow<'a, str>, Json<'a>)]> {
        match self {
            Json::Obj(o) => Some(o),
            _ => None,
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }
    /// Python truthiness (`if value:`): null/false/0/""/[]/{} are false.
    pub fn truthy(&self) -> bool {
        match self {
            Json::Null => false,
            Json::Bool(b) => *b,
            Json::Int(i) => *i != 0,
            Json::Float(f) => *f != 0.0,
            Json::Str(s) => !s.is_empty(),
            Json::Arr(a) => !a.is_empty(),
            Json::Obj(o) => !o.is_empty(),
        }
    }
    /// Deep-copy into an owned (`'static`) value.
    pub fn into_owned(self) -> Json<'static> {
        match self {
            Json::Null => Json::Null,
            Json::Bool(b) => Json::Bool(b),
            Json::Int(i) => Json::Int(i),
            Json::Float(f) => Json::Float(f),
            Json::Str(s) => Json::Str(Cow::Owned(s.into_owned())),
            Json::Arr(a) => Json::Arr(a.into_iter().map(|v| v.into_owned()).collect()),
            Json::Obj(o) => Json::Obj(o.into_iter().map(|(k, v)| (Cow::Owned(k.into_owned()), v.into_owned())).collect()),
        }
    }

    /// Serialize compactly (`json.dumps(obj, separators=(",", ":"))` style, but non-ASCII kept).
    pub fn to_string_compact(&self) -> String {
        let mut s = String::new();
        self.write_compact(&mut s);
        s
    }
    fn write_compact(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(i) => {
                let _ = write!(out, "{i}");
            }
            Json::Float(f) => {
                let _ = write!(out, "{f:?}");
            }
            Json::Str(s) => write_escaped(out, s),
            Json::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write_compact(out);
                }
                out.push(']');
            }
            Json::Obj(o) => {
                out.push('{');
                for (i, (k, v)) in o.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_escaped(out, k);
                    out.push(':');
                    v.write_compact(out);
                }
                out.push('}');
            }
        }
    }
}

/// Append `s` as a JSON string literal (quotes included).
pub fn write_escaped(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Kind of the next value, see [`Parser::peek_kind`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Null,
    Bool,
    Number,
    Str,
    Arr,
    Obj,
}

/// Zero-copy pull parser over a byte buffer.
pub struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
    /// the whole buffer is valid UTF-8 (checked once), so string slices need no validation
    utf8: bool,
}

#[inline(always)]
fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\n' | b'\r' | b'\t')
}

impl<'a> Parser<'a> {
    pub fn new(buf: &'a [u8]) -> Parser<'a> {
        // skip a UTF-8 BOM like python's utf-8-sig would not; json.load rejects BOMs, but be lenient
        let pos = if buf.starts_with(&[0xEF, 0xBB, 0xBF]) { 3 } else { 0 };
        // one validation pass for the whole document (std's ASCII fast path runs at many
        // GB/s); string slices cut at '"' boundaries of valid UTF-8 are then valid too
        let utf8 = std::str::from_utf8(buf).is_ok();
        Parser { buf, pos, utf8 }
    }

    #[inline(always)]
    fn slice_str(&self, s: &'a [u8]) -> Cow<'a, str> {
        if self.utf8 {
            // SAFETY: the whole buffer was validated and `s` is delimited by ASCII quotes
            Cow::Borrowed(unsafe { std::str::from_utf8_unchecked(s) })
        } else {
            match std::str::from_utf8(s) {
                Ok(s) => Cow::Borrowed(s),
                Err(_) => Cow::Owned(String::from_utf8_lossy(s).into_owned()),
            }
        }
    }

    /// Current byte offset.
    pub fn position(&self) -> usize {
        self.pos
    }

    #[cold]
    #[inline(never)]
    fn err(&self, what: &str) -> Error {
        Error::Msg(format!("JSON parse error at byte {}: {what}", self.pos))
    }

    #[inline(always)]
    fn ws(&mut self) {
        let buf = self.buf;
        let mut p = self.pos;
        // most values follow directly; pretty-printed input has "\n" + runs of spaces
        while p < buf.len() && is_ws(buf[p]) {
            p += 1;
            while p + 8 <= buf.len() && u64::from_le_bytes(buf[p..p + 8].try_into().unwrap()) == 0x2020_2020_2020_2020 {
                p += 8;
            }
        }
        self.pos = p;
    }

    #[inline(always)]
    fn next_nonws(&mut self) -> Result<u8> {
        if let Some(&b) = self.buf.get(self.pos) {
            if b > b' ' {
                return Ok(b);
            }
        }
        self.ws();
        match self.buf.get(self.pos) {
            Some(&b) => Ok(b),
            None => Err(self.err("unexpected end of input")),
        }
    }

    #[inline(always)]
    fn expect(&mut self, c: u8) -> Result<()> {
        if self.buf.get(self.pos) == Some(&c) {
            self.pos += 1;
            return Ok(());
        }
        self.expect_slow(c)
    }

    #[inline(never)]
    fn expect_slow(&mut self, c: u8) -> Result<()> {
        if self.next_nonws()? == c {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(&format!("expected '{}'", c as char)))
        }
    }

    /// Kind of the next value (skips whitespace).
    #[inline(always)]
    pub fn peek_kind(&mut self) -> Result<Kind> {
        Ok(match self.next_nonws()? {
            b'n' => Kind::Null,
            b't' | b'f' => Kind::Bool,
            b'"' => Kind::Str,
            b'[' => Kind::Arr,
            b'{' => Kind::Obj,
            b'-' | b'0'..=b'9' => Kind::Number,
            _ => return Err(self.err("unexpected character")),
        })
    }

    /// Begin an object. Returns false (and consumes `{}`) if it is empty.
    #[inline(always)]
    pub fn obj_begin(&mut self) -> Result<bool> {
        self.expect(b'{')?;
        if self.next_nonws()? == b'}' {
            self.pos += 1;
            return Ok(false);
        }
        // next_nonws skipped the whitespace: positioned on the first key's quote
        Ok(true)
    }

    /// Read an object key and the following ':'.
    #[inline(always)]
    pub fn key(&mut self) -> Result<Cow<'a, str>> {
        let k = self.str()?;
        self.expect(b':')?;
        // position on the value so its delimiter check hits the fast path
        self.ws();
        Ok(k)
    }

    /// After a member value: true if another member follows (consumes ','), false at '}'.
    #[inline(always)]
    pub fn obj_more(&mut self) -> Result<bool> {
        match self.next_nonws()? {
            b',' => {
                self.pos += 1;
                self.ws();
                Ok(true)
            }
            b'}' => {
                self.pos += 1;
                Ok(false)
            }
            _ => Err(self.err("expected ',' or '}'")),
        }
    }

    /// Iterate an object's members; `f` must consume the value (or call `p.skip()`).
    pub fn object<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(&mut Parser<'a>, Cow<'a, str>) -> Result<()>,
    {
        if !self.obj_begin()? {
            return Ok(());
        }
        loop {
            let k = self.key()?;
            f(self, k)?;
            if !self.obj_more()? {
                return Ok(());
            }
        }
    }

    /// Begin an array. Returns false (and consumes `[]`) if it is empty.
    pub fn arr_begin(&mut self) -> Result<bool> {
        self.expect(b'[')?;
        if self.next_nonws()? == b']' {
            self.pos += 1;
            return Ok(false);
        }
        Ok(true)
    }

    /// After an element: true if another element follows (consumes ','), false at ']'.
    pub fn arr_more(&mut self) -> Result<bool> {
        match self.next_nonws()? {
            b',' => {
                self.pos += 1;
                self.ws();
                Ok(true)
            }
            b']' => {
                self.pos += 1;
                Ok(false)
            }
            _ => Err(self.err("expected ',' or ']'")),
        }
    }

    /// Iterate an array's elements; `f` must consume each element.
    pub fn array<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(&mut Parser<'a>) -> Result<()>,
    {
        if !self.arr_begin()? {
            return Ok(());
        }
        loop {
            f(self)?;
            if !self.arr_more()? {
                return Ok(());
            }
        }
    }

    /// Parse a string value.
    #[inline]
    pub fn str(&mut self) -> Result<Cow<'a, str>> {
        self.expect(b'"')?;
        let start = self.pos;
        let buf = self.buf;
        let mut i = start;
        // fast scan for '"' or '\\' (or control chars, which are invalid but we tolerate)
        loop {
            // SWAR: process 8 bytes at a time
            while i + 8 <= buf.len() {
                let w = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
                let q = w ^ 0x2222_2222_2222_2222; // '"'
                let b = w ^ 0x5c5c_5c5c_5c5c_5c5c; // '\\'
                let hq = q.wrapping_sub(0x0101_0101_0101_0101) & !q & 0x8080_8080_8080_8080;
                let hb = b.wrapping_sub(0x0101_0101_0101_0101) & !b & 0x8080_8080_8080_8080;
                let h = hq | hb;
                if h != 0 {
                    i += (h.trailing_zeros() / 8) as usize;
                    break;
                }
                i += 8;
            }
            if i >= buf.len() {
                return Err(self.err("unterminated string"));
            }
            match buf[i] {
                b'"' => {
                    let s = &buf[start..i];
                    self.pos = i + 1;
                    return Ok(self.slice_str(s));
                }
                b'\\' => {
                    self.pos = start;
                    return self.str_escaped(i).map(Cow::Owned);
                }
                _ => i += 1,
            }
        }
    }

    #[cold]
    fn str_escaped(&mut self, first_esc: usize) -> Result<String> {
        let buf = self.buf;
        let mut out: Vec<u8> = Vec::with_capacity(first_esc - self.pos + 16);
        out.extend_from_slice(&buf[self.pos..first_esc]);
        let mut i = first_esc;
        loop {
            let c = *buf.get(i).ok_or_else(|| self.err("unterminated string"))?;
            match c {
                b'"' => {
                    self.pos = i + 1;
                    return Ok(match String::from_utf8(out) {
                        Ok(s) => s,
                        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
                    });
                }
                b'\\' => {
                    let e = *buf.get(i + 1).ok_or_else(|| self.err("bad escape"))?;
                    i += 2;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let cp = self.hex4(i)?;
                            i += 4;
                            let ch = if (0xD800..0xDC00).contains(&cp) {
                                // high surrogate: try to combine
                                if buf.get(i) == Some(&b'\\') && buf.get(i + 1) == Some(&b'u') {
                                    let lo = self.hex4(i + 2)?;
                                    if (0xDC00..0xE000).contains(&lo) {
                                        i += 6;
                                        char::from_u32(0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00))
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                char::from_u32(cp)
                            };
                            let ch = ch.unwrap_or('\u{FFFD}');
                            let mut tmp = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                        }
                        _ => return Err(self.err("bad escape")),
                    }
                }
                _ => {
                    out.push(c);
                    i += 1;
                }
            }
        }
    }

    fn hex4(&self, at: usize) -> Result<u32> {
        let s = self.buf.get(at..at + 4).ok_or_else(|| self.err("bad \\u escape"))?;
        let mut v = 0u32;
        for &c in s {
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(self.err("bad \\u escape")),
            };
            v = v * 16 + d as u32;
        }
        Ok(v)
    }

    /// Parse a number: `Ok(Json::Int)` or `Ok(Json::Float)`.
    #[inline]
    pub fn number(&mut self) -> Result<Json<'static>> {
        self.ws();
        let buf = self.buf;
        let start = self.pos;
        let mut i = start;
        let neg = buf.get(i) == Some(&b'-');
        if neg {
            i += 1;
        }
        let dstart = i;
        // fast path: up to 19 digits fit in u64 without overflow checks
        let mut v64: u64 = 0;
        while i < buf.len() && i - dstart < 19 && buf[i].is_ascii_digit() {
            v64 = v64 * 10 + (buf[i] - b'0') as u64;
            i += 1;
        }
        let mut v: u128 = v64 as u128;
        let mut overflow = false;
        while i < buf.len() && buf[i].is_ascii_digit() {
            match v.checked_mul(10).and_then(|x| x.checked_add((buf[i] - b'0') as u128)) {
                Some(x) => v = x,
                None => overflow = true,
            }
            i += 1;
        }
        if i == dstart {
            return Err(self.err("invalid number"));
        }
        let is_float = i < buf.len() && matches!(buf[i], b'.' | b'e' | b'E');
        if !is_float && !overflow && v <= i128::MAX as u128 {
            self.pos = i;
            let v = v as i128;
            return Ok(Json::Int(if neg { -v } else { v }));
        }
        // float (or huge int)
        while i < buf.len() && matches!(buf[i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
            i += 1;
        }
        let s = std::str::from_utf8(&buf[start..i]).map_err(|_| self.err("invalid number"))?;
        let f: f64 = s.parse().map_err(|_| self.err("invalid number"))?;
        self.pos = i;
        Ok(Json::Float(f))
    }

    /// Parse an integer value (floats are an error).
    #[inline]
    pub fn int(&mut self) -> Result<i128> {
        match self.number()? {
            Json::Int(i) => Ok(i),
            _ => Err(self.err("expected integer")),
        }
    }
    /// Parse an integer that must fit in u64.
    #[inline]
    pub fn u64(&mut self) -> Result<u64> {
        let i = self.int()?;
        u64::try_from(i).map_err(|_| self.err("integer out of u64 range"))
    }
    /// Parse an integer that must fit in i64.
    #[inline]
    pub fn i64(&mut self) -> Result<i64> {
        let i = self.int()?;
        i64::try_from(i).map_err(|_| self.err("integer out of i64 range"))
    }

    /// Parse `true` / `false`.
    pub fn bool(&mut self) -> Result<bool> {
        self.ws();
        if self.buf[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(true)
        } else if self.buf[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(false)
        } else {
            Err(self.err("expected boolean"))
        }
    }

    /// Consume `null` if present; returns whether it was null.
    pub fn null(&mut self) -> Result<bool> {
        self.ws();
        if self.buf[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Skip over any value without allocating.
    pub fn skip(&mut self) -> Result<()> {
        match self.next_nonws()? {
            b'"' => {
                // fast skip of a string
                self.pos += 1;
                let buf = self.buf;
                let mut i = self.pos;
                while i < buf.len() {
                    match buf[i] {
                        b'"' => {
                            self.pos = i + 1;
                            return Ok(());
                        }
                        b'\\' => i += 2,
                        _ => i += 1,
                    }
                }
                Err(self.err("unterminated string"))
            }
            b'{' | b'[' => {
                // skip nested structure by bracket counting (strings handled)
                let buf = self.buf;
                let mut depth = 0usize;
                let mut i = self.pos;
                while i < buf.len() {
                    match buf[i] {
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => {
                            depth -= 1;
                            if depth == 0 {
                                self.pos = i + 1;
                                return Ok(());
                            }
                        }
                        b'"' => {
                            i += 1;
                            while i < buf.len() && buf[i] != b'"' {
                                if buf[i] == b'\\' {
                                    i += 1;
                                }
                                i += 1;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                Err(self.err("unterminated structure"))
            }
            b't' | b'f' => self.bool().map(|_| ()),
            b'n' => {
                if self.null()? {
                    Ok(())
                } else {
                    Err(self.err("expected null"))
                }
            }
            _ => self.number().map(|_| ()),
        }
    }

    /// Parse any value into a DOM.
    pub fn value(&mut self) -> Result<Json<'a>> {
        Ok(match self.peek_kind()? {
            Kind::Null => {
                self.null()?;
                Json::Null
            }
            Kind::Bool => Json::Bool(self.bool()?),
            Kind::Number => self.number()?,
            Kind::Str => Json::Str(self.str()?),
            Kind::Arr => {
                let mut v = Vec::new();
                self.array(|p| {
                    v.push(p.value()?);
                    Ok(())
                })?;
                Json::Arr(v)
            }
            Kind::Obj => {
                let mut v = Vec::new();
                self.object(|p, k| {
                    let val = p.value()?;
                    v.push((k, val));
                    Ok(())
                })?;
                Json::Obj(v)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dom() {
        let u = |h: &str| format!("{}{}{}", '\\', 'u', h);
        let doc = format!(
            r#" {{"a": [1, -2, 3.5, true, null, "x\"y{}{}{}"], "b": {{"c": 18446744073709551615}}}} "#,
            u("00e9"),
            u("d83d"),
            u("de00")
        );
        let j = Json::parse(doc.as_bytes()).unwrap();
        assert_eq!(j.path(&["b", "c"]).unwrap().as_u64(), Some(u64::MAX));
        let a = j.get("a").unwrap().as_array().unwrap();
        assert_eq!(a[0], Json::Int(1));
        assert_eq!(a[1], Json::Int(-2));
        assert_eq!(a[2], Json::Float(3.5));
        assert_eq!(a[3], Json::Bool(true));
        assert!(a[4].is_null());
        assert_eq!(a[5].as_str(), Some("x\"y\u{e9}\u{1F600}"));
        let s = j.to_string_compact();
        assert_eq!(Json::parse(s.as_bytes()).unwrap(), j);
    }

    #[test]
    fn pull_and_skip() {
        let data = br#"{"skipme": {"x": [1, {"y": "}]"}], "z": "a\\\"b"}, "keep": 42, "e": {}, "f": []}"#;
        let mut p = Parser::new(data);
        let mut keep = 0;
        p.object(|p, k| {
            match k.as_ref() {
                "keep" => keep = p.u64()?,
                _ => p.skip()?,
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(keep, 42);
    }

    #[test]
    fn errors() {
        assert!(Json::parse(b"{").is_err());
        assert!(Json::parse(b"[1,]").is_err());
        assert!(Json::parse(b"\"abc").is_err());
        assert!(Json::parse(b"{} x").is_err());
    }
}
