//! Minimal JSON reader / writer with python `json` semantics, for `-c` config files,
//! `--save-config`, `-e` values and `vol.json` defaults.

use crate::renderers::pyfmt::{push_float, push_i128, push_json_str};

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    /// insertion ordered, like a python dict
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Obj(v) => v.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> &[Json] {
        match self {
            Json::Arr(v) => v,
            _ => &[],
        }
    }

    /// python `json.dumps(v, sort_keys=True, indent=indent)`
    pub fn dump(&self, indent: Option<usize>) -> String {
        let mut out = Vec::new();
        self.write(&mut out, indent, 0);
        String::from_utf8(out).unwrap_or_default()
    }

    fn write(&self, out: &mut Vec<u8>, indent: Option<usize>, level: usize) {
        let nl = |out: &mut Vec<u8>, level: usize| {
            if let Some(n) = indent {
                out.push(b'\n');
                for _ in 0..n * level {
                    out.push(b' ');
                }
            }
        };
        let sep: &[u8] = if indent.is_some() { b"," } else { b", " };
        match self {
            Json::Null => out.extend_from_slice(b"null"),
            Json::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
            Json::Int(i) => push_i128(out, *i),
            Json::Float(f) => {
                if f.is_nan() {
                    out.extend_from_slice(b"NaN")
                } else if f.is_infinite() {
                    out.extend_from_slice(if *f > 0.0 { b"Infinity" } else { b"-Infinity" })
                } else {
                    push_float(out, *f)
                }
            }
            Json::Str(s) => push_json_str(out, s),
            Json::Arr(v) => {
                if v.is_empty() {
                    out.extend_from_slice(b"[]");
                    return;
                }
                out.push(b'[');
                for (i, x) in v.iter().enumerate() {
                    if i > 0 {
                        out.extend_from_slice(sep);
                    }
                    nl(out, level + 1);
                    x.write(out, indent, level + 1);
                }
                nl(out, level);
                out.push(b']');
            }
            Json::Obj(v) => {
                if v.is_empty() {
                    out.extend_from_slice(b"{}");
                    return;
                }
                // python dicts keep the last value of duplicate keys
                let mut items: Vec<&(String, Json)> = Vec::new();
                for it in v {
                    match items.iter().position(|x| x.0 == it.0) {
                        Some(p) => items[p] = it,
                        None => items.push(it),
                    }
                }
                items.sort_by(|a, b| a.0.cmp(&b.0));
                out.push(b'{');
                for (i, (k, x)) in items.iter().map(|p| (&p.0, &p.1)).enumerate() {
                    if i > 0 {
                        out.extend_from_slice(sep);
                    }
                    nl(out, level + 1);
                    push_json_str(out, k);
                    out.extend_from_slice(b": ");
                    x.write(out, indent, level + 1);
                }
                nl(out, level);
                out.push(b'}');
            }
        }
    }
}

/// Parse error with python's `json.JSONDecodeError`-like message.
#[derive(Debug, Clone)]
pub struct JsonError(pub String);

struct P<'a> {
    s: &'a [u8],
    i: usize,
}

impl P<'_> {
    fn err<T>(&self, msg: &str) -> Result<T, JsonError> {
        Err(JsonError(format!("{msg}: char {}", self.i)))
    }
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn lit(&mut self, l: &[u8], v: Json) -> Result<Json, JsonError> {
        if self.s[self.i..].starts_with(l) {
            self.i += l.len();
            Ok(v)
        } else {
            self.err("Expecting value")
        }
    }
    fn value(&mut self) -> Result<Json, JsonError> {
        self.ws();
        let c = match self.s.get(self.i) {
            Some(c) => *c,
            None => return self.err("Expecting value"),
        };
        match c {
            b'n' => self.lit(b"null", Json::Null),
            b't' => self.lit(b"true", Json::Bool(true)),
            b'f' => self.lit(b"false", Json::Bool(false)),
            b'N' => self.lit(b"NaN", Json::Float(f64::NAN)),
            b'I' => self.lit(b"Infinity", Json::Float(f64::INFINITY)),
            b'"' => Ok(Json::Str(self.string()?)),
            b'[' => {
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Json::Arr(v));
                }
                loop {
                    v.push(self.value()?);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Json::Arr(v));
                        }
                        _ => return self.err("Expecting ',' delimiter"),
                    }
                }
            }
            b'{' => {
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Json::Obj(v));
                }
                loop {
                    self.ws();
                    if self.s.get(self.i) != Some(&b'"') {
                        return self.err("Expecting property name enclosed in double quotes");
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.s.get(self.i) != Some(&b':') {
                        return self.err("Expecting ':' delimiter");
                    }
                    self.i += 1;
                    let x = self.value()?;
                    v.push((k, x));
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Json::Obj(v));
                        }
                        _ => return self.err("Expecting ',' delimiter"),
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                if self.s[self.i..].starts_with(b"-Infinity") {
                    self.i += 9;
                    return Ok(Json::Float(f64::NEG_INFINITY));
                }
                let st = self.i;
                if self.s[self.i] == b'-' {
                    self.i += 1;
                }
                let mut float = false;
                while let Some(&c) = self.s.get(self.i) {
                    match c {
                        b'0'..=b'9' => {}
                        b'.' | b'e' | b'E' | b'+' | b'-' => float = true,
                        _ => break,
                    }
                    self.i += 1;
                }
                let t = std::str::from_utf8(&self.s[st..self.i]).unwrap_or("");
                if float {
                    t.parse::<f64>().map(Json::Float).or_else(|_| self.err("Expecting value"))
                } else {
                    t.parse::<i128>().map(Json::Int).or_else(|_| self.err("Expecting value"))
                }
            }
            _ => self.err("Expecting value"),
        }
    }
    fn string(&mut self) -> Result<String, JsonError> {
        self.i += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = match self.s.get(self.i) {
                Some(c) => *c,
                None => return self.err("Unterminated string starting at"),
            };
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = match self.s.get(self.i) {
                        Some(e) => *e,
                        None => return self.err("Unterminated string starting at"),
                    };
                    self.i += 1;
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
                            let mut cp = self.hex4()?;
                            if (0xd800..0xdc00).contains(&cp) && self.s[self.i..].starts_with(b"\\u") {
                                let save = self.i;
                                self.i += 2;
                                let lo = self.hex4()?;
                                if (0xdc00..0xe000).contains(&lo) {
                                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                                } else {
                                    self.i = save;
                                }
                            }
                            let ch = char::from_u32(cp).unwrap_or('\u{fffd}');
                            let mut b = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
                        }
                        _ => return self.err("Invalid \\escape"),
                    }
                }
                c if c < 0x20 => return self.err("Invalid control character at"),
                c => out.push(c),
            }
        }
        String::from_utf8(out).or_else(|_| self.err("invalid utf-8"))
    }
    fn hex4(&mut self) -> Result<u32, JsonError> {
        let h = self.s.get(self.i..self.i + 4).and_then(|h| std::str::from_utf8(h).ok());
        match h.and_then(|h| u32::from_str_radix(h, 16).ok()) {
            Some(v) => {
                self.i += 4;
                Ok(v)
            }
            None => self.err("Invalid \\uXXXX escape"),
        }
    }
}

/// python `json.loads`
pub fn parse(text: &str) -> Result<Json, JsonError> {
    let mut p = P { s: text.as_bytes(), i: 0 };
    let v = p.value()?;
    p.ws();
    if p.i != p.s.len() {
        return p.err("Extra data");
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let bs = '\\';
        let src = format!(r#"{{"b": [1, {{"x": []}}], "a": "{bs}u00e9{bs}ud83d{bs}ude00", "c": {{}}, "d": null, "e": 1.5}}"#);
        let v = parse(&src).unwrap();
        assert_eq!(v.get("a").and_then(|a| a.as_str()), Some("\u{e9}\u{1f600}"));
        let want = format!(r#"{{"a": "{bs}u00e9{bs}ud83d{bs}ude00", "b": [1, {{"x": []}}], "c": {{}}, "d": null, "e": 1.5}}"#);
        assert_eq!(v.dump(None), want);
        assert_eq!(parse("[1,\n 2]").unwrap().dump(Some(2)), "[\n  1,\n  2\n]");
        assert!(parse("[1,]").is_err());
    }
}
