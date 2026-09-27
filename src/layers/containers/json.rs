//! Minimal strict JSON parser with python `json.loads` acceptance rules (NaN/Infinity allowed,
//! no trailing data, no control characters in strings, last duplicate key wins), used for the
//! QEMU savevm configuration. Part of fastvol (Volatility Software License 1.0).

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    /// Integers that fit in i128 (python ints are unbounded; larger ones become `BigInt`).
    Int(i128),
    BigInt,
    Float(f64),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    /// python `dict.get(key)`; Err when self is not a dict (AttributeError in python).
    pub fn get(&self, key: &str) -> Result<Option<&Value>, ()> {
        match self {
            Value::Obj(items) => Ok(items.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v)),
            _ => Err(()),
        }
    }
}

const MAX_DEPTH: usize = 900;

pub(crate) fn parse(bytes: &[u8]) -> Result<Value, ()> {
    let s = std::str::from_utf8(bytes).map_err(|_| ())?;
    let b = s.as_bytes();
    let mut p = Parser { b, i: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != b.len() {
        return Err(());
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &str) -> bool {
        if self.b[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ()> {
        if depth > MAX_DEPTH {
            return Err(());
        }
        let c = *self.b.get(self.i).ok_or(())?;
        match c {
            b'{' => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.eat("}") {
                    return Ok(Value::Obj(items));
                }
                loop {
                    self.ws();
                    if self.b.get(self.i) != Some(&b'"') {
                        return Err(());
                    }
                    let k = self.string()?;
                    self.ws();
                    if !self.eat(":") {
                        return Err(());
                    }
                    self.ws();
                    let v = self.value(depth + 1)?;
                    items.push((k, v));
                    self.ws();
                    if self.eat(",") {
                        continue;
                    }
                    if self.eat("}") {
                        return Ok(Value::Obj(items));
                    }
                    return Err(());
                }
            }
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.eat("]") {
                    return Ok(Value::Arr(items));
                }
                loop {
                    self.ws();
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    if self.eat(",") {
                        continue;
                    }
                    if self.eat("]") {
                        return Ok(Value::Arr(items));
                    }
                    return Err(());
                }
            }
            b'"' => Ok(Value::Str(self.string()?)),
            b'n' if self.eat("null") => Ok(Value::Null),
            b't' if self.eat("true") => Ok(Value::Bool(true)),
            b'f' if self.eat("false") => Ok(Value::Bool(false)),
            b'N' if self.eat("NaN") => Ok(Value::Float(f64::NAN)),
            b'I' if self.eat("Infinity") => Ok(Value::Float(f64::INFINITY)),
            b'-' if self.b[self.i..].starts_with(b"-Infinity") => {
                self.i += 9;
                Ok(Value::Float(f64::NEG_INFINITY))
            }
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(()),
        }
    }

    fn number(&mut self) -> Result<Value, ()> {
        let start = self.i;
        let digits = |p: &mut Self| {
            let s = p.i;
            while p.i < p.b.len() && p.b[p.i].is_ascii_digit() {
                p.i += 1;
            }
            p.i - s
        };
        if self.b[self.i] == b'-' {
            self.i += 1;
        }
        // -?(0|[1-9]\d*)
        match self.b.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                digits(self);
            }
            _ => return Err(()),
        }
        let mut float = false;
        // (\.\d+)? — python only takes the fraction when digits follow
        if self.b.get(self.i) == Some(&b'.') && self.b.get(self.i + 1).is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
            digits(self);
            float = true;
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            let save = self.i;
            self.i += 1;
            if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if digits(self) == 0 {
                self.i = save;
            } else {
                float = true;
            }
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| ())?;
        if float {
            text.parse::<f64>().map(Value::Float).map_err(|_| ())
        } else {
            Ok(text.parse::<i128>().map(Value::Int).unwrap_or(Value::BigInt))
        }
    }

    fn hex4(&mut self) -> Result<u32, ()> {
        let h = self.b.get(self.i..self.i + 4).ok_or(())?;
        let s = std::str::from_utf8(h).map_err(|_| ())?;
        if !s.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(());
        }
        self.i += 4;
        u32::from_str_radix(s, 16).map_err(|_| ())
    }

    fn string(&mut self) -> Result<String, ()> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let start = self.i;
            while self.i < self.b.len() && self.b[self.i] != b'"' && self.b[self.i] != b'\\' && self.b[self.i] >= 0x20 {
                self.i += 1;
            }
            // the input is valid utf-8 and we only stop at ASCII bytes
            out.push_str(std::str::from_utf8(&self.b[start..self.i]).map_err(|_| ())?);
            match self.b.get(self.i) {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let c = *self.b.get(self.i).ok_or(())?;
                    self.i += 1;
                    match c {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut u = self.hex4()?;
                            if (0xd800..0xdc00).contains(&u) && self.b[self.i..].starts_with(b"\\u") {
                                let save = self.i;
                                self.i += 2;
                                let lo = self.hex4()?;
                                if (0xdc00..0xe000).contains(&lo) {
                                    u = 0x10000 + ((u - 0xd800) << 10) + (lo - 0xdc00);
                                } else {
                                    self.i = save;
                                }
                            }
                            // lone surrogates are legal in python str; keep a replacement char
                            out.push(char::from_u32(u).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err(()),
                    }
                }
                _ => return Err(()), // end of input or control character
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_compat() {
        let v = parse(br#" {"page_size": 4096, "devices": [{"vmsd_name": "PIIX3"}], "a": 1, "a": 2} "#).unwrap();
        assert_eq!(v.get("page_size").unwrap(), Some(&Value::Int(4096)));
        assert_eq!(v.get("a").unwrap(), Some(&Value::Int(2)));
        assert_eq!(v.get("zz").unwrap(), None);
        assert!(parse(b"{} x").is_err());
        assert!(parse(b"[1,]").is_err());
        assert!(parse(b"\"a\x01\"").is_err());
        assert!(parse(b"01").is_err());
        assert_eq!(parse(b"[NaN, -Infinity, 1e3, 1.5, -0]").unwrap().get("x"), Err(()));
        assert!(matches!(parse(b"123456789012345678901234567890123456789012").unwrap(), Value::BigInt));
        let esc = [b'"', b'\\', b'u', b'0', b'0', b'e', b'9', b'\\', b'u', b'd', b'8', b'3', b'd', b'\\', b'u', b'd', b'e', b'0', b'0', b'"'];
        assert_eq!(parse(&esc).unwrap(), Value::Str("\u{e9}\u{1f600}".into()));
        let deep = "[".repeat(2000);
        assert!(parse(deep.as_bytes()).is_err());
    }
}
