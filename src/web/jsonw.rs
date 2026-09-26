//! Minimal JSON writing (UTF-8 passthrough) for the web API. Reading uses `cli::json::parse`.

/// Append `s` as a JSON string literal.
pub fn str(out: &mut Vec<u8>, s: &str) {
    escape_into(out, s.as_bytes())
}

/// Append (lossy UTF-8) bytes as a JSON string literal.
pub fn bytes_str(out: &mut Vec<u8>, b: &[u8]) {
    match std::str::from_utf8(b) {
        Ok(_) => escape_into(out, b),
        Err(_) => escape_into(out, String::from_utf8_lossy(b).as_bytes()),
    }
}

/// `b` must be valid UTF-8.
fn escape_into(out: &mut Vec<u8>, b: &[u8]) {
    out.push(b'"');
    let mut start = 0;
    for (i, &c) in b.iter().enumerate() {
        let esc: &[u8] = match c {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            0..=0x1f | 0x7f => b"",
            _ => continue,
        };
        out.extend_from_slice(&b[start..i]);
        if esc.is_empty() {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.extend_from_slice(b"\\u00");
            out.push(HEX[(c >> 4) as usize]);
            out.push(HEX[(c & 15) as usize]);
        } else {
            out.extend_from_slice(esc);
        }
        start = i + 1;
    }
    out.extend_from_slice(&b[start..]);
    out.push(b'"');
}

/// A tiny JSON builder that places commas itself.
pub struct W {
    pub out: Vec<u8>,
    first: Vec<bool>,
    after_key: bool,
}

impl Default for W {
    fn default() -> Self {
        W::new()
    }
}

impl W {
    pub fn new() -> W {
        W { out: Vec::with_capacity(512), first: Vec::new(), after_key: false }
    }
    fn sep(&mut self) {
        if self.after_key {
            self.after_key = false;
            return;
        }
        if let Some(f) = self.first.last_mut() {
            if *f {
                *f = false;
            } else {
                self.out.push(b',');
            }
        }
    }
    pub fn obj(&mut self) -> &mut Self {
        self.sep();
        self.out.push(b'{');
        self.first.push(true);
        self
    }
    pub fn arr(&mut self) -> &mut Self {
        self.sep();
        self.out.push(b'[');
        self.first.push(true);
        self
    }
    pub fn end_obj(&mut self) -> &mut Self {
        self.first.pop();
        self.out.push(b'}');
        self
    }
    pub fn end_arr(&mut self) -> &mut Self {
        self.first.pop();
        self.out.push(b']');
        self
    }
    pub fn key(&mut self, k: &str) -> &mut Self {
        self.sep();
        str(&mut self.out, k);
        self.out.push(b':');
        self.after_key = true;
        self
    }
    pub fn s(&mut self, v: &str) -> &mut Self {
        self.sep();
        str(&mut self.out, v);
        self
    }
    pub fn sb(&mut self, v: &[u8]) -> &mut Self {
        self.sep();
        bytes_str(&mut self.out, v);
        self
    }
    pub fn i(&mut self, v: i128) -> &mut Self {
        self.sep();
        self.out.extend_from_slice(v.to_string().as_bytes());
        self
    }
    pub fn u(&mut self, v: u64) -> &mut Self {
        self.i(v as i128)
    }
    pub fn f(&mut self, v: f64) -> &mut Self {
        self.sep();
        if v.is_finite() {
            self.out.extend_from_slice(format!("{v}").as_bytes());
        } else {
            self.out.extend_from_slice(b"null");
        }
        self
    }
    pub fn b(&mut self, v: bool) -> &mut Self {
        self.sep();
        self.out.extend_from_slice(if v { b"true" } else { b"false" });
        self
    }
    pub fn null(&mut self) -> &mut Self {
        self.sep();
        self.out.extend_from_slice(b"null");
        self
    }
    /// Pre-serialized JSON value.
    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.sep();
        self.out.extend_from_slice(v);
        self
    }
    pub fn opt_s(&mut self, v: Option<&str>) -> &mut Self {
        match v {
            Some(s) => self.s(s),
            None => self.null(),
        }
    }
    pub fn ks(&mut self, k: &str, v: &str) -> &mut Self {
        self.key(k).s(v)
    }
    pub fn ki(&mut self, k: &str, v: i128) -> &mut Self {
        self.key(k).i(v)
    }
    pub fn ku(&mut self, k: &str, v: u64) -> &mut Self {
        self.key(k).u(v)
    }
    pub fn kb(&mut self, k: &str, v: bool) -> &mut Self {
        self.key(k).b(v)
    }
    pub fn done(self) -> Vec<u8> {
        self.out
    }
}
