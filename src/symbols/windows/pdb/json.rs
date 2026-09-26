// Derived from Volatility 3 (Volatility Software License 1.0): output format of
// framework/symbols/windows/pdbconv.py (`json.dumps(..., indent=2, sort_keys=True)`)
//! Minimal streaming JSON writer producing exactly what python's
//! `json.dumps(obj, indent=2, sort_keys=True)` (with the default `ensure_ascii=True`) produces.
//! Keys must be supplied already sorted by the caller.

use super::scan::find_json_escape;

pub(crate) struct JsonWriter {
    pub buf: Vec<u8>,
}

const HEX: &[u8; 16] = b"0123456789abcdef";

impl JsonWriter {
    pub fn with_capacity(n: usize) -> JsonWriter {
        JsonWriter { buf: Vec::with_capacity(n) }
    }

    #[inline]
    fn newline(&mut self, depth: usize) {
        const NL: &[u8; 33] = b"\n                                ";
        let n = 1 + 2 * depth;
        if n <= NL.len() {
            self.buf.extend_from_slice(&NL[..n]);
        } else {
            self.buf.push(b'\n');
            for _ in 0..depth {
                self.buf.extend_from_slice(b"  ");
            }
        }
    }

    /// Starts an object (`{`). Use [`JsonWriter::key`] for every member and
    /// [`JsonWriter::end_obj`] to close it. `depth` is the nesting level of the object itself.
    #[inline]
    pub fn begin_obj(&mut self) -> bool {
        self.buf.push(b'{');
        true
    }

    /// Writes the separator/indentation and `"key": ` for the next member of an object at
    /// nesting level `depth` (members are at `depth + 1`).
    #[inline]
    pub fn key_latin1(&mut self, first: &mut bool, depth: usize, key: &[u8]) {
        if !*first {
            self.buf.push(b',');
        }
        *first = false;
        self.newline(depth + 1);
        self.str_latin1(key);
        self.buf.extend_from_slice(b": ");
    }

    #[inline]
    pub fn key(&mut self, first: &mut bool, depth: usize, key: &str) {
        // All static keys are plain ASCII.
        self.key_latin1(first, depth, key.as_bytes());
    }

    /// Closes an object opened at nesting level `depth`; empty objects render as `{}`.
    #[inline]
    pub fn end_obj(&mut self, first: bool, depth: usize) {
        if !first {
            self.newline(depth);
        }
        self.buf.push(b'}');
    }

    #[inline]
    pub fn int(&mut self, v: i64) {
        const DIGITS: &[u8; 200] = b"\
            0001020304050607080910111213141516171819\
            2021222324252627282930313233343536373839\
            4041424344454647484950515253545556575859\
            6061626364656667686970717273747576777879\
            8081828384858687888990919293949596979899";
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        let mut u = v.unsigned_abs();
        while u >= 100 {
            let d = (u % 100) as usize * 2;
            u /= 100;
            i -= 2;
            tmp[i..i + 2].copy_from_slice(&DIGITS[d..d + 2]);
        }
        if u >= 10 {
            let d = u as usize * 2;
            i -= 2;
            tmp[i..i + 2].copy_from_slice(&DIGITS[d..d + 2]);
        } else {
            i -= 1;
            tmp[i] = b'0' + u as u8;
        }
        if v < 0 {
            self.buf.push(b'-');
        }
        self.buf.extend_from_slice(&tmp[i..]);
    }

    #[inline]
    pub fn boolean(&mut self, v: bool) {
        self.buf.extend_from_slice(if v { b"true" } else { b"false" });
    }

    #[inline]
    fn escape_u(&mut self, c: u32) {
        self.buf.extend_from_slice(b"\\u");
        for shift in [12u32, 8, 4, 0] {
            self.buf.push(HEX[((c >> shift) & 0xf) as usize]);
        }
    }

    #[inline]
    fn escape_char(&mut self, c: u32) {
        match c {
            0x22 => self.buf.extend_from_slice(b"\\\""),
            0x5c => self.buf.extend_from_slice(b"\\\\"),
            0x0a => self.buf.extend_from_slice(b"\\n"),
            0x0d => self.buf.extend_from_slice(b"\\r"),
            0x09 => self.buf.extend_from_slice(b"\\t"),
            0x08 => self.buf.extend_from_slice(b"\\b"),
            0x0c => self.buf.extend_from_slice(b"\\f"),
            0x20..=0x7e => self.buf.push(c as u8),
            0..=0xffff => self.escape_u(c),
            _ => {
                // UTF-16 surrogate pair, like python's ensure_ascii encoder
                let v = c - 0x10000;
                self.escape_u(0xd800 | ((v >> 10) & 0x3ff));
                self.escape_u(0xdc00 | (v & 0x3ff));
            }
        }
    }

    /// A string whose characters are the latin-1 decoding of `s` (python `str(bytes, "latin-1")`).
    #[inline]
    pub fn str_latin1(&mut self, s: &[u8]) {
        self.buf.push(b'"');
        match find_json_escape(s) {
            None => self.buf.extend_from_slice(s),
            Some(p) => {
                self.buf.extend_from_slice(&s[..p]);
                for &b in &s[p..] {
                    self.escape_char(b as u32);
                }
            }
        }
        self.buf.push(b'"');
    }

    /// A unicode string.
    pub fn str(&mut self, s: &str) {
        if find_json_escape(s.as_bytes()).is_none() {
            self.buf.push(b'"');
            self.buf.extend_from_slice(s.as_bytes());
            self.buf.push(b'"');
            return;
        }
        self.buf.push(b'"');
        for c in s.chars() {
            self.escape_char(c as u32);
        }
        self.buf.push(b'"');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_python() {
        let mut w = JsonWriter::with_capacity(64);
        w.str_latin1(b"a\"b\\c\n\x01\x7f\xe9 ~");
        assert_eq!(String::from_utf8(w.buf).unwrap(), r#""a\"b\\c\n\u0001\u007f\u00e9 ~""#);
        let mut w = JsonWriter::with_capacity(64);
        w.str("\u{1f600}\u{fffd}\t\x08\x0c\r");
        let bs = char::from(92);
        let want = format!("\"{bs}ud83d{bs}ude00{bs}ufffd{bs}t{bs}b{bs}f{bs}r\"");
        assert_eq!(String::from_utf8(w.buf).unwrap(), want);
    }

    #[test]
    fn layout_like_python() {
        let mut w = JsonWriter::with_capacity(64);
        let mut f = w.begin_obj();
        w.key(&mut f, 0, "a");
        let mut g = w.begin_obj();
        w.end_obj(g, 1);
        w.key(&mut f, 0, "b");
        g = w.begin_obj();
        w.key(&mut g, 1, "c");
        w.int(-12);
        w.key(&mut g, 1, "d");
        w.boolean(false);
        w.end_obj(g, 1);
        w.end_obj(f, 0);
        assert_eq!(
            String::from_utf8(w.buf).unwrap(),
            "{\n  \"a\": {},\n  \"b\": {\n    \"c\": -12,\n    \"d\": false\n  }\n}"
        );
        let mut w = JsonWriter::with_capacity(8);
        w.int(i64::MIN);
        assert_eq!(String::from_utf8(w.buf).unwrap(), i64::MIN.to_string());
    }
}
