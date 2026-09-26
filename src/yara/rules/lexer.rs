//! YARA rule-language tokenizer, a hand-written equivalent of libyara 4.5
//! `lexer.l` (flex longest-match semantics, same token classes, same errors).
//!
//! Error model (mirrors flex + `yyterminate()`): a lexical error is reported and
//! the token stream then ends (the parser sees end-of-file, which usually adds a
//! "syntax error, unexpected end of file"). `include` directives report an error
//! but lexing continues after them (libyara's include action does not terminate).
//! After the real end of input libyara's `yylineno` reads 0, which is what error
//! messages produced at that point show; `line()` reproduces that.

/// Keyword tokens (lexer.l keyword rules, which win over identifiers of the same
/// length because they are listed first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kw {
    Private,
    Global,
    Rule,
    Meta,
    Strings,
    Ascii,
    Wide,
    Xor,
    Base64,
    Base64Wide,
    Fullword,
    Nocase,
    Condition,
    True,
    False,
    Not,
    And,
    Or,
    At,
    In,
    Of,
    Them,
    For,
    All,
    Any,
    None,
    Entrypoint,
    Filesize,
    Matches,
    Contains,
    Startswith,
    Endswith,
    Icontains,
    Istartswith,
    Iendswith,
    Iequals,
    Import,
    Defined,
}

impl Kw {
    fn from_word(w: &[u8]) -> Option<Kw> {
        Some(match w {
            b"private" => Kw::Private,
            b"global" => Kw::Global,
            b"rule" => Kw::Rule,
            b"meta" => Kw::Meta,
            b"strings" => Kw::Strings,
            b"ascii" => Kw::Ascii,
            b"wide" => Kw::Wide,
            b"xor" => Kw::Xor,
            b"base64" => Kw::Base64,
            b"base64wide" => Kw::Base64Wide,
            b"fullword" => Kw::Fullword,
            b"nocase" => Kw::Nocase,
            b"condition" => Kw::Condition,
            b"true" => Kw::True,
            b"false" => Kw::False,
            b"not" => Kw::Not,
            b"and" => Kw::And,
            b"or" => Kw::Or,
            b"at" => Kw::At,
            b"in" => Kw::In,
            b"of" => Kw::Of,
            b"them" => Kw::Them,
            b"for" => Kw::For,
            b"all" => Kw::All,
            b"any" => Kw::Any,
            b"none" => Kw::None,
            b"entrypoint" => Kw::Entrypoint,
            b"filesize" => Kw::Filesize,
            b"matches" => Kw::Matches,
            b"contains" => Kw::Contains,
            b"startswith" => Kw::Startswith,
            b"endswith" => Kw::Endswith,
            b"icontains" => Kw::Icontains,
            b"istartswith" => Kw::Istartswith,
            b"iendswith" => Kw::Iendswith,
            b"iequals" => Kw::Iequals,
            b"import" => Kw::Import,
            b"defined" => Kw::Defined,
            _ => return None,
        })
    }

    /// Bison token name (`%token ... "<name>"` in grammar.y).
    pub fn name(self) -> &'static str {
        match self {
            Kw::Private => "<private>",
            Kw::Global => "<global>",
            Kw::Rule => "<rule>",
            Kw::Meta => "<meta>",
            Kw::Strings => "<strings>",
            Kw::Ascii => "<ascii>",
            Kw::Wide => "<wide>",
            Kw::Xor => "<xor>",
            Kw::Base64 => "<base64>",
            Kw::Base64Wide => "<base64wide>",
            Kw::Fullword => "<fullword>",
            Kw::Nocase => "<nocase>",
            Kw::Condition => "<condition>",
            Kw::True => "<true>",
            Kw::False => "<false>",
            Kw::Not => "<not>",
            Kw::And => "<and>",
            Kw::Or => "<or>",
            Kw::At => "<at>",
            Kw::In => "<in>",
            Kw::Of => "<of>",
            Kw::Them => "<them>",
            Kw::For => "<for>",
            Kw::All => "<all>",
            Kw::Any => "<any>",
            Kw::None => "<none>",
            Kw::Entrypoint => "<entrypoint>",
            Kw::Filesize => "<filesize>",
            Kw::Matches => "<matches>",
            Kw::Contains => "<contains>",
            Kw::Startswith => "<startswith>",
            Kw::Endswith => "<endswith>",
            Kw::Icontains => "<icontains>",
            Kw::Istartswith => "<istartswith>",
            Kw::Iendswith => "<iendswith>",
            Kw::Iequals => "<iequals>",
            Kw::Import => "<import>",
            Kw::Defined => "<defined>",
        }
    }
}

/// `int8` .. `uint32be` (lexer.l `u?int(8|16|32)(be)?`): the libyara index added
/// to OP_READ_INT: 0..2 int8/16/32, 3..5 uint8/16/32, +6 for big endian.
pub type IntFunc = u8;

#[derive(Clone, Debug, PartialEq)]
pub enum Tok {
    Eof,
    DotDot,
    Lt,
    Gt,
    Le,
    Ge,
    Eq,
    Neq,
    Shl,
    Shr,
    Kw(Kw),
    /// `$name*` (text includes the `$` and the `*`).
    StrIdWild(String),
    /// `$name` / `$`.
    StrId(String),
    /// `#name` (stored with a leading `$`, like libyara).
    StrCount(String),
    /// `@name` (stored with a leading `$`).
    StrOffset(String),
    /// `!name` (stored with a leading `$`).
    StrLength(String),
    IntFunc(IntFunc),
    Ident(String),
    Number(i64),
    Double(f64),
    Text(Vec<u8>),
    Regex { src: Vec<u8>, nocase: bool, dotall: bool },
    /// Hex string text including braces (comments still inside).
    Hex(String),
    /// Any other printable ASCII character.
    Char(u8),
}

impl Tok {
    /// Name used in bison "unexpected X" messages.
    pub fn name(&self) -> String {
        match self {
            Tok::Eof => "end of file".into(),
            Tok::DotDot => "..".into(),
            Tok::Lt => "<".into(),
            Tok::Gt => ">".into(),
            Tok::Le => "<=".into(),
            Tok::Ge => ">=".into(),
            Tok::Eq => "==".into(),
            Tok::Neq => "!=".into(),
            Tok::Shl => "<<".into(),
            Tok::Shr => ">>".into(),
            Tok::Kw(k) => k.name().into(),
            Tok::StrIdWild(_) => "string identifier with wildcard".into(),
            Tok::StrId(_) => "string identifier".into(),
            Tok::StrCount(_) => "string count".into(),
            Tok::StrOffset(_) => "string offset".into(),
            Tok::StrLength(_) => "string length".into(),
            Tok::IntFunc(_) => "integer function".into(),
            Tok::Ident(_) => "identifier".into(),
            Tok::Number(_) => "integer number".into(),
            Tok::Double(_) => "floating point number".into(),
            Tok::Text(_) => "text string".into(),
            Tok::Regex { .. } => "regular expression".into(),
            Tok::Hex(_) => "hex string".into(),
            Tok::Char(b'\\') => "'\\\\'".into(),
            // Characters the grammar never uses map to bison's YYUNDEF.
            Tok::Char(c) if b"|^&+-*%~{}:=().[],".contains(c) => format!("'{}'", *c as char),
            Tok::Char(_) => "invalid token".into(),
        }
    }
}

/// libyara YR_LEX_BUF_SIZE: strings / regexps longer than this - 2 bytes fail.
const LEX_BUF_SIZE: usize = 8192;
const MAX_IDENTIFIER: usize = 128;
const LLONG_MAX: i64 = i64::MAX;

/// A lexical error: message and the line it is reported at.
#[derive(Clone, Debug)]
pub struct LexError {
    pub msg: String,
    pub line: usize,
}

pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    /// flex `yylineno` (1-based; newlines consumed so far + 1).
    line: usize,
    /// Real end of input reached (libyara then reports line 0).
    at_eof: bool,
    /// A terminating lexical error happened: only Eof from now on.
    terminated: bool,
}

#[inline]
fn is_letter(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

#[inline]
fn is_ident_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a [u8]) -> Lexer<'a> {
        Lexer { src, pos: 0, line: 1, at_eof: false, terminated: false }
    }

    /// Current `yylineno` as libyara reports it (0 once the end of input was hit).
    pub fn line(&self) -> usize {
        if self.at_eof {
            0
        } else {
            self.line
        }
    }

    #[inline]
    fn peek_at(&self, off: usize) -> Option<u8> {
        self.src.get(self.pos + off).copied()
    }

    fn count_lines(&mut self, from: usize, to: usize) {
        let end = to.min(self.src.len());
        if from < end {
            self.line += self.src[from..end].iter().filter(|&&c| c == b'\n').count();
        }
    }

    /// Advance to `to`, counting newlines.
    fn advance_to(&mut self, to: usize) {
        let from = self.pos;
        self.count_lines(from, to);
        self.pos = to.min(self.src.len());
    }

    fn term(&mut self, msg: impl Into<String>) -> LexError {
        self.terminated = true;
        LexError { msg: msg.into(), line: self.line() }
    }

    /// Next token. `Err` = a reported lexical error; `include` errors are
    /// non-terminating (the next call continues), all others terminate.
    pub fn next_token(&mut self) -> Result<Tok, LexError> {
        if self.terminated {
            return Ok(Tok::Eof);
        }
        loop {
            let Some(c) = self.peek_at(0) else {
                self.at_eof = true;
                return Ok(Tok::Eof);
            };
            match c {
                b' ' | b'\t' | b'\r' | b'\n' => {
                    if c == b'\n' {
                        self.line += 1;
                    }
                    self.pos += 1;
                    continue;
                }
                b'/' => match self.peek_at(1) {
                    Some(b'*') => {
                        // Block comment; unterminated comments run to the end.
                        let start = self.pos + 2;
                        let end = find_sub(&self.src[start.min(self.src.len())..], b"*/")
                            .map(|i| start + i + 2)
                            .unwrap_or(self.src.len());
                        self.advance_to(end);
                        continue;
                    }
                    Some(b'/') => {
                        let end = memchr(b'\n', &self.src[self.pos..])
                            .map(|i| self.pos + i)
                            .unwrap_or(self.src.len());
                        self.pos = end;
                        continue;
                    }
                    _ => return self.lex_regex(),
                },
                _ => {}
            }
            return self.lex_token(c);
        }
    }

    fn lex_token(&mut self, c: u8) -> Result<Tok, LexError> {
        let p = self.pos;
        let two = |a: u8, b: u8| c == a && self.peek_at(1) == Some(b);
        // Multi-character operators (longest match).
        let op = if two(b'.', b'.') {
            Some(Tok::DotDot)
        } else if two(b'<', b'=') {
            Some(Tok::Le)
        } else if two(b'>', b'=') {
            Some(Tok::Ge)
        } else if two(b'=', b'=') {
            Some(Tok::Eq)
        } else if two(b'!', b'=') {
            // `!=` (2 chars) beats `!` alone; `!x` (identifier chars) is longer only
            // when followed by an identifier character, which `=` is not.
            Some(Tok::Neq)
        } else if two(b'<', b'<') {
            Some(Tok::Shl)
        } else if two(b'>', b'>') {
            Some(Tok::Shr)
        } else {
            None
        };
        if let Some(t) = op {
            self.pos += 2;
            return Ok(t);
        }
        match c {
            b'<' => {
                self.pos += 1;
                return Ok(Tok::Lt);
            }
            b'>' => {
                self.pos += 1;
                return Ok(Tok::Gt);
            }
            b'$' | b'#' | b'@' | b'!' => {
                let mut e = p + 1;
                while e < self.src.len() && is_ident_char(self.src[e]) {
                    e += 1;
                }
                let mut name = String::with_capacity(e - p + 1);
                name.push('$');
                for &b in &self.src[p + 1..e] {
                    name.push(b as char);
                }
                if c == b'$' && self.src.get(e) == Some(&b'*') {
                    name.push('*');
                    self.pos = e + 1;
                    return Ok(Tok::StrIdWild(name));
                }
                self.pos = e;
                return Ok(match c {
                    b'$' => Tok::StrId(name),
                    b'#' => Tok::StrCount(name),
                    b'@' => Tok::StrOffset(name),
                    _ => Tok::StrLength(name),
                });
            }
            b'"' => return self.lex_text(),
            b'{' => {
                if let Some(end) = hex_string_end(self.src, p) {
                    let text: String = self.src[p..end].iter().map(|&b| b as char).collect();
                    self.advance_to(end);
                    return Ok(Tok::Hex(text));
                }
                self.pos += 1;
                return Ok(Tok::Char(b'{'));
            }
            _ => {}
        }
        if c.is_ascii_digit() {
            return self.lex_number();
        }
        if is_letter(c) || c == b'_' {
            let mut e = p + 1;
            while e < self.src.len() && is_ident_char(self.src[e]) {
                e += 1;
            }
            let word = &self.src[p..e];
            // `include[ \t]+"` is longer than the bare identifier `include`.
            if word == b"include" {
                let mut q = e;
                while q < self.src.len() && (self.src[q] == b' ' || self.src[q] == b'\t') {
                    q += 1;
                }
                if q > e && self.src.get(q) == Some(&b'"') {
                    return self.lex_include(q + 1);
                }
            }
            self.pos = e;
            if let Some(k) = Kw::from_word(word) {
                return Ok(Tok::Kw(k));
            }
            if let Some(f) = int_func(word) {
                return Ok(Tok::IntFunc(f));
            }
            if word.len() > MAX_IDENTIFIER {
                return Err(self.term("identifier too long"));
            }
            return Ok(Tok::Ident(word.iter().map(|&b| b as char).collect()));
        }
        if (32..127).contains(&c) {
            self.pos += 1;
            return Ok(Tok::Char(c));
        }
        self.pos += 1;
        Err(self.term("non-ascii character"))
    }

    fn lex_include(&mut self, path_start: usize) -> Result<Tok, LexError> {
        // <include>[^"]+ then <include>" ; an unterminated include runs to EOF.
        match memchr(b'"', &self.src[path_start.min(self.src.len())..]) {
            Some(i) => {
                let end = path_start + i;
                let path: String = String::from_utf8_lossy(&self.src[path_start..end]).into_owned();
                self.advance_to(end + 1);
                Err(LexError { msg: format!("includes are not supported: {path}"), line: self.line() })
            }
            None => {
                self.advance_to(self.src.len());
                self.at_eof = true;
                Ok(Tok::Eof)
            }
        }
    }

    fn lex_number(&mut self) -> Result<Tok, LexError> {
        let p = self.pos;
        let s = self.src;
        let digits_end = |mut i: usize, f: fn(u8) -> bool| {
            while i < s.len() && f(s[i]) {
                i += 1;
            }
            i
        };
        // 0x{hexdigit}+
        if s[p] == b'0' && s.get(p + 1) == Some(&b'x') {
            let e = digits_end(p + 2, |b| b.is_ascii_hexdigit());
            if e > p + 2 {
                self.pos = e;
                return match parse_radix(&s[p + 2..e], 16) {
                    Some(v) => Ok(Tok::Number(v)),
                    None => Err(self.overflow(p, e)),
                };
            }
        }
        // 0o{octdigit}+
        if s[p] == b'0' && s.get(p + 1) == Some(&b'o') {
            let e = digits_end(p + 2, |b| (b'0'..=b'7').contains(&b));
            if e > p + 2 {
                self.pos = e;
                return match parse_radix(&s[p + 2..e], 8) {
                    Some(v) => Ok(Tok::Number(v)),
                    None => Err(self.overflow(p, e)),
                };
            }
        }
        let e = digits_end(p, |b| b.is_ascii_digit());
        // {digit}+"."{digit}+
        if s.get(e) == Some(&b'.') && s.get(e + 1).is_some_and(|b| b.is_ascii_digit()) {
            let e2 = digits_end(e + 1, |b| b.is_ascii_digit());
            self.pos = e2;
            let text = std::str::from_utf8(&s[p..e2]).unwrap_or("0");
            return Ok(Tok::Double(text.parse::<f64>().unwrap_or(0.0)));
        }
        // {digit}+(MB|KB)?
        let (mult, end) = match (s.get(e), s.get(e + 1)) {
            (Some(b'K'), Some(b'B')) => (1024i64, e + 2),
            (Some(b'M'), Some(b'B')) => (1_048_576i64, e + 2),
            _ => (1, e),
        };
        self.pos = end;
        let Some(v) = parse_radix(&s[p..e], 10) else {
            return Err(self.overflow(p, end));
        };
        if mult != 1 {
            if v > LLONG_MAX / mult {
                return Err(self.overflow(p, end));
            }
            return Ok(Tok::Number(v * mult));
        }
        Ok(Tok::Number(v))
    }

    fn overflow(&mut self, from: usize, to: usize) -> LexError {
        let text = String::from_utf8_lossy(&self.src[from..to]).into_owned();
        self.term(format!("integer overflow in \"{text}\""))
    }

    fn lex_text(&mut self) -> Result<Tok, LexError> {
        let s = self.src;
        let mut i = self.pos + 1;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let Some(&c) = s.get(i) else {
                // <<EOF>> inside a string: the scanner just ends.
                self.pos = s.len();
                self.at_eof = true;
                return Ok(Tok::Eof);
            };
            match c {
                b'"' => {
                    self.pos = i + 1;
                    return Ok(Tok::Text(buf));
                }
                b'\n' => {
                    self.pos = i + 1;
                    self.line += 1;
                    return Err(self.term("unterminated string"));
                }
                b'\\' => {
                    let Some(&n) = s.get(i + 1) else {
                        // A lone backslash before EOF matches no rule; flex echoes
                        // it and then hits EOF.
                        self.pos = s.len();
                        self.at_eof = true;
                        return Ok(Tok::Eof);
                    };
                    let (v, len) = match n {
                        b't' => (b'\t', 2),
                        b'r' => (b'\r', 2),
                        b'n' => (b'\n', 2),
                        b'"' => (b'"', 2),
                        b'\\' => (b'\\', 2),
                        b'x' if s.get(i + 2).is_some_and(|b| b.is_ascii_hexdigit())
                            && s.get(i + 3).is_some_and(|b| b.is_ascii_hexdigit()) =>
                        {
                            (hexval(s[i + 2]) << 4 | hexval(s[i + 3]), 4)
                        }
                        _ => {
                            if n == b'\n' {
                                self.line += 1;
                            }
                            self.pos = i + 2;
                            return Err(self.term("illegal escape sequence"));
                        }
                    };
                    if buf.len() + 1 >= LEX_BUF_SIZE - 1 {
                        self.pos = i + len;
                        return Err(self.term("out of space in lex_buf"));
                    }
                    buf.push(v);
                    i += len;
                }
                _ => {
                    // [^\\\n"]+ : one chunk, checked as a whole.
                    let mut e = i;
                    while e < s.len() && !matches!(s[e], b'\\' | b'\n' | b'"') {
                        e += 1;
                    }
                    if buf.len() + (e - i) >= LEX_BUF_SIZE - 1 {
                        self.pos = e;
                        return Err(self.term("out of space in lex_buf"));
                    }
                    buf.extend_from_slice(&s[i..e]);
                    i = e;
                }
            }
        }
    }

    fn lex_regex(&mut self) -> Result<Tok, LexError> {
        let s = self.src;
        let mut i = self.pos + 1;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let Some(&c) = s.get(i) else {
                self.pos = s.len();
                self.at_eof = true;
                return Ok(Tok::Eof);
            };
            match c {
                b'/' => {
                    let mut e = i + 1;
                    let mut nocase = false;
                    let mut dotall = false;
                    if s.get(e) == Some(&b'i') {
                        nocase = true;
                        e += 1;
                    }
                    if s.get(e) == Some(&b's') {
                        dotall = true;
                        e += 1;
                    }
                    self.pos = e;
                    if buf.is_empty() {
                        return Err(self.term("empty regular expression"));
                    }
                    return Ok(Tok::Regex { src: buf, nocase, dotall });
                }
                b'\n' => {
                    self.pos = i + 1;
                    self.line += 1;
                    return Err(self.term("unterminated regular expression"));
                }
                b'\\' => match s.get(i + 1) {
                    Some(b'/') => {
                        if buf.len() + 1 >= LEX_BUF_SIZE - 1 {
                            self.pos = i + 2;
                            return Err(self.term("out of space in lex_buf"));
                        }
                        buf.push(b'/');
                        i += 2;
                    }
                    Some(&n) if n != b'\n' => {
                        if buf.len() + 2 >= LEX_BUF_SIZE - 1 {
                            self.pos = i + 2;
                            return Err(self.term("out of space in lex_buf"));
                        }
                        buf.push(b'\\');
                        buf.push(n);
                        i += 2;
                    }
                    Some(_) => {
                        // Backslash-newline: flex echoes the backslash, then the
                        // newline rule fires.
                        self.pos = i + 2;
                        self.line += 1;
                        return Err(self.term("unterminated regular expression"));
                    }
                    None => {
                        self.pos = s.len();
                        self.at_eof = true;
                        return Ok(Tok::Eof);
                    }
                },
                _ => {
                    let mut e = i;
                    while e < s.len() && !matches!(s[e], b'/' | b'\n' | b'\\') {
                        e += 1;
                    }
                    if buf.len() + (e - i) >= LEX_BUF_SIZE - 1 {
                        self.pos = e;
                        return Err(self.term("out of space in lex_buf"));
                    }
                    buf.extend_from_slice(&s[i..e]);
                    i = e;
                }
            }
        }
    }
}

fn hexval(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// strtoll semantics restricted to what the lexer feeds it (digits only):
/// None on overflow (libyara checks `== LLONG_MAX && errno == ERANGE`).
fn parse_radix(digits: &[u8], radix: u32) -> Option<i64> {
    let mut v: i64 = 0;
    for &d in digits {
        let x = hexval(d) as i64;
        v = v.checked_mul(radix as i64)?.checked_add(x)?;
    }
    Some(v)
}

fn int_func(w: &[u8]) -> Option<IntFunc> {
    let (mut v, rest) = match w.strip_prefix(b"u") {
        Some(r) => (3u8, r),
        None => (0u8, w),
    };
    let (size, rest) = [(0u8, &b"int8"[..]), (1, b"int16"), (2, b"int32")]
        .iter()
        .find_map(|&(k, p)| rest.strip_prefix(p).map(|r| (k, r)))?;
    v += size;
    match rest {
        b"" => Some(v),
        b"be" => Some(v + 6),
        _ => None,
    }
}

fn memchr(b: u8, hay: &[u8]) -> Option<usize> {
    hay.iter().position(|&c| c == b)
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Longest match of the lexer.l hex-string rule starting at `src[p] == '{'`:
/// `\{(({hexdigit}|[ \-|\~\?\[\]\(\)\n\r\t]|\/\*(\/|\**[^*/])*\*+\/)+|\/\/.*\n)+\}`.
/// Returns the end offset (exclusive) or None when it does not match.
fn hex_string_end(src: &[u8], p: usize) -> Option<usize> {
    let mut i = p + 1;
    let mut items = 0usize;
    loop {
        let c = *src.get(i)?;
        match c {
            b'}' => {
                return if items > 0 { Some(i + 1) } else { None };
            }
            b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' | b' ' | b'-' | b'|' | b'~' | b'?' | b'[' | b']'
            | b'(' | b')' | b'\n' | b'\r' | b'\t' => {
                i += 1;
                items += 1;
            }
            b'/' => match src.get(i + 1) {
                Some(b'*') => {
                    // Block comment: must be closed by the first "*/".
                    let start = i + 2;
                    let rel = find_sub(src.get(start..)?, b"*/")?;
                    i = start + rel + 2;
                    items += 1;
                }
                Some(b'/') => {
                    // `//.*\n` : needs a terminating newline.
                    let rel = memchr(b'\n', src.get(i..)?)?;
                    i += rel + 1;
                    items += 1;
                }
                _ => return None,
            },
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(src: &str) -> Vec<Tok> {
        let mut l = Lexer::new(src.as_bytes());
        let mut v = Vec::new();
        loop {
            match l.next_token() {
                Ok(Tok::Eof) => break,
                Ok(t) => v.push(t),
                Err(e) => {
                    v.push(Tok::Ident(format!("ERR:{}", e.msg)));
                }
            }
        }
        v
    }

    #[test]
    fn yara_lexer_basic_tokens() {
        let t = toks("rule r1 : t { condition: $a and #a > 2 or @a[1] != !a }");
        assert_eq!(t[0], Tok::Kw(Kw::Rule));
        assert_eq!(t[1], Tok::Ident("r1".into()));
        assert_eq!(t[2], Tok::Char(b':'));
        assert_eq!(t[4], Tok::Char(b'{'));
        assert!(t.contains(&Tok::StrCount("$a".into())));
        assert!(t.contains(&Tok::StrOffset("$a".into())));
        assert!(t.contains(&Tok::StrLength("$a".into())));
        assert!(t.contains(&Tok::Neq));
    }

    #[test]
    fn yara_lexer_numbers() {
        assert_eq!(toks("10KB 2MB 0x10 0o17 1.5 7"), vec![
            Tok::Number(10240),
            Tok::Number(2 * 1048576),
            Tok::Number(16),
            Tok::Number(15),
            Tok::Double(1.5),
            Tok::Number(7)
        ]);
        assert_eq!(toks("9223372036854775807"), vec![Tok::Number(i64::MAX)]);
        let t = toks("9223372036854775808");
        assert!(matches!(&t[0], Tok::Ident(s) if s.starts_with("ERR:integer overflow")));
        assert_eq!(toks("0x"), vec![Tok::Number(0), Tok::Ident("x".into())]);
        assert_eq!(toks("1..2"), vec![Tok::Number(1), Tok::DotDot, Tok::Number(2)]);
    }

    #[test]
    fn yara_lexer_strings_and_regex() {
        assert_eq!(toks(r#""a\x41\n\"\\""#), vec![Tok::Text(b"aA\n\"\\".to_vec())]);
        assert_eq!(toks(r"/a\/b\d/is"), vec![Tok::Regex { src: b"a/b\\d".to_vec(), nocase: true, dotall: true }]);
        let t = toks(r#""a\q""#);
        assert!(matches!(&t[0], Tok::Ident(s) if s == "ERR:illegal escape sequence"));
        assert_eq!(toks("// c\n/* x\n */ 5"), vec![Tok::Number(5)]);
    }

    #[test]
    fn yara_lexer_hex_strings() {
        assert_eq!(toks("{ 4D 5A ?? [2-4] (00|01) }"), vec![Tok::Hex("{ 4D 5A ?? [2-4] (00|01) }".into())]);
        assert_eq!(toks("{ condition"), vec![Tok::Char(b'{'), Tok::Kw(Kw::Condition)]);
        assert_eq!(toks("{ 41 /* c } */ 42 // x }\n }").len(), 1);
        assert_eq!(toks("{}"), vec![Tok::Char(b'{'), Tok::Char(b'}')]);
    }

    #[test]
    fn yara_lexer_keywords_and_intfuncs() {
        assert_eq!(toks("uint32be int8 int8x"), vec![Tok::IntFunc(11), Tok::IntFunc(0), Tok::Ident("int8x".into())]);
        assert_eq!(toks("rules"), vec![Tok::Ident("rules".into())]);
        assert_eq!(toks("$ $* $a* # @ !"), vec![
            Tok::StrId("$".into()),
            Tok::StrIdWild("$*".into()),
            Tok::StrIdWild("$a*".into()),
            Tok::StrCount("$".into()),
            Tok::StrOffset("$".into()),
            Tok::StrLength("$".into())
        ]);
    }

    #[test]
    fn yara_lexer_never_panics_on_garbage() {
        let mut seed = 0x1234_5678u32;
        for _ in 0..2000 {
            let mut buf = Vec::new();
            for _ in 0..(seed % 40) {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let alphabet = b"{}()[]/*\\\"$#@!x0.9KBMiu\n ?|-~=<>";
                buf.push(alphabet[(seed as usize) % alphabet.len()]);
            }
            let mut l = Lexer::new(&buf);
            for _ in 0..1000 {
                if let Ok(Tok::Eof) = l.next_token() {
                    break;
                }
            }
        }
    }
}
