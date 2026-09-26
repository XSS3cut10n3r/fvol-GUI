//! YARA regular-expression / hex-string syntax trees and parsers, reproducing the
//! trees libyara 4.5 builds (re_lexer.l + re_grammar.y, hex_lexer.l + hex_grammar.y):
//! same node kinds, same shapes (binary left-nested alternations, nested
//! concatenations for groups), same flags (fast / greedy / ungreedy) and errors.
//! The exact shape matters because atom selection and code emission depend on it.

/// Maximum repeat bound (RE_MAX_RANGE = INT16_MAX).
pub const RE_MAX_RANGE: i32 = 32767;
/// Jumps longer than this split a hex string into chained parts.
pub const STRING_CHAINING_THRESHOLD: i32 = 200;
const MAX_DEPTH: usize = 400;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Class {
    pub negated: bool,
    pub bitmap: [u8; 32],
}

impl Class {
    #[inline]
    pub fn has(&self, c: u8) -> bool {
        self.bitmap[(c / 8) as usize] & (1 << (c % 8)) != 0
    }
    fn set(&mut self, c: u8) {
        self.bitmap[(c / 8) as usize] |= 1 << (c % 8);
    }
}

#[derive(Clone, Debug)]
pub enum Kind {
    Literal,
    MaskedLiteral,
    NotLiteral,
    MaskedNotLiteral,
    /// `.` / `??` (value 0, mask 0).
    Any,
    Class(Box<Class>),
    WordChar,
    NonWordChar,
    Space,
    NonSpace,
    Digit,
    NonDigit,
    WordBoundary,
    NonWordBoundary,
    AnchorStart,
    AnchorEnd,
    Empty,
    Concat(Vec<Node>),
    Alt(Box<Node>, Box<Node>),
    Star(Box<Node>),
    Plus(Box<Node>),
    /// `e{start,end}` (e = child)
    Range(Box<Node>),
    /// `.{start,end}` / hex jump
    RangeAny,
}

#[derive(Clone, Debug)]
pub struct Node {
    pub kind: Kind,
    pub value: u8,
    pub mask: u8,
    pub start: i32,
    pub end: i32,
    pub greedy: bool,
    /// Unique id (index into per-part code reference tables).
    pub id: u32,
}

#[derive(Clone, Debug)]
pub struct Ast {
    pub root: Node,
    /// RE_FLAGS_FAST_REGEXP (hex strings without alternatives).
    pub fast: bool,
    pub greedy: bool,
    pub ungreedy: bool,
    /// Number of node ids allocated.
    pub nodes: u32,
}

pub type PResult<T> = Result<T, String>;

struct Ids(u32);

impl Ids {
    fn node(&mut self, kind: Kind) -> Node {
        let id = self.0;
        self.0 += 1;
        Node { kind, value: 0, mask: 0, start: 0, end: 0, greedy: true, id }
    }
    fn lit(&mut self, v: u8) -> Node {
        let mut n = self.node(Kind::Literal);
        n.value = v;
        n.mask = 0xff;
        n
    }
}

// ---------------------------------------------------------------------------------------
// YARA regex lexer
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Char(u8),
    Class(Class),
    WordChar,
    NonWordChar,
    Space,
    NonSpace,
    Digit,
    NonDigit,
    WordBoundary,
    NonWordBoundary,
    /// (lo, hi)
    Range(i32, i32),
    /// one of ( ) | $ . ^ + * ?
    Sym(u8),
    Eof,
}

const WORD_CHARS: [u8; 32] = {
    let mut b = [0u8; 32];
    let mut c = 0usize;
    while c < 256 {
        let ch = c as u8;
        if ch.is_ascii_alphanumeric() || ch == b'_' {
            b[c / 8] |= 1 << (c % 8);
        }
        c += 1;
    }
    b
};
const SPACE_CHARS: [u8; 32] = {
    let mut b = [0u8; 32];
    let sp = [b' ', b'\t', b'\n', b'\x0b', b'\x0c', b'\r'];
    let mut i = 0;
    while i < sp.len() {
        let c = sp[i] as usize;
        b[c / 8] |= 1 << (c % 8);
        i += 1;
    }
    b
};

struct Lexer<'a> {
    s: &'a [u8],
    i: usize,
}

/// libyara escaped_char_value: text = `\` + c [+ 2 hex digits]. None = illegal.
fn escaped_value(c: u8, h1: Option<u8>, h2: Option<u8>) -> Option<u8> {
    match c {
        b'x' => {
            let (a, b) = (h1?, h2?);
            if !a.is_ascii_hexdigit() || !b.is_ascii_hexdigit() {
                return None;
            }
            let v = |x: u8| (x as char).to_digit(16).unwrap_or(0) as u8;
            Some(v(a) << 4 | v(b))
        }
        b'n' => Some(b'\n'),
        b't' => Some(b'\t'),
        b'r' => Some(b'\r'),
        b'f' => Some(0x0c),
        b'a' => Some(0x07),
        _ => Some(c),
    }
}

impl<'a> Lexer<'a> {
    fn peek(&self, k: usize) -> Option<u8> {
        self.s.get(self.i + k).copied()
    }

    /// read_escaped_char: the backslash is already consumed.
    fn read_escaped(&mut self) -> PResult<u8> {
        let c = match self.peek(0) {
            None | Some(0) => return Err("illegal escape sequence".into()),
            Some(c) => c,
        };
        self.i += 1;
        if c == b'x' {
            let h1 = self.peek(0);
            if matches!(h1, None | Some(0)) {
                return Err("illegal escape sequence".into());
            }
            self.i += 1;
            let h2 = self.peek(0);
            if matches!(h2, None | Some(0)) {
                return Err("illegal escape sequence".into());
            }
            self.i += 1;
            return escaped_value(c, h1, h2).ok_or_else(|| "illegal escape sequence".to_string());
        }
        escaped_value(c, None, None).ok_or_else(|| "illegal escape sequence".to_string())
    }

    fn digits(&self, from: usize) -> usize {
        let mut j = from;
        while j < self.s.len() && self.s[j].is_ascii_digit() {
            j += 1;
        }
        j
    }

    fn atoi(s: &[u8]) -> i64 {
        let mut v: i64 = 0;
        for &d in s {
            v = v.saturating_mul(10).saturating_add((d - b'0') as i64);
        }
        v
    }

    /// Try the `{n}` / `{n,m}` rules at self.i (which points at '{').
    fn try_range(&mut self) -> PResult<Option<Tok>> {
        let s = self.s;
        let i = self.i;
        // {digit*[ ]*,[ ]*digit*}
        let d1 = self.digits(i + 1);
        let mut j = d1;
        while j < s.len() && s[j] == b' ' {
            j += 1;
        }
        if j < s.len() && s[j] == b',' {
            let mut k = j + 1;
            while k < s.len() && s[k] == b' ' {
                k += 1;
            }
            let d2 = self.digits(k);
            if d2 < s.len() && s[d2] == b'}' {
                let lo = Self::atoi(&s[i + 1..d1]);
                let hi = if d2 == k { RE_MAX_RANGE as i64 } else { Self::atoi(&s[k..d2]) };
                if hi > RE_MAX_RANGE as i64 {
                    return Err("repeat interval too large".into());
                }
                if hi < lo || lo > i32::MAX as i64 {
                    return Err("bad repeat interval".into());
                }
                self.i = d2 + 1;
                return Ok(Some(Tok::Range(lo as i32, hi as i32)));
            }
        }
        // {digit+}
        if d1 > i + 1 && d1 < s.len() && s[d1] == b'}' {
            let v = Self::atoi(&s[i + 1..d1]);
            if v > RE_MAX_RANGE as i64 {
                return Err("repeat interval too large".into());
            }
            self.i = d1 + 1;
            return Ok(Some(Tok::Range(v as i32, v as i32)));
        }
        Ok(None)
    }

    fn class(&mut self) -> PResult<Tok> {
        let s = self.s;
        let mut cls = Class { negated: false, bitmap: [0; 32] };
        // Opening forms: "[^]" "[^" "[]" "["
        if s.get(self.i + 1) == Some(&b'^') {
            cls.negated = true;
            if s.get(self.i + 2) == Some(&b']') {
                cls.set(b']');
                self.i += 3;
            } else {
                self.i += 2;
            }
        } else if s.get(self.i + 1) == Some(&b']') {
            cls.set(b']');
            self.i += 2;
        } else {
            self.i += 1;
        }
        loop {
            let Some(c) = self.peek(0) else {
                return Err("missing terminating ] for character class".into());
            };
            if c == b']' {
                self.i += 1;
                return Ok(Tok::Class(cls));
            }
            // Range rule: (\x{hex}{2} | \\. | [^]\\]) - [^]]
            let start_len = if c == b'\\' {
                match self.peek(1) {
                    Some(b'x')
                        if self.peek(2).is_some_and(|h| h.is_ascii_hexdigit())
                            && self.peek(3).is_some_and(|h| h.is_ascii_hexdigit()) =>
                    {
                        Some(4)
                    }
                    Some(b'\n') | None => None,
                    Some(_) => Some(2),
                }
            } else {
                Some(1)
            };
            // The \x alternative and the \\. alternative can both apply; flex picks the
            // longest overall match, so try 4 first then 2.
            let mut range: Option<(usize, u8)> = None; // (total length, end char)
            if let Some(sl) = start_len {
                let cands: &[usize] = if sl == 4 { &[4, 2] } else if sl == 2 { &[2] } else { &[1] };
                for &l in cands {
                    if self.peek(l) == Some(b'-') {
                        if let Some(e) = self.peek(l + 1) {
                            if e != b']' {
                                range = Some((l + 2, e));
                                break;
                            }
                        }
                    }
                }
            }
            if let Some((total, end_ch)) = range {
                let start: u8 = if c == b'\\' {
                    let x = self.peek(1).unwrap_or(0);
                    let (h1, h2) = (self.peek(2), self.peek(3));
                    escaped_value(x, h1, h2).ok_or_else(|| "illegal escape sequence".to_string())?
                } else {
                    c
                };
                self.i += total;
                let end = if end_ch == b'\\' { self.read_escaped()? } else { end_ch };
                if end < start {
                    return Err("bad character range".into());
                }
                for x in start..=end {
                    cls.set(x);
                }
                continue;
            }
            if c == b'\\' {
                match self.peek(1) {
                    Some(b'w') => {
                        self.i += 2;
                        for k in 0..32 {
                            cls.bitmap[k] |= WORD_CHARS[k];
                        }
                        continue;
                    }
                    Some(b'W') => {
                        self.i += 2;
                        for k in 0..32 {
                            cls.bitmap[k] |= !WORD_CHARS[k];
                        }
                        continue;
                    }
                    Some(b's') => {
                        self.i += 2;
                        for k in 0..32 {
                            cls.bitmap[k] |= SPACE_CHARS[k];
                        }
                        continue;
                    }
                    Some(b'S') => {
                        self.i += 2;
                        for k in 0..32 {
                            cls.bitmap[k] |= !SPACE_CHARS[k];
                        }
                        continue;
                    }
                    Some(b'd') => {
                        self.i += 2;
                        for x in b'0'..=b'9' {
                            cls.set(x);
                        }
                        continue;
                    }
                    Some(b'D') => {
                        self.i += 2;
                        for k in 0..32 {
                            if k == 6 {
                                continue;
                            }
                            if k == 7 {
                                cls.bitmap[k] |= 0xfc;
                            } else {
                                cls.bitmap[k] = 0xff;
                            }
                        }
                        continue;
                    }
                    _ => {
                        self.i += 1;
                        let v = self.read_escaped()?;
                        cls.set(v);
                        continue;
                    }
                }
            }
            if c == b'\n' {
                // flex default rule echoes and skips it
                self.i += 1;
                continue;
            }
            if (32..127).contains(&c) {
                cls.set(c);
                self.i += 1;
                continue;
            }
            return Err("non-ascii character".into());
        }
    }

    fn next(&mut self) -> PResult<Tok> {
        let Some(c) = self.peek(0) else { return Ok(Tok::Eof) };
        match c {
            b'{' => {
                if let Some(t) = self.try_range()? {
                    return Ok(t);
                }
                self.i += 1;
                Ok(Tok::Char(b'{'))
            }
            b'[' => self.class(),
            b'\\' => {
                let n = self.peek(1);
                let t = match n {
                    Some(b'w') => Some(Tok::WordChar),
                    Some(b'W') => Some(Tok::NonWordChar),
                    Some(b's') => Some(Tok::Space),
                    Some(b'S') => Some(Tok::NonSpace),
                    Some(b'd') => Some(Tok::Digit),
                    Some(b'D') => Some(Tok::NonDigit),
                    Some(b'b') => Some(Tok::WordBoundary),
                    Some(b'B') => Some(Tok::NonWordBoundary),
                    Some(d) if d.is_ascii_digit() => return Err("backreferences are not allowed".into()),
                    _ => None,
                };
                if let Some(t) = t {
                    self.i += 2;
                    return Ok(t);
                }
                self.i += 1;
                Ok(Tok::Char(self.read_escaped()?))
            }
            b'(' | b')' | b'|' | b'$' | b'.' | b'^' | b'+' | b'*' | b'?' => {
                self.i += 1;
                Ok(Tok::Sym(c))
            }
            _ => {
                self.i += 1;
                Ok(Tok::Char(c))
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// YARA regex parser (grammar of re_grammar.y)
// ---------------------------------------------------------------------------------------

struct ReParser<'a> {
    lx: Lexer<'a>,
    tok: Tok,
    ids: Ids,
    greedy: bool,
    ungreedy: bool,
}

impl<'a> ReParser<'a> {
    fn bump(&mut self) -> PResult<()> {
        self.tok = self.lx.next()?;
        Ok(())
    }

    fn starts_repeat(&self) -> bool {
        matches!(
            self.tok,
            Tok::Char(_)
                | Tok::Class(_)
                | Tok::WordChar
                | Tok::NonWordChar
                | Tok::Space
                | Tok::NonSpace
                | Tok::Digit
                | Tok::NonDigit
                | Tok::WordBoundary
                | Tok::NonWordBoundary
                | Tok::Sym(b'(')
                | Tok::Sym(b'.')
                | Tok::Sym(b'^')
                | Tok::Sym(b'$')
        )
    }

    fn alternative(&mut self, depth: usize) -> PResult<Node> {
        if depth > MAX_DEPTH {
            return Err("regular expression too deeply nested".into());
        }
        let mut left = self.concatenation(depth)?;
        while self.tok == Tok::Sym(b'|') {
            self.bump()?;
            let right = if self.starts_repeat() { self.concatenation(depth)? } else { self.ids.node(Kind::Empty) };
            left = self.ids.node(Kind::Alt(Box::new(left), Box::new(right)));
        }
        Ok(left)
    }

    fn concatenation(&mut self, depth: usize) -> PResult<Node> {
        if !self.starts_repeat() {
            return Err("syntax error".into());
        }
        let mut v = Vec::new();
        while self.starts_repeat() {
            v.push(self.repeat(depth)?);
        }
        Ok(self.ids.node(Kind::Concat(v)))
    }

    fn repeat(&mut self, depth: usize) -> PResult<Node> {
        let zero_width = match self.tok {
            Tok::WordBoundary => Some(Kind::WordBoundary),
            Tok::NonWordBoundary => Some(Kind::NonWordBoundary),
            Tok::Sym(b'^') => Some(Kind::AnchorStart),
            Tok::Sym(b'$') => Some(Kind::AnchorEnd),
            _ => None,
        };
        if let Some(k) = zero_width {
            self.bump()?;
            return Ok(self.ids.node(k));
        }
        let single = self.single(depth)?;
        match self.tok {
            Tok::Sym(b'*') | Tok::Sym(b'+') => {
                let plus = self.tok == Tok::Sym(b'+');
                self.bump()?;
                let lazy = self.tok == Tok::Sym(b'?');
                if lazy {
                    self.bump()?;
                    self.ungreedy = true;
                } else {
                    self.greedy = true;
                }
                let mut n = self.ids.node(if plus { Kind::Plus(Box::new(single)) } else { Kind::Star(Box::new(single)) });
                n.greedy = !lazy;
                Ok(n)
            }
            Tok::Sym(b'?') | Tok::Range(..) => {
                let (lo, hi) = match self.tok {
                    Tok::Range(a, b) => (a, b),
                    _ => (0, 1),
                };
                self.bump()?;
                let lazy = self.tok == Tok::Sym(b'?');
                if lazy {
                    self.bump()?;
                    self.ungreedy = true;
                } else {
                    self.greedy = true;
                }
                let mut n = if matches!(single.kind, Kind::Any) {
                    self.ids.node(Kind::RangeAny)
                } else {
                    self.ids.node(Kind::Range(Box::new(single)))
                };
                n.start = lo;
                n.end = hi;
                n.greedy = !lazy;
                Ok(n)
            }
            _ => Ok(single),
        }
    }

    fn single(&mut self, depth: usize) -> PResult<Node> {
        let t = std::mem::replace(&mut self.tok, Tok::Eof);
        let n = match t {
            Tok::Sym(b'(') => {
                self.bump()?;
                let inner = self.alternative(depth + 1)?;
                if self.tok != Tok::Sym(b')') {
                    return Err("syntax error".into());
                }
                self.bump()?;
                return Ok(inner);
            }
            Tok::Sym(b'.') => self.ids.node(Kind::Any),
            Tok::Char(c) => self.ids.lit(c),
            Tok::WordChar => self.ids.node(Kind::WordChar),
            Tok::NonWordChar => self.ids.node(Kind::NonWordChar),
            Tok::Space => self.ids.node(Kind::Space),
            Tok::NonSpace => self.ids.node(Kind::NonSpace),
            Tok::Digit => self.ids.node(Kind::Digit),
            Tok::NonDigit => self.ids.node(Kind::NonDigit),
            Tok::Class(c) => self.ids.node(Kind::Class(Box::new(c))),
            _ => return Err("syntax error".into()),
        };
        self.bump()?;
        Ok(n)
    }
}

/// Parse a YARA regular expression (text between the slashes).
pub fn parse_regex(src: &[u8]) -> PResult<Ast> {
    // The C parser sees a NUL-terminated string.
    let src = match src.iter().position(|&b| b == 0) {
        Some(p) => &src[..p],
        None => src,
    };
    let mut p = ReParser { lx: Lexer { s: src, i: 0 }, tok: Tok::Eof, ids: Ids(0), greedy: false, ungreedy: false };
    p.bump()?;
    let root = p.alternative(0)?;
    if p.tok != Tok::Eof {
        return Err("syntax error".into());
    }
    Ok(Ast { root, fast: false, greedy: p.greedy, ungreedy: p.ungreedy, nodes: p.ids.0 })
}

// ---------------------------------------------------------------------------------------
// Hex strings
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum HTok {
    /// (value, mask, not)
    Byte(u8, u8, bool),
    Open,  // {
    Close, // }
    LParen,
    RParen,
    Pipe,
    /// Jump [..]: (lo, Some(hi)) / (lo, None) unbounded; lo None = "[-]"
    Jump(Option<i64>, Option<Option<i64>>),
    Eof,
}

struct HexLexer<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> HexLexer<'a> {
    fn hexv(c: u8) -> u8 {
        (c as char).to_digit(16).unwrap_or(0) as u8
    }

    fn skip_ws(&mut self) -> PResult<()> {
        loop {
            match self.s.get(self.i) {
                Some(b' ' | b'\t' | b'\r' | b'\n') => self.i += 1,
                Some(b'/') if self.s.get(self.i + 1) == Some(&b'*') => {
                    let mut j = self.i + 2;
                    loop {
                        if j + 1 >= self.s.len() {
                            // unterminated comment: flex keeps consuming to EOF
                            self.i = self.s.len();
                            return Ok(());
                        }
                        if self.s[j] == b'*' && self.s[j + 1] == b'/' {
                            self.i = j + 2;
                            break;
                        }
                        j += 1;
                    }
                }
                Some(b'/') if self.s.get(self.i + 1) == Some(&b'/') => {
                    while self.i < self.s.len() && self.s[self.i] != b'\n' {
                        self.i += 1;
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn next(&mut self) -> PResult<HTok> {
        self.skip_ws()?;
        let s = self.s;
        let Some(&c) = s.get(self.i) else { return Ok(HTok::Eof) };
        let hx = |k: usize| s.get(k).is_some_and(|c| c.is_ascii_hexdigit());
        let at = |k: usize| s.get(k).copied();
        let i = self.i;
        match c {
            b'{' => {
                self.i += 1;
                Ok(HTok::Open)
            }
            b'}' => {
                self.i += 1;
                Ok(HTok::Close)
            }
            b'(' => {
                self.i += 1;
                Ok(HTok::LParen)
            }
            b')' => {
                self.i += 1;
                Ok(HTok::RParen)
            }
            b'|' => {
                self.i += 1;
                Ok(HTok::Pipe)
            }
            b'[' => {
                self.i += 1;
                self.jump()
            }
            b'~' => {
                if hx(i + 1) && hx(i + 2) {
                    self.i += 3;
                    return Ok(HTok::Byte(Self::hexv(s[i + 1]) << 4 | Self::hexv(s[i + 2]), 0xff, true));
                }
                if hx(i + 1) && at(i + 2) == Some(b'?') {
                    self.i += 3;
                    return Ok(HTok::Byte(Self::hexv(s[i + 1]) << 4, 0xf0, true));
                }
                if at(i + 1) == Some(b'?') && hx(i + 2) {
                    self.i += 3;
                    return Ok(HTok::Byte(Self::hexv(s[i + 2]), 0x0f, true));
                }
                Err("invalid not operator (~) in hex string".into())
            }
            b'?' => {
                if at(i + 1) == Some(b'?') {
                    self.i += 2;
                    return Ok(HTok::Byte(0, 0, false));
                }
                if hx(i + 1) {
                    self.i += 2;
                    return Ok(HTok::Byte(Self::hexv(s[i + 1]), 0x0f, false));
                }
                Err("invalid character in hex string".into())
            }
            c if c.is_ascii_hexdigit() => {
                if hx(i + 1) {
                    self.i += 2;
                    return Ok(HTok::Byte(Self::hexv(c) << 4 | Self::hexv(s[i + 1]), 0xff, false));
                }
                if at(i + 1) == Some(b'?') {
                    self.i += 2;
                    return Ok(HTok::Byte(Self::hexv(c) << 4, 0xf0, false));
                }
                Err("uneven number of digits in hex string".into())
            }
            _ => Err("invalid character in hex string".into()),
        }
    }

    /// After '[': parse `N]`, `N-M]`, `N-]`, `-]` (whitespace allowed inside).
    fn jump(&mut self) -> PResult<HTok> {
        let s = self.s;
        let skip = |me: &mut Self| {
            while me.i < s.len() && matches!(s[me.i], b' ' | b'\t' | b'\r' | b'\n') {
                me.i += 1;
            }
        };
        let num = |me: &mut Self| -> Option<i64> {
            let st = me.i;
            while me.i < s.len() && s[me.i].is_ascii_digit() {
                me.i += 1;
            }
            if me.i == st {
                None
            } else {
                // atoi: saturate (overflowed values behave badly in C too)
                let mut v: i64 = 0;
                for &d in &s[st..me.i] {
                    v = v.saturating_mul(10).saturating_add((d - b'0') as i64);
                }
                Some(v.min(i32::MAX as i64))
            }
        };
        skip(self);
        let lo = num(self);
        skip(self);
        match s.get(self.i) {
            Some(b']') => {
                self.i += 1;
                match lo {
                    Some(v) => Ok(HTok::Jump(Some(v), None)),
                    None => Err("syntax error".into()),
                }
            }
            Some(b'-') => {
                self.i += 1;
                skip(self);
                let hi = num(self);
                skip(self);
                if s.get(self.i) != Some(&b']') {
                    return Err(if self.i < s.len() && !s[self.i].is_ascii_digit() {
                        "invalid character in hex string jump".into()
                    } else {
                        "syntax error".into()
                    });
                }
                self.i += 1;
                match (lo, hi) {
                    (None, None) => Ok(HTok::Jump(None, Some(None))),
                    (Some(a), h) => Ok(HTok::Jump(Some(a), Some(h))),
                    (None, Some(_)) => Err("syntax error".into()),
                }
            }
            Some(_) => Err("invalid character in hex string jump".into()),
            None => Err("syntax error".into()),
        }
    }
}

struct HexParser<'a> {
    lx: HexLexer<'a>,
    tok: HTok,
    ids: Ids,
    inside_or: u32,
    fast: bool,
}

impl<'a> HexParser<'a> {
    fn bump(&mut self) -> PResult<()> {
        self.tok = self.lx.next()?;
        Ok(())
    }

    fn is_token_start(&self) -> bool {
        matches!(self.tok, HTok::Byte(..) | HTok::LParen)
    }

    /// tokens: token | token token | token token_sequence token
    fn tokens(&mut self, depth: usize) -> PResult<Node> {
        if depth > MAX_DEPTH {
            return Err("hex string too deeply nested".into());
        }
        let first = self.token(depth)?;
        // Collect the rest: tokens or ranges; must end with a token.
        let mut rest: Vec<Node> = Vec::new();
        loop {
            if self.is_token_start() {
                rest.push(self.token(depth)?);
            } else if let HTok::Jump(..) = self.tok {
                let r = self.range()?;
                rest.push(r);
            } else {
                break;
            }
        }
        if rest.is_empty() {
            return Ok(first);
        }
        // last must be a token (not a range)
        let last_is_range = matches!(rest.last().map(|n| &n.kind), Some(Kind::RangeAny))
            || rest.last().is_some_and(|n| n.greedy == false && matches!(n.kind, Kind::MaskedLiteral) && n.mask == 0 && n.start == -1);
        if last_is_range {
            return Err("syntax error".into());
        }
        if rest.len() == 1 {
            let t2 = rest.pop().ok_or("syntax error")?;
            return Ok(self.ids.node(Kind::Concat(vec![first, t2])));
        }
        // token token_sequence token: the sequence node is created first (id order)
        let mut v = Vec::with_capacity(rest.len() + 1);
        v.push(first);
        v.extend(rest);
        Ok(self.ids.node(Kind::Concat(v)))
    }

    fn token(&mut self, depth: usize) -> PResult<Node> {
        match self.tok.clone() {
            HTok::Byte(v, m, not) => {
                self.bump()?;
                let n = if not {
                    let mut n = if m == 0xff { self.ids.node(Kind::NotLiteral) } else { self.ids.node(Kind::MaskedNotLiteral) };
                    n.value = v;
                    n.mask = m;
                    n
                } else if m == 0 {
                    self.ids.node(Kind::Any)
                } else if m == 0xff {
                    self.ids.lit(v)
                } else {
                    let mut n = self.ids.node(Kind::MaskedLiteral);
                    n.value = v;
                    n.mask = m;
                    n
                };
                Ok(n)
            }
            HTok::LParen => {
                self.bump()?;
                self.inside_or += 1;
                let mut left = self.tokens(depth + 1)?;
                while self.tok == HTok::Pipe {
                    self.bump()?;
                    self.fast = false;
                    let right = self.tokens(depth + 1)?;
                    left = self.ids.node(Kind::Alt(Box::new(left), Box::new(right)));
                }
                if self.tok != HTok::RParen {
                    return Err("syntax error".into());
                }
                self.bump()?;
                self.inside_or -= 1;
                Ok(left)
            }
            _ => Err("syntax error".into()),
        }
    }

    fn range(&mut self) -> PResult<Node> {
        let HTok::Jump(lo, hi) = self.tok.clone() else { return Err("syntax error".into()) };
        self.bump()?;
        let thr = STRING_CHAINING_THRESHOLD as i64;
        let mut n = match (lo, hi) {
            (Some(v), None) => {
                if v <= 0 {
                    return Err("invalid jump length".into());
                }
                if self.inside_or > 0 && v > thr {
                    return Err("jumps over 200 not allowed inside alternation (|)".into());
                }
                if v == 1 {
                    let mut n = self.ids.node(Kind::MaskedLiteral);
                    n.value = 0;
                    n.mask = 0;
                    n.start = -1; // marker: came from a range (for the tokens-ending check)
                    n
                } else {
                    let mut n = self.ids.node(Kind::RangeAny);
                    n.start = v as i32;
                    n.end = v as i32;
                    n
                }
            }
            (Some(a), Some(Some(b))) => {
                if self.inside_or > 0 && (a > thr || b > thr) {
                    return Err("jumps over 200 not allowed inside alternation (|)".into());
                }
                if a > b {
                    return Err("invalid jump range".into());
                }
                let mut n = self.ids.node(Kind::RangeAny);
                n.start = a as i32;
                n.end = b as i32;
                n
            }
            (Some(a), Some(None)) => {
                if self.inside_or > 0 {
                    return Err("unbounded jumps not allowed inside alternation (|)".into());
                }
                let mut n = self.ids.node(Kind::RangeAny);
                n.start = a as i32;
                n.end = i32::MAX;
                n
            }
            (None, Some(None)) => {
                if self.inside_or > 0 {
                    return Err("unbounded jumps not allowed inside alternation (|)".into());
                }
                let mut n = self.ids.node(Kind::RangeAny);
                n.start = 0;
                n.end = i32::MAX;
                n
            }
            _ => return Err("syntax error".into()),
        };
        n.greedy = false;
        Ok(n)
    }
}

/// Parse a hex string (`{ ... }` including braces).
pub fn parse_hex(src: &[u8]) -> PResult<Ast> {
    let src = match src.iter().position(|&b| b == 0) {
        Some(p) => &src[..p],
        None => src,
    };
    let mut p = HexParser { lx: HexLexer { s: src, i: 0 }, tok: HTok::Eof, ids: Ids(0), inside_or: 0, fast: true };
    p.bump()?;
    if p.tok != HTok::Open {
        return Err("syntax error".into());
    }
    p.bump()?;
    let mut root = p.tokens(0)?;
    if p.tok != HTok::Close {
        return Err("syntax error".into());
    }
    p.bump()?;
    if p.tok != HTok::Eof {
        return Err("syntax error".into());
    }
    clear_markers(&mut root);
    Ok(Ast { root, fast: p.fast, greedy: false, ungreedy: false, nodes: p.ids.0 })
}

fn clear_markers(n: &mut Node) {
    if matches!(n.kind, Kind::MaskedLiteral) && n.start == -1 {
        n.start = 0;
    }
    match &mut n.kind {
        Kind::Concat(v) => v.iter_mut().for_each(clear_markers),
        Kind::Alt(a, b) => {
            clear_markers(a);
            clear_markers(b);
        }
        Kind::Star(c) | Kind::Plus(c) | Kind::Range(c) => clear_markers(c),
        _ => {}
    }
}

// ---------------------------------------------------------------------------------------
// AST utilities (yr_re_ast_extract_literal, yr_re_ast_split_at_chaining_point)
// ---------------------------------------------------------------------------------------

/// The literal bytes if the AST is a plain literal (root LITERAL, or a CONCAT whose
/// children are all LITERAL nodes).
pub fn extract_literal(ast: &Ast) -> Option<Vec<u8>> {
    match &ast.root.kind {
        Kind::Literal => Some(vec![ast.root.value]),
        Kind::Concat(v) => {
            if v.iter().all(|c| matches!(c.kind, Kind::Literal)) {
                Some(v.iter().map(|c| c.value).collect())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Split at the first non-greedy RANGE_ANY child of a root CONCAT whose bounds exceed
/// the chaining threshold (and which is neither first nor last). Returns the
/// remainder AST and the gap (min, max).
pub fn split_at_chaining_point(ast: &mut Ast) -> Option<(Ast, i32, i32)> {
    let Kind::Concat(children) = &mut ast.root.kind else { return None };
    let n = children.len();
    for i in 0..n {
        let c = &children[i];
        if !c.greedy
            && matches!(c.kind, Kind::RangeAny)
            && i > 0
            && i + 1 < n
            && (c.start > STRING_CHAINING_THRESHOLD || c.end > STRING_CHAINING_THRESHOLD)
        {
            let (gmin, gmax) = (c.start, c.end);
            let rest: Vec<Node> = children.drain(i + 1..).collect();
            children.truncate(i);
            let root = Node { kind: Kind::Concat(rest), value: 0, mask: 0, start: 0, end: 0, greedy: true, id: ast.nodes };
            let rem = Ast { root, fast: ast.fast, greedy: ast.greedy, ungreedy: ast.ungreedy, nodes: ast.nodes + 1 };
            ast.nodes += 1;
            return Some((rem, gmin, gmax));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yara_yre_parse_basic() {
        assert!(parse_regex(b"abc").is_ok());
        assert!(parse_regex(b"a|").is_ok());
        assert!(parse_regex(b"|a").is_err());
        assert!(parse_regex(b"()").is_err());
        assert!(parse_regex(b"a**").is_err());
        assert!(parse_regex(b"\\1").is_err());
        assert!(parse_regex(b"a{2,1}").is_err());
        assert!(parse_regex(b"a{1,40000}").is_err());
        assert!(parse_regex(b"[a-").is_err());
        assert!(parse_regex(b"x{").is_ok());
        assert!(parse_regex(b"a{,3}").is_ok());
        assert!(parse_hex(b"{ 4D 5A }").is_ok());
        assert!(parse_hex(b"{ 4D [2] 5A }").is_ok());
        assert!(parse_hex(b"{ [2] 5A }").is_err());
        assert!(parse_hex(b"{ 4D [2] }").is_err());
        assert!(parse_hex(b"{ 4D ( 5A | 00 [1-300] 01 ) }").is_err());
        assert!(parse_hex(b"{ 4D ( 5A | 00 [1-3] 01 ) }").is_ok());
        assert!(parse_hex(b"{ 4 }").is_err());
        assert!(parse_hex(b"{ 4D [0] 5A }").is_err());
        assert!(parse_hex(b"{ 4D [3-1] 5A }").is_err());
        assert!(parse_hex(b"{ 4D [-] 5A }").is_ok());
        assert!(parse_hex(b"{ ~4D ?? ?1 2? ~?1 ~2? }").is_ok());
        let a = parse_hex(b"{ 4D 5A }").unwrap();
        assert_eq!(extract_literal(&a), Some(vec![0x4d, 0x5a]));
    }
}
