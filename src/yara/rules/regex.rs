//! Regular expressions of the `matches` operator: libyara 4.5 regexp syntax
//! (re_lexer.l / re_grammar.y), its compile-time limits (re.c `_yr_re_emit`:
//! split ids, jump offsets) and its `yr_re_exec(..., RE_FLAGS_SCAN)` search
//! semantics, evaluated by translating the parsed AST into an explicit
//! byte-set pattern for the crate's regex engine ([`crate::yara::regex`]).
//!
//! Scan semantics reproduced: yara starts a match attempt at every offset below
//! `T = min(len, YR_RE_SCAN_LIMIT=1024)` (only offset 0 for empty input), a match
//! may not consume bytes at or beyond `T`, `^` only matches at offset 0 and `$`
//! only at the real end of the string. Known approximation: `\b`/`\B` exactly at
//! offset `T` of a string longer than 1024 bytes see the end of the truncated
//! input instead of the next byte.

use crate::yara::regex::Regex;

/// RE_MAX_RANGE (INT16_MAX).
const RE_MAX_RANGE: i32 = 32767;
/// RE_MAX_SPLIT_ID.
const RE_MAX_SPLIT_ID: u32 = 128;
/// YR_RE_SCAN_LIMIT.
const SCAN_LIMIT: usize = 1024;
/// Parenthesis nesting cap (bison would run out of stack far later; real rules
/// never get close). Keeps every recursive walk shallow.
const MAX_DEPTH: usize = 200;

const WORD_CHARS: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x03, 0xFE, 0xFF, 0xFF, 0x87, 0xFE, 0xFF, 0xFF, 0x07, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const SPACE_CHARS: [u8; 32] = [
    0x00, 0x3E, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Clone, Debug, PartialEq)]
enum Node {
    Lit(u8),
    Any,
    Class { bitmap: [u8; 32], negated: bool },
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
    Range(Box<Node>, i32, i32),
    RangeAny(i32, i32),
}

#[derive(Clone, Debug, PartialEq)]
enum RTok {
    Char(u8),
    /// `{n,m}` / `{n}`: (lo, hi).
    Range(i32, i32),
    Class([u8; 32], bool),
    WordChar,
    NonWordChar,
    Space,
    NonSpace,
    Digit,
    NonDigit,
    WordBoundary,
    NonWordBoundary,
    /// One of `( ) | $ . ^ + * ?`.
    Special(u8),
    End,
}

struct RLexer<'a> {
    s: &'a [u8],
    i: usize,
}

/// C `atoi` on a digit run (glibc: strtol clamped to LONG_MAX, then truncated to int).
fn atoi(d: &[u8]) -> i32 {
    let mut v: i64 = 0;
    for &c in d {
        if !c.is_ascii_digit() {
            break;
        }
        v = v.saturating_mul(10).saturating_add((c - b'0') as i64);
    }
    v as i32
}

fn set_bit(bm: &mut [u8; 32], c: u8) {
    bm[(c / 8) as usize] |= 1 << (c % 8);
}

fn has_bit(bm: &[u8; 32], c: u8) -> bool {
    bm[(c / 8) as usize] & (1 << (c % 8)) != 0
}

impl<'a> RLexer<'a> {
    fn peek(&self, k: usize) -> Option<u8> {
        self.s.get(self.i + k).copied()
    }

    /// `read_escaped_char` after a consumed backslash: None = illegal.
    fn read_escaped(&mut self) -> Option<u8> {
        let c1 = self.peek(0)?;
        if c1 == 0 {
            return None;
        }
        self.i += 1;
        if c1 == b'x' {
            let a = self.peek(0).filter(|&c| c != 0)?;
            self.i += 1;
            let b = self.peek(0).filter(|&c| c != 0)?;
            self.i += 1;
            return escaped_value(&[b'\\', b'x', a, b]);
        }
        escaped_value(&[b'\\', c1])
    }

    fn next(&mut self) -> Result<RTok, String> {
        let Some(c) = self.peek(0) else {
            return Ok(RTok::End);
        };
        match c {
            b'{' => {
                if let Some((t, len)) = self.lex_range()? {
                    self.i += len;
                    return Ok(t);
                }
                self.i += 1;
                Ok(RTok::Char(b'{'))
            }
            b'[' => {
                self.i += 1;
                self.lex_class()
            }
            b'\\' => {
                match self.peek(1) {
                    Some(b'w') => return self.two(RTok::WordChar),
                    Some(b'W') => return self.two(RTok::NonWordChar),
                    Some(b's') => return self.two(RTok::Space),
                    Some(b'S') => return self.two(RTok::NonSpace),
                    Some(b'd') => return self.two(RTok::Digit),
                    Some(b'D') => return self.two(RTok::NonDigit),
                    Some(b'b') => return self.two(RTok::WordBoundary),
                    Some(b'B') => return self.two(RTok::NonWordBoundary),
                    Some(d) if d.is_ascii_digit() => return Err("backreferences are not allowed".into()),
                    _ => {}
                }
                self.i += 1;
                match self.read_escaped() {
                    Some(v) => Ok(RTok::Char(v)),
                    None => Err("illegal escape sequence".into()),
                }
            }
            b'(' | b')' | b'|' | b'$' | b'.' | b'^' | b'+' | b'*' | b'?' => {
                self.i += 1;
                Ok(RTok::Special(c))
            }
            _ => {
                self.i += 1;
                Ok(RTok::Char(c))
            }
        }
    }

    fn two(&mut self, t: RTok) -> Result<RTok, String> {
        self.i += 2;
        Ok(t)
    }

    /// `\{{digit}*[ ]*,[ ]*{digit}*\}` or `\{{digit}+\}` at `self.i`.
    fn lex_range(&self) -> Result<Option<(RTok, usize)>, String> {
        let s = &self.s[self.i..];
        let mut j = 1;
        let d1 = j;
        while j < s.len() && s[j].is_ascii_digit() {
            j += 1;
        }
        let lo_digits = &s[d1..j];
        if s.get(j) == Some(&b'}') && !lo_digits.is_empty() {
            let v = atoi(lo_digits);
            if v > RE_MAX_RANGE || v < 0 {
                return Err("repeat interval too large".into());
            }
            return Ok(Some((RTok::Range(v, v), j + 1)));
        }
        while s.get(j) == Some(&b' ') {
            j += 1;
        }
        if s.get(j) != Some(&b',') {
            return Ok(None);
        }
        j += 1;
        while s.get(j) == Some(&b' ') {
            j += 1;
        }
        let d2 = j;
        while j < s.len() && s[j].is_ascii_digit() {
            j += 1;
        }
        if s.get(j) != Some(&b'}') {
            return Ok(None);
        }
        let lo = atoi(lo_digits);
        let hi = if d2 == j { RE_MAX_RANGE } else { atoi(&s[d2..j]) };
        if hi > RE_MAX_RANGE {
            return Err("repeat interval too large".into());
        }
        if hi < lo || hi < 0 || lo < 0 {
            return Err("bad repeat interval".into());
        }
        Ok(Some((RTok::Range(lo, hi), j + 1)))
    }

    fn lex_class(&mut self) -> Result<RTok, String> {
        let mut bm = [0u8; 32];
        let mut negated = false;
        if self.peek(0) == Some(b'^') {
            negated = true;
            self.i += 1;
        }
        if self.peek(0) == Some(b']') {
            set_bit(&mut bm, b']');
            self.i += 1;
        }
        loop {
            let Some(c) = self.peek(0) else {
                return Err("missing terminating ] for character class".into());
            };
            if c == b']' {
                self.i += 1;
                return Ok(RTok::Class(bm, negated));
            }
            // Range rule: (\\x{hh}|\\.|[^]\\])-[^]]
            let start_len = if c == b'\\' {
                if self.peek(1) == Some(b'x')
                    && self.peek(2).is_some_and(|b| b.is_ascii_hexdigit())
                    && self.peek(3).is_some_and(|b| b.is_ascii_hexdigit())
                {
                    Some(4)
                } else if self.peek(1).is_some_and(|b| b != b'\n') {
                    Some(2)
                } else {
                    None
                }
            } else {
                Some(1)
            };
            if let Some(sl) = start_len {
                if self.peek(sl) == Some(b'-') && self.peek(sl + 1).is_some_and(|b| b != b']') {
                    let start = if c == b'\\' {
                        escaped_value(&self.s[self.i..self.i + sl]).ok_or_else(|| "illegal escape sequence".to_string())?
                    } else {
                        c
                    };
                    let mut end = self.s[self.i + sl + 1];
                    self.i += sl + 2;
                    if end == b'\\' {
                        end = self.read_escaped().ok_or_else(|| "illegal escape sequence".to_string())?;
                    }
                    if end < start {
                        return Err("bad character range".into());
                    }
                    for v in start..=end {
                        set_bit(&mut bm, v);
                    }
                    continue;
                }
            }
            if c == b'\\' {
                match self.peek(1) {
                    Some(b'w') => {
                        for (b, w) in bm.iter_mut().zip(WORD_CHARS) {
                            *b |= w;
                        }
                        self.i += 2;
                        continue;
                    }
                    Some(b'W') => {
                        for (b, w) in bm.iter_mut().zip(WORD_CHARS) {
                            *b |= !w;
                        }
                        self.i += 2;
                        continue;
                    }
                    Some(b's') => {
                        for (b, w) in bm.iter_mut().zip(SPACE_CHARS) {
                            *b |= w;
                        }
                        self.i += 2;
                        continue;
                    }
                    Some(b'S') => {
                        for (b, w) in bm.iter_mut().zip(SPACE_CHARS) {
                            *b |= !w;
                        }
                        self.i += 2;
                        continue;
                    }
                    Some(b'd') => {
                        for v in b'0'..=b'9' {
                            set_bit(&mut bm, v);
                        }
                        self.i += 2;
                        continue;
                    }
                    Some(b'D') => {
                        for (k, b) in bm.iter_mut().enumerate() {
                            if k == 6 {
                                continue;
                            }
                            if k == 7 {
                                *b |= 0xFC;
                            } else {
                                *b = 0xFF;
                            }
                        }
                        self.i += 2;
                        continue;
                    }
                    _ => {}
                }
                self.i += 1;
                let v = self.read_escaped().ok_or_else(|| "illegal escape sequence".to_string())?;
                set_bit(&mut bm, v);
                continue;
            }
            if (32..127).contains(&c) {
                set_bit(&mut bm, c);
                self.i += 1;
                continue;
            }
            if c == b'\n' {
                // flex `.` does not match a newline: no rule matches, the byte is
                // echoed and skipped.
                self.i += 1;
                continue;
            }
            return Err("non-ascii character".into());
        }
    }
}

/// `escaped_char_value` (non-strict): `text` starts with a backslash.
fn escaped_value(text: &[u8]) -> Option<u8> {
    let c1 = *text.get(1)?;
    Some(match c1 {
        b'x' => {
            let a = *text.get(2)?;
            let b = *text.get(3)?;
            if !a.is_ascii_hexdigit() || !b.is_ascii_hexdigit() {
                return None;
            }
            let h = |c: u8| match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => c - b'A' + 10,
            };
            h(a) << 4 | h(b)
        }
        b'n' => b'\n',
        b't' => b'\t',
        b'r' => b'\r',
        b'f' => 0x0c,
        b'a' => 0x07,
        other => other,
    })
}

struct RParser<'a> {
    lx: RLexer<'a>,
    tok: RTok,
    depth: usize,
}

impl<'a> RParser<'a> {
    fn bump(&mut self) -> Result<(), String> {
        self.tok = self.lx.next()?;
        Ok(())
    }

    // alternative : concatenation | alternative '|' concatenation | alternative '|'
    fn alternative(&mut self) -> Result<Node, String> {
        let mut left = self.concatenation()?;
        while self.tok == RTok::Special(b'|') {
            self.bump()?;
            let right = if self.starts_repeat() { self.concatenation()? } else { Node::Empty };
            left = Node::Alt(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn starts_repeat(&self) -> bool {
        matches!(
            self.tok,
            RTok::Char(_)
                | RTok::Class(..)
                | RTok::WordChar
                | RTok::NonWordChar
                | RTok::Space
                | RTok::NonSpace
                | RTok::Digit
                | RTok::NonDigit
                | RTok::WordBoundary
                | RTok::NonWordBoundary
                | RTok::Special(b'(' | b'.' | b'^' | b'$')
        )
    }

    fn concatenation(&mut self) -> Result<Node, String> {
        let mut items = Vec::new();
        if !self.starts_repeat() {
            return Err("syntax error".into());
        }
        while self.starts_repeat() {
            items.push(self.repeat()?);
        }
        Ok(Node::Concat(items))
    }

    fn repeat(&mut self) -> Result<Node, String> {
        let simple = match self.tok {
            RTok::WordBoundary => Some(Node::WordBoundary),
            RTok::NonWordBoundary => Some(Node::NonWordBoundary),
            RTok::Special(b'^') => Some(Node::AnchorStart),
            RTok::Special(b'$') => Some(Node::AnchorEnd),
            _ => None,
        };
        if let Some(n) = simple {
            self.bump()?;
            return Ok(n);
        }
        let single = self.single()?;
        let node = match self.tok {
            RTok::Special(b'*') => {
                self.bump()?;
                self.eat_lazy()?;
                Node::Star(Box::new(single))
            }
            RTok::Special(b'+') => {
                self.bump()?;
                self.eat_lazy()?;
                Node::Plus(Box::new(single))
            }
            RTok::Special(b'?') => {
                self.bump()?;
                self.eat_lazy()?;
                range_of(single, 0, 1)
            }
            RTok::Range(lo, hi) => {
                self.bump()?;
                self.eat_lazy()?;
                range_of(single, lo, hi)
            }
            _ => single,
        };
        Ok(node)
    }

    fn eat_lazy(&mut self) -> Result<(), String> {
        if self.tok == RTok::Special(b'?') {
            self.bump()?;
        }
        Ok(())
    }

    fn single(&mut self) -> Result<Node, String> {
        let t = std::mem::replace(&mut self.tok, RTok::End);
        let n = match t {
            RTok::Special(b'(') => {
                self.depth += 1;
                if self.depth > MAX_DEPTH {
                    return Err("memory exhausted".into());
                }
                self.bump()?;
                let inner = self.alternative()?;
                if self.tok != RTok::Special(b')') {
                    return Err("syntax error".into());
                }
                self.depth -= 1;
                inner
            }
            RTok::Special(b'.') => Node::Any,
            RTok::Char(c) => Node::Lit(c),
            RTok::WordChar => Node::WordChar,
            RTok::NonWordChar => Node::NonWordChar,
            RTok::Space => Node::Space,
            RTok::NonSpace => Node::NonSpace,
            RTok::Digit => Node::Digit,
            RTok::NonDigit => Node::NonDigit,
            RTok::Class(bitmap, negated) => Node::Class { bitmap, negated },
            _ => return Err("syntax error".into()),
        };
        self.bump()?;
        Ok(n)
    }
}

fn range_of(single: Node, lo: i32, hi: i32) -> Node {
    if single == Node::Any {
        Node::RangeAny(lo, hi)
    } else {
        Node::Range(Box::new(single), lo, hi)
    }
}

fn parse(src: &[u8]) -> Result<Node, String> {
    // libyara hands the regexp to its parser as a C string.
    let src = match src.iter().position(|&b| b == 0) {
        Some(p) => &src[..p],
        None => src,
    };
    let mut p = RParser { lx: RLexer { s: src, i: 0 }, tok: RTok::End, depth: 0 };
    p.bump()?;
    let root = p.alternative()?;
    if p.tok != RTok::End {
        return Err("syntax error".into());
    }
    Ok(root)
}

/// Code size / split accounting of `_yr_re_emit` (forward code), with the same
/// "too large" / "too complex" failures.
struct Emit {
    splits: u32,
}

const SPLIT: i64 = 4;
const JUMP: i64 = 3;
const CLASS: i64 = 34;
const REPEAT_ANY: i64 = 5;
const REPEAT: i64 = 9;

impl Emit {
    fn split(&mut self) -> Result<i64, String> {
        if self.splits == RE_MAX_SPLIT_ID {
            return Err("regular expression is too complex".into());
        }
        self.splits += 1;
        Ok(SPLIT)
    }

    fn size(&mut self, n: &Node) -> Result<i64, String> {
        const TOO_LARGE: &str = "regular expression is too large";
        Ok(match n {
            Node::Lit(_) => 2,
            Node::Class { .. } => CLASS,
            Node::Any
            | Node::WordChar
            | Node::NonWordChar
            | Node::Space
            | Node::NonSpace
            | Node::Digit
            | Node::NonDigit
            | Node::WordBoundary
            | Node::NonWordBoundary
            | Node::AnchorStart
            | Node::AnchorEnd => 1,
            Node::Empty => 0,
            Node::Concat(v) => {
                let mut t = 0;
                for c in v {
                    t += self.size(c)?;
                }
                t
            }
            Node::Plus(c) => {
                let cs = self.size(c)?;
                if -cs < i16::MIN as i64 {
                    return Err(TOO_LARGE.into());
                }
                cs + self.split()?
            }
            Node::Star(c) => {
                let sp = self.split()?;
                let cs = self.size(c)?;
                if -(sp + cs) < i16::MIN as i64 {
                    return Err(TOO_LARGE.into());
                }
                if sp + cs + JUMP > i16::MAX as i64 {
                    return Err(TOO_LARGE.into());
                }
                sp + cs + JUMP
            }
            Node::Alt(a, b) => {
                let sp = self.split()?;
                let a = self.size(a)?;
                if sp + a + JUMP > i16::MAX as i64 {
                    return Err(TOO_LARGE.into());
                }
                let b = self.size(b)?;
                if JUMP + b > i16::MAX as i64 {
                    return Err(TOO_LARGE.into());
                }
                sp + a + JUMP + b
            }
            Node::RangeAny(..) => REPEAT_ANY,
            Node::Range(c, lo, hi) => {
                let (lo, hi) = (*lo, *hi);
                let prolog = lo > 0;
                let repeat = hi > lo + 1 || hi > 2;
                let split = hi > lo;
                let epilog = hi > lo || hi > 1;
                let mut t = 0;
                if prolog {
                    t += self.size(c)?;
                }
                if repeat {
                    t += REPEAT + self.size(c)? + REPEAT;
                }
                let mut tail = 0;
                if split {
                    tail += self.split()?;
                }
                if epilog {
                    tail += self.size(c)?;
                }
                if split && tail > i16::MAX as i64 {
                    return Err(TOO_LARGE.into());
                }
                t + tail
            }
        })
    }
}

/// Translation into the crate engine's (python `re`) syntax using only explicit
/// byte sets, so that no flag or class semantics differ.
struct Translate {
    nocase: bool,
    dotall: bool,
    /// `$` can match (the string is not longer than the scan limit).
    end_reachable: bool,
    out: Vec<u8>,
}

fn push_hex(out: &mut Vec<u8>, b: u8) {
    const H: &[u8; 16] = b"0123456789abcdef";
    out.extend_from_slice(b"\\x");
    out.push(H[(b >> 4) as usize]);
    out.push(H[(b & 15) as usize]);
}

fn altercase(c: u8) -> u8 {
    if c.is_ascii_lowercase() {
        c - 32
    } else if c.is_ascii_uppercase() {
        c + 32
    } else {
        c
    }
}

impl Translate {
    fn set(&mut self, f: impl Fn(u8) -> bool) {
        let mut members = [false; 256];
        let mut count = 0;
        for c in 0..=255u8 {
            if f(c) {
                members[c as usize] = true;
                count += 1;
            }
        }
        if count == 0 {
            self.out.extend_from_slice(b"(?!)");
            return;
        }
        self.out.push(b'[');
        let mut c = 0usize;
        while c < 256 {
            if !members[c] {
                c += 1;
                continue;
            }
            let start = c;
            while c + 1 < 256 && members[c + 1] {
                c += 1;
            }
            push_hex(&mut self.out, start as u8);
            if c > start {
                self.out.push(b'-');
                push_hex(&mut self.out, c as u8);
            }
            c += 1;
        }
        self.out.push(b']');
    }

    fn node(&mut self, n: &Node) {
        let nocase = self.nocase;
        match n {
            Node::Lit(c) => {
                let c = *c;
                if nocase && altercase(c) != c {
                    self.set(|x| x == c || x == altercase(c));
                } else {
                    push_hex(&mut self.out, c);
                }
            }
            Node::Any => {
                let dotall = self.dotall;
                self.set(|x| dotall || x != b'\n');
            }
            Node::Class { bitmap, negated } => {
                let (bm, neg) = (*bitmap, *negated);
                self.set(|x| {
                    let mut r = has_bit(&bm, x);
                    if nocase {
                        r |= has_bit(&bm, altercase(x));
                    }
                    r != neg
                });
            }
            Node::WordChar => self.set(|x| x.is_ascii_alphanumeric() || x == b'_'),
            Node::NonWordChar => self.set(|x| !(x.is_ascii_alphanumeric() || x == b'_')),
            Node::Space => self.set(|x| matches!(x, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c)),
            Node::NonSpace => self.set(|x| !matches!(x, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c)),
            Node::Digit => self.set(|x| x.is_ascii_digit()),
            Node::NonDigit => self.set(|x| !x.is_ascii_digit()),
            Node::WordBoundary => self.out.extend_from_slice(b"\\b"),
            Node::NonWordBoundary => self.out.extend_from_slice(b"\\B"),
            Node::AnchorStart => self.out.extend_from_slice(b"\\A"),
            Node::AnchorEnd => {
                if self.end_reachable {
                    self.out.extend_from_slice(b"\\Z")
                } else {
                    self.out.extend_from_slice(b"(?!)")
                }
            }
            Node::Empty => {}
            Node::Concat(v) => {
                for c in v {
                    self.node(c);
                }
            }
            Node::Alt(a, b) => {
                self.out.extend_from_slice(b"(?:");
                self.node(a);
                self.out.push(b'|');
                self.node(b);
                self.out.push(b')');
            }
            Node::Star(c) => {
                self.group(c);
                self.out.push(b'*');
            }
            Node::Plus(c) => {
                self.group(c);
                self.out.push(b'+');
            }
            Node::Range(c, lo, hi) => {
                self.group(c);
                self.counted(*lo, *hi);
            }
            Node::RangeAny(lo, hi) => {
                self.node(&Node::Any);
                self.counted(*lo, *hi);
            }
        }
    }

    fn group(&mut self, c: &Node) {
        self.out.extend_from_slice(b"(?:");
        self.node(c);
        self.out.push(b')');
    }

    fn counted(&mut self, lo: i32, hi: i32) {
        // Inputs are at most SCAN_LIMIT bytes: an upper bound beyond that is as good
        // as unbounded and keeps the engine's automaton small.
        let s = if hi as usize > SCAN_LIMIT + 1 { format!("{{{lo},}}") } else { format!("{{{lo},{hi}}}") };
        self.out.extend_from_slice(s.as_bytes());
    }
}

/// A compiled `matches` operand.
pub struct CondRegex {
    root: Node,
    /// Engine for inputs whose end is reachable (`$` may match) / not.
    short: Option<Regex>,
    long: Option<Regex>,
}

impl std::fmt::Debug for CondRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CondRegex({:?})", self.root)
    }
}

impl CondRegex {
    /// Compile (yr_re_compile: parse + emit). Err = libyara's error message.
    pub fn new(src: &[u8], nocase: bool, dotall: bool) -> Result<CondRegex, String> {
        let root = parse(src)?;
        Emit { splits: 0 }.size(&root)?;
        let build = |end_reachable: bool| {
            let mut t = Translate { nocase, dotall, end_reachable, out: Vec::new() };
            t.node(&root);
            Regex::new(&t.out, 0).ok()
        };
        let short = build(true);
        let long = build(false);
        Ok(CondRegex { root, short, long })
    }

    /// `text matches /re/` (OP_MATCHES: yr_re_exec with RE_FLAGS_SCAN).
    pub fn is_match(&self, text: &[u8]) -> bool {
        let t = text.len().min(SCAN_LIMIT);
        let re = if text.len() <= SCAN_LIMIT { &self.short } else { &self.long };
        let Some(re) = re else {
            return false;
        };
        match re.search(&text[..t], 0) {
            Some((start, _)) => start < t || t == 0,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(re: &str, text: &str) -> bool {
        CondRegex::new(re.as_bytes(), false, false).unwrap().is_match(text.as_bytes())
    }

    fn err(re: &str) -> String {
        CondRegex::new(re.as_bytes(), false, false).unwrap_err()
    }

    #[test]
    fn yara_regex_basic_matching() {
        assert!(m("abc", "xxabcxx"));
        assert!(!m("abd", "xxabcxx"));
        assert!(m("^ab", "abc"));
        assert!(!m("^bc", "abc"));
        assert!(m("bc$", "abc"));
        assert!(!m("$", "abc"));
        assert!(!m("x*$", "abc"));
        assert!(m("$", ""));
        assert!(m("a.c", "abc"));
        assert!(!m("a.c", "a\nc"));
        assert!(CondRegex::new(b"a.c", false, true).unwrap().is_match(b"a\nc"));
        assert!(m("[a-c]+d", "zzbcd"));
        assert!(m("[^a-c]d", "zzxd"));
        assert!(m("\\d{2,3}", "a12"));
        assert!(!m("\\d{3}", "a12"));
        assert!(m("a|b", "b"));
        assert!(m("a|", "zzz"));
        assert!(m("\\bfoo\\b", "a foo b"));
        assert!(!m("\\bfoo\\b", "afoob"));
        assert!(m("a{,2}b", "b"));
        assert!(m("[]a]", "]"));
        assert!(m("a\\/b", "a/b"));
        assert!(m("\\x41", "A"));
        assert!(m("{", "{"));
        assert!(m("a{1", "a{1"));
        let r = CondRegex::new(b"ABC", true, false).unwrap();
        assert!(r.is_match(b"xabcx"));
        let r = CondRegex::new(b"[^a]", true, false).unwrap();
        assert!(!r.is_match(b"A"));
    }

    #[test]
    fn yara_regex_scan_limit() {
        let mut long = "a".repeat(1100);
        long.push('b');
        assert!(!m("b", &long));
        assert!(m("a", &long));
        assert!(!m("b$", &long));
        let mut s = "a".repeat(1023);
        s.push('b');
        assert!(m("b$", &s));
    }

    #[test]
    fn yara_regex_errors() {
        assert_eq!(err("a{2,1}"), "bad repeat interval");
        assert_eq!(err("a{99999}"), "repeat interval too large");
        assert_eq!(err("(a"), "syntax error");
        assert_eq!(err("[a"), "missing terminating ] for character class");
        assert_eq!(err("\\1"), "backreferences are not allowed");
        assert_eq!(err("a**"), "syntax error");
        assert_eq!(err("a\\"), "illegal escape sequence");
        assert_eq!(err("[z-a]"), "bad character range");
        assert_eq!(err("*a"), "syntax error");
        assert_eq!(err("()"), "syntax error");
        assert_eq!(err("^*"), "syntax error");
        let deep = "(".repeat(500) + &")".repeat(500);
        assert!(CondRegex::new(deep.as_bytes(), false, false).is_err());
        let many = "a*".repeat(129);
        assert_eq!(err(&many), "regular expression is too complex");
        assert!(CondRegex::new("a*".repeat(128).as_bytes(), false, false).is_ok());
    }
}
