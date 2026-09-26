//! Parser for python `re` bytes patterns (derived from the behaviour of CPython's
//! `re/_parser.py`, which is what volatility3 uses). Produces an AST that mirrors
//! sre's intermediate form; flags are resolved later when lowering to HIR.

use super::{Error, FLAG_ASCII, FLAG_DOTALL, FLAG_IGNORECASE, FLAG_LOCALE, FLAG_MULTILINE, FLAG_UNICODE, FLAG_VERBOSE};

/// sre's MAXREPEAT (unbounded repeat marker).
pub const MAXREPEAT: u64 = 4_294_967_295;
/// Maximum group nesting accepted (python would hit its recursion limit eventually).
const MAX_NESTING: usize = 400;
const MAXGROUPS: u64 = 1_073_741_823;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cat {
    Digit,
    NotDigit,
    Space,
    NotSpace,
    Word,
    NotWord,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetItem {
    Lit(u32),
    Range(u32, u32),
    Cat(Cat),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    Beginning,       // ^
    BeginningString, // \A
    Boundary,        // \b
    NonBoundary,     // \B
    End,             // $
    EndString,       // \Z \z
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepKind {
    Greedy,
    Lazy,
    Possessive,
}

#[derive(Clone, Debug)]
pub enum Node {
    Lit(u32),
    NotLit(u32),
    Any,
    In { negate: bool, items: Vec<SetItem> },
    At(At),
    Branch(Vec<Vec<Node>>),
    Repeat { min: u64, max: u64, kind: RepKind, item: Vec<Node> },
    /// A (possibly capturing) group with scoped flags.
    Sub { group: Option<u32>, add: u32, del: u32, p: Vec<Node> },
    Atomic(Vec<Node>),
    Assert { behind: bool, negate: bool, p: Vec<Node> },
    Failure,
    GroupRef(u32),
    GroupRefExists { group: u32, yes: Vec<Node>, no: Option<Vec<Node>> },
}

pub struct Parsed {
    pub nodes: Vec<Node>,
    /// Global flags (from the caller and inline `(?x)` at the start).
    pub flags: u32,
    /// Number of groups including group 0.
    pub groups: u32,
    pub names: Vec<(String, u32)>,
    /// (min, max) width of each group (index 0 unused), MAXWIDTH-saturated.
    pub group_widths: Vec<(u128, u128)>,
}

pub const MAXWIDTH: u128 = 1u128 << 64;

// ---------------------------------------------------------------------------------------
// Tokenizer: a "char" is one byte, or an escape pair (backslash + byte).
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tok {
    Ch(u32),
    Esc(u32),
}

struct Source<'a> {
    s: &'a [u32],
    /// str pattern (python `istext`)
    text: bool,
    index: usize,
    next: Option<Tok>,
    next_len: usize,
}

impl<'a> Source<'a> {
    fn new(s: &'a [u32], text: bool) -> Result<Source<'a>, Error> {
        let mut src = Source { s, text, index: 0, next: None, next_len: 0 };
        src.advance()?;
        Ok(src)
    }

    fn advance(&mut self) -> Result<(), Error> {
        let i = self.index;
        if i >= self.s.len() {
            self.next = None;
            self.next_len = 0;
            return Ok(());
        }
        let c = self.s[i];
        if c == 0x5c {
            if i + 1 >= self.s.len() {
                return Err(Error::new("bad escape (end of pattern)", self.s.len().saturating_sub(1)));
            }
            self.next = Some(Tok::Esc(self.s[i + 1]));
            self.next_len = 2;
            self.index = i + 2;
        } else {
            self.next = Some(Tok::Ch(c));
            self.next_len = 1;
            self.index = i + 1;
        }
        Ok(())
    }

    fn get(&mut self) -> Result<Option<Tok>, Error> {
        let t = self.next;
        self.advance()?;
        Ok(t)
    }

    fn matches(&mut self, c: u8) -> Result<bool, Error> {
        if self.next == Some(Tok::Ch(c as u32)) {
            self.advance()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn next_is_ch_in(&self, set: &[u8]) -> bool {
        matches!(self.next, Some(Tok::Ch(c)) if c < 128 && set.contains(&(c as u8)))
    }

    fn next_ch(&self) -> Option<u32> {
        match self.next {
            Some(Tok::Ch(c)) => Some(c),
            _ => None,
        }
    }

    fn tell(&self) -> usize {
        self.index - self.next_len
    }

    fn seek(&mut self, index: usize) -> Result<(), Error> {
        self.index = index;
        self.advance()
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T, Error> {
        Err(Error::new(msg, self.tell()))
    }

    /// Read up to `n` plain chars from `set`.
    fn getwhile(&mut self, n: usize, set: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        for _ in 0..n {
            match self.next {
                Some(Tok::Ch(c)) if c < 128 && set.contains(&(c as u8)) => {
                    out.push(c as u8);
                    self.advance()?;
                }
                _ => break,
            }
        }
        Ok(out)
    }

    fn getuntil(&mut self, term: u8, name: &str) -> Result<Vec<u32>, Error> {
        let mut out = Vec::new();
        loop {
            let c = self.next;
            self.advance()?;
            match c {
                None => {
                    if out.is_empty() {
                        return self.err(format!("missing {name}"));
                    }
                    return self.err(format!("missing {}, unterminated name", term as char));
                }
                Some(Tok::Ch(x)) if x == term as u32 => {
                    if out.is_empty() {
                        return self.err(format!("missing {name}"));
                    }
                    break;
                }
                Some(Tok::Ch(x)) => out.push(x),
                Some(Tok::Esc(x)) => {
                    out.push(0x5c);
                    out.push(x);
                }
            }
        }
        Ok(out)
    }
}

const DIGITS: &[u8] = b"0123456789";
const OCTDIGITS: &[u8] = b"01234567";
const HEXDIGITS: &[u8] = b"0123456789abcdefABCDEF";
const WHITESPACE: &[u8] = b" \t\n\r\x0b\x0c";
/// sre's SPECIAL_CHARS (`. \\ [ { ( ) * + ? ^ $ |`).
#[inline]
fn is_special(c: u32) -> bool {
    matches!(c, 0x2e | 0x5c | 0x5b | 0x7b | 0x28 | 0x29 | 0x2a | 0x2b | 0x3f | 0x5e | 0x24 | 0x7c)
}

fn is_ascii_letter(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

fn parse_int(digits: &[u8], radix: u32) -> u64 {
    let mut v: u64 = 0;
    for &d in digits {
        let x = (d as char).to_digit(radix).unwrap_or(0) as u64;
        v = v.saturating_mul(radix as u64).saturating_add(x);
    }
    v
}

/// python `str.isidentifier()` (bytes patterns: ASCII only).
fn is_identifier(name: &[u32], text: bool) -> bool {
    let word = |c: u32| -> bool {
        if c < 128 {
            (c as u8).is_ascii_alphanumeric() || c == 0x5f
        } else {
            text && super::unicode_class::in_table(super::unicode::WORD, c)
        }
    };
    let start = |c: u32| -> bool {
        if c < 128 {
            (c as u8).is_ascii_alphabetic() || c == 0x5f
        } else {
            word(c) && !super::unicode_class::in_table(super::unicode::DIGIT, c)
        }
    };
    match name.first() {
        None => false,
        Some(&c) if start(c) => name.iter().all(|&c| word(c)),
        _ => false,
    }
}

fn units_to_string(u: &[u32]) -> String {
    u.iter().map(|&c| char::from_u32(c).unwrap_or('\u{fffd}')).collect()
}

fn units_digits(u: &[u32]) -> Option<Vec<u8>> {
    if u.iter().all(|&c| (0x30..=0x39).contains(&c)) { Some(u.iter().map(|&c| c as u8).collect()) } else { None }
}

enum Esc {
    Node(Node),
    Cat(Cat),
}

// ---------------------------------------------------------------------------------------
// Parser state
// ---------------------------------------------------------------------------------------

struct State {
    flags: u32,
    names: Vec<(String, u32)>,
    /// None = open group.
    widths: Vec<Option<(u128, u128)>>,
    lookbehind_groups: Option<u32>,
    grouprefpos: Vec<(u32, usize)>,
}

impl State {
    fn groups(&self) -> u32 {
        self.widths.len() as u32
    }

    fn checkgroup(&self, gid: u32) -> bool {
        (gid as usize) < self.widths.len() && self.widths[gid as usize].is_some()
    }

    fn check_lookbehind_group(&self, gid: u32, src: &Source) -> Result<(), Error> {
        if let Some(lb) = self.lookbehind_groups {
            if !self.checkgroup(gid) {
                return src.err("cannot refer to an open group");
            }
            if gid >= lb {
                return src.err("cannot refer to group defined in the same lookbehind subpattern");
            }
        }
        Ok(())
    }
}

pub fn parse(pattern: &[u8], flags: u32) -> Result<Parsed, Error> {
    let units: Vec<u32> = pattern.iter().map(|&b| b as u32).collect();
    parse_units(&units, flags, false)
}

/// Parse a python str pattern (codepoints).
pub fn parse_str(pattern: &str, flags: u32) -> Result<Parsed, Error> {
    let units: Vec<u32> = pattern.chars().map(|c| c as u32).collect();
    parse_units(&units, flags, true)
}

fn parse_units(units: &[u32], flags: u32, text: bool) -> Result<Parsed, Error> {
    let mut src = Source::new(units, text)?;
    let mut state = State {
        flags,
        names: Vec::new(),
        widths: vec![None],
        lookbehind_groups: None,
        grouprefpos: Vec::new(),
    };
    let verbose = flags & FLAG_VERBOSE != 0;
    let nodes = parse_sub(&mut src, &mut state, verbose, 0)?;
    // fix_flags
    if text {
        if state.flags & FLAG_LOCALE != 0 {
            return Err(Error::new("cannot use LOCALE flag with a str pattern", 0));
        }
        if state.flags & FLAG_ASCII == 0 {
            state.flags |= FLAG_UNICODE;
        } else if state.flags & FLAG_UNICODE != 0 {
            return Err(Error::new("ASCII and UNICODE flags are incompatible", 0));
        }
    } else {
        if state.flags & FLAG_UNICODE != 0 {
            return Err(Error::new("cannot use UNICODE flag with a bytes pattern", 0));
        }
        if state.flags & FLAG_LOCALE != 0 && state.flags & FLAG_ASCII != 0 {
            return Err(Error::new("ASCII and LOCALE flags are incompatible", 0));
        }
    }
    if src.next.is_some() {
        return src.err("unbalanced parenthesis");
    }
    for &(g, pos) in &state.grouprefpos {
        if g >= state.groups() {
            return Err(Error::new(format!("invalid group reference {g}"), pos));
        }
    }
    let group_widths = state.widths.iter().map(|w| w.unwrap_or((0, 0))).collect();
    Ok(Parsed { nodes, flags: state.flags, groups: state.groups(), names: state.names, group_widths })
}

fn parse_sub(src: &mut Source, state: &mut State, verbose: bool, nested: usize) -> Result<Vec<Node>, Error> {
    if nested > MAX_NESTING {
        return src.err("too deeply nested");
    }
    let mut items: Vec<Vec<Node>> = Vec::new();
    let mut verbose = verbose;
    loop {
        let first = nested == 0 && items.is_empty();
        items.push(parse_seq(src, state, verbose, nested + 1, first)?);
        if !src.matches(b'|')? {
            break;
        }
        if nested == 0 {
            verbose = state.flags & FLAG_VERBOSE != 0;
        }
    }
    if items.len() == 1 {
        return Ok(items.pop().unwrap_or_default());
    }
    Ok(vec![Node::Branch(items)])
}

/// `\u XXXX` / `\U XXXXXXXX` (str patterns only). Returns None when not applicable.
fn unicode_escape(src: &mut Source, c: u8, start: usize) -> Result<Option<Esc>, Error> {
    if !src.text || (c != b'u' && c != b'U') {
        return Ok(None);
    }
    let n = if c == b'u' { 4 } else { 8 };
    let h = src.getwhile(n, HEXDIGITS)?;
    if h.len() != n {
        return Err(Error::new(format!("incomplete escape \\{}{}", c as char, String::from_utf8_lossy(&h)), start));
    }
    let v = parse_int(&h, 16);
    if v > 0x10ffff {
        return Err(Error::new(format!("bad escape \\{}{}", c as char, String::from_utf8_lossy(&h)), start));
    }
    Ok(Some(Esc::Node(Node::Lit(v as u32))))
}

fn class_escape(src: &mut Source, c: u32) -> Result<Esc, Error> {
    let start = src.tell().saturating_sub(2);
    if c >= 128 {
        return Ok(Esc::Node(Node::Lit(c)));
    }
    let c = c as u8;
    match c {
        b'a' => return Ok(Esc::Node(Node::Lit(0x07))),
        b'b' => return Ok(Esc::Node(Node::Lit(0x08))),
        b'f' => return Ok(Esc::Node(Node::Lit(0x0c))),
        b'n' => return Ok(Esc::Node(Node::Lit(0x0a))),
        b'r' => return Ok(Esc::Node(Node::Lit(0x0d))),
        b't' => return Ok(Esc::Node(Node::Lit(0x09))),
        b'v' => return Ok(Esc::Node(Node::Lit(0x0b))),
        b'\\' => return Ok(Esc::Node(Node::Lit(0x5c))),
        b'd' => return Ok(Esc::Cat(Cat::Digit)),
        b'D' => return Ok(Esc::Cat(Cat::NotDigit)),
        b's' => return Ok(Esc::Cat(Cat::Space)),
        b'S' => return Ok(Esc::Cat(Cat::NotSpace)),
        b'w' => return Ok(Esc::Cat(Cat::Word)),
        b'W' => return Ok(Esc::Cat(Cat::NotWord)),
        _ => {}
    }
    if c == b'x' {
        let h = src.getwhile(2, HEXDIGITS)?;
        if h.len() != 2 {
            return Err(Error::new(format!("incomplete escape \\x{}", String::from_utf8_lossy(&h)), start));
        }
        return Ok(Esc::Node(Node::Lit(parse_int(&h, 16) as u32)));
    }
    if let Some(e) = unicode_escape(src, c, start)? {
        return Ok(e);
    }
    if c == b'N' && src.text {
        return Err(Error::new("\\N{...} escapes are not supported", start));
    }
    if OCTDIGITS.contains(&c) {
        let mut d = vec![c];
        d.extend(src.getwhile(2, OCTDIGITS)?);
        let v = parse_int(&d, 8);
        if v > 0o377 {
            return Err(Error::new("octal escape value outside of range 0-0o377", start));
        }
        return Ok(Esc::Node(Node::Lit(v as u32)));
    }
    if DIGITS.contains(&c) || is_ascii_letter(c) {
        return Err(Error::new(format!("bad escape \\{}", c as char), start));
    }
    Ok(Esc::Node(Node::Lit(c as u32)))
}

fn escape(src: &mut Source, state: &mut State, c: u32) -> Result<Esc, Error> {
    let start = src.tell().saturating_sub(2);
    if c >= 128 {
        return Ok(Esc::Node(Node::Lit(c)));
    }
    let c = c as u8;
    match c {
        b'A' => return Ok(Esc::Node(Node::At(At::BeginningString))),
        b'b' => return Ok(Esc::Node(Node::At(At::Boundary))),
        b'B' => return Ok(Esc::Node(Node::At(At::NonBoundary))),
        b'z' | b'Z' => return Ok(Esc::Node(Node::At(At::EndString))),
        b'd' => return Ok(Esc::Cat(Cat::Digit)),
        b'D' => return Ok(Esc::Cat(Cat::NotDigit)),
        b's' => return Ok(Esc::Cat(Cat::Space)),
        b'S' => return Ok(Esc::Cat(Cat::NotSpace)),
        b'w' => return Ok(Esc::Cat(Cat::Word)),
        b'W' => return Ok(Esc::Cat(Cat::NotWord)),
        b'a' => return Ok(Esc::Node(Node::Lit(0x07))),
        b'f' => return Ok(Esc::Node(Node::Lit(0x0c))),
        b'n' => return Ok(Esc::Node(Node::Lit(0x0a))),
        b'r' => return Ok(Esc::Node(Node::Lit(0x0d))),
        b't' => return Ok(Esc::Node(Node::Lit(0x09))),
        b'v' => return Ok(Esc::Node(Node::Lit(0x0b))),
        b'\\' => return Ok(Esc::Node(Node::Lit(0x5c))),
        _ => {}
    }
    if c == b'x' {
        let h = src.getwhile(2, HEXDIGITS)?;
        if h.len() != 2 {
            return Err(Error::new(format!("incomplete escape \\x{}", String::from_utf8_lossy(&h)), start));
        }
        return Ok(Esc::Node(Node::Lit(parse_int(&h, 16) as u32)));
    }
    if let Some(e) = unicode_escape(src, c, start)? {
        return Ok(e);
    }
    if c == b'N' && src.text {
        return Err(Error::new("\\N{...} escapes are not supported", start));
    }
    if c == b'0' {
        let mut d = vec![c];
        d.extend(src.getwhile(2, OCTDIGITS)?);
        return Ok(Esc::Node(Node::Lit(parse_int(&d, 8) as u32)));
    }
    if DIGITS.contains(&c) {
        let mut d = vec![c];
        if let Some(n) = src.next_ch().filter(|&n| n < 128).map(|n| n as u8) {
            if DIGITS.contains(&n) {
                src.get()?;
                d.push(n);
                if OCTDIGITS.contains(&d[0]) && OCTDIGITS.contains(&d[1]) {
                    if let Some(n3) = src.next_ch().filter(|&n| n < 128).map(|n| n as u8) {
                        if OCTDIGITS.contains(&n3) {
                            src.get()?;
                            d.push(n3);
                            let v = parse_int(&d, 8);
                            if v > 0o377 {
                                return Err(Error::new("octal escape value outside of range 0-0o377", start));
                            }
                            return Ok(Esc::Node(Node::Lit(v as u32)));
                        }
                    }
                }
            }
        }
        let group = parse_int(&d, 10);
        if group < state.groups() as u64 {
            let g = group as u32;
            if !state.checkgroup(g) {
                return Err(Error::new("cannot refer to an open group", start));
            }
            state.check_lookbehind_group(g, src)?;
            return Ok(Esc::Node(Node::GroupRef(g)));
        }
        return Err(Error::new(format!("invalid group reference {group}"), start + 1));
    }
    if is_ascii_letter(c) {
        return Err(Error::new(format!("bad escape \\{}", c as char), start));
    }
    Ok(Esc::Node(Node::Lit(c as u32)))
}

fn cat_node(c: Cat) -> Node {
    Node::In { negate: false, items: vec![SetItem::Cat(c)] }
}

fn uniq(items: Vec<SetItem>) -> Vec<SetItem> {
    let mut out: Vec<SetItem> = Vec::with_capacity(items.len());
    for it in items {
        if !out.contains(&it) {
            out.push(it);
        }
    }
    out
}

fn parse_seq(src: &mut Source, state: &mut State, verbose: bool, nested: usize, first: bool) -> Result<Vec<Node>, Error> {
    let mut sub: Vec<Node> = Vec::with_capacity(8);
    let mut verbose = verbose;
    loop {
        let this = match src.next {
            None => break,
            Some(Tok::Ch(0x7c)) | Some(Tok::Ch(0x29)) => break,
            Some(t) => t,
        };
        src.get()?;
        if verbose {
            if let Tok::Ch(c) = this {
                if c < 128 && WHITESPACE.contains(&(c as u8)) {
                    continue;
                }
                if c == 0x23 {
                    loop {
                        match src.get()? {
                            None | Some(Tok::Ch(0x0a)) => break,
                            _ => {}
                        }
                    }
                    continue;
                }
            }
        }
        match this {
            Tok::Esc(c) => match escape(src, state, c)? {
                Esc::Node(n) => sub.push(n),
                Esc::Cat(c) => sub.push(cat_node(c)),
            },
            Tok::Ch(c) if !is_special(c) => {
                sub.push(Node::Lit(c));
                if !verbose {
                    // the rest of a run of plain characters
                    while let Some(Tok::Ch(c)) = src.next {
                        if is_special(c) {
                            break;
                        }
                        sub.push(Node::Lit(c));
                        src.advance()?;
                    }
                }
            }
            Tok::Ch(0x5b) => {
                let here = src.tell() - 1;
                let negate = src.matches(b'^')?;
                let mut set: Vec<SetItem> = Vec::new();
                loop {
                    let this = src.get()?;
                    let code1: Esc = match this {
                        None => return Err(Error::new("unterminated character set", here)),
                        Some(Tok::Ch(0x5d)) if !set.is_empty() => break,
                        Some(Tok::Esc(c)) => class_escape(src, c)?,
                        Some(Tok::Ch(c)) => Esc::Node(Node::Lit(c)),
                    };
                    if src.matches(b'-')? {
                        let that = src.get()?;
                        let code2 = match that {
                            None => return Err(Error::new("unterminated character set", here)),
                            Some(Tok::Ch(0x5d)) => {
                                match code1 {
                                    Esc::Cat(c) => set.push(SetItem::Cat(c)),
                                    Esc::Node(Node::Lit(c)) => set.push(SetItem::Lit(c)),
                                    Esc::Node(_) => {}
                                }
                                set.push(SetItem::Lit(0x2d));
                                break;
                            }
                            Some(Tok::Esc(c)) => class_escape(src, c)?,
                            Some(Tok::Ch(c)) => Esc::Node(Node::Lit(c)),
                        };
                        let (lo, hi) = match (code1, code2) {
                            (Esc::Node(Node::Lit(a)), Esc::Node(Node::Lit(b))) => (a, b),
                            _ => return Err(Error::new("bad character range", here)),
                        };
                        if hi < lo {
                            return Err(Error::new("bad character range", here));
                        }
                        set.push(SetItem::Range(lo, hi));
                    } else {
                        match code1 {
                            Esc::Cat(c) => set.push(SetItem::Cat(c)),
                            Esc::Node(Node::Lit(c)) => set.push(SetItem::Lit(c)),
                            Esc::Node(_) => {}
                        }
                    }
                }
                let set = uniq(set);
                if set.len() == 1 {
                    if let SetItem::Lit(c) = set[0] {
                        sub.push(if negate { Node::NotLit(c) } else { Node::Lit(c) });
                        continue;
                    }
                }
                sub.push(Node::In { negate, items: set });
            }
            Tok::Ch(c) if c == 0x3f || c == 0x2a || c == 0x2b || c == 0x7b => {
                let here = src.tell();
                let (min, max);
                match c as u8 {
                    b'?' => {
                        min = 0;
                        max = 1;
                    }
                    b'*' => {
                        min = 0;
                        max = MAXREPEAT;
                    }
                    b'+' => {
                        min = 1;
                        max = MAXREPEAT;
                    }
                    _ => {
                        if src.next == Some(Tok::Ch(0x7d)) {
                            sub.push(Node::Lit(0x7b));
                            continue;
                        }
                        let mut lo = Vec::new();
                        let mut hi = Vec::new();
                        while src.next_is_ch_in(DIGITS) {
                            if let Some(Tok::Ch(d)) = src.get()? {
                                lo.push(d as u8);
                            }
                        }
                        if src.matches(b',')? {
                            while src.next_is_ch_in(DIGITS) {
                                if let Some(Tok::Ch(d)) = src.get()? {
                                    hi.push(d as u8);
                                }
                            }
                        } else {
                            hi = lo.clone();
                        }
                        if !src.matches(b'}')? {
                            sub.push(Node::Lit(0x7b));
                            src.seek(here)?;
                            continue;
                        }
                        let mut mn = 0u64;
                        let mut mx = MAXREPEAT;
                        if !lo.is_empty() {
                            mn = parse_int(&lo, 10);
                            if mn >= MAXREPEAT {
                                return Err(Error::new("the repetition number is too large", here));
                            }
                        }
                        if !hi.is_empty() {
                            mx = parse_int(&hi, 10);
                            if mx >= MAXREPEAT {
                                return Err(Error::new("the repetition number is too large", here));
                            }
                            if mx < mn {
                                return Err(Error::new("min repeat greater than max repeat", here));
                            }
                        }
                        min = mn;
                        max = mx;
                    }
                }
                let item = match sub.pop() {
                    None | Some(Node::At(_)) => return Err(Error::new("nothing to repeat", here.saturating_sub(1))),
                    Some(n @ Node::Repeat { .. }) => {
                        let _ = n;
                        return Err(Error::new("multiple repeat", here.saturating_sub(1)));
                    }
                    Some(Node::Sub { group: None, add: 0, del: 0, p }) => p,
                    Some(n) => vec![n],
                };
                let kind = if src.matches(b'?')? {
                    RepKind::Lazy
                } else if src.matches(b'+')? {
                    RepKind::Possessive
                } else {
                    RepKind::Greedy
                };
                sub.push(Node::Repeat { min, max, kind, item });
            }
            Tok::Ch(0x2e) => sub.push(Node::Any),
            Tok::Ch(0x28) => {
                let start = src.tell() - 1;
                let mut capture = true;
                let mut atomic = false;
                let mut name: Option<String> = None;
                let mut add = 0u32;
                let mut del = 0u32;
                if src.matches(b'?')? {
                    let ch = match src.get()? {
                        None => return src.err("unexpected end of pattern"),
                        Some(Tok::Esc(_)) => return Err(Error::new("unknown extension ?\\", start)),
                        Some(Tok::Ch(c)) => if c < 128 { c as u8 } else { 0xff },
                    };
                    let ch: u8 = if ch < 128 { ch as u8 } else { 0xff };
                    match ch {
                        b'P' => {
                            if src.matches(b'<')? {
                                let n = src.getuntil(b'>', "group name")?;
                                if !is_identifier(&n, src.text) {
                                    return src.err("bad character in group name");
                                }
                                name = Some(units_to_string(&n));
                            } else if src.matches(b'=')? {
                                let n = src.getuntil(b')', "group name")?;
                                if !is_identifier(&n, src.text) {
                                    return src.err("bad character in group name");
                                }
                                let n = units_to_string(&n);
                                let gid = match state.names.iter().find(|(k, _)| *k == n) {
                                    Some(&(_, g)) => g,
                                    None => return src.err(format!("unknown group name '{n}'")),
                                };
                                if !state.checkgroup(gid) {
                                    return src.err("cannot refer to an open group");
                                }
                                state.check_lookbehind_group(gid, src)?;
                                sub.push(Node::GroupRef(gid));
                                continue;
                            } else {
                                return match src.get()? {
                                    None => src.err("unexpected end of pattern"),
                                    Some(_) => src.err("unknown extension ?P"),
                                };
                            }
                        }
                        b':' => capture = false,
                        b'#' => {
                            loop {
                                if src.next.is_none() {
                                    return Err(Error::new("missing ), unterminated comment", start));
                                }
                                if src.get()? == Some(Tok::Ch(0x29)) {
                                    break;
                                }
                            }
                            continue;
                        }
                        b'=' | b'!' | b'<' => {
                            let mut ch = ch;
                            let mut behind = false;
                            let mut saved_lb = None;
                            if ch == b'<' {
                                ch = match src.get()? {
                                    None => return src.err("unexpected end of pattern"),
                                    Some(Tok::Ch(c)) if c == 0x3d || c == 0x21 => c as u8,
                                    Some(_) => return src.err("unknown extension ?<"),
                                };
                                behind = true;
                                saved_lb = Some(state.lookbehind_groups);
                                if state.lookbehind_groups.is_none() {
                                    state.lookbehind_groups = Some(state.groups());
                                }
                            }
                            let p = parse_sub(src, state, verbose, nested + 1)?;
                            if let Some(lb) = saved_lb {
                                if lb.is_none() {
                                    state.lookbehind_groups = None;
                                }
                            }
                            if !src.matches(b')')? {
                                return Err(Error::new("missing ), unterminated subpattern", start));
                            }
                            if ch == b'=' {
                                sub.push(Node::Assert { behind, negate: false, p });
                            } else if !p.is_empty() {
                                sub.push(Node::Assert { behind, negate: true, p });
                            } else {
                                sub.push(Node::Failure);
                            }
                            continue;
                        }
                        b'(' => {
                            let condname = src.getuntil(b')', "group name")?;
                            let condgroup: u32;
                            let digits = units_digits(&condname);
                            if digits.is_none() {
                                if !is_identifier(&condname, src.text) {
                                    return src.err("bad character in group name");
                                }
                                let n = units_to_string(&condname);
                                condgroup = match state.names.iter().find(|(k, _)| *k == n) {
                                    Some(&(_, g)) => g,
                                    None => return src.err(format!("unknown group name '{n}'")),
                                };
                            } else {
                                let g = parse_int(&digits.unwrap_or_default(), 10);
                                if g == 0 {
                                    return src.err("bad group number");
                                }
                                if g >= MAXGROUPS {
                                    return src.err(format!("invalid group reference {g}"));
                                }
                                condgroup = g as u32;
                                if !state.grouprefpos.iter().any(|&(x, _)| x == condgroup) {
                                    state.grouprefpos.push((condgroup, src.tell() - condname.len() - 1));
                                }
                            }
                            state.check_lookbehind_group(condgroup, src)?;
                            let yes = parse_seq(src, state, verbose, nested + 1, false)?;
                            let no = if src.matches(b'|')? {
                                let no = parse_seq(src, state, verbose, nested + 1, false)?;
                                if src.next == Some(Tok::Ch(0x7c)) {
                                    return src.err("conditional backref with more than two branches");
                                }
                                Some(no)
                            } else {
                                None
                            };
                            if !src.matches(b')')? {
                                return Err(Error::new("missing ), unterminated subpattern", start));
                            }
                            sub.push(Node::GroupRefExists { group: condgroup, yes, no });
                            continue;
                        }
                        b'>' => {
                            capture = false;
                            atomic = true;
                        }
                        c if is_flag(c) || c == b'-' => {
                            match parse_flags(src, state, c)? {
                                None => {
                                    if !first || !sub.is_empty() {
                                        return Err(Error::new("global flags not at the start of the expression", start));
                                    }
                                    verbose = state.flags & FLAG_VERBOSE != 0;
                                    continue;
                                }
                                Some((a, d)) => {
                                    add = a;
                                    del = d;
                                    capture = false;
                                }
                            }
                        }
                        _ => return src.err(format!("unknown extension ?{}", ch as char)),
                    }
                }
                let group = if capture {
                    let gid = state.groups();
                    if gid as u64 >= MAXGROUPS {
                        return src.err("too many groups");
                    }
                    if let Some(n) = &name {
                        if let Some(&(_, og)) = state.names.iter().find(|(k, _)| k == n) {
                            return src.err(format!("redefinition of group name '{n}' as group {gid}; was group {og}"));
                        }
                        state.names.push((n.clone(), gid));
                    }
                    state.widths.push(None);
                    Some(gid)
                } else {
                    None
                };
                let sub_verbose = (verbose || add & FLAG_VERBOSE != 0) && del & FLAG_VERBOSE == 0;
                let p = parse_sub(src, state, sub_verbose, nested + 1)?;
                if !src.matches(b')')? {
                    return Err(Error::new("missing ), unterminated subpattern", start));
                }
                if let Some(g) = group {
                    let w = width(&p, &state.widths);
                    state.widths[g as usize] = Some(w);
                }
                if atomic {
                    sub.push(Node::Atomic(p));
                } else {
                    sub.push(Node::Sub { group, add, del, p });
                }
            }
            Tok::Ch(0x5e) => sub.push(Node::At(At::Beginning)),
            Tok::Ch(0x24) => sub.push(Node::At(At::End)),
            Tok::Ch(c) => return src.err(format!("unsupported special character {}", char::from_u32(c).unwrap_or('?'))),
        }
    }
    // Unpack non-capturing groups without flags.
    let mut out = Vec::with_capacity(sub.len());
    for n in sub {
        match n {
            Node::Sub { group: None, add: 0, del: 0, p } => out.extend(p),
            n => out.push(n),
        }
    }
    Ok(out)
}

fn is_flag(c: u8) -> bool {
    matches!(c, b'i' | b'L' | b'm' | b's' | b'x' | b'a' | b'u')
}

fn flag_bit(c: u8) -> u32 {
    match c {
        b'i' => FLAG_IGNORECASE,
        b'L' => FLAG_LOCALE,
        b'm' => FLAG_MULTILINE,
        b's' => FLAG_DOTALL,
        b'x' => FLAG_VERBOSE,
        b'a' => FLAG_ASCII,
        b'u' => FLAG_UNICODE,
        _ => 0,
    }
}

const TYPE_FLAGS: u32 = FLAG_ASCII | FLAG_LOCALE | FLAG_UNICODE;

/// Returns None for global flags `(?imsx)`, Some((add, del)) for scoped `(?i-s:...)`.
fn parse_flags(src: &mut Source, state: &mut State, first: u8) -> Result<Option<(u32, u32)>, Error> {
    let mut add = 0u32;
    let mut del = 0u32;
    let mut ch = first;
    if ch != b'-' {
        loop {
            let flag = flag_bit(ch);
            if ch == b'u' && !src.text {
                return src.err("bad inline flags: cannot use 'u' flag with a bytes pattern");
            }
            if ch == b'L' && src.text {
                return src.err("bad inline flags: cannot use 'L' flag with a str pattern");
            }
            add |= flag;
            if flag & TYPE_FLAGS != 0 && add & TYPE_FLAGS != flag {
                return src.err("bad inline flags: flags 'a', 'u' and 'L' are incompatible");
            }
            ch = match src.get()? {
                None => return src.err("missing -, : or )"),
                Some(Tok::Esc(_)) => return src.err("missing -, : or )"),
                Some(Tok::Ch(c)) => if c < 128 { c as u8 } else { 0xff },
            };
            if ch == b')' || ch == b'-' || ch == b':' {
                break;
            }
            if !is_flag(ch) {
                return src.err(if ch.is_ascii_alphabetic() { "unknown flag" } else { "missing -, : or )" });
            }
        }
    }
    if ch == b')' {
        state.flags |= add;
        return Ok(None);
    }
    if ch == b'-' {
        ch = match src.get()? {
            None => return src.err("missing flag"),
            Some(Tok::Esc(_)) => return src.err("missing flag"),
            Some(Tok::Ch(c)) => if c < 128 { c as u8 } else { 0xff },
        };
        if !is_flag(ch) {
            return src.err(if ch.is_ascii_alphabetic() { "unknown flag" } else { "missing flag" });
        }
        loop {
            let flag = flag_bit(ch);
            if flag & TYPE_FLAGS != 0 {
                return src.err("bad inline flags: cannot turn off flags 'a', 'u' and 'L'");
            }
            del |= flag;
            ch = match src.get()? {
                None => return src.err("missing :"),
                Some(Tok::Esc(_)) => return src.err("missing :"),
                Some(Tok::Ch(c)) => if c < 128 { c as u8 } else { 0xff },
            };
            if ch == b':' {
                break;
            }
            if !is_flag(ch) {
                return src.err(if ch.is_ascii_alphabetic() { "unknown flag" } else { "missing :" });
            }
        }
    }
    if add & del != 0 {
        return src.err("bad inline flags: flag turned on and off");
    }
    Ok(Some((add, del)))
}

/// sre `getwidth()`: (min, max) width, saturated at MAXWIDTH.
pub fn width(p: &[Node], groups: &[Option<(u128, u128)>]) -> (u128, u128) {
    let mut lo: u128 = 0;
    let mut hi: u128 = 0;
    for n in p {
        let (a, b) = match n {
            Node::Branch(items) => {
                let mut i = MAXWIDTH;
                let mut j = 0;
                for it in items {
                    let (l, h) = width(it, groups);
                    i = i.min(l);
                    j = j.max(h);
                }
                (i, j)
            }
            Node::Atomic(p) => width(p, groups),
            Node::Sub { p, .. } => width(p, groups),
            Node::Repeat { min, max, item, .. } => {
                let (i, j) = width(item, groups);
                let a = i.saturating_mul(*min as u128);
                let b = if *max == MAXREPEAT && j != 0 { MAXWIDTH } else { j.saturating_mul(*max as u128) };
                (a, b)
            }
            Node::Lit(_) | Node::NotLit(_) | Node::Any | Node::In { .. } => (1, 1),
            Node::GroupRef(g) => groups.get(*g as usize).and_then(|w| *w).unwrap_or((0, 0)),
            Node::GroupRefExists { yes, no, .. } => {
                let (mut i, mut j) = width(yes, groups);
                match no {
                    Some(no) => {
                        let (l, h) = width(no, groups);
                        i = i.min(l);
                        j = j.max(h);
                    }
                    None => i = 0,
                }
                (i, j)
            }
            Node::At(_) | Node::Assert { .. } | Node::Failure => (0, 0),
        };
        lo = lo.saturating_add(a);
        hi = hi.saturating_add(b);
    }
    (lo.min(MAXWIDTH), hi.min(MAXWIDTH))
}
