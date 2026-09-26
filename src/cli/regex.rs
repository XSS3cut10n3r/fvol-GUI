//! A small backtracking regular-expression engine with python `re` semantics for `str`
//! patterns, used by `--filters` patterns ending in `!` (volatility3 cli/text_filter.py calls
//! `re.search(pattern, f"{item}")`). Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Supported: literals and escapes, `.`, classes, `^ $ \A \Z \b \B`, groups (capturing, `(?:)`,
//! `(?P<name>)`, `(?P=name)`), look-ahead / fixed-width look-behind, alternation, greedy / lazy
//! quantifiers, backreferences and the `a i L m s u x` flags (inline, global or scoped).

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct ReError(pub String);

impl fmt::Display for ReError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Default)]
struct Flags {
    icase: bool,
    multiline: bool,
    dotall: bool,
    verbose: bool,
    ascii: bool,
}

#[derive(Debug, Clone)]
enum ClassItem {
    Range(char, char),
    Digit(bool),
    Word(bool),
    Space(bool),
}

#[derive(Debug, Clone)]
struct Class {
    negated: bool,
    items: Vec<ClassItem>,
    icase: bool,
    ascii: bool,
}

#[derive(Debug, Clone)]
enum Node {
    Empty,
    Lit(char, bool),
    Any(bool),
    Class(Box<Class>),
    Bol(bool),
    Eol(bool),
    StrStart,
    StrEnd,
    WordB(bool, bool),
    Group(Box<Node>, Option<usize>),
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat(Box<Node>, u32, u32, bool),
    Backref(usize, bool),
    Look(Box<Node>, bool, bool),
}

const INF: u32 = u32::MAX;

struct Parser<'a> {
    s: &'a [char],
    i: usize,
    ngroups: usize,
    names: Vec<(String, usize)>,
    open: Vec<usize>,
}

fn is_digit(c: char, ascii: bool) -> bool {
    c.is_ascii_digit() || (!ascii && !c.is_ascii() && c.is_numeric())
}
fn is_word(c: char, ascii: bool) -> bool {
    c == '_' || c.is_ascii_alphanumeric() || (!ascii && !c.is_ascii() && c.is_alphanumeric())
}
fn is_space(c: char, ascii: bool) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')
        || (!ascii && (matches!(c, '\x1c'..='\x1f' | '\u{85}') || (!c.is_ascii() && c.is_whitespace())))
}

fn lower(c: char) -> char {
    if c.is_ascii() { c.to_ascii_lowercase() } else { c.to_lowercase().next().unwrap_or(c) }
}
fn upper(c: char) -> char {
    if c.is_ascii() { c.to_ascii_uppercase() } else { c.to_uppercase().next().unwrap_or(c) }
}

impl Class {
    fn matches1(&self, c: char) -> bool {
        self.items.iter().any(|it| match *it {
            ClassItem::Range(a, b) => a <= c && c <= b,
            ClassItem::Digit(n) => is_digit(c, self.ascii) != n,
            ClassItem::Word(n) => is_word(c, self.ascii) != n,
            ClassItem::Space(n) => is_space(c, self.ascii) != n,
        })
    }
    fn matches(&self, c: char) -> bool {
        let m = self.matches1(c) || (self.icase && (self.matches1(lower(c)) || self.matches1(upper(c))));
        m != self.negated
    }
}

impl<'a> Parser<'a> {
    fn err<T>(&self, msg: &str) -> Result<T, ReError> {
        Err(ReError(format!("{msg} at position {}", self.i)))
    }
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }
    fn peek_at(&self, k: usize) -> Option<char> {
        self.s.get(self.i + k).copied()
    }
    fn skip_verbose(&mut self, f: Flags) {
        if !f.verbose {
            return;
        }
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.i += 1;
            } else if c == '#' {
                while let Some(c) = self.peek() {
                    self.i += 1;
                    if c == '\n' {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    fn parse_flags(&mut self, f: &mut Flags) -> Result<bool, ReError> {
        // after "(?", read flag letters; returns true when followed by ':' (scoped group)
        loop {
            match self.peek() {
                Some('i') => f.icase = true,
                Some('m') => f.multiline = true,
                Some('s') => f.dotall = true,
                Some('x') => f.verbose = true,
                Some('a') => f.ascii = true,
                Some('u') | Some('L') => {}
                Some(')') => {
                    self.i += 1;
                    return Ok(false);
                }
                Some(':') => {
                    self.i += 1;
                    return Ok(true);
                }
                Some('-') => {
                    // (?-i:...) remove flags
                    self.i += 1;
                    loop {
                        match self.peek() {
                            Some('i') => f.icase = false,
                            Some('m') => f.multiline = false,
                            Some('s') => f.dotall = false,
                            Some('x') => f.verbose = false,
                            Some(':') => {
                                self.i += 1;
                                return Ok(true);
                            }
                            _ => return self.err("missing :"),
                        }
                        self.i += 1;
                    }
                }
                _ => return self.err("unknown flag"),
            }
            self.i += 1;
        }
    }

    fn parse_alt(&mut self, f: Flags) -> Result<Node, ReError> {
        let mut branches = vec![self.parse_concat(f)?];
        while self.peek() == Some('|') {
            self.i += 1;
            branches.push(self.parse_concat(f)?);
        }
        Ok(if branches.len() == 1 { branches.pop().unwrap() } else { Node::Alt(branches) })
    }

    fn parse_concat(&mut self, f: Flags) -> Result<Node, ReError> {
        let mut items = Vec::new();
        loop {
            self.skip_verbose(f);
            match self.peek() {
                None | Some('|') | Some(')') => break,
                _ => {}
            }
            let atom = self.parse_atom(f)?;
            let atom = self.parse_quant(atom, f)?;
            items.push(atom);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().unwrap(),
            _ => Node::Concat(items),
        })
    }

    /// Try to parse `{m,n}` at the current position; None (position unchanged) if it is a literal.
    fn try_braces(&mut self) -> Option<(u32, u32)> {
        let save = self.i;
        if self.peek() != Some('{') {
            return None;
        }
        self.i += 1;
        let num = |p: &mut Self| -> Option<u32> {
            let st = p.i;
            while matches!(p.peek(), Some(c) if c.is_ascii_digit()) {
                p.i += 1;
            }
            if p.i == st { None } else { p.s[st..p.i].iter().collect::<String>().parse().ok().or(Some(INF - 1)) }
        };
        let lo = num(self);
        let (min, max) = if self.peek() == Some(',') {
            self.i += 1;
            let hi = num(self);
            (lo.unwrap_or(0), hi.unwrap_or(INF))
        } else {
            match lo {
                Some(v) => (v, v),
                None => {
                    self.i = save;
                    return None;
                }
            }
        };
        if self.peek() != Some('}') {
            self.i = save;
            return None;
        }
        self.i += 1;
        Some((min, max))
    }

    fn parse_quant(&mut self, mut atom: Node, f: Flags) -> Result<Node, ReError> {
        let mut quantified = false;
        loop {
            self.skip_verbose(f);
            let (min, max) = match self.peek() {
                Some('*') => {
                    self.i += 1;
                    (0, INF)
                }
                Some('+') => {
                    self.i += 1;
                    (1, INF)
                }
                Some('?') => {
                    self.i += 1;
                    (0, 1)
                }
                Some('{') => match self.try_braces() {
                    Some(q) => q,
                    None => return Ok(atom),
                },
                _ => return Ok(atom),
            };
            if quantified {
                return self.err("multiple repeat");
            }
            if min > max {
                return self.err("min repeat greater than max repeat");
            }
            if matches!(atom, Node::Empty | Node::Bol(_) | Node::Eol(_) | Node::StrStart | Node::StrEnd | Node::WordB(..)) {
                return self.err("nothing to repeat");
            }
            let mut greedy = true;
            if self.peek() == Some('?') {
                self.i += 1;
                greedy = false;
            } else if self.peek() == Some('+') {
                // possessive: approximated as greedy
                self.i += 1;
            }
            atom = Node::Repeat(Box::new(atom), min, max, greedy);
            quantified = true;
        }
    }

    fn parse_escape_char(&mut self, in_class: bool) -> Result<Result<char, ClassItem>, ReError> {
        // after the backslash
        let c = match self.peek() {
            Some(c) => c,
            None => return self.err("bad escape (end of pattern)"),
        };
        self.i += 1;
        let hex = |p: &mut Self, n: usize| -> Result<char, ReError> {
            let st = p.i;
            for _ in 0..n {
                match p.peek() {
                    Some(c) if c.is_ascii_hexdigit() => p.i += 1,
                    _ => return p.err("incomplete escape"),
                }
            }
            let v = u32::from_str_radix(&p.s[st..p.i].iter().collect::<String>(), 16).unwrap_or(0);
            char::from_u32(v).ok_or_else(|| ReError("bad escape".into()))
        };
        Ok(Ok(match c {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            'f' => '\x0c',
            'v' => '\x0b',
            'a' => '\x07',
            'b' if in_class => '\x08',
            'x' => hex(self, 2)?,
            'u' => hex(self, 4)?,
            'U' => hex(self, 8)?,
            'd' => return Ok(Err(ClassItem::Digit(false))),
            'D' => return Ok(Err(ClassItem::Digit(true))),
            'w' => return Ok(Err(ClassItem::Word(false))),
            'W' => return Ok(Err(ClassItem::Word(true))),
            's' => return Ok(Err(ClassItem::Space(false))),
            'S' => return Ok(Err(ClassItem::Space(true))),
            '0'..='7' if in_class || c == '0' => {
                let mut v = c as u32 - '0' as u32;
                for _ in 0..2 {
                    match self.peek() {
                        Some(d @ '0'..='7') => {
                            v = v * 8 + (d as u32 - '0' as u32);
                            self.i += 1;
                        }
                        _ => break,
                    }
                }
                if v > 0o377 {
                    return self.err("octal escape value outside of range");
                }
                char::from_u32(v).unwrap_or('\0')
            }
            c if c.is_ascii_alphanumeric() => return self.err("bad escape"),
            c => c,
        }))
    }

    fn parse_class(&mut self, f: Flags) -> Result<Node, ReError> {
        // after '['
        let mut cls = Class { negated: false, items: Vec::new(), icase: f.icase, ascii: f.ascii };
        if self.peek() == Some('^') {
            cls.negated = true;
            self.i += 1;
        }
        let mut first = true;
        loop {
            let c = match self.peek() {
                Some(c) => c,
                None => return self.err("unterminated character set"),
            };
            if c == ']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            self.i += 1;
            let lo = if c == '\\' {
                match self.parse_escape_char(true)? {
                    Ok(ch) => ch,
                    Err(item) => {
                        cls.items.push(item);
                        continue;
                    }
                }
            } else {
                c
            };
            if self.peek() == Some('-') && self.peek_at(1).is_some_and(|c| c != ']') {
                self.i += 1;
                let hc = self.peek().unwrap();
                self.i += 1;
                let hi = if hc == '\\' {
                    match self.parse_escape_char(true)? {
                        Ok(ch) => ch,
                        Err(_) => return self.err("bad character range"),
                    }
                } else {
                    hc
                };
                if hi < lo {
                    return self.err("bad character range");
                }
                cls.items.push(ClassItem::Range(lo, hi));
            } else {
                cls.items.push(ClassItem::Range(lo, lo));
            }
        }
        Ok(Node::Class(Box::new(cls)))
    }

    fn parse_group_name(&mut self, end: char) -> Result<String, ReError> {
        let st = self.i;
        while let Some(c) = self.peek() {
            if c == end {
                let name: String = self.s[st..self.i].iter().collect();
                self.i += 1;
                if name.is_empty() {
                    return self.err("missing group name");
                }
                return Ok(name);
            }
            self.i += 1;
        }
        self.err("missing group name terminator")
    }

    fn expect_close(&mut self) -> Result<(), ReError> {
        if self.peek() == Some(')') {
            self.i += 1;
            Ok(())
        } else {
            self.err("missing ), unterminated subpattern")
        }
    }

    fn parse_atom(&mut self, f: Flags) -> Result<Node, ReError> {
        let c = self.peek().unwrap();
        self.i += 1;
        Ok(match c {
            '.' => Node::Any(f.dotall),
            '^' => Node::Bol(f.multiline),
            '$' => Node::Eol(f.multiline),
            '[' => self.parse_class(f)?,
            '*' | '+' | '?' => return self.err("nothing to repeat"),
            '{' => {
                self.i -= 1;
                if self.try_braces().is_some() {
                    return self.err("nothing to repeat");
                }
                self.i += 1;
                Node::Lit('{', f.icase)
            }
            '(' => {
                if self.peek() == Some('?') {
                    self.i += 1;
                    match self.peek() {
                        Some(':') => {
                            self.i += 1;
                            let n = self.parse_alt(f)?;
                            self.expect_close()?;
                            Node::Group(Box::new(n), None)
                        }
                        Some('P') => {
                            self.i += 1;
                            match self.peek() {
                                Some('<') => {
                                    self.i += 1;
                                    let name = self.parse_group_name('>')?;
                                    self.ngroups += 1;
                                    let g = self.ngroups;
                                    self.names.push((name, g));
                                    self.open.push(g);
                                    let n = self.parse_alt(f)?;
                                    self.open.pop();
                                    self.expect_close()?;
                                    Node::Group(Box::new(n), Some(g))
                                }
                                Some('=') => {
                                    self.i += 1;
                                    let name = self.parse_group_name(')')?;
                                    match self.names.iter().find(|(n, _)| *n == name) {
                                        Some(&(_, g)) if !self.open.contains(&g) => Node::Backref(g, f.icase),
                                        _ => return self.err("unknown group name"),
                                    }
                                }
                                _ => return self.err("unknown extension ?P"),
                            }
                        }
                        Some('<') if self.peek_at(1) == Some('=') || self.peek_at(1) == Some('!') => {
                            let neg = self.peek_at(1) == Some('!');
                            self.i += 2;
                            let n = self.parse_alt(f)?;
                            self.expect_close()?;
                            if width(&n).is_none() {
                                return self.err("look-behind requires fixed-width pattern");
                            }
                            Node::Look(Box::new(n), false, neg)
                        }
                        Some('<') => {
                            self.i += 1;
                            let name = self.parse_group_name('>')?;
                            self.ngroups += 1;
                            let g = self.ngroups;
                            self.names.push((name, g));
                            self.open.push(g);
                            let n = self.parse_alt(f)?;
                            self.open.pop();
                            self.expect_close()?;
                            Node::Group(Box::new(n), Some(g))
                        }
                        Some('=') | Some('!') => {
                            let neg = self.peek() == Some('!');
                            self.i += 1;
                            let n = self.parse_alt(f)?;
                            self.expect_close()?;
                            Node::Look(Box::new(n), true, neg)
                        }
                        Some('#') => {
                            while let Some(c) = self.peek() {
                                self.i += 1;
                                if c == ')' {
                                    return Ok(Node::Empty);
                                }
                            }
                            return self.err("missing ), unterminated comment");
                        }
                        _ => {
                            let mut nf = f;
                            if self.parse_flags(&mut nf)? {
                                let n = self.parse_alt(nf)?;
                                self.expect_close()?;
                                Node::Group(Box::new(n), None)
                            } else {
                                return self.err("global flags not at the start of the expression");
                            }
                        }
                    }
                } else {
                    self.ngroups += 1;
                    let g = self.ngroups;
                    self.open.push(g);
                    let n = self.parse_alt(f)?;
                    self.open.pop();
                    self.expect_close()?;
                    Node::Group(Box::new(n), Some(g))
                }
            }
            '\\' => match self.peek() {
                Some('A') => {
                    self.i += 1;
                    Node::StrStart
                }
                Some('Z') => {
                    self.i += 1;
                    Node::StrEnd
                }
                Some('b') => {
                    self.i += 1;
                    Node::WordB(false, f.ascii)
                }
                Some('B') => {
                    self.i += 1;
                    Node::WordB(true, f.ascii)
                }
                Some(d @ '1'..='9') => {
                    // octal escape (three octal digits) or group reference
                    let d2 = self.peek_at(1);
                    let d3 = self.peek_at(2);
                    if let (Some(b @ '0'..='7'), Some(c3 @ '0'..='7')) = (d2, d3)
                        && d <= '7' {
                            self.i += 3;
                            let v = (d as u32 - 48) * 64 + (b as u32 - 48) * 8 + (c3 as u32 - 48);
                            if v > 0o377 {
                                return self.err("octal escape value outside of range");
                            }
                            return Ok(Node::Lit(char::from_u32(v).unwrap_or('\0'), f.icase));
                        }
                    self.i += 1;
                    let mut g = d as usize - '0' as usize;
                    if let Some(e @ '0'..='9') = self.peek() {
                        self.i += 1;
                        g = g * 10 + (e as usize - '0' as usize);
                    }
                    if g > self.ngroups || self.open.contains(&g) {
                        return self.err("invalid group reference");
                    }
                    Node::Backref(g, f.icase)
                }
                _ => match self.parse_escape_char(false)? {
                    Ok(ch) => Node::Lit(ch, f.icase),
                    Err(item) => Node::Class(Box::new(Class { negated: false, items: vec![item], icase: false, ascii: f.ascii })),
                },
            },
            ')' => return self.err("unbalanced parenthesis"),
            c => Node::Lit(c, f.icase),
        })
    }
}

/// Fixed match width of a node (in characters), None when variable.
fn width(n: &Node) -> Option<usize> {
    Some(match n {
        Node::Empty | Node::Bol(_) | Node::Eol(_) | Node::StrStart | Node::StrEnd | Node::WordB(..) | Node::Look(..) => 0,
        Node::Lit(..) | Node::Any(_) | Node::Class(_) => 1,
        Node::Group(n, _) => width(n)?,
        Node::Concat(v) => v.iter().map(width).sum::<Option<usize>>()?,
        Node::Alt(v) => {
            let w = width(&v[0])?;
            for b in &v[1..] {
                if width(b)? != w {
                    return None;
                }
            }
            w
        }
        Node::Repeat(n, a, b, _) if a == b => width(n)? * *a as usize,
        _ => return None,
    })
}

#[derive(Debug, Clone)]
enum Inst {
    Char(char, bool),
    Any(bool),
    Class(Box<Class>),
    Bol(bool),
    Eol(bool),
    StrStart,
    StrEnd,
    WordB(bool, bool),
    Split(usize, usize),
    Jmp(usize),
    Save(usize),
    Mark(usize),
    Progress(usize),
    Backref(usize, bool),
    Look(usize, bool, bool, usize),
    Match,
}

/// A compiled pattern.
#[derive(Debug, Clone)]
pub struct Regex {
    progs: Vec<Vec<Inst>>,
    ngroups: usize,
    nmarks: usize,
}

struct Compiler {
    progs: Vec<Vec<Inst>>,
    nmarks: usize,
}

impl Compiler {
    fn emit(&mut self, p: usize, i: Inst) -> usize {
        self.progs[p].push(i);
        self.progs[p].len() - 1
    }
    fn comp(&mut self, p: usize, n: &Node) -> Result<(), ReError> {
        match n {
            Node::Empty => {}
            Node::Lit(c, ic) => {
                self.emit(p, Inst::Char(*c, *ic));
            }
            Node::Any(d) => {
                self.emit(p, Inst::Any(*d));
            }
            Node::Class(c) => {
                self.emit(p, Inst::Class(c.clone()));
            }
            Node::Bol(m) => {
                self.emit(p, Inst::Bol(*m));
            }
            Node::Eol(m) => {
                self.emit(p, Inst::Eol(*m));
            }
            Node::StrStart => {
                self.emit(p, Inst::StrStart);
            }
            Node::StrEnd => {
                self.emit(p, Inst::StrEnd);
            }
            Node::WordB(neg, a) => {
                self.emit(p, Inst::WordB(*neg, *a));
            }
            Node::Group(n, g) => {
                if let Some(g) = g {
                    self.emit(p, Inst::Save(2 * g));
                    self.comp(p, n)?;
                    self.emit(p, Inst::Save(2 * g + 1));
                } else {
                    self.comp(p, n)?;
                }
            }
            Node::Concat(v) => {
                for n in v {
                    self.comp(p, n)?;
                }
            }
            Node::Alt(v) => {
                let mut jumps = Vec::new();
                for (k, b) in v.iter().enumerate() {
                    if k + 1 < v.len() {
                        let split = self.emit(p, Inst::Split(0, 0));
                        self.comp(p, b)?;
                        jumps.push(self.emit(p, Inst::Jmp(0)));
                        let next = self.progs[p].len();
                        self.progs[p][split] = Inst::Split(split + 1, next);
                    } else {
                        self.comp(p, b)?;
                    }
                }
                let end = self.progs[p].len();
                for j in jumps {
                    self.progs[p][j] = Inst::Jmp(end);
                }
            }
            Node::Repeat(n, min, max, greedy) => {
                let (min, max) = (*min, *max);
                if min > 1000 || (max != INF && max > 1000) {
                    return Err(ReError("repetition count too large for this engine".into()));
                }
                for _ in 0..min {
                    self.comp(p, n)?;
                }
                if max == INF {
                    let mark = self.nmarks;
                    self.nmarks += 1;
                    let l0 = self.emit(p, Inst::Split(0, 0));
                    self.emit(p, Inst::Mark(mark));
                    self.comp(p, n)?;
                    self.emit(p, Inst::Progress(mark));
                    self.emit(p, Inst::Jmp(l0));
                    let end = self.progs[p].len();
                    self.progs[p][l0] = if *greedy { Inst::Split(l0 + 1, end) } else { Inst::Split(end, l0 + 1) };
                } else {
                    let mut splits = Vec::new();
                    for _ in min..max {
                        splits.push(self.emit(p, Inst::Split(0, 0)));
                        self.comp(p, n)?;
                    }
                    let end = self.progs[p].len();
                    for s in splits {
                        self.progs[p][s] = if *greedy { Inst::Split(s + 1, end) } else { Inst::Split(end, s + 1) };
                    }
                }
            }
            Node::Backref(g, ic) => {
                self.emit(p, Inst::Backref(*g, *ic));
            }
            Node::Look(n, ahead, neg) => {
                let sub = self.progs.len();
                self.progs.push(Vec::new());
                self.comp(sub, n)?;
                self.emit(sub, Inst::Match);
                let w = if *ahead { 0 } else { width(n).unwrap_or(0) };
                self.emit(p, Inst::Look(sub, *ahead, *neg, w));
            }
        }
        Ok(())
    }
}

enum Frame {
    Branch(usize, usize),
    Cap(usize, usize),
    Mark(usize, usize),
}

impl Regex {
    pub fn new(pattern: &str) -> Result<Regex, ReError> {
        Self::new_flags(pattern, false)
    }

    /// python `re.compile(pattern, re.I if icase else 0)`. A pattern python rejects reports
    /// python's `str(re.error)` ("msg at position N"), taken from the python-exact parser of
    /// `yara::regex` (this engine's own error positions are approximate).
    pub fn new_flags(pattern: &str, icase: bool) -> Result<Regex, ReError> {
        Self::compile(pattern, icase).map_err(|own| {
            let flags = if icase { crate::yara::regex::FLAG_IGNORECASE } else { 0 };
            match crate::yara::regex::Regex::new_str(pattern, flags) {
                Err(e) => ReError(e.py_str_for_str(pattern)),
                Ok(_) => own,
            }
        })
    }

    fn compile(pattern: &str, icase: bool) -> Result<Regex, ReError> {
        let chars: Vec<char> = pattern.chars().collect();
        let mut p = Parser { s: &chars, i: 0, ngroups: 0, names: Vec::new(), open: Vec::new() };
        // global flags must be at the very start
        let mut flags = Flags { icase, ..Flags::default() };
        while p.peek() == Some('(') && p.peek_at(1) == Some('?') && p.peek_at(2).is_some_and(|c| "aiLmsux".contains(c)) {
            let save = p.i;
            p.i += 2;
            let mut nf = flags;
            if p.parse_flags(&mut nf)? {
                // scoped group, not global flags
                p.i = save;
                break;
            }
            flags = nf;
        }
        let node = p.parse_alt(flags)?;
        if p.i < chars.len() {
            return p.err("unbalanced parenthesis");
        }
        let mut c = Compiler { progs: vec![Vec::new()], nmarks: 0 };
        c.comp(0, &node)?;
        c.emit(0, Inst::Match);
        Ok(Regex { progs: c.progs, ngroups: p.ngroups, nmarks: c.nmarks })
    }

    /// python `bool(re.search(pattern, s))`
    pub fn is_match(&self, s: &str) -> bool {
        let chars: Vec<char> = s.chars().collect();
        let mut caps = vec![usize::MAX; 2 * self.ngroups + 2];
        let mut marks = vec![usize::MAX; self.nmarks];
        (0..=chars.len()).any(|start| self.run(0, &chars, start, &mut caps, &mut marks).is_some())
    }

    /// python `re.match(pattern, s)`: (end, group spans) of an anchored match. Char indices.
    pub fn match_prefix(&self, s: &str) -> Option<(usize, Vec<Option<(usize, usize)>>)> {
        let chars: Vec<char> = s.chars().collect();
        let mut caps = vec![usize::MAX; 2 * self.ngroups + 2];
        let mut marks = vec![usize::MAX; self.nmarks];
        let end = self.run(0, &chars, 0, &mut caps, &mut marks)?;
        let groups = (1..=self.ngroups)
            .map(|g| {
                let (a, b) = (caps[2 * g], caps[2 * g + 1]);
                if a == usize::MAX || b == usize::MAX { None } else { Some((a, b)) }
            })
            .collect();
        Some((end, groups))
    }

    fn run(&self, prog: usize, s: &[char], start: usize, caps: &mut [usize], marks: &mut [usize]) -> Option<usize> {
        let code = &self.progs[prog];
        let mut stack: Vec<Frame> = Vec::new();
        let mut pc = 0usize;
        let mut sp = start;
        let n = s.len();
        loop {
            let ok = match &code[pc] {
                Inst::Match => {
                    // leave captures as they are (only needed for backrefs inside the run)
                    return Some(sp);
                }
                Inst::Char(c, ic) => {
                    if sp < n && (s[sp] == *c || (*ic && lower(s[sp]) == lower(*c))) {
                        sp += 1;
                        pc += 1;
                        true
                    } else {
                        false
                    }
                }
                Inst::Any(dotall) => {
                    if sp < n && (*dotall || s[sp] != '\n') {
                        sp += 1;
                        pc += 1;
                        true
                    } else {
                        false
                    }
                }
                Inst::Class(c) => {
                    if sp < n && c.matches(s[sp]) {
                        sp += 1;
                        pc += 1;
                        true
                    } else {
                        false
                    }
                }
                Inst::Bol(m) => {
                    if sp == 0 || (*m && s[sp - 1] == '\n') {
                        pc += 1;
                        true
                    } else {
                        false
                    }
                }
                Inst::Eol(m) => {
                    if sp == n || (sp + 1 == n && s[sp] == '\n') || (*m && s[sp] == '\n') {
                        pc += 1;
                        true
                    } else {
                        false
                    }
                }
                Inst::StrStart => {
                    if sp == 0 {
                        pc += 1;
                        true
                    } else {
                        false
                    }
                }
                Inst::StrEnd => {
                    if sp == n {
                        pc += 1;
                        true
                    } else {
                        false
                    }
                }
                Inst::WordB(neg, a) => {
                    let before = sp > 0 && is_word(s[sp - 1], *a);
                    let after = sp < n && is_word(s[sp], *a);
                    if (before != after) != *neg {
                        pc += 1;
                        true
                    } else {
                        false
                    }
                }
                Inst::Split(a, b) => {
                    stack.push(Frame::Branch(*b, sp));
                    pc = *a;
                    true
                }
                Inst::Jmp(a) => {
                    pc = *a;
                    true
                }
                Inst::Save(slot) => {
                    stack.push(Frame::Cap(*slot, caps[*slot]));
                    caps[*slot] = sp;
                    pc += 1;
                    true
                }
                Inst::Mark(k) => {
                    stack.push(Frame::Mark(*k, marks[*k]));
                    marks[*k] = sp;
                    pc += 1;
                    true
                }
                Inst::Progress(k) => {
                    if marks[*k] != sp {
                        pc += 1;
                        true
                    } else {
                        false
                    }
                }
                Inst::Backref(g, ic) => {
                    let (a, b) = (caps[2 * g], caps[2 * g + 1]);
                    if a == usize::MAX || b == usize::MAX || b < a {
                        false
                    } else {
                        let len = b - a;
                        if sp + len <= n
                            && (0..len).all(|k| s[a + k] == s[sp + k] || (*ic && lower(s[a + k]) == lower(s[sp + k])))
                        {
                            sp += len;
                            pc += 1;
                            true
                        } else {
                            false
                        }
                    }
                }
                Inst::Look(sub, ahead, neg, w) => {
                    let found = if *ahead {
                        self.run(*sub, s, sp, caps, marks).is_some()
                    } else if sp >= *w {
                        self.run(*sub, s, sp - w, caps, marks) == Some(sp)
                    } else {
                        false
                    };
                    if found != *neg {
                        pc += 1;
                        true
                    } else {
                        false
                    }
                }
            };
            if !ok {
                // backtrack
                loop {
                    match stack.pop() {
                        None => return None,
                        Some(Frame::Branch(p2, s2)) => {
                            pc = p2;
                            sp = s2;
                            break;
                        }
                        Some(Frame::Cap(slot, old)) => caps[slot] = old,
                        Some(Frame::Mark(k, old)) => marks[k] = old,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Regex;

    fn m(p: &str, s: &str) -> bool {
        Regex::new(p).unwrap().is_match(s)
    }

    /// python 3.14 `str(re.error)` (dumpfiles --filter, --filters): the position is where
    /// python's parser reports it (this engine said "position 9" for "(unclosed").
    #[test]
    fn errors_read_like_python() {
        let e = |p: &str, icase: bool| Regex::new_flags(p, icase).err().unwrap().0;
        assert_eq!(e("(unclosed", false), "missing ), unterminated subpattern at position 0");
        assert_eq!(e("ab[c-", true), "unterminated character set at position 2");
        assert_eq!(e("é(", false), "missing ), unterminated subpattern at position 1");
        assert!(Regex::new_flags("NTDLL", true).unwrap().is_match("ntdll.dll"));
    }

    #[test]
    fn basics() {
        assert!(m("abc", "xxabcxx"));
        assert!(!m("^abc", "xxabc"));
        assert!(m("^a.c$", "abc"));
        assert!(m("abc$", "abc\n"));
        assert!(!m("abc\\Z", "abc\n"));
        assert!(m("[a-c]+x", "zzbcax"));
        assert!(m("[^a-c]", "abcd"));
        assert!(!m("[^a-c]", "abc"));
        assert!(m("(ab|cd){2}", "xabcdx"));
        assert!(m("svc(host)?\\.exe", "svchost.exe"));
        assert!(m("(?i)SVCHOST", "svchost.exe"));
        assert!(m("\\d{3,}", "a1234"));
        assert!(!m("\\d{3,}", "a12b"));
        assert!(m("(a)\\1", "xaa"));
        assert!(m("(?P<x>a)(?P=x)", "aa"));
        assert!(m("\\bfoo\\b", "a foo b"));
        assert!(!m("\\bfoo\\b", "afoob"));
        assert!(m("a(?=b)", "ab"));
        assert!(!m("a(?!b)", "ab"));
        assert!(m("(?<=a)b", "ab"));
        assert!(m("(a*)*b", "aaab"));
        assert!(m("x*", ""));
        assert!(m("a.*?c", "abbbc"));
        assert!(m("[\\]]", "]"));
        assert!(m("[]a]", "]"));
        assert!(m("a{,2}b", "b"));
        assert!(m("a{b", "a{b"));
        assert!(Regex::new("*a").is_err());
        assert!(Regex::new("(a").is_err());
        assert!(Regex::new("a)").is_err());
        assert!(Regex::new("\\q").is_err());
    }
}
