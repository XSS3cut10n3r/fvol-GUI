//! Rule parser + compiler: a recursive-descent equivalent of libyara 4.5
//! `grammar.y` / `parser.c` that type-checks conditions, resolves string / rule /
//! loop-variable references at compile time and emits code for the VM in
//! [`super::eval`] with the same instruction sequence semantics libyara emits.
//!
//! Error reporting follows yara-python: every error is reported as it happens
//! and the *last* one wins; after an error the parser skips to the next
//! `rule` / `private` / `global` / `import` token (bison `rules error rule`
//! recovery, including the "3 tokens before new syntax errors are reported"
//! rule). Recursion depth is capped, so no input can overflow the stack.

use std::collections::HashMap;

use super::eval::{IntRead, Op, Program, SRef, RE_BASE, STR_BASE, UNDEF};
use super::lexer::{Kw, LexError, Lexer, Tok};
use super::regex::CondRegex;
use super::{CompileError, MetaValue};
use crate::yara::scan::{Matcher, Modifiers, StringDef, StringKind};


const MAX_LOOP_NESTING: usize = 4;
const MAX_LOOP_VARS: usize = 2;
const INTERNAL_LOOP_VARS: usize = 3;
const MAX_STRINGS_PER_RULE: usize = 10000;
/// Nesting cap for recursive constructs (parentheses, unary operators, `not`).
const MAX_DEPTH: usize = 128;
const DEFAULT_BASE64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// A compiled rule.
#[derive(Clone, Debug)]
pub struct CRule {
    pub name: String,
    pub ns: u32,
    pub private: bool,
    pub global: bool,
    pub tags: Vec<String>,
    pub meta: Vec<(String, MetaValue)>,
    /// Global string indices of this rule's strings.
    pub strings: (u32, u32),
    /// Code range in [`Program::code`].
    pub code: (u32, u32),
}

/// Per-string compile information (global index).
#[derive(Clone, Debug)]
pub struct CString {
    pub rule: u32,
    pub private: bool,
    anonymous: bool,
    referenced: bool,
    fixed: bool,
    fixed_offset: i64,
    base64: bool,
}

/// Accumulated state of a (multi-source) compilation.
#[derive(Default)]
pub struct Compiler {
    pub namespaces: Vec<String>,
    pub rules: Vec<CRule>,
    pub strings: Vec<CString>,
    pub defs: Vec<StringDef>,
    pub prog: Program,
    /// (namespace, rule name) -> rule index.
    rule_index: HashMap<(u32, String), u32>,
    /// Rule-name prefixes used in `(prefix*)` rule sets, per namespace.
    wildcards: Vec<(u32, String)>,
}

impl Compiler {
    fn namespace(&mut self, name: &str) -> u32 {
        if let Some(i) = self.namespaces.iter().position(|n| n == name) {
            return i as u32;
        }
        self.namespaces.push(name.to_string());
        (self.namespaces.len() - 1) as u32
    }

    /// Compile one source into namespace `ns_name` (yr_compiler_add_string).
    pub fn add_source(&mut self, ns_name: &str, src: &[u8]) -> Result<(), CompileError> {
        let ns = self.namespace(ns_name);
        let mut p = Parser::new(self, ns, src);
        p.parse_rules();
        match p.error.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Final FIXED_OFFSET value for string `i` (StringDef::fixed_offset).
    pub fn finalize_defs(&mut self) {
        for (d, s) in self.defs.iter_mut().zip(&self.strings) {
            d.fixed_offset = if s.fixed && !s.base64 && s.fixed_offset != UNDEF { Some(s.fixed_offset) } else { None };
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ty {
    Int,
    Float,
    Str,
    Regex,
    Bool,
}

impl Ty {
    fn name(self) -> &'static str {
        match self {
            Ty::Int => "integer",
            Ty::Float => "float",
            Ty::Str => "string",
            Ty::Bool => "boolean",
            Ty::Regex => "",
        }
    }
}

/// Attributes of a parsed (sub)expression: libyara YR_EXPRESSION.
#[derive(Clone, Copy, Debug)]
struct Expr {
    ty: Ty,
    /// `value.integer` (YR_UNDEFINED when not a compile-time constant).
    ival: i64,
    /// Grammatically a `primary_expression` (may continue with arithmetic,
    /// comparisons, `of`, ...), as opposed to a boolean `expression`.
    primary: bool,
    /// Pool index of a literal text string.
    str_const: Option<u32>,
}

impl Expr {
    fn prim(ty: Ty, ival: i64) -> Expr {
        Expr { ty, ival, primary: true, str_const: None }
    }
    fn boolean() -> Expr {
        Expr { ty: Ty::Bool, ival: UNDEF, primary: false, str_const: None }
    }
}

#[inline]
fn undef(v: i64) -> bool {
    v == UNDEF
}

/// OPERATION(op, a, b): undefined if either side is.
#[inline]
fn operation(a: i64, b: i64, f: impl FnOnce(i64, i64) -> i64) -> i64 {
    if undef(a) || undef(b) {
        UNDEF
    } else {
        f(a, b)
    }
}

/// Unit error marker: details are stored in `Parser::error`.
struct Fail;
type PResult<T> = Result<T, Fail>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum VarTy {
    Int,
    Str,
}

struct LoopCtx {
    vars: Vec<(String, VarTy)>,
}

struct Parser<'a, 'c> {
    c: &'c mut Compiler,
    lx: Lexer<'a>,
    ns: u32,
    tok: Tok,
    tok_line: usize,
    prev_line: usize,
    /// Second lookahead (rarely needed).
    ahead: Option<(Tok, usize)>,
    error: Option<CompileError>,
    /// Bison yyerrstatus: tokens to shift before syntax errors are reported again.
    grace: u32,
    /// The last failure was a syntax error (bison discards the lookahead when
    /// such an error happens right after a recovery).
    syntax_fail: bool,
    consumed: u64,
    // Current rule.
    rule: u32,
    rule_strings_start: u32,
    str_lookup: HashMap<String, u32>,
    loops: Vec<LoopCtx>,
    for_of_slot: Option<u8>,
    depth: usize,
}

impl<'a, 'c> Parser<'a, 'c> {
    fn new(c: &'c mut Compiler, ns: u32, src: &'a [u8]) -> Parser<'a, 'c> {
        Parser {
            c,
            lx: Lexer::new(src),
            ns,
            tok: Tok::Eof,
            tok_line: 1,
            prev_line: 1,
            ahead: None,
            error: None,
            grace: 0,
            syntax_fail: false,
            consumed: 0,
            rule: 0,
            rule_strings_start: 0,
            str_lookup: HashMap::new(),
            loops: Vec::new(),
            for_of_slot: None,
            depth: 0,
        }
    }

    // ------------------------------------------------------------------ tokens

    fn lex(&mut self) -> (Tok, usize) {
        loop {
            match self.lx.next_token() {
                Ok(t) => return (t, self.lx.line()),
                Err(LexError { msg, line }) => self.record(msg, line),
            }
        }
    }

    fn advance(&mut self) {
        self.prev_line = self.tok_line;
        let (t, l) = match self.ahead.take() {
            Some(x) => x,
            None => self.lex(),
        };
        self.tok = t;
        self.tok_line = l;
        self.consumed += 1;
        if self.grace > 0 {
            self.grace -= 1;
        }
    }

    /// Drop the lookahead during error recovery (not a shift: `grace` stays).
    fn discard(&mut self) {
        let (t, l) = match self.ahead.take() {
            Some(x) => x,
            None => self.lex(),
        };
        self.tok = t;
        self.tok_line = l;
    }

    fn peek2(&mut self) -> &Tok {
        if self.ahead.is_none() {
            let x = self.lex();
            self.ahead = Some(x);
        }
        match &self.ahead {
            Some((t, _)) => t,
            None => &Tok::Eof,
        }
    }

    fn is_kw(&self, k: Kw) -> bool {
        self.tok == Tok::Kw(k)
    }

    fn is_char(&self, ch: u8) -> bool {
        self.tok == Tok::Char(ch)
    }

    // ------------------------------------------------------------------ errors

    fn record(&mut self, msg: String, line: usize) {
        self.error = Some(CompileError { msg, line });
    }

    /// Semantic error (yyerror from an action): always reported.
    fn sem<T>(&mut self, msg: impl Into<String>) -> PResult<T> {
        let line = self.tok_line;
        self.sem_at(msg, line)
    }

    fn sem_at<T>(&mut self, msg: impl Into<String>, line: usize) -> PResult<T> {
        self.record(msg.into(), line);
        self.syntax_fail = false;
        Err(Fail)
    }

    /// Bison syntax error on the current lookahead.
    fn unexpected<T>(&mut self, expecting: &str) -> PResult<T> {
        if self.grace == 0 {
            let mut msg = format!("syntax error, unexpected {}", self.tok.name());
            if !expecting.is_empty() {
                msg.push_str(", expecting ");
                msg.push_str(expecting);
            }
            let line = self.tok_line;
            self.record(msg, line);
        }
        self.syntax_fail = true;
        Err(Fail)
    }

    fn expect_char(&mut self, ch: u8, expecting: &str) -> PResult<()> {
        if self.is_char(ch) {
            self.advance();
            Ok(())
        } else {
            self.unexpected(expecting)
        }
    }

    fn enter(&mut self) -> PResult<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return self.sem("memory exhausted");
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    // ------------------------------------------------------------------ top level

    fn parse_rules(&mut self) {
        self.advance();
        loop {
            let start = self.consumed;
            let r = match &self.tok {
                Tok::Eof => break,
                Tok::Kw(Kw::Import) => self.parse_import(),
                Tok::Kw(Kw::Rule | Kw::Private | Kw::Global) => self.parse_rule(),
                _ => self.unexpected(""),
            };
            if r.is_err() && !self.recover(start) {
                break;
            }
        }
    }

    /// Bison error recovery (`rules: rules error rule | rules error import`):
    /// a syntax error right after a recovery (yyerrstatus == 3) discards the
    /// lookahead, then tokens are discarded until one that can start a rule or
    /// an import. Returns false when the end of input is reached (YYABORT).
    fn recover(&mut self, start: u64) -> bool {
        self.loops.clear();
        // libyara never resets loop_for_of_var_index on errors: a failed for-of
        // body leaves it set for the rest of the source (later for-of loops then
        // report "can't be nested").
        self.depth = 0;
        if (self.syntax_fail && self.grace == 3) || self.consumed == start {
            if self.tok == Tok::Eof {
                return false;
            }
            self.discard();
        }
        self.grace = 3;
        loop {
            match self.tok {
                Tok::Eof => return false,
                Tok::Kw(Kw::Rule | Kw::Private | Kw::Global | Kw::Import) => return true,
                _ => self.discard(),
            }
        }
    }

    fn parse_import(&mut self) -> PResult<()> {
        self.advance();
        match &self.tok {
            Tok::Text(name) => {
                let name = String::from_utf8_lossy(name).into_owned();
                self.advance();
                {
                    let _ = name;
                    self.sem_at("modules are not supported", self.prev_line)
                }
            }
            _ => self.unexpected("text string"),
        }
    }

    fn parse_rule(&mut self) -> PResult<()> {
        let mut private = false;
        let mut global = false;
        loop {
            match self.tok {
                Tok::Kw(Kw::Private) => private = true,
                Tok::Kw(Kw::Global) => global = true,
                _ => break,
            }
            self.advance();
        }
        if !self.is_kw(Kw::Rule) {
            return self.unexpected("<rule>");
        }
        self.advance();
        let name = match &self.tok {
            Tok::Ident(n) => n.clone(),
            _ => return self.unexpected("identifier"),
        };
        self.advance();
        // Phase 1 (yr_parser_reduce_rule_declaration_phase_1).
        let line = self.prev_line;
        if self.c.rule_index.contains_key(&(self.ns, name.clone())) {
            return self.sem_at(format!("duplicated identifier \"{name}\""), line);
        }
        if self.c.wildcards.iter().any(|(ns, p)| *ns == self.ns && name.as_bytes().starts_with(p.as_bytes())) {
            return self.sem_at(format!("rule identifier \"{name}\" matches previously used wildcard rule set"), line);
        }
        let idx = self.c.rules.len() as u32;
        let sstart = self.c.strings.len() as u32;
        self.c.rules.push(CRule {
            name: name.clone(),
            ns: self.ns,
            private,
            global,
            tags: Vec::new(),
            meta: Vec::new(),
            strings: (sstart, sstart),
            code: (0, 0),
        });
        self.c.rule_index.insert((self.ns, name.clone()), idx);
        self.rule = idx;
        self.rule_strings_start = sstart;
        self.str_lookup.clear();
        self.loops.clear();
        self.depth = 0;

        // Tags.
        if self.is_char(b':') {
            self.advance();
            if !matches!(self.tok, Tok::Ident(_)) {
                return self.unexpected("identifier");
            }
            let mut tags: Vec<String> = Vec::new();
            while let Tok::Ident(t) = &self.tok {
                let t = t.clone();
                self.advance();
                if tags.contains(&t) {
                    return self.sem_at(format!("duplicated tag identifier \"{t}\""), self.prev_line);
                }
                tags.push(t);
            }
            self.c.rules[idx as usize].tags = tags;
        }
        self.expect_char(b'{', "")?;

        // Meta.
        if self.is_kw(Kw::Meta) {
            self.advance();
            self.expect_char(b':', "':'")?;
            if !matches!(self.tok, Tok::Ident(_)) {
                return self.unexpected("identifier");
            }
            while let Tok::Ident(id) = &self.tok {
                let id = id.clone();
                self.advance();
                self.expect_char(b'=', "'='")?;
                let v = match &self.tok {
                    Tok::Text(s) => {
                        // Stored as a C string, decoded as UTF-8 with "ignore".
                        let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
                        MetaValue::Str(utf8_ignore(&s[..end]))
                    }
                    Tok::Number(n) => MetaValue::Int(*n as i32 as i64),
                    Tok::Char(b'-') => {
                        self.advance();
                        match &self.tok {
                            Tok::Number(n) => MetaValue::Int(n.wrapping_neg() as i32 as i64),
                            _ => return self.unexpected("integer number"),
                        }
                    }
                    Tok::Kw(Kw::True) => MetaValue::Bool(true),
                    Tok::Kw(Kw::False) => MetaValue::Bool(false),
                    _ => return self.unexpected(""),
                };
                self.advance();
                // yara-python builds a dict: a repeated key keeps its first
                // position and takes the last value.
                let meta = &mut self.c.rules[idx as usize].meta;
                match meta.iter_mut().find(|(k, _)| *k == id) {
                    Some(slot) => slot.1 = v,
                    None => meta.push((id, v)),
                }
            }
        }

        // Strings.
        if self.is_kw(Kw::Strings) {
            self.advance();
            self.expect_char(b':', "':'")?;
            if !matches!(self.tok, Tok::StrId(_)) {
                return self.unexpected("string identifier");
            }
            while let Tok::StrId(_) = &self.tok {
                self.parse_string_decl()?;
            }
        }

        // Condition.
        if !self.is_kw(Kw::Condition) {
            return self.unexpected("<condition>");
        }
        self.advance();
        self.expect_char(b':', "':'")?;
        let code_start = self.c.prog.code.len() as u32;
        let e = self.boolean_expression()?;
        let _ = e;
        if !self.is_char(b'}') {
            return self.unexpected("'}'");
        }
        self.advance();
        let code_end = self.c.prog.code.len() as u32;

        // Phase 2: unreferenced strings, string count.
        let send = self.c.strings.len() as u32;
        for i in sstart..send {
            let s = &self.c.strings[i as usize];
            if !s.referenced {
                let id = &self.c.defs[i as usize].id;
                if s.anonymous || id.as_bytes().get(1) != Some(&b'_') {
                    let msg = format!("unreferenced string \"{id}\"");
                    return self.sem_at(msg, self.prev_line);
                }
                self.c.strings[i as usize].fixed = false;
            }
            if (i - sstart) as usize + 1 > MAX_STRINGS_PER_RULE {
                return self.sem_at(
                    format!("too many strings in rule \"{name}\" (limit: {MAX_STRINGS_PER_RULE})"),
                    self.prev_line,
                );
            }
        }
        let r = &mut self.c.rules[idx as usize];
        r.strings = (sstart, send);
        r.code = (code_start, code_end);
        Ok(())
    }

    // ------------------------------------------------------------------ strings

    fn parse_string_decl(&mut self) -> PResult<()> {
        let id = match &self.tok {
            Tok::StrId(s) => s.clone(),
            _ => return self.unexpected("string identifier"),
        };
        self.advance();
        self.expect_char(b'=', "'='")?;
        let decl_line = self.tok_line;
        let mut mods = Modifiers::default();
        let mut empty = false;
        let kind = match std::mem::replace(&mut self.tok, Tok::Eof) {
            Tok::Text(s) => {
                self.advance();
                empty = s.is_empty();
                self.parse_text_modifiers(&mut mods, decl_line)?;
                StringKind::Text(s)
            }
            Tok::Regex { src, nocase, dotall } => {
                self.advance();
                self.parse_simple_modifiers(&mut mods, true, decl_line)?;
                if nocase {
                    mods.nocase = true;
                }
                StringKind::Regex { src, nocase, dotall }
            }
            Tok::Hex(h) => {
                self.advance();
                self.parse_simple_modifiers(&mut mods, false, decl_line)?;
                StringKind::Hex(h)
            }
            other => {
                self.tok = other;
                return self.unexpected("text string");
            }
        };

        // yr_parser_reduce_string_declaration checks.
        let anonymous = id == "$";
        if !anonymous && self.str_lookup.contains_key(&id) {
            return self.sem_at(format!("duplicated string identifier \"{id}\""), decl_line);
        }
        if empty {
            return self.sem_at(format!("empty string \"{id}\""), decl_line);
        }
        let base64 = mods.base64.is_some() || mods.base64wide.is_some();
        if !mods.wide {
            // STRING_FLAGS_ASCII is implied when not wide (base64 strings encode
            // the ascii form in that case as well).
            mods.ascii = true;
        }
        let gidx = self.c.strings.len() as u32;
        if !anonymous {
            self.str_lookup.insert(id.clone(), gidx);
        }
        if let Some(msg) = check_modifier_combination(&mods) {
            return self.sem_at(msg, decl_line);
        }
        let def = StringDef { id: id.clone(), kind, mods, fixed_offset: None };
        // Hex / regex validity comes from the matcher (libyara parses the
        // string at declaration time).
        let validate = !matches!(def.kind, StringKind::Text(_)) || base64;
        if let Err(e) = if validate { Matcher::new(std::slice::from_ref(&def)).map(|_| ()) } else { Ok(()) } {
            let msg = if e.starts_with("invalid ") {
                e
            } else {
                let what = if matches!(def.kind, StringKind::Hex(_)) { "hex string" } else { "regular expression" };
                format!("invalid {what} \"{id}\": {e}")
            };
            return self.sem_at(msg, decl_line);
        }
        let private = def.mods.private;
        self.c.defs.push(def);
        self.c.strings.push(CString {
            rule: self.rule,
            private,
            anonymous,
            referenced: false,
            fixed: true,
            fixed_offset: UNDEF,
            base64,
        });
        Ok(())
    }

    fn dup_modifier(&mut self, line: usize) -> PResult<()> {
        self.sem_at("duplicated modifier", line)
    }

    fn parse_text_modifiers(&mut self, m: &mut Modifiers, line: usize) -> PResult<()> {
        // Current alphabet (string_modifiers keeps a single one).
        let mut alphabet: Option<Vec<u8>> = None;
        loop {
            match self.tok {
                Tok::Kw(Kw::Wide) => flag(self, &mut m.wide, line)?,
                Tok::Kw(Kw::Ascii) => flag(self, &mut m.ascii, line)?,
                Tok::Kw(Kw::Nocase) => flag(self, &mut m.nocase, line)?,
                Tok::Kw(Kw::Fullword) => flag(self, &mut m.fullword, line)?,
                Tok::Kw(Kw::Private) => flag(self, &mut m.private, line)?,
                Tok::Kw(Kw::Xor) => {
                    self.advance();
                    let mut range = (0u8, 255u8);
                    if self.is_char(b'(') {
                        self.advance();
                        let lo = match self.tok {
                            Tok::Number(n) => n,
                            _ => return self.unexpected("integer number"),
                        };
                        self.advance();
                        if self.is_char(b')') {
                            self.advance();
                            if !(0..=255).contains(&lo) {
                                return self.sem_at("invalid xor range", line);
                            }
                            range = (lo as u8, lo as u8);
                        } else if self.is_char(b'-') {
                            self.advance();
                            let hi = match self.tok {
                                Tok::Number(n) => n,
                                _ => return self.unexpected("integer number"),
                            };
                            self.advance();
                            self.expect_char(b')', "')'")?;
                            let mut err = None;
                            if lo < 0 {
                                err = Some("lower bound for xor range exceeded (min: 0)");
                            }
                            if hi > 255 {
                                err = Some("upper bound for xor range exceeded (max: 255)");
                            }
                            if lo > hi {
                                err = Some("xor lower bound exceeds upper bound");
                            }
                            if let Some(e) = err {
                                return self.sem_at(e, line);
                            }
                            range = (lo as u8, hi as u8);
                        } else {
                            return self.unexpected("')' or '-'");
                        }
                    }
                    if m.xor.is_some() {
                        return self.dup_modifier(line);
                    }
                    m.xor = Some(range);
                }
                Tok::Kw(k @ (Kw::Base64 | Kw::Base64Wide)) => {
                    self.advance();
                    let mut custom = None;
                    if self.is_char(b'(') {
                        self.advance();
                        let a = match &self.tok {
                            Tok::Text(a) => a.clone(),
                            _ => return self.unexpected("text string"),
                        };
                        self.advance();
                        self.expect_char(b')', "')'")?;
                        if a.len() != 64 {
                            return self.sem_at("length of base64 alphabet must be 64", line);
                        }
                        custom = Some(a);
                    }
                    let this = custom.clone().unwrap_or_else(|| DEFAULT_BASE64_ALPHABET.to_vec());
                    match &alphabet {
                        Some(a) if *a != this => return self.sem_at("can not specify multiple alphabets", line),
                        Some(_) => {}
                        None => alphabet = Some(this),
                    }
                    let slot = if k == Kw::Base64 { &mut m.base64 } else { &mut m.base64wide };
                    if slot.is_some() {
                        return self.dup_modifier(line);
                    }
                    *slot = Some(custom);
                }
                _ => return Ok(()),
            }
        }

        fn flag(p: &mut Parser<'_, '_>, f: &mut bool, line: usize) -> PResult<()> {
            p.advance();
            if *f {
                return p.dup_modifier(line);
            }
            *f = true;
            Ok(())
        }
    }

    /// Regexp strings: wide ascii nocase fullword private; hex strings: private.
    fn parse_simple_modifiers(&mut self, m: &mut Modifiers, regex: bool, line: usize) -> PResult<()> {
        loop {
            let slot = match self.tok {
                Tok::Kw(Kw::Private) => &mut m.private,
                Tok::Kw(Kw::Wide) if regex => &mut m.wide,
                Tok::Kw(Kw::Ascii) if regex => &mut m.ascii,
                Tok::Kw(Kw::Nocase) if regex => &mut m.nocase,
                Tok::Kw(Kw::Fullword) if regex => &mut m.fullword,
                _ => return Ok(()),
            };
            if *slot {
                self.advance();
                return self.dup_modifier(line);
            }
            *slot = true;
            self.advance();
        }
    }

    // ------------------------------------------------------------------ emission

    fn emit(&mut self, op: Op) -> usize {
        self.c.prog.code.push(op);
        self.c.prog.code.len() - 1
    }

    fn here(&self) -> u32 {
        self.c.prog.code.len() as u32
    }

    fn patch(&mut self, at: usize, target: u32) {
        if let Some(op) = self.c.prog.code.get_mut(at) {
            *op = match *op {
                Op::JFalse(_) => Op::JFalse(target),
                Op::JTrue(_) => Op::JTrue(target),
                Op::JTrueP(_) => Op::JTrueP(target),
                o => o,
            };
        }
    }

    fn add_set(&mut self, items: &[u32]) -> u32 {
        let a = self.c.prog.set_items.len() as u32;
        self.c.prog.set_items.extend_from_slice(items);
        let b = self.c.prog.set_items.len() as u32;
        self.c.prog.sets.push((a, b));
        (self.c.prog.sets.len() - 1) as u32
    }

    fn str_const(&mut self, s: Vec<u8>) -> u32 {
        self.c.prog.str_pool.push(s);
        (self.c.prog.str_pool.len() - 1) as u32
    }

    /// OP_STR_TO_BOOL when a string is used as a boolean_expression.
    fn emit_str_to_bool(&mut self, e: Expr) {
        if e.ty == Ty::Str {
            self.emit(Op::StrToBool);
        }
    }

    fn check_type(&mut self, e: Expr, allowed: &[Ty], op: &str) -> PResult<()> {
        if allowed.contains(&e.ty) {
            return Ok(());
        }
        let msg = if e.ty == Ty::Regex { String::new() } else { format!("wrong type \"{}\" for {} operator", e.ty.name(), op) };
        self.sem(msg)
    }

    // ------------------------------------------------------------------ conditions

    /// boolean_expression at the lowest precedence (`or`).
    fn boolean_expression(&mut self) -> PResult<Expr> {
        let e = self.or_expr()?;
        self.emit_str_to_bool(e);
        Ok(Expr { primary: false, ..e })
    }

    fn or_expr(&mut self) -> PResult<Expr> {
        let mut l = self.and_expr()?;
        while self.is_kw(Kw::Or) {
            self.emit_str_to_bool(l);
            let j = self.emit(Op::JTrue(0));
            self.advance();
            let r = self.and_expr()?;
            self.emit_str_to_bool(r);
            self.emit(Op::Or);
            let t = self.here();
            self.patch(j, t);
            l = Expr::boolean();
        }
        Ok(l)
    }

    fn and_expr(&mut self) -> PResult<Expr> {
        let mut l = self.not_expr()?;
        while self.is_kw(Kw::And) {
            self.emit_str_to_bool(l);
            let j = self.emit(Op::JFalse(0));
            self.advance();
            let r = self.not_expr()?;
            self.emit_str_to_bool(r);
            self.emit(Op::And);
            let t = self.here();
            self.patch(j, t);
            l = Expr::boolean();
        }
        Ok(l)
    }

    fn not_expr(&mut self) -> PResult<Expr> {
        let op = match self.tok {
            Tok::Kw(Kw::Not) => Op::Not,
            Tok::Kw(Kw::Defined) => Op::Defined,
            _ => return self.cmp_expr(),
        };
        self.advance();
        self.enter()?;
        let e = self.not_expr()?;
        self.leave();
        self.emit_str_to_bool(e);
        self.emit(op);
        Ok(Expr::boolean())
    }

    /// The `expression` alternatives above `not` precedence.
    fn cmp_expr(&mut self) -> PResult<Expr> {
        match self.tok.clone() {
            Tok::Kw(Kw::True) | Tok::Kw(Kw::False) => {
                let v = self.is_kw(Kw::True) as i64;
                self.advance();
                self.emit(Op::Push(v));
                Ok(Expr::boolean())
            }
            Tok::Kw(Kw::For) => self.for_loop(),
            Tok::Kw(q @ (Kw::All | Kw::Any | Kw::None)) => {
                self.advance();
                self.emit(Op::Push(match q {
                    Kw::All => UNDEF,
                    Kw::Any => 1,
                    _ => 0,
                }));
                if !self.is_kw(Kw::Of) {
                    return self.unexpected("<of>");
                }
                self.of_expr()
            }
            Tok::StrId(id) => {
                self.advance();
                if self.is_kw(Kw::At) {
                    self.advance();
                    let e = self.primary(false)?;
                    self.check_type(e, &[Ty::Int], "at")?;
                    let r = self.string_ref(&id, RefKind::At(e.ival))?;
                    self.emit(Op::FoundAt(r));
                } else if self.is_kw(Kw::In) {
                    self.advance();
                    self.range()?;
                    let r = self.string_ref(&id, RefKind::Other)?;
                    self.emit(Op::FoundIn(r));
                } else {
                    let r = self.string_ref(&id, RefKind::Found)?;
                    self.emit(Op::Found(r));
                }
                Ok(Expr::boolean())
            }
            Tok::Char(b'(') => {
                self.advance();
                self.enter()?;
                let inner = self.or_expr()?;
                self.leave();
                if !self.is_char(b')') {
                    return self.unexpected("");
                }
                self.advance();
                if inner.primary {
                    // '(' primary_expression ')': may continue as a primary.
                    let e = self.binary(inner, 0, true)?;
                    self.after_primary(e)
                } else {
                    Ok(Expr { primary: false, ..inner })
                }
            }
            _ => {
                let e = self.primary(true)?;
                self.after_primary(e)
            }
        }
    }

    /// What may follow a complete primary_expression at `expression` level.
    fn after_primary(&mut self, e: Expr) -> PResult<Expr> {
        let op = match self.tok {
            Tok::Lt => "<",
            Tok::Gt => ">",
            Tok::Le => "<=",
            Tok::Ge => ">=",
            Tok::Eq => "==",
            Tok::Neq => "!=",
            Tok::Kw(Kw::Matches) => {
                self.advance();
                let (src, nocase, dotall) = match std::mem::replace(&mut self.tok, Tok::Eof) {
                    Tok::Regex { src, nocase, dotall } => (src, nocase, dotall),
                    other => {
                        self.tok = other;
                        return self.unexpected("regular expression");
                    }
                };
                self.advance();
                let idx = self.compile_regex(&src, nocase, dotall)?;
                self.check_type(e, &[Ty::Str], "matches")?;
                self.emit(Op::Push(RE_BASE + idx as i64));
                self.emit(Op::Matches);
                return Ok(Expr::boolean());
            }
            Tok::Kw(
                k @ (Kw::Contains
                | Kw::Icontains
                | Kw::Startswith
                | Kw::Istartswith
                | Kw::Endswith
                | Kw::Iendswith
                | Kw::Iequals),
            ) => {
                self.advance();
                let r = self.primary(false)?;
                let (name, op) = match k {
                    Kw::Contains => ("contains", Op::Contains),
                    Kw::Icontains => ("icontains", Op::IContains),
                    Kw::Startswith => ("startswith", Op::StartsWith),
                    Kw::Istartswith => ("istartswith", Op::IStartsWith),
                    Kw::Endswith => ("endswith", Op::EndsWith),
                    Kw::Iendswith => ("iendswith", Op::IEndsWith),
                    _ => ("iequals", Op::IEquals),
                };
                self.check_type(e, &[Ty::Str], name)?;
                self.check_type(r, &[Ty::Str], name)?;
                self.emit(op);
                return Ok(Expr::boolean());
            }
            Tok::Kw(Kw::Of) => {
                self.for_expression_check(e)?;
                return self.of_expr();
            }
            Tok::Char(b'%') => {
                // Only reached for `primary % of` (binary() stopped before it).
                self.advance(); // '%'
                self.advance(); // `of`
                return self.of_set(Some(e));
            }
            _ => return Ok(e),
        };
        self.advance();
        let r = self.primary(false)?;
        self.reduce_operation(op, e, r)?;
        Ok(Expr::boolean())
    }

    /// for_expression: primary_expression checks.
    fn for_expression_check(&mut self, e: Expr) -> PResult<()> {
        match e.ty {
            Ty::Int if !undef(e.ival) && e.ival < 0 => {
                let v = e.ival;
                self.sem(format!("invalid value in condition: \"{v}\""))
            }
            Ty::Float => self.sem("invalid value in condition: \"float\""),
            Ty::Str => {
                let s = match e.str_const {
                    Some(i) => {
                        let bytes = self.c.prog.str_pool.get(i as usize).cloned().unwrap_or_default();
                        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                        String::from_utf8_lossy(&bytes[..end]).into_owned()
                    }
                    None => "string in for_expression is invalid".into(),
                };
                self.sem(format!("invalid value in condition: \"{s}\""))
            }
            Ty::Regex => self.sem("invalid value in condition: \"regexp in for_expression is invalid\""),
            _ => Ok(()),
        }
    }

    /// `<quantifier already emitted> of <set> [in range | at expr]`.
    fn of_expr(&mut self) -> PResult<Expr> {
        self.advance(); // `of`
        self.of_set(None)
    }

    /// The `primary_expression '%' _OF_ ...` checks (run once the set is parsed).
    fn percent_check(&mut self, e: Expr) -> PResult<()> {
        self.check_type(e, &[Ty::Int], "%")?;
        if !undef(e.ival) && !(1..=100).contains(&e.ival) {
            return self.sem("percentage must be between 1 and 100 (inclusive)");
        }
        Ok(())
    }

    /// The set after `of`; `percent` = the percentage expression of `N% of`.
    fn of_set(&mut self, percent: Option<Expr>) -> PResult<Expr> {
        let is_rule_set = self.is_char(b'(') && matches!(self.peek2(), Tok::Ident(_));
        if is_rule_set {
            let set = self.rule_set()?;
            match percent {
                Some(e) => {
                    self.percent_check(e)?;
                    self.emit(Op::OfPercentRules(set));
                }
                None => {
                    self.emit(Op::OfRules(set));
                }
            }
            return Ok(Expr::boolean());
        }
        let items = self.string_set()?;
        let set = self.add_set(&items);
        if let Some(e) = percent {
            self.percent_check(e)?;
            self.emit(Op::OfPercentStrings(set));
            return Ok(Expr::boolean());
        }
        if self.is_kw(Kw::In) {
            self.advance();
            self.range()?;
            self.emit(Op::OfFoundIn(set));
        } else if self.is_kw(Kw::At) {
            self.advance();
            let e = self.primary(false)?;
            if e.ty != Ty::Int {
                return self.sem("invalid value in condition: \"at expression must be an integer\"");
            }
            self.emit(Op::OfFoundAt(set));
        } else {
            self.emit(Op::OfStrings(set));
        }
        Ok(Expr::boolean())
    }

    /// string_set: `them` or `( $a, $b*, ... )`. Marks strings referenced and
    /// clears their FIXED_OFFSET (yr_parser_emit_pushes_for_strings).
    fn string_set(&mut self) -> PResult<Vec<u32>> {
        let mut items = Vec::new();
        if self.is_kw(Kw::Them) {
            self.advance();
            self.push_strings("$*", &mut items)?;
            return Ok(items);
        }
        if !self.is_char(b'(') {
            return self.unexpected("<them> or '('");
        }
        self.advance();
        loop {
            match self.tok.clone() {
                Tok::StrId(id) | Tok::StrIdWild(id) => {
                    self.advance();
                    self.push_strings(&id, &mut items)?;
                }
                _ => return self.unexpected(""),
            }
            if self.is_char(b',') {
                self.advance();
                continue;
            }
            if self.is_char(b')') {
                self.advance();
                return Ok(items);
            }
            return self.unexpected("')' or ','");
        }
    }

    fn push_strings(&mut self, pattern: &str, items: &mut Vec<u32>) -> PResult<()> {
        let pat = pattern.as_bytes();
        let start = self.rule_strings_start as usize;
        let mut n = 0;
        for g in start..self.c.defs.len() {
            let id = self.c.defs[g].id.as_bytes();
            let common = id.iter().zip(pat).take_while(|(a, b)| a == b).count();
            let full = common == id.len() && common == pat.len();
            let wild = pat.get(common) == Some(&b'*');
            if full || wild {
                items.push(g as u32);
                let s = &mut self.c.strings[g];
                s.referenced = true;
                s.fixed = false;
                n += 1;
            }
        }
        if n == 0 {
            return self.sem(format!("undefined string \"{pattern}\""));
        }
        Ok(())
    }

    /// rule_set: `( rule, prefix*, ... )`.
    fn rule_set(&mut self) -> PResult<u32> {
        self.advance(); // '('
        let mut items: Vec<u32> = Vec::new();
        loop {
            let name = match &self.tok {
                Tok::Ident(n) => n.clone(),
                _ => return self.unexpected("identifier"),
            };
            self.advance();
            if self.is_char(b'*') {
                self.advance();
                self.c.wildcards.push((self.ns, name.clone()));
                let mut n = 0;
                let upto = (self.rule as usize + 1).min(self.c.rules.len());
                for i in 0..upto {
                    if self.c.rules[i].name.as_bytes().starts_with(name.as_bytes()) {
                        let key = (self.ns, self.c.rules[i].name.clone());
                        if let Some(&ri) = self.c.rule_index.get(&key) {
                            items.push(ri);
                            n += 1;
                        }
                    }
                }
                if n == 0 {
                    return self.sem(format!("undefined identifier \"{name}\""));
                }
            } else {
                match self.c.rule_index.get(&(self.ns, name.clone())) {
                    Some(&ri) => items.push(ri),
                    None => return self.sem(format!("undefined identifier \"{name}\"")),
                }
            }
            if self.is_char(b',') {
                self.advance();
                continue;
            }
            if self.is_char(b')') {
                self.advance();
                break;
            }
            return self.unexpected("')' or ','");
        }
        Ok(self.add_set(&items))
    }

    /// range: `( primary .. primary )`; emits lower then upper.
    fn range(&mut self) -> PResult<()> {
        if !self.is_char(b'(') {
            return self.unexpected("'('");
        }
        self.advance();
        let lo = self.primary(false)?;
        if self.tok != Tok::DotDot {
            return self.unexpected("..");
        }
        self.advance();
        let hi = self.primary(false)?;
        if !self.is_char(b')') {
            return self.unexpected("')'");
        }
        self.advance();
        self.range_check(lo, hi)
    }

    fn range_check(&mut self, lo: Expr, hi: Expr) -> PResult<()> {
        let mut err: Option<String> = None;
        if lo.ty != Ty::Int {
            err = Some("wrong type for range's lower bound".into());
        }
        if hi.ty != Ty::Int {
            err = Some("wrong type for range's upper bound".into());
        }
        if err.is_none() && !undef(lo.ival) && !undef(hi.ival) {
            if lo.ival > hi.ival {
                err = Some("invalid value in condition: \"range lower bound must be less than upper bound\"".into());
            } else if lo.ival < 0 {
                err = Some("invalid value in condition: \"range lower bound can not be negative\"".into());
            }
        }
        match err {
            Some(e) => self.sem(e),
            None => Ok(()),
        }
    }

    fn compile_regex(&mut self, src: &[u8], nocase: bool, dotall: bool) -> PResult<u32> {
        match CondRegex::new(src, nocase, dotall) {
            Ok(re) => {
                self.c.prog.regex_pool.push(re);
                Ok((self.c.prog.regex_pool.len() - 1) as u32)
            }
            Err(e) => self.sem(e),
        }
    }

    /// yr_parser_reduce_operation for comparisons and + - * \.
    fn reduce_operation(&mut self, op: &str, l: Expr, r: Expr) -> PResult<Ty> {
        let num = |t: Ty| t == Ty::Int || t == Ty::Float;
        if num(l.ty) && num(r.ty) {
            if l.ty != r.ty {
                self.emit(Op::IntToDbl(if l.ty == Ty::Int { 2 } else { 1 }));
            }
            let int = l.ty == Ty::Int && r.ty == Ty::Int;
            let o = match (op, int) {
                ("<", true) => Op::IntLt,
                (">", true) => Op::IntGt,
                ("<=", true) => Op::IntLe,
                (">=", true) => Op::IntGe,
                ("==", true) => Op::IntEq,
                ("!=", true) => Op::IntNeq,
                ("+", true) => Op::IntAdd,
                ("-", true) => Op::IntSub,
                ("*", true) => Op::IntMul,
                ("\\", true) => Op::IntDiv,
                ("<", false) => Op::DblLt,
                (">", false) => Op::DblGt,
                ("<=", false) => Op::DblLe,
                (">=", false) => Op::DblGe,
                ("==", false) => Op::DblEq,
                ("!=", false) => Op::DblNeq,
                ("+", false) => Op::DblAdd,
                ("-", false) => Op::DblSub,
                ("*", false) => Op::DblMul,
                _ => Op::DblDiv,
            };
            self.emit(o);
            Ok(if int { Ty::Int } else { Ty::Float })
        } else if l.ty == Ty::Str && r.ty == Ty::Str {
            let o = match op {
                "<" => Op::StrLt,
                ">" => Op::StrGt,
                "<=" => Op::StrLe,
                ">=" => Op::StrGe,
                "==" => Op::StrEq,
                "!=" => Op::StrNeq,
                _ => return self.sem(format!("strings don't support \"{op}\" operation")),
            };
            self.emit(o);
            Ok(Ty::Str)
        } else {
            self.sem("type mismatch")
        }
    }

    // ------------------------------------------------------------------ primary

    /// primary_expression (operator precedence climbing). `top` = parsed at
    /// `expression` level, where `primary % of ...` is allowed.
    fn primary(&mut self, top: bool) -> PResult<Expr> {
        let l = self.unary()?;
        self.binary(l, 0, top)
    }

    fn binop(&self) -> Option<(u8, &'static str)> {
        Some(match self.tok {
            Tok::Char(b'|') => (1, "|"),
            Tok::Char(b'^') => (2, "^"),
            Tok::Char(b'&') => (3, "&"),
            Tok::Shl => (4, "<<"),
            Tok::Shr => (4, ">>"),
            Tok::Char(b'+') => (5, "+"),
            Tok::Char(b'-') => (5, "-"),
            Tok::Char(b'*') => (6, "*"),
            Tok::Char(b'\\') => (6, "\\"),
            Tok::Char(b'%') => (6, "%"),
            _ => return None,
        })
    }

    fn binary(&mut self, mut l: Expr, min_prec: u8, top: bool) -> PResult<Expr> {
        while let Some((prec, op)) = self.binop() {
            if prec < min_prec {
                break;
            }
            if op == "%" && matches!(self.peek2(), Tok::Kw(Kw::Of)) {
                if top && min_prec == 0 {
                    break; // percentage quantifier, handled by after_primary
                }
                self.advance();
                return self.unexpected("");
            }
            self.advance();
            self.enter()?;
            let r0 = self.unary()?;
            let r = self.binary(r0, prec + 1, false)?;
            self.leave();
            l = self.combine(op, l, r)?;
        }
        Ok(l)
    }

    fn combine(&mut self, op: &str, l: Expr, r: Expr) -> PResult<Expr> {
        match op {
            "+" | "-" | "*" | "\\" => {
                let res = self.reduce_operation(op, l, r);
                if l.ty == Ty::Int && r.ty == Ty::Int {
                    res?;
                    let (i1, i2) = (l.ival, r.ival);
                    let v = match op {
                        "+" => {
                            if !undef(i1)
                                && !undef(i2)
                                && ((i2 > 0 && i1 > i64::MAX - i2) || (i2 < 0 && i1 < i64::MIN - i2))
                            {
                                return self.sem(format!("integer overflow in \"{i1} + {i2}\""));
                            }
                            operation(i1, i2, i64::wrapping_add)
                        }
                        "-" => {
                            if !undef(i1)
                                && !undef(i2)
                                && ((i2 < 0 && i1 > i64::MAX.wrapping_add(i2)) || (i2 > 0 && i1 < i64::MIN.wrapping_add(i2)))
                            {
                                return self.sem(format!("integer overflow in \"{i1} - {i2}\""));
                            }
                            operation(i1, i2, i64::wrapping_sub)
                        }
                        "*" => {
                            if !undef(i1) && !undef(i2) && i2 != 0 && i1.wrapping_abs() > i64::MAX / i2.wrapping_abs() {
                                return self.sem(format!("integer overflow in \"{i1} * {i2}\""));
                            }
                            operation(i1, i2, i64::wrapping_mul)
                        }
                        _ => {
                            if i2 == 0 {
                                return self.sem("division by zero");
                            }
                            operation(i1, i2, i64::wrapping_div)
                        }
                    };
                    Ok(Expr::prim(Ty::Int, v))
                } else {
                    res?;
                    Ok(Expr::prim(Ty::Float, l.ival))
                }
            }
            "%" => {
                self.check_type(l, &[Ty::Int], "%")?;
                self.check_type(r, &[Ty::Int], "%")?;
                self.emit(Op::Mod);
                if r.ival == 0 {
                    return self.sem("division by zero");
                }
                Ok(Expr::prim(Ty::Int, operation(l.ival, r.ival, i64::wrapping_rem)))
            }
            "^" | "&" | "|" => {
                // libyara checks `&` with the "^" operator name.
                let name = if op == "|" { "|" } else { "^" };
                self.check_type(l, &[Ty::Int], name)?;
                self.check_type(r, &[Ty::Int], name)?;
                let (o, v) = match op {
                    "^" => (Op::BitXor, operation(l.ival, r.ival, |a, b| a ^ b)),
                    "&" => (Op::BitAnd, operation(l.ival, r.ival, |a, b| a & b)),
                    _ => (Op::BitOr, operation(l.ival, r.ival, |a, b| a | b)),
                };
                self.emit(o);
                Ok(Expr::prim(Ty::Int, v))
            }
            _ => {
                // << and >> (libyara folds both constants with <<).
                self.check_type(l, &[Ty::Int], op)?;
                self.check_type(r, &[Ty::Int], op)?;
                self.emit(if op == "<<" { Op::Shl } else { Op::Shr });
                let v = if !undef(r.ival) && r.ival < 0 {
                    // ERROR_INVALID_OPERAND has no message text.
                    return self.sem("");
                } else if !undef(r.ival) && r.ival >= 64 {
                    0
                } else {
                    operation(l.ival, r.ival, |a, b| a.wrapping_shl(b as u32))
                };
                Ok(Expr::prim(Ty::Int, v))
            }
        }
    }

    fn unary(&mut self) -> PResult<Expr> {
        match self.tok {
            Tok::Char(b'-') => {
                self.advance();
                self.enter()?;
                let e = self.unary()?;
                self.leave();
                self.check_type(e, &[Ty::Int, Ty::Float], "-")?;
                if e.ty == Ty::Int {
                    self.emit(Op::IntMinus);
                    Ok(Expr::prim(Ty::Int, if undef(e.ival) { UNDEF } else { e.ival.wrapping_neg() }))
                } else {
                    self.emit(Op::DblMinus);
                    Ok(Expr::prim(Ty::Float, e.ival))
                }
            }
            Tok::Char(b'~') => {
                self.advance();
                self.enter()?;
                let e = self.unary()?;
                self.leave();
                self.check_type(e, &[Ty::Int], "~")?;
                self.emit(Op::BitNot);
                Ok(Expr::prim(Ty::Int, if undef(e.ival) { UNDEF } else { !e.ival }))
            }
            _ => self.atom(),
        }
    }

    fn atom(&mut self) -> PResult<Expr> {
        match self.tok.clone() {
            Tok::Char(b'(') => {
                self.advance();
                self.enter()?;
                let e = self.primary(false)?;
                self.leave();
                if !self.is_char(b')') {
                    return self.unexpected("");
                }
                self.advance();
                Ok(e)
            }
            Tok::Kw(Kw::Filesize) => {
                self.advance();
                self.emit(Op::Filesize);
                Ok(Expr::prim(Ty::Int, UNDEF))
            }
            Tok::Kw(Kw::Entrypoint) => {
                self.advance();
                self.emit(Op::Entrypoint);
                Ok(Expr::prim(Ty::Int, UNDEF))
            }
            Tok::IntFunc(k) => {
                self.advance();
                self.expect_char(b'(', "'('")?;
                self.enter()?;
                let e = self.primary(false)?;
                self.leave();
                if !self.is_char(b')') {
                    return self.unexpected("");
                }
                self.advance();
                self.check_type(e, &[Ty::Int], "intXXXX or uintXXXX")?;
                self.emit(Op::ReadInt(IntRead::from_index(k)));
                Ok(Expr::prim(Ty::Int, UNDEF))
            }
            Tok::Number(n) => {
                self.advance();
                self.emit(Op::Push(n));
                Ok(Expr::prim(Ty::Int, n))
            }
            Tok::Double(d) => {
                self.advance();
                self.emit(Op::Push(d.to_bits() as i64));
                Ok(Expr::prim(Ty::Float, UNDEF))
            }
            Tok::Text(s) => {
                self.advance();
                let i = self.str_const(s);
                self.emit(Op::Push(STR_BASE + i as i64));
                Ok(Expr { ty: Ty::Str, ival: UNDEF, primary: true, str_const: Some(i) })
            }
            Tok::Regex { src, nocase, dotall } => {
                self.advance();
                let i = self.compile_regex(&src, nocase, dotall)?;
                self.emit(Op::Push(RE_BASE + i as i64));
                Ok(Expr::prim(Ty::Regex, UNDEF))
            }
            Tok::StrCount(id) => {
                self.advance();
                if self.is_kw(Kw::In) {
                    self.advance();
                    self.range()?;
                    let r = self.string_ref(&id, RefKind::Other)?;
                    self.emit(Op::CountIn(r));
                } else {
                    let r = self.string_ref(&id, RefKind::Other)?;
                    self.emit(Op::Count(r));
                }
                Ok(Expr::prim(Ty::Int, UNDEF))
            }
            Tok::StrOffset(id) | Tok::StrLength(id) => {
                let offset = matches!(self.tok, Tok::StrOffset(_));
                self.advance();
                if self.is_char(b'[') {
                    self.advance();
                    self.enter()?;
                    self.primary(false)?;
                    self.leave();
                    if !self.is_char(b']') {
                        return self.unexpected("");
                    }
                    self.advance();
                } else {
                    self.emit(Op::Push(1));
                }
                let r = self.string_ref(&id, RefKind::Other)?;
                self.emit(if offset { Op::Offset(r) } else { Op::Length(r) });
                Ok(Expr::prim(Ty::Int, UNDEF))
            }
            Tok::Ident(name) => {
                self.advance();
                self.identifier(&name)
            }
            _ => self.unexpected(""),
        }
    }

    /// `identifier` (loop variable or rule reference); structure / index /
    /// call syntax on them is an error as no modules exist.
    fn identifier(&mut self, name: &str) -> PResult<Expr> {
        let e = if let Some((slot, ty)) = self.lookup_var(name) {
            self.emit(Op::PushM(slot));
            Expr::prim(if ty == VarTy::Int { Ty::Int } else { Ty::Str }, UNDEF)
        } else if let Some(&ri) = self.c.rule_index.get(&(self.ns, name.to_string())) {
            self.emit(Op::PushRule(ri));
            Expr::prim(Ty::Bool, UNDEF)
        } else {
            return self.sem(format!("undefined identifier \"{name}\""));
        };
        if self.is_char(b'.') {
            self.advance();
            if !matches!(self.tok, Tok::Ident(_)) {
                return self.unexpected("identifier");
            }
            self.advance();
            return self.sem(format!("\"{name}\" is not a structure"));
        }
        if self.is_char(b'[') {
            self.advance();
            self.enter()?;
            self.primary(false)?;
            self.leave();
            if !self.is_char(b']') {
                return self.unexpected("");
            }
            self.advance();
            return self.sem(format!("\"{name}\" is not an array or dictionary"));
        }
        if self.is_char(b'(') {
            self.advance();
            if !self.is_char(b')') {
                loop {
                    self.enter()?;
                    let a = self.or_expr()?;
                    self.leave();
                    let _ = a;
                    if self.is_char(b',') {
                        self.advance();
                        continue;
                    }
                    break;
                }
            }
            if !self.is_char(b')') {
                return self.unexpected("");
            }
            self.advance();
            return self.sem(format!("\"{name}\" is not a function"));
        }
        Ok(e)
    }

    fn lookup_var(&self, name: &str) -> Option<(u8, VarTy)> {
        let mut off = 0usize;
        for l in &self.loops {
            off += INTERNAL_LOOP_VARS;
            for (j, (n, t)) in l.vars.iter().enumerate() {
                if n == name {
                    return Some(((off + j) as u8, *t));
                }
            }
            off += l.vars.len();
        }
        None
    }

    fn var_frame(&self) -> usize {
        // Frame of the innermost loop: variables of all enclosing loops.
        let n = self.loops.len();
        self.loops.iter().take(n.saturating_sub(1)).map(|l| INTERNAL_LOOP_VARS + l.vars.len()).sum()
    }

    /// yr_parser_reduce_string_identifier: resolves `$x` (or the anonymous `$`
    /// of a for-of loop) and updates referenced / FIXED_OFFSET state.
    fn string_ref(&mut self, id: &str, kind: RefKind) -> PResult<SRef> {
        if id == "$" {
            let Some(slot) = self.for_of_slot else {
                return self.sem("wrong use of anonymous string");
            };
            let start = self.rule_strings_start as usize;
            for s in &mut self.c.strings[start..] {
                match kind {
                    RefKind::At(off) => {
                        if s.fixed_offset == UNDEF {
                            s.fixed_offset = off;
                        }
                        if s.fixed_offset != off {
                            s.fixed = false;
                        }
                    }
                    _ => s.fixed = false,
                }
            }
            return Ok(SRef::Var(slot));
        }
        let Some(&g) = self.str_lookup.get(id) else {
            return self.sem(format!("undefined string \"{id}\""));
        };
        let s = &mut self.c.strings[g as usize];
        match kind {
            RefKind::At(off) => {
                if s.fixed_offset == UNDEF {
                    s.fixed_offset = off;
                }
                if s.fixed_offset == UNDEF || s.fixed_offset != off {
                    s.fixed = false;
                }
            }
            _ => s.fixed = false,
        }
        s.referenced = true;
        Ok(SRef::Fixed(g))
    }

    // ------------------------------------------------------------------ loops

    fn for_loop(&mut self) -> PResult<Expr> {
        self.advance(); // for
        // for_expression
        match self.tok {
            Tok::Kw(q @ (Kw::All | Kw::Any | Kw::None)) => {
                self.advance();
                self.emit(Op::Push(match q {
                    Kw::All => UNDEF,
                    Kw::Any => 1,
                    _ => 0,
                }));
            }
            _ => {
                let e = self.primary(false)?;
                self.for_expression_check(e)?;
            }
        }
        if self.loops.len() == MAX_LOOP_NESTING {
            return self.sem("loop nesting limit exceeded");
        }
        self.loops.push(LoopCtx { vars: Vec::new() });
        let frame = self.var_frame();
        self.emit(Op::ClearM(frame as u8));
        self.emit(Op::ClearM((frame + 1) as u8));
        self.emit(Op::PopM((frame + 2) as u8));

        let mut for_of = false;
        if self.is_kw(Kw::Of) {
            // for_iteration: _OF_ string_iterator
            self.advance();
            let items = self.string_set()?;
            if self.for_of_slot.is_some() {
                return self.sem("'for <quantifier> of <string set>' loops can't be nested");
            }
            let set = self.add_set(&items);
            self.emit(Op::IterStartStringSet(set));
            if let Some(l) = self.loops.last_mut() {
                l.vars.push((String::new(), VarTy::Int));
            }
            self.for_of_slot = Some((frame + INTERNAL_LOOP_VARS) as u8);
            for_of = true;
        } else {
            // for_variables _IN_ iterator
            loop {
                let name = match &self.tok {
                    Tok::Ident(n) => n.clone(),
                    _ => return self.unexpected("identifier"),
                };
                self.advance();
                let nvars = self.loops.last().map(|l| l.vars.len()).unwrap_or(0);
                if nvars == MAX_LOOP_VARS {
                    return self.sem("too many loop variables");
                }
                if self.lookup_var(&name).is_some() {
                    return self.sem(format!("duplicated loop identifier \"{name}\""));
                }
                if let Some(l) = self.loops.last_mut() {
                    l.vars.push((name, VarTy::Int));
                }
                if self.is_char(b',') {
                    self.advance();
                    continue;
                }
                break;
            }
            if !self.is_kw(Kw::In) {
                return self.unexpected("<in>");
            }
            self.advance();
            let vty = self.iterator()?;
            let nvars = self.loops.last().map(|l| l.vars.len()).unwrap_or(0);
            if nvars != 1 {
                return self.sem(format!(
                    "iterator yields one value on each iteration , but the loop expects {nvars}"
                ));
            }
            if let Some(l) = self.loops.last_mut() {
                l.vars[0].1 = vty;
            }
        }
        if !self.is_char(b':') {
            return self.unexpected("':'");
        }
        self.advance();
        let nvars = self.loops.last().map(|l| l.vars.len()).unwrap_or(0);
        let loop_start = self.here();
        self.emit(Op::IterNext);
        for i in 0..nvars {
            self.emit(Op::PopM((frame + INTERNAL_LOOP_VARS + i) as u8));
        }
        let jexit = self.emit(Op::JTrueP(0));
        if !self.is_char(b'(') {
            return self.unexpected("'('");
        }
        self.advance();
        self.enter()?;
        self.boolean_expression()?;
        self.leave();
        if !self.is_char(b')') {
            return self.unexpected("");
        }
        self.advance();
        if for_of {
            self.for_of_slot = None;
        }
        self.emit(Op::IncrM((frame + 1) as u8));
        self.emit(Op::PushM(frame as u8));
        self.emit(Op::PushM((frame + 2) as u8));
        self.emit(Op::IterCondition);
        self.emit(Op::AddM(frame as u8));
        self.emit(Op::JTrueP(loop_start));
        let pop_at = self.here();
        self.patch(jexit, pop_at);
        self.emit(Op::IterPop);
        self.emit(Op::PushM((frame + 1) as u8));
        self.emit(Op::PushM(frame as u8));
        self.emit(Op::PushM((frame + 2) as u8));
        self.emit(Op::IterEnd);
        self.loops.pop();
        Ok(Expr::boolean())
    }

    /// iterator: identifier (never iterable without modules) or a set:
    /// `( enumeration )` or a range. Returns the loop variable type.
    fn iterator(&mut self) -> PResult<VarTy> {
        if let Tok::Ident(name) = self.tok.clone() {
            self.advance();
            self.identifier(&name)?;
            return self.sem(format!("identifier \"{name}\" is not iterable"));
        }
        if !self.is_char(b'(') {
            return self.unexpected("identifier or '('");
        }
        self.advance();
        let first = self.primary(false)?;
        if self.tok == Tok::DotDot {
            self.advance();
            let hi = self.primary(false)?;
            if !self.is_char(b')') {
                return self.unexpected("')'");
            }
            self.advance();
            self.range_check(first, hi)?;
            self.emit(Op::IterStartIntRange);
            return Ok(VarTy::Int);
        }
        // enumeration
        if first.ty != Ty::Int && first.ty != Ty::Str {
            return self.sem("wrong type for enumeration item");
        }
        let mut n: u32 = 1;
        while self.is_char(b',') {
            self.advance();
            let e = self.primary(false)?;
            if e.ty != first.ty {
                return self.sem("enumerations must be all the same type");
            }
            n += 1;
        }
        if !self.is_char(b')') {
            return self.unexpected("')' or ','");
        }
        self.advance();
        if first.ty == Ty::Int {
            self.emit(Op::IterStartIntEnum(n));
            Ok(VarTy::Int)
        } else {
            self.emit(Op::IterStartTextStringSet(n));
            Ok(VarTy::Str)
        }
    }
}

#[derive(Clone, Copy)]
enum RefKind {
    Found,
    At(i64),
    Other,
}

/// _yr_parser_check_string_modifiers.
fn check_modifier_combination(m: &Modifiers) -> Option<String> {
    let b64 = m.base64.is_some();
    let b64w = m.base64wide.is_some();
    if m.xor.is_some() && m.nocase {
        return Some("invalid modifier combination: xor nocase".into());
    }
    if m.nocase && (b64 || b64w) {
        return Some(if b64 { "invalid modifier combination: base64 nocase" } else { "invalid modifier combination: base64wide nocase" }.into());
    }
    if m.fullword && (b64 || b64w) {
        return Some(
            if b64 { "invalid modifier combination: base64 fullword" } else { "invalid modifier combination: base64wide fullword" }.into(),
        );
    }
    if m.xor.is_some() && (b64 || b64w) {
        return Some(if b64 { "invalid modifier combination: base64 xor" } else { "invalid modifier combination: base64wide xor" }.into());
    }
    None
}

/// Python `bytes.decode("utf-8", "ignore")`, re-encoded as UTF-8 bytes.
pub fn utf8_ignore(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    loop {
        match std::str::from_utf8(b) {
            Ok(s) => {
                out.extend_from_slice(s.as_bytes());
                return out;
            }
            Err(e) => {
                let good = e.valid_up_to();
                out.extend_from_slice(&b[..good]);
                let skip = e.error_len().unwrap_or(b.len() - good);
                b = &b[good + skip.max(1).min(b.len() - good)..];
                if b.is_empty() {
                    return out;
                }
            }
        }
    }
}
