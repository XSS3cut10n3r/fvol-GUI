//! YARA rule language: lexer, parser, condition evaluator and the public scanning
//! API, mirroring what yara-python 4.5 (`yara.compile(...)`, `rules.match(data=...)`)
//! returns and how volatility3's `YaraScanner` consumes it.
//! Owner: rules front-end owner. String matching is delegated to
//! [`crate::yara::scan::Matcher`].
//!
//! Layout:
//! * [`lexer`]  — lexer.l equivalent (tokens, escapes, numbers, hex / regexp literals);
//! * [`parser`] — grammar.y + parser.c: syntax, semantic checks, code generation;
//! * [`eval`]   — exec.c equivalent stack VM (YR_UNDEFINED semantics);
//! * [`regex`]  — yara regexp syntax for the `matches` operator;
//! * [`entry`]  — `entrypoint` (PE / ELF entry point file offset);
//! * [`volatility`] — yarascan.py glue (`get_rule`, `process_yara_options`, hits).
//!
//! Evaluation is separate from matching: [`Rules::evaluate`] takes per-string
//! match lists (global string index order, see [`Rules::string_defs`]) and
//! [`Rules::scan`] is `Matcher::scan` + `evaluate`.

use std::fmt;

pub mod entry;
pub mod eval;
pub mod lexer;
pub mod parser;
pub mod regex;
pub mod volatility;

#[cfg(test)]
mod difftest;
#[cfg(test)]
mod tests;

use crate::yara::scan::{Match, Matcher, StringDef, MAX_MATCH_DATA};
use eval::{Ctx, Program, Scratch, MEM_SIZE};

/// Compilation error (yara raises `yara.SyntaxError`, "line N: msg").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError {
    pub msg: String,
    pub line: usize,
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

impl std::error::Error for CompileError {}

impl From<CompileError> for crate::error::Error {
    fn from(e: CompileError) -> Self {
        crate::error::Error::Msg(format!("yara: {e}"))
    }
}

/// Metadata value (`meta:` section), as yara-python exposes it: integers are
/// truncated to a C `int` (yara-python builds them with `Py_BuildValue("i")`),
/// strings are cut at the first NUL and decoded as UTF-8 with errors ignored
/// (stored here re-encoded as UTF-8 bytes).
#[derive(Clone, Debug, PartialEq)]
pub enum MetaValue {
    Int(i64),
    Bool(bool),
    Str(Vec<u8>),
}

/// yara-python `StringMatchInstance`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub offset: usize,
    /// At most 512 bytes (YR_MAX_MATCH_DATA).
    pub matched_data: Vec<u8>,
    pub matched_length: usize,
    pub xor_key: u8,
}

/// yara-python `StringMatch` (strings in declaration order; only strings with at
/// least one match; private strings appear with no instances).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringMatch {
    pub identifier: String,
    pub instances: Vec<Instance>,
}

/// yara-python `Match` (matching non-private rules, in declaration order).
#[derive(Clone, Debug, PartialEq)]
pub struct RuleMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    /// yara-python's `meta` dict in insertion order (a repeated key keeps its
    /// first position and its last value).
    pub meta: Vec<(String, MetaValue)>,
    pub strings: Vec<StringMatch>,
}

/// Compiled rule set.
pub struct Rules {
    namespaces: Vec<String>,
    rules: Vec<parser::CRule>,
    strings: Vec<parser::CString>,
    defs: Vec<StringDef>,
    matcher: Matcher,
    prog: Program,
}

impl fmt::Debug for Rules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rules").field("rules", &self.rules.len()).field("strings", &self.defs.len()).finish()
    }
}

thread_local! {
    static SCRATCH: std::cell::RefCell<Scratch> = std::cell::RefCell::new(Scratch::default());
}

/// C-string view of a python `str` source (libyara parses sources with
/// `yy_scan_string`, i.e. up to the first NUL).
fn c_str(s: &str) -> &[u8] {
    let b = s.as_bytes();
    match b.iter().position(|&c| c == 0) {
        Some(p) => &b[..p],
        None => b,
    }
}

impl Rules {
    /// `yara.compile(source=src)` (namespace "default").
    pub fn compile(source: &str) -> Result<Rules, CompileError> {
        Self::compile_namespaced(&[("default", source)])
    }

    /// `yara.compile(sources={ns: src, ...})` (sources compiled in order; the
    /// first failing source aborts, reporting its last error like yara-python).
    pub fn compile_namespaced(sources: &[(&str, &str)]) -> Result<Rules, CompileError> {
        let mut c = parser::Compiler::default();
        for (ns, src) in sources {
            c.add_source(ns, c_str(src))?;
        }
        Self::build(c)
    }

    /// `yara.compile(file=f)`: raw file bytes (namespace "default"; NUL bytes
    /// are lexical errors instead of terminating the source).
    pub fn compile_file_source(data: &[u8]) -> Result<Rules, CompileError> {
        let mut c = parser::Compiler::default();
        c.add_source("default", data)?;
        Self::build(c)
    }

    fn build(mut c: parser::Compiler) -> Result<Rules, CompileError> {
        c.finalize_defs();
        let matcher = Matcher::new(&c.defs).map_err(|msg| CompileError { msg, line: 0 })?;
        Ok(Rules {
            namespaces: c.namespaces,
            rules: c.rules,
            strings: c.strings,
            defs: c.defs,
            matcher,
            prog: c.prog,
        })
    }

    /// All string declarations of all rules, in global index order (the order
    /// of the per-string match lists taken by [`Rules::evaluate`]).
    pub fn string_defs(&self) -> &[StringDef] {
        &self.defs
    }

    /// Number of rules (including private ones).
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// `rules.match(data=data)`.
    pub fn scan(&self, data: &[u8]) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        self.matcher.scan(data, &mut matches);
        self.evaluate(data, &matches)
    }

    /// Evaluate all conditions given the matches of every string
    /// (`matches[i]` = sorted matches of `string_defs()[i]`; missing entries
    /// count as "no match") and build the yara-python result list.
    pub fn evaluate(&self, data: &[u8], matches: &[Vec<Match>]) -> Vec<RuleMatch> {
        let matched = self.evaluate_rules(data, matches);
        let mut out = Vec::new();
        for (i, r) in self.rules.iter().enumerate() {
            if !matched[i] || r.private {
                continue;
            }
            out.push(self.rule_match(r, data, matches));
        }
        out
    }

    /// Final match state of every rule (declaration order, private rules
    /// included, global-rule namespace filtering applied).
    pub fn evaluate_rules(&self, data: &[u8], matches: &[Vec<Match>]) -> Vec<bool> {
        let n = self.rules.len();
        let mut rule_matched = vec![false; n];
        let mut ns_unsatisfied = vec![false; self.namespaces.len()];
        let mut entry_point = None;
        let mut mem = [0i64; MEM_SIZE];
        SCRATCH.with(|cell| {
            // Reuse the per-thread VM buffers (a fresh set if somehow re-entered).
            let mut fresh = Scratch::default();
            let mut guard = cell.try_borrow_mut();
            let scratch = match guard.as_deref_mut() {
                Ok(s) => s,
                Err(_) => &mut fresh,
            };
            for (i, r) in self.rules.iter().enumerate() {
                // libyara's required_eval shortcut: such a rule is false (not
                // evaluated) unless one of its strings matched.
                if r.required
                    && !(r.strings.0..r.strings.1).any(|g| matches.get(g as usize).is_some_and(|v| !v.is_empty()))
                {
                    if let (true, Some(u)) = (r.global, ns_unsatisfied.get_mut(r.ns as usize)) {
                        *u = true;
                    }
                    continue;
                }
                let v = {
                    let mut ctx = Ctx { data, matches, rule_matched: &rule_matched, entry_point: &mut entry_point };
                    self.prog.run(r.code.0 as usize, r.code.1 as usize, &mut ctx, scratch, &mut mem)
                };
                if !eval::is_undef(v) && v != 0 {
                    rule_matched[i] = true;
                } else if let (true, Some(u)) = (r.global, ns_unsatisfied.get_mut(r.ns as usize)) {
                    *u = true;
                }
            }
        });
        for (i, r) in self.rules.iter().enumerate() {
            if ns_unsatisfied.get(r.ns as usize).copied().unwrap_or(false) {
                rule_matched[i] = false;
            }
        }
        rule_matched
    }

    fn rule_match(&self, r: &parser::CRule, data: &[u8], matches: &[Vec<Match>]) -> RuleMatch {
        let mut strings = Vec::new();
        for g in r.strings.0..r.strings.1 {
            let g = g as usize;
            let ms = match matches.get(g) {
                Some(v) if !v.is_empty() => v,
                _ => continue,
            };
            let private = self.strings.get(g).is_some_and(|s| s.private);
            let instances = if private {
                Vec::new()
            } else {
                ms.iter()
                    .map(|m| {
                        let start = m.offset.min(data.len());
                        let end = start.saturating_add(m.len.min(MAX_MATCH_DATA)).min(data.len());
                        Instance {
                            offset: m.offset,
                            matched_data: data[start..end].to_vec(),
                            matched_length: m.len,
                            xor_key: m.xor_key,
                        }
                    })
                    .collect()
            };
            let identifier = self.defs.get(g).map(|d| d.id.clone()).unwrap_or_default();
            strings.push(StringMatch { identifier, instances });
        }
        RuleMatch {
            rule: r.name.clone(),
            namespace: self.namespaces.get(r.ns as usize).cloned().unwrap_or_default(),
            tags: r.tags.clone(),
            meta: r.meta.clone(),
            strings,
        }
    }
}
