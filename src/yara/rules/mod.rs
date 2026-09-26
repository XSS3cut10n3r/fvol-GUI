//! YARA rule language: lexer, parser, condition evaluator and the public scanning
//! API, mirroring what yara-python 4.5 (`yara.compile(...)`, `rules.match(data=...)`)
//! returns and how volatility3's `YaraScanner` consumes it.
//! Owner: rules front-end owner. String matching is delegated to
//! [`crate::yara::scan::Matcher`].

use std::fmt;

/// Compilation error (yara raises `yara.SyntaxError`).
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

/// Metadata value (`meta:` section).
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
    pub meta: Vec<(String, MetaValue)>,
    pub strings: Vec<StringMatch>,
}

/// Compiled rule set.
pub struct Rules {
    _private: (),
}

impl Rules {
    /// `yara.compile(source=src)` (namespace "default").
    pub fn compile(source: &str) -> Result<Rules, CompileError> {
        Self::compile_namespaced(&[("default", source)])
    }

    /// `yara.compile(sources={ns: src, ...})`.
    pub fn compile_namespaced(sources: &[(&str, &str)]) -> Result<Rules, CompileError> {
        let _ = sources;
        Err(CompileError { msg: "yara rules not implemented yet".into(), line: 0 })
    }

    /// `rules.match(data=data)`.
    pub fn scan(&self, data: &[u8]) -> Vec<RuleMatch> {
        let _ = data;
        Vec::new()
    }
}
