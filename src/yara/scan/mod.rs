//! YARA string matching engine: finds every match of every string declared in a
//! rule set, with libyara 4.5 semantics (what yara-python reports).
//!
//! Ownership: `scan/mod.rs`, `scan/literal.rs` and `yara/aho.rs` belong to the
//! strings/Aho-Corasick owner; `scan/re_string.rs` (hex + regex strings) belongs to
//! the regex owner. The rule front-end (`yara/rules`) only uses [`Matcher`].
//!
//! Semantics summary (libyara):
//! * every string reports ALL matching offsets (overlapping), one match per offset,
//!   sorted by offset; at most 1_000_000 matches per string (later ones dropped);
//! * text strings: `ascii` (default), `wide` (UTF-16LE-ish interleaved zeros),
//!   `nocase` (ASCII), `fullword`, `xor[(a[-b])]`, `base64[(alphabet)]`,
//!   `base64wide`, `private`;
//! * hex / regex strings go through [`re_string::ReString`].

pub mod hashf;
pub mod literal;
mod matcher;
pub mod re_string;
pub mod teddy;

#[cfg(test)]
mod bench;
#[cfg(test)]
mod tests;

pub use matcher::{Matcher, Scratch};

/// A string declaration as parsed from rule source.
#[derive(Clone, Debug)]
pub struct StringDef {
    /// Identifier including the `$` (`"$a"`, anonymous strings are `"$"`).
    pub id: String,
    pub kind: StringKind,
    pub mods: Modifiers,
    /// libyara STRING_FLAGS_FIXED_OFFSET: `Some(off)` when every reference to this
    /// string in the rule's condition is `$x at <constant off>` (see parser.c
    /// yr_parser_emit_pushes_for_strings / yr_parser_reduce_string_identifier;
    /// anonymous `$` inside for-of loops affects all strings of the rule; strings
    /// that are unreferenced keep None). The matcher then reports matches of this
    /// string ONLY at that offset. libyara clears it for non-literal hex/regex
    /// strings (a hex/regex string whose AST is a plain literal counts as literal)
    /// and for chained strings — the matcher applies those rules.
    pub fixed_offset: Option<i64>,
}

#[derive(Clone, Debug)]
pub enum StringKind {
    /// Text string with escapes already decoded (`\n \t \r \\ \" \xNN`).
    Text(Vec<u8>),
    /// Hex string source text including the braces, e.g. `{ 4D 5A ?? [2-4] (00|01) }`.
    Hex(String),
    /// Regular expression source between the slashes (as written, with `\/`
    /// already turned into `/`), plus the trailing `i` / `s` flags.
    Regex { src: Vec<u8>, nocase: bool, dotall: bool },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Modifiers {
    pub ascii: bool,
    pub wide: bool,
    pub nocase: bool,
    pub fullword: bool,
    pub private: bool,
    /// `xor` = Some((0, 255)), `xor(n)` = Some((n, n)), `xor(a-b)` = Some((a, b)).
    pub xor: Option<(u8, u8)>,
    /// `base64` = Some(None), `base64("alphabet")` = Some(Some(alphabet)).
    pub base64: Option<Option<Vec<u8>>>,
    pub base64wide: Option<Option<Vec<u8>>>,
}

/// One match of one string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Match {
    /// Offset of the first matched byte in the scanned data.
    pub offset: usize,
    /// Full match length (yara `match_length`; matched data is truncated to 512 bytes
    /// by the caller).
    pub len: usize,
    /// XOR key for `xor` strings, 0 otherwise.
    pub xor_key: u8,
}

/// Maximum matches kept per string (YR_MAX_STRING_MATCHES).
pub const MAX_STRING_MATCHES: usize = 1_000_000;
/// Maximum bytes of matched data reported per match (YR_MAX_MATCH_DATA).
pub const MAX_MATCH_DATA: usize = 512;

