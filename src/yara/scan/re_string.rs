//! Hex strings and regular-expression strings (libyara RE semantics).
//! Owner: regex owner. Used by [`super::Matcher`].
//!
//! Protocol: the matcher feeds every atom of every `ReString` into its multi-pattern
//! search; when atom `k` is found starting at data offset `pos`, it calls
//! `verify(data, k, pos, out)`, which appends zero or more matches (a single atom hit
//! can yield several start offsets because yara matches the part before the atom
//! backwards exhaustively). The matcher then inserts them into the string's match
//! list: one match per offset; if an offset already exists the new match replaces it
//! only when `greedy()` is true (STRING_FLAGS_GREEDY_REGEXP).
//! An atom with empty `bytes` means "no usable atom": verify at every offset.

use super::Modifiers;

/// One literal atom to search for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomSpec {
    /// Exact bytes to find (case / wide variants are already expanded into separate
    /// atoms). May be empty (see module docs).
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ReString {
    atoms: Vec<AtomSpec>,
    greedy: bool,
}

impl ReString {
    /// Compile a hex string (`{ ... }` source).
    pub fn new_hex(src: &str, mods: &Modifiers) -> Result<ReString, String> {
        let _ = (src, mods);
        Err("hex strings not implemented yet".into())
    }

    /// Compile a regex string (source between slashes, `/i`, `/s` flags).
    pub fn new_regex(src: &[u8], nocase: bool, dotall: bool, mods: &Modifiers) -> Result<ReString, String> {
        let _ = (src, nocase, dotall, mods);
        Err("regex strings not implemented yet".into())
    }

    pub fn atoms(&self) -> &[AtomSpec] {
        &self.atoms
    }

    /// Later matches at an existing offset replace the earlier one.
    pub fn greedy(&self) -> bool {
        self.greedy
    }

    /// Atom `atom` was found at `pos`: append matches (offset, len, xor_key=0).
    pub fn verify(&self, data: &[u8], atom: usize, pos: usize, out: &mut Vec<super::Match>) {
        let _ = (data, atom, pos, out);
    }
}
