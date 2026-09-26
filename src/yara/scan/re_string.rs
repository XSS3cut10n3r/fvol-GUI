//! Hex strings and regular-expression strings (libyara RE semantics).
//! Owner: regex owner. Used by [`super::Matcher`].
//!
//! Protocol: the matcher feeds every atom of every `ReString` into its multi-pattern
//! search and, scanning positions in increasing order, calls
//! `verify(state, data, k, pos, out)` for each hit of atom `k` starting at `pos`
//! (libyara order: hits ordered by atom END position, longer atoms first on ties,
//! identical atoms of one string in DESCENDING atom index; zero-length atoms — empty
//! `bytes` — are "hits" at every position 0..len, after the other hits ending at
//! that position). `verify` appends zero or more matches; the
//! matcher inserts them into the string's list: one match per offset, and when the
//! offset already exists the new match replaces the old one only if `greedy()`.
//! `state` (from `new_state`) carries per-scan data (chained strings); create /
//! `reset` it for every scanned buffer.

use super::{Match, Modifiers};
use crate::yara::yre::ast::{self, Ast};
use crate::yara::yre::atoms::{self, ChosenAtom};
use crate::yara::yre::emit::{self, Compiled};
use crate::yara::yre::exec::{self, Machine};

/// One literal atom to search for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomSpec {
    /// Exact bytes to find (case / wide / wildcard variants already expanded). Empty =
    /// "no usable atom": verify at every offset.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
enum PartKind {
    Literal(Vec<u8>),
    Re { code: Box<Compiled>, fast: bool },
}

#[derive(Clone, Debug)]
struct Part {
    kind: PartKind,
    atoms: Vec<ChosenAtom>,
    /// Gap from the previous part (chained strings).
    gap_min: i64,
    gap_max: i64,
    /// Literal fits entirely in its atom (STRING_FLAGS_FITS_IN_ATOM).
    fits_in_atom: bool,
}

#[derive(Clone, Debug)]
pub struct ReString {
    parts: Vec<Part>,
    atoms: Vec<AtomSpec>,
    /// atom index -> (part, index within part)
    atom_map: Vec<(u32, u32)>,
    greedy: bool,
    ascii: bool,
    wide: bool,
    nocase: bool,
    dotall: bool,
    fullword: bool,
    fixed_offset: Option<i64>,
}

#[derive(Clone, Copy, Debug)]
struct UMatch {
    offset: usize,
    len: usize,
    chain_length: u32,
}

/// Per-scan mutable state.
pub struct ReState {
    machine: Machine,
    unconfirmed: Vec<Vec<UMatch>>,
    tmp: Vec<(usize, usize, bool)>,
}

impl ReState {
    pub fn reset(&mut self) {
        for u in &mut self.unconfirmed {
            u.clear();
        }
    }
}

const MAX_UNCONFIRMED: usize = 1_000_000;

fn yr_isalnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

impl ReString {
    /// Compile a hex string (`{ ... }` source).
    pub fn new_hex(src: &str, mods: &Modifiers, fixed_offset: Option<i64>) -> Result<ReString, String> {
        let ast = ast::parse_hex(src.as_bytes()).map_err(|e| format!("invalid hex string: {e}"))?;
        // Hex strings: no wide / nocase; always dot-all; ascii.
        Self::build(ast, true, false, false, true, false, mods.private, fixed_offset)
    }

    /// Compile a regex string (source between slashes, `/i`, `/s` flags).
    pub fn new_regex(
        src: &[u8],
        nocase: bool,
        dotall: bool,
        mods: &Modifiers,
        fixed_offset: Option<i64>,
    ) -> Result<ReString, String> {
        let ast = ast::parse_regex(src).map_err(|e| format!("invalid regular expression: {e}"))?;
        if ast.greedy && ast.ungreedy {
            return Err("greedy and ungreedy quantifiers can't be mixed in a regular expression".into());
        }
        let ascii = mods.ascii || !mods.wide;
        Self::build(ast, ascii, mods.wide, nocase || mods.nocase, dotall, mods.fullword, mods.private, fixed_offset)
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        ast: Ast,
        ascii: bool,
        wide: bool,
        nocase: bool,
        dotall: bool,
        fullword: bool,
        _private: bool,
        fixed_offset: Option<i64>,
    ) -> Result<ReString, String> {
        let greedy = ast.greedy;
        // Split into chained parts.
        let mut asts = Vec::new();
        let mut gaps = vec![(0i64, 0i64)];
        let mut cur = ast;
        while let Some((rest, gmin, gmax)) = ast::split_at_chaining_point(&mut cur) {
            asts.push(cur);
            gaps.push((gmin as i64, gmax as i64));
            cur = rest;
        }
        asts.push(cur);
        let chained = asts.len() > 1;
        let mut parts = Vec::with_capacity(asts.len());
        for (i, a) in asts.iter().enumerate() {
            let (gap_min, gap_max) = gaps[i];
            if let Some(lit) = ast::extract_literal(a) {
                let atoms = atoms::from_literal(&lit, wide, ascii, nocase);
                let max_len = if wide { lit.len() * 2 } else { lit.len() };
                parts.push(Part {
                    kind: PartKind::Literal(lit),
                    atoms,
                    gap_min,
                    gap_max,
                    fits_in_atom: max_len <= atoms::MAX_ATOM_LENGTH,
                });
            } else {
                let code = emit::compile(a).map_err(|e| format!("invalid regular expression: {e}"))?;
                let mut atoms = atoms::from_re(a, wide, ascii, nocase);
                if atoms.is_empty() {
                    atoms.push(ChosenAtom { atom: atoms::Atom::default(), node: None, backtrack: 0 });
                }
                parts.push(Part { kind: PartKind::Re { code: Box::new(code), fast: a.fast }, atoms, gap_min, gap_max, fits_in_atom: false });
            }
        }
        // Flatten atoms (dedupe identical byte strings within a part).
        let mut specs = Vec::new();
        let mut map = Vec::new();
        for (pi, p) in parts.iter().enumerate() {
            let mut seen: Vec<(Vec<u8>, usize, Option<u32>)> = Vec::new();
            for (ai, a) in p.atoms.iter().enumerate() {
                let bytes = a.atom.bytes[..a.atom.len].to_vec();
                if seen.iter().any(|(b, bt, nd)| *b == bytes && *bt == a.backtrack && *nd == a.node) {
                    continue;
                }
                seen.push((bytes.clone(), a.backtrack, a.node));
                specs.push(AtomSpec { bytes });
                map.push((pi as u32, ai as u32));
            }
        }
        // FIXED_OFFSET survives only when the (head) part is a literal: libyara clears it
        // for non-literal parts and for every non-head chain part, and `$x at N`
        // refers to the head fragment.
        let fixed = if matches!(parts.first().map(|p| &p.kind), Some(PartKind::Literal(_))) { fixed_offset } else { None };
        Ok(ReString {
            parts,
            atoms: specs,
            atom_map: map,
            greedy: greedy && !chained,
            ascii,
            wide,
            nocase,
            dotall,
            fullword,
            fixed_offset: fixed,
        })
    }

    pub fn atoms(&self) -> &[AtomSpec] {
        &self.atoms
    }

    /// Later matches at an existing offset replace the earlier one.
    pub fn greedy(&self) -> bool {
        self.greedy
    }

    pub fn new_state(&self) -> ReState {
        ReState { machine: Machine::new(), unconfirmed: vec![Vec::new(); self.parts.len()], tmp: Vec::new() }
    }

    /// Atom `atom` was found at `pos`: append matches.
    pub fn verify(&self, st: &mut ReState, data: &[u8], atom: usize, pos: usize, out: &mut Vec<Match>) {
        let Some(&(pi, ai)) = self.atom_map.get(atom) else { return };
        let Some(part) = self.parts.get(pi as usize) else { return };
        let Some(ca) = part.atoms.get(ai as usize) else { return };
        if pos < ca.backtrack {
            return;
        }
        let offset = pos - ca.backtrack;
        if offset >= data.len() {
            return;
        }
        if let (Some(fo), 0) = (self.fixed_offset, pi) {
            if fo != offset as i64 {
                return;
            }
        }
        st.tmp.clear();
        match &part.kind {
            PartKind::Literal(s) => {
                let fm = self.verify_literal(part, ca, s, data, offset);
                if fm == 0 {
                    return;
                }
                let wide_flag = fm == s.len() * 2 && fm != s.len();
                st.tmp.push((offset, fm, wide_flag));
            }
            PartKind::Re { code, fast } => {
                let mut flags = 0u32;
                if self.greedy {
                    flags |= exec::F_GREEDY;
                }
                if self.nocase {
                    flags |= exec::F_NOCASE;
                }
                if self.dotall {
                    flags |= exec::F_DOTALL;
                }
                let fwd_start = match ca.node {
                    Some(id) => match code.fwd_ref.get(id as usize).copied().flatten() {
                        Some(pc) => pc,
                        None => return,
                    },
                    None => 0,
                };
                let bwd_start = ca.node.and_then(|id| code.bwd_ref.get(id as usize).copied().flatten());
                let mut noop = |_: usize, _: usize| {};
                // libyara: an ASCII pass then (independently) a WIDE pass.
                for wide_pass in [false, true] {
                    if (!wide_pass && !self.ascii) || (wide_pass && !self.wide) {
                        continue;
                    }
                    let f = if wide_pass { flags | exec::F_WIDE } else { flags };
                    let forward = run(&mut st.machine, &code.fwd, fwd_start, data, offset, f, *fast, &mut noop);
                    if forward != -1 && bwd_start.is_some() {
                        let b = bwd_start.unwrap_or(0);
                        let tmp = &mut st.tmp;
                        let mut cb = |start: usize, len: usize| tmp.push((start, len + forward as usize, wide_pass));
                        run(&mut st.machine, &code.bwd, b, data, offset, f | exec::F_BACKWARDS | exec::F_EXHAUSTIVE, *fast, &mut cb);
                    } else if forward >= 0 {
                        // (libyara passes the flags without RE_FLAGS_WIDE here)
                        st.tmp.push((offset, forward as usize, false));
                    }
                }
            }
        }
        // Match callback: fullword, chaining.
        let tmp = std::mem::take(&mut st.tmp);
        for &(moff, mlen, wflag) in &tmp {
            if self.fullword && !fullword_ok(data, moff, mlen, wflag) {
                continue;
            }
            if self.parts.len() > 1 {
                self.chained_match(st, pi as usize, moff, mlen, out);
            } else {
                out.push(Match { offset: moff, len: mlen, xor_key: 0 });
            }
        }
        st.tmp = tmp;
    }

    /// `_yr_scan_verify_literal_match` (no xor / base64 for hex & regex strings).
    fn verify_literal(&self, part: &Part, ca: &ChosenAtom, s: &[u8], data: &[u8], offset: usize) -> usize {
        let d = &data[offset..];
        if part.fits_in_atom {
            // The atom hit itself is the match; its length tells ascii from wide.
            let alen = ca.atom.len;
            return if d.len() >= alen { alen } else { 0 };
        }
        let cmp = |wide: bool, nocase: bool| -> usize {
            let n = s.len();
            if wide {
                if d.len() < n * 2 {
                    return 0;
                }
                for i in 0..n {
                    let a = d[i * 2];
                    let ok = if nocase { a.to_ascii_lowercase() == s[i].to_ascii_lowercase() } else { a == s[i] };
                    if !ok || d[i * 2 + 1] != 0 {
                        return 0;
                    }
                }
                n * 2
            } else {
                if d.len() < n {
                    return 0;
                }
                let ok = if nocase { d[..n].eq_ignore_ascii_case(s) } else { &d[..n] == s };
                if ok { n } else { 0 }
            }
        };
        let mut fm = 0;
        if self.ascii {
            fm = cmp(false, self.nocase);
        }
        if self.wide && fm == 0 {
            fm = cmp(true, self.nocase);
        }
        fm
    }

    /// `_yr_scan_verify_chained_string_match`.
    fn chained_match(&self, st: &mut ReState, p: usize, offset: usize, len: usize, out: &mut Vec<Match>) {
        let part = &self.parts[p];
        let add = if p == 0 {
            true
        } else {
            let lowest = st.unconfirmed[p].first().map_or(offset, |m| m.offset) as i64;
            let prev = &mut st.unconfirmed[p - 1];
            let mut add = false;
            let mut i = 0;
            while i < prev.len() {
                let m = prev[i];
                let ending = (m.offset + m.len) as i64;
                if ending + part.gap_max < lowest {
                    prev.remove(i);
                    continue;
                } else if ending + part.gap_max >= offset as i64 && ending + part.gap_min <= offset as i64 {
                    add = true;
                    break;
                }
                i += 1;
            }
            add
        };
        if !add {
            return;
        }
        if p + 1 == self.parts.len() {
            // Tail: update chain lengths back to the head.
            let n_prev = st.unconfirmed[p - 1].len();
            for i in 0..n_prev {
                let m = st.unconfirmed[p - 1][i];
                let ending = (m.offset + m.len) as i64;
                if ending + part.gap_max >= offset as i64 && ending + part.gap_min <= offset as i64 {
                    self.update_chain_length(st, p - 1, i, 1, 0);
                }
            }
            let full = (self.parts.len() - 1) as u32;
            let head = &mut st.unconfirmed[0];
            let mut i = 0;
            while i < head.len() {
                if head[i].chain_length == full {
                    let m = head.remove(i);
                    let total = offset + len - m.offset;
                    out.push(Match { offset: m.offset, len: total, xor_key: 0 });
                    continue;
                }
                i += 1;
            }
        } else {
            let list = &mut st.unconfirmed[p];
            if list.len() >= MAX_UNCONFIRMED {
                return;
            }
            // _yr_scan_add_match_to_list(replace_if_exists = false): sorted, unique.
            let mut at = list.len();
            while at > 0 {
                let o = list[at - 1].offset;
                if o == offset {
                    return;
                }
                if offset > o {
                    break;
                }
                at -= 1;
            }
            list.insert(at, UMatch { offset, len, chain_length: 0 });
        }
    }

    fn update_chain_length(&self, st: &mut ReState, p: usize, idx: usize, cl: u32, depth: usize) {
        if depth > 10_000 {
            return;
        }
        let Some(m) = st.unconfirmed[p].get_mut(idx) else { return };
        if m.chain_length == cl {
            return;
        }
        m.chain_length = cl;
        let moff = m.offset as i64;
        if p == 0 {
            return;
        }
        let part = &self.parts[p];
        let n_prev = st.unconfirmed[p - 1].len();
        for i in 0..n_prev {
            let mm = st.unconfirmed[p - 1][i];
            let ending = (mm.offset + mm.len) as i64;
            if ending + part.gap_max >= moff && ending + part.gap_min <= moff {
                self.update_chain_length(st, p - 1, i, cl + 1, depth + 1);
            }
        }
    }
}

/// Reference scan of a single `ReString` (naive atom search + libyara hit order +
/// match-list insertion rules). Used by tests and as an executable specification
/// of the protocol the fast matcher implements.
pub fn scan_reference(rs: &ReString, data: &[u8]) -> Vec<Match> {
    let mut st = rs.new_state();
    // (end, atom_len, atom index, start)
    let mut hits: Vec<(usize, usize, usize, usize)> = Vec::new();
    for (k, a) in rs.atoms().iter().enumerate() {
        let l = a.bytes.len();
        if l == 0 {
            for p in 0..data.len() {
                hits.push((p, 0, k, p));
            }
            continue;
        }
        if data.len() < l {
            continue;
        }
        for p in 0..=data.len() - l {
            if data[p..p + l] == a.bytes[..] {
                hits.push((p + l, l, k, p));
            }
        }
    }
    // libyara order: by end position; longer atoms first; identical atoms in reverse
    // insertion order (AC match lists are built by prepending).
    hits.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)).then(b.2.cmp(&a.2)));
    let mut list: Vec<Match> = Vec::new();
    let mut out = Vec::new();
    for (_, _, k, p) in hits {
        out.clear();
        rs.verify(&mut st, data, k, p, &mut out);
        for m in out.drain(..) {
            match list.binary_search_by(|x| x.offset.cmp(&m.offset)) {
                Ok(i) => {
                    if rs.greedy() {
                        list[i] = m;
                    }
                }
                Err(i) => {
                    if list.len() < super::MAX_STRING_MATCHES {
                        list.insert(i, m);
                    }
                }
            }
        }
    }
    list
}

#[allow(clippy::too_many_arguments)]
fn run(
    m: &mut Machine,
    prog: &emit::Program,
    start: u32,
    data: &[u8],
    pos: usize,
    flags: u32,
    fast: bool,
    cb: &mut dyn FnMut(usize, usize),
) -> i64 {
    if fast && flags & exec::F_WIDE == 0 {
        m.fast_exec(prog, start, data, pos, flags, cb)
    } else {
        m.exec(prog, start, data, pos, flags, cb).unwrap_or(-1)
    }
}

/// Fullword check of `_yr_scan_match_callback`.
fn fullword_ok(data: &[u8], off: usize, len: usize, wide: bool) -> bool {
    let n = data.len();
    if wide {
        if off >= 2 && data[off - 1] == 0 && yr_isalnum(data[off - 2]) {
            return false;
        }
        if off + len + 1 < n && data[off + len + 1] == 0 && yr_isalnum(data[off + len]) {
            return false;
        }
    } else {
        if off >= 1 && yr_isalnum(data[off - 1]) {
            return false;
        }
        if off + len < n && yr_isalnum(data[off + len]) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yara_re_string_chained_fixed_head() {
        // libyara keeps FIXED_OFFSET on a literal head of a chained hex string.
        let mut data = b"xxxxaxxAABA".to_vec();
        data.extend(std::iter::repeat_n(b'x', 40));
        data.extend(b"AxBBA");
        let m = Modifiers::default();
        let rs = ReString::new_hex("{ 61 [1-] (41|42) (41|42) 41 }", &m, Some(4)).unwrap();
        let got: Vec<(usize, usize)> = scan_reference(&rs, &data).iter().map(|x| (x.offset, x.len)).collect();
        assert_eq!(got, vec![(4, 7)]);
        let rs = ReString::new_hex("{ 61 [1-] (41|42) (41|42) 41 }", &m, Some(5)).unwrap();
        assert!(scan_reference(&rs, &data).is_empty());
    }

    #[test]
    fn yara_re_string_fast_exec_list_order() {
        // libyara's fast-exec position list is not sorted: first-in-list wins (len 11).
        let data = b"\xf2 bB\x00\x02 \x00ckx9x\x00AaA\x00aAa aA\x00\xde\x009\xefa\xe8\x00b sI@c\x00a\xed\x00bcA\x06";
        let rs = ReString::new_hex("{ 41 [0-2] [2-4] 41 [2-4] 00 }", &Modifiers::default(), None).unwrap();
        let got: Vec<(usize, usize)> = scan_reference(&rs, data).iter().map(|x| (x.offset, x.len)).collect();
        assert_eq!(got, vec![(14, 11), (16, 11), (19, 8)]);
    }
}
