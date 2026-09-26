//! Regular expressions over bytes with python `re` semantics (the behaviour volatility3
//! relies on in RegExScanner, regexscan, vadregexscan, vmaregexscan, ...).
//!
//! Pipeline: `parse` (python syntax, python errors) -> `hir` (flags resolved) ->
//! engine selection:
//! * "regular" patterns (no backrefs / lookaround / atomic / conditionals / nullable
//!   loop bodies) run on a lazy DFA (forward leftmost-first to find the end, reverse to
//!   find the start) with literal prefilters (memchr / memmem / byte sets / inner
//!   literals);
//! * everything else runs on a memoized backtracker that reproduces sre exactly and
//!   never goes exponential.
//!
//! Semantics notes: bytes patterns use ASCII classes (`\d \w \s`), IGNORECASE folds
//! ASCII letters only, `finditer` yields non-overlapping matches and allows an empty
//! match right after a non-empty one (python >= 3.7 rules).

pub mod backtrack;
pub mod dfa;
pub mod hir;
pub mod literal;
pub mod nfa;
pub mod parse;

#[cfg(test)]
mod difftest;
#[cfg(test)]
mod perftest;

use std::fmt;
use std::sync::Mutex;

pub const FLAG_IGNORECASE: u32 = 2;
pub const FLAG_LOCALE: u32 = 4;
pub const FLAG_MULTILINE: u32 = 8;
pub const FLAG_DOTALL: u32 = 16;
pub const FLAG_UNICODE: u32 = 32;
pub const FLAG_VERBOSE: u32 = 64;
pub const FLAG_ASCII: u32 = 256;

/// Python-style flag values (`re.I`, `re.M`, `re.S`, `re.X`, `re.A`, `re.L`).
pub struct Flags;
impl Flags {
    pub const I: u32 = FLAG_IGNORECASE;
    pub const L: u32 = FLAG_LOCALE;
    pub const M: u32 = FLAG_MULTILINE;
    pub const S: u32 = FLAG_DOTALL;
    pub const U: u32 = FLAG_UNICODE;
    pub const X: u32 = FLAG_VERBOSE;
    pub const A: u32 = FLAG_ASCII;
}

/// Pattern compilation error (python raises `re.error` / `OverflowError` / `ValueError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub msg: String,
    pub pos: usize,
}

impl Error {
    pub fn new(msg: impl Into<String>, pos: usize) -> Error {
        Error { msg: msg.into(), pos }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at position {}", self.msg, self.pos)
    }
}

impl std::error::Error for Error {}

impl From<Error> for crate::error::Error {
    fn from(e: Error) -> Self {
        crate::error::Error::Msg(format!("Invalid regex pattern: {e}"))
    }
}

/// Which engine answers searches.
enum Engine {
    /// Fixed-length sequence of byte sets (literals, case-insensitive / wide literals):
    /// the prefilter alone yields exact matches.
    Fixed { finder: literal::SeqFinder, seq: Vec<hir::ByteSet> },
    Dfa(Box<dfa::Searcher>),
    Backtrack,
}

/// The byte-set sequence if every match of `h` is exactly one fixed-length sequence of
/// byte sets (no assertions, no variable repeats).
fn fixed_sequence(h: &hir::Hir) -> Option<Vec<hir::ByteSet>> {
    fn walk(h: &hir::Hir, out: &mut Vec<hir::ByteSet>, depth: usize) -> bool {
        if depth > 100 || out.len() > 256 {
            return false;
        }
        match h {
            hir::Hir::Class(s) => {
                if s.is_empty() {
                    return false;
                }
                out.push(*s);
                true
            }
            hir::Hir::Concat(v) => v.iter().all(|x| walk(x, out, depth + 1)),
            hir::Hir::Capture { sub, .. } => walk(sub, out, depth + 1),
            hir::Hir::Repeat { min, max: Some(max), sub, .. } if min == max && *min <= 64 => {
                (0..*min).all(|_| walk(sub, out, depth + 1))
            }
            _ => false,
        }
    }
    let mut out = Vec::new();
    if walk(h, &mut out, 0) && !out.is_empty() { Some(out) } else { None }
}

/// A compiled regular expression (thread-safe; scratch space is pooled).
pub struct Regex {
    pattern: Box<[u8]>,
    flags: u32,
    groups: u32,
    names: Vec<(String, u32)>,
    bt: backtrack::Prog,
    engine: Engine,
    pool: Mutex<Vec<Box<Scratch>>>,
}

struct Scratch {
    bt: backtrack::Cache,
    dfa: Option<dfa::Cache>,
}

impl fmt::Debug for Regex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Regex({:?}, flags={})", String::from_utf8_lossy(&self.pattern), self.flags)
    }
}

impl Regex {
    /// Compile a bytes pattern with python flag bits (`re.compile(pattern, flags)`).
    pub fn new(pattern: &[u8], flags: u32) -> Result<Regex, Error> {
        let parsed = parse::parse(pattern, flags)?;
        let lowered = hir::lower(parsed)?;
        let props = hir::props(&lowered.hir, &lowered.group_widths);
        let mut bt = backtrack::Prog::new(&lowered.hir, lowered.groups, &lowered.group_widths)?;
        if lowered.hir.min_width(&lowered.group_widths) > 0 {
            bt.prefilter = literal::Prefilter::for_hir(&lowered.hir).map(|p| p.0);
        }
        let fixed = fixed_sequence(&lowered.hir).and_then(|seq| literal::SeqFinder::new(&seq).map(|f| (f, seq)));
        let engine = if let Some((finder, seq)) = fixed {
            Engine::Fixed { finder, seq }
        } else if props.is_regular() && props.nfa_size < 50_000 {
            match dfa::Searcher::new(&lowered.hir) {
                Some(s) => Engine::Dfa(Box::new(s)),
                None => Engine::Backtrack,
            }
        } else {
            Engine::Backtrack
        };
        Ok(Regex {
            pattern: pattern.into(),
            flags,
            groups: lowered.groups,
            names: lowered.names,
            bt,
            engine,
            pool: Mutex::new(Vec::new()),
        })
    }

    /// Compile with python-backtracker semantics only (testing / reference).
    #[doc(hidden)]
    pub fn new_backtrack_only(pattern: &[u8], flags: u32) -> Result<Regex, Error> {
        let mut r = Regex::new(pattern, flags)?;
        r.engine = Engine::Backtrack;
        Ok(r)
    }

    pub fn pattern(&self) -> &[u8] {
        &self.pattern
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Number of capturing groups (python `groups`).
    pub fn groups(&self) -> u32 {
        self.groups.saturating_sub(1)
    }

    pub fn group_index(&self, name: &str) -> Option<u32> {
        self.names.iter().find(|(n, _)| n == name).map(|&(_, g)| g)
    }

    /// Name of the engine used (for diagnostics / benchmarks).
    pub fn engine_name(&self) -> &'static str {
        match &self.engine {
            Engine::Fixed { .. } => "literal",
            Engine::Dfa(s) => s.strategy_name(),
            Engine::Backtrack => "backtrack",
        }
    }

    fn scratch(&self) -> Box<Scratch> {
        let got = match self.pool.lock() {
            Ok(mut p) => p.pop(),
            Err(_) => None,
        };
        let mut got = got;
        if let Some(sc) = got.as_mut() {
            if let Some(c) = sc.dfa.as_mut() {
                c.reset_stats();
            }
        }
        got.unwrap_or_else(|| {
            Box::new(Scratch {
                bt: backtrack::Cache::new(),
                dfa: match &self.engine {
                    Engine::Dfa(s) => Some(s.new_cache()),
                    Engine::Backtrack | Engine::Fixed { .. } => None,
                },
            })
        })
    }

    fn put_scratch(&self, s: Box<Scratch>) {
        if let Ok(mut p) = self.pool.lock() {
            if p.len() < 64 {
                p.push(s);
            }
        }
    }

    fn find_with(&self, sc: &mut Scratch, hay: &[u8], start: usize, anchored: bool, must_advance: bool) -> Option<(usize, usize)> {
        match (&self.engine, sc.dfa.as_mut()) {
            (Engine::Fixed { finder, seq }, _) => {
                let n = seq.len();
                if anchored {
                    let ok = start + n <= hay.len() && seq.iter().zip(&hay[start..start + n]).all(|(s, &b)| s.contains(b));
                    return if ok { Some((start, start + n)) } else { None };
                }
                let p = finder.find(hay, start)?;
                Some((p, p + n))
            }
            (Engine::Dfa(s), Some(c)) => s.find(c, hay, start, anchored, must_advance),
            _ => {
                let search = backtrack::Search { prog: &self.bt, hay };
                search.find(&mut sc.bt, start, anchored, must_advance)
            }
        }
    }

    /// python `pattern.search(hay, pos)`: leftmost match at or after `pos`.
    pub fn search(&self, hay: &[u8], pos: usize) -> Option<(usize, usize)> {
        let mut sc = self.scratch();
        let r = self.find_with(&mut sc, hay, pos.min(hay.len()), false, false);
        self.put_scratch(sc);
        r
    }

    /// Alias of `search(hay, pos)`.
    pub fn find_at(&self, hay: &[u8], pos: usize) -> Option<(usize, usize)> {
        self.search(hay, pos)
    }

    /// python `pattern.match(hay, pos)`: match anchored at `pos`.
    pub fn match_at(&self, hay: &[u8], pos: usize) -> Option<(usize, usize)> {
        let mut sc = self.scratch();
        let r = self.find_with(&mut sc, hay, pos.min(hay.len()), true, false);
        self.put_scratch(sc);
        r
    }

    pub fn is_match(&self, hay: &[u8]) -> bool {
        self.search(hay, 0).is_some()
    }

    /// python `re.finditer`: non-overlapping (start, end) spans.
    pub fn find_iter<'r, 'h>(&'r self, hay: &'h [u8]) -> FindIter<'r, 'h> {
        FindIter { re: self, hay, pos: 0, must_advance: false, done: false, scratch: Some(self.scratch()) }
    }

    /// Group spans of the match at `start` (python `m.span(i)` for every group; None
    /// for groups that did not participate). Group 0 is the whole match.
    pub fn captures_at(&self, hay: &[u8], pos: usize) -> Option<Vec<Option<(usize, usize)>>> {
        let (s, _) = self.search(hay, pos)?;
        let mut sc = self.scratch();
        let search = backtrack::Search { prog: &self.bt, hay };
        let r = search.find(&mut sc.bt, s, true, false).map(|_| {
            let slots = search.slots(&sc.bt);
            (0..self.groups as usize)
                .map(|g| {
                    let a = slots.get(2 * g).copied().unwrap_or(backtrack::SLOT_NONE);
                    let b = slots.get(2 * g + 1).copied().unwrap_or(backtrack::SLOT_NONE);
                    if a == backtrack::SLOT_NONE || b == backtrack::SLOT_NONE { None } else { Some((a, b)) }
                })
                .collect()
        });
        self.put_scratch(sc);
        r
    }
}

/// Iterator returned by [`Regex::find_iter`].
pub struct FindIter<'r, 'h> {
    re: &'r Regex,
    hay: &'h [u8],
    pos: usize,
    must_advance: bool,
    done: bool,
    scratch: Option<Box<Scratch>>,
}

impl Iterator for FindIter<'_, '_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<(usize, usize)> {
        if self.done {
            return None;
        }
        let sc = self.scratch.as_mut()?;
        match self.re.find_with(sc, self.hay, self.pos, false, self.must_advance) {
            Some((s, e)) if s < self.pos || e < s || (self.must_advance && e == self.pos) => {
                // Defensive: an engine must never go backwards or repeat an empty
                // match; stop rather than loop forever.
                self.done = true;
                None
            }
            Some((s, e)) => {
                self.must_advance = e == s;
                self.pos = e;
                Some((s, e))
            }
            None => {
                self.done = true;
                None
            }
        }
    }
}

impl Drop for FindIter<'_, '_> {
    fn drop(&mut self) {
        if let Some(s) = self.scratch.take() {
            self.re.put_scratch(s);
        }
    }
}

/// python `re.escape` for bytes.
pub fn escape(pattern: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pattern.len() * 2);
    for &b in pattern {
        // python 3.7+: escape only special characters
        if b"()[]{}?*+-|^$\\.&~# \t\n\r\x0b\x0c".contains(&b) {
            out.push(b'\\');
        }
        out.push(b);
    }
    out
}
