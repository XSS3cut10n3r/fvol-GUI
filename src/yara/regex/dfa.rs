//! Lazy DFA with leftmost-first (python / backtracking priority) semantics.
//!
//! A DFA state is an ordered set of NFA states ("core", before epsilon closure) plus
//! a few flags: the context of the byte *behind* the scan position (edge / newline /
//! word char / final newline — only the bits the pattern's assertions need), whether
//! new threads are still started at every position (unanchored search before the
//! first match), and whether a match ended at the boundary just before the byte that
//! led here (matches are reported one byte late, like RE2 / rust-regex). Transitions
//! are computed on demand and cached in a flat `u32` table indexed by
//! `state_id * stride + byte_class`; state ids carry tag bits so the hot loop needs a
//! single compare per byte.
//!
//! Search = forward unanchored DFA (finds the end of the leftmost-first match) + a
//! reverse anchored DFA (finds its start), optionally accelerated by a SIMD prefilter
//! on the required leading byte sequence, or an "inner literal" strategy (find a
//! required inner sequence, reverse-scan its prefix, forward-verify).

use super::hir::{is_word_byte, ByteSet, Hir, Look};
use super::literal::{self, Prefilter, SeqFinder};
use super::nfa::{NState, Nfa};
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

const TAG_START: u32 = 1 << 29;
const TAG_DEAD: u32 = 1 << 30;
const TAG_MATCH: u32 = 1 << 31;
const UNKNOWN: u32 = u32::MAX;
const ID_MASK: u32 = TAG_START - 1;

const CTX_NONE: u8 = 1;
const CTX_NL: u8 = 2;
const CTX_WORD: u8 = 4;
const CTX_FINAL_NL: u8 = 8;
const CTX_MASK: u8 = 15;
const F_RESTART: u8 = 16;
const F_SKIP_MATCH: u8 = 32;
const F_MATCH: u8 = 64;

/// Cache memory budget per direction before it is flushed.
const CACHE_LIMIT: usize = 16 << 20;

#[derive(Default)]
struct FxHasher(u64);
impl Hasher for FxHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0.rotate_left(5) ^ b as u64).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
        }
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.0 = (self.0.rotate_left(5) ^ i as u64).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.write_u32(i as u32)
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.0 = (self.0.rotate_left(5) ^ i as u64).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
}
type FxBuild = BuildHasherDefault<FxHasher>;

#[inline]
fn look_ok(l: Look, left: u8, right: u8) -> bool {
    match l {
        Look::Start => left & CTX_NONE != 0,
        Look::StartLine => left & (CTX_NONE | CTX_NL) != 0,
        Look::End => right & CTX_NONE != 0,
        Look::EndLine => right & (CTX_NONE | CTX_NL) != 0,
        Look::EndOrFinalNl => right & (CTX_NONE | CTX_FINAL_NL) != 0,
        Look::WordB | Look::WordBUni => (left & CTX_WORD != 0) != (right & CTX_WORD != 0),
        Look::NotWordB | Look::NotWordBUni => (left & CTX_WORD != 0) == (right & CTX_WORD != 0),
    }
}

/// One search direction (NFA + configuration).
struct Dir {
    nfa: Nfa,
    reverse: bool,
    /// Context bits of the "behind" byte kept in the state.
    behind_mask: u8,
    leftmost_first: bool,
    start_tag: bool,
}

impl Dir {
    fn new(nfa: Nfa, reverse: bool, leftmost_first: bool, start_tag: bool) -> Dir {
        let mut behind_mask = 0u8;
        for &l in &nfa.looks {
            match (l, reverse) {
                (Look::Start, false) => behind_mask |= CTX_NONE,
                (Look::StartLine, false) => behind_mask |= CTX_NONE | CTX_NL,
                (Look::End, true) => behind_mask |= CTX_NONE,
                (Look::EndLine, true) => behind_mask |= CTX_NONE | CTX_NL,
                (Look::EndOrFinalNl, true) => behind_mask |= CTX_NONE | CTX_FINAL_NL,
                (Look::WordB | Look::NotWordB | Look::WordBUni | Look::NotWordBUni, _) => behind_mask |= CTX_WORD,
                _ => {}
            }
        }
        Dir { nfa, reverse, behind_mask, leftmost_first, start_tag }
    }
}

/// Byte classes shared by all directions of a searcher.
struct Classes {
    map: [u8; 256],
    _n: usize,
    rep: Vec<u8>,
    ctx: Vec<u8>,
    stride: usize,
    eoi: usize,
    /// Class used for a '\n' that is the last byte of the haystack (python `$`).
    final_nl: Option<usize>,
}

impl Classes {
    fn new(nfas: &[&Nfa]) -> Classes {
        let mut boundary = [false; 257];
        let mut mark = |s: &ByteSet| {
            let mut b = 0usize;
            while b < 256 {
                if s.contains(b as u8) {
                    let mut e = b;
                    while e + 1 < 256 && s.contains((e + 1) as u8) {
                        e += 1;
                    }
                    boundary[b] = true;
                    boundary[e + 1] = true;
                    b = e + 1;
                } else {
                    b += 1;
                }
            }
        };
        let mut has_look = false;
        let mut has_final = false;
        for nfa in nfas {
            for st in &nfa.states {
                if let NState::Consume { set, .. } = st {
                    mark(set);
                }
            }
            has_look |= !nfa.looks.is_empty();
            has_final |= nfa.looks.contains(&Look::EndOrFinalNl);
        }
        if has_look {
            mark(&ByteSet::single(b'\n'));
            let mut w = ByteSet::EMPTY;
            for b in 0..=255u8 {
                if is_word_byte(b) {
                    w.insert(b);
                }
            }
            mark(&w);
        }
        let mut map = [0u8; 256];
        let mut rep = Vec::new();
        let mut cls: usize = 0;
        for b in 0..256usize {
            if b > 0 && boundary[b] {
                cls += 1;
            }
            map[b] = cls as u8;
            if rep.len() == cls {
                rep.push(b as u8);
            }
        }
        let n = cls + 1;
        let mut ctx: Vec<u8> = rep
            .iter()
            .map(|&b| {
                let mut c = 0;
                if b == b'\n' {
                    c |= CTX_NL;
                }
                if is_word_byte(b) {
                    c |= CTX_WORD;
                }
                c
            })
            .collect();
        ctx.push(CTX_NONE); // eoi
        let final_nl = if has_final {
            ctx.push(CTX_NL | CTX_FINAL_NL);
            rep.push(b'\n');
            Some(n + 1)
        } else {
            None
        };
        rep.insert(n, 0); // eoi placeholder rep (never consumed)
        let stride = n + if has_final { 2 } else { 1 };
        Classes { map, _n: n, rep, ctx, stride, eoi: n, final_nl }
    }

    #[inline]
    fn byte_ctx(&self, b: u8) -> u8 {
        self.ctx[self.map[b as usize] as usize]
    }
}

/// Per-direction lazily built transition table.
struct DCache {
    trans: Vec<u32>,
    /// Per state: (core offset, core len, flags).
    info: Vec<(u32, u32, u8)>,
    cores: Vec<u32>,
    map: HashMap<(Vec<u32>, u8), u32, FxBuild>,
    starts: Vec<u32>,
    stack: Vec<u32>,
    seen: Vec<u32>,
    seen_gen: u32,
    closure: Vec<u32>,
    core_buf: Vec<u32>,
    next_buf: Vec<u32>,
    clears: usize,
}

impl DCache {
    fn new(nfa_len: usize) -> DCache {
        DCache {
            trans: Vec::new(),
            info: Vec::new(),
            cores: Vec::new(),
            map: HashMap::default(),
            starts: vec![UNKNOWN; 128],
            stack: Vec::new(),
            seen: vec![0; nfa_len],
            seen_gen: 1,
            closure: Vec::new(),
            core_buf: Vec::new(),
            next_buf: Vec::new(),
            clears: 0,
        }
    }

    fn mem(&self) -> usize {
        self.trans.len() * 4 + self.cores.len() * 4 * 3 + self.info.len() * 12
    }

    fn clear(&mut self) {
        self.trans.clear();
        self.info.clear();
        self.cores.clear();
        self.map.clear();
        for s in self.starts.iter_mut() {
            *s = UNKNOWN;
        }
        self.clears += 1;
    }

    #[inline]
    fn next_gen(&mut self) {
        self.seen_gen = self.seen_gen.wrapping_add(1);
        if self.seen_gen == 0 {
            for s in self.seen.iter_mut() {
                *s = 0;
            }
            self.seen_gen = 1;
        }
    }
}

pub struct Cache {
    fwd: DCache,
    rev: DCache,
    pre_rev: Option<DCache>,
    /// Forward DFA without start tags (used once the prefilter proves ineffective).
    plain: DCache,
    stats: PreStats,
}

/// Prefilter effectiveness bookkeeping (per iterator).
#[derive(Default, Clone, Copy)]
pub struct PreStats {
    calls: u64,
    skipped: u64,
    off: bool,
}

impl Cache {
    /// Forget prefilter statistics (new haystack).
    pub fn reset_stats(&mut self) {
        self.stats = PreStats::default();
    }
}

enum Strategy {
    /// Plain forward DFA (+ reverse for the start), optional prefix prefilter.
    Core,
    /// Required inner sequence at top-level concat index; prefix reversed separately.
    Inner { finder: SeqFinder, pre: Dir },
}

pub struct Searcher {
    cls: Classes,
    fwd: Dir,
    /// Same NFA as `fwd`, without start-state tags.
    plain: Dir,
    rev: Dir,
    prefilter: Option<Prefilter>,
    strategy: Strategy,
    name: &'static str,
    /// Every match has this length: the start is `end - width` (no reverse scan).
    fixed_width: Option<usize>,
}

/// Top-level concatenation with captures unwrapped and repeats split into their
/// mandatory copies plus an optional remainder (`x{2,5}` -> `x x x{0,3}`), for the
/// inner-literal analysis only (same language; the searching NFAs use the original).
fn flatten_concat(h: &Hir) -> Vec<Hir> {
    fn go(h: &Hir, out: &mut Vec<Hir>, budget: &mut usize) {
        if *budget == 0 {
            out.push(h.clone());
            return;
        }
        *budget -= 1;
        match h {
            Hir::Concat(v) => v.iter().for_each(|x| go(x, out, budget)),
            Hir::Capture { sub, .. } => go(sub, out, budget),
            Hir::Repeat { min, max, greedy, sub } if *min >= 1 && *min <= 8 => {
                for _ in 0..*min {
                    go(sub, out, budget);
                }
                match max {
                    Some(m) if *m == *min => {}
                    _ => out.push(Hir::Repeat {
                        min: 0,
                        max: max.map(|m| m - *min),
                        greedy: *greedy,
                        sub: sub.clone(),
                    }),
                }
            }
            _ => out.push(h.clone()),
        }
    }
    let mut out = Vec::new();
    let mut budget = 256usize;
    go(h, &mut out, &mut budget);
    out
}

impl Searcher {
    pub fn new(h: &Hir) -> Option<Searcher> {
        let fnfa = Nfa::new(h, false)?;
        let rnfa = Nfa::new(h, true)?;
        let nullable = h.min_width(&[]) == 0;
        // Prefix prefilter.
        let mut prefilter = None;
        let mut pre_rate = u64::MAX;
        if !nullable {
            if let Some((p, rate)) = Prefilter::for_hir(h) {
                prefilter = Some(p);
                pre_rate = rate;
            }
        }
        // Inner literal strategy for top-level concatenations.
        let mut strategy = Strategy::Core;
        let mut inner_nfa = None;
        let flat = flatten_concat(h);
        if flat.len() > 1 {
            let v = &flat[..];
            let mut best: Option<(u64, usize, Vec<ByteSet>)> = None;
            for i in 1..v.len().min(12) {
                let rest = Hir::Concat(v[i..].to_vec());
                let (seq, _) = literal::positions(&rest);
                if seq.is_empty() {
                    continue;
                }
                let prefix = Hir::Concat(v[..i].to_vec());
                let pbytes = literal::bytes_of(&prefix);
                if !pbytes.intersect(&seq[0]).is_empty() {
                    continue;
                }
                let rate = literal::seq_rate(&seq);
                if best.as_ref().map_or(true, |b| rate < b.0) {
                    best = Some((rate, i, seq));
                }
            }
            if let Some((rate, i, seq)) = best {
                // Only worth it when much more selective than the prefix prefilter.
                if rate < (1 << 20) / 64 && rate.saturating_mul(8) < pre_rate {
                    let prefix = Hir::Concat(v[..i].to_vec());
                    if let (Some(f), Some(pn)) = (SeqFinder::new(&seq), Nfa::new(&prefix, true)) {
                        inner_nfa = Some(pn.clone());
                        strategy = Strategy::Inner { finder: f, pre: Dir::new(pn, true, false, false) };
                    }
                }
            }
        }
        let mut nfas: Vec<&Nfa> = vec![&fnfa, &rnfa];
        if let Some(n) = &inner_nfa {
            nfas.push(n);
        }
        let cls = Classes::new(&nfas);
        let use_start_tag = prefilter.is_some();
        let name = match (&strategy, &prefilter) {
            (Strategy::Inner { .. }, _) => "dfa+inner",
            (_, Some(_)) => "dfa+prefix",
            _ => "dfa",
        };
        Some(Searcher {
            cls,
            plain: Dir::new(fnfa.clone(), false, true, false),
            fwd: Dir::new(fnfa, false, true, use_start_tag),
            rev: Dir::new(rnfa, true, false, false),
            prefilter,
            strategy,
            name,
            fixed_width: match h.max_width() {
                Some(w) if w as u128 == h.min_width(&[]) && w > 0 => Some(w as usize),
                _ => None,
            },
        })
    }

    pub fn strategy_name(&self) -> &'static str {
        self.name
    }

    pub fn new_cache(&self) -> Cache {
        Cache {
            fwd: DCache::new(self.fwd.nfa.states.len()),
            rev: DCache::new(self.rev.nfa.states.len()),
            pre_rev: match &self.strategy {
                Strategy::Inner { pre, .. } => Some(DCache::new(pre.nfa.states.len())),
                Strategy::Core => None,
            },
            plain: DCache::new(self.plain.nfa.states.len()),
            stats: PreStats::default(),
        }
    }

    /// Leftmost-first match at or after `start` (python search / match semantics).
    pub fn find(&self, c: &mut Cache, hay: &[u8], start: usize, anchored: bool, must_advance: bool) -> Option<(usize, usize)> {
        if start > hay.len() {
            return None;
        }
        if anchored {
            let e = fwd_search(&self.cls, &self.plain, &mut c.plain, None, hay, start, true, must_advance).0?;
            return Some((start, e));
        }
        if let Strategy::Inner { finder, pre } = &self.strategy {
            if let Some(pc) = c.pre_rev.as_mut() {
                return self.find_inner(finder, pre, pc, &mut c.plain, &mut c.rev, hay, start, must_advance);
            }
        }
        let e = self.fwd_unanchored(c, hay, start, must_advance)?;
        if let Some(w) = self.fixed_width {
            if e >= start + w {
                return Some((e - w, e));
            }
        }
        let s = rev_search(&self.cls, &self.rev, &mut c.rev, hay, e, start)?;
        Some((s, e))
    }

    /// Unanchored forward search with the adaptive prefilter.
    fn fwd_unanchored(&self, c: &mut Cache, hay: &[u8], start: usize, must_advance: bool) -> Option<usize> {
        match &self.prefilter {
            Some(pf) if !c.stats.off => {
                let (e, pos, switched) =
                    fwd_search(&self.cls, &self.fwd, &mut c.fwd, Some((pf, &mut c.stats)), hay, start, false, must_advance);
                if switched {
                    fwd_search(&self.cls, &self.plain, &mut c.plain, None, hay, pos, false, false).0
                } else {
                    e
                }
            }
            _ => fwd_search(&self.cls, &self.plain, &mut c.plain, None, hay, start, false, must_advance).0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn find_inner(
        &self,
        finder: &SeqFinder,
        pre: &Dir,
        pc: &mut DCache,
        fc: &mut DCache,
        rc: &mut DCache,
        hay: &[u8],
        start: usize,
        must_advance: bool,
    ) -> Option<(usize, usize)> {
        let mut at = start;
        let mut work: usize = 0;
        loop {
            let j = finder.find(hay, at)?;
            if let Some(s) = rev_search(&self.cls, pre, pc, hay, j, start) {
                let (e, scanned, _) = fwd_search(&self.cls, &self.plain, fc, None, hay, s, true, must_advance && s == start);
                if let Some(e) = e {
                    return Some((s, e));
                }
                work += scanned.saturating_sub(j);
                if work > 2 * (j - start) + (1 << 16) {
                    // Forward verification keeps rescanning: fall back to the core DFA.
                    // Every remaining match starts after j (the prefix cannot consume
                    // the inner sequence's first byte), so resume there.
                    let from = j + 1;
                    let e = fwd_search(&self.cls, &self.plain, fc, None, hay, from, false, false).0?;
                    let s2 = rev_search(&self.cls, &self.rev, rc, hay, e, from)?;
                    return Some((s2, e));
                }
            }
            at = j + 1;
        }
    }
}

// ---------------------------------------------------------------------------------------
// State construction
// ---------------------------------------------------------------------------------------

fn tags_for(d: &Dir, core_empty: bool, flags: u8) -> u32 {
    let mut t = 0;
    if flags & F_MATCH != 0 {
        t |= TAG_MATCH;
    }
    if core_empty && flags & F_RESTART == 0 {
        t |= TAG_DEAD;
    }
    if core_empty && flags & F_RESTART != 0 && d.start_tag {
        t |= TAG_START;
    }
    t
}

/// Intern (core, flags) as a state; returns the tagged premultiplied id.
fn intern(cls: &Classes, d: &Dir, c: &mut DCache, core: Vec<u32>, flags: u8) -> (u32, Vec<u32>) {
    let key = (core, flags);
    if let Some(&id) = c.map.get(&key) {
        let tags = tags_for(d, key.0.is_empty(), flags);
        return (id | tags, key.0);
    }
    let idx = c.info.len();
    let id = (idx * cls.stride) as u32;
    c.info.push((c.cores.len() as u32, key.0.len() as u32, flags));
    c.cores.extend_from_slice(&key.0);
    c.trans.resize(c.trans.len() + cls.stride, UNKNOWN);
    let tags = tags_for(d, key.0.is_empty(), flags);
    let core = key.0.clone();
    c.map.insert(key, id);
    (id | tags, core)
}

fn start_state(cls: &Classes, d: &Dir, c: &mut DCache, behind: u8, anchored: bool, skip_match: bool) -> u32 {
    let behind = behind & d.behind_mask;
    let key = (behind as usize) | ((anchored as usize) << 4) | ((skip_match as usize) << 5);
    if let Some(&s) = c.starts.get(key) {
        if s != UNKNOWN {
            return s;
        }
    }
    if c.mem() > CACHE_LIMIT {
        c.clear();
    }
    let core = if anchored { vec![d.nfa.start] } else { Vec::new() };
    let mut flags = behind;
    if !anchored {
        flags |= F_RESTART;
    }
    if skip_match {
        flags |= F_SKIP_MATCH;
    }
    let (id, _) = intern(cls, d, c, core, flags);
    if let Some(slot) = c.starts.get_mut(key) {
        *slot = id;
    }
    id
}

/// Compute the transition from untagged state `sid` on class `class`. May flush the
/// cache (then `sid` is re-interned and updated). Returns the tagged target.
fn compute(cls: &Classes, d: &Dir, c: &mut DCache, sid: &mut u32, class: usize) -> u32 {
    if c.mem() > CACHE_LIMIT {
        // Flush, keeping the current state.
        let idx = (*sid as usize) / cls.stride;
        let (off, len, flags) = c.info[idx];
        let core = c.cores[off as usize..(off + len) as usize].to_vec();
        c.clear();
        let (nid, _) = intern(cls, d, c, core, flags);
        *sid = nid & ID_MASK;
    }
    let idx = (*sid as usize) / cls.stride;
    let (off, len, flags) = c.info[idx];
    let behind = flags & CTX_MASK;
    let ahead = cls.ctx[class];
    let (left, right) = if d.reverse { (ahead, behind) } else { (behind, ahead) };
    let restart = flags & F_RESTART != 0;
    let skip_match = flags & F_SKIP_MATCH != 0;
    let states = &d.nfa.states;

    let mut core = std::mem::take(&mut c.core_buf);
    core.clear();
    core.extend_from_slice(&c.cores[off as usize..(off + len) as usize]);
    if restart {
        core.push(d.nfa.start);
    }
    c.next_gen();
    let g1 = c.seen_gen;
    c.closure.clear();
    let mut matched = false;
    'roots: for &root in core.iter() {
        c.stack.clear();
        c.stack.push(root);
        while let Some(s) = c.stack.pop() {
            let si = s as usize;
            if si >= c.seen.len() || c.seen[si] == g1 {
                continue;
            }
            c.seen[si] = g1;
            match &states[si] {
                NState::Consume { .. } => c.closure.push(s),
                NState::Split { a, b } => {
                    c.stack.push(*b);
                    c.stack.push(*a);
                }
                NState::Look { look, next } => {
                    if look_ok(*look, left, right) {
                        c.stack.push(*next);
                    }
                }
                NState::Match => {
                    if skip_match {
                        continue;
                    }
                    matched = true;
                    if d.leftmost_first {
                        break 'roots;
                    }
                }
                NState::Fail => {}
            }
        }
    }
    // Step over the class representative.
    let mut next = std::mem::take(&mut c.next_buf);
    next.clear();
    if class != cls.eoi {
        let b = cls.rep[class];
        c.next_gen();
        let gen2 = c.seen_gen;
        for &s in &c.closure {
            if let NState::Consume { set, next: n } = &states[s as usize] {
                if set.contains(b) {
                    let ni = *n as usize;
                    if ni < c.seen.len() && c.seen[ni] != gen2 {
                        c.seen[ni] = gen2;
                        next.push(*n);
                    }
                }
            }
        }
    }
    let mut nflags = ahead & d.behind_mask;
    if restart && !(matched && d.leftmost_first) {
        nflags |= F_RESTART;
    }
    if matched {
        nflags |= F_MATCH;
    }
    c.core_buf = core;
    let (t, back) = intern(cls, d, c, next, nflags);
    c.next_buf = back;
    let slot = *sid as usize + class;
    if slot < c.trans.len() {
        c.trans[slot] = t;
    }
    t
}

#[inline(always)]
fn step(cls: &Classes, d: &Dir, c: &mut DCache, sid: &mut u32, class: usize) -> u32 {
    let t = c.trans[*sid as usize + class];
    if t != UNKNOWN { t } else { compute(cls, d, c, sid, class) }
}

// ---------------------------------------------------------------------------------------
// Searches
// ---------------------------------------------------------------------------------------

/// Forward search from `start`. Returns (end of leftmost-first match, position where
/// the scan stopped).
#[allow(clippy::too_many_arguments)]
fn fwd_search(
    cls: &Classes,
    d: &Dir,
    c: &mut DCache,
    mut pre: Option<(&Prefilter, &mut PreStats)>,
    hay: &[u8],
    start: usize,
    anchored: bool,
    must_advance: bool,
) -> (Option<usize>, usize, bool) {
    let n = hay.len();
    let mut p = start;
    let behind = if p == 0 { CTX_NONE } else { cls.byte_ctx(hay[p - 1]) };
    let mut sid = start_state(cls, d, c, behind, anchored, must_advance);
    let mut last: Option<usize> = None;
    if let (Some((pf, _)), false) = (pre.as_ref(), anchored) {
        match pf.find(hay, p) {
            None => return (None, n, false),
            Some(q) => {
                if q > p {
                    p = q;
                    sid = start_state(cls, d, c, cls.byte_ctx(hay[q - 1]), false, false);
                }
            }
        }
    }
    let end = if cls.final_nl.is_some() && n > 0 && hay[n - 1] == b'\n' { n - 1 } else { n };
    let map = &cls.map;
    sid &= ID_MASK;
    while p < end {
        // Hot loop: plain transitions.
        let mut t: u32;
        // SAFETY: `sid` is always the untagged premultiplied id of an interned state
        // whose row is fully allocated in `trans`; class ids are < stride; every
        // haystack read is at an index < end <= hay.len().
        unsafe {
            let tp = c.trans.as_ptr();
            let hp = hay.as_ptr();
            let mp = map.as_ptr();
            let cl = |q: usize| *mp.add(*hp.add(q) as usize) as usize;
            loop {
                if p + 4 <= end {
                    let t0 = *tp.add(sid as usize + cl(p));
                    if t0 >= TAG_START {
                        t = t0;
                        break;
                    }
                    let t1 = *tp.add(t0 as usize + cl(p + 1));
                    if t1 >= TAG_START {
                        sid = t0;
                        p += 1;
                        t = t1;
                        break;
                    }
                    let t2 = *tp.add(t1 as usize + cl(p + 2));
                    if t2 >= TAG_START {
                        sid = t1;
                        p += 2;
                        t = t2;
                        break;
                    }
                    let t3 = *tp.add(t2 as usize + cl(p + 3));
                    if t3 >= TAG_START {
                        sid = t2;
                        p += 3;
                        t = t3;
                        break;
                    }
                    sid = t3;
                    p += 4;
                    if p >= end {
                        t = sid;
                        break;
                    }
                } else {
                    t = *tp.add(sid as usize + cl(p));
                    if t >= TAG_START {
                        break;
                    }
                    sid = t;
                    p += 1;
                    if p >= end {
                        break;
                    }
                }
            }
        }
        if p >= end {
            break;
        }
        if t == UNKNOWN {
            t = compute(cls, d, c, &mut sid, map[hay[p] as usize] as usize);
        }
        if t & TAG_MATCH != 0 {
            last = Some(p);
        }
        if t & TAG_DEAD != 0 {
            return (last, p, false);
        }
        sid = t & ID_MASK;
        p += 1;
        if t & TAG_START != 0 {
            if let Some((pf, st)) = pre.as_mut() {
                match pf.find(hay, p) {
                    None => return (last, n, false),
                    Some(q) => {
                        st.calls += 1;
                        st.skipped += (q - p) as u64;
                        if st.calls >= 32 && st.skipped < st.calls * 24 {
                            // Candidates are too dense: continue without the prefilter.
                            st.off = true;
                            return (None, q, true);
                        }
                        if q > p {
                            p = q;
                            sid = start_state(cls, d, c, cls.byte_ctx(hay[q - 1]), false, false) & ID_MASK;
                        }
                    }
                }
            }
        }
    }
    if end < n && p == end {
        if let Some(fc) = cls.final_nl {
            let t = step(cls, d, c, &mut sid, fc);
            if t & TAG_MATCH != 0 {
                last = Some(end);
            }
            if t & TAG_DEAD != 0 {
                return (last, end, false);
            }
            sid = t & ID_MASK;
        }
    }
    let t = step(cls, d, c, &mut sid, cls.eoi);
    if t & TAG_MATCH != 0 {
        last = Some(n);
    }
    (last, n, false)
}

/// Reverse search from boundary `end` down to `min_start`; returns the smallest start
/// of a match ending exactly at `end`.
fn rev_search(cls: &Classes, d: &Dir, c: &mut DCache, hay: &[u8], end: usize, min_start: usize) -> Option<usize> {
    let n = hay.len();
    let behind = if end >= n {
        CTX_NONE
    } else if cls.final_nl.is_some() && end + 1 == n && hay[end] == b'\n' {
        CTX_NL | CTX_FINAL_NL
    } else {
        cls.byte_ctx(hay[end])
    };
    let mut sid = start_state(cls, d, c, behind, true, false) & ID_MASK;
    let mut last = None;
    let mut p = end;
    let map = &cls.map;
    while p > min_start {
        let b = hay[p - 1];
        let class = match cls.final_nl {
            Some(fc) if p == n && b == b'\n' => fc,
            _ => map[b as usize] as usize,
        };
        let t = step(cls, d, c, &mut sid, class);
        if t & TAG_MATCH != 0 {
            last = Some(p);
        }
        if t & TAG_DEAD != 0 {
            return last;
        }
        sid = t & ID_MASK;
        p -= 1;
    }
    let class = if p == 0 {
        cls.eoi
    } else {
        let b = hay[p - 1];
        match cls.final_nl {
            Some(fc) if p == n && b == b'\n' => fc,
            _ => map[b as usize] as usize,
        }
    };
    let t = step(cls, d, c, &mut sid, class);
    if t & TAG_MATCH != 0 {
        last = Some(p);
    }
    last
}
