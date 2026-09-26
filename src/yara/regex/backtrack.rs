//! Backtracking engine with exact sre (python `re`) semantics: priority-ordered
//! alternation, greedy/lazy/possessive repeats, sre's zero-width repeat protection,
//! backreferences, lookaround, atomic groups and conditionals.
//!
//! Exponential blow-up is prevented by memoization: a (pc, pos) state (extended with
//! the "iteration so far empty" bits of enclosing nullable loops) is explored at most
//! once per search; sub-matches (lookaround / atomic bodies) record failures with
//! marker frames so that successful sub-paths are never mis-recorded. Patterns with
//! backreferences / conditionals key the memo on the referenced capture spans.
//! The stack is explicit (heap allocated), so deep inputs can never overflow the
//! native stack.

use super::hir::{ByteSet, Hir, Look};
use super::Error;
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubKind {
    Ahead,
    NotAhead,
    Behind,
    NotBehind,
    Atomic,
}

#[derive(Clone, Copy, Debug)]
pub enum Inst {
    Byte(u8),
    Set(u32),
    Look(Look),
    Split(u32, u32),
    Jmp(u32),
    Save(u32),
    /// Single-byte-width item repeated; continuation at pc+1.
    RepOne { set: u32, min: u32, max: u32, greedy: bool },
    RegClear(u16),
    RegSet(u16),
    RegJmpIfEq(u16, u32),
    RegFailIfEq(u16),
    Backref { group: u32, icase: bool },
    /// Sub-match; body starts at pc+1 and ends with SubEnd; continuation at `next`.
    SubStart { id: u32, kind: SubKind, width: u32, next: u32 },
    SubEnd,
    /// If group matched continue at pc+1, else jump to `no`.
    Cond { group: u32, no: u32 },
    Match,
    Fail,
}

pub struct Prog {
    pub insts: Vec<Inst>,
    pub sets: Vec<ByteSet>,
    pub nslots: usize,
    pub nregs: usize,
    /// Per pc: memo key index (u32::MAX = not memoized).
    memo_key: Vec<u32>,
    /// Per pc: registers of enclosing nullable loops (index into reg_lists).
    reg_list: Vec<u32>,
    reg_lists: Vec<Vec<u16>>,
    /// Per pc: inside a sub-match body.
    in_sub: Vec<bool>,
    nmemo: usize,
    /// Extension bits per memo key (2^k variants).
    ext_bits: u32,
    nsubs: usize,
    capture_dependent: bool,
    /// Groups referenced by backrefs / conditionals.
    ref_groups: Vec<u32>,
}

const MAX_INSTS: usize = 2_000_000;
const NONE: usize = usize::MAX;

struct Compiler {
    insts: Vec<Inst>,
    sets: Vec<ByteSet>,
    nregs: usize,
    nsubs: u32,
    gw: Vec<(u128, u128)>,
    loop_stack: Vec<u16>,
    reg_list: Vec<u32>,
    reg_lists: Vec<Vec<u16>>,
    sub_depth: u32,
    in_sub: Vec<bool>,
    ref_groups: Vec<u32>,
}

impl Compiler {
    fn push(&mut self, i: Inst) -> Result<u32, Error> {
        if self.insts.len() >= MAX_INSTS {
            return Err(Error::new("regular expression is too large", 0));
        }
        let pc = self.insts.len() as u32;
        self.insts.push(i);
        let key = self.loop_stack.clone();
        let idx = match self.reg_lists.iter().position(|l| *l == key) {
            Some(i) => i,
            None => {
                self.reg_lists.push(key);
                self.reg_lists.len() - 1
            }
        };
        self.reg_list.push(idx as u32);
        self.in_sub.push(self.sub_depth > 0);
        Ok(pc)
    }

    fn pc(&self) -> u32 {
        self.insts.len() as u32
    }

    fn set_idx(&mut self, s: &ByteSet) -> u32 {
        if let Some(i) = self.sets.iter().position(|x| x == s) {
            return i as u32;
        }
        self.sets.push(*s);
        (self.sets.len() - 1) as u32
    }

    fn patch(&mut self, at: u32, target: u32) {
        match &mut self.insts[at as usize] {
            Inst::Split(_, y) if *y == u32::MAX => *y = target,
            Inst::Split(x, _) if *x == u32::MAX => *x = target,
            Inst::Jmp(t) => *t = target,
            Inst::RegJmpIfEq(_, t) => *t = target,
            Inst::SubStart { next, .. } => *next = target,
            Inst::Cond { no, .. } => *no = target,
            _ => {}
        }
    }

    fn compile(&mut self, h: &Hir, depth: usize) -> Result<(), Error> {
        if depth > 3000 {
            return Err(Error::new("pattern too deeply nested", 0));
        }
        match h {
            Hir::Empty => {}
            Hir::Fail => {
                self.push(Inst::Fail)?;
            }
            Hir::Class(s) => {
                if let Some(b) = s.as_single() {
                    self.push(Inst::Byte(b))?;
                } else {
                    let i = self.set_idx(s);
                    self.push(Inst::Set(i))?;
                }
            }
            Hir::Look(l) => {
                self.push(Inst::Look(*l))?;
            }
            Hir::Concat(v) => {
                for x in v {
                    self.compile(x, depth + 1)?;
                }
            }
            Hir::Alt(v) => {
                let mut jumps = Vec::new();
                for (i, x) in v.iter().enumerate() {
                    if i + 1 < v.len() {
                        let split = self.push(Inst::Split(0, u32::MAX))?;
                        let first = self.pc();
                        if let Inst::Split(a, _) = &mut self.insts[split as usize] {
                            *a = first;
                        }
                        self.compile(x, depth + 1)?;
                        jumps.push(self.push(Inst::Jmp(u32::MAX))?);
                        let next = self.pc();
                        self.patch(split, next);
                    } else {
                        self.compile(x, depth + 1)?;
                    }
                }
                let end = self.pc();
                for j in jumps {
                    self.patch(j, end);
                }
            }
            Hir::Capture { index, sub } => {
                self.push(Inst::Save(index * 2))?;
                self.compile(sub, depth + 1)?;
                self.push(Inst::Save(index * 2 + 1))?;
            }
            Hir::Repeat { min, max, greedy, sub } => self.repeat(*min, *max, *greedy, sub, depth)?,
            Hir::Backref { group, icase } => {
                if !self.ref_groups.contains(group) {
                    self.ref_groups.push(*group);
                }
                self.push(Inst::Backref { group: *group, icase: *icase })?;
            }
            Hir::LookAround { behind, negate, width, sub } => {
                let kind = match (behind, negate) {
                    (false, false) => SubKind::Ahead,
                    (false, true) => SubKind::NotAhead,
                    (true, false) => SubKind::Behind,
                    (true, true) => SubKind::NotBehind,
                };
                self.sub(kind, *width, sub, depth)?;
            }
            Hir::Atomic(sub) => self.sub(SubKind::Atomic, 0, sub, depth)?,
            Hir::Cond { group, yes, no } => {
                if !self.ref_groups.contains(group) {
                    self.ref_groups.push(*group);
                }
                let c = self.push(Inst::Cond { group: *group, no: u32::MAX })?;
                self.compile(yes, depth + 1)?;
                let j = self.push(Inst::Jmp(u32::MAX))?;
                let l = self.pc();
                self.patch(c, l);
                self.compile(no, depth + 1)?;
                let end = self.pc();
                self.patch(j, end);
            }
        }
        Ok(())
    }

    fn sub(&mut self, kind: SubKind, width: u32, sub: &Hir, depth: usize) -> Result<(), Error> {
        let id = self.nsubs;
        self.nsubs += 1;
        let s = self.push(Inst::SubStart { id, kind, width, next: u32::MAX })?;
        self.sub_depth += 1;
        // Loops outside the sub-body do not influence it.
        let saved = std::mem::take(&mut self.loop_stack);
        self.compile(sub, depth + 1)?;
        self.push(Inst::SubEnd)?;
        self.loop_stack = saved;
        self.sub_depth -= 1;
        let next = self.pc();
        self.patch(s, next);
        Ok(())
    }

    fn repeat(&mut self, min: u32, max: Option<u32>, greedy: bool, sub: &Hir, depth: usize) -> Result<(), Error> {
        if let Hir::Class(s) = sub {
            let set = self.set_idx(s);
            self.push(Inst::RepOne { set, min, max: max.unwrap_or(u32::MAX), greedy })?;
            return Ok(());
        }
        if max == Some(0) {
            return Ok(());
        }
        let nullable = sub.min_width(&self.gw) == 0;
        // Mandatory copies.
        for _ in 0..min {
            self.compile(sub, depth + 1)?;
            if self.insts.len() >= MAX_INSTS {
                return Err(Error::new("regular expression is too large", 0));
            }
        }
        let optional: Option<u32> = max.map(|m| m - min);
        if optional == Some(0) {
            return Ok(());
        }
        if !nullable {
            match optional {
                None => {
                    // L: Split(ITER, EXIT) / lazy Split(EXIT, ITER)
                    let l = self.push(Inst::Split(u32::MAX, u32::MAX))?;
                    let body = self.pc();
                    self.compile(sub, depth + 1)?;
                    self.push(Inst::Jmp(l))?;
                    let exit = self.pc();
                    self.insts[l as usize] = if greedy { Inst::Split(body, exit) } else { Inst::Split(exit, body) };
                }
                Some(k) => {
                    let mut splits = Vec::new();
                    for _ in 0..k {
                        let s = self.push(Inst::Split(u32::MAX, u32::MAX))?;
                        splits.push((s, self.pc()));
                        self.compile(sub, depth + 1)?;
                    }
                    let exit = self.pc();
                    for (s, body) in splits {
                        self.insts[s as usize] = if greedy { Inst::Split(body, exit) } else { Inst::Split(exit, body) };
                    }
                }
            }
            return Ok(());
        }
        // Nullable body: sre zero-width protection with a register.
        if self.nregs >= u16::MAX as usize {
            return Err(Error::new("regular expression is too large", 0));
        }
        let r = self.nregs as u16;
        self.nregs += 1;
        self.push(Inst::RegClear(r))?;
        self.loop_stack.push(r);
        match optional {
            None => {
                if greedy {
                    let l = self.push(Inst::RegJmpIfEq(r, u32::MAX))?;
                    let s = self.push(Inst::Split(u32::MAX, u32::MAX))?;
                    let iter = self.push(Inst::RegSet(r))?;
                    self.compile(sub, depth + 1)?;
                    self.push(Inst::Jmp(l))?;
                    let exit = self.pc();
                    self.insts[s as usize] = Inst::Split(iter, exit);
                    self.patch(l, exit);
                } else {
                    let l = self.push(Inst::Split(u32::MAX, u32::MAX))?;
                    let chk = self.push(Inst::RegFailIfEq(r))?;
                    self.push(Inst::RegSet(r))?;
                    self.compile(sub, depth + 1)?;
                    self.push(Inst::Jmp(l))?;
                    let exit = self.pc();
                    self.insts[l as usize] = Inst::Split(exit, chk);
                }
            }
            Some(k) => {
                let mut splits = Vec::new();
                let mut eqjumps = Vec::new();
                for i in 0..k {
                    if greedy {
                        if i > 0 {
                            eqjumps.push(self.push(Inst::RegJmpIfEq(r, u32::MAX))?);
                        }
                        let s = self.push(Inst::Split(u32::MAX, u32::MAX))?;
                        splits.push((s, self.pc()));
                        self.push(Inst::RegSet(r))?;
                        self.compile(sub, depth + 1)?;
                    } else {
                        let s = self.push(Inst::Split(u32::MAX, u32::MAX))?;
                        splits.push((s, self.pc()));
                        if i > 0 {
                            self.push(Inst::RegFailIfEq(r))?;
                        }
                        self.push(Inst::RegSet(r))?;
                        self.compile(sub, depth + 1)?;
                    }
                }
                let exit = self.pc();
                for (s, body) in splits {
                    self.insts[s as usize] = if greedy { Inst::Split(body, exit) } else { Inst::Split(exit, body) };
                }
                for j in eqjumps {
                    self.patch(j, exit);
                }
            }
        }
        self.loop_stack.pop();
        Ok(())
    }
}

impl Prog {
    pub fn new(h: &Hir, ngroups: u32, gw: &[(u128, u128)]) -> Result<Prog, Error> {
        let mut c = Compiler {
            insts: Vec::new(),
            sets: Vec::new(),
            nregs: 0,
            nsubs: 0,
            gw: gw.to_vec(),
            loop_stack: Vec::new(),
            reg_list: Vec::new(),
            reg_lists: vec![Vec::new()],
            sub_depth: 0,
            in_sub: Vec::new(),
            ref_groups: Vec::new(),
        };
        c.compile(h, 0)?;
        c.push(Inst::Match)?;
        // Memo keys: split targets, RepOne continuations, SubStart and their continuations.
        let n = c.insts.len();
        let mut want = vec![false; n];
        for (pc, inst) in c.insts.iter().enumerate() {
            match *inst {
                Inst::Split(x, y) => {
                    if (x as usize) < n {
                        want[x as usize] = true;
                    }
                    if (y as usize) < n {
                        want[y as usize] = true;
                    }
                }
                Inst::RepOne { .. } => {
                    if pc + 1 < n {
                        want[pc + 1] = true;
                    }
                }
                Inst::SubStart { next, .. } => {
                    if (next as usize) < n {
                        want[next as usize] = true;
                    }
                }
                _ => {}
            }
        }
        let mut memo_key = vec![u32::MAX; n];
        let mut nmemo = 0usize;
        for pc in 0..n {
            if want[pc] {
                memo_key[pc] = nmemo as u32;
                nmemo += 1;
            }
        }
        let max_depth = c.reg_lists.iter().map(|l| l.len()).max().unwrap_or(0);
        let ext_bits = max_depth.min(8) as u32;
        // Deeper nesting of nullable loops than 8: those pcs are simply not memoized.
        for pc in 0..n {
            if c.reg_lists[c.reg_list[pc] as usize].len() > 8 {
                memo_key[pc] = u32::MAX;
            }
        }
        let capture_dependent = !c.ref_groups.is_empty();
        Ok(Prog {
            insts: c.insts,
            sets: c.sets,
            nslots: (ngroups as usize) * 2,
            nregs: c.nregs,
            memo_key,
            reg_list: c.reg_list,
            reg_lists: c.reg_lists,
            in_sub: c.in_sub,
            nmemo,
            ext_bits,
            nsubs: c.nsubs as usize,
            capture_dependent,
            ref_groups: c.ref_groups,
        })
    }
}

// ---------------------------------------------------------------------------------------
// Paged memo bitset
// ---------------------------------------------------------------------------------------

const PAGE_SHIFT: usize = 10;
const PAGE: usize = 1 << PAGE_SHIFT;
const MEMO_BUDGET_BYTES: usize = 256 << 20;

struct Memo {
    /// Bits per position: keys * variants.
    keys: usize,
    pages: Vec<Option<Box<[u64]>>>,
    touched: Vec<usize>,
    words_per_page: usize,
    allocated: usize,
    exact: HashSet<(u32, usize, Box<[usize]>)>,
}

impl Memo {
    fn new(keys: usize, hay_len: usize) -> Memo {
        let npages = (hay_len + 1) / PAGE + 1;
        let words_per_page = (keys * PAGE).div_ceil(64);
        Memo { keys, pages: vec![None; npages], touched: Vec::new(), words_per_page, allocated: 0, exact: HashSet::new() }
    }

    /// Returns true if the bit was already set; sets it.
    #[inline]
    fn test_and_set(&mut self, key: usize, pos: usize) -> bool {
        let page = pos >> PAGE_SHIFT;
        if page >= self.pages.len() {
            return false;
        }
        let bit = key * PAGE + (pos & (PAGE - 1));
        if self.pages[page].is_none() {
            if self.allocated + self.words_per_page * 8 > MEMO_BUDGET_BYTES {
                return false; // over budget: memo is only an optimization
            }
            self.pages[page] = Some(vec![0u64; self.words_per_page].into_boxed_slice());
            self.allocated += self.words_per_page * 8;
            self.touched.push(page);
        }
        match &mut self.pages[page] {
            Some(p) => {
                let w = &mut p[bit >> 6];
                let m = 1u64 << (bit & 63);
                let was = *w & m != 0;
                *w |= m;
                was
            }
            None => false,
        }
    }

    #[inline]
    fn test(&self, key: usize, pos: usize) -> bool {
        let page = pos >> PAGE_SHIFT;
        match self.pages.get(page) {
            Some(Some(p)) => {
                let bit = key * PAGE + (pos & (PAGE - 1));
                p[bit >> 6] >> (bit & 63) & 1 != 0
            }
            _ => false,
        }
    }

    fn clear(&mut self) {
        for &p in &self.touched {
            self.pages[p] = None;
        }
        self.touched.clear();
        self.allocated = 0;
        self.exact.clear();
    }
}

// ---------------------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Frame {
    Alt { pc: u32, pos: usize },
    Slot { slot: u32, old: usize },
    Reg { r: u16, old: usize },
    RepGreedy { next: u32, min_pos: usize, cur: usize },
    RepLazy { next: u32, set: u32, max_pos: usize, cur: usize },
    /// Sub-match barrier.
    Barrier { pc: u32, pos: usize },
    /// Record failure of memo key at pos when popped.
    MemoFail { key: u32, pos: usize },
}

/// Scratch state reused across searches.
pub struct Cache {
    stack: Vec<Frame>,
    slots: Vec<usize>,
    regs: Vec<usize>,
    memo: Option<Memo>,
}

impl Cache {
    pub fn new() -> Cache {
        Cache { stack: Vec::new(), slots: Vec::new(), regs: Vec::new(), memo: None }
    }
}

impl Default for Cache {
    fn default() -> Self {
        Cache::new()
    }
}

#[inline]
pub fn look_at(look: Look, hay: &[u8], pos: usize) -> bool {
    let n = hay.len();
    match look {
        Look::Start => pos == 0,
        Look::StartLine => pos == 0 || (pos <= n && hay[pos - 1] == b'\n'),
        Look::EndOrFinalNl => pos == n || (pos + 1 == n && hay[pos] == b'\n'),
        Look::EndLine => pos >= n || hay[pos] == b'\n',
        Look::End => pos >= n,
        Look::WordB | Look::NotWordB | Look::WordBYara | Look::NotWordBYara => {
            let before = pos > 0 && pos <= n && super::hir::is_word_byte(hay[pos - 1]);
            let after = pos < n && super::hir::is_word_byte(hay[pos]);
            match look {
                Look::WordB => before != after,
                Look::NotWordB => before == after,
                Look::WordBYara => before != after,
                _ => before == after,
            }
        }
    }
}

pub struct Search<'a> {
    pub prog: &'a Prog,
    pub hay: &'a [u8],
}

impl<'a> Search<'a> {
    /// Leftmost match starting at >= `start` (python `search` semantics), optionally
    /// anchored at `start`. With `must_advance`, an empty match at `start` is rejected
    /// (python finditer rule). Returns (start, end) and fills `slots` in the cache.
    pub fn find(&self, cache: &mut Cache, start: usize, anchored: bool, must_advance: bool) -> Option<(usize, usize)> {
        let prog = self.prog;
        let hay = self.hay;
        if start > hay.len() {
            return None;
        }
        let keys = prog.nmemo << prog.ext_bits;
        let keys = keys + prog.nsubs * 2;
        match &mut cache.memo {
            Some(m) if m.keys == keys && m.pages.len() == (hay.len() + 1) / PAGE + 1 => m.clear(),
            _ => cache.memo = Some(Memo::new(keys, hay.len())),
        }
        cache.slots.clear();
        cache.slots.resize(prog.nslots.max(2), NONE);
        cache.regs.clear();
        cache.regs.resize(prog.nregs, NONE);
        let mut s = start;
        loop {
            if let Some(end) = self.run(cache, s, start, must_advance) {
                if cache.slots.len() >= 2 {
                    cache.slots[0] = s;
                    cache.slots[1] = end;
                }
                return Some((s, end));
            }
            if anchored || s >= hay.len() {
                return None;
            }
            s += 1;
        }
    }

    fn memo_index(&self, cache: &Cache, pc: usize, pos: usize) -> Option<usize> {
        let prog = self.prog;
        let k = prog.memo_key[pc];
        if k == u32::MAX {
            return None;
        }
        let mut ext = 0usize;
        if prog.ext_bits > 0 {
            let list = &prog.reg_lists[prog.reg_list[pc] as usize];
            for (i, &r) in list.iter().enumerate() {
                if cache.regs[r as usize] == pos {
                    ext |= 1 << i;
                }
            }
        }
        Some(((k as usize) << prog.ext_bits) | ext)
    }

    /// Check the memo for (pc, pos). Returns true if the state must be skipped.
    /// For main-flow states: visited semantics (mark now). For sub-body states:
    /// failure semantics (a MemoFail marker is pushed).
    #[inline]
    fn memo_skip(&self, cache: &mut Cache, pc: usize, pos: usize) -> bool {
        let Some(key) = self.memo_index(cache, pc, pos) else {
            return false;
        };
        let prog = self.prog;
        if prog.capture_dependent {
            let mut spans = Vec::with_capacity(prog.ref_groups.len() * 2);
            for &g in &prog.ref_groups {
                let a = cache.slots.get(g as usize * 2).copied().unwrap_or(NONE);
                let b = cache.slots.get(g as usize * 2 + 1).copied().unwrap_or(NONE);
                spans.push(a);
                spans.push(b);
            }
            let k = (key as u32, pos, spans.into_boxed_slice());
            let memo = match cache.memo.as_mut() {
                Some(m) => m,
                None => return false,
            };
            if prog.in_sub[pc] {
                if memo.exact.contains(&k) {
                    return true;
                }
                // No marker bookkeeping for exact keys inside sub bodies: skip memo.
                return false;
            }
            if memo.exact.len() > 4_000_000 {
                return false;
            }
            return !memo.exact.insert(k);
        }
        let memo = match cache.memo.as_mut() {
            Some(m) => m,
            None => return false,
        };
        if prog.in_sub[pc] {
            if memo.test(key, pos) {
                return true;
            }
            cache.stack.push(Frame::MemoFail { key: key as u32, pos });
            false
        } else {
            memo.test_and_set(key, pos)
        }
    }

    fn set_slot(cache: &mut Cache, slot: usize, val: usize) {
        if slot < cache.slots.len() {
            let old = cache.slots[slot];
            cache.stack.push(Frame::Slot { slot: slot as u32, old });
            cache.slots[slot] = val;
        }
    }

    fn sub_key(&self, id: u32, which: usize) -> usize {
        (self.prog.nmemo << self.prog.ext_bits) + id as usize * 2 + which
    }

    /// Run from `start`; returns the match end.
    fn run(&self, cache: &mut Cache, start: usize, search_start: usize, must_advance: bool) -> Option<usize> {
        let prog = self.prog;
        let hay = self.hay;
        let insts = &prog.insts[..];
        cache.stack.clear();
        let mut pc: usize = 0;
        let mut pos: usize = start;
        'outer: loop {
            // Execute until failure.
            let failed: bool = 'exec: loop {
                let Some(inst) = insts.get(pc) else { break 'exec true };
                match *inst {
                    Inst::Byte(b) => {
                        if pos < hay.len() && hay[pos] == b {
                            pos += 1;
                            pc += 1;
                        } else {
                            break 'exec true;
                        }
                    }
                    Inst::Set(i) => {
                        if pos < hay.len() && prog.sets[i as usize].contains(hay[pos]) {
                            pos += 1;
                            pc += 1;
                        } else {
                            break 'exec true;
                        }
                    }
                    Inst::Look(l) => {
                        if look_at(l, hay, pos) {
                            pc += 1;
                        } else {
                            break 'exec true;
                        }
                    }
                    Inst::Split(x, y) => {
                        cache.stack.push(Frame::Alt { pc: y, pos });
                        pc = x as usize;
                        if self.memo_skip(cache, pc, pos) {
                            break 'exec true;
                        }
                    }
                    Inst::Jmp(t) => pc = t as usize,
                    Inst::Save(slot) => {
                        Self::set_slot(cache, slot as usize, pos);
                        pc += 1;
                    }
                    Inst::RepOne { set, min, max, greedy } => {
                        let s = &prog.sets[set as usize];
                        let lim = if max == u32::MAX { hay.len() } else { hay.len().min(pos.saturating_add(max as usize)) };
                        if greedy {
                            let mut e = pos;
                            while e < lim && s.contains(hay[e]) {
                                e += 1;
                            }
                            let min_pos = pos + min as usize;
                            if e < min_pos {
                                break 'exec true;
                            }
                            cache.stack.push(Frame::RepGreedy { next: pc as u32 + 1, min_pos, cur: e });
                            pos = e;
                            pc += 1;
                            if self.memo_skip(cache, pc, pos) {
                                break 'exec true;
                            }
                        } else {
                            let min_pos = pos + min as usize;
                            if min_pos > hay.len() {
                                break 'exec true;
                            }
                            let mut e = pos;
                            while e < min_pos {
                                if !s.contains(hay[e]) {
                                    break;
                                }
                                e += 1;
                            }
                            if e < min_pos {
                                break 'exec true;
                            }
                            cache.stack.push(Frame::RepLazy { next: pc as u32 + 1, set, max_pos: lim, cur: e });
                            pos = e;
                            pc += 1;
                            if self.memo_skip(cache, pc, pos) {
                                break 'exec true;
                            }
                        }
                    }
                    Inst::RegClear(r) => {
                        let old = cache.regs[r as usize];
                        cache.stack.push(Frame::Reg { r, old });
                        cache.regs[r as usize] = NONE;
                        pc += 1;
                    }
                    Inst::RegSet(r) => {
                        let old = cache.regs[r as usize];
                        cache.stack.push(Frame::Reg { r, old });
                        cache.regs[r as usize] = pos;
                        pc += 1;
                    }
                    Inst::RegJmpIfEq(r, t) => {
                        if cache.regs[r as usize] == pos {
                            pc = t as usize;
                        } else {
                            pc += 1;
                        }
                    }
                    Inst::RegFailIfEq(r) => {
                        if cache.regs[r as usize] == pos {
                            break 'exec true;
                        }
                        pc += 1;
                    }
                    Inst::Backref { group, icase } => {
                        let a = cache.slots.get(group as usize * 2).copied().unwrap_or(NONE);
                        let b = cache.slots.get(group as usize * 2 + 1).copied().unwrap_or(NONE);
                        if a == NONE || b == NONE || a > b || b > hay.len() {
                            break 'exec true;
                        }
                        let len = b - a;
                        if pos + len > hay.len() {
                            break 'exec true;
                        }
                        let ok = if icase {
                            hay[a..b].iter().zip(&hay[pos..pos + len]).all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
                        } else {
                            hay[a..b] == hay[pos..pos + len]
                        };
                        if !ok {
                            break 'exec true;
                        }
                        pos += len;
                        pc += 1;
                    }
                    Inst::SubStart { id, kind, width, next } => {
                        let memo = cache.memo.as_ref();
                        let known_fail = !prog.capture_dependent && memo.map_or(false, |m| m.test(self.sub_key(id, 0), pos));
                        let known_true = !prog.capture_dependent && memo.map_or(false, |m| m.test(self.sub_key(id, 1), pos));
                        match kind {
                            SubKind::NotAhead | SubKind::NotBehind if known_true => {
                                pc = next as usize;
                                continue;
                            }
                            _ if known_fail => break 'exec true,
                            _ => {}
                        }
                        let body_pos = match kind {
                            SubKind::Behind | SubKind::NotBehind => {
                                if pos < width as usize {
                                    // Cannot look behind: positive fails, negative succeeds.
                                    if kind == SubKind::NotBehind {
                                        pc = next as usize;
                                        continue;
                                    }
                                    break 'exec true;
                                }
                                pos - width as usize
                            }
                            _ => pos,
                        };
                        cache.stack.push(Frame::Barrier { pc: pc as u32, pos });
                        pc += 1;
                        pos = body_pos;
                    }
                    Inst::SubEnd => {
                        // Find the innermost barrier.
                        let mut bi = cache.stack.len();
                        let mut found = None;
                        while bi > 0 {
                            bi -= 1;
                            if let Frame::Barrier { pc: bpc, pos: bpos } = cache.stack[bi] {
                                found = Some((bi, bpc, bpos));
                                break;
                            }
                        }
                        let Some((bi, bpc, bpos)) = found else { break 'exec true };
                        let Some(Inst::SubStart { id, kind, next, .. }) = insts.get(bpc as usize).copied() else {
                            break 'exec true;
                        };
                        match kind {
                            SubKind::NotAhead | SubKind::NotBehind => {
                                // Body matched: assertion fails. Undo everything above the barrier.
                                while cache.stack.len() > bi + 1 {
                                    if let Some(f) = cache.stack.pop() {
                                        Self::undo(cache, f);
                                    }
                                }
                                cache.stack.pop();
                                let k = self.sub_key(id, 0);
                                if let Some(m) = cache.memo.as_mut() {
                                    m.test_and_set(k, bpos);
                                }
                                break 'exec true;
                            }
                            _ => {
                                // Commit: drop choice frames above the barrier, keep undo info.
                                let mut w = bi;
                                for r in bi + 1..cache.stack.len() {
                                    let f = cache.stack[r];
                                    if matches!(f, Frame::Slot { .. } | Frame::Reg { .. }) {
                                        cache.stack[w] = f;
                                        w += 1;
                                    }
                                }
                                cache.stack.truncate(w);
                                if kind != SubKind::Atomic {
                                    pos = bpos;
                                }
                                pc = next as usize;
                                if self.memo_skip(cache, pc, pos) {
                                    break 'exec true;
                                }
                            }
                        }
                    }
                    Inst::Cond { group, no } => {
                        let a = cache.slots.get(group as usize * 2).copied().unwrap_or(NONE);
                        let b = cache.slots.get(group as usize * 2 + 1).copied().unwrap_or(NONE);
                        if a != NONE && b != NONE && a <= b {
                            pc += 1;
                        } else {
                            pc = no as usize;
                        }
                    }
                    Inst::Match => {
                        if must_advance && pos == search_start {
                            break 'exec true;
                        }
                        return Some(pos);
                    }
                    Inst::Fail => break 'exec true,
                }
            };
            debug_assert!(failed);
            // Backtrack.
            loop {
                let Some(f) = cache.stack.pop() else { return None };
                match f {
                    Frame::Alt { pc: p, pos: q } => {
                        pc = p as usize;
                        pos = q;
                        if self.memo_skip(cache, pc, pos) {
                            continue;
                        }
                        continue 'outer;
                    }
                    Frame::Slot { .. } | Frame::Reg { .. } => Self::undo(cache, f),
                    Frame::RepGreedy { next, min_pos, cur } => {
                        let mut c = cur;
                        while c > min_pos {
                            c -= 1;
                            if !self.memo_would_skip(cache, next as usize, c) {
                                cache.stack.push(Frame::RepGreedy { next, min_pos, cur: c });
                                pc = next as usize;
                                pos = c;
                                if self.memo_skip(cache, pc, pos) {
                                    break;
                                }
                                continue 'outer;
                            }
                        }
                    }
                    Frame::RepLazy { next, set, max_pos, cur } => {
                        let s = &prog.sets[set as usize];
                        let mut c = cur;
                        while c < max_pos && s.contains(hay[c]) {
                            c += 1;
                            if !self.memo_would_skip(cache, next as usize, c) {
                                cache.stack.push(Frame::RepLazy { next, set, max_pos, cur: c });
                                pc = next as usize;
                                pos = c;
                                if self.memo_skip(cache, pc, pos) {
                                    break;
                                }
                                continue 'outer;
                            }
                        }
                    }
                    Frame::Barrier { pc: bpc, pos: bpos } => {
                        // Sub body exhausted without success.
                        let Some(Inst::SubStart { id, kind, next, .. }) = insts.get(bpc as usize).copied() else {
                            continue;
                        };
                        match kind {
                            SubKind::NotAhead | SubKind::NotBehind => {
                                let k = self.sub_key(id, 1);
                                if let Some(m) = cache.memo.as_mut() {
                                    m.test_and_set(k, bpos);
                                }
                                pc = next as usize;
                                pos = bpos;
                                continue 'outer;
                            }
                            _ => {
                                let k = self.sub_key(id, 0);
                                if let Some(m) = cache.memo.as_mut() {
                                    m.test_and_set(k, bpos);
                                }
                            }
                        }
                    }
                    Frame::MemoFail { key, pos: q } => {
                        if let Some(m) = cache.memo.as_mut() {
                            m.test_and_set(key as usize, q);
                        }
                    }
                }
            }
        }
    }

    /// Like memo_skip but without side effects (used to skip dead RepOne positions).
    fn memo_would_skip(&self, cache: &Cache, pc: usize, pos: usize) -> bool {
        if self.prog.capture_dependent {
            return false;
        }
        match (self.memo_index(cache, pc, pos), cache.memo.as_ref()) {
            (Some(k), Some(m)) => m.test(k, pos),
            _ => false,
        }
    }

    fn undo(cache: &mut Cache, f: Frame) {
        match f {
            Frame::Slot { slot, old } => {
                if let Some(s) = cache.slots.get_mut(slot as usize) {
                    *s = old;
                }
            }
            Frame::Reg { r, old } => {
                if let Some(s) = cache.regs.get_mut(r as usize) {
                    *s = old;
                }
            }
            _ => {}
        }
    }

    /// Capture slots of the last successful `find`.
    pub fn slots<'c>(&self, cache: &'c Cache) -> &'c [usize] {
        &cache.slots
    }
}

pub const SLOT_NONE: usize = NONE;
