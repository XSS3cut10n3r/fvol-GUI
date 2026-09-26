//! Thompson NFA over bytes, compiled from "regular" HIR (no backrefs / lookaround /
//! atomic / conditionals). Split states are ordered by priority (first = preferred),
//! which is what leftmost-first (python / backtracking) semantics need. A reversed
//! NFA (concatenations reversed) is used to find match starts.

use super::hir::{ByteSet, Hir, Look};

#[derive(Clone, Debug)]
pub enum NState {
    Consume { set: ByteSet, next: u32 },
    Split { a: u32, b: u32 },
    Look { look: Look, next: u32 },
    Match,
    Fail,
}

#[derive(Clone, Debug)]
pub struct Nfa {
    pub states: Vec<NState>,
    pub start: u32,
    pub looks: Vec<Look>,
}

pub const MAX_NFA_STATES: usize = 200_000;

struct Builder {
    states: Vec<NState>,
    reverse: bool,
    looks: Vec<Look>,
}

impl Builder {
    fn push(&mut self, s: NState) -> Option<u32> {
        if self.states.len() >= MAX_NFA_STATES {
            return None;
        }
        self.states.push(s);
        Some((self.states.len() - 1) as u32)
    }

    fn compile(&mut self, h: &Hir, next: u32, depth: usize) -> Option<u32> {
        if depth > 3000 {
            return None;
        }
        match h {
            Hir::Empty => Some(next),
            Hir::Fail => self.push(NState::Fail),
            Hir::Class(s) => {
                if s.is_empty() {
                    self.push(NState::Fail)
                } else {
                    self.push(NState::Consume { set: *s, next })
                }
            }
            Hir::Look(l) => {
                if !self.looks.contains(l) {
                    self.looks.push(*l);
                }
                self.push(NState::Look { look: *l, next })
            }
            Hir::Concat(v) => {
                let mut n = next;
                if self.reverse {
                    for x in v.iter() {
                        n = self.compile(x, n, depth + 1)?;
                    }
                } else {
                    for x in v.iter().rev() {
                        n = self.compile(x, n, depth + 1)?;
                    }
                }
                Some(n)
            }
            Hir::Alt(v) => {
                let mut starts = Vec::with_capacity(v.len());
                for x in v {
                    starts.push(self.compile(x, next, depth + 1)?);
                }
                let mut n = *starts.last()?;
                for &s in starts.iter().rev().skip(1) {
                    n = self.push(NState::Split { a: s, b: n })?;
                }
                Some(n)
            }
            Hir::Capture { sub, .. } => self.compile(sub, next, depth + 1),
            Hir::Repeat { min, max, greedy, sub } => {
                let opt_start = match max {
                    None => {
                        let l = self.push(NState::Fail)?;
                        let body = self.compile(sub, l, depth + 1)?;
                        self.states[l as usize] =
                            if *greedy { NState::Split { a: body, b: next } } else { NState::Split { a: next, b: body } };
                        l
                    }
                    Some(m) => {
                        let k = m.saturating_sub(*min);
                        let mut n = next;
                        for _ in 0..k {
                            let body = self.compile(sub, n, depth + 1)?;
                            n = if *greedy {
                                self.push(NState::Split { a: body, b: next })?
                            } else {
                                self.push(NState::Split { a: next, b: body })?
                            };
                        }
                        n
                    }
                };
                let mut n = opt_start;
                for _ in 0..*min {
                    n = self.compile(sub, n, depth + 1)?;
                }
                Some(n)
            }
            Hir::Backref { .. } | Hir::LookAround { .. } | Hir::Atomic(_) | Hir::Cond { .. } | Hir::UClass(_) => None,
        }
    }
}

impl Nfa {
    pub fn new(h: &Hir, reverse: bool) -> Option<Nfa> {
        let mut b = Builder { states: Vec::new(), reverse, looks: Vec::new() };
        let m = b.push(NState::Match)?;
        let start = b.compile(h, m, 0)?;
        Some(Nfa { states: b.states, start, looks: b.looks })
    }
}
