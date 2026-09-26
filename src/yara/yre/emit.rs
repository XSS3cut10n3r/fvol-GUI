//! Code emission for YARA regex / hex ASTs, mirroring libyara's `_yr_re_emit`:
//! the same instruction sequence (splits with ids, jumps, repeat start/end with
//! counters, repeat-any), the same forward / backward programs and the same per-node
//! code references (atoms point at them), plus libyara's limits (128 split ids,
//! 16-bit relative jumps measured in libyara's byte encoding).

use super::ast::{Ast, Class, Kind, Node};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Literal(u8),
    MaskedLiteral(u8, u8),
    NotLiteral(u8),
    MaskedNotLiteral(u8, u8),
    Any,
    Class(u32),
    WordChar,
    NonWordChar,
    Space,
    NonSpace,
    Digit,
    NonDigit,
    WordBoundary,
    NonWordBoundary,
    MatchAtStart,
    MatchAtEnd,
    /// SPLIT_A: prefer the next instruction; alternative at `target`.
    SplitA { id: u8, target: u32 },
    /// SPLIT_B: prefer `target`; alternative is the next instruction.
    SplitB { id: u8, target: u32 },
    Jump(u32),
    /// Loop body starts at pc+1; `end` = pc right after the matching RepeatEnd.
    RepeatStart { greedy: bool, min: u16, max: u16, end: u32 },
    /// `body` = first pc of the loop body.
    RepeatEnd { greedy: bool, min: u16, max: u16, body: u32 },
    RepeatAny { greedy: bool, min: u16, max: u16 },
    Match,
}

impl Op {
    /// Size of the instruction in libyara's byte encoding.
    fn size(&self) -> i64 {
        match self {
            Op::Literal(_) | Op::NotLiteral(_) => 2,
            Op::MaskedLiteral(..) | Op::MaskedNotLiteral(..) => 3,
            Op::Class(_) => 34,
            Op::SplitA { .. } | Op::SplitB { .. } => 4,
            Op::Jump(_) => 3,
            Op::RepeatStart { .. } | Op::RepeatEnd { .. } => 9,
            Op::RepeatAny { .. } => 5,
            _ => 1,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Program {
    pub ops: Vec<Op>,
    pub classes: Vec<Class>,
}

/// Forward and backward programs of one AST plus code references per node id.
#[derive(Clone, Debug)]
pub struct Compiled {
    pub fwd: Program,
    pub bwd: Program,
    pub fwd_ref: Vec<Option<u32>>,
    pub bwd_ref: Vec<Option<u32>>,
}

const DONT_SET_FWD: u8 = 1;
const DONT_SET_BWD: u8 = 2;
const BACKWARDS: u8 = 4;
const MAX_SPLIT_ID: u32 = 128;

struct Emitter<'a> {
    prog: Program,
    /// libyara byte offset of each op (plus one entry for the end).
    boff: Vec<i64>,
    next_split: u32,
    refs: &'a mut Vec<Option<u32>>,
}

type EResult<T> = Result<T, String>;

const TOO_LARGE: &str = "regular expression is too large";

impl<'a> Emitter<'a> {
    fn cur(&self) -> i64 {
        *self.boff.last().unwrap_or(&0)
    }

    fn pc(&self) -> u32 {
        self.prog.ops.len() as u32
    }

    fn emit(&mut self, op: Op) -> EResult<u32> {
        if self.prog.ops.len() >= 4_000_000 {
            return Err(TOO_LARGE.into());
        }
        let pc = self.pc();
        let end = self.cur() + op.size();
        self.prog.ops.push(op);
        self.boff.push(end);
        Ok(pc)
    }

    fn split(&mut self, a: bool) -> EResult<u32> {
        if self.next_split >= MAX_SPLIT_ID {
            return Err("regular expression is too complex".into());
        }
        let id = self.next_split as u8;
        self.next_split += 1;
        self.emit(if a { Op::SplitA { id, target: 0 } } else { Op::SplitB { id, target: 0 } })
    }

    fn off(&self, pc: u32) -> i64 {
        self.boff.get(pc as usize).copied().unwrap_or(0)
    }

    fn set_target(&mut self, at: u32, target: u32) {
        match &mut self.prog.ops[at as usize] {
            Op::SplitA { target: t, .. } | Op::SplitB { target: t, .. } => *t = target,
            Op::Jump(t) => *t = target,
            _ => {}
        }
    }

    /// Returns the pc of the node's first instruction (None if no code).
    fn node(&mut self, n: &Node, flags: u8, depth: usize) -> EResult<Option<u32>> {
        if depth > 1000 {
            return Err(TOO_LARGE.into());
        }
        let mut first: Option<u32> = None;
        match &n.kind {
            Kind::Literal => first = Some(self.emit(Op::Literal(n.value))?),
            Kind::NotLiteral => first = Some(self.emit(Op::NotLiteral(n.value))?),
            Kind::MaskedLiteral => first = Some(self.emit(Op::MaskedLiteral(n.value, n.mask))?),
            Kind::MaskedNotLiteral => first = Some(self.emit(Op::MaskedNotLiteral(n.value, n.mask))?),
            Kind::WordChar => first = Some(self.emit(Op::WordChar)?),
            Kind::NonWordChar => first = Some(self.emit(Op::NonWordChar)?),
            Kind::WordBoundary => first = Some(self.emit(Op::WordBoundary)?),
            Kind::NonWordBoundary => first = Some(self.emit(Op::NonWordBoundary)?),
            Kind::Space => first = Some(self.emit(Op::Space)?),
            Kind::NonSpace => first = Some(self.emit(Op::NonSpace)?),
            Kind::Digit => first = Some(self.emit(Op::Digit)?),
            Kind::NonDigit => first = Some(self.emit(Op::NonDigit)?),
            Kind::Any => first = Some(self.emit(Op::Any)?),
            Kind::Class(c) => {
                let idx = self.prog.classes.len() as u32;
                self.prog.classes.push((**c).clone());
                first = Some(self.emit(Op::Class(idx))?);
            }
            Kind::AnchorStart => first = Some(self.emit(Op::MatchAtStart)?),
            Kind::AnchorEnd => first = Some(self.emit(Op::MatchAtEnd)?),
            Kind::Empty => {}
            Kind::Concat(v) => {
                if flags & BACKWARDS != 0 {
                    let mut it = v.iter().rev();
                    if let Some(h) = it.next() {
                        first = self.node(h, flags, depth + 1)?;
                    }
                    for c in it {
                        self.node(c, flags, depth + 1)?;
                    }
                } else {
                    let mut it = v.iter();
                    if let Some(h) = it.next() {
                        first = self.node(h, flags, depth + 1)?;
                    }
                    for c in it {
                        self.node(c, flags, depth + 1)?;
                    }
                }
            }
            Kind::Plus(child) => {
                // L1: code for e ; split L1, L2 ; L2:
                let f = self.node(child, flags, depth + 1)?;
                let l1 = f.unwrap_or(self.pc());
                if self.off(l1) - self.cur() < i16::MIN as i64 {
                    return Err(TOO_LARGE.into());
                }
                let s = self.split(!n.greedy)?; // greedy: SPLIT_B (prefer jumping back)
                self.set_target(s, l1);
                first = f;
            }
            Kind::Star(child) => {
                // L1: split L1, L2 ; code for e ; jmp L1 ; L2:
                let s = self.split(n.greedy)?; // greedy: SPLIT_A (prefer entering)
                self.node(child, flags, depth + 1)?;
                if self.off(s) - self.cur() < i16::MIN as i64 {
                    return Err(TOO_LARGE.into());
                }
                self.emit(Op::Jump(s))?;
                if self.cur() - self.off(s) > i16::MAX as i64 {
                    return Err(TOO_LARGE.into());
                }
                let l2 = self.pc();
                self.set_target(s, l2);
                first = Some(s);
            }
            Kind::Alt(a, b) => {
                // split L1, L2 ; L1: e1 ; jmp L3 ; L2: e2 ; L3:
                let s = self.split(true)?;
                self.node(a, flags, depth + 1)?;
                let j = self.emit(Op::Jump(0))?;
                if self.cur() - self.off(s) > i16::MAX as i64 {
                    return Err(TOO_LARGE.into());
                }
                let l2 = self.pc();
                self.set_target(s, l2);
                self.node(b, flags, depth + 1)?;
                if self.cur() - self.off(j) > i16::MAX as i64 {
                    return Err(TOO_LARGE.into());
                }
                let l3 = self.pc();
                self.set_target(j, l3);
                first = Some(s);
            }
            Kind::RangeAny => {
                let op = Op::RepeatAny {
                    greedy: n.greedy,
                    min: n.start.clamp(0, u16::MAX as i32) as u16,
                    max: (n.end as u32 & 0xffff) as u16,
                };
                first = Some(self.emit(op)?);
            }
            Kind::Range(child) => {
                let (start, end) = (n.start, n.end);
                let emit_prolog = start > 0;
                let emit_repeat = end > start + 1 || end > 2;
                let emit_split = end > start;
                let emit_epilog = end > start || end > 1;
                if emit_prolog {
                    first = self.node(child, flags, depth + 1)?;
                }
                if emit_repeat {
                    let mut min = start;
                    let mut max = end;
                    if emit_prolog {
                        max -= 1;
                        min -= 1;
                    }
                    if emit_split {
                        max -= 1;
                    } else {
                        min -= 1;
                        max -= 1;
                    }
                    let (min, max) = (min.clamp(0, u16::MAX as i32) as u16, max.clamp(0, u16::MAX as i32) as u16);
                    let rs = self.emit(Op::RepeatStart { greedy: n.greedy, min, max, end: 0 })?;
                    if !emit_prolog {
                        first = Some(rs);
                    }
                    let body = self.pc();
                    self.node(child, flags | DONT_SET_FWD | DONT_SET_BWD, depth + 1)?;
                    self.emit(Op::RepeatEnd { greedy: n.greedy, min, max, body })?;
                    let after = self.pc();
                    if let Op::RepeatStart { end, .. } = &mut self.prog.ops[rs as usize] {
                        *end = after;
                    }
                }
                let mut s = None;
                if emit_split {
                    s = Some(self.split(n.greedy)?);
                }
                if emit_epilog {
                    let f = self.node(child, if emit_prolog { flags | DONT_SET_FWD } else { flags }, depth + 1)?;
                    if !(emit_prolog || emit_repeat) {
                        first = f;
                    }
                }
                if let Some(s) = s {
                    if self.cur() - self.off(s) > i16::MAX as i64 {
                        return Err(TOO_LARGE.into());
                    }
                    let l3 = self.pc();
                    self.set_target(s, l3);
                }
            }
        }
        let id = n.id as usize;
        if id < self.refs.len() {
            if flags & BACKWARDS != 0 {
                if flags & DONT_SET_BWD == 0 {
                    self.refs[id] = Some(self.pc());
                }
            } else if flags & DONT_SET_FWD == 0 {
                self.refs[id] = first;
            }
        }
        Ok(first)
    }
}

fn emit_one(ast: &Ast, backwards: bool, refs: &mut Vec<Option<u32>>) -> EResult<Program> {
    let mut e = Emitter { prog: Program::default(), boff: vec![0], next_split: 0, refs };
    e.node(&ast.root, if backwards { BACKWARDS } else { 0 }, 0)?;
    e.emit(Op::Match)?;
    Ok(e.prog)
}

pub fn compile(ast: &Ast) -> EResult<Compiled> {
    let n = ast.nodes as usize + 1;
    let mut fwd_ref = vec![None; n];
    let mut bwd_ref = vec![None; n];
    let fwd = emit_one(ast, false, &mut fwd_ref)?;
    let bwd = emit_one(ast, true, &mut bwd_ref)?;
    Ok(Compiled { fwd, bwd, fwd_ref, bwd_ref })
}
