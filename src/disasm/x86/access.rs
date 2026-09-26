//! capstone detail-mode register access (`cs_regs_access`) for the x86 decoder.
//! (placeholder, rules filled in below)

use super::detail::{self, DetailOps};
use super::{Insn, Mode, Reg};
use std::ops::Deref;

/// Capacity of a [`RegList`] (capstone's `cs_regs` holds 64; x86 never needs more than ~20).
pub const MAX_REGS: usize = 32;

/// A small fixed-capacity register list in capstone order (no allocation). Dereferences to
/// `&[Reg]`; [`RegList::name`] gives capstone's (mode aware) names.
#[derive(Clone, Copy, Debug)]
pub struct RegList {
    n: u8,
    mode: Mode,
    regs: [Reg; MAX_REGS],
}

impl RegList {
    #[inline]
    pub(crate) fn new(mode: Mode) -> Self {
        RegList { n: 0, mode, regs: [Reg::NONE; MAX_REGS] }
    }
    #[inline]
    pub(crate) fn push(&mut self, r: Reg) {
        if (self.n as usize) < MAX_REGS {
            self.regs[self.n as usize] = r;
            self.n += 1;
        }
    }
    #[inline]
    pub(crate) fn push_unique(&mut self, r: Reg) {
        if !self.contains(r) {
            self.push(r);
        }
    }
    /// True if `r` is in the list.
    #[inline]
    pub fn contains(&self, r: Reg) -> bool {
        self.regs[..self.n as usize].contains(&r)
    }
    /// True if a register named `name` (capstone naming, e.g. "rax", "r10", "eflags") is in the
    /// list.
    pub fn contains_name(&self, name: &str) -> bool {
        self.iter().any(|&r| detail::reg_name(r, self.mode) == name)
    }
    /// capstone's name of the `i`-th register ("" if out of range).
    pub fn name(&self, i: usize) -> &'static str {
        self.get(i).map_or("", |&r| detail::reg_name(r, self.mode))
    }
    /// Iterator over capstone's names.
    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        let mode = self.mode;
        self.iter().map(move |&r| detail::reg_name(r, mode))
    }
}

impl Deref for RegList {
    type Target = [Reg];
    #[inline]
    fn deref(&self) -> &[Reg] {
        &self.regs[..self.n as usize]
    }
}

/// Detail operands with access flags plus capstone's implicit register lists.
pub(crate) struct Info {
    pub ops: DetailOps,
    pub read: RegList,
    pub write: RegList,
}

pub(crate) fn info(insn: &Insn) -> Info {
    let ops = detail::cs_operands(insn);
    Info { ops, read: RegList::new(insn.mode), write: RegList::new(insn.mode) }
}

impl Insn {
    /// capstone's detail operands (`insn.operands`), including `size` and `access`.
    pub fn detail_operands(&self) -> DetailOps {
        info(self).ops
    }
    /// capstone's implicit registers (`insn.regs_read`, `insn.regs_write`).
    pub fn implicit_regs(&self) -> (RegList, RegList) {
        let i = info(self);
        (i.read, i.write)
    }
    /// capstone's `insn.regs_access()` -> (regs_read, regs_write).
    pub fn regs_access(&self) -> (RegList, RegList) {
        let i = info(self);
        let (mut r, mut w) = (i.read, i.write);
        for o in i.ops.iter() {
            match o.op {
                super::Operand::Reg(x) => {
                    if o.access & detail::CS_AC_READ != 0 {
                        r.push_unique(x);
                    }
                    if o.access & detail::CS_AC_WRITE != 0 {
                        w.push_unique(x);
                    }
                }
                super::Operand::Mem(m) => {
                    // capstone does not de-duplicate segment registers
                    if !m.segment.is_none() {
                        r.push(m.segment);
                    }
                    if !m.base.is_none() {
                        r.push_unique(m.base);
                    }
                    if !m.index.is_none() {
                        r.push_unique(m.index);
                    }
                }
                _ => {}
            }
        }
        (r, w)
    }
}
