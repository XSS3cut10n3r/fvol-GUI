//! capstone *detail mode* view of a decoded instruction: `cs_x86.operands` (type, value, size,
//! access), `cs_x86.opcode` and the register naming capstone uses in detail output.
//!
//! Everything is computed on demand from the plain [`Insn`] (raw bytes, table entry, decoded
//! operands); nothing here allocates. Register access information (implicit registers, operand
//! access flags) comes from `access.rs`.

use super::regs::{self, RFLAGS};
use super::tables::{self, Entry};
use super::{Insn, Mem, MemSize, Mode, Operand, Reg, MAX_OPS};
use std::ops::Deref;

/// capstone `CS_AC_READ`.
pub const CS_AC_READ: u8 = 1;
/// capstone `CS_AC_WRITE`.
pub const CS_AC_WRITE: u8 = 2;
/// Maximum number of capstone detail operands (`cs_x86.operands` has 8 slots).
pub const MAX_DETAIL_OPS: usize = 8;

/// One capstone x86 detail operand (`cs_x86_op`).
///
/// `op` holds the value: `Operand::Reg` (`X86_OP_REG`, `.reg`), `Operand::Imm` (`X86_OP_IMM`,
/// `.imm`; relative branch targets are absolute, like capstone) or `Operand::Mem`
/// (`X86_OP_MEM`, `.mem.segment/.base/.index/.scale/.disp`; `Mem::size` is the printed size
/// keyword and `Mem::bcst` the `{1toN}` factor). `size` / `access` are capstone's `size` and
/// `access` fields.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DetailOp {
    pub op: Operand,
    /// capstone operand `size` in bytes.
    pub size: u8,
    /// capstone operand `access`: [`CS_AC_READ`] | [`CS_AC_WRITE`] (0 when capstone has none).
    pub access: u8,
}

impl DetailOp {
    #[inline]
    pub fn is_reg(&self) -> bool {
        matches!(self.op, Operand::Reg(_))
    }
    #[inline]
    pub fn is_imm(&self) -> bool {
        matches!(self.op, Operand::Imm(_))
    }
    #[inline]
    pub fn is_mem(&self) -> bool {
        matches!(self.op, Operand::Mem(_))
    }
    /// Register of an `X86_OP_REG` operand.
    #[inline]
    pub fn reg(&self) -> Option<Reg> {
        match self.op {
            Operand::Reg(r) => Some(r),
            _ => None,
        }
    }
    /// Value of an `X86_OP_IMM` operand.
    #[inline]
    pub fn imm(&self) -> Option<i64> {
        match self.op {
            Operand::Imm(v) => Some(v),
            _ => None,
        }
    }
    /// The `X86_OP_MEM` operand (`.mem`).
    #[inline]
    pub fn mem(&self) -> Option<&Mem> {
        match self.op {
            Operand::Mem(ref m) => Some(m),
            _ => None,
        }
    }
    /// capstone `access & CS_AC_READ`.
    #[inline]
    pub fn is_read(&self) -> bool {
        self.access & CS_AC_READ != 0
    }
    /// capstone `access & CS_AC_WRITE`.
    #[inline]
    pub fn is_written(&self) -> bool {
        self.access & CS_AC_WRITE != 0
    }
}

/// capstone's `insn.operands` (x86 detail), a fixed-capacity list (no allocation).
/// Dereferences to `&[DetailOp]`.
#[derive(Clone, Copy, Debug, Default)]
pub struct DetailOps {
    pub(crate) n: u8,
    pub(crate) ops: [DetailOp; MAX_DETAIL_OPS],
}

impl DetailOps {
    #[inline]
    pub(crate) fn push(&mut self, op: DetailOp) {
        if (self.n as usize) < MAX_DETAIL_OPS {
            self.ops[self.n as usize] = op;
            self.n += 1;
        }
    }
    #[inline]
    pub(crate) fn insert(&mut self, at: usize, op: DetailOp) {
        let n = self.n as usize;
        if n < MAX_DETAIL_OPS && at <= n {
            self.ops.copy_within(at..n, at + 1);
            self.ops[at] = op;
            self.n += 1;
        }
    }
    #[inline]
    pub(crate) fn remove(&mut self, at: usize) {
        let n = self.n as usize;
        if at < n {
            self.ops.copy_within(at + 1..n, at);
            self.ops[n - 1] = DetailOp::default();
            self.n -= 1;
        }
    }
}

impl Deref for DetailOps {
    type Target = [DetailOp];
    #[inline]
    fn deref(&self) -> &[DetailOp] {
        &self.ops[..self.n as usize]
    }
}

// ------------------------------------------------------------------------------------ prefixes

/// Legacy prefixes / REX as seen by the decoder (derived from the raw bytes).
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct Prefixes {
    pub has66: bool,
    pub has67: bool,
    /// Last segment override prefix byte (0 if none).
    pub seg: u8,
    /// Last of F0 / F2 / F3 (0 if none).
    pub lockrep: u8,
    /// Effective REX byte (0 if none).
    pub rex: u8,
    /// Index of the first opcode (or VEX/EVEX/XOP escape) byte.
    pub op: usize,
}

/// Scan the prefixes exactly like the decoder does (a REX byte only counts when it immediately
/// precedes the opcode).
pub(crate) fn prefixes(insn: &Insn) -> Prefixes {
    let d = insn.raw();
    let m64 = insn.mode == Mode::X86_64;
    let mut p = Prefixes::default();
    let mut i = 0usize;
    while i < d.len() {
        let b = d[i];
        match b {
            0xF0 | 0xF2 | 0xF3 => p.lockrep = b,
            0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => p.seg = b,
            0x66 => p.has66 = true,
            0x67 => p.has67 = true,
            0x40..=0x4F if m64 => {
                let mut j = i + 1;
                while j < d.len() && d[j] & 0xF0 == 0x40 {
                    j += 1;
                }
                if j < d.len()
                    && matches!(d[j], 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 | 0x67)
                {
                    i = j;
                    continue;
                }
                p.rex = d[j - 1];
                p.op = j;
                return p;
            }
            _ => break,
        }
        i += 1;
    }
    p.op = i;
    p
}

/// Vector-extension escape used by the instruction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum VexKind {
    None,
    Vex2,
    Vex3,
    Evex,
    Xop,
}

pub(crate) fn vex_kind(insn: &Insn, p: &Prefixes) -> VexKind {
    let d = insn.raw();
    let m64 = insn.mode == Mode::X86_64;
    let (Some(&b), Some(&nb)) = (d.get(p.op), d.get(p.op + 1)) else {
        return VexKind::None;
    };
    match b {
        0xC4 | 0xC5 | 0x62 if m64 || nb & 0xC0 == 0xC0 => match b {
            0xC4 => VexKind::Vex3,
            0xC5 => VexKind::Vex2,
            _ => VexKind::Evex,
        },
        0x8F if nb & 0x38 != 0 => VexKind::Xop,
        _ => VexKind::None,
    }
}

// ------------------------------------------------------------------------------------ opcode

/// capstone's `cs_x86.opcode` for this instruction: the opcode bytes after the prefixes
/// (`[op]`, `[0f, op]`, `[0f, 38|3a, op]`), for 3DNow! `[0f, suffix]`, and for VEX / XOP / EVEX
/// the raw escape bytes (`[c5, P0]`, `[c4|8f, P0, P1]`, `[62, P0, P1, P2]`), zero padded.
pub(crate) fn capstone_opcode(insn: &Insn) -> [u8; 4] {
    let d = insn.raw();
    let p = prefixes(insn);
    let at = |k: usize| d.get(p.op + k).copied().unwrap_or(0);
    match vex_kind(insn, &p) {
        VexKind::Vex2 => return [0xC5, at(1), 0, 0],
        VexKind::Vex3 => return [0xC4, at(1), at(2), 0],
        VexKind::Xop => return [0x8F, at(1), at(2), 0],
        VexKind::Evex => return [0x62, at(1), at(2), at(3)],
        VexKind::None => {}
    }
    let b = at(0);
    if b != 0x0F {
        return [b, 0, 0, 0];
    }
    match at(1) {
        // capstone drops the 38 / 3a escape
        0x38 | 0x3A => [0x0F, at(2), 0, 0],
        0x0F => [0x0F, d.last().copied().unwrap_or(0), 0, 0],
        b2 => [0x0F, b2, 0, 0],
    }
}

// ------------------------------------------------------------------------------------ operands

/// Table entry of a decoded instruction.
#[inline]
pub(crate) fn entry(insn: &Insn) -> Option<&'static Entry> {
    tables::tables().entries.get(insn.entry as usize)
}

/// capstone register operand size.
pub(crate) fn reg_size(r: Reg, mode: Mode) -> u8 {
    let m64 = mode == Mode::X86_64;
    match r.0 {
        // capstone's 32-bit size table: cr0..cr4 and dr0..dr15 are 4 bytes, cr5..cr15 8
        regs::CR0..=109 => {
            if m64 || (r.0 >= regs::CR0 + 5 && r.0 < regs::DR0) {
                8
            } else {
                4
            }
        }
        regs::K0..=229 => 2,
        regs::BND0..=233 => 16,
        _ => r.size(),
    }
}

/// Size capstone reports for a memory operand without a printed size keyword.
fn bare_mem_size(insn: &Insn, p: &Prefixes, ops: &[Operand]) -> u8 {
    let m64 = insn.mode == Mode::X86_64;
    let native = if m64 { 8 } else { 4 };
    match insn.base_mnemonic() {
        "lea" => ops.first().map_or(0, |o| match *o {
            Operand::Reg(r) => r.size(),
            _ => 0,
        }),
        // far indirect jmp / call (FF /5, FF /3); "ljmp" / "lcall" when 66 / REX.W is present
        "jmp" => {
            if m64 {
                8
            } else {
                6
            }
        }
        "call" => native,
        "ljmp" | "lcall" => {
            if m64 {
                10
            } else {
                6
            }
        }
        "les" | "lds" | "lss" | "lfs" | "lgs" | "fxsave" | "fxrstor" | "fxsave64" | "fxrstor64" | "xsave"
        | "xrstor" | "xsaves" | "xrstors" | "xsavec" | "xsaveopt" | "xsave64" | "xrstor64" | "xsaves64"
        | "xrstors64" | "xsavec64" | "xsaveopt64" => native,
        "fnstenv" | "fldenv" | "fstenv" => 28,
        "sgdt" | "sidt" | "lgdt" | "lidt" => {
            if m64 {
                10
            } else {
                6
            }
        }
        "bndldx" | "bndstx" => 16,
        _ => {
            let _ = p;
            0
        }
    }
}

/// Build capstone's detail operand list (access flags are filled in by `access.rs`).
pub(crate) fn cs_operands(insn: &Insn) -> DetailOps {
    let mut out = DetailOps::default();
    let ops = insn.ops();
    let e = entry(insn);
    let p = prefixes(insn);
    let m64 = insn.mode == Mode::X86_64;
    let rexw = p.rex & 8 != 0;
    // capstone's size for branch targets / ret imm16 / enter
    let branch_size: u8 = if m64 {
        if p.has66 || rexw { 4 } else { 8 }
    } else if p.has66 {
        2
    } else {
        4
    };
    let mut op0_size = 0u8;
    let mut k = 0usize;
    while k < ops.len().min(MAX_OPS) {
        let o = &ops[k];
        let spec = e.and_then(|e| e.ops.get(k)).copied().unwrap_or_default();
        if spec.src == tables::S_FARPTR {
            // ptr16:16 / ptr16:32: selector (2 bytes) then offset (always reported as 4)
            out.push(DetailOp { op: *o, size: 2, access: 0 });
            if let Some(o2) = ops.get(k + 1) {
                out.push(DetailOp { op: *o2, size: 4, access: 0 });
            }
            k += 2;
            continue;
        }
        let size = match *o {
            Operand::None => {
                k += 1;
                continue;
            }
            Operand::Reg(r) => reg_size(r, insn.mode),
            Operand::Mem(ref m) => {
                if m.size == MemSize::None || m.size == MemSize::Ptr {
                    bare_mem_size(insn, &p, ops)
                } else {
                    m.size.bytes()
                }
            }
            Operand::Imm(_) => {
                let first = out.n == 0 || out.ops[0].is_imm();
                if spec.src == tables::S_REL {
                    branch_size
                } else if spec.src != tables::S_IMM {
                    // literal 1 of shifts
                    if first { 1 } else { op0_size }
                } else if first {
                    match spec.cls {
                        tables::I_U8 if out.n == 0 => 1,
                        tables::I_U16 | tables::I_S16 | tables::I_W4 => branch_size,
                        tables::I_S8N | tables::I_ZN => {
                            if p.has66 {
                                2
                            } else if m64 {
                                8
                            } else {
                                4
                            }
                        }
                        _ => {
                            if out.n > 0 {
                                op0_size
                            } else if m64 {
                                if p.has66 { 2 } else { 8 }
                            } else if p.has66 {
                                2
                            } else {
                                4
                            }
                        }
                    }
                } else if spec.cls == tables::I_U8 {
                    1
                } else {
                    op0_size
                }
            }
        };
        if out.n == 0 {
            op0_size = size;
        }
        out.push(DetailOp { op: *o, size, access: 0 });
        k += 1;
    }
    match insn.base_mnemonic() {
        // capstone keeps the implicit ST(0) as the first operand
        "fxch" if out.n == 1 => {
            out.insert(0, DetailOp { op: Operand::Reg(Reg(regs::ST0)), size: 10, access: 0 });
        }
        // legacy-SSE forms with an implicit xmm0 (printed, but not a detail operand)
        "pblendvb" | "blendvps" | "blendvpd" | "sha256rnds2" if out.n == 3 => out.remove(2),
        // D0 /2, D1 /2 on memory: "rcl m" has a hidden literal 1
        "rcl" if out.n == 1 && out.ops[0].is_mem() => {
            out.push(DetailOp { op: Operand::Imm(1), size: 0, access: 0 });
        }
        _ => {}
    }
    // EVEX opmask: capstone lists {kN} as a separate operand right after the destination.
    if insn.evex & 0x80 != 0 && out.n > 0 {
        out.insert(1, DetailOp { op: Operand::Reg(Reg(regs::K0 + (insn.evex & 7))), size: 2, access: 0 });
    }
    out
}

/// capstone's name for `r` in detail output (`cs_reg_name`): like [`Reg::name`], except that
/// the flags register is "eflags" in 32-bit mode and "rflags" in 64-bit mode.
#[inline]
pub fn reg_name(r: Reg, mode: Mode) -> &'static str {
    if r.0 == RFLAGS && mode == Mode::X86_32 { "eflags" } else { r.name() }
}

impl Insn {
    /// capstone's `insn.opcode` (x86 detail `opcode[4]`). Unlike the decoder's `opcode` field
    /// this reproduces capstone for VEX/EVEX/XOP (raw escape bytes) and 3DNow! (`[0f, suffix]`).
    #[inline]
    pub fn capstone_opcode(&self) -> [u8; 4] {
        capstone_opcode(self)
    }
    /// python `inst.opcode.count(0) == len(inst.opcode)`: all four capstone opcode bytes are 0
    /// (only `add r/m8, r8` = `00 /r` has that).
    #[inline]
    pub fn opcode_all_zero(&self) -> bool {
        self.capstone_opcode() == [0; 4]
    }
    /// capstone's register name in this instruction's mode (`inst.reg_name(r)`), see
    /// [`reg_name`].
    #[inline]
    pub fn reg_name(&self, r: Reg) -> &'static str {
        reg_name(r, self.mode)
    }
}
