//! Table-driven x86 / x86-64 decoder producing capstone-5-identical Intel syntax.
//!
//! * `decode()` fills a plain `Copy` [`Insn`] (no heap allocation); text is produced only on
//!   demand by [`Insn::write_mnemonic`] / [`Insn::write_op_str`] into a caller-provided String.
//! * Opcode tables are compiled once (lazily) from a compact textual spec (`spec_*.rs`) into
//!   dense per-map `[u32; 256]` roots plus small decision nodes (prefix / W / L / mod / reg / rm
//!   / operand-size selectors), so decoding is a handful of indexed loads per instruction.

mod decode;
mod format;
pub mod regs;
mod spec_legacy;
mod spec_sse;
mod spec_vex;
mod spec_evex;
mod tables;

pub use regs::Reg;

/// CPU mode.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Mode {
    /// 32-bit protected mode (capstone `CS_MODE_32`, volatility "intel").
    X86_32,
    /// 64-bit long mode (capstone `CS_MODE_64`, volatility "intel64").
    X86_64,
}

/// Memory operand size keyword as printed by capstone ("dword ptr" ...).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u8)]
pub enum MemSize {
    /// No keyword at all (`lea`, `lgdt`, ...).
    #[default]
    None = 0,
    /// Just "ptr" (opaque memory, e.g. `call ptr [rax]`).
    Ptr,
    Byte,
    Word,
    Dword,
    Qword,
    /// 80-bit BCD (`fbld tbyte ptr`).
    Tbyte,
    /// 80-bit float (`fld xword ptr`).
    Xword,
    Xmmword,
    Ymmword,
    Zmmword,
}

impl MemSize {
    /// Operand size in bytes (0 when unknown / opaque).
    pub fn bytes(self) -> u8 {
        match self {
            MemSize::None | MemSize::Ptr => 0,
            MemSize::Byte => 1,
            MemSize::Word => 2,
            MemSize::Dword => 4,
            MemSize::Qword => 8,
            MemSize::Tbyte | MemSize::Xword => 10,
            MemSize::Xmmword => 16,
            MemSize::Ymmword => 32,
            MemSize::Zmmword => 64,
        }
    }
}

/// A memory operand: `size ptr seg:[base + index*scale + disp]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Mem {
    /// Segment override (only set when a segment prefix applies), else `Reg::NONE`.
    pub segment: Reg,
    /// Base register (`rip`/`eip` for RIP-relative), or `Reg::NONE`.
    pub base: Reg,
    /// Index register or `Reg::NONE`.
    pub index: Reg,
    /// 1, 2, 4 or 8.
    pub scale: u8,
    /// Printed size keyword.
    pub size: MemSize,
    /// EVEX embedded broadcast factor (`{1toN}`), 0 when none.
    pub bcst: u8,
    /// Displacement (sign-extended).
    pub disp: i64,
}

/// A decoded operand (Intel operand order, destination first).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Operand {
    #[default]
    None,
    Reg(Reg),
    /// Immediate. For relative branches this is the absolute target address.
    Imm(i64),
    Mem(Mem),
}

/// Maximum number of explicit operands.
pub const MAX_OPS: usize = 5;

/// A decoded instruction. Plain data; formatting is done on demand.
#[derive(Clone, Copy, Debug)]
pub struct Insn {
    pub address: u64,
    /// Length in bytes (1..=15).
    pub size: u8,
    pub mode: Mode,
    /// Raw instruction bytes (`bytes[..size]`).
    pub bytes: [u8; 15],
    pub op_count: u8,
    pub operands: [Operand; MAX_OPS],
    /// Mnemonic id (index into the mnemonic table).
    pub(crate) mnem: u16,
    /// Printed prefix combination id (see `format::PREFIX_STR`).
    pub(crate) pfx: u8,
    /// Per operand printing flags (see `format`).
    pub(crate) ofmt: [u8; MAX_OPS],
    /// EVEX opmask register number (0 = none printed unless `evex_k_printed`).
    pub(crate) evex: u8,
    /// EVEX rounding / sae decoration (0 = none).
    pub(crate) sae: u8,
    /// Table entry index (for access info).
    pub(crate) entry: u16,
    /// Opcode bytes as capstone's `insn.opcode` (x86 detail).
    pub opcode: [u8; 4],
    /// REX prefix byte (0 if none).
    pub rex: u8,
}

impl Default for Insn {
    fn default() -> Self {
        Insn {
            address: 0,
            size: 0,
            mode: Mode::X86_64,
            bytes: [0; 15],
            op_count: 0,
            operands: [Operand::None; MAX_OPS],
            mnem: 0,
            pfx: 0,
            ofmt: [0; MAX_OPS],
            evex: 0,
            sae: 0,
            entry: 0,
            opcode: [0; 4],
            rex: 0,
        }
    }
}

impl Insn {
    /// Instruction bytes.
    #[inline]
    pub fn raw(&self) -> &[u8] {
        &self.bytes[..self.size as usize]
    }
    /// Explicit operands.
    #[inline]
    pub fn ops(&self) -> &[Operand] {
        &self.operands[..self.op_count as usize]
    }
    /// The base mnemonic without printed prefixes (e.g. "movsb" for "rep movsb").
    #[inline]
    pub fn base_mnemonic(&self) -> &'static str {
        tables::tables().mnems[self.mnem as usize]
    }
    /// capstone's full mnemonic (with printed prefixes such as "rep ", "lock ", "bnd ").
    pub fn mnemonic(&self) -> String {
        let mut s = String::new();
        self.write_mnemonic(&mut s);
        s
    }
    /// capstone's operand string.
    pub fn op_str(&self) -> String {
        let mut s = String::new();
        self.write_op_str(&mut s);
        s
    }
    /// Append the mnemonic to `out`.
    #[inline]
    pub fn write_mnemonic(&self, out: &mut String) {
        format::write_mnemonic(self, out)
    }
    /// Append the operand string to `out`.
    #[inline]
    pub fn write_op_str(&self, out: &mut String) {
        format::write_op_str(self, out)
    }
    /// Address of the next instruction.
    #[inline]
    pub fn next_address(&self) -> u64 {
        self.address.wrapping_add(self.size as u64)
    }
    /// True if the instruction's full mnemonic equals `m` (without allocating).
    pub fn mnemonic_is(&self, m: &str) -> bool {
        let p = format::PREFIX_STR[self.pfx as usize];
        let b = self.base_mnemonic();
        m.len() == p.len() + b.len() && m.starts_with(p) && m.ends_with(b)
    }
}

/// Decode one instruction at the start of `data`, located at `address`.
/// Returns `None` where capstone would fail to decode (invalid / truncated).
#[inline]
pub fn decode(data: &[u8], address: u64, mode: Mode) -> Option<Insn> {
    let mut insn = Insn::default();
    if decode::decode_into(data, address, mode, &mut insn) { Some(insn) } else { None }
}

/// Decode into an existing `Insn` (avoids re-initialising it); returns false if invalid.
#[inline]
pub fn decode_into(data: &[u8], address: u64, mode: Mode, insn: &mut Insn) -> bool {
    decode::decode_into(data, address, mode, insn)
}

/// Length of the instruction at the start of `data` (0 if invalid), without building operands
/// text. (Operand structures are still decoded; this is the same work as `decode`.)
#[inline]
pub fn insn_len(data: &[u8], mode: Mode) -> usize {
    let mut insn = Insn::default();
    if decode::decode_into(data, 0, mode, &mut insn) { insn.size as usize } else { 0 }
}

/// Iterator over consecutive instructions, stopping at the first undecodable one
/// (exactly like capstone's `Cs.disasm`).
pub struct Iter<'a> {
    data: &'a [u8],
    pos: usize,
    addr: u64,
    mode: Mode,
}

impl<'a> Iter<'a> {
    pub fn new(data: &'a [u8], address: u64, mode: Mode) -> Self {
        Iter { data, pos: 0, addr: address, mode }
    }
    /// Offset (into the data) of the next instruction to decode / where decoding stopped.
    pub fn offset(&self) -> usize {
        self.pos
    }
}

impl Iterator for Iter<'_> {
    type Item = Insn;
    #[inline]
    fn next(&mut self) -> Option<Insn> {
        if self.pos >= self.data.len() {
            return None;
        }
        let insn = decode(&self.data[self.pos..], self.addr, self.mode)?;
        self.pos += insn.size as usize;
        self.addr = self.addr.wrapping_add(insn.size as u64);
        Some(insn)
    }
}

/// Append `addr` formatted like python's `f"{addr:#x}"`.
#[inline]
pub fn push_addr(out: &mut String, addr: u64) {
    format::push_hex(out, addr)
}

/// `capstone.Cs(...).disasm(data, address)` equivalent.
pub fn disasm(data: &[u8], address: u64, mode: Mode) -> Iter<'_> {
    Iter::new(data, address, mode)
}
