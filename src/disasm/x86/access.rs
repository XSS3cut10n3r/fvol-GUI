//! capstone *detail mode* for the x86 decoder: `regs_access()`, implicit registers, detail
//! operands (with `size` / `access`) and `insn.opcode`, matching capstone 5.0.7 (`md.detail =
//! True`) exactly on real code (0 mismatches over 1.74M unique instructions of Windows / Linux
//! binaries, both modes; see `examples/disasm_detail_diff.rs`).
//!
//! # API (all allocation free; everything is computed on demand from a decoded [`Insn`])
//!
//! | capstone (python)                     | rsvol                                               |
//! |---------------------------------------|-----------------------------------------------------|
//! | `inst.regs_access()` -> (read, write) | `insn.regs_access()` -> `(RegList, RegList)`        |
//! | `inst.regs_read` / `inst.regs_write`  | `insn.implicit_regs()` -> `(RegList, RegList)`      |
//! | `inst.reg_name(r)`                    | `insn.reg_name(r)` / `list.name(i)` / `list.names()`|
//! | `inst.reg_name(r) == "rax"` for any r | `list.contains_name("rax")`, `insn.regs_written_contains("rax")` |
//! | `inst.operands` (x86 detail)          | `insn.detail_operands()` -> `DetailOps` (`&[DetailOp]`) |
//! | `op.type` / `.reg` / `.imm` / `.mem`  | `op.op` (`Operand::Reg/Imm/Mem`), `op.reg()`, `op.imm()`, `op.mem()` |
//! | `op.size` / `op.access`               | `op.size` / `op.access` (`CS_AC_READ` / `CS_AC_WRITE`) |
//! | `inst.opcode`                         | `insn.capstone_opcode()`; all zero: `insn.opcode_all_zero()` |
//!
//! Register names follow capstone, including its mode-dependent name of the flags register:
//! "eflags" in 32-bit mode, "rflags" in 64-bit mode. `regs_access()` is capstone's
//! `X86_reg_access`: implicit registers first, then the operands in order (registers by their
//! access flags, memory operands' segment / base / index as read), de-duplicated except for
//! segment registers (`cmpsb byte ptr es:[esi], byte ptr es:[edi]` reads "es" twice). Capstone
//! quirks are reproduced, e.g. `test eax, imm` (A9) lists eax as written, `test [m], r` (84/85)
//! reads nothing and writes no flags, `push ax` in 64-bit mode uses "esp".
//!
//! # Porting the capstone-using plugins
//!
//! `windows.malware.direct_system_calls._is_syscall_block` (and `indirect_system_calls`, which
//! reuses it with other `invalid_ops` / `termination_ops`):
//! ```text
//! for insn in x86::disasm(data, address, mode) {           // md.disasm, stops at invalid bytes
//!     // disasm_bytes += f"{inst.address:#x}: {inst.mnemonic} {inst.op_str}; "
//!     x86::push_addr(&mut s, insn.address); s.push_str(": ");
//!     insn.write_mnemonic(&mut s); s.push(' '); insn.write_op_str(&mut s); s.push_str("; ");
//!     if insn.opcode_all_zero() { break }                  // inst.opcode.count(0) == len(...)
//!     // `op in [...]` compares the FULL mnemonic: "bnd jmp" / "rep ret" are not "jmp" / "ret"
//!     if invalid_ops.iter().any(|m| insn.mnemonic_is(m)) { break }
//!     else if termination_ops.iter().any(|m| insn.mnemonic_is(m)) { end = Some(insn); break }
//!     else if insn.mnemonic_is("syscall") { ... }
//!     else {
//!         // `except capstone.CsError: continue` is dead code: with detail on, cs_regs_access only
//!         // fails for SKIPDATA pseudo-instructions or diet builds, which md.disasm never yields.
//!         let (_, w) = insn.regs_access();                 // compute once, test the list
//!         // python's per-register `if reg in ["eax","rax"]: ... elif reg == "r10": ...` is two
//!         // independent tests over the list (one register is never both)
//!         if w.contains_name("eax") || w.contains_name("rax") { found_movreax = true }
//!         if w.contains_name("r10") { found_movr10 = true }
//!     }
//! }
//! ```
//! `indirect_system_calls._indirect_syscall_block_target` only reads 6 raw bytes from the layer
//! at `inst.address` (no disassembler detail needed).
//!
//! `windows.skeleton_key_check._get_rip_relative_target` (64-bit, detail on):
//! ```text
//! fn rip_relative_target(insn: &Insn) -> Option<u64> {
//!     let ops = insn.detail_operands();
//!     // python: inst.operands[1] raises IndexError (not CsError) with < 2 operands; mov / lea,
//!     // the only callers, always have 2 detail operands
//!     let m = ops.get(1)?.mem()?;                          // opnd.type != X86_OP_MEM -> None
//!     if insn.reg_name(m.base) != "rip" { return None }    // reg_name(0) is None != "rip"
//!     // python ints do not wrap: outside [0, 2^64) the layer read raises -> treat as unreadable
//!     let t = insn.address as i128 + insn.size as i128 + m.disp as i128;
//!     u64::try_from(t).ok()
//! }
//! ```
//! and in `_analyze_cdlocatecsystem` compare full mnemonics (`insn.mnemonic_is("int3")`,
//! `"mov"`, `"lea"`); note `if target_address:` treats a target of 0 as "not found".
//!
//! `linux.malware.check_syscall._get_table_info_disassembly` compares `mnemonic == "CMP"`, which
//! is never true (capstone mnemonics are lowercase), so it always returns 0 and the plugin falls
//! back to `_get_table_info_other`: port it as `0` without disassembling anything.
//!
//! # How it works
//!
//! capstone's answer is "implicit registers of the LLVM opcode" + "explicit operands according to
//! their access flags"; both come from capstone's per-LLVM-opcode tables. We reproduce them with a
//! compact rule spec (`access_spec.rs`) keyed by our mnemonic and refined, only where capstone's
//! LLVM opcodes differ, by operand signature, printed prefix, mode, mandatory-prefix / EVEX
//! context, address size or opcode. The spec is learned from capstone's own detail output
//! (`examples/disasm_detail_diff.rs learn` over real code, opcode sweeps, random bytes and
//! EVEX / compare-predicate mutations) and compiled once into flat arrays; a lookup is an index by
//! mnemonic id plus a scan over a handful of rules. Mnemonics without rules (rare AVX-512 / XOP
//! forms capstone decodes differently) use a heuristic (destination written, sources read).
//!
//! Not reproduced: capstone detail fields other than the above (`prefix`, `rex`, `addr_size`,
//! `modrm`, `sib*`, `disp`, `*_cc`, `avx_sae`, `avx_rm`, `eflags`, operand `avx_bcast` /
//! `avx_zero_opmask`, `groups`), and values capstone reads from uninitialised memory (some
//! AVX-512 access flags come out as 253 / 255, `bndmk`'s memory size changes between runs).

use super::detail::{self, DetailOp, DetailOps, Prefixes};
use super::regs::{self, RFLAGS};
use super::{Insn, Mode, Operand, Reg};
use std::ops::Deref;
use std::sync::OnceLock;

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
    pub(crate) fn reset(&mut self, mode: Mode) {
        self.n = 0;
        self.mode = mode;
    }
    /// Replace the contents with the first `n` of a template's fixed-size register array
    /// (fixed-size copy: no memcpy call).
    #[inline]
    fn set_fixed(&mut self, mode: Mode, regs: &[Reg; TPL_REGS], n: u8) {
        self.regs[..TPL_REGS].copy_from_slice(regs);
        self.n = n.min(TPL_REGS as u8);
        self.mode = mode;
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

// ------------------------------------------------------------------------------------ features

/// Operand signature token of a detail operand: `r1 r2 r4 r8` (GPRs), `rs rc rd rf rq rx ry
/// rz rk rb rp` (segment, control, debug, x87, mmx, xmm, ymm, zmm, mask, bound, ip),
/// `m<size>` (memory), `i<size>` (immediate).
pub(crate) fn op_code(o: &DetailOp) -> u16 {
    match o.op {
        Operand::Reg(r) => 0x100 | reg_class(r) as u16,
        Operand::Mem(_) => 0x200 | o.size as u16,
        Operand::Imm(_) => 0x300 | o.size as u16,
        Operand::None => 0,
    }
}

fn reg_class(r: Reg) -> u8 {
    // last id of each contiguous register class (see regs.rs)
    const GPR8_END: u8 = regs::AX - 1;
    const GPR16_END: u8 = regs::EAX - 1;
    const GPR32_END: u8 = regs::RAX - 1;
    const GPR64_END: u8 = regs::RAX + 15;
    const SEG_END: u8 = regs::ES + 5;
    const CR_END: u8 = regs::CR0 + 15;
    const DR_END: u8 = regs::DR0 + 15;
    const ST_END: u8 = regs::ST0 + 7;
    const MM_END: u8 = regs::MM0 + 7;
    const XMM_END: u8 = regs::XMM0 + 31;
    const YMM_END: u8 = regs::YMM0 + 31;
    const ZMM_END: u8 = regs::ZMM0 + 31;
    const K_END: u8 = regs::K0 + 7;
    const BND_END: u8 = regs::BND0 + 3;
    match r.0 {
        regs::AL..=GPR8_END => 1,
        regs::AX..=GPR16_END => 2,
        regs::EAX..=GPR32_END => 4,
        regs::RAX..=GPR64_END => 8,
        regs::ES..=SEG_END => b's',
        regs::CR0..=CR_END => b'c',
        regs::DR0..=DR_END => b'd',
        regs::ST0..=ST_END => b'f',
        regs::MM0..=MM_END => b'q',
        regs::XMM0..=XMM_END => b'x',
        regs::YMM0..=YMM_END => b'y',
        regs::ZMM0..=ZMM_END => b'z',
        regs::K0..=K_END => b'k',
        regs::BND0..=BND_END => b'b',
        _ => b'p',
    }
}

/// Text form of [`op_code`].
pub(crate) fn op_token(code: u16) -> String {
    match code >> 8 {
        1 => {
            let c = (code & 0xFF) as u8;
            if c <= 8 { format!("r{c}") } else { format!("r{}", c as char) }
        }
        2 => format!("m{}", code & 0xFF),
        3 => format!("i{}", code & 0xFF),
        _ => "?".to_string(),
    }
}

fn parse_op_token(t: &str) -> Option<u16> {
    let b = t.as_bytes();
    match b.first()? {
        b'r' => {
            let rest = &t[1..];
            if let Ok(n) = rest.parse::<u8>() {
                Some(0x100 | n as u16)
            } else if rest.len() == 1 {
                Some(0x100 | rest.as_bytes()[0] as u16)
            } else {
                None
            }
        }
        b'm' => Some(0x200 | t[1..].parse::<u8>().ok()? as u16),
        b'i' => Some(0x300 | t[1..].parse::<u8>().ok()? as u16),
        _ => None,
    }
}

/// Printed-prefix feature (the decoder's printed prefix id).
fn pfx_token(id: u8) -> &'static str {
    match id {
        0 => "-",
        1 => "lock",
        2 => "rep",
        3 => "repe",
        4 => "repne",
        5 => "bnd",
        6 => "repz",
        7 => "notrack",
        8 => "bnd_notrack",
        9 => "xacquire_lock",
        10 => "xrelease_lock",
        11 => "xacquire",
        12 => "xrelease",
        _ => "?",
    }
}

fn parse_pfx(t: &str) -> Option<u8> {
    (0..13u8).find(|&i| pfx_token(i) == t)
}

fn asz(insn: &Insn, p: &Prefixes) -> u8 {
    match (insn.mode, p.has67) {
        (Mode::X86_64, false) => 8,
        (Mode::X86_64, true) | (Mode::X86_32, false) => 4,
        (Mode::X86_32, true) => 2,
    }
}

/// Opcode feature: the decoder's opcode bytes (trailing zeros trimmed, at least one byte) and
/// ModRM.reg when the instruction has a ModRM byte. Packed as `bytes << 4 | reg` (reg 8 = none).
fn opc_key(insn: &Insn, p: &Prefixes) -> u32 {
    let o = insn.opcode;
    let packed = (o[0] as u32) << 16 | (o[1] as u32) << 8 | o[2] as u32;
    let has_modrm = detail::entry(insn).is_some_and(|e| e.flags & super::tables::F_MODRM != 0);
    let reg = if has_modrm {
        // ModRM follows the opcode bytes (VEX/EVEX/XOP: after the escape + payload + opcode)
        let d = insn.raw();
        let len = match detail::vex_kind(insn, p) {
            detail::VexKind::Vex2 => 3,
            detail::VexKind::Vex3 | detail::VexKind::Xop => 4,
            detail::VexKind::Evex => 5,
            detail::VexKind::None => {
                if o[0] == 0x0F {
                    if o[1] == 0x38 || o[1] == 0x3A { 3 } else { 2 }
                } else {
                    1
                }
            }
        };
        d.get(p.op + len).map_or(8, |m| (m >> 3) as u32 & 7)
    } else {
        8
    };
    packed << 4 | reg
}

fn opc_token(key: u32) -> String {
    let b = [(key >> 20) as u8, (key >> 12) as u8, (key >> 4) as u8];
    let n = if b[2] != 0 {
        3
    } else if b[1] != 0 {
        2
    } else {
        1
    };
    let mut s: String = b[..n].iter().map(|x| format!("{x:02x}")).collect();
    if key & 15 != 8 {
        s.push('/');
        s.push((b'0' + (key & 15) as u8) as char);
    }
    s
}

fn parse_opc(t: &str) -> Option<u32> {
    let (hex, reg) = match t.split_once('/') {
        Some((h, r)) => (h, r.parse::<u32>().ok().filter(|&v| v < 8)?),
        None => (t, 8),
    };
    if hex.len() % 2 != 0 || hex.is_empty() || hex.len() > 6 {
        return None;
    }
    let mut b = [0u8; 3];
    for i in 0..hex.len() / 2 {
        b[i] = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(((b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32) << 4 | reg)
}

/// Rule features of an instruction in the spec's text form (for the learner in
/// `examples/disasm_detail_diff.rs`): [kinds, full signature, mode, printed prefix, address size,
/// opcode, prefix context] (`k:`, `s:`, `m32/m64`, `p:`, `a..`, `o:`, `c:` in the spec).
#[doc(hidden)]
pub fn learn_features(insn: &Insn) -> [String; 7] {
    let p = detail::prefixes(insn);
    let ops = detail::cs_operands(insn, &p);
    let full: Vec<String> = ops.iter().map(|o| op_token(op_code(o))).collect();
    let coarse: String = full.iter().map(|t| &t[..1]).collect();
    [
        if coarse.is_empty() { "-".into() } else { coarse },
        if full.is_empty() { "-".into() } else { full.join(",") },
        if insn.mode == Mode::X86_64 { "m64".into() } else { "m32".into() },
        pfx_token(insn.pfx).into(),
        format!("a{}", asz(insn, &p) * 8),
        opc_token(opc_key(insn, &p)),
        ctx_token(ctx(insn, &p)).into(),
    ]
}

/// Mandatory-prefix context of a legacy-encoded instruction (capstone/LLVM pick different
/// opcodes for e.g. `66 0f c8` and `66 f2 0f c8`): 0 none, 1 66, 2 f3, 3 f2, 4 66+f3, 5 66+f2;
/// plus 8 when REX.W is set; EVEX instructions: 16 | 1 (zero-masking) | 2 (EVEX.b);
/// VEX / XOP: 20 | W.
fn ctx(insn: &Insn, p: &Prefixes) -> u8 {
    let at = |k: usize| insn.raw().get(p.op + k).copied().unwrap_or(0);
    match detail::vex_kind(insn, p) {
        detail::VexKind::None => {}
        detail::VexKind::Evex => {
            let p2 = at(3);
            return 16 | (p2 >> 7) | ((p2 >> 3) & 2);
        }
        detail::VexKind::Vex2 => return 20,
        detail::VexKind::Vex3 | detail::VexKind::Xop => return 20 | (at(2) >> 7),
    }
    let base = match p.lockrep {
        0xF3 => 2 + 2 * p.has66 as u8,
        0xF2 => 3 + 2 * p.has66 as u8,
        _ => p.has66 as u8,
    };
    base | if p.rex & 8 != 0 { 8 } else { 0 }
}

const CTX_TOKENS: [&str; 22] = [
    "np", "66", "f3", "f2", "66f3", "66f2", "?6", "?7", "w", "66w", "f3w", "f2w", "66f3w", "66f2w",
    "?14", "?15", "e", "ez", "eb", "ezb", "v", "vw",
];

fn ctx_token(c: u8) -> &'static str {
    CTX_TOKENS.get(c as usize).copied().unwrap_or("?")
}

/// Decoder mnemonics without any access rule (they use the fallback heuristic).
#[doc(hidden)]
pub fn uncovered_mnemonics() -> Vec<&'static str> {
    let t = super::tables::tables();
    let r = rules();
    let mut v: Vec<&'static str> = t
        .mnems
        .iter()
        .enumerate()
        .filter(|(i, m)| !m.is_empty() && r.by_mnem.get(*i).is_none_or(|x| x.0 == x.1))
        .map(|(_, m)| *m)
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

// ------------------------------------------------------------------------------------ rules

// register tokens beyond the `Reg` ids: native-size GPRs / instruction pointer
const T_NATIVE: u8 = 240; // 240 + n: rax..rdi (64-bit) / eax..edi (32-bit)
const T_NATIVE_END: u8 = T_NATIVE + 7;
const T_IP: u8 = 248;
// the symbolic tokens must not collide with register ids
const _: () = assert!(regs::NREGS <= T_NATIVE as usize);

#[derive(Clone, Copy, Default)]
struct Rule {
    /// 0 any, 1 = 32-bit, 2 = 64-bit
    mode: u8,
    /// 0xFF any, else printed prefix id
    pfx: u8,
    /// 0 any, else address size in bytes
    asz: u8,
    /// 0 any, else opc_key + 1
    opc: u32,
    /// 0xFF any, else prefix context (see `ctx`)
    ctx: u8,
    /// 0 none, 1 coarse (operand kinds), 2 full signature
    sigk: u8,
    nsig: u8,
    sig: [u16; 8],
    nacc: u8,
    acc: [u8; 8],
    rd: (u16, u8),
    wr: (u16, u8),
}

struct Rules {
    /// per mnemonic id: range of rules
    by_mnem: Vec<(u32, u32)>,
    rules: Vec<Rule>,
    toks: Vec<u8>,
    /// spec lines whose mnemonic the decoder does not know / that failed to parse (tests)
    #[allow(dead_code)]
    unknown: Vec<String>,
    #[allow(dead_code)]
    bad: Vec<String>,
}

static RULES: OnceLock<Rules> = OnceLock::new();

fn rules() -> &'static Rules {
    RULES.get_or_init(|| compile(&[super::access_spec::MANUAL, super::access_spec::SPEC]))
}

fn parse_reg_token(t: &str) -> Option<u8> {
    const NAT: [&str; 8] = ["*ax", "*cx", "*dx", "*bx", "*sp", "*bp", "*si", "*di"];
    if t == "flags" {
        return Some(RFLAGS);
    }
    if t == "*ip" {
        return Some(T_IP);
    }
    if let Some(i) = NAT.iter().position(|n| *n == t) {
        return Some(T_NATIVE + i as u8);
    }
    Reg::from_name(t).map(|r| r.0)
}

fn compile(specs: &[&str]) -> Rules {
    let t = super::tables::tables();
    let mut ids: std::collections::HashMap<&str, u16> = std::collections::HashMap::new();
    for (i, m) in t.mnems.iter().enumerate() {
        ids.entry(m).or_insert(i as u16);
    }
    // (mnemonic id, line order, rule)
    let mut all: Vec<(u16, usize, Rule)> = Vec::new();
    let mut toks: Vec<u8> = Vec::new();
    let mut unknown = Vec::new();
    let mut bad = Vec::new();
    for (ln, line) in specs.iter().flat_map(|s| s.lines()).enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((head, body)) = line.split_once('=') else { continue };
        let mut hw = head.split_whitespace();
        let Some(mn) = hw.next() else { continue };
        let Some(&id) = ids.get(mn) else {
            unknown.push(line.to_string());
            continue;
        };
        let mut r = Rule { pfx: 0xFF, ctx: 0xFF, ..Default::default() };
        let mut ok = true;
        for c in hw {
            if let Some(s) = c.strip_prefix("k:") {
                r.sigk = 1;
                if s != "-" {
                    for ch in s.bytes() {
                        let code = match ch {
                            b'r' => 0x100,
                            b'm' => 0x200,
                            b'i' => 0x300,
                            _ => {
                                ok = false;
                                0
                            }
                        };
                        if (r.nsig as usize) < 8 {
                            r.sig[r.nsig as usize] = code;
                            r.nsig += 1;
                        }
                    }
                }
            } else if let Some(s) = c.strip_prefix("s:") {
                r.sigk = 2;
                if s != "-" {
                    for tok in s.split(',') {
                        match parse_op_token(tok) {
                            Some(code) if (r.nsig as usize) < 8 => {
                                r.sig[r.nsig as usize] = code;
                                r.nsig += 1;
                            }
                            _ => ok = false,
                        }
                    }
                }
            } else if c == "m32" {
                r.mode = 1;
            } else if c == "m64" {
                r.mode = 2;
            } else if let Some(s) = c.strip_prefix("p:") {
                match parse_pfx(s) {
                    Some(v) => r.pfx = v,
                    None => ok = false,
                }
            } else if let Some(s) = c.strip_prefix('a') {
                match s.parse::<u8>() {
                    Ok(v @ (16 | 32 | 64)) => r.asz = v / 8,
                    _ => ok = false,
                }
            } else if let Some(s) = c.strip_prefix("c:") {
                match CTX_TOKENS.iter().position(|t| *t == s) {
                    Some(v) => r.ctx = v as u8,
                    None => ok = false,
                }
            } else if let Some(s) = c.strip_prefix("o:") {
                match parse_opc(s) {
                    Some(v) => r.opc = v + 1,
                    None => ok = false,
                }
            } else {
                ok = false;
            }
        }
        let mut parts = body.split('|');
        let acc = parts.next().unwrap_or("").trim();
        if acc != "-" {
            for ch in acc.bytes() {
                if (r.nacc as usize) < 8 && ch.is_ascii_digit() {
                    r.acc[r.nacc as usize] = ch - b'0';
                    r.nacc += 1;
                }
            }
        }
        for which in 0..2 {
            let list = parts.next().unwrap_or("").trim();
            let start = toks.len();
            for tok in list.split(',').map(str::trim).filter(|x| !x.is_empty()) {
                match parse_reg_token(tok) {
                    Some(v) => toks.push(v),
                    None => ok = false,
                }
            }
            let range = (start as u16, (toks.len() - start) as u8);
            if which == 0 {
                r.rd = range;
            } else {
                r.wr = range;
            }
        }
        if ok {
            all.push((id, ln, r));
        } else {
            bad.push(line.to_string());
        }
    }
    all.sort_by_key(|&(id, ln, _)| (id, ln));
    let mut by_mnem = vec![(0u32, 0u32); t.mnems.len()];
    let mut rules = Vec::with_capacity(all.len());
    let mut i = 0;
    while i < all.len() {
        let id = all[i].0;
        let start = rules.len() as u32;
        while i < all.len() && all[i].0 == id {
            rules.push(all[i].2);
            i += 1;
        }
        if let Some(slot) = by_mnem.get_mut(id as usize) {
            *slot = (start, rules.len() as u32);
        }
    }
    // mnemonics sharing a name (aliases) share the rules
    for (i, m) in t.mnems.iter().enumerate() {
        if let Some(&id) = ids.get(m) {
            if by_mnem[i] == (0, 0) {
                by_mnem[i] = by_mnem[id as usize];
            }
        }
    }
    Rules { by_mnem, rules, toks, unknown, bad }
}

#[inline]
fn resolve(tok: u8, mode: Mode) -> Reg {
    let m64 = mode == Mode::X86_64;
    match tok {
        T_IP => Reg(if m64 { regs::RIP } else { regs::EIP }),
        T_NATIVE..=T_NATIVE_END => Reg(if m64 { regs::RAX } else { regs::EAX } + (tok - T_NATIVE)),
        _ => Reg(tok),
    }
}

/// Detail operands with access flags plus capstone's implicit register lists.
pub(crate) struct Info {
    pub ops: DetailOps,
    pub read: RegList,
    pub write: RegList,
}

pub(crate) fn info(insn: &Insn) -> Info {
    let mut i = Info { ops: DetailOps::default(), read: RegList::new(insn.mode), write: RegList::new(insn.mode) };
    fill(insn, &mut i.ops, &mut i.read, &mut i.write);
    i
}

// ------------------------------------------------------------------------------------ template cache
//
// The detail view of an instruction (operand sizes / access flags / provenance, implicit
// registers) depends only on a small "shape": decoder entry and mnemonic, mode, prefix context,
// opcode bytes, ModRM.reg and the kinds / register classes / printed memory sizes of the
// operands. A per-thread direct-mapped cache maps that shape to the computed template, so the
// rule matching and operand-size logic run once per distinct shape; a hit only copies operand
// values into the template. The key covers every input of the slow path, so hits are exact.

const TPL_REGS: usize = 12;
const CACHE_SLOTS: usize = 4096;

#[derive(Clone, Copy)]
struct Tpl {
    key: [u64; 2],
    n: u8,
    nrd: u8,
    nwr: u8,
    src: [u8; detail::MAX_DETAIL_OPS],
    size: [u8; detail::MAX_DETAIL_OPS],
    access: [u8; detail::MAX_DETAIL_OPS],
    rd: [Reg; TPL_REGS],
    wr: [Reg; TPL_REGS],
}

const TPL_EMPTY: Tpl = Tpl {
    key: [0; 2],
    n: 0,
    nrd: 0,
    nwr: 0,
    src: [0; detail::MAX_DETAIL_OPS],
    size: [0; detail::MAX_DETAIL_OPS],
    access: [0; detail::MAX_DETAIL_OPS],
    rd: [Reg::NONE; TPL_REGS],
    wr: [Reg::NONE; TPL_REGS],
};

thread_local! {
    static CACHE: std::cell::RefCell<Vec<Tpl>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Operand kind / register class / printed memory size in 6 bits.
#[inline]
fn op_kind(o: &Operand) -> u64 {
    match *o {
        Operand::None => 0,
        Operand::Reg(r) => {
            const R8_END: u8 = regs::AX - 1;
            const R16_END: u8 = regs::EAX - 1;
            const R32_END: u8 = regs::RAX - 1;
            const R64_END: u8 = regs::RAX + 15;
            const SEG_END: u8 = regs::ES + 5;
            const CR_END: u8 = regs::CR0 + 15;
            const DR_END: u8 = regs::DR0 + 15;
            const ST_END: u8 = regs::ST0 + 7;
            const MM_END: u8 = regs::MM0 + 7;
            const XMM_END: u8 = regs::XMM0 + 31;
            const YMM_END: u8 = regs::YMM0 + 31;
            const ZMM_END: u8 = regs::ZMM0 + 31;
            const K_END: u8 = regs::K0 + 7;
            const BND_END: u8 = regs::BND0 + 3;
            let c: u64 = match r.0 {
                regs::AL..=R8_END => 0,
                regs::AX..=R16_END => 1,
                regs::EAX..=R32_END => 2,
                regs::RAX..=R64_END => 3,
                regs::ES..=SEG_END => 4,
                regs::CR0..=CR_END => 5,
                regs::DR0..=DR_END => 6,
                regs::ST0..=ST_END => 7,
                regs::MM0..=MM_END => 8,
                regs::XMM0..=XMM_END => 9,
                regs::YMM0..=YMM_END => 10,
                regs::ZMM0..=ZMM_END => 11,
                regs::K0..=K_END => 12,
                regs::BND0..=BND_END => 13,
                // other registers are not keyed (see tpl_key)
                _ => 15,
            };
            0x10 | c
        }
        Operand::Mem(ref m) => 0x20 | m.size as u64,
        Operand::Imm(_) => 0x30,
    }
}

/// The shape key of `insn` (see above); `None` when the instruction cannot be keyed.
#[inline]
fn tpl_key(insn: &Insn, p: &Prefixes) -> Option<[u64; 2]> {
    let ops = insn.ops();
    if ops.len() > 5 {
        return None;
    }
    // "other" registers (rip, eip, ...) are keyed by identity
    for o in ops {
        if let Operand::Reg(r) = o {
            if r.0 > regs::BND0 + 3 || (r.0 > regs::RAX + 15 && r.0 < regs::ES) {
                return None;
            }
        }
    }
    // vector-prefix kind, prefix context (as `ctx`) and the byte after the opcode (ModRM when
    // present; keying it unconditionally only makes the key finer, never ambiguous)
    let d = insn.raw();
    let at = |k: usize| d.get(p.op + k).copied().unwrap_or(0) as u64;
    let vkind = detail::vex_kind(insn, p);
    let (c, mpos): (u64, usize) = match vkind {
        detail::VexKind::None => {
            let o = insn.opcode;
            let len = if o[0] == 0x0F {
                if o[1] == 0x38 || o[1] == 0x3A { 3 } else { 2 }
            } else {
                1
            };
            let base: u64 = match p.lockrep {
                0xF3 => 2 + 2 * p.has66 as u64,
                0xF2 => 3 + 2 * p.has66 as u64,
                _ => p.has66 as u64,
            };
            (base | if p.rex & 8 != 0 { 8 } else { 0 }, len)
        }
        detail::VexKind::Evex => {
            let p2 = at(3);
            (16 | (p2 >> 7) | ((p2 >> 3) & 2), 5)
        }
        detail::VexKind::Vex2 => (20, 3),
        detail::VexKind::Vex3 | detail::VexKind::Xop => (20 | (at(2) >> 7), 4),
    };
    let reg = if p.op + mpos < d.len() { (at(mpos) >> 3) & 7 } else { 8 };
    let vk = vkind as u64;
    let lr: u64 = match p.lockrep {
        0xF0 => 1,
        0xF2 => 2,
        0xF3 => 3,
        _ => 0,
    };
    let k0 = insn.entry as u64
        | (insn.mnem as u64) << 16
        | (insn.pfx as u64 & 15) << 32
        | ((insn.mode == Mode::X86_64) as u64) << 36
        | (p.has66 as u64) << 37
        | (p.has67 as u64) << 38
        | ((p.rex >> 3) as u64 & 1) << 39
        | lr << 40
        | vk << 42
        | (c & 31) << 45
        | reg << 50
        | ((insn.evex >> 6) as u64 & 3) << 54
        | (ops.len() as u64) << 56
        | 1 << 63;
    let o = insn.opcode;
    let mut k1 = o[0] as u64 | (o[1] as u64) << 8 | (o[2] as u64) << 16;
    for (i, op) in ops.iter().enumerate() {
        k1 |= op_kind(op) << (24 + 6 * i);
    }
    Some([k0, k1])
}

#[inline]
fn tpl_hash(k: &[u64; 2]) -> usize {
    let h = (k[0] ^ k[1].rotate_left(29)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    (h >> 52) as usize & (CACHE_SLOTS - 1)
}

/// Detail operands (with access flags) and implicit register lists of `insn`, written into
/// reused buffers (no intermediate copies).
fn fill(insn: &Insn, ops: &mut DetailOps, read: &mut RegList, write: &mut RegList) {
    let p = detail::prefixes(insn);
    let Some(key) = tpl_key(insn, &p) else {
        fill_slow(insn, &p, ops, read, write);
        return;
    };
    let h = tpl_hash(&key);
    CACHE.with(|c| {
        let Ok(mut c) = c.try_borrow_mut() else {
            fill_slow(insn, &p, ops, read, write);
            return;
        };
        if c.is_empty() {
            c.resize(CACHE_SLOTS, TPL_EMPTY);
        }
        let t = &c[h];
        if t.key == key {
            let src_ops = &insn.operands;
            let n = t.n as usize;
            for i in 0..n {
                let s = t.src[i];
                let op = match s {
                    detail::SRC_ST0 => Operand::Reg(Reg(regs::ST0)),
                    detail::SRC_ONE => Operand::Imm(1),
                    detail::SRC_KMASK => Operand::Reg(Reg(regs::K0 + (insn.evex & 7))),
                    k => src_ops[(k as usize).min(super::MAX_OPS - 1)],
                };
                ops.ops[i] = DetailOp { op, size: t.size[i], access: t.access[i] };
                ops.src[i] = s;
            }
            ops.n = t.n;
            read.set_fixed(insn.mode, &t.rd, t.nrd);
            write.set_fixed(insn.mode, &t.wr, t.nwr);
            return;
        }
        fill_slow(insn, &p, ops, read, write);
        if read.len() > TPL_REGS || write.len() > TPL_REGS {
            return;
        }
        let mut t = TPL_EMPTY;
        t.key = key;
        t.n = ops.n;
        for i in 0..ops.n as usize {
            let s = ops.src[i];
            if s >= super::MAX_OPS as u8 && !matches!(s, detail::SRC_ST0 | detail::SRC_ONE | detail::SRC_KMASK) {
                return;
            }
            t.src[i] = s;
            t.size[i] = ops.ops[i].size;
            t.access[i] = ops.ops[i].access;
        }
        t.nrd = read.len() as u8;
        t.nwr = write.len() as u8;
        t.rd[..read.len()].copy_from_slice(read);
        t.wr[..write.len()].copy_from_slice(write);
        c[h] = t;
    })
}

fn fill_slow(insn: &Insn, p: &Prefixes, ops: &mut DetailOps, read: &mut RegList, write: &mut RegList) {
    let p = *p;
    detail::cs_operands_into(insn, &p, ops);
    read.reset(insn.mode);
    write.reset(insn.mode);
    let rs = rules();
    let (s, e) = rs.by_mnem.get(insn.mnem as usize).copied().unwrap_or((0, 0));
    let n = ops.n as usize;
    let mode = if insn.mode == Mode::X86_64 { 2 } else { 1 };
    // features are computed lazily, at most once each
    let mut codes = [0u16; 8];
    let mut have_codes = false;
    let mut f_opc = u32::MAX;
    let mut f_ctx = 0xFFu8;
    let mut hit = None;
    for r in rs.rules.get(s as usize..e as usize).unwrap_or(&[]) {
        if r.mode != 0 && r.mode != mode {
            continue;
        }
        if r.pfx != 0xFF && r.pfx != insn.pfx {
            continue;
        }
        if r.sigk != 0 {
            if r.nsig as usize != n {
                continue;
            }
            if !have_codes {
                for (k, o) in ops.iter().enumerate() {
                    codes[k] = op_code(o);
                }
                have_codes = true;
            }
            if r.sigk == 1 {
                if (0..n).any(|k| r.sig[k] != codes[k] & 0xFF00) {
                    continue;
                }
            } else if r.sig[..n] != codes[..n] {
                continue;
            }
        }
        if r.asz != 0 && r.asz != asz(insn, &p) {
            continue;
        }
        if r.opc != 0 {
            if f_opc == u32::MAX {
                f_opc = opc_key(insn, &p) + 1;
            }
            if r.opc != f_opc {
                continue;
            }
        }
        if r.ctx != 0xFF {
            if f_ctx == 0xFF {
                f_ctx = ctx(insn, &p);
            }
            if r.ctx != f_ctx {
                continue;
            }
        }
        hit = Some(r);
        break;
    }
    match hit {
        Some(r) => {
            for k in 0..n {
                ops.ops[k].access = if k < r.nacc as usize { r.acc[k] } else { 0 };
            }
            let span = |(start, len): (u16, u8)| {
                rs.toks.get(start as usize..start as usize + len as usize).unwrap_or(&[])
            };
            for &t in span(r.rd) {
                read.push(resolve(t, insn.mode));
            }
            for &t in span(r.wr) {
                write.push(resolve(t, insn.mode));
            }
        }
        None => fallback(ops, detail::vex_kind(insn, &p) != detail::VexKind::None),
    }
}

/// Heuristic for mnemonics the spec does not know: destination written (VEX/EVEX/XOP) or read+written
/// (legacy), sources read, immediates 0.
fn fallback(ops: &mut DetailOps, vex: bool) {
    let n = ops.n as usize;
    for k in 0..n {
        ops.ops[k].access = if ops.ops[k].is_imm() {
            0
        } else if k == 0 && n > 1 && vex {
            detail::CS_AC_WRITE
        } else if k == 0 && n > 1 {
            detail::CS_AC_READ | detail::CS_AC_WRITE
        } else {
            detail::CS_AC_READ
        };
    }
}

/// Everything capstone's detail mode reports for one instruction, computed in one pass
/// (use [`Insn::detail`] when more than one of the individual accessors is needed).
#[derive(Clone, Copy, Debug)]
pub struct Detail {
    /// `insn.operands` (with `size` and `access`)
    pub ops: DetailOps,
    /// `insn.regs_read` (implicit)
    pub implicit_read: RegList,
    /// `insn.regs_write` (implicit)
    pub implicit_write: RegList,
    /// `insn.regs_access()[0]`
    pub regs_read: RegList,
    /// `insn.regs_access()[1]`
    pub regs_write: RegList,
}

/// capstone's `X86_reg_access`: implicit registers first, then explicit operands in order.
fn reg_access_into(ops: &DetailOps, iread: &RegList, iwrite: &RegList, r: &mut RegList, w: &mut RegList) {
    // fixed-size struct copies (inlined vector moves, no memcpy call)
    *r = *iread;
    *w = *iwrite;
    for o in ops.iter() {
        match o.op {
            Operand::Reg(x) => {
                if o.access & detail::CS_AC_READ != 0 {
                    r.push_unique(x);
                }
                if o.access & detail::CS_AC_WRITE != 0 {
                    w.push_unique(x);
                }
            }
            Operand::Mem(m) => {
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
}

impl Detail {
    /// An empty detail record (reuse it with [`Insn::detail_into`]).
    pub fn new() -> Self {
        let l = RegList::new(Mode::X86_64);
        Detail { ops: DetailOps::default(), implicit_read: l, implicit_write: l, regs_read: l, regs_write: l }
    }
}

impl Default for Detail {
    fn default() -> Self {
        Detail::new()
    }
}

impl Insn {
    /// All of capstone's detail information in one pass (operands, implicit registers and
    /// `regs_access()`), cheaper than calling the individual accessors separately.
    pub fn detail(&self) -> Detail {
        let mut d = Detail::new();
        self.detail_into(&mut d);
        d
    }
    /// [`Insn::detail`] into a reused record (fastest: no zeroing, no copies).
    pub fn detail_into(&self, d: &mut Detail) {
        fill(self, &mut d.ops, &mut d.implicit_read, &mut d.implicit_write);
        reg_access_into(&d.ops, &d.implicit_read, &d.implicit_write, &mut d.regs_read, &mut d.regs_write);
    }
    /// capstone's detail operands (`insn.operands`), including `size` and `access`.
    pub fn detail_operands(&self) -> DetailOps {
        info(self).ops
    }
    /// capstone's implicit registers (`insn.regs_read`, `insn.regs_write`).
    pub fn implicit_regs(&self) -> (RegList, RegList) {
        let i = info(self);
        (i.read, i.write)
    }
    /// capstone's `insn.regs_access()` -> (regs_read, regs_write): implicit registers first,
    /// then explicit operands in order (registers by their access flags, memory operands'
    /// segment / base / index as read), de-duplicated except for segment registers — exactly
    /// capstone's `X86_reg_access`.
    pub fn regs_access(&self) -> (RegList, RegList) {
        let i = info(self);
        let (mut r, mut w) = (RegList::new(self.mode), RegList::new(self.mode));
        reg_access_into(&i.ops, &i.read, &i.write, &mut r, &mut w);
        (r, w)
    }
    /// True if `regs_access()`'s written list contains a register named `name` (capstone
    /// naming): `direct_system_calls`' `reg_name(r) in ["eax", "rax"]` / `== "r10"` test.
    pub fn regs_written_contains(&self, name: &str) -> bool {
        self.regs_access().1.contains_name(name)
    }
    /// True if `regs_access()`'s read list contains a register named `name`.
    pub fn regs_read_contains(&self, name: &str) -> bool {
        self.regs_access().0.contains_name(name)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Mode, Operand, decode};
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    fn acc(h: &str, mode: Mode) -> (String, String) {
        let i = decode(&hex(h), 0x1000, mode).expect("decodes");
        let (r, w) = i.regs_access();
        (r.names().collect::<Vec<_>>().join(","), w.names().collect::<Vec<_>>().join(","))
    }

    #[test]
    fn disasm_access_spec_compiles_fully() {
        let r = rules();
        assert!(r.bad.is_empty(), "unparsable spec lines: {:?}", &r.bad[..r.bad.len().min(5)]);
        assert!(
            r.unknown.is_empty(),
            "unknown mnemonics: {:?}",
            &r.unknown[..r.unknown.len().min(5)]
        );
        assert!(r.rules.len() > 1000);
    }

    #[test]
    fn disasm_op_tokens_round_trip() {
        for code in [
            0x101u16,
            0x102,
            0x104,
            0x108,
            0x100 | b'x' as u16,
            0x100 | b'k' as u16,
            0x200,
            0x204,
            0x21C,
            0x300,
            0x301,
            0x308,
        ] {
            assert_eq!(parse_op_token(&op_token(code)), Some(code), "{code:#x}");
        }
        for t in ["f6/1", "0f18/4", "0f38f0", "a9", "00"] {
            assert_eq!(opc_token(parse_opc(t).unwrap()), t);
        }
        for i in 0..22u8 {
            assert_eq!(CTX_TOKENS.iter().position(|t| *t == ctx_token(i)), Some(i as usize));
        }
    }

    // expected values produced by capstone 5.0.7 (python bindings, detail=True)
    #[test]
    fn disasm_regs_access_matches_capstone() {
        let m64 = Mode::X86_64;
        let m32 = Mode::X86_32;
        assert_eq!(acc("4c8bd1", m64), ("rcx".into(), "r10".into())); // mov r10, rcx
        assert_eq!(acc("b855000000", m64), ("".into(), "eax".into())); // mov eax, 0x55
        assert_eq!(acc("31c0", m64), ("eax".into(), "rflags,eax".into())); // xor eax, eax
        assert_eq!(acc("0f05", m64), ("".into(), "".into())); // syscall
        assert_eq!(acc("f3a4", m64), ("rdi,rsi,rflags,rcx".into(), "rdi,rsi,rcx".into()));
        assert_eq!(acc("e800000000", m64), ("rsp,rip".into(), "rsp".into())); // call
        assert_eq!(acc("50", m64), ("rsp,rax".into(), "rsp".into())); // push rax
        assert_eq!(acc("666a01", m64), ("esp".into(), "esp".into())); // push 1 (16-bit)
        assert_eq!(acc("488d0501000000", m64), ("rip".into(), "rax".into())); // lea rax, [rip + 1]
        assert_eq!(acc("ff2500000000", m64), ("rip".into(), "".into())); // jmp qword ptr [rip]
        assert_eq!(acc("0000", m64), ("rax,al".into(), "rflags".into())); // add byte ptr [rax], al
        assert_eq!(acc("64488b042530000000", m64), ("fs".into(), "rax".into()));
        assert_eq!(acc("d9c9", m64), ("st(0)".into(), "fpsw".into())); // fxch st(1)
        assert_eq!(acc("62f1fd4958400410", m64), ("zmm0,k1,rax".into(), "zmm0".into()));
        // 32-bit: the flags register is named "eflags"; segment registers are not de-duplicated
        assert_eq!(acc("26a6", m32), ("edi,esi,eflags,es,es".into(), "edi,esi,eflags".into()));
        assert_eq!(acc("a900000000", m32), ("eax".into(), "eflags,eax".into())); // test eax, 0 (!)
        assert_eq!(acc("8508", m32), ("eax".into(), "".into())); // test [eax], ecx: no flags (!)
        assert_eq!(acc("f3ab", m32), ("eax,edi,eflags,ecx,es".into(), "edi,ecx".into()));
        let i = decode(&hex("b855000000"), 0, m64).unwrap();
        assert!(i.regs_written_contains("eax") && !i.regs_written_contains("rax"));
        assert!(decode(&hex("4c8bd1"), 0, m64).unwrap().regs_written_contains("r10"));
    }

    #[test]
    fn disasm_detail_operands_and_opcode() {
        // lea rax, [rip + 1]: operands[1] is MEM with base rip (skeleton_key_check)
        let i = decode(&hex("488d0501000000"), 0x1000, Mode::X86_64).unwrap();
        let ops = i.detail_operands();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].op, Operand::Reg(Reg(regs::RAX)));
        assert_eq!((ops[0].size, ops[0].access), (8, 2));
        let m = ops[1].mem().unwrap();
        assert_eq!((i.reg_name(m.base), m.disp, ops[1].size, ops[1].access), ("rip", 1, 8, 1));
        assert_eq!(i.address + i.size as u64 + m.disp as u64, 0x1008);
        // EVEX: {k1} is its own operand; opcode is the raw EVEX prefix
        let i = decode(&hex("62f1fd4958400410"), 0, Mode::X86_64).unwrap();
        assert_eq!(i.detail_operands().len(), 4);
        assert_eq!(i.capstone_opcode(), [0x62, 0xf1, 0xfd, 0x49]);
        assert_eq!(
            decode(&hex("c5f97ec0"), 0, Mode::X86_64).unwrap().capstone_opcode(),
            [0xc5, 0xf9, 0, 0]
        );
        assert_eq!(
            decode(&hex("660f3a0fd90c"), 0, Mode::X86_32).unwrap().capstone_opcode(),
            [0x0f, 0x0f, 0, 0]
        );
        assert!(decode(&hex("0000"), 0, Mode::X86_64).unwrap().opcode_all_zero());
        assert!(!decode(&hex("0100"), 0, Mode::X86_64).unwrap().opcode_all_zero());
        // imm sizes: branch targets are 8 bytes in 64-bit mode, 4 with REX.W / 66
        let i = decode(&hex("e800000000"), 0x1000, Mode::X86_64).unwrap();
        assert_eq!((i.detail_operands()[0].imm(), i.detail_operands()[0].size), (Some(0x1005), 8));
        let i = decode(&hex("48eb00"), 0x1000, Mode::X86_64).unwrap();
        assert_eq!(i.detail_operands()[0].size, 4);
        // implicit regs
        let (r, w) = decode(&hex("f3a4"), 0, Mode::X86_64).unwrap().implicit_regs();
        assert_eq!(r.names().collect::<Vec<_>>(), ["rdi", "rsi", "rflags", "rcx"]);
        assert_eq!(w.names().collect::<Vec<_>>(), ["rdi", "rsi", "rcx"]);
    }

    /// Differential check of regs_access / implicit regs / detail operands / opcode against the
    /// capstone detail references of `bench/scripts/disasm_detail_diff.py gen` (skipped when
    /// absent; first 100k lines of the real-code corpora only — run
    /// `examples/disasm_detail_diff cmp` for everything).
    #[test]
    fn disasm_detail_matches_capstone_corpora() {
        use std::io::BufRead;
        let dir = std::path::Path::new("/home/user/rs-vol/testdata/scratch/disasm/ref");
        let names = |l: &RegList| l.names().collect::<Vec<_>>().join(",");
        let unhex = |s: &str| -> Vec<u8> {
            (0..s.len() / 2)
                .filter_map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
                .collect()
        };
        let mut bad = Vec::new();
        let mut n = 0;
        for name in ["real64", "real32"] {
            let Ok(f) = std::fs::File::open(dir.join(format!("{name}.det"))) else {
                eprintln!("{name}.det not found in {dir:?}; skipping");
                continue;
            };
            for line in std::io::BufReader::new(f).lines().take(100_000) {
                let Ok(line) = line else { break };
                let p: Vec<&str> = line.split('\t').collect();
                if p.len() < 17 {
                    continue;
                }
                let mode = if p[1] == "64" { Mode::X86_64 } else { Mode::X86_32 };
                let addr = u64::from_str_radix(p[2], 16).unwrap_or(0);
                let Some(i) = decode(&unhex(p[3]), addr, mode) else {
                    bad.push(format!("{name} {}: undecodable", p[3]));
                    continue;
                };
                n += 1;
                let (r, w) = i.regs_access();
                let (ir, iw) = i.implicit_regs();
                let opc: String = i.capstone_opcode().iter().map(|b| format!("{b:02x}")).collect();
                let ops: Vec<String> = i
                    .detail_operands()
                    .iter()
                    .map(|o| {
                        let reg = |x: Reg| if x.is_none() { "-" } else { i.reg_name(x) };
                        match o.op {
                            Operand::Reg(x) => format!("r,{},{},{}", reg(x), o.size, o.access),
                            Operand::Imm(v) => format!("i,{v},{},{}", o.size, o.access),
                            Operand::Mem(m) => format!(
                                "m,{},{},{},{},{},{},{},",
                                reg(m.segment),
                                reg(m.base),
                                reg(m.index),
                                m.scale,
                                m.disp,
                                o.size,
                                o.access
                            ),
                            Operand::None => "?".into(),
                        }
                    })
                    .collect();
                // capstone's mem operands end with ",BCAST": compare without it
                let cs_ops: Vec<String> = p[14]
                    .split('|')
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        if s.starts_with("m,") {
                            s[..s.rfind(',').unwrap_or(s.len()) + 1].to_string()
                        } else {
                            s.to_string()
                        }
                    })
                    .collect();
                let got = [opc, names(&ir), names(&iw), names(&r), names(&w), ops.join("|")];
                let exp = [p[5], p[10], p[11], p[12], p[13], &cs_ops.join("|")];
                if got.iter().zip(exp.iter()).any(|(g, e)| g != e) && bad.len() < 20 {
                    bad.push(format!(
                        "{name} {} {} {}:\n  got {:?}\n  exp {:?}",
                        p[3], p[15], p[16], got, exp
                    ));
                }
            }
        }
        assert!(
            bad.is_empty(),
            "{} mismatches vs capstone detail (of {n}):\n{}",
            bad.len(),
            bad.join("\n")
        );
        assert!(n >= 100_000 || !dir.join("real64.det").exists(), "only {n} instructions checked");
    }

    #[test]
    fn disasm_regs_access_never_panics_on_random_bytes() {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let prefixes = [
            0x66u8, 0x67, 0xF2, 0xF3, 0xF0, 0x2E, 0x26, 0x64, 0x65, 0x48, 0x41, 0x4F, 0xC4, 0xC5,
            0x62, 0x8F, 0x0F,
        ];
        let mut buf = [0u8; 15];
        let mut n = 0usize;
        for it in 0..200_000u32 {
            for b in buf.iter_mut() {
                *b = next() as u8;
            }
            // bias towards prefixes / escapes
            let k = (next() % 4) as usize;
            for b in buf.iter_mut().take(k) {
                *b = prefixes[(next() % prefixes.len() as u64) as usize];
            }
            let mode = if it & 1 == 0 { Mode::X86_64 } else { Mode::X86_32 };
            let len = 1 + (next() % 15) as usize;
            if let Some(i) = decode(&buf[..len], next(), mode) {
                let ops = i.detail_operands();
                let (r, w) = i.regs_access();
                let (ir, iw) = i.implicit_regs();
                assert!(ops.len() <= super::super::MAX_DETAIL_OPS);
                assert!(
                    r.len() <= MAX_REGS
                        && w.len() <= MAX_REGS
                        && ir.len() <= r.len()
                        && iw.len() <= w.len()
                );
                let _ =
                    (i.capstone_opcode(), i.regs_written_contains("rax"), r.name(0), w.name(99));
                n += 1;
            }
        }
        assert!(n > 50_000);
    }
}
