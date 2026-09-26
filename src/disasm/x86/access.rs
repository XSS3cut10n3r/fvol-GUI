//! capstone detail-mode register access (`cs_regs_access`) for the x86 decoder.
//!
//! (see the porting guide at the end of this comment block — written once the API settled)
//!
//! How it works: capstone's answer is `implicit regs of the LLVM opcode` + `explicit operands
//! according to their access flags`. Both depend on capstone's per-LLVM-opcode tables, which we
//! reproduce with a compact rule spec (`access_spec.rs`) keyed by our mnemonic and refined by
//! operand signature / mode / printed prefix / address size / opcode where capstone's LLVM
//! opcodes differ. The spec was learned from capstone's own detail output over real code and
//! opcode sweeps (`examples/disasm_detail_diff.rs learn`) and is compiled once into flat
//! arrays; a lookup is an index by mnemonic id plus a scan over a handful of rules.

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
    match r.0 {
        1..=20 => 1,
        21..=36 => 2,
        37..=52 => 4,
        53..=68 => 8,
        regs::ES..=77 => b's',
        regs::CR0..=93 => b'c',
        regs::DR0..=109 => b'd',
        regs::ST0..=117 => b'f',
        regs::MM0..=125 => b'q',
        regs::XMM0..=157 => b'x',
        regs::YMM0..=189 => b'y',
        regs::ZMM0..=221 => b'z',
        regs::K0..=229 => b'k',
        regs::BND0..=233 => b'b',
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
    let n = if b[2] != 0 { 3 } else if b[1] != 0 { 2 } else { 1 };
    let mut s: String = b[..n].iter().map(|x| format!("{x:02x}")).collect();
    if key & 15 != 8 {
        s.push('/');
        s.push((b'0' + (key & 15) as u8) as char);
    }
    s
}

fn parse_opc(t: &str) -> Option<u32> {
    let (hex, reg) = match t.split_once('/') {
        Some((h, r)) => (h, r.parse::<u32>().ok()?),
        None => (t, 8),
    };
    if hex.len() % 2 != 0 || hex.is_empty() || hex.len() > 6 {
        return None;
    }
    let mut b = [0u8; 3];
    for i in 0..hex.len() / 2 {
        b[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(((b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32) << 4 | reg)
}

/// Rule features of an instruction in the spec's text form (for the learner in
/// `examples/disasm_detail_diff.rs`): (coarse sig, full sig, mode, prefix, asz, opcode).
#[doc(hidden)]
pub fn learn_features(insn: &Insn) -> [String; 7] {
    let ops = detail::cs_operands(insn);
    let p = detail::prefixes(insn);
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
/// plus 8 when REX.W is set; EVEX instructions: 16, 17 with zero-masking.
fn ctx(insn: &Insn, p: &Prefixes) -> u8 {
    match detail::vex_kind(insn, p) {
        detail::VexKind::None => {}
        detail::VexKind::Evex => return 16 | (insn.evex >> 6 & 1),
        _ => return 0,
    }
    let base = match p.lockrep {
        0xF3 => 2 + 2 * p.has66 as u8,
        0xF2 => 3 + 2 * p.has66 as u8,
        _ => p.has66 as u8,
    };
    base | if p.rex & 8 != 0 { 8 } else { 0 }
}

const CTX_TOKENS: [&str; 18] = [
    "np", "66", "f3", "f2", "66f3", "66f2", "?6", "?7", "w", "66w", "f3w", "f2w", "66f3w", "66f2w",
    "?14", "?15", "e", "ez",
];

fn ctx_token(c: u8) -> &'static str {
    CTX_TOKENS.get(c as usize).copied().unwrap_or("?")
}

// ------------------------------------------------------------------------------------ rules

// register tokens beyond the `Reg` ids: native-size GPRs / instruction pointer
const T_NATIVE: u8 = 240; // 240 + n: rax..rdi (64-bit) / eax..edi (32-bit)
const T_IP: u8 = 248;

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
}

static RULES: OnceLock<Rules> = OnceLock::new();

fn rules() -> &'static Rules {
    RULES.get_or_init(|| compile(super::access_spec::SPEC))
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

fn compile(spec: &str) -> Rules {
    let t = super::tables::tables();
    let mut ids: std::collections::HashMap<&str, u16> = std::collections::HashMap::new();
    for (i, m) in t.mnems.iter().enumerate() {
        ids.entry(m).or_insert(i as u16);
    }
    // (mnemonic id, line order, rule)
    let mut all: Vec<(u16, usize, Rule)> = Vec::new();
    let mut toks: Vec<u8> = Vec::new();
    for (ln, line) in spec.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((head, body)) = line.split_once('=') else { continue };
        let mut hw = head.split_whitespace();
        let Some(mn) = hw.next() else { continue };
        let Some(&id) = ids.get(mn) else { continue };
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
    Rules { by_mnem, rules, toks }
}

#[inline]
fn resolve(tok: u8, mode: Mode) -> Reg {
    let m64 = mode == Mode::X86_64;
    match tok {
        T_IP => Reg(if m64 { regs::RIP } else { regs::EIP }),
        T_NATIVE..=247 => Reg(if m64 { regs::RAX } else { regs::EAX } + (tok - T_NATIVE)),
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
    let mut ops = detail::cs_operands(insn);
    let mut read = RegList::new(insn.mode);
    let mut write = RegList::new(insn.mode);
    let rs = rules();
    let (s, e) = rs.by_mnem.get(insn.mnem as usize).copied().unwrap_or((0, 0));
    let mut codes = [0u16; 8];
    for (k, o) in ops.iter().enumerate() {
        codes[k] = op_code(o);
    }
    let n = ops.n as usize;
    let p = detail::prefixes(insn);
    let mode = if insn.mode == Mode::X86_64 { 2 } else { 1 };
    let mut hit = None;
    for r in &rs.rules[s as usize..e as usize] {
        if r.mode != 0 && r.mode != mode {
            continue;
        }
        if r.pfx != 0xFF && r.pfx != insn.pfx {
            continue;
        }
        match r.sigk {
            1 => {
                if r.nsig as usize != n || (0..n).any(|k| r.sig[k] != codes[k] & 0xFF00) {
                    continue;
                }
            }
            2 => {
                if r.nsig as usize != n || r.sig[..n] != codes[..n] {
                    continue;
                }
            }
            _ => {}
        }
        if r.asz != 0 && r.asz != asz(insn, &p) {
            continue;
        }
        if r.opc != 0 && r.opc != opc_key(insn, &p) + 1 {
            continue;
        }
        if r.ctx != 0xFF && r.ctx != ctx(insn, &p) {
            continue;
        }
        hit = Some(r);
        break;
    }
    match hit {
        Some(r) => {
            for k in 0..n {
                ops.ops[k].access = if k < r.nacc as usize { r.acc[k] } else { 0 };
            }
            let toks = &rs.toks;
            for &t in toks.iter().skip(r.rd.0 as usize).take(r.rd.1 as usize) {
                read.push(resolve(t, insn.mode));
            }
            for &t in toks.iter().skip(r.wr.0 as usize).take(r.wr.1 as usize) {
                write.push(resolve(t, insn.mode));
            }
        }
        None => fallback(&mut ops),
    }
    Info { ops, read, write }
}

/// Heuristic for mnemonics the spec does not know: destination read+write, sources read.
fn fallback(ops: &mut DetailOps) {
    let n = ops.n as usize;
    for k in 0..n {
        ops.ops[k].access = if ops.ops[k].is_imm() {
            0
        } else if k == 0 && n > 1 {
            detail::CS_AC_READ | detail::CS_AC_WRITE
        } else {
            detail::CS_AC_READ
        };
    }
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
    /// capstone's `insn.regs_access()` -> (regs_read, regs_write): implicit registers first,
    /// then explicit operands in order (registers by their access flags, memory operands'
    /// segment / base / index as read), de-duplicated except for segment registers — exactly
    /// capstone's `X86_reg_access`.
    pub fn regs_access(&self) -> (RegList, RegList) {
        let i = info(self);
        let (mut r, mut w) = (i.read, i.write);
        for o in i.ops.iter() {
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
