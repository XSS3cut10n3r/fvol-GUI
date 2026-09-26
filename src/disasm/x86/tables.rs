//! Opcode table compiler: parses the textual instruction spec (spec_*.rs) once and builds dense
//! lookup tables: per opcode map a `[u32; 256]` root, whose entries are either a leaf (entry
//! index), 0 (invalid) or the offset of a decision node `[kind, child0, child1, ...]` selecting on
//! mode / mandatory prefix / W / L / EVEX.b / ModRM.mod / reg / rm / REX.B / operand size /
//! address size.
//!
//! Spec line grammar:   MAP OPC [SELECTORS] : MNEMONIC [OPERANDS] [; FLAGS]
//!   MAP       1 0f 38 3a 3dn v1 v2 v3 e1 e2 e3 e5 e6 x8 x9 xa
//!   OPC       hex byte or range ("50-57")
//!   SELECTORS mode32 mode64 | np 66 f3 f2 (joinable with '|') | w0 w1 | l0 l1 l2 l3 (joinable)
//!             | b0 b1 | m (mod!=3) r (mod==3) | /N or /N-M or /N,M | rmN rmN-M | rexb0 rexb1
//!             | o16 o32 o64 (operand size) | d16 d32 d64 (operand size, 64-bit default)
//!             | a16 a32 a64 (address size)
//!   OPERANDS  comma separated, see `parse_op`.
//!   FLAGS     space separated, see `parse_flag`.

use super::regs;
use super::MAX_OPS;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------------------- maps
pub(crate) const MAP_1: usize = 0;
pub(crate) const MAP_0F: usize = 1;
pub(crate) const MAP_38: usize = 2;
pub(crate) const MAP_3A: usize = 3;
pub(crate) const MAP_3DN: usize = 4;
pub(crate) const MAP_V1: usize = 5; // VEX maps 1..3 -> 5..7
pub(crate) const MAP_E1: usize = 8; // EVEX maps 1,2,3,5,6 -> 8,9,10,11,12
pub(crate) const MAP_X8: usize = 13; // XOP maps 8,9,a -> 13,14,15
pub(crate) const NMAPS: usize = 16;

// ---------------------------------------------------------------------------------------- selectors
pub(crate) const SEL_MODE: u32 = 0; // 0 = 32-bit, 1 = 64-bit
pub(crate) const SEL_PFX: u32 = 1; // 0 np, 1 66, 2 f3, 3 f2, 4 66+f3, 5 66+f2
pub(crate) const SEL_W: u32 = 2;
pub(crate) const SEL_L: u32 = 3; // 0..3
pub(crate) const SEL_B: u32 = 4; // EVEX.b
pub(crate) const SEL_MOD: u32 = 5; // 0 mem, 1 reg
pub(crate) const SEL_REG: u32 = 6;
pub(crate) const SEL_RM: u32 = 7;
pub(crate) const SEL_REXB: u32 = 8;
pub(crate) const SEL_O: u32 = 9; // 0 16, 1 32, 2 64
pub(crate) const SEL_D: u32 = 10; // same, with 64-bit default operand size in long mode
pub(crate) const SEL_A: u32 = 11; // address size 0 16, 1 32, 2 64
pub(crate) const SEL_H66: u32 = 12; // 0x66 prefix present (0/1)
pub(crate) const NSEL: usize = 13;
const ARITY: [u32; NSEL] = [2, 6, 2, 4, 2, 2, 8, 8, 2, 3, 3, 3, 2];

// ---------------------------------------------------------------------------------------- operands
// operand sources
pub(crate) const S_NONE: u8 = 0;
pub(crate) const S_REG: u8 = 1; // ModRM.reg
pub(crate) const S_RM: u8 = 2; // ModRM.rm, register or memory
pub(crate) const S_MEM: u8 = 3; // ModRM.rm, memory only
pub(crate) const S_RMREG: u8 = 4; // ModRM.rm, register only
pub(crate) const S_VVVV: u8 = 5;
pub(crate) const S_OPREG: u8 = 6; // opcode low 3 bits + REX.B
pub(crate) const S_IS4: u8 = 7; // imm8[7:4] register
pub(crate) const S_IMM: u8 = 8;
pub(crate) const S_REL: u8 = 9;
pub(crate) const S_MOFFS: u8 = 10;
pub(crate) const S_STRSRC: u8 = 11; // [rsi]
pub(crate) const S_STRDST: u8 = 12; // [rdi]
pub(crate) const S_FARPTR: u8 = 13; // ptr16:16/32 immediate (two operands)
pub(crate) const S_FIXED: u8 = 14; // fixed register (cls = register id)
pub(crate) const S_CONST1: u8 = 15; // literal 1
pub(crate) const S_ACC: u8 = 16; // accumulator of size cls (al/ax/eax/rax)
pub(crate) const S_STRRBX: u8 = 17; // [rbx + al]  (xlat; unused by capstone printing)
pub(crate) const S_RC: u8 = 18; // EVEX rounding control / sae operand
pub(crate) const S_KMASK: u8 = 19; // standalone {kN} operand
pub(crate) const S_VSIB: u8 = 20; // VSIB memory operand (cls = index vector class)

// register classes
pub(crate) const C_B: u8 = 1;
pub(crate) const C_W: u8 = 2;
pub(crate) const C_D: u8 = 3;
pub(crate) const C_Q: u8 = 4;
pub(crate) const C_V: u8 = 5; // operand size
pub(crate) const C_Y: u8 = 6; // 64 if REX.W/VEX.W (in 64-bit mode) else 32
pub(crate) const C_Z: u8 = 7; // operand size, 64 -> 32
pub(crate) const C_N: u8 = 8; // native: 32 in 32-bit mode, 64 in 64-bit mode
pub(crate) const C_SEG: u8 = 9;
pub(crate) const C_CR: u8 = 10;
pub(crate) const C_DR: u8 = 11;
pub(crate) const C_MM: u8 = 12;
pub(crate) const C_XMM: u8 = 13;
pub(crate) const C_YMM: u8 = 14;
pub(crate) const C_ZMM: u8 = 15;
pub(crate) const C_VL: u8 = 16; // xmm/ymm/zmm by L
pub(crate) const C_K: u8 = 17;
pub(crate) const C_BND: u8 = 18;
pub(crate) const C_ST: u8 = 19;
pub(crate) const C_VLH: u8 = 20; // half vector: xmm/xmm/ymm by L (EVEX), xmm/xmm (VEX)
pub(crate) const C_A: u8 = 21; // address size GPR
pub(crate) const C_WY: u8 = 22; // 16 if 66 else 32 / 64 (W)  (used by some movs)
pub(crate) const C_VLQ: u8 = 23; // quarter vector: xmm,xmm,xmm by L
pub(crate) const C_DV: u8 = 24; // 32 unless REX.W (64), ignoring 66 (movsxd style)

// immediate kinds (cls when src == S_IMM)
pub(crate) const I_U8: u8 = 1; // u8imm, printed & 0xff
pub(crate) const I_S8: u8 = 2; // imm8 sign-extended to the operand size
pub(crate) const I_U16: u8 = 3;
pub(crate) const I_Z: u8 = 4; // imm16/imm32 by operand size (sign-extended when 64)
pub(crate) const I_V: u8 = 5; // imm16/32/64 by operand size (mov r64, imm64)
pub(crate) const I_S8N: u8 = 6; // imm8 sign-extended, "native" printing (push imm8)
pub(crate) const I_ZN: u8 = 7; // imm16/32 by operand size with d64 semantics (push imm)
pub(crate) const I_U32: u8 = 8;
pub(crate) const I_S16: u8 = 9; // imm16 sign-extended, printed signed
pub(crate) const I_ZS: u8 = 10; // imm16/32 sign-extended, printed signed
pub(crate) const I_W4: u8 = 11; // 4 immediate bytes consumed, low 16 bits printed (capstone quirk)
pub(crate) const I_LO4: u8 = 12; // low nibble of the is4 byte (no byte consumed)

// memory keyword (mk)
pub(crate) const K_DEF: u8 = 0; // derived from the register class
pub(crate) const K_NONE: u8 = 1;
pub(crate) const K_PTR: u8 = 2;
pub(crate) const K_B: u8 = 3;
pub(crate) const K_W: u8 = 4;
pub(crate) const K_D: u8 = 5;
pub(crate) const K_Q: u8 = 6;
pub(crate) const K_T: u8 = 7; // tbyte
pub(crate) const K_XW: u8 = 8; // xword (80-bit float)
pub(crate) const K_X: u8 = 9; // xmmword
pub(crate) const K_YMM: u8 = 10;
pub(crate) const K_ZMM: u8 = 11;
pub(crate) const K_V: u8 = 12; // by operand size
pub(crate) const K_Y: u8 = 13; // dword/qword by W
pub(crate) const K_VL: u8 = 14; // xmm/ymm/zmm by L
pub(crate) const K_VLH: u8 = 15; // qword/xmm/ymm by L (half)
pub(crate) const K_VLQ: u8 = 16; // dword/qword/xmm by L (quarter)
pub(crate) const K_VLE: u8 = 17; // word/dword/qword by L (eighth)
pub(crate) const K_N: u8 = 18; // dword/qword by mode
pub(crate) const K_A: u8 = 19; // by address size (word/dword/qword)
pub(crate) const K_Z: u8 = 20; // word/dword by operand size (64 -> dword)

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct OpSpec {
    pub src: u8,
    pub cls: u8,
    pub mk: u8,
}

// ---------------------------------------------------------------------------------------- flags
pub(crate) const F_MODRM: u64 = 1 << 0;
pub(crate) const F_LOCK: u64 = 1 << 1; // LOCK allowed (with memory operand)
pub(crate) const F_REP: u64 = 1 << 2; // F3 -> "rep", F2 -> "repne"
pub(crate) const F_REPE: u64 = 1 << 3; // F3 -> "repe", F2 -> "repne"
pub(crate) const F_BND: u64 = 1 << 4; // F2 -> "bnd"
pub(crate) const F_REPZ: u64 = 1 << 5; // F3 -> "repz"
pub(crate) const F_NOTRACK: u64 = 1 << 6; // 3E -> "notrack"
pub(crate) const F_XA: u64 = 1 << 7; // F2/F3 -> "xacquire"/"xrelease" even without lock
pub(crate) const F_D64: u64 = 1 << 8; // default 64-bit operand size in long mode
pub(crate) const F_F64: u64 = 1 << 9; // forced 64-bit operand size in long mode
pub(crate) const F_IMMU: u64 = 1 << 10; // print immediates unsigned (masked to operand size)
pub(crate) const F_NOVVVV: u64 = 1 << 11; // VEX/EVEX vvvv must be 1111
pub(crate) const F_EVK: u64 = 1 << 12; // EVEX: opmask decoration on first operand
pub(crate) const F_EVZ: u64 = 1 << 13; // EVEX: zeroing allowed
pub(crate) const F_BCST_D: u64 = 1 << 14; // EVEX.b on memory -> {1toN} dword elements
pub(crate) const F_BCST_Q: u64 = 1 << 15; // EVEX.b on memory -> {1toN} qword elements
pub(crate) const F_ER: u64 = 1 << 16; // EVEX.b on register form -> {rn-sae} rounding
pub(crate) const F_SAE: u64 = 1 << 17; // EVEX.b on register form -> {sae}
pub(crate) const F_3DN: u64 = 1 << 18;
pub(crate) const F_NOSEG: u64 = 1 << 19; // segment prefix not printed
pub(crate) const F_MODRM_MEMONLY: u64 = 1 << 20; // (internal)
pub(crate) const F_RELQ: u64 = 1 << 21; // capstone rel16/rel32 quirks for jmp/jcc (see decode)
pub(crate) const F_NOREXW_O: u64 = 1 << 22;
pub(crate) const F_BCST_W: u64 = 1 << 23; // {1toN} word elements
pub(crate) const F_KNOTZERO: u64 = 1 << 24; // EVEX: aaa must not be 0
pub(crate) const F_NOEVK: u64 = 1 << 25; // EVEX: aaa must be 0
pub(crate) const F_REGFORM: u64 = 1 << 26; // ModRM.mod ignored: rm is always a register
pub(crate) const F_CMP8: u64 = 1 << 27; // imm < 8 selects a cmpXXps alias (imm dropped)
pub(crate) const F_CMP32: u64 = 1 << 28; // imm < 32 selects a vcmpXXps alias
pub(crate) const F_REPF3: u64 = 1 << 29; // F3 -> "rep", F2 -> nothing (capstone movsd quirk)
pub(crate) const F_INVALID: u64 = 1 << 30; // explicit "INVALID" override entry
pub(crate) const F_Z66: u64 = 1 << 31; // accumulator/operand size: 16 with 66 else 32 (REX.W ignored)
pub(crate) const F_NOZ: u64 = 1 << 32; // EVEX.z must be 0
pub(crate) const F_NOBR: u64 = 1 << 33; // EVEX.b must be 0 (register form)
pub(crate) const F_NOBM: u64 = 1 << 34; // EVEX.b must be 0 (memory form)
pub(crate) const F_BCST_QB: u64 = 1 << 35; // {1toN} by qword, printed "byte ptr", disp8 unscaled
pub(crate) const F_NOPFX: u64 = 1 << 36; // (computed) entry has no mandatory-prefix constraint
pub(crate) const F_BCST_HALF: u64 = 1 << 37; // {1toN}: N = vector bytes / (2 * element size)
pub(crate) const F_VPCMP: u64 = 1 << 38; // AVX-512 vpcmp{b,w,d,q,u*} predicate aliases (imm 0-7 but 3, 7)
pub(crate) const F_VPCOM: u64 = 1 << 39; // XOP vpcom* predicate aliases (imm 0-7)

#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct Entry {
    pub mnem: u16,
    pub nops: u8,
    pub ops: [OpSpec; MAX_OPS],
    pub flags: u64,
    /// EVEX disp8 scale override (0 = memory operand size)
    pub dn: u8,
    /// First alias mnemonic id (cmpXXps style predicates), 0 if none.
    pub alias: u16,
    /// (derived) register class of the last S_VSIB operand, 0 if none.
    pub vsib: u8,
    /// (derived) has an S_KMASK operand.
    pub kmask: bool,
    /// (derived) has an S_KMASK or S_RC operand (formatted by the general op_str loop).
    pub fdeco: bool,
}

const CMP_PREDS: [&str; 32] = [
    "eq", "lt", "le", "unord", "neq", "nlt", "nle", "ord", "eq_uq", "nge", "ngt", "false", "neq_oq",
    "ge", "gt", "true", "eq_os", "lt_oq", "le_oq", "unord_s", "neq_us", "nlt_uq", "nle_uq", "ord_s",
    "eq_us", "nge_uq", "ngt_uq", "false_os", "neq_os", "ge_oq", "gt_oq", "true_us",
];

pub(crate) struct Tables {
    pub mnems: Vec<&'static str>,
    /// Mnemonics zero-padded to 31 bytes, byte 31 = length (fixed-size copies when formatting).
    pub mnem_pad: Vec<[u8; 32]>,
    pub entries: Vec<Entry>,
    pub roots: Vec<[u32; 256]>,
    pub nodes: Vec<u32>,
    /// Predicate alias mnemonic ids (Entry::alias + imm), 0 = no alias.
    pub aliases: Vec<u16>,
}

pub(crate) const LEAF: u32 = 1 << 31;

static TABLES: OnceLock<Tables> = OnceLock::new();

#[inline]
pub(crate) fn tables() -> &'static Tables {
    TABLES.get_or_init(build)
}

// ---------------------------------------------------------------------------------------- parsing

struct Raw {
    sel: [u8; NSEL], // bitmask of allowed values per selector (all ones = any)
    spec: u32,       // specificity
    entry: u16,
    line: u32,
}

fn full(k: usize) -> u8 {
    ((1u32 << ARITY[k]) - 1) as u8
}

fn map_index(s: &str) -> Option<usize> {
    Some(match s {
        "1" => MAP_1,
        "0f" => MAP_0F,
        "38" => MAP_38,
        "3a" => MAP_3A,
        "3dn" => MAP_3DN,
        "v1" => MAP_V1,
        "v2" => MAP_V1 + 1,
        "v3" => MAP_V1 + 2,
        "e1" => MAP_E1,
        "e2" => MAP_E1 + 1,
        "e3" => MAP_E1 + 2,
        "e5" => MAP_E1 + 3,
        "e6" => MAP_E1 + 4,
        "x8" => MAP_X8,
        "x9" => MAP_X8 + 1,
        "xa" => MAP_X8 + 2,
        _ => return None,
    })
}

fn parse_range(s: &str, max: u32) -> Option<u8> {
    // "3", "4-7", "0,2"
    let mut m = 0u32;
    for part in s.split(',') {
        if let Some((a, b)) = part.split_once('-') {
            let a: u32 = a.parse().ok()?;
            let b: u32 = b.parse().ok()?;
            if a > b || b >= max {
                return None;
            }
            for v in a..=b {
                m |= 1 << v;
            }
        } else {
            let v: u32 = part.parse().ok()?;
            if v >= max {
                return None;
            }
            m |= 1 << v;
        }
    }
    Some(m as u8)
}

fn parse_sel(tok: &str, sel: &mut [u8; NSEL]) -> Result<(), String> {
    let set = |sel: &mut [u8; NSEL], k: u32, m: u8| {
        let k = k as usize;
        if sel[k] == full(k) {
            sel[k] = m;
        } else {
            sel[k] &= m;
        }
    };
    // joinable prefixes / L values: "np|66", "l0|l1"
    // mandatory prefix values: 0 np, 1 66, 2 f3, 3 f2, 4 66+f3, 5 66+f2.
    // "f3"/"f2" include the 66-combined contexts; "xf3"/"xf2" exclude them; "6f3"/"6f2" are
    // only the 66-combined ones.
    if tok.contains('|') || matches!(tok, "np" | "66" | "f3" | "f2" | "xf3" | "xf2" | "6f3" | "6f2") {
        let mut m = 0u8;
        let mut kind = None;
        for p in tok.split('|') {
            let pm: Option<u8> = match p {
                "f3" => Some(0b000100),
                "f2" => Some(0b001000),
                "xf3" => Some(0b000100),
                "xf2" => Some(0b001000),
                "6f3" => Some(0b010000),
                "6f2" => Some(0b100000),
                _ => None,
            };
            if let Some(pm) = pm {
                if kind.is_some() && kind != Some(SEL_PFX) {
                    return Err(format!("mixed joined selector {tok}"));
                }
                kind = Some(SEL_PFX);
                m |= pm;
                continue;
            }
            let (k, v) = match p {
                "np" => (SEL_PFX, 0),
                "66" => (SEL_PFX, 1),
                "l0" => (SEL_L, 0),
                "l1" => (SEL_L, 1),
                "l2" => (SEL_L, 2),
                "l3" => (SEL_L, 3),
                "o16" => (SEL_O, 0),
                "o32" => (SEL_O, 1),
                "o64" => (SEL_O, 2),
                "d16" => (SEL_D, 0),
                "d32" => (SEL_D, 1),
                "d64" => (SEL_D, 2),
                "a16" => (SEL_A, 0),
                "a32" => (SEL_A, 1),
                "a64" => (SEL_A, 2),
                _ => return Err(format!("bad joined selector {p}")),
            };
            if kind.is_some() && kind != Some(k) {
                return Err(format!("mixed joined selector {tok}"));
            }
            kind = Some(k);
            m |= 1 << v;
        }
        set(sel, kind.unwrap(), m);
        return Ok(());
    }
    match tok {
        "mode32" => set(sel, SEL_MODE, 1),
        "mode64" => set(sel, SEL_MODE, 2),
        "w0" => set(sel, SEL_W, 1),
        "w1" => set(sel, SEL_W, 2),
        "l0" => set(sel, SEL_L, 1),
        "l1" => set(sel, SEL_L, 2),
        "l2" => set(sel, SEL_L, 4),
        "l3" => set(sel, SEL_L, 8),
        "b0" => set(sel, SEL_B, 1),
        "b1" => set(sel, SEL_B, 2),
        "m" => set(sel, SEL_MOD, 1),
        "r" => set(sel, SEL_MOD, 2),
        "rexb0" => set(sel, SEL_REXB, 1),
        "rexb1" => set(sel, SEL_REXB, 2),
        "o16" => set(sel, SEL_O, 1),
        "o32" => set(sel, SEL_O, 2),
        "o64" => set(sel, SEL_O, 4),
        "d16" => set(sel, SEL_D, 1),
        "d32" => set(sel, SEL_D, 2),
        "d64" => set(sel, SEL_D, 4),
        "a16" => set(sel, SEL_A, 1),
        "a32" => set(sel, SEL_A, 2),
        "a64" => set(sel, SEL_A, 4),
        "n66" => set(sel, SEL_H66, 1),
        "p66" => set(sel, SEL_H66, 2),
        _ => {
            if let Some(r) = tok.strip_prefix('/') {
                let m = parse_range(r, 8).ok_or_else(|| format!("bad /reg {tok}"))?;
                set(sel, SEL_REG, m);
            } else if let Some(r) = tok.strip_prefix("rm") {
                let m = parse_range(r, 8).ok_or_else(|| format!("bad rm {tok}"))?;
                set(sel, SEL_RM, m);
                set(sel, SEL_MOD, 2);
            } else if let Some(hex) = tok.strip_prefix('@') {
                // exact ModRM byte (mod must be 3)
                let b = u8::from_str_radix(hex, 16).map_err(|_| format!("bad modrm {tok}"))?;
                if b < 0xC0 {
                    return Err(format!("exact modrm must be >= c0: {tok}"));
                }
                set(sel, SEL_MOD, 2);
                set(sel, SEL_REG, 1 << ((b >> 3) & 7));
                set(sel, SEL_RM, 1 << (b & 7));
            } else {
                return Err(format!("bad selector {tok}"));
            }
        }
    }
    Ok(())
}

fn reg_class(s: &str) -> Option<u8> {
    Some(match s {
        "b" => C_B,
        "w" => C_W,
        "d" => C_D,
        "q" => C_Q,
        "v" => C_V,
        "y" => C_Y,
        "z" => C_Z,
        "n" => C_N,
        "s" => C_SEG,
        "c" => C_CR,
        "dr" => C_DR,
        "mm" => C_MM,
        "x" => C_XMM,
        "ymm" => C_YMM,
        "zmm" => C_ZMM,
        "X" => C_VL,
        "Xh" => C_VLH,
        "Xq" => C_VLQ,
        "k" => C_K,
        "bnd" => C_BND,
        "st" => C_ST,
        "A" => C_A,
        "wy" => C_WY,
        "dv" => C_DV,
        _ => return None,
    })
}

fn mem_kw(s: &str) -> Option<u8> {
    Some(match s {
        "n" => K_NONE,
        "p" => K_PTR,
        "b" => K_B,
        "w" => K_W,
        "d" => K_D,
        "q" => K_Q,
        "t" => K_T,
        "xw" => K_XW,
        "x" => K_X,
        "ymm" => K_YMM,
        "zmm" => K_ZMM,
        "v" => K_V,
        "y" => K_Y,
        "X" => K_VL,
        "Xh" => K_VLH,
        "Xq" => K_VLQ,
        "Xe" => K_VLE,
        "N" => K_N,
        "A" => K_A,
        "z" => K_Z,
        _ => return None,
    })
}

fn parse_op(tok: &str) -> Result<OpSpec, String> {
    let bad = || format!("bad operand {tok}");
    match tok {
        "1" => return Ok(OpSpec { src: S_CONST1, cls: 0, mk: 0 }),
        "rc" => return Ok(OpSpec { src: S_RC, cls: 0, mk: 0 }),
        "kmask" => return Ok(OpSpec { src: S_KMASK, cls: 0, mk: 0 }),
        "eAX" => return Ok(OpSpec { src: S_ACC, cls: C_V, mk: 0 }),
        "zAX" => return Ok(OpSpec { src: S_ACC, cls: C_Z, mk: 0 }),
        "aAX" => return Ok(OpSpec { src: S_ACC, cls: C_A, mk: 0 }),
        "nAX" => return Ok(OpSpec { src: S_ACC, cls: C_N, mk: 0 }),
        "far" => return Ok(OpSpec { src: S_FARPTR, cls: 0, mk: 0 }),
        "farc" => return Ok(OpSpec { src: S_FARPTR, cls: 1, mk: 0 }),
        _ => {}
    }
    if let Some((src, rest)) = tok.split_once(':') {
        let (cls_s, mk_s) = match rest.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (rest, None),
        };
        let src = match src {
            "r" => S_REG,
            "m" => S_RM,
            "M" => S_MEM,
            "R" => S_RMREG,
            "v" => S_VVVV,
            "o" => S_OPREG,
            "4" => S_IS4,
            "i" => S_IMM,
            "j" => S_REL,
            "a" => S_MOFFS,
            "S" => S_STRSRC,
            "D" => S_STRDST,
            "Vs" => S_VSIB,
            _ => return Err(bad()),
        };
        let cls = match src {
            S_IMM => match cls_s {
                "b" => I_U8,
                "bs" => I_S8,
                "bn" => I_S8N,
                "w" => I_U16,
                "z" => I_Z,
                "zn" => I_ZN,
                "v" => I_V,
                "d" => I_U32,
                "ws" => I_S16,
                "zs" => I_ZS,
                "w4" => I_W4,
                "lo4" => I_LO4,
                _ => return Err(bad()),
            },
            S_REL => match cls_s {
                "b" => 1,
                "z" => 4,
                _ => return Err(bad()),
            },
            S_MEM if cls_s.is_empty() => 0,
            _ => reg_class(cls_s).ok_or_else(bad)?,
        };
        let mk = match mk_s {
            Some(m) => mem_kw(m).ok_or_else(bad)?,
            None => K_DEF,
        };
        return Ok(OpSpec { src, cls, mk });
    }
    // fixed register
    let name = match tok {
        "st0" => "st(0)",
        "st1" => "st(1)",
        _ => tok,
    };
    let r = super::Reg::from_name(name).ok_or_else(bad)?;
    Ok(OpSpec { src: S_FIXED, cls: r.0, mk: 0 })
}

fn parse_flag(tok: &str) -> Result<u64, String> {
    Ok(match tok {
        "lock" => F_LOCK,
        "rep" => F_REP,
        "repe" => F_REPE,
        "bnd" => F_BND,
        "repz" => F_REPZ,
        "notrack" => F_NOTRACK,
        "xa" => F_XA,
        "d64" => F_D64,
        "f64" => F_F64,
        "immu" => F_IMMU,
        "novvvv" => F_NOVVVV,
        "k" => F_EVK,
        "kz" => F_EVK | F_EVZ,
        "z" => F_EVZ,
        "noz" => F_NOZ,
        "nobr" => F_NOBR,
        "nobm" => F_NOBM,
        "bqb" => F_BCST_QB,
        "bh" => F_BCST_HALF,
        "vpcmp" => F_VPCMP,
        "vpcom" => F_VPCOM,
        "bd" => F_BCST_D,
        "bq" => F_BCST_Q,
        "bw" => F_BCST_W,
        "er" => F_ER,
        "sae" => F_SAE,
        "noseg" => F_NOSEG,
        "modrm" => F_MODRM,
        "relq" => F_RELQ,
        "knz" => F_KNOTZERO,
        "nok" => F_NOEVK,
        "regform" => F_REGFORM,
        "cmp8" => F_CMP8,
        "cmp32" => F_CMP32,
        "repf3" => F_REPF3,
        "z66" => F_Z66,
        _ => return Err(format!("bad flag {tok}")),
    })
}

struct Builder {
    mnems: Vec<&'static str>,
    mnem_idx: std::collections::HashMap<&'static str, u16>,
    entries: Vec<Entry>,
    raws: Vec<Vec<Raw>>, // per map*256 + opcode
    errors: Vec<String>,
    aliases: Vec<u16>,
}

impl Builder {
    fn mnem(&mut self, m: &'static str) -> u16 {
        if let Some(&i) = self.mnem_idx.get(m) {
            return i;
        }
        let i = self.mnems.len() as u16;
        self.mnems.push(m);
        self.mnem_idx.insert(m, i);
        i
    }

    fn line(&mut self, ln: u32, line: &'static str) -> Result<(), String> {
        let line = match line.find('#') {
            Some(p) => &line[..p],
            None => line,
        };
        let line = line.trim();
        if line.is_empty() {
            return Ok(());
        }
        let (lhs, rhs) = line.split_once(':').ok_or("missing ':'")?;
        // careful: operands contain ':' too; the first ':' surrounded by spaces separates.
        let (lhs, rhs) = if let Some(p) = line.find(" : ") {
            (&line[..p], &line[p + 3..])
        } else {
            (lhs, rhs)
        };
        let mut lt = lhs.split_whitespace();
        let map = map_index(lt.next().ok_or("no map")?).ok_or("bad map")?;
        let opc = lt.next().ok_or("no opcode")?;
        let (lo, hi) = match opc.split_once('-') {
            Some((a, b)) => (
                u8::from_str_radix(a, 16).map_err(|_| "bad opcode")?,
                u8::from_str_radix(b, 16).map_err(|_| "bad opcode")?,
            ),
            None => {
                let v = u8::from_str_radix(opc, 16).map_err(|_| "bad opcode")?;
                (v, v)
            }
        };
        let mut sel = [0u8; NSEL];
        for (k, s) in sel.iter_mut().enumerate() {
            *s = full(k);
        }
        let mut uses_modrm_sel = false;
        for t in lt {
            parse_sel(t, &mut sel)?;
        }
        for k in [SEL_MOD, SEL_REG, SEL_RM] {
            if sel[k as usize] != full(k as usize) {
                uses_modrm_sel = true;
            }
        }
        let (body, flags_s) = match rhs.split_once(';') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (rhs.trim(), ""),
        };
        let (mn, ops_s) = match body.split_once(char::is_whitespace) {
            Some((a, b)) => (a, b.trim()),
            None => (body, ""),
        };
        let mut e = Entry { mnem: self.mnem(mn), ..Default::default() };
        if mn == "INVALID" {
            e.flags |= F_INVALID;
        }
        if !ops_s.is_empty() {
            for (i, t) in ops_s.split(',').enumerate() {
                if i >= MAX_OPS {
                    return Err("too many operands".into());
                }
                e.ops[i] = parse_op(t.trim())?;
                e.nops += 1;
            }
        }
        for o in &e.ops[..e.nops as usize] {
            if o.src == S_VSIB {
                e.vsib = o.cls;
            } else if o.src == S_KMASK {
                e.kmask = true;
            }
            if o.src == S_KMASK || o.src == S_RC {
                e.fdeco = true;
            }
        }
        for t in flags_s.split_whitespace() {
            if let Some(n) = t.strip_prefix('n').and_then(|x| x.parse::<u8>().ok()) {
                e.dn = n;
                continue;
            }
            e.flags |= parse_flag(t)?;
        }
        if uses_modrm_sel || e.ops.iter().any(|o| matches!(o.src, S_REG | S_RM | S_MEM | S_RMREG | S_VSIB)) {
            e.flags |= F_MODRM;
        }
        if map == MAP_3DN {
            e.flags |= F_3DN | F_MODRM;
        }
        if e.flags & (F_CMP8 | F_CMP32 | F_VPCMP | F_VPCOM) != 0 {
            // "cmpps" -> cmpeqps.. ; "vcmpps" -> vcmpeqps.. ; "vpcmpd" -> vpcmpeqd ; "vpcomb" -> vpcomltb
            const VPCMP: [&str; 8] = ["eq", "lt", "le", "#3", "neq", "nlt", "nle", "#7"];
            const VPCOM: [&str; 8] = ["lt", "le", "gt", "ge", "eq", "neq", "false", "true"];
            let (pre, suf, preds): (&str, &str, &[&str]) = if e.flags & F_VPCMP != 0 {
                (&mn[..5], &mn[5..], &VPCMP)
            } else if e.flags & F_VPCOM != 0 {
                (&mn[..5], &mn[5..], &VPCOM)
            } else {
                let (a, b) = mn.split_at(mn.len() - 2);
                (a, b, if e.flags & F_CMP8 != 0 { &CMP_PREDS[..8] } else { &CMP_PREDS[..] })
            };
            let first = self.aliases.len() as u16;
            for p in preds.iter() {
                let id = if p.starts_with('#') {
                    0
                } else {
                    let name: &'static str = Box::leak(format!("{pre}{p}{suf}").into_boxed_str());
                    self.mnem(name)
                };
                self.aliases.push(id);
            }
            e.alias = first;
        }
        if sel[SEL_PFX as usize] == full(SEL_PFX as usize) {
            e.flags |= F_NOPFX;
        }
        let idx = self.entries.len() as u16;
        self.entries.push(e);
        let mut spec: u32 = (0..NSEL).map(|k| if sel[k] != full(k) { 1 + (8 - sel[k].count_ones()) } else { 0 }).sum();
        if mn == "INVALID" {
            // explicit invalidity overrides always win
            spec += 1000;
        }
        for op in lo..=hi {
            self.raws[map * 256 + op as usize].push(Raw { sel, spec, entry: idx, line: ln });
        }
        Ok(())
    }

    fn build_node(&mut self, nodes: &mut Vec<u32>, list: &[&Raw], level: usize, ctx: &str) -> u32 {
        if list.is_empty() {
            return 0;
        }
        for k in level..NSEL {
            let f = full(k);
            if list.iter().any(|r| r.sel[k] != f) {
                // make a switch at this level
                let ar = ARITY[k] as usize;
                let off = nodes.len();
                nodes.push(k as u32);
                nodes.extend(std::iter::repeat_n(0, ar));
                for v in 0..ar {
                    let sub: Vec<&Raw> = list.iter().copied().filter(|r| r.sel[k] & (1 << v) != 0).collect();
                    let child = self.build_node(nodes, &sub, k + 1, ctx);
                    nodes[off + 1 + v] = child;
                }
                return off as u32;
            }
        }
        // leaf: most specific wins
        let best = list.iter().map(|r| r.spec).max().unwrap_or(0);
        let winners: Vec<&&Raw> = list.iter().filter(|r| r.spec == best).collect();
        if winners.len() > 1 {
            let e0 = &self.entries[winners[0].entry as usize];
            let same = |e: &Entry| e.mnem == e0.mnem && e.nops == e0.nops && e.ops == e0.ops && e.flags == e0.flags;
            if winners.iter().any(|w| !same(&self.entries[w.entry as usize])) {
                self.errors.push(format!(
                    "{ctx}: ambiguous entries at lines {:?}",
                    winners.iter().map(|w| w.line).collect::<Vec<_>>()
                ));
            }
        }
        LEAF | winners[0].entry as u32
    }
}

fn build() -> Tables {
    let mut b = Builder {
        mnems: vec![""],
        mnem_idx: Default::default(),
        entries: vec![Entry::default()],
        raws: (0..NMAPS * 256).map(|_| Vec::new()).collect(),
        errors: vec![],
        aliases: vec![0],
    };
    for (si, spec) in [super::spec_legacy::SPEC, super::spec_sse::SPEC, super::spec_vex::SPEC, super::spec_evex::SPEC]
        .iter()
        .enumerate()
    {
        for (ln, line) in spec.lines().enumerate() {
            let ln = (si as u32 + 1) * 100000 + ln as u32 + 1;
            if let Err(e) = b.line(ln, line) {
                b.errors.push(format!("spec line {ln}: {e}: {line}"));
            }
        }
    }
    let mut nodes = vec![0u32];
    let mut roots = vec![[0u32; 256]; NMAPS];
    let raws = std::mem::take(&mut b.raws);
    for map in 0..NMAPS {
        for op in 0..256 {
            let list: Vec<&Raw> = raws[map * 256 + op].iter().collect();
            if list.is_empty() {
                continue;
            }
            let ctx = format!("map {map} op {op:02x}");
            roots[map][op] = b.build_node(&mut nodes, &list, 0, &ctx);
        }
    }
    if !b.errors.is_empty() {
        // Spec errors are programming errors; report them loudly in debug builds / tests.
        #[cfg(debug_assertions)]
        panic!("x86 spec errors:\n{}", b.errors.join("\n"));
        #[cfg(not(debug_assertions))]
        eprintln!("x86 spec errors:\n{}", b.errors.join("\n"));
    }
    let _ = regs::NREGS;
    let mnem_pad = b
        .mnems
        .iter()
        .map(|m| {
            let mut p = [0u8; 32];
            let n = m.len().min(31);
            p[..n].copy_from_slice(&m.as_bytes()[..n]);
            p[31] = n as u8;
            p
        })
        .collect();
    Tables { mnems: b.mnems, mnem_pad, entries: b.entries, roots, nodes, aliases: b.aliases }
}

