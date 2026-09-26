//! x86 register identifiers, named exactly like capstone 5 prints them.

/// A register. `Reg::NONE` (0) means "no register".
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, PartialOrd, Ord)]
pub struct Reg(pub u8);

// Register id layout (contiguous classes so that `base + n` addressing works).
pub(crate) const AL: u8 = 1; // al cl dl bl
pub(crate) const AH: u8 = 5; // ah ch dh bh
pub(crate) const SPL: u8 = 9; // spl bpl sil dil  (so AL+n for n in 0..4, SPL-4+n for n in 4..8)
pub(crate) const R8B: u8 = 13; // r8b..r15b
pub(crate) const AX: u8 = 21; // ax..di, r8w..r15w
pub(crate) const EAX: u8 = 37; // eax..edi, r8d..r15d
pub(crate) const RAX: u8 = 53; // rax..rdi, r8..r15
pub(crate) const RIP: u8 = 69;
pub(crate) const EIP: u8 = 70;
pub(crate) const IP: u8 = 71;
pub(crate) const ES: u8 = 72; // es cs ss ds fs gs
pub(crate) const CR0: u8 = 78; // cr0..cr15
pub(crate) const DR0: u8 = 94; // dr0..dr15
pub(crate) const ST0: u8 = 110; // st(0)..st(7)
pub(crate) const MM0: u8 = 118; // mm0..mm7
pub(crate) const XMM0: u8 = 126; // xmm0..xmm31
pub(crate) const YMM0: u8 = 158; // ymm0..ymm31
pub(crate) const ZMM0: u8 = 190; // zmm0..zmm31
pub(crate) const K0: u8 = 222; // k0..k7
pub(crate) const BND0: u8 = 230; // bnd0..bnd3
pub(crate) const RFLAGS: u8 = 234;
pub(crate) const FPSW: u8 = 235;
pub(crate) const MXCSR: u8 = 236;
pub(crate) const RIZ: u8 = 237;
pub(crate) const EIZ: u8 = 238;
pub(crate) const NREGS: usize = 239;

pub(crate) static NAMES: [&str; NREGS] = [
    "", "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", "spl", "bpl", "sil", "dil", "r8b", "r9b",
    "r10b", "r11b", "r12b", "r13b", "r14b", "r15b", "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "eax", "ecx", "edx", "ebx", "esp",
    "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "rax", "rcx",
    "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "eip", "ip", "es", "cs", "ss", "ds", "fs", "gs", "cr0", "cr1", "cr2", "cr3", "cr4", "cr5",
    "cr6", "cr7", "cr8", "cr9", "cr10", "cr11", "cr12", "cr13", "cr14", "cr15", "dr0", "dr1", "dr2",
    "dr3", "dr4", "dr5", "dr6", "dr7", "dr8", "dr9", "dr10", "dr11", "dr12", "dr13", "dr14", "dr15",
    "st(0)", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)", "mm0", "mm1", "mm2",
    "mm3", "mm4", "mm5", "mm6", "mm7", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6",
    "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "xmm16", "xmm17",
    "xmm18", "xmm19", "xmm20", "xmm21", "xmm22", "xmm23", "xmm24", "xmm25", "xmm26", "xmm27",
    "xmm28", "xmm29", "xmm30", "xmm31", "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6",
    "ymm7", "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15", "ymm16", "ymm17",
    "ymm18", "ymm19", "ymm20", "ymm21", "ymm22", "ymm23", "ymm24", "ymm25", "ymm26", "ymm27",
    "ymm28", "ymm29", "ymm30", "ymm31", "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6",
    "zmm7", "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15", "zmm16", "zmm17",
    "zmm18", "zmm19", "zmm20", "zmm21", "zmm22", "zmm23", "zmm24", "zmm25", "zmm26", "zmm27",
    "zmm28", "zmm29", "zmm30", "zmm31", "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7", "bnd0",
    "bnd1", "bnd2", "bnd3", "rflags", "fpsw", "mxcsr", "riz", "eiz",
];

impl Reg {
    pub const NONE: Reg = Reg(0);

    /// capstone's name for the register ("" for NONE).
    #[inline]
    pub fn name(self) -> &'static str {
        NAMES.get(self.0 as usize).copied().unwrap_or("")
    }
    #[inline]
    pub fn is_none(self) -> bool {
        self.0 == 0
    }
    /// Look a register up by its capstone name.
    pub fn from_name(name: &str) -> Option<Reg> {
        NAMES.iter().position(|n| *n == name && !n.is_empty()).map(|i| Reg(i as u8))
    }
    /// Size in bytes of a general purpose / vector register (0 if unknown).
    pub fn size(self) -> u8 {
        match self.0 {
            1..=20 => 1,
            21..=36 | IP | 72..=77 => 2,
            37..=52 | EIP => 4,
            53..=68 | RIP => 8,
            ST0..=117 => 10,
            MM0..=125 => 8,
            XMM0..=157 => 16,
            YMM0..=189 => 32,
            ZMM0..=221 => 64,
            K0..=229 => 8,
            _ => 0,
        }
    }
    /// For a general purpose register, the full 64-bit register (e.g. `eax` -> `rax`, `ah` -> `rax`).
    pub fn gpr64(self) -> Option<Reg> {
        let n = match self.0 {
            1..=4 => self.0 - 1,
            5..=8 => self.0 - 5,
            9..=12 => self.0 - 5,
            13..=20 => self.0 - 5,
            21..=36 => self.0 - AX,
            37..=52 => self.0 - EAX,
            53..=68 => self.0 - RAX,
            _ => return None,
        };
        Some(Reg(RAX + n))
    }
}

/// 8-bit GPR number `n` (0..16); `rex` selects spl/bpl/sil/dil instead of ah/ch/dh/bh.
#[inline]
pub(crate) fn gpr8(n: u8, rex: bool) -> u8 {
    if n < 4 {
        AL + n
    } else if n < 8 {
        if rex { SPL + n - 4 } else { AH + n - 4 }
    } else {
        R8B + (n - 8)
    }
}

/// GPR of the given size in bytes.
#[inline]
pub(crate) fn gpr(n: u8, size: u8, rex: bool) -> u8 {
    match size {
        1 => gpr8(n, rex),
        2 => AX + n,
        4 => EAX + n,
        _ => RAX + n,
    }
}
