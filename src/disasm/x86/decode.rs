//! The x86 decoding engine: prefixes, opcode maps, VEX/EVEX/XOP, ModRM/SIB, operands.
//! Mirrors capstone 5's (LLVM-derived) decoder semantics, including its quirks.

use super::regs::*;
use super::tables::*;
use super::{Insn, Mem, MemSize, Mode, Operand, Reg, MAX_OPS};

// operand print flags (Insn::ofmt)
pub(crate) const OF_SIGNED: u8 = 1; // immediate printed signed
pub(crate) const OF_MOFFS: u8 = 2; // memory displacement printed unsigned (moffs)

// printed prefix ids (see format::PREFIX_STR)
pub(crate) const P_NONE: u8 = 0;
pub(crate) const P_LOCK: u8 = 1;
pub(crate) const P_REP: u8 = 2;
pub(crate) const P_REPE: u8 = 3;
pub(crate) const P_REPNE: u8 = 4;
pub(crate) const P_BND: u8 = 5;
pub(crate) const P_REPZ: u8 = 6;
pub(crate) const P_NOTRACK: u8 = 7;
pub(crate) const P_BND_NOTRACK: u8 = 8;
pub(crate) const P_XACQ_LOCK: u8 = 9;
pub(crate) const P_XREL_LOCK: u8 = 10;
pub(crate) const P_XACQ: u8 = 11;
pub(crate) const P_XREL: u8 = 12;

#[inline(always)]
fn is_legacy_prefix(b: u8) -> bool {
    matches!(b, 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 | 0x67)
}

/// Prefix byte classes: bit 0 legacy prefix, bit 1 REX (0x40-0x4F, 64-bit mode only).
static PFX_CLASS: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut b = 0;
    while b < 256 {
        let v = b as u8;
        if matches!(v, 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 | 0x67) {
            t[b] = 1;
        } else if v & 0xF0 == 0x40 {
            t[b] = 2;
        }
        b += 1;
    }
    t
};

/// Opcode bytes that start a 0F escape or a VEX / EVEX / XOP prefix.
static ESC_BYTE: [bool; 256] = {
    let mut t = [false; 256];
    t[0x0F] = true;
    t[0xC4] = true;
    t[0xC5] = true;
    t[0x62] = true;
    t[0x8F] = true;
    t
};

const VEX_NONE: u8 = 0;
const VEX_VEX: u8 = 1;
const VEX_EVEX: u8 = 2;
const VEX_XOP: u8 = 3;

struct St<'a> {
    d: &'a [u8],
    n: usize,
    pos: usize,
    m64: bool,
    rex: u8,
    // vector extension state
    vex: u8,
    vvvv: u8, // full 5-bit register number (already un-inverted)
    l: u8,
    w: bool,
    evex_rr: u8, // EVEX.R' (as 0/16)
    evex_x: u8, // EVEX.X as 0/16 for register rm
    evex_z: bool,
    evex_b: bool,
    evex_aaa: u8,
    evex_vp: u8, // V' as 0/16
    // modrm
    modrm: u8,
    has_modrm: bool,
    osz: u8,
    asz: u8,
    seg: u8, // segment register id or 0
    disp8n: u8, // EVEX compressed disp8 scale
    has66: bool,
    mosz: u8, // operand size used for memory size keywords
    vvvv_hi: u8, // 32-bit mode: ignored vvvv bit 3 (still must be 0 when vvvv is unused)
    z16: bool,
    is4: u8,
    vsib: u8,   // VSIB index register class (0 = normal SIB)
    rel: u8,    // 1 + index of the relative branch operand (0 = none)
}

impl St<'_> {
    #[inline(always)]
    fn byte(&mut self) -> Option<u8> {
        if self.pos < self.n {
            let b = self.d[self.pos];
            self.pos += 1;
            Some(b)
        } else {
            None
        }
    }
    #[inline(always)]
    fn le(&mut self, size: usize) -> Option<u64> {
        if self.pos + size > self.n {
            return None;
        }
        let mut v = 0u64;
        for k in 0..size {
            v |= (self.d[self.pos + k] as u64) << (8 * k);
        }
        self.pos += size;
        Some(v)
    }
}

#[inline]
fn seg_reg(prefix: u8) -> u8 {
    match prefix {
        0x26 => ES,
        0x2E => ES + 1,
        0x36 => ES + 2,
        0x3E => ES + 3,
        0x64 => ES + 4,
        0x65 => ES + 5,
        _ => 0,
    }
}

pub(crate) fn decode_into(data: &[u8], addr: u64, mode: Mode, out: &mut Insn) -> bool {
    match mode {
        Mode::X86_64 => decode_impl::<true, true, true>(data, addr, mode, out),
        Mode::X86_32 => decode_impl::<true, false, true>(data, addr, mode, out),
    }
}

/// Length-only decode: the same decoder instantiated into a local scratch `Insn`, so the
/// operand values it never reads are dead code; validity checks are all kept.
pub(crate) fn insn_len(data: &[u8], mode: Mode) -> usize {
    let mut insn = Insn::default();
    let ok = match mode {
        Mode::X86_64 => decode_impl::<true, true, false>(data, 0, mode, &mut insn),
        Mode::X86_32 => decode_impl::<true, false, false>(data, 0, mode, &mut insn),
    };
    if ok { insn.size as usize } else { 0 }
}

/// Instructions with legacy prefixes (restart of the specialized path below).
#[inline(never)]
fn decode_prefixed(data: &[u8], addr: u64, mode: Mode, out: &mut Insn) -> bool {
    match mode {
        Mode::X86_64 => decode_impl::<false, true, true>(data, addr, mode, out),
        Mode::X86_32 => decode_impl::<false, false, true>(data, addr, mode, out),
    }
}

/// The decoder. `NOLEG = true` is the common-case instantiation: it hands any instruction with a
/// legacy (non-REX) prefix to the `false` one, so all legacy prefix state is compile-time
/// constant there and the prefix rules below fold away. Same source for both.
/// `FULL = false` (insn_len) only needs validity + length: operand values are not stored.
#[inline(always)]
fn decode_impl<const NOLEG: bool, const M64: bool, const FULL: bool>(data: &[u8], addr: u64, mode: Mode, out: &mut Insn) -> bool {
    let t = tables();
    let n = data.len().min(15);
    let d = &data[..n];
    let m64 = M64; // == (mode == Mode::X86_64), a constant per instantiation
    let mut i = 0usize;
    let mut lockrep = 0u8;
    let mut segp = 0u8;
    let mut has66 = false;
    let mut has67 = false;
    let mut rex = 0u8;
    let mut xacq = 0u8;
    // LLVM-7 style mandatory prefix: the last F2/F3 immediately followed by 0F/66/REX, else a 66
    // immediately followed by 0F/REX (only if no F2/F3 was mandatory).
    let mut mand = 0u8;
    let pfx_mask = 1 | ((m64 as u8) << 1);
    loop {
        if i >= n {
            return false;
        }
        let b = d[i];
        if PFX_CLASS[b as usize] & pfx_mask == 0 {
            break; // not a prefix: fast exit (common case)
        }
        if m64 && b & 0xF0 == 0x40 {
            let mut j = i + 1;
            while j < n && d[j] & 0xF0 == 0x40 {
                j += 1;
            }
            if j >= n {
                return false;
            }
            if is_legacy_prefix(d[j]) {
                i = j;
                continue;
            }
            rex = d[j - 1];
            i = j;
            break;
        }
        if NOLEG {
            return decode_prefixed(data, addr, mode, out);
        }
        match b {
            0xF0 | 0xF2 | 0xF3 => {
                if i == 0 && b != 0xF0 {
                    if i + 1 >= n {
                        return false;
                    }
                    let nb = d[i + 1];
                    if nb == 0xF0 || (nb & 0xFE) == 0x86 || (nb & 0xF8) == 0x90 {
                        xacq = b;
                    }
                    if b == 0xF3 && matches!(nb, 0x88 | 0x89 | 0xC6 | 0xC7) {
                        xacq = b;
                    }
                    if m64 && nb & 0xF0 == 0x40 && i + 2 >= n {
                        return false;
                    }
                }
                if b != 0xF0 && i + 1 < n {
                    let nb = d[i + 1];
                    if nb == 0x0F || nb == 0x66 || (m64 && nb & 0xF0 == 0x40) {
                        mand = b;
                    }
                }
                lockrep = b;
            }
            0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => segp = b,
            0x66 => {
                has66 = true;
                if mand == 0 && i + 1 < n {
                    let nb = d[i + 1];
                    if nb == 0x0F || (m64 && nb & 0xF0 == 0x40) {
                        mand = 0x66;
                    }
                }
            }
            0x67 => has67 = true,
            _ => break,
        }
        i += 1;
    }

    let mut st = St {
        d,
        n,
        pos: i,
        m64,
        rex,
        vex: VEX_NONE,
        vvvv: 0,
        l: 0,
        w: rex & 8 != 0,
        evex_rr: 0,
        evex_x: 0,
        evex_z: false,
        evex_b: false,
        evex_aaa: 0,
        evex_vp: 0,
        modrm: 0,
        has_modrm: false,
        osz: 4,
        asz: if m64 { if has67 { 4 } else { 8 } } else if has67 { 2 } else { 4 },
        seg: seg_reg(segp),
        disp8n: 1,
        vsib: 0,
        has66,
        mosz: 4,
        vvvv_hi: 0,
        z16: false,
        is4: 0,
        rel: 0,
    };

    // ------------------------------------------------------------------ opcode / vector prefixes
    let b = st.byte().unwrap_or(0);
    // one table lookup rules out all escape / vector-prefix bytes for most opcodes
    let esc = ESC_BYTE[b as usize];
    let map: usize;
    let op: u8;
    let mut pfx: usize; // mandatory prefix selector value
    let mut opcode = [0u8; 4];
    if esc && b == 0x0F {
        let b2 = match st.byte() {
            Some(x) => x,
            None => return false,
        };
        if b2 == 0x38 || b2 == 0x3A {
            let b3 = match st.byte() {
                Some(x) => x,
                None => return false,
            };
            map = if b2 == 0x38 { MAP_38 } else { MAP_3A };
            op = b3;
            opcode = [0x0F, b2, b3, 0];
        } else if b2 == 0x0F {
            map = MAP_3DN;
            op = 0;
            opcode = [0x0F, 0x0F, 0, 0];
        } else {
            map = MAP_0F;
            op = b2;
            opcode = [0x0F, b2, 0, 0];
        }
        // context: the mandatory prefix alone, else the legacy prefixes (66 / F2|F3)
        pfx = match mand {
            0x66 => 1,
            0xF3 => 2,
            0xF2 => 3,
            _ => {
                let r = match lockrep {
                    0xF3 => 2,
                    0xF2 => 3,
                    _ => 0,
                };
                if r != 0 {
                    // XS/XD + ADSIZE contexts are empty in 32-bit mode
                    if has67 && !m64 && !has66 {
                        return false;
                    }
                    // REX.W contexts have no OPSIZE variant (REXW_XS / REXW_XD win)
                    if m64 && rex & 8 != 0 {
                        r
                    } else {
                        r + 2 * has66 as usize
                    }
                } else {
                    has66 as usize
                }
            }
        };
    } else if esc && (b == 0xC4 || b == 0xC5) && st.pos < n && (m64 || d[st.pos] & 0xC0 == 0xC0) {
        // VEX (a LOCK or REX prefix makes it invalid; 66/F2/F3 are ignored)
        if lockrep == 0xF0 || rex != 0 {
            return false;
        }
        let b1 = d[st.pos];
        st.pos += 1;
        let (r, x, bb, mmmmm, b2) = if b == 0xC5 {
            (b1 & 0x80 == 0, false, false, 1u8, b1 & 0x7F)
        } else {
            let b2 = match st.byte() {
                Some(v) => v,
                None => return false,
            };
            (b1 & 0x80 == 0, b1 & 0x40 == 0, b1 & 0x20 == 0, b1 & 0x1F, b2)
        };
        let w = b == 0xC4 && b2 & 0x80 != 0;
        let vvvv = (!b2 >> 3) & 0xF;
        st.vex = VEX_VEX;
        st.l = (b2 >> 2) & 1;
        st.w = w;
        pfx = (b2 & 3) as usize;
        pfx = [0, 1, 2, 3][pfx];
        if m64 {
            st.rex = 0x40 | ((w as u8) << 3) | ((r as u8) << 2) | ((x as u8) << 1) | bb as u8;
            st.vvvv = vvvv;
        } else {
            st.rex = 0;
            st.vvvv = vvvv & 7;
            st.vvvv_hi = vvvv & 8;
        }
        if !(1..=3).contains(&mmmmm) {
            return false;
        }
        map = MAP_V1 + mmmmm as usize - 1;
        op = match st.byte() {
            Some(v) => v,
            None => return false,
        };
        opcode = [op, 0, 0, 0];
        let _ = (lockrep, has66, rex);
    } else if esc && b == 0x62 && st.pos < n && (m64 || d[st.pos] & 0xC0 == 0xC0) {
        // EVEX (a LOCK or REX prefix makes it invalid)
        if st.pos + 3 > n || lockrep == 0xF0 || rex != 0 {
            return false;
        }
        let p0 = d[st.pos];
        let p1 = d[st.pos + 1];
        let p2 = d[st.pos + 2];
        st.pos += 3;
        let mm = p0 & 3;
        if p0 & 0x0C != 0 || p1 & 0x04 == 0 {
            return false;
        }
        let r = p0 & 0x80 == 0;
        let x = p0 & 0x40 == 0;
        let bb = p0 & 0x20 == 0;
        let rr = p0 & 0x10 == 0;
        let w = p1 & 0x80 != 0;
        let vvvv = (!p1 >> 3) & 0xF;
        st.vex = VEX_EVEX;
        st.w = w;
        pfx = (p1 & 3) as usize;
        st.evex_z = p2 & 0x80 != 0;
        st.l = (p2 >> 5) & 3;
        st.evex_b = p2 & 0x10 != 0;
        let vp = p2 & 0x08 == 0;
        st.evex_aaa = p2 & 7;
        if m64 {
            st.rex = 0x40 | ((w as u8) << 3) | ((r as u8) << 2) | ((x as u8) << 1) | bb as u8;
            st.vvvv = vvvv | if vp { 16 } else { 0 };
            st.evex_rr = if rr { 16 } else { 0 };
            st.evex_x = if x { 16 } else { 0 };
            st.evex_vp = if vp { 16 } else { 0 };
        } else {
            st.rex = 0;
            st.vvvv = vvvv & 7;
            st.vvvv_hi = vvvv & 8;
        }
        map = match mm {
            1 => MAP_E1,
            2 => MAP_E1 + 1,
            3 => MAP_E1 + 2,
            _ => return false,
        };
        op = match st.byte() {
            Some(v) => v,
            None => return false,
        };
        opcode = [op, 0, 0, 0];
    } else if esc && b == 0x8F && st.pos < n && d[st.pos] & 0x38 != 0 {
        // XOP
        if st.pos + 2 > n {
            return false;
        }
        let b1 = d[st.pos];
        let b2 = d[st.pos + 1];
        st.pos += 2;
        let r = b1 & 0x80 == 0;
        let x = b1 & 0x40 == 0;
        let bb = b1 & 0x20 == 0;
        let mmmmm = b1 & 0x1F;
        let w = b2 & 0x80 != 0;
        st.vex = VEX_XOP;
        st.w = w;
        st.l = (b2 >> 2) & 1;
        pfx = (b2 & 3) as usize;
        let vvvv = (!b2 >> 3) & 0xF;
        if m64 {
            st.rex = 0x40 | ((w as u8) << 3) | ((r as u8) << 2) | ((x as u8) << 1) | bb as u8;
            st.vvvv = vvvv;
        } else {
            st.rex = 0;
            st.vvvv = vvvv & 7;
            st.vvvv_hi = vvvv & 8;
        }
        map = match mmmmm {
            8 => MAP_X8,
            9 => MAP_X8 + 1,
            10 => MAP_X8 + 2,
            _ => return false,
        };
        op = match st.byte() {
            Some(v) => v,
            None => return false,
        };
        opcode = [op, 0, 0, 0];
    } else {
        if st.pos > n || i >= n {
            return false;
        }
        map = MAP_1;
        op = b;
        opcode = [b, 0, 0, 0];
        pfx = match lockrep {
            0xF3 => 2,
            0xF2 => 3,
            _ => has66 as usize,
        };
    }

    // operand sizes
    let rexw = st.rex & 8 != 0 && m64;
    let osz_def: u8 = if m64 {
        if rexw {
            8
        } else if has66 {
            2
        } else {
            4
        }
    } else if has66 {
        2
    } else {
        4
    };
    let osz_d64: u8 = if m64 {
        if rexw {
            8
        } else if has66 {
            2
        } else {
            8
        }
    } else {
        osz_def
    };

    // ------------------------------------------------------------------ table walk
    let mut node = if map == MAP_3DN { 1 } else { t.roots[map][op as usize] };
    let mut entry_idx: usize = 0;
    let mut fallback = false;
    if map == MAP_3DN {
        // 3DNow!: operands first, the opcode is the trailing byte.
        node = 0;
        let _ = node;
    } else {
        let modrm_pos = st.pos;
        let (mm, have_modrm) = if modrm_pos < n { (d[modrm_pos], true) } else { (0, false) };
        let sz = |s: u8| -> u64 {
            match s {
                2 => 0,
                4 => 1,
                _ => 2,
            }
        };
        let root = node;
        if root != 0 && root & LEAF == 0 {
            // decision node: selector values packed 4 bits each, in SEL_* order (built only when
            // the opcode actually needs one)
            let w = if st.vex != VEX_NONE { st.w } else { rexw };
            let evex_rc = st.vex == VEX_EVEX && st.evex_b && mm >> 6 == 3;
            let mut sw: u64 = (m64 as u64)
                | (pfx as u64) << (4 * SEL_PFX)
                | (w as u64) << (4 * SEL_W)
                | (if evex_rc { 2 } else { st.l as u64 }) << (4 * SEL_L)
                | (st.evex_b as u64) << (4 * SEL_B)
                | ((mm >> 6 == 3) as u64) << (4 * SEL_MOD)
                | (((mm >> 3) & 7) as u64) << (4 * SEL_REG)
                | ((mm & 7) as u64) << (4 * SEL_RM)
                | ((st.rex & 1) as u64) << (4 * SEL_REXB)
                | sz(osz_def) << (4 * SEL_O)
                | sz(osz_d64) << (4 * SEL_D)
                | sz(st.asz) << (4 * SEL_A)
                | (has66 as u64) << (4 * SEL_H66);
            node = match walk(t, root, sw, have_modrm) {
                Some(x) => x,
                None => return false,
            };
            if node == 0 && st.vex == VEX_NONE && mand == 0 && pfx == 1 && has67 && map != MAP_1 {
                // OPSIZE_ADSIZE context also inherits the prefix-less entries (via ADSIZE)
                sw &= !(0xF << (4 * SEL_PFX));
                node = match walk(t, root, sw, have_modrm) {
                    Some(x) => x,
                    None => return false,
                };
            }
            if node == 0 && evex_rc {
                // rounding / sae register forms: scalar (LIG) entries are listed under L=0
                sw &= !(0xF << (4 * SEL_L));
                node = match walk(t, root, sw, have_modrm) {
                    Some(x) => x,
                    None => return false,
                };
            }
            if node == 0 && rexw && pfx != 0 && st.vex == VEX_NONE && map != MAP_1 {
                // capstone/LLVM REX.W contexts inherit the no-prefix (W0) entries
                sw &= !((0xF << (4 * SEL_PFX)) | (0xF << (4 * SEL_W)));
                node = match walk(t, root, sw, have_modrm) {
                    Some(x) => x,
                    None => return false,
                };
                fallback = true;
            }
        }
        if node == 0 {
            return false;
        }
        entry_idx = (node & 0xFFFF) as usize;
        if t.entries[entry_idx].flags & F_INVALID != 0 {
            return false;
        }
    }

    // 3DNow! path
    if map == MAP_3DN {
        let e = Entry {
            nops: 2,
            ops: [
                OpSpec { src: S_REG, cls: C_MM, mk: 0 },
                OpSpec { src: S_RM, cls: C_MM, mk: 0 },
                OpSpec::default(),
                OpSpec::default(),
                OpSpec::default(),
            ],
            flags: F_MODRM,
            mnem: 0,
            alias: 0,
            dn: 0,
            vsib: 0,
            kmask: false,
        };
        st.osz = osz_def;
        if !operands::<FULL>(&mut st, &e, out, addr, mode, 0) {
            return false;
        }
        let sfx = match st.byte() {
            Some(v) => v,
            None => return false,
        };
        let node = t.roots[MAP_3DN][sfx as usize];
        if node == 0 || node & LEAF == 0 {
            return false;
        }
        let e2 = &t.entries[(node & 0xFFFF) as usize];
        if lockrep == 0xF0 {
            return false;
        }
        out.mnem = e2.mnem;
        out.entry = (node & 0xFFFF) as u16;
        out.pfx = P_NONE;
        opcode = [0x0F, 0x0F, sfx, 0];
        return finish::<FULL>(&st, out, addr, mode, opcode);
    }

    let e = &t.entries[entry_idx];
    let flags = e.flags;
    st.osz = if flags & F_Z66 != 0 {
        if has66 {
            2
        } else {
            4
        }
    } else if m64 && flags & F_F64 != 0 {
        8
    } else if flags & F_D64 != 0 {
        osz_d64
    } else {
        osz_def
    };

    if flags & F_NOVVVV != 0 && st.vex != VEX_NONE {
        let uses_vsib = e.ops[..e.nops as usize].iter().any(|o| o.src == S_VSIB);
        let v = if uses_vsib { st.vvvv & 15 } else { st.vvvv };
        if (v | st.vvvv_hi) != 0 {
            return false;
        }
    }
    if st.vex == VEX_EVEX && st.evex_b && e.ops[..e.nops as usize].iter().any(|o| o.src == S_VSIB) {
        // gathers / scatters: no embedded broadcast
        return false;
    }
    st.has66 = has66;
    st.mosz = st.osz;
    if st.vex == VEX_NONE && map != MAP_1 {
        // capstone prints the memory size of the LLVM instruction variant matched for the
        // prefix context, while GPR registers follow the prefixes.
        if fallback {
            st.w = false;
            st.mosz = 4;
        } else if flags & F_NOPFX != 0 {
            if pfx >= 4 && !(m64 && map == MAP_0F && (0x82..=0x8F).contains(&op)) {
                // XS_OPSIZE / XD_OPSIZE contexts hold no prefix-less instructions
                // (capstone quirk: except jcc rel32 in 64-bit mode)
                return false;
            }
            if (mand == 0xF2 || mand == 0xF3) && has66 {
                // F2/F3 context: the 32/64-bit variant is matched (no 16-bit equivalent)
                st.mosz = if rexw { 8 } else { 4 };
            }
            if pfx == 1 && rexw {
                // hint nops (/z keyword) have no 64-bit variant: the 16-bit one wins
                st.z16 = true;
            }
        } else if pfx == 1 && rexw {
            st.mosz = 2;
        }
    } else if map == MAP_1 && flags & F_D64 != 0 && has66 {
        // push/pop memory forms: 66 wins over REX.W for the memory size
        st.mosz = 2;
    }

    // EVEX decorations / validity
    let mut deco = 0u8;
    let mut sae = 0u8;
    let mut bcst_elem = 0u8;
    if st.vex == VEX_EVEX {
        let reg_form = st.pos < n && d[st.pos] >> 6 == 3;
        if st.evex_aaa != 0 {
            if flags & F_NOEVK != 0 {
                return false;
            }
        } else if flags & F_KNOTZERO != 0 {
            return false;
        }
        let zok = flags & F_EVZ != 0;
        if st.evex_z && !zok && flags & F_NOZ != 0 {
            return false;
        }
        if flags & F_EVK != 0 && (st.evex_aaa != 0 || (st.evex_z && zok)) {
            deco = 0x80 | if st.evex_z && zok { 0x40 } else { 0 };
        }
        deco |= st.evex_aaa;
        if st.evex_b {
            if reg_form {
                if flags & F_ER != 0 {
                    sae = 1 + st.l;
                    st.l = 2;
                } else if flags & F_SAE != 0 {
                    sae = 5;
                    st.l = 2;
                } else if flags & F_NOBR != 0 {
                    return false;
                }
            } else if flags & F_BCST_D != 0 {
                bcst_elem = 4;
            } else if flags & F_BCST_Q != 0 {
                bcst_elem = 8;
            } else if flags & F_BCST_W != 0 {
                bcst_elem = 2;
            } else if flags & F_BCST_QB != 0 {
                bcst_elem = 0x88; // qword count, byte keyword, unscaled disp8
            } else if flags & F_NOBM != 0 {
                return false;
            }
        }
        // compressed disp8 scale
        st.disp8n = if e.dn != 0 {
            e.dn
        } else if bcst_elem == 0x88 {
            1
        } else if bcst_elem != 0 {
            bcst_elem
        } else {
            let mut nn = 1;
            for o in &e.ops[..e.nops as usize] {
                if matches!(o.src, S_RM | S_MEM | S_VSIB) {
                    nn = memsize_for(&st, o.cls, o.mk).bytes().max(1);
                    break;
                }
            }
            nn
        };
    }
    // (precomputed from the operand list: last S_VSIB class, any S_KMASK)
    if e.vsib != 0 {
        st.vsib = e.vsib;
    }
    if e.kmask {
        deco &= 0x7F;
    }

    if lockrep == 0xF0 && flags & F_LOCK == 0 {
        return false;
    }
    out.mnem = e.mnem;
    out.entry = entry_idx as u16;

    if !operands::<FULL>(&mut st, e, out, addr, mode, op) {
        return false;
    }
    out.evex = deco;
    out.sae = sae;
    if FULL && bcst_elem != 0 {
        let vl: u8 = if st.l >= 2 { 64 } else { 16 << st.l };
        for k in 0..out.op_count as usize {
            if let Operand::Mem(ref mut m) = out.operands[k] {
                m.bcst = vl / (bcst_elem & 0x0F);
                if flags & F_BCST_HALF != 0 {
                    m.bcst /= 2;
                }
                m.size = match bcst_elem {
                    2 => MemSize::Word,
                    4 => MemSize::Dword,
                    0x88 => MemSize::Byte,
                    _ => MemSize::Qword,
                };
            }
        }
    }
    let has_mem = st.has_modrm && st.modrm >> 6 != 3;
    if FULL && flags & (F_CMP8 | F_CMP32 | F_VPCMP | F_VPCOM) != 0 && out.op_count > 0 {
        let last = out.op_count as usize - 1;
        if let Operand::Imm(v) = out.operands[last] {
            let lim = if flags & F_CMP32 != 0 { 32 } else { 8 };
            // EVEX: capstone aliases masked compares by imm & 0x1f
            let v = if st.vex == VEX_EVEX && flags & F_CMP32 != 0 && (st.evex_aaa != 0 || (st.evex_b && has_mem)) {
                v & 0x1F
            } else {
                v
            };
            if (v as u64) < lim {
                let a = t.aliases[e.alias as usize + v as usize];
                if a != 0 {
                    out.mnem = a;
                    out.op_count -= 1;
                }
            }
        }
    }

    // ------------------------------------------------------------------ printed prefix
    let mut pp = P_NONE;
    match lockrep {
        0xF0 => {
            // LOCK requires a memory operand
            if !has_mem {
                return false;
            }
            pp = match xacq {
                0xF2 => P_XACQ_LOCK,
                0xF3 => P_XREL_LOCK,
                _ => P_LOCK,
            };
        }
        0xF2 => {
            if flags & (F_REP | F_REPE) != 0 {
                pp = P_REPNE;
            } else if flags & F_BND != 0 {
                pp = P_BND;
            } else if flags & F_XA != 0 && xacq != 0 && has_mem {
                pp = P_XACQ;
            }
        }
        0xF3 => {
            if flags & (F_REP | F_REPF3) != 0 {
                pp = P_REP;
            } else if flags & F_REPE != 0 {
                pp = P_REPE;
            } else if flags & F_REPZ != 0 {
                pp = P_REPZ;
            } else if flags & F_XA != 0 && xacq != 0 && has_mem {
                pp = P_XREL;
            }
        }
        _ => {}
    }
    // a repeat prefix that differs from the (consumed) mandatory F2/F3 is printed
    // (capstone: only for movss, whose id is in its repne-capable list)
    if pp == P_NONE && map == MAP_0F && (op == 0x10 || op == 0x11) && lockrep == 0xF2 && mand == 0xF3 {
        pp = P_REPNE;
    }
    if segp == 0x3E && flags & F_NOTRACK != 0 {
        pp = if pp == P_BND { P_BND_NOTRACK } else { P_NOTRACK };
    }
    out.pfx = pp;
    finish::<FULL>(&st, out, addr, mode, opcode)
}

/// Walk the decision tree from `node`; `None` if a ModRM selector is needed but missing.
#[inline(always)]
fn walk(t: &Tables, mut node: u32, sw: u64, have_modrm: bool) -> Option<u32> {
    while node != 0 && node & LEAF == 0 {
        let off = node as usize;
        let kind = t.nodes[off];
        if !have_modrm && kind.wrapping_sub(SEL_MOD) <= SEL_RM - SEL_MOD {
            return None;
        }
        let v = (sw.wrapping_shr(kind.wrapping_mul(4)) & 15) as usize;
        node = t.nodes[off + 1 + v];
    }
    Some(node)
}

/// `KEEP[n]`: mask keeping the low `n` bytes of a little-endian u128.
static KEEP: [u128; 16] = {
    let mut t = [0u128; 16];
    let mut k = 1;
    while k < 16 {
        t[k] = (1u128 << (8 * k)) - 1;
        k += 1;
    }
    t
};

/// The first `len` bytes of `d` (`len <= d.len() <= 15`), zero padded to 15.
#[inline(always)]
fn insn_bytes(d: &[u8], len: usize) -> [u8; 15] {
    let mut out = [0u8; 15];
    if let Some(w) = d.first_chunk::<15>() {
        // full window: one fixed-size copy + mask instead of a variable-length memcpy
        let mut x = [0u8; 16];
        x[..15].copy_from_slice(w);
        let v = u128::from_le_bytes(x) & KEEP[len & 15];
        out.copy_from_slice(&v.to_le_bytes()[..15]);
    } else {
        let len = len.min(d.len());
        out[..len].copy_from_slice(&d[..len]);
    }
    out
}

#[inline(always)]
fn finish<const FULL: bool>(st: &St, out: &mut Insn, addr: u64, mode: Mode, opcode: [u8; 4]) -> bool {
    let len = st.pos;
    if len > 15 || len > st.n {
        return false;
    }
    out.size = len as u8;
    if !FULL {
        return true;
    }
    out.address = addr;
    out.mode = mode;
    out.bytes = insn_bytes(st.d, len);
    out.opcode = opcode;
    out.rex = st.rex;
    // resolve the relative branch target now that the length is known
    if st.rel != 0 {
        let k = st.rel as usize - 1;
        if k < out.op_count as usize && k < MAX_OPS && out.ofmt[k] & OF_REL != 0 {
            if let Operand::Imm(rel) = out.operands[k] {
                let mut tgt = addr.wrapping_add(len as u64).wrapping_add(rel as u64);
                if mode != Mode::X86_64 {
                    tgt &= 0xFFFF_FFFF;
                }
                if out.ofmt[k] & OF_REL16 != 0 {
                    tgt &= 0xFFFF;
                }
                out.operands[k] = Operand::Imm(tgt as i64);
                out.ofmt[k] &= !(OF_REL | OF_REL16);
            }
        }
    }
    true
}

pub(crate) const OF_REL: u8 = 8;
pub(crate) const OF_REL16: u8 = 16;
pub(crate) const OF_BCST: u8 = 32;
pub(crate) const OF_FARSEP: u8 = 64; // printed after ':' instead of ", "
pub(crate) const OF_RC: u8 = 128; // EVEX rounding slot (printed only when active)
pub(crate) const OF_KMASK: u8 = 4; // standalone {kN}

#[inline]
fn gpr_by_size(n: u8, size: u8, rex: bool) -> u8 {
    gpr(n, size, rex)
}

#[inline(always)]
fn memsize_for(st: &St, cls: u8, mk: u8) -> MemSize {
    let mk = if mk == K_DEF {
        match cls {
            C_B => K_B,
            C_W => K_W,
            C_D => K_D,
            C_Q => K_Q,
            C_V => K_V,
            C_Y => K_Y,
            C_Z => K_Z,
            C_N => K_N,
            C_DV => {
                if st.rex & 8 != 0 {
                    K_Q
                } else {
                    K_D
                }
            }
            C_MM => K_Q,
            C_XMM => K_X,
            C_YMM => K_YMM,
            C_ZMM => K_ZMM,
            C_VL => K_VL,
            C_VLH => K_VLH,
            C_VLQ => K_VLQ,
            C_A => K_A,
            C_SEG => K_W,
            _ => K_NONE,
        }
    } else {
        mk
    };
    match mk {
        K_NONE => MemSize::None,
        K_PTR => MemSize::Ptr,
        K_B => MemSize::Byte,
        K_W => MemSize::Word,
        K_D => MemSize::Dword,
        K_Q => MemSize::Qword,
        K_T => MemSize::Tbyte,
        K_XW => MemSize::Xword,
        K_X => MemSize::Xmmword,
        K_YMM => MemSize::Ymmword,
        K_ZMM => MemSize::Zmmword,
        K_V => match st.mosz {
            2 => MemSize::Word,
            4 => MemSize::Dword,
            _ => MemSize::Qword,
        },
        K_Z => {
            if st.mosz == 2 || st.z16 {
                MemSize::Word
            } else {
                MemSize::Dword
            }
        }
        K_Y => {
            if st.w && st.m64 {
                MemSize::Qword
            } else {
                MemSize::Dword
            }
        }
        K_N => {
            if st.m64 {
                MemSize::Qword
            } else {
                MemSize::Dword
            }
        }
        K_A => match st.asz {
            2 => MemSize::Word,
            4 => MemSize::Dword,
            _ => MemSize::Qword,
        },
        K_VL => match st.l {
            0 => MemSize::Xmmword,
            1 => MemSize::Ymmword,
            _ => MemSize::Zmmword,
        },
        K_VLH => match st.l {
            0 => MemSize::Qword,
            1 => MemSize::Xmmword,
            _ => MemSize::Ymmword,
        },
        K_VLQ => match st.l {
            0 => MemSize::Dword,
            1 => MemSize::Qword,
            _ => MemSize::Xmmword,
        },
        K_VLE => match st.l {
            0 => MemSize::Word,
            1 => MemSize::Dword,
            _ => MemSize::Qword,
        },
        _ => MemSize::None,
    }
}

/// Register id for register class `cls` and register number `num` (already REX-extended).
/// Returns 0 when invalid.
#[inline(always)]
fn reg_for(st: &St, cls: u8, num: u8) -> u8 {
    let rexp = st.rex != 0;
    match cls {
        C_B => gpr8(num & 15, rexp),
        C_W => AX + (num & 15),
        C_D => EAX + (num & 15),
        C_Q => RAX + (num & 15),
        C_V => gpr_by_size(num & 15, st.osz, rexp),
        C_Z => {
            if st.osz == 2 {
                AX + (num & 15)
            } else {
                EAX + (num & 15)
            }
        }
        C_Y => {
            if st.w && st.m64 {
                RAX + (num & 15)
            } else {
                EAX + (num & 15)
            }
        }
        C_DV => {
            if st.rex & 8 != 0 {
                RAX + (num & 15)
            } else {
                EAX + (num & 15)
            }
        }
        C_N => {
            if st.m64 {
                RAX + (num & 15)
            } else {
                EAX + (num & 15)
            }
        }
        C_A => gpr_by_size(num & 15, st.asz, rexp),
        C_SEG => {
            let s = num & 7;
            if s > 5 {
                0
            } else {
                ES + s
            }
        }
        C_CR => CR0 + (num & 15),
        C_DR => DR0 + (num & 15),
        C_MM => MM0 + (num & 7),
        C_XMM => XMM0 + (num & 31),
        C_YMM => YMM0 + (num & 31),
        C_ZMM => ZMM0 + (num & 31),
        C_VL => match st.l {
            0 => XMM0 + (num & 31),
            1 => YMM0 + (num & 31),
            _ => ZMM0 + (num & 31),
        },
        C_VLH => match st.l {
            0 | 1 => XMM0 + (num & 31),
            _ => YMM0 + (num & 31),
        },
        C_VLQ => XMM0 + (num & 31),
        C_K => {
            if num > 7 {
                0
            } else {
                K0 + num
            }
        }
        C_BND => {
            if num > 3 {
                0
            } else {
                BND0 + num
            }
        }
        C_ST => ST0 + (num & 7),
        _ => 0,
    }
}

#[inline]
fn is_vec_class(cls: u8) -> bool {
    matches!(cls, C_XMM | C_YMM | C_ZMM | C_VL | C_VLH | C_VLQ)
}

/// Parse the ModRM memory operand (st.modrm already read, mod != 3).
#[inline(always)]
fn parse_mem(st: &mut St) -> Option<Mem> {
    let md = st.modrm >> 6;
    let rm = st.modrm & 7;
    let mut m = Mem { segment: Reg(st.seg), scale: 1, ..Default::default() };
    if st.asz == 2 {
        const B16: [(u8, u8); 8] = [
            (AX + 3, AX + 6),
            (AX + 3, AX + 7),
            (AX + 5, AX + 6),
            (AX + 5, AX + 7),
            (AX + 6, 0),
            (AX + 7, 0),
            (AX + 5, 0),
            (AX + 3, 0),
        ];
        let (b, x) = B16[rm as usize];
        if md == 0 && rm == 6 {
            m.disp = st.le(2)? as u16 as i16 as i64;
        } else {
            m.base = Reg(b);
            m.index = Reg(x);
            match md {
                1 => m.disp = st.byte()? as i8 as i64 * st.disp8n as i64,
                2 => m.disp = st.le(2)? as u16 as i16 as i64,
                _ => {}
            }
        }
        if st.vsib != 0 {
            return None;
        }
        return Some(m);
    }
    let rb = if st.rex & 1 != 0 { 8 } else { 0 };
    let rx = if st.rex & 2 != 0 { 8 } else { 0 };
    let base_of = |st: &St, r: u8| -> u8 {
        if st.asz == 8 {
            RAX + r
        } else {
            EAX + r
        }
    };
    if rm == 4 {
        let sib = st.byte()?;
        let scale = 1u8 << (sib >> 6);
        let idx = ((sib >> 3) & 7) | rx;
        let bs = sib & 7;
        if st.vsib != 0 {
            let r = reg_for(st, st.vsib, idx | st.evex_vp);
            if r == 0 {
                return None;
            }
            m.index = Reg(r);
        } else if idx != 4 {
            m.index = Reg(base_of(st, idx));
        } else {
            // LLVM prints riz for SIB forms that did not need a SIB byte (capstone never
            // prints eiz).
            let base_none = bs == 5 && md == 0;
            if st.asz == 8 && (scale != 1 || (!base_none && bs != 4)) {
                m.index = Reg(RIZ);
            }
        }
        m.scale = scale;
        if bs == 5 && md == 0 {
            m.disp = st.le(4)? as u32 as i32 as i64;
        } else {
            m.base = Reg(base_of(st, bs | rb));
        }
    } else if st.vsib != 0 {
        return None;
    } else if rm == 5 && md == 0 {
        if st.m64 {
            m.base = Reg(if st.asz == 8 { RIP } else { EIP });
        }
        m.disp = st.le(4)? as u32 as i32 as i64;
        return Some(m);
    } else {
        m.base = Reg(base_of(st, rm | rb));
    }
    match md {
        1 => m.disp = st.byte()? as i8 as i64 * st.disp8n as i64,
        2 => m.disp = st.le(4)? as u32 as i32 as i64,
        _ => {}
    }
    Some(m)
}

#[inline(always)]
fn operands<const FULL: bool>(st: &mut St, e: &Entry, out: &mut Insn, _addr: u64, mode: Mode, op: u8) -> bool {
    let m64 = mode == Mode::X86_64;
    // ModRM / memory
    let mut mem = Mem::default();
    if e.flags & F_MODRM != 0 {
        let m = match st.byte() {
            Some(v) => v,
            None => return false,
        };
        st.modrm = m;
        st.has_modrm = true;
        if e.flags & F_REGFORM != 0 {
            st.modrm |= 0xC0;
        } else if m >> 6 != 3 {
            mem = match parse_mem(st) {
                Some(v) => v,
                None => return false,
            };
        }
    }
    out.op_count = e.nops;
    out.ofmt = [0; MAX_OPS];
    out.evex = 0;
    out.sae = 0;
    // The first two operands are expanded inline (straight-line, no loop: in a loop LLVM
    // hoists the many per-source invariants into a costly prologue); the rest go out of line.
    let nops = (e.nops as usize).min(MAX_OPS);
    if nops > 0 {
        if !operand_inl::<FULL>(st, e, 0, &mem, out, m64, op) {
            return false;
        }
        if nops > 1 {
            if !operand_inl::<FULL>(st, e, 1, &mem, out, m64, op) {
                return false;
            }
            for k in 2..nops {
                if !operand(st, e, k, &mem, out, m64, op) {
                    return false;
                }
            }
        }
    }
    true
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn operand(st: &mut St, e: &Entry, k: usize, mem: &Mem, out: &mut Insn, m64: bool, op: u8) -> bool {
    operand_inl::<true>(st, e, k, mem, out, m64, op)
}

/// Decode explicit operand `k` (spec `e.ops[k]`).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn operand_inl<const FULL: bool>(st: &mut St, e: &Entry, k: usize, mem: &Mem, out: &mut Insn, m64: bool, op: u8) -> bool {
    let s = e.ops[k];
    let modrm = st.modrm;
    let is_reg = modrm >> 6 == 3;
    let rexr = if st.rex & 4 != 0 { 8 } else { 0 };
    let rexb = if st.rex & 1 != 0 { 8 } else { 0 };
    {
        let o = match s.src {
            S_REG => {
                let mut num = ((modrm >> 3) & 7) | rexr;
                if is_vec_class(s.cls) {
                    num |= st.evex_rr;
                } else if st.evex_rr != 0 && s.cls != C_K {
                    return false;
                }
                let r = reg_for(st, s.cls, num);
                if r == 0 {
                    return false;
                }
                Operand::Reg(Reg(r))
            }
            S_RM | S_MEM | S_RMREG | S_VSIB => {
                if is_reg {
                    if s.src == S_MEM || s.src == S_VSIB {
                        return false;
                    }
                    let mut num = (modrm & 7) | rexb;
                    if is_vec_class(s.cls) {
                        num |= st.evex_x;
                    }
                    let r = reg_for(st, s.cls, num);
                    if r == 0 {
                        return false;
                    }
                    Operand::Reg(Reg(r))
                } else {
                    if s.src == S_RMREG {
                        return false;
                    }
                    let mut mm = *mem;
                    mm.size = memsize_for(st, s.cls, s.mk);
                    Operand::Mem(mm)
                }
            }
            S_VVVV => {
                let r = reg_for(st, s.cls, st.vvvv);
                if r == 0 {
                    return false;
                }
                Operand::Reg(Reg(r))
            }
            S_OPREG => {
                let num = (op & 7) | rexb;
                Operand::Reg(Reg(reg_for(st, s.cls, num)))
            }
            S_IS4 => {
                let b = match st.byte() {
                    Some(v) => v,
                    None => return false,
                };
                st.is4 = b;
                // capstone does not mask the is4 register to 3 bits in 32-bit mode
                let num = b >> 4;
                Operand::Reg(Reg(reg_for(st, s.cls, num)))
            }
            S_FIXED => Operand::Reg(Reg(s.cls)),
            S_ACC => {
                let size = if s.cls == C_A {
                    if m64 { st.asz } else { 4 }
                } else if s.cls == C_N {
                    if m64 { 8 } else { 4 }
                } else if s.cls == C_Z && st.osz == 8 {
                    4
                } else {
                    st.osz
                };
                Operand::Reg(Reg(gpr(0, size, false)))
            }
            S_CONST1 => Operand::Imm(1),
            S_RC => {
                out.ofmt[k] |= OF_RC;
                Operand::None
            }
            S_KMASK => {
                out.ofmt[k] |= OF_KMASK;
                Operand::None
            }
            S_IMM => {
                let (v, signed) = match s.cls {
                    I_U8 => match st.byte() {
                        Some(b) => (b as i64, false),
                        None => return false,
                    },
                    I_S8 | I_S8N => {
                        let b = match st.byte() {
                            Some(b) => b as i8 as i64,
                            None => return false,
                        };
                        if e.flags & F_IMMU != 0 {
                            (mask_osz(b, st.osz), false)
                        } else {
                            (b, true)
                        }
                    }
                    I_U16 => match st.le(2) {
                        Some(v) => (v as i64, false),
                        None => return false,
                    },
                    I_U32 => match st.le(4) {
                        Some(v) => (v as i64, false),
                        None => return false,
                    },
                    I_LO4 => ((st.is4 & 0x0F) as i64, false),
                    I_W4 => match st.le(4) {
                        Some(v) => ((v & 0xFFFF) as i64, false),
                        None => return false,
                    },
                    I_S16 => match st.le(2) {
                        Some(v) => (v as u16 as i16 as i64, true),
                        None => return false,
                    },
                    I_ZS => {
                        if st.osz == 2 {
                            match st.le(2) {
                                Some(v) => (v as u16 as i16 as i64, true),
                                None => return false,
                            }
                        } else {
                            match st.le(4) {
                                Some(v) => (v as u32 as i32 as i64, true),
                                None => return false,
                            }
                        }
                    }
                    I_Z | I_ZN => {
                        if st.osz == 2 {
                            match st.le(2) {
                                Some(v) => (v as i64, false),
                                None => return false,
                            }
                        } else {
                            let v = match st.le(4) {
                                Some(v) => v,
                                None => return false,
                            };
                            if st.osz == 8 {
                                let sv = v as u32 as i32 as i64;
                                if e.flags & F_IMMU != 0 { (sv, false) } else { (sv, true) }
                            } else {
                                (v as i64, false)
                            }
                        }
                    }
                    _ => {
                        // I_V
                        let size = st.osz as usize;
                        match st.le(size) {
                            Some(v) => (v as i64, false),
                            None => return false,
                        }
                    }
                };
                if signed {
                    out.ofmt[k] |= OF_SIGNED;
                }
                Operand::Imm(v)
            }
            S_REL => {
                let rel = if s.cls == 1 {
                    match st.byte() {
                        Some(b) => b as i8 as i64,
                        None => return false,
                    }
                } else if st.osz == 2 {
                    // capstone: jmp/jcc rel16 are zero-extended in 32-bit mode (F_RELQ),
                    // call rel16 and 64-bit mode forms are sign-extended.
                    match st.le(2) {
                        Some(v) => {
                            if !m64 && e.flags & F_RELQ != 0 && st.asz != 2 {
                                v as i64
                            } else {
                                v as u16 as i16 as i64
                            }
                        }
                        None => return false,
                    }
                } else {
                    match st.le(4) {
                        Some(v) => {
                            let mut v = v as u32;
                            // capstone: with an 0x67 prefix in 32-bit mode jmp/jcc rel32 get
                            // bits 16..31 forced on when bit 15 is set.
                            if !m64 && st.asz == 2 && e.flags & F_RELQ != 0 && v & 0x8000 != 0 {
                                v |= 0xFFFF_0000;
                            }
                            v as i32 as i64
                        }
                        None => return false,
                    }
                };
                out.ofmt[k] |= OF_REL;
                st.rel = k as u8 + 1;
                Operand::Imm(rel)
            }
            S_MOFFS => {
                let v = match st.le(st.asz as usize) {
                    Some(v) => v,
                    None => return false,
                };
                out.ofmt[k] |= OF_MOFFS;
                Operand::Mem(Mem {
                    segment: Reg(st.seg),
                    disp: v as i64,
                    scale: 1,
                    size: memsize_for(st, s.cls, s.mk),
                    ..Default::default()
                })
            }
            S_STRSRC | S_STRDST => {
                let base = if s.src == S_STRSRC { 6 } else { 7 };
                let seg = if s.src == S_STRSRC {
                    st.seg
                } else if m64 {
                    0
                } else {
                    ES
                };
                Operand::Mem(Mem {
                    segment: Reg(seg),
                    base: Reg(gpr(base, st.asz, false)),
                    scale: 1,
                    size: memsize_for(st, s.cls, s.mk),
                    ..Default::default()
                })
            }
            S_FARPTR => {
                // ptr16:16 / ptr16:32 -> two immediates (selector, offset)
                let off = match st.le(if st.osz == 2 { 2 } else { 4 }) {
                    Some(v) => v,
                    None => return false,
                };
                let sel = match st.le(2) {
                    Some(v) => v,
                    None => return false,
                };
                out.operands[k] = Operand::Imm(sel as i64);
                if k + 1 < MAX_OPS {
                    out.operands[k + 1] = Operand::Imm(off as i64);
                    out.ofmt[k + 1] = if s.cls == 0 { OF_FARSEP } else { 0 };
                    out.op_count = out.op_count.max(k as u8 + 2);
                }
                return true;
            }
            _ => Operand::None,
        };
        if FULL {
            // per-variant stores: lets LLVM thread each source arm to its own (small) store
            // instead of merging every variant's fields into one generic 16-byte write
            out.operands[k] = match o {
                Operand::Reg(r) => Operand::Reg(r),
                Operand::Imm(v) => Operand::Imm(v),
                Operand::Mem(m) => Operand::Mem(m),
                Operand::None => Operand::None,
            };
        }
    }
    true
}

#[inline]
fn mask_osz(v: i64, osz: u8) -> i64 {
    match osz {
        1 => v & 0xFF,
        2 => v & 0xFFFF,
        4 => v & 0xFFFF_FFFF,
        _ => v,
    }
}

#[allow(dead_code)]
fn _unused(_: MemSize) {}
