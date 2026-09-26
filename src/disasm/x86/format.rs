//! capstone 5 Intel-syntax text formatting (X86IntelInstPrinter semantics).
//!
//! Text is appended to the caller's String through its byte buffer: every primitive reserves its
//! own worst case, then does fixed-size stores from zero-padded tables (register names, size
//! keywords, mnemonics) and branch-free hex conversion, so there is no memcpy call or UTF-8
//! re-validation per piece. Only ASCII is ever written.

use super::decode::{OF_FARSEP, OF_KMASK, OF_MOFFS, OF_RC, OF_SIGNED};
use super::regs::NAMES;
use super::{Insn, Mem, Mode, Operand};

pub(crate) static PREFIX_STR: [&str; 13] = [
    "",
    "lock ",
    "rep ",
    "repe ",
    "repne ",
    "bnd ",
    "repz ",
    "notrack ",
    "bnd notrack ",
    "xacquire lock ",
    "xrelease lock ",
    "xacquire ",
    "xrelease ",
];

static SIZE_KW: [&str; 11] = [
    "",
    "ptr ",
    "byte ptr ",
    "word ptr ",
    "dword ptr ",
    "qword ptr ",
    "tbyte ptr ",
    "xword ptr ",
    "xmmword ptr ",
    "ymmword ptr ",
    "zmmword ptr ",
];

static SAE_STR: [&str; 6] = ["", "{rn-sae}", "{rd-sae}", "{ru-sae}", "{rz-sae}", "{sae}"];

/// Zero-padded `N`-byte copies of `src` (index-compatible), lengths clamped to `N`.
const fn padded<const N: usize, const K: usize>(src: &[&str]) -> ([[u8; N]; K], [u8; K]) {
    let mut t = [[0u8; N]; K];
    let mut l = [0u8; K];
    let mut i = 0;
    while i < src.len() && i < K {
        let b = src[i].as_bytes();
        let mut j = 0;
        while j < b.len() && j < N {
            t[i][j] = b[j];
            j += 1;
        }
        l[i] = j as u8;
        i += 1;
    }
    (t, l)
}

/// Register names by id (all 256 u8 ids valid; unknown ids are empty, like `Reg::name`).
static REG: ([[u8; 8]; 256], [u8; 256]) = padded(&NAMES);
static PFX: ([[u8; 16]; 16], [u8; 16]) = padded(&PREFIX_STR);
static KW: ([[u8; 16]; 16], [u8; 16]) = padded(&SIZE_KW);
static SAE: ([[u8; 16]; 8], [u8; 8]) = padded(&SAE_STR);

/// Append-only byte writer over a String's buffer: a raw cursor into spare capacity that is
/// reserved in bounded batches (`room`), so individual stores carry no capacity check.
struct W<'a> {
    v: &'a mut Vec<u8>,
    p: *mut u8,
    n: usize,
    /// bytes still guaranteed writable at `p + n` (only used by debug assertions)
    #[cfg(debug_assertions)]
    left: usize,
}

/// Upper bound of bytes stored (including fixed-size overshoot) by one operand, the mnemonic,
/// or one address; `room(ROOM)` is called before each of those.
const ROOM: usize = 256;

impl<'a> W<'a> {
    #[inline(always)]
    fn new(v: &'a mut Vec<u8>) -> Self {
        let n = v.len();
        let p = v.as_mut_ptr();
        W {
            v,
            p,
            n,
            #[cfg(debug_assertions)]
            left: 0,
        }
    }
    /// Make sure `k` more bytes can be stored.
    #[inline(always)]
    fn room(&mut self, k: usize) {
        if self.v.capacity() - self.n < k {
            // SAFETY: bytes [old len, n) were initialized by previous stores.
            unsafe { self.v.set_len(self.n) };
            self.v.reserve(k);
            self.p = self.v.as_mut_ptr();
        }
        #[cfg(debug_assertions)]
        {
            self.left = self.v.capacity() - self.n;
        }
    }
    /// Append the first `len` bytes of `src`, storing all `N` (branch-free fixed-size copy).
    #[inline(always)]
    fn put<const N: usize>(&mut self, src: &[u8; N], len: usize) {
        #[cfg(debug_assertions)]
        {
            assert!(self.left >= N && len <= N);
            self.left -= len;
        }
        // SAFETY: callers keep every batch of stores within the capacity made available by
        // `room(ROOM)` (see ROOM); `len <= N` for all call sites (table lengths are clamped).
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), self.p.add(self.n), N) };
        self.n += len;
    }
    #[inline(always)]
    fn b(&mut self, c: u8) {
        self.put(&[c], 1);
    }
    #[inline(always)]
    fn s2(&mut self, s: &[u8; 2]) {
        self.put(s, 2);
    }
    #[inline(always)]
    fn s3(&mut self, s: &[u8; 3]) {
        self.put(s, 3);
    }
    #[inline(always)]
    fn reg(&mut self, r: u8) {
        self.put(&REG.0[r as usize], REG.1[r as usize] as usize);
    }
    /// "0x" + lowercase hex digits.
    #[inline(always)]
    fn hex(&mut self, v: u64) {
        let (d, k) = hex_digits(v);
        self.put(b"0x", 2);
        self.put(&d, k);
    }
    /// Small decimal (fast path for one digit).
    #[inline(always)]
    fn dec(&mut self, v: u64) {
        if v < 10 {
            self.b(b'0' + v as u8);
        } else {
            let mut buf = [0u8; 20];
            let mut i = 20;
            let mut x = v;
            while x != 0 && i > 0 {
                i -= 1;
                buf[i] = b'0' + (x % 10) as u8;
                x /= 10;
            }
            let mut o = [0u8; 20];
            o[..20 - i].copy_from_slice(&buf[i..]);
            self.put(&o, 20 - i);
        }
    }
    /// capstone printImm(positive=true) for a non-negative / unsigned value.
    #[inline(always)]
    fn uimm(&mut self, v: u64) {
        if v > 9 { self.hex(v) } else { self.b(b'0' + v as u8) }
    }
    /// capstone's default signed immediate printing.
    #[inline(always)]
    fn simm(&mut self, v: i64) {
        if v >= 0 {
            self.uimm(v as u64);
        } else if v == i64::MIN {
            self.put(b"0x8000000000000000", 18);
        } else if v < -9 {
            self.b(b'-');
            self.hex(v.unsigned_abs());
        } else {
            self.b(b'-');
            self.b(b'0' + v.unsigned_abs() as u8);
        }
    }
}

impl Drop for W<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: every byte in [len, n) was stored by `put` within reserved capacity.
        unsafe { self.v.set_len(self.n) };
    }
}

/// Lowercase hex digits of `v`, most significant first, left-aligned in 16 bytes; + digit count.
/// Branch-free: nibbles are spread to bytes with SWAR shifts, then mapped to ASCII.
#[inline(always)]
fn hex_digits(v: u64) -> ([u8; 16], usize) {
    const ONES: u128 = 0x0101_0101_0101_0101_0101_0101_0101_0101;
    let k = ((64 - (v | 1).leading_zeros() + 3) >> 2) as usize; // 1..=16
    let mut x = v as u128;
    x = (x & 0xFFFF_FFFF) | ((x & 0xFFFF_FFFF_0000_0000) << 32);
    x = (x & 0x0000_0000_0000_FFFF_0000_0000_0000_FFFF) | ((x & 0x0000_0000_FFFF_0000_0000_0000_FFFF_0000) << 16);
    x = (x & 0x0000_00FF_0000_00FF_0000_00FF_0000_00FF) | ((x & 0x0000_FF00_0000_FF00_0000_FF00_0000_FF00) << 8);
    x = (x & 0x000F_000F_000F_000F_000F_000F_000F_000F) | ((x & 0x00F0_00F0_00F0_00F0_00F0_00F0_00F0_00F0) << 4);
    // byte i = nibble i; '0'..'9' then 'a'..'f' (+0x27 when the nibble is > 9)
    let gt9 = ((x + ONES * 6) >> 4) & ONES;
    let a = x + ONES * 0x30 + gt9 * 0x27;
    // most significant used nibble to byte 15, then byte-reverse: digits start at byte 0
    let a = (a << (8 * (16 - k))).swap_bytes();
    (a.to_le_bytes(), k)
}

/// Append the full mnemonic (printed prefixes + base mnemonic).
pub(crate) fn write_mnemonic(insn: &Insn, out: &mut String) {
    // SAFETY: only ASCII is appended (see `W::put`).
    let mut w = W::new(unsafe { out.as_mut_vec() });
    w.room(ROOM);
    let p = insn.pfx as usize & 15;
    w.put(&PFX.0[p], PFX.1[p] as usize);
    let t = super::tables::tables();
    match t.mnem_pad.get(insn.mnem as usize) {
        Some(m) => w.put(m, m[31] as usize),
        None => w.put(&[0u8; 1], 0),
    }
}

/// "0x..." lowercase hex.
#[inline]
pub(crate) fn push_hex(out: &mut String, v: u64) {
    // SAFETY: only ASCII is appended (see `W::put`).
    let mut w = W::new(unsafe { out.as_mut_vec() });
    w.room(ROOM);
    w.hex(v);
}

#[inline(always)]
fn write_mem(w: &mut W, m: &Mem, mode: Mode, moffs: bool) {
    let kw = m.size as usize & 15;
    w.put(&KW.0[kw], KW.1[kw] as usize);
    if !m.segment.is_none() {
        w.reg(m.segment.0);
        w.b(b':');
    }
    w.b(b'[');
    let mut need_plus = false;
    if !m.base.is_none() {
        w.reg(m.base.0);
        need_plus = true;
    }
    if !m.index.is_none() {
        if need_plus {
            w.s3(b" + ");
        }
        w.reg(m.index.0);
        if m.scale != 1 {
            w.b(b'*');
            w.dec(m.scale as u64);
        }
        need_plus = true;
    }
    if moffs {
        w.uimm(m.disp as u64);
    } else if m.disp != 0 {
        if need_plus {
            if m.disp < 0 {
                w.s3(b" - ");
                w.uimm(m.disp.unsigned_abs());
            } else {
                w.s3(b" + ");
                w.uimm(m.disp as u64);
            }
        } else if m.disp < 0 {
            let v = if mode == Mode::X86_64 { m.disp as u64 } else { m.disp as u64 & 0xFFFF_FFFF };
            w.uimm(v);
        } else {
            w.uimm(m.disp as u64);
        }
    } else if !need_plus {
        w.b(b'0');
    }
    w.b(b']');
    if m.bcst != 0 {
        w.put(b"{1to", 4);
        w.dec(m.bcst as u64);
        w.b(b'}');
    }
}

/// Append the operand string.
pub(crate) fn write_op_str(insn: &Insn, out: &mut String) {
    // SAFETY: only ASCII is appended (see `W::put`).
    let mut w = W::new(unsafe { out.as_mut_vec() });
    let mut first = true;
    for k in 0..(insn.op_count as usize).min(insn.operands.len()) {
        w.room(ROOM);
        let f = insn.ofmt[k];
        if f & OF_RC != 0 {
            if insn.sae != 0 {
                if !first {
                    w.s2(b", ");
                }
                let i = insn.sae as usize % 6;
                w.put(&SAE.0[i], SAE.1[i] as usize);
                first = false;
            }
            continue;
        }
        if !first {
            if f & OF_FARSEP != 0 {
                w.b(b':');
            } else {
                w.s2(b", ");
            }
        }
        first = false;
        if f & OF_KMASK != 0 {
            w.s2(b"{k");
            w.b(b'0' + (insn.evex & 7));
            w.b(b'}');
            continue;
        }
        match insn.operands[k] {
            Operand::Reg(r) => w.reg(r.0),
            Operand::Imm(v) => {
                if f & OF_SIGNED != 0 {
                    w.simm(v)
                } else {
                    w.uimm(v as u64)
                }
            }
            Operand::Mem(ref m) => write_mem(&mut w, m, insn.mode, f & OF_MOFFS != 0),
            Operand::None => {}
        }
        if k == 0 && insn.evex & 0x80 != 0 {
            w.s3(b" {k");
            w.b(b'0' + (insn.evex & 7));
            w.b(b'}');
            if insn.evex & 0x40 != 0 {
                w.put(b" {z}", 4);
            }
        }
    }
}
