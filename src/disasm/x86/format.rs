//! capstone 5 Intel-syntax text formatting (X86IntelInstPrinter semantics).

use super::decode::{OF_FARSEP, OF_KMASK, OF_MOFFS, OF_RC, OF_SIGNED};
use super::{Insn, Mem, MemSize, Mode, Operand};

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

pub(crate) fn write_mnemonic(insn: &Insn, out: &mut String) {
    out.push_str(PREFIX_STR[insn.pfx as usize]);
    out.push_str(insn.base_mnemonic());
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// "0x..." lowercase hex.
#[inline]
pub(crate) fn push_hex(out: &mut String, v: u64) {
    let mut buf = [0u8; 18];
    let mut i = 18;
    let mut x = v;
    loop {
        i -= 1;
        buf[i] = HEX[(x & 15) as usize];
        x >>= 4;
        if x == 0 {
            break;
        }
    }
    i -= 1;
    buf[i] = b'x';
    i -= 1;
    buf[i] = b'0';
    // SAFETY-free: ASCII only
    out.push_str(std::str::from_utf8(&buf[i..]).unwrap_or(""));
}

#[inline]
fn push_dec(out: &mut String, v: u64) {
    let mut buf = [0u8; 20];
    let mut i = 20;
    let mut x = v;
    loop {
        i -= 1;
        buf[i] = b'0' + (x % 10) as u8;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    out.push_str(std::str::from_utf8(&buf[i..]).unwrap_or(""));
}

/// capstone printImm(positive=true) for a non-negative / unsigned value.
#[inline]
pub(crate) fn push_uimm(out: &mut String, v: u64) {
    if v > 9 {
        push_hex(out, v);
    } else {
        push_dec(out, v);
    }
}

/// capstone's default signed immediate printing.
#[inline]
pub(crate) fn push_simm(out: &mut String, v: i64) {
    if v >= 0 {
        push_uimm(out, v as u64);
    } else if v == i64::MIN {
        out.push_str("0x8000000000000000");
    } else if v < -9 {
        out.push_str("-");
        push_hex(out, v.unsigned_abs());
    } else {
        out.push('-');
        push_dec(out, v.unsigned_abs());
    }
}

fn size_kw(s: MemSize) -> &'static str {
    match s {
        MemSize::None => "",
        MemSize::Ptr => "ptr ",
        MemSize::Byte => "byte ptr ",
        MemSize::Word => "word ptr ",
        MemSize::Dword => "dword ptr ",
        MemSize::Qword => "qword ptr ",
        MemSize::Tbyte => "tbyte ptr ",
        MemSize::Xword => "xword ptr ",
        MemSize::Xmmword => "xmmword ptr ",
        MemSize::Ymmword => "ymmword ptr ",
        MemSize::Zmmword => "zmmword ptr ",
    }
}

fn write_mem(out: &mut String, m: &Mem, mode: Mode, moffs: bool) {
    out.push_str(size_kw(m.size));
    if !m.segment.is_none() {
        out.push_str(m.segment.name());
        out.push(':');
    }
    out.push('[');
    let mut need_plus = false;
    if !m.base.is_none() {
        out.push_str(m.base.name());
        need_plus = true;
    }
    if !m.index.is_none() {
        if need_plus {
            out.push_str(" + ");
        }
        out.push_str(m.index.name());
        if m.scale != 1 {
            out.push('*');
            push_dec(out, m.scale as u64);
        }
        need_plus = true;
    }
    if moffs {
        push_uimm(out, m.disp as u64);
    } else if m.disp != 0 {
        if need_plus {
            if m.disp < 0 {
                out.push_str(" - ");
                push_uimm(out, m.disp.unsigned_abs());
            } else {
                out.push_str(" + ");
                push_uimm(out, m.disp as u64);
            }
        } else if m.disp < 0 {
            let v = if mode == Mode::X86_64 { m.disp as u64 } else { m.disp as u64 & 0xFFFF_FFFF };
            push_uimm(out, v);
        } else {
            push_uimm(out, m.disp as u64);
        }
    } else if !need_plus {
        out.push('0');
    }
    out.push(']');
    if m.bcst != 0 {
        out.push_str("{1to");
        push_dec(out, m.bcst as u64);
        out.push('}');
    }
}

static SAE_STR: [&str; 6] = ["", "{rn-sae}", "{rd-sae}", "{ru-sae}", "{rz-sae}", "{sae}"];

pub(crate) fn write_op_str(insn: &Insn, out: &mut String) {
    let mut first = true;
    for k in 0..insn.op_count as usize {
        let f = insn.ofmt[k];
        if f & OF_RC != 0 {
            if insn.sae != 0 {
                if !first {
                    out.push_str(", ");
                }
                out.push_str(SAE_STR[insn.sae as usize % 6]);
                first = false;
            }
            continue;
        }
        if !first {
            if f & OF_FARSEP != 0 {
                out.push(':');
            } else {
                out.push_str(", ");
            }
        }
        first = false;
        if f & OF_KMASK != 0 {
            out.push_str("{k");
            push_dec(out, (insn.evex & 7) as u64);
            out.push('}');
            continue;
        }
        match insn.operands[k] {
            Operand::Reg(r) => out.push_str(r.name()),
            Operand::Imm(v) => {
                if insn.ofmt[k] & OF_SIGNED != 0 {
                    push_simm(out, v)
                } else {
                    push_uimm(out, v as u64)
                }
            }
            Operand::Mem(ref m) => write_mem(out, m, insn.mode, insn.ofmt[k] & OF_MOFFS != 0),
            Operand::None => {}
        }
        if k == 0 && insn.evex & 0x80 != 0 {
            out.push_str(" {k");
            push_dec(out, (insn.evex & 7) as u64);
            out.push('}');
            if insn.evex & 0x40 != 0 {
                out.push_str(" {z}");
            }
        }
    }
}
