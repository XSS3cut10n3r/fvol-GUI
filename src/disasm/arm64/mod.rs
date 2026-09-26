//! AArch64 disassembler producing capstone-5-identical text (`CS_ARCH_ARM64`, little endian).
//!
//! The instruction classes live in a textual spec (`spec_data.rs`) that was learned by probing
//! the capstone oracle (bench/scripts/gen_arm64_spec.py); `engine.rs` compiles it lazily into
//! flat tables + a decision tree.  A few alias families whose printing depends on comparisons
//! between operand values are formatted by hand-written handlers below.

pub(crate) mod engine;
mod spec_data;

use engine::{Engine, Handler, Res};
use std::sync::OnceLock;

fn engine() -> &'static Engine {
    static E: OnceLock<Engine> = OnceLock::new();
    E.get_or_init(|| Engine::compile(spec_data::SPEC, HANDLERS))
}

const HANDLERS: &[(&str, Handler)] = &[("bitfield", h_bitfield), ("invalid", h_invalid)];

/// Encodings capstone rejects inside a region another class would claim.
fn h_invalid(_w: u32, _addr: u64, _out: &mut String) -> Res {
    Res::Invalid
}

// ------------------------------------------------------------------------------------------
// handlers

fn push_gpr(out: &mut String, sf: bool, n: u32) {
    if n == 31 {
        out.push_str(if sf { "xzr" } else { "wzr" });
    } else {
        out.push(if sf { 'x' } else { 'w' });
        engine::push_dec(out, n as u64);
    }
}

fn push_imm32(out: &mut String, v: i32) {
    out.push('#');
    if v < 0 {
        out.push('-');
    }
    let u = v.unsigned_abs() as u64;
    if u > 9 {
        out.push_str("0x");
        engine::push_hex(out, u);
    } else {
        engine::push_dec(out, u);
    }
}

/// SBFM / BFM / UBFM and their preferred aliases (asr, lsl, lsr, sxtb/h/w, uxtb/h, sbfiz,
/// sbfx, ubfiz, ubfx, bfc, bfi, bfxil); selection rules per the ARM ARM alias conditions.
fn h_bitfield(w: u32, _addr: u64, out: &mut String) -> Res {
    let sf = w >> 31 != 0;
    let opc = (w >> 29) & 3;
    let n = (w >> 22) & 1;
    let immr = ((w >> 16) & 63) as i32;
    let imms = ((w >> 10) & 63) as i32;
    let rn = (w >> 5) & 31;
    let rd = w & 31;
    if opc == 3 || (sf as u32) != n || (!sf && (immr >= 32 || imms >= 32)) {
        return Res::Invalid;
    }
    let width: i32 = if sf { 64 } else { 32 };
    let two = |out: &mut String, m: &str| {
        out.push_str(m);
        out.push('\t');
        push_gpr(out, sf, rd);
        out.push_str(", ");
        push_gpr(out, sf, rn);
        out.push_str(", ");
    };
    if opc == 1 {
        if rn == 31 && (immr == 0 || imms < immr) {
            out.push_str("bfc\t");
            push_gpr(out, sf, rd);
            out.push_str(", ");
            push_imm32(out, (width - immr) % width);
            out.push_str(", ");
            push_imm32(out, imms + 1);
        } else if imms < immr {
            two(out, "bfi");
            push_imm32(out, (width - immr) % width);
            out.push_str(", ");
            push_imm32(out, imms + 1);
        } else {
            two(out, "bfxil");
            push_imm32(out, immr);
            out.push_str(", ");
            push_imm32(out, imms - immr + 1);
        }
        return Res::Ok;
    }
    let signed = opc == 0;
    if immr == 0 {
        let m = match imms {
            7 if signed => Some("sxtb"),
            7 if !sf => Some("uxtb"),
            15 if signed => Some("sxth"),
            15 if !sf => Some("uxth"),
            31 if signed && sf => Some("sxtw"),
            _ => None,
        };
        if let Some(m) = m {
            out.push_str(m);
            out.push('\t');
            push_gpr(out, sf, rd);
            out.push_str(", ");
            push_gpr(out, false, rn);
            return Res::Ok;
        }
    }
    if !signed && imms != width - 1 && imms + 1 == immr {
        two(out, "lsl");
        push_imm32(out, width - 1 - imms);
    } else if imms == width - 1 {
        two(out, if signed { "asr" } else { "lsr" });
        push_imm32(out, immr);
    } else if immr > imms {
        two(out, if signed { "sbfiz" } else { "ubfiz" });
        push_imm32(out, width - immr);
        out.push_str(", ");
        push_imm32(out, imms + 1);
    } else {
        two(out, if signed { "sbfx" } else { "ubfx" });
        push_imm32(out, immr);
        out.push_str(", ");
        push_imm32(out, imms - immr + 1);
    }
    Res::Ok
}

// ------------------------------------------------------------------------------------------
// public API

/// A decoded AArch64 instruction (always 4 bytes). Text is produced on demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub address: u64,
    pub size: u8,
    /// The raw little-endian instruction word.
    pub word: u32,
}

impl Insn {
    /// Append `mnemonic\top_str` (capstone text) to `out`.
    pub fn write_text(&self, out: &mut String) {
        engine().render(self.word, self.address, out);
    }

    pub fn mnemonic(&self) -> String {
        let mut s = String::new();
        self.write_text(&mut s);
        match s.find('\t') {
            Some(i) => s[..i].to_string(),
            None => s,
        }
    }

    pub fn op_str(&self) -> String {
        let mut s = String::new();
        self.write_text(&mut s);
        match s.find('\t') {
            Some(i) => s[i + 1..].to_string(),
            None => String::new(),
        }
    }
}

/// Decode the instruction at the start of `data` (at virtual address `addr`).
pub fn decode(data: &[u8], addr: u64) -> Option<Insn> {
    let b: [u8; 4] = data.get(..4)?.try_into().ok()?;
    let word = u32::from_le_bytes(b);
    let mut s = String::new();
    if engine().render(word, addr, &mut s) {
        Some(Insn {
            address: addr,
            size: 4,
            word,
        })
    } else {
        None
    }
}

/// Iterator over consecutive instructions, stopping at the first invalid word (like capstone).
pub struct Disasm<'a> {
    data: &'a [u8],
    addr: u64,
    scratch: String,
}

impl Iterator for Disasm<'_> {
    type Item = Insn;
    fn next(&mut self) -> Option<Insn> {
        let b: [u8; 4] = self.data.get(..4)?.try_into().ok()?;
        let word = u32::from_le_bytes(b);
        self.scratch.clear();
        if !engine().render(word, self.addr, &mut self.scratch) {
            self.data = &[];
            return None;
        }
        let i = Insn {
            address: self.addr,
            size: 4,
            word,
        };
        self.data = &self.data[4..];
        self.addr = self.addr.wrapping_add(4);
        Some(i)
    }
}

/// `capstone.Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(data, addr)` equivalent.
pub fn disasm(data: &[u8], addr: u64) -> Disasm<'_> {
    Disasm {
        data,
        addr,
        scratch: String::new(),
    }
}

/// Append volatility's rendering (`"\n{addr:#x}:\t{mnemonic}\t{op_str}"` per instruction,
/// stopping at the first undecodable word) to `out`.
pub fn format_arm64_into(data: &[u8], addr: u64, out: &mut String) {
    let e = engine();
    let mut a = addr;
    for chunk in data.as_chunks::<4>().0 {
        let word = u32::from_le_bytes(*chunk);
        let mark = out.len();
        out.push_str("\n0x");
        engine::push_hex(out, a);
        out.push_str(":\t");
        if !e.render(word, a, out) {
            out.truncate(mark);
            return;
        }
        a = a.wrapping_add(4);
    }
}

/// Render one word (text `mnemonic\top_str`), for tests and the differential harness.
pub fn render_word(word: u32, addr: u64, out: &mut String) -> bool {
    engine().render(word, addr, out)
}

/// Force the lazy spec compilation (benchmarks).
pub fn warm_up() {
    let _ = engine();
}

/// The compiled engine (benchmarks / diagnostics).
#[allow(dead_code)]
pub(crate) fn engine_ref() -> &'static Engine {
    engine()
}

#[cfg(test)]
mod tests;
