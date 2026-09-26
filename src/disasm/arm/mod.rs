//! 32-bit ARM disassembler producing capstone-5-identical text (`CS_ARCH_ARM`, `CS_MODE_ARM`,
//! little endian, ARM state only).
//!
//! Same design as `arm64`: a textual spec learned by probing the capstone oracle
//! (bench/scripts/gen_arm32_spec.py, `spec_data.rs`) compiled lazily by the shared engine
//! (`arm64/engine.rs`).  Conditional instructions are specified in their AL form; the engine
//! folds the condition suffix into the mnemonic (spec record `F cond`).

mod spec_data;

use super::arm64::engine::{self, Engine, Handler, Res};
use std::sync::OnceLock;

fn engine() -> &'static Engine {
    static E: OnceLock<Engine> = OnceLock::new();
    E.get_or_init(|| Engine::compile(spec_data::SPEC, HANDLERS))
}

fn h_invalid(_w: u32, _addr: u64, _out: &mut String) -> Res {
    Res::Invalid
}

const HANDLERS: &[(&str, Handler)] = &[("invalid", h_invalid)];

/// A decoded ARM instruction (always 4 bytes). Text is produced on demand.
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
        Some(Insn { address: addr, size: 4, word })
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
        let i = Insn { address: self.addr, size: 4, word };
        self.data = &self.data[4..];
        self.addr = self.addr.wrapping_add(4);
        Some(i)
    }
}

/// `capstone.Cs(CS_ARCH_ARM, CS_MODE_ARM).disasm(data, addr)` equivalent.
pub fn disasm(data: &[u8], addr: u64) -> Disasm<'_> {
    Disasm { data, addr, scratch: String::new() }
}

/// Append volatility's rendering (`"\n{addr:#x}:\t{mnemonic}\t{op_str}"` per instruction,
/// stopping at the first undecodable word) to `out`.
pub fn format_arm_into(data: &[u8], addr: u64, out: &mut String) {
    let e = engine();
    let mut a = addr;
    for chunk in data.chunks_exact(4) {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
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

#[cfg(test)]
mod tests;
