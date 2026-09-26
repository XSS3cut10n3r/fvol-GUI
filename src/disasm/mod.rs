//! capstone-compatible disassembler (x86 / x86-64; ARM / ARM64 best effort).
//!
//! volatility3 uses capstone in two ways, both covered here:
//!  * the text renderer's `Disassembly` column (`format_capstone`), which prints for each
//!    instruction `"\n{address:#x}:\t{mnemonic}\t{op_str}"` and stops at the first undecodable
//!    instruction, exactly like `capstone.Cs.disasm`;
//!  * plugins that inspect instructions programmatically (`decode` / `disasm` iterators with
//!    structured operands).
//!
//! The x86 decoder is table driven and allocation free; see `x86/`.

pub mod arm64;
pub mod x86;

pub use x86::{decode, disasm, Insn, Mem, MemSize, Mode, Operand, Reg};

/// Render `data` located at `offset` like volatility3's `display_disassembly` (capstone):
/// the concatenation of `"\n{addr:#x}:\t{mnemonic}\t{op_str}"` for every instruction until the
/// first undecodable one. `arch` is one of "intel", "intel64", "arm", "arm64"; unknown
/// architectures produce an empty string.
pub fn format_capstone(data: &[u8], offset: u64, arch: &str) -> String {
    let mut out = String::with_capacity(data.len() * 12);
    format_capstone_into(data, offset, arch, &mut out);
    out
}

/// Like `format_capstone` but appends to `out` (reusable buffer).
pub fn format_capstone_into(data: &[u8], offset: u64, arch: &str, out: &mut String) {
    let mode = match arch {
        "intel" => Mode::X86_32,
        "intel64" => Mode::X86_64,
        "arm64" => return arm64::format_arm64_into(data, offset, out),
        _ => return,
    };
    let mut pos = 0usize;
    let mut addr = offset;
    let mut insn = Insn::default();
    while pos < data.len() {
        if !x86::decode_into(&data[pos..], addr, mode, &mut insn) {
            break;
        }
        out.push('\n');
        x86::push_addr(out, addr);
        out.push_str(":\t");
        insn.write_mnemonic(out);
        out.push('\t');
        insn.write_op_str(out);
        pos += insn.size as usize;
        addr = addr.wrapping_add(insn.size as u64);
    }
}

#[cfg(test)]
mod tests;
