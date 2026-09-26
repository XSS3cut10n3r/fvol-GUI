//! disasm

/// Capstone-compatible listing as volatility3's `display_disassembly` builds it: the concatenated
/// `"\n{address:#x}:\t{mnemonic}\t{op_str}"` lines for `data` starting at `offset`, for `arch` in
/// intel / intel64 / arm / arm64.
///
/// STUB (CLI agent): the disasm agent provides the real implementation; this placeholder is
/// replaced at merge.
pub fn format_capstone(_data: &[u8], _offset: u64, _arch: &str) -> String {
    String::new()
}
