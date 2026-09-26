//! Linux helpers used by the automagic (python `symbols/linux/__init__.py` pieces).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

/// python `LinuxIntelStacker.virtual_to_physical_address`: kernel virtual -> physical
/// (ignores KASLR).
pub fn virtual_to_physical_address(addr: u64) -> u64 {
    if addr > 0xFFFF_FFFF_8000_0000 { addr.wrapping_sub(0xFFFF_FFFF_8000_0000) } else { addr.wrapping_sub(0xC000_0000) }
}
