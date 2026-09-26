//! Mac helpers used by the automagic (python `automagic/mac.py` pieces).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

/// python `MacIntelStacker.virtual_to_physical_address`.
pub fn virtual_to_physical_address(addr: u64) -> u64 {
    if addr > 0xFFFF_FF80_0000_0000 { addr.wrapping_sub(0xFFFF_FF80_0000_0000) } else { addr.wrapping_sub(0xFF80_0000_0000) }
}
