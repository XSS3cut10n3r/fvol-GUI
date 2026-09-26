//! python `symbols/windows/extensions/kdbg.py` (`_KDDEBUGGER_DATA64` helpers).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::error::Result;
use crate::objects::Obj;

/// python `KDDEBUGGER_DATA64.get_build_lab()`: 32-byte string at `NtBuildLab`
/// (utf-8, errors="replace").
pub fn get_build_lab(kdbg: &Obj) -> Result<String> {
    let addr = kdbg.m("NtBuildLab")?.u64()?;
    kdbg.at_addr(addr).read_string(32, "utf-8", "replace")
}

/// python `KDDEBUGGER_DATA64.get_csdversion()`: `(unsigned long at CmNtCSDVersion >> 8) & 0xffffffff`.
pub fn get_csdversion(kdbg: &Obj) -> Result<i128> {
    let addr = kdbg.m("CmNtCSDVersion")?.u64()?;
    let v = Obj::named(kdbg.sp, "unsigned long", addr)?.int()?;
    Ok((v >> 8) & 0xFFFF_FFFF)
}
