//! python `symbols/linux/utilities/tainting.py`: `Tainting` (kernel / module taint flags
//! parsing) and `constants.linux.TAINT_FLAGS`.
//!
//! For plugin porters:
//!   * `Tainting.get_taints_parsed(ctx, kernel, taints, is_module)` ->
//!     `Tainting::new(k).get_taints_parsed(taints, is_module)?` (build the [`Tainting`] once per
//!     run: it reads the kernel's `taint_flags` table once, like python's `lru_cache`).
//!   * `Tainting.get_taints_as_plain_string(...)` -> [`Tainting::get_taints_as_plain_string`].
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::error::{Error, Result};
use crate::objects::Module;

/// python `constants.linux.TaintFlag`.
#[derive(Clone, Copy, Debug)]
pub struct TaintFlag {
    pub shift: u64,
    pub desc: &'static str,
    pub when_present: bool,
    pub module: bool,
}

const fn tf(shift: u32, desc: &'static str, when_present: bool, module: bool) -> TaintFlag {
    TaintFlag { shift: 1 << shift, desc, when_present, module }
}

/// python `constants.linux.TAINT_FLAGS` (insertion order kept).
pub const TAINT_FLAGS: [(char, TaintFlag); 21] = [
    ('P', tf(0, "PROPRIETARY_MODULE", true, true)),
    ('G', tf(0, "PROPRIETARY_MODULE", false, true)),
    ('F', tf(1, "FORCED_MODULE", true, false)),
    ('S', tf(2, "CPU_OUT_OF_SPEC", true, false)),
    ('R', tf(3, "FORCED_RMMOD", true, false)),
    ('M', tf(4, "MACHINE_CHECK", true, false)),
    ('B', tf(5, "BAD_PAGE", true, false)),
    ('U', tf(6, "USER", true, false)),
    ('D', tf(7, "DIE", true, false)),
    ('A', tf(8, "OVERRIDDEN_ACPI_TABLE", true, false)),
    ('W', tf(9, "WARN", true, false)),
    ('C', tf(10, "CRAP", true, true)),
    ('I', tf(11, "FIRMWARE_WORKAROUND", true, false)),
    ('O', tf(12, "OOT_MODULE", true, true)),
    ('E', tf(13, "UNSIGNED_MODULE", true, true)),
    ('L', tf(14, "SOFTLOCKUP", true, false)),
    ('K', tf(15, "LIVEPATCH", true, true)),
    ('X', tf(16, "AUX", true, true)),
    ('T', tf(17, "RANDSTRUCT", true, false)),
    ('N', tf(18, "TEST", true, true)),
    ('J', tf(19, "FWCTL", true, false)),
];

/// python `TAINT_FLAGS.get(character)`.
pub fn taint_flag(c: char) -> Option<&'static TaintFlag> {
    TAINT_FLAGS.iter().find(|(k, _)| *k == c).map(|(_, f)| f)
}

/// One kernel `struct taint_flag`, read like python reads it (errors kept where they occur).
struct KernelFlag {
    /// `None` = no `module` member (kernels after "taint/module: Remove ... module field").
    module: Option<Result<bool>>,
    c_true: Result<i128>,
    c_false: Result<i128>,
}

fn copy_err<T: Copy>(r: &Result<T>) -> Result<T> {
    match r {
        Ok(v) => Ok(*v),
        Err(e) => Err(match e {
            Error::InvalidAddress { addr } => Error::InvalidAddress { addr: *addr },
            Error::Swapped { addr } => Error::Swapped { addr: *addr },
            Error::Symbol(s) => Error::Symbol(s.clone()),
            Error::Unsatisfied(s) => Error::Unsatisfied(s.clone()),
            Error::Layer(s) => Error::Layer(s.clone()),
            Error::Io(e) => Error::msg(e.to_string()),
            Error::Msg(s) => Error::Msg(s.clone()),
        }),
    }
}

/// python `Tainting` bound to one kernel (the `taint_flags` table read once).
pub struct Tainting {
    /// python `_get_kernel_taint_flags_list` (`None` when the kernel has no `taint_flags`).
    flags: Option<Vec<KernelFlag>>,
}

impl Tainting {
    /// Read the kernel's `taint_flags` table (python `_get_kernel_taint_flags_list`).
    pub fn new(vm: &Module) -> Result<Tainting> {
        if !vm.has_symbol("taint_flags") {
            return Ok(Tainting { flags: None });
        }
        let arr = vm.object_from_symbol("taint_flags")?;
        let mut flags = Vec::with_capacity(arr.count() as usize);
        for i in 0..arr.count() {
            let f = arr.at(i)?;
            let module = if f.has_member("module") { Some(f.m("module").and_then(|m| m.bool())) } else { None };
            let c_true = f.m("c_true").and_then(|c| c.int());
            let c_false = f.m("c_false").and_then(|c| c.int());
            flags.push(KernelFlag { module, c_true, c_false });
        }
        Ok(Tainting { flags: Some(flags) })
    }

    /// python `_module_flags_taint_pre_4_10_rc1(taints, is_module)`.
    fn pre_4_10_rc1(taints: i128, is_module: bool) -> String {
        let mut s = String::new();
        for (c, f) in TAINT_FLAGS.iter() {
            if is_module && !f.module {
                continue;
            }
            if taints & f.shift as i128 != 0 {
                s.push(*c);
            }
        }
        s
    }

    /// python `_module_flags_taint_post_4_10_rc1(taints, is_module)`.
    fn post_4_10_rc1(flags: &[KernelFlag], taints: i128, is_module: bool) -> Result<String> {
        let mut s = String::new();
        for (bit, f) in flags.iter().enumerate() {
            if is_module {
                if let Some(m) = &f.module {
                    if !copy_err(m)? {
                        continue;
                    }
                }
            }
            // python `chr()` raises ValueError (-> continue) outside 0..=0x10FFFF
            let c_true = copy_err(&f.c_true)?;
            let c_true = match u32::try_from(c_true).ok().and_then(char::from_u32) {
                Some(c) => c,
                None => continue,
            };
            let c_false = copy_err(&f.c_false)?;
            let c_false = match u32::try_from(c_false).ok().and_then(char::from_u32) {
                Some(c) => c,
                None => continue,
            };
            let set = if bit < 127 { taints & (1i128 << bit) != 0 } else { false };
            if set {
                s.push(c_true);
            } else if c_false != ' ' {
                s.push(c_false);
            }
        }
        Ok(s)
    }

    /// python `Tainting.get_taints_as_plain_string(ctx, kernel, taints, is_module)`.
    pub fn get_taints_as_plain_string(&self, taints: i128, is_module: bool) -> Result<String> {
        match &self.flags {
            Some(f) if !f.is_empty() => Self::post_4_10_rc1(f, taints, is_module),
            _ => Ok(Self::pre_4_10_rc1(taints, is_module)),
        }
    }

    /// python `Tainting.get_taints_parsed(ctx, kernel, taints, is_module)`.
    pub fn get_taints_parsed(&self, taints: i128, is_module: bool) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for c in self.get_taints_as_plain_string(taints, is_module)?.chars() {
            match taint_flag(c) {
                None => out.push(format!("<UNKNOWN_TAINT_CHAR_{c}>")),
                Some(f) if f.when_present => out.push(f.desc.to_string()),
                Some(_) => {}
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_4_10_strings() {
        // OOT + UNSIGNED, module flags only
        assert_eq!(Tainting::pre_4_10_rc1((1 << 12) | (1 << 13) | (1 << 9), true), "OE");
        assert_eq!(Tainting::pre_4_10_rc1(1, false), "PG");
        let t = Tainting { flags: None };
        assert_eq!(t.get_taints_parsed(1, true).unwrap(), vec!["PROPRIETARY_MODULE".to_string()]);
    }
}
