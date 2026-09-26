//! python `symbols/linux/extensions/__init__.py` `kernel_cap_struct` / `kernel_cap_t`
//! (process capability sets), as the [`CapsExt`] trait on [`Obj`].
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use super::fs::tgt;
use super::vmlinux_of;
use crate::error::{Error, Result};
use crate::objects::Obj;

/// python `linux_constants.CAPABILITIES` (bit number = index).
pub const CAPABILITIES: [&str; 41] = [
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "kill",
    "setgid",
    "setuid",
    "setpcap",
    "linux_immutable",
    "net_bind_service",
    "net_broadcast",
    "net_admin",
    "net_raw",
    "ipc_lock",
    "ipc_owner",
    "sys_module",
    "sys_rawio",
    "sys_chroot",
    "sys_ptrace",
    "sys_pacct",
    "sys_admin",
    "sys_boot",
    "sys_nice",
    "sys_resource",
    "sys_time",
    "sys_tty_config",
    "mknod",
    "lease",
    "audit_write",
    "audit_control",
    "setfcap",
    "mac_override",
    "mac_admin",
    "syslog",
    "wake_alarm",
    "block_suspend",
    "audit_read",
    "perfmon",
    "bpf",
    "checkpoint_restore",
];

/// python `kernel_cap_struct.get_last_cap_value()`.
pub fn get_last_cap_value() -> i128 {
    CAPABILITIES.len() as i128 - 1
}

/// python `kernel_cap_struct.capabilities_to_string(bitfield)`.
pub fn capabilities_to_string(bits: i128) -> Vec<&'static str> {
    CAPABILITIES.iter().enumerate().filter(|(i, _)| bits & (1i128 << i) != 0).map(|(_, n)| *n).collect()
}

/// `kernel_cap_struct` / `kernel_cap_t` methods (the object may be a pointer to it).
pub trait CapsExt {
    /// python `get_kernel_cap_full()`: `(1 << (cap_last_cap + 1)) - 1` (the framework's list
    /// size when the kernel has no `cap_last_cap`).
    fn get_kernel_cap_full(&self) -> Result<i128>;
    /// python `get_capabilities()` (the bitfield masked with the full set).
    fn get_capabilities(&self) -> Result<i128>;
    /// python `enumerate_capabilities()`.
    fn enumerate_capabilities(&self) -> Result<Vec<&'static str>>;
    /// python `has_capability(name)` (`Err` for an unknown name, like python's AttributeError).
    fn has_capability(&self, capability: &str) -> Result<bool>;
}

/// `cap_last_cap` (cached per kernel table; python reads it on every call).
fn cap_last_cap(o: &Obj) -> Result<i128> {
    use std::sync::Mutex;
    static CACHE: Mutex<Vec<(usize, i128)>> = Mutex::new(Vec::new());
    let key = o.table() as *const _ as usize;
    if let Some(v) = CACHE.lock().unwrap().iter().find(|e| e.0 == key) {
        return Ok(v.1);
    }
    let vm = vmlinux_of(o)?;
    let v = if vm.has_symbol("cap_last_cap") { vm.object_from_symbol("cap_last_cap")?.int()? } else { get_last_cap_value() };
    CACHE.lock().unwrap().push((key, v));
    Ok(v)
}

impl CapsExt for Obj {
    fn get_kernel_cap_full(&self) -> Result<i128> {
        let last = cap_last_cap(self)?;
        if !(-1..=125).contains(&last) {
            return Err(Error::msg(format!("OverflowError: capability bit {last} out of range")));
        }
        Ok((1i128 << (last + 1)) - 1)
    }

    fn get_capabilities(&self) -> Result<i128> {
        let c = tgt(self)?;
        let value = if c.has_member("val") {
            // kernel_cap_t (>= 6.3): u64
            c.m("val")?.int()?
        } else {
            if !c.has_member("cap") {
                return Err(Error::msg("VolatilityException: Unsupported kernel capabilities implementation"));
            }
            let cap = c.m("cap")?;
            if cap.is_array() {
                match cap.count() {
                    1 => cap.at(0)?.int()?,
                    2 => (cap.at(1)?.int()? << 32) | cap.at(0)?.int()?,
                    _ => return Err(Error::msg("VolatilityException: Unsupported kernel capabilities implementation")),
                }
            } else {
                cap.int()?
            }
        };
        Ok(value & self.get_kernel_cap_full()?)
    }

    fn enumerate_capabilities(&self) -> Result<Vec<&'static str>> {
        Ok(capabilities_to_string(self.get_capabilities()?))
    }

    fn has_capability(&self, capability: &str) -> Result<bool> {
        let Some(i) = CAPABILITIES.iter().position(|c| *c == capability) else {
            return Err(Error::msg(format!("AttributeError: Unknown capability with name '{capability}'")));
        };
        Ok((1i128 << i) & self.get_capabilities()? != 0)
    }
}
