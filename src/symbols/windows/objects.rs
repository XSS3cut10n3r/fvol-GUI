//! Named executive objects: python `DEVICE_OBJECT`, `DRIVER_OBJECT`, `OBJECT_SYMBOLIC_LINK`,
//! `KMUTANT` and `FILE_OBJECT` class extensions (names through the object header's
//! `NameInfo`, see [`super::pool::PoolExt`]).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! use crate::symbols::windows::prelude::*;
//! let name = driver.get_driver_name()?;                 // header.NameInfo.Name.String
//! let path = file_obj.file_name_with_device()?;         // Value::Str or Value::Unreadable
//! let acl = file_obj.access_string()?;                  // "RWDrwd" style
//! for dev in device.get_attached_devices() { let dev = dev?; ... }
//! ```

use super::ext::WinExt;
use super::pool::PoolExt;
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::renderers::Value;

/// Device chains longer than this are treated as smear: we stop with an error (python would
/// keep walking distinct addresses).
pub const MAX_ATTACHED_DEVICES: usize = 1 << 16;

/// Named executive object helpers on [`Obj`].
pub trait ObjectsExt {
    /// python `header.NameInfo.Name.String` for any executive object (the body of
    /// `DEVICE_OBJECT.get_device_name`, `DRIVER_OBJECT.get_driver_name`,
    /// `OBJECT_SYMBOLIC_LINK.get_link_name`, `KMUTANT.get_name`). `Err(Error::Msg)` starting
    /// with "Could not find _OBJECT_HEADER_NAME_INFO" is python's `ValueError`.
    fn object_header_name(&self) -> Result<String>;
    /// python `DEVICE_OBJECT.get_device_name()`.
    fn get_device_name(&self) -> Result<String> {
        self.object_header_name()
    }
    /// python `DRIVER_OBJECT.get_driver_name()`.
    fn get_driver_name(&self) -> Result<String> {
        self.object_header_name()
    }
    /// python `OBJECT_SYMBOLIC_LINK.get_link_name()`.
    fn get_link_name(&self) -> Result<String> {
        self.object_header_name()
    }
    /// python `KMUTANT.get_name()`.
    fn mutant_name(&self) -> Result<String> {
        self.object_header_name()
    }
    /// python `DEVICE_OBJECT.get_attached_devices()`: the `AttachedDevice` chain. Like python,
    /// the walk is NOT stopped by a NULL pointer (python's `while device:` is always true for a
    /// struct): the object at the pointer value (address 0 for NULL) is yielded too, and the
    /// walk ends when a pointer cannot be read (caught, like python) or an address repeats. A
    /// trailing `Err` is a non-address error python would raise.
    fn get_attached_devices(&self) -> Vec<Result<Obj>>;
    /// python `DRIVER_OBJECT.get_devices()`: `DeviceObject`, then the `NextDevice` chain, with
    /// the same python semantics as [`get_attached_devices`](Self::get_attached_devices).
    fn get_devices(&self) -> Vec<Result<Obj>>;
    /// python `FILE_OBJECT.file_name_with_device()`: `\Device\<name>` + `FileName`, or
    /// `Value::Unreadable` when neither part could be read.
    fn file_name_with_device(&self) -> Result<Value>;
    /// python `FILE_OBJECT.access_string()` ("RWDrwd", `-` for unset flags).
    fn access_string(&self) -> Result<String>;
}

/// python's device-chain generators (`get_attached_devices` / `get_devices`): start at
/// `obj.<first>` and follow `<next>`; InvalidAddressException ends the walk silently, a
/// repeated address ends it too.
fn walk_device_chain(obj: &Obj, first: &str, next: &str) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    let mut device = match obj.m(first).and_then(|p| p.deref()) {
        Ok(d) => d,
        Err(e) if e.is_invalid_address() => return out,
        Err(e) => return vec![Err(e)],
    };
    let mut seen = crate::util::FxHashSet::default();
    loop {
        if !seen.insert(device.addr) {
            break;
        }
        if out.len() >= MAX_ATTACHED_DEVICES {
            out.push(Err(Error::msg("device chain too long (smear)")));
            break;
        }
        out.push(Ok(device));
        device = match device.m(next).and_then(|p| p.deref()) {
            Ok(d) => d,
            Err(e) if e.is_invalid_address() => break,
            Err(e) => {
                out.push(Err(e));
                break;
            }
        };
    }
    out
}

/// python's `ValueError` from `OBJECT_HEADER.NameInfo`.
pub fn is_name_info_value_error(e: &Error) -> bool {
    matches!(e, Error::Msg(m) if m.starts_with("Could not find _OBJECT_HEADER_NAME_INFO"))
}

impl ObjectsExt for Obj {
    fn object_header_name(&self) -> Result<String> {
        self.get_object_header(None)?.name_info()?.m("Name")?.get_string()
    }

    fn get_attached_devices(&self) -> Vec<Result<Obj>> {
        walk_device_chain(self, "AttachedDevice", "AttachedDevice")
    }

    fn get_devices(&self) -> Vec<Result<Obj>> {
        walk_device_chain(self, "DeviceObject", "NextDevice")
    }

    fn file_name_with_device(&self) -> Result<Value> {
        let mut name: Option<String> = None;
        // the pointer is checked against the native layer: the object may live on a physical
        // layer (filescan) or a virtual one (handles)
        let dev = self.m("DeviceObject")?;
        if self.native().is_valid(dev.u64()?, 1) {
            match dev.deref().and_then(|d| d.get_device_name()) {
                Ok(n) => name = Some(format!("\\Device\\{n}")),
                Err(e) if is_name_info_value_error(&e) => {}
                Err(e) => return Err(e),
            }
        }
        // suppress(TypeError, InvalidAddressException): UnreadableValue + str is a TypeError
        match self.m("FileName").and_then(|f| f.get_string()) {
            Ok(s) => {
                if let Some(n) = &mut name {
                    n.push_str(&s);
                }
            }
            Err(e) if e.is_invalid_address() => {}
            Err(e) => return Err(e),
        }
        Ok(name.map(Value::Str).unwrap_or(Value::Unreadable))
    }

    fn access_string(&self) -> Result<String> {
        let mut s = String::with_capacity(6);
        for (m, c) in [("ReadAccess", 'R'), ("WriteAccess", 'W'), ("DeleteAccess", 'D'), ("SharedRead", 'r'), ("SharedWrite", 'w'), ("SharedDelete", 'd')] {
            s.push(if self.m(m)?.int()? != 0 { c } else { '-' });
        }
        Ok(s)
    }
}
