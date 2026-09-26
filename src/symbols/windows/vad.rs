//! python `MMVAD_SHORT` / `MMVAD` class extensions (symbols/windows/extensions/__init__.py),
//! valid for `_MMVAD_SHORT`, `_MMVAD`, `_MMADDRESS_NODE`, `_MM_AVL_NODE`, `_RTL_BALANCED_NODE`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! use crate::symbols::windows::prelude::*;
//! for vad in proc.get_vad_root()?.traverse() { let vad = vad?; let start = vad.get_start()?; }
//! ```

use super::ext::WinExt;
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::renderers::Value;
use crate::util::FxHashSet;

fn attr(what: &str) -> Error {
    Error::Symbol(format!("AttributeError: {what}"))
}

/// VAD node methods.
pub trait VadExt {
    /// python `get_tag()`: the 4-byte pool tag in front of the node (utf-8 strict), None when
    /// unreadable / undecodable.
    fn get_tag(&self) -> Option<String>;
    /// python `traverse()`: the VAD tree in python order (node, left subtree, right subtree),
    /// each node cast to `_MMVAD_SHORT` / `_MMVAD` by tag. A trailing `Err` = python raised
    /// ("Vad tree is too deep" or a missing member).
    fn traverse(&self) -> Vec<Result<Obj>>;
    /// python `get_left_child()` (the pointer member).
    fn get_left_child(&self) -> Result<Obj>;
    /// python `get_right_child()`.
    fn get_right_child(&self) -> Result<Obj>;
    /// python `get_parent()` (value, low 2 bits cleared where python does).
    fn get_parent(&self) -> Result<i128>;
    /// python `get_start()`: first address of the range.
    fn get_start(&self) -> Result<u64>;
    /// python `get_end()`: last address of the range.
    fn get_end(&self) -> Result<u64>;
    /// python `get_size()`.
    fn get_size(&self) -> Result<u64>;
    /// python `get_commit_charge()` (the member object; `.int()` it).
    fn get_commit_charge(&self) -> Result<Obj>;
    /// python `get_private_memory()` (the member object).
    fn get_private_memory(&self) -> Result<Obj>;
    /// python `Protection` property (None when absent).
    fn vad_protection(&self) -> Result<Option<i128>>;
    /// python `get_protection(protect_values, winnt_protections)`.
    fn get_protection(&self, protect_values: &[i128], winnt_protections: &[(&str, i128)]) -> Result<String>;
    /// python `get_file_name()`: `_MMVAD` mapped file name or NotApplicable.
    fn get_file_name(&self) -> Value;
}

fn traverse_rec(node: Obj, visited: &mut FxHashSet<u64>, depth: u32, out: &mut Vec<Result<Obj>>) -> Result<()> {
    if depth > 100 {
        return Err(Error::msg("Vad tree is too deep"));
    }
    if !visited.insert(node.addr) {
        return Ok(());
    }
    let tag = node.get_tag();
    let target = match tag.as_deref() {
        Some("VadS") | Some("VadF") => Some("_MMVAD_SHORT"),
        Some(t) if t.starts_with("Vad") => Some("_MMVAD"),
        _ if depth == 0 => None,
        _ => return Ok(()),
    };
    if let Some(t) = target {
        out.push(Ok(node.cast(t)?));
    }
    for left in [true, false] {
        let child = if left { node.get_left_child() } else { node.get_right_child() };
        match child.and_then(|p| p.deref()) {
            Ok(c) => traverse_rec(c, visited, depth + 1, out)?,
            Err(e) if e.is_invalid_address() => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn child(o: &Obj, a: &str, b: &str) -> Result<Obj> {
    if o.has_member(a) {
        return o.m(a);
    }
    if o.has_member(b) {
        return o.m(b);
    }
    if o.has_member("VadNode") {
        let v = o.m("VadNode")?;
        if v.has_member(a) {
            return v.m(a);
        }
        if v.has_member(b) {
            return v.m(b);
        }
    } else if o.has_member("Core") {
        let c = o.m("Core")?;
        if c.has_member("VadNode") {
            let v = c.m("VadNode")?;
            if v.has_member(a) {
                return v.m(a);
            }
            if v.has_member(b) {
                return v.m(b);
            }
        }
    }
    Err(attr(&format!("Unable to find the {} child member", if a == "LeftChild" { "left" } else { "right" })))
}

impl VadExt for Obj {
    fn get_tag(&self) -> Option<String> {
        let back = if self.table().is_64bit() { 12 } else { 4 };
        let tag = self.at_addr(self.addr.wrapping_sub(back)).cast_bytes(4).bytes().ok()?;
        String::from_utf8(tag).ok()
    }

    fn traverse(&self) -> Vec<Result<Obj>> {
        let mut out = Vec::new();
        let mut visited = FxHashSet::default();
        if let Err(e) = traverse_rec(*self, &mut visited, 0, &mut out) {
            out.push(Err(e));
        }
        out
    }

    fn get_left_child(&self) -> Result<Obj> {
        child(self, "LeftChild", "Left")
    }

    fn get_right_child(&self) -> Result<Obj> {
        child(self, "RightChild", "Right")
    }

    fn get_parent(&self) -> Result<i128> {
        if self.has_member("Parent") {
            return self.m("Parent")?.int();
        }
        if self.has_member("u1") && self.m("u1")?.has_member("Parent") {
            return Ok(self.path("u1.Parent")?.int()? & !0x3);
        }
        if self.has_member("VadNode") {
            let v = self.m("VadNode")?;
            if v.has_member("u1") {
                return Ok(v.path("u1.Parent")?.int()? & !0x3);
            } else if v.has_member("ParentValue") {
                return Ok(v.m("ParentValue")?.int()? & !0x3);
            }
        } else if self.has_member("Core") {
            let v = self.path("Core.VadNode")?;
            if v.has_member("u1") {
                return Ok(v.path("u1.Parent")?.int()? & !0x3);
            } else if v.has_member("ParentValue") {
                return Ok(v.m("ParentValue")?.int()? & !0x3);
            }
        }
        Err(attr("Unable to find the parent member"))
    }

    fn get_start(&self) -> Result<u64> {
        let base = if self.has_member("StartingVpn") {
            *self
        } else if self.has_member("Core") {
            self.m("Core")?
        } else {
            return Err(attr("Unable to find the starting VPN member"));
        };
        let vpn = base.m("StartingVpn")?.int()?;
        let v = if base.has_member("StartingVpnHigh") { (vpn << 12) | (base.m("StartingVpnHigh")?.int()? << 44) } else { vpn << 12 };
        Ok(v as u64)
    }

    fn get_end(&self) -> Result<u64> {
        let base = if self.has_member("EndingVpn") {
            *self
        } else if self.has_member("Core") {
            self.m("Core")?
        } else {
            return Err(attr("Unable to find the ending VPN member"));
        };
        let vpn = base.m("EndingVpn")?.int()?;
        let v = if base.has_member("EndingVpnHigh") {
            (((vpn + 1) << 12) | (base.m("EndingVpnHigh")?.int()? << 44)) - 1
        } else {
            ((vpn + 1) << 12) - 1
        };
        Ok(v as u64)
    }

    fn get_size(&self) -> Result<u64> {
        Ok(self.get_end()?.wrapping_sub(self.get_start()?).wrapping_add(1))
    }

    fn get_commit_charge(&self) -> Result<Obj> {
        if self.has_member("CommitCharge") {
            return self.m("CommitCharge");
        }
        if self.has_member("u1") && self.m("u1")?.has_member("VadFlags1") {
            return self.path("u1.VadFlags1.CommitCharge");
        }
        if self.has_member("u") && self.m("u")?.has_member("VadFlags") {
            return self.path("u.VadFlags.CommitCharge");
        }
        if self.has_member("Core") {
            let c = self.m("Core")?;
            if c.has_member("CommitCharge") {
                return c.m("CommitCharge");
            }
            return c.path("u1.VadFlags1.CommitCharge");
        }
        Err(attr("Unable to find the commit charge member"))
    }

    fn get_private_memory(&self) -> Result<Obj> {
        let try_path = |o: &Obj, a: &str, b: &str| -> Result<Option<Obj>> {
            if o.has_member(a) {
                let x = o.m(a)?;
                if x.has_member(b) {
                    let y = x.m(b)?;
                    if y.has_member("PrivateMemory") {
                        return Ok(Some(y.m("PrivateMemory")?));
                    }
                }
            }
            Ok(None)
        };
        if let Some(v) = try_path(self, "u1", "VadFlags1")? {
            return Ok(v);
        }
        if let Some(v) = try_path(self, "u", "VadFlags")? {
            return Ok(v);
        }
        if self.has_member("Core") {
            let c = self.m("Core")?;
            if let Some(v) = try_path(&c, "u1", "VadFlags1")? {
                return Ok(v);
            }
            if let Some(v) = try_path(&c, "u", "VadFlags")? {
                return Ok(v);
            }
        }
        Err(attr("Unable to find the private memory member"))
    }

    fn vad_protection(&self) -> Result<Option<i128>> {
        if self.has_member("u") {
            Ok(Some(self.path("u.VadFlags.Protection")?.int()?))
        } else if self.has_member("Core") {
            Ok(Some(self.path("Core.u.VadFlags.Protection")?.int()?))
        } else {
            Ok(None)
        }
    }

    fn get_protection(&self, protect_values: &[i128], winnt_protections: &[(&str, i128)]) -> Result<String> {
        let protect = self.vad_protection()?.ok_or_else(|| Error::msg("TypeError: list indices must be integers or slices, not NoneType"))?;
        // python list indexing: negative indexes count from the end; out of range -> 0
        let idx = if protect < 0 { protect_values.len() as i128 + protect } else { protect };
        let value = if idx >= 0 && (idx as usize) < protect_values.len() { protect_values[idx as usize] } else { 0 };
        let names: Vec<&str> = winnt_protections.iter().filter(|(_, m)| value & m != 0).map(|(n, _)| *n).collect();
        Ok(names.join("|"))
    }

    fn get_file_name(&self) -> Value {
        if self.struct_name() != Some("_MMVAD") {
            return Value::NotApplicable;
        }
        let r = (|| -> Result<Option<String>> {
            let fname = if self.has_member("ControlArea") {
                self.path("ControlArea.FilePointer.FileName")?
            } else {
                let fp = self.path("Subsection.ControlArea.FilePointer")?;
                let fo = if fp.is_pointer() { fp.deref()? } else { fp.fast_ref_dereference()? };
                fo.cast("_FILE_OBJECT")?.m("FileName")?
            };
            if fname.m("Length")?.int()? > 0 {
                return Ok(Some(fname.get_string()?));
            }
            Ok(None)
        })();
        match r {
            Ok(Some(s)) => Value::Str(s),
            _ => Value::NotApplicable,
        }
    }
}
