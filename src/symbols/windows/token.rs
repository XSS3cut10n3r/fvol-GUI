//! python `TOKEN` and `KTIMER` class extensions (symbols/windows/extensions/__init__.py).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::error::{Error, Result};
use crate::objects::util::{bswap_64, rol};
use crate::objects::{Module, Obj, Space};
use crate::util::pyformat::fmt_int;

fn kernel_module(o: &Obj, native: bool) -> Result<Module> {
    let layer = if native { o.native() } else { o.layer() };
    let kvo = layer
        .as_intel()
        .and_then(|i| i.kernel_virtual_offset())
        .filter(|k| *k != 0)
        .ok_or_else(|| Error::msg("Intel layer does not have an associated kernel virtual offset, failing"))?;
    Ok(Module { sp: Space::on(layer, o.table()), offset: kvo })
}

/// `_TOKEN` methods.
pub trait TokenExt {
    /// python `TOKEN.get_sids()`: SID strings (`S-1-5-18` ...). python stops at the first SID
    /// failing the IsValidSid check and skips unreadable ones.
    fn get_sids(&self) -> Result<Vec<String>>;
    /// python `TOKEN.privileges()`: (index/LUID, present, enabled, enabled_by_default).
    fn privileges(&self) -> Result<Vec<(i128, bool, bool, bool)>>;
}

impl TokenExt for Obj {
    fn get_sids(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let count = self.m("UserAndGroupCount")?.int()?;
        if count >= 0xFFFF {
            return Ok(out);
        }
        let nt = kernel_module(self, false)?;
        let arr_addr = self.m("UserAndGroups")?.u64()?;
        let sa_ty = nt.get_type("_SID_AND_ATTRIBUTES")?;
        let arr = Obj::new(nt.sp, crate::symbols::Ty::Void, arr_addr).cast_array(count as u64, sa_ty);
        for sa in arr.elements() {
            let r = (|| -> Result<Option<String>> {
                let sid = sa.m("Sid")?.deref()?.cast("_SID")?;
                let rev = sid.m("Revision")?.int()?;
                let sub_count = sid.m("SubAuthorityCount")?.int()?;
                if rev & 0xF != 1 || sub_count > 15 {
                    return Ok(None);
                }
                let ia = sid.path("IdentifierAuthority.Value")?;
                let id_auth = ia.ints()?.last().copied();
                let sub = sid.m("SubAuthority")?.cast_array_of(sub_count as u64, "unsigned long")?.ints()?;
                let mut s = format!("S-{rev}");
                match id_auth {
                    Some(v) => s.push_str(&format!("-{v}")),
                    None => s.push('-'),
                }
                for v in sub {
                    s.push_str(&format!("-{v}"));
                }
                Ok(Some(s))
            })();
            match r {
                Ok(Some(s)) => out.push(s),
                Ok(None) => return Ok(out),
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    fn privileges(&self) -> Result<Vec<(i128, bool, bool, bool)>> {
        let privs = self.m("Privileges")?;
        if privs.has_member("Present") {
            let present = privs.m("Present")?.int()?;
            let enabled = privs.m("Enabled")?.int()?;
            let default = privs.m("EnabledByDefault")?.int()?;
            return Ok((0..64).map(|i| (i as i128, present & (1 << i) != 0, enabled & (1 << i) != 0, default & (1 << i) != 0)).collect());
        }
        // Windows XP: pointer to an array of _LUID_AND_ATTRIBUTES
        let count = self.m("PrivilegeCount")?.int()?;
        if count >= 1024 {
            return Ok(Vec::new());
        }
        let la = self.table().get_type("_LUID_AND_ATTRIBUTES")?;
        let arr = privs.deref()?.cast_array(count as u64, la);
        let mut out = Vec::new();
        for l in arr.elements() {
            let attrs = l.m("Attributes")?.int()?;
            out.push((l.path("Luid.LowPart")?.int()?, true, attrs & 2 != 0, attrs & 1 != 0));
        }
        Ok(out)
    }
}

/// `_KTIMER` methods.
pub trait KtimerExt {
    /// python `KTIMER.get_signaled()`: "Yes" / "-".
    fn get_signaled(&self) -> Result<&'static str>;
    /// python `KTIMER.valid_type()`.
    fn valid_type(&self) -> Result<bool>;
    /// python `KTIMER.get_due_time()`: `"{HighPart:#010x}:{LowPart:#010x}"`.
    fn get_due_time(&self) -> Result<String>;
    /// python `KTIMER.get_dpc()`: the decoded `_KDPC` (Windows 7+), else the raw `Dpc` pointer.
    fn get_dpc(&self) -> Result<Obj>;
}

impl KtimerExt for Obj {
    fn get_signaled(&self) -> Result<&'static str> {
        Ok(if self.path("Header.SignalState")?.int()? != 0 { "Yes" } else { "-" })
    }
    fn valid_type(&self) -> Result<bool> {
        let t = self.path("Header.Type")?.int()?;
        Ok(t == 8 || t == 9)
    }
    fn get_due_time(&self) -> Result<String> {
        let d = self.m("DueTime")?;
        Ok(format!("{}:{}", fmt_int(d.m("HighPart")?.int()?, "#010x"), fmt_int(d.m("LowPart")?.int()?, "#010x")))
    }
    fn get_dpc(&self) -> Result<Obj> {
        let nt = kernel_module(self, true)?;
        if nt.has_symbol("KiWaitNever") && nt.has_symbol("KiWaitAlways") {
            let wait_never = nt.object("unsigned long long", nt.get_symbol("KiWaitNever")?.address)?.u64()?;
            let wait_always = nt.object("unsigned long long", nt.get_symbol("KiWaitAlways")?.address)?.u64()?;
            let low_byte = (wait_never & 0xFF) as u32;
            let entry = rol(self.m("Dpc")?.raw_u64()? ^ wait_never, low_byte, 64);
            let intel = self.native().as_intel().ok_or_else(|| Error::msg("not an intel layer"))?;
            let swap_xor = intel.canonicalize(self.addr);
            let entry = bswap_64(entry ^ swap_xor);
            let dpc = entry ^ wait_always;
            return Obj::named(Space::get(self.layer(), self.layer(), self.table()), "_KDPC", dpc);
        }
        self.m("Dpc")
    }
}

#[cfg(test)]
mod tests {
    use crate::util::pyformat::fmt_int;
    #[test]
    fn due_time_format() {
        assert_eq!(format!("{}:{}", fmt_int(-1, "#010x"), fmt_int(0x1234, "#010x")), "-0x0000001:0x00001234");
    }
}
