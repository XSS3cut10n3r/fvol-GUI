//! windows.getservicesids.GetServiceSIDs (python `plugins/windows/getservicesids.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::layers::registry::is_invalid_or_registry;
use crate::plugins::windows::registry::hivelist::list_hives;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::registry::{RegExt, is_key_error};

pub struct GetServiceSIDs;

/// python `createservicesid(svc)`: `S-1-5-80-` + the SHA1 of the upper-cased UTF-16-ish name
/// (each character followed by NUL, upper-cased, UTF-8 encoded) as five little-endian u32s.
pub fn createservicesid(svc: &str) -> String {
    let mut uni = String::with_capacity(svc.len() * 2);
    for c in svc.chars() {
        uni.push(c);
        uni.push('\0');
    }
    let sha = crate::crypto::sha1::digest(uni.to_uppercase().as_bytes());
    let mut s = String::from("S-1-5-80");
    for i in 0..5 {
        let v = u32::from_le_bytes(sha[i * 4..i * 4 + 4].try_into().unwrap());
        s.push('-');
        s.push_str(&v.to_string());
    }
    s
}

impl Plugin for GetServiceSIDs {
    fn name(&self) -> &'static str {
        "windows.getservicesids.GetServiceSIDs"
    }
    fn description(&self) -> &'static str {
        "Lists process token sids."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("SID", ColType::Str), Column::new("Service", ColType::Str)])?;
        let k = ctx.windows_kernel()?;
        let known = &super::sids::data().service_names;
        for hive in list_hives(ctx, k, Some("machine\\system"), None) {
            let hive = hive?;
            let services = match hive.get_key_node("CurrentControlSet\\Services") {
                Ok(s) => s,
                Err(e) if is_key_error(&e) || is_invalid_or_registry(&e) => match hive.get_key_node("ControlSet001\\Services") {
                    Ok(s) => s,
                    Err(e) if is_key_error(&e) || is_invalid_or_registry(&e) => continue,
                    Err(e) => return Err(e),
                },
                Err(e) => return Err(e),
            };
            for s in services.get_subkeys() {
                let s = s?;
                let name = match s.get_name() {
                    Ok(n) => n,
                    Err(e) if is_invalid_or_registry(&e) => continue,
                    Err(e) => return Err(e),
                };
                if !known.contains(&name) {
                    out.row(0, vec![Value::Str(createservicesid(&name)), Value::Str(name)])?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_sid() {
        // from the reference output
        assert_eq!(createservicesid(".NET CLR Networking 4.0.0.0"), "S-1-5-80-4151353957-356578678-4163131872-800126167-2037860865");
    }
}
