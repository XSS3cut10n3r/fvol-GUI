//! mac.trustedbsd.Trustedbsd (python `plugins/mac/trustedbsd.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::util::pointer_to_string;
use crate::plugins::mac::lsmod::list_modules;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::{generate_kernel_handler_info, lookup_module_address};

pub struct Trustedbsd;

impl Plugin for Trustedbsd {
    fn name(&self) -> &'static str {
        "mac.trustedbsd.Trustedbsd"
    }
    fn description(&self) -> &'static str {
        "Checks for malicious trustedbsd modules"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![
            Column::new("Member", ColType::Str),
            Column::new("Policy Name", ColType::Str),
            Column::new("Handler Address", ColType::Hex),
            Column::new("Handler Module", ColType::Str),
            Column::new("Handler Symbol", ColType::Str),
        ])?;
        let handlers = generate_kernel_handler_info(k, list_modules(k))?;
        let policy_list = k.object_from_symbol("mac_policy_list")?.cast("mac_policy_list")?;
        let entries_addr = policy_list.m("entries")?.u64()?;
        let count = policy_list.m("staticmax")?.int()? + 1;
        let elem = k.object_abs("mac_policy_list_element", entries_addr)?;
        let esize = elem.size();
        for i in 0..count.clamp(0, u32::MAX as i128) as u64 {
            let ent = elem.at_addr(entries_addr.wrapping_add(esize.wrapping_mul(i)));
            // mpc = ent.mpc.dereference(); ops = mpc.mpc_ops.dereference()
            let (mpc, ops) = match ent.m("mpc").and_then(|p| p.deref()).and_then(|mpc| mpc.m("mpc_ops")?.deref().map(|ops| (mpc, ops))) {
                Ok(x) => x,
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            };
            let ent_name = match mpc.m("mpc_name").and_then(|n| pointer_to_string(&n, 255)) {
                Ok(s) => s,
                Err(e) if e.is_invalid_address() => "N/A".to_string(),
                Err(e) => return Err(e),
            };
            for (check, member) in ops.members() {
                // getattr(ops, check): pointers/ints are read here (errors propagate)
                let call_addr = member.int()?;
                if call_addr == 0 {
                    continue;
                }
                let (module, symbol) = lookup_module_address(k.table, &handlers, call_addr, Some(k.offset));
                out.row(
                    0,
                    vec![Value::SStr(check), Value::Str(ent_name.clone()), Value::Int(call_addr), Value::Str(module), Value::Str(symbol.to_string())],
                )?;
            }
        }
        Ok(())
    }
}
