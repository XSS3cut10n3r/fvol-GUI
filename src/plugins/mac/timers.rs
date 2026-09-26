//! mac.timers.Timers (python `plugins/mac/timers.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::mac::lsmod::list_modules;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::{MAX_ELEMENTS, MacExt, generate_kernel_handler_info, lookup_module_address};

pub struct Timers;

impl Plugin for Timers {
    fn name(&self) -> &'static str {
        "mac.timers.Timers"
    }
    fn description(&self) -> &'static str {
        "Check for malicious kernel timers."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![
            Column::new("Function", ColType::Hex),
            Column::new("Param 0", ColType::Hex),
            Column::new("Param 1", ColType::Hex),
            Column::new("Deadline", ColType::Int),
            Column::new("Entry Time", ColType::Int),
            Column::new("Module", ColType::Str),
            Column::new("Symbol", ColType::Str),
        ])?;
        let handlers = generate_kernel_handler_info(k, list_modules(k))?;
        let real_ncpus = k.object_from_symbol("real_ncpus")?.int()?;
        let cpu_data_ptrs_ptr = k.get_symbol("cpu_data_ptr")?.address;
        // kernel.object("pointer", offset=<cpu_data_ptr>): the first element of the array
        let cpu_data_ptrs_addr = k.object("pointer", cpu_data_ptrs_ptr)?.u64()?;
        // python then views an ARRAY OF cpu_data STRUCTS at that address (count real_ncpus)
        let cpu_data = k.object_abs("cpu_data", cpu_data_ptrs_addr)?;
        let size = cpu_data.size();
        let count = real_ncpus.clamp(0, u32::MAX as i128) as u64;
        for i in 0..count {
            let cpu = cpu_data.at_addr(cpu_data.addr.wrapping_add(size.wrapping_mul(i)));
            let queue = cpu.m("rtclock_timer")?.m("queue")?.m("head")?;
            for timer in queue.walk_list(&queue, "q_link", "call_entry", MAX_ELEMENTS) {
                let timer = timer?;
                let handler = match timer.m("func").and_then(|f| f.u64()) {
                    Ok(h) => h,
                    Err(e) if e.is_invalid_address() => continue,
                    Err(e) => return Err(e),
                };
                let entry_time = if timer.has_member("entry_time") { timer.m("entry_time")?.int()? } else { -1 };
                let (module, symbol) = lookup_module_address(k.table, &handlers, handler as i128, Some(k.offset));
                let param0 = timer.m("param0")?.u64()?;
                let param1 = timer.m("param1")?.u64()?;
                let deadline = timer.m("deadline")?.int()?;
                out.row(
                    0,
                    vec![
                        Value::Int(handler as i128),
                        Value::Int(param0 as i128),
                        Value::Int(param1 as i128),
                        Value::Int(deadline),
                        Value::Int(entry_time),
                        Value::Str(module),
                        Value::Str(symbol.to_string()),
                    ],
                )?;
            }
        }
        Ok(())
    }
}
