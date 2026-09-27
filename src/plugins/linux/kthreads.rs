//! linux.kthreads.Kthreads (python `plugins/linux/kthreads.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::util::{array_to_string, pointer_to_string};
use crate::plugins::linux::pslist::list_tasks;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::LinuxExt;
use crate::symbols::linux::modules::{ALL_GATHERERS, module_lookup_by_addresses, run_modules_scanners};

pub struct Kthreads;

impl Plugin for Kthreads {
    fn name(&self) -> &'static str {
        "linux.kthreads.Kthreads"
    }
    fn description(&self) -> &'static str {
        "Enumerates kthread functions"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("TID", ColType::Int),
            Column::new("Thread Name", ColType::Str),
            Column::new("Handler Address", ColType::Hex),
            Column::new("Module", ColType::Str),
            Column::new("Symbol", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        let t = k.table;
        let kt = t.user_type("kthread").ok_or_else(|| Error::Symbol("Unknown symbol: kthread".into()))?;
        if t.member(kt, "threadfn").is_none() {
            return Err(Error::msg("Unsupported kthread implementation. This plugin only works with kernels >= 5.8"));
        }
        let known_modules = run_modules_scanners(k, &ALL_GATHERERS)?;
        let no_filter = |_: &crate::objects::Obj| Ok(false);
        // python looks each handler up as it goes; the lookups only read the symbol tables, so
        // the rows are gathered first and all kernel symbols are resolved in one pass over the
        // table (module_lookup_by_addresses: same results, same error points) instead of one
        // lookup each (which builds the whole address index)
        let mut rows: Vec<(i128, String, u64)> = Vec::new();
        let walked = list_tasks(k, &no_filter, true, &mut |task| {
            if !task.is_kernel_thread()? {
                return Ok(true);
            }
            let base = if task.has_member("worker_private") { task.m("worker_private")? } else { task.m("set_child_tid")? };
            if !base.is_readable() {
                return Ok(true);
            }
            let kthread = base.deref()?.cast("kthread")?;
            let threadfn = kthread.m("threadfn")?;
            let fnv = threadfn.u64()?;
            if fnv == 0 || !threadfn.is_readable() {
                return Ok(true);
            }
            let mut thread_name = array_to_string(&task.m("comm")?, None)?;
            if kthread.has_member("full_name") {
                match pointer_to_string(&kthread.m("full_name")?, 255) {
                    Ok(n) => thread_name = n,
                    Err(e) if e.is_invalid_address() => {}
                    Err(e) => return Err(e),
                }
            }
            rows.push((task.m("pid")?.int()?, thread_name, fnv));
            Ok(true)
        });
        let addrs: Vec<u64> = rows.iter().map(|r| r.2).collect();
        let lookups = module_lookup_by_addresses(k, &known_modules, &addrs);
        for ((pid, thread_name, fnv), lookup) in rows.into_iter().zip(lookups) {
            let (info, symbol) = lookup?;
            let module = info.map_or(Value::NotAvailable, |i| Value::Str(i.name));
            let symbol = match symbol {
                Some(s) if !s.is_empty() => Value::Str(s),
                _ => Value::NotAvailable,
            };
            out.row(0, vec![Value::Int(pid), Value::Str(thread_name), Value::Int(fnv as i128), module, symbol])?;
        }
        walked
    }
}
