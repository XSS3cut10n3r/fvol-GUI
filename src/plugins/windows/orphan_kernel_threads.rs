//! windows.orphan_kernel_threads.Threads (python `plugins/windows/orphan_kernel_threads.py`, a
//! ThrdScan subclass): scanned system threads whose start address is in no loaded module.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::plugins::windows::ssdt::build_module_collection;
use crate::plugins::windows::thrdscan::{columns, scan_threads_each, thread_rows_out, timeline_of};
use crate::plugins::{Config, Plugin, TimelineEvent};
use crate::renderers::RowSink;
use crate::symbols::windows::WinExt;

pub struct Threads;

/// python `AttributeError` or `InvalidAddressException`.
fn attribute_or_invalid(e: &Error) -> bool {
    e.is_invalid_address() || matches!(e, Error::Symbol(s) if s.starts_with("AttributeError"))
}

/// python `Threads.list_orphan_kernel_threads(context, kernel_module_name)`: scanned threads of
/// System (pid 4) or its children that are not terminated, start in kernel space and whose
/// start address maps to no loaded module. A trailing `Err` = python raised there.
pub fn list_orphan_kernel_threads(ctx: &Context, k: &WinKernel) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let collection = build_module_collection(k)?;
        let kernel_space_start = super::modules::get_kernel_space_start(k)?;
        scan_threads_each(ctx, k, |thread| {
            let r = (|| -> Result<(u64, u64, u64)> {
                let proc = thread.owning_process()?;
                let pid = proc.m("UniqueProcessId")?.u64()?;
                let ppid = proc.m("InheritedFromUniqueProcessId")?.u64()?;
                let start = thread.m("StartAddress")?.u64()?;
                Ok((pid, ppid, start))
            })();
            let (pid, ppid, start) = match r {
                Ok(v) => v,
                Err(e) if attribute_or_invalid(&e) => return Ok(true),
                Err(e) => return Err(e),
            };
            if pid != 4 && ppid != 4 {
                return Ok(true);
            }
            if thread.path("ExitTime.QuadPart")?.int()? > 0 || thread.path("Tcb.State")?.int()? == 4 {
                return Ok(true);
            }
            if start < kernel_space_start {
                return Ok(true);
            }
            if !collection.contains(start) {
                out.push(Ok(thread));
            }
            Ok(true)
        })
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

impl Plugin for Threads {
    fn name(&self) -> &'static str {
        "windows.orphan_kernel_threads.Threads"
    }
    fn description(&self) -> &'static str {
        "Lists process threads"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(columns())?;
        let k = ctx.windows_kernel()?;
        thread_rows_out(list_orphan_kernel_threads(ctx, k), out)
    }
    fn timeline(&self, ctx: &Context, _cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        Some(ctx.windows_kernel().and_then(|k| timeline_of(list_orphan_kernel_threads(ctx, k))))
    }
}
