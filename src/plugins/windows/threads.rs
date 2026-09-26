//! windows.threads.Threads (python `plugins/windows/threads.py`, a ThrdScan subclass whose
//! threads come from each process' `ThreadListHead`) and its classmethods [`list_threads`] /
//! [`list_process_threads`].
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::Obj;
use crate::plugins::windows::pslist::list_processes;
use crate::plugins::windows::thrdscan::{columns, thread_rows, timeline_of};
use crate::plugins::{Config, Plugin, TimelineEvent};
use crate::renderers::RowSink;
use crate::symbols::windows::WinExt;

pub struct Threads;

/// python `Threads.list_threads(context, kernel_module_name, proc)`: the `_ETHREAD`s of
/// `proc.ThreadListHead` (stopping at the first repeated thread). A trailing `Err` = python
/// raised there.
pub fn list_threads(k: &WinKernel, proc: &Obj) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    let head = match proc.m("ThreadListHead") {
        Ok(h) => h,
        Err(e) => return vec![Err(e)],
    };
    let mut seen = crate::util::FxHashSet::default();
    for t in head.list_of(&format!("{}!_ETHREAD", k.table.name()), "ThreadListEntry") {
        match t {
            Ok(t) => {
                if !seen.insert(t.addr) {
                    break;
                }
                out.push(Ok(t));
            }
            Err(e) => {
                out.push(Err(e));
                break;
            }
        }
    }
    out
}

/// python `Threads.list_process_threads(context, kernel_module_name)`: the threads of every
/// process of `PsList.list_processes` (python reads its pid filter from the root config, which
/// is never set, so all processes). A trailing `Err` = python raised there.
pub fn list_process_threads(k: &WinKernel) -> Vec<Result<Obj>> {
    let _t = crate::util::trace::span("list_process_threads");
    let procs = list_processes(k, &|_| Ok(false));
    // each process' list is independent: walk them in parallel, keep python's order
    let per = crate::util::par::par_map(procs.len(), |i| match &procs[i] {
        Ok(p) => list_threads(k, p),
        Err(_) => Vec::new(),
    });
    let mut out = Vec::new();
    for (p, threads) in procs.into_iter().zip(per) {
        if let Err(e) = p {
            out.push(Err(e));
            break;
        }
        let failed = threads.last().is_some_and(|t| t.is_err());
        out.extend(threads);
        if failed {
            break;
        }
    }
    out
}

impl Plugin for Threads {
    fn name(&self) -> &'static str {
        "windows.threads.Threads"
    }
    fn description(&self) -> &'static str {
        "Lists process threads"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(columns())?;
        let k = ctx.windows_kernel()?;
        thread_rows(list_process_threads(k), &mut |r| out.row(0, r))
    }
    fn timeline(&self, ctx: &Context, _cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        Some(ctx.windows_kernel().and_then(|k| timeline_of(list_process_threads(k))))
    }
}
