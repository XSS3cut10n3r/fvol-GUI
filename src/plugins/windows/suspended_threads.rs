//! windows.suspended_threads.SuspendedThreads (python `plugins/windows/suspended_threads.py`):
//! suspended, non-terminated threads with the file / symbol of their start addresses.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::util::array_to_string;
use crate::plugins::windows::thread_pe_symbols::{CollectedModules, Range, get_process_modules, path_and_symbol_for_address, vads_for_process_cache};
use crate::plugins::windows::threads::list_process_threads;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;
use crate::util::FxHashMap;

pub struct SuspendedThreads;

/// `value or renderers.NotAvailableValue()`.
fn or_na(s: Option<String>) -> Value {
    match s {
        Some(s) if !s.is_empty() => Value::Str(s),
        _ => Value::NotAvailable,
    }
}

impl Plugin for SuspendedThreads {
    fn name(&self) -> &'static str {
        "windows.suspended_threads.SuspendedThreads"
    }
    fn description(&self) -> &'static str {
        "Enumerates suspended threads."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Process", ColType::Str),
            Column::new("PID", ColType::Int),
            Column::new("TID", ColType::Int),
            Column::new("StartFile", ColType::Str),
            Column::new("StartSymbol", ColType::Str),
            Column::new("StartAddress", ColType::Hex),
            Column::new("Win32StartFile", ColType::Str),
            Column::new("Win32StartSymbol", ColType::Str),
            Column::new("Win32StartAddress", ColType::Hex),
        ])?;
        let k = ctx.windows_kernel()?;
        let mut vads_cache: FxHashMap<u64, Vec<Range>> = FxHashMap::default();
        let mut proc_modules: Option<CollectedModules> = None;
        let threads = list_process_threads(k);
        // python's per-thread try block; independent reads, done in parallel
        let pre = |thread: &crate::objects::Obj| -> Result<Option<(crate::objects::Obj, u64, String, u64, u64, u64)>> {
            let tcb = thread.m("Tcb")?;
            if tcb.m("SuspendCount")?.int()? == 0 {
                return Ok(None);
            }
            if tcb.m("State")?.int()? == 4 {
                return Ok(None);
            }
            let owner = thread.owning_process()?;
            let cid = thread.m("Cid")?;
            let pid = cid.m("UniqueProcess")?.u64()?;
            let name = array_to_string(&owner.m("ImageFileName")?, None)?;
            let tid = cid.m("UniqueThread")?.u64()?;
            let start = thread.m("StartAddress")?.u64()?;
            let win32 = thread.m("Win32StartAddress")?.u64()?;
            Ok(Some((owner, pid, name, tid, start, win32)))
        };
        let pres = crate::util::par::par_map(threads.len(), |i| threads[i].as_ref().ok().map(pre));
        for (thread, r) in threads.into_iter().zip(pres) {
            thread?;
            let r = r.unwrap_or(Ok(None));
            let (owner, pid, name, tid, start, win32) = match r {
                Ok(Some(v)) => v,
                Ok(None) => continue,
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            };
            if vads_for_process_cache(&mut vads_cache, &owner)?.is_none() {
                continue;
            }
            // python: `if not proc_modules` (an empty collection is rebuilt next time)
            if proc_modules.as_ref().is_none_or(|m| m.order.is_empty()) {
                proc_modules = Some(get_process_modules(k, &mut vads_cache)?);
            }
            let pm = proc_modules.as_ref().unwrap();
            let vads = &vads_cache[&owner.addr];
            let (start_file, start_sym) = path_and_symbol_for_address(ctx, pm, vads, start)?;
            let (win32_file, win32_sym) = path_and_symbol_for_address(ctx, pm, vads, win32)?;
            // the only false positive found in mass scanning of samples
            if start_file.as_deref().is_some_and(|f| f.ends_with("\\WorkFoldersShell.dll")) || win32_file.as_deref().is_some_and(|f| f.ends_with("\\WorkFoldersShell.dll")) {
                continue;
            }
            out.row(
                0,
                vec![
                    Value::Str(name),
                    Value::Int(pid as i128),
                    Value::Int(tid as i128),
                    or_na(start_file),
                    or_na(start_sym),
                    Value::Int(start as i128),
                    or_na(win32_file),
                    or_na(win32_sym),
                    Value::Int(win32 as i128),
                ],
            )?;
        }
        Ok(())
    }
}
