//! windows.cmdline.CmdLine (python `plugins/windows/cmdline.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::util::array_to_string;
use crate::objects::{Obj, Space};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;

pub struct CmdLine;

/// python `CmdLine.get_cmdline(context, kernel_table_name, proc)`: the PEB's
/// `ProcessParameters.CommandLine` string.
pub fn get_cmdline(proc: &Obj) -> Result<String> {
    let pl = proc.add_process_layer()?;
    let peb = Obj::named(Space::on(pl, proc.table()), "_PEB", proc.m("Peb")?.u64()?)?;
    peb.m("ProcessParameters")?.m("CommandLine")?.get_string()
}

impl Plugin for CmdLine {
    fn name(&self) -> &'static str {
        "windows.cmdline.CmdLine"
    }
    fn description(&self) -> &'static str {
        "Lists process command line arguments."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Process IDs to include (all other processes are excluded)", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Args", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let pids = cfg.get_ints("pid");
        let filter = super::pslist::pid_filter(&pids);
        let procs = super::pslist::list_processes(k, &filter);
        let row = |proc: &Obj| -> Result<Vec<Value>> {
            let name = array_to_string(&proc.m("ImageFileName")?, None)?;
            let args = match proc.m("UniqueProcessId").and_then(|p| p.int()).and_then(|_| get_cmdline(proc)) {
                Ok(s) if !s.is_empty() => Value::Str(s),
                Ok(_) => Value::Unreadable,
                Err(e) if e.is_invalid_address() => Value::Unreadable,
                Err(e) => return Err(e),
            };
            Ok(vec![Value::Int(proc.m("UniqueProcessId")?.int()?), Value::Str(name), args])
        };
        // independent per-process reads: compute in parallel, emit in python order
        let rows = crate::util::par::par_map(procs.len(), |i| procs[i].as_ref().ok().map(row));
        for (p, r) in procs.into_iter().zip(rows) {
            p?;
            out.row(0, r.expect("row computed for every listed process")?)?;
        }
        Ok(())
    }
}
