//! windows.joblinks.JobLinks (python `plugins/windows/joblinks.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;

pub struct JobLinks;

fn offset_of(k: &WinKernel, o: &Obj, physical: bool) -> Result<u64> {
    if !physical {
        return Ok(o.addr);
    }
    match k.layer.translate_addr(o.addr) {
        Some((pa, _)) => Ok(pa),
        None => Err(Error::invalid(o.addr)),
    }
}

/// Rows (depth, values) of one process; a trailing Err = python raised (a non address error).
fn proc_rows(k: &WinKernel, proc: &Obj, physical: bool) -> Vec<Result<(usize, Vec<Value>)>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let offset = offset_of(k, proc, physical)?;
        let job = proc.m("Job")?.deref()?;
        out.push(Ok((
            0,
            vec![
                Value::Int(offset as i128),
                Value::Str(array_to_string(&proc.m("ImageFileName")?, None)?),
                Value::Int(proc.m("UniqueProcessId")?.int()?),
                Value::Int(proc.m("InheritedFromUniqueProcessId")?.int()?),
                proc.get_session_id()?,
                Value::Int(job.m("SessionId")?.int()?),
                Value::Bool(proc.get_is_wow64()?),
                Value::Int(job.m("TotalProcesses")?.int()?),
                Value::Int(job.m("ActiveProcesses")?.int()?),
                Value::Int(job.m("TotalTerminatedProcesses")?.int()?),
                Value::NotApplicable,
                Value::SStr("(Original Process)"),
            ],
        )));
        for entry in job.m("ProcessListHead")?.to_list("_EPROCESS", "JobLinks", true, true, None) {
            let entry = entry?;
            let offset = offset_of(k, &entry, physical)?;
            out.push(Ok((
                1,
                vec![
                    Value::Int(offset as i128),
                    Value::Str(array_to_string(&entry.m("ImageFileName")?, None)?),
                    Value::Int(entry.m("UniqueProcessId")?.int()?),
                    Value::Int(entry.m("InheritedFromUniqueProcessId")?.int()?),
                    entry.get_session_id()?,
                    Value::Int(0),
                    Value::Bool(entry.get_is_wow64()?),
                    Value::Int(0),
                    Value::Int(0),
                    Value::Int(0),
                    Value::SStr("Yes"),
                    Value::Str(entry.get_peb()?.m("ProcessParameters")?.m("ImagePathName")?.get_string()?),
                ],
            )));
        }
        Ok(())
    })();
    match r {
        Ok(()) => {}
        Err(e) if e.is_invalid_address() => {}
        Err(e) => out.push(Err(e)),
    }
    out
}

impl Plugin for JobLinks {
    fn name(&self) -> &'static str {
        "windows.joblinks.JobLinks"
    }
    fn description(&self) -> &'static str {
        "Print process job link information"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::flag("physical", "Display physical offset instead of virtual")]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let physical = cfg.get_bool("physical");
        out.begin(vec![
            Column::new(if physical { "Offset(P)" } else { "Offset(V)" }, ColType::Hex),
            Column::new("Name", ColType::Str),
            Column::new("PID", ColType::Int),
            Column::new("PPID", ColType::Int),
            Column::new("Sess", ColType::Int),
            Column::new("JobSess", ColType::Int),
            Column::new("Wow64", ColType::Bool),
            Column::new("Total", ColType::Int),
            Column::new("Active", ColType::Int),
            Column::new("Term", ColType::Int),
            Column::new("JobLink", ColType::Str),
            Column::new("Process", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let procs = super::pslist::list_processes(k, &|_| Ok(false));
        let per_proc = crate::util::par::par_map(procs.len(), |i| match &procs[i] {
            Ok(p) => proc_rows(k, p, physical),
            Err(_) => Vec::new(),
        });
        for (p, rows) in procs.into_iter().zip(per_proc) {
            p?;
            for r in rows {
                let (d, v) = r?;
                out.row(d, v)?;
            }
        }
        Ok(())
    }
}
