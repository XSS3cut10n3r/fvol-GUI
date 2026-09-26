//! linux.ptrace.Ptrace (python `plugins/linux/ptrace.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::linux::pslist::collect_tasks;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::LinuxExt;

pub struct Ptrace;

/// The rows (depth, values) of one task, empty when it neither traces nor is traced.
fn task_rows(task: &Obj) -> Result<Vec<(usize, Vec<Value>)>> {
    // python `enumerate_ptrace_tasks`: `is_being_ptraced or is_ptracing`
    if !(task.is_being_ptraced()? || task.is_ptracing()?) {
        return Ok(Vec::new());
    }
    let comm = array_to_string(&task.m("comm")?, None)?;
    let user_pid = task.m("tgid")?.int()?;
    let user_tid = task.m("pid")?.int()?;
    let tracer = match task.get_ptrace_tracer_tid()? {
        Some(t) if t != 0 => Value::Int(t),
        _ => Value::NotAvailable,
    };
    let tracees = task.get_ptrace_tracee_tids()?;
    let flags = match task.get_ptrace_tracee_flags()? {
        Some(f) if !f.is_empty() => Value::Str(f),
        _ => Value::NotAvailable,
    };
    let tracees: Vec<Value> = if tracees.is_empty() { vec![Value::NotAvailable] } else { tracees.into_iter().map(Value::Int).collect() };
    Ok(tracees
        .into_iter()
        .enumerate()
        .map(|(level, tracee)| (level, vec![Value::Str(comm.clone()), Value::Int(user_pid), Value::Int(user_tid), tracer.clone(), tracee, flags.clone()]))
        .collect())
}

impl Plugin for Ptrace {
    fn name(&self) -> &'static str {
        "linux.ptrace.Ptrace"
    }
    fn description(&self) -> &'static str {
        "Enumerates ptrace's tracer and tracee tasks"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Process", ColType::Str),
            Column::new("PID", ColType::Int),
            Column::new("TID", ColType::Int),
            Column::new("Tracer TID", ColType::Int),
            Column::new("Tracee TID", ColType::Int),
            Column::new("Flags", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        let (tasks, tail) = collect_tasks(k, &|_| Ok(false), true);
        let rows = crate::util::par::par_map(tasks.len(), |i| task_rows(&tasks[i]));
        for r in rows {
            for (depth, row) in r? {
                out.row(depth, row)?;
            }
        }
        match tail {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
