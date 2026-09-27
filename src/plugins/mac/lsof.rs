//! mac.lsof.Lsof (python `plugins/mac/lsof.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! On images where a file's `fo_type` is outside the enumeration, python dies with
//! `ValueError` in the middle of the output; the rows before it are printed and the process
//! exits with status 1. The same happens here (the error is raised as a panic, see
//! `symbols::mac::files::raise_python`).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::mac::pslist::{PSLIST_METHODS, list_tasks, pid_filter};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::files::{files_descriptors_for_process, raise_python};

pub struct Lsof;

impl Plugin for Lsof {
    fn name(&self) -> &'static str {
        "mac.lsof.Lsof"
    }
    fn description(&self) -> &'static str {
        "Lists all open file descriptors for all processes."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![Column::new("PID", ColType::Int), Column::new("File Descriptor", ColType::Int), Column::new("File Path", ColType::Str)])?;
        let pids = cfg.get_ints("pid");
        let filter = pid_filter(&pids);
        let tasks = list_tasks(k, cfg.get_str("pslist_method").unwrap_or(PSLIST_METHODS[0]), &filter);
        // per task in parallel, rows formatted on the workers, emitted in python's order; a
        // python builtin exception (`raise_python` crashes like python) is raised here, on the
        // output thread, after the rows before it
        let (tasks, mut task_errs): (Vec<Option<crate::objects::Obj>>, Vec<Option<crate::error::Error>>) = tasks
            .into_iter()
            .map(|t| match t {
                Ok(t) => (Some(t), None),
                Err(e) => (None, Some(e)),
            })
            .unzip();
        let enc = out.encoder();
        crate::plugins::stream_blocks(
            enc.as_ref(),
            tasks.len(),
            |i, b| -> Option<(crate::error::Error, bool)> {
                let task = tasks[i].as_ref()?;
                let pid = match task.m("p_pid").and_then(|p| p.int()) {
                    Ok(p) => p,
                    Err(e) => return Some((e, false)),
                };
                for e in files_descriptors_for_process(task) {
                    match e {
                        Ok(e) if e.path.is_empty() => {}
                        Ok(e) => b.push_ref(&[Value::Int(pid), Value::Int(e.fd as i128), Value::Str(e.path)]),
                        Err(e) => return Some((e, true)),
                    }
                }
                None
            },
            |i, b, err| {
                if let Some(e) = task_errs[i].take() {
                    return Err(e);
                }
                b.emit(out)?;
                match err.flatten() {
                    Some((e, true)) => Err(raise_python(e)),
                    Some((e, false)) => Err(e),
                    None => Ok(true),
                }
            },
        )
    }
}
