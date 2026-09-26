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
use crate::util::par::par_map;

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
        // per-process work in parallel, emitted in python order
        let per_task = par_map(tasks.len(), |i| match &tasks[i] {
            Ok(task) => Some(task.m("p_pid").and_then(|p| p.int()).map(|pid| (pid, files_descriptors_for_process(task)))),
            Err(_) => None,
        });
        for (t, res) in tasks.into_iter().zip(per_task) {
            t?;
            let (pid, fds) = res.expect("computed for Ok tasks")?;
            for e in fds {
                let e = e.map_err(raise_python)?;
                if !e.path.is_empty() {
                    out.row(0, vec![Value::Int(pid), Value::Int(e.fd as i128), Value::Str(e.path)])?;
                }
            }
        }
        Ok(())
    }
}
