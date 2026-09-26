//! windows.vadwalk.VadWalk (python `plugins/windows/vadwalk.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::prelude::*;

pub struct VadWalk;

/// Rows of one process (a trailing Err = python raised there).
fn proc_rows(proc: &Obj) -> Vec<Result<Vec<Value>>> {
    let mut rows = Vec::new();
    let r = (|| -> Result<()> {
        let mut fixed: Option<(i128, String)> = None;
        for v in super::vadinfo::list_vads(proc, &|_| Ok(false)) {
            let vad = v?;
            if fixed.is_none() {
                fixed = Some((proc.m("UniqueProcessId")?.int()?, array_to_string(&proc.m("ImageFileName")?, None)?));
            }
            let (pid, name) = fixed.as_ref().unwrap();
            let mask = vad.layer().address_mask() as i128;
            rows.push(Ok(vec![
                Value::Int(*pid),
                Value::Str(name.clone()),
                Value::Int(vad.addr as i128),
                Value::Int(vad.get_parent()? & mask),
                Value::Int(vad.get_left_child()?.int()?),
                Value::Int(vad.get_right_child()?.int()?),
                Value::Int(vad.get_start()? as i128),
                Value::Int(vad.get_end()? as i128),
                match vad.get_tag() {
                    Some(t) => Value::Str(t),
                    None => Value::SStr("None"),
                },
            ]));
        }
        Ok(())
    })();
    if let Err(e) = r {
        rows.push(Err(e));
    }
    rows
}

impl Plugin for VadWalk {
    fn name(&self) -> &'static str {
        "windows.vadwalk.VadWalk"
    }
    fn description(&self) -> &'static str {
        "Walk the VAD tree."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Process IDs to include (all other processes are excluded)", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Offset", ColType::Hex),
            Column::new("Parent", ColType::Hex),
            Column::new("Left", ColType::Hex),
            Column::new("Right", ColType::Hex),
            Column::new("Start", ColType::Hex),
            Column::new("End", ColType::Hex),
            Column::new("Tag", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let pids = cfg.get_ints("pid");
        let filter = super::pslist::pid_filter(&pids);
        let procs = super::pslist::list_processes(k, &filter);
        let per_proc = crate::util::par::par_map(procs.len(), |i| match &procs[i] {
            Ok(p) => proc_rows(p),
            Err(_) => Vec::new(),
        });
        for (p, rows) in procs.into_iter().zip(per_proc) {
            p?;
            for r in rows {
                out.row(0, r?)?;
            }
        }
        Ok(())
    }
}
