//! windows.privileges.Privs (python `plugins/windows/privileges.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::prelude::*;

pub struct Privs;

/// Rows of one process (a trailing Err = python raised there).
fn proc_rows(task: &Obj) -> Vec<Result<Vec<Value>>> {
    let token = match task.m("Token").and_then(|t| t.fast_ref_dereference()) {
        Ok(t) => t,
        Err(e) if e.is_invalid_address() => return Vec::new(),
        Err(e) => return vec![Err(e)],
    };
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let token = token.cast("_TOKEN")?;
        let info = &super::sids::data().privileges;
        let mut fixed: Option<(i128, String)> = None;
        for (value, present, enabled, default) in token.privileges()? {
            let Some((name, desc)) = info.get(&value) else { continue };
            if fixed.is_none() {
                fixed = Some((task.m("UniqueProcessId")?.int()?, array_to_string(&task.m("ImageFileName")?, None)?));
            }
            let (pid, pname) = fixed.as_ref().unwrap();
            let mut attrs = Vec::with_capacity(3);
            if present {
                attrs.push("Present");
            }
            if enabled {
                attrs.push("Enabled");
            }
            if default {
                attrs.push("Default");
            }
            out.push(Ok(vec![
                Value::Int(*pid),
                Value::Str(pname.clone()),
                Value::Int(value),
                Value::Str(name.clone()),
                Value::Str(attrs.join(",")),
                Value::Str(desc.clone()),
            ]));
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

impl Plugin for Privs {
    fn name(&self) -> &'static str {
        "windows.privileges.Privs"
    }
    fn description(&self) -> &'static str {
        "Lists process token privileges"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Value", ColType::Int),
            Column::new("Privilege", ColType::Str),
            Column::new("Attributes", ColType::Str),
            Column::new("Description", ColType::Str),
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
