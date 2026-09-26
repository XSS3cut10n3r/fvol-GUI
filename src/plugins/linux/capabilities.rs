//! linux.capabilities.Capabilities (python `plugins/linux/capabilities.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::linux::pslist::{collect_tasks, pid_filter};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::prelude::*;

pub struct Capabilities;

/// python `Capabilities._decode_cap(cap)`: "" (no capability), "all" (the full set) or the
/// comma-separated capability names.
pub fn decode_cap(cap: &Obj) -> Result<String> {
    let v = cap.get_capabilities()?;
    if v == 0 {
        return Ok(String::new());
    }
    if v == cap.get_kernel_cap_full()? {
        return Ok("all".into());
    }
    Ok(cap.enumerate_capabilities()?.join(", "))
}

/// python `Capabilities.get_task_capabilities(task)` rendered as a row.
fn task_row(task: &Obj) -> Result<Vec<Value>> {
    let comm = array_to_string(&task.m("comm")?, None)?;
    let pid = task.m("pid")?.int()?;
    let tgid = task.m("tgid")?.int()?;
    let ppid = task.get_parent_pid()?;
    let euid = task.m("cred")?.deref()?.cred_value("euid")?;
    let cred = task.m("real_cred")?;
    let sets = [cred.m("cap_inheritable")?, cred.m("cap_permitted")?, cred.m("cap_effective")?, cred.m("cap_bset")?];
    let ambient = if cred.has_member("cap_ambient") { Some(cred.m("cap_ambient")?) } else { None };
    let mut row = vec![Value::Str(comm), Value::Int(pid), Value::Int(tgid), Value::Int(ppid), Value::Int(euid)];
    for s in &sets {
        row.push(Value::Str(decode_cap(s)?));
    }
    row.push(match ambient {
        Some(a) => Value::Str(decode_cap(&a)?),
        None => Value::NotAvailable,
    });
    Ok(row)
}

impl Plugin for Capabilities {
    fn name(&self) -> &'static str {
        "linux.capabilities.Capabilities"
    }
    fn description(&self) -> &'static str {
        "Lists process capabilities"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pids", "Filter on specific process IDs.", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.linux_kernel()?;
        // python `_check_capabilities_support` reads cap_last_cap (warning only)
        if k.has_symbol("cap_last_cap") {
            k.object_from_symbol("cap_last_cap")?.int()?;
        }
        out.begin(vec![
            Column::new("Name", ColType::Str),
            Column::new("Tid", ColType::Int),
            Column::new("Pid", ColType::Int),
            Column::new("PPid", ColType::Int),
            Column::new("EUID", ColType::Int),
            Column::new("cap_inheritable", ColType::Str),
            Column::new("cap_permitted", ColType::Str),
            Column::new("cap_effective", ColType::Str),
            Column::new("cap_bounding", ColType::Str),
            Column::new("cap_ambient", ColType::Str),
        ])?;
        let pids = cfg.get_ints("pids");
        let filter = pid_filter(&pids);
        let (tasks, tail) = collect_tasks(k, &filter, false);
        let rows = crate::util::par::par_map(tasks.len(), |i| task_row(&tasks[i]));
        for r in rows {
            out.row(0, r?)?;
        }
        match tail {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
