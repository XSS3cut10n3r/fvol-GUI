//! linux.psaux.PsAux (python `plugins/linux/psaux.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::strings::decode_utf8;
use crate::objects::util::array_to_string;
use crate::plugins::linux::pslist::{collect_tasks, pid_filter};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::LinuxExt;
use crate::symbols::table::StrErrors;

pub struct PsAux;

/// python `PsAux._get_command_line_args(task, name)`: the NUL-separated argv joined with
/// spaces, `[comm]` for tasks without an mm, `Value::Unreadable` when it cannot be read.
pub fn get_command_line_args(task: &Obj, name: &str) -> Result<Value> {
    let mm = match task.m("mm").and_then(|m| m.u64()) {
        Ok(v) => v,
        Err(e) if e.is_invalid_address() => 0,
        Err(e) => return Err(e),
    };
    let mut args = if mm != 0 {
        let Some(proc_layer) = task.add_process_layer()? else { return Ok(Value::Unreadable) };
        let mm = task.m("mm")?;
        let start = mm.m("arg_start")?.u64()?;
        let size = mm.m("arg_end")?.int()? - mm.m("arg_start")?.int()?;
        if !(0 < size && size <= 4096) {
            return Ok(Value::Unreadable);
        }
        let mut buf = vec![0u8; size as usize];
        if proc_layer.read(start, &mut buf).is_err() {
            return Ok(Value::Unreadable);
        }
        // decode, split on NUL, join with spaces == replace NUL by space
        decode_utf8(&buf, StrErrors::Replace)?.replace('\0', " ")
    } else {
        format!("[{name}]")
    };
    if args.ends_with(' ') && args.chars().count() > 1 {
        args.pop();
    }
    Ok(Value::Str(args))
}

fn task_row(task: &Obj) -> Result<Vec<Value>> {
    let pid = task.m("pid")?.int()?;
    let ppid = task.get_parent_pid()?;
    let name = array_to_string(&task.m("comm")?, None)?;
    let args = get_command_line_args(task, &name)?;
    Ok(vec![Value::Int(pid), Value::Int(ppid), Value::Str(name), args])
}

impl Plugin for PsAux {
    fn name(&self) -> &'static str {
        "linux.psaux.PsAux"
    }
    fn description(&self) -> &'static str {
        "Lists processes with their command line arguments"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("PPID", ColType::Int),
            Column::new("COMM", ColType::Str),
            Column::new("ARGS", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        let pids = cfg.get_ints("pid");
        let filter = pid_filter(&pids);
        let (tasks, tail) = collect_tasks(k, &filter, false);
        // per task in parallel, rows formatted on the workers, emitted in python's order
        crate::plugins::emit_par_blocks(out, super::task_items(tasks, tail), |t, b| {
            b.push(task_row(t)?);
            Ok(())
        })
    }
}
