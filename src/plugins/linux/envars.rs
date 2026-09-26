//! linux.envars.Envars (python `plugins/linux/envars.py`).
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

pub struct Envars;

/// python `Envars.get_task_env_variables(context, task, env_area_max_size=8192)`: the task's
/// `(key, value)` environment pairs (empty when the area fails the sanity checks or is not
/// mapped). `Err` where python raises.
pub fn get_task_env_variables(task: &Obj, env_area_max_size: i128) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    array_to_string(&task.m("comm")?, None)?;
    task.m("pid")?.int()?;
    let mm = task.m("mm")?;
    let env_start = mm.m("env_start")?.int()?;
    let env_end = mm.m("env_end")?.int()?;
    let size = env_end - env_start;
    if !(0 < size && size <= env_area_max_size) {
        return Ok(out);
    }
    let Some(proc_layer) = task.add_process_layer()? else { return Ok(out) };
    let start = env_start as u64;
    if !proc_layer.is_valid(start, size as u64) {
        return Ok(out);
    }
    let mut data = vec![0u8; size as usize];
    proc_layer.read(start, &mut data)?;
    // envar_data.rstrip(b"\x00")
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
    for pair in data[..end].split(|&b| b == 0) {
        let s = decode_utf8(pair, StrErrors::Replace)?;
        match s.split_once('=') {
            Some((k, v)) => out.push((k.to_string(), v.to_string())),
            // python: ValueError on unpacking -> abort this task
            None => break,
        }
    }
    Ok(out)
}

fn task_rows(task: &Obj) -> Result<Vec<Vec<Value>>> {
    if task.is_kernel_thread()? {
        return Ok(Vec::new());
    }
    let pid = task.m("pid")?.int()?;
    let name = array_to_string(&task.m("comm")?, None)?;
    let ppid = task.get_parent_pid()?;
    Ok(get_task_env_variables(task, 8192)?
        .into_iter()
        .map(|(k, v)| vec![Value::Int(pid), Value::Int(ppid), Value::Str(name.clone()), Value::Str(k), Value::Str(v)])
        .collect())
}

impl Plugin for Envars {
    fn name(&self) -> &'static str {
        "linux.envars.Envars"
    }
    fn description(&self) -> &'static str {
        "Lists processes with their environment variables"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("PPID", ColType::Int),
            Column::new("COMM", ColType::Str),
            Column::new("KEY", ColType::Str),
            Column::new("VALUE", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        let pids = cfg.get_ints("pid");
        let filter = pid_filter(&pids);
        let (tasks, tail) = collect_tasks(k, &filter, false);
        let rows = crate::util::par::par_map(tasks.len(), |i| task_rows(&tasks[i]));
        for r in rows {
            for row in r? {
                out.row(0, row)?;
            }
        }
        match tail {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
