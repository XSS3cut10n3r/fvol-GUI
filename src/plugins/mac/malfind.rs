//! mac.malfind.Malfind (python `plugins/mac/malfind.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! NOTE python's quirk, reproduced: `_list_injections` yields the map entries that are NOT
//! suspicious (`if not vma.is_suspicious(...)`).

use crate::context::Context;
use crate::layers::LayerExt;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::MacExt;
use crate::symbols::mac::vm::MacVmExt;

pub struct Malfind;

/// A task's rows (python `_list_injections` + the `_generator` tuple) in python order; a
/// trailing `Err` is where python raised.
fn task_rows(task: &Obj, kernel_table: &str, arch: &'static str) -> Vec<Result<Vec<Value>>> {
    let mut rows = Vec::new();
    let r = (|| -> Result<()> {
        let process_name = array_to_string(&task.m("p_comm")?, None)?;
        let Some(layer) = task.add_process_layer()? else { return Ok(()) };
        for vma in task.get_map_iter() {
            let e = vma?.deref()?;
            if e.is_suspicious(kernel_table)? {
                continue;
            }
            let links = e.m("links")?;
            let start = links.m("start")?.u64()?;
            let data = layer.read_vec_padded(start, 64);
            // the tuple: p_pid, links.start, links.end, get_perms() are read in this order
            let pid = task.m("p_pid")?.int()?;
            let end = links.m("end")?.u64()?;
            let perms = e.get_perms()?;
            rows.push(Ok(vec![
                Value::Int(pid),
                Value::Str(process_name.clone()),
                Value::Int(start as i128),
                Value::Int(end as i128),
                Value::Str(perms),
                Value::Bytes(data.clone()),
                Value::Disassembly { data, offset: start, arch: Some(arch) },
            ]));
        }
        Ok(())
    })();
    if let Err(e) = r {
        rows.push(Err(e));
    }
    rows
}

impl Plugin for Malfind {
    fn name(&self) -> &'static str {
        "mac.malfind.Malfind"
    }
    fn description(&self) -> &'static str {
        "Lists process memory ranges that potentially contain injected code."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Start", ColType::Hex),
            Column::new("End", ColType::Hex),
            Column::new("Protection", ColType::Str),
            Column::new("Hexdump", ColType::HexBytes),
            Column::new("Disasm", ColType::Disassembly),
        ])?;
        let pids = cfg.get_ints("pid");
        let filter = super::pslist::pid_filter(&pids);
        let tasks = super::pslist::list_tasks(k, "tasks", &filter);
        // python: `kernel.get_type("pointer").size == 4` -> 32-bit
        let arch = if k.size_of("pointer")? == 4 { "intel" } else { "intel64" };
        let kernel_table = k.table.name();
        let per_task = crate::util::par::par_map(tasks.len(), |i| match &tasks[i] {
            Ok(t) => task_rows(t, kernel_table, arch),
            Err(_) => Vec::new(),
        });
        for (task, rows) in tasks.into_iter().zip(per_task) {
            task?;
            for r in rows {
                out.row(0, r?)?;
            }
        }
        Ok(())
    }
}
