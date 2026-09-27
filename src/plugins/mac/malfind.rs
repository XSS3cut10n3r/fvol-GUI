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
use crate::renderers::{ColType, Column, RowBlock, RowSink, Value};
use crate::symbols::mac::MacExt;
use crate::symbols::mac::vm::{MacVmExt, map_entries};

pub struct Malfind;

/// A task's rows (python `_list_injections` + the `_generator` tuple) pushed into `b` in
/// python order; `Err` is where python raised (after those rows).
fn task_rows(task: &Obj, kernel_table: &str, arch: &'static str, b: &mut RowBlock) -> Result<()> {
    let process_name = array_to_string(&task.m("p_comm")?, None)?;
    let Some(layer) = task.add_process_layer()? else { return Ok(()) };
    // python re-reads these per row: same memory, same values, and add_process_layer()
    // already read p_pid successfully
    let mut p_pid: Option<i128> = None;
    for e in map_entries(task) {
        let e = e?;
        // is_suspicious(): get_perms() (python calls it again for the row: same value)
        let perms = e.vma_perms()?;
        if perms == "rwx" || (perms == "r-x" && e.get_path(kernel_table)?.is_empty()) {
            continue;
        }
        // links.start (the data read), then p_pid, links.start, links.end: p_pid cannot
        // fail (see above), so reading start and end together is equivalent
        let (start, end) = e.vma_range()?;
        let data = layer.read_vec_padded(start, 64);
        let pid = match p_pid {
            Some(p) => p,
            None => *p_pid.insert(task.m("p_pid")?.int()?),
        };
        b.push_ref(&[
            Value::Int(pid),
            Value::Str(process_name.clone()),
            Value::Int(start as i128),
            Value::Int(end as i128),
            Value::SStr(perms),
            Value::Bytes(data.clone()),
            Value::Disassembly { data, offset: start, arch: Some(arch) },
        ]);
    }
    Ok(())
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
        // per task in parallel, rows formatted on the workers, emitted in python's order
        crate::plugins::emit_par_blocks(out, tasks, |t, b| task_rows(t, kernel_table, arch, b))
    }
}
