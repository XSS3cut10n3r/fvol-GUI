//! linux.elfs.Elfs (python `plugins/linux/elfs.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! `Elfs.elf_dump` lives in [`crate::symbols::linux::elf::elf_dump`].

use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::util::array_to_string;
use crate::objects::{LayerRef, Obj};
use crate::plugins::linux::pslist::{collect_tasks, pid_filter};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::elf;
use crate::symbols::linux::prelude::*;

pub struct Elfs;

/// One output row before the (sequential) `--dump` step.
struct Row {
    task: Obj,
    vma: Obj,
    layer: LayerRef,
    values: Vec<Value>,
}

/// The rows of one task (python `_generator` loop body); the `Err` is where python raised.
fn task_rows(task: &Obj) -> (Vec<Row>, Option<Error>) {
    let mut rows = Vec::new();
    let r = (|| -> Result<()> {
        let Some(layer) = task.add_process_layer()? else { return Ok(()) };
        let name = array_to_string(&task.m("comm")?, None)?;
        for vma in task.m("mm")?.deref()?.get_vma_iter() {
            let vma = vma?;
            let vm_start = vma.m("vm_start")?.u64()?;
            let mut hdr = [0u8; 4];
            layer.read_padded(vm_start, &mut hdr);
            if &hdr != b"\x7fELF" {
                continue;
            }
            let path = vma.vma_get_name(task)?;
            let pid = task.m("pid")?.int()?;
            let vm_end = vma.m("vm_end")?.u64()?;
            rows.push(Row {
                task: *task,
                vma,
                layer,
                values: vec![
                    Value::Int(pid),
                    Value::Str(name.clone()),
                    Value::Int(vm_start as i128),
                    Value::Int(vm_end as i128),
                    match path {
                        Some(p) if !p.is_empty() => Value::Str(p),
                        _ => Value::NotAvailable,
                    },
                    Value::SStr("Disabled"),
                ],
            });
        }
        Ok(())
    })();
    (rows, r.err())
}

impl Plugin for Elfs {
    fn name(&self) -> &'static str {
        "linux.elfs.Elfs"
    }
    fn description(&self) -> &'static str {
        "Lists all memory mapped ELF files for all processes."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional(),
            Requirement::flag("dump", "Extract listed processes"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Start", ColType::Hex),
            Column::new("End", ColType::Hex),
            Column::new("File Path", ColType::Str),
            Column::new("File Output", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        let pids = cfg.get_ints("pid");
        let dump = cfg.get_bool("dump");
        let filter = pid_filter(&pids);
        let (tasks, tail) = collect_tasks(k, &filter, false);
        let elf_table = elf::elf_table(ctx)?;
        let per_task = crate::util::par::par_map(tasks.len(), |i| task_rows(&tasks[i]));
        for (rows, err) in per_task {
            for mut row in rows {
                if dump {
                    row.values[5] = match elf::elf_dump_ex(ctx, row.layer, elf_table, &row.vma, &row.task)? {
                        Some((_, final_name)) => Value::Str(final_name),
                        None => Value::SStr("Error outputting file"),
                    };
                }
                out.row(0, row.values)?;
            }
            if let Some(e) = err {
                return Err(e);
            }
        }
        match tail {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
