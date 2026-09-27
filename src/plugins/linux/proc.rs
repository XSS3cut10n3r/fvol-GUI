//! linux.proc.Maps (python `plugins/linux/proc.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::linux::pslist::{collect_tasks, pid_filter};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::prelude::*;

pub struct Maps;

/// python `Maps.MAXSIZE_DEFAULT` (1 GiB).
pub const MAXSIZE_DEFAULT: i128 = 1024 * 1024 * 1024;

/// python `Maps.list_vmas(task, filter_func)`: the task's valid VMAs accepted by `filter`
/// (true = keep). Empty for kernel threads / unreadable `mm`. A trailing `Err` = python raised.
pub fn list_vmas(task: &Obj, filter: &dyn Fn(&Obj) -> Result<bool>) -> Vec<Result<Obj>> {
    let mm = match task.m("mm") {
        Ok(m) => m,
        Err(e) => return vec![Err(e)],
    };
    match mm.u64() {
        Ok(0) => return Vec::new(),
        Ok(_) => {}
        Err(e) => return vec![Err(e)],
    }
    if !mm.is_readable() {
        return Vec::new();
    }
    let mm = match mm.deref() {
        Ok(m) => m,
        Err(e) => return vec![Err(e)],
    };
    let mut out = Vec::new();
    for v in mm.get_vma_iter() {
        match v.and_then(|vma| Ok((vma, filter(&vma)?))) {
            Ok((vma, true)) => out.push(Ok(vma)),
            Ok((_, false)) => {}
            Err(e) => {
                out.push(Err(e));
                break;
            }
        }
    }
    out
}

/// python `Maps.vma_dump(context, task, vm_start, vm_end, open_method, maxsize)`: write
/// `pid.<pid>.vma.<start>-<end>.dmp`; returns the output file name, `Ok(None)` where python
/// returns None, `Err` where python raises.
pub fn vma_dump(ctx: &Context, task: &Obj, vm_start: u64, vm_end: u64, maxsize: i128) -> Result<Option<String>> {
    let pid = task.m("pid")?.int()?;
    let proc_layer = match task.add_process_layer() {
        Ok(l) => l,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    let vm_size = vm_end as i128 - vm_start as i128;
    if vm_size < 0 || maxsize <= vm_size {
        return Ok(None);
    }
    // python: `context.layers[None]` raises KeyError when no process layer could be built
    let proc_layer = proc_layer.ok_or_else(|| crate::error::Error::msg("KeyError: None"))?;
    let file_name = format!("pid.{pid}.vma.{vm_start:#x}-{vm_end:#x}.dmp");
    let r = (|| -> Result<String> {
        let (f, name) = ctx.create_output_file(&file_name)?;
        // python's `read(off, 10 MiB, pad=True)` loop, zero pages as holes (most of a process's
        // mappings were never paged in)
        crate::cli::files::dump_padded_reads(&f, proc_layer, vm_start, vm_size as u128)?;
        Ok(name)
    })();
    // python: `except Exception: return None`
    Ok(r.ok())
}

/// One VMA row before the (sequential) dump step.
struct Row {
    task: Obj,
    vm_start: u64,
    vm_end: u64,
    values: Vec<Value>,
}

/// The rows of one task (python `_generator` body), `Err` at the end where python raised.
fn task_rows(task: &Obj, addresses: &[i128]) -> (Vec<Row>, Option<crate::error::Error>) {
    let mut rows = Vec::new();
    let r = (|| -> Result<()> {
        let mm = task.m("mm")?;
        if !(mm.u64()? != 0 && mm.is_readable()) {
            return Ok(());
        }
        let name = array_to_string(&task.m("comm")?, None)?;
        let pid = task.m("pid")?.int()?;
        let filter = |x: &Obj| -> Result<bool> {
            if addresses.is_empty() {
                return Ok(true);
            }
            let (s, e) = (x.m("vm_start")?.int()?, x.m("vm_end")?.int()?);
            Ok(addresses.iter().any(|a| s <= *a && *a <= e))
        };
        for vma in list_vmas(task, &filter) {
            let vma = vma?;
            let flags = vma.get_protection()?;
            let page_offset = vma.get_page_offset()?;
            let mut inode_num: i128 = 0;
            let (major, minor) = match (|| -> Result<(i128, i128)> {
                let dentry = vma.m("vm_file")?.get_dentry()?;
                let inode_ptr = dentry.m("d_inode")?;
                inode_num = inode_ptr.m("i_ino")?.int()?;
                let sb = inode_ptr.m("i_sb")?;
                Ok((sb.major()?, sb.minor()?))
            })() {
                Ok(v) => v,
                Err(e) if e.is_invalid_address() => (0, 0),
                Err(e) => return Err(e),
            };
            let path = vma.vma_get_name(task)?;
            let vm_start = vma.m("vm_start")?.u64()?;
            let vm_end = vma.m("vm_end")?.u64()?;
            rows.push(Row {
                task: *task,
                vm_start,
                vm_end,
                values: vec![
                    Value::Int(pid),
                    Value::Str(name.clone()),
                    Value::Int(vm_start as i128),
                    Value::Int(vm_end as i128),
                    Value::Str(flags),
                    Value::Int(page_offset as i128),
                    Value::Int(major),
                    Value::Int(minor),
                    Value::Int(inode_num),
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

impl Plugin for Maps {
    fn name(&self) -> &'static str {
        "linux.proc.Maps"
    }
    fn description(&self) -> &'static str {
        "Lists all memory maps for all processes."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional(),
            Requirement::flag("dump", "Extract listed memory segments"),
            Requirement::new(
                "address",
                "Process virtual memory addresses to include (all other VMA sections are excluded). This can be any virtual address within the VMA section.",
                ReqKind::ListInt,
            )
            .optional(),
            Requirement::new("maxsize", "Maximum size for dumped VMA sections (all the bigger sections will be ignored)", ReqKind::Int)
                .default(ConfigValue::Int(MAXSIZE_DEFAULT))
                .optional(),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Start", ColType::Hex),
            Column::new("End", ColType::Hex),
            Column::new("Flags", ColType::Str),
            Column::new("PgOff", ColType::Hex),
            Column::new("Major", ColType::Int),
            Column::new("Minor", ColType::Int),
            Column::new("Inode", ColType::Int),
            Column::new("File Path", ColType::Str),
            Column::new("File output", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        let pids = cfg.get_ints("pid");
        let addresses = cfg.get_ints("address");
        let dump = cfg.get_bool("dump");
        let maxsize = cfg.get_int("maxsize").unwrap_or(MAXSIZE_DEFAULT);
        let filter = pid_filter(&pids);
        let (tasks, tail) = collect_tasks(k, &filter, false);
        if !dump {
            // per task in parallel, rows formatted on the workers, emitted in python's order
            return crate::plugins::emit_par_blocks(out, super::task_items(tasks, tail), |t, b| {
                let (rows, err) = task_rows(t, &addresses);
                for row in rows {
                    b.push(row.values);
                }
                err.map_or(Ok(()), Err)
            });
        }
        // --dump: python dumps each row's region before the next row (in order, stopping at
        // its first failure)
        let per_task = crate::util::par::par_map(tasks.len(), |i| task_rows(&tasks[i], &addresses));
        for (rows, err) in per_task {
            for mut row in rows {
                if dump {
                    // python: `if vm_start and vm_end:` then dump
                    let fo = if row.vm_start != 0 && row.vm_end != 0 { vma_dump(ctx, &row.task, row.vm_start, row.vm_end, maxsize)? } else { None };
                    row.values[10] = Value::Str(fo.unwrap_or_else(|| "Error outputting file".into()));
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
