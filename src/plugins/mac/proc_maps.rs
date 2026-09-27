//! mac.proc_maps.Maps (python `plugins/mac/proc_maps.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! [`list_vmas`] / [`vma_dump`] are python's `Maps.list_vmas` / `Maps.vma_dump` classmethods,
//! for other mac plugins.

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::MacExt;
use crate::symbols::mac::vm::{MacVmExt, map_entries};
use std::io::Write;

pub struct Maps;

/// python `Maps.MAXSIZE_DEFAULT` (1 GiB).
pub const MAXSIZE_DEFAULT: i128 = 1024 * 1024 * 1024;

/// python `Maps.list_vmas(task, filter_func)`: the task's map entries for which `keep` returns
/// true (python's filter_func returns True to KEEP). NOTE: yields the `vm_map_entry` structs
/// (python yields `vm_map_entry *` pointers; member access is the same). A trailing `Err`
/// means python raised there.
pub fn list_vmas(task: &Obj, keep: &dyn Fn(&Obj) -> Result<bool>) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    for vma in map_entries(task) {
        match vma.and_then(|v| keep(&v).map(|k| (v, k))) {
            Ok((v, true)) => out.push(Ok(v)),
            Ok((_, false)) => {}
            Err(e) => {
                out.push(Err(e));
                break;
            }
        }
    }
    out
}

/// python `Maps.vma_dump(context, task, vm_start, vm_end, open_method, maxsize)`: writes
/// `pid.<pid>.vma.<start:#x>-<end:#x>.dmp` (the range read from the process layer with
/// padding, in 10 MiB chunks) and returns the file name python prints, `Ok(None)` where python
/// returns None (negative size, `maxsize <= size`, unreadable DTB, file errors). `Err` = the
/// `task.p_pid` read raised (python does not catch that).
pub fn vma_dump(ctx: &Context, task: &Obj, vm_start: u64, vm_end: u64, maxsize: i128) -> Result<Option<String>> {
    let pid = task.m("p_pid")?.int()?;
    let layer = match task.add_process_layer() {
        Ok(l) => l,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    let vm_size = vm_end as i128 - vm_start as i128;
    if vm_size < 0 || maxsize <= vm_size {
        return Ok(None);
    }
    // python: `context.layers[None]` -> KeyError, a crash with traceback
    let Some(layer) = layer else { panic!("KeyError: None") };
    let file_name = format!("pid.{pid}.vma.{vm_start:#x}-{vm_end:#x}.dmp");
    let Ok((mut f, final_name)) = ctx.create_output_file(&file_name) else { return Ok(None) };
    const CHUNK: u64 = 1024 * 1024 * 10;
    let end = vm_start + vm_size as u64;
    let mut buf = vec![0u8; CHUNK.min(vm_size as u64) as usize];
    let mut offset = vm_start;
    while offset < end {
        let n = CHUNK.min(end - offset) as usize;
        layer.read_padded(offset, &mut buf[..n]);
        if f.write_all(&buf[..n]).is_err() {
            return Ok(None);
        }
        offset += n as u64;
    }
    Ok(Some(final_name))
}

/// One vma's row minus the dump column. `perms` is evaluated by python after the dump.
struct VmaRow {
    start: u64,
    end: u64,
    path: String,
    perms: Result<&'static str>,
}

/// A task's vma rows in python order; a trailing `Err` is where python raised (before that
/// vma's dump).
fn task_rows(task: &Obj, addresses: &[i128], kernel_table: &str) -> Vec<Result<VmaRow>> {
    let keep = |v: &Obj| -> Result<bool> {
        if addresses.is_empty() {
            return Ok(true);
        }
        // [addr for addr in address_list if vma.links.start <= addr <= vma.links.end]
        let links = v.m("links")?;
        let start = links.m("start")?.int()?;
        let mut end = None;
        for &a in addresses {
            if start <= a {
                let e = match end {
                    Some(e) => e,
                    None => *end.insert(links.m("end")?.int()?),
                };
                if a <= e {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    };
    let mut rows = Vec::new();
    for vma in list_vmas(task, &keep) {
        let r = (|| -> Result<VmaRow> {
            let e = vma?;
            let (start, end) = e.vma_range()?;
            let mut path = e.get_path(kernel_table)?;
            if path.is_empty() {
                path = e.vma_special_path()?.to_string();
            }
            Ok(VmaRow { start, end, path, perms: e.vma_perms() })
        })();
        let stop = r.is_err();
        rows.push(r);
        if stop {
            break;
        }
    }
    rows
}

impl Plugin for Maps {
    fn name(&self) -> &'static str {
        "mac.proc_maps.Maps"
    }
    fn description(&self) -> &'static str {
        "Lists process memory ranges that potentially contain injected code."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional(),
            Requirement::flag("dump", "Extract listed memory segments"),
            Requirement::new(
                "address",
                "Process virtual memory addresses to include (all other VMA sections are excluded). This can be any virtual address within the VMA section. Virtual addresses must be separated by a space.",
                ReqKind::ListInt,
            )
            .optional(),
            Requirement::new("maxsize", "Maximum size for dumped VMA sections (all the bigger sections will be ignored)", ReqKind::Int)
                .optional()
                .default(ConfigValue::Int(MAXSIZE_DEFAULT)),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Start", ColType::Hex),
            Column::new("End", ColType::Hex),
            Column::new("Protection", ColType::Str),
            Column::new("Map Name", ColType::Str),
            Column::new("File output", ColType::Str),
        ])?;
        let pids = cfg.get_ints("pid");
        let filter = super::pslist::pid_filter(&pids);
        let addresses = cfg.get_ints("address");
        let dump = cfg.get_bool("dump");
        let maxsize = cfg.get_int("maxsize").unwrap_or(MAXSIZE_DEFAULT);
        let kernel_table = k.table.name();
        let tasks = super::pslist::list_tasks(k, "tasks", &filter);
        if !dump {
            // per task in parallel, rows formatted on the workers, emitted in python's order
            return crate::plugins::emit_par_blocks(out, tasks, |task, b| {
                let name = array_to_string(&task.m("p_comm")?, None)?;
                let pid = task.m("p_pid")?.int()?;
                for r in task_rows(task, &addresses, kernel_table) {
                    let r = r?;
                    b.push_ref(&[
                        Value::Int(pid),
                        Value::Str(name.clone()),
                        Value::Int(r.start as i128),
                        Value::Int(r.end as i128),
                        Value::SStr(r.perms?),
                        Value::Str(r.path),
                        Value::SStr("Disabled"),
                    ]);
                }
                Ok(())
            });
        }
        // --dump: per task: (pid, name) then the vma rows; tasks are independent, computed in
        // parallel, emitted and dumped in python order (a dump before its row)
        let per_task = crate::util::par::par_map(tasks.len(), |i| {
            let Ok(task) = &tasks[i] else { return Err(crate::error::Error::msg("")) };
            // one small leak per task instead of a String per row
            let name: &'static str = Box::leak(array_to_string(&task.m("p_comm")?, None)?.into_boxed_str());
            let pid = task.m("p_pid")?.int()?;
            Ok((pid, name, task_rows(task, &addresses, kernel_table)))
        });
        for (task, rows) in tasks.into_iter().zip(per_task) {
            let task = task?;
            let (pid, name, rows) = rows?;
            for r in rows {
                let r = r?;
                let file_output = if dump {
                    match vma_dump(ctx, &task, r.start, r.end, maxsize)? {
                        Some(n) => Value::Str(n),
                        None => Value::SStr("Error outputting file"),
                    }
                } else {
                    Value::SStr("Disabled")
                };
                out.row(
                    0,
                    vec![
                        Value::Int(pid),
                        Value::SStr(name),
                        Value::Int(r.start as i128),
                        Value::Int(r.end as i128),
                        Value::SStr(r.perms?),
                        Value::Str(r.path),
                        file_output,
                    ],
                )?;
            }
        }
        Ok(())
    }
}
