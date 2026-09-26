//! linux.library_list.LibraryList (python `plugins/linux/library_list.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::linux::pslist::{collect_tasks, pid_filter};
use crate::plugins::linux::pyexc::raise_if_python;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::linux::elf::{Elf, LinkMap};
use crate::symbols::linux::prelude::*;
use crate::util::FxHashSet;

pub struct LibraryList;

/// python `LibraryList._get_libdl_libraries(proc_layer_name, vma_start)` for one VMA: the
/// ELF's link maps with non-zero `l_addr` and `l_name`, handed to `f` (with `l_addr`). An
/// invalid address while walking (python's `except InvalidAddressException: pass`) ends this
/// VMA's list; errors of `f` (python's consumers, outside that `try`) are returned.
fn libdl_libraries(elf: &Elf, kernel_table: TableRef, f: &mut dyn FnMut(LinkMap, u64) -> Result<()>) -> Result<()> {
    let mut consumer_err = None;
    let r = elf.get_link_maps(kernel_table, &mut |lm| {
        let l_addr = lm.l_addr()?;
        if l_addr != 0 && lm.l_name()? != 0 {
            if let Err(e) = f(lm, l_addr) {
                consumer_err = Some(e);
                return Ok(false);
            }
        }
        Ok(true)
    });
    if let Some(e) = consumer_err {
        return Err(e);
    }
    match r {
        Err(e) if e.is_invalid_address() => Ok(()),
        r => r,
    }
}

/// python `_get_tasks_libraries` for one task: `(task name, tgid, l_addr, name)` values;
/// the `Err` is where python raised.
fn task_rows(task: &Obj, elf_table: TableRef, kernel_table: TableRef) -> (Vec<Vec<Value>>, Option<Error>) {
    let mut rows = Vec::new();
    let r = (|| -> Result<()> {
        let task_name = array_to_string(&task.m("comm")?, None)?;
        let Some(layer) = task.add_process_layer()? else { return Ok(()) };
        // python `_get_libdl_maps`: first link map per l_addr across the task's VMAs
        let mut seen: FxHashSet<u64> = FxHashSet::default();
        for vma in task.m("mm")?.deref()?.get_vma_iter() {
            let vm_start = vma?.m("vm_start")?.u64()?;
            let Some(elf) = Elf::new(layer, elf_table, vm_start)? else { continue };
            libdl_libraries(&elf, kernel_table, &mut |lm, l_addr| {
                if seen.contains(&l_addr) {
                    return Ok(());
                }
                // python `_get_task_libraries`: skip unreadable / empty names
                if let Some(name) = lm.get_name()?
                    && !name.is_empty()
                {
                    let tgid = task.m("tgid")?.int()?;
                    rows.push(vec![Value::Str(task_name.clone()), Value::Int(tgid), Value::Int(l_addr as i128), Value::Str(name)]);
                }
                seen.insert(l_addr);
                Ok(())
            })?;
        }
        Ok(())
    })();
    (rows, r.err())
}

impl Plugin for LibraryList {
    fn name(&self) -> &'static str {
        "linux.library_list.LibraryList"
    }
    fn description(&self) -> &'static str {
        "Enumerate libraries loaded into processes"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pids", "Filter on specific process IDs", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Name", ColType::Str),
            Column::new("Pid", ColType::Int),
            Column::new("LoadAddress", ColType::Hex),
            Column::new("Path", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        let pids = cfg.get_ints("pids");
        let filter = pid_filter(&pids);
        let (tasks, tail) = collect_tasks(k, &filter, false);
        let elf_table = crate::symbols::linux::elf::elf_table(ctx)?;
        let per_task = crate::util::par::par_map(tasks.len(), |i| task_rows(&tasks[i], elf_table, k.table));
        for (rows, err) in per_task {
            for row in rows {
                out.row(0, row)?;
            }
            if let Some(e) = err {
                return Err(raise_if_python(e));
            }
        }
        match tail {
            Some(e) => Err(raise_if_python(e)),
            None => Ok(()),
        }
    }
}
