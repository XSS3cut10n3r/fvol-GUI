//! linux.pscallstack.PsCallStack (python `plugins/linux/pscallstack.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::util::array_to_string;
use crate::objects::{Field, LayerRef, Obj};
use crate::plugins::linux::pslist::{list_tasks, pid_filter};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::LinuxExt;
use crate::symbols::linux::kallsyms::{Kallsyms, KasSymbol};

pub struct PsCallStack;

/// python `StackEntry` (name / type / module are None when unresolved).
#[derive(Clone, Debug)]
pub struct StackEntry {
    pub position: u64,
    pub address: u64,
    pub value: u64,
    pub symbol: Option<KasSymbol>,
}

/// Pre-resolved `task_struct` members used per task.
pub struct CallStackFields {
    stack: Field,
    files: Field,
    thread_sp: Field,
    pid: Field,
}

impl CallStackFields {
    /// Resolve the members once per kernel.
    pub fn new(k: &LinuxKernel) -> Result<CallStackFields> {
        Ok(CallStackFields {
            stack: Field::new(k.table, "task_struct", "stack")?,
            files: Field::new(k.table, "task_struct", "files")?,
            thread_sp: Field::path(k.table, "task_struct", "thread.sp")?,
            pid: Field::new(k.table, "task_struct", "pid")?,
        })
    }
}

/// python `PsCallStack.get_task_callstack(context, kernel, task, kas, include_unresolved)`:
/// the stack entries of `task` from `thread.sp` to the top of its kernel stack. `entries`
/// receives the rows python would have yielded before returning `Err` (python raised there).
pub fn get_task_callstack(k: &LinuxKernel, f: &CallStackFields, task: &Obj, kas: &Kallsyms, include_unresolved: bool, entries: &mut Vec<StackEntry>) -> Result<()> {
    let Some(task_layer) = task.get_address_space_layer()? else { return Ok(()) };
    let pointer_size = k.table.size_of(k.get_type("pointer")?);
    let thread_size = k.layer.page_size() << 2;
    let base = k.layer.canonicalize(task.f(&f.stack).u64()?);
    let top = base.wrapping_add(thread_size);
    task.f(&f.files).u64()?;
    let rsp = task.f(&f.thread_sp).u64()?;
    if !(base <= rsp && rsp < top) {
        let pid = task.f(&f.pid).int()?;
        return Err(Error::msg(format!("Invalid stack pointer {rsp:#x} for task {pid}")));
    }
    walk_stack(task_layer, k.vlayer.address_mask(), rsp, top, pointer_size, kas, include_unresolved, entries)
}

#[allow(clippy::too_many_arguments)]
fn walk_stack(layer: LayerRef, mask: u64, rsp: u64, top: u64, pointer_size: u64, kas: &Kallsyms, include_unresolved: bool, entries: &mut Vec<StackEntry>) -> Result<()> {
    // read the whole stack range once, then walk it (python reads slot by slot and stops at
    // the first unreadable slot)
    if pointer_size == 0 || pointer_size > 8 {
        return Err(Error::msg("unsupported pointer size"));
    }
    let len = ((top - rsp).div_ceil(pointer_size) * pointer_size) as usize;
    let mut buf = vec![0u8; len];
    let readable = match layer.read(rsp & mask, &mut buf) {
        Ok(()) => len,
        Err(_) => {
            // exact prefix: slot by slot
            let mut n = 0usize;
            let mut sp = rsp;
            while sp < top {
                if layer.read(sp & mask, &mut buf[n..n + pointer_size as usize]).is_err() {
                    break;
                }
                n += pointer_size as usize;
                sp += pointer_size;
            }
            n
        }
    };
    let mut idx = 0u64;
    let mut off = 0usize;
    while off + pointer_size as usize <= readable {
        let mut b = [0u8; 8];
        b[..pointer_size as usize].copy_from_slice(&buf[off..off + pointer_size as usize]);
        let v = u64::from_le_bytes(b);
        let sp = rsp + off as u64;
        if v != 0 {
            let sym = kas.lookup_address(v)?;
            if sym.is_some() || include_unresolved {
                entries.push(StackEntry { position: idx, address: sp & mask, value: v & mask, symbol: sym });
            }
        }
        idx += 1;
        off += pointer_size as usize;
    }
    Ok(())
}

fn row(pid: i128, comm: &str, e: StackEntry) -> Result<Vec<Value>> {
    let (name, ty, module) = match e.symbol {
        Some(s) => {
            let ty = match s.type_ {
                Some(t) => Value::Str(t),
                // python's TreeGrid rejects None in a str column
                None => return Err(Error::msg("TypeError: Values item with index 6 is the wrong type for column Type")),
            };
            let module = match s.module_name {
                Some(m) if !m.is_empty() => Value::Str(m),
                _ => Value::NotAvailable,
            };
            (Value::Str(s.name), ty, module)
        }
        None => (Value::NotAvailable, Value::NotAvailable, Value::NotAvailable),
    };
    Ok(vec![Value::Int(pid), Value::Str(comm.to_string()), Value::Int(e.position as i128), Value::Int(e.address as i128), Value::Int(e.value as i128), name, ty, module])
}

impl Plugin for PsCallStack {
    fn name(&self) -> &'static str {
        "linux.pscallstack.PsCallStack"
    }
    fn description(&self) -> &'static str {
        "Enumerates the call stack of each task"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional(),
            Requirement::flag("unresolved", "Include unresolved stack values"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("TID", ColType::Int),
            Column::new("Comm", ColType::Str),
            Column::new("Position", ColType::Int),
            Column::new("Address", ColType::Hex),
            Column::new("Value", ColType::Hex),
            Column::new("Name", ColType::Str),
            Column::new("Type", ColType::Str),
            Column::new("Module", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        let kas = Kallsyms::get(k)?;
        let include_unresolved = cfg.get_bool("unresolved");
        let pids = cfg.get_ints("pid");
        let filter = pid_filter(&pids);
        let mut tasks = Vec::new();
        let list_err = list_tasks(k, &filter, true, &mut |t| {
            tasks.push(t);
            Ok(true)
        })
        .err();
        let f = CallStackFields::new(k)?;
        // per task: (pid, comm, rows, error) computed on all cores, emitted in python order
        struct TaskOut {
            comm: Result<String>,
            pid: Result<i128>,
            entries: Vec<StackEntry>,
            err: Option<Error>,
        }
        let results = crate::util::par::par_map(tasks.len(), |i| {
            let t = &tasks[i];
            let comm = t.m("comm").and_then(|c| array_to_string(&c, None));
            if comm.is_err() {
                return TaskOut { comm, pid: Ok(0), entries: Vec::new(), err: None };
            }
            let mut entries = Vec::new();
            let err = get_task_callstack(k, &f, t, kas, include_unresolved, &mut entries).err();
            let pid = if entries.is_empty() { Ok(0) } else { t.f(&f.pid).int() };
            TaskOut { comm, pid, entries, err }
        });
        for r in results {
            let comm = r.comm?;
            if !r.entries.is_empty() {
                let pid = r.pid?;
                for e in r.entries {
                    out.row(0, row(pid, &comm, e)?)?;
                }
            }
            if let Some(e) = r.err {
                return Err(e);
            }
        }
        match list_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
