//! mac.pslist.PsList (python `plugins/mac/pslist.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! The `list_tasks*` functions are python's classmethods, for other mac plugins:
//! ```ignore
//! let k = ctx.mac_kernel()?;
//! for p in list_tasks(k, "tasks", &|_| Ok(false)) { let proc = p?; ... }
//! ```
//! Like python, some methods yield `proc *` POINTER objects (allproc's first element,
//! sessions, process_group, pid_hash_table): member access dereferences, and `addr` (python
//! `vol.offset`) is where the pointer lives -- which is what python prints.

use crate::automagic::mac::MacKernel;
use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::{MAX_ELEMENTS, MacExt, fromtimestamp_local};
use crate::util::FxHashSet;

pub struct PsList;

/// python `PsList.pslist_methods`.
pub const PSLIST_METHODS: [&str; 5] = ["tasks", "allproc", "process_group", "sessions", "pid_hash_table"];

/// A task filter: returns true for processes to SKIP (python `filter_func`).
pub type Filter<'a> = &'a dyn Fn(&Obj) -> Result<bool>;

/// python `PsList.create_pid_filter(pid_list)`: skip processes whose `p_pid` is not listed.
pub fn pid_filter(pids: &[i128]) -> impl Fn(&Obj) -> Result<bool> + '_ {
    move |p: &Obj| {
        if pids.is_empty() {
            return Ok(false);
        }
        let pid = p.m("p_pid")?.int()?;
        Ok(!pids.contains(&pid))
    }
}

/// python `PsList.get_list_tasks(method)(context, kernel, filter_func)`; unknown methods fall
/// back to "tasks" like python. A trailing `Err` means python would have raised there.
pub fn list_tasks(k: &MacKernel, method: &str, filter: Filter) -> Vec<Result<Obj>> {
    match method {
        "allproc" => list_tasks_allproc(k, filter),
        "process_group" => list_tasks_process_group(k, filter),
        "sessions" => list_tasks_sessions(k, filter),
        "pid_hash_table" => list_tasks_pid_hash_table(k, filter),
        _ => list_tasks_tasks(k, filter),
    }
}

/// Run `body`, turning an early `Err` into a trailing `Err` item.
fn collect(body: impl FnOnce(&mut Vec<Result<Obj>>) -> Result<()>) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    if let Err(e) = body(&mut out) {
        out.push(Err(e));
    }
    out
}

/// python `PsList.list_tasks_allproc`.
pub fn list_tasks_allproc(k: &MacKernel, filter: Filter) -> Vec<Result<Obj>> {
    collect(|out| {
        let layer = k.vlayer;
        // `.lh_first` constructs (reads) the pointer
        let mut proc = k.object_from_symbol("allproc")?.m("lh_first")?;
        proc.u64()?;
        let mut seen = FxHashSet::default();
        while proc.addr != 0 {
            if !seen.insert(proc.addr) {
                // "Recursive process list detected (a result of non-atomic acquisition)."
                break;
            }
            if layer.is_valid(proc.addr, proc.size()) && !filter(&proc)? {
                out.push(Ok(proc));
            }
            match proc.m("p_list").and_then(|l| l.m("le_next")).and_then(|p| p.deref()) {
                Ok(p) => proc = p,
                Err(e) if e.is_invalid_address() => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    })
}

/// python `PsList.list_tasks_tasks` (the default).
pub fn list_tasks_tasks(k: &MacKernel, filter: Filter) -> Vec<Result<Obj>> {
    collect(|out| {
        let layer = k.vlayer;
        let queue_entry = k.object_from_symbol("tasks")?;
        let mut seen = FxHashSet::default();
        for task in queue_entry.walk_list(&queue_entry, "tasks", "task", MAX_ELEMENTS) {
            let task = task?;
            if !seen.insert(task.addr) {
                break;
            }
            let proc = match task.m("bsd_info").and_then(|p| p.deref()).and_then(|o| o.cast("proc")) {
                Ok(p) => p,
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            };
            if layer.is_valid(proc.addr, proc.size()) && !filter(&proc)? {
                out.push(Ok(proc));
            }
        }
        Ok(())
    })
}

/// `kernel.object("array", offset=<table pointer value>, count=<hash mask> + 1,
/// subtype=<head type>)`. NOTE: python's `Module.object` adds the module offset (KASLR shift)
/// to the already absolute pointer value; mirrored for identical output.
fn hash_table(k: &MacKernel, size_sym: &str, table_sym: &str, head_type: &str) -> Result<Obj> {
    let table_size = k.object_from_symbol(size_sym)?.int()?;
    let tbl = k.object_from_symbol(table_sym)?.u64()?;
    let elem = k.get_type(head_type)?;
    let count = (table_size + 1).clamp(0, u32::MAX as i128) as u64;
    Ok(k.object_abs(head_type, tbl.wrapping_add(k.offset))?.cast_array(count, elem))
}

/// python `PsList.list_tasks_sessions` (yields `s_leader` pointers).
pub fn list_tasks_sessions(k: &MacKernel, filter: Filter) -> Vec<Result<Obj>> {
    collect(|out| {
        let arr = hash_table(k, "sesshash", "sesshashtbl", "sesshashhead")?;
        for i in 0..arr.count() {
            let head = arr.at(i)?;
            for proc in head.walk_list_head("s_hash", MAX_ELEMENTS) {
                let proc = proc?;
                let leader = proc.m("s_leader")?;
                leader.u64()?;
                if leader.is_readable() && !filter(&leader)? {
                    out.push(Ok(leader));
                }
            }
        }
        Ok(())
    })
}

/// python `PsList.list_tasks_process_group` (yields `proc` pointers).
pub fn list_tasks_process_group(k: &MacKernel, filter: Filter) -> Vec<Result<Obj>> {
    collect(|out| {
        let arr = hash_table(k, "pgrphash", "pgrphashtbl", "pgrphashhead")?;
        for i in 0..arr.count() {
            let head = arr.at(i)?;
            for pgrp in head.walk_list_head("pg_hash", MAX_ELEMENTS) {
                let pgrp = pgrp?;
                for proc in pgrp.m("pg_members")?.walk_list_head("p_pglist", MAX_ELEMENTS) {
                    let proc = proc?;
                    if !filter(&proc)? {
                        out.push(Ok(proc));
                    }
                }
            }
        }
        Ok(())
    })
}

/// python `PsList.list_tasks_pid_hash_table` (yields `proc` pointers).
pub fn list_tasks_pid_hash_table(k: &MacKernel, filter: Filter) -> Vec<Result<Obj>> {
    collect(|out| {
        let arr = hash_table(k, "pidhash", "pidhashtbl", "pidhashhead")?;
        for i in 0..arr.count() {
            let head = arr.at(i)?;
            for proc in head.walk_list_head("p_hash", MAX_ELEMENTS) {
                let proc = proc?;
                if !filter(&proc)? {
                    out.push(Ok(proc));
                }
            }
        }
        Ok(())
    })
}

/// One python `_generator` row for `task` (a proc or a `proc *`).
fn row(task: &Obj) -> Result<Vec<Value>> {
    let name = array_to_string(&task.m("p_comm")?, None)?;
    let pid = task.m("p_pid")?.int()?;
    let uid = task.m("p_uid")?.int()?;
    let gid = task.m("p_gid")?.int()?;
    let start = task.m("p_start")?;
    let secs = start.m("tv_sec")?.int()?;
    let usecs = start.m("tv_usec")?.int()?;
    // datetime.datetime.fromtimestamp(sec + usec / 1e6): naive local time. Garbage times make
    // python raise ValueError (not a volatility exception): the plugin dies with a traceback
    // and no "\n\n" block -- the fastvol CLI's equivalent of that is a plugin panic.
    let start_time = match fromtimestamp_local(secs as f64 + usecs as f64 / 1e6) {
        Ok(t) => t,
        Err(py_exception) => panic!("{py_exception}"),
    };
    let ppid = task.m("p_ppid")?.int()?;
    Ok(vec![
        Value::Int(task.addr as i128),
        Value::Str(name),
        Value::Int(pid),
        Value::Int(uid),
        Value::Int(gid),
        Value::DateTime(start_time),
        Value::Int(ppid),
    ])
}

impl Plugin for PsList {
    fn name(&self) -> &'static str {
        "mac.pslist.PsList"
    }
    fn description(&self) -> &'static str {
        "Lists the processes present in a particular mac memory image."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pslist_method", "Method to determine for processes", ReqKind::Choice(PSLIST_METHODS.to_vec()))
                .optional()
                .default(ConfigValue::Str(PSLIST_METHODS[0].into())),
            Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional(),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![
            Column::new("OFFSET", ColType::Hex),
            Column::new("NAME", ColType::Str),
            Column::new("PID", ColType::Int),
            Column::new("UID", ColType::Int),
            Column::new("GID", ColType::Int),
            Column::new("Start Time", ColType::DateTime),
            Column::new("PPID", ColType::Int),
        ])?;
        let method = cfg.get_str("pslist_method").unwrap_or(PSLIST_METHODS[0]);
        let pids = cfg.get_ints("pid");
        let filter = pid_filter(&pids);
        for task in list_tasks(k, method, &filter) {
            out.row(0, row(&task?)?)?;
        }
        Ok(())
    }
}
