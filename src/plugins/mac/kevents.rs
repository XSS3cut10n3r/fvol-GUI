//! mac.kevents.Kevents (python `plugins/mac/kevents.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::mac::MacKernel;
use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::mac::pslist::{Filter, PSLIST_METHODS, list_tasks, pid_filter};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::{MAX_ELEMENTS, MacExt};
use crate::util::par::par_map;

pub struct Kevents;

/// python `Kevents.event_types`.
fn event_type(i: i128) -> Option<&'static str> {
    Some(match i {
        1 => "EVFILT_READ",
        2 => "EVFILT_WRITE",
        3 => "EVFILT_AIO",
        4 => "EVFILT_VNODE",
        5 => "EVFILT_PROC",
        6 => "EVFILT_SIGNAL",
        7 => "EVFILT_TIMER",
        8 => "EVFILT_MACHPORT",
        9 => "EVFILT_FS",
        10 => "EVFILT_USER",
        12 => "EVFILT_VM",
        _ => return None,
    })
}

const VNODE_FILTERS: &[(&str, i128)] =
    &[("NOTE_DELETE", 1), ("NOTE_WRITE", 2), ("NOTE_EXTEND", 4), ("NOTE_ATTRIB", 8), ("NOTE_LINK", 0x10), ("NOTE_RENAME", 0x20), ("NOTE_REVOKE", 0x40)];
const PROC_FILTERS: &[(&str, i128)] = &[
    ("NOTE_EXIT", 0x8000_0000),
    ("NOTE_EXITSTATUS", 0x0400_0000),
    ("NOTE_FORK", 0x4000_0000),
    ("NOTE_EXEC", 0x2000_0000),
    ("NOTE_SIGNAL", 0x0800_0000),
    ("NOTE_REAP", 0x1000_0000),
];
const TIMER_FILTERS: &[(&str, i128)] = &[("NOTE_SECONDS", 1), ("NOTE_USECONDS", 2), ("NOTE_NSECONDS", 4), ("NOTE_ABSOLUTE", 8)];

/// python `Kevents._parse_flags(filter_index, filter_flags)`.
fn parse_flags(filter_index: i128, flags: i128) -> String {
    let filters = match filter_index {
        4 => VNODE_FILTERS,
        5 => PROC_FILTERS,
        7 => TIMER_FILTERS,
        _ => return String::new(),
    };
    if flags == 0 {
        return String::new();
    }
    filters.iter().filter(|(_, v)| flags & v == *v).map(|(n, _)| *n).collect::<Vec<_>>().join(",")
}

/// python `Kevents._walk_klist_array(kernel, fdp, array_pointer_member, array_size_member)`.
/// NOTE: python's `kernel.object(..., offset=pointer)` (no `absolute=True`) adds the kernel
/// module offset (KASLR shift) to the pointer value; mirrored.
fn walk_klist_array(k: &MacKernel, fdp: &Obj, ptr_member: &str, size_member: &str, out: &mut Vec<Result<Obj>>) -> bool {
    let arr = (|| -> Result<(u64, i128)> {
        let p = fdp.m(ptr_member)?.u64()?;
        let size = fdp.m(size_member)?.int()?;
        Ok((p, size))
    })();
    let (ptr, size) = match arr {
        Ok(x) => x,
        Err(e) if e.is_invalid_address() => return true,
        Err(e) => {
            out.push(Err(e));
            return false;
        }
    };
    let head = match k.object("klist", ptr) {
        Ok(h) => h,
        Err(e) => {
            out.push(Err(e));
            return false;
        }
    };
    let esize = head.size();
    let count = (size + 1).clamp(0, u32::MAX as i128) as u64;
    for i in 0..count {
        let klist = head.at_addr(head.addr.wrapping_add(esize.wrapping_mul(i)));
        for kn in klist.walk_slist("kn_link", MAX_ELEMENTS) {
            let err = kn.is_err();
            out.push(kn);
            if err {
                return false;
            }
        }
    }
    true
}

/// python `Kevents._get_task_kevents(kernel, task)`: the `knote *` pointers of one task.
pub fn get_task_kevents(k: &MacKernel, task: &Obj) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    // fdp = task.p_fd (the pointer is read; errors propagate)
    let fdp = match task.m("p_fd").and_then(|p| p.u64().map(|_| p)) {
        Ok(p) => p,
        Err(e) => return vec![Err(e)],
    };
    if !walk_klist_array(k, &fdp, "fd_knlist", "fd_knlistsize", &mut out) {
        return out;
    }
    if !walk_klist_array(k, &fdp, "fd_knhash", "fd_knhashmask", &mut out) {
        return out;
    }
    match task.m("p_klist") {
        Ok(p_klist) => out.extend(p_klist.walk_slist("kn_link", MAX_ELEMENTS)),
        Err(e) if e.is_invalid_address() => {}
        Err(e) => out.push(Err(e)),
    }
    out
}

/// python `Kevents.list_kernel_events(context, kernel_module_name, filter_func)`:
/// `(task_name, pid, knote *)` in python order (trailing `Err` = python raised).
pub fn list_kernel_events(k: &MacKernel, filter: Filter) -> Vec<Result<(String, i128, Obj)>> {
    let tasks = list_tasks(k, PSLIST_METHODS[0], filter);
    let per_task = par_map(tasks.len(), |i| match &tasks[i] {
        Ok(t) => task_events(k, t),
        Err(_) => Vec::new(),
    });
    let mut out = Vec::new();
    for (t, items) in tasks.into_iter().zip(per_task) {
        if let Err(e) = t {
            out.push(Err(e));
            return out;
        }
        let stop = matches!(items.last(), Some(Err(_)));
        out.extend(items);
        if stop {
            return out;
        }
    }
    out
}

fn task_events(k: &MacKernel, task: &Obj) -> Vec<Result<(String, i128, Obj)>> {
    let head = (|| -> Result<(String, i128)> { Ok((array_to_string(&task.m("p_comm")?, None)?, task.m("p_pid")?.int()?)) })();
    let (name, pid) = match head {
        Ok(h) => h,
        Err(e) => return vec![Err(e)],
    };
    get_task_kevents(k, task).into_iter().map(|kn| kn.map(|kn| (name.clone(), pid, kn))).collect()
}

/// The `_generator` row for one knote (`None` = skipped).
fn knote_row(name: &str, pid: i128, kn: &Obj) -> Result<Option<Vec<Value>>> {
    let kevent = kn.m("kn_kevent")?;
    let filter_index = -kevent.m("filter")?.int()?;
    let Some(filter_name) = event_type(filter_index) else { return Ok(None) };
    let ident = match kevent.m("ident").and_then(|i| i.int()) {
        Ok(v) => v,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    let context = parse_flags(filter_index, kn.m("kn_sfflags")?.int()?);
    Ok(Some(vec![Value::Int(pid), Value::Str(name.to_string()), Value::Int(ident), Value::SStr(filter_name), Value::Str(context)]))
}

impl Plugin for Kevents {
    fn name(&self) -> &'static str {
        "mac.kevents.Kevents"
    }
    fn description(&self) -> &'static str {
        "Lists event handlers registered by processes"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Ident", ColType::Int),
            Column::new("Filter", ColType::Str),
            Column::new("Context", ColType::Str),
        ])?;
        let pids = cfg.get_ints("pid");
        let filter = pid_filter(&pids);
        for item in list_kernel_events(k, &filter) {
            let (name, pid, kn) = item?;
            if let Some(row) = knote_row(&name, pid, &kn)? {
                out.row(0, row)?;
            }
        }
        Ok(())
    }
}
