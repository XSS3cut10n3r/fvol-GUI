//! mac.netstat.Netstat (python `plugins/mac/netstat.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Like mac.lsof, python dies with `ValueError` on images with an out-of-range `fo_type`
//! (raised inside `files_descriptors_for_process`); mirrored with a panic after the rows python
//! printed.

use crate::automagic::mac::MacKernel;
use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::mac::pslist::{PSLIST_METHODS, list_tasks, pid_filter};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::files::{fileproc_fg_type, files_descriptors_for_process, raise_python};
use crate::symbols::mac::net::{socket_get_converted_connection_info, socket_get_family, socket_get_protocol_as_string, socket_get_state};
use crate::util::par::par_map;

pub struct Netstat;

/// python `Netstat.list_sockets` for one task: `(task_name, pid, socket)` items; a trailing
/// `Err` means python raised there.
pub fn task_sockets(task: &Obj) -> Vec<Result<(String, i128, Obj)>> {
    let mut out = Vec::new();
    let head = (|| -> Result<(String, i128)> { Ok((array_to_string(&task.m("p_comm")?, None)?, task.m("p_pid")?.int()?)) })();
    let (task_name, pid) = match head {
        Ok(h) => h,
        Err(e) => return vec![Err(e)],
    };
    let native = task.native();
    for fd in files_descriptors_for_process(task) {
        let filp = match fd {
            Ok(fd) => fd.fileproc,
            Err(e) => {
                out.push(Err(e));
                return out;
            }
        };
        match fileproc_fg_type(&filp) {
            Ok(Some(t)) if t == "SOCKET" => {}
            Ok(_) => continue,
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => {
                out.push(Err(e));
                return out;
            }
        }
        let socket = match filp.m("f_fglob").and_then(|g| g.m("fg_data")).and_then(|d| d.deref()).and_then(|s| s.cast("socket")) {
            Ok(s) => s,
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => {
                out.push(Err(e));
                return out;
            }
        };
        if !native.is_valid(socket.addr, socket.size()) {
            continue;
        }
        out.push(Ok((task_name.clone(), pid, socket)));
    }
    out
}

/// python `Netstat.list_sockets(context, kernel_module_name, filter_func)` (the "tasks"
/// pslist method), items in python order.
pub fn list_sockets(k: &MacKernel, filter: crate::plugins::mac::pslist::Filter) -> Vec<Result<(String, i128, Obj)>> {
    let mut out = Vec::new();
    for t in list_tasks(k, PSLIST_METHODS[0], filter) {
        match t {
            Ok(task) => {
                let items = task_sockets(&task);
                let stop = matches!(items.last(), Some(Err(_)));
                out.extend(items);
                if stop {
                    return out;
                }
            }
            Err(e) => {
                out.push(Err(e));
                return out;
            }
        }
    }
    out
}

/// The `_generator` row for one socket, `None` when python skips it.
fn socket_row(task_name: &str, pid: i128, socket: &Obj) -> Result<Option<Vec<Value>>> {
    let family = socket_get_family(socket)?;
    let process = format!("{task_name}/{pid}");
    if family == 1 {
        let path = match socket.m("so_pcb").and_then(|p| p.deref()).and_then(|o| o.cast("unpcb")).and_then(|u| u.m("unp_addr")?.m("sun_path")).and_then(|p| array_to_string(&p, None)) {
            Ok(p) => p,
            Err(e) if e.is_invalid_address() => return Ok(None),
            Err(e) => return Err(e),
        };
        return Ok(Some(vec![
            Value::Int(socket.addr as i128),
            Value::SStr("UNIX"),
            Value::Str(path),
            Value::Int(0),
            Value::SStr(""),
            Value::Int(0),
            Value::SStr(""),
            Value::Str(process),
        ]));
    }
    if family == 2 || family == 30 {
        let state = socket_get_state(socket)?;
        let proto = socket_get_protocol_as_string(socket)?;
        if let Some((lip, lport, rip, rport)) = socket_get_converted_connection_info(socket)? {
            return Ok(Some(vec![
                Value::Int(socket.addr as i128),
                Value::SStr(proto),
                Value::Str(lip),
                Value::Int(lport),
                Value::Str(rip),
                Value::Int(rport),
                Value::SStr(state),
                Value::Str(process),
            ]));
        }
    }
    Ok(None)
}

impl Plugin for Netstat {
    fn name(&self) -> &'static str {
        "mac.netstat.Netstat"
    }
    fn description(&self) -> &'static str {
        "Lists all network connections for all processes."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("Proto", ColType::Str),
            Column::new("Local IP", ColType::Str),
            Column::new("Local Port", ColType::Int),
            Column::new("Remote IP", ColType::Str),
            Column::new("Remote Port", ColType::Int),
            Column::new("State", ColType::Str),
            Column::new("Process", ColType::Str),
        ])?;
        let pids = cfg.get_ints("pid");
        let filter = pid_filter(&pids);
        let tasks = list_tasks(k, PSLIST_METHODS[0], &filter);
        // each task's rows (and the error python would raise there), computed in parallel
        let per_task: Vec<Vec<Result<Vec<Value>>>> = par_map(tasks.len(), |i| {
            let Ok(task) = &tasks[i] else { return Vec::new() };
            let mut rows = Vec::new();
            for item in task_sockets(task) {
                match item.and_then(|(name, pid, sock)| socket_row(&name, pid, &sock)) {
                    Ok(Some(r)) => rows.push(Ok(r)),
                    Ok(None) => {}
                    Err(e) => {
                        rows.push(Err(e));
                        break;
                    }
                }
            }
            rows
        });
        for (t, rows) in tasks.into_iter().zip(per_task) {
            t?;
            for r in rows {
                out.row(0, r.map_err(raise_python)?)?;
            }
        }
        Ok(())
    }
}
