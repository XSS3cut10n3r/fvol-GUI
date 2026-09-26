//! linux.lsof.Lsof (python `plugins/linux/lsof.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! * [`list_fds`] is python's `Lsof.list_fds` (tasks incl. threads x their open files).
//! * [`fd_user`] is python's `FDInternal.to_user()` (the rendered row fields).

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::linux::pslist::{collect_tasks, pid_filter};
use crate::plugins::{Config, Plugin, ReqKind, Requirement, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::prelude::*;
use crate::symbols::linux::utilities::{FdEntry, files_descriptors_for_process};

pub struct Lsof;

/// python `FDUser` (the fields of one output row).
pub struct FdUser {
    pub task_tgid: i128,
    pub task_tid: i128,
    pub task_comm: String,
    pub fd_num: u64,
    pub full_path: String,
    pub device: Value,
    pub inode_num: Value,
    pub inode_type: Value,
    pub file_mode: Value,
    pub change_time: Value,
    pub modification_time: Value,
    pub access_time: Value,
    pub inode_size: Value,
}

impl FdUser {
    /// python `dataclasses.astuple(fd_user)`.
    pub fn into_row(self) -> Vec<Value> {
        vec![
            Value::Int(self.task_tgid),
            Value::Int(self.task_tid),
            Value::Str(self.task_comm),
            Value::Int(self.fd_num as i128),
            Value::Str(self.full_path),
            self.device,
            self.inode_num,
            self.inode_type,
            self.file_mode,
            self.change_time,
            self.modification_time,
            self.access_time,
            self.inode_size,
        ]
    }
}

/// python `FDInternal(task, fd_fields).to_user()`. `Err` where python raises.
pub fn fd_user(task: &Obj, fd: &FdEntry) -> Result<FdUser> {
    let task_tgid = task.m("tgid")?.int()?;
    let task_tid = task.m("pid")?.int()?;
    let task_comm = array_to_string(&task.m("comm")?, None)?;
    let (fd_num, filp, full_path) = fd;
    let mut u = FdUser {
        task_tgid,
        task_tid,
        task_comm,
        fd_num: *fd_num,
        full_path: full_path.clone(),
        device: Value::NotAvailable,
        inode_num: Value::NotAvailable,
        inode_type: Value::NotAvailable,
        file_mode: Value::NotAvailable,
        change_time: Value::NotAvailable,
        modification_time: Value::NotAvailable,
        access_time: Value::NotAvailable,
        inode_size: Value::NotAvailable,
    };
    let Some(inode) = filp.get_inode()? else { return Ok(u) };
    let sb = inode.m("i_sb")?;
    u.device = if sb.u64()? != 0 && sb.is_readable() { Value::Str(format!("{}:{}", sb.major()?, sb.minor()?)) } else { Value::NotAvailable };
    u.inode_num = Value::Int(inode.m("i_ino")?.int()?);
    u.inode_type = inode.get_inode_type()?.map_or(Value::Unparsable, Value::SStr);
    u.file_mode = Value::Str(inode.get_file_mode()?);
    u.change_time = inode.get_change_time()?;
    u.modification_time = inode.get_modification_time()?;
    u.access_time = inode.get_access_time()?;
    u.inode_size = Value::Int(inode.m("i_size")?.int()?);
    Ok(u)
}

/// python `Lsof.list_fds(context, kernel, filter_func, include_files_only)` fused with
/// `to_user()`, computed per task in parallel: calls `f` with each row in python's order.
/// Stops at python's first exception (returned as `Err` after the rows before it).
pub fn for_each_fd_user(k: &LinuxKernel, filter: &dyn Fn(&Obj) -> Result<bool>, files_only: bool, f: &mut dyn FnMut(FdUser) -> Result<()>) -> Result<()> {
    let (tasks, tail) = collect_tasks(k, filter, true);
    let per_task = crate::util::par::par_map(tasks.len(), |i| -> Vec<Result<FdUser>> {
        let task = &tasks[i];
        let mut out = Vec::new();
        for e in files_descriptors_for_process(task, files_only) {
            match e.and_then(|fd| fd_user(task, &fd)) {
                Ok(u) => out.push(Ok(u)),
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            }
        }
        out
    });
    for rows in per_task {
        for r in rows {
            f(r?)?;
        }
    }
    tail.map_or(Ok(()), Err)
}

/// python `Lsof.list_fds`: `(task, (fd, filp, path))` for every open file of every task
/// (threads included), in python's order. A trailing `Err` = python raised there.
pub fn list_fds(k: &LinuxKernel, filter: &dyn Fn(&Obj) -> Result<bool>, files_only: bool) -> Vec<Result<(Obj, FdEntry)>> {
    let (tasks, tail) = collect_tasks(k, filter, true);
    let per_task = crate::util::par::par_map(tasks.len(), |i| files_descriptors_for_process(&tasks[i], files_only));
    let mut out = Vec::new();
    for (task, fds) in tasks.iter().zip(per_task) {
        for e in fds {
            match e {
                Ok(fd) => out.push(Ok((*task, fd))),
                Err(e) => {
                    out.push(Err(e));
                    return out;
                }
            }
        }
    }
    if let Some(e) = tail {
        out.push(Err(e));
    }
    out
}

fn columns() -> Vec<Column> {
    vec![
        Column::new("PID", ColType::Int),
        Column::new("TID", ColType::Int),
        Column::new("Process", ColType::Str),
        Column::new("FD", ColType::Int),
        Column::new("Path", ColType::Str),
        Column::new("Device", ColType::Str),
        Column::new("Inode", ColType::Int),
        Column::new("Type", ColType::Str),
        Column::new("Mode", ColType::Str),
        Column::new("Changed", ColType::DateTime),
        Column::new("Modified", ColType::DateTime),
        Column::new("Accessed", ColType::DateTime),
        Column::new("Size", ColType::Int),
    ]
}

impl Plugin for Lsof {
    fn name(&self) -> &'static str {
        "linux.lsof.Lsof"
    }
    fn description(&self) -> &'static str {
        "Lists open files for each processes."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional(),
            Requirement::flag("files_only", "Include only file descriptors of type file"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(columns())?;
        let k = ctx.linux_kernel()?;
        let pids = cfg.get_ints("pid");
        let filter = pid_filter(&pids);
        for_each_fd_user(k, &filter, cfg.get_bool("files_only"), &mut |u| out.row(0, u.into_row()))
    }
    fn timeline_events(&self, ctx: &Context, cfg: &Config) -> Option<(Vec<TimelineEvent>, Option<Error>)> {
        let mut ev = Vec::new();
        let r = (|| -> Result<()> {
            let k = ctx.linux_kernel()?;
            let pids = cfg.get_ints("pid");
            let filter = pid_filter(&pids);
            for_each_fd_user(k, &filter, false, &mut |u| {
                let description = format!("Process {} ({}/{}) Open '{}'", u.task_comm, u.task_tgid, u.task_tid, u.full_path);
                ev.push(TimelineEvent { description: description.clone(), kind: TimeKind::Changed, time: u.change_time });
                ev.push(TimelineEvent { description: description.clone(), kind: TimeKind::Modified, time: u.modification_time });
                ev.push(TimelineEvent { description, kind: TimeKind::Accessed, time: u.access_time });
                Ok(())
            })
        })();
        Some((ev, r.err()))
    }
}
