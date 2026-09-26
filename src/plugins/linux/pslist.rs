//! linux.pslist.PsList (python `plugins/linux/pslist.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, Plugin, ReqKind, Requirement, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, DateTime, RowSink, Value};
use crate::symbols::linux::LinuxExt;
use crate::util::FxHashSet;

pub struct PsList;

/// python `PsList.create_pid_filter(pid_list)`: true = skip the task (filters on `task.pid`).
pub fn pid_filter(pids: &[i128]) -> impl Fn(&Obj) -> Result<bool> + '_ {
    move |t: &Obj| {
        if pids.is_empty() {
            return Ok(false);
        }
        Ok(!pids.contains(&t.m("pid")?.int()?))
    }
}

/// python `PsList.list_tasks(context, kernel, filter_func, include_threads)`: walk
/// `init_task.tasks` forward then backward (deduplicated), valid tasks only (the init_task
/// itself is not yielded). Streams tasks to `f` (return false to stop); `Err` = python raised.
pub fn list_tasks(k: &LinuxKernel, filter: &dyn Fn(&Obj) -> Result<bool>, include_threads: bool, f: &mut dyn FnMut(Obj) -> Result<bool>) -> Result<()> {
    let init_task = k.object_from_symbol("init_task")?;
    let sym = init_task.full_type_name();
    let tasks = init_task.m("tasks")?;
    let mut seen = FxHashSet::default();
    for forward in [true, false] {
        for t in tasks.to_list(&sym, "tasks", forward, true, None) {
            let t = t?;
            if !seen.insert(t.addr) {
                continue;
            }
            if !t.is_valid() {
                continue;
            }
            if filter(&t)? {
                continue;
            }
            if !f(t)? {
                return Ok(());
            }
            if include_threads {
                for th in t.get_threads() {
                    if !f(th?)? {
                        return Ok(());
                    }
                }
            }
        }
    }
    Ok(())
}

/// python `TaskFields`.
pub struct TaskFields {
    pub offset: u64,
    pub user_pid: i128,
    pub user_tid: i128,
    pub user_ppid: i128,
    pub name: String,
    /// (uid, gid, euid, egid) when the cred is readable
    pub creds: Option<[i128; 4]>,
    pub creation_time: Option<DateTime>,
}

/// python `PsList.get_task_fields(task, decorate_comm)`.
pub fn get_task_fields(task: &Obj, decorate_comm: bool) -> Result<TaskFields> {
    let mut name = array_to_string(&task.m("comm")?, None)?;
    if decorate_comm {
        if task.is_kernel_thread()? {
            name = format!("[{name}]");
        } else if task.is_user_thread()? {
            name = format!("{{{name}}}");
        }
    }
    let cred = task.m("cred")?;
    let valid_cred = cred.u64()? != 0 && cred.is_readable();
    let creation_time = task.get_create_time().ok();
    let user_pid = task.m("tgid")?.int()?;
    let user_tid = task.m("pid")?.int()?;
    let user_ppid = task.get_parent_pid()?;
    let creds = if valid_cred {
        let c = cred.deref()?;
        Some([c.cred_value("uid")?, c.cred_value("gid")?, c.cred_value("euid")?, c.cred_value("egid")?])
    } else {
        None
    };
    Ok(TaskFields { offset: task.addr, user_pid, user_tid, user_ppid, name, creds, creation_time })
}

fn run_rows(ctx: &Context, cfg: &Config, out: &mut dyn FnMut(Vec<Value>) -> Result<()>) -> Result<()> {
    let k = ctx.linux_kernel()?;
    let pids = cfg.get_ints("pid");
    let filter = pid_filter(&pids);
    let threads = cfg.get_bool("threads");
    let decorate = cfg.get_bool("decorate_comm");
    let dump = cfg.get_bool("dump");
    list_tasks(k, &filter, threads, &mut |t| {
        let file_output = if dump { dump_elf(ctx, k, &t) } else { Value::SStr("Disabled") };
        let tf = get_task_fields(&t, decorate)?;
        let cred = |i: usize| tf.creds.map_or(Value::NotAvailable, |c| Value::Int(c[i]));
        out(vec![
            Value::Int(tf.offset as i128),
            Value::Int(tf.user_pid),
            Value::Int(tf.user_tid),
            Value::Int(tf.user_ppid),
            Value::Str(tf.name),
            cred(0),
            cred(1),
            cred(2),
            cred(3),
            tf.creation_time.map_or(Value::NotAvailable, Value::DateTime),
            file_output,
        ])?;
        Ok(true)
    })
}

/// python `PsList._get_file_output(task)` (`--dump`). Dumping the main ELF of a process needs
/// the VMA walk (maple tree / mmap list) and the ELF reconstruction of `linux.elfs`, which are
/// not ported yet: report python's "VMA start matching task start_code not found" text only
/// where it is certain, else the error text.
fn dump_elf(_ctx: &Context, _k: &LinuxKernel, task: &Obj) -> Value {
    match task.add_process_layer() {
        Ok(None) => Value::NotApplicable,
        _ => Value::SStr("Error outputting file"),
    }
}

impl Plugin for PsList {
    fn name(&self) -> &'static str {
        "linux.pslist.PsList"
    }
    fn description(&self) -> &'static str {
        "Lists the processes present in a particular linux memory image."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional(),
            Requirement::flag("threads", "Include user threads"),
            Requirement::flag("decorate_comm", "Show `user threads` comm in curly brackets, and `kernel threads` comm in square brackets"),
            Requirement::flag("dump", "Extract listed processes"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("OFFSET (V)", ColType::Hex),
            Column::new("PID", ColType::Int),
            Column::new("TID", ColType::Int),
            Column::new("PPID", ColType::Int),
            Column::new("COMM", ColType::Str),
            Column::new("UID", ColType::Int),
            Column::new("GID", ColType::Int),
            Column::new("EUID", ColType::Int),
            Column::new("EGID", ColType::Int),
            Column::new("CREATION TIME", ColType::DateTime),
            Column::new("File output", ColType::Str),
        ])?;
        run_rows(ctx, cfg, &mut |r| out.row(0, r))
    }
    fn timeline(&self, ctx: &Context, cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        let mut ev = Vec::new();
        let r = (|| -> Result<()> {
            let k = ctx.linux_kernel()?;
            let pids = cfg.get_ints("pid");
            let filter = pid_filter(&pids);
            list_tasks(k, &filter, true, &mut |t| {
                let tf = get_task_fields(&t, false)?;
                let description = format!("Process {}/{} {} ({})", tf.user_pid, tf.user_tid, tf.name, tf.offset);
                ev.push(TimelineEvent { description, kind: TimeKind::Created, time: tf.creation_time.map_or(Value::NotAvailable, Value::DateTime) });
                Ok(true)
            })
        })();
        Some(r.map(|_| ev))
    }
}
