//! linux.pstree.PsTree (python `plugins/linux/pstree.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::plugins::linux::pslist::{collect_tasks, get_task_fields, pid_filter};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::LinuxExt;
use crate::util::{FxHashMap, FxHashSet};

pub struct PsTree;

/// python's PsTree state (`_tasks`, `_levels`, `_children`; dict insertion order kept).
struct Tree {
    order: Vec<i128>,
    tasks: FxHashMap<i128, Obj>,
    levels: FxHashMap<i128, i64>,
    children: FxHashMap<i128, Vec<i128>>,
}

impl Tree {
    /// python `find_level(pid)`.
    fn find_level(&mut self, pid: i128) -> Result<()> {
        let mut seen_ppids = FxHashSet::default();
        let mut seen_offsets = FxHashSet::default();
        let mut level = 0i64;
        let mut proc = self.tasks.get(&pid).copied();
        while let Some(p) = proc {
            let ppid_self = p.m("pid")?.int()?;
            if ppid_self == 0 {
                break;
            }
            let parent_pid = if p.is_thread_group_leader()? { p.get_parent_pid()? } else { p.m("tgid")?.int()? };
            if seen_ppids.contains(&parent_pid) || seen_offsets.contains(&p.addr) {
                break;
            }
            if parent_pid == 0 && ppid_self > 2 {
                break;
            }
            seen_ppids.insert(parent_pid);
            seen_offsets.insert(p.addr);
            let c = self.children.entry(parent_pid).or_default();
            if !c.contains(&ppid_self) {
                c.push(ppid_self);
            }
            proc = self.tasks.get(&parent_pid).copied();
            level += 1;
        }
        self.levels.insert(pid, level);
        Ok(())
    }
}

type Fields = (u64, i128, i128, i128, String);

/// python `yield_processes(pid)` (recursive, sorted children).
fn yield_processes(tree: &Tree, pid: i128, decorate: bool, out: &mut dyn FnMut(i64, Fields) -> Result<bool>) -> Result<bool> {
    let task = tree.tasks[&pid];
    let tf = get_task_fields(&task, decorate)?;
    let level = tree.levels[&tf.user_tid] - 1;
    let tid = tf.user_tid;
    if !out(level, (tf.offset, tf.user_pid, tf.user_tid, tf.user_ppid, tf.name))? {
        return Ok(false);
    }
    if let Some(ch) = tree.children.get(&tid) {
        let mut ch = ch.clone();
        ch.sort_unstable();
        for c in ch {
            if !yield_processes(tree, c, decorate, out)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

impl Plugin for PsTree {
    fn name(&self) -> &'static str {
        "linux.pstree.PsTree"
    }
    fn description(&self) -> &'static str {
        "Plugin for listing processes in a tree based on their parent process ID."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional(),
            Requirement::flag("threads", "Include user threads"),
            Requirement::flag("decorate_comm", "Show `user threads` comm in curly brackets, and `kernel threads` comm in square brackets"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("OFFSET (V)", ColType::Hex),
            Column::new("PID", ColType::Int),
            Column::new("TID", ColType::Int),
            Column::new("PPID", ColType::Int),
            Column::new("COMM", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        let pids = cfg.get_ints("pid");
        let filter = pid_filter(&pids);
        let decorate = cfg.get_bool("decorate_comm");
        let (tasks, tail) = collect_tasks(k, &filter, cfg.get_bool("threads"));
        // python consumes the whole task generator before yielding any row
        if let Some(e) = tail {
            return Err(e);
        }
        let mut tree = Tree { order: Vec::new(), tasks: FxHashMap::default(), levels: FxHashMap::default(), children: FxHashMap::default() };
        for t in tasks {
            let pid = t.m("pid")?.int()?;
            if tree.tasks.insert(pid, t).is_none() {
                tree.order.push(pid);
            }
        }
        for i in 0..tree.order.len() {
            let pid = tree.order[i];
            tree.find_level(pid)?;
        }
        // `seen_processes` holds whole field tuples (python rebinds `pid = fields[1]`)
        let mut seen: FxHashSet<Fields> = FxHashSet::default();
        for &pid in &tree.order {
            if tree.levels[&pid] != 1 {
                continue;
            }
            yield_processes(&tree, pid, decorate, &mut |level, f| {
                if !seen.insert(f.clone()) {
                    return Ok(false);
                }
                out.row(level.max(0) as usize, vec![Value::Int(f.0 as i128), Value::Int(f.1), Value::Int(f.2), Value::Int(f.3), Value::Str(f.4)])?;
                Ok(true)
            })?;
        }
        Ok(())
    }
}
