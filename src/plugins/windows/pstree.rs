//! windows.pstree.PsTree (python `plugins/windows/pstree.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;
use crate::util::pyset::PyIntSet;
use crate::util::{FxHashMap, FxHashSet};

pub struct PsTree;

/// The process tree state of python's `PsTree` instance.
struct Tree {
    /// `_processes` in dict insertion order: (pid, proc, offset); a repeated pid keeps its first
    /// position and takes the last value (python dict assignment).
    procs: Vec<(u64, Obj, u64)>,
    index: FxHashMap<u64, usize>,
    /// `_levels`, parallel to `procs`.
    levels: Vec<i128>,
    children: FxHashMap<u64, PyIntSet>,
    ancestors: FxHashSet<u64>,
}

fn row(proc: &Obj, offset: u64, level: i128) -> Result<(i128, Vec<Value>)> {
    let mut r = vec![
        Value::Int(proc.m("UniqueProcessId")?.int()?),
        Value::Int(proc.m("InheritedFromUniqueProcessId")?.int()?),
        Value::Str(proc.image_file_name_str()?),
        Value::Int(offset as i128),
        Value::Int(proc.m("ActiveThreads")?.int()?),
        proc.get_handle_count(),
        proc.get_session_id()?,
        Value::Bool(proc.get_is_wow64()?),
        proc.get_create_time()?,
        proc.get_exit_time()?,
    ];
    // audit = proc.SeAuditProcessCreationInfo.ImageFileName.Name; audit.get_string() or N/A
    match proc.path("SeAuditProcessCreationInfo.ImageFileName").and_then(|p| p.m("Name")).and_then(|n| n.get_string()) {
        Ok(s) if !s.is_empty() => r.push(Value::Str(s)),
        Ok(_) => r.push(Value::NotAvailable),
        Err(e) if e.is_invalid_address() => r.push(Value::NotAvailable),
        Err(e) => return Err(e),
    }
    let params = (|| -> Result<(String, String)> {
        let pp = proc.get_peb()?.m("ProcessParameters")?;
        Ok((pp.m("CommandLine")?.get_string()?, pp.m("ImagePathName")?.get_string()?))
    })();
    match params {
        Ok((c, p)) => {
            r.push(Value::Str(c));
            r.push(Value::Str(p));
        }
        Err(e) if e.is_invalid_address() => {
            r.push(Value::NotAvailable);
            r.push(Value::NotAvailable);
        }
        Err(e) => return Err(e),
    }
    Ok((level - 1, r))
}

impl Tree {
    /// python `find_level(pid, filter_func)`.
    fn find_level(&mut self, idx: usize, filter: &dyn Fn(&Obj) -> Result<bool>) -> Result<()> {
        let pid = self.procs[idx].0;
        let mut seen = FxHashSet::default();
        seen.insert(pid);
        let mut level = 0i128;
        let mut proc = Some(self.procs[idx].1);
        let filtered = !filter(&self.procs[idx].1)?;
        while let Some(p) = proc {
            let ppid = p.m("InheritedFromUniqueProcessId")?.u64()?;
            if seen.contains(&ppid) {
                break;
            }
            let upid = p.m("UniqueProcessId")?.u64()?;
            if filtered {
                self.ancestors.insert(upid);
            }
            self.children.entry(ppid).or_default().add(upid);
            seen.insert(ppid);
            proc = self.index.get(&ppid).map(|&i| self.procs[i].1);
            level += 1;
        }
        self.levels[idx] = level;
        Ok(())
    }

    /// python `yield_processes(pid, descendant)` (recursive in python, an explicit stack here):
    /// appends the rows' process indices in output order; an Err is where python raised.
    /// Rows are computed afterwards; this only fixes the order.
    fn walk(
        &self,
        idx: usize,
        done: &mut FxHashSet<u64>,
        filter: &dyn Fn(&Obj) -> Result<bool>,
        order: &mut Vec<usize>,
    ) -> Result<()> {
        // (children of a visited process in python set order, next child, descendant flag of
        // that process, its `descendant or not filter_func(proc)` once evaluated)
        struct Frame {
            kids: Vec<u64>,
            next: usize,
            descendant: bool,
            idx: usize,
            child_desc: Option<bool>,
        }
        let mut stack: Vec<Frame> = Vec::new();
        let mut pending = Some((idx, false));
        loop {
            if let Some((i, descendant)) = pending.take() {
                let pid = self.procs[i].0;
                if done.insert(pid) && (self.ancestors.contains(&pid) || descendant) {
                    order.push(i);
                    let kids = self.children.get(&pid).map(|k| k.iter().collect()).unwrap_or_default();
                    stack.push(Frame { kids, next: 0, descendant, idx: i, child_desc: None });
                }
            }
            let Some(top) = stack.last_mut() else { return Ok(()) };
            if top.next >= top.kids.len() {
                stack.pop();
                continue;
            }
            let child = top.kids[top.next];
            top.next += 1;
            // `descendant or not filter_func(proc)` is evaluated per child (same result each time)
            let desc = match top.child_desc {
                Some(v) => v,
                None => {
                    let v = top.descendant || !filter(&self.procs[top.idx].1)?;
                    top.child_desc = Some(v);
                    v
                }
            };
            match self.index.get(&child) {
                Some(&ci) => pending = Some((ci, desc)),
                None => return Err(Error::msg(format!("KeyError: {child}"))),
            }
        }
    }
}

fn physical_offset(k: &WinKernel, addr: u64) -> Result<u64> {
    match k.layer.translate_addr(addr) {
        Some((pa, _)) => Ok(pa),
        None => Err(Error::invalid(addr)),
    }
}

fn run_tree(ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
    let k = ctx.windows_kernel()?;
    let physical = cfg.get_bool("physical");
    let pids = cfg.get_ints("pid");
    let filter = super::pslist::pid_filter(&pids);
    let mut t = Tree {
        procs: Vec::new(),
        index: FxHashMap::default(),
        levels: Vec::new(),
        children: FxHashMap::default(),
        ancestors: FxHashSet::default(),
    };
    for p in super::pslist::list_processes(k, &|_| Ok(false)) {
        let proc = p?;
        let offset = if physical { physical_offset(k, proc.addr)? } else { proc.addr };
        let pid = proc.m("UniqueProcessId")?.u64()?;
        match t.index.get(&pid) {
            Some(&i) => t.procs[i] = (pid, proc, offset),
            None => {
                t.index.insert(pid, t.procs.len());
                t.procs.push((pid, proc, offset));
            }
        }
    }
    t.levels = vec![0; t.procs.len()];
    for i in 0..t.procs.len() {
        t.find_level(i, &filter)?;
    }
    let mut done = FxHashSet::default();
    let mut order = Vec::new();
    let mut walk_err = None;
    for i in 0..t.procs.len() {
        if t.levels[i] == 1 {
            if let Err(e) = t.walk(i, &mut done, &filter, &mut order) {
                walk_err = Some(e);
                break;
            }
        }
    }
    // rows are independent reads: compute them in parallel, emit in python order
    let rows = crate::util::par::par_map(order.len(), |j| {
        let i = order[j];
        row(&t.procs[i].1, t.procs[i].2, t.levels[i])
    });
    for r in rows {
        let (depth, values) = r?;
        out.row(depth.max(0) as usize, values)?;
    }
    match walk_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

impl Plugin for PsTree {
    fn name(&self) -> &'static str {
        "windows.pstree.PsTree"
    }
    fn description(&self) -> &'static str {
        "Plugin for listing processes in a tree based on their parent process ID."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::flag("physical", "Display physical offsets instead of virtual"),
            Requirement::new(
                "pid",
                "Process ID to include (with ancestors and descendants, all other processes are excluded)",
                ReqKind::ListInt,
            )
            .optional(),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let off = if cfg.get_bool("physical") { "Offset(P)" } else { "Offset(V)" };
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("PPID", ColType::Int),
            Column::new("ImageFileName", ColType::Str),
            Column::new(off, ColType::Hex),
            Column::new("Threads", ColType::Int),
            Column::new("Handles", ColType::Int),
            Column::new("SessionId", ColType::Int),
            Column::new("Wow64", ColType::Bool),
            Column::new("CreateTime", ColType::DateTime),
            Column::new("ExitTime", ColType::DateTime),
            Column::new("Audit", ColType::Str),
            Column::new("Cmd", ColType::Str),
            Column::new("Path", ColType::Str),
        ])?;
        run_tree(ctx, cfg, out)
    }
}
