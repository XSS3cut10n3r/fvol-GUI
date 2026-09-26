//! linux.bash.Bash (python `plugins/linux/bash.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! The `hist_entry` class lives in [`crate::symbols::linux::bash`].

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::scan::{BytesScanner, MultiStringScanner, scan};
use crate::objects::util::array_to_string;
use crate::objects::{Obj, Space};
use crate::plugins::linux::pslist::{collect_tasks, pid_filter};
use crate::plugins::{Config, Plugin, ReqKind, Requirement, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::linux::bash::{HistEntry, bash_table};
use crate::symbols::linux::prelude::*;

pub struct Bash;

/// One output row: (pid, process name, command time, command).
type Row = (i128, String, Value, String);

/// python `_generator` body for one task; the `Err` is where python raised.
fn task_rows(task: &Obj, table: TableRef, ts_offset: u64, is_32bit: bool) -> (Vec<Row>, Option<Error>) {
    let mut rows = Vec::new();
    let r = (|| -> Result<()> {
        let task_name = array_to_string(&task.m("comm")?, None)?;
        if !matches!(task_name.as_str(), "bash" | "sh" | "dash") {
            return Ok(());
        }
        let Some(layer) = task.add_process_layer()? else { return Ok(()) };
        let sections = task.get_process_memory_sections(true)?;
        // find '#' values on the heap, then pointers to them
        let bangs = scan(layer, &BytesScanner::new(b"#"), Some(&sections));
        let mut entries: Vec<HistEntry> = Vec::new();
        if !bangs.is_empty() {
            let patterns: Vec<Vec<u8>> = bangs
                .iter()
                .map(|&a| if is_32bit { (a as u32).to_le_bytes().to_vec() } else { a.to_le_bytes().to_vec() })
                .collect();
            let hits = scan(layer, &MultiStringScanner::new(&patterns), Some(&sections));
            let sp = Space::on(layer, table);
            for (address, _) in hits {
                let hist = Obj::named(sp, "hist_entry", address.wrapping_sub(ts_offset))?;
                if let Some(h) = HistEntry::parse(&hist)? {
                    entries.push(h);
                }
            }
        }
        // python `sorted(..., key=get_time_as_integer)` (stable)
        entries.sort_by_key(|h| h.time);
        let pid = task.m("pid")?.int()?;
        for h in entries {
            rows.push((pid, task_name.clone(), h.time_object(), h.command));
        }
        Ok(())
    })();
    (rows, r.err())
}

/// python `Bash._generator(list_tasks(pid filter))`: rows in python order, `f` per row.
fn generate(ctx: &Context, cfg: &Config, f: &mut dyn FnMut(Row) -> Result<()>) -> Result<()> {
    let k = ctx.linux_kernel()?;
    let pids = cfg.get_ints("pid");
    let filter = pid_filter(&pids);
    let is_32bit = !k.table.is_64bit();
    let table = bash_table(ctx, !is_32bit)?;
    let ts_offset = Obj::named(Space::on(k.vlayer, table), "hist_entry", 0)?.member_offset("timestamp")?;
    let (tasks, tail) = collect_tasks(k, &filter, false);
    let per_task = crate::util::par::par_map(tasks.len(), |i| task_rows(&tasks[i], table, ts_offset, is_32bit));
    for (rows, err) in per_task {
        for row in rows {
            f(row)?;
        }
        if let Some(e) = err {
            return Err(e);
        }
    }
    match tail {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

impl Plugin for Bash {
    fn name(&self) -> &'static str {
        "linux.bash.Bash"
    }
    fn description(&self) -> &'static str {
        "Recovers bash command history from memory."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Process IDs to include (all other processes are excluded)", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("CommandTime", ColType::DateTime),
            Column::new("Command", ColType::Str),
        ])?;
        generate(ctx, cfg, &mut |(pid, name, time, cmd)| out.row(0, vec![Value::Int(pid), Value::Str(name), time, Value::Str(cmd)]))
    }
    fn timeline(&self, ctx: &Context, cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        let mut ev = Vec::new();
        let r = generate(ctx, cfg, &mut |(pid, name, time, cmd)| {
            ev.push(TimelineEvent { description: format!("{pid} ({name}): \"{cmd}\""), kind: TimeKind::Created, time });
            Ok(())
        });
        Some(r.map(|_| ev))
    }
}
