//! mac.bash.Bash (python `plugins/mac/bash.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! For `bash`/`sh`/`dash` processes: scan the heap (python `get_process_memory_sections(...,
//! rw_no_file=True)`) for `#`, then for pointers to those `#`s, and validate a bash
//! `hist_entry` (linux `bash32`/`bash64` ISF) around each hit.

use crate::context::Context;
use crate::error::Result;
use crate::layers::scan::{BytesScanner, MultiStringScanner, scan};
use crate::objects::util::array_to_string;
use crate::objects::{LayerRef, Obj, Space};
use crate::symbols::TableRef;
use crate::plugins::{Config, Plugin, ReqKind, Requirement, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::bash::{HistEntry, bash_table};
use crate::symbols::mac::MacExt;
use crate::symbols::mac::vm::{MacVmExt, scan_sections};

pub struct Bash;

/// The per-task core of python `Bash._generator`: scan `sections` of `layer` for `#`, then for
/// the pointer-sized values of those addresses (`struct.pack("I"/"Q", address)`), and keep the
/// valid `hist_entry`s whose `timestamp` field is such a pointer, sorted (stably) by time.
fn find_history(layer: LayerRef, sections: &[(u64, u64)], bash_table: TableRef, ts_offset: u64, is_32bit: bool) -> Result<Vec<(Obj, HistEntry)>> {
    let bang_addrs: Vec<Vec<u8>> = scan(layer, &BytesScanner::new(b"#"), Some(sections))
        .into_iter()
        .map(|a| {
            if is_32bit {
                let a = u32::try_from(a).unwrap_or_else(|_| panic!("struct.error: 'I' format requires 0 <= number <= 4294967295"));
                a.to_le_bytes().to_vec()
            } else {
                a.to_le_bytes().to_vec()
            }
        })
        .collect();
    // python computes the sections again for the second scan (same result)
    let sp = Space::on(layer, bash_table);
    let mut history: Vec<(Obj, HistEntry)> = Vec::new();
    for (address, _) in scan(layer, &MultiStringScanner::new(&bang_addrs), Some(sections)) {
        let hist = Obj::named(sp, "hist_entry", address.wrapping_sub(ts_offset))?;
        if let Some(h) = HistEntry::parse(&hist)? {
            history.push((hist, h));
        }
    }
    // sorted(history_entries, key=get_time_as_integer): stable, on python's exact ints
    history.sort_by(|a, b| a.1.time_int.cmp(&b.1.time_int));
    Ok(history)
}

/// python `Bash._generator` rows: (pid, task name, CommandTime, Command). The rows of one task
/// are computed together; tasks run in parallel and are emitted in python order through `emit`
/// (`Ok(false)` stops). A returned `Err` is where python raised.
fn generate(ctx: &Context, cfg: &Config, emit: &mut dyn FnMut(Vec<Value>) -> Result<bool>) -> Result<()> {
    let k = ctx.mac_kernel()?;
    let is_32bit = !k.table.is_64bit();
    let bash_table = bash_table(ctx, !is_32bit)?;
    let ts_offset = bash_table.offset_of("hist_entry", "timestamp")?;
    let pids = cfg.get_ints("pid");
    let filter = super::pslist::pid_filter(&pids);
    let tasks = super::pslist::list_tasks(k, "tasks", &filter);
    // python passes the kernel MODULE name as the table name (see symbols::mac::vm)
    const CONFIG_KERNEL: &str = "kernel";
    let task_rows = |task: &Obj| -> Result<Vec<Vec<Value>>> {
        let task_name = array_to_string(&task.m("p_comm")?, None)?;
        if !matches!(task_name.as_str(), "bash" | "sh" | "dash") {
            return Ok(Vec::new());
        }
        let Some(layer) = task.add_process_layer()? else { return Ok(Vec::new()) };
        let sections = scan_sections(&task.get_process_memory_sections(CONFIG_KERNEL, true)?);
        let history = find_history(layer, &sections, bash_table, ts_offset, is_32bit)?;
        let mut rows = Vec::with_capacity(history.len());
        for (_, hist) in history {
            rows.push(vec![Value::Int(task.m("p_pid")?.int()?), Value::Str(task_name.clone()), hist.time_object(), Value::Str(hist.command)]);
        }
        Ok(rows)
    };
    let per_task = crate::util::par::par_map(tasks.len(), |i| match &tasks[i] {
        Ok(t) => task_rows(t),
        Err(_) => Ok(Vec::new()),
    });
    for (task, rows) in tasks.into_iter().zip(per_task) {
        task?;
        for r in rows? {
            if !emit(r)? {
                return Ok(());
            }
        }
    }
    Ok(())
}

impl Plugin for Bash {
    fn name(&self) -> &'static str {
        "mac.bash.Bash"
    }
    fn description(&self) -> &'static str {
        "Recovers bash command history from memory."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("CommandTime", ColType::DateTime),
            Column::new("Command", ColType::Str),
        ])?;
        generate(ctx, cfg, &mut |r| out.row(0, r).map(|_| true))
    }
    fn timeline(&self, ctx: &Context, cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        let mut ev = Vec::new();
        let r = generate(ctx, cfg, &mut |mut r| {
            let command = match r.pop() {
                Some(Value::Str(s)) => s,
                _ => String::new(),
            };
            let time = r.pop().unwrap_or(Value::NotAvailable);
            let name = match r.pop() {
                Some(Value::Str(s)) => s,
                _ => String::new(),
            };
            let pid = match r.pop() {
                Some(Value::Int(p)) => p,
                _ => 0,
            };
            ev.push(TimelineEvent { description: format!("{pid} ({name}): \"{command}\""), kind: TimeKind::Created, time });
            Ok(true)
        });
        Some(r.map(|_| ev))
    }
}

#[cfg(test)]
mod tests {
    use super::find_history;
    use crate::error::{Error, Result};
    use crate::layers::{Layer, Mapping};
    use crate::objects::leak_layer;
    use crate::renderers::Value;
    use crate::symbols::isf::{BuildOptions, load_table};
    use std::sync::Arc;

    /// Flat little-endian memory, 48-bit address space.
    struct Mem(Vec<u8>);
    impl Layer for Mem {
        fn name(&self) -> &str {
            "m1a_bash_mem"
        }
        fn max_address(&self) -> u64 {
            (1 << 48) - 1
        }
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let a = addr as usize;
            match self.0.get(a..a + buf.len()) {
                Some(s) => {
                    buf.copy_from_slice(s);
                    Ok(())
                }
                None => Err(Error::invalid(addr)),
            }
        }
        fn is_valid(&self, addr: u64, len: u64) -> bool {
            addr.checked_add(len).is_some_and(|e| e <= self.0.len() as u64)
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
            f(Mapping { offset: addr, len, mapped: addr });
        }
    }

    /// The scan + hist_entry pipeline on a synthetic heap: validity rules, stable sort on
    /// python ints (a negative stamp sorts first, equal stamps keep scan order), times.
    #[test]
    fn history_pipeline() {
        let mut m = vec![0u8; 0x4000];
        let mut put = |at: usize, b: &[u8]| m[at..at + b.len()].copy_from_slice(b);
        // (hist_entry address, timestamp string address, timestamp, line address, line)
        let entries: [(usize, usize, &[u8], usize, &[u8]); 7] = [
            (0x1800, 0x1000, b"#1500000000", 0x1010, b"ls -la"),
            (0x1818, 0x1020, b"#1400000000", 0x1030, b"whoami"),
            (0x1830, 0x1040, b"#12345", 0x1050, b"short"),
            (0x1848, 0x1060, b"#-1500000000", 0x1078, b"neg"),
            (0x1860, 0x1090, b"#1400000000", 0x10a0, b"second-dup"),
            (0x1878, 0x10c0, b"#14000000x0", 0x1010, b"ls -la"),
            (0x1890, 0x10e0, b"#1400000000", 0x10f0, b""),
        ];
        for &(h, ts, tss, line, ls) in &entries {
            put(ts, tss);
            put(line, ls);
            put(h, &(line as u64).to_le_bytes());
            put(h + 8, &(ts as u64).to_le_bytes());
        }
        let layer = leak_layer(Arc::new(Mem(m)));
        let json = include_bytes!("../../../data/isf/linux/bash64.json");
        let table = crate::symbols::register(load_table(json, "bash64", "test", &BuildOptions::default()).unwrap(), "m1a_bash_test");
        let ts_offset = table.offset_of("hist_entry", "timestamp").unwrap();
        let hist = find_history(layer, &[(0x1000, 0x2000)], table, ts_offset, false).unwrap();
        let got: Vec<(u64, String)> = hist.iter().map(|(o, h)| (o.addr, h.command.clone())).collect();
        assert_eq!(
            got,
            [(0x1848, "neg".to_string()), (0x1818, "whoami".to_string()), (0x1860, "second-dup".to_string()), (0x1800, "ls -la".to_string())]
        );
        assert!(matches!(hist[0].1.time_object(), Value::Unparsable));
        match hist[1].1.time_object() {
            Value::DateTime(d) => assert_eq!(d.secs, 1400000000),
            v => panic!("{v:?}"),
        }
    }
}
