//! linux.vmaregexscan.VmaRegExScan (python `plugins/linux/vmaregexscan.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Each task's VMAs are scanned with python's `RegExScanner` semantics (`re.DOTALL`,
//! `finditer` per 16 MiB + 4 KiB chunk, hits starting in the chunk's first 16 MiB), then the
//! hit is re-matched (`re.match`, no flags) against the 128 bytes read at the hit.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::scan::{DEFAULT_CHUNK_SIZE, FnScanner, scan};
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::linux::pslist::{collect_tasks, pid_filter};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::prelude::*;
use crate::yara::regex::{Flags, Regex};

pub struct VmaRegExScan;

/// python `VmaRegExScan.MAXSIZE_DEFAULT` (the context size python actually reads; the
/// `--maxsize` option is accepted but unused, like python).
pub const MAXSIZE_DEFAULT: i128 = 128;

/// python `scanners.RegExScanner(pattern)` (flags `re.DOTALL`) as a chunk scanner: the start
/// of every `finditer` match that begins before `chunk_size`.
pub fn regex_scanner(re: &Regex) -> FnScanner<u64, impl Fn(&[u8], u64, &mut Vec<u64>) + Sync + '_> {
    FnScanner::new(move |data: &[u8], off: u64, hits: &mut Vec<u64>| {
        for (s, _) in re.find_iter(data) {
            if s as u64 >= DEFAULT_CHUNK_SIZE {
                break;
            }
            hits.push(off + s as u64);
        }
    })
}

/// The compiled patterns: `RegExScanner`'s (`re.DOTALL`) and `re.match`'s (no flags).
struct Patterns {
    scan: Regex,
    rematch: Regex,
}

/// python `_generator` body for one task; the `Err` is where python raised.
fn task_rows(task: &Obj, pats: &std::result::Result<Patterns, String>) -> (Vec<Vec<Value>>, Option<Error>) {
    let mut rows = Vec::new();
    let r = (|| -> Result<()> {
        if task.m("mm")?.u64()? == 0 {
            return Ok(());
        }
        let name = array_to_string(&task.m("comm")?, None)?;
        let Some(layer) = task.add_process_layer()? else { return Ok(()) };
        let sections = task.get_process_memory_sections(false)?;
        // python compiles the pattern here (RegExScanner.__init__), per task
        let p = pats.as_ref().map_err(|m| Error::msg(m.clone()))?;
        let hits = scan(layer, &regex_scanner(&p.scan), Some(&sections));
        if hits.is_empty() {
            return Ok(());
        }
        let user_pid = task.m("tgid")?.int()?;
        let mut buf = vec![0u8; MAXSIZE_DEFAULT as usize];
        for offset in hits {
            layer.read_padded(offset, &mut buf);
            let m = match p.rematch.match_at(&buf, 0) {
                Some((s, e)) => &buf[s..e],
                None => &buf[..],
            };
            rows.push(vec![
                Value::Int(user_pid),
                Value::Str(name.clone()),
                Value::Int(offset as i128),
                Value::Str(String::from_utf8_lossy(m).into_owned()),
                Value::Bytes(m.to_vec()),
            ]);
        }
        Ok(())
    })();
    (rows, r.err())
}

impl Plugin for VmaRegExScan {
    fn name(&self) -> &'static str {
        "linux.vmaregexscan.VmaRegExScan"
    }
    fn description(&self) -> &'static str {
        "Scans all virtual memory areas for tasks using RegEx."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional(),
            Requirement::new("pattern", "RegEx pattern", ReqKind::Str),
            Requirement::new("maxsize", "Maximum size in bytes for displayed context", ReqKind::Int)
                .default(ConfigValue::Int(MAXSIZE_DEFAULT))
                .optional(),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Offset", ColType::Hex),
            Column::new("Text", ColType::Str),
            Column::new("Hex", ColType::Bytes),
        ])?;
        let k = ctx.linux_kernel()?;
        let pids = cfg.get_ints("pid");
        let filter = pid_filter(&pids);
        let pattern = cfg.get_str("pattern").unwrap_or("").as_bytes();
        let pats = Regex::new(pattern, Flags::S)
            .and_then(|scan| Ok(Patterns { scan, rematch: Regex::new(pattern, 0)? }))
            .map_err(|e| format!("re.error: {e}"));
        let (tasks, tail) = collect_tasks(k, &filter, false);
        let per_task = crate::util::par::par_map(tasks.len(), |i| task_rows(&tasks[i], &pats));
        for (rows, err) in per_task {
            for row in rows {
                out.row(0, row)?;
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
}
