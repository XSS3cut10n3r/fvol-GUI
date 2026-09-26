//! linux.vmaregexscan.VmaRegExScan (python `plugins/linux/vmaregexscan.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Each task's VMAs are scanned with python's `RegExScanner` semantics (`re.DOTALL`,
//! `finditer` per 16 MiB + 4 KiB chunk, hits starting in the chunk's first 16 MiB), then the
//! hit is re-matched (`re.match`, no flags) against the 128 bytes read at the hit.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::scan::{DEFAULT_CHUNK_SIZE, FnScanner, scan_each};
use crate::objects::{LayerRef, Obj};
use crate::objects::util::array_to_string;
use crate::plugins::linux::pslist::{collect_tasks, pid_filter};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::prelude::*;
use crate::yara::regex::{Flags, Regex};
use crate::yara::rules::volatility::{HitRun, push_run};

pub struct VmaRegExScan;

/// python `VmaRegExScan.MAXSIZE_DEFAULT` (the context size python actually reads; the
/// `--maxsize` option is accepted but unused, like python).
pub const MAXSIZE_DEFAULT: i128 = 128;

/// python `scanners.RegExScanner(pattern)` (flags `re.DOTALL`) as a chunk scanner: the start
/// of every `finditer` match that begins before `chunk_size`, as runs of offsets.
pub fn regex_scanner(re: &Regex) -> FnScanner<HitRun, impl Fn(&[u8], u64, &mut Vec<HitRun>) + Sync + '_> {
    FnScanner::new(move |data: &[u8], off: u64, hits: &mut Vec<HitRun>| {
        let base = hits.len();
        for (s, _) in re.find_iter(data) {
            if s as u64 >= DEFAULT_CHUNK_SIZE {
                break;
            }
            push_run(hits, base, off + s as u64, 0);
        }
    })
}

/// The compiled patterns: `RegExScanner`'s (`re.DOTALL`) and `re.match`'s (no flags).
struct Patterns {
    scan: Regex,
    rematch: Regex,
}

/// Hit runs one task may collect before its rows are streamed straight from the scan instead.
const TASK_RUNS_CAP: usize = 1 << 20;

/// A scanned task: its layer, sections, pid and name, and its hits (`None`: more than
/// [`TASK_RUNS_CAP`] runs, scan again while rendering).
struct TaskHits {
    layer: LayerRef,
    sections: Vec<(u64, u64)>,
    pid: i128,
    name: String,
    runs: Option<Vec<HitRun>>,
}

/// python `_generator` body for one task up to its rows; the `Err` is where python raised.
fn task_hits(task: &Obj, pats: &std::result::Result<Patterns, String>) -> (Option<TaskHits>, Option<Error>) {
    let r = (|| -> Result<Option<TaskHits>> {
        if task.m("mm")?.u64()? == 0 {
            return Ok(None);
        }
        let name = array_to_string(&task.m("comm")?, None)?;
        let Some(layer) = task.add_process_layer()? else { return Ok(None) };
        let sections = task.get_process_memory_sections(false)?;
        // python compiles the pattern here (RegExScanner.__init__), per task
        let p = pats.as_ref().map_err(|m| Error::msg(m.clone()))?;
        let mut runs = Vec::new();
        let mut over = false;
        scan_each(layer, &regex_scanner(&p.scan), Some(&sections), |run| {
            runs.push(run);
            over = runs.len() > TASK_RUNS_CAP;
            !over
        });
        if runs.is_empty() {
            return Ok(None);
        }
        let pid = task.m("tgid")?.int()?;
        Ok(Some(TaskHits { layer, sections, pid, name, runs: (!over).then_some(runs) }))
    })();
    match r {
        Ok(t) => (t, None),
        Err(e) => (None, Some(e)),
    }
}

/// The rows of one task's hits (python: `layer.read(offset, 128, pad=True)` re-matched with
/// `re.match`).
fn emit_runs(t: &TaskHits, rematch: &Regex, runs: &[HitRun], out: &mut dyn RowSink) -> Result<()> {
    let mut buf = [0u8; MAXSIZE_DEFAULT as usize];
    for run in runs {
        for offset in run.offsets() {
            t.layer.read_padded(offset, &mut buf);
            let m = match rematch.match_at(&buf, 0) {
                Some((s, e)) => &buf[s..e],
                None => &buf[..],
            };
            out.row(
                0,
                vec![
                    Value::Int(t.pid),
                    Value::Str(t.name.clone()),
                    Value::Int(offset as i128),
                    Value::Str(String::from_utf8_lossy(m).into_owned()),
                    Value::Bytes(m.to_vec()),
                ],
            )?;
        }
    }
    Ok(())
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
            .map_err(|e| format!("re.PatternError: {}", e.py_str(pattern)));
        let (tasks, tail) = collect_tasks(k, &filter, false);
        // tasks scanned in parallel, rows emitted in python order; workers run ahead only while
        // the waiting hits stay small
        let weight = |r: &(Option<TaskHits>, Option<Error>)| 64 + r.0.as_ref().and_then(|t| t.runs.as_ref()).map_or(0, |v| v.capacity() * std::mem::size_of::<HitRun>());
        let mut result: Result<()> = Ok(());
        crate::yara::rules::regions::stream_ordered(tasks.len(), 64 << 20, |i| task_hits(&tasks[i], &pats), weight, |_, (t, err)| {
            if let (Some(t), Ok(p)) = (t, &pats) {
                let r = match &t.runs {
                    Some(runs) => emit_runs(&t, &p.rematch, runs, out),
                    None => {
                        // too many hits to hold: stream them from a second scan
                        let mut r = Ok(());
                        scan_each(t.layer, &regex_scanner(&p.scan), Some(&t.sections), |run| {
                            r = emit_runs(&t, &p.rematch, &[run], out);
                            r.is_ok()
                        });
                        r
                    }
                };
                if let Err(e) = r {
                    result = Err(e);
                    return false;
                }
            }
            if let Some(e) = err {
                result = Err(e);
                return false;
            }
            true
        });
        result?;
        match tail {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
