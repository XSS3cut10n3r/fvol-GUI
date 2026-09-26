//! windows.cmdscan.CmdScan (python `plugins/windows/cmdscan.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::layers::scan::{BytesScanner, scan};
use crate::objects::{Obj, Space};
use crate::plugins::windows::consoles::{
    ConhostProc, Data, ProcResult, Prop, PySet, SetElem, columns, config_ints, conhosts, emit_rows, get_console_settings_from_registry, pack_h,
    py_exception, py_hex, raise,
};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::RowSink;
use crate::symbols::TableRef;
use crate::symbols::windows::consoles::ConsoleExt;
use crate::symbols::windows::prelude::*;

pub struct CmdScan;

/// python `CmdScan.get_filtered_vads(proc, size_filter=0x40000000)`: (start, size) of the
/// VADs smaller than `size_filter` (python ints: a VAD whose end is below its start has a
/// negative size and is kept).
pub fn get_filtered_vads(proc: &Obj, size_filter: i128) -> Result<Vec<(i128, i128)>> {
    let mut out = Vec::new();
    for v in proc.get_vad_root()?.traverse() {
        let vad = v?;
        let base = vad.get_start()? as i128;
        let size = vad.get_end()? as i128 - vad.get_start()? as i128 + 1;
        if size < size_filter {
            out.push((base, size));
        }
    }
    Ok(out)
}

/// python `_coalesce_sections` (sort, then merge a section into the previous one when it
/// starts at or before the end of the previously *listed* section), keeping only the
/// sections python's scan iterator can map (positive lengths).
fn python_sections(mut secs: Vec<(i128, i128)>) -> Vec<(u64, u64)> {
    secs.sort();
    let mut result: Vec<(i128, i128)> = Vec::with_capacity(secs.len());
    let mut position = 0i128;
    for (start, length) in secs {
        match result.last_mut() {
            Some(last) if start <= position => last.1 = start + length - last.0,
            _ => result.push((start, length)),
        }
        position = start + length;
    }
    result.into_iter().filter(|&(s, l)| s >= 0 && l > 0 && s <= u64::MAX as i128 && l <= u64::MAX as i128).map(|(s, l)| (s as u64, l as u64)).collect()
}

/// The properties python collects for a `_COMMAND_HISTORY` candidate (python catches every
/// exception and keeps the properties collected so far).
fn history_properties(ch: &Obj, max_history_value: i128) -> Vec<Prop> {
    let mut p: Vec<Prop> = Vec::new();
    let _ = (|| -> Result<()> {
        if !ch.command_history_is_valid(max_history_value)? {
            return Ok(());
        }
        const CH: &str = "_COMMAND_HISTORY";
        let mut push = |level: usize, name: String, address: Option<u64>, data: Data| p.push(Prop { level, name, address, data });
        push(0, CH.into(), Some(ch.addr), Data::None);
        let app = ch.m("Application")?;
        push(1, format!("{CH}.Application"), Some(app.addr), ch.get_application()?.map(Data::Str).unwrap_or(Data::None));
        let ph = ch.m("ConsoleProcessHandle")?.m("ProcessHandle")?;
        let phv = ph.int()?;
        push(1, format!("{CH}.ProcessHandle"), Some(ph.addr), Data::Str(py_hex(phv)));
        push(1, format!("{CH}.CommandCount"), None, Data::Int(ch.command_count()?));
        let ld = ch.m("LastDisplayed")?;
        let ldv = ld.int()?;
        push(1, format!("{CH}.LastDisplayed"), Some(ld.addr), Data::Int(ldv));
        let ccm = ch.m("CommandCountMax")?;
        let ccmv = ccm.int()?;
        push(1, format!("{CH}.CommandCountMax"), Some(ccm.addr), Data::Int(ccmv));
        let bucket = ch.m("CommandBucket")?;
        push(1, format!("{CH}.CommandBucket"), Some(bucket.addr), Data::Str(String::new()));
        for c in ch.scan_command_bucket(None)? {
            let (cmd_index, cmd) = c?;
            if let Ok(s) = cmd.get_command_string() {
                push(2, format!("{CH}.CommandBucket_Command_{cmd_index}"), Some(cmd.addr), s.map(Data::Str).unwrap_or(Data::None));
            }
        }
        Ok(())
    })();
    p
}

/// python `CmdScan.get_command_history` for one conhost process. Python passes the VAD
/// *generator* as `sections` to every scan, so only the first `max_history` value (in set
/// order) scans anything; the later scans get an exhausted generator.
fn history_for(c: &ConhostProc, table: TableRef, mut vads: Result<Vec<(i128, i128)>>, max_history: &[SetElem]) -> ProcResult {
    let mut res = ProcResult { found: Vec::new(), last_candidate: None };
    let r = (|| -> Result<()> {
        let sp = Space::on(c.layer, table);
        let ty = table.get_type("_COMMAND_HISTORY")?;
        let ccm_offset = table.offset_of("_COMMAND_HISTORY", "CommandCountMax")?;
        for (idx, v) in max_history.iter().enumerate() {
            let needle = pack_h(v)?;
            let value = match v {
                SetElem::Int(i) => *i,
                SetElem::Bytes(_) => 0,
            };
            let sections = if idx == 0 {
                match std::mem::replace(&mut vads, Ok(Vec::new())) {
                    Ok(v) => python_sections(v),
                    Err(e) => return Err(e),
                }
            } else {
                Vec::new()
            };
            if sections.is_empty() {
                continue;
            }
            for address in scan(c.layer, &BytesScanner::new(&needle), Some(&sections)) {
                let ch = Obj::new(sp, ty, address.wrapping_sub(ccm_offset));
                res.last_candidate = Some(ch.addr);
                let props = history_properties(&ch, value);
                if !props.is_empty() {
                    res.found.push(Ok((ch.addr, props)));
                }
            }
        }
        Ok(())
    })();
    if let Err(e) = r {
        res.found.push(Err(e));
    }
    res
}

impl Plugin for CmdScan {
    fn name(&self) -> &'static str {
        "windows.cmdscan.CmdScan"
    }
    fn description(&self) -> &'static str {
        "Looks for Windows Command History lists"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::flag("no_registry", "Don't search the registry for possible values of CommandHistorySize"),
            Requirement::new("max_history", "CommandHistorySize values to search for.", ReqKind::ListInt)
                .optional()
                .default(ConfigValue::List(vec![ConfigValue::Int(50)])),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(columns())?;
        let k = ctx.windows_kernel()?;
        let mut max_history = PySet::from_ints(&config_ints(cfg, "max_history", 50));
        if !cfg.get_bool("no_registry") {
            get_console_settings_from_registry(ctx, k, &mut max_history, None)?;
        }
        let max_history = max_history.elems();
        let ch = conhosts(ctx, k, false);
        let table = match &ch.table {
            Some(Ok(t)) => Some(*t),
            _ => None,
        };
        let _t = crate::util::trace::span("cmdscan: command histories");
        let results: Vec<Option<ProcResult>> = crate::util::par::par_map(ch.procs.len(), |i| match (&ch.procs[i], table) {
            (Ok((c, Some(_))), Some(t)) => Some(history_for(c, t, get_filtered_vads(&c.proc, 0x4000_0000), &max_history)),
            _ => None,
        });
        let mut table_err = match ch.table {
            Some(Err(e)) => Some(e),
            _ => None,
        };
        // python's `command_history` local survives from one process to the next
        let mut carry: Option<u64> = None;
        for (p, r) in ch.procs.into_iter().zip(results) {
            let (c, exe) = p.map_err(raise)?;
            if exe.is_none() {
                continue;
            }
            if let Some(e) = table_err.take() {
                return Err(raise(e));
            }
            let Some(r) = r else { continue };
            if r.last_candidate.is_some() {
                carry = r.last_candidate;
            }
            if r.found.is_empty() && carry.is_none() {
                return Err(raise(py_exception("UnboundLocalError: cannot access local variable 'command_history' where it is not associated with a value")));
            }
            emit_rows(out, &c.proc, r.found, carry, "_COMMAND_HISTORY", "History Not Found", Data::cmdscan_value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_coalescing() {
        assert_eq!(python_sections(vec![(0x2000, 0x1000), (0x1000, 0x1000)]), vec![(0x1000, 0x2000)]);
        // python quirk: a section inside the previous one shrinks it
        assert_eq!(python_sections(vec![(0, 100), (10, 5), (50, 10)]), vec![(0, 15), (50, 10)]);
        assert_eq!(python_sections(vec![(100, 50), (120, -10)]), vec![(100, 10)]);
        assert_eq!(python_sections(vec![(10, 0), (20, -5)]), vec![]);
    }
}
