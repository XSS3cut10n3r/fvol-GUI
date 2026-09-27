//! windows.vadyarascan.VadYaraScan (python `plugins/windows/vadyarascan.py`): YARA rules over
//! every process' VADs (each VAD read whole, python `layer.read(start, size, pad=True)`), by
//! the region engine [`crate::yara::rules::regions`] (identical VADs scanned once, unmapped
//! pages skipped, hits streamed VAD by VAD).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::{LayerRef, Obj};
use crate::plugins::linux::vmayarascan::layer_data;
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::prelude::*;
use crate::yara::rules::Rules;
use crate::yara::rules::volatility::process_yara_options;

pub struct VadYaraScan;

/// python `YaraScan.get_yarascan_option_requirements()`.
pub fn yarascan_option_requirements() -> Vec<Requirement> {
    vec![
        Requirement::flag("insensitive", "Makes the search case insensitive"),
        Requirement::flag("wide", "Match wide (unicode) strings"),
        Requirement::new("yara_string", "Yara rules (as a string)", ReqKind::Str).optional(),
        Requirement::new("yara_file", "Yara rules (as a file)", ReqKind::Uri).optional(),
        Requirement::new("yara_compiled_file", "Yara compiled rules (as a file)", ReqKind::Uri).optional(),
        Requirement::new("max_size", "Set the maximum size (default is 1GB)", ReqKind::Int)
            .optional()
            .default(ConfigValue::Int(0x40000000)),
    ]
}

/// python `YaraScan.process_yara_options(dict(config))` (None = no rules given).
pub fn rules_from_config(cfg: &Config) -> Result<Option<Rules>> {
    // str(yara.SyntaxError) is "line N: msg"
    let compile_err = |e: crate::yara::rules::CompileError| Error::msg(format!("yara.SyntaxError: {e}"));
    if let Some(s) = cfg.get_str("yara_string") {
        return process_yara_options(Some(s), None, cfg.get_bool("insensitive"), cfg.get_bool("wide")).map_err(compile_err);
    }
    if let Some(url) = cfg.get_str("yara_file") {
        let src = crate::symbols::store::IsfLocation::Url(url.to_string()).read().map_err(|e| crate::util::paths::resource_error(url, e))?;
        return process_yara_options(None, Some(&src), false, false).map_err(compile_err);
    }
    if cfg.get_str("yara_compiled_file").is_some() {
        return Err(Error::msg("compiled yara rule files are not supported"));
    }
    Ok(None)
}

/// python `SANITY_CHECK`: VADs above 1 GiB are not scanned.
const SANITY_CHECK: u64 = 1024 * 1024 * 1024;

impl Plugin for VadYaraScan {
    fn name(&self) -> &'static str {
        "windows.vadyarascan.VadYaraScan"
    }
    fn description(&self) -> &'static str {
        "Scans all the Virtual Address Descriptor memory maps using yara."
    }
    fn requirements(&self) -> Vec<Requirement> {
        let mut r = yarascan_option_requirements();
        r.push(Requirement::new("pid", "Process IDs to include (all other processes are excluded)", ReqKind::ListInt).optional());
        r
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("PID", ColType::Int),
            Column::new("CreateTime", ColType::DateTime),
            Column::new("PPID", ColType::Int),
            Column::new("ImageFileName", ColType::Str),
            Column::new("SessionId", ColType::Int),
            Column::new("Threads", ColType::Int),
            Column::new("Rule", ColType::Str),
            Column::new("Component", ColType::Str),
            Column::new("Value", ColType::LayerData),
        ])?;
        let rules = rules_from_config(cfg)?;
        let k = ctx.windows_kernel()?;
        let pids = cfg.get_ints("pid");
        // the processes and their VADs (python's loop, up to where python would raise)
        let mut tasks: Vec<(Obj, LayerRef, Vec<(u64, u64)>)> = Vec::new();
        let mut failure = None;
        for task in crate::plugins::windows::pslist::list_processes(k, &crate::plugins::windows::pslist::pid_filter(&pids)) {
            let r = (|| -> Result<Option<(Obj, LayerRef, Vec<(u64, u64)>)>> {
                let task = task?;
                let layer = task.add_process_layer()?;
                let mut maps = Vec::new();
                for vad in task.get_vad_root()?.traverse() {
                    let vad = vad?;
                    let (start, size) = (vad.get_start()?, vad.get_size()?);
                    if size > SANITY_CHECK {
                        continue;
                    }
                    maps.push((start, size));
                }
                if maps.is_empty() {
                    return Ok(None);
                }
                if rules.is_none() {
                    return Err(Error::msg("ValueError: No rules provided to YaraScanner"));
                }
                Ok(Some((task, layer, maps)))
            })();
            match r {
                Ok(Some(t)) => tasks.push(t),
                Ok(None) => {}
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        if let Some(rules) = rules.as_ref() {
            // every VAD of every task in python order; identical VADs are scanned once and the
            // hits stream out VAD by VAD (bounded memory)
            let mut owner = Vec::new();
            let mut regions: Vec<crate::yara::rules::regions::Region<'_>> = Vec::new();
            for (ti, (_, layer, maps)) in tasks.iter().enumerate() {
                for &(start, size) in maps {
                    owner.push(ti);
                    regions.push((*layer, start, size));
                }
            }
            // the task columns are read at the task's first hit (python reads them per row;
            // the first failure is the same)
            let mut cols: Option<(usize, [Value; 6])> = None;
            crate::yara::rules::regions::scan_regions(rules, &regions, |i, hits| {
                let ti = owner[i];
                let (task, layer) = (&tasks[ti].0, tasks[ti].1);
                let start = regions[i].1;
                crate::yara::rules::regions::for_each_prepared(
                    hits,
                    |h| layer_data(layer, start + h.offset, h.len as u64),
                    |h, data| {
                        if cols.as_ref().is_none_or(|c| c.0 != ti) {
                            cols = Some((
                                ti,
                                [
                                    Value::Int(task.m("UniqueProcessId")?.int()?),
                                    task.get_create_time()?,
                                    Value::Int(task.m("InheritedFromUniqueProcessId")?.int()?),
                                    Value::Str(task.image_file_name_str()?),
                                    task.get_session_id()?,
                                    Value::Int(task.m("ActiveThreads")?.int()?),
                                ],
                            ));
                        }
                        let Some((_, c)) = cols.as_ref() else { unreachable!() };
                        let offset = start + h.offset;
                        out.row(
                            0,
                            vec![
                                Value::Int(offset as i128),
                                c[0].clone(),
                                c[1].clone(),
                                c[2].clone(),
                                c[3].clone(),
                                c[4].clone(),
                                c[5].clone(),
                                Value::Str(rules.hit_rule(h.string).to_string()),
                                Value::Str(rules.hit_string(h.string).to_string()),
                                data,
                            ],
                        )
                    },
                )
            })?;
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// python's traceback line for a bad rule is `yara.SyntaxError: line N: msg` (the line
    /// number was missing, and vmayarascan printed `RuntimeError: yara: ...`).
    #[test]
    fn syntax_error_text_like_yara_python() {
        let mut cfg = Config::default();
        cfg.set("yara_string", crate::plugins::ConfigValue::Str("{ZZ}".into()));
        let e = rules_from_config(&cfg).err().unwrap().to_string();
        assert!(e.starts_with("yara.SyntaxError: line 1: "), "{e}");
        let e = crate::plugins::linux::vmayarascan::yara_rules_from_config(&cfg).err().unwrap().to_string();
        assert!(e.starts_with("yara.SyntaxError: line 1: "), "{e}");
    }
}
