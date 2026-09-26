//! windows.vadyarascan.VadYaraScan (python `plugins/windows/vadyarascan.py`): YARA rules over
//! every process' VADs (each VAD read whole, python `layer.read(start, size, pad=True)`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::windows::malware::malfind::layer_data;
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::prelude::*;
use crate::yara::rules::Rules;
use crate::yara::rules::volatility::{process_yara_options, scanner_hits};

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
    let compile_err = |e: crate::yara::rules::CompileError| Error::msg(format!("yara.SyntaxError: {}", e.msg));
    if let Some(s) = cfg.get_str("yara_string") {
        return process_yara_options(Some(s), None, cfg.get_bool("insensitive"), cfg.get_bool("wide")).map_err(compile_err);
    }
    if let Some(url) = cfg.get_str("yara_file") {
        let src = crate::symbols::store::IsfLocation::Url(url.to_string()).read()?;
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
        let mut buf: Vec<u8> = Vec::new();
        for task in crate::plugins::windows::pslist::list_processes(k, &crate::plugins::windows::pslist::pid_filter(&pids)) {
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
                continue;
            }
            let Some(rules) = rules.as_ref() else {
                return Err(Error::msg("ValueError: No rules provided to YaraScanner"));
            };
            // each VAD is scanned on its own; scan them in parallel batches of bounded size
            let mut i = 0;
            while i < maps.len() {
                let mut j = i;
                let mut bytes = 0u64;
                while j < maps.len() && (j == i || bytes + maps[j].1 <= 256 << 20) {
                    bytes += maps[j].1;
                    j += 1;
                }
                let batch = &maps[i..j];
                let hits = if batch.len() == 1 {
                    let (start, size) = batch[0];
                    buf.resize(size as usize, 0);
                    layer.read_padded(start, &mut buf);
                    vec![scanner_hits(rules, &buf, start)]
                } else {
                    crate::util::par::par_map(batch.len(), |b| {
                        let (start, size) = batch[b];
                        let mut data = vec![0u8; size as usize];
                        layer.read_padded(start, &mut data);
                        scanner_hits(rules, &data, start)
                    })
                };
                for (offset, rule, name, value) in hits.into_iter().flatten() {
                    out.row(
                        0,
                        vec![
                            Value::Int(offset as i128),
                            Value::Int(task.m("UniqueProcessId")?.int()?),
                            task.get_create_time()?,
                            Value::Int(task.m("InheritedFromUniqueProcessId")?.int()?),
                            Value::Str(task.image_file_name_str()?),
                            task.get_session_id()?,
                            Value::Int(task.m("ActiveThreads")?.int()?),
                            Value::Str(rule),
                            Value::Str(name),
                            layer_data(layer, offset, value.len() as u64),
                        ],
                    )?;
                }
                i = j;
            }
        }
        Ok(())
    }
}
