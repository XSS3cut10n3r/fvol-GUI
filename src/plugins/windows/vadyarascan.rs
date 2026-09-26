//! windows.vadyarascan.VadYaraScan (python `plugins/windows/vadyarascan.py`): YARA rules over
//! every process' VADs (each VAD read whole, python `layer.read(start, size, pad=True)`). VADs
//! with identical contents (same size and page mappings) are scanned once.
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

/// VADs above this size are scanned by at most [`BIG_THREADS`] workers (each worker keeps one
/// buffer as large as the largest VAD it scanned).
const BIG_VAD: u64 = 64 << 20;
const BIG_THREADS: usize = 2;

/// One YARA hit relative to its VAD: (offset, rule, string identifier, matched length).
type RelHit = (u64, String, String, usize);

/// Identity of a VAD's padded bytes: its size and how its pages map (runs relative to the VAD
/// start with their physical target). Equal signatures mean equal bytes, e.g. a DLL mapped at
/// the same address with the same resident pages in many processes, or unbacked reservations.
fn vad_signature(layer: LayerRef, start: u64, size: u64) -> (u64, u64, u64) {
    use std::hash::Hasher;
    let mut h1 = crate::util::fxhash::FxHasher::default();
    let mut h2 = crate::util::fxhash::FxHasher::default();
    layer.mapping_targets(start, size, &mut |m, l| {
        let id = l as *const dyn crate::layers::Layer as *const u8 as u64;
        for (i, v) in [m.offset.wrapping_sub(start), m.len, m.mapped, id].into_iter().enumerate() {
            h1.write_u64(v);
            h2.write_u64(v.rotate_left(17 + i as u32) ^ 0x9e37_79b9_7f4a_7c15);
        }
        true
    });
    (size, h1.finish(), h2.finish())
}

/// `YaraScanner(rules)(layer.read(start, size, pad=True), start)` for every VAD of every task,
/// as hits relative to the VAD. Each distinct VAD content is scanned once, in parallel waves
/// of bounded memory.
fn scan_vads(rules: &Rules, tasks: &[(Obj, LayerRef, Vec<(u64, u64)>)]) -> Vec<Vec<std::sync::Arc<Vec<RelHit>>>> {
    use crate::util::par::par_map;
    let items: Vec<(usize, u64, u64)> = tasks.iter().enumerate().flat_map(|(ti, (_, _, maps))| maps.iter().map(move |&(s, z)| (ti, s, z))).collect();
    let sigs = par_map(items.len(), |i| {
        let (ti, s, z) = items[i];
        vad_signature(tasks[ti].1, s, z)
    });
    let mut slot: crate::util::FxHashMap<(u64, u64, u64), usize> = crate::util::FxHashMap::default();
    let mut unique: Vec<usize> = Vec::new();
    let item_slot: Vec<usize> = sigs
        .iter()
        .enumerate()
        .map(|(i, s)| {
            *slot.entry(*s).or_insert_with(|| {
                unique.push(i);
                unique.len() - 1
            })
        })
        .collect();
    crate::util::trace::note(|| {
        let total: u64 = items.iter().map(|i| i.2).sum();
        let distinct: u64 = unique.iter().map(|&i| items[i].2).sum();
        format!("vadyarascan: {} vads ({total} bytes), {} distinct ({distinct} bytes)", items.len(), unique.len())
    });
    // small VADs on every core, big ones on a few (bounded memory); each worker reuses one
    // buffer (no page faults on fresh allocations)
    thread_local! {
        static BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }
    let scan_one = |u: usize| -> std::sync::Arc<Vec<RelHit>> {
        let (ti, s, z) = items[unique[u]];
        BUF.with(|b| {
            let mut data = b.borrow_mut();
            data.resize(z as usize, 0);
            tasks[ti].1.read_padded(s, &mut data);
            std::sync::Arc::new(scanner_hits(rules, &data, 0).into_iter().map(|(o, r, n, v)| (o, r, n, v.len())).collect())
        })
    };
    let (small, big): (Vec<usize>, Vec<usize>) = (0..unique.len()).partition(|&u| items[unique[u]].2 <= BIG_VAD);
    let small_hits = par_map(small.len(), |j| scan_one(small[j]));
    let big_hits = crate::util::par::par_map_bounded(big.len(), BIG_THREADS, |j| scan_one(big[j]));
    let mut results: Vec<Option<std::sync::Arc<Vec<RelHit>>>> = vec![None; unique.len()];
    for (u, h) in small.into_iter().zip(small_hits).chain(big.into_iter().zip(big_hits)) {
        results[u] = Some(h);
    }
    let results: Vec<std::sync::Arc<Vec<RelHit>>> = results.into_iter().map(|r| r.unwrap_or_default()).collect();
    let mut out: Vec<Vec<std::sync::Arc<Vec<RelHit>>>> = tasks.iter().map(|t| Vec::with_capacity(t.2.len())).collect();
    for (i, &(ti, _, _)) in items.iter().enumerate() {
        out[ti].push(results[item_slot[i]].clone());
    }
    out
}

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
            let hits = scan_vads(rules, &tasks);
            for ((task, layer, maps), per_vad) in tasks.iter().zip(hits) {
                for (&(start, _), vad_hits) in maps.iter().zip(per_vad) {
                    for (rel, rule, name, len) in vad_hits.iter() {
                        let offset = start + *rel;
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
                                Value::Str(rule.clone()),
                                Value::Str(name.clone()),
                                layer_data(*layer, offset, *len as u64),
                            ],
                        )?;
                    }
                }
            }
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
