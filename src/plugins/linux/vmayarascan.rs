//! linux.vmayarascan.VmaYaraScan (python `plugins/linux/vmayarascan.py`), with the option
//! handling of python `plugins/yarascan.py` (`YaraScan.get_yarascan_option_requirements`,
//! `process_yara_options`, `YaraScanner`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Every VMA (up to 1 GiB) of every task is read as one padded buffer and matched by the YARA
//! engine ([`crate::yara::rules`]) like python's `scanner(proc_layer.read(start, size,
//! pad=True), start)`. Large buffers live in an anonymous mapping filled only where the VMA
//! is mapped, so unmapped stretches cost no memory (they read as the kernel's zero page).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::Layer;
use crate::objects::{LayerRef, Obj};
use crate::plugins::linux::pslist::{collect_tasks, pid_filter};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::prelude::*;
use crate::yara::rules::Rules;
use crate::yara::rules::volatility::{process_yara_options, scanner_hits};

pub struct VmaYaraScan;

/// python `vmayarascan` `sanity_check` (1 GiB): larger VMAs are not scanned.
const SANITY_CHECK: u64 = 1024 * 1024 * 1024;

/// python `YaraScan.get_yarascan_option_requirements()` (the CLI-visible yarascan options).
pub fn yarascan_option_requirements() -> Vec<Requirement> {
    vec![
        Requirement::flag("insensitive", "Makes the search case insensitive"),
        Requirement::flag("wide", "Match wide (unicode) strings"),
        Requirement::new("yara_string", "Yara rules (as a string)", ReqKind::Str).optional(),
        Requirement::new("yara_file", "Yara rules (as a file)", ReqKind::Uri).optional(),
        Requirement::new("yara_compiled_file", "Yara compiled rules (as a file)", ReqKind::Uri).optional(),
        Requirement::new("max_size", "Set the maximum size (default is 1GB)", ReqKind::Int)
            .default(ConfigValue::Int(0x4000_0000))
            .optional(),
    ]
}

/// python `YaraScan.process_yara_options(config)`: the compiled rules, `Ok(None)` when no
/// rule option is given (python logs an error and returns None), `Err` where python raises
/// (a YARA syntax error, an unreadable rule file). Compiled rule files (`yara_compiled_file`,
/// `yara.load`) are not supported.
pub fn yara_rules_from_config(cfg: &Config) -> Result<Option<Rules>> {
    let file_src;
    let file = match (cfg.get_str("yara_string"), cfg.get_str("yara_file")) {
        (None, Some(url)) => {
            file_src = crate::symbols::store::IsfLocation::Url(url.to_string()).read()?;
            Some(&file_src[..])
        }
        _ => None,
    };
    if cfg.get_str("yara_string").is_none() && file.is_none() && cfg.get_str("yara_compiled_file").is_some() {
        return Err(Error::msg("yara compiled rule files (--yara-compiled-file) are not supported"));
    }
    Ok(process_yara_options(cfg.get_str("yara_string"), file, cfg.get_bool("insensitive"), cfg.get_bool("wide"))?)
}

/// python `LayerDataRenderer.render_bytes(LayerData(layer, offset, length))` with the CLI's
/// zero context bytes: the padded read of `[offset, offset + length)` and the indices python
/// reports as unreadable, including its quirks (`layer.mapping(start, end, True)` is passed the
/// END offset as the length, the map only advances one run per byte and a byte just past a run
/// counts as mapped).
pub fn layer_data(layer: &dyn Layer, offset: u64, length: u64) -> Value {
    let start = offset;
    let end = offset.wrapping_add(length);
    let mut errors = Vec::new();
    if layer.lower().is_some() && length > 0 {
        let mut maps: Vec<(u64, u64)> = Vec::new();
        layer.mapping(start, end, &mut |m| {
            maps.push((m.offset, m.len));
            // later runs can only matter while they start at or before `end`
            m.offset <= end && maps.len() as u64 <= length + 1
        });
        match maps.first() {
            None => {
                // python: `next(mapping)` raises StopIteration (the renderer crashes); render
                // every byte as unreadable instead
                errors.extend(0..length as u32);
            }
            Some(&first) => {
                let mut it = maps[1..].iter();
                let (mut moff, mut mlen) = first;
                for i in start..end {
                    if i < moff {
                        errors.push((i - start) as u32);
                    }
                    if i as u128 > moff as u128 + mlen as u128 {
                        if let Some(&(o, l)) = it.next() {
                            (moff, mlen) = (o, l);
                        }
                    }
                    if i as u128 > moff as u128 + mlen as u128 {
                        errors.push((i - start) as u32);
                    }
                }
            }
        }
    }
    let mut data = vec![0u8; length as usize];
    layer.read_padded(start, &mut data);
    Value::LayerBytes { data, errors }
}

unsafe extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
}

/// A zero-initialised byte buffer; big ones are anonymous mappings whose untouched pages
/// stay unallocated.
enum ZeroBuf {
    Heap(Vec<u8>),
    Map(*mut u8, usize),
}

impl ZeroBuf {
    fn new(len: usize) -> ZeroBuf {
        const PROT_RW: i32 = 1 | 2;
        const MAP_PRIVATE_ANON_NORESERVE: i32 = 0x02 | 0x20 | 0x4000;
        if len >= 1 << 20 {
            let p = unsafe { mmap(std::ptr::null_mut(), len, PROT_RW, MAP_PRIVATE_ANON_NORESERVE, -1, 0) };
            if p as usize != usize::MAX && !p.is_null() {
                return ZeroBuf::Map(p, len);
            }
        }
        ZeroBuf::Heap(vec![0u8; len])
    }
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            ZeroBuf::Heap(v) => v,
            ZeroBuf::Map(p, n) => unsafe { std::slice::from_raw_parts_mut(*p, *n) },
        }
    }
}

impl Drop for ZeroBuf {
    fn drop(&mut self) {
        if let ZeroBuf::Map(p, n) = *self {
            unsafe { munmap(p, n) };
        }
    }
}

/// python `proc_layer.read(start, size, pad=True)` into a [`ZeroBuf`]: only the mapped runs
/// are copied, the rest stays zero.
fn read_vma(layer: &dyn Layer, start: u64, size: u64) -> ZeroBuf {
    let mut buf = ZeroBuf::new(size as usize);
    let b = buf.as_mut();
    layer.mapping(start, size, &mut |m| {
        let off = (m.offset - start) as usize;
        layer.read_padded(m.offset, &mut b[off..off + m.len as usize]);
        true
    });
    buf
}

/// python `VmaYaraScan.get_vma_maps(task)`: `(vm_start, vm_end - vm_start)` of every VMA.
pub fn get_vma_maps(task: &Obj) -> Result<Vec<(u64, u64)>> {
    let mm = task.m("mm")?;
    if mm.u64()? == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for vma in mm.deref()?.get_vma_iter() {
        let vma = vma?;
        let end = vma.m("vm_end")?.u64()?;
        let start = vma.m("vm_start")?.u64()?;
        out.push((start, end.wrapping_sub(start)));
    }
    Ok(out)
}

/// The VMAs python scans for one task (`Ok(None)` = task skipped), `Err` where python raises
/// before scanning it.
fn task_vmas(task: &Obj) -> Result<Option<(LayerRef, i128, Vec<(u64, u64)>)>> {
    let Some(layer) = task.add_process_layer()? else { return Ok(None) };
    let vmas: Vec<(u64, u64)> = get_vma_maps(task)?.into_iter().filter(|&(_, size)| size <= SANITY_CHECK).collect();
    if vmas.is_empty() {
        return Ok(None);
    }
    Ok(Some((layer, task.m("tgid")?.int()?, vmas)))
}

impl Plugin for VmaYaraScan {
    fn name(&self) -> &'static str {
        "linux.vmayarascan.VmaYaraScan"
    }
    fn description(&self) -> &'static str {
        "Scans all virtual memory areas for tasks using yara."
    }
    fn requirements(&self) -> Vec<Requirement> {
        let mut v = yarascan_option_requirements();
        v.push(Requirement::new("pid", "Process IDs to include (all other processes are excluded)", ReqKind::ListInt).optional());
        v
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("PID", ColType::Int),
            Column::new("Rule", ColType::Str),
            Column::new("Component", ColType::Str),
            Column::new("Value", ColType::LayerData),
        ])?;
        let k = ctx.linux_kernel()?;
        // yara.SyntaxError / an unreadable rule file: not volatility exceptions, python's
        // plugin dies with a traceback (a panic is rsvol's equivalent)
        let rules = yara_rules_from_config(cfg).unwrap_or_else(|e| panic!("{e}"));
        let pids = cfg.get_ints("pid");
        let filter = pid_filter(&pids);
        let (tasks, tail) = collect_tasks(k, &filter, false);
        let per_task = crate::util::par::par_map(tasks.len(), |i| task_vmas(&tasks[i]));
        // one work item per VMA, in python order, up to the first task python fails on
        let mut items: Vec<(LayerRef, i128, u64, u64)> = Vec::new();
        let mut first_err: Option<Error> = None;
        for r in per_task {
            match r {
                Ok(Some(_)) if rules.is_none() => {
                    // python: `YaraScanner(rules=None)` at the first task with VMAs
                    return Err(Error::msg("ValueError: No rules provided to YaraScanner"));
                }
                Ok(Some((layer, tgid, vmas))) => items.extend(vmas.into_iter().map(|(s, n)| (layer, tgid, s, n))),
                Ok(None) => {}
                Err(e) => {
                    first_err = Some(e);
                    break;
                }
            }
        }
        let tail = first_err.or(tail);
        let Some(rules) = rules.as_ref() else {
            return match tail {
                Some(e) => Err(e),
                None => Ok(()),
            };
        };
        // Scan the VMAs on all cores, biggest first (cost ~ VMA size; a few big VMAs would
        // otherwise form the tail), then emit in python order. Only one buffer per worker is
        // alive at a time; the hits are small.
        let mut order: Vec<usize> = (0..items.len()).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(items[i].3));
        let done = crate::util::par::par_map(order.len(), |k| {
            let (layer, tgid, start, size) = items[order[k]];
            let mut buf = read_vma(layer, start, size);
            let hits = scanner_hits(rules, buf.as_mut(), start);
            drop(buf);
            hits.into_iter()
                .map(|(offset, rule, name, value)| {
                    vec![Value::Int(offset as i128), Value::Int(tgid), Value::Str(rule), Value::Str(name), layer_data(layer, offset, value.len() as u64)]
                })
                .collect::<Vec<_>>()
        });
        let mut slots: Vec<Vec<Vec<Value>>> = (0..items.len()).map(|_| Vec::new()).collect();
        for (k, rows) in done.into_iter().enumerate() {
            slots[order[k]] = rows;
        }
        for rows in slots {
            for row in rows {
                out.row(0, row)?;
            }
        }
        match tail {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
