//! vmscan.Vmscan (python `plugins/vmscan.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! python's `PageStartScanner` only looks at the first 4 bytes of every page of every scan
//! chunk (`range(data_offset % 0x1000, len(data), 0x1000)`, no `chunk_size` filter, so the
//! page in a chunk's overlap is reported by both chunks). We replay python's chunk list and
//! read just those 4 bytes per page (in parallel), instead of streaming the whole image.

use crate::context::Context;
use crate::error::Result;
use crate::layers::scan::chunk_layout;
use crate::layers::{Layer, LayerExt};
use crate::objects::{Obj, Space};
use crate::symbols::TableRef;
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::store::IsfLocation;

pub struct Vmscan;

const PAGE: u64 = 0x1000;

/// python `Vmscan._gather_vmcs_structures`: (revision id signature, table name, table); a
/// later table with the same revision id wins, like python's dict.
fn gather_vmcs_structures() -> Vec<([u8; 4], String, TableRef)> {
    // the embedded ISFs stand in for python's install dirs only when those are absent
    let have_py = crate::symbols::store::python_install().is_some();
    let locs: Vec<IsfLocation> = crate::symbols::symbol_path()
        .all()
        .into_iter()
        .filter(|l| !(have_py && matches!(l, IsfLocation::Embedded { .. })))
        .filter(|l| {
            let u = l.url();
            let path = u.rsplit_once('!').map_or(u.as_str(), |(_, m)| m);
            path.contains("/generic/vmcs/") || path.starts_with("generic/vmcs/")
        })
        .collect();
    let mut seen: Vec<String> = Vec::new();
    let mut out: Vec<([u8; 4], String, TableRef)> = Vec::new();
    for l in &locs {
        let u = l.url();
        let base = u.rsplit('/').next().unwrap_or("").split('.').next().unwrap_or("").to_string();
        // IntermediateSymbolTable.create(filename=base): the first file with that name, table
        // name free_table_name(base)
        let n = seen.iter().filter(|s| **s == base).count() + 1;
        seen.push(base.clone());
        let Some(first) = locs.iter().find(|x| x.url().rsplit('/').next().unwrap_or("").split('.').next() == Some(base.as_str())) else {
            continue;
        };
        let Ok(t) = crate::symbols::load_location(first, &base, None, 0) else { continue };
        let Some(rev) = t
            .get_symbol("revision_id")
            .ok()
            .and_then(|s| s.constant_data)
            .and_then(|cd| std::str::from_utf8(cd).ok())
            .and_then(|s| s.trim().parse::<u32>().ok())
        else {
            continue;
        };
        let sig = rev.to_le_bytes();
        let name = format!("{base}{n}");
        match out.iter_mut().find(|e| e.0 == sig) {
            Some(e) => {
                e.1 = name;
                e.2 = t;
            }
            None => out.push((sig, name, t)),
        }
    }
    out
}

/// python `_verify_vmcs_page` + the row: `None` = python skipped the page (a failed test or an
/// InvalidAddressException / AttributeError). Any failed test skips the page (python 3.11+:
/// every non-empty `VMCSTest` flag combination has a `name`), and so does any later read error,
/// so the checks stop at the first failure.
fn check(layer: &'static dyn Layer, table: TableRef, off: u64) -> Option<(u64, u64)> {
    let r = (|| -> Result<Option<(u64, u64)>> {
        let vmcs = Obj::named(Space::on(layer, table), "_VMCS", off)?;
        let failed = layer.read_vec(off + 4, 4)? != [0, 0, 0, 0]
            || vmcs.m("vmcs_link_ptr")?.int()? != 0xFFFF_FFFF_FFFF_FFFF
            || vmcs.m("host_cr4")?.int()? & (1 << 13) == 0
            || vmcs.m("guest_cr3")?.int()? == 0
            || vmcs.m("host_cr3")?.int()? == 0
            || vmcs.m("guest_cr4")?.int()? & 0xFFFF_FFFF_FF88_9000 != 0;
        if failed {
            return Ok(None);
        }
        Ok(Some((vmcs.m("ept")?.int()? as u64, vmcs.m("guest_cr3")?.int()? as u64)))
    })();
    r.ok().flatten()
}

impl Plugin for Vmscan {
    fn name(&self) -> &'static str {
        "vmscan.Vmscan"
    }
    fn description(&self) -> &'static str {
        "Scans for Intel VT-d structures and generates VM volatility configs for them"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("log-threshold", "Number of criteria failed to log to debug output", ReqKind::Int)
            .optional()
            .default(ConfigValue::Int(2))]
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        // python: the primary layer, moved down to its memory_layer when it has one
        let layer = super::primary::physical(ctx, "Physical base memory layer")?;
        let structures = {
            let _t = crate::util::trace::span("vmscan: vmcs tables");
            gather_vmcs_structures()
        };
        out.begin(vec![
            Column::new("Architecture", ColType::Str),
            Column::new("VMCS Physical offset", ColType::Hex),
            Column::new("EPT", ColType::Hex),
            Column::new("Guest CR3", ColType::Hex),
        ])?;
        if structures.is_empty() {
            // python: PageStartScanner([]) raises ValueError("No signatures passed to constructor")
            panic!("ValueError: No signatures passed to constructor");
        }
        // 4 bytes per page: `pread` them from the backing file (no page tables are built for
        // the 1.3M pages of a 5 GiB image, unlike touching the mapping)
        let file = crate::layers::base_file(layer);
        let direct = layer.as_file().is_some() || layer.lower().is_some_and(|l| l.as_file().is_some());
        let sig_at = |addr: u64| -> Option<[u8; 4]> {
            if let (true, Some(f)) = (direct, file) {
                use std::os::unix::fs::FileExt;
                let off = if layer.as_file().is_some() {
                    addr
                } else {
                    match layer.translate(addr) {
                        Some((o, rem)) if rem >= 4 => o,
                        _ => return layer.read_array::<4>(addr).ok(),
                    }
                };
                let mut b = [0u8; 4];
                return f.file().read_exact_at(&mut b, off).ok().map(|_| b);
            }
            layer.read_array::<4>(addr).ok()
        };
        // the raw signature hits (chunk start, offset in chunk, structure) come from the scan
        // cache when an earlier run (or another physical scan's sweep) recorded them; the VMCS
        // checks run every time
        let sigs: Vec<u32> = structures.iter().map(|s| u32::from_le_bytes(s.0)).collect();
        let _t = crate::util::trace::span("vmscan: page starts + checks");
        let raw = crate::layers::scancache::page_start_hits(layer, &sigs, || {
            let chunks = chunk_layout(layer, 0x1000000, 0x1000, None);
            let per_chunk: Vec<Vec<(u64, u64, u32)>> = crate::util::par::par_map(chunks.len(), |ci| {
                let (start, len) = chunks[ci];
                let mut hits = Vec::new();
                // python: a data-layer chunk that cannot be read entirely has no hits
                if layer.lower().is_none() && !layer.is_valid(start, len) {
                    return hits;
                }
                let mut ps = start % PAGE;
                while ps + 4 <= len {
                    if let Some(sig) = sig_at(start + ps)
                        && let Some(si) = structures.iter().position(|s| s.0 == sig)
                    {
                        hits.push((start, ps, si as u32));
                    }
                    ps += PAGE;
                }
                hits
            });
            per_chunk.concat()
        });
        let check_one = |i: usize| {
            let (start, ps, si) = raw[i];
            structures.get(si as usize).and_then(|s| check(layer, s.2, start + ps))
        };
        // a few us per hit: threads pay off beyond a few hundred hits
        let checked: Vec<Option<(u64, u64)>> =
            if raw.len() < 256 { (0..raw.len()).map(check_one).collect() } else { crate::util::par::par_map(raw.len(), check_one) };
        for (&(start, ps, si), c) in raw.iter().zip(checked) {
            if let Some((ept, cr3)) = c {
                out.row(0, vec![Value::Str(structures[si as usize].1.clone()), Value::Int((start + ps) as i128), Value::Int(ept as i128), Value::Int(cr3 as i128)])?;
            }
        }
        Ok(())
    }
}
