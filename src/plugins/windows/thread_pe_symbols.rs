//! Minimal private subset of python `plugins/windows/pe_symbols.py` (`PESymbols`) used by the
//! thread plugins (thrdscan / threads / orphan_kernel_threads / suspended_threads /
//! debugregisters): VAD file ranges per process and address -> (file, symbol) resolution.
//!
//! TODO(dedupe): owned by W2b pe_symbols — replace every item here with the W2b port once it
//! lands on main.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::{LayerRef, Obj};
use crate::renderers::Value;
use crate::symbols::windows::prelude::*;
use crate::util::FxHashMap;

/// python `pe_symbols.range_type`: (start, size, file path).
// TODO(dedupe): owned by W2b pe_symbols
pub type Range = (u64, u64, String);

/// python `PESymbols.get_proc_vads_with_file_paths(proc)`: the process' VADs that map a file
/// (a path containing a backslash). An `Err` is python raising (e.g. a broken VAD walk).
// TODO(dedupe): owned by W2b pe_symbols
pub fn get_proc_vads_with_file_paths(proc: &Obj) -> Result<Vec<Range>> {
    let mut vads = Vec::new();
    let root = match proc.get_vad_root() {
        Ok(r) => r,
        Err(e) if e.is_invalid_address() => return Ok(vads),
        Err(e) => return Err(e),
    };
    for vad in root.traverse() {
        let vad = vad?;
        let Value::Str(path) = vad.get_file_name() else { continue };
        if !path.contains('\\') {
            continue;
        }
        vads.push((vad.get_start()?, vad.get_size()?, path));
    }
    Ok(vads)
}

/// python `PESymbols.range_info_for_address(ranges, address)`.
// TODO(dedupe): owned by W2b pe_symbols
pub fn range_info_for_address(ranges: &[Range], address: u64) -> Option<&Range> {
    ranges.iter().find(|(start, size, _)| *start as u128 <= address as u128 && (address as u128) < *start as u128 + *size as u128)
}

/// python `PESymbols.filepath_for_address(ranges, address)`.
// TODO(dedupe): owned by W2b pe_symbols
pub fn filepath_for_address(ranges: &[Range], address: u64) -> Option<&str> {
    range_info_for_address(ranges, address).map(|r| r.2.as_str())
}

/// python `PESymbols.filename_for_path(filepath)`: `ntpath.basename(filepath).lower()`.
// TODO(dedupe): owned by W2b pe_symbols
pub fn filename_for_path(filepath: &str) -> String {
    crate::plugins::windows::modules::ntpath_basename(filepath).to_lowercase()
}

/// python `collected_modules_type`: lower-case file name -> (process layer, start, size), in
/// python's dict order.
// TODO(dedupe): owned by W2b pe_symbols
#[derive(Default)]
pub struct CollectedModules {
    pub order: Vec<String>,
    pub map: FxHashMap<String, Vec<(LayerRef, u64, u64)>>,
}

/// python `PESymbols.get_process_modules(context, kernel_module_name, None)`: every file mapped
/// in every process (by file name), with the process layer and VAD range.
// TODO(dedupe): owned by W2b pe_symbols
pub fn get_process_modules(k: &WinKernel) -> Result<CollectedModules> {
    let _t = crate::util::trace::span("get_process_modules");
    let mut out = CollectedModules::default();
    let procs = crate::plugins::windows::pslist::list_processes(k, &|_| Ok(false));
    // the per-process VAD walks are independent: run them in parallel, merge in python's order
    let per = crate::util::par::par_map(procs.len(), |i| -> Option<Result<(LayerRef, Vec<Range>)>> {
        let proc = procs[i].as_ref().ok()?;
        let layer = match proc.add_process_layer() {
            Ok(l) => l,
            Err(e) if e.is_invalid_address() => return None,
            Err(e) => return Some(Err(e)),
        };
        Some(get_proc_vads_with_file_paths(proc).map(|v| (layer, v)))
    });
    for (p, r) in procs.into_iter().zip(per) {
        p?;
        let Some(r) = r else { continue };
        let (layer, vads) = r?;
        for (start, size, path) in vads {
            let name = filename_for_path(&path);
            let e = out.map.entry(name.clone()).or_default();
            if e.is_empty() {
                out.order.push(name);
            }
            e.push((layer, start, size));
        }
    }
    Ok(out)
}

/// python `PESymbols.path_and_symbol_for_address(context, config_path, collected_modules,
/// ranges, address)`: the file mapped at `address` and the symbol name there.
///
/// Known gap (TODO(dedupe): owned by W2b pe_symbols): the symbol lookup (python
/// `find_symbols`: the module's PDB, then its export table) is not ported here; the symbol is
/// always None.
pub fn path_and_symbol_for_address(_ctx: &Context, _collected: &CollectedModules, ranges: &[Range], address: u64) -> Result<(Option<String>, Option<String>)> {
    if address == 0 {
        return Ok((None, None));
    }
    let Some(filepath) = filepath_for_address(ranges, address) else { return Ok((None, None)) };
    Ok((Some(filepath.to_string()), None))
}
