//! windows.pe_symbols.PESymbols (python `plugins/windows/pe_symbols.py`) and its symbol
//! resolution API, used by many other plugins (etwpatch, debugregisters, unhooked system
//! calls, ...).
//!
//! Symbols of a PE module (a kernel module or a file-backed process VAD) are resolved first
//! through the module's PDB (`PDBUtility.symbol_table_from_pdb`), then through its export table
//! (the image reconstructed from memory and parsed like `pefile`), trying every place the
//! module was found until everything wanted is resolved -- in python's exact order.
//!
//! ```ignore
//! use crate::plugins::windows::pe_symbols::{self, WantedSymbols};
//! let wanted = vec![("ntdll.dll".to_string(), WantedSymbols::names(&["NtCreateFile"]))];
//! let found = pe_symbols::addresses_for_process_symbols(ctx, k, &wanted)?;
//! for (module, symbols) in &found { for (name, addr) in symbols { .. } }
//!
//! // file path + symbol of an address inside a process (debugregisters style)
//! let collected = pe_symbols::get_process_modules(k, None)?;
//! let ranges = pe_symbols::get_proc_vads_with_file_paths(&proc)?;
//! let (path, sym) = pe_symbols::path_and_symbol_for_address(ctx, &collected, &ranges, addr)?;
//! ```
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::objects::{LayerRef, Module, Obj, Space};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::windows::pefile::{Export, PeError, PeFile};
use crate::symbols::windows::prelude::*;
use crate::symbols::windows::pe;
use crate::automagic::windows::PdbSig;
use crate::util::FxHashMap;

pub struct PESymbols;

/// python `wanted_names_identifier`.
pub const WANTED_NAMES_IDENTIFIER: &str = "names";
/// python `wanted_addresses_identifier`.
pub const WANTED_ADDRESSES_IDENTIFIER: &str = "addresses";

/// python `PESymbols.os_module_name`: special handling of the kernel's PDB names.
pub const OS_MODULE_NAME: &str = "ntoskrnl.exe";

/// python `constants.windows.KERNEL_MODULE_NAMES`.
pub const KERNEL_MODULE_NAMES: [&str; 4] = ["ntkrnlmp", "ntkrnlpa", "ntkrpamp", "ntoskrnl"];

/// What to resolve in one module (python `filter_module_info`: a dict with a `"names"` and/or
/// an `"addresses"` list; names are looked up first).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WantedSymbols {
    /// `{"names": [...]}`: symbol names to resolve to addresses.
    pub names: Option<Vec<String>>,
    /// `{"addresses": [...]}`: addresses to resolve to symbol names.
    pub addresses: Option<Vec<u64>>,
}

impl WantedSymbols {
    /// `{"names": names}`
    pub fn names(names: &[&str]) -> WantedSymbols {
        WantedSymbols { names: Some(names.iter().map(|s| s.to_string()).collect()), addresses: None }
    }
    /// `{"addresses": addresses}`
    pub fn addresses(addresses: &[u64]) -> WantedSymbols {
        WantedSymbols { names: None, addresses: Some(addresses.to_vec()) }
    }
    fn is_empty(&self) -> bool {
        self.names.is_none() && self.addresses.is_none()
    }
}

/// python `filter_modules_type` (an insertion-ordered dict): lower-case module file name ->
/// wanted symbols.
pub type FilterModules = Vec<(String, WantedSymbols)>;

/// python `found_symbols_type`: module -> [(symbol name, address)] in resolution order.
pub type FoundSymbols = Vec<(String, Vec<(String, u64)>)>;

/// python `range_type`: (start, size, file path) of a VAD mapping a file.
pub type Range = (u64, u64, String);

/// python `collected_module_instance`: (layer, start, size) where a module was found.
#[derive(Clone, Copy)]
pub struct ModuleInstance {
    pub layer: LayerRef,
    pub start: u64,
    pub size: u64,
}

/// python `collected_modules_type`: module file name (lower case) -> every place it was found,
/// in discovery order.
pub type CollectedModules = FxHashMap<String, Vec<ModuleInstance>>;

/// python `PESymbols.range_info_for_address(ranges, address)`.
pub fn range_info_for_address(ranges: &[Range], address: u64) -> Option<&Range> {
    ranges.iter().find(|(start, size, _)| *start as u128 <= address as u128 && (address as u128) < *start as u128 + *size as u128)
}

/// python `PESymbols.filepath_for_address(ranges, address)`.
pub fn filepath_for_address(ranges: &[Range], address: u64) -> Option<&str> {
    range_info_for_address(ranges, address).map(|r| r.2.as_str())
}

/// python `PESymbols.filename_for_path(filepath)`: `ntpath.basename(filepath).lower()`.
pub fn filename_for_path(filepath: &str) -> String {
    super::modules::ntpath_basename(filepath).to_lowercase()
}

/// A symbol resolver for one place a module was found (python `PDBSymbolFinder` /
/// `ExportSymbolFinder`).
enum Finder {
    /// the module's PDB symbols, based at the module start
    Pdb(Module),
    /// the module's export table (`pefile` ExportData list)
    Exports { start: u64, exports: Vec<Export> },
}

impl Finder {
    /// python `get_address_for_name(name)`.
    fn address_for_name(&self, name: &str) -> Result<Option<u128>> {
        match self {
            Finder::Pdb(m) => match m.get_symbol(name) {
                Ok(s) => Ok(Some(m.offset as u128 + s.address as u128)),
                Err(Error::Symbol(_)) => Ok(None),
                Err(e) => Err(e),
            },
            Finder::Exports { start, exports } => {
                for e in exports {
                    // export.name.decode("ascii") (AttributeError -> None for ordinal-only)
                    if let Some(n) = &e.name {
                        if !n.is_empty() && n.as_slice() == name.as_bytes() {
                            return match e.address {
                                Some(a) => Ok(Some(*start as u128 + a as u128)),
                                None => Err(Error::msg("TypeError: unsupported operand type(s) for +: 'int' and 'NoneType'")),
                            };
                        }
                    }
                }
                Ok(None)
            }
        }
    }

    /// python `get_name_for_address(address)`.
    fn name_for_address(&self, address: u64) -> Result<Option<String>> {
        match self {
            Finder::Pdb(m) => Ok(m.symbols_at(address, 0).first().map(|n| n.split('!').next().unwrap_or("").to_string())),
            Finder::Exports { start, exports } => {
                for e in exports {
                    let Some(a) = e.address else {
                        return Err(Error::msg("TypeError: unsupported operand type(s) for +: 'NoneType' and 'int'"));
                    };
                    if a as u128 + *start as u128 == address as u128 {
                        return Ok(e.name.as_ref().map(|n| String::from_utf8_lossy(n).into_owned()));
                    }
                }
                Ok(None)
            }
        }
    }
}

/// python `PESymbols.get_pefile_obj(...)` + `parse_data_directories([EXPORT])`: the exports of
/// the PE at `base`. `Ok(None)`: no PE (InvalidAddressException / ValueError) or no export
/// directory; `Err`: an exception python does not catch here.
pub fn get_exports(pe_table: TableRef, layer: LayerRef, base: u64) -> Result<Option<Vec<Export>>> {
    let dos = Obj::named(Space::on(layer, pe_table), "_IMAGE_DOS_HEADER", base)?;
    let (view, err) = pe::reconstruct_view(&dos);
    if let Some(e) = err {
        if e.is_invalid_or_value() {
            return Ok(None);
        }
        return Err(Error::msg(e.to_string()));
    }
    let pe = match PeFile::parse(&view) {
        Ok(p) => p,
        Err(PeError::Format(m)) => return Err(Error::msg(format!("PEFormatError: {m}"))),
        Err(e) => return Err(Error::msg(e.to_string())),
    };
    Ok(pe.parse_exports().map(|d| d.symbols))
}

/// The PDB file names python tries for a module (`PESymbols._get_pdb_module`): the kernel
/// names for `ntoskrnl.exe`, else `name[:-3] + "pdb"` and the same with its first character
/// upper-cased.
fn pdb_candidates(mod_name: &str) -> Vec<String> {
    if mod_name == OS_MODULE_NAME {
        return KERNEL_MODULE_NAMES.iter().map(|n| format!("{n}.pdb")).collect();
    }
    let chars: Vec<char> = mod_name.chars().collect();
    let keep = chars.len().saturating_sub(3);
    let lower: String = chars[..keep].iter().collect::<String>() + "pdb";
    let mut it = lower.chars();
    let first_upper = match it.next() {
        Some(c) => c.to_uppercase().collect::<String>() + it.as_str(),
        None => String::new(),
    };
    vec![lower, first_upper]
}

/// python `PDBUtility.pdbname_scan(...)` over one module instance: the first RSDS record
/// naming `pdb_name` (what `symbol_table_from_pdb` uses).
fn scan_pdb_name(inst: &ModuleInstance, pdb_name: &str) -> Option<PdbSig> {
    let mut first = None;
    crate::automagic::windows::pdbname_scan(inst.layer, &[pdb_name.as_bytes()], Some(inst.start), Some(inst.start.wrapping_add(inst.size)), |s| {
        first = Some(s);
        false
    });
    first
}

/// The pure (memory-scanning) part of `_get_pdb_module` for one instance: the scan result of
/// each candidate name, up to the first one that found an RSDS record.
fn scan_pdb_names(inst: &ModuleInstance, names: &[String]) -> Vec<Option<PdbSig>> {
    let mut out = Vec::new();
    for n in names {
        let s = scan_pdb_name(inst, n);
        let hit = s.is_some();
        out.push(s);
        if hit {
            break;
        }
    }
    out
}

/// python `PESymbols._get_pdb_module(...)` given the scan results of [`scan_pdb_names`]: load
/// (or download) the symbol table of the first candidate that works.
fn pdb_module_from_scans(ctx: &Context, inst: &ModuleInstance, names: &[String], scans: &[Option<PdbSig>]) -> Option<Module> {
    for (j, name) in names.iter().enumerate() {
        let sig = match scans.get(j) {
            Some(s) => s.clone(),
            None => scan_pdb_name(inst, name),
        };
        // SymbolSpaceError (no GUID in the module / no symbols for it) -> next name
        let Some(sig) = sig else { continue };
        if let Ok(t) = ctx.load_windows_pdb(&sig.pdb_name, &sig.guid, sig.age) {
            return Some(Module::new(inst.layer, t, inst.start));
        }
    }
    None
}

/// How many module instances are prepared ahead of python's sequential walk.
fn lookahead() -> usize {
    crate::util::par::threads().max(2)
}

/// python `PESymbols._resolve_symbols_through_methods(...)`: resolve `wanted` in every
/// instance of `mod_name`, PDBs first then export tables, stopping as soon as one kind of
/// wanted value is exhausted. Returns (found, remaining). The per-instance work (PDB name
/// scans, export table parsing) runs ahead in parallel; results are consumed in python's
/// order.
fn resolve_symbols_through_methods(ctx: &Context, instances: &[ModuleInstance], wanted: &WantedSymbols, mod_name: &str) -> Result<(Vec<(String, u64)>, WantedSymbols)> {
    let mut found: Vec<(String, u64)> = Vec::new();
    let mut remaining = wanted.clone();
    let pe_table = ctx.load_isf("windows/pe")?;
    let names = pdb_candidates(mod_name);
    let mut done = false;
    let mut err: Option<Error> = None;
    crate::util::par::par_map_stream(
        instances.len(),
        lookahead(),
        |i| scan_pdb_names(&instances[i], &names),
        |i, scans| {
            let Some(m) = pdb_module_from_scans(ctx, &instances[i], &names, &scans) else { return true };
            match get_symbol_values(&mut remaining, &Finder::Pdb(m), &mut found) {
                Ok(false) => true,
                Ok(true) => {
                    done = true;
                    false
                }
                Err(e) => {
                    err = Some(e);
                    false
                }
            }
        },
    );
    if let Some(e) = err {
        return Err(e);
    }
    if done {
        return Ok((found, remaining));
    }
    crate::util::par::par_map_stream(
        instances.len(),
        lookahead(),
        |i| get_exports(pe_table, instances[i].layer, instances[i].start),
        |i, r| {
            let exports = match r {
                Ok(Some(e)) => e,
                Ok(None) => return true,
                Err(e) => {
                    err = Some(e);
                    return false;
                }
            };
            match get_symbol_values(&mut remaining, &Finder::Exports { start: instances[i].start, exports }, &mut found) {
                Ok(false) => true,
                Ok(true) => false,
                Err(e) => {
                    err = Some(e);
                    false
                }
            }
        },
    );
    if let Some(e) = err {
        return Err(e);
    }
    Ok((found, remaining))
}

/// python `PESymbols._get_symbol_value(wanted, resolver)` driven by the caller's loop:
/// records found symbols, removes them from `remaining`; true = a wanted list ran empty
/// (python's `done_processing`).
fn get_symbol_values(remaining: &mut WantedSymbols, finder: &Finder, found: &mut Vec<(String, u64)>) -> Result<bool> {
    if remaining.is_empty() {
        return Ok(false); // python warns and yields nothing
    }
    if let Some(names) = &remaining.names {
        let all_wanted = names.clone();
        for name in all_wanted {
            if let Some(addr) = finder.address_for_name(&name)? {
                if addr != 0 {
                    found.push((name.clone(), addr as u64));
                    let list = remaining.names.as_mut().unwrap();
                    if let Some(i) = list.iter().position(|n| *n == name) {
                        list.remove(i);
                    }
                    if list.is_empty() {
                        remaining.names = None;
                        return Ok(true);
                    }
                }
            }
        }
    }
    if let Some(addrs) = &remaining.addresses {
        let all_wanted = addrs.clone();
        for addr in all_wanted {
            if let Some(name) = finder.name_for_address(addr)? {
                if !name.is_empty() {
                    found.push((name, addr));
                    let list = remaining.addresses.as_mut().unwrap();
                    if let Some(i) = list.iter().position(|a| *a == addr) {
                        list.remove(i);
                    }
                    if list.is_empty() {
                        remaining.addresses = None;
                        return Ok(true);
                    }
                }
            }
        }
    }
    Ok(false)
}

/// python `PESymbols.find_symbols(context, config_path, wanted_modules, collected_modules)`:
/// (found symbols, missing symbols) per module, in `wanted` order.
pub fn find_symbols(ctx: &Context, wanted: &FilterModules, collected: &CollectedModules) -> Result<(FoundSymbols, FilterModules)> {
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for (mod_name, w) in wanted {
        let Some(instances) = collected.get(mod_name) else { continue };
        let (f, m) = resolve_symbols_through_methods(ctx, instances, w, mod_name)?;
        if !f.is_empty() {
            found.push((mod_name.clone(), f));
        }
        if !m.is_empty() {
            missing.push((mod_name.clone(), m));
        }
    }
    Ok((found, missing))
}

/// The lower-case module names of a filter (python's `endswith` tuple).
fn filter_check(filter: Option<&FilterModules>) -> Option<Vec<String>> {
    match filter {
        Some(f) if !f.is_empty() => Some(f.iter().map(|(k, _)| k.to_lowercase()).collect()),
        _ => None,
    }
}

/// python `PESymbols.get_kernel_modules(context, kernel, filter_modules)`: session layer,
/// base and size of each wanted kernel module (the first module is `ntoskrnl.exe` when
/// asked for).
pub fn get_kernel_modules(k: &WinKernel, filter: Option<&FilterModules>) -> Result<CollectedModules> {
    let check = filter_check(filter);
    let session_layers = super::modules::get_session_layers(k, &[])?;
    let gather_kernel = check.as_ref().map(|c| c.iter().any(|n| n == OS_MODULE_NAME)).unwrap_or(false);
    let mut found: CollectedModules = FxHashMap::default();
    for (index, m) in super::modules::list_modules(k).into_iter().enumerate() {
        let m = m?;
        let mut mod_name = match m.m("BaseDllName")?.get_string() {
            Ok(n) => n.to_lowercase(),
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => return Err(e),
        };
        match &check {
            None => mod_name = OS_MODULE_NAME.to_string(),
            Some(_) if gather_kernel && index == 0 => mod_name = OS_MODULE_NAME.to_string(),
            Some(c) => {
                if !c.iter().any(|s| mod_name.ends_with(s.as_str())) {
                    continue;
                }
            }
        }
        let base = m.m("DllBase")?.u64()?;
        let Some(layer) = super::modules::find_session_layer(&session_layers, base) else { continue };
        let size = m.m("SizeOfImage")?.u64()?;
        found.entry(mod_name).or_default().push(ModuleInstance { layer, start: base, size });
    }
    Ok(found)
}

/// python `PESymbols.get_proc_vads_with_file_paths(proc)`: the process's VADs that map a file
/// (a path containing a backslash).
pub fn get_proc_vads_with_file_paths(proc: &Obj) -> Result<Vec<Range>> {
    let root = match proc.get_vad_root() {
        Ok(r) => r,
        Err(e) if e.is_invalid_address() => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut vads = Vec::new();
    for v in root.traverse() {
        let vad = v?;
        let path = match vad.get_file_name() {
            Value::Str(s) => s,
            _ => continue,
        };
        if !path.contains('\\') {
            continue;
        }
        vads.push((vad.get_start()?, vad.get_size()?, path));
    }
    Ok(vads)
}

/// python `PESymbols.get_vads_for_process_cache(vads_cache, owner_proc)`: the file-mapping
/// VADs of a process, cached by EPROCESS address; None for processes without any.
pub fn get_vads_for_process_cache<'c>(cache: &'c mut FxHashMap<u64, Vec<Range>>, proc: &Obj) -> Result<Option<&'c Vec<Range>>> {
    if !cache.contains_key(&proc.addr) {
        let v = get_proc_vads_with_file_paths(proc)?;
        cache.insert(proc.addr, v);
    }
    let v = &cache[&proc.addr];
    Ok(if v.is_empty() { None } else { Some(v) })
}

/// python `PESymbols.get_all_vads_with_file_paths(context, kernel)`: (process, process layer,
/// file-mapping VADs) for every process whose layer can be built. A trailing `Err` marks
/// where python raised.
pub fn get_all_vads_with_file_paths(k: &WinKernel) -> Vec<Result<(Obj, LayerRef, Vec<Range>)>> {
    let procs = super::pslist::list_processes(k, &|_| Ok(false));
    // independent per process: walk the VAD trees in parallel, keep python's order
    let per: Vec<Option<Result<(Obj, LayerRef, Vec<Range>)>>> = crate::util::par::par_map(procs.len(), |i| {
        let proc = match &procs[i] {
            Ok(p) => *p,
            Err(_) => return None,
        };
        let layer = match proc.add_process_layer() {
            Ok(l) => l,
            Err(e) if e.is_invalid_address() => return None,
            Err(e) => return Some(Err(e)),
        };
        Some(get_proc_vads_with_file_paths(&proc).map(|v| (proc, layer, v)))
    });
    let mut out = Vec::new();
    for (p, r) in procs.into_iter().zip(per) {
        if let Err(e) = p {
            out.push(Err(e));
            break;
        }
        match r {
            None => {}
            Some(Ok(v)) => out.push(Ok(v)),
            Some(Err(e)) => {
                out.push(Err(e));
                break;
            }
        }
    }
    out
}

/// python `PESymbols.get_process_modules(context, kernel, filter_modules)`: every file-mapping
/// VAD of every process, keyed by lower-case file name (filtered with python's `endswith`).
pub fn get_process_modules(k: &WinKernel, filter: Option<&FilterModules>) -> Result<CollectedModules> {
    get_process_modules_cached(k, filter, &mut FxHashMap::default())
}

/// [`get_process_modules`] sharing python's `vads_cache` dict (see
/// [`get_vads_for_process_cache`]): the file-mapping VADs of processes already in the cache
/// are reused and the others are added to it (a process' VADs are the same whoever asks, so
/// plugins that use both avoid walking every VAD tree twice).
pub fn get_process_modules_cached(k: &WinKernel, filter: Option<&FilterModules>, vads_cache: &mut FxHashMap<u64, Vec<Range>>) -> Result<CollectedModules> {
    let check = filter_check(filter);
    let procs = super::pslist::list_processes(k, &|_| Ok(false));
    // independent per process: walk the uncached VAD trees in parallel, merge in python's order
    let cache: &FxHashMap<u64, Vec<Range>> = vads_cache;
    let per = crate::util::par::par_map(procs.len(), |i| -> Option<Result<(LayerRef, Option<Vec<Range>>)>> {
        let proc = procs[i].as_ref().ok()?;
        let layer = match proc.add_process_layer() {
            Ok(l) => l,
            Err(e) if e.is_invalid_address() => return None,
            Err(e) => return Some(Err(e)),
        };
        if cache.contains_key(&proc.addr) {
            return Some(Ok((layer, None)));
        }
        Some(get_proc_vads_with_file_paths(proc).map(|v| (layer, Some(v))))
    });
    let mut found: CollectedModules = FxHashMap::default();
    for (p, r) in procs.into_iter().zip(per) {
        let proc = p?;
        let Some(r) = r else { continue };
        let (layer, computed) = r?;
        if let Some(v) = computed {
            vads_cache.insert(proc.addr, v);
        }
        for (start, size, path) in &vads_cache[&proc.addr] {
            let name = filename_for_path(path);
            if let Some(c) = &check {
                if !c.iter().any(|s| name.ends_with(s.as_str())) {
                    continue;
                }
            }
            found.entry(name).or_default().push(ModuleInstance { layer, start: *start, size: *size });
        }
    }
    Ok(found)
}

/// python `PESymbols.addresses_for_process_symbols(context, config_path, kernel, symbols)`.
pub fn addresses_for_process_symbols(ctx: &Context, k: &WinKernel, symbols: &FilterModules) -> Result<FoundSymbols> {
    let collected = get_process_modules(k, Some(symbols))?;
    Ok(find_symbols(ctx, symbols, &collected)?.0)
}

/// python `PESymbols.path_and_symbol_for_address(context, config_path, collected_modules,
/// ranges, address)`: (file path, symbol name) for an address inside `ranges`.
pub fn path_and_symbol_for_address(ctx: &Context, collected: &CollectedModules, ranges: &[Range], address: u64) -> Result<(Option<String>, Option<String>)> {
    if address == 0 {
        return Ok((None, None));
    }
    let Some(filepath) = filepath_for_address(ranges, address) else { return Ok((None, None)) };
    if filepath.is_empty() {
        return Ok((None, None));
    }
    let filename = filename_for_path(filepath);
    let wanted: FilterModules = vec![(filename.clone(), WantedSymbols::addresses(&[address]))];
    let (found, _missing) = find_symbols(ctx, &wanted, collected)?;
    match found.iter().find(|(m, _)| *m == filename) {
        Some((_, syms)) if !syms.is_empty() => Ok((Some(filepath.to_string()), Some(syms[0].0.clone()))),
        _ => Ok((Some(filepath.to_string()), None)),
    }
}

impl Plugin for PESymbols {
    fn name(&self) -> &'static str {
        "windows.pe_symbols.PESymbols"
    }
    fn description(&self) -> &'static str {
        "Prints symbols in PE files in process and kernel memory"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("source", "Where to resolve symbols.", ReqKind::Choice(vec!["kernel", "processes"])),
            Requirement::new("module", "Module in which to resolve symbols. Use \"ntoskrnl.exe\" to resolve in the base kernel executable.", ReqKind::Str),
            Requirement::new("symbols", "Symbol name to resolve", ReqKind::ListStr).optional(),
            Requirement::new("addresses", "Address of symbol to resolve", ReqKind::ListInt).optional(),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("Module", ColType::Str), Column::new("Symbol", ColType::Str), Column::new("Address", ColType::Hex)])?;
        let k = ctx.windows_kernel()?;
        let module = cfg.get_str("module").unwrap_or("").to_lowercase();
        let symbols = cfg.get_strs("symbols");
        let addresses: Vec<u64> = cfg.get_ints("addresses").into_iter().map(|a| a as u64).collect();
        let wanted = if !symbols.is_empty() {
            WantedSymbols { names: Some(symbols), addresses: None }
        } else if !addresses.is_empty() {
            WantedSymbols { names: None, addresses: Some(addresses) }
        } else {
            // vollog.error("--address or --symbol must be specified")
            return Ok(());
        };
        let filter: FilterModules = vec![(module, wanted)];
        let collected = if cfg.get_str("source") == Some("kernel") { get_kernel_modules(k, Some(&filter))? } else { get_process_modules(k, Some(&filter))? };
        let (found, _missing) = find_symbols(ctx, &filter, &collected)?;
        for (module, syms) in found {
            for (sym, addr) in syms {
                out.row(0, vec![Value::Str(module.clone()), Value::Str(sym), Value::Int(addr as i128)])?;
            }
        }
        Ok(())
    }
}
