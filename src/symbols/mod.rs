//! Symbols: ISF loading into flat, cached [`SymbolTable`]s, symbol file discovery, the global
//! symbol space (tables by name, python `context.symbol_space`), and OS-specific helpers
//! (`windows` class extensions, `linux` / `mac` helpers).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Tables live for the whole process (`&'static SymbolTable`): objects reference them without
//! lifetimes. Register a table with [`register`] (done by the `Context` loaders).

pub mod embedded;
pub mod isf;
pub(crate) mod lazy;
pub(crate) mod stream;
pub mod linux;
pub mod mac;
pub mod pycache;
pub mod store;
pub mod table;
pub mod windows;
pub mod zipfile;

pub use isf::BuildOptions;
pub use store::{IsfLocation, SymbolPath};
pub use table::{Member, PdbInfo, Prim, PrimKind, StrEnc, StrErrors, Symbol, SymbolTable, Ty, TypeIdx, UserKind};

use crate::util::FxHashMap;
use std::sync::Mutex;

/// A registered, process-lifetime symbol table.
pub type TableRef = &'static SymbolTable;

static SPACE: Mutex<Option<FxHashMap<String, TableRef>>> = Mutex::new(None);

/// Register `table` in the global symbol space under a free name derived from `prefix`
/// (python `symbol_space.free_table_name(prefix)`: `prefix1`, `prefix2`, ...) and return the
/// leaked `'static` table.
pub fn register(mut table: SymbolTable, prefix: &str) -> TableRef {
    let mut g = SPACE.lock().unwrap();
    let map = g.get_or_insert_with(Default::default);
    let mut n = 1;
    while map.contains_key(&format!("{prefix}{n}")) {
        n += 1;
    }
    let name = format!("{prefix}{n}");
    table.set_name(&name);
    let t: TableRef = Box::leak(Box::new(table));
    map.insert(name, t);
    t
}

/// Register under an exact name (replacing nothing: fails if taken).
pub fn register_as(mut table: SymbolTable, name: &str) -> Option<TableRef> {
    let mut g = SPACE.lock().unwrap();
    let map = g.get_or_insert_with(Default::default);
    if map.contains_key(name) {
        return None;
    }
    table.set_name(name);
    let t: TableRef = Box::leak(Box::new(table));
    map.insert(name.to_string(), t);
    Some(t)
}

/// Look up a registered table by name.
pub fn table(name: &str) -> Option<TableRef> {
    SPACE.lock().unwrap().as_ref().and_then(|m| m.get(name).copied())
}

static PATH: std::sync::RwLock<Option<&'static SymbolPath>> = std::sync::RwLock::new(None);

/// Set the process-wide symbol search path (python `volatility3.symbols.__path__`). The
/// `Context` does this from `-s`. A different path replaces the previous one (tables loaded
/// through the old path stay registered; `load_isf` memoizes per path).
pub fn set_symbol_path(p: SymbolPath) {
    let mut w = PATH.write().unwrap_or_else(|e| e.into_inner());
    if w.is_some_and(|c| *c == p) {
        return;
    }
    *w = Some(Box::leak(Box::new(p)));
}

/// The process-wide symbol search path (default: no `-s` dirs).
pub fn symbol_path() -> &'static SymbolPath {
    if let Some(p) = *PATH.read().unwrap_or_else(|e| e.into_inner()) {
        return p;
    }
    let mut w = PATH.write().unwrap_or_else(|e| e.into_inner());
    *w.get_or_insert_with(|| Box::leak(Box::new(SymbolPath::new(&[]))))
}

static REMOTE: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// python `constants.REMOTE_ISF_URL` (`-u/--remote-isf-url`); python ignores it when
/// `--offline`, so `offline` clears it.
pub fn set_remote_isf_url(url: Option<String>, offline: bool) {
    *REMOTE.write().unwrap_or_else(|e| e.into_inner()) = url.filter(|_| !offline);
}

/// The remote identifier list URL in effect (None when unset or offline).
pub fn remote_isf_url() -> Option<String> {
    REMOTE.read().unwrap_or_else(|e| e.into_inner()).clone()
}

static LOADED: Mutex<Option<FxHashMap<String, TableRef>>> = Mutex::new(None);

/// python `IntermediateSymbolTable.create(context, config_path, sub_path, filename,
/// native_types=..., table_mapping=...)`, memoized: the same request returns the same table.
///
/// `natives`: use another table's native types (python `native_types=kernel natives`).
/// `mapping`: python `table_mapping`, e.g. `&[("nt_symbols", kernel.name())]`.
///
/// ```ignore
/// let pe = symbols::load_isf("windows", "pe", None, &[])?;
/// ```
pub fn load_isf(sub_path: &str, filename: &str, natives: Option<TableRef>, mapping: &[(&str, &str)]) -> crate::error::Result<TableRef> {
    let path = symbol_path();
    let key = format!(
        "{:p}|{sub_path}/{filename}|{}|{}",
        path,
        natives.map(|n| n.name()).unwrap_or(""),
        mapping.iter().map(|(a, b)| format!("{a}={b}")).collect::<Vec<_>>().join(",")
    );
    if let Some(t) = LOADED.lock().unwrap().as_ref().and_then(|m| m.get(&key).copied()) {
        return Ok(t);
    }
    let opts = BuildOptions { natives: natives.map(|n| n.natives().into_iter().map(|(a, b)| (a, b)).collect()) };
    let mut t = store::load_named(path, sub_path, filename, filename, &opts)?;
    t.set_table_mapping(mapping);
    let base = std::path::Path::new(filename).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| filename.to_string());
    let t = register(t, &base);
    LOADED.lock().unwrap().get_or_insert_with(Default::default).insert(key, t);
    Ok(t)
}

/// Load a table from an explicit location and register it (python `IntermediateSymbolTable(isf_url=...)`).
pub fn load_location(loc: &IsfLocation, prefix: &str, natives: Option<TableRef>, symbol_mask: u64) -> crate::error::Result<TableRef> {
    let key = format!("@{}|{}|{symbol_mask}", loc.url(), natives.map(|n| n.name()).unwrap_or(""));
    if let Some(t) = LOADED.lock().unwrap().as_ref().and_then(|m| m.get(&key).copied()) {
        return Ok(t);
    }
    let opts = BuildOptions { natives: natives.map(|n| n.natives()) };
    let mut t = store::load(loc, prefix, &opts)?;
    t.set_symbol_mask(symbol_mask);
    let t = register(t, prefix);
    LOADED.lock().unwrap().get_or_insert_with(Default::default).insert(key, t);
    Ok(t)
}

/// Register a table built elsewhere (e.g. speculatively on another thread) exactly as
/// [`load_location`] would have loaded it: same memo key, same registered name. A table for
/// that key already registered wins (the built one is dropped).
pub fn adopt_location(loc: &IsfLocation, prefix: &str, natives: Option<TableRef>, symbol_mask: u64, mut t: SymbolTable) -> TableRef {
    let key = format!("@{}|{}|{symbol_mask}", loc.url(), natives.map(|n| n.name()).unwrap_or(""));
    if let Some(t) = LOADED.lock().unwrap().as_ref().and_then(|m| m.get(&key).copied()) {
        return t;
    }
    t.set_symbol_mask(symbol_mask);
    let t = register(t, prefix);
    LOADED.lock().unwrap().get_or_insert_with(Default::default).insert(key, t);
    t
}

/// Resolve a `table!type` reference from `from` (through its table mapping) to a registered
/// table and type.
pub fn resolve_ref(from: TableRef, name: &str) -> Option<(TableRef, Ty)> {
    match name.split_once('!') {
        Some((prefix, tname)) => {
            let t = table(from.map_table_name(prefix))?;
            t.get_type(tname).ok().map(|ty| (t, ty))
        }
        None => from.get_type(name).ok().map(|ty| (from, ty)),
    }
}
