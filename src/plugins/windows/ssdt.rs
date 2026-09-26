//! windows.ssdt.SSDT (python `plugins/windows/ssdt.py`) and the shared kernel-module
//! collection python builds with `SSDT.build_module_collection` (a `contexts.ModuleCollection`
//! of `SizedModule`s, one per loaded kernel module, all using the KERNEL symbol table).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! use crate::plugins::windows::ssdt::build_module_collection;
//! let coll = build_module_collection(k)?;
//! for (module_name, symbols) in coll.module_symbols(addr) {
//!     // python: for module_name, symbol_generator in
//!     //             collection.get_module_symbols_by_absolute_location(addr)
//! }
//! if coll.contains(addr) { /* python: list(...) is non-empty */ }
//! ```

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::windows::WinExt;

pub struct Ssdt;

/// One python `SizedModule` of a [`ModuleCollection`].
#[derive(Clone, Debug)]
pub struct CollectedModule {
    /// python `module.name` (`os.path.splitext(BaseDllName)[0]`, made unique by
    /// `context.modules.free_module_name`).
    pub name: String,
    /// python `module.offset` (`DllBase`).
    pub base: u64,
    /// python `module.size` (`SizeOfImage`).
    pub size: u64,
}

/// python `contexts.ModuleCollection` as returned by `SSDT.build_module_collection`: the
/// loaded kernel modules, each resolving symbols through the kernel symbol table relative to
/// its own base (python's quirk: a non-kernel module reports whatever kernel symbol sits at the
/// same relative offset).
#[derive(Clone, Debug)]
pub struct ModuleCollection {
    pub modules: Vec<CollectedModule>,
    table: TableRef,
}

impl ModuleCollection {
    /// A collection over explicit modules using `table` for symbol lookups.
    pub fn new(table: TableRef, modules: Vec<CollectedModule>) -> ModuleCollection {
        ModuleCollection { modules, table }
    }

    /// python `get_module_symbols_by_absolute_location(offset, size)`: `(module name, symbol
    /// names)` for every module whose `[base, base + size]` (inclusive) intersects
    /// `[offset, offset + size]`, in module order. Symbol names are without the table prefix
    /// (python's `symbol.split("!")[1]`).
    pub fn module_symbols_sized(&self, offset: u64, size: u64) -> Vec<(&str, Vec<&'static str>)> {
        let mut out = Vec::new();
        let off = offset as u128;
        for m in &self.modules {
            let (base, msize) = (m.base as u128, m.size as u128);
            if off <= base + msize && off + size as u128 >= base {
                // SizedModule.get_symbols_by_absolute_location
                let syms = if off > base + msize { Vec::new() } else { self.symbols_rel(offset.wrapping_sub(m.base), offset < m.base, size) };
                out.push((m.name.as_str(), syms));
            }
        }
        out
    }

    /// [`module_symbols_sized`](Self::module_symbols_sized) with python's default `size=0`.
    pub fn module_symbols(&self, offset: u64) -> Vec<(&str, Vec<&'static str>)> {
        self.module_symbols_sized(offset, 0)
    }

    /// True when some module contains `offset` (python: the lookup generator is non-empty).
    pub fn contains(&self, offset: u64) -> bool {
        let off = offset as u128;
        self.modules.iter().any(|m| off <= m.base as u128 + m.size as u128 && off >= m.base as u128)
    }

    /// python `symbol_space.get_symbols_by_location(rel, size, table)` (a negative relative
    /// offset only matches symbols in `[rel, rel + size]`, i.e. none with non-negative addresses
    /// unless `rel + size >= 0`).
    fn symbols_rel(&self, rel: u64, negative: bool, size: u64) -> Vec<&'static str> {
        if negative {
            // rel is (offset - base) < 0: python bisects to index 0 and yields symbols with
            // address <= rel + size
            let neg = rel.wrapping_neg(); // |offset - base|
            if size < neg {
                return Vec::new();
            }
            return self.table.symbols_at(0, size - neg);
        }
        self.table.symbols_at(rel, size)
    }
}

/// python `os.path.splitext(p)[0]` (posixpath: separator `/`, leading dots do not start an
/// extension).
pub fn splitext_root(p: &str) -> &str {
    let sep = p.rfind('/').map(|i| i as isize).unwrap_or(-1);
    let dot = p.rfind('.').map(|i| i as isize).unwrap_or(-1);
    if dot > sep {
        let bytes = p.as_bytes();
        let mut i = (sep + 1) as usize;
        while (i as isize) < dot {
            if bytes[i] != b'.' {
                return &p[..dot as usize];
            }
            i += 1;
        }
    }
    p
}

/// Regex metacharacters that make python's `re.match(rf"^{prefix}[0-9]*$", name)` differ from
/// a plain prefix test.
fn has_re_meta(s: &str) -> bool {
    s.chars().any(|c| ".^$*+?{}[]\\|()".contains(c))
}

/// python `ModuleContainer.free_module_name(prefix)` over `existing` module names: `prefix`
/// when no name matches `^{prefix}[0-9]*$`, else `prefix + str(n)` for the first unused
/// `n >= number of matches`. `Err` mirrors python's `re.error` on an invalid pattern.
pub fn free_module_name(existing: &[String], prefix: &str) -> Result<String> {
    let count = if has_re_meta(prefix) {
        let re = crate::cli::regex::Regex::new(&format!("^{prefix}[0-9]*$")).map_err(|e| Error::msg(format!("re.error: {e}")))?;
        existing.iter().filter(|n| re.match_prefix(n).is_some()).count()
    } else {
        existing
            .iter()
            .filter(|n| {
                let Some(rest) = n.strip_prefix(prefix) else { return false };
                // python `$` also matches before one trailing newline
                let rest = rest.strip_suffix('\n').unwrap_or(rest);
                rest.bytes().all(|b| b.is_ascii_digit())
            })
            .count()
    };
    if count == 0 {
        return Ok(prefix.to_string());
    }
    let mut n = count;
    loop {
        let cand = format!("{prefix}{n}");
        if !existing.iter().any(|e| *e == cand) {
            return Ok(cand);
        }
        n += 1;
    }
}

/// python `SSDT.build_module_collection(context, kernel_module_name)`: a [`ModuleCollection`]
/// of `Modules.list_modules` (modules with an unreadable `BaseDllName` are skipped; any other
/// error aborts, like python). Module names are made unique against the modules python's
/// context already holds (just `"kernel"` in a plain CLI run).
pub fn build_module_collection(k: &WinKernel) -> Result<ModuleCollection> {
    let _t = crate::util::trace::span("build_module_collection");
    let mut names: Vec<String> = vec!["kernel".to_string()];
    let mut mods = Vec::new();
    for m in super::modules::list_modules(k) {
        let m = m?;
        let with_ext = match m.m("BaseDllName")?.get_string() {
            Ok(n) => n,
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => return Err(e),
        };
        let base = m.m("DllBase")?.u64()?;
        let size = m.m("SizeOfImage")?.u64()?;
        let name = free_module_name(&names, splitext_root(&with_ext))?;
        names.push(name.clone());
        mods.push(CollectedModule { name, base, size });
    }
    Ok(ModuleCollection::new(k.table, mods))
}

/// The resolved service table: `(index, function address)` per entry; a trailing `Err` is
/// python raising while reading that element.
fn service_table(k: &WinKernel) -> Result<Vec<Result<(u64, u64)>>> {
    let table_addr = k.get_symbol("KiServiceTable")?.address;
    let limit_addr = k.get_symbol("KiServiceLimit")?.address;
    let limit = k.object("int", limit_addr)?.int()?;
    let is64 = k.table.is_64bit();
    let count = limit.max(0) as u64;
    // 64-bit: signed 32-bit offsets from the table; 32-bit: absolute pointers
    let arr = k.object("int", table_addr)?.cast_array_of(count, if is64 { "long" } else { "unsigned long" })?;
    let resolve = |raw: u32| -> u64 {
        if is64 {
            // python: kvo + service_table_address + (func >> 4) (arithmetic shift)
            (k.base as i128 + table_addr as i128 + ((raw as i32) >> 4) as i128) as u64
        } else {
            raw as u64
        }
    };
    let mut out = Vec::with_capacity(count as usize);
    let mut buf = vec![0u8; count as usize * 4];
    if k.vlayer.read(arr.addr, &mut buf).is_ok() {
        for (i, c) in buf.chunks_exact(4).enumerate() {
            out.push(Ok((i as u64, resolve(u32::from_le_bytes(c.try_into().unwrap())))));
        }
        return Ok(out);
    }
    for i in 0..count {
        match arr.at(i).and_then(|e| e.int()) {
            Ok(v) => out.push(Ok((i, resolve(v as u32)))),
            Err(e) => {
                out.push(Err(e));
                break;
            }
        }
    }
    Ok(out)
}

impl Plugin for Ssdt {
    fn name(&self) -> &'static str {
        "windows.ssdt.SSDT"
    }
    fn description(&self) -> &'static str {
        "Lists the system call table."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Index", ColType::Int),
            Column::new("Address", ColType::Hex),
            Column::new("Module", ColType::Str),
            Column::new("Symbol", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let collection = build_module_collection(k)?;
        for e in service_table(k)? {
            let (idx, function) = e?;
            for (module_name, syms) in collection.module_symbols(function) {
                if syms.is_empty() {
                    out.row(0, vec![Value::Int(idx as i128), Value::Int(function as i128), Value::str(module_name), Value::NotAvailable])?;
                }
                for s in syms {
                    out.row(0, vec![Value::Int(idx as i128), Value::Int(function as i128), Value::str(module_name), Value::str(s)])?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitext() {
        assert_eq!(splitext_root("ntoskrnl.exe"), "ntoskrnl");
        assert_eq!(splitext_root("a.b.sys"), "a.b");
        assert_eq!(splitext_root(".hidden"), ".hidden");
        assert_eq!(splitext_root("..x"), "..x");
        assert_eq!(splitext_root("noext"), "noext");
        assert_eq!(splitext_root("dir.d/file"), "dir.d/file");
        assert_eq!(splitext_root(""), "");
        assert_eq!(splitext_root("x."), "x");
    }

    #[test]
    fn free_names() {
        let mut ex = vec!["kernel".to_string()];
        assert_eq!(free_module_name(&ex, "ntoskrnl").unwrap(), "ntoskrnl");
        ex.push("ntoskrnl".into());
        assert_eq!(free_module_name(&ex, "ntoskrnl").unwrap(), "ntoskrnl1");
        ex.push("ntoskrnl1".into());
        assert_eq!(free_module_name(&ex, "ntoskrnl").unwrap(), "ntoskrnl2");
        ex.push("a1".into());
        assert_eq!(free_module_name(&ex, "a").unwrap(), "a2");
        assert_eq!(free_module_name(&ex, "a.").unwrap(), "a.1");
        ex.push("ab".into());
        assert_eq!(free_module_name(&ex, "a.").unwrap(), "a.2");
        assert_eq!(free_module_name(&ex, "b").unwrap(), "b");
    }
}
