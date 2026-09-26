//! windows.registry.getcellroutine.GetCellRoutine (python `plugins/windows/registry/
//! getcellroutine.py`): reports registry hives whose `_HHIVE.GetCellRoutine` handler is hooked
//! (points outside the kernel module).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::windows::modules::list_modules;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;

pub struct GetCellRoutine;

/// python `constants.windows.KERNEL_MODULE_NAMES`.
const KERNEL_MODULE_NAMES: [&str; 4] = ["ntkrnlmp", "ntkrnlpa", "ntkrpamp", "ntoskrnl"];

/// A module in the collection: uniquified name, base, size.
struct Mod {
    name: String,
    base: u64,
    size: u64,
}

/// python `os.path.splitext(name)[0]`.
fn splitext_stem(name: &str) -> &str {
    let b = name.as_bytes();
    let dot = name.rfind('.');
    if let Some(d) = dot {
        // an extension only if some char before the dot is not '.'
        if b[..d].iter().any(|&c| c != b'.') {
            return &name[..d];
        }
    }
    name
}

/// python `ssdt.SSDT.build_module_collection` — names uniquified like `free_module_name`.
fn build_modules(k: &crate::context::WinKernel) -> Vec<Mod> {
    let mut out: Vec<Mod> = Vec::new();
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in list_modules(k) {
        let Ok(m) = m else { continue };
        let name_with_ext = match m.m("BaseDllName").and_then(|n| n.get_string()) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let stem = splitext_stem(&name_with_ext).to_string();
        let name = if used.contains(&stem) {
            let mut c = used.len();
            while used.contains(&format!("{stem}{c}")) {
                c += 1;
            }
            format!("{stem}{c}")
        } else {
            stem
        };
        used.insert(name.clone());
        let (Ok(base), Ok(size)) = (m.m("DllBase").and_then(|o| o.u64()), m.m("SizeOfImage").and_then(|o| o.u64())) else { continue };
        out.push(Mod { name, base, size });
    }
    out
}

impl Plugin for GetCellRoutine {
    fn name(&self) -> &'static str {
        "windows.registry.getcellroutine.GetCellRoutine"
    }
    fn description(&self) -> &'static str {
        "Reports registry hives with a hooked GetCellRoutine handler"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Hive Offset", ColType::Hex),
            Column::new("Hive Name", ColType::Str),
            Column::new("GetCellRoutine Module", ColType::Str),
            Column::new("GetCellRoutine Handler", ColType::Hex),
        ])?;
        let k = ctx.windows_kernel()?;
        let mods = build_modules(k);
        for hive in super::hivelist::list_hives(ctx, k, None, None) {
            let hive = hive?;
            let cellroutine = match hive.hive().m("GetCellRoutine").and_then(|o| o.u64()) {
                Ok(v) => v,
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            };
            let name = Value::Str(crate::symbols::windows::registry::cmhive_get_name(&hive.cmhive()).unwrap_or_default());
            let matches: Vec<&Mod> = mods.iter().filter(|m| m.base <= cellroutine && cellroutine <= m.base + m.size).collect();
            if matches.is_empty() {
                out.row(0, vec![Value::Int(hive.hive_offset() as i128), name.clone(), Value::NotAvailable, Value::Int(cellroutine as i128)])?;
            } else {
                for m in matches {
                    if !KERNEL_MODULE_NAMES.contains(&m.name.as_str()) {
                        out.row(0, vec![Value::Int(hive.hive_offset() as i128), name.clone(), Value::Str(m.name.clone()), Value::Int(cellroutine as i128)])?;
                    }
                }
            }
        }
        Ok(())
    }
}
