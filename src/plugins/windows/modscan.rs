//! windows.modscan.ModScan (python `plugins/windows/modscan.py`): `Modules` with the module
//! list replaced by a pool scan for `MmLd` (`_LDR_DATA_TABLE_ENTRY`) allocations.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::Obj;
use crate::plugins::windows::modules;
use crate::plugins::windows::poolscanner::{builtin_constraints, generate_pool_scan_each};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::RowSink;

pub struct ModScan;

/// python `ModScan.scan_modules(context, kernel_module_name)` (a trailing `Err` = python
/// raised there).
pub fn scan_modules(ctx: &Context, k: &WinKernel) -> Vec<Result<Obj>> {
    let constraints = builtin_constraints(k.table.name(), &[b"MmLd"]);
    let mut v = Vec::new();
    if let Err(e) = generate_pool_scan_each(ctx, k, k.table, &constraints, |hit| {
        v.push(Ok(hit.object));
        Ok(true)
    }) {
        v.push(Err(e));
    }
    v
}

impl Plugin for ModScan {
    fn name(&self) -> &'static str {
        "windows.modscan.ModScan"
    }
    fn description(&self) -> &'static str {
        "Scans for modules present in a particular windows memory image."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::flag("dump", "Extract listed modules"),
            Requirement::new("base", "Extract a single module with BASE address", ReqKind::Int).optional(),
            Requirement::new("name", "module name/sub string", ReqKind::Str).optional(),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(modules::columns())?;
        let k = ctx.windows_kernel()?;
        modules::generate(ctx, cfg, out, &mut || scan_modules(ctx, k))
    }
}
