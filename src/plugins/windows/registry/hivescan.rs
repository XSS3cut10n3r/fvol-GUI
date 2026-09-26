//! windows.registry.hivescan.HiveScan (python `plugins/windows/registry/hivescan.py`):
//! `_CMHIVE`s found through the big page pool table (`CM10`, Windows 8.1+ x64) or by pool
//! scanning (older systems). [`scan_hives`] is python's `HiveScan.scan_hives`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::Obj;
use crate::plugins::windows::bigpools::list_big_pools_each;
use crate::plugins::windows::poolscanner::{builtin_constraints, generate_pool_scan_each};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::versions;

pub struct HiveScan;

/// python `HiveScan.scan_hives(context, kernel_name)`: `_CMHIVE` objects from the big pool
/// table (Windows 8.1+ x64) or from a `CM10` pool scan. A trailing `Err` = python raised.
pub fn scan_hives(ctx: &Context, k: &WinKernel) -> Vec<Result<Obj>> {
    let is_64bit = k.table.is_64bit();
    if versions::IS_WINDOWS_8_1_OR_LATER.check(k.table) && is_64bit {
        let mut out = Vec::new();
        let tags = ["CM10".to_string()];
        if let Err(e) = list_big_pools_each(ctx, k, Some(&tags), false, |p| {
            out.push(Ok(k.object_abs("_CMHIVE", p.m("Va")?.int()? as u64)?));
            Ok(true)
        }) {
            out.push(Err(e));
        }
        out
    } else {
        let constraints = builtin_constraints(k.table.name(), &[b"CM10"]);
        let mut out = Vec::new();
        if let Err(e) = generate_pool_scan_each(ctx, k, k.table, &constraints, |hit| {
            out.push(Ok(hit.object));
            Ok(true)
        }) {
            out.push(Err(e));
        }
        out
    }
}

impl Plugin for HiveScan {
    fn name(&self) -> &'static str {
        "windows.registry.hivescan.HiveScan"
    }
    fn description(&self) -> &'static str {
        "Scans for registry hives present in a particular windows memory image."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("Offset", ColType::Hex)])?;
        let k = ctx.windows_kernel()?;
        for h in scan_hives(ctx, k) {
            let h = h?;
            out.row(0, vec![Value::Int(h.addr as i128)])?;
        }
        Ok(())
    }
}
