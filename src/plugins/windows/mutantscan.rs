//! windows.mutantscan.MutantScan (python `plugins/windows/mutantscan.py`): pool-scanned
//! `_KMUTANT` objects.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::Obj;
use crate::plugins::windows::poolscanner::{builtin_constraints, generate_pool_scan_each};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::objects::{ObjectsExt, is_name_info_value_error};

pub struct MutantScan;

/// python `MutantScan.scan_mutants(context, kernel_module_name)`, streaming (`f` returns
/// `Ok(false)` to stop).
pub fn scan_mutants_each(ctx: &Context, k: &WinKernel, mut f: impl FnMut(Obj) -> Result<bool>) -> Result<()> {
    let constraints = builtin_constraints(k.table.name(), &[b"Mut\xe1", b"Muta"]);
    generate_pool_scan_each(ctx, k, k.table, &constraints, |hit| f(hit.object))
}

impl Plugin for MutantScan {
    fn name(&self) -> &'static str {
        "windows.mutantscan.MutantScan"
    }
    fn description(&self) -> &'static str {
        "Scans for mutexes present in a particular windows memory image."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("Offset", ColType::Hex), Column::new("Name", ColType::Str)])?;
        let k = ctx.windows_kernel()?;
        scan_mutants_each(ctx, k, |mutant| {
            let name = match mutant.mutant_name() {
                Ok(n) => Value::Str(n),
                Err(e) if e.is_invalid_address() || is_name_info_value_error(&e) => Value::NotApplicable,
                Err(e) => return Err(e),
            };
            out.row(0, vec![Value::Int(mutant.addr as i128), name])?;
            Ok(true)
        })
    }
}
