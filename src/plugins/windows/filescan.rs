//! windows.filescan.FileScan (python `plugins/windows/filescan.py`): pool-scanned
//! `_FILE_OBJECT`s.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::Obj;
use crate::plugins::windows::poolscanner::{builtin_constraints, generate_pool_scan_each};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;

pub struct FileScan;

/// python `FileScan.scan_files(context, kernel_module_name)`, streaming (`f` returns
/// `Ok(false)` to stop).
pub fn scan_files_each(ctx: &Context, k: &WinKernel, mut f: impl FnMut(Obj) -> Result<bool>) -> Result<()> {
    let constraints = builtin_constraints(k.table.name(), &[b"Fil\xe5", b"File"]);
    generate_pool_scan_each(ctx, k, k.table, &constraints, |hit| f(hit.object))
}

/// python `FileScan.scan_files(...)` collected (a trailing `Err` = python raised there).
pub fn scan_files(ctx: &Context, k: &WinKernel) -> Vec<Result<Obj>> {
    let mut v = Vec::new();
    if let Err(e) = scan_files_each(ctx, k, |o| {
        v.push(Ok(o));
        Ok(true)
    }) {
        v.push(Err(e));
    }
    v
}

impl Plugin for FileScan {
    fn name(&self) -> &'static str {
        "windows.filescan.FileScan"
    }
    fn description(&self) -> &'static str {
        "Scans for file objects present in a particular windows memory image."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("Offset", ColType::Hex), Column::new("Name", ColType::Str)])?;
        let k = ctx.windows_kernel()?;
        scan_files_each(ctx, k, |fo| {
            match fo.m("FileName").and_then(|n| n.get_string()) {
                Ok(name) => out.row(0, vec![Value::Int(fo.addr as i128), Value::Str(name)])?,
                Err(e) if e.is_invalid_address() => {}
                Err(e) => return Err(e),
            }
            Ok(true)
        })
    }
}
