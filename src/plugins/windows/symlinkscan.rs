//! windows.symlinkscan.SymlinkScan (python `plugins/windows/symlinkscan.py`): pool-scanned
//! `_OBJECT_SYMBOLIC_LINK` objects.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::Obj;
use crate::plugins::windows::poolscanner::{builtin_constraints, generate_pool_scan_each};
use crate::plugins::{Config, Plugin, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;
use crate::symbols::windows::objects::{ObjectsExt, is_name_info_value_error};

pub struct SymlinkScan;

/// python `SymlinkScan.scan_symlinks(context, kernel_module_name)`, streaming (`f` returns
/// `Ok(false)` to stop).
pub fn scan_symlinks_each(ctx: &Context, k: &WinKernel, mut f: impl FnMut(Obj) -> Result<bool>) -> Result<()> {
    let constraints = builtin_constraints(k.table.name(), &[b"Sym\xe2", b"Symb"]);
    generate_pool_scan_each(ctx, k, k.table, &constraints, |hit| f(hit.object))
}

/// python `_generator()`: (offset, create time, from name, to name) rows.
fn rows(ctx: &Context, out: &mut dyn FnMut(Vec<Value>) -> Result<()>) -> Result<()> {
    let k = ctx.windows_kernel()?;
    scan_symlinks_each(ctx, k, |link| {
        let from = match link.get_link_name() {
            Ok(n) => n,
            Err(e) if e.is_invalid_address() || is_name_info_value_error(&e) => return Ok(true),
            Err(e) => return Err(e),
        };
        let to = match link.m("LinkTarget").and_then(|t| t.get_string()) {
            Ok(n) => n,
            Err(e) if e.is_invalid_address() => return Ok(true),
            Err(e) => return Err(e),
        };
        out(vec![Value::Int(link.addr as i128), link.get_create_time()?, Value::Str(from), Value::Str(to)])?;
        Ok(true)
    })
}

impl Plugin for SymlinkScan {
    fn name(&self) -> &'static str {
        "windows.symlinkscan.SymlinkScan"
    }
    fn description(&self) -> &'static str {
        "Scans for links present in a particular windows memory image."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("CreateTime", ColType::DateTime),
            Column::new("From Name", ColType::Str),
            Column::new("To Name", ColType::Str),
        ])?;
        rows(ctx, &mut |r| out.row(0, r))
    }
    fn timeline(&self, ctx: &Context, _cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        let mut ev = Vec::new();
        let r = rows(ctx, &mut |r| {
            let s = |v: &Value| match v {
                Value::Str(s) => s.clone(),
                _ => String::new(),
            };
            ev.push(TimelineEvent { description: format!("Symlink: {} -> {}", s(&r[2]), s(&r[3])), kind: TimeKind::Created, time: r[1].clone() });
            Ok(())
        });
        Some(r.map(|_| ev))
    }
}
