//! windows.unloadedmodules.UnloadedModules (python `plugins/windows/unloadedmodules.py`): the
//! kernel's `MmUnloadedDrivers` ring.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::{Obj, Space};
use crate::plugins::{Config, Plugin, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::windows::WinExt;
use crate::util::time::wintime_to_datetime;

pub struct UnloadedModules;

/// python `UnloadedModules.create_unloadedmodules_table(context, symbol_table, config_path)`:
/// the `unloadedmodules-x64/x86` ISF with the kernel's natives, `nt_symbols` mapped to the
/// kernel table.
pub fn create_unloadedmodules_table(ctx: &Context, k: &WinKernel) -> Result<TableRef> {
    let file = if k.table.is_64bit() { "windows/unloadedmodules-x64" } else { "windows/unloadedmodules-x86" };
    ctx.load_isf_with(file, Some(k.table), &[("nt_symbols", k.table.name())])
}

/// One entry of python `list_unloadedmodules`: (name, start, end, `CurrentTime`).
pub type UnloadedModule = (String, u64, u64, u64);

/// python `UnloadedModules.list_unloadedmodules(context, kernel_module_name, table)`: the
/// plausible entries of `MmUnloadedDrivers` (count from `MmLastUnloadedDriver`, capped at 1024;
/// unreadable entries skipped). A trailing `Err` = python raised there.
pub fn list_unloadedmodules(k: &WinKernel, table: TableRef) -> Vec<Result<UnloadedModule>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let array_ptr = k.object("pointer", k.get_symbol("MmUnloadedDrivers")?.address)?.u64()?;
        let count_ty = if k.table.is_64bit() { "unsigned long long" } else { "unsigned long" };
        let mut count = k.object(count_ty, k.get_symbol("MmLastUnloadedDriver")?.address)?.u64()?;
        if count > 1024 {
            count = 1024;
        }
        let arr = Obj::named(Space::on(k.vlayer, table), "_UNLOADED_DRIVERS", array_ptr & k.vlayer.address_mask())?.m("UnloadedDrivers")?.with_count(count);
        let kernel_space_start = super::modules::get_kernel_space_start(k)?;
        let mask = k.vlayer.address_mask();
        for i in 0..count {
            let driver = arr.at(i)?;
            let e = (|| -> Result<UnloadedModule> {
                let start = driver.m("StartAddress")?.u64()? & mask;
                let end = driver.m("EndAddress")?.u64()? & mask;
                let time = driver.m("CurrentTime")?.u64()?;
                let name = driver.m("Name")?.get_string()?;
                Ok((name, start, end, time))
            })();
            let (name, start, end, time) = match e {
                Ok(v) => v,
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            };
            if time > 1024 && start > kernel_space_start && start & 0xFFF == 0 && end & 0xFFF == 0 && end > kernel_space_start {
                out.push(Ok((name, start, end, time)));
            }
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

/// python `_generator()` rows: (name, start, end, time).
fn rows(ctx: &Context, out: &mut dyn FnMut(Vec<Value>) -> Result<()>) -> Result<()> {
    let k = ctx.windows_kernel()?;
    // python logs an error and yields nothing when the symbols are missing
    if !k.has_symbol("MmUnloadedDrivers") || !k.has_symbol("MmLastUnloadedDriver") {
        return Ok(());
    }
    let table = create_unloadedmodules_table(ctx, k)?;
    for e in list_unloadedmodules(k, table) {
        let (name, start, end, time) = e?;
        out(vec![Value::Str(name), Value::Int(start as i128), Value::Int(end as i128), wintime_to_datetime(time as i128)])?;
    }
    Ok(())
}

impl Plugin for UnloadedModules {
    fn name(&self) -> &'static str {
        "windows.unloadedmodules.UnloadedModules"
    }
    fn description(&self) -> &'static str {
        "Lists the unloaded kernel modules."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Name", ColType::Str),
            Column::new("StartAddress", ColType::Hex),
            Column::new("EndAddress", ColType::Hex),
            Column::new("Time", ColType::DateTime),
        ])?;
        rows(ctx, &mut |r| out.row(0, r))
    }
    fn timeline(&self, ctx: &Context, _cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        let mut ev = Vec::new();
        let r = rows(ctx, &mut |r| {
            let name = match &r[0] {
                Value::Str(s) => s.clone(),
                _ => String::new(),
            };
            ev.push(TimelineEvent { description: format!("Unloaded Module: {name}"), kind: TimeKind::Changed, time: r[3].clone() });
            Ok(())
        });
        Some(r.map(|_| ev))
    }
}
