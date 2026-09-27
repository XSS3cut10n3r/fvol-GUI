//! windows.timers.Timers (python `plugins/windows/timers.py`): kernel timers and the module /
//! symbol of their (decoded) DPC routine.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::plugins::windows::kpcrs::list_kpcrs;
use crate::plugins::windows::ssdt::{ModuleCollection, build_module_collection};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowBlock, RowSink, Value};
use crate::symbols::windows::prelude::*;
use crate::symbols::windows::versions;

pub struct Timers;

/// python `Timers.list_timers(context, kernel_module_name)`: every `_KTIMER` linked from the
/// per-processor timer tables (Windows 7+) or `KiTimerTableListHead` (XP / 2003 / Vista), in
/// python's order. `f` returns `Ok(false)` to stop; an `Err` is python raising there.
pub fn list_timers_each(k: &WinKernel, mut f: impl FnMut(Obj) -> Result<bool>) -> Result<()> {
    let ktimer = format!("{}!_KTIMER", k.table.name());
    let walk = |head: Obj, f: &mut dyn FnMut(Obj) -> Result<bool>| -> Result<bool> {
        for t in head.list_of(&ktimer, "TimerListEntry") {
            if !f(t?)? {
                return Ok(false);
            }
        }
        Ok(true)
    };
    if versions::IS_WINDOWS_7.check(k.table) || versions::IS_WINDOWS_8_OR_LATER.check(k.table) {
        for r in list_kpcrs(k) {
            let (kpcr, _) = r?;
            let table = kpcr.m("Prcb")?.m("TimerTable")?;
            let entries = table.m("TimerEntries")?;
            if table.has_member("TableState") {
                for i in 0..entries.count() {
                    let row = entries.at(i)?;
                    for j in 0..row.count() {
                        if !walk(row.at(j)?.m("Entry")?, &mut f)? {
                            return Ok(());
                        }
                    }
                }
            } else {
                for i in 0..entries.count() {
                    if !walk(entries.at(i)?.m("Entry")?, &mut f)? {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    } else if versions::IS_XP_OR_2003.check(k.table) || versions::IS_VISTA_OR_LATER.check(k.table) {
        let size = if k.table.is_64bit() || versions::IS_VISTA_OR_LATER.check(k.table) { 512 } else { 256 };
        let heads = k.object("_LIST_ENTRY", k.get_symbol("KiTimerTableListHead")?.address)?.cast_array_of(size, "_LIST_ENTRY")?;
        for i in 0..size {
            if !walk(heads.at(i)?, &mut f)? {
                return Ok(());
            }
        }
        Ok(())
    } else {
        Err(Error::msg("NotImplementedError: This version of Windows is not supported!"))
    }
}

/// python `_generator`'s rows for one timer, pushed to `block` (an error = python raised
/// after them).
fn timer_rows(timer: &Obj, collection: &ModuleCollection, block: &mut RowBlock) -> Result<()> {
    if !timer.valid_type()? {
        return Ok(());
    }
    let routine = (|| -> Result<Option<u64>> {
        let dpc = timer.get_dpc()?;
        // `dpc == 0` is only ever true for the raw pointer (a struct never equals 0)
        if dpc.is_pointer() && dpc.u64()? == 0 {
            return Ok(None);
        }
        let r = dpc.m("DeferredRoutine")?.u64()?;
        Ok(if r == 0 { None } else { Some(r) })
    })();
    let routine = match routine {
        Ok(Some(r)) => r,
        Ok(None) => return Ok(()),
        Err(e) if e.is_invalid_address() => return Ok(()),
        Err(e) => return Err(e),
    };
    let row = |module: Value, symbol: Value| -> Result<Vec<Value>> {
        Ok(vec![
            Value::Int(timer.addr as i128),
            Value::Str(timer.get_due_time()?),
            Value::Int(timer.m("Period")?.int()?),
            Value::SStr(timer.get_signaled()?),
            Value::Int(routine as i128),
            module,
            symbol,
        ])
    };
    let found = collection.module_symbols(routine);
    if found.is_empty() {
        block.push(row(Value::NotAvailable, Value::NotAvailable)?);
    }
    for (module_name, syms) in found {
        if syms.is_empty() {
            block.push(row(Value::str(module_name), Value::NotAvailable)?);
        }
        for s in syms {
            block.push(row(Value::str(module_name), Value::str(s))?);
        }
    }
    Ok(())
}

/// Timers whose rows one worker builds at a time.
const CHUNK: usize = 128;

impl Plugin for Timers {
    fn name(&self) -> &'static str {
        "windows.timers.Timers"
    }
    fn description(&self) -> &'static str {
        "Print kernel timers and associated module DPCs"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("DueTime", ColType::Str),
            Column::new("Period(ms)", ColType::Int),
            Column::new("Signaled", ColType::Str),
            Column::new("Routine", ColType::Hex),
            Column::new("Module", ColType::Str),
            Column::new("Symbol", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        // the rows look up the kernel symbols at many routines: build the table's address
        // index on another core while the modules and timer lists are walked
        let table = k.table;
        std::thread::spawn(move || {
            table.symbols_at(0, 1);
        });
        let collection = build_module_collection(k)?;
        // the timer lists first (python's order, and where the walk raised), then the rows
        // (module + symbol lookups) in parallel, emitted in order
        let mut timers: Vec<Obj> = Vec::new();
        let walk_err = list_timers_each(k, |timer| {
            timers.push(timer);
            Ok(true)
        })
        .err();
        let mut items: Vec<Result<&[Obj]>> = timers.chunks(CHUNK).map(Ok).collect();
        items.extend(walk_err.map(Err));
        crate::plugins::emit_par_blocks(out, items, |chunk, block| {
            for timer in *chunk {
                timer_rows(timer, &collection, block)?;
            }
            Ok(())
        })
    }
}
