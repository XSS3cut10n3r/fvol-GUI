//! windows.debugregisters.DebugRegisters (python `plugins/windows/debugregisters.py`): threads
//! with active hardware breakpoints (Dr7 != 0) pointing into mapped files.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::plugins::windows::thread_pe_symbols::{CollectedModules, Range, get_process_modules, path_and_symbol_for_address, vads_for_process_cache};
use crate::plugins::windows::threads::list_process_threads;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;
use crate::util::FxHashMap;

pub struct DebugRegisters;

/// python `DebugRegisters._get_debug_info(ethread)`: (owning process, dr7, dr0, dr1, dr2, dr3)
/// for threads with active debug registers, else None.
pub fn get_debug_info(ethread: &Obj) -> Result<Option<(Obj, u64, [u64; 4])>> {
    let r = (|| -> Result<(u64, i128)> {
        let tf = ethread.m("Tcb")?.m("TrapFrame")?;
        Ok((tf.m("Dr7")?.u64()?, ethread.m("Tcb")?.m("State")?.int()?))
    })();
    let (dr7, state) = match r {
        Ok(v) => v,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    // 0 = debug registers not active, 4 = terminated
    if dr7 == 0 || state == 4 {
        return Ok(None);
    }
    let owner = match ethread.owning_process() {
        Ok(p) => p,
        Err(e) if e.is_invalid_address() || matches!(&e, Error::Symbol(s) if s.starts_with("AttributeError")) => return Ok(None),
        Err(e) => return Err(e),
    };
    let tf = ethread.m("Tcb")?.m("TrapFrame")?;
    let drs = [tf.m("Dr0")?.u64()?, tf.m("Dr1")?.u64()?, tf.m("Dr2")?.u64()?, tf.m("Dr3")?.u64()?];
    if drs.iter().all(|d| *d == 0) {
        return Ok(None);
    }
    Ok(Some((owner, dr7, drs)))
}

impl Plugin for DebugRegisters {
    fn name(&self) -> &'static str {
        "windows.debugregisters.DebugRegisters"
    }
    fn description(&self) -> &'static str {
        ""
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let mut cols = vec![
            Column::new("Process", ColType::Str),
            Column::new("PID", ColType::Int),
            Column::new("TID", ColType::Int),
            Column::new("State", ColType::Int),
            Column::new("Dr7", ColType::Int),
        ];
        for i in 0..4 {
            cols.push(Column::new(format!("Dr{i}"), ColType::Hex));
            cols.push(Column::new(format!("Range{i}"), ColType::Str));
            cols.push(Column::new(format!("Symbol{i}"), ColType::Str));
        }
        out.begin(cols)?;
        let k = ctx.windows_kernel()?;
        let mut vads_cache: FxHashMap<u64, Vec<Range>> = FxHashMap::default();
        let mut proc_modules: Option<CollectedModules> = None;
        for thread in list_process_threads(k) {
            let thread = thread?;
            let Some((owner, dr7, drs)) = get_debug_info(&thread)? else { continue };
            if vads_for_process_cache(&mut vads_cache, &owner)?.is_none() {
                continue;
            }
            // python: `if not proc_modules` (an empty collection is rebuilt next time)
            if proc_modules.as_ref().is_none_or(|m| m.order.is_empty()) {
                proc_modules = Some(get_process_modules(k, &mut vads_cache)?);
            }
            let pm = proc_modules.as_ref().unwrap();
            let vads = &vads_cache[&owner.addr];
            let mut resolved = Vec::with_capacity(4);
            for d in drs {
                resolved.push(path_and_symbol_for_address(ctx, pm, vads, d)?);
            }
            // if none map to an actual file VAD then bail
            if resolved.iter().all(|(f, _)| f.as_deref().is_none_or(str::is_empty)) {
                continue;
            }
            let name = owner.image_file_name_str()?;
            let tid = thread.m("Cid")?.m("UniqueThread")?.u64()?;
            let or_na = |s: Option<String>| match s {
                Some(s) if !s.is_empty() => Value::Str(s),
                _ => Value::NotApplicable,
            };
            let mut row = vec![
                Value::Str(name),
                Value::Int(owner.m("UniqueProcessId")?.int()?),
                Value::Int(tid as i128),
                Value::Int(thread.m("Tcb")?.m("State")?.int()?),
                Value::Int(dr7 as i128),
            ];
            for (d, (file, sym)) in drs.into_iter().zip(resolved) {
                row.push(Value::Int(d as i128));
                row.push(or_na(file));
                row.push(or_na(sym));
            }
            out.row(0, row)?;
        }
        Ok(())
    }
}
