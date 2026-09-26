//! linux.tracing.perf_events.PerfEvents (python `plugins/linux/tracing/perf_events.py`): the
//! performance events (`perf_event_list`) of every task, with their attached eBPF program.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::objects::util::{array_to_string, pointer_to_string};
use crate::plugins::linux::pslist::list_tasks;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::prelude::*;

pub struct PerfEvents;

/// One event yielded by python `PerfEvents.list_perf_events`.
pub struct PerfEvent {
    pub task: Obj,
    pub event: Obj,
    pub event_name: String,
    pub program_name: String,
    pub full_name: Option<String>,
    /// `event.prog` (None on kernels without the member).
    pub program_address: Option<u64>,
}

/// python `AttributeError` (a missing member).
fn is_attribute_error(e: &Error) -> bool {
    matches!(e, Error::Symbol(m) | Error::Msg(m) if m.starts_with("AttributeError"))
}

/// The strings of one event (python's `try` block); `Ok(None)` = python's
/// `except InvalidAddressException: continue`.
fn event_strings(event: &Obj) -> Result<Option<(String, Option<String>, String)>> {
    let r = (|| -> Result<(String, Option<String>, String)> {
        let event_name = pointer_to_string(&event.m("pmu")?.m("name")?, 64)?;
        let full_name = match event.m("prog").and_then(|p| p.m("aux")).and_then(|a| a.m("ksym")).and_then(|k| k.m("name")) {
            Ok(name) => Some(array_to_string(&name, Some(512))?),
            Err(e) if is_attribute_error(&e) => None,
            Err(e) => return Err(e),
        };
        let program_name = array_to_string(&event.m("prog")?.m("aux")?.m("name")?, None)?;
        Ok((event_name, full_name, program_name))
    })();
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.is_invalid_address() => Ok(None),
        Err(e) => Err(e),
    }
}

/// python `PerfEvents.list_perf_events(context, vmlinux_module_name)`: streams each event to
/// `f` (return `Ok(false)` to stop). `Err` = python raised there.
pub fn list_perf_events(k: &LinuxKernel, f: &mut dyn FnMut(PerfEvent) -> Result<bool>) -> Result<()> {
    let t = k.table;
    if !t.user_type("perf_event").is_some_and(|u| t.member(u, "owner_entry").is_some()) {
        // python: vollog.warning("This kernel does not have performance events enabled ...")
        return Ok(());
    }
    let sym = format!("{}!perf_event", t.name());
    let has_prog = t.user_type("perf_event").is_some_and(|u| t.member(u, "prog").is_some());
    list_tasks(k, &|_| Ok(false), true, &mut |task| {
        for event in task.m("perf_event_list")?.list_of(&sym, "owner_entry") {
            let event = event?;
            let Some((event_name, full_name, program_name)) = event_strings(&event)? else { continue };
            let program_address = if has_prog {
                let a = event.m("prog")?.u64()?;
                if a == 0 {
                    continue;
                }
                Some(a)
            } else {
                None
            };
            if !f(PerfEvent { task, event, event_name, program_name, full_name, program_address })? {
                return Ok(false);
            }
        }
        Ok(true)
    })
}

impl Plugin for PerfEvents {
    fn name(&self) -> &'static str {
        "linux.tracing.perf_events.PerfEvents"
    }
    fn description(&self) -> &'static str {
        "Lists performance events for each process."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.linux_kernel()?;
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Event", ColType::Str),
            Column::new("Short Program Name", ColType::Str),
            Column::new("Full Name", ColType::Str),
            Column::new("Address", ColType::Hex),
        ])?;
        let s = |v: String| if v.is_empty() { Value::NotAvailable } else { Value::Str(v) };
        list_perf_events(k, &mut |ev| {
            let task_name = array_to_string(&ev.task.m("comm")?, None)?;
            let address = ev.program_address.map_or(Value::NotAvailable, |a| Value::Int(a as i128));
            out.row(
                0,
                vec![
                    Value::Int(ev.task.m("pid")?.int()?),
                    Value::Str(task_name),
                    s(ev.event_name),
                    s(ev.program_name),
                    ev.full_name.map_or(Value::NotAvailable, s),
                    address,
                ],
            )?;
            Ok(true)
        })
    }
}
