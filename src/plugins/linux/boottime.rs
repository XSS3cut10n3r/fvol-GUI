//! linux.boottime.Boottime (python `plugins/linux/boottime.py`, a timeliner plugin).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::linux::pslist::list_tasks;
use crate::plugins::{Config, Plugin, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, DateTime, RowSink, Value};
use crate::symbols::linux::LinuxExt;

pub struct Boottime;

/// python `Boottime.get_time_namespaces_bootime(context, kernel)`: (time namespace id, boot
/// time; `None` = python's `UnparsableValue`) for the first task of each time namespace.
/// Streams to `f`; `Err` = python raised there.
pub fn get_time_namespaces_boottime(k: &LinuxKernel, f: &mut dyn FnMut(Option<i128>, Option<DateTime>) -> Result<()>) -> Result<()> {
    let mut seen: Vec<Option<i128>> = Vec::new();
    list_tasks(k, &|_| Ok(false), false, &mut |task| {
        let ns = task.get_time_namespace_id()?;
        if seen.contains(&ns) {
            return Ok(true);
        }
        seen.push(ns);
        let boottime = task.get_boottime(false)?;
        f(ns, boottime)?;
        Ok(true)
    })
}

fn boottime_value(b: Option<DateTime>) -> Value {
    b.map_or(Value::Unparsable, Value::DateTime)
}

impl Plugin for Boottime {
    fn name(&self) -> &'static str {
        "linux.boottime.Boottime"
    }
    fn description(&self) -> &'static str {
        "Shows the time the system was started"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("TIME NS", ColType::Int), Column::new("Boot Time", ColType::DateTime)])?;
        let k = ctx.linux_kernel()?;
        get_time_namespaces_boottime(k, &mut |ns, b| {
            let ns = match ns {
                Some(v) if v != 0 => Value::Int(v),
                _ => Value::NotAvailable,
            };
            out.row(0, vec![ns, boottime_value(b)])
        })
    }
    fn timeline_events(&self, ctx: &Context, _cfg: &Config) -> Option<(Vec<TimelineEvent>, Option<Error>)> {
        let mut ev = Vec::new();
        let r = ctx.linux_kernel().and_then(|k| {
            get_time_namespaces_boottime(k, &mut |ns, b| {
                let id = ns.map_or("None".to_string(), |v| v.to_string());
                ev.push(TimelineEvent { description: format!("System boot time for time namespace {id}"), kind: TimeKind::Created, time: boottime_value(b) });
                Ok(())
            })
        });
        Some((ev, r.err()))
    }
}
