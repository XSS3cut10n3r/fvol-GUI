//! linux.tracing.perf_events.PerfEvents (python `plugins/linux/tracing/perf_events.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! STUB: not yet ported.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct PerfEvents;

impl Plugin for PerfEvents {
    fn name(&self) -> &'static str {
        "linux.tracing.perf_events.PerfEvents"
    }
    fn description(&self) -> &'static str {
        "Lists performance events for each process."
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("linux.tracing.perf_events.PerfEvents: not yet ported"))
    }
}
