//! linux.tracing.tracepoints.CheckTracepoints (python `plugins/linux/tracing/tracepoints.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! STUB: not yet ported.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct CheckTracepoints;

impl Plugin for CheckTracepoints {
    fn name(&self) -> &'static str {
        "linux.tracing.tracepoints.CheckTracepoints"
    }
    fn description(&self) -> &'static str {
        "TODO"
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("linux.tracing.tracepoints.CheckTracepoints: not yet ported"))
    }
}
