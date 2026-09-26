//! linux.tracing.ftrace.CheckFtrace (python `plugins/linux/tracing/ftrace.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! STUB: not yet ported.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct CheckFtrace;

impl Plugin for CheckFtrace {
    fn name(&self) -> &'static str {
        "linux.tracing.ftrace.CheckFtrace"
    }
    fn description(&self) -> &'static str {
        "TODO"
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("linux.tracing.ftrace.CheckFtrace: not yet ported"))
    }
}
