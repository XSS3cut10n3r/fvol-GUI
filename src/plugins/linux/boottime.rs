//! linux.boottime.Boottime (python `plugins/linux/boottime.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! STUB: not yet ported.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct Boottime;

impl Plugin for Boottime {
    fn name(&self) -> &'static str {
        "linux.boottime.Boottime"
    }
    fn description(&self) -> &'static str {
        "Shows the time the system was started"
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("linux.boottime.Boottime: not yet ported"))
    }
}
