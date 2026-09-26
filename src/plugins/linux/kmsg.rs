//! linux.kmsg.Kmsg (python `plugins/linux/kmsg.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! STUB: not yet ported.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct Kmsg;

impl Plugin for Kmsg {
    fn name(&self) -> &'static str {
        "linux.kmsg.Kmsg"
    }
    fn description(&self) -> &'static str {
        "Kernel log buffer reader"
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("linux.kmsg.Kmsg: not yet ported"))
    }
}
