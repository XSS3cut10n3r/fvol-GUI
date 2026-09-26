//! linux.lsmod.Lsmod (python `plugins/linux/lsmod.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! STUB: not yet ported.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct Lsmod;

impl Plugin for Lsmod {
    fn name(&self) -> &'static str {
        "linux.lsmod.Lsmod"
    }
    fn description(&self) -> &'static str {
        "Lists loaded kernel modules."
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("linux.lsmod.Lsmod: not yet ported"))
    }
}
