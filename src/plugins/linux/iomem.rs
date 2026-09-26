//! linux.iomem.IOMem (python `plugins/linux/iomem.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! STUB: not yet ported.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct IOMem;

impl Plugin for IOMem {
    fn name(&self) -> &'static str {
        "linux.iomem.IOMem"
    }
    fn description(&self) -> &'static str {
        "Generates an output similar to /proc/iomem on a running system."
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("linux.iomem.IOMem: not yet ported"))
    }
}
