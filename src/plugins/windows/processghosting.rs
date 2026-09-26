//! windows.processghosting.ProcessGhosting (python `plugins/windows/processghosting.py`):
//! deprecated alias of [`windows.malware.processghosting.ProcessGhosting`](super::malware::processghosting).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct ProcessGhosting;

impl Plugin for ProcessGhosting {
    fn name(&self) -> &'static str {
        "windows.processghosting.ProcessGhosting"
    }
    fn description(&self) -> &'static str {
        "Lists processes whose DeletePending bit is set or whose FILE_OBJECT is set to 0 or Vads that are DeleteOnClose (deprecated)."
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        super::malware::processghosting::ProcessGhosting.run(ctx, cfg, out)
    }
}
