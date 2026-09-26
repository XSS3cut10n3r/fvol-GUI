//! linux.vmcoreinfo.VMCoreInfo (python `plugins/linux/vmcoreinfo.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! STUB: not yet ported.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct VMCoreInfo;

impl Plugin for VMCoreInfo {
    fn name(&self) -> &'static str {
        "linux.vmcoreinfo.VMCoreInfo"
    }
    fn description(&self) -> &'static str {
        "Enumerate VMCoreInfo tables"
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("linux.vmcoreinfo.VMCoreInfo: not yet ported"))
    }
}
