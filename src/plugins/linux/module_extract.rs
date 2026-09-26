//! linux.module_extract.ModuleExtract (python `plugins/linux/module_extract.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! STUB: not yet ported.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct ModuleExtract;

impl Plugin for ModuleExtract {
    fn name(&self) -> &'static str {
        "linux.module_extract.ModuleExtract"
    }
    fn description(&self) -> &'static str {
        "Recreates an ELF file from a specific address in the kernel"
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("linux.module_extract.ModuleExtract: not yet ported"))
    }
}
