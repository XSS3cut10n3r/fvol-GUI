//! windows.ldrmodules.LdrModules (python `plugins/windows/ldrmodules.py`): deprecated alias of
//! [`windows.malware.ldrmodules.LdrModules`](super::malware::ldrmodules).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::RowSink;

pub struct LdrModules;

impl Plugin for LdrModules {
    fn name(&self) -> &'static str {
        "windows.ldrmodules.LdrModules"
    }
    fn description(&self) -> &'static str {
        "Lists the loaded modules in a particular windows memory image."
    }
    fn requirements(&self) -> Vec<Requirement> {
        super::malware::ldrmodules::LdrModules.requirements()
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        super::malware::ldrmodules::LdrModules.run(ctx, cfg, out)
    }
}
