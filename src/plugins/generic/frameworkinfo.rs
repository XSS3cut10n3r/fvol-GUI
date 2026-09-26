//! frameworkinfo.FrameworkInfo (python `plugins/frameworkinfo.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct FrameworkInfo;

impl Plugin for FrameworkInfo {
    fn name(&self) -> &'static str {
        "frameworkinfo.FrameworkInfo"
    }
    fn description(&self) -> &'static str {
        "Plugin to list the various modular components of Volatility"
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("frameworkinfo.FrameworkInfo: not implemented yet"))
    }
}
