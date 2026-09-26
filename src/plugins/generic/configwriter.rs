//! configwriter.ConfigWriter (python `plugins/configwriter.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::RowSink;

pub struct ConfigWriter;

impl Plugin for ConfigWriter {
    fn name(&self) -> &'static str {
        "configwriter.ConfigWriter"
    }
    fn description(&self) -> &'static str {
        "Runs the automagics and both prints and outputs configuration in the output directory."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::flag("extra", "Outputs whole configuration tree")]
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("configwriter.ConfigWriter: not implemented yet"))
    }
}
