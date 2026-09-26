//! timeliner.Timeliner (python `plugins/timeliner.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::RowSink;

pub struct Timeliner;

impl Plugin for Timeliner {
    fn name(&self) -> &'static str {
        "timeliner.Timeliner"
    }
    fn description(&self) -> &'static str {
        "Runs all relevant plugins that provide time related information and orders the results by time."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::flag("record-config", "Whether to record the state of all the plugins once complete"),
            Requirement::new("plugin-filter", "Only run plugins featuring this substring", ReqKind::ListStr)
                .optional()
                .default(ConfigValue::List(Vec::new())),
            Requirement::flag("create-bodyfile", "Whether to create a body file whilst producing results"),
        ]
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("timeliner.Timeliner: not implemented yet"))
    }
}
