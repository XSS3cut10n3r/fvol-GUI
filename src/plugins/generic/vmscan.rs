//! vmscan.Vmscan (python `plugins/vmscan.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::RowSink;

pub struct Vmscan;

impl Plugin for Vmscan {
    fn name(&self) -> &'static str {
        "vmscan.Vmscan"
    }
    fn description(&self) -> &'static str {
        "Scans for Intel VT-d structures and generates VM volatility configs for them"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("log-threshold", "Number of criteria failed to log to debug output", ReqKind::Int)
            .optional()
            .default(ConfigValue::Int(2))]
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("vmscan.Vmscan: not implemented yet"))
    }
}
