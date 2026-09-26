//! regexscan.RegExScan (python `plugins/regexscan.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::RowSink;

pub struct RegExScan;

/// python `RegExScan.MAXSIZE_DEFAULT`.
pub const MAXSIZE_DEFAULT: i128 = 128;

impl Plugin for RegExScan {
    fn name(&self) -> &'static str {
        "regexscan.RegExScan"
    }
    fn description(&self) -> &'static str {
        "Scans kernel memory using RegEx patterns."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pattern", "RegEx pattern", ReqKind::Str),
            Requirement::new("maxsize", "Maximum size in bytes for displayed context", ReqKind::Int)
                .optional()
                .default(ConfigValue::Int(MAXSIZE_DEFAULT)),
        ]
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("regexscan.RegExScan: not implemented yet"))
    }
}
