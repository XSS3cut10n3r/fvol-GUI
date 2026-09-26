//! isfinfo.IsfInfo (python `plugins/isfinfo.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::RowSink;

pub struct IsfInfo;

impl Plugin for IsfInfo {
    fn name(&self) -> &'static str {
        "isfinfo.IsfInfo"
    }
    fn description(&self) -> &'static str {
        "Determines information about the currently available ISF files, or a specific one"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("filter", "String that must be present in the file URI to display the ISF", ReqKind::ListStr)
                .optional()
                .default(ConfigValue::List(Vec::new())),
            Requirement::new("isf", "Specific ISF file to process", ReqKind::Uri).optional(),
            Requirement::flag("validate", "Validate against schema if possible"),
            Requirement::flag("live", "Traverse all files, rather than use the cache"),
        ]
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("isfinfo.IsfInfo: not implemented yet"))
    }
}
