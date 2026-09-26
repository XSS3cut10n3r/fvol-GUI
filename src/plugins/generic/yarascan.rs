//! yarascan.YaraScan (python `plugins/yarascan.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::RowSink;

pub struct YaraScan;

/// python `YaraScan.get_yarascan_option_requirements()` (shared with windows.vadyarascan /
/// linux.vmayarascan).
pub fn yarascan_option_requirements() -> Vec<Requirement> {
    vec![
        Requirement::flag("insensitive", "Makes the search case insensitive"),
        Requirement::flag("wide", "Match wide (unicode) strings"),
        Requirement::new("yara_string", "Yara rules (as a string)", ReqKind::Str).optional(),
        Requirement::new("yara_file", "Yara rules (as a file)", ReqKind::Uri).optional(),
        Requirement::new("yara_compiled_file", "Yara compiled rules (as a file)", ReqKind::Uri).optional(),
        Requirement::new("max_size", "Set the maximum size (default is 1GB)", ReqKind::Int)
            .optional()
            .default(ConfigValue::Int(0x40000000)),
    ]
}

impl Plugin for YaraScan {
    fn name(&self) -> &'static str {
        "yarascan.YaraScan"
    }
    fn description(&self) -> &'static str {
        "Scans kernel memory using yara rules (string or file)."
    }
    fn requirements(&self) -> Vec<Requirement> {
        yarascan_option_requirements()
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("yarascan.YaraScan: not implemented yet"))
    }
}
