//! windows.getservicesids.GetServiceSIDs (python `plugins/windows/getservicesids.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink};

pub struct GetServiceSIDs;

impl Plugin for GetServiceSIDs {
    fn name(&self) -> &'static str {
        "windows.getservicesids.GetServiceSIDs"
    }
    fn description(&self) -> &'static str {
        "Lists process token sids."
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("SID", ColType::Str), Column::new("Service", ColType::Str)])?;
        Err(Error::msg("windows.getservicesids.GetServiceSIDs: not implemented yet"))
    }
}
