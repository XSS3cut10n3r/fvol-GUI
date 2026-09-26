//! windows.getsids.GetSIDs (python `plugins/windows/getsids.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink};

pub struct GetSIDs;

impl Plugin for GetSIDs {
    fn name(&self) -> &'static str {
        "windows.getsids.GetSIDs"
    }
    fn description(&self) -> &'static str {
        "Print the SIDs owning each process"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional()]
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("SID", ColType::Str),
            Column::new("Name", ColType::Str),
        ])?;
        Err(Error::msg("windows.getsids.GetSIDs: not implemented yet"))
    }
}
