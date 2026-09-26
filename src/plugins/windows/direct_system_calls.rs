//! windows.direct_system_calls.DirectSystemCalls (python `plugins/windows/direct_system_calls.py`):
//! deprecated alias of
//! [`windows.malware.direct_system_calls.DirectSystemCalls`](super::malware::direct_system_calls).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::windows::malware::direct_system_calls::{DIRECT, run_finder};
use crate::plugins::windows::vadyarascan::yarascan_option_requirements;
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::RowSink;

pub struct DirectSystemCalls;

impl Plugin for DirectSystemCalls {
    fn name(&self) -> &'static str {
        "windows.direct_system_calls.DirectSystemCalls"
    }
    fn description(&self) -> &'static str {
        "Detects the Direct System Call technique used to bypass EDRs (deprecated)."
    }
    fn requirements(&self) -> Vec<Requirement> {
        yarascan_option_requirements()
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        run_finder(ctx, &DIRECT, out)
    }
}
