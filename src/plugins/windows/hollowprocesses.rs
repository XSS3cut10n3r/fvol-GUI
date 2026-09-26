//! windows.hollowprocesses.HollowProcesses (python `plugins/windows/hollowprocesses.py`):
//! deprecated alias of [`windows.malware.hollowprocesses.HollowProcesses`](super::malware::hollowprocesses).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::RowSink;

pub struct HollowProcesses;

impl Plugin for HollowProcesses {
    fn name(&self) -> &'static str {
        "windows.hollowprocesses.HollowProcesses"
    }
    fn description(&self) -> &'static str {
        "Lists hollowed processes (deprecated)"
    }
    fn requirements(&self) -> Vec<Requirement> {
        super::malware::hollowprocesses::HollowProcesses.requirements()
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        super::malware::hollowprocesses::HollowProcesses.run(ctx, cfg, out)
    }
}
