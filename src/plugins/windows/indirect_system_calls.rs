//! windows.indirect_system_calls.IndirectSystemCalls (python
//! `plugins/windows/indirect_system_calls.py`): deprecated alias of
//! [`windows.malware.indirect_system_calls.IndirectSystemCalls`](super::malware::indirect_system_calls).
//!
//! python quirk reproduced: the alias subclasses `DirectSystemCalls` and the rename machinery
//! does not copy the replacement's `__init__`, so it runs the *direct* system call finder.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::windows::malware::direct_system_calls::{DIRECT, run_finder};
use crate::plugins::windows::vadyarascan::yarascan_option_requirements;
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::RowSink;

pub struct IndirectSystemCalls;

impl Plugin for IndirectSystemCalls {
    fn name(&self) -> &'static str {
        "windows.indirect_system_calls.IndirectSystemCalls"
    }
    fn description(&self) -> &'static str {
        "Detects the Indirect System Call technique used to bypass EDRs (deprecated)."
    }
    fn requirements(&self) -> Vec<Requirement> {
        yarascan_option_requirements()
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        run_finder(ctx, &DIRECT, out)
    }
}
