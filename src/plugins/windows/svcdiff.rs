//! windows.svcdiff.SvcDiff (python `plugins/windows/svcdiff.py`): deprecated alias of
//! [`windows.malware.svcdiff.SvcDiff`](super::malware::svcdiff).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct SvcDiff;

impl Plugin for SvcDiff {
    fn name(&self) -> &'static str {
        "windows.svcdiff.SvcDiff"
    }
    fn description(&self) -> &'static str {
        "Compares services found through list walking versus scanning to find rootkits (deprecated)."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        super::malware::svcdiff::run(ctx, out)
    }
}
