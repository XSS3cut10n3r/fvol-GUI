//! windows.malfind.Malfind (python `plugins/windows/malfind.py`): deprecated alias of
//! [`windows.malware.malfind.Malfind`](super::malware::malfind).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::RowSink;

pub struct Malfind;

impl Plugin for Malfind {
    fn name(&self) -> &'static str {
        "windows.malfind.Malfind"
    }
    fn description(&self) -> &'static str {
        "Lists process memory ranges that potentially contain injected code (deprecated)."
    }
    fn requirements(&self) -> Vec<Requirement> {
        super::malware::malfind::Malfind.requirements()
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        super::malware::malfind::Malfind.run(ctx, cfg, out)
    }
}
