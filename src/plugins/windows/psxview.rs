//! windows.psxview.PsXView (python `plugins/windows/psxview.py`): deprecated alias of
//! [`windows.malware.psxview.PsXView`](super::malware::psxview).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::RowSink;

pub struct PsXView;

impl Plugin for PsXView {
    fn name(&self) -> &'static str {
        "windows.psxview.PsXView"
    }
    fn description(&self) -> &'static str {
        // python 3.13+ dedents docstrings; the `\` continuation keeps the indentation inline
        "Lists all processes found via four of the methods described in \"The Art of Memory Forensics\" which may help     identify processes that are trying to hide themselves.\n\nWe recommend using -r pretty if you are looking at this plugin's output in a terminal.\ndeprecated."
    }
    fn requirements(&self) -> Vec<Requirement> {
        super::malware::psxview::PsXView.requirements()
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        super::malware::psxview::PsXView.run(ctx, cfg, out)
    }
}
