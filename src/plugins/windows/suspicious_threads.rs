//! windows.suspicious_threads.SuspiciousThreads (python `plugins/windows/suspicious_threads.py`):
//! deprecated alias of [`windows.malware.suspicious_threads.SuspiciousThreads`](super::malware::suspicious_threads).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::RowSink;

pub struct SuspiciousThreads;

impl Plugin for SuspiciousThreads {
    fn name(&self) -> &'static str {
        "windows.suspicious_threads.SuspiciousThreads"
    }
    fn description(&self) -> &'static str {
        "Lists suspicious userland process threads (deprecated)."
    }
    fn requirements(&self) -> Vec<Requirement> {
        super::malware::suspicious_threads::SuspiciousThreads.requirements()
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        super::malware::suspicious_threads::SuspiciousThreads.run(ctx, cfg, out)
    }
}
