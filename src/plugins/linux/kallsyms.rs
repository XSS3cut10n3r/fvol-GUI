//! linux.kallsyms.Kallsyms (python `plugins/linux/kallsyms.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! STUB: not yet ported.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct Kallsyms;

impl Plugin for Kallsyms {
    fn name(&self) -> &'static str {
        "linux.kallsyms.Kallsyms"
    }
    fn description(&self) -> &'static str {
        "Kallsyms symbols enumeration plugin."
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("linux.kallsyms.Kallsyms: not yet ported"))
    }
}
