//! linux.ebpf.EBPF (python `plugins/linux/ebpf.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! STUB: not yet ported.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct Ebpf;

impl Plugin for Ebpf {
    fn name(&self) -> &'static str {
        "linux.ebpf.EBPF"
    }
    fn description(&self) -> &'static str {
        "Enumerate eBPF programs"
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("linux.ebpf.EBPF: not yet ported"))
    }
}
