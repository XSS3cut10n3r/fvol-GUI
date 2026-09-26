//! banners.Banners (python `plugins/banners.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct Banners;

impl Plugin for Banners {
    fn name(&self) -> &'static str {
        "banners.Banners"
    }
    fn description(&self) -> &'static str {
        "Attempts to identify potential linux banners in an image"
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("banners.Banners: not implemented yet"))
    }
}
