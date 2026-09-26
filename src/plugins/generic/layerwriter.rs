//! layerwriter.LayerWriter (python `plugins/layerwriter.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::RowSink;

pub struct LayerWriter;

/// python `LayerWriter.default_block_size`.
pub const DEFAULT_BLOCK_SIZE: i128 = 0x500000;

impl Plugin for LayerWriter {
    fn name(&self) -> &'static str {
        "layerwriter.LayerWriter"
    }
    fn description(&self) -> &'static str {
        "Runs the automagics and writes out the primary layer produced by the stacker."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("block_size", "Size of blocks to copy over", ReqKind::Int)
                .optional()
                .default(ConfigValue::Int(DEFAULT_BLOCK_SIZE)),
            Requirement::flag("list", "List available layers"),
            Requirement::new("layers", "Names of layers to write (defaults to the highest non-mapped layer)", ReqKind::ListStr).optional(),
        ]
    }
    fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
        Err(Error::msg("layerwriter.LayerWriter: not implemented yet"))
    }
}
