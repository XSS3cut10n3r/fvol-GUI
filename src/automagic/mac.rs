//! Mac automagic (python `automagic/mac.py`: MacIntelStacker, MacSymbolFinder) producing the
//! [`MacKernel`] handle behind `Context::mac_kernel()`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! STUB -- implemented by the Mac automagic sub-agent (it owns this file).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::IntelLayer;
use crate::objects::{LayerRef, Module};
use crate::symbols::TableRef;

/// The macOS kernel (python `context.modules[config["kernel"]]` for mac plugins plus its
/// layers). Derefs to the kernel [`Module`] (offset = python `kernel_virtual_offset`).
pub struct MacKernel {
    /// The kernel module (virtual layer, kernel symbol table, base = kaslr shift).
    pub module: Module,
    /// The kernel virtual layer (python `layer_name`, an `Intel32e` layer).
    pub layer: &'static IntelLayer,
    /// Same layer as `&dyn Layer`.
    pub vlayer: LayerRef,
    /// The physical layer (python `memory_layer`).
    pub phys: LayerRef,
    /// The kernel symbol table.
    pub table: TableRef,
    /// python `kernel_virtual_offset` (KASLR shift).
    pub kaslr_shift: u64,
    /// python `page_map_offset`.
    pub dtb: u64,
    /// The matched kernel banner (`version` constant data).
    pub banner: Vec<u8>,
}

impl std::ops::Deref for MacKernel {
    type Target = Module;
    fn deref(&self) -> &Module {
        &self.module
    }
}

/// Run the Mac automagic for `ctx` (called once by `Context::mac_kernel`).
pub fn init(ctx: &Context) -> Result<MacKernel> {
    let _ = ctx;
    Err(Error::Unsatisfied("Mac automagic not implemented yet".into()))
}
