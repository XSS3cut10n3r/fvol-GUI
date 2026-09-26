//! Linux automagic (python `automagic/linux.py`: LinuxIntelStacker, LinuxIntelVMCOREINFOStacker,
//! LinuxSymbolFinder) producing the [`LinuxKernel`] handle behind `Context::linux_kernel()`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! STUB -- implemented by the Linux automagic sub-agent (it owns this file).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::IntelLayer;
use crate::objects::{LayerRef, Module};
use crate::symbols::TableRef;

/// The Linux kernel (python `context.modules[config["kernel"]]` for linux plugins plus its
/// layers). Derefs to the kernel [`Module`] (offset = python `kernel_virtual_offset`, i.e. the
/// virtual ASLR shift; the symbol table has python's `symbol_mask` = layer address mask).
pub struct LinuxKernel {
    /// The kernel module (virtual layer, kernel symbol table, base = aslr_shift).
    pub module: Module,
    /// The kernel virtual layer (python `layer_name`, `LinuxIntel32e` / `Intel32e` / ...).
    pub layer: &'static IntelLayer,
    /// Same layer as `&dyn Layer`.
    pub vlayer: LayerRef,
    /// The physical layer (python `memory_layer`).
    pub phys: LayerRef,
    /// The kernel symbol table.
    pub table: TableRef,
    /// Physical KASLR shift.
    pub kaslr_shift: u64,
    /// Virtual ASLR shift (python `kernel_virtual_offset`).
    pub aslr_shift: u64,
    /// python `page_map_offset`.
    pub dtb: u64,
    /// The matched `linux_banner`.
    pub banner: Vec<u8>,
}

impl std::ops::Deref for LinuxKernel {
    type Target = Module;
    fn deref(&self) -> &Module {
        &self.module
    }
}

/// Run the Linux automagic for `ctx` (called once by `Context::linux_kernel`).
pub fn init(ctx: &Context) -> Result<LinuxKernel> {
    let _ = ctx;
    Err(Error::Unsatisfied("Linux automagic not implemented yet".into()))
}
