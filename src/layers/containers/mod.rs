//! Container format layers (LiME / ELF / crash dump / VMware / QEMU / AVML / Xen ...).
//! STUB (core agent) -- replaced wholesale by the formats agent at merge.

use super::{FileLayer, Layer};
use crate::error::Result;
use std::sync::Arc;

/// Stack container layers on the input file. The stub treats every file as a raw image and
/// returns the file layer itself.
pub fn stack(file: Arc<FileLayer>) -> Result<Arc<dyn Layer>> {
    Ok(file)
}
