//! linux.module_extract.ModuleExtract (python `plugins/linux/module_extract.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::layers::Layer;
use crate::objects::util::array_to_string;
use crate::plugins::windows::pslist::sanitize_filename;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::module_extract::extract_module;
use std::io::Write;

pub struct ModuleExtract;

/// python `f"{x:#x}"` for a python int.
fn py_hex(v: i128) -> String {
    if v < 0 { format!("-{:#x}", v.unsigned_abs()) } else { format!("{v:#x}") }
}

impl Plugin for ModuleExtract {
    fn name(&self) -> &'static str {
        "linux.module_extract.ModuleExtract"
    }
    fn description(&self) -> &'static str {
        "Recreates an ELF file from a specific address in the kernel"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("base", "Base virtual address to reconstruct an ELF file", ReqKind::Int)]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("Base", ColType::Hex), Column::new("File Size", ColType::Int), Column::new("File output", ColType::Str)])?;
        let k = ctx.linux_kernel()?;
        let base = cfg.get_int("base").unwrap_or(0);
        // python: "Given base address (...) is not valid in the kernel address space."
        if base < 0 || base > u64::MAX as i128 || !k.layer.is_valid(base as u64, 1) {
            return Ok(());
        }
        let module = k.object_abs("module", base as u64)?;
        let elf = match extract_module(k, &module)? {
            Some(e) if !e.is_empty() => e,
            // python: "Unable to reconstruct the ELF for module struct at ..."
            _ => return Ok(()),
        };
        let module_name = array_to_string(&module.m("name")?, None)?;
        let file_name = sanitize_filename(&format!("kernel_module.{module_name}.{}.elf", py_hex(base)));
        let (mut f, final_name) = ctx.create_output_file(&file_name)?;
        f.write_all(&elf)?;
        out.row(0, vec![Value::Int(base), Value::Int(elf.len() as i128), Value::Str(final_name)])
    }
}
