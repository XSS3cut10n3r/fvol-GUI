//! linux.vmcoreinfo.VMCoreInfo (python `plugins/linux/vmcoreinfo.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::generic::primary::primary;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::vmcoreinfo::{VmValue, search_vmcoreinfo_elf_note_cached};

pub struct VMCoreInfo;

/// python `hex(int)`.
fn py_hex(v: i128) -> String {
    if v < 0 { format!("-{:#x}", v.unsigned_abs()) } else { format!("{v:#x}") }
}

impl Plugin for VMCoreInfo {
    fn name(&self) -> &'static str {
        "linux.vmcoreinfo.VMCoreInfo"
    }
    fn description(&self) -> &'static str {
        "Enumerate VMCoreInfo tables"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let p = primary(ctx, "Memory layer to scan")?;
        out.begin(vec![Column::new("Offset", ColType::Hex), Column::new("Key", ColType::Str), Column::new("Value", ColType::Str)])?;
        let mut err = None;
        search_vmcoreinfo_elf_note_cached(p.layer, |off, table| {
            for (key, value) in &table.entries {
                let v = match value {
                    VmValue::Int(i) if key.starts_with("SYMBOL(") || key == "KERNELOFFSET" => py_hex(*i),
                    VmValue::Int(i) => i.to_string(),
                    VmValue::Str(s) => s.clone(),
                };
                if let Err(e) = out.row(0, vec![Value::Int(off as i128), Value::Str(key.clone()), Value::Str(v)]) {
                    err = Some(e);
                    return false;
                }
            }
            true
        })?;
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
