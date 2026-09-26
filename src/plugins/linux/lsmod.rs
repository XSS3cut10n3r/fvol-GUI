//! linux.lsmod.Lsmod (python `plugins/linux/lsmod.py`) and python's
//! `linux_utilities_modules.ModuleDisplayPlugin` (the shared output of lsmod, check_modules and
//! hidden_modules: [`columns`], [`generate_results`]).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::util::array_to_string;
use crate::objects::{Module, Obj};
use crate::plugins::windows::pslist::sanitize_filename;
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::module::ModuleExt;
use crate::symbols::linux::module_extract::extract_module;
use crate::symbols::linux::modules::{get_load_parameters, list_modules};
use crate::symbols::linux::tainting::Tainting;
use std::io::Write;

pub struct Lsmod;

/// python `ModuleDisplayPlugin.columns_results`.
pub fn columns() -> Vec<Column> {
    vec![
        Column::new("Offset", ColType::Hex),
        Column::new("Module Name", ColType::Str),
        Column::new("Code Size", ColType::Hex),
        Column::new("Taints", ColType::Str),
        Column::new("Load Arguments", ColType::Str),
        Column::new("File Output", ColType::Str),
    ]
}

/// The `dump` requirement shared by the module display plugins.
pub fn dump_requirement() -> Requirement {
    Requirement::flag("dump", "Extract listed modules")
}

/// python `ModuleDisplayPlugin.generate_results(context, implementation, kernel, dump, open)`:
/// one row per module yielded by the implementation (`modules`: python's `module.vol.offset`
/// and the `module` struct; an `Err` item is where the python generator raised). Rows are
/// emitted as they are produced (python's renderer prints them before a later exception).
pub fn generate_results(ctx: &Context, vm: &Module, modules: impl IntoIterator<Item = Result<(u64, Obj)>>, dump: bool, out: &mut dyn RowSink) -> Result<()> {
    out.begin(columns())?;
    let tainting = std::cell::OnceCell::new();
    for module in modules {
        let (offset, module) = module?;
        let name = match module.m("name").and_then(|n| array_to_string(&n, None)) {
            Ok(n) => n,
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => return Err(e),
        };
        let code_size = module.get_init_size()? + module.get_core_size()?;
        let taints_v = module.m("taints")?.int()?;
        let t = match tainting.get() {
            Some(t) => t,
            None => {
                let _ = tainting.set(Tainting::new(vm)?);
                tainting.get().unwrap()
            }
        };
        let taints = t.get_taints_parsed(taints_v, true)?.join(",");
        let mut params = Vec::new();
        for p in get_load_parameters(vm, &module) {
            let (k, v) = p?;
            params.push(format!("{k}={v}"));
        }
        let parameters = params.join(", ");
        let file_output = if dump {
            match extract_module(vm, &module)? {
                Some(elf) if !elf.is_empty() => {
                    let file_name = sanitize_filename(&format!("kernel_module.{name}.{offset:#x}.elf"));
                    let (mut f, _) = ctx.create_output_file(&file_name)?;
                    f.write_all(&elf)?;
                    Value::Str(file_name)
                }
                _ => Value::NotAvailable,
            }
        } else {
            Value::NotApplicable
        };
        out.row(
            0,
            vec![Value::Int(offset as i128), Value::Str(name), Value::Int(code_size), Value::Str(taints), Value::Str(parameters), file_output],
        )?;
    }
    Ok(())
}

impl Plugin for Lsmod {
    fn name(&self) -> &'static str {
        "linux.lsmod.Lsmod"
    }
    fn description(&self) -> &'static str {
        "Lists loaded kernel modules."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![dump_requirement()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.linux_kernel()?;
        generate_results(ctx, k, list_modules(k).into_iter().map(|m| m.map(|m| (m.addr, m))), cfg.get_bool("dump"), out)
    }
}
