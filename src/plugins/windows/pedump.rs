//! windows.pedump.PEDump (python `plugins/windows/pedump.py`): reconstruct the PE file at a
//! base address in process or kernel memory. The shared dump helpers (`PEDump.dump_pe`,
//! `dump_ldr_entry`) live in [`super::modules`]; the per-base helpers are here.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::LayerRef;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::windows::WinExt;
use crate::util::pyformat::fmt_int;

pub struct PEDump;

/// python `PEDump.dump_pe_at_base(context, pe_table, layer, open_method, proc_offset, pid,
/// base)`: writes `PE.<proc_offset>.<pid>.<base>.dmp`; returns the printed name or None.
pub fn dump_pe_at_base(ctx: &Context, pe_table: TableRef, layer: LayerRef, proc_offset: u64, pid: i128, base: i128) -> Option<String> {
    let file_name = format!("PE.{proc_offset:#x}.{pid}.{}.dmp", fmt_int(base, "#x"));
    super::modules::dump_pe(ctx, pe_table, layer, &file_name, base as u64)
}

/// python `PEDump.dump_kernel_pe_at_base(context, kernel, pe_table, open_method, base)`:
/// `(4, "Kernel", file name)` when a session layer maps `base` and the dump worked.
pub fn dump_kernel_pe_at_base(ctx: &Context, k: &WinKernel, pe_table: TableRef, base: i128) -> Result<Option<(i128, String, String)>> {
    let session_layers = super::modules::get_session_layers(k, &[])?;
    match super::modules::find_session_layer(&session_layers, base as u64) {
        Some(layer) => Ok(dump_pe_at_base(ctx, pe_table, layer, 0, 4, base).map(|f| (4, "Kernel".to_string(), f))),
        // vollog.warning("Unable to find a session layer with the provided base address mapped in the kernel.")
        None => Ok(None),
    }
}

impl Plugin for PEDump {
    fn name(&self) -> &'static str {
        "windows.pedump.PEDump"
    }
    fn description(&self) -> &'static str {
        "Allows extracting PE Files from a specific address in a specific address space"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Process IDs to include (all other processes are excluded)", ReqKind::ListInt).optional(),
            Requirement::new("base", "Base address to reconstruct a PE file", ReqKind::Int),
            Requirement::flag("kernel_module", "Extract from kernel address space."),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("PID", ColType::Int), Column::new("Process", ColType::Str), Column::new("File output", ColType::Str)])?;
        let k = ctx.windows_kernel()?;
        let pe_table = ctx.load_isf("windows/pe")?;
        let pids = cfg.get_ints("pid");
        let kernel_module = cfg.get_bool("kernel_module");
        let base = cfg.get_int("base").unwrap_or(0);
        if kernel_module && !pids.is_empty() {
            // vollog.error("Only 'kernel-module' or 'pid' should be set, not both")
            return Ok(());
        }
        if !kernel_module && pids.is_empty() {
            // vollog.error("Either 'kernel-module' or 'pid' argument must be set")
            return Ok(());
        }
        if kernel_module {
            if let Some((pid, name, file)) = dump_kernel_pe_at_base(ctx, k, pe_table, base)? {
                out.row(0, vec![Value::Int(pid), Value::Str(name), Value::Str(file)])?;
            }
            return Ok(());
        }
        let filter = super::pslist::pid_filter(&pids);
        for p in super::pslist::list_processes(k, &filter) {
            let proc = p?;
            let pid = proc.m("UniqueProcessId")?.int()?;
            let name = proc.image_file_name_str()?;
            let layer = proc.add_process_layer()?;
            if let Some(file) = dump_pe_at_base(ctx, pe_table, layer, proc.addr, pid, base) {
                out.row(0, vec![Value::Int(pid), Value::Str(name), Value::Str(file)])?;
            }
        }
        Ok(())
    }
}
