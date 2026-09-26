//! windows.driverirp.DriverIrp (python `plugins/windows/driverirp.py`): the IRP major function
//! handlers of every scanned driver, resolved to kernel modules / symbols.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::windows::driverscan::scan_drivers_each;
use crate::plugins::windows::ssdt::build_module_collection;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::objects::{ObjectsExt, is_name_info_value_error};

pub struct DriverIrp;

/// python `driverirp.MAJOR_FUNCTIONS` (index = IRP major function code).
pub const MAJOR_FUNCTIONS: [&str; 28] = [
    "IRP_MJ_CREATE",
    "IRP_MJ_CREATE_NAMED_PIPE",
    "IRP_MJ_CLOSE",
    "IRP_MJ_READ",
    "IRP_MJ_WRITE",
    "IRP_MJ_QUERY_INFORMATION",
    "IRP_MJ_SET_INFORMATION",
    "IRP_MJ_QUERY_EA",
    "IRP_MJ_SET_EA",
    "IRP_MJ_FLUSH_BUFFERS",
    "IRP_MJ_QUERY_VOLUME_INFORMATION",
    "IRP_MJ_SET_VOLUME_INFORMATION",
    "IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CONTROL",
    "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    "IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL",
    "IRP_MJ_CLEANUP",
    "IRP_MJ_CREATE_MAILSLOT",
    "IRP_MJ_QUERY_SECURITY",
    "IRP_MJ_SET_SECURITY",
    "IRP_MJ_POWER",
    "IRP_MJ_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CHANGE",
    "IRP_MJ_QUERY_QUOTA",
    "IRP_MJ_SET_QUOTA",
    "IRP_MJ_PNP",
];

/// python `MAJOR_FUNCTIONS.index("IRP_MJ_SHUTDOWN")`.
pub const IRP_MJ_SHUTDOWN: u64 = 16;

impl Plugin for DriverIrp {
    fn name(&self) -> &'static str {
        "windows.driverirp.DriverIrp"
    }
    fn description(&self) -> &'static str {
        "List IRPs for drivers in a particular windows memory image."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("Driver Name", ColType::Str),
            Column::new("IRP", ColType::Str),
            Column::new("Address", ColType::Hex),
            Column::new("Module", ColType::Str),
            Column::new("Symbol", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let collection = build_module_collection(k)?;
        let kernel_space_start = super::modules::get_kernel_space_start(k)?;
        scan_drivers_each(ctx, k, |driver| {
            let driver_name = match driver.get_driver_name() {
                Ok(n) => Value::Str(n),
                Err(e) if e.is_invalid_address() || is_name_info_value_error(&e) => Value::NotApplicable,
                Err(e) => return Err(e),
            };
            let mf = driver.m("MajorFunction")?;
            for i in 0..mf.count() {
                let irp_handler = match mf.at(i).and_then(|p| p.u64()) {
                    Ok(v) => v,
                    Err(e) if e.is_invalid_address() => continue,
                    Err(e) => return Err(e),
                };
                // smear
                if irp_handler < kernel_space_start {
                    continue;
                }
                let irp = MAJOR_FUNCTIONS.get(i as usize).copied().unwrap_or("");
                let row = |module: Value, symbol: Value| {
                    vec![Value::Int(driver.addr as i128), driver_name.clone(), Value::SStr(irp), Value::Int(irp_handler as i128), module, symbol]
                };
                let found = collection.module_symbols(irp_handler);
                if found.is_empty() {
                    out.row(0, row(Value::NotAvailable, Value::NotAvailable))?;
                }
                for (module_name, syms) in found {
                    if syms.is_empty() {
                        out.row(0, row(Value::str(module_name), Value::NotAvailable))?;
                    }
                    for s in syms {
                        out.row(0, row(Value::str(module_name), Value::str(s)))?;
                    }
                }
            }
            Ok(true)
        })
    }
}
