//! windows.driverscan.DriverScan (python `plugins/windows/driverscan.py`) and its reusable
//! classmethods: [`scan_drivers_each`] / [`scan_drivers`] (pool-scanned `_DRIVER_OBJECT`s with
//! a sane `DriverStart`) and [`get_names_for_driver`].
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! use crate::plugins::windows::driverscan::{scan_drivers_each, get_names_for_driver};
//! scan_drivers_each(ctx, k, |driver| {
//!     let (driver_name, service_key, name) = get_names_for_driver(&driver)?;
//!     ...; Ok(true)                       // false = stop
//! })?;
//! ```

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::Obj;
use crate::plugins::windows::poolscanner::{builtin_constraints, generate_pool_scan_each};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::objects::{ObjectsExt, is_name_info_value_error};
use crate::symbols::windows::WinExt;

pub struct DriverScan;

/// python `DriverScan.scan_drivers(context, kernel_module_name)`, streaming: every pool-scanned
/// `_DRIVER_OBJECT` whose `DriverStart` is readable on the scanned layer and is either 0 or
/// above the kernel space start, in python's order (`f` returns `Ok(false)` to stop). Errors
/// python raises midway are returned after the drivers found before them.
pub fn scan_drivers_each(ctx: &Context, k: &WinKernel, mut f: impl FnMut(Obj) -> Result<bool>) -> Result<()> {
    let constraints = builtin_constraints(k.table.name(), &[b"Dri\xf6", b"Driv"]);
    let driver_start_offset = k.offset_of("_DRIVER_OBJECT", "DriverStart")?;
    let kernel_space_start = super::modules::get_kernel_space_start(k)?;
    generate_pool_scan_each(ctx, k, k.table, &constraints, |hit| {
        let d = hit.object;
        if !d.layer().is_valid(d.addr.wrapping_add(driver_start_offset), 8) {
            return Ok(true);
        }
        let ds = d.m("DriverStart")?.u64()?;
        if ds == 0 || ds > kernel_space_start {
            return f(d);
        }
        Ok(true)
    })
}

/// python `DriverScan.scan_drivers(...)` collected (a trailing `Err` = python raised there).
pub fn scan_drivers(ctx: &Context, k: &WinKernel) -> Vec<Result<Obj>> {
    let mut v = Vec::new();
    if let Err(e) = scan_drivers_each(ctx, k, |d| {
        v.push(Ok(d));
        Ok(true)
    }) {
        v.push(Err(e));
    }
    v
}

/// `Ok(Some(s))`, or `Ok(None)` for python's caught `InvalidAddressException`.
fn caught(r: Result<String>) -> Result<Option<String>> {
    match r {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.is_invalid_address() => Ok(None),
        Err(e) => Err(e),
    }
}

/// python `DriverScan.get_names_for_driver(driver)`: (driver name from the object header,
/// `DriverExtension.ServiceKeyName`, `DriverName`), each None when unreadable.
pub fn get_names_for_driver(driver: &Obj) -> Result<(Option<String>, Option<String>, Option<String>)> {
    let driver_name = match driver.get_driver_name() {
        Ok(n) => Some(n),
        Err(e) if e.is_invalid_address() || is_name_info_value_error(&e) => None,
        Err(e) => return Err(e),
    };
    let service_key = caught(driver.m("DriverExtension").and_then(|x| x.m("ServiceKeyName")).and_then(|x| x.get_string()))?;
    let name = caught(driver.m("DriverName").and_then(|x| x.get_string()))?;
    Ok((driver_name, service_key, name))
}

/// python truthiness of an optional string.
pub fn truthy(s: &Option<String>) -> bool {
    s.as_ref().is_some_and(|s| !s.is_empty())
}

/// python `s or renderers.NotAvailableValue()`.
pub fn or_not_available(s: Option<String>) -> Value {
    match s {
        Some(s) if !s.is_empty() => Value::Str(s),
        _ => Value::NotAvailable,
    }
}

impl Plugin for DriverScan {
    fn name(&self) -> &'static str {
        "windows.driverscan.DriverScan"
    }
    fn description(&self) -> &'static str {
        "Scans for drivers present in a particular windows memory image."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("Start", ColType::Hex),
            Column::new("Size", ColType::Hex),
            Column::new("Service Key", ColType::Str),
            Column::new("Driver Name", ColType::Str),
            Column::new("Name", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        scan_drivers_each(ctx, k, |d| {
            let (driver_name, service_key, name) = get_names_for_driver(&d)?;
            // Prior to #1481, this plugin reported dozens to hundreds of junk drivers per sample
            if !truthy(&driver_name) && !truthy(&service_key) && !truthy(&name) {
                return Ok(true);
            }
            out.row(
                0,
                vec![
                    Value::Int(d.addr as i128),
                    Value::Int(d.m("DriverStart")?.u64()? as i128),
                    Value::Int(d.m("DriverSize")?.int()?),
                    or_not_available(service_key),
                    or_not_available(driver_name),
                    or_not_available(name),
                ],
            )?;
            Ok(true)
        })
    }
}
