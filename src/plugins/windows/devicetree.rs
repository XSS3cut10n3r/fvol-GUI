//! windows.devicetree.DeviceTree (python `plugins/windows/devicetree.py`): drivers, their
//! devices and the attached-device chains as a tree.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::plugins::windows::driverscan::scan_drivers_each;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;
use crate::symbols::windows::objects::{ObjectsExt, is_name_info_value_error};

pub struct DeviceTree;

/// python `devicetree.DEVICE_CODES` (`DEVICE_CODES.get(code, "UNKNOWN")`).
pub fn device_code(code: i128) -> &'static str {
    match code {
        0x27 => "FILE_DEVICE_8042_PORT",
        0x32 => "FILE_DEVICE_ACPI",
        0x29 => "FILE_DEVICE_BATTERY",
        0x01 => "FILE_DEVICE_BEEP",
        0x2A => "FILE_DEVICE_BUS_EXTENDER",
        0x02 => "FILE_DEVICE_CD_ROM",
        0x03 => "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
        0x30 => "FILE_DEVICE_CHANGER",
        0x04 => "FILE_DEVICE_CONTROLLER",
        0x05 => "FILE_DEVICE_DATALINK",
        0x06 => "FILE_DEVICE_DFS",
        0x35 => "FILE_DEVICE_DFS_FILE_SYSTEM",
        0x36 => "FILE_DEVICE_DFS_VOLUME",
        0x07 => "FILE_DEVICE_DISK",
        0x08 => "FILE_DEVICE_DISK_FILE_SYSTEM",
        0x33 => "FILE_DEVICE_DVD",
        0x09 => "FILE_DEVICE_FILE_SYSTEM",
        0x3A => "FILE_DEVICE_FIPS",
        0x34 => "FILE_DEVICE_FULLSCREEN_VIDEO",
        0x0A => "FILE_DEVICE_INPORT_PORT",
        0x0B => "FILE_DEVICE_KEYBOARD",
        0x2F => "FILE_DEVICE_KS",
        0x39 => "FILE_DEVICE_KSEC",
        0x0C => "FILE_DEVICE_MAILSLOT",
        0x2D => "FILE_DEVICE_MASS_STORAGE",
        0x0D => "FILE_DEVICE_MIDI_IN",
        0x0E => "FILE_DEVICE_MIDI_OUT",
        0x2B => "FILE_DEVICE_MODEM",
        0x0F => "FILE_DEVICE_MOUSE",
        0x10 => "FILE_DEVICE_MULTI_UNC_PROVIDER",
        0x11 => "FILE_DEVICE_NAMED_PIPE",
        0x12 => "FILE_DEVICE_NETWORK",
        0x13 => "FILE_DEVICE_NETWORK_BROWSER",
        0x14 => "FILE_DEVICE_NETWORK_FILE_SYSTEM",
        0x28 => "FILE_DEVICE_NETWORK_REDIRECTOR",
        0x15 => "FILE_DEVICE_NULL",
        0x16 => "FILE_DEVICE_PARALLEL_PORT",
        0x17 => "FILE_DEVICE_PHYSICAL_NETCARD",
        0x18 => "FILE_DEVICE_PRINTER",
        0x19 => "FILE_DEVICE_SCANNER",
        0x1C => "FILE_DEVICE_SCREEN",
        0x37 => "FILE_DEVICE_SERENUM",
        0x1A => "FILE_DEVICE_SERIAL_MOUSE_PORT",
        0x1B => "FILE_DEVICE_SERIAL_PORT",
        0x31 => "FILE_DEVICE_SMARTCARD",
        0x2E => "FILE_DEVICE_SMB",
        0x1D => "FILE_DEVICE_SOUND",
        0x1E => "FILE_DEVICE_STREAMS",
        0x1F => "FILE_DEVICE_TAPE",
        0x20 => "FILE_DEVICE_TAPE_FILE_SYSTEM",
        0x38 => "FILE_DEVICE_TERMSRV",
        0x21 => "FILE_DEVICE_TRANSPORT",
        0x22 => "FILE_DEVICE_UNKNOWN",
        0x2C => "FILE_DEVICE_VDM",
        0x23 => "FILE_DEVICE_VIDEO",
        0x24 => "FILE_DEVICE_VIRTUAL_DISK",
        0x25 => "FILE_DEVICE_WAVE_IN",
        0x26 => "FILE_DEVICE_WAVE_OUT",
        _ => "UNKNOWN",
    }
}

/// `get_device_name()` / `get_driver_name()` with python's `except (ValueError,
/// InvalidAddressException)` -> `UnparsableValue`.
fn name_or_unparsable(r: Result<String>) -> Result<Value> {
    match r {
        Ok(n) => Ok(Value::Str(n)),
        Err(e) if e.is_invalid_address() || is_name_info_value_error(&e) => Ok(Value::Unparsable),
        Err(e) => Err(e),
    }
}

/// The rows of one driver (python's try block around it); stops at the first error.
fn driver_rows(driver: &Obj, out: &mut dyn RowSink) -> Result<()> {
    let off = Value::Int(driver.addr as i128);
    let driver_name = name_or_unparsable(driver.get_driver_name())?;
    out.row(0, vec![off.clone(), Value::SStr("DRV"), driver_name.clone(), Value::NotApplicable, Value::NotApplicable, Value::NotApplicable])?;
    for device in driver.get_devices() {
        let device = device?;
        let device_name = name_or_unparsable(device.get_device_name())?;
        let device_type = device_code(device.m("DeviceType")?.int()?);
        out.row(1, vec![off.clone(), Value::SStr("DEV"), driver_name.clone(), device_name, Value::NotApplicable, Value::SStr(device_type)])?;
        for (i, attached) in device.get_attached_devices().into_iter().enumerate() {
            let attached = attached?;
            let device_name = name_or_unparsable(attached.get_device_name())?;
            let att_driver_name = attached.m("DriverObject")?.m("DriverName")?.get_string()?;
            let att_type = device_code(attached.m("DeviceType")?.int()?);
            out.row(
                i + 2,
                vec![off.clone(), Value::SStr("ATT"), driver_name.clone(), device_name, Value::Str(att_driver_name), Value::SStr(att_type)],
            )?;
        }
    }
    Ok(())
}

impl Plugin for DeviceTree {
    fn name(&self) -> &'static str {
        "windows.devicetree.DeviceTree"
    }
    fn description(&self) -> &'static str {
        "Listing tree based on drivers and attached devices in a particular windows memory image."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("Type", ColType::Str),
            Column::new("DriverName", ColType::Str),
            Column::new("DeviceName", ColType::Str),
            Column::new("DriverNameOfAttDevice", ColType::Str),
            Column::new("DeviceType", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        scan_drivers_each(ctx, k, |driver| {
            match driver_rows(&driver, out) {
                Ok(()) => {}
                Err(e) if e.is_invalid_address() => {}
                Err(e) => return Err(e),
            }
            Ok(true)
        })
    }
}
