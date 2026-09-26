//! windows.crashinfo.Crashinfo (python `plugins/windows/crashinfo.py`): the header of a
//! Windows crash dump.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::layers::containers::crash;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};

pub struct Crashinfo;

/// python `str(datetime.timedelta(microseconds=x))` for a non-negative float `x`
/// (rounded half-even to whole microseconds like the timedelta constructor).
pub fn timedelta_str(micros: f64) -> String {
    let us = {
        let f = micros.floor();
        let d = micros - f;
        let r = if d > 0.5 || (d == 0.5 && (f as i128) % 2 != 0) { f + 1.0 } else { f };
        r as i128
    };
    let days = us.div_euclid(86_400_000_000);
    let rem = us.rem_euclid(86_400_000_000);
    let secs = rem / 1_000_000;
    let frac = rem % 1_000_000;
    let (h, m, s) = (secs / 3600, (secs / 60) % 60, secs % 60);
    let mut out = String::new();
    if days != 0 {
        out.push_str(&format!("{days} day{}, ", if days.abs() != 1 { "s" } else { "" }));
    }
    out.push_str(&format!("{h}:{m:02}:{s:02}"));
    if frac != 0 {
        out.push_str(&format!(".{frac:06}"));
    }
    out
}

/// python `utility.array_to_string` of a char array: bytes up to the first NUL, UTF-8 with
/// replacement characters.
fn char_array(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

impl Plugin for Crashinfo {
    fn name(&self) -> &'static str {
        "windows.crashinfo.Crashinfo"
    }
    fn description(&self) -> &'static str {
        "Lists the information from a Windows crash dump."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        // requirement "primary" (a translation layer over the image)
        let (phys, _) = ctx.physical_arc().map_err(|_| crate::plugins::unsatisfied(&["primary"]))?;
        let Some(h) = crash::find_header(phys) else {
            // vollog.error("This plugin requires a Windows crash dump"); raise
            panic!("No active exception to reraise");
        };
        out.begin(vec![
            Column::new("Signature", ColType::Str),
            Column::new("MajorVersion", ColType::Int),
            Column::new("MinorVersion", ColType::Int),
            Column::new("DirectoryTableBase", ColType::Hex),
            Column::new("PfnDataBase", ColType::Hex),
            Column::new("PsLoadedModuleList", ColType::Hex),
            Column::new("PsActiveProcessHead", ColType::Hex),
            Column::new("MachineImageType", ColType::Int),
            Column::new("NumberProcessors", ColType::Int),
            Column::new("KdDebuggerDataBlock", ColType::Hex),
            Column::new("DumpType", ColType::Str),
            Column::new("SystemUpTime", ColType::Str),
            Column::new("Comment", ColType::Str),
            Column::new("SystemTime", ColType::DateTime),
            Column::new("BitmapHeaderSize", ColType::Hex),
            Column::new("BitmapSize", ColType::Hex),
            Column::new("BitmapPages", ColType::Hex),
        ])?;
        let dump_type = match h.dump_type {
            1 => "Full Dump (0x1)".to_string(),
            5 => "Bitmap Dump (0x5)".to_string(),
            t => format!("Unknown/Unsupported ({t:#x})"),
        };
        let (hs, bs, pages) = match (&h.summary, h.dump_type) {
            (Some(s), 5) => (Value::Int(s.header_size as i128), Value::Int(s.bitmap_size as i128), Value::Int(s.pages as i128)),
            _ => (Value::NotApplicable, Value::NotApplicable, Value::NotApplicable),
        };
        out.row(
            0,
            vec![
                Value::Str(char_array(&h.signature)),
                Value::Int(h.major_version as i128),
                Value::Int(h.minor_version as i128),
                Value::Int(h.directory_table_base as i128),
                Value::Int(h.pfn_data_base as i128),
                Value::Int(h.ps_loaded_module_list as i128),
                Value::Int(h.ps_active_process_head as i128),
                Value::Int(h.machine_image_type as i128),
                Value::Int(h.number_processors as i128),
                Value::Int(h.kd_debugger_data_block as i128),
                Value::Str(dump_type),
                Value::Str(timedelta_str(h.system_up_time as f64 / 10.0)),
                Value::Str(char_array(&h.comment)),
                crate::util::time::wintime_to_datetime(h.system_time as i128),
                hs,
                bs,
                pages,
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::timedelta_str;

    #[test]
    fn timedelta() {
        assert_eq!(timedelta_str(0.0), "0:00:00");
        assert_eq!(timedelta_str(1.5), "0:00:00.000002");
        assert_eq!(timedelta_str(2.5), "0:00:00.000002");
        assert_eq!(timedelta_str(3_600_000_000.0 * 25.0 + 1.0), "1 day, 1:00:00.000001");
        assert_eq!(timedelta_str(86_400_000_000.0 * 3.0), "3 days, 0:00:00");
    }
}
