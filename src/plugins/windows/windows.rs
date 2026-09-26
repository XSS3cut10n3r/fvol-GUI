//! windows.windows.Windows (python `plugins/windows/windows.py`): the windows (tagWND) of the
//! desktop of each window station.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::util::array_to_string;
use crate::plugins::windows::windowstations::scan_window_stations;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::gui::{GuiExt, WndRef, desktop_windows};

pub struct Windows;

/// python `Windows.list_windows(context, config_path, kernel)`, streaming
/// `(station name, desktop name, window, window name)`.
/// (Window order within a sibling group: see [`desktop_windows`].)
pub fn list_windows(ctx: &Context, k: &WinKernel, mut f: impl FnMut(&str, &Option<String>, WndRef, Option<String>) -> Result<bool>) -> Result<()> {
    scan_window_stations(ctx, k, |winsta, station_name, _session_id| {
        for (desktop, desktop_name) in winsta.winsta_desktops(k.table)? {
            // python: desktop.pDeskInfo.spwnd (both pointers read) -> the spwnd Pointer object
            let top = match desktop.m("pDeskInfo").and_then(|p| p.m("spwnd")).and_then(WndRef::from_pointer) {
                Ok(t) => t,
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            };
            let mut go = true;
            desktop_windows(top, 10000, &mut |w, name| {
                go = f(&station_name, &desktop_name, w, name)?;
                Ok(go)
            })?;
            if !go {
                return Ok(false);
            }
        }
        Ok(true)
    })
}

impl Plugin for Windows {
    fn name(&self) -> &'static str {
        "windows.windows.Windows"
    }
    fn description(&self) -> &'static str {
        "Enumerates the Windows of Desktop instances"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("Station", ColType::Str),
            Column::new("Session", ColType::Int),
            Column::new("Desktop", ColType::Str),
            Column::new("Window", ColType::Str),
            Column::new("Procedure", ColType::Hex),
            Column::new("Process", ColType::Str),
            Column::new("PID", ColType::Int),
        ])?;
        let k = ctx.windows_kernel()?;
        // python keeps `process_pid` from an earlier row when only the name could be read
        let mut process_pid: Option<i128> = None;
        list_windows(ctx, k, |station_name, desktop_name, window, window_name| {
            let w = window.wnd;
            let mut process_name = None;
            if let Some(process) = w.wnd_get_process()? {
                let r = (|| -> Result<()> {
                    process_name = Some(array_to_string(&process.m("ImageFileName")?, None)?);
                    process_pid = Some(process.m("UniqueProcessId")?.int()?);
                    Ok(())
                })();
                match r {
                    Ok(()) => {}
                    Err(e) if e.is_invalid_address() => {}
                    Err(e) => return Err(e),
                }
            }
            let Some(process_name) = process_name else { return Ok(true) };
            let Some(sess_id) = w.wnd_get_session_id()? else { return Ok(true) };
            let window_proc = match w.wnd_get_window_procedure()? {
                None => Value::NotAvailable,
                Some(p) if p == 0 || p > 0x1000 => Value::Int(p as i128),
                Some(_) => return Ok(true),
            };
            let Some(pid) = process_pid else {
                panic!("UnboundLocalError: cannot access local variable 'process_pid' where it is not associated with a value")
            };
            let Some(desktop_name) = desktop_name.clone() else {
                panic!("TypeError: Values item with index 3 is the wrong type for column Desktop (got <class 'NoneType'> but expected <class 'str'>)")
            };
            out.row(
                0,
                vec![
                    Value::Int(window.offset as i128),
                    Value::str(station_name),
                    Value::Int(sess_id),
                    Value::Str(desktop_name),
                    window_name.filter(|n| !n.is_empty()).map(Value::Str).unwrap_or(Value::NotAvailable),
                    window_proc,
                    Value::Str(process_name),
                    Value::Int(pid),
                ],
            )?;
            Ok(true)
        })
    }
}
