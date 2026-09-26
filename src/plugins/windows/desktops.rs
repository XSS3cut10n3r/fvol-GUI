//! windows.desktops.Desktops (python `plugins/windows/desktops.py`): the desktop of each
//! window station (found by scanning) and the threads of each desktop.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::plugins::windows::windowstations::scan_window_stations;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::gui::GuiExt;

pub struct Desktops;

/// One output row of Desktops / DeskScan: (desktop offset, station name, session id,
/// desktop name, process name, pid).
pub type DesktopRow = (u64, String, i128, Option<String>, String, i128);

/// The table both plugins render.
pub fn desktop_columns() -> Vec<Column> {
    vec![
        Column::new("Offset", ColType::Hex),
        Column::new("Window Station", ColType::Str),
        Column::new("Session", ColType::Int),
        Column::new("Desktop", ColType::Str),
        Column::new("Process", ColType::Str),
        Column::new("PID", ColType::Int),
    ]
}

/// Render one [`DesktopRow`]. python passes the desktop name through as-is; a None name
/// fails the TreeGrid's type validation (an uncaught `TypeError`, i.e. a crash: panic).
pub fn desktop_values(r: DesktopRow) -> Vec<Value> {
    let Some(desktop_name) = r.3 else {
        panic!("TypeError: Values item with index 3 is the wrong type for column Desktop (got <class 'NoneType'> but expected <class 'str'>)")
    };
    vec![Value::Int(r.0 as i128), Value::Str(r.1), Value::Int(r.2), Value::Str(desktop_name), Value::Str(r.4), Value::Int(r.5)]
}

/// python `Desktops.list_desktops(context, config_path, kernel)`, streaming.
pub fn list_desktops(ctx: &Context, k: &WinKernel, mut f: impl FnMut(DesktopRow) -> Result<bool>) -> Result<()> {
    scan_window_stations(ctx, k, |winsta, station_name, session_id| {
        for (desktop, desktop_name) in winsta.winsta_desktops(k.table)? {
            for t in desktop.desktop_get_threads() {
                let (_thread, process_name, pid) = t?;
                if !f((desktop.addr, station_name.clone(), session_id, desktop_name.clone(), process_name, pid))? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    })
}

impl Plugin for Desktops {
    fn name(&self) -> &'static str {
        "windows.desktops.Desktops"
    }
    fn description(&self) -> &'static str {
        "Enumerates the Desktop instances of each Window Station"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(desktop_columns())?;
        let k = ctx.windows_kernel()?;
        list_desktops(ctx, k, |r| {
            out.row(0, desktop_values(r))?;
            Ok(true)
        })
    }
}
