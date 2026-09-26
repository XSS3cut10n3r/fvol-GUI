//! windows.deskscan.DeskScan (python `plugins/windows/deskscan.py`): desktops found by pool
//! scanning (`Desk` tag) and their threads.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::plugins::windows::desktops::{DesktopRow, desktop_columns, desktop_values};
use crate::plugins::windows::windowstations::scan_gui_object;
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;
use crate::symbols::windows::gui::GuiExt;
use crate::symbols::windows::pool::PoolExt;

pub struct DeskScan;

/// python `DeskScan.scan_desktops(context, config_path, kernel)`, streaming.
pub fn scan_desktops(ctx: &Context, k: &WinKernel, mut f: impl FnMut(DesktopRow) -> Result<bool>) -> Result<()> {
    scan_gui_object(ctx, k, b"Desk", "tagDESKTOP", |desktop| {
        let Some(desktop_name) = desktop.executive_name(Some(k.table))?.filter(|n| !n.is_empty()) else { return Ok(true) };
        let Some(winsta) = desktop.desktop_get_window_station()? else { return Ok(true) };
        let Some((winsta_name, session_id)) = winsta.winsta_get_info(k.table)? else { return Ok(true) };
        for t in desktop.desktop_get_threads() {
            let (_thread, process_name, pid) = t?;
            if !f((desktop.addr, winsta_name.clone(), session_id, Some(desktop_name.clone()), process_name, pid))? {
                return Ok(false);
            }
        }
        Ok(true)
    })
}

impl Plugin for DeskScan {
    fn name(&self) -> &'static str {
        "windows.deskscan.DeskScan"
    }
    fn description(&self) -> &'static str {
        "Scans for the Desktop instances of each Window Station"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(desktop_columns())?;
        let k = ctx.windows_kernel()?;
        scan_desktops(ctx, k, |r| {
            out.row(0, desktop_values(r))?;
            Ok(true)
        })
    }
}
