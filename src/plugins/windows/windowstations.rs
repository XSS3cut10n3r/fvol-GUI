//! windows.windowstations.WindowStations (python `plugins/windows/windowstations.py`) and its
//! reusable classmethods: [`get_session_map`], [`scan_gui_object`] (generic scanner for
//! win32k pool objects, re-created in their session's address space) and
//! [`scan_window_stations`].
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::{Obj, Space};
use crate::plugins::windows::modules::get_session_layers_map;
use crate::plugins::windows::poolscanner::{generate_pool_scan_each, gui_poolscanner_constraints};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::windows::gui::{GuiExt, create_gui_table};
use crate::util::FxHashSet;

pub struct WindowStations;

/// python `WindowStations.get_session_map(context, kernel, gui_table)`: session id -> the GUI
/// table bound to that session's layer (python `context.module(gui_table, session_layer,
/// kernel.offset)`), in python's dict order.
pub fn get_session_map(k: &WinKernel, gui_table: TableRef) -> Result<Vec<(i128, &'static Space)>> {
    Ok(get_session_layers_map(k, &[])?.into_iter().map(|(sid, layer)| (sid, Space::on(layer, gui_table))).collect())
}

/// python `WindowStations.scan_gui_object(context, config_path, kernel, object_tag,
/// object_type)`, streaming: every pool object with `tag` whose session is known, as an
/// `object_type` of the GUI table in its session's layer (`f` returns false to stop).
pub fn scan_gui_object(ctx: &Context, k: &WinKernel, tag: &[u8], object_type: &str, mut f: impl FnMut(Obj) -> Result<bool>) -> Result<()> {
    // python raises NotImplementedError (not a volatility exception, so a crash) for x86 and
    // unknown versions
    let gui_table = match create_gui_table(ctx, k.table) {
        Ok(t) => t,
        Err(crate::error::Error::Msg(m)) if m.starts_with("NotImplementedError") => panic!("{m}"),
        Err(e) => return Err(e),
    };
    let constraints = gui_poolscanner_constraints(gui_table.name(), &[tag]);
    let session_map = get_session_map(k, gui_table)?;
    let ty = gui_table.get_type(object_type)?;
    generate_pool_scan_each(ctx, k, gui_table, &constraints, |hit| {
        let mem = hit.object;
        let session_id = match mem.struct_name() {
            Some("tagWINDOWSTATION") => mem.winsta_get_session_id()?,
            Some("tagDESKTOP") => mem.desktop_get_session_id()?,
            Some("tagWND") => mem.wnd_get_session_id()?,
            _ => None,
        };
        let Some(sid) = session_id else { return Ok(true) };
        let Some((_, sp)) = session_map.iter().find(|(s, _)| *s == sid) else { return Ok(true) };
        f(Obj::new(sp, ty, mem.addr))
    })
}

/// python `WindowStations.scan_window_stations(context, config_path, kernel)`, streaming
/// `(tagWINDOWSTATION, name, session id)`.
pub fn scan_window_stations(ctx: &Context, k: &WinKernel, mut f: impl FnMut(Obj, String, i128) -> Result<bool>) -> Result<()> {
    let mut seen = FxHashSet::default();
    scan_gui_object(ctx, k, b"Wind", "tagWINDOWSTATION", |scanned| {
        for winsta in scanned.winsta_traverse()? {
            if !seen.insert(winsta.addr) {
                continue;
            }
            if let Some((name, sid)) = winsta.winsta_get_info(k.table)? {
                if !f(winsta, name, sid)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    })
}

impl Plugin for WindowStations {
    fn name(&self) -> &'static str {
        "windows.windowstations.WindowStations"
    }
    fn description(&self) -> &'static str {
        "Scans for top level Windows Stations"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("Offset", ColType::Hex), Column::new("Name", ColType::Str), Column::new("SessionId", ColType::Int)])?;
        let k = ctx.windows_kernel()?;
        scan_window_stations(ctx, k, |winsta, name, sid| {
            out.row(0, vec![Value::Int(winsta.addr as i128), Value::Str(name), Value::Int(sid)])?;
            Ok(true)
        })
    }
}
