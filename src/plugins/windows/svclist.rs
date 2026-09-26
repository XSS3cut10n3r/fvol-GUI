//! windows.svclist.SvcList (python `plugins/windows/svclist.py`): services reachable from the
//! `Sc27` service-header list inside the services.exe image.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::layers::scan::{BytesScanner, scan};
use crate::objects::Obj;
use crate::plugins::windows::svcscan::{Prereq, ServiceRow, columns, enumerate_headers, get_prereq_info, services_filter};
use crate::plugins::{Config, Plugin};
use crate::renderers::text::RowEncoder;
use crate::renderers::{RowSink, Value};
use crate::symbols::windows::prelude::*;
use crate::symbols::windows::versions;

pub struct SvcList;

/// python `SvcList._get_exe_range(proc)`: `[(start, size)]` of the VAD mapping
/// `...\services.exe`, or None.
fn get_exe_range(proc: &Obj) -> Result<Option<(u64, u64)>> {
    for vad in proc.get_vad_root()?.traverse() {
        let vad = vad?;
        if let Value::Str(f) = vad.get_file_name() {
            if f.to_lowercase().ends_with("\\services.exe") {
                return Ok(Some((vad.get_start()?, vad.get_size()?)));
            }
        }
    }
    Ok(None)
}

/// python `SvcList.service_list(...)`: every row python yields, in order (formatted with `enc`
/// when given).
pub fn service_list(k: &WinKernel, pre: &Prereq, enc: Option<&RowEncoder>, f: &mut dyn FnMut(ServiceRow) -> Result<()>) -> Result<()> {
    if !k.table.is_64bit() || !versions::IS_WIN10_15063_OR_LATER.check(k.table) {
        // python: vollog.warning("This plugin only supports Windows 10 version 15063+ ...")
        return Ok(());
    }
    for proc in crate::plugins::windows::pslist::list_processes(k, &services_filter) {
        let proc = proc?;
        let proc_layer = match proc.add_process_layer() {
            Ok(l) => l,
            Err(e) if e.is_invalid_address() => {
                // the warning's f-string reads the pid
                proc.m("UniqueProcessId")?.int()?;
                continue;
            }
            Err(e) => return Err(e),
        };
        let Some(range) = get_exe_range(&proc)? else { continue };
        let offsets = scan(proc_layer, &BytesScanner::new(b"Sc27"), Some(&[range]));
        enumerate_headers(pre.table, &pre.binary_map, proc_layer, &offsets, enc, f)?;
    }
    Ok(())
}

impl Plugin for SvcList {
    fn name(&self) -> &'static str {
        "windows.svclist.SvcList"
    }
    fn description(&self) -> &'static str {
        "Lists services contained with the services.exe doubly linked list of services"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(columns())?;
        let k = ctx.windows_kernel()?;
        let pre = get_prereq_info(ctx, k)?;
        let enc = out.encoder();
        service_list(k, &pre, enc.as_ref(), &mut |row| row.emit(out))
    }
}
