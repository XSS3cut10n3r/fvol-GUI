//! windows.modules.Modules (python `plugins/windows/modules.py`) and the pedump helpers it
//! uses (`PEDump.dump_pe`, `dump_ldr_entry`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::objects::{LayerRef, Obj, Space};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::windows::{WinExt, pe};
use std::io::Write;

pub struct Modules;

/// python `Modules.list_modules(context, kernel)`: `PsLoadedModuleList` entries
/// (`_KLDR_DATA_TABLE_ENTRY` on Windows 10+, else `_LDR_DATA_TABLE_ENTRY`). A trailing `Err`
/// means python would have raised at that point.
pub fn list_modules(k: &WinKernel) -> Vec<Result<Obj>> {
    let r = (|| -> Result<Vec<Result<Obj>>> {
        if k.base == 0 {
            return Err(Error::msg("Intel layer does not have an associated kernel virtual offset, failing"));
        }
        let tname = if k.table.user_type("_KLDR_DATA_TABLE_ENTRY").is_some() { "_KLDR_DATA_TABLE_ENTRY" } else { "_LDR_DATA_TABLE_ENTRY" };
        let head = k.get_symbol("PsLoadedModuleList")?.address;
        let list_entry = k.object("_LIST_ENTRY", head)?;
        let reloff = k.offset_of(tname, "InLoadOrderLinks")?;
        let module = k.object_abs(tname, list_entry.addr.wrapping_sub(reloff))?;
        Ok(module.m("InLoadOrderLinks")?.to_list(tname, "InLoadOrderLinks", true, true, None).collect())
    })();
    match r {
        Ok(v) => v,
        Err(e) => vec![Err(e)],
    }
}

/// python `Modules.get_kernel_space_start(context, kernel)`: the value of `MmSystemRangeStart`
/// (0xFFFF800000000000 / 0x80000000 when it is paged out), masked to the kernel layer.
pub fn get_kernel_space_start(k: &WinKernel) -> Result<u64> {
    let (ty, default) = if k.table.is_64bit() { ("unsigned long long", 0xFFFF_8000_0000_0000u64) } else { ("unsigned long", 0x8000_0000) };
    let off = k.get_symbol("MmSystemRangeStart")?.address;
    let start = match k.object(ty, off).and_then(|o| o.u64()) {
        Ok(v) => v,
        Err(e) if e.is_invalid_address() => default,
        Err(e) => return Err(e),
    };
    Ok(start & k.vlayer.address_mask())
}

/// python `Modules.get_session_layers(context, kernel, pids)`: one process layer per session.
pub fn get_session_layers(k: &WinKernel, pids: &[i128]) -> Result<Vec<LayerRef>> {
    let filter = super::pslist::pid_filter(pids);
    let mut seen: Vec<i128> = Vec::new();
    let mut out = Vec::new();
    for p in super::pslist::list_processes(k, &filter) {
        let proc = p?;
        let r = (|| -> Result<(i128, LayerRef)> {
            let pl = proc.add_process_layer()?;
            let session = proc.m("Session")?.u64()?;
            let sid = if k.table.user_type("_MM_SESSION_SPACE").is_some() {
                k.object_abs("_MM_SESSION_SPACE", session)?.m("SessionId")?.int()?
            } else {
                k.object_abs("unsigned long", session.wrapping_add(8))?.int()?
            };
            Ok((sid, pl))
        })();
        match r {
            Ok((sid, pl)) => {
                if seen.contains(&sid) {
                    continue;
                }
                seen.push(sid);
                out.push(pl);
            }
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// python `Modules.get_session_layers_map(context, kernel, pids)`: `(session id, process
/// layer)` for the first process of each session, in process-list order (python's dict).
pub fn get_session_layers_map(k: &WinKernel, pids: &[i128]) -> Result<Vec<(i128, LayerRef)>> {
    let filter = super::pslist::pid_filter(pids);
    let has_session_space = k.table.user_type("_MM_SESSION_SPACE").is_some();
    let mut out: Vec<(i128, LayerRef)> = Vec::new();
    for p in super::pslist::list_processes(k, &filter) {
        let proc = p?;
        let r = (|| -> Result<(i128, LayerRef)> {
            let pl = proc.add_process_layer()?;
            let session = proc.m("Session")?.u64()?;
            let sid = if has_session_space {
                k.object_abs("_MM_SESSION_SPACE", session)?.m("SessionId")?.int()?
            } else {
                k.object_abs("unsigned long", session.wrapping_add(8))?.int()?
            };
            Ok((sid, pl))
        })();
        match r {
            Ok((sid, pl)) => {
                if !out.iter().any(|(s, _)| *s == sid) {
                    out.push((sid, pl));
                }
            }
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// python `Modules.find_session_layer(context, session_layers, base)`.
pub fn find_session_layer(layers: &[LayerRef], base: u64) -> Option<LayerRef> {
    layers.iter().copied().find(|l| l.is_valid(base, 1))
}

/// python `PEDump.dump_pe(context, pe_table, layer, open_method, file_name, base)`: the file is
/// always created and committed; returns the printed name, or None when reconstruction failed.
/// python returns `preferred_filename` inside the `with` block (before close), i.e. the
/// requested name even when the file got a `-N` suffix.
pub fn dump_pe(ctx: &Context, pe_table: TableRef, layer: LayerRef, file_name: &str, base: u64) -> Option<String> {
    let (mut f, _final_name) = ctx.create_output_file(file_name).ok()?;
    let printed = file_name.to_string();
    let dos = Obj::named(Space::on(layer, pe_table), "_IMAGE_DOS_HEADER", base).ok()?;
    let (pieces, err) = pe::reconstruct(&dos);
    let _ = pe::write_pieces(&mut f, &pieces);
    let _ = f.flush();
    if err.is_some() { None } else { Some(printed) }
}

/// python `ntpath.basename`.
pub fn ntpath_basename(p: &str) -> &str {
    let p = if p.len() >= 2 && p.as_bytes()[1] == b':' { &p[2..] } else { p };
    match p.rfind(['\\', '/']) {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

/// python `PEDump.dump_ldr_entry(context, pe_table, ldr_entry, open_method, layer_name, prefix)`.
pub fn dump_ldr_entry(ctx: &Context, pe_table: TableRef, ldr: &Obj, layer: Option<LayerRef>, prefix: &str) -> Result<Option<String>> {
    let name = match ldr.m("FullDllName")?.get_string() {
        Ok(n) => n,
        Err(e) if e.is_invalid_address() => "UnreadableDLLName".to_string(),
        Err(e) => return Err(e),
    };
    let layer = layer.unwrap_or(ldr.layer());
    let base = ldr.m("DllBase")?.u64()?;
    let file_name = format!("{prefix}{}.{:#x}.{:#x}.dmp", ntpath_basename(&name), ldr.addr, base);
    Ok(dump_pe(ctx, pe_table, layer, &file_name, base))
}

impl Plugin for Modules {
    fn name(&self) -> &'static str {
        "windows.modules.Modules"
    }
    fn description(&self) -> &'static str {
        "Lists the loaded kernel modules."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::flag("dump", "Extract listed modules"),
            Requirement::new("base", "Extract a single module with BASE address", ReqKind::Int).optional(),
            Requirement::new("name", "module name/sub string", ReqKind::Str).optional(),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("Base", ColType::Hex),
            Column::new("Size", ColType::Hex),
            Column::new("Name", ColType::Str),
            Column::new("Path", ColType::Str),
            Column::new("File output", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let dump = cfg.get_bool("dump");
        let base_filter = cfg.get_int("base").filter(|b| *b != 0);
        let name_filter = cfg.get_str("name").filter(|n| !n.is_empty());
        let (pe_table, session_layers) = if dump { (Some(ctx.load_isf("windows/pe")?), get_session_layers(k, &[])?) } else { (None, Vec::new()) };
        for m in list_modules(k) {
            let m = m?;
            let dll_base = m.m("DllBase")?.u64()?;
            if let Some(b) = base_filter {
                if b != dll_base as i128 {
                    continue;
                }
            }
            let base_name = match m.m("BaseDllName")?.get_string() {
                Ok(n) => {
                    if let Some(f) = name_filter {
                        if !n.contains(f) {
                            continue;
                        }
                    }
                    Value::Str(n)
                }
                Err(e) if e.is_invalid_address() => Value::Unreadable,
                Err(e) => return Err(e),
            };
            let full_name = match m.m("FullDllName")?.get_string() {
                Ok(n) => Value::Str(n),
                Err(e) if e.is_invalid_address() => Value::Unreadable,
                Err(e) => return Err(e),
            };
            let file_output = if dump {
                match find_session_layer(&session_layers, dll_base) {
                    Some(l) => match dump_ldr_entry(ctx, pe_table.unwrap(), &m, Some(l), "")? {
                        Some(n) => Value::Str(n),
                        None => Value::SStr("Error outputting file"),
                    },
                    None => Value::Str(format!("Cannot find a viable session layer for {dll_base:#x}")),
                }
            } else {
                Value::SStr("Disabled")
            };
            out.row(
                0,
                vec![Value::Int(m.addr as i128), Value::Int(dll_base as i128), Value::Int(m.m("SizeOfImage")?.int()?), base_name, full_name, file_output],
            )?;
        }
        Ok(())
    }
}
