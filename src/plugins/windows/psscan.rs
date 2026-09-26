//! windows.psscan.PsScan (python `plugins/windows/psscan.py`): processes found by pool
//! scanning (`Proc` / `Pro\xe3` tags), plus python's reusable classmethods
//! ([`scan_processes`], [`virtual_process_from_physical`], [`physical_offset_from_virtual`],
//! [`create_offset_filter`], [`get_osversion`]).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::plugins::windows::poolscanner::{builtin_constraints, generate_pool_scan_each};
use crate::plugins::windows::pslist::{pid_filter, process_dump};
use crate::plugins::{Config, Plugin, ReqKind, Requirement, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;
use crate::symbols::{StrEnc, StrErrors};

pub struct PsScan;

/// python `PsScan.scan_processes(context, kernel, filter_func)`, streaming: every `_EPROCESS`
/// the pool scan finds that `filter` does not reject (filter returns true = skip) is passed to
/// `f` in python's order (`Ok(false)` stops). Errors python would raise midway are returned
/// after the processes found before them.
pub fn scan_processes_each(ctx: &Context, k: &WinKernel, filter: &dyn Fn(&Obj) -> Result<bool>, mut f: impl FnMut(Obj) -> Result<bool>) -> Result<()> {
    let constraints = builtin_constraints(k.table.name(), &[b"Pro\xe3", b"Proc"]);
    generate_pool_scan_each(ctx, k, k.table, &constraints, |hit| {
        if filter(&hit.object)? {
            return Ok(true);
        }
        f(hit.object)
    })
}

/// python `PsScan.scan_processes(...)` collected (a trailing `Err` = python raised there).
pub fn scan_processes(ctx: &Context, k: &WinKernel, filter: &dyn Fn(&Obj) -> Result<bool>) -> Vec<Result<Obj>> {
    let mut v = Vec::new();
    if let Err(e) = scan_processes_each(ctx, k, filter, |p| {
        v.push(Ok(p));
        Ok(true)
    }) {
        v.push(Err(e));
    }
    v
}

/// python `PsScan.physical_offset_from_virtual(context, layer_name, proc)`: the physical
/// address of the process object (`mapping(offset, 0)[0]`; unmapped = error, like python).
pub fn physical_offset_from_virtual(k: &WinKernel, proc: &Obj) -> Result<u64> {
    match k.layer.translate_addr(proc.addr) {
        Some((pa, _)) => Ok(pa),
        None => Err(Error::invalid(proc.addr)),
    }
}

/// python `PsScan.create_offset_filter(context, layer_name, offset, physical, exclude)`
/// (returns true for processes to skip; no offset = keep everything).
pub fn create_offset_filter(k: &WinKernel, offset: Option<u64>, physical: bool, exclude: bool) -> impl Fn(&Obj) -> Result<bool> + '_ {
    move |proc: &Obj| {
        let Some(offset) = offset.filter(|o| *o != 0) else { return Ok(false) };
        let at = if physical { physical_offset_from_virtual(k, proc)? } else { proc.addr };
        Ok(if exclude { at == offset } else { at != offset })
    }
}

/// python `PsScan.get_osversion(context, kernel)`: (NtMajorVersion, NtMinorVersion, build).
pub fn get_osversion(k: &WinKernel) -> Result<(i128, i128, i128)> {
    let kuser = crate::plugins::windows::info::get_kuser_structure(k)?;
    let major = kuser.m("NtMajorVersion")?.int()?;
    let minor = kuser.m("NtMinorVersion")?.int()?;
    let vers = crate::plugins::windows::info::get_version_structure(k)?;
    let build = vers.m("MinorVersion")?.int()?;
    Ok((major, minor, build))
}

/// python `PsScan.virtual_process_from_physical(context, kernel, proc)`: bounce through the
/// first thread to the `_EPROCESS` on the kernel's virtual layer (None if the bounce does not
/// lead back to `proc`). An `Err` that is not a paging fault is python raising.
pub fn virtual_process_from_physical(k: &WinKernel, proc: &Obj) -> Result<Option<Obj>> {
    let version = get_osversion(k)?;
    let tleoffset = k.offset_of("_ETHREAD", "ThreadListEntry")?;
    let mut offsets = vec![tleoffset];
    if version == (6, 1, 7601) && k.layer.bits_per_register() == 64 {
        offsets.push(tleoffset + 8);
    }
    for ofs in offsets {
        let flink = proc.m("ThreadListHead")?.m("Flink")?.u64()?;
        let ethread = k.object_abs("_ETHREAD", flink.wrapping_sub(ofs))?;
        let vproc = ethread.owning_process()?;
        let ph = physical_offset_from_virtual(k, &vproc)?;
        if proc.addr == ph {
            return Ok(Some(vproc));
        }
    }
    Ok(None)
}

/// The name python's psscan prints for a dump: `file_handle.preferred_filename` read BEFORE
/// the handle is closed, i.e. the sanitized requested name (the file on disk may get a `-N`
/// suffix). Same reads as `process_dump`, which succeeded when this is called.
fn preferred_dump_name(k: &WinKernel, proc: &Obj) -> Option<String> {
    let pl = proc.add_process_layer().ok()?;
    let peb = Obj::named(crate::objects::Space::on(pl, k.table), "_PEB", proc.m("Peb").ok()?.u64().ok()?).ok()?;
    let base = peb.m("ImageBaseAddress").ok()?.u64().ok()?;
    let name = proc.image_file_name_str().ok()?;
    let pid = proc.m("UniqueProcessId").ok()?.int().ok()?;
    Some(crate::plugins::windows::pslist::sanitize_filename(&format!("{pid}.{name}.{base:#x}.dmp")))
}

fn rows(ctx: &Context, cfg: &Config, out: &mut dyn FnMut(Vec<Value>) -> Result<()>) -> Result<()> {
    let k = ctx.windows_kernel()?;
    let physical = cfg.get_bool("physical");
    let dump = cfg.get_bool("dump");
    let pids = cfg.get_ints("pid");
    let filter = pid_filter(&pids);
    let vlayer_id = k.vlayer as *const dyn crate::layers::Layer as *const u8;
    scan_processes_each(ctx, k, &filter, |proc| {
        let mut file_output = Value::SStr("Disabled");
        if dump {
            let vproc = if proc.layer() as *const dyn crate::layers::Layer as *const u8 == vlayer_id {
                Some(proc)
            } else {
                match virtual_process_from_physical(k, &proc) {
                    Ok(v) => v,
                    Err(e) if e.is_invalid_address() => None,
                    Err(e) => return Err(e),
                }
            };
            file_output = Value::SStr("Error outputting file");
            if let Some(vproc) = vproc {
                if let Some(written) = process_dump(ctx, k, &vproc) {
                    file_output = Value::Str(preferred_dump_name(k, &vproc).unwrap_or(written));
                }
            }
        }
        let offset = if physical { physical_offset_from_virtual(k, &proc)? } else { proc.addr };
        let row = (|| -> Result<Vec<Value>> {
            let name = proc.m("ImageFileName")?;
            let name = name.cast_string(name.count(), StrEnc::Utf8, StrErrors::Replace).string()?;
            Ok(vec![
                Value::Int(proc.m("UniqueProcessId")?.int()?),
                Value::Int(proc.m("InheritedFromUniqueProcessId")?.int()?),
                Value::Str(name),
                Value::Int(offset as i128),
                Value::Int(proc.m("ActiveThreads")?.int()?),
                proc.get_handle_count(),
                proc.get_session_id()?,
                Value::Bool(proc.get_is_wow64()?),
                proc.get_create_time()?,
                proc.get_exit_time()?,
                file_output.clone(),
            ])
        })();
        match row {
            Ok(r) => out(r)?,
            Err(e) if e.is_invalid_address() => {}
            Err(e) => return Err(e),
        }
        Ok(true)
    })
}

impl Plugin for PsScan {
    fn name(&self) -> &'static str {
        "windows.psscan.PsScan"
    }
    fn description(&self) -> &'static str {
        "Scans for processes present in a particular windows memory image."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Process ID to include (all other processes are excluded)", ReqKind::ListInt).optional(),
            Requirement::flag("dump", "Extract listed processes"),
            Requirement::flag("physical", "Display physical offset instead of virtual"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let off = if cfg.get_bool("physical") { "Offset(P)" } else { "Offset(V)" };
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("PPID", ColType::Int),
            Column::new("ImageFileName", ColType::Str),
            Column::new(off, ColType::Hex),
            Column::new("Threads", ColType::Int),
            Column::new("Handles", ColType::Int),
            Column::new("SessionId", ColType::Int),
            Column::new("Wow64", ColType::Bool),
            Column::new("CreateTime", ColType::DateTime),
            Column::new("ExitTime", ColType::DateTime),
            Column::new("File output", ColType::Str),
        ])?;
        rows(ctx, cfg, &mut |r| out.row(0, r))
    }
    fn timeline(&self, ctx: &Context, cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        let mut ev = Vec::new();
        let r = rows(ctx, cfg, &mut |r| {
            let off = match &r[3] {
                Value::Int(i) => *i,
                _ => 0,
            };
            let name = match &r[2] {
                Value::Str(s) => s.clone(),
                _ => String::new(),
            };
            let pid = match &r[0] {
                Value::Int(i) => *i,
                _ => 0,
            };
            // python: f"Process: {pid} {name} ({Hex(offset)})" -- Hex is an int subclass -> decimal
            let description = format!("Process: {pid} {name} ({off})");
            ev.push(TimelineEvent { description: description.clone(), kind: TimeKind::Created, time: r[8].clone() });
            ev.push(TimelineEvent { description, kind: TimeKind::Modified, time: r[9].clone() });
            Ok(())
        });
        Some(r.map(|_| ev))
    }
}
