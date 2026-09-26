//! windows.pslist.PsList (python `plugins/windows/pslist.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::objects::{Obj, Space};
use crate::plugins::{Config, Plugin, ReqKind, Requirement, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::{WinExt, pe};
use crate::symbols::{StrEnc, StrErrors};
use crate::util::FxHashSet;
use std::io::Write;

pub struct PsList;

/// python `PsList.create_pid_filter(pid_list)`: returns true for processes to SKIP.
pub fn pid_filter(pids: &[i128]) -> impl Fn(&Obj) -> Result<bool> + '_ {
    move |p: &Obj| {
        if pids.is_empty() {
            return Ok(false);
        }
        let pid = p.m("UniqueProcessId")?.int()?;
        Ok(!pids.contains(&pid))
    }
}

/// python `PsList.list_processes(context, kernel, filter_func)`: walk PsActiveProcessHead
/// forward then backward (deduplicated). `filter` returns true to skip a process. A trailing
/// `Err` means python would have raised at that point.
pub fn list_processes(k: &WinKernel, filter: &dyn Fn(&Obj) -> Result<bool>) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        if k.base == 0 {
            return Err(Error::msg("Intel layer does not have an associated kernel virtual offset, failing"));
        }
        let aph = k.get_symbol("PsActiveProcessHead")?.address;
        let list_entry = k.object("_LIST_ENTRY", aph)?;
        let reloff = k.offset_of("_EPROCESS", "ActiveProcessLinks")?;
        let eproc = k.object_abs("_EPROCESS", list_entry.addr.wrapping_sub(reloff))?;
        let links = eproc.m("ActiveProcessLinks")?;
        let mut seen = FxHashSet::default();
        for forward in [true, false] {
            for p in links.to_list("_EPROCESS", "ActiveProcessLinks", forward, true, None) {
                let p = p?;
                if !seen.insert(p.addr) {
                    continue;
                }
                if !filter(&p)? {
                    out.push(Ok(p));
                }
            }
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

/// python `PsList.process_dump(...)`: write the process image (`pid.name.base.dmp`); returns
/// the printed file name or None ("Error outputting file").
pub fn process_dump(ctx: &Context, k: &WinKernel, proc: &Obj) -> Option<String> {
    let pe_table = ctx.load_isf("windows/pe").ok()?;
    let r = (|| -> Result<(std::fs::File, String, Obj)> {
        let _pid = proc.m("UniqueProcessId")?.int()?;
        let pl = proc.add_process_layer()?;
        let peb = Obj::named(Space::on(pl, k.table), "_PEB", proc.m("Peb")?.u64()?)?;
        let base = peb.m("ImageBaseAddress")?.u64()?;
        let dos = Obj::named(Space::on(pl, pe_table), "_IMAGE_DOS_HEADER", base)?;
        let name = proc.image_file_name_str()?;
        let pid = proc.m("UniqueProcessId")?.int()?;
        let fname = sanitize_filename(&format!("{pid}.{name}.{base:#x}.dmp"));
        let (f, printed) = ctx.create_output_file(&fname)?;
        Ok((f, printed, dos))
    })();
    let (mut f, printed, dos) = r.ok()?;
    let (pieces, _err) = pe::reconstruct(&dos);
    let _ = pe::write_pieces(&mut f, &pieces);
    let _ = f.flush();
    Some(printed)
}

/// python `FileHandlerInterface.sanitize_filename`.
pub fn sanitize_filename(name: &str) -> String {
    const ALLOWED: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.- ()[]{}!$%^#~,";
    name.chars().map(|c| if ALLOWED.contains(c) { c } else { '_' }).collect()
}

fn rows(ctx: &Context, cfg: &Config, out: &mut dyn FnMut(Vec<Value>) -> Result<()>) -> Result<()> {
    let k = ctx.windows_kernel()?;
    let physical = cfg.get_bool("physical");
    let dump = cfg.get_bool("dump");
    let pids = cfg.get_ints("pid");
    let filter = pid_filter(&pids);
    for p in list_processes(k, &filter) {
        let proc = p?;
        let offset = if physical {
            match k.layer.translate_addr(proc.addr) {
                Some((pa, _)) => pa,
                None => return Err(Error::invalid(proc.addr)),
            }
        } else {
            proc.addr
        };
        let mut file_output = Value::SStr("Disabled");
        let row = (|| -> Result<Vec<Value>> {
            if dump {
                file_output = match process_dump(ctx, k, &proc) {
                    Some(n) => Value::Str(n),
                    None => Value::SStr("Error outputting file"),
                };
            }
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
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl Plugin for PsList {
    fn name(&self) -> &'static str {
        "windows.pslist.PsList"
    }
    fn description(&self) -> &'static str {
        "Lists the processes present in a particular windows memory image."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::flag("physical", "Display physical offsets instead of virtual"),
            Requirement::new("pid", "Process ID to include (all other processes are excluded)", ReqKind::ListInt).optional(),
            Requirement::flag("dump", "Extract listed processes"),
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
