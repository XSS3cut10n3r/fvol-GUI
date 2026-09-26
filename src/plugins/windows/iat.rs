//! windows.iat.IAT (python `plugins/windows/iat.py`): the import table of every process's
//! main executable, parsed like `pefile` from the image reconstructed out of memory.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::{Obj, Space};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::pefile::{PeError, PeFile};
use crate::symbols::windows::{WinExt, pe};

pub struct IAT;

impl Plugin for IAT {
    fn name(&self) -> &'static str {
        "windows.iat.IAT"
    }
    fn description(&self) -> &'static str {
        "Extract Import Address Table to list API (functions) used by a program contained in external libraries"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Process ID to include (all other processes are excluded)", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Name", ColType::Str),
            Column::new("Library", ColType::Str),
            Column::new("Bound", ColType::Bool),
            Column::new("Function", ColType::Str),
            Column::new("Address", ColType::Hex),
        ])?;
        let k = ctx.windows_kernel()?;
        let pids = cfg.get_ints("pid");
        let filter = super::pslist::pid_filter(&pids);
        let procs = super::pslist::list_processes(k, &filter);
        let pe_table = ctx.load_isf("windows/pe")?;

        // rows of one process; a trailing Err = python raised (uncaught) there
        let proc_rows = |proc: &Obj| -> Vec<Result<Vec<Value>>> {
            let mut rows = Vec::new();
            let r = (|| -> Result<()> {
                let pid = proc.m("UniqueProcessId")?.int()?;
                let pl = proc.add_process_layer()?;
                let peb = Obj::named(Space::on(pl, k.table), "_PEB", proc.m("Peb")?.u64()?)?;
                let image_base = peb.m("ImageBaseAddress")?.u64()?;
                let dos = Obj::named(Space::on(pl, pe_table), "_IMAGE_DOS_HEADER", image_base)?;
                // reconstruct: InvalidAddressException / ValueError only log a warning; the
                // partial data is parsed anyway
                let (view, err) = pe::reconstruct_view(&dos);
                if let Some(e) = err {
                    if !e.is_invalid_or_value() {
                        return Err(Error::msg(e.to_string()));
                    }
                }
                let pe = match PeFile::parse(&view) {
                    Ok(p) => p,
                    Err(PeError::Format(_)) => return Ok(()),
                    Err(e) => return Err(Error::msg(e.to_string())),
                };
                let Some(descs) = pe.parse_imports() else { return Ok(()) };
                let image_base = pe.optional_header.image_base as u128;
                let mut name: Option<String> = None;
                for d in descs {
                    let dll = String::from_utf8_lossy(&d.dll).into_owned();
                    let bound = d.time_date_stamp != 0;
                    for imp in d.imports {
                        if name.is_none() {
                            name = Some(proc.image_file_name_str()?);
                        }
                        let func = match &imp.name {
                            Some(n) if !n.is_empty() => Value::Str(String::from_utf8_lossy(n).into_owned()),
                            _ => Value::NotAvailable,
                        };
                        rows.push(Ok(vec![
                            Value::Int(pid),
                            Value::Str(name.clone().unwrap()),
                            Value::Str(dll.clone()),
                            Value::Bool(bound),
                            func,
                            Value::Int((image_base + imp.address) as i128),
                        ]));
                    }
                }
                Ok(())
            })();
            match r {
                Ok(()) => {}
                Err(e) if e.is_invalid_address() => {}
                Err(e) => rows.push(Err(e)),
            }
            rows
        };
        let per_proc = crate::util::par::par_map(procs.len(), |i| match &procs[i] {
            Ok(p) => proc_rows(p),
            Err(_) => Vec::new(),
        });
        for (p, rows) in procs.into_iter().zip(per_proc) {
            p?;
            for r in rows {
                out.row(0, r?)?;
            }
        }
        Ok(())
    }
}
