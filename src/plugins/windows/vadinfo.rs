//! windows.vadinfo.VadInfo (python `plugins/windows/vadinfo.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::prelude::*;

pub struct VadInfo;

/// python `vadinfo.winnt_protections` (dict order).
pub const WINNT_PROTECTIONS: [(&str, i128); 12] = [
    ("PAGE_NOACCESS", 0x01),
    ("PAGE_READONLY", 0x02),
    ("PAGE_READWRITE", 0x04),
    ("PAGE_WRITECOPY", 0x08),
    ("PAGE_EXECUTE", 0x10),
    ("PAGE_EXECUTE_READ", 0x20),
    ("PAGE_EXECUTE_READWRITE", 0x40),
    ("PAGE_EXECUTE_WRITECOPY", 0x80),
    ("PAGE_GUARD", 0x100),
    ("PAGE_NOCACHE", 0x200),
    ("PAGE_WRITECOMBINE", 0x400),
    ("PAGE_TARGETS_INVALID", 0x4000_0000),
];

/// python `VadInfo.MAXSIZE_DEFAULT`.
pub const MAXSIZE_DEFAULT: i128 = 1024 * 1024 * 1024;

/// python `VadInfo.protect_values(context, layer, table)`: the kernel's `MmProtectToValue`
/// array (32 ints).
pub fn protect_values(k: &WinKernel) -> Result<Vec<i128>> {
    let addr = k.get_symbol("MmProtectToValue")?.address;
    let int = k.get_type("int")?;
    k.object("int", addr)?.cast_array(32, int).ints()
}

/// python `VadInfo.list_vads(proc, filter_func)` (filter returns true = skip).
pub fn list_vads(proc: &Obj, filter: &dyn Fn(&Obj) -> Result<bool>) -> Vec<Result<Obj>> {
    let root = match proc.get_vad_root() {
        Ok(r) => r,
        Err(e) => return vec![Err(e)],
    };
    let mut out = Vec::new();
    for v in root.traverse() {
        match v {
            Ok(v) => match filter(&v) {
                Ok(true) => {}
                Ok(false) => out.push(Ok(v)),
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            },
            Err(e) => {
                out.push(Err(e));
                break;
            }
        }
    }
    out
}

/// python `VadInfo.vad_dump(context, proc, vad, open_method, maxsize)`: writes
/// `pid.<pid>.vad.<start>-<end>.dmp`; returns the printed file name or None.
pub fn vad_dump(ctx: &Context, proc: &Obj, vad: &Obj, maxsize: i128) -> Option<String> {
    let (start, end) = match (vad.get_start(), vad.get_end()) {
        (Ok(s), Ok(e)) => (s, e),
        _ => return None,
    };
    let size = vad.get_size().ok()?;
    if 0 < maxsize && maxsize < size as i128 {
        return None;
    }
    let pid = proc.m("UniqueProcessId").and_then(|p| p.int()).ok()?;
    let pl = proc.add_process_layer().ok()?;
    let name = format!("pid.{pid}.vad.{start:#x}-{end:#x}.dmp");
    let (f, final_name) = ctx.create_output_file(&name).ok()?;
    // python writes `read(off, 10 MiB, pad=True)` chunks of [start, start + size): only the
    // mapped runs can hold anything but zeros; zero pages stay holes of the same file
    let stop = start.wrapping_add(size);
    if start < stop {
        let mut w = crate::plugins::windows::memmap::SparseDump::new(&f);
        let mut res = Ok(());
        pl.mapping_targets(start, stop - start, &mut |m, _| {
            res = w.range(pl, m.offset, m.len, m.offset - start);
            res.is_ok()
        });
        w.set_size(stop - start);
        if res.is_err() || w.finish().is_err() {
            return None;
        }
    }
    Some(final_name)
}

impl Plugin for VadInfo {
    fn name(&self) -> &'static str {
        "windows.vadinfo.VadInfo"
    }
    fn description(&self) -> &'static str {
        "Lists process memory ranges."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("address", "Process virtual memory address to include (all other address ranges are excluded).", ReqKind::Int).optional(),
            Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional(),
            Requirement::flag("dump", "Extract listed memory ranges"),
            Requirement::new("maxsize", "Maximum size for dumped VAD sections (all the bigger sections will be ignored)", ReqKind::Int)
                .optional()
                .default(ConfigValue::Int(MAXSIZE_DEFAULT)),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Offset", ColType::Hex),
            Column::new("Start VPN", ColType::Hex),
            Column::new("End VPN", ColType::Hex),
            Column::new("Tag", ColType::Str),
            Column::new("Protection", ColType::Str),
            Column::new("CommitCharge", ColType::Int),
            Column::new("PrivateMemory", ColType::Int),
            Column::new("Parent", ColType::Hex),
            Column::new("File", ColType::Str),
            Column::new("File output", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let pids = cfg.get_ints("pid");
        let pid_filter = super::pslist::pid_filter(&pids);
        let address = cfg.get_int("address");
        let dump = cfg.get_bool("dump");
        let maxsize = cfg.get_int("maxsize").unwrap_or(MAXSIZE_DEFAULT);
        let filter = |v: &Obj| -> Result<bool> {
            match address {
                Some(a) => Ok(!(v.get_start()? as i128 <= a && a <= v.get_end()? as i128)),
                None => Ok(false),
            }
        };
        // python reads MmProtectToValue per row; read it once, failing at the first row like python
        let pv = std::sync::OnceLock::new();
        let pv_get = || -> Result<&Vec<i128>> {
            match pv.get_or_init(|| protect_values(k).map_err(|e| e.to_string())) {
                Ok(v) => Ok(v),
                Err(e) => Err(crate::error::Error::msg(e.clone())),
            }
        };
        // rows of one process, in python order; a trailing Err = python raised there
        let proc_rows = |proc: &Obj| -> Vec<Result<Vec<Value>>> {
            let mut rows = Vec::new();
            let r = (|| -> Result<()> {
                let process_name = array_to_string(&proc.m("ImageFileName")?, None)?;
                for v in list_vads(proc, &filter) {
                    let vad = v?;
                    let file_output = if dump {
                        match vad_dump(ctx, proc, &vad, maxsize) {
                            Some(n) => Value::Str(n),
                            None => Value::SStr("Error outputting file"),
                        }
                    } else {
                        Value::SStr("Disabled")
                    };
                    let tag = match vad.get_tag() {
                        Some(t) => Value::Str(t),
                        None => Value::SStr("None"),
                    };
                    rows.push(Ok(vec![
                        Value::Int(proc.m("UniqueProcessId")?.int()?),
                        Value::Str(process_name.clone()),
                        Value::Int(k.layer.canonicalize(vad.addr) as i128),
                        Value::Int(vad.get_start()? as i128),
                        Value::Int(vad.get_end()? as i128),
                        tag,
                        Value::Str(vad.get_protection(pv_get()?, &WINNT_PROTECTIONS)?),
                        Value::Int(vad.get_commit_charge()?.int()?),
                        Value::Int(vad.get_private_memory()?.int()?),
                        Value::Int(vad.get_parent()?),
                        vad.get_file_name(),
                        file_output,
                    ]));
                }
                Ok(())
            })();
            if let Err(e) = r {
                rows.push(Err(e));
            }
            rows
        };
        let procs = super::pslist::list_processes(k, &pid_filter);
        // processes are independent: compute in parallel, emit in python order. With --dump,
        // stay sequential so a failure stops before later dumps exactly like python.
        let per_proc: Vec<Vec<Result<Vec<Value>>>> = if dump {
            Vec::new()
        } else {
            crate::util::par::par_map(procs.len(), |i| match &procs[i] {
                Ok(p) => proc_rows(p),
                Err(_) => Vec::new(),
            })
        };
        let mut per_proc = per_proc.into_iter();
        for p in procs {
            let proc = p?;
            let rows = if dump { proc_rows(&proc) } else { per_proc.next().unwrap_or_default() };
            for r in rows {
                out.row(0, r?)?;
            }
        }
        Ok(())
    }
}
