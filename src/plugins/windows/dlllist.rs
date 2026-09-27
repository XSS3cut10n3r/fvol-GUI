//! windows.dlllist.DllList (python `plugins/windows/dlllist.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::cli::regex::Regex;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::plugins::{Config, Plugin, ReqKind, Requirement, TimelineEvent};
use crate::renderers::{ColType, Column, RowBlock, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::windows::WinExt;
use crate::util::time::wintime_to_datetime;

pub struct DllList;

/// One output item of a process: a row, python's `return None` (regex error), or a raise.
enum Item {
    Row(Vec<Value>),
    Stop,
}

struct Opts<'a> {
    /// `Some(Ok(re))` when `--name` is set; `Some(Err)` = python's `re.error` path.
    name: Option<std::result::Result<Regex, ()>>,
    base: Option<i128>,
    dump: Option<TableRef>,
    load_time_field: bool,
    ctx: &'a Context,
}

/// python `DllList._generator` for one process (a trailing `Err` = python raised there).
fn proc_items(o: &Opts, proc: &Obj) -> Vec<Result<Item>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let proc_id = proc.m("UniqueProcessId")?.int()?;
        let proc_layer = proc.add_process_layer()?;
        for entry in proc.load_order_modules() {
            let entry = entry?;
            let (mut base_name, mut full_name) = (Value::Unreadable, Value::Unreadable);
            match entry.m("BaseDllName").and_then(|n| n.get_string()) {
                Ok(b) => {
                    base_name = Value::Str(b);
                    match entry.m("FullDllName").and_then(|n| n.get_string()) {
                        Ok(f) => full_name = Value::Str(f),
                        Err(e) if e.is_invalid_address() => {}
                        Err(e) => return Err(e),
                    }
                }
                Err(e) if e.is_invalid_address() => {}
                Err(e) => return Err(e),
            }
            if let Some(re) = &o.name {
                let Ok(re) = re else {
                    out.push(Ok(Item::Stop));
                    return Ok(());
                };
                let (Value::Str(b), Value::Str(f)) = (&base_name, &full_name) else { continue };
                if !re.is_match(b) && !re.is_match(f) {
                    continue;
                }
            }
            if let Some(b) = o.base {
                if b != entry.m("DllBase")?.int()? {
                    continue;
                }
            }
            let load_time = if o.load_time_field {
                match entry.path("LoadTime.QuadPart").and_then(|q| q.int()) {
                    Ok(v) => wintime_to_datetime(v),
                    Err(e) if e.is_invalid_address() => Value::Unreadable,
                    Err(e) => return Err(e),
                }
            } else {
                Value::NotApplicable
            };
            let file_output = match o.dump {
                Some(pe) => match super::modules::dump_ldr_entry(o.ctx, pe, &entry, Some(proc_layer), &format!("pid.{proc_id}."))? {
                    Some(n) if !n.is_empty() => Value::Str(n),
                    _ => Value::SStr("Error outputting file"),
                },
                None => Value::SStr("Disabled"),
            };
            let hexv = |name: &str| -> Result<Value> {
                match entry.m(name).and_then(|x| x.int()) {
                    Ok(v) => Ok(Value::Int(v)),
                    Err(e) if e.is_invalid_address() => Ok(Value::NotAvailable),
                    Err(e) => Err(e),
                }
            };
            let dllbase = hexv("DllBase")?;
            let size = hexv("SizeOfImage")?;
            let load_count = entry.get_load_count().map(Value::Int).unwrap_or(Value::NotAvailable);
            out.push(Ok(Item::Row(vec![
                Value::Int(proc.m("UniqueProcessId")?.int()?),
                Value::Str(proc.image_file_name_str()?),
                dllbase,
                size,
                base_name,
                full_name,
                load_count,
                load_time,
                file_output,
            ])));
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

/// How one process' rows ended.
enum Tail {
    Done,
    /// python's `return None` (the generator ends)
    Stop,
    Raise(Error),
}

/// One process' rows into `block` (formatted there when the sink has an encoder).
fn proc_block(o: &Opts, proc: &Obj, block: &mut RowBlock) -> Tail {
    for it in proc_items(o, proc) {
        match it {
            Ok(Item::Row(r)) => block.push(r),
            Ok(Item::Stop) => return Tail::Stop,
            Err(e) => return Tail::Raise(e),
        }
    }
    Tail::Done
}

/// Where python's rows go.
enum Emit<'a> {
    Values(&'a mut dyn FnMut(Vec<Value>) -> Result<()>),
    Sink(&'a mut dyn RowSink),
}

/// Runs python's generator, handing each row to `emit`.
fn rows(ctx: &Context, cfg: &Config, dump: bool, emit: Emit) -> Result<()> {
    let k = ctx.windows_kernel()?;
    let pids = cfg.get_ints("pid");
    let pid_filter = super::pslist::pid_filter(&pids);
    let offset = cfg.get_int("offset").filter(|o| *o != 0);
    // python lists the processes before the generator starts
    let procs = match offset {
        Some(off) => {
            let f = super::psscan::create_offset_filter(k, Some(off as u64), true, false);
            super::psscan::scan_processes(ctx, k, &f)
        }
        None => super::pslist::list_processes(k, &pid_filter),
    };
    let pe = if dump { Some(ctx.load_isf("windows/pe")?) } else { None };
    let kuser = super::info::get_kuser_structure(k)?;
    let (major, minor) = (kuser.m("NtMajorVersion")?.int()?, kuser.m("NtMinorVersion")?.int()?);
    let name = cfg.get_str("name").filter(|n| !n.is_empty()).map(|n| {
        Regex::new_flags(n, cfg.get_bool("ignore-case")).map_err(|_| ())
    });
    let o = Opts {
        name,
        base: cfg.get_int("base").filter(|b| *b != 0),
        dump: pe,
        load_time_field: major > 6 || (major == 6 && minor >= 1),
        ctx,
    };
    // processes are independent: compute in parallel, emit in python order. With --dump stay
    // sequential so an error stops before later dumps exactly like python.
    let mut sink_row;
    let emit: &mut dyn FnMut(Vec<Value>) -> Result<()> = match emit {
        Emit::Sink(out) if !dump => {
            // the rows formatted on the workers
            let enc = out.encoder();
            let blocks = crate::plugins::par_blocks(enc.as_ref(), procs.len(), |i, block| match &procs[i] {
                Ok(p) => proc_block(&o, p, block),
                Err(_) => Tail::Done,
            });
            for (p, (block, tail)) in procs.into_iter().zip(blocks) {
                p?;
                block.emit(out)?;
                match tail {
                    Tail::Done => {}
                    Tail::Stop => return Ok(()),
                    Tail::Raise(e) => return Err(e),
                }
            }
            return Ok(());
        }
        Emit::Sink(out) => {
            sink_row = move |r: Vec<Value>| out.row(0, r);
            &mut sink_row
        }
        Emit::Values(f) => f,
    };
    let mut per_proc = if dump {
        Vec::new()
    } else {
        crate::util::par::par_map(procs.len(), |i| match &procs[i] {
            Ok(p) => proc_items(&o, p),
            Err(_) => Vec::new(),
        })
    }
    .into_iter();
    for p in procs {
        let proc = p?;
        let items = if dump { proc_items(&o, &proc) } else { per_proc.next().unwrap_or_default() };
        for it in items {
            match it? {
                Item::Row(r) => emit(r)?,
                Item::Stop => return Ok(()),
            }
        }
    }
    Ok(())
}

impl Plugin for DllList {
    fn name(&self) -> &'static str {
        "windows.dlllist.DllList"
    }
    fn description(&self) -> &'static str {
        "Lists the loaded DLLs in a particular windows memory image."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Process IDs to include (all other processes are excluded)", ReqKind::ListInt).optional(),
            Requirement::new("offset", "Process offset in the physical address space", ReqKind::Int).optional(),
            Requirement::new("base", "Specify a base virtual address in process memory", ReqKind::Int).optional(),
            Requirement::new("name", "Specify a regular expression to match dll name(s)", ReqKind::Str).optional(),
            Requirement::flag("ignore-case", "Specify case insensitivity for the regular expression name matching"),
            Requirement::flag("dump", "Extract listed DLLs"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Base", ColType::Hex),
            Column::new("Size", ColType::Hex),
            Column::new("Name", ColType::Str),
            Column::new("Path", ColType::Str),
            Column::new("LoadCount", ColType::Int),
            Column::new("LoadTime", ColType::DateTime),
            Column::new("File output", ColType::Str),
        ])?;
        rows(ctx, cfg, cfg.get_bool("dump"), Emit::Sink(out))
    }
    fn timeline(&self, ctx: &Context, cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        // python checks `isinstance(row_data[6], datetime.datetime)`, but column 6 is LoadCount
        // (an int), so no event is ever produced; the generator still runs (without --dump:
        // generate_timeline lists processes itself, ignoring --offset).
        let mut c = cfg.clone();
        c.values.remove("offset");
        c.values.remove("pid");
        Some(rows(ctx, &c, cfg.get_bool("dump"), Emit::Values(&mut |_| Ok(()))).map(|_| Vec::new()))
    }
}
