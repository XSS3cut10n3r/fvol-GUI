//! windows.thrdscan.ThrdScan (python `plugins/windows/thrdscan.py`) and the thread-row
//! machinery shared with `windows.threads.Threads` and `windows.orphan_kernel_threads.Threads`
//! (both python subclasses of ThrdScan): [`scan_threads_each`], [`gather_thread_info`] /
//! [`ThreadInfo`] and [`thread_rows`] (python `ThrdScan._generator`, with the per-process VAD
//! file lookups done in parallel).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::Obj;
use crate::plugins::windows::poolscanner::{builtin_constraints, generate_pool_scan_each};
use crate::plugins::windows::pe_symbols::{Range, filepath_for_address, get_proc_vads_with_file_paths};
use crate::plugins::{Config, Plugin, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;
use crate::symbols::windows::ext::MAX_PID;
use crate::util::FxHashMap;

pub struct ThrdScan;

/// python `ThrdScan.scan_threads(context, module_name)`, streaming: `_ETHREAD`s found by pool
/// scanning (`Thr\xe5` / `Thre`), in python's order (`f` returns `Ok(false)` to stop).
pub fn scan_threads_each(ctx: &Context, k: &WinKernel, mut f: impl FnMut(Obj) -> Result<bool>) -> Result<()> {
    let constraints = builtin_constraints(k.table.name(), &[b"Thr\xe5", b"Thre"]);
    generate_pool_scan_each(ctx, k, k.table, &constraints, |hit| f(hit.object))
}

/// python `ThrdScan.scan_threads(...)` collected (a trailing `Err` = python raised there).
pub fn scan_threads(ctx: &Context, k: &WinKernel) -> Vec<Result<Obj>> {
    let mut v = Vec::new();
    if let Err(e) = scan_threads_each(ctx, k, |t| {
        v.push(Ok(t));
        Ok(true)
    }) {
        v.push(Err(e));
    }
    v
}

/// python `ThrdScan.ThreadInfo`.
#[derive(Clone, Debug)]
pub struct ThreadInfo {
    pub offset: u64,
    pub pid: u64,
    pub tid: u64,
    pub start_addr: u64,
    pub start_path: Option<String>,
    pub win32_start_addr: u64,
    pub win32_start_path: Option<String>,
    /// `Value::DateTime` or an absent value
    pub create_time: Value,
    pub exit_time: Value,
}

/// The part of python `gather_thread_info` before the VAD lookups: the thread fields and the
/// owning process whose VADs python would consult (`None` when python skips the lookup).
#[derive(Clone, Debug)]
pub struct ThreadPre {
    pub info: ThreadInfo,
    pub owner: Option<Obj>,
}

/// python `gather_thread_info` up to the VAD lookup. `Ok(None)` = python returns None;
/// `with_vads` = python's `vads_cache is not None`.
pub fn gather_thread_pre(ethread: &Obj, with_vads: bool) -> Result<Option<ThreadPre>> {
    let r = (|| -> Result<(u64, u64, u64, u64, Value, Value, Option<Obj>)> {
        let cid = ethread.m("Cid")?;
        let pid = cid.m("UniqueProcess")?.u64()?;
        let tid = cid.m("UniqueThread")?.u64()?;
        let start = ethread.m("StartAddress")?.u64()?;
        let win32 = ethread.m("Win32StartAddress")?.u64()?;
        let create = ethread.get_create_time()?;
        let exit = ethread.get_exit_time()?;
        let owner = if with_vads { Some(ethread.owning_process()?) } else { None };
        Ok((pid, tid, start, win32, create, exit, owner))
    })();
    let (pid, tid, start, win32, create, exit, owner) = match r {
        Ok(v) => v,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    // filter junk PIDs
    if pid > MAX_PID || pid == 0 || pid % 4 != 0 {
        return Ok(None);
    }
    let owner = match owner {
        Some(p) if p.is_valid() && p.m("UniqueProcessId")?.u64()? != 4 => Some(p),
        _ => None,
    };
    Ok(Some(ThreadPre {
        info: ThreadInfo {
            offset: ethread.addr,
            pid,
            tid,
            start_addr: start,
            start_path: None,
            win32_start_addr: win32,
            win32_start_path: None,
            create_time: create,
            exit_time: exit,
        },
        owner,
    }))
}

/// python `ThrdScan.gather_thread_info(ethread, vads_cache)` (one thread; `vads_cache` None =
/// python's `None`). For many threads use [`thread_rows`], which shares and parallelizes the
/// VAD walks.
pub fn gather_thread_info(ethread: &Obj, vads_cache: Option<&mut FxHashMap<u64, Vec<Range>>>) -> Result<Option<ThreadInfo>> {
    let Some(pre) = gather_thread_pre(ethread, vads_cache.is_some())? else { return Ok(None) };
    let mut info = pre.info;
    if let (Some(owner), Some(cache)) = (pre.owner, vads_cache) {
        if !cache.contains_key(&owner.addr) {
            let v = get_proc_vads_with_file_paths(&owner)?;
            cache.insert(owner.addr, v);
        }
        let vads = &cache[&owner.addr];
        if !vads.is_empty() {
            info.start_path = filepath_for_address(vads, info.start_addr).map(str::to_string);
            info.win32_start_path = filepath_for_address(vads, info.win32_start_addr).map(str::to_string);
        }
    }
    Ok(Some(info))
}

/// python `ThrdScan._generator` over the threads of `implementation` (a trailing `Err` = the
/// implementation raised there): one row per [`ThreadInfo`], in order. The per-thread reads and
/// the per-process VAD walks (python's `vads_cache`) run in parallel; errors surface exactly
/// where python would raise.
pub fn thread_rows(threads: Vec<Result<Obj>>, out: &mut dyn FnMut(Vec<Value>) -> Result<()>) -> Result<()> {
    let n_ok = threads.iter().take_while(|t| t.is_ok()).count();
    let objs: Vec<Obj> = threads[..n_ok].iter().map(|t| *t.as_ref().unwrap()).collect();
    let pres = crate::util::par::par_map(objs.len(), |i| gather_thread_pre(&objs[i], true));
    // the processes python would walk the VADs of (first-occurrence order), walked in parallel
    let mut owners: Vec<Obj> = Vec::new();
    let mut index: FxHashMap<u64, usize> = FxHashMap::default();
    for p in pres.iter() {
        match p {
            Ok(Some(ThreadPre { owner: Some(o), .. })) => {
                index.entry(o.addr).or_insert_with(|| {
                    owners.push(*o);
                    owners.len() - 1
                });
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let vads = crate::util::par::par_map(owners.len(), |i| get_proc_vads_with_file_paths(&owners[i]));
    let mut vads: Vec<Option<Result<Vec<Range>>>> = vads.into_iter().map(Some).collect();
    for pre in pres {
        let Some(pre) = pre? else { continue };
        let mut info = pre.info;
        if let Some(owner) = pre.owner {
            let slot = &mut vads[index[&owner.addr]];
            if let Some(Err(_)) = slot {
                // python raised while building this process' VAD list
                return Err(slot.take().unwrap().unwrap_err());
            }
            if let Some(Ok(v)) = slot {
                if !v.is_empty() {
                    info.start_path = filepath_for_address(v, info.start_addr).map(str::to_string);
                    info.win32_start_path = filepath_for_address(v, info.win32_start_addr).map(str::to_string);
                }
            }
        }
        out(info_row(info))?;
    }
    if let Some(Err(e)) = threads.into_iter().nth(n_ok) {
        return Err(e);
    }
    Ok(())
}

/// The TreeGrid row of one [`ThreadInfo`] (python `ThrdScan._generator`).
pub fn info_row(info: ThreadInfo) -> Vec<Value> {
    let path = |p: Option<String>| match p {
        Some(s) if !s.is_empty() => Value::Str(s),
        _ => Value::NotAvailable,
    };
    vec![
        Value::Int(info.offset as i128),
        Value::Int(info.pid as i128),
        Value::Int(info.tid as i128),
        Value::Int(info.start_addr as i128),
        path(info.start_path),
        Value::Int(info.win32_start_addr as i128),
        path(info.win32_start_path),
        info.create_time,
        info.exit_time,
    ]
}

/// The TreeGrid columns of ThrdScan and its subclasses.
pub fn columns() -> Vec<Column> {
    vec![
        Column::new("Offset", ColType::Hex),
        Column::new("PID", ColType::Int),
        Column::new("TID", ColType::Int),
        Column::new("StartAddress", ColType::Hex),
        Column::new("StartPath", ColType::Str),
        Column::new("Win32StartAddress", ColType::Hex),
        Column::new("Win32StartPath", ColType::Str),
        Column::new("CreateTime", ColType::DateTime),
        Column::new("ExitTime", ColType::DateTime),
    ]
}

/// python `ThrdScan.generate_timeline()` over rows produced by [`thread_rows`].
pub fn timeline_of(threads: Vec<Result<Obj>>) -> Result<Vec<TimelineEvent>> {
    let mut ev = Vec::new();
    thread_rows(threads, &mut |r| {
        // skip threads with no creation time (mainly system process threads)
        if !matches!(r[7], Value::DateTime(_)) {
            return Ok(());
        }
        let int = |v: &Value| match v {
            Value::Int(i) => *i,
            _ => 0,
        };
        // python formats Hex(offset) and the Pointer pid/tid with f-strings: decimal ints
        let description = format!("Thread: Tid {} in Pid {} (Offset {})", int(&r[2]), int(&r[1]), int(&r[0]));
        ev.push(TimelineEvent { description: description.clone(), kind: TimeKind::Created, time: r[7].clone() });
        if matches!(r[8], Value::DateTime(_)) {
            ev.push(TimelineEvent { description, kind: TimeKind::Modified, time: r[8].clone() });
        }
        Ok(())
    })?;
    Ok(ev)
}

impl Plugin for ThrdScan {
    fn name(&self) -> &'static str {
        "windows.thrdscan.ThrdScan"
    }
    fn description(&self) -> &'static str {
        "Scans for windows threads."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(columns())?;
        let k = ctx.windows_kernel()?;
        thread_rows(scan_threads(ctx, k), &mut |r| out.row(0, r))
    }
    fn timeline(&self, ctx: &Context, _cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        Some(ctx.windows_kernel().and_then(|k| timeline_of(scan_threads(ctx, k))))
    }
}
