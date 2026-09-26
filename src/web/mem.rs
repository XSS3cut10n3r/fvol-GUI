//! Memory access for the hex viewer: layer lookup (physical / kernel / process) and page-wise
//! reads that report unreadable ranges instead of failing.

use super::session::{Session, plain_err};
use crate::objects::LayerRef;

/// Most bytes one hex-view request may read.
pub const MAX_READ: u64 = 256 * 1024;

/// The user address space of process `pid` (None: the process has none, e.g. a kernel thread).
pub fn process_layer(s: &Session, pid: i128) -> Result<Option<LayerRef>, String> {
    let ctx = &s.ctx;
    match s.os() {
        Some("windows") => {
            use crate::symbols::windows::WinExt;
            let k = ctx.windows_kernel().map_err(|e| plain_err(&e))?;
            let pids = [pid];
            let f = crate::plugins::windows::pslist::pid_filter(&pids);
            for p in crate::plugins::windows::pslist::list_processes(k, &f).into_iter().flatten() {
                return p.add_process_layer().map(Some).map_err(|e| plain_err(&e));
            }
            Err(format!("process {pid} was not found in the active process list"))
        }
        Some("linux") => {
            use crate::symbols::linux::LinuxExt;
            let k = ctx.linux_kernel().map_err(|e| plain_err(&e))?;
            let pids = [pid];
            let f = crate::plugins::linux::pslist::pid_filter(&pids);
            let mut found: Option<Result<Option<LayerRef>, String>> = None;
            let _ = crate::plugins::linux::pslist::list_tasks(k, &f, false, &mut |t| {
                found = Some(t.add_process_layer().map_err(|e| plain_err(&e)));
                Ok(false)
            });
            found.unwrap_or_else(|| Err(format!("task {pid} was not found in the task list")))
        }
        Some("mac") => {
            use crate::symbols::mac::MacExt;
            let k = ctx.mac_kernel().map_err(|e| plain_err(&e))?;
            let pids = [pid];
            let f = crate::plugins::mac::pslist::pid_filter(&pids);
            for p in crate::plugins::mac::pslist::list_tasks(k, "tasks", &f).into_iter().flatten() {
                return p.add_process_layer().map_err(|e| plain_err(&e));
            }
            Err(format!("process {pid} was not found in the task list"))
        }
        _ => Err("the operating system of this image has not been identified".into()),
    }
}

/// Read `[addr, addr+len)` page by page: (bytes with unreadable bytes zeroed, unreadable ranges
/// as (offset, len) relative to `addr`).
pub fn read_range(l: LayerRef, addr: u64, len: u64) -> (Vec<u8>, Vec<(u64, u64)>) {
    let len = len.min(MAX_READ);
    let mut data = vec![0u8; len as usize];
    let mut bad: Vec<(u64, u64)> = Vec::new();
    let mut off = 0u64;
    while off < len {
        let a = addr.wrapping_add(off);
        let page_end = (a | 0xfff).wrapping_add(1);
        let n = if page_end <= a { len - off } else { (page_end - a).min(len - off) };
        let buf = &mut data[off as usize..(off + n) as usize];
        if l.read(a, buf).is_err() {
            buf.fill(0);
            match bad.last_mut() {
                Some(b) if b.0 + b.1 == off => b.1 += n,
                _ => bad.push((off, n)),
            }
        }
        off += n;
    }
    (data, bad)
}
