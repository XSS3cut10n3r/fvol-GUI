//! linux.psscan.PsScan (python `plugins/linux/psscan.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::Result;
use crate::layers::scan::{MultiStringScanner, scan};
use crate::objects::{Obj, Space};
use crate::plugins::linux::pslist::get_task_fields;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};

pub struct PsScan;

/// python `DescExitStateEnum` (name of a valid `exit_state`).
pub fn exit_state_name(v: i128) -> Option<&'static str> {
    match v {
        0x00 => Some("TASK_RUNNING"),
        0x10 => Some("EXIT_DEAD"),
        0x20 => Some("EXIT_ZOMBIE"),
        0x30 => Some("EXIT_TRACE"),
        _ => None,
    }
}

/// python `PsScan.scan_tasks(context, vmlinux_module_name, kernel_layer_name)`: scan the
/// physical layer for the `*_sched_class` addresses stored in `task_struct.sched_class`;
/// returns the `task_struct` candidates (on the physical layer, pointers native to the kernel
/// layer) that pass the exit_state / pid sanity checks, in scan order. A trailing `Err` =
/// python raised there.
pub fn scan_tasks(k: &LinuxKernel) -> Vec<Result<Obj>> {
    let r = (|| -> Result<(Vec<(u64, u32)>, u64, crate::symbols::Ty)> {
        let is_64 = k.table.is_64bit();
        let sched_off = k.offset_of("task_struct", "sched_class")?;
        let task_ty = k.get_type("task_struct")?;
        let mut needles: Vec<Vec<u8>> = Vec::new();
        // names and addresses only (no symbol record is decoded: cheap on a lazy table too)
        for (name, address) in k.table.symbol_names_addrs() {
            if name.windows(12).any(|w| w == b"_sched_class") {
                let addr = k.layer.canonicalize(k.module.offset.wrapping_add(address));
                needles.push(if is_64 { addr.to_le_bytes().to_vec() } else { (addr as u32).to_le_bytes().to_vec() });
            }
        }
        if needles.is_empty() {
            return Err(crate::error::Error::msg("ValueError: MultiRegexp cannot be used with an empty set of search strings"));
        }
        let scanner = MultiStringScanner::new(&needles);
        Ok((scan(k.phys, &scanner, None), sched_off, task_ty))
    })();
    let (hits, sched_off, task_ty) = match r {
        Ok(v) => v,
        Err(e) => return vec![Err(e)],
    };
    let sp = Space::get(k.phys, k.vlayer, k.table);
    // validate candidates in parallel; keep scan order
    let checked = crate::util::par::par_map(hits.len(), |i| -> Result<Option<Obj>> {
        let t = Obj::new(sp, task_ty, hits[i].0.wrapping_sub(sched_off));
        if exit_state_name(t.m("exit_state")?.int()?).is_none() {
            return Ok(None);
        }
        let pid = t.m("pid")?.int()?;
        if !(0 < pid && pid < 65535) {
            return Ok(None);
        }
        Ok(Some(t))
    });
    let mut out = Vec::new();
    for c in checked {
        match c {
            Ok(Some(t)) => out.push(Ok(t)),
            Ok(None) => {}
            Err(e) => {
                out.push(Err(e));
                break;
            }
        }
    }
    out
}

fn task_row(t: &Obj) -> Result<Vec<Value>> {
    let tf = get_task_fields(t, false)?;
    let es = exit_state_name(t.m("exit_state")?.int()?).ok_or_else(|| crate::error::Error::msg("ValueError: not a valid DescExitStateEnum"))?;
    Ok(vec![Value::Int(tf.offset as i128), Value::Int(tf.user_pid), Value::Int(tf.user_tid), Value::Int(tf.user_ppid), Value::Str(tf.name), Value::SStr(es)])
}

impl Plugin for PsScan {
    fn name(&self) -> &'static str {
        "linux.psscan.PsScan"
    }
    fn description(&self) -> &'static str {
        "Scans for processes present in a particular linux image."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("OFFSET (P)", ColType::Hex),
            Column::new("PID", ColType::Int),
            Column::new("TID", ColType::Int),
            Column::new("PPID", ColType::Int),
            Column::new("COMM", ColType::Str),
            Column::new("EXIT_STATE", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        let tasks = scan_tasks(k);
        let rows = crate::util::par::par_map(tasks.len(), |i| match &tasks[i] {
            Ok(t) => task_row(t),
            Err(_) => Ok(Vec::new()),
        });
        for (t, r) in tasks.into_iter().zip(rows) {
            t?;
            out.row(0, r?)?;
        }
        Ok(())
    }
}
