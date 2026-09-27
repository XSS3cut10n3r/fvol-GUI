//! linux.pidhashtable.PIDHashTable (python `plugins/linux/pidhashtable.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::plugins::linux::pslist::get_task_fields;
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::container_of;
use crate::symbols::linux::idstorage::idr_get_entries;
use crate::util::FxHashSet;

pub struct PIDHashTable;

/// python `_is_valid_task(task)`: `task and task.pid > 0 and task.parent.is_readable()`.
fn is_valid_task(t: &Obj) -> Result<bool> {
    Ok(t.m("pid")?.int()? > 0 && t.m("parent")?.is_readable())
}

/// python `_get_pidtype_pid()` (`pid_type` enum's `PIDTYPE_PID`).
fn pidtype_pid(k: &LinuxKernel) -> Result<Option<u64>> {
    let e = k.get_enumeration("pid_type")?;
    Ok(k.table.enum_constants(e).find(|c| c.0 == "PIDTYPE_PID").map(|c| c.1 as u64))
}

/// python `_task_for_radix_pid_node(nodep)` (kernels >= 4.15).
fn task_for_radix_pid_node(k: &LinuxKernel, nodep: u64, pidtype: Option<u64>) -> Result<Option<Obj>> {
    let pid = k.object_abs("pid", nodep)?;
    let pidtype = pidtype.ok_or_else(|| Error::msg("TypeError: list indices must be integers or slices, not NoneType"))?;
    let first = pid.m("tasks")?.at(pidtype)?.m("first")?;
    let v = first.u64()?;
    if !(v != 0 && first.is_readable()) {
        return Ok(None);
    }
    let t = k.table;
    let has = |m: &str| t.user_type("task_struct").is_some_and(|u| t.member(u, m).is_some());
    let member = if has("pids") {
        "pids"
    } else if has("pid_links") {
        "pid_links"
    } else {
        return Ok(None);
    };
    let off = k.offset_of("task_struct", member)?;
    Ok(Some(k.object_abs("task_struct", v.wrapping_sub(off))?))
}

/// python `_pid_namespace_idr()`.
fn pid_namespace_idr(k: &LinuxKernel) -> Result<Vec<Obj>> {
    let ns = k.object("pid_namespace", k.get_symbol("init_pid_ns")?.address)?;
    let pidtype = pidtype_pid(k)?;
    let entries = idr_get_entries(&ns.m("idr")?);
    // resolve entries in parallel, keep order and python's first error
    let res = crate::util::par::par_map(entries.len(), |i| -> Result<Option<Obj>> {
        let nodep = match &entries[i] {
            Ok(v) => *v,
            Err(_) => return Ok(None),
        };
        match task_for_radix_pid_node(k, nodep, pidtype)? {
            Some(t) if is_valid_task(&t)? => Ok(Some(t)),
            _ => Ok(None),
        }
    });
    let mut out = Vec::new();
    for (e, r) in entries.into_iter().zip(res) {
        if let Err(err) = e {
            return Err(err);
        }
        if let Some(t) = r? {
            out.push(t);
        }
    }
    Ok(out)
}

/// python `_walk_upid(seen_upids, upid)`.
fn walk_upid(k: &LinuxKernel, seen: &mut Vec<u64>, seen_set: &mut FxHashSet<u64>, mut upid: Option<Obj>) -> Result<()> {
    while let Some(u) = upid {
        if !k.vlayer.is_valid(u.addr, 1) || seen_set.contains(&u.addr) {
            break;
        }
        seen_set.insert(u.addr);
        seen.push(u.addr);
        let next = u.m("pid_chain")?.m("next")?;
        let nv = next.u64()?;
        if !(nv != 0 && next.is_readable()) {
            break;
        }
        upid = container_of(nv, "upid", "pid_chain", k)?;
    }
    Ok(())
}

/// python `_pid_hash_implementation()` (2.6.24 <= kernels < 4.15).
fn pid_hash_implementation(k: &LinuxKernel) -> Result<Vec<Obj>> {
    let shift = k.object_from_symbol("pidhash_shift")?.int()?;
    let size = 1u64.checked_shl(shift as u32).unwrap_or(0);
    let ptr = k.object_from_symbol("pid_hash")?.u64()?;
    let hl_ty = k.get_type("hlist_head")?;
    let arr = k.object_abs("hlist_head", ptr)?.cast_array(size, hl_ty);
    let mut seen = Vec::new();
    let mut seen_set = FxHashSet::default();
    for i in 0..size {
        let mut ent = arr.at(i)?.m("first")?;
        while ent.u64()? != 0 && ent.is_readable() {
            // python passes `ent.vol.offset` (the pointer object's own address) here
            let upid = container_of(ent.addr, "upid", "pid_chain", k)?
                .ok_or_else(|| Error::msg("AttributeError: 'NoneType' object has no attribute 'vol'"))?;
            if seen_set.contains(&upid.addr) {
                break;
            }
            walk_upid(k, &mut seen, &mut seen_set, Some(upid))?;
            // `ent = ent.next`: the `next` field of the node `ent` points to
            ent = ent.m("next")?;
        }
    }
    // python iterates the `seen_upids` set: CPython's set iteration order
    let off_pids = k.offset_of("task_struct", "pids")?;
    let pidtype = pidtype_pid(k)?.ok_or_else(|| Error::msg("TypeError: list indices must be integers or slices, not NoneType"))?;
    let mut out = Vec::new();
    for upid in py_int_set_order(&seen) {
        let Some(pid) = container_of(upid, "pid", "numbers", k)? else { continue };
        let first = pid.m("tasks")?.at(pidtype)?.m("first")?;
        let v = first.u64()?;
        if !(v != 0 && first.is_readable()) {
            continue;
        }
        let t = k.object_abs("task_struct", v.wrapping_sub(off_pids))?;
        if is_valid_task(&t)? {
            out.push(t);
        }
    }
    Ok(out)
}

/// python `PIDHashTable.get_tasks()`: the tasks reachable from the PID hash table / IDR,
/// sorted by (tgid, pid). `Ok(None)` when the kernel's implementation is unknown.
pub fn get_tasks(k: &LinuxKernel) -> Result<Option<Vec<Obj>>> {
    let t = k.table;
    let has = |ty: &str, m: &str| t.user_type(ty).is_some_and(|u| t.member(u, m).is_some());
    let pid_hash = k.has_symbol("pid_hash") && k.has_symbol("pidhash_shift");
    let has_pid_numbers = has("pid", "numbers");
    let has_pid_chain = has("upid", "pid_chain");
    let pid_idr = has("pid_namespace", "idr");
    let mut tasks = if pid_idr {
        pid_namespace_idr(k)?
    } else if pid_hash && has_pid_numbers && has_pid_chain {
        pid_hash_implementation(k)?
    } else {
        return Ok(None);
    };
    let mut keys = Vec::with_capacity(tasks.len());
    for t in &tasks {
        keys.push((t.m("tgid")?.int()?, t.m("pid")?.int()?));
    }
    let mut idx: Vec<usize> = (0..tasks.len()).collect();
    idx.sort_by_key(|&i| keys[i]); // stable, like python's sorted
    tasks = idx.into_iter().map(|i| tasks[i]).collect();
    Ok(Some(tasks))
}

/// The iteration order of a CPython `set` of non-negative ints (< 2**61 - 1, so `hash(x) == x`)
/// built by adding `values` in order (CPython `setobject.c`: linear probing of 9 + perturbed
/// open addressing, resize x4 when 3/5 full).
pub fn py_int_set_order(values: &[u64]) -> Vec<u64> {
    const LINEAR_PROBES: usize = 9;
    const PERTURB_SHIFT: u32 = 5;
    fn insert_clean(table: &mut [Option<u64>], key: u64) {
        let mask = table.len() - 1;
        let mut perturb = key as usize;
        let mut i = key as usize & mask;
        loop {
            if table[i].is_none() {
                table[i] = Some(key);
                return;
            }
            if i + LINEAR_PROBES <= mask {
                for j in 1..=LINEAR_PROBES {
                    if table[i + j].is_none() {
                        table[i + j] = Some(key);
                        return;
                    }
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb)) & mask;
        }
    }
    let mut table: Vec<Option<u64>> = vec![None; 8];
    let mut used = 0usize;
    for &key in values {
        let mask = table.len() - 1;
        let mut perturb = key as usize;
        let mut i = key as usize & mask;
        let mut slot = None;
        let mut dup = false;
        while slot.is_none() && !dup {
            let probes = if i + LINEAR_PROBES <= mask { LINEAR_PROBES } else { 0 };
            for j in 0..=probes {
                match table[i + j] {
                    None => {
                        slot = Some(i + j);
                        break;
                    }
                    Some(k) if k == key => {
                        dup = true;
                        break;
                    }
                    _ => {}
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb)) & mask;
        }
        let Some(slot) = slot else { continue };
        table[slot] = Some(key);
        used += 1;
        if used * 5 >= mask * 3 {
            let minused = if used > 50000 { used * 2 } else { used * 4 };
            let mut newsize = 8usize;
            while newsize <= minused {
                newsize <<= 1;
            }
            let mut nt: Vec<Option<u64>> = vec![None; newsize];
            for k in table.iter().flatten() {
                insert_clean(&mut nt, *k);
            }
            table = nt;
        }
    }
    table.into_iter().flatten().collect()
}

impl Plugin for PIDHashTable {
    fn name(&self) -> &'static str {
        "linux.pidhashtable.PIDHashTable"
    }
    fn description(&self) -> &'static str {
        "Enumerates processes through the PID hash table"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::flag("decorate_comm", "Show `user threads` comm in curly brackets, and `kernel threads` comm in square brackets")]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("OFFSET", ColType::Hex),
            Column::new("PID", ColType::Int),
            Column::new("TID", ColType::Int),
            Column::new("PPID", ColType::Int),
            Column::new("COMM", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        let decorate = cfg.get_bool("decorate_comm");
        let Some(tasks) = get_tasks(k)? else { return Ok(()) };
        // per task in parallel, rows formatted on the workers, emitted in python's order
        crate::plugins::emit_par_blocks(out, tasks.into_iter().map(Ok).collect(), |t, b| {
            let tf = get_task_fields(t, decorate)?;
            b.push_ref(&[Value::Int(tf.offset as i128), Value::Int(tf.user_pid), Value::Int(tf.user_tid), Value::Int(tf.user_ppid), Value::Str(tf.name)]);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    /// Order produced by CPython 3.14 for the same inserts (see the generator below).
    const EXPECTED: [u64; 60] = [
        0x888084105100, 0x8880af636580, 0x8880bd02b500, 0x88800522e900, 0x8880bf421a00, 0x888048bdee80, 0x8880e4218780, 0x888027df4280, 0x88804ac26c80, 0x88805b8ad600,
        0x888096ab1100, 0x88802f3fb080, 0x8880f6fac8c0, 0x8880299e5200, 0x888033022a40, 0x8880d5555300, 0x8880acc18300, 0x8880b85a8b40, 0x8880f5767c40, 0x8880f82f1580,
        0x888060860600, 0x8880685c1600, 0x888085723e40, 0x8880ac880e40, 0x8880b68d0680, 0x8880202bd680, 0x8880d7a22f40, 0x8880c5add800, 0x888012d9e780, 0x8880d57f10c0,
        0x8880c8ea8a40, 0x88802e30a9c0, 0x888004a6ecc0, 0x8880b1bac940, 0x88808f14dfc0, 0x8880f9825c40, 0x88809a1630c0, 0x8880b1baa840, 0x888016ccb5c0, 0x8880b2a840c0,
        0x8880158ba140, 0x88802df6d0c0, 0x8880560ba140, 0x8880635e91c0, 0x8880799f31c0, 0x8880e14fa2c0, 0x8880adb8d2c0, 0x8880f347b2c0, 0x8880e8eaf340, 0x8880254f4b80,
        0x888096e223c0, 0x8880082c1440, 0x8880ed027800, 0x88800b934d00, 0x8880e8c37540, 0x8880820df5c0, 0x8880fc827e00, 0x888074f28e00, 0x88802921fe00, 0x8880d3e487c0,
    ];

    #[test]
    fn cpython_set_order() {
        let mut x: u64 = 12345;
        let mut vals = Vec::new();
        for _ in 0..60 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            vals.push(0x8880_0000_0000 + ((x >> 20) & 0xffff_ffc0));
        }
        let dup: Vec<u64> = vals[..5].to_vec();
        vals.extend(dup);
        assert_eq!(super::py_int_set_order(&vals), EXPECTED.to_vec());
    }
}
