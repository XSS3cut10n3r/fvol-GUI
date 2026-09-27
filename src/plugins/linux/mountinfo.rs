//! linux.mountinfo.MountInfo (python `plugins/linux/mountinfo.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! * [`get_mountinfo`] is python's `MountInfo.get_mountinfo(mnt, task)`.
//! * [`tasks_mountpoints`] is python's `MountInfo._get_tasks_mountpoints(tasks, filtered_by_pids)`.
//! * [`get_superblocks`] is python's `MountInfo.get_superblocks(context, kernel)` (used by
//!   `linux.pagecache`).
//!
//! `--mount-format` joins a python `set` of option strings: its iteration order depends on
//! python's per-process randomized `str` hash, so python's own column order varies between
//! runs. We emulate CPython's set order with the `PYTHONHASHSEED=0` string hash
//! (`util::pyset`), i.e. the order of a python run with hash randomization disabled.

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::plugins::linux::pslist::{list_tasks, pid_filter};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::fs::ptr_ok;
use crate::symbols::linux::prelude::*;
use crate::symbols::linux::utilities::get_path_mnt;
use crate::symbols::linux::fs::tgt;
use crate::util::{FxHashMap, FxHashSet};
use crate::util::pyset::{PySet, py_hash_str_seed0};

pub struct MountInfo;

/// python `MountInfoData`.
pub struct MountInfoData {
    pub mnt_id: i128,
    pub parent_id: i128,
    pub st_dev: String,
    pub mnt_root_path: String,
    pub path_root: String,
    pub mnt_opts: Vec<&'static str>,
    pub fields: Vec<String>,
    /// `None` = python's `superblock.get_type()` returned None.
    pub mnt_type: Option<String>,
    pub devname: String,
    pub sb_opts: Vec<&'static str>,
}

/// python `MountInfo.get_mountinfo(mnt, task)` (the kernel's `show_mountinfo`): `Ok(None)`
/// where python returns None, `Err` where it raises.
pub fn get_mountinfo(mnt: &Obj, task: &Obj) -> Result<Option<MountInfoData>> {
    let mnt_root = mnt.get_mnt_root()?;
    if mnt_root.u64()? == 0 {
        return Ok(None);
    }
    let path_root = get_path_mnt(task, mnt)?;
    if path_root.is_empty() {
        return Ok(None);
    }
    let mnt_root_path = mnt_root.dentry_path()?;
    let mnt_id = mnt.m("mnt_id")?.int()?;
    let parent_id = mnt.m("mnt_parent")?.m("mnt_id")?.int()?;
    let sb = mnt.get_mnt_sb()?;
    if !ptr_ok(&sb)? {
        return Ok(None);
    }
    let st_dev = format!("{}:{}", sb.major()?, sb.minor()?);
    let mut mnt_opts = vec![mnt.get_flags_access()?];
    mnt_opts.extend(mnt.get_flags_opts()?);
    let mut fields = Vec::new();
    if mnt.is_shared()? != 0 {
        fields.push(format!("shared:{}", mnt.m("mnt_group_id")?.int()?));
    }
    if mnt.is_slave()? {
        let master = mnt.m("mnt_master")?.m("mnt_group_id")?.int()?;
        fields.push(format!("master:{master}"));
        let dominating_id = mnt.get_dominating_id(&task.m("fs")?.m("root")?)?;
        if dominating_id != 0 && dominating_id != master {
            fields.push(format!("propagate_from:{dominating_id}"));
        }
    }
    if mnt.is_unbindable()? != 0 {
        fields.push("unbindable".into());
    }
    let mnt_type = sb.sb_get_type()?;
    let mut devname = mnt.get_devname()?;
    if devname.is_empty() {
        devname = "none".into();
    }
    let mut sb_opts = vec![sb.get_flags_access()?];
    sb_opts.extend(sb.get_flags_opts()?);
    Ok(Some(MountInfoData { mnt_id, parent_id, st_dev, mnt_root_path, path_root, mnt_opts, fields, mnt_type, devname, sb_opts }))
}

/// python `MountInfo._get_tasks_mountpoints(tasks, filtered_by_pids)`: calls `f(task, mount,
/// mnt_ns_id)` for every mount point of every task's mount namespace (deduplicated by mount
/// id unless `filtered_by_pids`); `mnt_ns_id` is `None` where python uses NotAvailableValue.
/// `f` returns false to stop. `Err` where python raises.
///
/// python walks the mount list of a namespace again for every task in it; the list (same
/// memory, same result, errors included) is read once per namespace here.
pub fn tasks_mountpoints(tasks: &mut dyn FnMut(&mut dyn FnMut(Obj) -> Result<bool>) -> Result<()>, filtered_by_pids: bool, f: &mut dyn FnMut(&Obj, &Obj, Option<i128>) -> Result<bool>) -> Result<()> {
    let mut seen = FxHashSet::default();
    let mut namespaces: FxHashMap<u64, NsMounts> = FxHashMap::default();
    tasks(&mut |task| {
        let fs = task.m("fs")?;
        if !ptr_ok(&fs)? {
            return Ok(true);
        }
        let nsproxy = task.m("nsproxy")?;
        if !ptr_ok(&nsproxy)? {
            return Ok(true);
        }
        let mnt_ns = nsproxy.m("mnt_ns")?;
        if !ptr_ok(&mnt_ns)? {
            return Ok(true);
        }
        let uncached;
        let ns = match tgt(&mnt_ns) {
            Ok(t) => namespaces.entry(t.addr).or_insert_with(|| NsMounts::read(&mnt_ns)),
            Err(_) => {
                uncached = NsMounts::read(&mnt_ns);
                &uncached
            }
        };
        let mnt_ns_id = match &ns.id {
            Ok(v) => *v,
            Err(e) => return Err(super::clone_err(e)),
        };
        for m in &ns.mounts {
            let (mount, mnt_id) = match m {
                Ok(Some(x)) => x,
                // python: `mount.mnt_id` on None
                Ok(None) => return Err(crate::error::Error::msg("AttributeError: 'NoneType' object has no attribute 'mnt_id'")),
                Err(e) => return Err(super::clone_err(e)),
            };
            if !filtered_by_pids {
                let mnt_id = match mnt_id {
                    Ok(v) => *v,
                    Err(e) => return Err(super::clone_err(e)),
                };
                if !seen.insert(mnt_id) {
                    continue;
                }
            }
            if !f(&task, mount, mnt_ns_id)? {
                return Ok(false);
            }
        }
        Ok(true)
    })
}

/// What `_get_tasks_mountpoints` reads from a task's mount namespace.
struct NsMounts {
    /// python `mnt_ns.get_mnt_ns_inode()` (`None`: an AttributeError, NotAvailableValue)
    id: Result<Option<i128>>,
    /// python `mnt_ns.get_mount_points()` (a trailing `Err` = python raised), each mount with
    /// its `mnt_id` (read by python only when not filtering by pid)
    mounts: Vec<Result<Option<(Obj, Result<i128>)>>>,
}

impl NsMounts {
    fn read(mnt_ns: &Obj) -> NsMounts {
        let id = match mnt_ns.get_mnt_ns_inode() {
            Ok(v) => Ok(Some(v)),
            Err(e) if is_attribute_error(&e) => Ok(None),
            Err(e) => Err(e),
        };
        let mounts = mnt_ns.get_mount_points().into_iter().map(|m| m.map(|m| m.map(|m| (m, m.m("mnt_id").and_then(|i| i.int()))))).collect();
        NsMounts { id, mounts }
    }
}

fn is_attribute_error(e: &crate::error::Error) -> bool {
    matches!(e, crate::error::Error::Symbol(_)) || e.to_string().starts_with("AttributeError")
}

/// python `MountInfo.get_superblocks(context, kernel)`: `(super_block, mount point path)` for
/// each distinct readable superblock reachable from the tasks' mount namespaces, in python's
/// order. A trailing `Err` = python raised there.
///
/// The mount points are listed first; their paths and superblocks are read in parallel and
/// then deduplicated in python's order (every error is kept where python would raise it).
pub fn get_superblocks(k: &LinuxKernel) -> Vec<Result<(Obj, String)>> {
    let (mounts, tail) = collect_mountpoints(k, &|_: &Obj| Ok(false), false);
    // per mount point: None = python `continue`s before the seen check; else the superblock
    // pointer value and python's `(sb.dereference(), path_root)`
    let infos = crate::util::par::par_map(mounts.len(), |i| -> Result<Option<(u64, Result<(Obj, String)>)>> {
        let (task, mnt, _) = &mounts[i];
        let path_root = get_path_mnt(task, mnt)?;
        if path_root.is_empty() {
            return Ok(None);
        }
        let sb = mnt.get_mnt_sb()?;
        if !ptr_ok(&sb)? {
            return Ok(None);
        }
        Ok(Some((sb.u64()?, sb.deref().map(|d| (d, path_root)))))
    });
    let mut out = Vec::new();
    let mut seen_sb = FxHashSet::default();
    for info in infos {
        match info {
            Ok(None) => {}
            Ok(Some((sb, r))) => {
                if !seen_sb.insert(sb) {
                    continue;
                }
                let stop = r.is_err();
                out.push(r);
                if stop {
                    return out;
                }
            }
            Err(e) => {
                out.push(Err(e));
                return out;
            }
        }
    }
    if let Some(e) = tail {
        out.push(Err(e));
    }
    out
}

/// [`tasks_mountpoints`] over [`list_tasks`]`(k, filter)` collected: `(task, mount,
/// mnt_ns_id)` in python's order, and the `Err` python raised after them, if any.
fn collect_mountpoints(k: &LinuxKernel, filter: &dyn Fn(&Obj) -> Result<bool>, filtered_by_pids: bool) -> (Vec<(Obj, Obj, Option<i128>)>, Option<crate::error::Error>) {
    let mut v = Vec::new();
    let r = tasks_mountpoints(&mut |f| list_tasks(k, filter, false, f), filtered_by_pids, &mut |task, mnt, id| {
        v.push((*task, *mnt, id));
        Ok(true)
    });
    (v, r.err())
}

/// python `",".join(set(mnt_opts) | set(sb_opts))` in CPython set order (`PYTHONHASHSEED=0`).
fn join_opts_set(mnt_opts: &[&'static str], sb_opts: &[&'static str]) -> String {
    let mut set: PySet<&'static str> = PySet::new();
    for o in mnt_opts.iter().chain(sb_opts) {
        let h = py_hash_str_seed0(o);
        if !set.contains(h, o) {
            set.add(h, o);
        }
    }
    set.iter().copied().collect::<Vec<_>>().join(",")
}

impl Plugin for MountInfo {
    fn name(&self) -> &'static str {
        "linux.mountinfo.MountInfo"
    }
    fn description(&self) -> &'static str {
        "Lists mount points on processes mount namespaces"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pids", "Filter on specific process IDs.", ReqKind::ListInt).optional(),
            Requirement::new("mntns", "Filter results by mount namespace. Otherwise, all of them are shown.", ReqKind::ListInt).optional(),
            Requirement::flag(
                "mount-format",
                "Shows a brief summary of the mount points information with similar output format to the older /proc/[pid]/mounts or the user-land command 'mount -l'.",
            ),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let pids = cfg.get_ints("pids");
        let mnt_ns_ids = cfg.get_ints("mntns");
        let mount_format = cfg.get_bool("mount-format");
        let filtered_by_pids = !pids.is_empty();
        let mut cols = vec![Column::new("MNT_NS_ID", ColType::Int)];
        if filtered_by_pids {
            cols.push(Column::new("PID", ColType::Int));
        }
        if mount_format {
            for n in ["DEVNAME", "PATH", "FSTYPE", "MNT_OPTS"] {
                cols.push(Column::new(n, ColType::Str));
            }
        } else {
            cols.push(Column::new("MOUNT ID", ColType::Int));
            cols.push(Column::new("PARENT_ID", ColType::Int));
            for n in ["MAJOR:MINOR", "ROOT", "MOUNT_POINT", "MOUNT_OPTIONS", "FIELDS", "FSTYPE", "MOUNT_SRC", "SB_OPTIONS"] {
                cols.push(Column::new(n, ColType::Str));
            }
        }
        out.begin(cols)?;
        let k = ctx.linux_kernel()?;
        let filter = pid_filter(&pids);
        let (mounts, tail) = collect_mountpoints(k, &filter, filtered_by_pids);
        // the rows (python's `get_mountinfo` per mount point) are built on all cores
        let row = |task: &Obj, mnt: &Obj, mnt_ns_id: Option<i128>| -> Result<Option<Vec<Value>>> {
            if let Some(id) = mnt_ns_id {
                if !mnt_ns_ids.is_empty() && !mnt_ns_ids.contains(&id) {
                    return Ok(None);
                }
            }
            let Some(mi) = get_mountinfo(mnt, task)? else { return Ok(None) };
            let mut row = Vec::with_capacity(12);
            row.push(mnt_ns_id.map_or(Value::NotAvailable, Value::Int));
            if filtered_by_pids {
                row.push(Value::Int(task.m("pid")?.int()?));
            }
            // python puts None in the row: TreeGrid's type check raises TypeError
            let Some(mnt_type) = mi.mnt_type.map(Value::Str) else {
                let idx = row.len() + if mount_format { 2 } else { 7 };
                return Err(crate::error::Error::msg(format!(
                    "TypeError: Values item with index {idx} is the wrong type for column FSTYPE (got <class 'NoneType'> but expected <class 'str'>)"
                )));
            };
            if mount_format {
                let opts = join_opts_set(&mi.mnt_opts, &mi.sb_opts);
                row.extend([Value::Str(mi.devname), Value::Str(mi.path_root), mnt_type, Value::Str(opts)]);
            } else {
                row.extend([
                    Value::Int(mi.mnt_id),
                    Value::Int(mi.parent_id),
                    Value::Str(mi.st_dev),
                    Value::Str(mi.mnt_root_path),
                    Value::Str(mi.path_root),
                    Value::Str(mi.mnt_opts.join(",")),
                    Value::Str(mi.fields.join(" ")),
                    mnt_type,
                    Value::Str(mi.devname),
                    Value::Str(mi.sb_opts.join(",")),
                ]);
            }
            Ok(Some(row))
        };
        super::stream_chunks(out, mounts.len(), 4, |r, b| {
            for (task, mnt, id) in &mounts[r] {
                match row(task, mnt, *id) {
                    Ok(Some(v)) => b.push(v),
                    Ok(None) => {}
                    Err(e) => return Some(e),
                }
            }
            None
        })?;
        tail.map_or(Ok(()), Err)
    }
}
