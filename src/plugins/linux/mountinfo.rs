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
use crate::util::FxHashSet;
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
pub fn tasks_mountpoints(tasks: &mut dyn FnMut(&mut dyn FnMut(Obj) -> Result<bool>) -> Result<()>, filtered_by_pids: bool, f: &mut dyn FnMut(&Obj, &Obj, Option<i128>) -> Result<bool>) -> Result<()> {
    let mut seen = FxHashSet::default();
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
        let mnt_ns_id = match mnt_ns.get_mnt_ns_inode() {
            Ok(v) => Some(v),
            Err(e) if is_attribute_error(&e) => None,
            Err(e) => return Err(e),
        };
        for m in mnt_ns.get_mount_points() {
            let Some(mount) = m? else {
                // python: `mount.mnt_id` on None
                return Err(crate::error::Error::msg("AttributeError: 'NoneType' object has no attribute 'mnt_id'"));
            };
            if !filtered_by_pids {
                let mnt_id = mount.m("mnt_id")?.int()?;
                if !seen.insert(mnt_id) {
                    continue;
                }
            }
            if !f(&task, &mount, mnt_ns_id)? {
                return Ok(false);
            }
        }
        Ok(true)
    })
}

fn is_attribute_error(e: &crate::error::Error) -> bool {
    matches!(e, crate::error::Error::Symbol(_)) || e.to_string().starts_with("AttributeError")
}

/// python `MountInfo.get_superblocks(context, kernel)`: `(super_block, mount point path)` for
/// each distinct readable superblock reachable from the tasks' mount namespaces, in python's
/// order. A trailing `Err` = python raised there.
pub fn get_superblocks(k: &LinuxKernel) -> Vec<Result<(Obj, String)>> {
    let mut out = Vec::new();
    let mut seen_sb = FxHashSet::default();
    let no_filter = |_: &Obj| Ok(false);
    let r = tasks_mountpoints(
        &mut |f| list_tasks(k, &no_filter, false, f),
        false,
        &mut |task, mnt, _| {
            let path_root = get_path_mnt(task, mnt)?;
            if path_root.is_empty() {
                return Ok(true);
            }
            let sb = mnt.get_mnt_sb()?;
            if !ptr_ok(&sb)? {
                return Ok(true);
            }
            if !seen_sb.insert(sb.u64()?) {
                return Ok(true);
            }
            out.push(Ok((sb.deref()?, path_root)));
            Ok(true)
        },
    );
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
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
        tasks_mountpoints(&mut |f| list_tasks(k, &filter, false, f), filtered_by_pids, &mut |task, mnt, mnt_ns_id| {
            if let Some(id) = mnt_ns_id {
                if !mnt_ns_ids.is_empty() && !mnt_ns_ids.contains(&id) {
                    return Ok(true);
                }
            }
            let Some(mi) = get_mountinfo(mnt, task)? else { return Ok(true) };
            let mut row = vec![mnt_ns_id.map_or(Value::NotAvailable, Value::Int)];
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
            out.row(0, row)?;
            Ok(true)
        })
    }
}
