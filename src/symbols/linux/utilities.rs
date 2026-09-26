//! python `symbols/linux/__init__.py` `LinuxUtilities`: file / mount path reconstruction
//! (the kernel's `prepend_path` / `d_path`), per-task file descriptors, internal list walking.
//! (`container_of` / `get_module_from_volobj_type` live in the parent module; the deprecated
//! module helpers moved to `symbols::linux::modules`.)
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Object conventions follow python exactly: `filp`, `dentry`, `rdentry`, `rmnt` are pointer
//! objects (`file *`, `dentry *`, `vfsmount *`); `vfsmnt` is a `vfsmount *` (python's
//! `file.get_vfsmnt()`, kernels < 3.3 style) or a `vfsmount` struct (`mount.get_vfsmnt_current()`).

use super::fs::{FsExt, ptr_ok, tgt};
use super::{LinuxExt, vmlinux_of};
use crate::error::{Error, Result};
use crate::layers::LayerExt;
use crate::objects::util::pointer_to_string;
use crate::objects::{Module, Obj};

/// python `LinuxUtilities.deleted`.
pub const DELETED: &str = "(deleted)";
/// python `LinuxUtilities.smear`.
pub const SMEAR: &str = "<potentially smeared>";

/// python `LinuxUtilities._get_path_file(task, filp)`.
pub fn get_path_file(task: &Obj, filp: &Obj) -> Result<String> {
    let fs = task.m("fs")?;
    let rdentry = fs.get_root_dentry()?;
    let rmnt = fs.get_root_mnt()?;
    let vfsmnt = filp.get_vfsmnt()?;
    let dentry = filp.get_dentry()?;
    do_get_path(&rdentry, &rmnt, &dentry, &vfsmnt)
}

/// python `LinuxUtilities.get_path_mnt(task, mnt)` (`mnt`: a `mount`, or `vfsmount` < 3.3).
pub fn get_path_mnt(task: &Obj, mnt: &Obj) -> Result<String> {
    let fs = task.m("fs")?;
    let rdentry = fs.get_root_dentry()?;
    let rmnt = fs.get_root_mnt()?;
    let vfsmnt = mnt.get_vfsmnt_current()?;
    let dentry = mnt.get_dentry_current()?;
    do_get_path(&rdentry, &rmnt, &dentry, &vfsmnt)
}

/// Memo key of a `do_get_path` call: (layer identity, rdentry, rmnt, dentry, vfsmnt value or
/// address, vfsmnt is a pointer). Memory never changes during a run, so equal keys always give
/// equal results; only successes are cached.
type PathKey = (usize, u64, u64, u64, u64, bool);

thread_local! {
    static PATH_MEMO: std::cell::RefCell<crate::util::FxHashMap<PathKey, String>> = std::cell::RefCell::new(Default::default());
}

/// python `LinuxUtilities.do_get_path(rdentry, rmnt, dentry, vfsmnt)` (the kernel's
/// `prepend_path`). Memoized per thread (the same file is usually mapped / opened many times).
pub fn do_get_path(rdentry: &Obj, rmnt: &Obj, dentry: &Obj, vfsmnt: &Obj) -> Result<String> {
    let key = (|| -> Result<PathKey> {
        let lk = dentry.layer() as *const dyn crate::layers::Layer as *const u8 as usize;
        let v = if vfsmnt.is_pointer() { vfsmnt.u64()? } else { vfsmnt.addr };
        Ok((lk, rdentry.u64()?, rmnt.u64()?, dentry.u64()?, v, vfsmnt.is_pointer()))
    })();
    let Ok(key) = key else { return do_get_path_uncached(rdentry, rmnt, dentry, vfsmnt) };
    if let Some(p) = PATH_MEMO.with(|m| m.borrow().get(&key).cloned()) {
        return Ok(p);
    }
    let r = do_get_path_uncached(rdentry, rmnt, dentry, vfsmnt)?;
    PATH_MEMO.with(|m| {
        let mut m = m.borrow_mut();
        if m.len() > 1 << 16 {
            m.clear();
        }
        m.insert(key, r.clone());
    });
    Ok(r)
}

fn do_get_path_uncached(rdentry: &Obj, rmnt: &Obj, dentry: &Obj, vfsmnt: &Obj) -> Result<String> {
    if !(ptr_ok(rdentry)? && ptr_ok(rmnt)?) {
        return Ok(String::new());
    }
    if vfsmnt.is_pointer() && !ptr_ok(vfsmnt)? {
        return Ok(String::new());
    }
    let rdentry_v = rdentry.u64()?;
    let inode = dentry.m("d_inode")?;
    inode.u64()?;
    let mut dentry = *dentry;
    let mut vfsmnt = *vfsmnt;
    let mut rev: Vec<String> = Vec::new();
    let mut smeared = false;
    // python has no loop guard here (a d_parent cycle would hang it); cap absurd walks
    let mut budget = 1u32 << 20;
    loop {
        let dv = dentry.u64()?;
        if !(dv != 0 && dentry.is_readable()) {
            break;
        }
        if dv == rdentry_v && vfsmnt.is_equal(rmnt)? {
            break;
        }
        budget -= 1;
        if budget == 0 {
            break;
        }
        let mnt_root = vfsmnt.get_mnt_root()?.u64()?;
        if dv == mnt_root || dentry.is_root()? {
            // Escaped?
            if dv != vfsmnt.get_mnt_root()?.u64()? {
                break;
            }
            // Global root?
            if !vfsmnt.has_parent()? {
                break;
            }
            let d = vfsmnt.get_dentry_parent()?;
            d.u64()?;
            let v = vfsmnt.get_vfsmnt_parent()?;
            dentry = d;
            vfsmnt = v;
            continue;
        }
        let d = tgt(&dentry)?;
        let parent = d.m("d_parent")?;
        parent.u64()?;
        let dname = d.m("d_name")?.name_as_str()?;
        if dname.is_empty() {
            smeared = true;
        }
        rev.push(dname.trim_matches('/').to_string());
        dentry = parent;
    }
    rev.reverse();
    let mut path = format!("/{}", rev.join("/"));
    if smeared {
        return Ok(format!("{SMEAR} {path}"));
    }
    if ptr_ok(&inode)? {
        let i = inode.deref()?;
        if inode_valid(&i)? && i.m("i_nlink")?.int()? == 0 {
            path = format!(" {path} {DELETED}");
        }
    }
    Ok(path)
}

/// python `inode.is_valid()` with exceptions kept.
fn inode_valid(i: &Obj) -> Result<bool> {
    Ok(i.m("i_ino")?.int()? > 0 && i.path("i_count.counter")?.int()? >= 0)
}

/// python `LinuxUtilities._get_new_sock_pipe_path(context, task, filp)`: the
/// `socket:[inode]` / `pipe:[inode]` / `anon_inode:[..]` style names.
pub fn get_new_sock_pipe_path(filp: &Obj) -> Result<String> {
    if !ptr_ok(filp)? {
        return Ok(format!("<invalid file pointer> {:x}", filp.u64()?));
    }
    let dentry = filp.get_dentry()?;
    if !ptr_ok(&dentry)? {
        return Ok(format!("<invalid dentry pointer> {:x}", dentry.u64()?));
    }
    let kernel = vmlinux_of(&dentry)?;
    let sym_addr = dentry.m("d_op")?.m("d_dname")?;
    let sym_v = sym_addr.u64()?;
    if !(sym_v != 0 && sym_addr.is_readable()) {
        return Ok(format!("<invalid d_dname pointer> {sym_v:x}"));
    }
    let symbs = symbols_at_cached(&kernel, sym_v);
    let inode = dentry.m("d_inode")?;
    let inode_v = inode.u64()?;
    if !(inode_v != 0 && inode.is_readable() && inode_valid(&inode.deref()?)?) {
        return Ok(format!("<invalid dentry inode> {inode_v:x}"));
    }
    let pre_name: String = if symbs.len() == 1 {
        match symbs[0] {
            "sockfs_dname" => "socket".into(),
            "anon_inodefs_dname" => "anon_inode".into(),
            "pipefs_dname" => "pipe".into(),
            "simple_dname" => {
                let name = dentry.m("d_name")?.m("name")?;
                if name.u64()? != 0 {
                    let s = name.deref()?.read_string(255, "utf-8", "replace")?;
                    return Ok(format!("/{s} (deleted)"));
                }
                String::new()
            }
            "ns_dname" => ns_dname(&kernel, &dentry, &inode)?,
            sym => format!("<unsupported d_op symbol> {sym}"),
        }
    } else {
        format!("<unknown d_dname pointer> {sym_v:x}")
    };
    Ok(format!("{pre_name}:[{}]", inode.m("i_ino")?.int()?))
}

/// python `kernel.get_symbols_by_absolute_location(addr)` for the handful of `d_dname`
/// callbacks (no full address index; cached per kernel + address).
fn symbols_at_cached(kernel: &Module, addr: u64) -> Vec<&'static str> {
    use std::sync::Mutex;
    type Entry = (usize, u64, Vec<&'static str>);
    static CACHE: Mutex<Vec<Entry>> = Mutex::new(Vec::new());
    let key = kernel.table() as *const _ as usize;
    let mut cache = CACHE.lock().unwrap();
    if let Some(e) = cache.iter().find(|e| e.0 == key && e.1 == addr) {
        return e.2.clone();
    }
    // One scan of the symbol records also resolves the d_dname callbacks python knows (their
    // addresses by name), so lsof / sockstat pay for one linear scan instead of one per
    // callback. Results are exactly `symbols_at_exact(a)` for each address `a`.
    let mut addrs = vec![addr];
    for n in ["sockfs_dname", "anon_inodefs_dname", "pipefs_dname", "simple_dname", "ns_dname"] {
        if let Ok(a) = kernel.symbol_addr(n) {
            let a = a & kernel.sp.native_mask;
            if !addrs.contains(&a) && !cache.iter().any(|e| e.0 == key && e.1 == a) {
                addrs.push(a);
            }
        }
    }
    let rel: Vec<u64> = addrs.iter().map(|a| a.wrapping_sub(kernel.offset)).collect();
    let res = kernel.table().symbols_at_exact_multi(&rel);
    for (a, v) in addrs.iter().zip(res) {
        cache.push((key, *a, v));
    }
    cache.iter().find(|e| e.0 == key && e.1 == addr).map(|e| e.2.clone()).unwrap_or_default()
}

/// The `ns_dname` branch of `_get_new_sock_pipe_path` (SymbolError / IndexError -> the
/// "<unsupported ns_dname implementation>" text, like python).
fn ns_dname(kernel: &Module, dentry: &Obj, inode: &Obj) -> Result<String> {
    const UNSUPPORTED: &str = "<unsupported ns_dname implementation>";
    let t = kernel.table();
    let Some(ns_common) = t.user_type("ns_common") else { return Ok(UNSUPPORTED.into()) };
    let Some(stashed) = t.member(ns_common, "stashed") else { return Ok(UNSUPPORTED.into()) };
    let ns_ops = if t.type_name(stashed.ty) == "atomic64_t" {
        let fsdata = dentry.m("d_fsdata")?;
        if !ptr_ok(&fsdata)? {
            return Ok(UNSUPPORTED.into());
        }
        match fsdata.deref()?.cast("proc_ns_operations") {
            Ok(o) => o,
            Err(Error::Symbol(_)) => return Ok(UNSUPPORTED.into()),
            Err(e) => return Err(e),
        }
    } else {
        let private = inode.m("i_private")?;
        if !ptr_ok(&private)? {
            return Ok(UNSUPPORTED.into());
        }
        match private.deref()?.cast("ns_common") {
            Ok(o) => o.m("ops")?,
            Err(Error::Symbol(_)) => return Ok(UNSUPPORTED.into()),
            Err(e) => return Err(e),
        }
    };
    match ns_ops.m("name") {
        Ok(n) => pointer_to_string(&n, 255),
        Err(Error::Symbol(_)) => Ok(UNSUPPORTED.into()),
        Err(e) => Err(e),
    }
}

/// python `LinuxUtilities.path_for_file(context, task, filp, files_only)`.
pub fn path_for_file(task: &Obj, filp: &Obj, files_only: bool) -> Result<String> {
    // Memory smear protection: check that both the file and dentry pointers are valid
    let dentry = match filp.get_dentry().and_then(|d| {
        d.is_root()?;
        Ok(d)
    }) {
        Ok(d) => d,
        Err(e) if e.is_invalid_address() => return Ok(String::new()),
        Err(e) => return Err(e),
    };
    if dentry.u64()? == 0 {
        return Ok(String::new());
    }
    let dname_is_valid = (|| -> Result<bool> {
        let d_op = dentry.m("d_op")?;
        if d_op.u64()? == 0 || !d_op.has_member("d_dname") {
            return Ok(false);
        }
        Ok(d_op.m("d_dname")?.u64()? != 0)
    })();
    let dname_is_valid = match dname_is_valid {
        Ok(v) => v,
        Err(e) if e.is_invalid_address() => false,
        Err(e) => return Err(e),
    };
    if dname_is_valid && !files_only { get_new_sock_pipe_path(filp) } else { get_path_file(task, filp) }
}

/// One entry of [`files_descriptors_for_process`]: (fd number, `file *` pointer object, path).
pub type FdEntry = (u64, Obj, String);

/// python `LinuxUtilities.files_descriptors_for_process(context, symbol_table, task,
/// files_only)`: the open files of `task`. Empty where python returns None; a trailing `Err`
/// where python's generator raises mid-way.
pub fn files_descriptors_for_process(task: &Obj, files_only: bool) -> Vec<Result<FdEntry>> {
    let mut out = Vec::new();
    let head = (|| -> Result<Option<(Obj, u64)>> {
        let files = task.m("files")?;
        let fd_table = files.get_fds()?;
        if fd_table.u64()? == 0 {
            return Ok(None);
        }
        let max_fds = files.get_max_fds()?.int()?;
        Ok(Some((fd_table, max_fds.max(0) as u64)))
    })();
    let (fd_table, max_fds) = match head {
        Ok(Some(v)) => v,
        Ok(None) => return out,
        Err(e) if e.is_invalid_address() => return out,
        Err(e) => return vec![Err(e)],
    };
    if max_fds > 500_000 {
        return out;
    }
    let file_ty = match task.table().get_type("file") {
        Ok(t) => t,
        Err(e) => return vec![Err(e)],
    };
    let arr = match crate::objects::util::array_of_pointers(&fd_table, max_fds, file_ty) {
        Ok(a) => a,
        Err(e) => return vec![Err(e)],
    };
    // the element pointers, read in one go when the whole array is mapped
    let ps = fd_table.size() as usize;
    let bulk = arr.layer().read_vec(arr.addr, ps * max_fds as usize).ok();
    for i in 0..max_fds {
        let r = (|| -> Result<Option<FdEntry>> {
            let filp = arr.at(i)?;
            let v = match &bulk {
                Some(b) => {
                    let mut x = [0u8; 8];
                    x[..ps].copy_from_slice(&b[i as usize * ps..i as usize * ps + ps]);
                    u64::from_le_bytes(x) & filp.sp.native_mask
                }
                None => filp.u64()?,
            };
            if v == 0 || !filp.is_readable() {
                return Ok(None);
            }
            let path = path_for_file(task, &filp, files_only)?;
            Ok(Some((i, filp, path)))
        })();
        match r {
            Ok(Some(e)) => out.push(Ok(e)),
            Ok(None) => {}
            Err(e) => {
                out.push(Err(e));
                break;
            }
        }
    }
    out
}

/// python `LinuxUtilities.walk_internal_list(vmlinux, struct_name, list_member, list_start,
/// max_count)`. Note: like python, each element is created at `list_start.vol.offset` (the
/// address of the pointer object itself), then `list_start = element.<list_member>`.
pub fn walk_internal_list(vmlinux: &Module, struct_name: &str, list_member: &str, list_start: &Obj, max_count: u64) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    let mut seen = crate::util::FxHashSet::default();
    let mut cur = *list_start;
    let mut count = 0u64;
    let r = (|| -> Result<()> {
        loop {
            if cur.u64()? == 0 {
                return Ok(());
            }
            if !seen.insert(cur.addr) {
                return Ok(());
            }
            if !cur.is_readable() {
                return Ok(());
            }
            let s = vmlinux.object_abs(struct_name, cur.addr)?;
            out.push(Ok(s));
            cur = s.m(list_member)?;
            if count == max_count {
                return Ok(());
            }
            count += 1;
        }
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

/// python `LinuxUtilities.convert_fourcc_code(code)`.
pub fn convert_fourcc_code(code: u128) -> String {
    let n = (128 - code.leading_zeros() as usize).div_ceil(8);
    (0..n).map(|i| char::from_u32(((code >> (i * 8)) & 0xFF) as u32).unwrap_or('\0')).collect()
}

/// python `vm_area_struct._do_get_name(context, task)` / `get_name()`: the VMA's file path,
/// `[heap]`, `[stack]`, `[vdso]` or "Anonymous Mapping"; `Ok(None)` on
/// InvalidAddressException (python's `get_name` returns None then).
pub fn vma_get_name(vma: &Obj, task: &Obj) -> Result<Option<String>> {
    match vma_do_get_name(vma, task) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.is_invalid_address() => Ok(None),
        Err(e) => Err(e),
    }
}

fn vma_do_get_name(vma: &Obj, task: &Obj) -> Result<String> {
    let v = tgt(vma)?;
    let vm_file = v.m("vm_file")?;
    if vm_file.u64()? != 0 {
        return path_for_file(task, &vm_file, false);
    }
    let start = v.m("vm_start")?.u64()?;
    let end = v.m("vm_end")?.u64()?;
    let mm = task.m("mm")?;
    if start <= mm.m("start_brk")?.u64()? && end >= mm.m("brk")?.u64()? {
        return Ok("[heap]".into());
    }
    let stack = mm.m("start_stack")?.u64()?;
    if start <= stack && stack <= end {
        return Ok("[stack]".into());
    }
    let ctx = v.m("vm_mm")?.m("context")?;
    if ctx.has_member("vdso") && start == ctx.m("vdso")?.u64()? {
        return Ok("[vdso]".into());
    }
    Ok("Anonymous Mapping".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn fourcc() {
        assert_eq!(super::convert_fourcc_code(0x3432_5258), "XR24");
        assert_eq!(super::convert_fourcc_code(0), "");
    }
}

#[cfg(test)]
mod image_tests {
    use super::*;
    use crate::context::{Context, GlobalOptions};
    use crate::objects::util::array_to_string;
    use crate::renderers::Value;

    fn v(x: Value) -> String {
        match x {
            Value::DateTime(d) => crate::util::time::fmt_quick(&d),
            Value::Str(s) => s,
            Value::SStr(s) => s.into(),
            Value::Int(i) => i.to_string(),
            _ => "-".into(),
        }
    }

    /// Prints `linux.lsof.Lsof`-like rows to check `files_descriptors_for_process` /
    /// `path_for_file` / the inode helpers against python's reference:
    /// `RSVOL_BENCH_IMAGE=<image> cargo test --profile fast lsof_like -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn lsof_like() {
        let image = std::env::var("RSVOL_BENCH_IMAGE").unwrap();
        let opts = GlobalOptions { file: Some(image), symbol_dirs: vec!["/home/user/rs-vol/testdata/symbols".into()], ..Default::default() };
        let ctx = Context::new(opts).unwrap();
        let k = ctx.linux_kernel().unwrap();
        crate::plugins::linux::pslist::list_tasks(k, &|_| Ok(false), true, &mut |task| {
            let comm = array_to_string(&task.m("comm")?, None)?;
            for e in files_descriptors_for_process(&task, false) {
                let (fd, filp, path) = e?;
                let pre = format!("LS\t{}\t{}\t{comm}\t{fd}\t{path}", task.m("tgid")?.int()?, task.m("pid")?.int()?);
                match filp.get_inode()? {
                    Some(i) => {
                        let sb = i.m("i_sb")?;
                        let dev = if ptr_ok(&sb)? { format!("{}:{}", sb.major()?, sb.minor()?) } else { "-".into() };
                        println!(
                            "{pre}\t{dev}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                            i.m("i_ino")?.int()?,
                            i.get_inode_type()?.unwrap_or("-"),
                            i.get_file_mode()?,
                            v(i.get_change_time()?),
                            v(i.get_modification_time()?),
                            v(i.get_access_time()?),
                            i.m("i_size")?.int()?
                        );
                    }
                    None => println!("{pre}\t-\t-\t-\t-\t-\t-\t-\t-"),
                }
            }
            Ok(true)
        })
        .unwrap();
    }
}
