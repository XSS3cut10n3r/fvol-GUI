//! python `symbols/linux/extensions/__init__.py` filesystem class extensions, as the [`FsExt`]
//! trait on [`Obj`]: `fs_struct`, `files_struct`, `qstr`, `dentry`, `inode`, `super_block`,
//! `mount`, `vfsmount`, `mnt_namespace`, `address_space`, `page`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Conventions (same as [`super::LinuxExt`]):
//!   * Every method accepts either the struct object or a pointer to it (python's `Pointer`
//!     forwards attribute access to the target, so `ptr.is_root()` works in python too).
//!   * Where python returns a member that is a pointer, the method returns the pointer object
//!     (read its value with `.u64()?`, follow it with `.deref()?`).
//!   * `Err` where python raises (InvalidAddressException propagates unless python catches it).
//!   * Methods whose python name is shared by several classes dispatch on the struct name
//!     (e.g. [`FsExt::get_flags_access`] for `super_block` / `mount` / `vfsmount`); a few that
//!     would clash with other traits carry a prefix (`sb_get_type`, `dentry_path`,
//!     `page_get_content`, ...).

use super::container_of;
use super::idstorage::PageCache;
use super::timespec::Timespec;
use super::{HListIter, LinuxExt, ListIter, vmlinux_of};
use crate::error::{Error, Result};
use crate::objects::util::pointer_to_string;
use crate::objects::Obj;
use crate::renderers::Value;
use crate::util::FxHashSet;

/// The struct behind `o` (dereferences a pointer, like python's `Pointer.__getattr__`).
#[inline]
pub(crate) fn tgt(o: &Obj) -> Result<Obj> {
    if o.is_pointer() { o.deref() } else { Ok(*o) }
}

/// python `bool(ptr) and ptr.is_readable()` for a pointer object (reads the value).
#[inline]
pub(crate) fn ptr_ok(p: &Obj) -> Result<bool> {
    Ok(p.u64()? != 0 && p.is_readable())
}

/// `include/linux/kdev_t.h` `MINORBITS`.
pub const MINORBITS: u32 = 20;
/// python `super_block.SB_RDONLY`.
pub const SB_RDONLY: i128 = 1;
/// python `super_block.SB_OPTS` (insertion order = python dict order).
pub const SB_OPTS: [(i128, &str); 4] = [(16, "sync"), (128, "dirsync"), (64, "mand"), (1 << 25, "lazytime")];

/// python `mount.MNT_*` flags.
pub const MNT_NOSUID: i128 = 0x01;
pub const MNT_NODEV: i128 = 0x02;
pub const MNT_NOEXEC: i128 = 0x04;
pub const MNT_NOATIME: i128 = 0x08;
pub const MNT_NODIRATIME: i128 = 0x10;
pub const MNT_RELATIME: i128 = 0x20;
pub const MNT_READONLY: i128 = 0x40;
pub const MNT_SHRINKABLE: i128 = 0x100;
pub const MNT_WRITE_HOLD: i128 = 0x200;
pub const MNT_SHARED: i128 = 0x1000;
pub const MNT_UNBINDABLE: i128 = 0x2000;
/// python `mount.MNT_FLAGS` (insertion order).
pub const MNT_FLAGS: [(i128, &str); 6] =
    [(MNT_NOSUID, "nosuid"), (MNT_NODEV, "nodev"), (MNT_NOEXEC, "noexec"), (MNT_NOATIME, "noatime"), (MNT_NODIRATIME, "nodiratime"), (MNT_RELATIME, "relatime")];

/// Iterator of python `dentry.get_subdirs()`: the child `dentry` objects. Yields `Err` once
/// where python raises (including python's `AttributeError` when the hlist walk of kernels
/// >= 6.8 yields `None` for an invalid container). An hlist cycle (python loops forever)
/// ends the walk.
pub enum SubdirIter {
    List(ListIter),
    HList(HListIter, FxHashSet<u64>),
}

impl Iterator for SubdirIter {
    type Item = Result<Obj>;
    fn next(&mut self) -> Option<Result<Obj>> {
        match self {
            SubdirIter::List(it) => it.next(),
            SubdirIter::HList(it, seen) => match it.next()? {
                Ok(Some(d)) => {
                    if !seen.insert(d.addr) {
                        return None;
                    }
                    Some(Ok(d))
                }
                Ok(None) => Some(Err(Error::msg("AttributeError: 'NoneType' object has no attribute 'vol'"))),
                Err(e) => Some(Err(e)),
            },
        }
    }
}

/// Filesystem class extensions on [`Obj`].
pub trait FsExt {
    // ---- fs_struct
    /// python `fs_struct.get_root_dentry()` (a `dentry *` pointer object).
    fn get_root_dentry(&self) -> Result<Obj>;
    /// python `fs_struct.get_root_mnt()` (a `vfsmount *` pointer object).
    fn get_root_mnt(&self) -> Result<Obj>;

    // ---- files_struct
    /// python `files_struct.get_fds()`: `fdt.fd.dereference()`, i.e. the `file *` pointer
    /// object at the start of the fd array (its value, fd 0, is read like python does).
    fn get_fds(&self) -> Result<Obj>;
    /// python `files_struct.get_max_fds()` (the `max_fds` integer object).
    fn get_max_fds(&self) -> Result<Obj>;

    // ---- qstr
    /// python `qstr.name_as_str()`: "" when the name cannot be read (the `len` read may raise).
    fn name_as_str(&self) -> Result<String>;

    // ---- dentry
    /// python `dentry.path()` (`__dentry_path`).
    fn dentry_path(&self) -> Result<String>;
    /// python `dentry.is_root()` (`vol.offset == d_parent`).
    fn is_root(&self) -> Result<bool>;
    /// python `dentry.is_subdir(old_dentry)`. Like python, `old_dentry` is compared by value
    /// when it is a pointer, and `d_ancestor` receives the object itself (python compares
    /// `d_parent` with `ancestor_dentry.vol.offset`, the pointer's own address).
    fn is_subdir(&self, old_dentry: &Obj) -> Result<bool>;
    /// python `dentry.d_ancestor(ancestor_dentry)`: compares `d_parent` values with
    /// `ancestor.addr` (python `ancestor_dentry.vol.offset`). Returns python's
    /// `current_dentry` (the dentry or a `d_parent` pointer object).
    fn d_ancestor(&self, ancestor: &Obj) -> Result<Option<Obj>>;
    /// python `dentry.get_subdirs()` (`d_children` hlist on kernels >= 6.8, `d_subdirs`
    /// list_head before).
    fn get_subdirs(&self) -> SubdirIter;

    // ---- inode
    /// python `inode.is_dir` .. `is_sticky` (`S_ISDIR(i_mode)` ...).
    fn is_dir(&self) -> Result<bool>;
    fn is_reg(&self) -> Result<bool>;
    fn is_link(&self) -> Result<bool>;
    fn is_fifo(&self) -> Result<bool>;
    fn is_sock(&self) -> Result<bool>;
    fn is_block(&self) -> Result<bool>;
    fn is_char(&self) -> Result<bool>;
    fn is_sticky(&self) -> Result<bool>;
    /// python `inode.get_inode_type()` ("DIR", "REG", ... or None).
    fn get_inode_type(&self) -> Result<Option<&'static str>>;
    /// python `inode.get_access_time()` (`Value::DateTime` or `Value::Unparsable`).
    fn get_access_time(&self) -> Result<Value>;
    /// python `inode.get_modification_time()`.
    fn get_modification_time(&self) -> Result<Value>;
    /// python `inode.get_change_time()`.
    fn get_change_time(&self) -> Result<Value>;
    /// python `inode.get_file_mode()` (`stat.filemode(i_mode)`).
    fn get_file_mode(&self) -> Result<String>;
    /// python `inode.get_pages()`: the cached `page` objects. A trailing `Err` = python raised.
    fn get_pages(&self) -> Vec<Result<Obj>>;
    /// python `inode.get_contents()`: `(page_index, page bytes)`. A trailing `Err` = raised.
    fn get_contents(&self) -> Vec<Result<(u64, Vec<u8>)>>;

    // ---- super_block
    /// python `super_block.major` (`s_dev >> MINORBITS`).
    fn major(&self) -> Result<i128>;
    /// python `super_block.minor`.
    fn minor(&self) -> Result<i128>;
    /// python `super_block.uuid` (`str(uuid.UUID(bytes=...))`).
    fn uuid(&self) -> Result<String>;
    /// python `super_block.get_type()` (`"ext4"`, `"fuse.sshfs"`, ...), None when unreadable.
    fn sb_get_type(&self) -> Result<Option<String>>;

    // ---- super_block / mount / vfsmount
    /// python `get_flags_access()` of `super_block`, `mount` and `vfsmount` ("ro" / "rw").
    fn get_flags_access(&self) -> Result<&'static str>;
    /// python `get_flags_opts()` of `super_block`, `mount` and `vfsmount`.
    fn get_flags_opts(&self) -> Result<Vec<&'static str>>;

    // ---- mount / vfsmount (dispatch on the struct name like the python classes)
    /// python `mount.get_mnt_sb()` / `vfsmount.get_mnt_sb()` (a `super_block *`).
    fn get_mnt_sb(&self) -> Result<Obj>;
    /// python `get_mnt_root()` (a `dentry *`).
    fn get_mnt_root(&self) -> Result<Obj>;
    /// python `get_mnt_flags()` (the flags integer object).
    fn get_mnt_flags(&self) -> Result<Obj>;
    /// python `get_mnt_parent()`: `mount` -> `mount *`; `vfsmount` -> `vfsmount *` (< 3.3) or
    /// the real mount's `mount *` (>= 3.3).
    fn get_mnt_parent(&self) -> Result<Obj>;
    /// python `get_mnt_mountpoint()` (a `dentry *`).
    fn get_mnt_mountpoint(&self) -> Result<Obj>;
    /// python `mount.get_parent_mount()` (`self.mnt.get_parent_mount()`: raises, like python).
    fn get_parent_mount(&self) -> Result<Obj>;
    /// python `has_parent()`.
    fn has_parent(&self) -> Result<bool>;
    /// python `get_vfsmnt_current()`: `mount` -> the `vfsmount` struct; `vfsmount` -> its
    /// `get_mnt_parent()`.
    fn get_vfsmnt_current(&self) -> Result<Obj>;
    /// python `get_vfsmnt_parent()`.
    fn get_vfsmnt_parent(&self) -> Result<Obj>;
    /// python `get_dentry_current()` (a `dentry *`).
    fn get_dentry_current(&self) -> Result<Obj>;
    /// python `get_dentry_parent()` (a `dentry *`).
    fn get_dentry_parent(&self) -> Result<Obj>;
    /// python `is_shared()` (the masked flag value, truthy like python).
    fn is_shared(&self) -> Result<i128>;
    /// python `is_unbindable()`.
    fn is_unbindable(&self) -> Result<i128>;
    /// python `is_slave()` (`mnt_master and mnt_master.vol.offset != 0`).
    fn is_slave(&self) -> Result<bool>;
    /// python `get_devname()` (`pointer_to_string(mnt_devname, 255)`).
    fn get_devname(&self) -> Result<String>;
    /// python `mount.get_dominating_id(root)` (`root` = a `path` struct, e.g. `fs.root`).
    fn get_dominating_id(&self, root: &Obj) -> Result<i128>;
    /// python `mount.get_peer_under_root(ns, root)` (`ns` = `mnt_namespace *` value).
    fn get_peer_under_root(&self, ns: u64, root: &Obj) -> Result<Option<Obj>>;
    /// python `mount.is_path_reachable(current_dentry, root)`.
    fn is_path_reachable(&self, current_dentry: &Obj, root: &Obj) -> Result<bool>;
    /// python `mount.next_peer()`.
    fn next_peer(&self) -> Result<Obj>;
    /// python `vfsmount.is_equal(vfsmount_ptr)` (`vfsmount_ptr` must be a pointer object).
    fn is_equal(&self, vfsmount_ptr: &Obj) -> Result<bool>;

    // ---- mnt_namespace
    /// python `mnt_namespace.get_inode()` (the namespace inode number).
    fn get_mnt_ns_inode(&self) -> Result<i128>;
    /// python `mnt_namespace.get_mount_points()`: `mount` objects (`None` where python's
    /// `container_of` yields None). A trailing `Err` = python raised.
    fn get_mount_points(&self) -> Vec<Result<Option<Obj>>>;

    // ---- address_space
    /// python `address_space.i_pages` (the `i_pages` or `page_tree` member).
    fn i_pages(&self) -> Result<Obj>;

    // ---- page
    /// python `page.is_valid()` (exceptions kept).
    fn page_is_valid(&self) -> Result<bool>;
    /// python `page.to_paddr()` (python int; may be negative for garbage).
    fn to_paddr(&self) -> Result<i128>;
    /// python `page.get_content()`.
    fn page_get_content(&self) -> Result<Option<Vec<u8>>>;
    /// python `page.get_flags_list()`.
    fn get_flags_list(&self) -> Result<Vec<&'static str>>;
}

/// python `stat.S_IFMT` values.
const S_IFMT: i128 = 0o170000;
const S_IFDIR: i128 = 0o040000;
const S_IFCHR: i128 = 0o020000;
const S_IFBLK: i128 = 0o060000;
const S_IFREG: i128 = 0o100000;
const S_IFIFO: i128 = 0o010000;
const S_IFLNK: i128 = 0o120000;
const S_IFSOCK: i128 = 0o140000;

/// python `stat.filemode(mode)` (the C `_stat` implementation: unknown file types are `?`).
pub fn filemode(mode: i128) -> String {
    let mut s = String::with_capacity(10);
    s.push(match mode & S_IFMT {
        S_IFLNK => 'l',
        S_IFSOCK => 's',
        S_IFREG => '-',
        S_IFBLK => 'b',
        S_IFDIR => 'd',
        S_IFCHR => 'c',
        S_IFIFO => 'p',
        // CPython _stat.filemode: unknown file type
        _ => '?',
    });
    // (mask, char) groups as in python's _filemode_table; the first matching entry wins
    let groups: [&[(i128, char)]; 9] = [
        &[(0o400, 'r')],
        &[(0o200, 'w')],
        &[(0o100 | 0o4000, 's'), (0o4000, 'S'), (0o100, 'x')],
        &[(0o040, 'r')],
        &[(0o020, 'w')],
        &[(0o010 | 0o2000, 's'), (0o2000, 'S'), (0o010, 'x')],
        &[(0o004, 'r')],
        &[(0o002, 'w')],
        &[(0o001 | 0o1000, 't'), (0o1000, 'T'), (0o001, 'x')],
    ];
    for g in groups {
        s.push(g.iter().find(|(m, _)| mode & m == *m).map_or('-', |x| x.1));
    }
    s
}

fn struct_is(o: &Obj, name: &str) -> bool {
    o.struct_name() == Some(name)
}

/// python `vfsmount._get_real_mnt()`: the `mount` containing this `vfsmount` (kernels >= 3.3).
fn real_mnt(v: &Obj) -> Result<Obj> {
    let vm = vmlinux_of(v)?;
    container_of(v.addr, "mount", "mnt", &vm)?.ok_or_else(|| Error::msg("AttributeError: 'NoneType' object has no attribute (vfsmount._get_real_mnt)"))
}

/// python `vfsmount._is_kernel_prior_to_struct_mount()`.
fn prior_to_struct_mount(v: &Obj) -> bool {
    v.has_member("mnt_parent")
}

/// python `_time_member_to_datetime(member)`.
fn inode_time(i: &Obj, member: &str) -> Result<Value> {
    let i = tgt(i)?;
    // (`{member}_sec`, `{member}_nsec`, `__{member}`) without formatting them per call
    let names: (std::borrow::Cow<str>, std::borrow::Cow<str>, std::borrow::Cow<str>) = match member {
        "i_atime" => ("i_atime_sec".into(), "i_atime_nsec".into(), "__i_atime".into()),
        "i_mtime" => ("i_mtime_sec".into(), "i_mtime_nsec".into(), "__i_mtime".into()),
        "i_ctime" => ("i_ctime_sec".into(), "i_ctime_nsec".into(), "__i_ctime".into()),
        _ => (format!("{member}_sec").into(), format!("{member}_nsec").into(), format!("__{member}").into()),
    };
    let (sec, nsec, under) = (&*names.0, &*names.1, &*names.2);
    let ts = if i.has_member(sec) && i.has_member(nsec) {
        // python adds `has_member(..._nsec) / 1e9` (True / 1e9): replicate
        Timespec::from_ints(i.m(sec)?.int()?, 1)
    } else if i.has_member(under) {
        i.m(under)?.timespec()?
    } else if i.has_member(member) {
        i.m(member)?.timespec()?
    } else {
        return Err(Error::msg("VolatilityException: Unsupported kernel inode type implementation"));
    };
    Ok(ts.to_datetime().map_or(Value::Unparsable, Value::DateTime))
}

fn imode(i: &Obj) -> Result<i128> {
    tgt(i)?.m("i_mode")?.int()
}

impl FsExt for Obj {
    fn get_root_dentry(&self) -> Result<Obj> {
        let s = tgt(self)?;
        if s.has_member("rootmnt") {
            return s.m("root");
        }
        let root = s.m("root")?;
        if root.has_member("dentry") {
            return root.m("dentry");
        }
        Err(Error::msg("AttributeError: Unable to find the root dentry"))
    }

    fn get_root_mnt(&self) -> Result<Obj> {
        let s = tgt(self)?;
        if s.has_member("rootmnt") {
            return s.m("rootmnt");
        }
        let root = s.m("root")?;
        if root.has_member("mnt") {
            return root.m("mnt");
        }
        Err(Error::msg("AttributeError: Unable to find the root mount"))
    }

    fn get_fds(&self) -> Result<Obj> {
        let s = tgt(self)?;
        let fd = if s.has_member("fdt") {
            s.m("fdt")?.m("fd")?
        } else if s.has_member("fd") {
            s.m("fd")?
        } else {
            return Err(Error::msg("AttributeError: Unable to find files -> file descriptors"));
        };
        let first = fd.deref()?;
        // python constructs the `file *` Pointer object, which reads its value
        first.u64()?;
        Ok(first)
    }

    fn get_max_fds(&self) -> Result<Obj> {
        let s = tgt(self)?;
        if s.has_member("fdt") {
            s.m("fdt")?.m("max_fds")
        } else if s.has_member("max_fds") {
            s.m("max_fds")
        } else {
            Err(Error::msg("AttributeError: Unable to find files -> maximum file descriptors"))
        }
    }

    fn name_as_str(&self) -> Result<String> {
        let s = tgt(self)?;
        let len = if s.has_member("len") { s.m("len")?.int()? + 1 } else { 255 };
        // `len` is unsigned: `len + 1 >= 1`, so only InvalidAddressException can occur here
        match s.m("name").and_then(|n| pointer_to_string(&n, len as u64)) {
            Ok(v) => Ok(v),
            Err(e) if e.is_invalid_address() => Ok(String::new()),
            Err(e) => Err(e),
        }
    }

    fn dentry_path(&self) -> Result<String> {
        let mut rev: Vec<String> = Vec::new();
        let mut seen = FxHashSet::default();
        // python keeps `current_dentry` as the object: the dentry first, then `d_parent`
        // pointer objects (whose vol.offset is the address of the d_parent field)
        let mut cur = *self;
        loop {
            if cur.is_root()? {
                break;
            }
            let cur_off = cur.addr;
            if seen.contains(&cur_off) {
                break;
            }
            let d = tgt(&cur)?;
            let parent = d.m("d_parent")?;
            parent.u64()?;
            rev.push(d.m("d_name")?.name_as_str()?);
            seen.insert(cur_off);
            cur = parent;
        }
        rev.reverse();
        Ok(format!("/{}", rev.join("/")))
    }

    fn is_root(&self) -> Result<bool> {
        let d = tgt(self)?;
        Ok(d.addr == d.m("d_parent")?.u64()?)
    }

    fn is_subdir(&self, old_dentry: &Obj) -> Result<bool> {
        let d = tgt(self)?;
        // python `self.vol.offset == old_dentry` (int vs Pointer compares the value; a struct
        // never equals an int)
        if old_dentry.is_pointer() && d.addr == old_dentry.u64()? {
            return Ok(true);
        }
        Ok(d.d_ancestor(old_dentry)?.is_some())
    }

    fn d_ancestor(&self, ancestor: &Obj) -> Result<Option<Obj>> {
        let mut seen = FxHashSet::default();
        let mut cur = *self;
        loop {
            if cur.is_root()? || seen.contains(&cur.addr) {
                return Ok(None);
            }
            let d = tgt(&cur)?;
            let parent = d.m("d_parent")?;
            if parent.u64()? == ancestor.addr {
                return Ok(Some(cur));
            }
            seen.insert(cur.addr);
            cur = parent;
        }
    }

    fn get_subdirs(&self) -> SubdirIter {
        let r = (|| -> Result<SubdirIter> {
            let d = tgt(self)?;
            let ty = format!("{}!dentry", d.table().name());
            if d.has_member("d_sib") && d.has_member("d_children") {
                // kernels >= 6.8: `d_children` is an hlist_head
                return Ok(SubdirIter::HList(d.m("d_children")?.hlist_to_list(&ty, "d_sib"), FxHashSet::default()));
            }
            let (member, head) = if d.has_member("d_child") && d.has_member("d_subdirs") {
                ("d_child", d.m("d_subdirs")?)
            } else if d.has_member("d_u") && d.has_member("d_subdirs") {
                ("d_u", d.m("d_subdirs")?)
            } else {
                return Err(Error::msg("VolatilityException: Unsupported dentry type"));
            };
            Ok(SubdirIter::List(head.list_of(&ty, member)))
        })();
        r.unwrap_or_else(|e| SubdirIter::List(ListIter::failed(e)))
    }

    fn is_dir(&self) -> Result<bool> {
        Ok(imode(self)? & S_IFMT == S_IFDIR)
    }
    fn is_reg(&self) -> Result<bool> {
        Ok(imode(self)? & S_IFMT == S_IFREG)
    }
    fn is_link(&self) -> Result<bool> {
        Ok(imode(self)? & S_IFMT == S_IFLNK)
    }
    fn is_fifo(&self) -> Result<bool> {
        Ok(imode(self)? & S_IFMT == S_IFIFO)
    }
    fn is_sock(&self) -> Result<bool> {
        Ok(imode(self)? & S_IFMT == S_IFSOCK)
    }
    fn is_block(&self) -> Result<bool> {
        Ok(imode(self)? & S_IFMT == S_IFBLK)
    }
    fn is_char(&self) -> Result<bool> {
        Ok(imode(self)? & S_IFMT == S_IFCHR)
    }
    fn is_sticky(&self) -> Result<bool> {
        Ok(imode(self)? & 0o1000 != 0)
    }

    fn get_inode_type(&self) -> Result<Option<&'static str>> {
        let m = imode(self)? & S_IFMT;
        Ok(match m {
            S_IFDIR => Some("DIR"),
            S_IFREG => Some("REG"),
            S_IFLNK => Some("LNK"),
            S_IFIFO => Some("FIFO"),
            S_IFSOCK => Some("SOCK"),
            S_IFCHR => Some("CHR"),
            S_IFBLK => Some("BLK"),
            _ => None,
        })
    }

    fn get_access_time(&self) -> Result<Value> {
        inode_time(self, "i_atime")
    }
    fn get_modification_time(&self) -> Result<Value> {
        inode_time(self, "i_mtime")
    }
    fn get_change_time(&self) -> Result<Value> {
        inode_time(self, "i_ctime")
    }

    fn get_file_mode(&self) -> Result<String> {
        Ok(filemode(imode(self)?))
    }

    fn get_pages(&self) -> Vec<Result<Obj>> {
        let r = (|| -> Result<Option<Obj>> {
            let i = tgt(self)?;
            if i.m("i_size")?.int()? == 0 {
                return Ok(None);
            }
            let map = i.m("i_mapping")?;
            if !(ptr_ok(&map)? && map.m("nrpages")?.int()? > 0) {
                return Ok(None);
            }
            Ok(Some(map.deref()?))
        })();
        match r {
            Ok(Some(mapping)) => match vmlinux_of(&mapping).and_then(|vm| PageCache::new(vm, mapping)) {
                Ok(pc) => pc.get_cached_pages(),
                Err(e) => vec![Err(e)],
            },
            Ok(None) => Vec::new(),
            Err(e) => vec![Err(e)],
        }
    }

    fn get_contents(&self) -> Vec<Result<(u64, Vec<u8>)>> {
        let mut out = Vec::new();
        let i_mapping = match tgt(self).and_then(|i| i.m("i_mapping")?.u64()) {
            Ok(v) => v,
            Err(e) => return vec![Err(e)],
        };
        for p in self.get_pages() {
            let r = p.and_then(|page| {
                if page.m("mapping")?.u64()? != i_mapping {
                    return Ok(None);
                }
                let index = page.m("index")?.u64()?;
                Ok(page.page_get_content()?.filter(|c| !c.is_empty()).map(|c| (index, c)))
            });
            match r {
                Ok(Some(v)) => out.push(Ok(v)),
                Ok(None) => {}
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            }
        }
        out
    }

    fn major(&self) -> Result<i128> {
        Ok(tgt(self)?.m("s_dev")?.int()? >> MINORBITS)
    }

    fn minor(&self) -> Result<i128> {
        Ok(tgt(self)?.m("s_dev")?.int()? & ((1 << MINORBITS) - 1))
    }

    fn uuid(&self) -> Result<String> {
        let s = tgt(self)?;
        if !s.has_member("s_uuid") {
            return Err(Error::msg("AttributeError: super_block struct does not support s_uuid direct attribute access, probably indicating a kernel version < 2.6.39-rc1."));
        }
        let u = s.m("s_uuid")?;
        let arr = if u.has_member("b") { u.m("b")? } else { u };
        let b: Vec<u8> = arr.ints()?.into_iter().map(|v| v as u8).collect();
        if b.len() != 16 {
            return Err(Error::msg("ValueError: bytes is not a 16-char string"));
        }
        let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
        Ok(format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]))
    }

    fn sb_get_type(&self) -> Result<Option<String>> {
        let s = tgt(self)?;
        let t = s.m("s_type")?;
        if !ptr_ok(&t)? {
            return Ok(None);
        }
        let name = t.m("name")?;
        if !ptr_ok(&name)? {
            return Ok(None);
        }
        let mut ty = pointer_to_string(&name, 255)?;
        let sub = s.m("s_subtype")?;
        if ptr_ok(&sub)? {
            ty.push('.');
            ty.push_str(&pointer_to_string(&sub, 255)?);
        }
        Ok(Some(ty))
    }

    fn get_flags_access(&self) -> Result<&'static str> {
        let s = tgt(self)?;
        let ro = match s.struct_name() {
            Some("super_block") => s.m("s_flags")?.int()? & SB_RDONLY != 0,
            Some("vfsmount") => s.m("mnt_flags")?.int()? & MNT_READONLY != 0,
            _ => s.get_mnt_flags()?.int()? & MNT_READONLY != 0,
        };
        Ok(if ro { "ro" } else { "rw" })
    }

    fn get_flags_opts(&self) -> Result<Vec<&'static str>> {
        let s = tgt(self)?;
        if struct_is(&s, "super_block") {
            let f = s.m("s_flags")?.int()?;
            return Ok(SB_OPTS.iter().filter(|(m, _)| m & f != 0).map(|x| x.1).collect());
        }
        let f = if struct_is(&s, "vfsmount") { s.m("mnt_flags")?.int()? } else { s.get_mnt_flags()?.int()? };
        Ok(MNT_FLAGS.iter().filter(|(m, _)| m & f != 0).map(|x| x.1).collect())
    }

    fn get_mnt_sb(&self) -> Result<Obj> {
        let s = tgt(self)?;
        if struct_is(&s, "vfsmount") {
            return s.m("mnt_sb");
        }
        if s.has_member("mnt") {
            s.m("mnt")?.m("mnt_sb")
        } else if s.has_member("mnt_sb") {
            s.m("mnt_sb")
        } else {
            Err(Error::msg("AttributeError: Unable to find mount -> super block"))
        }
    }

    fn get_mnt_root(&self) -> Result<Obj> {
        let s = tgt(self)?;
        if struct_is(&s, "vfsmount") {
            return s.m("mnt_root");
        }
        if s.has_member("mnt") {
            s.m("mnt")?.m("mnt_root")
        } else if s.has_member("mnt_root") {
            s.m("mnt_root")
        } else {
            Err(Error::msg("AttributeError: Unable to find mount -> mount root"))
        }
    }

    fn get_mnt_flags(&self) -> Result<Obj> {
        let s = tgt(self)?;
        if struct_is(&s, "vfsmount") {
            return s.m("mnt_flags");
        }
        if s.has_member("mnt") {
            s.m("mnt")?.m("mnt_flags")
        } else if s.has_member("mnt_flags") {
            s.m("mnt_flags")
        } else {
            Err(Error::msg("AttributeError: Unable to find mount -> mount flags"))
        }
    }

    fn get_mnt_parent(&self) -> Result<Obj> {
        let s = tgt(self)?;
        if struct_is(&s, "vfsmount") {
            if prior_to_struct_mount(&s) {
                return s.m("mnt_parent");
            }
            return real_mnt(&s)?.get_mnt_parent();
        }
        s.m("mnt_parent")
    }

    fn get_mnt_mountpoint(&self) -> Result<Obj> {
        let s = tgt(self)?;
        if struct_is(&s, "vfsmount") && !s.has_member("mnt_mountpoint") {
            return real_mnt(&s)?.m("mnt_mountpoint");
        }
        s.m("mnt_mountpoint")
    }

    fn get_parent_mount(&self) -> Result<Obj> {
        // python: `self.mnt.get_parent_mount()` - vfsmount has no such method (AttributeError)
        Err(Error::msg("AttributeError: 'vfsmount' object has no attribute 'get_parent_mount'"))
    }

    fn has_parent(&self) -> Result<bool> {
        let s = tgt(self)?;
        if struct_is(&s, "vfsmount") {
            if prior_to_struct_mount(&s) {
                return Ok(s.m("mnt_parent")?.u64()? != s.addr);
            }
            return real_mnt(&s)?.has_parent();
        }
        Ok(s.m("mnt_parent")?.u64()? != s.addr)
    }

    fn get_vfsmnt_current(&self) -> Result<Obj> {
        let s = tgt(self)?;
        if struct_is(&s, "vfsmount") {
            return s.get_mnt_parent();
        }
        s.m("mnt")
    }

    fn get_vfsmnt_parent(&self) -> Result<Obj> {
        let s = tgt(self)?;
        if struct_is(&s, "vfsmount") {
            if prior_to_struct_mount(&s) {
                return s.get_mnt_parent();
            }
            return real_mnt(&s)?.get_vfsmnt_parent();
        }
        s.get_mnt_parent()?.get_vfsmnt_current()
    }

    fn get_dentry_current(&self) -> Result<Obj> {
        let s = tgt(self)?;
        if struct_is(&s, "vfsmount") {
            if prior_to_struct_mount(&s) {
                return s.get_mnt_mountpoint();
            }
            return real_mnt(&s)?.get_dentry_current();
        }
        s.get_vfsmnt_current()?.m("mnt_root")
    }

    fn get_dentry_parent(&self) -> Result<Obj> {
        let s = tgt(self)?;
        if struct_is(&s, "vfsmount") {
            if prior_to_struct_mount(&s) {
                return s.get_mnt_mountpoint();
            }
            return real_mnt(&s)?.get_mnt_mountpoint();
        }
        s.get_mnt_parent()?.get_dentry_current()
    }

    fn is_shared(&self) -> Result<i128> {
        Ok(self.get_mnt_flags()?.int()? & MNT_SHARED)
    }

    fn is_unbindable(&self) -> Result<i128> {
        Ok(self.get_mnt_flags()?.int()? & MNT_UNBINDABLE)
    }

    fn is_slave(&self) -> Result<bool> {
        let s = tgt(self)?;
        let m = s.m("mnt_master")?;
        // python `mnt_master and mnt_master.vol.offset != 0` (the pointer's own address)
        Ok(m.u64()? != 0 && m.addr != 0)
    }

    fn get_devname(&self) -> Result<String> {
        pointer_to_string(&tgt(self)?.m("mnt_devname")?, 255)
    }

    fn get_dominating_id(&self, root: &Obj) -> Result<i128> {
        let s = tgt(self)?;
        let ns = s.m("mnt_ns")?.u64()?;
        let mut seen = FxHashSet::default();
        // python keeps the `mnt_master` pointer objects: their vol.offset (own address) is what
        // goes into the seen set
        let mut cur = s.m("mnt_master")?;
        loop {
            if cur.u64()? == 0 || cur.addr == 0 || seen.contains(&cur.addr) {
                return Ok(0);
            }
            let m = cur.deref()?;
            if let Some(peer) = m.get_peer_under_root(ns, root)? {
                if peer.addr != 0 {
                    return peer.m("mnt_group_id")?.int();
                }
            }
            seen.insert(cur.addr);
            cur = m.m("mnt_master")?;
        }
    }

    fn get_peer_under_root(&self, ns: u64, root: &Obj) -> Result<Option<Obj>> {
        let start = tgt(self)?;
        let mut seen = FxHashSet::default();
        let mut cur = start;
        while !seen.contains(&cur.addr) {
            if cur.m("mnt_ns")?.u64()? == ns {
                let root_dentry = cur.m("mnt")?.m("mnt_root")?;
                if cur.is_path_reachable(&root_dentry, root)? {
                    return Ok(Some(cur));
                }
            }
            seen.insert(cur.addr);
            cur = cur.next_peer()?;
            if cur.addr == start.addr {
                break;
            }
        }
        Ok(None)
    }

    fn is_path_reachable(&self, current_dentry: &Obj, root: &Obj) -> Result<bool> {
        let root = tgt(root)?;
        let root_mnt = root.m("mnt")?.u64()?;
        let mut seen = FxHashSet::default();
        // `cur` is the mount (python's current_mnt, which becomes the `mnt_parent` pointer
        // object: its vol.offset - the field's address - is what the seen set records)
        let mut cur = tgt(self)?;
        let mut cur_off = cur.addr;
        let mut dentry = *current_dentry;
        while cur.m("mnt")?.addr != root_mnt && cur.has_parent()? && !seen.contains(&cur_off) {
            dentry = cur.m("mnt_mountpoint")?;
            seen.insert(cur_off);
            let parent = cur.m("mnt_parent")?;
            cur_off = parent.addr;
            cur = parent.deref()?;
        }
        if cur.m("mnt")?.addr != root_mnt {
            return Ok(false);
        }
        dentry.is_subdir(&root.m("dentry")?)
    }

    fn next_peer(&self) -> Result<Obj> {
        let s = tgt(self)?;
        let off = s.member_offset("mnt_share")?;
        let next = s.m("mnt_share")?.m("next")?.deref()?;
        Ok(s.at_addr(next.addr.wrapping_sub(off)))
    }

    fn is_equal(&self, vfsmount_ptr: &Obj) -> Result<bool> {
        let s = tgt(self)?;
        if !vfsmount_ptr.is_pointer() {
            return Err(Error::msg("VolatilityException: Unexpected argument type. It has to be a 'vfsmount *'"));
        }
        Ok(s.addr == vfsmount_ptr.u64()?)
    }

    fn get_mnt_ns_inode(&self) -> Result<i128> {
        let s = tgt(self)?;
        if s.has_member("proc_inum") {
            return s.m("proc_inum")?.int();
        }
        if s.has_member("ns") {
            let ns = s.m("ns")?;
            if ns.has_member("inum") {
                return ns.m("inum")?.int();
            }
        }
        Err(Error::msg("AttributeError: Unable to find mnt_namespace inode"))
    }

    fn get_mount_points(&self) -> Vec<Result<Option<Obj>>> {
        let s = match tgt(self) {
            Ok(s) => s,
            Err(e) => return vec![Err(e)],
        };
        let table = s.table();
        if s.has_member("list") {
            let mnt_type = if table.has_type("mount") { format!("{}!mount", table.name()) } else { format!("{}!vfsmount", table.name()) };
            return match s.m("list") {
                Ok(l) => l.list_of(&mnt_type, "mnt_list").map(|r| r.map(Some)).collect(),
                Err(e) => vec![Err(e)],
            };
        }
        if s.has_member("mounts") {
            if let Ok(m) = s.m("mounts") {
                if m.struct_name() == Some("rb_root") {
                    let vm = match vmlinux_of(&s) {
                        Ok(v) => v,
                        Err(e) => return vec![Err(e)],
                    };
                    let mut out = Vec::new();
                    for n in super::idstorage::rb_get_nodes(&m) {
                        match n.and_then(|node| container_of(node, "mount", "mnt_node", &vm)) {
                            Ok(x) => out.push(Ok(x)),
                            Err(e) => {
                                out.push(Err(e));
                                break;
                            }
                        }
                    }
                    return out;
                }
            }
        }
        vec![Err(Error::msg("VolatilityException: Unsupported kernel mount namespace implementation"))]
    }

    fn i_pages(&self) -> Result<Obj> {
        let s = tgt(self)?;
        if s.has_member("i_pages") {
            s.m("i_pages")
        } else if s.has_member("page_tree") {
            s.m("page_tree")
        } else {
            Err(Error::msg("VolatilityException: Unsupported page cache tree"))
        }
    }

    fn page_is_valid(&self) -> Result<bool> {
        let p = tgt(self)?;
        let mapping = p.m("mapping")?;
        if mapping.u64()? != 0 && !mapping.is_readable() {
            return Ok(false);
        }
        Ok(p.to_paddr()? >= 0)
    }

    fn to_paddr(&self) -> Result<i128> {
        let p = tgt(self)?;
        let vm = vmlinux_of(&p)?;
        let intel = vm.layer().as_intel().ok_or_else(|| Error::msg("LayerException: vmemmap_start calculation isn't currently supported"))?;
        let start = vmemmap_start(&vm, intel)?;
        let pagec = intel.canonicalize(p.addr) as i128;
        let size = vm.size_of("page")? as i128;
        if size == 0 {
            return Err(Error::msg("ZeroDivisionError: integer division or modulo by zero"));
        }
        let pfn = (pagec - start).div_euclid(size);
        Ok(pfn * intel.page_size() as i128)
    }

    fn page_get_content(&self) -> Result<Option<Vec<u8>>> {
        let p = tgt(self)?;
        let vm = vmlinux_of(&p)?;
        let page_size = vm.layer().as_intel().map_or(0x1000, |i| i.page_size());
        let phys: &dyn crate::layers::Layer = match p.layer().as_intel() {
            Some(i) => i.phys().as_ref(),
            None => p.layer(),
        };
        let paddr = p.to_paddr()?;
        if paddr == 0 {
            return Ok(None);
        }
        if paddr < 0 || !phys.is_valid(paddr as u64, page_size) {
            return Ok(None);
        }
        let mut buf = vec![0u8; page_size as usize];
        phys.read(paddr as u64, &mut buf)?;
        Ok(Some(buf))
    }

    fn get_flags_list(&self) -> Result<Vec<&'static str>> {
        let p = tgt(self)?;
        let t: crate::symbols::TableRef = p.table();
        let flags = p.m("flags")?.int()?;
        let Some(e) = t.enumeration("pageflags") else { return Ok(Vec::new()) };
        Ok(t.enum_constants(e).filter(|(_, v)| (0..127).contains(v) && flags & (1i128 << v) != 0).map(|(n, _)| n).collect())
    }
}

/// python `page._intel_vmemmap_start` (cached per kernel table).
fn vmemmap_start(vm: &crate::objects::Module, intel: &crate::layers::IntelLayer) -> Result<i128> {
    use std::sync::Mutex;
    static CACHE: Mutex<Vec<(usize, i128)>> = Mutex::new(Vec::new());
    let key = vm.table() as *const _ as usize;
    if let Some(v) = CACHE.lock().unwrap().iter().find(|e| e.0 == key) {
        return Ok(v.1);
    }
    let v: i128 = if vm.has_symbol("mem_section") {
        if vm.has_symbol("vmemmap_base") {
            vm.object_from_symbol("vmemmap_base")?.int()?
        } else if intel.mode() != crate::layers::PagingMode::La57 {
            0xFFFF_EA00_0000_0000
        } else {
            return Err(Error::msg("VolatilityException: 5-level paging is not yet supported"));
        }
    } else if vm.has_symbol("mem_map") {
        vm.object_from_symbol("mem_map")?.int()?
    } else if vm.has_symbol("node_data") {
        return Err(Error::msg("VolatilityException: NUMA systems are not yet supported"));
    } else {
        return Err(Error::msg("VolatilityException: Unsupported Linux memory model"));
    };
    if v == 0 {
        return Err(Error::msg("VolatilityException: Something went wrong, we shouldn't be here"));
    }
    CACHE.lock().unwrap().push((key, v));
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::filemode;

    #[test]
    fn filemode_like_python() {
        assert_eq!(filemode(0o100644), "-rw-r--r--");
        assert_eq!(filemode(0o040755), "drwxr-xr-x");
        assert_eq!(filemode(0o104755), "-rwsr-xr-x");
        assert_eq!(filemode(0o041777), "drwxrwxrwt");
        assert_eq!(filemode(0o120777), "lrwxrwxrwx");
        assert_eq!(filemode(0o102644), "-rw-r-Sr--");
        assert_eq!(filemode(0), "?---------");
        assert_eq!(filemode(0o600), "?rw-------");
    }
}

#[cfg(test)]
mod image_tests {
    use super::*;
    use crate::context::{Context, GlobalOptions};
    use crate::symbols::linux::utilities::get_path_mnt;

    /// Prints `linux.mountinfo.MountInfo`-like rows (default options) to check the mount /
    /// dentry helpers against python's reference:
    /// `FASTVOL_BENCH_IMAGE=<image> cargo test --profile fast mountinfo_like -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn mountinfo_like() {
        let image = crate::util::env::var("BENCH_IMAGE").unwrap();
        let opts = GlobalOptions { file: Some(image), symbol_dirs: vec!["/home/user/rs-vol/testdata/symbols".into()], ..Default::default() };
        let ctx = Context::new(opts).unwrap();
        let k = ctx.linux_kernel().unwrap();
        let mut seen = FxHashSet::default();
        crate::plugins::linux::pslist::list_tasks(k, &|_| Ok(false), false, &mut |task| {
            let fs = task.m("fs")?;
            let ns = task.m("nsproxy")?;
            if !(ptr_ok(&fs)? && ptr_ok(&ns)? && ptr_ok(&ns.m("mnt_ns")?)?) {
                return Ok(true);
            }
            let mnt_ns = ns.m("mnt_ns")?;
            let ns_id = mnt_ns.get_mnt_ns_inode()?;
            for m in mnt_ns.get_mount_points() {
                let m = m?.unwrap();
                let mnt_id = m.m("mnt_id")?.int()?;
                if !seen.insert(mnt_id) {
                    continue;
                }
                let mnt_root = m.get_mnt_root()?;
                if mnt_root.u64()? == 0 {
                    continue;
                }
                let path_root = get_path_mnt(&task, &m)?;
                if path_root.is_empty() {
                    continue;
                }
                let root_path = mnt_root.dentry_path()?;
                let parent_id = m.m("mnt_parent")?.m("mnt_id")?.int()?;
                let sb = m.get_mnt_sb()?;
                if !ptr_ok(&sb)? {
                    continue;
                }
                let st_dev = format!("{}:{}", sb.major()?, sb.minor()?);
                let mut mnt_opts = vec![m.get_flags_access()?];
                mnt_opts.extend(m.get_flags_opts()?);
                let mut fields: Vec<String> = Vec::new();
                if m.is_shared()? != 0 {
                    fields.push(format!("shared:{}", m.m("mnt_group_id")?.int()?));
                }
                if m.is_slave()? {
                    let master = m.m("mnt_master")?.m("mnt_group_id")?.int()?;
                    fields.push(format!("master:{master}"));
                    let dom = m.get_dominating_id(&fs.m("root")?)?;
                    if dom != 0 && dom != master {
                        fields.push(format!("propagate_from:{dom}"));
                    }
                }
                if m.is_unbindable()? != 0 {
                    fields.push("unbindable".into());
                }
                let ty = sb.sb_get_type()?.unwrap_or_else(|| "-".into());
                let mut devname = m.get_devname()?;
                if devname.is_empty() {
                    devname = "none".into();
                }
                let mut sb_opts = vec![sb.get_flags_access()?];
                sb_opts.extend(sb.get_flags_opts()?);
                println!("MI\t{ns_id}\t{mnt_id}\t{parent_id}\t{st_dev}\t{root_path}\t{path_root}\t{}\t{}\t{ty}\t{devname}\t{}", mnt_opts.join(","), fields.join(" "), sb_opts.join(","));
            }
            Ok(true)
        })
        .unwrap();
    }
}
