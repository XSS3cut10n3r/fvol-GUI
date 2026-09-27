//! linux.pagecache.Files, linux.pagecache.InodePages, linux.pagecache.RecoverFs (python
//! `plugins/linux/pagecache.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! * [`get_inodes`] is python's `Files.get_inodes(context, kernel, follow_symlinks)` (walks the
//!   dentry trees of every mounted superblock, streaming like python's generator).
//! * [`inode_user_row`] is python's `InodeInternal.to_user()` + `format_fields_with_headers`.
//! * [`inode_page_writes`] is python's `InodePages.write_inode_content_to_stream` minus the
//!   stream: the `(file offset, physical address, length)` writes it would perform.
//! * RecoverFs writes the same tarball python's `tarfile` (PAX format) produces
//!   ([`crate::util::pytar`]) through our own gzip / bzip2 / xz encoders; member names, modes,
//!   sizes and contents are python's, timestamps are the run time (as in python).

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::Layer;
use crate::objects::{Field, Obj};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::fs::{ptr_ok, tgt};
use crate::symbols::linux::prelude::*;
use crate::util::FxHashSet;
use std::io::Write;
use std::sync::Arc;

pub struct Files;
pub struct InodePages;
pub struct RecoverFs;

/// python `InodeInternal`.
#[derive(Clone)]
pub struct InodeInternal {
    /// the `super_block` struct
    pub superblock: Obj,
    /// the superblock mount point path
    pub mountpoint: Arc<str>,
    /// the `inode` struct
    pub inode: Obj,
    /// the dentry full path (`"a -> b"` for followed symlinks)
    pub path: String,
}

/// python `inode.is_valid()` with its exceptions kept (`i_ino > 0 and i_count.counter >= 0`).
pub fn inode_valid(i: &Obj) -> Result<bool> {
    let i = tgt(i)?;
    Ok(i.m("i_ino")?.int()? > 0 && i.path("i_count.counter")?.int()? >= 0)
}

/// `LinuxPageCacheException` (python catches only this one around page cache walks).
pub fn is_page_cache_exception(e: &Error) -> bool {
    e.to_string().starts_with("LinuxPageCacheException")
}

/// python `Files._follow_symlink(inode_ptr, symlink_path)`.
fn follow_symlink(inode: &Obj, symlink_path: String) -> Result<String> {
    Ok(match symlink_dest(inode)? {
        Some(dest) => format!("{symlink_path} -> {dest}"),
        None => symlink_path,
    })
}

/// `inode.is_link and inode.has_member("i_link") and inode.i_link and inode.i_link.is_readable()`
/// then `i_link.dereference().cast("string", max_length=255, encoding="utf-8", errors="replace")`.
fn symlink_dest(inode: &Obj) -> Result<Option<String>> {
    if inode.is_pointer() && inode.u64()? == 0 {
        return Ok(None);
    }
    let i = tgt(inode)?;
    if !i.is_link()? || !i.has_member("i_link") {
        return Ok(None);
    }
    let l = i.m("i_link")?;
    if !ptr_ok(&l)? {
        return Ok(None);
    }
    Ok(Some(l.deref()?.read_string(255, "utf-8", "replace")?))
}

/// Struct members of the dentry walk, resolved once (hot loop: no member-name hashing).
struct WalkFields {
    d_inode: Field,
    d_name: Field,
    q_name: Field,
    i_ino: Field,
    i_count: Field,
    i_mode: Field,
    i_mapping: Field,
}

impl WalkFields {
    fn new(t: crate::symbols::TableRef) -> Result<WalkFields> {
        Ok(WalkFields {
            d_inode: Field::new(t, "dentry", "d_inode")?,
            d_name: Field::new(t, "dentry", "d_name")?,
            q_name: Field::new(t, "qstr", "name")?,
            i_ino: Field::new(t, "inode", "i_ino")?,
            i_count: Field::path(t, "inode", "i_count.counter")?,
            i_mode: Field::new(t, "inode", "i_mode")?,
            i_mapping: Field::new(t, "inode", "i_mapping")?,
        })
    }

    /// python `inode.is_valid()` (exceptions kept).
    #[inline]
    fn inode_valid(&self, i: &Obj) -> Result<bool> {
        Ok(i.f(&self.i_ino).int()? > 0 && i.f(&self.i_count).int()? >= 0)
    }
}

const S_IFMT: i128 = 0o170000;
const S_IFDIR: i128 = 0o040000;
const S_IFLNK: i128 = 0o120000;

/// python `Files._walk_dentry(seen_dentries, root_dentry, parent_dir)`: depth-first, calls
/// `f(file_path, dentry, inode_ptr, inode)` (python's yield; `inode_ptr` / `inode` are the
/// dentry's `d_inode` pointer and struct, already checked readable + valid exactly like python
/// re-checks them) before descending into a directory. `f` returns false to stop the whole
/// walk (`Ok(false)` is propagated).
fn walk_dentry(w: &WalkFields, seen: &mut FxHashSet<u64>, root: Obj, parent_dir: &str, f: &mut dyn FnMut(String, Obj, &Obj, Obj) -> Result<bool>) -> Result<bool> {
    struct Frame {
        iter: crate::symbols::linux::SubdirIter,
        root_addr: u64,
        parent_dir: String,
    }
    let mut stack = vec![Frame { iter: root.get_subdirs(), root_addr: root.addr, parent_dir: parent_dir.to_string() }];
    while let Some(top) = stack.last_mut() {
        let Some(next) = top.iter.next() else {
            stack.pop();
            continue;
        };
        let dentry = next?;
        if dentry.addr == top.root_addr || !seen.insert(dentry.addr) {
            continue;
        }
        let inode_ptr = dentry.f(&w.d_inode);
        if !ptr_ok(&inode_ptr)? {
            continue;
        }
        let inode = inode_ptr.deref()?;
        if !w.inode_valid(&inode)? {
            continue;
        }
        let d_name = dentry.f(&w.d_name);
        if d_name.f(&w.q_name).u64()? == 0 {
            continue;
        }
        let name = d_name.name_as_str()?;
        let mut file_path = String::with_capacity(top.parent_dir.len() + 1 + name.len());
        file_path.push_str(&top.parent_dir);
        file_path.push('/');
        file_path.push_str(&name);
        // python evaluates `inode.is_dir` after the consumer ran; reading i_mode early has no
        // side effect, its error (if any) is only returned at python's point
        let mode = inode.f(&w.i_mode).int();
        let dir_path = match &mode {
            Ok(m) if m & S_IFMT == S_IFDIR => Some(file_path.clone()),
            _ => None,
        };
        if !f(file_path, dentry, &inode_ptr, inode)? {
            return Ok(false);
        }
        mode?;
        if let Some(parent_dir) = dir_path {
            stack.push(Frame { iter: dentry.get_subdirs(), root_addr: dentry.addr, parent_dir });
        }
    }
    Ok(true)
}

/// python `Files.get_inodes(context, kernel, follow_symlinks)`: streams every cached inode
/// (superblock roots, then their dentry trees) to `f` in python's order; `f` returns false
/// to stop. `Err` where python raises.
///
/// The dentry trees are read in parallel (all directories of a tree level at once, see
/// [`DentryForest`]) and then replayed in python's depth-first order with python's `seen`
/// sets. A dentry graph that is not a forest (a dentry reached twice, a child equal to its
/// parent: smear / corruption) would make python's `seen` set change the walk, so it falls
/// back to the sequential walk ([`get_inodes_seq`]).
pub fn get_inodes(k: &LinuxKernel, follow_symlinks: bool, f: &mut dyn FnMut(InodeInternal) -> Result<bool>) -> Result<()> {
    match prepare_walk(k, follow_symlinks)? {
        Prepared::Forest(mut walk, tail) => {
            let _s = crate::util::trace::span("pagecache: replay");
            if walk.replay(&mut |w, r| {
                let v = w.view(&r);
                f(InodeInternal { superblock: v.superblock, mountpoint: w.roots[r.root as usize].mountpoint.clone(), inode: v.inode, path: v.path.into_owned() })
            })? {
                tail.map_or(Ok(()), Err)?;
            }
            Ok(())
        }
        Prepared::Seq(w, roots) => get_inodes_seq(&w, roots, follow_symlinks, f),
    }
}

/// [`get_inodes`] collected for parallel consumers: python's inodes in order (see
/// [`InodeList::view`]) and the `Err` python raised after them, if any. The walk only records
/// where each inode is; paths are built by the consumers.
pub fn collect_inode_list(k: &LinuxKernel, follow_symlinks: bool) -> (InodeList, Option<Error>) {
    let prepared = match prepare_walk(k, follow_symlinks) {
        Ok(p) => p,
        Err(e) => return (InodeList::Owned(Vec::new()), Some(e)),
    };
    match prepared {
        Prepared::Forest(mut walk, tail) => {
            let _s = crate::util::trace::span("pagecache: replay");
            let mut refs = Vec::with_capacity(walk.forest.children() + walk.roots.len());
            let r = walk.replay(&mut |_, r| {
                refs.push(r);
                Ok(true)
            });
            (InodeList::Refs { walk, refs }, r.err().or(tail))
        }
        Prepared::Seq(w, roots) => {
            let mut v = Vec::new();
            let r = get_inodes_seq(&w, roots, follow_symlinks, &mut |i| {
                v.push(i);
                Ok(true)
            });
            (InodeList::Owned(v), r.err())
        }
    }
}

/// python's inodes of [`collect_inode_list`].
pub enum InodeList {
    /// positions in a replayed [`Walk`]
    Refs { walk: Walk, refs: Vec<InodeRef> },
    /// from the sequential walk
    Owned(Vec<InodeInternal>),
}

impl InodeList {
    pub fn len(&self) -> usize {
        match self {
            InodeList::Refs { refs, .. } => refs.len(),
            InodeList::Owned(v) => v.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// The `i`-th inode.
    pub fn view(&self, i: usize) -> InodeView<'_> {
        match self {
            InodeList::Refs { walk, refs } => walk.view(&refs[i]),
            InodeList::Owned(v) => {
                let ii = &v[i];
                InodeView { superblock: ii.superblock, mountpoint: &ii.mountpoint, inode: ii.inode, path: std::borrow::Cow::Borrowed(&ii.path) }
            }
        }
    }
}

/// An [`InodeInternal`] borrowed from an [`InodeList`].
pub struct InodeView<'a> {
    pub superblock: Obj,
    pub mountpoint: &'a str,
    pub inode: Obj,
    pub path: std::borrow::Cow<'a, str>,
}

/// Where an inode python yields is in a [`Walk`]: the root inode of tree `root` (`node ==
/// u32::MAX`) or child `child` of directory node `node`, whose path is `dirs[dir]`.
#[derive(Clone, Copy, Debug)]
pub struct InodeRef {
    root: u32,
    node: u32,
    child: u32,
    dir: u32,
}

/// The listed dentry forest with the superblock roots it starts from, replayed in python's
/// order.
pub struct Walk {
    /// the roots that passed python's checks, in order (tree `i` of the forest is `roots[i]`)
    roots: Vec<SbRoot>,
    forest: DentryForest,
    /// paths of the directories python descends into (and each tree's `parent_dir`)
    dirs: Vec<String>,
    follow_symlinks: bool,
}

/// What [`prepare_walk`] found.
enum Prepared {
    /// the forest and the `Err` python raised after its trees (while listing superblocks)
    Forest(Walk, Option<Error>),
    /// not a forest: python's sequential walk over these roots
    Seq(WalkFields, Vec<Result<Option<SbRoot>>>),
}

/// The superblock roots and the parallel dentry listing of [`get_inodes`].
fn prepare_walk(k: &LinuxKernel, follow_symlinks: bool) -> Result<Prepared> {
    let w = WalkFields::new(k.table)?;
    let sbs = {
        let _s = crate::util::trace::span("pagecache: get_superblocks");
        crate::plugins::linux::mountinfo::get_superblocks(k)
    };
    // superblock roots with python's per-superblock checks (the seen_inodes dedupe is replayed)
    let mut roots: Vec<Result<Option<SbRoot>>> = Vec::new();
    for sb in sbs {
        let r = sb.and_then(|(superblock, mountpoint)| sb_root(&w, superblock, mountpoint));
        let stop = r.is_err();
        roots.push(r);
        if stop {
            break;
        }
    }
    let forest = {
        let _s = crate::util::trace::span("pagecache: parallel dentry listing");
        let starts: Vec<Obj> = roots.iter().filter_map(|r| r.as_ref().ok().and_then(|o| o.as_ref())).map(|r| r.root_dentry).collect();
        DentryForest::build(&w, &starts, follow_symlinks)
    };
    // FASTVOL_PAGECACHE_SEQ=1 forces the sequential walk (cross-checks the parallel one)
    let forest = forest.filter(|_| crate::util::env::var_os("PAGECACHE_SEQ").is_none());
    let Some(forest) = forest else { return Ok(Prepared::Seq(w, roots)) };
    // an `Err` can only be the last entry: python raised after the trees before it
    let mut tail = None;
    let mut ok = Vec::with_capacity(roots.len());
    for r in roots {
        match r {
            Ok(Some(root)) => ok.push(root),
            Ok(None) => {}
            Err(e) => tail = Some(e),
        }
    }
    Ok(Prepared::Forest(Walk { roots: ok, forest, dirs: Vec::new(), follow_symlinks }, tail))
}

impl Walk {
    /// python's `get_inodes` loop over the trees: `f(self, inode)` for every inode python
    /// yields, in order (`Ok(false)`: `f` asked to stop). `Err` where python raises.
    fn replay(&mut self, f: &mut dyn FnMut(&Walk, InodeRef) -> Result<bool>) -> Result<bool> {
        let mut seen_inodes = FxHashSet::default();
        seen_inodes.reserve(self.forest.children() + self.roots.len());
        for t in 0..self.roots.len() {
            let root = &self.roots[t];
            if !root.mapping_ok {
                continue;
            }
            if !seen_inodes.insert(root.root_inode_ptr) {
                continue;
            }
            if !f(self, InodeRef { root: t as u32, node: u32::MAX, child: 0, dir: 0 })? {
                return Ok(false);
            }
            let root_dir = self.dirs.len() as u32;
            self.dirs.push(self.roots[t].parent_dir.clone());
            if !self.replay_tree(t, root_dir, &mut seen_inodes, f)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Replays tree `t` in python's depth-first order (`_walk_dentry` + `get_inodes`'s checks):
    /// calls `f` for every inode python yields, then descends into directories;
    /// `Ok(false)` when `f` asked to stop, `Err` where python raises.
    fn replay_tree(&mut self, t: usize, root_dir: u32, seen_inodes: &mut FxHashSet<u64>, f: &mut dyn FnMut(&Walk, InodeRef) -> Result<bool>) -> Result<bool> {
        let mut stack: Vec<(usize, usize, u32)> = vec![(t, 0, root_dir)];
        while let Some(&(n, i, d)) = stack.last() {
            let node = &self.forest.dirs[n];
            if i >= node.children.len() {
                if let Some(e) = &node.err {
                    return Err(e.clone_err());
                }
                stack.pop();
                continue;
            }
            stack.last_mut().unwrap().1 += 1;
            let c = &node.children[i];
            if c.skip {
                continue;
            }
            // python re-checks `d_inode` readable + `is_valid()` here: same memory, same result
            if *c.mapping_ok.as_ref().map_err(CloneErr::clone_err)? && seen_inodes.insert(c.inode_ptr) {
                if self.follow_symlinks {
                    // `_follow_symlink`: `inode.is_link` reads i_mode
                    match &c.mode {
                        Err(e) => return Err(e.clone_err()),
                        Ok(m) if m & S_IFMT == S_IFLNK => {
                            if let Some(Err(e)) = &c.symlink {
                                return Err(e.clone_err());
                            }
                        }
                        Ok(_) => {}
                    }
                }
                if !f(self, InodeRef { root: t as u32, node: n as u32, child: i as u32, dir: d })? {
                    return Ok(false);
                }
            }
            // python: `if inode.is_dir:` after the consumer
            if let Err(e) = &c.mode {
                return Err(e.clone_err());
            }
            if let Some(sub) = c.dir {
                let parent = &self.dirs[d as usize];
                let mut path = String::with_capacity(parent.len() + 1 + c.name.len());
                path.push_str(parent);
                path.push('/');
                path.push_str(&c.name);
                let id = self.dirs.len() as u32;
                self.dirs.push(path);
                stack.push((sub, 0, id));
            }
        }
        Ok(true)
    }

    /// The inode `r` points to, with its path (`"a -> b"` for a followed symlink).
    fn view(&self, r: &InodeRef) -> InodeView<'_> {
        let root = &self.roots[r.root as usize];
        if r.node == u32::MAX {
            return InodeView { superblock: root.superblock, mountpoint: &root.mountpoint, inode: root.root_inode, path: std::borrow::Cow::Borrowed(&root.mountpoint) };
        }
        let c = &self.forest.dirs[r.node as usize].children[r.child as usize];
        let parent = &self.dirs[r.dir as usize];
        let dest = match (&c.mode, &c.symlink) {
            (Ok(m), Some(Ok(Some(dest)))) if self.follow_symlinks && m & S_IFMT == S_IFLNK => Some(dest.as_str()),
            _ => None,
        };
        let mut path = String::with_capacity(parent.len() + 1 + c.name.len() + dest.map_or(0, |d| d.len() + 4));
        path.push_str(parent);
        path.push('/');
        path.push_str(&c.name);
        if let Some(dest) = dest {
            path.push_str(" -> ");
            path.push_str(dest);
        }
        InodeView { superblock: root.superblock, mountpoint: &root.mountpoint, inode: c.inode, path: std::borrow::Cow::Owned(path) }
    }
}

/// A superblock root that passed python's checks (`s_root`, `is_root()`, readable + valid
/// root inode).
struct SbRoot {
    superblock: Obj,
    mountpoint: Arc<str>,
    parent_dir: String,
    root_dentry: Obj,
    root_inode_ptr: u64,
    root_inode: Obj,
    /// `root_inode.i_mapping and root_inode.i_mapping.is_readable()`
    mapping_ok: bool,
}

/// python's per-superblock root checks in `get_inodes` (`Ok(None)` = python `continue`).
fn sb_root(w: &WalkFields, superblock: Obj, mountpoint: String) -> Result<Option<SbRoot>> {
    let mountpoint: Arc<str> = mountpoint.into();
    let parent_dir = if &*mountpoint == "/" { String::new() } else { mountpoint.to_string() };
    let root_dentry_ptr = superblock.m("s_root")?;
    if root_dentry_ptr.u64()? == 0 {
        return Ok(None);
    }
    let root_dentry = root_dentry_ptr.deref()?;
    if !root_dentry.is_root()? {
        return Ok(None);
    }
    let root_inode_ptr = root_dentry.f(&w.d_inode);
    if !ptr_ok(&root_inode_ptr)? {
        return Ok(None);
    }
    let root_inode = root_inode_ptr.deref()?;
    if !w.inode_valid(&root_inode)? {
        return Ok(None);
    }
    let mapping_ok = ptr_ok(&root_inode.f(&w.i_mapping))?;
    Ok(Some(SbRoot { superblock, mountpoint, parent_dir, root_dentry, root_inode_ptr: root_inode_ptr.u64()?, root_inode, mapping_ok }))
}

/// Cloning an [`Error`] computed once and surfaced where python raises.
trait CloneErr {
    fn clone_err(&self) -> Error;
}

impl CloneErr for Error {
    fn clone_err(&self) -> Error {
        match self {
            Error::InvalidAddress { addr } => Error::InvalidAddress { addr: *addr },
            Error::Swapped { addr } => Error::Swapped { addr: *addr },
            Error::Symbol(s) => Error::Symbol(s.clone()),
            Error::Unsatisfied(s) => Error::Unsatisfied(s.clone()),
            Error::Layer(s) => Error::Layer(s.clone()),
            Error::Io(e) => Error::Msg(e.to_string()),
            Error::Msg(s) => Error::Msg(s.clone()),
        }
    }
}

/// One child of a directory as python's `_walk_dentry` + `get_inodes` would process it,
/// computed ahead of time (reads have no side effects; errors are kept and surfaced only
/// where python raises).
struct ChildInfo {
    dentry: Obj,
    /// python `continue`s before the yield (no readable/valid inode, NULL name pointer)
    skip: bool,
    name: String,
    inode_ptr: u64,
    inode: Obj,
    /// `inode.i_mode` (python reads it for `is_dir` after the consumer ran)
    mode: Result<i128>,
    /// `get_inodes`: `file_inode.i_mapping and file_inode.i_mapping.is_readable()`
    mapping_ok: Result<bool>,
    /// `_follow_symlink`'s target (only computed when following symlinks and it is a link)
    symlink: Option<Result<Option<String>>>,
    /// index of this child's [`DirNode`] when it is a directory
    dir: Option<usize>,
}

impl ChildInfo {
    fn skipped(dentry: Obj) -> ChildInfo {
        ChildInfo { dentry, skip: true, name: String::new(), inode_ptr: 0, inode: dentry, mode: Ok(0), mapping_ok: Ok(false), symlink: None, dir: None }
    }
}

/// A directory's children in list order; `err` = python raised after these children (while
/// listing the directory or processing the next child).
struct DirNode {
    children: Vec<ChildInfo>,
    err: Option<Error>,
}

/// Every superblock's dentry tree, listed in parallel: the first `starts.len()` nodes are
/// the roots, in order.
struct DentryForest {
    dirs: Vec<DirNode>,
}

impl DentryForest {
    /// Lists all directories reachable from `starts` on all cores: every directory is a work
    /// item on a shared queue served by long-lived workers (dentry trees are lopsided, e.g.
    /// `/usr` or `/sys` hold most dentries; the workers keep their page-translation caches
    /// warm). `None` when a dentry is reached twice or equals its parent: python's `seen` set
    /// would then change the walk.
    fn build(w: &WalkFields, starts: &[Obj], follow_symlinks: bool) -> Option<DentryForest> {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::{Condvar, Mutex};
        const SHARDS: usize = 64;
        struct Queue {
            tasks: Vec<(usize, Obj)>,
            busy: usize,
        }
        let queue = Mutex::new(Queue { tasks: starts.iter().enumerate().map(|(i, d)| (i, *d)).rev().collect(), busy: 0 });
        let cv = Condvar::new();
        let next_id = AtomicUsize::new(starts.len());
        let abort = AtomicBool::new(false);
        let seen: Vec<Mutex<FxHashSet<u64>>> = (0..SHARDS).map(|_| Mutex::new(FxHashSet::default())).collect();
        let first_seen = |a: u64| seen[((a >> 6) as usize ^ (a >> 17) as usize) % SHARDS].lock().unwrap().insert(a);
        let worker = || -> Vec<(usize, Obj, Vec<ChildInfo>, Option<Error>)> {
            let mut done = Vec::new();
            loop {
                let (id, dentry) = {
                    let mut q = queue.lock().unwrap();
                    loop {
                        if abort.load(Ordering::Relaxed) {
                            return done;
                        }
                        if let Some(t) = q.tasks.pop() {
                            q.busy += 1;
                            break t;
                        }
                        if q.busy == 0 {
                            cv.notify_all();
                            return done;
                        }
                        q = cv.wait(q).unwrap();
                    }
                };
                let (mut children, err) = list_dir(w, dentry, follow_symlinks);
                let mut new_tasks = Vec::new();
                for c in &mut children {
                    if c.dentry.addr == dentry.addr || !first_seen(c.dentry.addr) {
                        abort.store(true, Ordering::Relaxed);
                    }
                    if !c.skip && matches!(c.mode, Ok(m) if m & S_IFMT == S_IFDIR) {
                        let nid = next_id.fetch_add(1, Ordering::Relaxed);
                        c.dir = Some(nid);
                        new_tasks.push((nid, c.dentry));
                    }
                }
                done.push((id, dentry, children, err));
                let k = new_tasks.len();
                let mut q = queue.lock().unwrap();
                q.busy -= 1;
                // depth-first-ish: newest subdirectories first keeps the queue short
                q.tasks.extend(new_tasks.into_iter().rev());
                let finished = q.tasks.is_empty() && q.busy == 0;
                drop(q);
                if finished || abort.load(Ordering::Relaxed) {
                    cv.notify_all();
                } else {
                    for _ in 0..k {
                        cv.notify_one();
                    }
                }
            }
        };
        let threads = crate::util::par::threads().max(1);
        let parts: Vec<Vec<(usize, Obj, Vec<ChildInfo>, Option<Error>)>> = if threads == 1 {
            vec![worker()]
        } else {
            std::thread::scope(|sc| {
                let hs: Vec<_> = (0..threads).map(|_| sc.spawn(&worker)).collect();
                hs.into_iter().map(|h| h.join().expect("dentry listing worker panicked")).collect()
            })
        };
        if abort.load(Ordering::Relaxed) {
            return None;
        }
        let n = next_id.load(Ordering::Relaxed);
        let mut slots: Vec<Option<DirNode>> = (0..n).map(|_| None).collect();
        for (id, _dentry, children, err) in parts.into_iter().flatten() {
            slots[id] = Some(DirNode { children, err });
        }
        let dirs: Option<Vec<DirNode>> = slots.into_iter().collect();
        Some(DentryForest { dirs: dirs? })
    }

    /// Number of children of all directories.
    fn children(&self) -> usize {
        self.dirs.iter().map(|d| d.children.len()).sum()
    }
}

/// Lists one directory like python's `_walk_dentry` loop body (minus the `seen` set, which
/// the forest checks): `(children, error)`.
fn list_dir(w: &WalkFields, dir: Obj, follow_symlinks: bool) -> (Vec<ChildInfo>, Option<Error>) {
    let mut out = Vec::new();
    for next in dir.get_subdirs() {
        let dentry = match next {
            Ok(d) => d,
            Err(e) => return (out, Some(e)),
        };
        match child_info(w, dentry, follow_symlinks) {
            Ok(c) => out.push(c),
            Err(e) => {
                // python raised while processing this child (after adding it to `seen`)
                out.push(ChildInfo::skipped(dentry));
                return (out, Some(e));
            }
        }
    }
    (out, None)
}

/// python's per-child steps of `_walk_dentry` (up to the yield) plus what `get_inodes` reads.
fn child_info(w: &WalkFields, dentry: Obj, follow_symlinks: bool) -> Result<ChildInfo> {
    let inode_ptr = dentry.f(&w.d_inode);
    if !ptr_ok(&inode_ptr)? {
        return Ok(ChildInfo::skipped(dentry));
    }
    let inode = inode_ptr.deref()?;
    if !w.inode_valid(&inode)? {
        return Ok(ChildInfo::skipped(dentry));
    }
    let d_name = dentry.f(&w.d_name);
    if d_name.f(&w.q_name).u64()? == 0 {
        return Ok(ChildInfo::skipped(dentry));
    }
    let name = d_name.name_as_str()?;
    let mode = inode.f(&w.i_mode).int();
    let mapping_ok = ptr_ok(&inode.f(&w.i_mapping));
    let symlink = match &mode {
        Ok(m) if follow_symlinks && m & S_IFMT == S_IFLNK => Some(symlink_dest(&inode_ptr)),
        _ => None,
    };
    Ok(ChildInfo { dentry, skip: false, name, inode_ptr: inode_ptr.u64()?, inode, mode, mapping_ok, symlink, dir: None })
}

/// The sequential [`get_inodes`] (exact python semantics for any dentry graph), used when the
/// parallel listing finds a dentry twice.
fn get_inodes_seq(w: &WalkFields, roots: Vec<Result<Option<SbRoot>>>, follow_symlinks: bool, f: &mut dyn FnMut(InodeInternal) -> Result<bool>) -> Result<()> {
    let mut seen_inodes = FxHashSet::default();
    let mut seen_dentries = FxHashSet::default();
    for r in roots {
        let Some(root) = r? else { continue };
        if !root.mapping_ok {
            continue;
        }
        if !seen_inodes.insert(root.root_inode_ptr) {
            continue;
        }
        if !f(InodeInternal { superblock: root.superblock, mountpoint: root.mountpoint.clone(), inode: root.root_inode, path: root.mountpoint.to_string() })? {
            return Ok(());
        }
        let superblock = root.superblock;
        let mountpoint = root.mountpoint.clone();
        let cont = walk_dentry(w, &mut seen_dentries, root.root_dentry, &root.parent_dir, &mut |file_path, _file_dentry, file_inode_ptr, file_inode| {
            // python re-checks `d_inode` readable + `is_valid()` here: same memory, same result
            if !ptr_ok(&file_inode.f(&w.i_mapping))? {
                return Ok(true);
            }
            if !seen_inodes.insert(file_inode_ptr.u64()?) {
                return Ok(true);
            }
            let path = if follow_symlinks && file_inode.f(&w.i_mode).int()? & S_IFMT == S_IFLNK { follow_symlink(file_inode_ptr, file_path)? } else { file_path };
            f(InodeInternal { superblock, mountpoint: mountpoint.clone(), inode: file_inode, path })
        })?;
        if !cont {
            return Ok(());
        }
    }
    Ok(())
}

/// [`get_inodes`] collected into a Vec; the `Err` (if any) is where python raised, after
/// yielding the returned inodes.
pub fn collect_inodes(k: &LinuxKernel, follow_symlinks: bool) -> (Vec<InodeInternal>, Option<Error>) {
    let mut v = Vec::new();
    let r = get_inodes(k, follow_symlinks, &mut |i| {
        v.push(i);
        Ok(true)
    });
    (v, r.err())
}

/// python `InodeInternal.to_user(kernel_layer)` formatted by `Files.format_fields_with_headers`:
/// the 14 `Files` columns. `Err` where python raises.
pub fn inode_user_row(ii: &InodeInternal, page_size: u64) -> Result<Vec<Value>> {
    let v = InodeView { superblock: ii.superblock, mountpoint: &ii.mountpoint, inode: ii.inode, path: std::borrow::Cow::Borrowed(&ii.path) };
    inode_user_values(v, page_size).map(Vec::from)
}

/// [`inode_user_row`] of an [`InodeView`], as an array (no `Vec` per row).
pub fn inode_user_values(ii: InodeView, page_size: u64) -> Result<[Value; 14]> {
    let sb = &ii.superblock;
    let i = &ii.inode;
    let device = format!("{}:{}", sb.major()?, sb.minor()?);
    let inode_num = i.m("i_ino")?.int()?;
    let inode_type = i.get_inode_type()?.map_or(Value::Unparsable, Value::SStr);
    let i_size = i.m("i_size")?.int()?;
    // int(math.ceil(self.inode.i_size / float(kernel_layer.page_size)))
    let inode_pages = (i_size as f64 / page_size as f64).ceil() as i128;
    let cached_pages = i.m("i_mapping")?.m("nrpages")?.int()?;
    let file_mode = i.get_file_mode()?;
    let atime = i.get_access_time()?;
    let mtime = i.get_modification_time()?;
    let ctime = i.get_change_time()?;
    Ok([
        Value::Int(sb.addr as i128),
        Value::Str(ii.mountpoint.to_string()),
        Value::Str(device),
        Value::Int(inode_num),
        Value::Int(i.addr as i128),
        inode_type,
        Value::Int(inode_pages),
        Value::Int(cached_pages),
        Value::Str(file_mode),
        atime,
        mtime,
        ctime,
        Value::Str(ii.path.into_owned()),
        Value::Int(i_size),
    ])
}

fn files_columns() -> Vec<Column> {
    vec![
        Column::new("SuperblockAddr", ColType::Hex),
        Column::new("MountPoint", ColType::Str),
        Column::new("Device", ColType::Str),
        Column::new("InodeNum", ColType::Int),
        Column::new("InodeAddr", ColType::Hex),
        Column::new("FileType", ColType::Str),
        Column::new("InodePages", ColType::Int),
        Column::new("CachedPages", ColType::Int),
        Column::new("FileMode", ColType::Str),
        Column::new("AccessTime", ColType::DateTime),
        Column::new("ModificationTime", ColType::DateTime),
        Column::new("ChangeTime", ColType::DateTime),
        Column::new("FilePath", ColType::Str),
        Column::new("InodeSize", ColType::Int),
    ]
}

fn page_size(k: &LinuxKernel) -> u64 {
    k.layer.page_size()
}

/// Per-inode results computed in parallel, consumed in python's order.
fn par_rows<T: Send>(inodes: &[InodeInternal], f: impl Fn(&InodeInternal) -> Result<Option<T>> + Sync) -> Vec<Result<Option<T>>> {
    crate::util::par::par_map(inodes.len(), |i| f(&inodes[i]))
}

impl Plugin for Files {
    fn name(&self) -> &'static str {
        "linux.pagecache.Files"
    }
    fn description(&self) -> &'static str {
        "Lists files from memory"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("type", "List of space-separated file type filters i.e. --type REG DIR", ReqKind::ListStr).optional(),
            Requirement::new("find", "Filename (full path) to find", ReqKind::Str).optional(),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(files_columns())?;
        let k = ctx.linux_kernel()?;
        let ps = page_size(k);
        let types = cfg.get_strs("type");
        let find = cfg.get_str("find").filter(|s| !s.is_empty()).map(str::to_string);
        let type_ok = |inode: &Obj| -> Result<bool> {
            if types.is_empty() {
                return Ok(true);
            }
            // `get_inode_type() not in types_filter` (None is never in a list of str)
            Ok(inode.get_inode_type()?.is_some_and(|t| types.iter().any(|x| x == t)))
        };
        if let Some(find) = find {
            // python breaks at the first match: stream and stop there
            let mut found = None;
            get_inodes(k, true, &mut |ii| {
                if !type_ok(&ii.inode)? {
                    return Ok(true);
                }
                if ii.path == find {
                    found = Some(inode_user_row(&ii, ps)?);
                    return Ok(false);
                }
                Ok(true)
            })?;
            if let Some(row) = found {
                out.row(0, row)?;
            }
            return Ok(());
        }
        let (inodes, tail) = {
            let _s = crate::util::trace::span("pagecache: get_inodes walk");
            collect_inode_list(k, true)
        };
        {
            // rows built (paths too) and formatted on all cores, in python's order
            let _s = crate::util::trace::span("pagecache: to_user rows + render");
            super::stream_chunks(out, inodes.len(), 128, |r, b| {
                for i in r {
                    let ii = inodes.view(i);
                    match type_ok(&ii.inode).and_then(|ok| if ok { inode_user_values(ii, ps).map(Some) } else { Ok(None) }) {
                        Ok(Some(row)) => b.push_ref(&row),
                        Ok(None) => {}
                        Err(e) => return Some(e),
                    }
                }
                None
            })?;
        }
        tail.map_or(Ok(()), Err)
    }
    fn timeline_events(&self, ctx: &Context, _cfg: &Config) -> Option<(Vec<TimelineEvent>, Option<Error>)> {
        let mut ev = Vec::new();
        let r = (|| -> Result<()> {
            let k = ctx.linux_kernel()?;
            let ps = page_size(k);
            let (inodes, tail) = collect_inodes(k, true);
            let rows = par_rows(&inodes, |ii| inode_user_row(ii, ps).map(Some));
            for (ii, r) in inodes.iter().zip(rows) {
                let mut row = r?.unwrap();
                let description = format!("Cached Inode for {}", ii.path);
                let ctime = row.pop().map(|_| row.remove(11)).unwrap();
                let mtime = row.remove(10);
                let atime = row.remove(9);
                ev.push(TimelineEvent { description: description.clone(), kind: TimeKind::Accessed, time: atime });
                ev.push(TimelineEvent { description: description.clone(), kind: TimeKind::Modified, time: mtime });
                ev.push(TimelineEvent { description, kind: TimeKind::Changed, time: ctime });
            }
            tail.map_or(Ok(()), Err)
        })();
        Some((ev, r.err()))
    }
}

/// One write python's `write_inode_content_to_stream` performs: `len` bytes of the page at
/// physical address `paddr` written at file offset `offset`.
#[derive(Clone, Copy, Debug)]
pub struct PageWrite {
    pub offset: u64,
    pub paddr: u64,
    pub len: u64,
}

/// python `InodePages.write_inode_content_to_stream(context, layer, inode, stream)` without the
/// stream: the page writes in python's order (`inode.get_contents()`, bounds-checked against
/// `i_size`). A `LinuxPageCacheException` ends the list like python's `except`; other errors
/// are returned (python raises). `inode` must be a regular file (callers check `is_reg`).
pub fn inode_page_writes(inode: &Obj, page_size: u64) -> Result<Vec<PageWrite>> {
    let i = tgt(inode)?;
    let inode_size = i.m("i_size")?.int()?;
    let i_mapping = i.m("i_mapping")?.u64()?;
    let phys: &dyn Layer = match i.layer().as_intel() {
        Some(l) => l.phys().as_ref(),
        None => i.layer(),
    };
    let mut out = Vec::new();
    for p in i.get_pages() {
        let page = match p {
            Ok(p) => p,
            Err(e) if is_page_cache_exception(&e) => break,
            Err(e) => return Err(e),
        };
        // inode.get_contents()
        if page.m("mapping")?.u64()? != i_mapping {
            continue;
        }
        let page_index = page.m("index")?.u64()? as i128;
        let paddr = page.to_paddr()?;
        if paddr == 0 || paddr < 0 || !phys.is_valid(paddr as u64, page_size) {
            continue;
        }
        let current_fp = page_index * page_size as i128;
        let max_length = inode_size - current_fp;
        let len = max_length.min(page_size as i128);
        if current_fp >= inode_size || current_fp + len > inode_size || len < 0 {
            continue;
        }
        out.push(PageWrite { offset: current_fp as u64, paddr: paddr as u64, len: len as u64 });
    }
    Ok(out)
}

/// Physical layer the page contents are read from (python `page.get_content()`).
fn page_phys(k: &LinuxKernel) -> &'static dyn Layer {
    k.layer.phys().as_ref()
}

/// Reads the page content of a write (python `page.get_content()[:len]`).
fn read_page(phys: &dyn Layer, w: &PageWrite, buf: &mut [u8]) -> Result<()> {
    phys.read(w.paddr, &mut buf[..w.len as usize])
}

impl Plugin for InodePages {
    fn name(&self) -> &'static str {
        "linux.pagecache.InodePages"
    }
    fn description(&self) -> &'static str {
        "Lists and recovers cached inode pages"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("find", "Filename (full path) to find ", ReqKind::Str).optional(),
            Requirement::new("inode", "Inode address", ReqKind::Int).optional(),
            Requirement::flag("dump", "Extract inode content"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PageVAddr", ColType::Hex),
            Column::new("PagePAddr", ColType::Hex),
            Column::new("MappingAddr", ColType::Hex),
            Column::new("Index", ColType::Int),
            Column::new("DumpSafe", ColType::Bool),
            Column::new("Flags", ColType::Str),
            Column::new("Output File", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        let ps = page_size(k);
        let find = cfg.get_str("find").filter(|s| !s.is_empty()).map(str::to_string);
        let inode_addr = cfg.get_int("inode").filter(|v| *v != 0);
        if inode_addr.is_some() && find.is_some() {
            eprintln!("ERROR    volatility3.plugins.linux.pagecache: Cannot use --inode and --find simultaneously");
            return Ok(());
        }
        let inode = if let Some(find) = find {
            let mut found = None;
            get_inodes(k, true, &mut |ii| {
                if ii.path == find {
                    found = Some(ii.inode);
                    return Ok(false);
                }
                Ok(true)
            })?;
            match found {
                Some(i) => i,
                None => {
                    eprintln!("ERROR    volatility3.plugins.linux.pagecache: Unable to find inode with path {find}");
                    return Ok(());
                }
            }
        } else if let Some(a) = inode_addr {
            k.object_abs("inode", a as u64)?
        } else {
            eprintln!("ERROR    volatility3.plugins.linux.pagecache: You must use either --inode or --find");
            return Ok(());
        };
        if !inode_valid(&inode)? {
            eprintln!("ERROR    volatility3.plugins.linux.pagecache: Invalid inode at {:#x}", inode.addr);
            return Ok(());
        }
        if !inode.is_reg()? {
            eprintln!("ERROR    volatility3.plugins.linux.pagecache: The inode is not a regular file");
            return Ok(());
        }
        let mut filename = Value::NotApplicable;
        if cfg.get_bool("dump") {
            let name = crate::plugins::windows::pslist::sanitize_filename(&format!("inode_0x{:x}.dmp", inode.addr));
            write_inode_content_to_file(ctx, k, &inode, &name, ps)?;
            filename = Value::Str(name);
        }
        // _generate_inode_fields
        let inode_size = inode.m("i_size")?.int()?;
        let i_mapping = inode.m("i_mapping")?.u64()?;
        for p in inode.get_pages() {
            let page = match p {
                Ok(p) => p,
                Err(e) if is_page_cache_exception(&e) => break,
                Err(e) => return Err(e),
            };
            let mapping = page.m("mapping")?;
            if mapping.u64()? != i_mapping {
                continue;
            }
            let paddr = page.to_paddr()?;
            let index = page.m("index")?.int()?;
            let file_offset = index * ps as i128;
            let dump_safe = file_offset < inode_size && mapping.u64()? != 0 && mapping.is_readable();
            let flags: Vec<&str> = page.get_flags_list()?.into_iter().map(|x| x.strip_prefix("PG_").unwrap_or(x)).collect();
            let flags = flags.join(",");
            out.row(0, vec![Value::Int(page.addr as i128), Value::Int(paddr), Value::Int(mapping.u64()? as i128), Value::Int(index), Value::Bool(dump_safe), Value::Str(flags), filename.clone()])?;
        }
        Ok(())
    }
}

/// python `InodePages.write_inode_content_to_file(...)` with python's `CLIDirectFileHandler`
/// semantics: the file is always created; on the first page it is extended (sparse) to
/// `i_size`, then each page is written at its offset.
fn write_inode_content_to_file(ctx: &Context, k: &LinuxKernel, inode: &Obj, name: &str, ps: u64) -> Result<()> {
    use std::os::unix::fs::FileExt;
    let (file, _final_name) = ctx.create_output_file(name)?;
    let inode_size = inode.m("i_size")?.int()?;
    let writes = inode_page_writes(inode, ps)?;
    let phys = page_phys(k);
    let mut buf = vec![0u8; ps as usize];
    let mut initialized = false;
    for w in &writes {
        read_page(phys, w, &mut buf)?;
        if !initialized {
            file.set_len(inode_size.max(0) as u64)?;
            initialized = true;
        }
        file.write_all_at(&buf[..w.len as usize], w.offset)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------- RecoverFs

/// A compressed output stream (python's `tarfile.open(mode="w:gz"|"w:bz2"|"w:xz")` layer).
trait FinishWrite: Write + Send {
    fn finish(self: Box<Self>) -> std::io::Result<()>;
}

impl<W: Write + Send> FinishWrite for crate::codecs::xz_enc::XzEncoder<W> {
    fn finish(self: Box<Self>) -> std::io::Result<()> {
        (*self).finish()?.flush()
    }
}

impl<W: Write + Send> FinishWrite for crate::codecs::bzip2_enc::Bzip2Encoder<W> {
    fn finish(self: Box<Self>) -> std::io::Result<()> {
        (*self).finish()?.flush()
    }
}

impl<W: Write + Send> FinishWrite for crate::codecs::gzip_enc::GzipEncoder<W> {
    fn finish(self: Box<Self>) -> std::io::Result<()> {
        (*self).finish()?.flush()
    }
}

/// Our deflate level for the `.tar.gz`. python uses zlib level 9; the tarball bytes differ from
/// python's anyway (the member mtimes and the gzip MTIME are the time of the run), only the
/// tar members must match. Level 1 is the single-probe fast finder: half the CPU of level 4
/// for ~8% more output (noble ELF image: 3.8 GB tar -> 905 MB; level 4: 837 MB; python's zlib
/// -9: 842 MB), and the run is bound by compression CPU, then by writeback of the output.
/// The gzip header stays python's (XFL = 2).
const GZ_LEVEL: u32 = 1;

/// python `tarfile.open(fileobj=..., mode=f"w:{format}")`: gzip (`GzipFile(compresslevel=9)`,
/// header MTIME `int(time.time())`), bzip2 (`BZ2File(compresslevel=9)`) or xz
/// (`LZMAFile(preset=None)` = preset 6, CRC64).
fn open_compressor(format: &str, file: std::fs::File, mtime: u32) -> Result<Box<dyn FinishWrite>> {
    // the file writes run on their own thread: when the kernel throttles them (dirty-page
    // writeback), the compressor keeps going
    let w = crate::util::bgwrite::ThreadWriter::new(file, 1 << 20, 16);
    match format {
        "gz" => {
            let mut opts = crate::codecs::gzip_enc::GzipOptions::python(9, mtime);
            opts.level = GZ_LEVEL;
            Ok(Box::new(crate::codecs::gzip_enc::GzipEncoder::new(w, opts)))
        }
        // python `bz2.BZ2File(fileobj, "w", compresslevel=9)`
        "bz2" => Ok(Box::new(crate::codecs::bzip2_enc::Bzip2Encoder::new(w, 9))),
        // python `lzma.LZMAFile(fileobj, "w", preset=None)` (preset 6, CRC64 check)
        "xz" => Ok(Box::new(crate::codecs::xz_enc::XzEncoder::new(w, 6))),
        other => Err(Error::msg(format!("ValueError: unknown compression format {other:?}"))),
    }
}

/// python `PurePath(symlink_source.lstrip("/")).parent.parts` length.
fn parent_depth(source: &str) -> usize {
    let n = source.trim_start_matches('/').split('/').filter(|p| !p.is_empty() && *p != ".").count();
    n.saturating_sub(1)
}

/// python `RecoverFs._tar_add_lnk` link name patching: absolute targets become relative to the
/// symlink's directory (`../..` + target), so they never reference the analyst's filesystem.
pub fn relative_symlink_dest(symlink_source: &str, symlink_dest: &str) -> Result<String> {
    if !symlink_dest.starts_with('/') {
        return Ok(symlink_dest.to_string());
    }
    // PurePosixPath: exactly two leading slashes are a distinct root ("//"), which is not
    // relative to "/" (python raises ValueError)
    if symlink_dest.starts_with("//") && !symlink_dest.starts_with("///") {
        return Err(Error::msg(format!("ValueError: '{symlink_dest}' is not in the subpath of '/'")));
    }
    let mut parts: Vec<&str> = vec![".."; parent_depth(symlink_source)];
    parts.extend(symlink_dest.split('/').filter(|p| !p.is_empty() && *p != "."));
    Ok(if parts.is_empty() { ".".to_string() } else { parts.join("/") })
}

/// python `time.time()`.
fn py_time() -> f64 {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    // CPython: _PyTime_AsSecondsDouble(ns) = ns / 1e9 (as a double)
    d.as_nanos() as f64 / 1e9
}

impl Plugin for RecoverFs {
    fn name(&self) -> &'static str {
        "linux.pagecache.RecoverFs"
    }
    fn description(&self) -> &'static str {
        "Recovers the cached filesystem (directories, files, symlinks) into a compressed tarball."
    }
    fn epilog(&self) -> Option<&'static str> {
        Some(
            "Details: level 0 directories are named after the UUID of the parent superblock; metadata aren't replicated to extracted objects; objects modification time is set to the plugin run time; absolute symlinks\n    are converted to relative symlinks to prevent referencing the analyst's filesystem.\n    Troubleshooting: to fix extraction errors related to long paths, please consider using https://github.com/mxmlnkn/ratarmount.",
        )
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::flag("tmpfs_only", "Extracts only files from tmpfs file systems"),
            Requirement::new("compression_format", "Compression format (default: gz)", ReqKind::Choice(vec!["gz", "bz2", "xz"]))
                .optional()
                .default(ConfigValue::Str("gz".into())),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let mut cols = files_columns();
        cols.push(Column::new("Recovered FileSize", ColType::Int));
        out.begin(cols)?;
        let k = ctx.linux_kernel()?;
        let ps = page_size(k);
        let format = cfg.get_str("compression_format").unwrap_or("gz").to_string();
        let tmpfs_only = cfg.get_bool("tmpfs_only");
        recover_fs(ctx, k, ps, &format, tmpfs_only, out)
    }
}

/// What the sequential tar pass needs per inode, computed in parallel beforehand.
struct Prep {
    kind: Kind,
    /// REG: the page writes (`Err`: python raised in `write_inode_content_to_stream`)
    writes: Option<Result<Vec<PageWrite>>>,
    /// the `Files` row (python `to_user`), computed eagerly; only used when python reaches it
    row: Result<Vec<Value>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Reg,
    Dir,
    Lnk,
    Other,
}

fn inode_kind(i: &Obj) -> Result<Kind> {
    // python: `is_reg or is_dir or is_link` then `if is_reg / elif is_dir / elif is_link`
    Ok(if i.is_reg()? {
        Kind::Reg
    } else if i.is_dir()? {
        Kind::Dir
    } else if i.is_link()? {
        Kind::Lnk
    } else {
        Kind::Other
    })
}

fn recover_fs(ctx: &Context, k: &LinuxKernel, ps: u64, format: &str, tmpfs_only: bool, out: &mut dyn RowSink) -> Result<()> {
    // tarfile.open(...) -> GzipFile header mtime; then `mtime = time.time()`
    let mtime = py_time();
    let uuid_as_prefix = k.table.user_type("super_block").is_some_and(|u| k.table.member(u, "s_uuid").is_some());
    let walk_span = crate::util::trace::span("recoverfs: get_inodes walk");
    let (inodes, tail) = collect_inodes(k, false);
    drop(walk_span);
    let prep_span = crate::util::trace::span("recoverfs: prep (page lists, rows)");
    // superblock types (python `superblock.get_type()`, evaluated per inode; same result for
    // every inode of a superblock), used to skip work python never reaches
    let mut sb_types: crate::util::FxHashMap<u64, Option<Option<String>>> = Default::default();
    for ii in &inodes {
        sb_types.entry(ii.superblock.addr).or_insert_with(|| ii.superblock.sb_get_type().ok());
    }
    let needed = |ii: &InodeInternal| -> bool {
        if !ii.path.starts_with('/') {
            return false;
        }
        match sb_types.get(&ii.superblock.addr) {
            // python raises at `get_type()` first
            Some(None) | None => false,
            Some(Some(t)) => t.as_deref().is_some_and(|t| !t.is_empty() && (!tmpfs_only || t == "tmpfs")),
        }
    };
    let preps: Vec<Result<Prep>> = crate::util::par::par_map(inodes.len(), |idx| {
        let ii = &inodes[idx];
        let kind = inode_kind(&ii.inode)?;
        if kind == Kind::Other || !needed(ii) {
            return Ok(Prep { kind, writes: None, row: Err(Error::msg("not needed")) });
        }
        let writes = if kind == Kind::Reg { Some(inode_page_writes(&ii.inode, ps)) } else { None };
        let row = inode_user_row(ii, ps);
        Ok(Prep { kind, writes, row })
    });

    // the tarball goes to a temporary file in the output directory; python only writes the
    // file once the whole generator finished, so it is committed at the very end
    let tmp_path = {
        let dir = ctx.opts.output_dir.as_str();
        let dir = if dir.is_empty() { "." } else { dir };
        std::fs::create_dir_all(dir)?;
        format!("{dir}/tmp_fastvol_recoverfs_{}.vol3", std::process::id())
    };
    // python's file handler writes a mkstemp file (mode 0o600) that it renames into place
    let tmp_file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(crate::cli::files::OUTPUT_FILE_MODE).open(&tmp_path)?
    };
    drop(prep_span);
    let tar_span = crate::util::trace::span("recoverfs: tar + compress");
    let result = (|| -> Result<()> {
        let comp = open_compressor(format, tmp_file, mtime as u32)?;
        let mut tar = crate::util::pytar::PyTarWriter::new(comp, mtime);
        let phys = page_phys(k);
        let mut visited: FxHashSet<String> = FxHashSet::default();
        let mut sb_cache: crate::util::FxHashMap<u64, (Option<String>, String)> = Default::default();
        let mut buf = vec![0u8; ps as usize];
        for (ii, prep) in inodes.iter().zip(preps) {
            let prep = prep?;
            if prep.kind == Kind::Other {
                continue;
            }
            if !ii.path.starts_with('/') {
                continue;
            }
            let sb = ii.superblock;
            let (sb_type, prefix) = match sb_cache.get(&sb.addr) {
                Some(v) => v.clone(),
                None => {
                    let t = sb.sb_get_type()?;
                    let v = (t, String::new());
                    sb_cache.insert(sb.addr, v.clone());
                    v
                }
            };
            let Some(sb_type) = sb_type.filter(|t| !t.is_empty()) else { continue };
            if tmpfs_only && sb_type != "tmpfs" {
                continue;
            }
            let prefix = if !prefix.is_empty() {
                prefix
            } else {
                let p = if uuid_as_prefix { format!("/{}", sb.uuid()?) } else { format!("/{}:{}", sb.major()?, sb.minor()?) };
                sb_cache.get_mut(&sb.addr).unwrap().1 = p.clone();
                p
            };
            let prefixed_path = format!("{prefix}{}", ii.path);
            // python: `visited_paths = seen_prefixes = set()` (one set)
            if visited.contains(&prefixed_path) {
                continue;
            } else if !visited.contains(&prefix) {
                tar.add_dir(&prefix)?;
                visited.insert(prefix.clone());
            }
            visited.insert(prefixed_path.clone());
            let mut extracted = Value::NotApplicable;
            let mut path = ii.path.clone();
            match prep.kind {
                Kind::Reg => {
                    let writes = prep.writes.unwrap()?;
                    // io.BytesIO semantics: truncate() never extends; the buffer ends at the
                    // end of the furthest write, gaps are zero-filled, later writes win
                    let size = writes.iter().map(|w| w.offset + w.len).max().unwrap_or(0);
                    tar.begin_file(&format!("{prefix}{}", ii.path), size)?;
                    let ascending = writes.windows(2).all(|p| p[0].offset + p[0].len <= p[1].offset);
                    if ascending {
                        let mut pos = 0u64;
                        for w in &writes {
                            tar.write_zeros(w.offset - pos)?;
                            read_page(phys, w, &mut buf)?;
                            tar.write_content(&buf[..w.len as usize])?;
                            pos = w.offset + w.len;
                        }
                    } else {
                        let mut content = vec![0u8; size as usize];
                        for w in &writes {
                            read_page(phys, w, &mut buf)?;
                            content[w.offset as usize..(w.offset + w.len) as usize].copy_from_slice(&buf[..w.len as usize]);
                        }
                        tar.write_content(&content)?;
                    }
                    extracted = Value::Int(size as i128);
                }
                Kind::Dir => tar.add_dir(&prefixed_path)?,
                Kind::Lnk => {
                    let Some(dest) = symlink_dest(&ii.inode)? else { continue };
                    tar.add_symlink(&format!("{prefix}{}", ii.path), &relative_symlink_dest(&ii.path, &dest)?)?;
                    path = format!("{} -> {dest}", ii.path);
                }
                Kind::Other => unreachable!(),
            }
            let mut row = prep.row?;
            row[12] = Value::Str(path);
            row.push(extracted);
            out.row(0, row)?;
        }
        if let Some(e) = tail {
            return Err(e);
        }
        let comp = tar.close()?;
        comp.finish()?;
        Ok(())
    })();
    drop(tar_span);
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    let (_f, final_name) = ctx.create_output_file(&format!("recovered_fs.tar.{format}"))?;
    let final_path = {
        let dir = ctx.opts.output_dir.as_str();
        if dir.is_empty() { final_name } else { format!("{dir}/{final_name}") }
    };
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::relative_symlink_dest;

    #[test]
    fn symlink_dest_like_python_purepath() {
        // expected values from python 3.14 pathlib (RecoverFs._tar_add_lnk)
        let cases = [
            ("/sys/kernel/security/evm", "/integrity/evm/evm", "../../../integrity/evm/evm"),
            ("/a", "/b", "b"),
            ("/a/b/c", "/", "../.."),
            ("/a/b", "/c/./d/", "../c/d"),
            ("/a/b", "///c", "../c"),
            ("/a//b/c", "/d/../e", "../../d/../e"),
            ("/", "/", "."),
            ("/a/b", "rel/x", "rel/x"),
        ];
        for (src, dst, exp) in cases {
            assert_eq!(relative_symlink_dest(src, dst).unwrap(), exp, "{src} -> {dst}");
        }
        assert!(relative_symlink_dest("/x", "//y").is_err());
    }
}
