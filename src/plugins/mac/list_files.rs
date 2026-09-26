//! mac.list_files.List_Files (python `plugins/mac/list_files.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! The vnode walk mirrors python's object semantics exactly, which decide what is visited and
//! which address is printed:
//! * vnodes reached through list walkers / mount members are POINTER objects: truthy when
//!   non-zero, `in loop_vnodes` tests the pointer VALUE, but `vol.offset` / `vol.size` (the
//!   dict key, the validity check and the printed address) are those of the pointer itself;
//! * vnodes reached through `.dereference()` are STRUCT objects: always truthy, never `in`
//!   the dict (python hashes them by identity), `vol.offset` is the vnode address.
//! `loop_vnodes` keeps python's dict insertion order.
//!
//! Speed: the walk itself is inherently sequential (dict order), so it only decides WHETHER a
//! vnode name can be read (`pointer_to_string` fails iff the pointer or the string's first
//! page is unreadable); the strings are read afterwards in parallel, and the paths are built
//! in parallel too. Each vnode's four fields come from one zero-copy slice when possible.

use crate::automagic::mac::MacKernel;
use crate::context::Context;
use crate::error::Result;
use crate::layers::{Layer, LayerExt};
use crate::objects::util::address_to_string;
use crate::objects::{LayerRef, Obj, Space};
use crate::plugins::mac::mount::list_mounts;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::Ty;
use crate::symbols::mac::{MAX_ELEMENTS, MacExt};
use crate::util::FxHashMap;
use crate::util::par::par_map;

pub struct ListFiles;

/// A python vnode object as `_walk_vnode` sees it.
#[derive(Clone, Copy, Debug)]
enum VObj {
    /// A `vnode *` pointer object living at `loc` with value `value`.
    Ptr { loc: u64, value: u64 },
    /// A `vnode` struct object at `addr`.
    Struct { addr: u64 },
}

impl VObj {
    /// The vnode struct address member accesses go to.
    #[inline]
    fn base(self) -> u64 {
        match self {
            VObj::Ptr { value, .. } => value,
            VObj::Struct { addr } => addr,
        }
    }
    /// python `vol.offset`.
    #[inline]
    fn offset(self) -> u64 {
        match self {
            VObj::Ptr { loc, .. } => loc,
            VObj::Struct { addr } => addr,
        }
    }
}

/// Where an entry's name comes from.
enum Name {
    /// `pointer_to_string(v_name, 255)` of this (readable) pointer value, read after the walk.
    Ptr(u64),
    /// `full_path()` (VROOT vnodes), computed during the walk like python.
    Str(String),
}

/// One `loop_vnodes` item: key -> `(v_name, parent_val, vnode)`.
struct Entry {
    key: u64,
    name: Name,
    parent: Option<u64>,
}

/// The fields the walk reads from one vnode (`None` = unreadable).
#[derive(Clone, Copy)]
struct VInfo {
    flag: Option<u32>,
    name_ptr: Option<u64>,
    parent: Option<u64>,
    next: Option<u64>,
}

/// python recursion limit stand-in: nested `_walk_vnode` calls beyond this depth would make
/// python raise RecursionError (its limit is 1000 frames, ~25 of which are below/beside it).
const MAX_DEPTH: usize = 975;

struct Walker {
    layer: &'static dyn Layer,
    sp: &'static Space,
    vnode_ty: Ty,
    vnode_size: u64,
    ptr_size: u64,
    ptr_mask: u64,
    off_v_flag: u64,
    off_v_name: u64,
    off_v_parent: u64,
    off_tqe_next: u64,
    entries: Vec<Entry>,
    index: FxHashMap<u64, u32>,
    null_valid: Option<bool>,
}

#[inline]
fn rd(s: &[u8], off: u64, size: u64) -> Option<u64> {
    let o = off as usize;
    match size {
        8 => s.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())),
        4 => s.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64),
        _ => None,
    }
}

impl Walker {
    fn new(k: &MacKernel) -> Result<Walker> {
        let t = k.table;
        let vnode_ty = t.get_type("vnode")?;
        let ptr_size = t.size_of(t.get_type("pointer")?);
        let mnt = Obj::new(k.sp, vnode_ty, 0).m("v_mntvnodes")?;
        Ok(Walker {
            layer: k.vlayer,
            sp: k.sp,
            vnode_ty,
            vnode_size: t.size_of(vnode_ty),
            ptr_size,
            ptr_mask: k.vlayer.address_mask(),
            off_v_flag: t.offset_of("vnode", "v_flag")?,
            off_v_name: t.offset_of("vnode", "v_name")?,
            off_v_parent: t.offset_of("vnode", "v_parent")?,
            off_tqe_next: mnt.addr + mnt.member_offset("tqe_next")?,
            entries: Vec::new(),
            index: FxHashMap::with_capacity_and_hasher(1 << 16, Default::default()),
            null_valid: None,
        })
    }

    #[inline]
    fn read_ptr(&self, addr: u64) -> Option<u64> {
        let v = if self.ptr_size == 4 { self.layer.read_u32(addr).ok()? as u64 } else { self.layer.read_u64(addr).ok()? };
        Some(v & self.ptr_mask)
    }

    /// The walk's fields of the vnode at `base`: one slice when the struct is in one mapped
    /// page (then every field read succeeds, as python's would), else field by field.
    fn vinfo(&self, base: u64) -> VInfo {
        if let Some(s) = self.layer.slice(base, self.vnode_size as usize) {
            let p = |off| rd(s, off, self.ptr_size).map(|v| v & self.ptr_mask);
            return VInfo {
                flag: rd(s, self.off_v_flag, 4).map(|v| v as u32),
                name_ptr: p(self.off_v_name),
                parent: p(self.off_v_parent),
                next: p(self.off_tqe_next),
            };
        }
        VInfo {
            flag: self.layer.read_u32(base.wrapping_add(self.off_v_flag)).ok(),
            name_ptr: self.read_ptr(base.wrapping_add(self.off_v_name)),
            parent: self.read_ptr(base.wrapping_add(self.off_v_parent)),
            next: self.read_ptr(base.wrapping_add(self.off_tqe_next)),
        }
    }

    /// python `_vnode_name(vnode)`, deciding only whether it is None (the string itself is
    /// read later unless python computes `full_path()`).
    fn vnode_name(&self, base: u64, info: &VInfo) -> Result<Option<Name>> {
        let v_flag = match info.flag {
            Some(f) => f,
            // uncaught in python: re-read for the exact error
            None => self.layer.read_u32(base.wrapping_add(self.off_v_flag))?,
        };
        if v_flag & 1 == 1 {
            return Obj::new(self.sp, self.vnode_ty, base).full_path().map(|s| Some(Name::Str(s)));
        }
        Ok(match info.name_ptr {
            // gather_contiguous_bytes raises iff the string's first page is unmapped
            Some(p) if self.layer.is_valid(p, 1) => Some(Name::Ptr(p)),
            _ => None,
        })
    }

    /// python `_get_parent(context, vnode)`: the parent vnode STRUCT address.
    #[inline]
    fn get_parent(&mut self, info: &VInfo) -> Option<u64> {
        info.parent.filter(|&p| self.valid_vnode(p))
    }

    /// python `is_valid(p, vnode.size)` for a vnode struct address (NULL is by far the most
    /// common invalid one: answered once).
    #[inline]
    fn valid_vnode(&mut self, p: u64) -> bool {
        if p == 0 {
            if let Some(v) = self.null_valid {
                return v;
            }
            let v = self.layer.is_valid(0, self.vnode_size);
            self.null_valid = Some(v);
            return v;
        }
        self.layer.is_valid(p, self.vnode_size)
    }

    /// python `_add_vnode(context, vnode, loop_vnodes)`; returns `Some(info)` when added.
    fn add_vnode(&mut self, v: VObj) -> Result<Option<VInfo>> {
        let key = v.offset();
        let valid = match v {
            VObj::Ptr { .. } => self.layer.is_valid(key, self.ptr_size),
            VObj::Struct { .. } => self.valid_vnode(key),
        };
        if !valid || self.index.contains_key(&key) {
            return Ok(None);
        }
        let info = self.vinfo(v.base());
        let Some(name) = self.vnode_name(v.base(), &info)? else { return Ok(None) };
        let parent = self.get_parent(&info);
        self.index.insert(key, self.entries.len() as u32);
        self.entries.push(Entry { key, name, parent });
        Ok(Some(info))
    }

    /// python `_walk_vnode(context, vnode, loop_vnodes)`.
    fn walk_vnode(&mut self, v: VObj, depth: usize) -> Result<bool> {
        if depth > MAX_DEPTH {
            panic!("RecursionError: maximum recursion depth exceeded");
        }
        let mut added = false;
        let mut vnode = v;
        loop {
            // `while vnode:` and `if vnode in loop_vnodes: return added`
            if let VObj::Ptr { value, .. } = vnode {
                if value == 0 {
                    break;
                }
                if self.index.contains_key(&value) {
                    return Ok(added);
                }
            }
            let Some(info) = self.add_vnode(vnode)? else { break };
            added = true;
            let mut parent = self.get_parent(&info);
            // `while parent and parent not in loop_vnodes` (a struct is never `in`)
            while let Some(p) = parent {
                if !self.walk_vnode(VObj::Struct { addr: p }, depth + 1)? {
                    break;
                }
                let pi = self.vinfo(p);
                parent = self.get_parent(&pi);
            }
            match info.next {
                Some(next) => vnode = VObj::Struct { addr: next },
                None => break,
            }
        }
        Ok(added)
    }

    /// python `_walk_vnodelist(context, list_head, loop_vnodes)`.
    fn walk_vnodelist(&mut self, list_head: &Obj) -> Result<()> {
        for vnode in list_head.walk_tailq("v_mntvnodes", MAX_ELEMENTS) {
            let p = vnode?;
            let value = p.u64()?;
            self.walk_vnode(VObj::Ptr { loc: p.addr, value }, 0)?;
        }
        Ok(())
    }

    /// A `vnode *` member of a mount (python reads the pointer on attribute access).
    fn walk_member(&mut self, mnt: &Obj, member: &str) -> Result<()> {
        let p = mnt.m(member)?;
        let value = p.u64()?;
        self.walk_vnode(VObj::Ptr { loc: p.addr, value }, 0)?;
        Ok(())
    }
}

/// python `utility.pointer_to_string(ptr, 255)` for the pointer value `addr`: zero-copy when
/// the NUL is found in the first page part (bytes after it cannot change the result), else
/// the exact python routine.
fn read_cstring_255(layer: LayerRef, addr: u64) -> Result<String> {
    let in_page = (0x1000 - (addr & 0xfff)).min(255) as usize;
    if let Some(s) = layer.slice(addr, in_page) {
        if let Some(end) = s.iter().position(|&b| b == 0) {
            let s = &s[..end];
            if s.is_ascii() {
                // decode("utf-8", "replace") cut at NUL/U+FFFD is the identity on ASCII
                return Ok(String::from_utf8_lossy(s).into_owned());
            }
        }
    }
    address_to_string(layer, addr, 255, "replace", "utf-8")
}

/// python `List_Files._walk_mounts`.
fn walk_mounts(k: &MacKernel) -> Result<Walker> {
    let mut w = Walker::new(k)?;
    for mnt in list_mounts(k) {
        let mnt = mnt?;
        w.walk_vnodelist(&mnt.m("mnt_vnodelist")?)?;
        w.walk_vnodelist(&mnt.m("mnt_workerqueue")?)?;
        w.walk_vnodelist(&mnt.m("mnt_newvnodes")?)?;
        w.walk_member(&mnt, "mnt_vnodecovered")?;
        w.walk_member(&mnt, "mnt_realrootvp")?;
        w.walk_member(&mnt, "mnt_devvp")?;
    }
    Ok(w)
}

/// python `List_Files._build_path(vnodes, vnode_name, parent_offset)`.
fn build_path(w: &Walker, names: &[String], i: usize) -> String {
    let name = names[i].as_str();
    let mut rev: Vec<&str> = vec![name];
    // `seen_offsets`: a short list scanned linearly (chains are short), a set when long
    let mut seen: Vec<u64> = Vec::new();
    let mut seen_set: crate::util::FxHashSet<u64> = Default::default();
    let mut cur = w.entries[i].parent;
    let mut cycle = false;
    while let Some(po) = cur {
        let Some(&j) = w.index.get(&po) else { break };
        let e = &w.entries[j as usize];
        match e.parent {
            None => cur = Some(0),
            Some(pp) => {
                let dup = if seen.len() < 64 { seen.contains(&pp) } else { seen_set.contains(&pp) };
                if dup {
                    cycle = true;
                    break;
                }
                if seen.len() < 64 {
                    seen.push(pp);
                    if seen.len() == 64 {
                        seen_set.extend(seen.iter().copied());
                    }
                } else {
                    seen_set.insert(pp);
                }
                cur = Some(pp);
            }
        }
        rev.push(&names[j as usize]);
    }
    let path = if !cycle && rev.len() > 1 {
        rev.reverse();
        rev.join("/")
    } else {
        name.to_string()
    };
    match path.strip_prefix('/') {
        Some(rest) if rest.starts_with('/') => rest.to_string(),
        _ => path,
    }
}

/// [`build_path`] for every entry, memoized along the parent chains (they are long: this image
/// has directories ~600 levels deep). For an acyclic chain python's list is the parent's list
/// plus the entry's name; a chain that runs into a cycle gives the bare name. When 0 is a key
/// (python's `parent_offset = 0` could then continue a chain) the direct algorithm is used.
fn build_paths(w: &Walker, names: &[String]) -> Vec<String> {
    let n = w.entries.len();
    if w.index.contains_key(&0) {
        return par_map(n, |i| build_path(w, names, i));
    }
    const UNSEEN: u8 = 0;
    const ACTIVE: u8 = 1;
    const DONE: u8 = 2;
    const CYCLIC: u8 = 3;
    let parent_of = |j: usize| w.entries[j].parent.and_then(|p| w.index.get(&p)).map(|&x| x as usize);
    let mut state = vec![UNSEEN; n];
    let mut joined: Vec<String> = vec![String::new(); n];
    let mut stack: Vec<usize> = Vec::new();
    for i in 0..n {
        if state[i] != UNSEEN {
            continue;
        }
        let mut j = i;
        let cyclic = loop {
            state[j] = ACTIVE;
            stack.push(j);
            match parent_of(j) {
                None => break false,
                Some(p) => match state[p] {
                    UNSEEN => j = p,
                    DONE => break false,
                    _ => break true, // ACTIVE (a cycle) or CYCLIC
                },
            }
        };
        while let Some(j) = stack.pop() {
            if cyclic {
                state[j] = CYCLIC;
                continue;
            }
            joined[j] = match parent_of(j) {
                Some(p) => {
                    let mut s = String::with_capacity(joined[p].len() + 1 + names[j].len());
                    s.push_str(&joined[p]);
                    s.push('/');
                    s.push_str(&names[j]);
                    s
                }
                None => names[j].clone(),
            };
            state[j] = DONE;
        }
    }
    joined
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            if state[i] == CYCLIC {
                names[i].clone()
            } else if p.starts_with("//") {
                p[1..].to_string()
            } else {
                p
            }
        })
        .collect()
}

/// python `List_Files.list_files(context, kernel_module_name)`: `(vnode vol.offset, full
/// path)` in python order.
pub fn list_files(k: &MacKernel) -> Result<Vec<(u64, String)>> {
    let w = {
        let _t = crate::util::trace::span("list_files walk");
        walk_mounts(k)?
    };
    let names: Vec<String> = {
        let _t = crate::util::trace::span("list_files names");
        let layer = w.layer;
        let res: Vec<Result<String>> = par_map(w.entries.len(), |i| match &w.entries[i].name {
            Name::Str(s) => Ok(s.clone()),
            Name::Ptr(p) => read_cstring_255(layer, *p),
        });
        res.into_iter().collect::<Result<_>>()?
    };
    let _t = crate::util::trace::span("list_files build paths");
    let paths = build_paths(&w, &names);
    Ok(w.entries.iter().map(|e| e.key).zip(paths).collect())
}

impl Plugin for ListFiles {
    fn name(&self) -> &'static str {
        "mac.list_files.List_Files"
    }
    fn description(&self) -> &'static str {
        "Lists all open file descriptors for all processes."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![Column::new("Address", ColType::Hex), Column::new("File Path", ColType::Str)])?;
        let files = list_files(k)?;
        let _t = crate::util::trace::span("list_files render");
        for (addr, path) in files {
            out.row(0, vec![Value::Int(addr as i128), Value::Str(path)])?;
        }
        Ok(())
    }
}
