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

use crate::automagic::mac::MacKernel;
use crate::context::Context;
use crate::error::Result;
use crate::layers::{Layer, LayerExt};
use crate::objects::util::pointer_to_string;
use crate::objects::{Obj, Space};
use crate::plugins::mac::mount::list_mounts;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::Ty;
use crate::symbols::mac::{MAX_ELEMENTS, MacExt};
use crate::util::FxHashMap;

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

/// One `loop_vnodes` value: `(v_name, parent_val, vnode)`.
struct Entry {
    key: u64,
    name: String,
    parent: Option<u64>,
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
}

impl Walker {
    fn new(k: &MacKernel) -> Result<Walker> {
        let t = k.table;
        let vnode_ty = t.get_type("vnode")?;
        let ptr_size = t.size_of(t.get_type("pointer")?);
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
            off_tqe_next: t.offset_of("vnode", "v_mntvnodes")? + {
                let o = Obj::new(k.sp, vnode_ty, 0).m("v_mntvnodes")?;
                o.member_offset("tqe_next")?
            },
            entries: Vec::new(),
            index: FxHashMap::default(),
        })
    }

    #[inline]
    fn read_ptr(&self, addr: u64) -> Result<u64> {
        let v = if self.ptr_size == 4 { self.layer.read_u32(addr)? as u64 } else { self.layer.read_u64(addr)? };
        Ok(v & self.ptr_mask)
    }

    fn vnode_obj(&self, addr: u64) -> Obj {
        Obj::new(self.sp, self.vnode_ty, addr)
    }

    /// python `_vnode_name(vnode)`.
    fn vnode_name(&self, v: VObj) -> Result<Option<String>> {
        let base = v.base();
        let v_flag = self.layer.read_u32(base.wrapping_add(self.off_v_flag))?;
        if v_flag & 1 == 1 {
            return self.vnode_obj(base).full_path().map(Some);
        }
        let name_ptr = match self.read_ptr(base.wrapping_add(self.off_v_name)) {
            Ok(p) => p,
            Err(e) if e.is_invalid_address() => return Ok(None),
            Err(e) => return Err(e),
        };
        match read_cstring_255(self.layer, name_ptr, || self.vnode_obj(base).m("v_name")) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// python `_get_parent(context, vnode)`: the parent vnode STRUCT address.
    fn get_parent(&self, v: VObj) -> Result<Option<u64>> {
        let p = match self.read_ptr(v.base().wrapping_add(self.off_v_parent)) {
            Ok(p) => p,
            Err(e) if e.is_invalid_address() => return Ok(None),
            Err(e) => return Err(e),
        };
        if !self.layer.is_valid(p, self.vnode_size) {
            return Ok(None);
        }
        Ok(Some(p))
    }

    /// python `_add_vnode(context, vnode, loop_vnodes)`.
    fn add_vnode(&mut self, v: VObj) -> Result<bool> {
        let size = match v {
            VObj::Ptr { .. } => self.ptr_size,
            VObj::Struct { .. } => self.vnode_size,
        };
        let key = v.offset();
        if !self.layer.is_valid(key, size) {
            return Ok(false);
        }
        if self.index.contains_key(&key) {
            return Ok(false);
        }
        let Some(name) = self.vnode_name(v)? else { return Ok(false) };
        let parent = self.get_parent(v)?;
        self.index.insert(key, self.entries.len() as u32);
        self.entries.push(Entry { key, name, parent });
        Ok(true)
    }

    /// python `vnode in loop_vnodes`.
    #[inline]
    fn contains(&self, v: VObj) -> bool {
        match v {
            VObj::Ptr { value, .. } => self.index.contains_key(&value),
            VObj::Struct { .. } => false,
        }
    }

    /// python `_walk_vnode(context, vnode, loop_vnodes)`.
    fn walk_vnode(&mut self, v: VObj, depth: usize) -> Result<bool> {
        if depth > MAX_DEPTH {
            panic!("RecursionError: maximum recursion depth exceeded");
        }
        let mut added = false;
        let mut vnode = v;
        loop {
            // `while vnode:`
            if let VObj::Ptr { value: 0, .. } = vnode {
                break;
            }
            if self.contains(vnode) {
                return Ok(added);
            }
            if !self.add_vnode(vnode)? {
                break;
            }
            added = true;
            // `while parent and parent not in loop_vnodes` (a struct is never `in`)
            let mut parent = self.get_parent(vnode)?;
            while let Some(p) = parent {
                if !self.walk_vnode(VObj::Struct { addr: p }, depth + 1)? {
                    break;
                }
                parent = self.get_parent(VObj::Struct { addr: p })?;
            }
            match self.read_ptr(vnode.base().wrapping_add(self.off_tqe_next)) {
                Ok(next) => vnode = VObj::Struct { addr: next },
                Err(e) if e.is_invalid_address() => break,
                Err(e) => return Err(e),
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

/// python `utility.pointer_to_string(ptr, 255)` for the pointer value `addr`: a direct read
/// when all 255 bytes are mapped (the common case), else the exact python routine.
fn read_cstring_255(layer: &dyn Layer, addr: u64, ptr: impl FnOnce() -> Result<Obj>) -> Result<String> {
    let mut buf = [0u8; 255];
    if layer.read(addr, &mut buf).is_ok() {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let s = &buf[..end];
        if s.is_ascii() {
            // decode("utf-8", "replace") cut at NUL/U+FFFD is the identity on ASCII
            return Ok(String::from_utf8(s.to_vec()).unwrap_or_default());
        }
    }
    pointer_to_string(&ptr()?, 255)
}

/// python `List_Files._walk_mounts`: `(key, name, parent)` in dict order.
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
fn build_path(w: &Walker, name: &str, parent: Option<u64>) -> String {
    let mut rev: Vec<&str> = vec![name];
    let mut seen: crate::util::FxHashSet<u64> = Default::default();
    let mut cur = parent;
    let mut cycle = false;
    while let Some(po) = cur {
        let Some(&i) = w.index.get(&po) else { break };
        let e = &w.entries[i as usize];
        match e.parent {
            None => cur = Some(0),
            Some(pp) if seen.contains(&pp) => {
                cycle = true;
                break;
            }
            Some(pp) => {
                seen.insert(pp);
                cur = Some(pp);
            }
        }
        rev.push(&e.name);
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

/// python `List_Files.list_files(context, kernel_module_name)`: `(vnode vol.offset, full
/// path)` in python order.
pub fn list_files(k: &MacKernel) -> Result<Vec<(u64, String)>> {
    let w = walk_mounts(k)?;
    Ok(w.entries.iter().map(|e| (e.key, build_path(&w, &e.name, e.parent))).collect())
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
        let w = walk_mounts(k)?;
        for e in &w.entries {
            out.row(0, vec![Value::Int(e.key as i128), Value::Str(build_path(&w, &e.name, e.parent))])?;
        }
        Ok(())
    }
}
