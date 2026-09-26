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
use crate::objects::Obj;
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

/// python `Files._walk_dentry(seen_dentries, root_dentry, parent_dir)`: depth-first, calls
/// `f(file_path, dentry)` (python's yield) before descending into a directory. `f` returns
/// false to stop the whole walk (`Ok(false)` is propagated).
fn walk_dentry(seen: &mut FxHashSet<u64>, root: Obj, parent_dir: &str, f: &mut dyn FnMut(String, Obj) -> Result<bool>) -> Result<bool> {
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
        let inode_ptr = dentry.m("d_inode")?;
        if !ptr_ok(&inode_ptr)? {
            continue;
        }
        let inode = inode_ptr.deref()?;
        if !inode_valid(&inode)? {
            continue;
        }
        let d_name = dentry.m("d_name")?;
        if d_name.m("name")?.u64()? == 0 {
            continue;
        }
        let file_path = format!("{}/{}", top.parent_dir, d_name.name_as_str()?);
        if !f(file_path.clone(), dentry)? {
            return Ok(false);
        }
        if inode.is_dir()? {
            stack.push(Frame { iter: dentry.get_subdirs(), root_addr: dentry.addr, parent_dir: file_path });
        }
    }
    Ok(true)
}

/// python `Files.get_inodes(context, kernel, follow_symlinks)`: streams every cached inode
/// (superblock roots, then their dentry trees) to `f` in python's order; `f` returns false
/// to stop. `Err` where python raises.
pub fn get_inodes(k: &LinuxKernel, follow_symlinks: bool, f: &mut dyn FnMut(InodeInternal) -> Result<bool>) -> Result<()> {
    let mut seen_inodes = FxHashSet::default();
    let mut seen_dentries = FxHashSet::default();
    for sb in crate::plugins::linux::mountinfo::get_superblocks(k) {
        let (superblock, mountpoint) = sb?;
        let mountpoint: Arc<str> = mountpoint.into();
        let parent_dir = if &*mountpoint == "/" { "" } else { &*mountpoint };
        let root_dentry_ptr = superblock.m("s_root")?;
        if root_dentry_ptr.u64()? == 0 {
            continue;
        }
        let root_dentry = root_dentry_ptr.deref()?;
        if !root_dentry.is_root()? {
            continue;
        }
        let root_inode_ptr = root_dentry.m("d_inode")?;
        if !ptr_ok(&root_inode_ptr)? {
            continue;
        }
        let root_inode = root_inode_ptr.deref()?;
        if !inode_valid(&root_inode)? {
            continue;
        }
        if !ptr_ok(&root_inode.m("i_mapping")?)? {
            continue;
        }
        if !seen_inodes.insert(root_inode_ptr.u64()?) {
            continue;
        }
        if !f(InodeInternal { superblock, mountpoint: mountpoint.clone(), inode: root_inode, path: mountpoint.to_string() })? {
            return Ok(());
        }
        let cont = walk_dentry(&mut seen_dentries, root_dentry, parent_dir, &mut |file_path, file_dentry| {
            let file_inode_ptr = file_dentry.m("d_inode")?;
            if !ptr_ok(&file_inode_ptr)? {
                return Ok(true);
            }
            let file_inode = file_inode_ptr.deref()?;
            if !inode_valid(&file_inode)? {
                return Ok(true);
            }
            if !ptr_ok(&file_inode.m("i_mapping")?)? {
                return Ok(true);
            }
            if !seen_inodes.insert(file_inode_ptr.u64()?) {
                return Ok(true);
            }
            let path = if follow_symlinks { follow_symlink(&file_inode_ptr, file_path)? } else { file_path };
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
    Ok(vec![
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
        Value::Str(ii.path.clone()),
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
        let type_ok = |ii: &InodeInternal| -> Result<bool> {
            if types.is_empty() {
                return Ok(true);
            }
            // `get_inode_type() not in types_filter` (None is never in a list of str)
            Ok(ii.inode.get_inode_type()?.is_some_and(|t| types.iter().any(|x| x == t)))
        };
        if let Some(find) = find {
            // python breaks at the first match: stream and stop there
            let mut found = None;
            get_inodes(k, true, &mut |ii| {
                if !type_ok(&ii)? {
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
        let (inodes, tail) = collect_inodes(k, true);
        let rows = par_rows(&inodes, |ii| if type_ok(ii)? { inode_user_row(ii, ps).map(Some) } else { Ok(None) });
        for r in rows {
            if let Some(row) = r? {
                out.row(0, row)?;
            }
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

/// Stored-block gzip writer (valid gzip, no compression).
/// TODO(l3): replaced by the codec encoders.
struct StoredGzip<W: Write + Send> {
    w: W,
    crc: u32,
    len: u64,
}

impl<W: Write + Send> StoredGzip<W> {
    fn new(mut w: W, mtime: u32) -> std::io::Result<Self> {
        let mut h = vec![0x1f, 0x8b, 8, 0];
        h.extend_from_slice(&mtime.to_le_bytes());
        h.extend_from_slice(&[2, 0xff]);
        w.write_all(&h)?;
        Ok(StoredGzip { w, crc: 0, len: 0 })
    }
}

impl<W: Write + Send> Write for StoredGzip<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for c in buf.chunks(65535) {
            let mut h = [0u8; 5];
            h[1..3].copy_from_slice(&(c.len() as u16).to_le_bytes());
            h[3..5].copy_from_slice(&(!(c.len() as u16)).to_le_bytes());
            self.w.write_all(&h)?;
            self.w.write_all(c)?;
        }
        self.crc = crate::codecs::crc::crc32_update(self.crc, buf);
        self.len += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

impl<W: Write + Send> FinishWrite for StoredGzip<W> {
    fn finish(mut self: Box<Self>) -> std::io::Result<()> {
        self.w.write_all(&[1, 0, 0, 0xff, 0xff])?;
        self.w.write_all(&self.crc.to_le_bytes())?;
        self.w.write_all(&(self.len as u32).to_le_bytes())?;
        self.w.flush()
    }
}

fn open_compressor(format: &str, file: std::fs::File, mtime: u32) -> Result<Box<dyn FinishWrite>> {
    let w = std::io::BufWriter::with_capacity(1 << 20, file);
    match format {
        "gz" => Ok(Box::new(StoredGzip::new(w, mtime)?)),
        other => Err(Error::msg(format!("compression format {other} not supported yet"))),
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
    let (inodes, tail) = collect_inodes(k, false);
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
        format!("{dir}/tmp_rsvol_recoverfs_{}.vol3", std::process::id())
    };
    let tmp_file = std::fs::File::create(&tmp_path)?;
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
