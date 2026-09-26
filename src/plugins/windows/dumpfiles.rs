//! windows.dumpfiles.DumpFiles (python `plugins/windows/dumpfiles.py`): dumps the cached
//! contents (DataSectionObject / ImageSectionObject control areas and the SharedCacheMap) of
//! the `_FILE_OBJECT`s reachable from process handles and VADs, or at given addresses.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Everything python makes observable (row order, which objects are skipped, which output
//! files exist with which `-N` suffix and which bytes) is reproduced; the work is reordered
//! so the expensive parts run in parallel:
//!
//! 1. candidate file objects per process (handles, then VADs, filter applied) -- parallel;
//! 2. python's `dumped_files` de-duplication -- sequential, python order;
//! 3. `process_file_object` up to the dump loop (device type, name, valid caches) -- parallel;
//! 4. output files are created sequentially in python order (the `-N` collision suffixes
//!    depend on it; python also commits a file for every "Error dumping file" row, holding
//!    whatever was written before the error);
//! 5. page lists are computed in parallel and written largest-first on all cores with
//!    `pwritev` straight from the mmapped image (no intermediate copies; gaps stay holes);
//! 6. rows are emitted in order, then python's fatal error (if any) is returned.

use crate::cli::regex::Regex;
use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::layers::metadata;
use crate::objects::{Field, LayerRef, Obj, Space};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::cache::{control_area_is_valid, shared_cache_map_is_valid};
use crate::symbols::windows::pool::TypeMap;
use crate::symbols::windows::prelude::*;
use crate::symbols::{Prim, TableRef, Ty};
use crate::util::FxHashSet;
use crate::util::par;
use crate::util::trace::span;
use std::fs::File;
use std::os::unix::io::AsRawFd;

pub struct DumpFiles;

const FILE_DEVICE_DISK: i128 = 0x7;
const FILE_DEVICE_NETWORK_FILE_SYSTEM: i128 = 0x14;
const PAGE: u64 = 0x1000;

/// The three file caches (python `EXTENSION_CACHE_MAP`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cache {
    Data,
    Image,
    Vacb,
}

impl Cache {
    fn name(self) -> &'static str {
        match self {
            Cache::Data => "DataSectionObject",
            Cache::Image => "ImageSectionObject",
            Cache::Vacb => "SharedCacheMap",
        }
    }
    fn ext(self) -> &'static str {
        match self {
            Cache::Data => "dat",
            Cache::Image => "img",
            Cache::Vacb => "vacb",
        }
    }
}

/// python `ntpath.basename(p)` for the names `file_name_with_device()` produces (they start
/// with `\Device\`, so there is never a drive part): everything after the last `\` or `/`.
fn ntpath_basename(p: &str) -> &str {
    match p.rfind(['\\', '/']) {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

// ---------------------------------------------------------------------------------------------
// handles (python handles.Handles.handles / _make_handle_array / _get_item)
// TODO(dedupe): owned by W1 (windows.handles helpers)

/// Pre-resolved handle table layout for one kernel.
struct HandleWalker {
    vl: LayerRef,
    sp: &'static Space,
    ptr_ty: Ty,
    ptr_size: u64,
    entry_ty: Ty,
    entry_size: u64,
    is_64: bool,
    /// pre-Windows 8 `_HANDLE_TABLE_ENTRY.Object`
    has_object: bool,
    header_ty: Ty,
    has_type_index: bool,
}

impl HandleWalker {
    fn new(k: &WinKernel) -> Result<HandleWalker> {
        let t = k.table;
        let entry_ty = t.get_type("_HANDLE_TABLE_ENTRY")?;
        let ptr_ty = t.get_type("pointer")?;
        let header_ty = t.get_type("_OBJECT_HEADER")?;
        let sp = Space::on(k.vlayer, t);
        let entry = Obj::new(sp, entry_ty, 0);
        let header = Obj::new(sp, header_ty, 0);
        Ok(HandleWalker {
            vl: k.vlayer,
            sp,
            ptr_ty,
            ptr_size: t.size_of(ptr_ty),
            entry_ty,
            entry_size: t.size_of(entry_ty),
            is_64: t.is_64bit(),
            has_object: entry.has_member("Object"),
            header_ty,
            has_type_index: header.has_member("TypeIndex"),
        })
    }

    /// python `Handles.handles(handle_table)`: the `_OBJECT_HEADER`s of the table's in-use
    /// entries, in python order. A trailing `Err` = python raised.
    fn handles(&self, handle_table: &Obj) -> Vec<Result<Obj>> {
        let mut out = Vec::new();
        let tc = match handle_table.m("TableCode").and_then(|t| t.u64()) {
            Ok(v) => v,
            Err(e) if e.is_invalid_address() => return out,
            Err(e) => return vec![Err(e)],
        };
        if let Err(e) = self.make_handle_array(tc & !7, tc & 7, &mut out) {
            out.push(Err(e));
        }
        out
    }

    fn make_handle_array(&self, offset: u64, level: u64, out: &mut Vec<Result<Obj>>) -> Result<()> {
        let (subtype, size) = if level > 0 { (self.ptr_ty, self.ptr_size) } else { (self.entry_ty, self.entry_size) };
        if size == 0 {
            return Err(Error::msg("ZeroDivisionError: division by zero"));
        }
        let count = 0x1000 / size;
        if !self.vl.is_valid(offset, 1) {
            return Ok(());
        }
        let base = Obj::new(self.sp, subtype, offset).addr;
        for i in 0..count {
            let entry = Obj::new(self.sp, subtype, base.wrapping_add(i * size));
            if level > 0 {
                // python reads the pointer when indexing the array
                let v = match entry.u64() {
                    Ok(v) => v,
                    Err(e) if e.is_invalid_address() => continue,
                    Err(e) => return Err(e),
                };
                if !self.vl.is_valid(entry.addr, 1) {
                    continue;
                }
                self.make_handle_array(v, level - 1, out)?;
            } else {
                if !self.vl.is_valid(entry.addr, 1) {
                    continue;
                }
                let Some(item) = self.get_item(&entry)? else { continue };
                if self.has_type_index {
                    match item.m("TypeIndex").and_then(|t| t.int()) {
                        Ok(0) => {}
                        Ok(_) => out.push(Ok(item)),
                        Err(e) if e.is_invalid_address() => {}
                        Err(e) => return Err(e),
                    }
                } else {
                    // `if item.Type.Name:` -- a struct, always true once the pointer is read
                    item.m("Type")?.u64()?;
                    out.push(Ok(item));
                }
            }
        }
        Ok(())
    }

    /// python `Handles._get_item(entry)`: the object header of a handle table entry.
    fn get_item(&self, entry: &Obj) -> Result<Option<Obj>> {
        if self.has_object {
            // before windows 8
            let obj = entry.m("Object")?;
            if !self.vl.is_valid(obj.u64()?, 1) {
                return Ok(None);
            }
            let header = match obj.cast("_EX_FAST_REF")?.fast_ref_dereference() {
                Ok(p) => p.cast("_OBJECT_HEADER")?,
                Err(e) if e.is_invalid_address() => return Ok(None),
                Err(e) => return Err(e),
            };
            entry.m("GrantedAccess")?.int()?;
            return Ok(Some(header));
        }
        let offset = if self.is_64 {
            let bits = match entry.m("ObjectPointerBits")?.u64() {
                Ok(v) => v,
                Err(e) if e.is_invalid_address() => return Ok(None),
                Err(e) => return Err(e),
            };
            if bits == 0 {
                return Ok(None);
            }
            bits << 4
        } else {
            let it = match entry.m("InfoTable")?.u64() {
                Ok(v) => v,
                Err(e) if e.is_invalid_address() => return Ok(None),
                Err(e) => return Err(e),
            };
            if it == 0 {
                return Ok(None);
            }
            it & !7
        };
        let header = Obj::new(self.sp, self.header_ty, offset);
        match entry.m("GrantedAccessBits")?.int() {
            Ok(_) => Ok(Some(header)),
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// candidate file objects

/// One step of python's `_generator` loop: a file object reaching the `dumped_files` check,
/// or the exception that ended the generator.
enum Step {
    Cand(Obj),
    Fatal(Error),
}

/// `file_re.search(file_obj.file_name_with_device())` (Unreadable names never match).
fn name_matches(fo: &Obj, re: Option<&Regex>) -> Result<bool> {
    let Some(re) = re else { return Ok(true) };
    Ok(match fo.file_name_with_device()? {
        Value::Str(s) => re.is_match(&s),
        _ => false,
    })
}

/// The file object behind a control area's `FilePointer` (python
/// `FilePointer.dereference()`: `_EX_FAST_REF` since Windows 7, a plain pointer before).
fn file_pointer_target(fp: &Obj) -> Result<Obj> {
    if fp.is_pointer() { fp.deref() } else { fp.fast_ref_dereference() }
}

/// python's per-process part of `_generator`: handles, then VADs.
fn proc_steps(hw: &HandleWalker, proc: &Obj, type_map: &TypeMap, cookie: Option<u64>, re: Option<&Regex>) -> Vec<Step> {
    let mut out = Vec::new();
    macro_rules! guard {
        ($r:expr) => {
            match $r {
                Ok(Some(fo)) => out.push(Step::Cand(fo)),
                Ok(None) => {}
                Err(e) if e.is_invalid_address() => {}
                Err(e) => {
                    out.push(Step::Fatal(e));
                    return out;
                }
            }
        };
    }
    let object_table = match proc.m("ObjectTable").and_then(|p| p.u64().map(|_| p)) {
        Ok(p) => p,
        Err(e) if e.is_invalid_address() => return out,
        Err(e) => return vec![Step::Fatal(e)],
    };
    for entry in hw.handles(&object_table) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                out.push(Step::Fatal(e));
                return out;
            }
        };
        guard!((|| -> Result<Option<Obj>> {
            if entry.get_object_type(type_map, cookie)?.as_deref() != Some("File") {
                return Ok(None);
            }
            let fo = entry.m("Body")?.cast("_FILE_OBJECT")?;
            Ok(if name_matches(&fo, re)? { Some(fo) } else { None })
        })());
    }
    let root = match proc.get_vad_root() {
        Ok(r) => r,
        Err(e) => {
            out.push(Step::Fatal(e));
            return out;
        }
    };
    for vad in root.traverse() {
        let vad = match vad {
            Ok(v) => v,
            Err(e) => {
                out.push(Step::Fatal(e));
                return out;
            }
        };
        guard!((|| -> Result<Option<Obj>> {
            let fo = if vad.has_member("ControlArea") {
                // Windows XP and 2003
                file_pointer_target(&vad.m("ControlArea")?.m("FilePointer")?)?
            } else if vad.has_member("Subsection") {
                file_pointer_target(&vad.m("Subsection")?.m("ControlArea")?.m("FilePointer")?)?.cast("_FILE_OBJECT")?
            } else {
                return Ok(None);
            };
            if !fo.is_valid() {
                return Ok(None);
            }
            Ok(if name_matches(&fo, re)? { Some(fo) } else { None })
        })());
    }
    out
}

// ---------------------------------------------------------------------------------------------
// process_file_object

/// python `process_file_object` up to the dump loop: None = not a file on disk; Some((name,
/// dump parameters)). `Err` = python raised before yielding anything.
fn file_info(fo: &Obj) -> Result<Option<(Value, Vec<(Cache, Obj)>)>> {
    let dt = fo.m("DeviceObject")?.m("DeviceType")?.int()?;
    if dt != FILE_DEVICE_DISK && dt != FILE_DEVICE_NETWORK_FILE_SYSTEM {
        return Ok(None);
    }
    let name = fo.file_name_with_device()?;
    let mut params = Vec::with_capacity(3);
    for (member, cache) in [("DataSectionObject", Cache::Data), ("ImageSectionObject", Cache::Image)] {
        let r = (|| -> Result<Option<Obj>> {
            let ca = fo.m("SectionObjectPointer")?.m(member)?.deref()?.cast("_CONTROL_AREA")?;
            Ok(if control_area_is_valid(&ca) { Some(ca) } else { None })
        })();
        match r {
            Ok(Some(ca)) => params.push((cache, ca)),
            Ok(None) => {}
            Err(e) if e.is_invalid_address() => {}
            Err(e) => return Err(e),
        }
    }
    let r = (|| -> Result<Option<Obj>> {
        let scm = fo.m("SectionObjectPointer")?.m("SharedCacheMap")?.deref()?.cast("_SHARED_CACHE_MAP")?;
        Ok(if shared_cache_map_is_valid(&scm)? { Some(scm) } else { None })
    })();
    match r {
        Ok(Some(scm)) => params.push((Cache::Vacb, scm)),
        Ok(None) => {}
        Err(e) if e.is_invalid_address() => {}
        Err(e) => return Err(e),
    }
    Ok(Some((name, params)))
}

/// One output file (one row).
struct Job {
    fo: u64,
    base: String,
    cache: Cache,
    mobj: Obj,
}

// ---------------------------------------------------------------------------------------------
// CONTROL_AREA.get_available_pages() with bulk PTE reads

/// An `_MMPTE` bit field decoded from the PTE's bytes.
#[derive(Clone, Copy)]
struct BitF {
    off: usize,
    prim: Prim,
    /// (start, end) of a bit field; None for a plain integer
    bits: Option<(u8, u8)>,
}

impl BitF {
    fn new(t: TableRef, path: &str) -> Result<BitF> {
        let f = Field::path(t, "_MMPTE", path)?;
        let (prim, bits) = match f.ty {
            Ty::BitField { start, end, base } => (base, Some((start, end))),
            Ty::Int(p) => (p, None),
            _ => return Err(Error::msg(format!("_MMPTE.{path} is not an integer"))),
        };
        Ok(BitF { off: f.offset as usize, prim, bits })
    }
    fn span(&self) -> usize {
        self.off + self.prim.size as usize
    }
    #[inline(always)]
    fn get(&self, b: &[u8]) -> i128 {
        let v = self.prim.decode_int(&b[self.off..self.off + self.prim.size as usize]);
        match self.bits {
            Some((start, end)) => {
                let mask = if end >= 127 { -1i128 } else { (1i128 << end) - 1 };
                (v & mask) >> start
            }
            None => v,
        }
    }
}

/// Pre-resolved `_MMPTE` layout.
struct PteDecoder {
    size: usize,
    valid: BitF,
    hard_pfn: BitF,
    proto: BitF,
    trans: BitF,
    trans_pfn: BitF,
    /// `u.Subsect.SubsectionAddressHigh/Low` (32-bit non-PAE only)
    subsect: Option<(BitF, BitF)>,
}

impl PteDecoder {
    fn new(t: TableRef) -> Result<PteDecoder> {
        let size = t.size_of(t.get_type("_MMPTE")?) as usize;
        let d = PteDecoder {
            size,
            valid: BitF::new(t, "u.Hard.Valid")?,
            hard_pfn: BitF::new(t, "u.Hard.PageFrameNumber")?,
            proto: BitF::new(t, "u.Soft.Prototype")?,
            trans: BitF::new(t, "u.Trans.Transition")?,
            trans_pfn: BitF::new(t, "u.Trans.PageFrameNumber")?,
            subsect: match (BitF::new(t, "u.Subsect.SubsectionAddressHigh"), BitF::new(t, "u.Subsect.SubsectionAddressLow")) {
                (Ok(h), Ok(l)) => Some((h, l)),
                _ => None,
            },
        };
        let mut span = [d.valid, d.hard_pfn, d.proto, d.trans, d.trans_pfn].iter().map(|f| f.span()).max().unwrap_or(0);
        if let Some((h, l)) = d.subsect {
            span = span.max(h.span()).max(l.span());
        }
        if size == 0 || span > size {
            return Err(Error::msg("unexpected _MMPTE layout"));
        }
        Ok(d)
    }
}

/// Pages of a file: (layer offset, file offset, size).
type Pages = Vec<(u64, u64, u64)>;

/// python `CONTROL_AREA.get_available_pages()`: pages in python order; `Err` = the generator
/// raised after yielding the pages already in `out`.
fn control_area_pages(ca: &Obj, dec: &PteDecoder, out: &mut Pages) -> Result<()> {
    let layer = ca.layer();
    let mask = ca.sp.layer_mask;
    let is_64 = ca.table().is_64bit();
    let is_pae = metadata(layer).pae.unwrap_or(false);
    let mut subsection = ca.get_subsection()?;
    let sector_size: u64 = if ca.path("u.Flags.Image")?.int()? != 1 { 0x1000 } else { 0x200 };
    let pte = dec.size as u64;
    let mut buf = vec![0u8; 512 * dec.size];
    let mut seen: FxHashSet<u64> = FxHashSet::default();
    loop {
        // `while subsection != 0`: the first subsection is a struct, the next ones pointers
        if subsection.is_pointer() && subsection.u64()? == 0 {
            break;
        }
        match subsection.m("ControlArea").and_then(|c| c.u64()) {
            Ok(v) if v == ca.addr => {}
            Ok(_) => break,
            Err(e) if e.is_invalid_address() => break,
            Err(e) => return Err(e),
        }
        let at = if subsection.is_pointer() { subsection.u64()? } else { subsection.addr };
        if !seen.insert(at) {
            // python would loop forever on a subsection cycle
            return Err(Error::msg("subsection list cycle"));
        }
        let mut subsection_offset = subsection.m("StartingSector")?.u64()?.wrapping_mul(sector_size);
        let ptes = subsection.m("PtesInSubsection")?.u64()?;
        if ptes > 0 {
            let base = subsection.m("SubsectionBase")?.u64()?;
            let mut i = 0u64;
            while i < ptes {
                let n = (ptes - i).min(512);
                let start = base.wrapping_add(pte.wrapping_mul(i)) & mask;
                let len = (n * pte) as usize;
                let contiguous = start.checked_add(len as u64 - 1).is_some_and(|e| e <= mask);
                let bulk = contiguous && layer.read(start, &mut buf[..len]).is_ok();
                for j in 0..n {
                    let b = if bulk {
                        &buf[(j * pte) as usize..((j + 1) * pte) as usize]
                    } else {
                        let a = base.wrapping_add(pte.wrapping_mul(i + j)) & mask;
                        layer.read(a, &mut buf[..dec.size])?;
                        &buf[..dec.size]
                    };
                    let file_offset = subsection_offset.wrapping_add((i + j).wrapping_mul(PAGE));
                    if dec.valid.get(b) == 1 {
                        out.push(((dec.hard_pfn.get(b) as u64) << 12, file_offset, PAGE));
                    } else if dec.proto.get(b) == 1 {
                        if !is_64 && !is_pae {
                            let (h, l) = dec.subsect.ok_or_else(|| Error::msg("AttributeError: Subsect"))?;
                            subsection_offset = ((h.get(b) as u64) << 7) | ((l.get(b) as u64) << 3);
                        }
                    } else if dec.trans.get(b) == 1 {
                        out.push((((dec.trans_pfn.get(b) as u64) & ((1u64 << 33) - 1)) << 12, file_offset, PAGE));
                    }
                }
                i += n;
            }
        }
        subsection = subsection.m("NextSubsection")?;
    }
    Ok(())
}

/// The pages python writes for a job and whether it reports success. `phys` is the layer the
/// control area pages are read from.
fn job_pages(job: &Job, dec: Option<&PteDecoder>, phys: LayerRef) -> (Pages, bool) {
    match job.cache {
        Cache::Data | Cache::Image => {
            let mut pages = Vec::new();
            let ok = match dec {
                Some(dec) => control_area_pages(&job.mobj, dec, &mut pages).is_ok(),
                None => {
                    // unusual _MMPTE layout: the generic (object API) port
                    let mut ok = true;
                    for p in job.mobj.get_available_pages() {
                        match p {
                            Ok(p) => pages.push(p),
                            Err(_) => ok = false,
                        }
                    }
                    ok
                }
            };
            // python's FileLayer.read raises for ranges outside the file even with pad=True
            // (padding only covers short reads): the dump stops at that page
            if phys.as_file().is_some()
                && let Some(bad) = pages.iter().position(|&(m, _, n)| !phys.is_valid(m, n))
            {
                pages.truncate(bad);
                return (pages, false);
            }
            let ok = ok && !pages.is_empty();
            (pages, ok)
        }
        Cache::Vacb => {
            // python builds the whole list first: an exception means nothing is written
            let all = job.mobj.get_available_pages();
            if all.iter().any(|p| p.is_err()) {
                return (Vec::new(), false);
            }
            let pages: Pages = all.into_iter().filter_map(|p| p.ok()).collect();
            let ok = !pages.is_empty();
            (pages, ok)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// writing

#[repr(C)]
struct IoVec {
    base: *const u8,
    len: usize,
}

unsafe extern "C" {
    fn pwritev(fd: i32, iov: *const IoVec, iovcnt: i32, offset: i64) -> isize;
}

const IOV_MAX: usize = 1024;
static ZERO: [u8; PAGE as usize] = [0; PAGE as usize];

/// Batches positional writes of contiguous file ranges into `pwritev` calls. Slices come
/// straight from the mmapped layers (`'static`); padded fallback pages live in `arena` until
/// the batch is flushed.
struct PageWriter {
    fd: i32,
    iov: Vec<IoVec>,
    start: u64,
    end: u64,
    arena: Vec<Vec<u8>>,
}

impl PageWriter {
    fn new(fd: i32) -> PageWriter {
        PageWriter { fd, iov: Vec::with_capacity(IOV_MAX), start: 0, end: 0, arena: Vec::new() }
    }

    #[inline]
    fn push(&mut self, off: u64, data: &[u8]) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if !self.iov.is_empty() && (off != self.end || self.iov.len() == IOV_MAX) {
            self.flush()?;
        }
        if self.iov.is_empty() {
            self.start = off;
            self.end = off;
        }
        if let Some(last) = self.iov.last_mut()
            && last.base.wrapping_add(last.len) == data.as_ptr()
        {
            last.len += data.len();
        } else {
            self.iov.push(IoVec { base: data.as_ptr(), len: data.len() });
        }
        self.end += data.len() as u64;
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut off = self.start;
        let mut first = 0usize;
        while first < self.iov.len() {
            let cnt = (self.iov.len() - first) as i32;
            let r = unsafe { pwritev(self.fd, self.iov[first..].as_ptr(), cnt, off as i64) };
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                self.iov.clear();
                self.arena.clear();
                return Err(e);
            }
            if r == 0 {
                self.iov.clear();
                self.arena.clear();
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            // advance past what was written (short writes)
            let mut n = r as usize;
            off += n as u64;
            while n > 0 {
                let v = &mut self.iov[first];
                if n >= v.len {
                    n -= v.len;
                    first += 1;
                } else {
                    v.base = v.base.wrapping_add(n);
                    v.len -= n;
                    n = 0;
                }
            }
        }
        self.iov.clear();
        self.arena.clear();
        Ok(())
    }

    /// python `filedata.seek(fileoffset); filedata.write(layer.read(memoffset, size, pad=True))`
    fn page(&mut self, layer: LayerRef, mem: u64, foff: u64, size: u64) -> std::io::Result<()> {
        let mut pos = 0u64;
        while pos < size {
            let m = mem.wrapping_add(pos);
            let n = (size - pos).min(PAGE - (m & (PAGE - 1)));
            let at = foff.wrapping_add(pos);
            match layer.slice(m, n as usize) {
                Some(s) => self.push(at, s)?,
                None => {
                    let mut b = vec![0u8; n as usize];
                    layer.read_padded(m, &mut b);
                    if b.iter().all(|&x| x == 0) {
                        self.push(at, &ZERO[..n as usize])?;
                    } else {
                        let p: *const u8 = b.as_ptr();
                        self.arena.push(b);
                        // the arena keeps the heap buffer alive (and unmoved) until the flush
                        self.push(at, unsafe { std::slice::from_raw_parts(p, n as usize) })?;
                    }
                }
            }
            pos += n;
        }
        Ok(())
    }
}

fn write_pages(f: &File, layer: LayerRef, pages: &Pages) -> std::io::Result<()> {
    let mut w = PageWriter::new(f.as_raw_fd());
    for &(mem, foff, size) in pages {
        w.page(layer, mem, foff, size)?;
    }
    w.flush()
}

// ---------------------------------------------------------------------------------------------
// driver

/// Create the output files in python order, then compute and write every file's pages on
/// all cores. Returns (final name, success) per created job and the error that stopped the
/// creation (python would have raised there).
fn dump_jobs(ctx: &Context, k: &WinKernel, jobs: &[Job]) -> Result<(Vec<(String, bool)>, Option<Error>)> {
    let dec = PteDecoder::new(k.table).ok();
    let mut files = Vec::with_capacity(jobs.len());
    let mut stop = None;
    {
        let _t = span("dumpfiles: create files");
        for j in jobs {
            let desired = format!("file.{:#x}.{:#x}.{}.{}.{}", j.fo, j.mobj.addr, j.cache.name(), j.base, j.cache.ext());
            match ctx.create_output_file(&desired) {
                Ok(f) => files.push(f),
                Err(e) => {
                    stop = Some(e);
                    break;
                }
            }
        }
    }
    let n = files.len();
    let pages: Vec<(Pages, bool)> = {
        let _t = span("dumpfiles: page lists");
        par::par_map(n, |i| job_pages(&jobs[i], dec.as_ref(), k.phys))
    };
    {
        let _t = span("dumpfiles: write");
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(pages[i].0.iter().map(|p| p.2).sum::<u64>()));
        let errs: Vec<Option<std::io::Error>> = par::par_map(n, |o| {
            let i = order[o];
            let layer = if jobs[i].cache == Cache::Vacb { k.vlayer } else { k.phys };
            write_pages(&files[i].0, layer, &pages[i].0).err()
        });
        if let Some(e) = errs.into_iter().flatten().next() {
            return Err(e.into());
        }
    }
    let res = files.into_iter().zip(pages).map(|((_, name), (_, ok))| (name, ok)).collect();
    Ok((res, stop))
}

/// Jobs for the unique file objects in `cands` (in order), stopping at python's first fatal
/// error. `dedupe` = python's `dumped_files` set (process path only).
fn build_jobs(cands: Vec<Step>, dedupe: bool) -> (Vec<Job>, Option<Error>) {
    let mut fos = Vec::new();
    let mut fatal = None;
    let mut dumped: FxHashSet<u64> = FxHashSet::default();
    for s in cands {
        match s {
            Step::Cand(fo) => {
                if dedupe && !dumped.insert(fo.addr) {
                    continue;
                }
                fos.push(fo);
            }
            Step::Fatal(e) => {
                fatal = Some(e);
                break;
            }
        }
    }
    let infos = {
        let _t = span("dumpfiles: process_file_object");
        par::par_map(fos.len(), |i| file_info(&fos[i]))
    };
    let mut jobs = Vec::new();
    for (fo, info) in fos.iter().zip(infos) {
        match info {
            Ok(Some((name, params))) => {
                if params.is_empty() {
                    continue;
                }
                let base = match &name {
                    Value::Str(s) => ntpath_basename(s).to_string(),
                    // ntpath.basename(UnreadableValue()) raises TypeError
                    _ => return (jobs, Some(Error::msg("TypeError: expected str, bytes or os.PathLike object, not UnreadableValue"))),
                };
                for (cache, mobj) in params {
                    jobs.push(Job { fo: fo.addr, base: base.clone(), cache, mobj });
                }
            }
            Ok(None) => {}
            Err(e) if e.is_invalid_address() => {}
            Err(e) => return (jobs, Some(e)),
        }
    }
    (jobs, fatal)
}

impl Plugin for DumpFiles {
    fn name(&self) -> &'static str {
        "windows.dumpfiles.DumpFiles"
    }
    fn description(&self) -> &'static str {
        "Dumps cached file contents from Windows memory samples."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Process ID to include (all other processes are excluded)", ReqKind::Int).optional(),
            Requirement::new("virtaddr", "Dump the _FILE_OBJECTs at the given virtual address(es)", ReqKind::ListInt).optional(),
            Requirement::new("physaddr", "Dump a single _FILE_OBJECTs at the given physical address(es)", ReqKind::ListInt).optional(),
            Requirement::new("filter", "Dump files matching regular expression FILTER", ReqKind::Str).optional(),
            Requirement::flag("ignore-case", "Ignore case in filter match"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let filter = cfg.get_str("filter").filter(|f| !f.is_empty()).map(|s| s.to_string());
        let virt = cfg.get_ints("virtaddr");
        let phys = cfg.get_ints("physaddr");
        if filter.is_some() && (!virt.is_empty() || !phys.is_empty()) {
            return Err(Error::msg("ValueError: Cannot use filter flag with an address flag"));
        }
        let k = ctx.windows_kernel()?;
        out.begin(vec![
            Column::new("Cache", ColType::Str),
            Column::new("FileObject", ColType::Hex),
            Column::new("FileName", ColType::Str),
            Column::new("Result", ColType::Str),
        ])?;
        let (jobs, fatal) = if !virt.is_empty() || !phys.is_empty() {
            let sp_v = Space::on(k.vlayer, k.table);
            let sp_p = Space::get(k.phys, k.vlayer, k.table);
            let fo_ty = k.get_type("_FILE_OBJECT")?;
            let cands = virt
                .iter()
                .map(|&a| (a, sp_v))
                .chain(phys.iter().map(|&a| (a, sp_p)))
                .map(|(a, sp)| Step::Cand(Obj::new(sp, fo_ty, a as u64)))
                .collect();
            build_jobs(cands, false)
        } else {
            let re = match &filter {
                Some(f) => {
                    let pat = if cfg.get_bool("ignore-case") { format!("(?i){f}") } else { f.clone() };
                    Some(Regex::new(&pat).map_err(|e| Error::msg(format!("re.error: {}", e.0)))?)
                }
                None => None,
            };
            let _t = span("dumpfiles: candidates");
            let type_map = crate::plugins::windows::poolscanner::get_type_map(k)?;
            let cookie = crate::plugins::windows::poolscanner::find_cookie(k)?;
            let hw = HandleWalker::new(k)?;
            let pids: Vec<i128> = cfg.get_int("pid").into_iter().collect();
            let pid_filter = super::pslist::pid_filter(&pids);
            let procs = super::pslist::list_processes(k, &pid_filter);
            let per_proc: Vec<Vec<Step>> = par::par_map(procs.len(), |i| match &procs[i] {
                Ok(p) => proc_steps(&hw, p, &type_map, cookie, re.as_ref()),
                Err(_) => Vec::new(),
            });
            let mut steps = Vec::new();
            for (p, s) in procs.into_iter().zip(per_proc) {
                match p {
                    Ok(_) => steps.extend(s),
                    Err(e) => {
                        steps.push(Step::Fatal(e));
                        break;
                    }
                }
            }
            drop(_t);
            build_jobs(steps, true)
        };
        let (results, stop) = dump_jobs(ctx, k, &jobs)?;
        for (j, (name, ok)) in jobs.iter().zip(results) {
            out.row(
                0,
                vec![
                    Value::SStr(j.cache.name()),
                    Value::Int(j.fo as i128),
                    Value::Str(j.base.clone()),
                    if ok { Value::Str(name) } else { Value::SStr("Error dumping file") },
                ],
            )?;
        }
        match stop.or(fatal) {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename() {
        assert_eq!(ntpath_basename("\\Device\\HarddiskVolume2\\Windows\\System32\\ntdll.dll"), "ntdll.dll");
        assert_eq!(ntpath_basename("\\Device\\HarddiskVolume2\\"), "");
        assert_eq!(ntpath_basename("\\Device\\Mup\\a/b.txt"), "b.txt");
        assert_eq!(ntpath_basename("x"), "x");
    }
}
