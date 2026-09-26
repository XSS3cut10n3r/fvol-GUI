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
//! 4. page lists (`get_available_pages`, control-area PTEs decoded from bulk reads) --
//!    parallel;
//! 5. one output file per row (python also commits a file for every "Error dumping file"
//!    row, holding whatever was written before the error). When no preferred name collides
//!    (all distinct, none existing) the writers create them in parallel; otherwise they are
//!    created one by one in python order, which decides the `-N` suffixes;
//! 6. pages are written largest file first with `pwritev` straight from the mmapped image
//!    (no intermediate copies). When a file's page ranges are disjoint, all-zero pages are
//!    left as holes (python's gaps are holes too): same bytes, less page-cache writeback;
//! 7. rows are emitted in order, then python's fatal error (if any) is raised.
//!
//! The run is bound by the kernel's buffered-write throughput (see the trace spans,
//! `RSVOL_TRACE=1`); everything else takes a few tens of milliseconds.

use crate::cli::regex::Regex;
use crate::plugins::windows::handles::HandleWalker;
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
use std::sync::atomic::{AtomicU64, Ordering};

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
pub fn file_pointer_target(fp: &Obj) -> Result<Obj> {
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
            Ok(e) => e.header,
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
            return Err(Error::msg(CYCLE));
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
                if out.len() > MAX_PAGES {
                    // a smeared PtesInSubsection: python would write a file of this size page
                    // by page; we refuse to hold the page list
                    return Err(Error::msg(CYCLE));
                }
            }
        }
        subsection = subsection.m("NextSubsection")?;
    }
    Ok(())
}

/// Marker of a subsection list cycle (python would loop forever) or an absurd page count:
/// reported as a dump error.
const CYCLE: &str = "subsection list cycle or absurd size";
/// 64 GiB worth of 4 KiB pages.
const MAX_PAGES: usize = 1 << 24;

/// What python's `dump_file_producer` does for one job.
struct Dump {
    /// pages written (in order) before python returned or raised
    pages: Pages,
    /// python returned the file handle (no exception, bytes written)
    ok: bool,
    /// an exception python does not catch there (it ends the plugin)
    fatal: Option<Error>,
}

/// The pages python writes for a job and whether it reports success. `phys` is the layer the
/// control area pages are read from.
fn job_pages(job: &Job, dec: Option<&PteDecoder>, phys: LayerRef) -> Dump {
    match job.cache {
        Cache::Data | Cache::Image => {
            let mut pages = Vec::new();
            let err = match dec {
                Some(dec) => control_area_pages(&job.mobj, dec, &mut pages).err(),
                // unusual _MMPTE layout: the generic (object API) port
                None => job.mobj.get_available_pages().into_iter().filter_map(|p| p.map(|p| pages.push(p)).err()).next(),
            };
            // python's FileLayer.read raises for ranges outside the file even with pad=True
            // (padding only covers short reads): the dump stops at that page
            if phys.as_file().is_some()
                && let Some(bad) = pages.iter().position(|&(m, _, n)| !phys.is_valid(m, n))
            {
                pages.truncate(bad);
                return Dump { pages, ok: false, fatal: None };
            }
            match err {
                None => {
                    let ok = !pages.is_empty();
                    Dump { pages, ok, fatal: None }
                }
                Some(e) if e.is_invalid_address() || matches!(&e, Error::Msg(m) if m == CYCLE) => Dump { pages, ok: false, fatal: None },
                Some(e) => Dump { pages, ok: false, fatal: Some(e) },
            }
        }
        Cache::Vacb => {
            // python builds the whole list first: an exception means nothing is written
            let mut all = job.mobj.get_available_pages();
            if let Some(Err(_)) = all.last() {
                let Some(Err(e)) = all.pop() else { unreachable!() };
                let fatal = if e.is_invalid_address() { None } else { Some(e) };
                return Dump { pages: Vec::new(), ok: false, fatal };
            }
            let pages: Pages = all.into_iter().filter_map(|p| p.ok()).collect();
            let ok = !pages.is_empty();
            Dump { pages, ok, fatal: None }
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
/// Writer threads: the write phase is bound by page-cache writeback throttling, more writers
/// only add filesystem lock contention.
const WRITERS: usize = 8;
static ZERO: [u8; PAGE as usize] = [0; PAGE as usize];

/// Whether `b` is all zero bytes (64 bytes per step; data pages usually exit in the first).
#[inline]
fn is_zero(b: &[u8]) -> bool {
    // SAFETY: u64 has no invalid bit patterns; align_to splits off unaligned ends
    let (pre, mid, post) = unsafe { b.align_to::<u64>() };
    if pre.iter().any(|&x| x != 0) || post.iter().any(|&x| x != 0) {
        return false;
    }
    mid.chunks(8).all(|c| c.iter().fold(0, |a, &x| a | x) == 0)
}

/// Batches positional writes of contiguous file ranges into `pwritev` calls. Slices come
/// straight from the mmapped layers (`'static`); padded fallback pages live in `arena` until
/// the batch is flushed. With `sparse` (the file's page ranges are disjoint), all-zero pages
/// are not written at all: they stay holes, which read back as the same zeros.
struct PageWriter {
    fd: i32,
    sparse: bool,
    iov: Vec<IoVec>,
    start: u64,
    end: u64,
    arena: Vec<Vec<u8>>,
    /// end of the furthest byte actually written
    written_end: u64,
    /// bytes written / pwritev calls (trace statistics)
    bytes: u64,
    calls: u64,
}

impl PageWriter {
    fn new(fd: i32, sparse: bool) -> PageWriter {
        PageWriter { fd, sparse, iov: Vec::with_capacity(IOV_MAX), start: 0, end: 0, arena: Vec::new(), written_end: 0, bytes: 0, calls: 0 }
    }

    #[inline]
    fn push(&mut self, off: u64, data: &[u8]) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if self.sparse && is_zero(data) {
            return Ok(());
        }
        self.written_end = self.written_end.max(off + data.len() as u64);
        self.ensure(off)?;
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

    /// Flush the batch unless data at `off` can extend it.
    #[inline]
    fn ensure(&mut self, off: u64) -> std::io::Result<()> {
        if !self.iov.is_empty() && (off != self.end || self.iov.len() == IOV_MAX) {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut off = self.start;
        let mut first = 0usize;
        while first < self.iov.len() {
            let cnt = (self.iov.len() - first) as i32;
            let r = unsafe { pwritev(self.fd, self.iov[first..].as_ptr(), cnt, off as i64) };
            self.calls += 1;
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
            self.bytes += n as u64;
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
            match layer.slice_bulk(m, n as usize) {
                Some(s) => self.push(at, s)?,
                None => {
                    let mut b = vec![0u8; n as usize];
                    layer.read_padded(m, &mut b);
                    if is_zero(&b) {
                        self.push(at, &ZERO[..n as usize])?;
                    } else {
                        // flush first: the arena (which keeps the heap buffer alive and unmoved
                        // until the batch is written) is cleared by every flush
                        self.ensure(at)?;
                        let p: *const u8 = b.as_ptr();
                        self.arena.push(b);
                        // SAFETY: `p` points into the buffer just moved into the arena
                        self.push(at, unsafe { std::slice::from_raw_parts(p, n as usize) })?;
                    }
                }
            }
            pos += n;
        }
        Ok(())
    }
}

/// Whether the file ranges of `pages` (in this order) are strictly ascending and disjoint.
fn ascending_disjoint<'a>(pages: impl Iterator<Item = &'a (u64, u64, u64)>) -> bool {
    let mut end = 0u64;
    for &(_, foff, size) in pages {
        if foff < end {
            return false;
        }
        end = foff.saturating_add(size);
    }
    true
}

/// Write `pages` (python order) into `f` with the exact result of python's seek+write
/// sequence: when the ranges are disjoint their order is irrelevant, so they are written in
/// file order and all-zero pages are left as holes (the file is extended to python's size);
/// overlapping ranges are written in python order, zeros included, so later pages win.
fn write_pages(f: &File, layer: LayerRef, pages: &Pages) -> std::io::Result<()> {
    let sorted;
    let (list, sparse): (&Pages, bool) = if ascending_disjoint(pages.iter()) {
        (pages, true)
    } else {
        let mut s = pages.clone();
        s.sort_by_key(|p| p.1);
        sorted = s;
        if ascending_disjoint(sorted.iter().filter(|p| p.2 > 0)) { (&sorted, true) } else { (pages, false) }
    };
    let mut w = PageWriter::new(f.as_raw_fd(), sparse);
    for &(mem, foff, size) in list {
        w.page(layer, mem, foff, size)?;
    }
    w.flush()?;
    let end = pages.iter().filter(|p| p.2 > 0).map(|p| p.1 + p.2).max().unwrap_or(0);
    if w.written_end < end {
        f.set_len(end)?;
    }
    if crate::util::trace::enabled() {
        STATS[0].fetch_add(pages.iter().map(|p| p.2).sum::<u64>(), Ordering::Relaxed);
        STATS[1].fetch_add(w.bytes, Ordering::Relaxed);
        STATS[2].fetch_add(w.calls, Ordering::Relaxed);
    }
    Ok(())
}

/// trace counters: bytes python writes, bytes we write, pwritev calls
static STATS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

// ---------------------------------------------------------------------------------------------
// driver

/// Whether none of `names` (all distinct) exists in `dir`: then python's `CLIFileHandler`
/// gives every file its preferred name whatever the creation order, so the parallel writers
/// can create them.
fn names_free(dir: &str, names: &[String]) -> bool {
    let mut uniq: FxHashSet<&str> = FxHashSet::default();
    if !names.iter().all(|n| uniq.insert(n.as_str())) {
        return false;
    }
    match std::fs::read_dir(dir) {
        Ok(entries) => entries.into_iter().all(|e| e.is_ok_and(|e| e.file_name().to_str().is_none_or(|n| !uniq.contains(n)))),
        Err(_) => false,
    }
}

/// Compute every job's pages (parallel), create the output files as python would up to the
/// first job python crashes in, write them on all cores (largest first). Returns the number
/// of jobs whose rows python prints, (final name, success) per created file, and the error
/// that ended the plugin, if any.
fn dump_jobs(ctx: &Context, k: &WinKernel, jobs: &[Job]) -> Result<(usize, Vec<(String, bool)>, Option<Error>)> {
    let mut dumps: Vec<Dump> = {
        let _t = span("dumpfiles: page lists");
        let dec = PteDecoder::new(k.table).ok();
        par::par_map(jobs.len(), |i| job_pages(&jobs[i], dec.as_ref(), k.phys))
    };
    // python opens the file of the job it crashes in, but never yields its row
    let (mut rows, create_upto, mut fatal) = match dumps.iter().position(|d| d.fatal.is_some()) {
        Some(f) => (f, f + 1, dumps[f].fatal.take()),
        None => (jobs.len(), jobs.len(), None),
    };
    let names: Vec<String> = jobs[..create_upto]
        .iter()
        .map(|j| format!("file.{:#x}.{:#x}.{}.{}.{}", j.fo, j.mobj.addr, j.cache.name(), j.base, j.cache.ext()))
        .collect();
    let dir = if ctx.opts.output_dir.is_empty() { "." } else { ctx.opts.output_dir.as_str() };
    let parallel = !names.is_empty() && std::fs::create_dir_all(dir).is_ok() && names_free(dir, &names);
    // the order-dependent case (python's `-N` collision suffixes): create one by one
    let mut files: Vec<(File, String)> = Vec::new();
    if !parallel {
        let _t = span("dumpfiles: create files");
        for name in &names {
            match ctx.create_output_file(name) {
                Ok(f) => files.push(f),
                Err(e) => {
                    rows = rows.min(files.len());
                    fatal = Some(e);
                    break;
                }
            }
        }
    }
    let n = if parallel { names.len() } else { files.len() };
    let mut final_names: Vec<String> = vec![String::new(); n];
    {
        let _t = span("dumpfiles: create + write");
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(dumps[i].pages.iter().map(|p| p.2).sum::<u64>()));
        let res: Vec<std::io::Result<String>> = par::par_map_bounded(n, WRITERS, |o| {
            let i = order[o];
            let layer = if jobs[i].cache == Cache::Vacb { k.vlayer } else { k.phys };
            if !parallel {
                write_pages(&files[i].0, layer, &dumps[i].pages)?;
                return Ok(files[i].1.clone());
            }
            let path = format!("{dir}/{}", names[i]);
            let (f, name) = match crate::cli::files::open_new(&path) {
                Ok(f) => (f, names[i].clone()),
                // someone else created it meanwhile: python would pick the next free `-N` name
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    ctx.create_output_file(&names[i]).map_err(|e| std::io::Error::other(e.to_string()))?
                }
                Err(e) => return Err(e),
            };
            write_pages(&f, layer, &dumps[i].pages)?;
            Ok(name)
        });
        for (o, r) in res.into_iter().enumerate() {
            final_names[order[o]] = r?;
        }
        if crate::util::trace::enabled() {
            let [a, b, c] = &STATS;
            eprintln!(
                "[trace] dumpfiles: {n} files (parallel create: {parallel}), python writes {} MiB, we write {} MiB in {} pwritev calls",
                a.load(Ordering::Relaxed) >> 20,
                b.load(Ordering::Relaxed) >> 20,
                c.load(Ordering::Relaxed)
            );
        }
    }
    drop(files);
    let res = final_names.into_iter().zip(dumps).map(|(name, d)| (name, d.ok)).collect();
    Ok((rows, res, fatal))
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

/// End the plugin with `e`: python exceptions that are not volatility exceptions (ValueError,
/// TypeError, re.error, the "Vad tree is too deep" RuntimeError, ...) crash python with a
/// traceback, which is a panic here; volatility exceptions are returned.
fn raise(e: Error) -> Result<()> {
    const PY: [&str; 8] = ["ValueError", "TypeError", "NameError", "RuntimeError", "re.PatternError", "AttributeError", "ZeroDivisionError", "IndexError"];
    let m = match &e {
        Error::Msg(m) | Error::Symbol(m) => m.as_str(),
        _ => "",
    };
    if m == "Vad tree is too deep" {
        panic!("RuntimeError: {m}");
    }
    if PY.iter().any(|p| m.starts_with(p)) {
        panic!("{m}");
    }
    Err(e)
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
            return raise(Error::msg("ValueError: Cannot use filter flag with an address flag"));
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
                    // re.compile(filter, re.I if ignore-case else 0)
                    match Regex::new_flags(f, cfg.get_bool("ignore-case")) {
                        Ok(r) => Some(r),
                        Err(e) => return raise(Error::msg(format!("re.PatternError: {}", e.0))),
                    }
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
        let (nrows, results, stop) = dump_jobs(ctx, k, &jobs)?;
        for (j, (name, ok)) in jobs.iter().zip(results).take(nrows) {
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
            Some(e) => raise(e),
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

    /// A memory layer whose pages >= `slice_limit` are only readable through `read` (the
    /// padded fallback path of the writer); everything past the buffer reads as zeros.
    struct MemLayer {
        data: Vec<u8>,
        slice_limit: u64,
    }

    impl crate::layers::Layer for MemLayer {
        fn name(&self) -> &str {
            "mem"
        }
        fn max_address(&self) -> u64 {
            self.data.len() as u64 - 1
        }
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let a = addr as usize;
            match self.data.get(a..a + buf.len()) {
                Some(s) => {
                    buf.copy_from_slice(s);
                    Ok(())
                }
                None => Err(Error::invalid(addr)),
            }
        }
        fn is_valid(&self, addr: u64, len: u64) -> bool {
            addr + len <= self.data.len() as u64
        }
        fn mapping(&self, _addr: u64, _len: u64, _f: &mut dyn FnMut(crate::layers::Mapping) -> bool) {}
        fn slice(&self, addr: u64, len: usize) -> Option<&[u8]> {
            if addr >= self.slice_limit {
                return None;
            }
            self.data.get(addr as usize..addr as usize + len)
        }
    }

    /// python's `seek(off); write(layer.read(mem, size, pad=True))` sequence on a fresh file.
    fn model(layer: LayerRef, pages: &Pages) -> Vec<u8> {
        let mut f: Vec<u8> = Vec::new();
        for &(mem, foff, size) in pages {
            let mut b = vec![0u8; size as usize];
            layer.read_padded(mem, &mut b);
            let end = (foff + size) as usize;
            if f.len() < end {
                f.resize(end, 0);
            }
            f[foff as usize..end].copy_from_slice(&b);
        }
        f
    }

    #[test]
    fn writer_matches_python_seek_write() {
        let mut data = vec![0u8; 64 * 0x1000];
        for (i, b) in data.iter_mut().enumerate() {
            let page = i / 0x1000;
            // pages 3, 7, 12 and 40 are all zero
            if ![3, 7, 12, 40].contains(&page) {
                *b = (i * 7 + page) as u8 | 1;
            }
        }
        let layer = crate::objects::leak_layer(std::sync::Arc::new(MemLayer { data, slice_limit: 32 * 0x1000 }));
        let p = |page: u64, foff: u64| (page * 0x1000, foff, 0x1000u64);
        let cases: Vec<Pages> = vec![
            // ascending with zero pages, holes and a trailing zero page (file extended)
            vec![p(1, 0), p(3, 0x1000), p(4, 0x3000), p(5, 0x4000), p(7, 0x9000)],
            // unordered but disjoint, fallback (non-sliceable) pages mixed in, unaligned offsets
            vec![p(35, 0x5400), p(2, 0x400), p(36, 0x6400), p(40, 0x7400), p(9, 0x1400), p(33, 0x2400)],
            // overlapping: later pages win, zeros included
            vec![p(1, 0), p(2, 0x800), p(3, 0x1000), p(34, 0x400), p(12, 0x2000), p(5, 0x2000)],
            // beyond the layer (padded zeros) at the end
            vec![p(10, 0), p(100, 0x1000)],
            // more than IOV_MAX contiguous chunks, alternating slice / fallback sources
            (0..1500u64).map(|i| p(if i % 3 == 0 { 33 + i % 20 } else { i % 30 }, i * 0x1000)).collect(),
            // a 256 KiB VACB-style page straddling the fallback boundary
            vec![(30 * 0x1000 + 0x10, 0x100, 0x40000)],
        ];
        let dir = std::env::temp_dir().join(format!("rsvol-dumpfiles-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (i, pages) in cases.iter().enumerate() {
            let path = dir.join(format!("case{i}"));
            let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
            write_pages(&f, layer, pages).unwrap();
            drop(f);
            assert!(std::fs::read(&path).unwrap() == model(layer, pages), "case {i}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn zero_check() {
        let mut b = vec![0u8; 4096 + 3];
        assert!(is_zero(&b[1..]));
        b[4096 + 2] = 1;
        assert!(!is_zero(&b[1..]));
        b[4096 + 2] = 0;
        b[1] = 1;
        assert!(!is_zero(&b[1..]));
        assert!(is_zero(&b[2..]));
    }
}
