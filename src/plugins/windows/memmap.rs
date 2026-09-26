//! windows.memmap.Memmap (python `plugins/windows/memmap.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::layers::intel::{IntelLayer, Target, TopPiece};
use crate::layers::{Layer, Mapping};
use crate::objects::LayerRef;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::pyfmt;
use crate::renderers::text::RowEncoder;
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;
use crate::util::FxHashMap;
use std::sync::OnceLock;

pub struct Memmap;

/// python `proc_layer.mapping(0x0, proc_layer.maximum_address, ignore_errors=True)` runs
/// (including runs backed by swap layers).
fn runs(layer: LayerRef) -> Vec<Mapping> {
    let mut v = Vec::new();
    layer.mapping_targets(0, layer.max_address(), &mut |m, _| {
        v.push(m);
        true
    });
    v
}

/// A process's rows: its runs (formatted by the output thread), or already formatted.
enum Rows {
    Runs(Vec<Mapping>),
    Encoded((Vec<u8>, usize)),
}

/// One memmap row (python's tuple), the file output being "Disabled".
#[inline]
fn row_values(m: &Mapping, file_offset: u64) -> [Value; 5] {
    [
        Value::Int(m.offset as i128),
        Value::Int(m.mapped as i128),
        Value::Int(m.len as i128),
        Value::Int(file_offset as i128),
        Value::SStr("Disabled"),
    ]
}

/// The process's rows (without --dump) formatted by `enc` into `out`: (bytes, row count).
fn encode_runs(layer: LayerRef, enc: &RowEncoder, mut out: Vec<u8>) -> (Vec<u8>, usize) {
    out.clear();
    let (mut n, mut file_offset) = (0usize, 0u64);
    let null = enc.is_null();
    layer.mapping_targets(0, layer.max_address(), &mut |m, _| {
        if !null {
            enc.row(&mut out, &row_values(&m, file_offset));
        }
        n += 1;
        file_offset = file_offset.wrapping_add(m.len);
        true
    });
    (out, n)
}

/// The runs of a top-level page-table piece shared by several processes (the kernel half),
/// walked once, with each run's row as a template around its "Offset in File" cell.
struct SharedPiece {
    runs: Vec<(Mapping, Target)>,
    /// per run: end of its template prefix in `pre` and suffix in `suf`
    ends: Vec<(u32, u32)>,
    pre: Vec<u8>,
    suf: Vec<u8>,
}

/// The column that differs between processes for a shared run.
const FILE_OFFSET_COL: usize = 3;

impl SharedPiece {
    fn build(il: &IntelLayer, p: &TopPiece, enc: &RowEncoder) -> SharedPiece {
        let mut runs = Vec::new();
        il.mapping_with_targets(p.start, p.len, &mut |m, t| {
            runs.push((m, t));
            true
        });
        let (mut pre, mut suf, mut ends) = (Vec::new(), Vec::new(), Vec::with_capacity(runs.len()));
        for (m, _) in &runs {
            enc.row_template(&row_values(m, 0), FILE_OFFSET_COL, &mut pre, &mut suf);
            ends.push((pre.len() as u32, suf.len() as u32));
        }
        // spare bytes after the data: `push_padded` copies short pieces with one fixed copy
        pre.extend_from_slice(&[0; PAD]);
        suf.extend_from_slice(&[0; PAD]);
        SharedPiece { runs, ends, pre, suf }
    }

    /// Run `j`'s row with `file_offset` as its "Offset in File".
    #[inline]
    fn emit(&self, out: &mut Vec<u8>, enc: &RowEncoder, j: usize, file_offset: u64) {
        let (p0, s0) = if j == 0 { (0, 0) } else { self.ends[j - 1] };
        let (p1, s1) = self.ends[j];
        push_padded(out, &self.pre, p0 as usize, p1 as usize);
        enc.cell_u64(out, FILE_OFFSET_COL, file_offset);
        push_padded(out, &self.suf, s0 as usize, s1 as usize);
    }

    /// The rows of runs `js` (file offsets counting up from `file_offset`); returns the file
    /// offset after them. The hot loop of an all-process memmap: one reservation, fixed-size
    /// copies and stores.
    fn emit_all(&self, out: &mut Vec<u8>, enc: &RowEncoder, js: std::ops::Range<usize>, mut file_offset: u64) -> u64 {
        let Some(hex) = enc.u64_cell_text(FILE_OFFSET_COL) else {
            for j in js {
                self.emit(out, enc, j, file_offset);
                file_offset = file_offset.wrapping_add(self.runs[j].0.len);
            }
            return file_offset;
        };
        if js.is_empty() {
            return file_offset;
        }
        let span = |v: &[(u32, u32)], j: usize, k: fn(&(u32, u32)) -> u32| if j == 0 { 0 } else { k(&v[j - 1]) as usize };
        let (pa, sa) = (span(&self.ends, js.start, |e| e.0), span(&self.ends, js.start, |e| e.1));
        let (pb, sb) = (self.ends[js.end - 1].0 as usize, self.ends[js.end - 1].1 as usize);
        // data + the widest cell per row + the fixed-copy overshoot
        out.reserve((pb - pa) + (sb - sa) + js.len() * 24 + 2 * PAD);
        unsafe {
            let base = out.as_mut_ptr().add(out.len());
            let mut d = base;
            let (pre, suf) = (self.pre.as_ptr(), self.suf.as_ptr());
            for j in js {
                let (p0, s0) = if j == 0 { (0, 0) } else { self.ends[j - 1] };
                let (p1, s1) = self.ends[j];
                d = copy_padded(d, pre, p0 as usize, p1 as usize, self.pre.len());
                d = d.add(if hex { pyfmt::write_0x_hex_u64(d, file_offset) } else { pyfmt::write_u64(d, file_offset) });
                d = copy_padded(d, suf, s0 as usize, s1 as usize, self.suf.len());
                file_offset = file_offset.wrapping_add(self.runs[j].0.len);
            }
            let len = out.len() + d.offset_from(base) as usize;
            out.set_len(len);
        }
        file_offset
    }
}

/// Copy `src[a..b]` (of an arena of `src_len` bytes with `PAD` spare bytes) to `dst`; returns
/// the end. Short pieces are one fixed-size `PAD`-byte copy (`dst` must have room for it).
#[inline(always)]
unsafe fn copy_padded(dst: *mut u8, src: *const u8, a: usize, b: usize, src_len: usize) -> *mut u8 {
    let n = b - a;
    unsafe {
        if n <= PAD && a + PAD <= src_len {
            std::ptr::copy_nonoverlapping(src.add(a), dst, PAD);
        } else {
            std::ptr::copy_nonoverlapping(src.add(a), dst, n);
        }
        dst.add(n)
    }
}

/// Spare bytes after a template arena's data.
const PAD: usize = 64;

/// Append `src[a..b]`: one fixed-size copy when it fits in `PAD` bytes (`src` has `PAD`
/// spare bytes after its data).
#[inline(always)]
fn push_padded(out: &mut Vec<u8>, src: &[u8], a: usize, b: usize) {
    let n = b - a;
    if n <= PAD && a + PAD <= src.len() {
        out.reserve(PAD);
        unsafe {
            let len = out.len();
            std::ptr::copy_nonoverlapping(src.as_ptr().add(a), out.as_mut_ptr().add(len), PAD);
            out.set_len(len + n);
        }
    } else {
        out.extend_from_slice(&src[a..b]);
    }
}

/// Top-level pieces that at least two processes share: built on first use by any worker.
type Shared = FxHashMap<TopPiece, OnceLock<SharedPiece>>;

/// The top-level pieces of `[0, max_address)` of every process layer that at least two
/// of them have in common.
fn shared_pieces(layers: &[Option<(i128, LayerRef)>]) -> Shared {
    let mut count: FxHashMap<TopPiece, u32> = FxHashMap::default();
    for (_, l) in layers.iter().flatten() {
        if let Some(pieces) = l.as_intel().and_then(|il| il.top_level_pieces(0, l.max_address())) {
            for p in pieces {
                *count.entry(p).or_insert(0) += 1;
            }
        }
    }
    count.into_iter().filter(|&(_, c)| c >= 2).map(|(p, _)| (p, OnceLock::new())).collect()
}

/// `encode_runs`, walking the shared pieces once for all processes and emitting their runs
/// from row templates. Runs are coalesced across piece seams exactly like `mapping()` does.
fn encode_process(layer: LayerRef, enc: &RowEncoder, shared: &Shared, mut out: Vec<u8>) -> (Vec<u8>, usize) {
    let Some(il) = layer.as_intel() else { return encode_runs(layer, enc, out) };
    let Some(pieces) = il.top_level_pieces(0, layer.max_address()) else { return encode_runs(layer, enc, out) };
    out.clear();
    let (mut n, mut file_offset) = (0usize, 0u64);
    // one row: from its template, or formatted
    let emit = |out: &mut Vec<u8>, n: &mut usize, file_offset: &mut u64, m: &Mapping, tmpl: Option<(&SharedPiece, usize)>| {
        match tmpl {
            Some((sp, j)) => sp.emit(out, enc, j, *file_offset),
            None => enc.row(out, &row_values(m, *file_offset)),
        }
        *n += 1;
        *file_offset = file_offset.wrapping_add(m.len);
    };
    // the last run so far (not emitted yet: it may merge with the next one), with its template
    let mut pending: Option<(Mapping, Target, Option<(&SharedPiece, usize)>)> = None;
    let mut own: Vec<(Mapping, Target)> = Vec::new();
    for p in &pieces {
        let (runs, sp): (&[(Mapping, Target)], Option<&SharedPiece>) = match shared.get(p) {
            Some(cell) => {
                let sp = cell.get_or_init(|| SharedPiece::build(il, p, enc));
                (&sp.runs, Some(sp))
            }
            None => {
                own.clear();
                il.mapping_with_targets(p.start, p.len, &mut |m, t| {
                    own.push((m, t));
                    true
                });
                (&own, None)
            }
        };
        let Some((&(first, first_t), rest)) = runs.split_first() else { continue };
        // the first run may continue the previous piece's last one
        if let Some((pm, pt, ptmpl)) = pending.take() {
            if pm.offset.wrapping_add(pm.len) == first.offset && pm.mapped.wrapping_add(pm.len) == first.mapped && pt == first_t {
                pending = Some((Mapping { len: pm.len + first.len, ..pm }, pt, None));
            } else {
                emit(&mut out, &mut n, &mut file_offset, &pm, ptmpl);
                pending = Some((first, first_t, sp.map(|sp| (sp, 0))));
            }
        } else {
            pending = Some((first, first_t, sp.map(|sp| (sp, 0))));
        }
        let Some((&(last, last_t), middle)) = rest.split_last() else { continue };
        // runs of one piece never merge (the piece's runs are coalesced): all but the last are
        // final as soon as the next one is seen
        if let Some((pm, _, ptmpl)) = pending.take() {
            emit(&mut out, &mut n, &mut file_offset, &pm, ptmpl);
        }
        match sp {
            Some(sp) => {
                file_offset = sp.emit_all(&mut out, enc, 1..1 + middle.len(), file_offset);
                n += middle.len();
                pending = Some((last, last_t, Some((sp, runs.len() - 1))));
            }
            None => {
                for (m, _) in middle {
                    emit(&mut out, &mut n, &mut file_offset, m, None);
                }
                pending = Some((last, last_t, None));
            }
        }
    }
    if let Some((pm, _, ptmpl)) = pending {
        emit(&mut out, &mut n, &mut file_offset, &pm, ptmpl);
    }
    (out, n)
}

#[repr(C)]
struct IoVec {
    base: *const u8,
    len: usize,
}

unsafe extern "C" {
    fn pwritev(fd: i32, iov: *const IoVec, iovcnt: i32, offset: i64) -> isize;
}

/// Whether `b` is all zero bytes (data pages usually exit on the first word).
#[inline]
fn is_zero(b: &[u8]) -> bool {
    // SAFETY: u64 has no invalid bit patterns; align_to splits off the unaligned ends
    let (pre, mid, post) = unsafe { b.align_to::<u64>() };
    pre.iter().all(|&x| x == 0) && post.iter().all(|&x| x == 0) && mid.chunks(8).all(|c| c.iter().fold(0, |a, &x| a | x) == 0)
}

/// Writes layer data into a fresh dump file at given file offsets with exactly the bytes of
/// python's `layer.read(offset, size, pad=True)` + `file.write(...)`: pages that read as
/// zeros are left as holes (which read back as the same zeros, without page-cache traffic),
/// the others go out in large `pwritev` batches straight from the mmapped image.
pub(crate) struct SparseDump<'f> {
    file: &'f std::fs::File,
    iov: Vec<IoVec>,
    /// file offsets of the pending batch
    start: u64,
    end: u64,
    /// padded reads referenced by the pending batch
    bufs: Vec<Vec<u8>>,
    /// the size python's file ends up with
    size: u64,
    written_end: u64,
}

impl<'f> SparseDump<'f> {
    const PAGE: u64 = 0x1000;
    const IOV_MAX: usize = 1024;

    pub(crate) fn new(file: &'f std::fs::File) -> SparseDump<'f> {
        SparseDump { file, iov: Vec::new(), start: 0, end: 0, bufs: Vec::new(), size: 0, written_end: 0 }
    }

    /// `layer` bytes `[mem, mem + len)` (padded) at file offset `foff`.
    pub(crate) fn range(&mut self, layer: &dyn Layer, mem: u64, len: u64, foff: u64) -> std::io::Result<()> {
        self.size = self.size.max(foff.saturating_add(len));
        let mut pos = 0u64;
        while pos < len {
            let m = mem.wrapping_add(pos);
            let n = (len - pos).min(Self::PAGE - (m & (Self::PAGE - 1)));
            let at = foff + pos;
            match layer.slice(m, n as usize) {
                Some(s) => {
                    if !is_zero(s) {
                        self.push(at, s.as_ptr(), s.len())?;
                    }
                }
                None => {
                    let mut b = vec![0u8; n as usize];
                    layer.read_padded(m, &mut b);
                    if !is_zero(&b) {
                        // the buffer must outlive the batch: flush a batch it can't extend first
                        if !self.iov.is_empty() && (at != self.end || self.iov.len() == Self::IOV_MAX) {
                            self.flush()?;
                        }
                        let p = b.as_ptr();
                        self.bufs.push(b);
                        self.push(at, p, n as usize)?;
                    }
                }
            }
            pos += n;
        }
        Ok(())
    }

    #[inline]
    fn push(&mut self, at: u64, p: *const u8, n: usize) -> std::io::Result<()> {
        if !self.iov.is_empty() && (at != self.end || self.iov.len() == Self::IOV_MAX) {
            self.flush()?;
        }
        if self.iov.is_empty() {
            self.start = at;
            self.end = at;
        }
        match self.iov.last_mut() {
            Some(last) if last.base.wrapping_add(last.len) == p => last.len += n,
            _ => self.iov.push(IoVec { base: p, len: n }),
        }
        self.end += n as u64;
        self.written_end = self.written_end.max(self.end);
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let (mut first, mut off) = (0usize, self.start);
        while first < self.iov.len() {
            let r = unsafe { pwritev(self.file.as_raw_fd(), self.iov[first..].as_ptr(), (self.iov.len() - first) as i32, off as i64) };
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                self.iov.clear();
                self.bufs.clear();
                return Err(e);
            }
            if r == 0 {
                self.iov.clear();
                self.bufs.clear();
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            // skip what was written (short writes)
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
        self.bufs.clear();
        Ok(())
    }

    /// The file is (at least) `size` bytes long, like python's after writing that many.
    pub(crate) fn set_size(&mut self, size: u64) {
        self.size = self.size.max(size);
    }

    /// Write what is pending and give the file its full size.
    pub(crate) fn finish(mut self) -> std::io::Result<()> {
        self.flush()?;
        if self.written_end < self.size {
            self.file.set_len(self.size)?;
        }
        Ok(())
    }
}

impl Plugin for Memmap {
    fn name(&self) -> &'static str {
        "windows.memmap.Memmap"
    }
    fn description(&self) -> &'static str {
        "Prints the memory map"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Process ID to include (all other processes are excluded)", ReqKind::Int).optional(),
            Requirement::flag("dump", "Extract listed memory segments"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Virtual", ColType::Hex),
            Column::new("Physical", ColType::Hex),
            Column::new("Size", ColType::Hex),
            Column::new("Offset in File", ColType::Hex),
            Column::new("File output", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let pids: Vec<i128> = cfg.get_int("pid").into_iter().collect();
        let filter = super::pslist::pid_filter(&pids);
        let dump = cfg.get_bool("dump");
        let procs = super::pslist::list_processes(k, &filter);
        // (pid, layer) per process; None = python's `continue` on InvalidAddressException
        let mut errs: Vec<Option<crate::error::Error>> = Vec::with_capacity(procs.len());
        let layers: Vec<Option<(i128, LayerRef)>> = procs
            .iter()
            .map(|p| {
                let (v, e) = match p {
                    Ok(proc) => match proc.m("UniqueProcessId").and_then(|p| p.int()).and_then(|pid| Ok((pid, proc.add_process_layer()?))) {
                        Ok(v) => (Some(v), None),
                        Err(e) if e.is_invalid_address() => (None, None),
                        Err(e) => (None, Some(e)),
                    },
                    Err(_) => (None, None),
                };
                errs.push(e);
                v
            })
            .collect();
        // walking a whole address space is independent per process: stream them in parallel
        // (bounded look-ahead), emit in python order. Without --dump the workers also format
        // the rows (the renderer's encoder), so the output thread only copies bytes.
        let enc = if dump { None } else { out.encoder() };
        let shared = if enc.is_some() { shared_pieces(&layers) } else { Shared::default() };
        let pool: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());
        let mut result: Result<()> = Ok(());
        let mut procs = procs.into_iter();
        crate::util::par::par_map_stream(
            layers.len(),
            4,
            |i| match (&layers[i], &enc) {
                (Some((_, l)), Some(enc)) => {
                    // output buffers are recycled: no fresh pages to fault in per process
                    let buf = pool.lock().unwrap_or_else(|e| e.into_inner()).pop().unwrap_or_default();
                    Rows::Encoded(encode_process(*l, enc, &shared, buf))
                }
                (Some((_, l)), None) => Rows::Runs(runs(*l)),
                (None, _) => Rows::Runs(Vec::new()),
            },
            |i, rows| {
                let r = (|| -> Result<()> {
                    procs.next().unwrap()?;
                    if let Some(e) = errs[i].take() {
                        return Err(e);
                    }
                    let Some((pid, layer)) = layers[i] else { return Ok(()) };
                    let maps = match rows {
                        Rows::Encoded((block, n)) => {
                            out.rows_encoded(&block, n)?;
                            pool.lock().unwrap_or_else(|e| e.into_inner()).push(block);
                            return Ok(());
                        }
                        Rows::Runs(maps) => maps,
                    };
                    let name = format!("pid.{pid}.dmp");
                    let file = if dump { Some(ctx.create_output_file(&name)?.0) } else { None };
                    let mut w = file.as_ref().map(SparseDump::new);
                    let mut file_offset: u64 = 0;
                    for m in maps {
                        let file_output = match w.as_mut() {
                            Some(w) => {
                                w.range(layer, m.offset, m.len, file_offset)?;
                                Value::Str(name.clone())
                            }
                            None => Value::SStr("Disabled"),
                        };
                        out.row_ref(
                            0,
                            &[
                                Value::Int(m.offset as i128),
                                Value::Int(m.mapped as i128),
                                Value::Int(m.len as i128),
                                Value::Int(file_offset as i128),
                                file_output,
                            ],
                        )?;
                        file_offset = file_offset.wrapping_add(m.len);
                    }
                    if let Some(w) = w {
                        w.finish()?;
                    }
                    Ok(())
                })();
                match r {
                    Ok(()) => true,
                    Err(e) => {
                        result = Err(e);
                        false
                    }
                }
            },
        );
        result
    }
}
