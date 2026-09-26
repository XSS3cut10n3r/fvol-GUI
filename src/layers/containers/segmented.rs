//! Segment-table physical layer shared by every container format.
//! Derived from Volatility 3's layers/segmented.py and layers/linear.py (Volatility Software
//! License 1.0).
//!
//! Python keeps a list of (address, mapped address, length, mapped length) tuples in the
//! order the format produced them and looks an address up with
//! `bisect_right(segments, (address, base.maximum_address))`, then walks the request segment
//! by segment (`mapping`). Two representations reproduce that exactly:
//!
//! * FAST (the normal case): when the python list is sorted by address, segments only touch
//!   or coincide (equal starts: the later one wins) and no mapped offset reaches the end of
//!   the base, python's lookup equals "the last segment starting at or before the address owns
//!   it". The list is then normalised once into a flat, sorted, non-overlapping run table,
//!   adjacent compatible runs are merged, and lookups are a last-hit check plus a binary
//!   search. A read inside one raw run is a single memcpy from the mmap.
//! * EXACT: anything else (unsorted QEMU page lists, overlapping ELF/crash segments, ...) runs
//!   python's bisect over the original list order and python's mapping loop, so even the
//!   position-dependent results python gives for such inputs are reproduced.
//!
//! Run kinds:
//!   * RAW   – linear mapping onto the lower layer (LiME, ELF, crash, VMware, Xen, raw QEMU
//!             pages, uncompressed AVML frames);
//!   * FILL  – a page filled with one byte stored in the lower layer (QEMU "compressed" pages);
//!   * BLOCK – an encoded block decoded on demand through a small thread-safe cache
//!             (snappy-compressed AVML frames).

use super::Base;
use crate::codecs::snappy;
use crate::error::{Error, Result};
use crate::layers::file::FileLayer;
use crate::layers::{Layer, Mapping};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

const KIND_MASK: u64 = 3 << 62;
const KIND_RAW: u64 = 0;
const KIND_FILL: u64 = 1 << 62;
const KIND_BLOCK: u64 = 2 << 62;
const VAL_MASK: u64 = (1 << 62) - 1;
/// Lower offset used for raw data that can never be read (out-of-range source offsets).
const UNREADABLE: u64 = VAL_MASK;

/// Static zero page returned by `slice` for zero-filled runs.
static ZEROS: [u8; 65536] = [0; 65536];

/// Where the bytes of an input segment come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Src {
    /// Linear: lower-layer offset of the segment's first byte.
    Raw(u64),
    /// Every byte equals the byte stored at lower-layer offset `at` (value `byte`).
    Fill { at: u64, byte: u8 },
    /// Encoded block (index into the block table); the segment starts at decoded offset 0.
    Block(u32),
}

/// One input segment in python list order: `(start, length, source)`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Seg {
    pub start: u64,
    pub len: u64,
    pub src: Src,
}

/// An encoded block in the lower layer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Block {
    pub off: u64,
    pub clen: u32,
    pub ulen: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Codec {
    None,
    Snappy,
}

/// Normalised run: `[start, end)` with a kind-tagged source word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Run {
    start: u64,
    end: u64,
    src: u64,
}

/// A segment in python list order (EXACT mode). `key` is python's mapped offset, which takes
/// part in the bisect comparison; `end` may exceed 2^64 in python, hence u128.
#[derive(Clone, Copy, Debug)]
struct PySeg {
    start: u64,
    end: u128,
    key: u64,
    src: u64,
}

impl PySeg {
    #[inline]
    fn run(&self) -> Run {
        Run { start: self.start, end: self.end.min(u64::MAX as u128) as u64, src: self.src }
    }
}

const CACHE_SLOTS: usize = 64;

struct Slot {
    idx: usize,
    /// Resumable decoder state: only the prefix a reader needed has been decoded.
    st: snappy::Partial,
    buf: Vec<u8>,
}

/// Direct-mapped cache of decoded blocks; one mutex per slot.
struct BlockCache {
    slots: Box<[Mutex<Slot>]>,
}

impl BlockCache {
    fn new() -> BlockCache {
        BlockCache { slots: (0..CACHE_SLOTS).map(|_| Mutex::new(Slot { idx: usize::MAX, st: snappy::Partial::default(), buf: Vec::new() })).collect() }
    }
}

pub struct SegmentedLayer {
    name: &'static str,
    lower: Arc<dyn Layer>,
    file: Option<Arc<FileLayer>>,
    /// Bytes addressable in the lower layer (python `maximum_address + 1`).
    base_len: u64,
    /// FAST mode table (empty in EXACT mode).
    runs: Box<[Run]>,
    /// EXACT mode: python's list. None in FAST mode.
    exact: Option<Box<[PySeg]>>,
    max_addr: u64,
    hint: AtomicUsize,
    blocks: Box<[Block]>,
    codec: Codec,
    cache: Option<BlockCache>,
}

/// How python reads a segment's source.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    /// Linear layers read exactly the requested sub-range from the lower layer.
    Linear,
    /// Non-linear layers (QEMU, AVML) read the whole mapped segment and then slice it: a raw
    /// segment that is not entirely inside the lower layer can never be read.
    WholeSegment,
}

impl SegmentedLayer {
    /// Build from python-ordered segments. Fails (like python) when there are none.
    pub(crate) fn new(name: &'static str, base: &Base, segs: Vec<Seg>) -> Result<SegmentedLayer> {
        Self::with_blocks(name, base, segs, Vec::new(), Codec::None, Access::Linear)
    }

    /// python's QemuSuspendLayer does not check for segments at construction: an empty layer
    /// stacks and every read fails.
    pub(crate) fn new_nonlinear_allow_empty(name: &'static str, base: &Base, segs: Vec<Seg>) -> Result<SegmentedLayer> {
        if segs.is_empty() {
            return Ok(Self::build(name, base, segs, Vec::new(), Codec::None, Access::WholeSegment, 0));
        }
        Self::with_blocks(name, base, segs, Vec::new(), Codec::None, Access::WholeSegment)
    }

    pub(crate) fn with_blocks(
        name: &'static str,
        base: &Base,
        segs: Vec<Seg>,
        blocks: Vec<Block>,
        codec: Codec,
        access: Access,
    ) -> Result<SegmentedLayer> {
        let last = match segs.last() {
            Some(s) => *s,
            None => return Err(Error::Layer(format!("{name}: no segments defined"))),
        };
        // python: maximum_address = last segment (list order) start + length - 1
        let max_addr = last.start.saturating_add(last.len).saturating_sub(1);
        Ok(Self::build(name, base, segs, blocks, codec, access, max_addr))
    }

    fn build(
        name: &'static str,
        base: &Base,
        mut segs: Vec<Seg>,
        blocks: Vec<Block>,
        codec: Codec,
        access: Access,
        max_addr: u64,
    ) -> SegmentedLayer {
        let base_len = base.len();
        let base_max = base_len as i128 - 1;
        // python's mapped offset (bisect tie-break key) and our tagged source word
        let key_src = |s: &Seg| -> (u64, u64) {
            match s.src {
                Src::Raw(off) => {
                    let whole_ok = access == Access::Linear || off.checked_add(s.len).is_some_and(|e| e <= base_len);
                    (off, if off > VAL_MASK || !whole_ok { UNREADABLE } else { off })
                }
                // python reads the fill byte at read time: an out-of-range byte makes the
                // whole page unreadable.
                Src::Fill { at, byte } => (at, if at >= base_len || at >= (1 << 54) { UNREADABLE } else { KIND_FILL | (at << 8) | byte as u64 }),
                Src::Block(i) => match blocks.get(i as usize) {
                    Some(b) => (b.off, KIND_BLOCK | i as u64),
                    None => (u64::MAX, UNREADABLE),
                },
            }
        };
        // FAST mode is exact iff python's list is sorted, segments do not partially overlap
        // and no mapped offset reaches the end of the base (which changes bisect tie-breaks).
        let fast = segs.windows(2).all(|w| {
            let (a, b) = (&w[0], &w[1]);
            b.start == a.start || (b.start > a.start && b.start as u128 >= a.start as u128 + a.len as u128)
        }) && segs.iter().all(|s| (key_src(s).0 as i128) < base_max);
        let mut runs: Vec<Run> = Vec::new();
        let mut exact = None;
        if fast {
            // sorted: the later of equal starts wins, every run ends at the next start
            segs.sort_by_key(|s| s.start); // stable, and a no-op for a sorted list
            runs.reserve(segs.len());
            for k in 0..segs.len() {
                let s = segs[k];
                let mut end = s.start.saturating_add(s.len);
                if let Some(next) = segs.get(k + 1) {
                    end = end.min(next.start);
                }
                if end <= s.start {
                    continue;
                }
                let run = Run { start: s.start, end, src: key_src(&s).1 };
                if let Some(prev) = runs.last_mut()
                    && prev.end == run.start
                    && mergeable(prev, &run)
                {
                    prev.end = run.end;
                    continue;
                }
                runs.push(run);
            }
        } else {
            exact = Some(
                segs.iter()
                    .map(|s| {
                        let (key, src) = key_src(s);
                        PySeg { start: s.start, end: s.start as u128 + s.len as u128, key, src }
                    })
                    .collect(),
            );
        }
        let cache = if blocks.is_empty() { None } else { Some(BlockCache::new()) };
        SegmentedLayer {
            name,
            lower: base.layer.clone(),
            file: base.file.clone(),
            base_len,
            runs: runs.into_boxed_slice(),
            exact,
            max_addr,
            hint: AtomicUsize::new(0),
            blocks: blocks.into_boxed_slice(),
            codec,
            cache,
        }
    }

    /// python class name of the layer ("LimeLayer", ...).
    pub fn class_name(&self) -> &'static str {
        self.name
    }

    /// Number of runs after normalisation/merging (diagnostics, tests); EXACT mode reports the
    /// python segment count.
    pub fn run_count(&self) -> usize {
        match &self.exact {
            Some(e) => e.len(),
            None => self.runs.len(),
        }
    }

    /// Whether the layer had to fall back to python-order emulation.
    pub fn is_exact_mode(&self) -> bool {
        self.exact.is_some()
    }

    // ----------------------------------------------------------------------------- FAST mode

    /// Index of the run containing `addr` (Ok) or of the first run starting after it (Err).
    #[inline(always)]
    fn find(&self, addr: u64) -> std::result::Result<usize, usize> {
        let runs = &self.runs[..];
        let h = self.hint.load(Ordering::Relaxed);
        if let Some(r) = runs.get(h)
            && addr >= r.start
        {
            if addr < r.end {
                return Ok(h);
            }
            match runs.get(h + 1) {
                None => return Err(h + 1),
                Some(r2) => {
                    if addr < r2.start {
                        return Err(h + 1);
                    }
                    if addr < r2.end {
                        self.hint.store(h + 1, Ordering::Relaxed);
                        return Ok(h + 1);
                    }
                }
            }
        }
        let i = runs.partition_point(|r| r.start <= addr);
        if i > 0 && addr < runs[i - 1].end {
            self.hint.store(i - 1, Ordering::Relaxed);
            Ok(i - 1)
        } else {
            Err(i)
        }
    }

    // ---------------------------------------------------------------------------- EXACT mode

    /// python `_find_segment` (bisect_right with the `(offset, base.maximum_address)` key).
    fn py_find(&self, segs: &[PySeg], offset: u128, next: bool) -> Option<usize> {
        let base_max = self.base_len as i128 - 1;
        let (mut lo, mut hi) = (0usize, segs.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            let s = &segs[mid];
            // key < segment  <=>  offset < start, or offset == start and base_max <= mapped
            let less = offset < s.start as u128 || (offset == s.start as u128 && base_max <= s.key as i128);
            if less {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        if next {
            return (lo < segs.len()).then_some(lo);
        }
        if lo > 0 {
            let s = &segs[lo - 1];
            if (s.start as u128) <= offset && offset < s.end {
                return Some(lo - 1);
            }
        }
        None
    }

    /// python `NonLinearlySegmentedLayer.mapping`: calls `f(chunk_start, chunk_len, segment)`;
    /// Err(first unmapped address) when a gap is hit and `ignore_errors` is false.
    fn py_mapping(
        &self,
        segs: &[PySeg],
        offset: u64,
        length: u64,
        ignore_errors: bool,
        f: &mut dyn FnMut(u64, u64, &PySeg) -> bool,
    ) -> std::result::Result<(), u64> {
        let end = offset as u128 + length as u128;
        let mut current = offset as u128;
        loop {
            let (lo, size, i) = match self.py_find(segs, current, false) {
                Some(i) => {
                    let s = &segs[i];
                    (current, s.end - current, i)
                }
                None => {
                    if !ignore_errors {
                        return Err(current.min(u64::MAX as u128) as u64);
                    }
                    let Some(i) = self.py_find(segs, current, true) else { return Ok(()) };
                    let s = &segs[i];
                    current = s.start as u128;
                    if current > end {
                        return Ok(());
                    }
                    (current, s.end - current, i)
                }
            };
            let chunk = size.min(end - lo);
            if chunk == 0 {
                // zero-length segment or end of request (python may spin here forever)
                return Ok(());
            }
            if lo > u64::MAX as u128 || !f(lo as u64, chunk.min(u64::MAX as u128) as u64, &segs[i]) {
                return Ok(());
            }
            current += chunk;
            if current >= end {
                return Ok(());
            }
        }
    }

    #[cold]
    fn exact_read(&self, segs: &[PySeg], addr: u64, buf: &mut [u8]) -> Result<()> {
        let mut bad = None;
        let r = self.py_mapping(segs, addr, buf.len() as u64, false, &mut |lo, n, s| {
            let o = (lo - addr) as usize;
            if let Err(b) = self.copy_run(&s.run(), lo, &mut buf[o..o + n as usize]) {
                bad = Some(b);
                return false;
            }
            true
        });
        match (r, bad) {
            (Err(a), _) | (_, Some(a)) => Err(Error::invalid(a)),
            _ => Ok(()),
        }
    }

    #[cold]
    fn exact_read_padded(&self, segs: &[PySeg], addr: u64, buf: &mut [u8]) {
        buf.fill(0);
        let _ = self.py_mapping(segs, addr, buf.len() as u64, true, &mut |lo, n, s| {
            let o = (lo - addr) as usize;
            self.copy_run_padded(&s.run(), lo, &mut buf[o..o + n as usize]);
            true
        });
    }

    // ------------------------------------------------------------------------------- shared

    /// Lower-layer offset for a raw run at layer address `a` (None if it overflows).
    #[inline(always)]
    fn raw_off(r: &Run, a: u64) -> Option<u64> {
        (r.src & VAL_MASK).checked_add(a - r.start)
    }

    /// Copy the bytes of run `r` starting at layer address `a` into `out` (which must not
    /// extend past the run). Err carries the first unreadable layer address.
    #[inline(always)]
    fn copy_run(&self, r: &Run, a: u64, out: &mut [u8]) -> std::result::Result<(), u64> {
        match r.src & KIND_MASK {
            KIND_RAW => {
                let lo = Self::raw_off(r, a).ok_or(a)?;
                if let Some(f) = &self.file {
                    let data = f.data();
                    if let Ok(l) = usize::try_from(lo)
                        && let Some(end) = l.checked_add(out.len())
                        && end <= data.len()
                    {
                        out.copy_from_slice(&data[l..end]);
                        return Ok(());
                    }
                    let avail = self.base_len.saturating_sub(lo).min(out.len() as u64);
                    Err(a + avail)
                } else {
                    self.lower.read(lo, out).map_err(|_| a)
                }
            }
            KIND_FILL => {
                out.fill(r.src as u8);
                Ok(())
            }
            _ => {
                let bi = (r.src & VAL_MASK) as usize;
                self.copy_block(bi, (a - r.start) as usize, out).map_err(|_| a)
            }
        }
    }

    /// Like `copy_run` but zero-fills whatever cannot be read.
    fn copy_run_padded(&self, r: &Run, a: u64, out: &mut [u8]) {
        if let Err(bad) = self.copy_run(r, a, out) {
            let good = (bad - a) as usize;
            if r.src & KIND_MASK == KIND_RAW && good > 0 {
                // copy the readable prefix (truncated file)
                let _ = self.copy_run(r, a, &mut out[..good]);
            }
            out[good..].fill(0);
        }
    }

    /// Bytes `[inner, inner + out.len())` of decoded block `bi`. Minimum work: a read of the
    /// whole block decodes straight into the caller's buffer; smaller reads decode only the
    /// prefix they need into the block's cache slot and later reads resume from there.
    fn copy_block(&self, bi: usize, inner: usize, out: &mut [u8]) -> std::result::Result<(), ()> {
        let (Some(cache), Some(b)) = (self.cache.as_ref(), self.blocks.get(bi)) else {
            return Err(());
        };
        if self.codec != Codec::Snappy {
            return Err(());
        }
        let ulen = b.ulen as usize;
        let need = inner.checked_add(out.len()).ok_or(())?;
        if need > ulen {
            return Err(());
        }
        let owned;
        let comp: &[u8] = match &self.file {
            Some(f) => f.slice(b.off, b.clen as usize).ok_or(())?,
            None => {
                let mut v = vec![0u8; b.clen as usize];
                self.lower.read(b.off, &mut v).map_err(|_| ())?;
                owned = v;
                &owned
            }
        };
        if inner == 0 && out.len() == ulen {
            return match snappy::decompress_into(comp, out) {
                Ok(n) if n == ulen => Ok(()),
                _ => Err(()),
            };
        }
        let slot = &cache.slots[bi % CACHE_SLOTS];
        let mut g = slot.lock().unwrap_or_else(PoisonError::into_inner);
        let g = &mut *g;
        if g.idx != bi {
            g.idx = usize::MAX;
            g.st = snappy::Partial::start(comp).map_err(|_| ())?;
            if g.st.ulen != ulen {
                return Err(());
            }
            if g.buf.len() < ulen {
                g.buf.resize(ulen, 0);
            }
            g.idx = bi;
        }
        if g.st.op < need
            && snappy::decompress_continue(comp, &mut g.buf[..ulen], &mut g.st, need).is_err()
        {
            g.idx = usize::MAX;
            return Err(());
        }
        out.copy_from_slice(&g.buf[inner..need]);
        Ok(())
    }

    /// Whether the whole source of `[a, e)` inside run `r` is present in the lower layer.
    fn piece_valid(&self, r: &Run, a: u64, e: u64) -> bool {
        match r.src & KIND_MASK {
            KIND_RAW => match Self::raw_off(r, a) {
                Some(lo) => lo.checked_add(e - a).is_some_and(|end| end <= self.base_len),
                None => false,
            },
            KIND_FILL => true,
            _ => match self.blocks.get((r.src & VAL_MASK) as usize) {
                Some(b) => b.off.checked_add(b.clen as u64).is_some_and(|end| end <= self.base_len),
                None => false,
            },
        }
    }

    /// Mapping entry for the part `[s, e)` of run `r` (None when its source is not present).
    #[inline]
    fn piece_mapping(&self, r: &Run, s: u64, e: u64) -> Option<Mapping> {
        match r.src & KIND_MASK {
            KIND_RAW => {
                let lo = Self::raw_off(r, s)?;
                if lo >= self.base_len {
                    return None;
                }
                Some(Mapping { offset: s, len: (e - s).min(self.base_len - lo), mapped: lo })
            }
            KIND_FILL => Some(Mapping { offset: s, len: e - s, mapped: (r.src & VAL_MASK) >> 8 }),
            _ => self.blocks.get((r.src & VAL_MASK) as usize).map(|b| Mapping { offset: s, len: e - s, mapped: b.off }),
        }
    }

    #[inline]
    fn run_slice(&self, r: &Run, addr: u64, len: usize) -> Option<&[u8]> {
        if len as u64 > r.end - addr {
            return None;
        }
        match r.src & KIND_MASK {
            KIND_RAW => {
                let lo = usize::try_from(Self::raw_off(r, addr)?).ok()?;
                self.file.as_ref()?.data().get(lo..lo.checked_add(len)?)
            }
            KIND_FILL if r.src & 0xff == 0 && len <= ZEROS.len() => Some(&ZEROS[..len]),
            _ => None,
        }
    }

    fn run_translate(&self, r: &Run, addr: u64) -> Option<(u64, u64)> {
        if r.src & KIND_MASK != KIND_RAW {
            return None;
        }
        let lo = Self::raw_off(r, addr)?;
        if lo >= self.base_len {
            return None;
        }
        Some((lo, (r.end - addr).min(self.base_len - lo)))
    }
}

#[inline]
fn mergeable(a: &Run, b: &Run) -> bool {
    match (a.src & KIND_MASK, b.src & KIND_MASK) {
        (KIND_RAW, KIND_RAW) => {
            a.src != UNREADABLE && b.src != UNREADABLE && a.src.checked_add(a.end - a.start) == Some(b.src)
        }
        (KIND_FILL, KIND_FILL) => (a.src & 0xff) == (b.src & 0xff),
        _ => false,
    }
}


impl Layer for SegmentedLayer {
    fn name(&self) -> &str {
        self.name
    }

    fn max_address(&self) -> u64 {
        self.max_addr
    }

    #[inline]
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        if let Some(segs) = &self.exact {
            return self.exact_read(segs, addr, buf);
        }
        let mut i = match self.find(addr) {
            Ok(i) => i,
            Err(_) => return Err(Error::invalid(addr)),
        };
        let n = buf.len();
        let mut done = 0usize;
        loop {
            let r = self.runs[i];
            let a = addr + done as u64;
            let take = usize::try_from(r.end - a).unwrap_or(usize::MAX).min(n - done);
            if let Err(bad) = self.copy_run(&r, a, &mut buf[done..done + take]) {
                return Err(Error::invalid(bad));
            }
            done += take;
            if done == n {
                return Ok(());
            }
            i += 1;
            let next = addr + done as u64;
            match self.runs.get(i) {
                Some(r2) if r2.start == next => {}
                _ => return Err(Error::invalid(next)),
            }
        }
    }

    fn read_padded(&self, addr: u64, buf: &mut [u8]) {
        if let Some(segs) = &self.exact {
            return self.exact_read_padded(segs, addr, buf);
        }
        let n = buf.len();
        let mut i = match self.find(addr) {
            Ok(i) | Err(i) => i,
        };
        let mut done = 0usize;
        while done < n {
            let Some(a) = addr.checked_add(done as u64) else {
                buf[done..].fill(0);
                return;
            };
            let Some(r) = self.runs.get(i) else {
                buf[done..].fill(0);
                return;
            };
            if r.start > a {
                let gap = usize::try_from(r.start - a).unwrap_or(usize::MAX).min(n - done);
                buf[done..done + gap].fill(0);
                done += gap;
                continue;
            }
            if a >= r.end {
                i += 1;
                continue;
            }
            let take = usize::try_from(r.end - a).unwrap_or(usize::MAX).min(n - done);
            let r = *r;
            self.copy_run_padded(&r, a, &mut buf[done..done + take]);
            done += take;
            i += 1;
        }
    }

    fn is_valid(&self, addr: u64, len: u64) -> bool {
        if let Some(segs) = &self.exact {
            if len == 0 {
                return self.py_find(segs, addr as u128, false).is_some();
            }
            let mut ok = true;
            let r = self.py_mapping(segs, addr, len, false, &mut |lo, n, s| {
                ok = self.piece_valid(&s.run(), lo, lo + n);
                ok
            });
            return r.is_ok() && ok;
        }
        let Ok(mut i) = self.find(addr) else {
            return false;
        };
        if len == 0 {
            return true;
        }
        let Some(end) = addr.checked_add(len) else {
            return false;
        };
        let mut a = addr;
        loop {
            let r = self.runs[i];
            let e = r.end.min(end);
            if !self.piece_valid(&r, a, e) {
                return false;
            }
            if e == end {
                return true;
            }
            i += 1;
            match self.runs.get(i) {
                Some(r2) if r2.start == e => a = e,
                _ => return false,
            }
        }
    }

    fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
        if len == 0 {
            return;
        }
        if let Some(segs) = &self.exact {
            let _ = self.py_mapping(segs, addr, len, true, &mut |lo, n, s| match self.piece_mapping(&s.run(), lo, lo + n) {
                Some(m) => f(m),
                None => true,
            });
            return;
        }
        let end = addr.saturating_add(len);
        let mut i = match self.find(addr) {
            Ok(i) | Err(i) => i,
        };
        while let Some(r) = self.runs.get(i) {
            if r.start >= end {
                break;
            }
            if let Some(m) = self.piece_mapping(r, r.start.max(addr), r.end.min(end))
                && !f(m)
            {
                return;
            }
            i += 1;
        }
    }

    fn lower(&self) -> Option<&Arc<dyn Layer>> {
        Some(&self.lower)
    }

    #[inline]
    fn slice(&self, addr: u64, len: usize) -> Option<&[u8]> {
        if let Some(segs) = &self.exact {
            let s = &segs[self.py_find(segs, addr as u128, false)?];
            return self.run_slice(&s.run(), addr, len);
        }
        let i = self.find(addr).ok()?;
        self.run_slice(&self.runs[i], addr, len)
    }

    fn translate(&self, addr: u64) -> Option<(u64, u64)> {
        if let Some(segs) = &self.exact {
            let s = &segs[self.py_find(segs, addr as u128, false)?];
            return self.run_translate(&s.run(), addr);
        }
        let i = self.find(addr).ok()?;
        self.run_translate(&self.runs[i], addr)
    }
}
