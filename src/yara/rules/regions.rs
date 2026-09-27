// Derived from Volatility 3 (Volatility Software License 1.0): the region loops of
// volatility3/framework/plugins/windows/vadyarascan.py and linux/vmayarascan.py.
//! YARA over many regions of translation layers, the engine of `windows.vadyarascan` and
//! `linux.vmayarascan`. python runs, per region, `YaraScanner(rules)(layer.read(start, size,
//! pad=True), start)` and yields the rows of one region at a time. Here:
//!
//! * regions whose padded bytes are provably identical (same size and page mappings, e.g. a
//!   DLL mapped by many processes, or unbacked reservations) are scanned once;
//! * a region is materialised in a per-worker buffer that is kept all zero outside the
//!   runs the previous region stored: only the mapped runs are copied and only the stale
//!   bytes cleared, and the string search skips the unmapped holes
//!   ([`Rules::scan_refs`] with holes). A region costs its mapped bytes, not its size;
//! * hits come back as [`HitRef`]s (16 bytes, no data copies) and stream to the caller in
//!   region order while workers run ahead only as long as the unconsumed hits stay under a
//!   memory budget: a rule matching zeros (a million hits per region and string) runs in
//!   bounded memory, like python.

use crate::error::Result;
use crate::layers::Layer;
use crate::yara::rules::{HitRef, Rules};
use std::sync::{Condvar, Mutex};

/// Regions above this size are scanned in a buffer of their own (freed afterwards) by at
/// most [`BIG_THREADS`] workers at a time; smaller ones reuse a per-worker buffer.
const BIG: usize = 64 << 20;
const BIG_THREADS: usize = 2;
/// Unconsumed hits the workers may run ahead with (bytes).
const PENDING_BUDGET: usize = 64 << 20;
/// Hits kept for later identical regions (bytes); beyond it they are rescanned.
const KEPT_BUDGET: usize = 128 << 20;

/// One region: `(layer, start, size)`.
pub type Region<'a> = (&'a dyn Layer, u64, u64);

/// Scan every region and call `emit(i, hits)` for region `i` in order, with the hit offsets
/// relative to the region start (python's `offset - start`). Stops at the first error of
/// `emit` and returns it.
pub fn scan_regions(rules: &Rules, regions: &[Region<'_>], mut emit: impl FnMut(usize, &[HitRef]) -> Result<()>) -> Result<()> {
    use crate::util::par::par_map;
    let n = regions.len();
    if n == 0 {
        return Ok(());
    }
    let sigs = par_map(n, |i| signature(regions[i]));
    let mut slot: crate::util::FxHashMap<(u64, u64, u64), usize> = crate::util::FxHashMap::default();
    let mut unique: Vec<usize> = Vec::new();
    let item_slot: Vec<usize> = sigs
        .iter()
        .enumerate()
        .map(|(i, s)| {
            *slot.entry(*s).or_insert_with(|| {
                unique.push(i);
                unique.len() - 1
            })
        })
        .collect();
    drop(slot);
    let mut last_use = vec![0usize; unique.len()];
    for (i, &s) in item_slot.iter().enumerate() {
        last_use[s] = i;
    }
    crate::util::trace::note(|| {
        let total: u64 = regions.iter().map(|r| r.2).sum();
        let distinct: u64 = unique.iter().map(|&i| regions[i].2).sum();
        format!("yara regions: {n} ({total} bytes), {} distinct ({distinct} bytes)", unique.len())
    });
    let gate = Gate::new(BIG_THREADS);
    let scan_slot = |u: usize| -> Vec<HitRef> {
        let (layer, start, size) = regions[unique[u]];
        scan_region(rules, layer, start, size, &gate)
    };
    let mut results: Vec<Option<Vec<HitRef>>> = (0..unique.len()).map(|_| None).collect();
    let mut kept = 0usize;
    let mut next = 0usize;
    let mut err = None;
    stream_ordered(unique.len(), PENDING_BUDGET, |u| scan_slot(u), weight, |u, hits| {
        results[u] = Some(hits);
        // every region up to the next one whose content is still being scanned
        while next < n && item_slot[next] <= u {
            let s = item_slot[next];
            let rescanned;
            let hits: &[HitRef] = match &results[s] {
                Some(h) => h,
                None => {
                    // dropped for the memory budget: scan again
                    rescanned = scan_slot(s);
                    &rescanned
                }
            };
            if let Err(e) = emit(next, hits) {
                err = Some(e);
                return false;
            }
            if last_use[s] == next
                && s != u
                && let Some(h) = results[s].take()
            {
                kept -= weight(&h);
            }
            next += 1;
        }
        // keep the hits for the identical regions still to come, within the budget
        if last_use[u] >= next {
            let w = results[u].as_ref().map_or(0, weight);
            if kept + w <= KEPT_BUDGET {
                kept += w;
            } else {
                results[u] = None;
            }
        } else {
            results[u] = None;
        }
        true
    });
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// `emit(hit, prepare(hit))` for every hit in order, with `prepare` (e.g. the row's
/// `LayerData` read) run on all cores for big hit lists, a bounded batch at a time.
pub fn for_each_prepared<V, P, E>(hits: &[HitRef], prepare: P, mut emit: E) -> Result<()>
where
    V: Send,
    P: Fn(&HitRef) -> V + Sync,
    E: FnMut(&HitRef, V) -> Result<()>,
{
    const BATCH: usize = 16 << 10;
    for batch in hits.chunks(BATCH) {
        if batch.len() < 512 {
            for h in batch {
                emit(h, prepare(h))?;
            }
            continue;
        }
        let vals = crate::util::par::par_map(batch.len(), |j| prepare(&batch[j]));
        for (h, v) in batch.iter().zip(vals) {
            emit(h, v)?;
        }
    }
    Ok(())
}

fn weight(h: &Vec<HitRef>) -> usize {
    64 + h.capacity() * std::mem::size_of::<HitRef>()
}

/// Identity of a region's padded bytes: its size and how its pages map (runs relative to
/// the start, with their target offsets and layers). Equal signatures mean equal bytes.
fn signature((layer, start, size): Region<'_>) -> (u64, u64, u64) {
    use std::hash::Hasher;
    let mut h1 = crate::util::fxhash::FxHasher::default();
    let mut h2 = crate::util::fxhash::FxHasher::default();
    layer.mapping_targets(start, size, &mut |m, l| {
        let id = l as *const dyn Layer as *const u8 as u64;
        for (i, v) in [m.offset.wrapping_sub(start), m.len, m.mapped, id].into_iter().enumerate() {
            h1.write_u64(v);
            h2.write_u64(v.rotate_left(17 + i as u32) ^ 0x9e37_79b9_7f4a_7c15);
        }
        true
    });
    (size, h1.finish(), h2.finish())
}

/// `rules.match(layer.read(start, size, pad=True))` as [`HitRef`]s relative to `start`.
fn scan_region(rules: &Rules, layer: &dyn Layer, start: u64, size: u64, gate: &Gate) -> Vec<HitRef> {
    let z = size as usize;
    let mut hits = Vec::new();
    if z > BIG {
        gate.enter();
        let mut w = WorkBuf::default();
        w.load(layer, start, z);
        rules.scan_refs(w.data(z), &w.holes, &mut hits);
        drop(w);
        gate.leave();
        return hits;
    }
    thread_local! {
        static BUF: std::cell::RefCell<WorkBuf> = std::cell::RefCell::new(WorkBuf::default());
    }
    BUF.with(|b| match b.try_borrow_mut() {
        Ok(mut w) => {
            w.load(layer, start, z);
            rules.scan_refs(w.data(z), &w.holes, &mut hits);
        }
        Err(_) => {
            let mut w = WorkBuf::default();
            w.load(layer, start, z);
            rules.scan_refs(w.data(z), &w.holes, &mut hits);
        }
    });
    hits
}

unsafe extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
}

/// A zero-initialised buffer: an anonymous mapping, so pages never written cost no memory
/// (they read as the kernel's zero page).
struct ZeroBuf {
    ptr: *mut u8,
    len: usize,
    heap: Vec<u8>,
}

impl ZeroBuf {
    fn new(len: usize) -> ZeroBuf {
        const PROT_RW: i32 = 1 | 2;
        const MAP_PRIVATE_ANON_NORESERVE: i32 = 0x02 | 0x20 | 0x4000;
        if len > 0 {
            // SAFETY: a fresh private anonymous mapping, released in Drop
            let p = unsafe { mmap(std::ptr::null_mut(), len, PROT_RW, MAP_PRIVATE_ANON_NORESERVE, -1, 0) };
            if p as usize != usize::MAX && !p.is_null() {
                return ZeroBuf { ptr: p, len, heap: Vec::new() };
            }
        }
        let mut heap = vec![0u8; len];
        ZeroBuf { ptr: heap.as_mut_ptr(), len, heap }
    }
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: ptr/len describe the live mapping (or `heap`'s allocation)
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
    fn as_ref(&self) -> &[u8] {
        // SAFETY: as in as_mut
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Default for ZeroBuf {
    fn default() -> ZeroBuf {
        ZeroBuf { ptr: std::ptr::NonNull::dangling().as_ptr(), len: 0, heap: Vec::new() }
    }
}

impl Drop for ZeroBuf {
    fn drop(&mut self) {
        if self.len > 0 && self.heap.is_empty() {
            // SAFETY: the mapping created in new()
            unsafe { munmap(self.ptr, self.len) };
        }
    }
}

// SAFETY: ZeroBuf owns its memory exclusively
unsafe impl Send for ZeroBuf {}

/// A region buffer that stays all zero outside `dirty` (ascending byte runs).
#[derive(Default)]
struct WorkBuf {
    buf: ZeroBuf,
    dirty: Vec<(usize, usize)>,
    runs: Vec<(usize, usize)>,
    /// The zero ranges of the last region loaded (complement of `runs`).
    holes: Vec<(usize, usize)>,
}

impl WorkBuf {
    /// `layer.read_padded(start, &mut buf[..z])`, storing only the mapped runs (the
    /// padded read's zero fill is already there), then `holes` = the unmapped ranges.
    fn load(&mut self, layer: &dyn Layer, start: u64, z: usize) {
        if self.buf.len < z {
            // a fresh mapping is all zero
            let cap = z.max(self.buf.len.saturating_mul(2)).max(1 << 20);
            let cap = if z <= BIG { cap.min(BIG) } else { z };
            self.buf = ZeroBuf::new(cap);
            self.dirty.clear();
        }
        self.runs.clear();
        let buf = self.buf.as_mut();
        let runs = &mut self.runs;
        // python's read(pad=True) of a translation layer: every mapped chunk read from the
        // layer it maps into (physical memory or a swap file), the rest zero
        layer.mapping_targets(start, z as u64, &mut |m, target| {
            let off = m.offset.wrapping_sub(start) as usize;
            if off >= z {
                return false;
            }
            let len = (m.len as usize).min(z - off);
            target.read_padded(m.mapped, &mut buf[off..off + len]);
            match runs.last_mut() {
                Some(r) if r.0 + r.1 == off => r.1 += len,
                _ => runs.push((off, len)),
            }
            true
        });
        // clear what earlier regions left outside the new runs
        let mut keep = Vec::new();
        let mut j = 0usize;
        for &(a, l) in &self.dirty {
            let e = a + l;
            let pe = e.min(z);
            let mut p = a;
            while p < pe {
                while j < self.runs.len() && self.runs[j].0 + self.runs[j].1 <= p {
                    j += 1;
                }
                match self.runs.get(j) {
                    Some(&(ra, rl)) if ra < pe => {
                        if ra > p {
                            buf[p..ra].fill(0);
                        }
                        p = p.max(ra + rl);
                    }
                    _ => {
                        buf[p..pe].fill(0);
                        p = pe;
                    }
                }
            }
            if e > z {
                keep.push((a.max(z), e - a.max(z)));
            }
        }
        self.dirty.clear();
        self.dirty.extend_from_slice(&self.runs);
        self.dirty.extend_from_slice(&keep);
        self.holes.clear();
        let mut at = 0usize;
        for &(a, l) in &self.runs {
            if a > at {
                self.holes.push((at, a - at));
            }
            at = at.max(a + l);
        }
        if at < z {
            self.holes.push((at, z - at));
        }
    }

    fn data(&self, z: usize) -> &[u8] {
        &self.buf.as_ref()[..z]
    }
}

/// A counting semaphore.
struct Gate {
    free: Mutex<usize>,
    cv: Condvar,
}

impl Gate {
    fn new(n: usize) -> Gate {
        Gate { free: Mutex::new(n.max(1)), cv: Condvar::new() }
    }
    fn enter(&self) {
        let mut f = self.free.lock().unwrap_or_else(|e| e.into_inner());
        while *f == 0 {
            f = self.cv.wait(f).unwrap_or_else(|e| e.into_inner());
        }
        *f -= 1;
    }
    fn leave(&self) {
        *self.free.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.cv.notify_one();
    }
}

/// Parallel map over `0..n` whose results reach `consume` on the calling thread in index
/// order (`consume` returns false to stop). Workers run ahead of the consumer only while the
/// finished, unconsumed results weigh at most `budget` (as measured by `weight`), so the
/// memory held is about `budget` plus one result per worker.
pub fn stream_ordered<R, F, W, C>(n: usize, budget: usize, f: F, weight: W, mut consume: C)
where
    R: Send,
    F: Fn(usize) -> R + Sync,
    W: Fn(&R) -> usize + Sync,
    C: FnMut(usize, R) -> bool,
{
    let t = crate::util::par::threads().min(n);
    if t <= 1 {
        for i in 0..n {
            if !consume(i, f(i)) {
                return;
            }
        }
        return;
    }
    struct State<R> {
        slots: Vec<Option<(R, usize)>>,
        next: usize,
        consumed: usize,
        pending: usize,
        stop: bool,
        panicked: bool,
    }
    let st = Mutex::new(State { slots: (0..n).map(|_| None).collect(), next: 0, consumed: 0, pending: 0, stop: false, panicked: false });
    let ready = Condvar::new();
    let space = Condvar::new();
    let lock = || st.lock().unwrap_or_else(|e| e.into_inner());
    let mut panicked = false;
    std::thread::scope(|s| {
        for _ in 0..t {
            s.spawn(|| {
                loop {
                    let i = {
                        let mut g = lock();
                        loop {
                            if g.stop || g.next >= n {
                                return;
                            }
                            // the item the consumer waits for is always claimed first, so
                            // waiting here while others are pending cannot deadlock
                            if g.next == g.consumed || g.pending <= budget {
                                break;
                            }
                            g = space.wait(g).unwrap_or_else(|e| e.into_inner());
                        }
                        g.next += 1;
                        g.next - 1
                    };
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(i)));
                    let mut g = lock();
                    match r {
                        Ok(r) => {
                            let w = weight(&r);
                            g.pending += w;
                            g.slots[i] = Some((r, w));
                        }
                        Err(_) => {
                            g.panicked = true;
                            g.stop = true;
                        }
                    }
                    drop(g);
                    ready.notify_all();
                    space.notify_all();
                }
            });
        }
        for i in 0..n {
            let r = {
                let mut g = lock();
                loop {
                    if let Some((r, w)) = g.slots[i].take() {
                        g.pending -= w;
                        g.consumed = i + 1;
                        break Some(r);
                    }
                    if g.panicked {
                        break None;
                    }
                    g = ready.wait(g).unwrap_or_else(|e| e.into_inner());
                }
            };
            space.notify_all();
            let Some(r) = r else {
                panicked = true;
                break;
            };
            if !consume(i, r) {
                break;
            }
        }
        lock().stop = true;
        space.notify_all();
    });
    if panicked {
        panic!("region scan worker panicked");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_ordered_in_order_with_budget() {
        let mut seen = Vec::new();
        stream_ordered(5000, 1000, |i| vec![i as u8; i % 97], |v| v.len(), |i, v| {
            assert_eq!(v.len(), i % 97);
            seen.push(i);
            true
        });
        assert_eq!(seen, (0..5000).collect::<Vec<_>>());
        // early stop
        let mut last = 0;
        stream_ordered(5000, 0, |i| i, |_| 1, |i, _| {
            last = i;
            i < 100
        });
        assert_eq!(last, 100);
    }
}
