//! windows.statistics.Statistics (python `plugins/windows/statistics.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! python's loop is
//!
//! ```text
//! page_addr = 0; expected_page_size = 1 << layer.bits_per_register   # 2**64 on x64
//! while page_addr < layer.maximum_address:
//!     try:   list(layer.mapping(page_addr, 2 * expected_page_size))[0] ...   # never completes
//!     except Swapped/Paged/InvalidAddressException as e: count it, page_size = 1 << e.invalid_bits
//!     page_addr += page_size
//! ```
//!
//! `mapping()` without `ignore_errors` walks forward from `page_addr` until the FIRST address
//! that fails to translate (or whose physical chunk is invalid) and raises there, so every
//! iteration lands in an exception branch: "Valid pages" is always 0, every counted page is
//! "large" (1 << invalid_bits != 2**64) and the step is the size of the faulting entry, which
//! may lie far beyond `page_addr`. python re-walks the same valid run for every step inside it
//! (quadratic: ~1000 s). Here each iteration is O(1): the first failure at/after an address is
//! found by a forward page-table walk, and remembered for every later `page_addr` up to the end
//! of the faulting entry (the answer cannot change there). Each valid page is walked once.

use crate::context::Context;
use crate::error::Result;
use crate::layers::Layer;
use crate::layers::intel::{IntelLayer, PagingMode, Target};
use crate::plugins::{Config, Plugin, UnsatKind, unsatisfied_described};
use crate::renderers::{ColType, Column, RowSink, Value};

pub struct Statistics;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fail {
    /// `SwappedInvalidAddressException` with `invalid_bits`
    Swapped(u32),
    /// `PagedInvalidAddressException` with `invalid_bits`
    Paged(u32),
    /// a plain `InvalidAddressException` (physical chunk not valid)
    Other,
    /// the walk never failed (cannot happen on real page tables; python would run for ages)
    Never,
}

/// The first failure python's `mapping(addr, huge)` raises: (failing address, end of the
/// faulting entry's range, kind).
fn first_failure(il: &IntelLayer, deps: &[std::sync::Arc<dyn Layer>], cur: &mut (u64, u64), start: u64) -> (u64, u64, Fail) {
    let space: u64 = il.max_address().wrapping_add(1);
    let mut addr = start;
    loop {
        match il.translate_cursor(addr, cur) {
            Ok((phys, bits, target)) => {
                let ps = 1u64.checked_shl(bits).unwrap_or(0);
                let chunk = if ps == 0 { u64::MAX - addr } else { ps - (addr & (ps - 1)) };
                let lower: &dyn Layer = match target {
                    Target::Phys => il.phys().as_ref(),
                    Target::Swap(n) => match deps.get(1 + n as usize) {
                        Some(l) => l.as_ref(),
                        None => return (addr, addr.wrapping_add(1), Fail::Other),
                    },
                };
                if !lower.is_valid(phys, chunk) {
                    return (addr, addr.wrapping_add(1), Fail::Other);
                }
                match addr.checked_add(chunk) {
                    Some(a) => addr = a,
                    None => return (addr, u64::MAX, Fail::Never),
                }
                // python keeps going (addresses wrap inside the translation); a full lap
                // without a fault would never end in python either
                if space != 0 && addr.wrapping_sub(start) > space {
                    return (addr, u64::MAX, Fail::Never);
                }
            }
            Err(f) => {
                let size = 1u64.checked_shl(f.invalid_bits).unwrap_or(0);
                let end = if size == 0 { u64::MAX } else { (addr & !(size - 1)).saturating_add(size) };
                let kind = if f.swap_offset.is_some() { Fail::Swapped(f.invalid_bits) } else { Fail::Paged(f.invalid_bits) };
                return (addr, end, kind);
            }
        }
    }
}

/// python's loop state: the counters (valid, valid large, swapped, swapped large, invalid,
/// invalid large, other invalid) and `page_addr`.
struct Steps {
    c: [i128; 7],
    page_addr: u128,
    /// `layer.maximum_address` (the loop runs while `page_addr` is below it)
    max: u128,
    /// `expected_page_size = 1 << layer.bits_per_register`
    expected: u128,
    done: bool,
}

impl Steps {
    fn new(il: &IntelLayer) -> Steps {
        let max = il.max_address() as u128;
        Steps { c: [0; 7], page_addr: 0, max, expected: 1u128 << il.bits_per_register(), done: max == 0 }
    }

    /// `n` iterations of python's loop that all land in the exception branch of `fail`.
    fn count(&mut self, fail: Fail, n: u128) {
        let n_i = n as i128;
        match fail {
            Fail::Swapped(b) => {
                self.c[2] += n_i;
                let ps = 1u128 << b;
                if ps != self.expected {
                    self.c[3] += n_i;
                }
                self.page_addr += n * ps;
            }
            Fail::Paged(b) => {
                self.c[4] += n_i;
                let ps = 1u128 << b;
                if ps != self.expected {
                    self.c[5] += n_i;
                }
                self.page_addr += n * ps;
            }
            Fail::Other => {
                self.c[6] += 1;
                self.page_addr += self.expected;
            }
            Fail::Never => self.done = true,
        }
        if self.page_addr >= self.max {
            self.done = true;
        }
    }

    /// Every iteration from `page_addr` on whose first failure is `fail` found by one search:
    /// python gets the same answer for every `page_addr` below `end` (the end of the faulting
    /// entry, see [`first_failure`]).
    fn run(&mut self, fail: Fail, end: u128) {
        match fail {
            Fail::Swapped(b) | Fail::Paged(b) => {
                let lim = end.min(self.max);
                let n = if self.page_addr < lim { (lim - self.page_addr).div_ceil(1u128 << b) } else { 1 };
                self.count(fail, n);
            }
            _ => self.count(fail, 1),
        }
    }

    /// python's loop verbatim (one page-table search per new faulting entry) while
    /// `page_addr < until`.
    fn serial(&mut self, il: &IntelLayer, deps: &[std::sync::Arc<dyn Layer>], cur: &mut (u64, u64), until: u128) {
        // (end of the faulting entry, failure) for the last search
        let mut cached: Option<(u64, Fail)> = None;
        while !self.done && self.page_addr < until {
            let p = self.page_addr as u64;
            let fail = match cached {
                Some((end, f)) if p < end => f,
                _ => {
                    let (_, end, f) = first_failure(il, deps, cur, p);
                    cached = Some((end, f));
                    f
                }
            };
            self.count(fail, 1);
        }
    }
}

/// python's counters, one search at a time on the calling thread (the reference for
/// [`statistics`]).
#[cfg(test)]
fn statistics_serial(il: &IntelLayer) -> [i128; 7] {
    let mut st = Steps::new(il);
    st.serial(il, &il.dependencies(), &mut (0, 0), u128::MAX);
    st.c
}

/// A run of the address space as a page-table walk sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Iv {
    /// `[start, end)`: consecutive faulting entries of one kind and size (each `1 << bits`
    /// long and aligned, except where the run was cut at a chunk boundary)
    Fault { start: u64, end: u64, fail: Fail },
    /// `[start, end)`: pages that translate and whose whole page is valid in the target layer
    Valid { start: u64, end: u64 },
    /// `[start, start + len)`: (the rest of) one page that translates to `phys` in dependency
    /// `lower` (None: no such layer) where that range is not valid
    Bad { start: u64, len: u64, phys: u64, lower: Option<usize> },
}

/// Most intervals one chunk may produce; a chunk with more is finished by python's loop (keeps
/// the memory of the chunks in flight bounded).
const CHUNK_CAP: usize = 1 << 14;

/// The runs of `[start, end)` in address order (`end` = 0: to the end of the 64-bit space),
/// and where the walk stopped early (a chunk with more than `cap` runs, or a page-table answer
/// this representation does not cover); the rest is then left to python's loop.
fn walk_chunk(il: &IntelLayer, deps: &[std::sync::Arc<dyn Layer>], start: u64, end: u64, cap: usize) -> (Vec<Iv>, Option<u64>) {
    let mut v: Vec<Iv> = Vec::new();
    let mut cur = (0u64, 0u64);
    let mut a = start;
    let in_range = |a: u64| if end == 0 { a >= start } else { a < end };
    let clamp = |e: u64| if end != 0 && e > end { end } else { e };
    while in_range(a) {
        if v.len() >= cap {
            return (v, Some(a));
        }
        match il.translate_cursor(a, &mut cur) {
            Ok((phys, bits, target)) => {
                if bits >= 64 {
                    return (v, Some(a));
                }
                let ps = 1u64 << bits;
                let Some(page_end) = (a & !(ps - 1)).checked_add(ps) else { return (v, Some(a)) };
                let page_end = clamp(page_end);
                let len = page_end - a;
                let lower = match target {
                    Target::Phys => Some(0),
                    Target::Swap(n) => (1 + (n as usize) < deps.len()).then_some(1 + n as usize),
                };
                let valid = match (target, lower) {
                    (Target::Phys, _) => il.phys().is_valid(phys, len),
                    (_, Some(l)) => deps[l].is_valid(phys, len),
                    (_, None) => false,
                };
                if valid {
                    match v.last_mut() {
                        Some(Iv::Valid { end: e, .. }) if *e == a => *e = page_end,
                        _ => v.push(Iv::Valid { start: a, end: page_end }),
                    }
                } else {
                    v.push(Iv::Bad { start: a, len, phys, lower });
                }
                if page_end == 0 {
                    break;
                }
                a = page_end;
            }
            Err(f) => {
                if f.invalid_bits >= 64 {
                    return (v, Some(a));
                }
                let size = 1u64 << f.invalid_bits;
                let fail = if f.swap_offset.is_some() { Fail::Swapped(f.invalid_bits) } else { Fail::Paged(f.invalid_bits) };
                let Some(e) = (a & !(size - 1)).checked_add(size) else { return (v, Some(a)) };
                let e = clamp(e);
                match v.last_mut() {
                    Some(Iv::Fault { end: pe, fail: pf, .. }) if *pe == a && *pf == fail => *pe = e,
                    _ => v.push(Iv::Fault { start: a, end: e, fail }),
                }
                if e == 0 {
                    break;
                }
                a = e;
            }
        }
    }
    (v, None)
}

/// python's loop driven by the runs of the address space (in address order): each run is
/// consumed in O(1) (all iterations python spends inside a run of faulting entries of one kind
/// at once).
struct Replay<'a> {
    st: Steps,
    il: &'a IntelLayer,
    deps: &'a [std::sync::Arc<dyn Layer>],
    cur: (u64, u64),
    /// `page_addr` lies in translating pages before the current run: python's search from it
    /// ends at the first run that does not translate validly
    pending: bool,
}

impl Replay<'_> {
    fn feed(&mut self, iv: &Iv) {
        while !self.st.done {
            let p = self.st.page_addr;
            match *iv {
                Iv::Fault { start, end, fail } => {
                    if p >= end as u128 && !self.pending {
                        return;
                    }
                    if self.pending {
                        // the search from p stops at the entry starting this run
                        self.pending = false;
                        let b = match fail {
                            Fail::Swapped(b) | Fail::Paged(b) => b,
                            _ => unreachable!(),
                        };
                        let size = 1u128 << b;
                        let entry_end = (start as u128 & !(size - 1)) + size;
                        self.st.run(fail, entry_end);
                    } else {
                        // p inside the run: each iteration lands in an entry of this run
                        self.st.run(fail, end as u128);
                    }
                }
                Iv::Valid { end, .. } => {
                    if self.pending || p < end as u128 {
                        self.pending = true;
                    }
                    return;
                }
                Iv::Bad { start, len, phys, lower } => {
                    if !self.pending && p >= start as u128 + len as u128 {
                        return;
                    }
                    let other = if self.pending || p == start as u128 {
                        true
                    } else {
                        // python's search from p checks the rest of the page from p on
                        let off = (p - start as u128) as u64;
                        !lower.is_some_and(|l| {
                            let layer: &dyn Layer = if l == 0 { self.il.phys().as_ref() } else { self.deps[l].as_ref() };
                            layer.is_valid(phys.wrapping_add(off), len - off)
                        })
                    };
                    if other {
                        self.pending = false;
                        self.st.count(Fail::Other, 1);
                    } else {
                        self.pending = true;
                    }
                    return;
                }
            }
        }
    }

    /// The runs of the chunk `[start, end)` (`stop`: the runs end there, python's loop covers
    /// the rest of the chunk).
    fn chunk(&mut self, ivs: &[Iv], stop: Option<u64>, end: u64) {
        for iv in ivs {
            if self.st.done {
                return;
            }
            self.feed(iv);
        }
        if stop.is_some() && !self.st.done {
            let until = if end == 0 { u128::MAX } else { end as u128 };
            self.st.serial(self.il, self.deps, &mut self.cur, until);
            self.pending = false;
        }
    }

    /// After the last run: a pending search walks past the end of the address space (the
    /// translation wraps), exactly as python's does.
    fn finish(&mut self) {
        if !self.st.done {
            self.st.serial(self.il, self.deps, &mut self.cur, u128::MAX);
        }
    }
}

/// (log2 of the top-level entry size, log2 of the work chunk size) of a paging mode. Chunks
/// are at least as large (and as aligned) as the largest page.
fn chunk_bits(mode: PagingMode) -> (u32, u32) {
    match mode {
        PagingMode::Intel32 => (22, 26),
        PagingMode::Pae => (30, 26),
        PagingMode::Intel32e => (39, 30),
        PagingMode::La57 => (48, 39),
    }
}

/// python's counters: (valid, valid large, swapped, swapped large, invalid, invalid large,
/// other invalid). The address space is cut into chunks whose runs are found in parallel
/// (top-level entries that do not translate are one chunk each); python's sequential stepping
/// then consumes the runs in order on this thread.
fn statistics(il: &IntelLayer) -> [i128; 7] {
    let (top_bits, ch_bits) = chunk_bits(il.mode());
    statistics_with(il, top_bits, ch_bits, CHUNK_CAP)
}

/// [`statistics`] with explicit top-level entry / chunk sizes (log2) and per-chunk run cap.
fn statistics_with(il: &IntelLayer, top_bits: u32, ch_bits: u32, cap: usize) -> [i128; 7] {
    let deps = il.dependencies();
    let region_bits = top_bits.max(ch_bits);
    let space: u128 = il.max_address() as u128 + 1;
    // the chunks: (start, end) with end 0 = the end of the 64-bit space
    let mut chunks: Vec<(u64, u64)> = Vec::new();
    let mut cur = (0u64, 0u64);
    let mut a: u128 = 0;
    while a < space {
        let r_end = (a + (1u128 << region_bits)).min(space);
        let whole = matches!(il.translate_cursor(a as u64, &mut cur), Err(f) if f.invalid_bits >= region_bits && f.invalid_bits < 64);
        let step: u128 = if whole { r_end - a } else { 1u128 << ch_bits };
        let mut s = a;
        while s < r_end {
            let e = (s + step).min(r_end);
            chunks.push((s as u64, e as u64));
            s = e;
        }
        a = r_end;
    }
    let mut rp = Replay { st: Steps::new(il), il, deps: &deps, cur: (0, 0), pending: false };
    let lookahead = crate::util::par::threads() * 4;
    crate::util::par::par_map_stream(
        chunks.len(),
        lookahead,
        |i| walk_chunk(il, &deps, chunks[i].0, chunks[i].1, cap),
        |i, (ivs, stop)| {
            rp.chunk(&ivs, stop, chunks[i].1);
            !rp.st.done
        },
    );
    rp.finish();
    rp.st.c
}

impl Plugin for Statistics {
    fn name(&self) -> &'static str {
        "windows.statistics.Statistics"
    }
    fn description(&self) -> &'static str {
        "Lists statistics about the memory space."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Valid pages (all)", ColType::Int),
            Column::new("Valid pages (large)", ColType::Int),
            Column::new("Swapped Pages (all)", ColType::Int),
            Column::new("Swapped Pages (large)", ColType::Int),
            Column::new("Invalid Pages (all)", ColType::Int),
            Column::new("Invalid Pages (large)", ColType::Int),
            Column::new("Other Invalid Pages (all)", ColType::Int),
        ])?;
        // python's requirement is a translation layer "primary" (python's automagic only
        // satisfies it with the Windows stacker; Linux / Mac images are unsatisfied)
        let il: &IntelLayer = match ctx.windows_kernel() {
            Ok(k) => k.layer,
            Err(e) if matches!(e, crate::error::Error::Unsatisfied(_)) => {
                return Err(unsatisfied_described(&[("primary", UnsatKind::Layer, "Memory layer for the kernel")]));
            }
            Err(e) => return Err(e),
        };
        let c = statistics(il);
        out.row(0, c.iter().map(|v| Value::Int(*v)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Context, GlobalOptions};

    /// The chunked / replayed counters equal python's sequential loop on the test images, also
    /// with tiny chunks and run caps (every chunk finished by the sequential fallback, pending
    /// searches crossing chunk boundaries).
    #[test]
    #[ignore]
    fn parallel_statistics_match_sequential_loop() {
        let imgs = [
            ("/home/user/cbc2/task2/memory-dirty.raw", None),
            ("/home/user/rs-vol/testdata/images/windows/rsvol-win10-x64-17763-imagery.raw", None),
            ("/home/user/rs-vol/testdata/images/windows/memlabs-lab0-win7sp1-x86.raw", Some("/home/user/rs-vol/testdata/symbols")),
            ("/home/user/rs-vol/testdata/images/windows/synth-memlabs-lab0-win7sp1-x86-bitmap.dmp", Some("/home/user/rs-vol/testdata/symbols")),
        ];
        for (img, sym) in imgs {
            if !std::path::Path::new(img).exists() {
                continue;
            }
            let mut o = GlobalOptions { file: Some(img.into()), ..Default::default() };
            if let Some(s) = sym {
                o.symbol_dirs = vec![s.into()];
            }
            let ctx = Context::new(o).unwrap();
            let il = ctx.windows_kernel().unwrap().layer;
            let want = statistics_serial(il);
            assert_eq!(statistics(il), want, "{img}");
            let (top, ch) = chunk_bits(il.mode());
            // chunks never split a page: at least the largest page size
            let page = match il.mode() {
                PagingMode::Intel32 => 22,
                PagingMode::Pae => 21,
                _ => 30,
            };
            for (t, c, cap) in [(top, ch, 1), (top, ch, 3), (ch, ch, 5), (top, page, 1 << 14), (top, page, 2)] {
                assert_eq!(statistics_with(il, t, c, cap), want, "{img} top {t} chunk {c} cap {cap}");
            }
            println!("{img}: {want:?}");
        }
    }
}
