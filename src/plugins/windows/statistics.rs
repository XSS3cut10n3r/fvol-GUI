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
//! (quadratic: ~1000 s).
//!
//! Here python's stepping runs over the list of *failures* of an aligned page-table walk, in
//! address order: every faulting entry (adjacent ones that fault the same way merged) and
//! every page whose physical data is invalid ([`Rec`]). The first failure at or after an
//! address is the next listed one (the pages before it are valid), and every step inside one
//! failure's range counts the same, so a whole range is counted at once ([`statistics`]).
//! The list is built as the stepping needs it ([`Failures::find`]): the upper levels of the
//! page tables are classified on all cores first ([`units`]), and a run of mapped parts is
//! walked on all cores in small parts when the stepping reaches it; the parts it jumps over
//! are never walked. The result is exactly the sequential walk's ([`first_failure`]).

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

/// A failure of the aligned page-table walk: `[start, end)` faults with `fail` (one entry, or a
/// run of adjacent entries that fault the same way), or is a page whose physical data is not
/// valid (`Fail::Other`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rec {
    start: u64,
    end: u64,
    fail: Fail,
}

/// Append `r`, merging it into an adjacent run of the same fault.
fn push(out: &mut Vec<Rec>, r: Rec) {
    if let Some(l) = out.last_mut()
        && l.end == r.start
        && l.fail == r.fail
        && r.fail != Fail::Other
    {
        l.end = r.end;
        return;
    }
    out.push(r);
}

/// The failures of every page and faulting entry that starts in `[s, e)`, in address order
/// (one starting before `s` belongs to the part before). Starting at `s`, the walk visits
/// exactly the pages and entries a walk from further down would.
fn walk_part(il: &IntelLayer, deps: &[std::sync::Arc<dyn Layer>], s: u64, e: u64, out: &mut Vec<Rec>) {
    let mut cur = (0u64, 0u64);
    let mut addr = s;
    while addr < e {
        let (start, end, fail) = match il.translate_cursor(addr, &mut cur) {
            Ok((phys, bits, target)) => {
                let Some(ps) = 1u64.checked_shl(bits) else { return };
                let start = addr & !(ps - 1);
                // (a page reached at its start: python checks all of it)
                let valid = start < s
                    || match target {
                        Target::Phys => il.phys().is_valid(phys, ps),
                        Target::Swap(n) => deps.get(1 + n as usize).is_some_and(|l| l.is_valid(phys, ps)),
                    };
                (start, start.saturating_add(ps), if valid { None } else { Some(Fail::Other) })
            }
            Err(f) => {
                let size = 1u64.checked_shl(f.invalid_bits).unwrap_or(0);
                let (start, end) = if size == 0 { (0, u64::MAX) } else { (addr & !(size - 1), (addr & !(size - 1)).saturating_add(size)) };
                (start, end, Some(if f.swap_offset.is_some() { Fail::Swapped(f.invalid_bits) } else { Fail::Paged(f.invalid_bits) }))
            }
        };
        if start >= s
            && let Some(fail) = fail
        {
            push(out, Rec { start, end, fail });
        }
        if end <= addr {
            return;
        }
        addr = end;
    }
}

/// A part of the address space, in address order.
#[derive(Clone, Copy, Debug)]
enum Unit {
    /// a whole entry faults: one failure
    Fault(Rec),
    /// `[s, e)` is mapped at a lower level: walked in small parts when python's loop gets there
    Mapped(u64, u64),
}

/// The layer's address space `[0, max_address]` as [`Unit`]s: cut at top-level entries (one
/// that faults as a whole is a single failure), those cut at the next level's entries and
/// classified on all cores. A mapped part is walked ([`walk_part`]) only when python's loop
/// reaches it (see [`Failures::find`]): the loop's steps skip much of the space.
fn units(il: &IntelLayer, top: u32, mid: u32) -> Vec<Unit> {
    let space = il.max_address() as u128 + 1;
    let mut mids: Vec<(u64, u64)> = Vec::new();
    let mut out: Vec<Option<Unit>> = Vec::new();
    let mut cur = (0u64, 0u64);
    let mut r: u128 = 0;
    while r < space {
        if let Err(f) = il.translate_cursor(r as u64, &mut cur)
            && f.invalid_bits >= top
        {
            // the whole entry (or more) faults: one failure (the walk jumps past everything
            // it covers, so it starts here)
            let size = 1u128 << f.invalid_bits.min(127);
            let end = ((r & !(size - 1)) + size).min(u64::MAX as u128);
            out.push(Some(Unit::Fault(Rec { start: r as u64, end: end as u64, fail: fault_of(&f) })));
            r = end.max(r + 1);
            continue;
        }
        // (spaces are at most 2^57: ends fit in u64)
        let end = (r + (1u128 << top)).min(space);
        let mut p = r;
        while p < end {
            let q = (p + (1u128 << mid)).min(end);
            mids.push((p as u64, q as u64));
            out.push(None);
            p = q;
        }
        r = end;
    }
    // the parts: a whole fault (`None`: inside the one of a part before), or mapped
    let mut classified = par_map_batched(mids.len(), |i| {
        let (s, e) = mids[i];
        match il.translate_cursor(s, &mut (0, 0)) {
            Err(f) if f.invalid_bits >= mid => {
                let size = 1u64.checked_shl(f.invalid_bits).unwrap_or(0);
                let start = if size == 0 { 0 } else { s & !(size - 1) };
                (start >= s).then(|| Unit::Fault(Rec { start, end: start.saturating_add(size), fail: fault_of(&f) }))
            }
            _ => Some(Unit::Mapped(s, e)),
        }
    })
    .into_iter();
    out.into_iter().filter_map(|u| u.or_else(|| classified.next().flatten())).collect()
}

fn fault_of(f: &crate::layers::intel::Fault) -> Fail {
    if f.swap_offset.is_some() { Fail::Swapped(f.invalid_bits) } else { Fail::Paged(f.invalid_bits) }
}

/// [`crate::util::par::par_map`] for many tiny items (most parts are a single fault): a few
/// dozen per task, not one atomic claim each. Task `b` of `k` takes items `b, b + k, ...`:
/// the costly items (dense mappings) sit together and are spread over all tasks.
fn par_map_batched<R: Send>(n: usize, f: impl Fn(usize) -> R + Sync) -> Vec<R> {
    let k = n.div_ceil(16).min(crate::util::par::threads() * 8).max(1);
    let parts = crate::util::par::par_map(k, |b| (b..n).step_by(k).map(&f).collect::<Vec<R>>());
    let mut parts: Vec<std::vec::IntoIter<R>> = parts.into_iter().map(|p| p.into_iter()).collect();
    (0..n).map(|i| parts[i % k].next().expect("batched result")).collect()
}

/// The failures of the aligned walk ([`Rec`]s in address order), found as python's loop asks
/// for them.
struct Failures<'a> {
    il: &'a IntelLayer,
    deps: Vec<std::sync::Arc<dyn Layer>>,
    units: Vec<Unit>,
    /// the first unit not looked at yet
    next_unit: usize,
    /// log2 of the small parts a mapped part is walked in
    small: u32,
    /// the failures found so far (of the units looked at)
    recs: Vec<Rec>,
}

impl Failures<'_> {
    /// Make `recs` hold the first failure that ends after `p`, if there is one: units that
    /// end at or before `p` are skipped unwalked, and a run of mapped units is walked (on all
    /// cores, in small parts, from `p` on) as a whole, since python's loop steps through all
    /// of it (inside mapped parts no failure is larger than a small part).
    fn find(&mut self, p: u64) {
        while self.recs.last().is_none_or(|r| r.end <= p) && self.next_unit < self.units.len() {
            match self.units[self.next_unit] {
                Unit::Fault(r) => {
                    if r.end > p {
                        push(&mut self.recs, r);
                    }
                    self.next_unit += 1;
                }
                Unit::Mapped(..) => {
                    let mut parts = Vec::new();
                    while let Some(&Unit::Mapped(s, e)) = self.units.get(self.next_unit) {
                        let mut first = s.max(p & !((1u64 << self.small) - 1));
                        if first > s {
                            // the page (or faulting entry) there may start in an earlier small
                            // part (a 1 GiB page): walk from where it starts
                            let bits = match self.il.translate_cursor(first, &mut (0, 0)) {
                                Ok((_, bits, _)) => bits,
                                Err(f) => f.invalid_bits,
                            };
                            let start = first & !(1u64.checked_shl(bits).unwrap_or(0).wrapping_sub(1));
                            first = start.max(s) & !((1u64 << self.small) - 1);
                        }
                        parts.extend((first..e.max(first)).step_by(1usize << self.small).map(|a| (a, (a + (1u64 << self.small)).min(e))));
                        self.next_unit += 1;
                    }
                    let (il, deps) = (self.il, &self.deps);
                    let found = par_map_batched(parts.len(), |i| {
                        let mut out = Vec::new();
                        walk_part(il, deps, parts[i].0, parts[i].1, &mut out);
                        out
                    });
                    crate::util::trace::note(|| format!("statistics: walked {} small parts from {p:#x}", parts.len()));
                    found.into_iter().flatten().filter(|r| r.end > p).for_each(|r| push(&mut self.recs, r));
                }
            }
        }
    }

    /// The first failure of the whole space (where a walk continues after the end).
    fn first(&self) -> Option<Rec> {
        match *self.units.first()? {
            Unit::Fault(r) => Some(r),
            Unit::Mapped(..) => {
                // walk until the first failure (rare: a mapped first entry and nothing to the end)
                let mut out = Vec::new();
                for u in &self.units {
                    match *u {
                        Unit::Fault(r) => return Some(r),
                        Unit::Mapped(s, e) => {
                            walk_part(self.il, &self.deps, s, e, &mut out);
                            if let Some(r) = out.first() {
                                return Some(*r);
                            }
                        }
                    }
                }
                None
            }
        }
    }
}

/// python's counters: (valid, valid large, swapped, swapped large, invalid, invalid large,
/// other invalid).
fn statistics(il: &IntelLayer) -> [i128; 7] {
    // log2 of the ranges of a top-level entry, a part, and a small part of a mapped part
    let (top, mid, small) = match il.mode() {
        PagingMode::Intel32 => (22, 22, 22),
        PagingMode::Pae => (30, 21, 21),
        PagingMode::Intel32e => (39, 30, 21),
        PagingMode::La57 => (48, 39, 30),
    };
    let units = {
        let _t = crate::util::trace::span("statistics: upper page-table levels");
        units(il, top, mid)
    };
    let _t = crate::util::trace::span("statistics: stepping");
    let mut fs = Failures { il, deps: il.dependencies(), units, next_unit: 0, small, recs: Vec::new() };
    let mut c = [0i128; 7];
    let expected: u128 = 1u128 << il.bits_per_register();
    let max = il.max_address() as u128;
    let space = max + 1;
    let mut page_addr: u128 = 0;
    // (end of the failure's range, failure) for the last lookup
    let mut cached: Option<(u128, Fail)> = None;
    // the first failure ending after `page_addr`
    let mut next = 0usize;
    let mut cur = (0u64, 0u64);
    while page_addr < max {
        let (end, fail) = match cached {
            Some((end, f)) if page_addr < end => (end, f),
            _ => {
                // what python's `mapping(page_addr, ...)` raises: the walk from `page_addr`
                // (see `first_failure`) ends at the first failure at or after it
                let p = page_addr as u64;
                fs.find(p);
                while next < fs.recs.len() && fs.recs[next].end <= p {
                    next += 1;
                }
                let found = match fs.recs.get(next) {
                    // inside a page whose data is invalid: python checks the page from `p`
                    Some(r) if r.start <= p && r.fail == Fail::Other => {
                        let (_, end, f) = first_failure(il, &fs.deps, &mut cur, p);
                        (end as u128, f)
                    }
                    // inside a faulting range, or on valid pages up to the next failure
                    Some(r) if r.fail == Fail::Other => (r.start as u128 + 1, r.fail),
                    Some(r) => (r.end as u128, r.fail),
                    // valid pages up to the end: the walk goes on at the start of the space
                    None => match fs.first() {
                        Some(r) if r.fail == Fail::Other => (r.start as u128 + space + 1, r.fail),
                        Some(r) => (r.end as u128 + space, r.fail),
                        None => (u128::MAX, Fail::Never),
                    },
                };
                cached = Some(found);
                found
            }
        };
        let (b, all, large) = match fail {
            Fail::Swapped(b) => (b, 2, 3),
            Fail::Paged(b) => (b, 4, 5),
            Fail::Other => {
                c[6] += 1;
                page_addr += expected;
                continue;
            }
            Fail::Never => break,
        };
        // every step below the range's end counts the same
        let step = 1u128 << b;
        let k = (end.min(max) - page_addr).div_ceil(step);
        c[all] += k as i128;
        if step != expected {
            c[large] += k as i128;
        }
        page_addr += k * step;
    }
    c
}

/// python's counters, by the sequential walk (the reference for [`statistics`]).
#[cfg(test)]
fn statistics_serial(il: &IntelLayer) -> [i128; 7] {
    let mut c = [0i128; 7];
    let bits = il.bits_per_register();
    let expected: u128 = 1u128 << bits;
    let max = il.max_address() as u128;
    let deps = il.dependencies();
    let mut page_addr: u128 = 0;
    // (end of the faulting entry, failure) for the last search
    let mut cached: Option<(u64, Fail)> = None;
    let mut cur = (0u64, 0u64);
    while page_addr < max {
        let p = page_addr as u64;
        let fail = match cached {
            Some((end, f)) if p < end => f,
            _ => {
                let (_, end, f) = first_failure(il, &deps, &mut cur, p);
                cached = Some((end, f));
                f
            }
        };
        let page_size: u128 = match fail {
            Fail::Swapped(b) => {
                c[2] += 1;
                let ps = 1u128 << b;
                if ps != expected {
                    c[3] += 1;
                }
                ps
            }
            Fail::Paged(b) => {
                c[4] += 1;
                let ps = 1u128 << b;
                if ps != expected {
                    c[5] += 1;
                }
                ps
            }
            Fail::Other => {
                c[6] += 1;
                expected
            }
            Fail::Never => break,
        };
        page_addr += page_size;
    }
    c
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
    use crate::layers::Mapping;
    use crate::layers::intel::PteFlavor;
    use std::sync::Arc;

    /// A physical layer backed by a Vec.
    struct Buf(Vec<u8>);
    impl Layer for Buf {
        fn name(&self) -> &str {
            "buf"
        }
        fn max_address(&self) -> u64 {
            self.0.len() as u64 - 1
        }
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let a = addr as usize;
            match self.0.get(a..a + buf.len()) {
                Some(s) => {
                    buf.copy_from_slice(s);
                    Ok(())
                }
                None => Err(crate::error::Error::invalid(addr)),
            }
        }
        fn is_valid(&self, addr: u64, len: u64) -> bool {
            addr.checked_add(len).is_some_and(|e| e <= self.0.len() as u64)
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
            f(Mapping { offset: addr, len, mapped: addr });
        }
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Random page tables for `mode` (Windows flavor: swapped and transition entries too):
    /// the physical image and the DTB. Physical memory is `phys_len` bytes; pages and tables
    /// may point beyond it.
    fn random_tables(rng: &mut Rng, mode: PagingMode, phys_len: usize, other_permille: u64) -> (Vec<u8>, u64) {
        // (index bits, large pages allowed) per level, top first; entry size
        let (levels, es): (&[(u32, bool)], usize) = match mode {
            PagingMode::Intel32 => (&[(10, true), (10, false)], 4),
            PagingMode::Pae => (&[(2, false), (9, true), (9, false)], 8),
            PagingMode::Intel32e => (&[(9, false), (9, true), (9, true), (9, false)], 8),
            PagingMode::La57 => (&[(9, false), (9, false), (9, true), (9, true), (9, false)], 8),
        };
        let mut mem = vec![0u8; phys_len];
        let mut next_table = 0x1000usize;
        let mut budget = 40usize;
        fn put(mem: &mut [u8], at: usize, es: usize, e: u64) {
            mem[at..at + es].copy_from_slice(&e.to_le_bytes()[..es]);
        }
        // the physical address bits a PTE can hold
        let pfn_bits = if es == 4 { 32 } else { 36 };
        struct Gen<'a> {
            levels: &'a [(u32, bool)],
            es: usize,
            pfn_bits: u32,
            phys_len: usize,
            other_permille: u64,
        }
        let g = Gen { levels, es, pfn_bits, phys_len, other_permille };
        fn table(rng: &mut Rng, mem: &mut Vec<u8>, g: &Gen, level: usize, next: &mut usize, budget: &mut usize) -> u64 {
            let (levels, es, pfn_bits, phys_len) = (g.levels, g.es, g.pfn_bits, g.phys_len);
            let at = *next;
            *next += 0x1000;
            let (bits, large) = levels[level];
            let last = level + 1 == levels.len();
            // bits of address covered by one entry at this level
            let cover: u32 = 12 + levels[level + 1..].iter().map(|l| l.0).sum::<u32>();
            // mostly empty tables at the top, denser below
            let density = if level == 0 && bits > 2 { 8 } else if level == 0 { 75 } else { 3 + rng.below(40) };
            for i in 0..(1usize << bits) {
                if rng.below(100) >= density {
                    // runs of the same thing are common in real tables
                    continue;
                }
                let kind = rng.below(100);
                // a page's frame: mostly inside physical memory, sometimes beyond it (python's
                // "other"); 0 (not present) when it cannot be placed
                let page = |rng: &mut Rng, align_bits: u32| -> u64 {
                    let pages = (phys_len as u64) >> align_bits;
                    if pages == 0 || rng.below(1000) < g.other_permille {
                        if g.other_permille == 0 {
                            return 0;
                        }
                        ((1u64 << pfn_bits) - ((1 + rng.below(4)) << align_bits)) & !((1 << align_bits) - 1)
                    } else {
                        rng.below(pages) << align_bits
                    }
                };
                let e: u64 = if last {
                    match kind {
                        0..=69 => page(rng, 12) | 1,
                        // transition (valid for the Windows flavor)
                        70..=79 => page(rng, 12) | (1 << 11),
                        // swapped (pagefile) entries
                        80..=89 => {
                            if es == 8 {
                                ((1 + rng.below(1000)) << 32) | 0x80
                            } else {
                                ((1 + rng.below(1000)) << 12) | 0x80
                            }
                        }
                        // not present, other bits
                        _ => rng.next() & !1 & !(1 << 11) & if es == 4 { 0xffff_ffff } else { u64::MAX },
                    }
                } else if kind < 15 && large {
                    match page(rng, cover) {
                        0 => 0,
                        p => p | 0x81,
                    }
                } else if kind < 20 {
                    // a table beyond physical memory
                    ((phys_len as u64 + 0x1000 * (1 + rng.below(8))) & !0xfff) | 1
                } else if kind < 30 && es == 8 {
                    ((1 + rng.below(1000)) << 32) | 0x80
                } else if *budget > 0 && *next + 0x1000 <= phys_len {
                    *budget -= 1;
                    table(rng, mem, g, level + 1, next, budget) | 1
                } else {
                    0
                };
                put(mem, at + i * es, es, e);
            }
            at as u64
        }
        let dtb = table(rng, &mut mem, &g, 0, &mut next_table, &mut budget);
        (mem, dtb)
    }

    /// The parallel walk + range stepping gives exactly the sequential walk's counters, on
    /// random page tables of every paging mode (holes, large pages, swapped / transition /
    /// out-of-range entries, tables beyond memory).
    #[test]
    fn parallel_equals_sequential() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for round in 0..150 {
            let mode = [PagingMode::Intel32e, PagingMode::Pae, PagingMode::Intel32, PagingMode::Intel32e, PagingMode::La57][round % 5];
            // no / rare / frequent pages beyond memory (the first one ends python's loop)
            let other = [0, 0, 1, 30, 0, 3][round % 6];
            let (mem, dtb) = random_tables(&mut rng, mode, 0x80_0000, other);
            let phys: Arc<dyn Layer> = Arc::new(Buf(mem));
            for flavor in [PteFlavor::Windows, PteFlavor::Generic] {
                let il = IntelLayer::new("t", phys.clone(), dtb, mode, flavor);
                let serial = statistics_serial(&il);
                assert_eq!(statistics(&il), serial, "round {round} {mode:?} {flavor:?}");
            }
        }
    }

    /// Hand-made corner cases: an empty space, a fully mapped first entry, invalid data at the
    /// very start and end.
    #[test]
    fn corner_cases() {
        // nothing mapped at all: every top-level entry faults
        let phys: Arc<dyn Layer> = Arc::new(Buf(vec![0u8; 0x4000]));
        for mode in [PagingMode::Intel32e, PagingMode::Pae, PagingMode::Intel32] {
            let il = IntelLayer::new("t", phys.clone(), 0x1000, mode, PteFlavor::Windows);
            assert_eq!(statistics(&il), statistics_serial(&il), "{mode:?}");
        }
        // a DTB beyond memory: the very first table read fails (one fault covers the space)
        let il = IntelLayer::new("t", phys.clone(), 0x10_0000, PagingMode::Intel32e, PteFlavor::Windows);
        assert_eq!(statistics(&il), statistics_serial(&il));
        // Intel32: PDE 0 a 4 MiB page beyond memory ("other" at address 0), PDE 1023 a table
        // of valid pages up to the end of the space (the walk wraps around)
        let mut m = vec![0u8; 0x80_0000];
        m[0x1000..0x1004].copy_from_slice(&(0xff80_0000u32 | 0x81).to_le_bytes());
        m[0x1000 + 1023 * 4..0x1000 + 1024 * 4].copy_from_slice(&(0x2000u32 | 1).to_le_bytes());
        for i in 0..1024usize {
            m[0x2000 + i * 4..0x2004 + i * 4].copy_from_slice(&((0x10_0000 + i as u32 * 0x1000) | 1).to_le_bytes());
        }
        let phys: Arc<dyn Layer> = Arc::new(Buf(m.clone()));
        let il = IntelLayer::new("t", phys, 0x1000, PagingMode::Intel32, PteFlavor::Windows);
        assert_eq!(statistics(&il), statistics_serial(&il));
        // PDE 0 valid 4 MiB page, the rest not present except PDE 1023 (valid to the end)
        m[0x1000..0x1004].copy_from_slice(&(0x40_0000u32 | 0x81).to_le_bytes());
        let phys: Arc<dyn Layer> = Arc::new(Buf(m));
        let il = IntelLayer::new("t", phys, 0x1000, PagingMode::Intel32, PteFlavor::Windows);
        assert_eq!(statistics(&il), statistics_serial(&il));
    }
}
