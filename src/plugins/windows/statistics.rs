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
use crate::layers::intel::{IntelLayer, Target};
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
fn first_failure(il: &IntelLayer, deps: &[std::sync::Arc<dyn Layer>], start: u64) -> (u64, u64, Fail) {
    let space: u64 = il.max_address().wrapping_add(1);
    let mut addr = start;
    loop {
        match il.translate_raw(addr) {
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

/// python's counters: (valid, valid large, swapped, swapped large, invalid, invalid large,
/// other invalid).
fn statistics(il: &IntelLayer) -> [i128; 7] {
    let mut c = [0i128; 7];
    let bits = il.bits_per_register();
    let expected: u128 = 1u128 << bits;
    let max = il.max_address() as u128;
    let deps = il.dependencies();
    let mut page_addr: u128 = 0;
    // (end of the faulting entry, failure) for the last search
    let mut cached: Option<(u64, Fail)> = None;
    while page_addr < max {
        let p = page_addr as u64;
        let fail = match cached {
            Some((end, f)) if p < end => f,
            _ => {
                let (_, end, f) = first_failure(il, &deps, p);
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
