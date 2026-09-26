//! LiME physical memory images.
//! Derived from Volatility 3's layers/lime.py (Volatility Software License 1.0).
//!
//! File = sequence of 32-byte headers `<IIQQQ` (magic "EMiL", version 1, start, end
//! (inclusive), reserved) each followed by `end - start + 1` bytes of memory.

use super::segmented::{Seg, SegmentedLayer, Src};
use super::Base;
use crate::error::{Error, Result};

pub const MAGIC: u32 = 0x4C69_4D45;
pub const VERSION: u32 = 1;
const HEADER: u64 = 32;

/// python `LimeLayer._check_header`: (start, end) of the header at `offset`.
fn check_header(base: &Base, offset: u64) -> Result<(u64, u64)> {
    let h = base
        .bytes(offset, HEADER as usize)
        .map_err(|_| Error::Layer(format!("LiME: offset {offset:#x} does not exist")))?;
    let magic = u32::from_le_bytes(h[0..4].try_into().unwrap());
    let version = u32::from_le_bytes(h[4..8].try_into().unwrap());
    if magic != MAGIC {
        return Err(Error::Layer(format!("LiME: bad magic {magic:#x} at {offset:#x}")));
    }
    if version != VERSION {
        return Err(Error::Layer(format!("LiME: unexpected version {version} at {offset:#x}")));
    }
    let start = u64::from_le_bytes(h[8..16].try_into().unwrap());
    let end = u64::from_le_bytes(h[16..24].try_into().unwrap());
    Ok((start, end))
}

/// python `LimeStacker.stack`.
pub(crate) fn stack(base: &Base) -> Result<SegmentedLayer> {
    check_header(base, 0)?;
    let len = base.len();
    let mut segs = Vec::new();
    let mut maxaddr = 0u64;
    let mut offset = 0u64;
    // python: while offset < base.maximum_address
    while offset.saturating_add(1) < len {
        let (start, end) = check_header(base, offset)?;
        if start < maxaddr || end < start {
            return Err(Error::Layer(format!("LiME: bad start/end {start:#x}/{end:#x} at {offset:#x}")));
        }
        // end is inclusive; a full 2^64 segment is clamped (addresses are u64 anyway)
        let seg_len = (end - start).saturating_add(1);
        segs.push(Seg { start, len: seg_len, src: Src::Raw(offset + HEADER) });
        maxaddr = end;
        match offset.checked_add(HEADER).and_then(|o| o.checked_add(seg_len)) {
            Some(o) => offset = o,
            None => break,
        }
    }
    SegmentedLayer::new("LimeLayer", base, segs)
}
