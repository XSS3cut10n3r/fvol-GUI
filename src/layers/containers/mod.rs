//! Container format layers (LiME / ELF / crash dump / VMware / QEMU / AVML / Xen ...).
//! STUB (core agent) -- replaced wholesale by the formats agent at merge.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
// TEMPORARY (core sub-agent): replaced by the formats agent at merge.
// Minimal python-faithful `Elf64Layer` (python `layers/elf.py`, PT_LOAD segments) and `LimeLayer`
// (python `layers/lime.py`) on a shared `SegmentedLayer` (python `layers/segmented.py`), so the
// Linux test images (QEMU `dump-guest-memory` ELF cores and LiME dumps) can be read.

use super::{FileLayer, Layer, Mapping};
use crate::error::{Error, Result};
use std::sync::Arc;

/// Stack container layers on the input file (python container stackers, stack_order 10).
/// Returns the file layer itself when no container format is recognised.
pub fn stack(file: Arc<FileLayer>) -> Result<Arc<dyn Layer>> {
    if let Some(l) = SegmentedLayer::lime(&file) {
        return Ok(Arc::new(l));
    }
    if let Some(l) = SegmentedLayer::elf64(&file) {
        return Ok(Arc::new(l));
    }
    Ok(file)
}

/// One segment (python `(address, mapped address, length, mapped_length)`; length ==
/// mapped_length for the linear layers here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub addr: u64,
    pub mapped: u64,
    pub len: u64,
}

/// python `SegmentedLayer` (linear, `_track_offset = True`) over the file layer.
pub struct SegmentedLayer {
    class: &'static str,
    file: Arc<FileLayer>,
    base: Arc<dyn Layer>,
    /// In python list order (python never sorts them; `bisect` assumes they are).
    segs: Vec<Segment>,
    base_max: u64,
}

impl SegmentedLayer {
    fn new(class: &'static str, file: &Arc<FileLayer>, segs: Vec<Segment>) -> Option<SegmentedLayer> {
        if segs.is_empty() {
            return None;
        }
        Some(SegmentedLayer { class, file: file.clone(), base: file.clone(), segs, base_max: file.max_address() })
    }

    /// python `LimeStacker.stack` + `LimeLayer._load_segments` (None = python raised).
    pub fn lime(file: &Arc<FileLayer>) -> Option<SegmentedLayer> {
        const MAGIC: u32 = 0x4C69_4D45;
        const HDR: u64 = 32;
        let data = file.data();
        let header = |off: u64| -> Option<(u64, u64)> {
            let o = usize::try_from(off).ok()?;
            let h = data.get(o..o.checked_add(HDR as usize)?)?;
            let magic = u32::from_le_bytes(h[0..4].try_into().unwrap());
            let version = u32::from_le_bytes(h[4..8].try_into().unwrap());
            if magic != MAGIC || version != 1 {
                return None;
            }
            Some((u64::from_le_bytes(h[8..16].try_into().unwrap()), u64::from_le_bytes(h[16..24].try_into().unwrap())))
        };
        header(0)?;
        let base_max = file.max_address();
        let (mut maxaddr, mut offset) = (0u64, 0u64);
        let mut segs = Vec::new();
        while offset < base_max {
            let (start, end) = header(offset)?;
            if start < maxaddr || end < start {
                return None;
            }
            let len = (end - start).checked_add(1)?;
            segs.push(Segment { addr: start, mapped: offset + HDR, len });
            maxaddr = end;
            offset = offset.checked_add(HDR)?.checked_add(len)?;
        }
        SegmentedLayer::new("LimeLayer", file, segs)
    }

    /// python `Elf64Stacker.stack` + `Elf64Layer._load_segments` (None = python raised or
    /// declined).
    pub fn elf64(file: &Arc<FileLayer>) -> Option<SegmentedLayer> {
        let data = file.data();
        let h = data.get(..7)?;
        if u32::from_le_bytes(h[0..4].try_into().unwrap()) != 0x464C_457F || h[4] != 2 {
            return None;
        }
        let mask = file.address_mask();
        let rd = |off: u64, n: usize| -> Option<u64> {
            let o = usize::try_from(off & mask).ok()?;
            let b = data.get(o..o.checked_add(n)?)?;
            let mut v = [0u8; 8];
            v[..n].copy_from_slice(b);
            Some(u64::from_le_bytes(v))
        };
        let phoff = rd(32, 8)?;
        let phentsize = rd(54, 2)?;
        let phnum = rd(56, 2)?;
        let mut segs = Vec::new();
        for i in 0..phnum {
            let ph = phoff.wrapping_add(i * phentsize);
            let p_type = rd(ph, 4)?;
            let filesz = rd(ph.wrapping_add(32), 8)?;
            let memsz = rd(ph.wrapping_add(40), 8)?;
            if p_type == 1 && filesz == memsz && filesz > 0 {
                segs.push(Segment { addr: rd(ph.wrapping_add(24), 8)?, mapped: rd(ph.wrapping_add(8), 8)?, len: memsz });
            }
        }
        SegmentedLayer::new("Elf64Layer", file, segs)
    }

    /// The segments (python `_segments`).
    pub fn segments(&self) -> &[Segment] {
        &self.segs
    }

    /// python `bisect_right(self._segments, (offset, base_max))`.
    fn bisect(&self, offset: u64) -> usize {
        let (mut lo, mut hi) = (0usize, self.segs.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            let s = &self.segs[mid];
            // (offset, base_max) < (addr, mapped, len, mapped_len)
            let less = offset < s.addr || (offset == s.addr && self.base_max <= s.mapped);
            if less {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        lo
    }

    /// python `_find_segment(offset)`.
    #[inline]
    fn find(&self, offset: u64) -> Option<&Segment> {
        let i = self.bisect(offset);
        if i == 0 {
            return None;
        }
        let s = &self.segs[i - 1];
        if s.addr <= offset && (offset as u128) < s.addr as u128 + s.len as u128 { Some(s) } else { None }
    }

    /// python `_find_segment(offset, next=True)`.
    fn find_next(&self, offset: u64) -> Option<&Segment> {
        self.segs.get(self.bisect(offset))
    }

    /// python `mapping(offset, length, ignore_errors)`: runs (offset, len, mapped); with
    /// `ignore_errors == false` a gap returns `Err(first unmapped offset)`. Zero-length runs
    /// (which python can yield) are skipped.
    fn walk(&self, offset: u64, length: u64, ignore_errors: bool, f: &mut dyn FnMut(u64, u64, u64) -> bool) -> std::result::Result<(), u64> {
        let end = offset as u128 + length as u128;
        let mut current = offset as u128;
        loop {
            let (logical, mapped, size) = match self.find(current as u64).filter(|_| current <= u64::MAX as u128) {
                Some(s) => {
                    let diff = current as u64 - s.addr;
                    (current, s.mapped as u128 + diff as u128, (s.len - diff) as u128)
                }
                None => {
                    if !ignore_errors {
                        return Err(current as u64);
                    }
                    if current > u64::MAX as u128 {
                        return Ok(());
                    }
                    match self.find_next(current as u64) {
                        Some(s) => {
                            current = s.addr as u128;
                            if s.addr as u128 > end {
                                return Ok(());
                            }
                            (s.addr as u128, s.mapped as u128, s.len as u128)
                        }
                        None => return Ok(()),
                    }
                }
            };
            let chunk = size.min(end - logical);
            if chunk > 0 && !f(logical as u64, chunk as u64, mapped as u64) {
                return Ok(());
            }
            current += chunk;
            if current >= end {
                return Ok(());
            }
            if chunk == 0 {
                // python would yield an empty run and then stop (current >= end)
                return Ok(());
            }
        }
    }

    fn read_impl(&self, addr: u64, buf: &mut [u8], pad: bool) -> Result<()> {
        if let Some(s) = self.slice(addr, buf.len()) {
            buf.copy_from_slice(s);
            return Ok(());
        }
        if pad {
            buf.fill(0);
        }
        let mut err = None;
        let r = self.walk(addr, buf.len() as u64, pad, &mut |off, len, mapped| {
            let start = (off - addr) as usize;
            let dst = &mut buf[start..start + len as usize];
            if pad {
                self.base.read_padded(mapped, dst);
            } else if let Err(e) = self.base.read(mapped, dst) {
                err = Some(e);
                return false;
            }
            true
        });
        if let Err(bad) = r {
            return Err(Error::invalid(bad));
        }
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl Layer for SegmentedLayer {
    fn name(&self) -> &str {
        "memory_layer"
    }

    /// python `maximum_address`: last segment's address + length - 1.
    fn max_address(&self) -> u64 {
        let s = self.segs[self.segs.len() - 1];
        s.addr.wrapping_add(s.len).wrapping_sub(1)
    }

    fn min_address(&self) -> u64 {
        self.segs[0].addr
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        self.read_impl(addr, buf, false)
    }

    fn read_padded(&self, addr: u64, buf: &mut [u8]) {
        let _ = self.read_impl(addr, buf, true);
    }

    fn is_valid(&self, addr: u64, len: u64) -> bool {
        let mut ok = true;
        let r = self.walk(addr, len.max(1), false, &mut |_, _, mapped| {
            ok = self.base.is_valid(mapped, 1);
            ok
        });
        r.is_ok() && ok
    }

    fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
        let _ = self.walk(addr, len, true, &mut |offset, len, mapped| f(Mapping { offset, len, mapped }));
    }

    fn lower(&self) -> Option<&Arc<dyn Layer>> {
        Some(&self.base)
    }

    #[inline]
    fn slice(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let s = self.find(addr)?;
        let diff = addr - s.addr;
        if len as u64 > s.len - diff {
            return None;
        }
        self.file.slice(s.mapped.checked_add(diff)?, len)
    }

    fn translate(&self, addr: u64) -> Option<(u64, u64)> {
        let s = self.find(addr)?;
        let diff = addr - s.addr;
        Some((s.mapped.wrapping_add(diff), s.len - diff))
    }

    fn class_name(&self) -> &'static str {
        self.class
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(segs: &[(u64, u64, u64)], base_max: u64) -> SegmentedLayer {
        let tmp = std::env::temp_dir().join(format!("rsvol-seg-test-{}", std::process::id()));
        std::fs::write(&tmp, vec![7u8; (base_max + 1) as usize]).unwrap();
        let f = Arc::new(FileLayer::open(&tmp).unwrap());
        let _ = std::fs::remove_file(&tmp);
        SegmentedLayer::new("Elf64Layer", &f, segs.iter().map(|&(addr, mapped, len)| Segment { addr, mapped, len }).collect()).unwrap()
    }

    #[test]
    fn mapping_is_per_segment_like_python() {
        // two adjacent segments, contiguous in both spaces: python still yields two runs
        let l = layer(&[(0, 0x10, 0x100), (0x100, 0x110, 0x100), (0x300, 0x210, 0x10)], 0x400);
        let mut v = Vec::new();
        l.mapping(0, 0x1000, &mut |m| {
            v.push((m.offset, m.len, m.mapped));
            true
        });
        assert_eq!(v, vec![(0, 0x100, 0x10), (0x100, 0x100, 0x110), (0x300, 0x10, 0x210)]);
        let mut v = Vec::new();
        l.mapping(0x80, 0x290, &mut |m| {
            v.push((m.offset, m.len, m.mapped));
            true
        });
        assert_eq!(v, vec![(0x80, 0x80, 0x90), (0x100, 0x100, 0x110), (0x300, 0x10, 0x210)]);
        assert_eq!(l.max_address(), 0x30f);
        assert!(l.is_valid(0x1ff, 2));
        assert!(!l.is_valid(0x1ff, 3));
        let mut b = [0u8; 4];
        assert!(l.read(0x1fe, &mut b).is_err());
        assert!(matches!(l.read(0x1fe, &mut b), Err(Error::InvalidAddress { addr: 0x200 })));
        l.read_padded(0x1fe, &mut b);
        assert_eq!(b, [7, 7, 0, 0]);
        assert_eq!(l.translate(0x105), Some((0x115, 0xfb)));
    }
}
