//! ELF64 core dumps (QEMU `dump-guest-memory`, VirtualBox `dumpvmcore`, kdump ...) and Xen
//! dump-core files.
//! Derived from Volatility 3's layers/elf.py and layers/xen.py (Volatility Software License
//! 1.0), using the Elf64_Ehdr/Phdr/Shdr layouts of symbols/linux/elf.json and the arrays of
//! symbols/linux/xen.json.

use super::segmented::{Seg, SegmentedLayer, Src};
use super::Base;
use crate::error::{Error, Result};

const ELF_MAGIC: u32 = 0x464C_457F;
const ELFCLASS64: u8 = 2;
const PT_LOAD: u32 = 1;
const XEN_PAGE: u64 = 0x1000;

/// python `Elf64Layer._check_header` (also used by the Xen layer): magic and 64-bit class.
/// VirtualBox writes an ELF version of 0, which is accepted.
fn check_header(base: &Base) -> Result<()> {
    let h = base.bytes(0, 7).map_err(|_| Error::Layer("ELF: header not in base layer".into()))?;
    if u32::from_le_bytes(h[0..4].try_into().unwrap()) != ELF_MAGIC {
        return Err(Error::Layer("ELF: bad magic".into()));
    }
    if h[4] != ELFCLASS64 {
        return Err(Error::Layer(format!("ELF: class is not 64-bit (2): {}", h[4])));
    }
    Ok(())
}

/// python `Elf64Stacker.stack`: PT_LOAD program headers with `p_filesz == p_memsz > 0`
/// become (p_paddr, p_offset, p_memsz) segments.
pub(crate) fn stack_elf64(base: &Base) -> Result<SegmentedLayer> {
    check_header(base)?;
    let phnum = base.u16le(0x38)? as u64;
    let phoff = base.u64le(0x20)?;
    let phentsize = base.u16le(0x36)? as u64;
    let mut segs = Vec::new();
    for i in 0..phnum {
        let off = i
            .checked_mul(phentsize)
            .and_then(|d| phoff.checked_add(d))
            .ok_or_else(|| Error::Layer("ELF: program header offset overflow".into()))?;
        let p_type = base.u32le(off)?;
        // unknown p_type values raise ValueError in python and are skipped; only PT_LOAD matters
        if p_type != PT_LOAD {
            continue;
        }
        let filesz = base.u64le(off.checked_add(0x20).ok_or_else(ovf)?)?;
        let memsz = base.u64le(off.checked_add(0x28).ok_or_else(ovf)?)?;
        if filesz == memsz && filesz > 0 {
            let paddr = base.u64le(off + 0x18)?;
            let p_offset = base.u64le(off + 0x08)?;
            segs.push(Seg { start: paddr, len: memsz, src: Src::Raw(p_offset) });
        }
    }
    if segs.is_empty() {
        return Err(Error::Layer("ELF: no segments defined".into()));
    }
    SegmentedLayer::new("Elf64Layer", base, segs)
}

fn ovf() -> Error {
    Error::Layer("ELF: offset overflow".into())
}

/// python `XenCoreDumpStacker.stack`. Sections are located by the index of their name in the
/// NUL-split section-name string table (as python does). Only the `.xen_pfn` (HVM) form can
/// load: python's xen.json declares `.xen_p2m` entries as plain integers, so the p2m (PV)
/// branch raises AttributeError on `entry.pfn` and the layer never stacks.
pub(crate) fn stack_xen(base: &Base) -> Result<SegmentedLayer> {
    check_header(base)?;
    let shnum = base.u16le(0x3c)? as u64;
    let shoff = base.u64le(0x28)?;
    let shentsize = base.u16le(0x3a)? as u64;
    let shstrndx = base.u16le(0x3e)? as u64;
    let shdr = |i: u64| -> Result<u64> {
        i.checked_mul(shentsize)
            .and_then(|d| shoff.checked_add(d))
            .ok_or_else(|| Error::Layer("Xen: section header offset overflow".into()))
    };
    let mut names: Option<Vec<Vec<u8>>> = None;
    for i in 0..shnum {
        if i == shstrndx {
            let h = shdr(i)?;
            let off = base.u64le(h + 0x18)?;
            let size = base.u64le(h + 0x20)?;
            if size == 0 {
                // python FileLayer.read raises ValueError for non-positive lengths
                return Err(Error::Layer("Xen: empty section name table".into()));
            }
            let size = usize::try_from(size).map_err(|_| Error::invalid(off))?;
            let data = base.bytes(off, size)?;
            names = Some(data.split(|&b| b == 0).map(|s| s.to_vec()).collect());
        }
    }
    let names = names.ok_or_else(|| Error::Layer("No segment names, not a Xen Core Dump".into()))?;
    let index_of = |n: &[u8]| names.iter().position(|s| s.as_slice() == n).map(|i| i as u64);
    // (sh_offset, sh_size) of the section at list index `idx` (IndexError in python if absent)
    let section = |idx: u64| -> Result<(u64, u64)> {
        if idx >= shnum {
            return Err(Error::Layer("Xen: section index out of range".into()));
        }
        let h = shdr(idx)?;
        Ok((base.u64le(h + 0x18)?, base.u64le(h + 0x20)?))
    };
    let p2m = match index_of(b".xen_p2m") {
        Some(i) => Some(section(i)?),
        None => None,
    };
    let pfn = match index_of(b".xen_pfn") {
        Some(i) => Some(section(i)?),
        None => None,
    };
    let pages_idx = index_of(b".xen_pages").ok_or_else(|| Error::Layer("Xen: no .xen_pages".into()))?;
    if pages_idx >= shnum {
        return Err(Error::Layer("Xen: section index out of range".into()));
    }
    let pages_off = base.u64le(shdr(pages_idx)? + 0x18)?;
    let mut segs = Vec::new();
    match (p2m, pfn) {
        (None, Some((off, size))) => {
            let count = size / 8;
            if let Some(f) = &base.file {
                // fast path: the whole array must be readable entry by entry, as in python
                for i in 0..count {
                    let at = off.checked_add(i * 8).ok_or_else(ovf)?;
                    let entry = match f.data().get(at as usize..at as usize + 8) {
                        Some(b) => u64::from_le_bytes(b.try_into().unwrap()),
                        None => return Err(Error::invalid(at)),
                    };
                    push_pfn(&mut segs, entry, pages_off, i);
                }
            } else {
                for i in 0..count {
                    let entry = base.u64le(off.checked_add(i * 8).ok_or_else(ovf)?)?;
                    push_pfn(&mut segs, entry, pages_off, i);
                }
            }
        }
        (Some((_, size)), None) => {
            let _ = size;
            return Err(Error::Layer("Xen: p2m dumps are not loadable by volatility3 2.28.2".into()));
        }
        (Some(_), Some(_)) => return Err(Error::Layer("Both P2M and PFN in Xen Core Dump".into())),
        (None, None) => return Err(Error::Layer("Neither P2M nor PFN in Xen Core Dump".into())),
    }
    if segs.is_empty() {
        return Err(Error::Layer("Xen: no segments defined".into()));
    }
    SegmentedLayer::new("XenCoreDumpLayer", base, segs)
}

#[inline]
fn push_pfn(segs: &mut Vec<Seg>, entry: u64, pages_off: u64, i: u64) {
    if entry != 0 && entry != 0xFFFF_FFFF {
        // addresses beyond 2^64 (garbage pfns) cannot be addressed by a u64 layer
        if let (Some(start), Some(src)) = (entry.checked_mul(XEN_PAGE), i.checked_mul(XEN_PAGE).and_then(|d| pages_off.checked_add(d))) {
            segs.push(Seg { start, len: XEN_PAGE, src: Src::Raw(src) });
        }
    }
}
