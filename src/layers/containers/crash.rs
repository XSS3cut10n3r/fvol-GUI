//! Windows crash dumps (32/64-bit, complete memory dumps (DumpType 1) and bitmap dumps
//! (DumpType 5: kernel / automatic / active / full bitmap dumps)).
//! Derived from Volatility 3's layers/crash.py and symbols/windows/extensions/crash.py
//! (Volatility Software License 1.0). Offsets come from symbols/windows/crash.json,
//! crash64.json and crash_common.json.

use super::segmented::{Seg, SegmentedLayer, Src};
use super::Base;
use crate::error::{Error, Result};
use crate::layers::Layer;
use std::sync::Arc;

pub const SIGNATURE: u32 = 0x4547_4150; // "PAGE"
pub const VALIDDUMP32: u32 = 0x504D_5544; // "DUMP"
pub const VALIDDUMP64: u32 = 0x3436_5544; // "DU64"
const PAGE: u64 = 0x1000;

/// Field offsets of `_DUMP_HEADER` / `_DUMP_HEADER64`.
struct Layout {
    valid: u32,
    header_pages: u64,
    ptr64: bool,
    directory_table_base: u64,
    pfn_data_base: u64,
    ps_loaded_module_list: u64,
    ps_active_process_head: u64,
    machine_image_type: u64,
    number_processors: u64,
    bugcheck_code: u64,
    bugcheck_params: u64,
    kd_debugger_data_block: u64,
    phys_mem: u64,
    runs: u64,
    comment: u64,
    dump_type: u64,
    system_up_time: u64,
    system_time: u64,
}

const L32: Layout = Layout {
    valid: VALIDDUMP32,
    header_pages: 1,
    ptr64: false,
    directory_table_base: 0x10,
    pfn_data_base: 0x14,
    ps_loaded_module_list: 0x18,
    ps_active_process_head: 0x1c,
    machine_image_type: 0x20,
    number_processors: 0x24,
    bugcheck_code: 0x28,
    bugcheck_params: 0x2c,
    kd_debugger_data_block: 0x60,
    phys_mem: 0x64,
    runs: 0x6c,
    comment: 0x820,
    dump_type: 0xf88,
    system_up_time: 0xfb8,
    system_time: 0xfc0,
};

const L64: Layout = Layout {
    valid: VALIDDUMP64,
    header_pages: 2,
    ptr64: true,
    directory_table_base: 0x10,
    pfn_data_base: 0x18,
    ps_loaded_module_list: 0x20,
    ps_active_process_head: 0x28,
    machine_image_type: 0x30,
    number_processors: 0x34,
    bugcheck_code: 0x38,
    bugcheck_params: 0x40,
    kd_debugger_data_block: 0x80,
    phys_mem: 0x88,
    runs: 0x98,
    comment: 0xfb0,
    dump_type: 0xf98,
    system_up_time: 0x1030,
    system_time: 0xfa8,
};

/// `_SUMMARY_DUMP` (bitmap dumps), located `header_pages` pages into the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryHeader {
    pub signature: [u8; 4],
    pub valid_dump: [u8; 4],
    pub dump_options: u32,
    pub header_size: u64,
    pub pages: u64,
    pub bitmap_size: u64,
}

/// The dump header fields volatility3 plugins use (windows.crashinfo).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashHeader {
    pub is64: bool,
    pub signature: [u8; 4],
    pub valid_dump: [u8; 4],
    pub major_version: u32,
    pub minor_version: u32,
    pub directory_table_base: u64,
    pub pfn_data_base: u64,
    pub ps_loaded_module_list: u64,
    pub ps_active_process_head: u64,
    pub machine_image_type: u32,
    pub number_processors: u32,
    pub bugcheck_code: u32,
    pub bugcheck_parameters: [u64; 4],
    pub kd_debugger_data_block: u64,
    pub comment: Vec<u8>,
    pub dump_type: u32,
    pub system_up_time: u64,
    pub system_time: u64,
    pub summary: Option<SummaryHeader>,
}

fn check_header(base: &Base, l: &Layout) -> Result<()> {
    let h = base.bytes(0, 8).map_err(|_| Error::Layer("crash: header not found".into()))?;
    let sig = u32::from_le_bytes(h[0..4].try_into().unwrap());
    let valid = u32::from_le_bytes(h[4..8].try_into().unwrap());
    if sig != SIGNATURE {
        return Err(Error::Layer(format!("crash: bad signature {sig:#x}")));
    }
    if valid != l.valid {
        return Err(Error::Layer(format!("crash: invalid dump {valid:#x}")));
    }
    Ok(())
}

fn ptr(base: &Base, l: &Layout, off: u64) -> Result<u64> {
    if l.ptr64 { base.u64le(off) } else { Ok(base.u32le(off)? as u64) }
}

/// python `WindowsCrashDumpStacker.stack`: try the 32-bit then the 64-bit layout.
pub(crate) fn stack(base: &Base) -> Result<SegmentedLayer> {
    if check_header(base, &L32).is_ok() {
        return build(base, &L32, "WindowsCrashDump32Layer");
    }
    check_header(base, &L64)?;
    build(base, &L64, "WindowsCrashDump64Layer")
}

fn build(base: &Base, l: &Layout, name: &'static str) -> Result<SegmentedLayer> {
    let _dtb = ptr(base, l, l.directory_table_base)?;
    let dump_type = base.u32le(l.dump_type)?;
    let segs = match dump_type {
        1 => full_segments(base, l)?,
        5 => bitmap_segments(base, l)?,
        t => return Err(Error::Layer(format!("crash: unsupported dump format {t:#x}"))),
    };
    if segs.is_empty() {
        return Err(Error::Layer("crash: no segments defined".into()));
    }
    SegmentedLayer::new(name, base, segs)
}

/// DumpType 1: `PhysicalMemoryBlockBuffer` runs, data starts after the header page(s).
fn full_segments(base: &Base, l: &Layout) -> Result<Vec<Seg>> {
    let nruns = base.u32le(l.phys_mem)? as u64;
    let mut segs = Vec::with_capacity(nruns.min(4096) as usize);
    let mut page_off = l.header_pages;
    let esz = if l.ptr64 { 16 } else { 8 };
    for i in 0..nruns {
        let at = l.runs + i * esz;
        let (base_page, count) = if l.ptr64 {
            (base.u64le(at)?, base.u64le(at + 8)?)
        } else {
            (base.u32le(at)? as u64, base.u32le(at + 4)? as u64)
        };
        if let (Some(start), Some(len), Some(src)) =
            (base_page.checked_mul(PAGE), count.checked_mul(PAGE), page_off.checked_mul(PAGE))
        {
            segs.push(Seg { start, len, src: Src::Raw(src) });
        }
        page_off = page_off.saturating_add(count);
    }
    Ok(segs)
}

fn summary_offset(l: &Layout) -> u64 {
    PAGE * l.header_pages
}

/// DumpType 5: runs of set bits in the `_SUMMARY_DUMP` page bitmap; the pages present are
/// stored consecutively from `HeaderSize`.
fn bitmap_segments(base: &Base, l: &Layout) -> Result<Vec<Seg>> {
    let so = summary_offset(l);
    let header_size = base.u64le(so + 0x20)?;
    let bitmap_size = base.u64le(so + 0x30)?;
    let count = bitmap_size / 32 + (bitmap_size % 32 != 0) as u64; // (BitmapSize + 31) // 32
    let nbytes = count.checked_mul(4).ok_or_else(|| Error::Layer("crash: bitmap too large".into()))?;
    let nbytes = usize::try_from(nbytes).map_err(|_| Error::invalid(so + 0x38))?;
    // python reads each element as it iterates; any unreadable element aborts construction
    let bitmap = base.bytes(so + 0x38, nbytes)?;
    let mut segs = Vec::new();
    let mut file_off = header_size;
    let mut run: Option<(u64, u64)> = None; // (first page, file offset)
    let mut page = 0u64;
    let push = |segs: &mut Vec<Seg>, (p0, o0): (u64, u64), end_page: u64| {
        segs.push(Seg { start: p0 * PAGE, len: (end_page - p0) * PAGE, src: Src::Raw(o0) });
    };
    for w in bitmap.chunks_exact(4) {
        let v = u32::from_le_bytes(w.try_into().unwrap());
        if v == u32::MAX {
            if run.is_none() {
                run = Some((page, file_off));
            }
            file_off = file_off.saturating_add(32 * PAGE);
        } else if v == 0 {
            if let Some(r) = run.take() {
                push(&mut segs, r, page);
            }
        } else {
            let mut b = 0u32;
            while b < 32 {
                let rest = v >> b;
                if rest & 1 == 1 {
                    let ones = (!rest).trailing_zeros().min(32 - b);
                    if run.is_none() {
                        run = Some((page + b as u64, file_off));
                    }
                    file_off = file_off.saturating_add(ones as u64 * PAGE);
                    b += ones;
                } else {
                    let zeros = if rest == 0 { 32 - b } else { rest.trailing_zeros() };
                    if let Some(r) = run.take() {
                        push(&mut segs, r, page + b as u64);
                    }
                    b += zeros;
                }
            }
        }
        page += 32;
    }
    if let Some(r) = run.take() {
        push(&mut segs, r, page);
    }
    Ok(segs)
}

/// Parse the dump header (and the bitmap summary header for DumpType 5) from the layer the
/// crash layer is stacked on (normally the FileLayer).
pub fn read_header(lower: &Arc<dyn Layer>) -> Result<CrashHeader> {
    let base = Base { layer: lower.clone(), file: None };
    let l = if check_header(&base, &L32).is_ok() {
        &L32
    } else {
        check_header(&base, &L64)?;
        &L64
    };
    let mut bugcheck_parameters = [0u64; 4];
    for (i, p) in bugcheck_parameters.iter_mut().enumerate() {
        *p = ptr(&base, l, l.bugcheck_params + i as u64 * if l.ptr64 { 8 } else { 4 })?;
    }
    let dump_type = base.u32le(l.dump_type)?;
    let summary = if dump_type == 5 {
        let so = summary_offset(l);
        let s = base.bytes(so, 0x38)?;
        Some(SummaryHeader {
            signature: s[0..4].try_into().unwrap(),
            valid_dump: s[4..8].try_into().unwrap(),
            dump_options: u32::from_le_bytes(s[8..12].try_into().unwrap()),
            header_size: u64::from_le_bytes(s[0x20..0x28].try_into().unwrap()),
            pages: u64::from_le_bytes(s[0x28..0x30].try_into().unwrap()),
            bitmap_size: u64::from_le_bytes(s[0x30..0x38].try_into().unwrap()),
        })
    } else {
        None
    };
    Ok(CrashHeader {
        is64: l.ptr64,
        signature: base.array(0)?,
        valid_dump: base.array(4)?,
        major_version: base.u32le(8)?,
        minor_version: base.u32le(0xc)?,
        directory_table_base: ptr(&base, l, l.directory_table_base)?,
        pfn_data_base: ptr(&base, l, l.pfn_data_base)?,
        ps_loaded_module_list: ptr(&base, l, l.ps_loaded_module_list)?,
        ps_active_process_head: ptr(&base, l, l.ps_active_process_head)?,
        machine_image_type: base.u32le(l.machine_image_type)?,
        number_processors: base.u32le(l.number_processors)?,
        bugcheck_code: base.u32le(l.bugcheck_code)?,
        bugcheck_parameters,
        kd_debugger_data_block: ptr(&base, l, l.kd_debugger_data_block)?,
        comment: base.bytes(l.comment, 128)?.into_owned(),
        dump_type,
        system_up_time: base.u64le(l.system_up_time)?,
        system_time: base.u64le(l.system_time)?,
        summary,
    })
}

/// Walk a physical layer stack and return the crash dump header if a crash layer is part of
/// it (windows.crashinfo).
pub fn find_header(physical: &Arc<dyn Layer>) -> Option<CrashHeader> {
    let mut cur = Some(physical);
    while let Some(l) = cur {
        if matches!(l.name(), "WindowsCrashDump32Layer" | "WindowsCrashDump64Layer") {
            return read_header(l.lower()?).ok();
        }
        cur = l.lower();
    }
    None
}
