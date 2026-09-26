//! python `CONTROL_AREA`, `SHARED_CACHE_MAP`, `VACB` and `ERESOURCE` class extensions
//! (symbols/windows/extensions/__init__.py) -- file cache / section object helpers used by
//! dumpfiles & co.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::error::{Error, Result};
use crate::layers::metadata;
use crate::objects::{Obj, Space};
use crate::symbols::Ty;

const PAGE_SIZE: u64 = 0x1000;
const VACB_BLOCK: u64 = 0x40000;
const VACB_OFFSET_SHIFT: u32 = 18;
const VACB_LEVEL_SHIFT: u32 = 7;
const VACB_SIZE_OF_FIRST_LEVEL: i128 = 1 << (VACB_OFFSET_SHIFT + VACB_LEVEL_SHIFT);
const VACB_ARRAY: u64 = 0x80;

/// Section / cache helpers.
pub trait CacheExt {
    /// python `CONTROL_AREA.get_subsection()`: `_SUBSECTION` right after the control area.
    fn get_subsection(&self) -> Result<Obj>;
    /// python `CONTROL_AREA.get_pte(offset)`: an `_MMPTE` at `offset`.
    fn get_pte(&self, offset: u64) -> Result<Obj>;
    /// python `CONTROL_AREA.get_available_pages()` / `SHARED_CACHE_MAP.get_available_pages()`
    /// (dispatch on type): (physical-or-virtual offset, file offset, size) tuples in python
    /// order; a trailing `Err` = python raised midway.
    fn get_available_pages(&self) -> Vec<Result<(u64, u64, u64)>>;
    /// python `VACB.get_file_offset()`.
    fn get_file_offset(&self) -> Result<u64>;
}

/// python `CONTROL_AREA.is_valid()`.
pub fn control_area_is_valid(o: &Obj) -> bool {
    (|| -> Result<bool> {
        let seg = o.m("Segment")?;
        if seg.m("ControlArea")?.u64()? != o.addr {
            return Ok(false);
        }
        if seg.m("SizeOfSegment")?.int()? != seg.m("TotalNumberOfPtes")?.int()? * PAGE_SIZE as i128 {
            return Ok(false);
        }
        Ok(true)
    })()
    .unwrap_or(false)
}

/// python `SHARED_CACHE_MAP.is_valid()` (reads are not guarded in python: errors propagate).
pub fn shared_cache_map_is_valid(o: &Obj) -> Result<bool> {
    let fs = o.path("FileSize.QuadPart")?.int()?;
    let vdl = o.path("ValidDataLength.QuadPart")?.int()?;
    if fs <= 0 || vdl <= 0 {
        return Ok(false);
    }
    let ss = o.path("SectionSize.QuadPart")?.int()?;
    if ss < 0 || (fs < vdl && vdl != 0x7FFF_FFFF_FFFF_FFFF) {
        return Ok(false);
    }
    Ok(true)
}

/// python `ERESOURCE.is_valid()`.
pub fn eresource_is_valid(o: &Obj) -> Result<bool> {
    let layer = o.layer();
    if !layer.is_valid(o.addr, 1) {
        return Ok(false);
    }
    let sw = o.m("SharedWaiters")?;
    let ksem = o.table().size_of(o.table().get_type("_KSEMAPHORE")?);
    // python checks the validity of the SharedWaiters member itself (vol.offset), not its target
    let waiters_valid = sw.u64()? == 0 || layer.is_valid(sw.addr, ksem);
    let r = (|| -> Result<bool> {
        let srl = o.m("SystemResourcesList")?;
        let flink = srl.m("Flink")?;
        let blink = srl.m("Blink")?;
        Ok(waiters_valid
            && flink.u64()? != blink.u64()?
            && flink.m("Blink")?.u64()? == o.addr
            && blink.m("Flink")?.u64()? == o.addr
            && o.m("NumberOfSharedWaiters")?.int()? == 0)
    })();
    match r {
        Ok(v) => Ok(v),
        Err(e) if e.is_invalid_address() => Ok(false),
        Err(e) => Err(e),
    }
}

fn control_area_pages(ca: &Obj, out: &mut Vec<Result<(u64, u64, u64)>>) -> Result<()> {
    let t = ca.table();
    let mmpte_size = t.size_of(t.get_type("_MMPTE")?);
    let mut subsection = ca.get_subsection()?;
    let is_64 = t.is_64bit();
    let is_pae = metadata(ca.layer()).pae.unwrap_or(false);
    let sector_size = if ca.path("u.Flags.Image")?.int()? != 1 { 0x1000u64 } else { 0x200 };
    // python: `while subsection != 0` -- the first subsection is a struct (always != 0), later
    // ones are NextSubsection pointers (compared by value)
    loop {
        if subsection.is_pointer() && subsection.u64()? == 0 {
            break;
        }
        match subsection.m("ControlArea").and_then(|c| c.u64()) {
            Ok(v) if v == ca.addr => {}
            Ok(_) => break,
            Err(e) if e.is_invalid_address() => break,
            Err(e) => return Err(e),
        }
        let starting_sector = subsection.m("StartingSector")?.u64()?;
        let mut subsection_offset = starting_sector.wrapping_mul(sector_size);
        let mut ptecount = 0u64;
        loop {
            let ptes = subsection.m("PtesInSubsection")?.u64()?;
            if ptecount >= ptes {
                break;
            }
            let base = subsection.m("SubsectionBase")?.u64()?;
            let pte_offset = base.wrapping_add(mmpte_size.wrapping_mul(ptecount));
            let file_offset = subsection_offset.wrapping_add(ptecount * 0x1000);
            let mmpte = ca.get_pte(pte_offset)?;
            if mmpte.path("u.Hard.Valid")?.int()? == 1 {
                let pfn = mmpte.path("u.Hard.PageFrameNumber")?.u64()?;
                out.push(Ok((pfn << 12, file_offset, PAGE_SIZE)));
            } else if mmpte.path("u.Soft.Prototype")?.int()? == 1 {
                if !is_64 && !is_pae {
                    let hi = mmpte.path("u.Subsect.SubsectionAddressHigh")?.u64()?;
                    let lo = mmpte.path("u.Subsect.SubsectionAddressLow")?.u64()?;
                    subsection_offset = (hi << 7) | (lo << 3);
                }
            } else if mmpte.path("u.Trans.Transition")?.int()? == 1 {
                let pfn = mmpte.path("u.Trans.PageFrameNumber")?.u64()?;
                out.push(Ok(((pfn & ((1u64 << 33) - 1)) << 12, file_offset, PAGE_SIZE)));
            }
            ptecount += 1;
        }
        subsection = subsection.m("NextSubsection")?;
    }
    Ok(())
}

fn save_vacb(vacb: &Obj, out: &mut Vec<Result<(u64, u64, u64)>>) -> Result<()> {
    out.push(Ok((vacb.m("BaseAddress")?.u64()?, vacb.get_file_offset()?, VACB_BLOCK)));
    Ok(())
}

/// python `context.object(table!array, layer_name=self.vol.layer_name, ...)` (native = layer).
fn pointer_array(scm: &Obj, at: u64, count: u64) -> Result<Obj> {
    let ptr = scm.table().get_type("pointer")?;
    Ok(Obj::new(Space::on(scm.layer(), scm.table()), Ty::Void, at).cast_array(count, ptr))
}

fn process_index_array(scm: &Obj, array_pointer: u64, level: i128, limit: i128, out: &mut Vec<Result<(u64, u64, u64)>>) -> Result<()> {
    if level > limit {
        // python returns a fresh [] which the caller assigns over its accumulated list
        out.clear();
        return Ok(());
    }
    let arr = pointer_array(scm, array_pointer, VACB_ARRAY)?;
    for counter in 0..VACB_ARRAY {
        let e = arr.at(counter)?;
        let v = e.u64()?;
        if v == 0 {
            continue;
        }
        let vacb = e.deref()?.cast("_VACB")?;
        if vacb.m("SharedCacheMap")?.u64()? == scm.addr {
            save_vacb(&vacb, out)?;
        } else {
            process_index_array(scm, v, level + 1, limit, out)?;
        }
    }
    Ok(())
}

fn shared_cache_map_pages(scm: &Obj, out: &mut Vec<Result<(u64, u64, u64)>>) -> Result<()> {
    let section_size = scm.path("SectionSize.QuadPart")?.int()?;
    let full_blocks = section_size.div_euclid(VACB_BLOCK as i128);
    let left_over = section_size.rem_euclid(VACB_BLOCK as i128);
    let initial = scm.m("InitialVacbs")?;
    let mut iterval: i128 = 0;
    while iterval < full_blocks && full_blocks <= 4 {
        let r = (|| -> Result<()> {
            let vacb = initial.at(iterval as u64)?;
            if vacb.m("SharedCacheMap")?.u64()? == scm.addr {
                save_vacb(&vacb, out)?;
            }
            Ok(())
        })();
        match r {
            Ok(()) => {}
            Err(e) if e.is_invalid_address() => {}
            Err(e) => return Err(e),
        }
        iterval += 1;
    }
    if left_over > 0 && full_blocks < 4 {
        let vacb = initial.at(iterval as u64)?;
        if vacb.m("SharedCacheMap")?.u64()? == scm.addr {
            save_vacb(&vacb, out)?;
        }
    }
    let vacbs = scm.m("Vacbs")?.u64()?;
    if vacbs == 0 {
        return Ok(());
    }
    if initial.at(0)?.addr == vacbs {
        return Ok(());
    }
    let psize = scm.table().size_of(scm.table().get_type("pointer")?);
    if section_size <= VACB_SIZE_OF_FIRST_LEVEL {
        let array_head = vacbs;
        let mut counter: i128 = 0;
        let mut last_counter: i128 = -1;
        while counter < full_blocks {
            last_counter = counter;
            let entry = Obj::named(Space::on(scm.layer(), scm.table()), "pointer", array_head.wrapping_add((counter as u64).wrapping_mul(psize)))?;
            counter += 1;
            if entry.u64()? == 0 {
                continue;
            }
            let vacb = entry.deref()?.cast("_VACB")?;
            if vacb.m("SharedCacheMap")?.u64()? == scm.addr {
                save_vacb(&vacb, out)?;
            }
        }
        if left_over > 0 {
            // python uses the loop variable `counter` of `for counter in range(full_blocks)`
            // (NameError when full_blocks == 0)
            if last_counter < 0 {
                return Err(Error::msg("NameError: name 'counter' is not defined"));
            }
            let entry = Obj::named(
                Space::on(scm.layer(), scm.table()),
                "pointer",
                array_head.wrapping_add(((last_counter + 1) as u64).wrapping_mul(psize)),
            )?;
            if entry.u64()? == 0 {
                return Ok(());
            }
            let vacb = entry.deref()?.cast("_VACB")?;
            if vacb.m("SharedCacheMap")?.u64()? == scm.addr {
                save_vacb(&vacb, out)?;
            }
        }
        return Ok(());
    }
    // sparse multilevel VACB index array
    // python math.log(x, 2) == ln(x) / ln(2) (can land just above an integer for powers of 2)
    let lg = ((section_size as f64).ln() / std::f64::consts::LN_2).ceil();
    let limit_depth = ((lg - VACB_OFFSET_SHIFT as f64) / VACB_LEVEL_SHIFT as f64).ceil() as i128;
    let arr = pointer_array(scm, vacbs, VACB_ARRAY)?;
    for counter in 0..VACB_ARRAY {
        let e = arr.at(counter)?;
        let v = e.u64()?;
        if v == 0 {
            continue;
        }
        let vacb = e.deref()?.cast("_VACB")?;
        if vacb.m("SharedCacheMap")?.u64()? == scm.addr {
            save_vacb(&vacb, out)?;
        } else {
            process_index_array(scm, v, 2, limit_depth, out)?;
        }
    }
    Ok(())
}

impl CacheExt for Obj {
    fn get_subsection(&self) -> Result<Obj> {
        Obj::named(self.sp, "_SUBSECTION", self.addr.wrapping_add(self.size()))
    }

    fn get_pte(&self, offset: u64) -> Result<Obj> {
        Obj::named(self.sp, "_MMPTE", offset)
    }

    fn get_available_pages(&self) -> Vec<Result<(u64, u64, u64)>> {
        let mut out = Vec::new();
        let r = match self.struct_name() {
            Some("_SHARED_CACHE_MAP") => shared_cache_map_pages(self, &mut out),
            _ => control_area_pages(self, &mut out),
        };
        if let Err(e) = r {
            out.push(Err(e));
        }
        out
    }

    fn get_file_offset(&self) -> Result<u64> {
        Ok(self.path("Overlay.FileOffset.QuadPart")?.u64()? & 0xFFFF_FFFF_FFFF_0000)
    }
}
