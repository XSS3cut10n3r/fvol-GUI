//! windows.virtmap.VirtMap (python `plugins/windows/virtmap.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};

pub struct VirtMap;

/// python `dict` of region name -> [(start, size)] (insertion ordered).
pub type VirtualMap = Vec<(String, Vec<(i128, i128)>)>;

fn push(map: &mut VirtualMap, name: &str, range: (i128, i128)) {
    match map.iter_mut().find(|(n, _)| n == name) {
        Some((_, v)) => v.push(range),
        None => map.push((name.to_string(), vec![range])),
    }
}

fn lookup(k: &WinKernel, en: u32, value: i128) -> Result<&'static str> {
    k.table.enum_lookup(en, value).ok_or_else(|| Error::msg("ValueError: The value of the enumeration is outside the possible choices"))
}

/// python `VirtMap._enumerate_system_va_type(large_page_size, system_range_start, module, type_array)`.
fn enumerate_system_va_type(k: &WinKernel, en: u32, large_page_size: i128, system_range_start: i128, type_array: &Obj) -> Result<VirtualMap> {
    let mut result = VirtualMap::new();
    let mut start = system_range_start;
    let mut prev: Option<&str> = None;
    let mut cur_size = large_page_size;
    for v in type_array.ints()? {
        let entry = lookup(k, en, v)?;
        if prev != Some(entry) {
            push(&mut result, entry, (start, cur_size));
            start += cur_size;
            cur_size = large_page_size;
        } else {
            cur_size += large_page_size;
        }
        prev = Some(entry);
    }
    Ok(result)
}

/// python `VirtMap.determine_map(module)`: the kernel's virtual address space regions.
pub fn determine_map(k: &WinKernel) -> Result<VirtualMap> {
    let en = k.get_enumeration("_MI_SYSTEM_VA_TYPE")?;
    let large_page_size = (0x1000i128 * 0x1000) / k.size_of("_MMPTE")? as i128;
    if k.has_symbol("MiVisibleState") {
        let addr = k.get_symbol("MiVisibleState")?.address;
        let vs_ty = k.get_type("_MI_VISIBLE_STATE")?;
        let visible_state = k.object("pointer", addr)?.cast_pointer_to(vs_ty)?.deref()?;
        if visible_state.has_member("SystemVaRegions") {
            let regions = visible_state.m("SystemVaRegions")?;
            let mut result = VirtualMap::new();
            for i in 0..regions.count() {
                let name = lookup(k, en, i as i128)?;
                let r = regions.at(i)?;
                push(&mut result, name, (r.m("BaseAddress")?.int()?, r.m("NumberOfBytes")?.int()?));
            }
            Ok(result)
        } else if visible_state.has_member("SystemVaType") {
            let srs = k.object("pointer", k.get_symbol("MmSystemRangeStart")?.address)?.int()?;
            enumerate_system_va_type(k, en, large_page_size, srs, &visible_state.m("SystemVaType")?)
        } else {
            Err(Error::Symbol("SystemVaRegions: Required structures not found".into()))
        }
    } else if k.has_symbol("MiSystemVaType") {
        let srs = k.object("pointer", k.get_symbol("MmSystemRangeStart")?.address)?.int()?;
        let count = (0xFFFF_FFFFi128 + 1 - srs).div_euclid(large_page_size);
        let arr = k.object("char", k.get_symbol("MiSystemVaType")?.address)?.cast_array_of(count.max(0) as u64, "char")?;
        enumerate_system_va_type(k, en, large_page_size, srs, &arr)
    } else {
        Err(Error::Symbol("MiVisibleState: Required structures not found".into()))
    }
}

/// python `VirtMap.scannable_sections(module)`: every range of a region whose name does not
/// contain "Unused".
pub fn scannable_sections(k: &WinKernel) -> Result<Vec<(i128, i128)>> {
    Ok(determine_map(k)?.into_iter().filter(|(n, _)| !n.contains("Unused")).flat_map(|(_, v)| v).collect())
}

impl Plugin for VirtMap {
    fn name(&self) -> &'static str {
        "windows.virtmap.VirtMap"
    }
    fn description(&self) -> &'static str {
        "Lists virtual mapped sections."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Region", ColType::Str),
            Column::new("Start offset", ColType::Hex),
            Column::new("End offset", ColType::Hex),
        ])?;
        let k = ctx.windows_kernel()?;
        let mut map = determine_map(k)?;
        map.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, ranges) in map {
            for (start, end) in ranges {
                out.row(0, vec![Value::Str(name.clone()), Value::Int(start), Value::Int(end)])?;
            }
        }
        Ok(())
    }
}
