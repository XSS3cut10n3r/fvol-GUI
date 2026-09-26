//! windows.registry.hivescan.HiveScan (python `plugins/windows/registry/hivescan.py`):
//! `_CMHIVE`s found through the big page pool table (`CM10`, Windows 8.1+ x64) or by pool
//! scanning (older systems). [`scan_hives`] is python's `HiveScan.scan_hives`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::layers::LayerExt;
use crate::objects::{Field, Obj};
use crate::plugins::windows::poolscanner::{builtin_constraints, generate_pool_scan_each};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::versions;

pub struct HiveScan;

/// python `BigPools.list_big_pools(context, kernel, tags, show_free)`: the valid
/// `_POOL_TRACKER_BIG_PAGES` entries of `PoolBigPageTable` whose tag is in `tags` (all when
/// None). A trailing `Err` is where python raised.
// TODO(dedupe): owned by W1 (windows.bigpools); minimal private version for hivescan.
pub fn list_big_pools(ctx: &Context, k: &WinKernel, tags: Option<&[&str]>, show_free: bool) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let table_addr = k.object("unsigned long long", k.get_symbol("PoolBigPageTable")?.address)?.u64()?;
        let size = k.object("unsigned long", k.get_symbol("PoolBigPageTableSize")?.address)?.u64()?;
        let (sp, ty) = match k.get_type("_POOL_TRACKER_BIG_PAGES") {
            Ok(t) => (k.sp, t),
            Err(_) => {
                let mut name = if versions::IS_WIN10.check(k.table) {
                    "bigpools-win10".to_string()
                } else if versions::IS_VISTA_OR_LATER.check(k.table) {
                    "bigpools-vista".to_string()
                } else {
                    "bigpools".to_string()
                };
                name.push_str(if k.table.is_64bit() { "-x64" } else { "-x86" });
                let t = ctx.load_isf_with(&format!("windows/bigpools/{name}"), None, &[("nt_symbols", k.table.name())])?;
                let sp = crate::objects::Space::on(k.vlayer, t);
                (sp, t.get_type("_POOL_TRACKER_BIG_PAGES")?)
            }
        };
        let t = sp.table;
        let esize = t.size_of(ty);
        let tname = t.type_name(ty);
        let key_f = Field::new(t, &tname, "Key")?;
        let va_f = Field::new(t, &tname, "Va")?;
        let arr = Obj::new(sp, ty, table_addr);
        let tag_of = |key: u32| -> String { key.to_le_bytes().iter().filter(|&&x| 32 < x && x < 127).map(|&x| x as char).collect() };
        let wanted = |key: u32| -> bool {
            match tags {
                None => true,
                Some(ts) => {
                    let s = tag_of(key);
                    ts.iter().any(|t| *t == s)
                }
            }
        };
        // fast path: the whole table in one read (python reads entry by entry; same result
        // when everything is readable)
        let bulk = if esize > 0 && size.checked_mul(esize).is_some_and(|n| n <= 256 << 20) {
            k.vlayer.read_vec(arr.addr, (size * esize) as usize).ok()
        } else {
            None
        };
        let ko = key_f.offset as usize;
        let vo = va_f.offset as usize;
        let key_is_u32 = matches!(key_f.ty, crate::symbols::Ty::Int(p) if p.size == 4 && !p.signed);
        let va_is_u64 = matches!(va_f.ty, crate::symbols::Ty::Int(p) if p.size == 8 && !p.signed);
        for i in 0..size {
            let e = arr.at_addr(arr.addr.wrapping_add(i.wrapping_mul(esize)));
            let (key, va_lo) = match (&bulk, key_is_u32 && va_is_u64) {
                (Some(b), true) => {
                    let o = (i * esize) as usize;
                    let key = u32::from_le_bytes(b[o + ko..o + ko + 4].try_into().unwrap());
                    let va = u64::from_le_bytes(b[o + vo..o + vo + 8].try_into().unwrap());
                    (key as i128, va)
                }
                _ => {
                    let key = e.f(&key_f).int()?;
                    (key, 0)
                }
            };
            if key <= 0 {
                continue;
            }
            if !wanted(key as u32) {
                continue;
            }
            let free = match (&bulk, key_is_u32 && va_is_u64) {
                (Some(_), true) => va_lo & 1 == 1,
                _ => e.f(&va_f).int()? & 1 == 1,
            };
            if show_free || !free {
                out.push(Ok(e));
            }
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

/// python `HiveScan.scan_hives(context, kernel_name)`: `_CMHIVE` objects from the big pool
/// table (Windows 8.1+ x64) or from a `CM10` pool scan. A trailing `Err` = python raised.
pub fn scan_hives(ctx: &Context, k: &WinKernel) -> Vec<Result<Obj>> {
    let is_64bit = k.table.is_64bit();
    if versions::IS_WINDOWS_8_1_OR_LATER.check(k.table) && is_64bit {
        let mut out = Vec::new();
        for p in list_big_pools(ctx, k, Some(&["CM10"]), false) {
            match p.and_then(|p| {
                let va = p.m("Va")?.int()? as u64;
                k.object_abs("_CMHIVE", va)
            }) {
                Ok(h) => out.push(Ok(h)),
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            }
        }
        out
    } else {
        let constraints = builtin_constraints(k.table.name(), &[b"CM10"]);
        let mut out = Vec::new();
        if let Err(e) = generate_pool_scan_each(ctx, k, k.table, &constraints, |hit| {
            out.push(Ok(hit.object));
            Ok(true)
        }) {
            out.push(Err(e));
        }
        out
    }
}

impl Plugin for HiveScan {
    fn name(&self) -> &'static str {
        "windows.registry.hivescan.HiveScan"
    }
    fn description(&self) -> &'static str {
        "Scans for registry hives present in a particular windows memory image."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("Offset", ColType::Hex)])?;
        let k = ctx.windows_kernel()?;
        for h in scan_hives(ctx, k) {
            let h = h?;
            out.row(0, vec![Value::Int(h.addr as i128)])?;
        }
        Ok(())
    }
}
