//! windows.bigpools.BigPools (python `plugins/windows/bigpools.py`): the kernel's big page
//! pool tracker table (`PoolBigPageTable`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::{Field, Obj};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::pool::PoolExt;
use crate::symbols::windows::versions;
use crate::symbols::{Ty, TableRef};

pub struct BigPools;

/// The table holding `_POOL_TRACKER_BIG_PAGES`: the kernel's, or python's fallback
/// `windows/bigpools/bigpools[-vista|-win10]-x86|x64` ISF mapped onto the kernel table.
pub fn big_page_table_type(ctx: &Context, k: &WinKernel) -> Result<(TableRef, Ty)> {
    if let Ok(ty) = k.table.get_type("_POOL_TRACKER_BIG_PAGES") {
        return Ok((k.table, ty));
    }
    let mut file = if versions::IS_WIN10.check(k.table) {
        "bigpools-win10".to_string()
    } else if versions::IS_VISTA_OR_LATER.check(k.table) {
        "bigpools-vista".to_string()
    } else {
        "bigpools".to_string()
    };
    file.push_str(if k.table.is_64bit() { "-x64" } else { "-x86" });
    let t = ctx.load_isf_with(&format!("windows/bigpools/{file}"), None, &[("nt_symbols", k.table.name())])?;
    Ok((t, t.get_type("_POOL_TRACKER_BIG_PAGES")?))
}

/// python `BigPools.list_big_pools(context, kernel_module_name, tags, show_free)`: every valid
/// (`Key > 0`) tracker entry matching `tags` (None = all) that is in use (or free too with
/// `show_free`). `f` gets the entries in table order (`Ok(false)` stops); an unreadable entry
/// is python raising (returned after the entries before it).
pub fn list_big_pools_each(ctx: &Context, k: &WinKernel, tags: Option<&[String]>, show_free: bool, mut f: impl FnMut(Obj) -> Result<bool>) -> Result<()> {
    let table_ptr = k.object("unsigned long long", k.get_symbol("PoolBigPageTable")?.address)?.u64()?;
    let count = k.object("unsigned long", k.get_symbol("PoolBigPageTableSize")?.address)?.u64()?;
    let (t, ty) = big_page_table_type(ctx, k)?;
    let esize = t.size_of(ty);
    let sp = crate::objects::Space::on(k.vlayer, t);
    let key = Field::new(t, "_POOL_TRACKER_BIG_PAGES", "Key")?;
    let va = Field::new(t, "_POOL_TRACKER_BIG_PAGES", "Va")?;
    for i in 0..count {
        let entry = Obj::new(sp, ty, table_ptr.wrapping_add(i.wrapping_mul(esize)));
        // is_valid(): Key > 0
        if entry.f(&key).int()? <= 0 {
            continue;
        }
        if let Some(tags) = tags {
            let k = entry.get_key()?;
            if !tags.iter().any(|t| *t == k) {
                continue;
            }
        }
        if !show_free && entry.f(&va).int()? & 1 == 1 {
            continue;
        }
        if !f(entry)? {
            break;
        }
    }
    Ok(())
}

impl Plugin for BigPools {
    fn name(&self) -> &'static str {
        "windows.bigpools.BigPools"
    }
    fn description(&self) -> &'static str {
        "List big page pools."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("tags", "Comma separated list of pool tags to filter pools returned", ReqKind::Str).optional(),
            Requirement::flag("show-free", "Show freed regions (otherwise only show allocations in use)"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Allocation", ColType::Hex),
            Column::new("Tag", ColType::Str),
            Column::new("PoolType", ColType::Str),
            Column::new("NumberOfBytes", ColType::Hex),
            Column::new("Status", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let tags: Option<Vec<String>> = cfg.get_str("tags").filter(|s| !s.is_empty()).map(|s| s.split(',').map(|x| x.to_string()).collect());
        let show_free = cfg.get_bool("show-free");
        list_big_pools_each(ctx, k, tags.as_deref(), show_free, |bp| {
            let num_bytes = bp.get_number_of_bytes()?;
            let status = if bp.is_free()? { "Free" } else { "Allocated" };
            out.row(0, vec![Value::Int(bp.m("Va")?.int()?), Value::Str(bp.get_key()?), bp.get_pool_type()?, num_bytes, Value::SStr(status)])?;
            Ok(true)
        })
    }
}
