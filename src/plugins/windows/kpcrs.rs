//! windows.kpcrs.KPCRs (python `plugins/windows/kpcrs.py`): the `_KPCR` of every processor,
//! from `KiProcessorBlock`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::objects::Obj;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};

pub struct KPCRs;

/// python `KPCRs.list_kpcrs(context, kernel_module_name)`: `(kpcr, kpcr.CurrentPrcb or
/// kpcr.Prcb)` per processor whose `_KPRCB` is readable (first byte), in `KiProcessorBlock`
/// order. A trailing `Err` = python raised there.
pub fn list_kpcrs(k: &WinKernel) -> Vec<Result<(Obj, Obj)>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        k.get_type("_KPCR")?;
        let reloff = k.offset_of("_KPCR", "Prcb")?;
        let member = if k.table.user_type("_KPCR").is_some_and(|ut| k.table.member(ut, "CurrentPrcb").is_some()) { "CurrentPrcb" } else { "Prcb" };
        let cpu_count = k.object("unsigned int", k.get_symbol("KeNumberProcessors")?.address)?.u64()?;
        // python constructs (reads) the first pointer, then recasts it as an array of pointers
        let block = k.object("pointer", k.get_symbol("KiProcessorBlock")?.address)?;
        block.u64()?;
        let ptr_ty = k.get_type("pointer")?;
        let arr = block.cast_array(cpu_count, ptr_ty);
        for i in 0..cpu_count {
            // iterating the array reads each pointer
            let kprcb = arr.at(i)?.u64()?;
            if !k.vlayer.is_valid(kprcb, 1) {
                continue;
            }
            let kpcr = k.object_abs("_KPCR", kprcb.wrapping_sub(reloff) & k.vlayer.address_mask())?;
            let m = kpcr.m(member)?;
            if m.is_pointer() {
                // python's member() constructs (reads) the pointer
                m.u64()?;
            }
            out.push(Ok((kpcr, m)));
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

impl Plugin for KPCRs {
    fn name(&self) -> &'static str {
        "windows.kpcrs.KPCRs"
    }
    fn description(&self) -> &'static str {
        "Print KPCR structure for each processor"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("Offset", ColType::Hex), Column::new("PRCB Offset", ColType::Hex)])?;
        let k = ctx.windows_kernel()?;
        for r in list_kpcrs(k) {
            let (kpcr, prcb) = r?;
            // python: format_hints.Hex(current_prcb) (the pointer value)
            let v = if prcb.is_pointer() { prcb.int()? } else { prcb.addr as i128 };
            out.row(0, vec![Value::Int(kpcr.addr as i128), Value::Int(v)])?;
        }
        Ok(())
    }
}
