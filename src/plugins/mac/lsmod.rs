//! mac.lsmod.Lsmod (python `plugins/mac/lsmod.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::mac::MacKernel;
use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::util::FxHashSet;

pub struct Lsmod;

/// python `Lsmod.list_modules(context, darwin_module_name)`: the first module is a
/// `kmod_info` struct, the following ones are `kmod_info *` POINTER objects (python yields
/// `kmod.next`; member access dereferences, `addr` is where the pointer lives -- which is
/// what python prints). A trailing `Err` means python raised there.
pub fn list_modules(k: &MacKernel) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    // `object_from_symbol` constructs (reads) the pointer: errors propagate
    let kmod_ptr = match k.object_from_symbol("kmod").and_then(|p| p.u64().map(|v| (p, v))) {
        Ok(p) => p,
        Err(e) => return vec![Err(e)],
    };
    let first = match kmod_ptr.0.target_ty() {
        Some(_) => match Obj::named(kmod_ptr.0.sp.native_space(), "kmod_info", kmod_ptr.1) {
            Ok(o) => o,
            Err(e) => return vec![Err(e)],
        },
        None => return vec![Err(crate::error::Error::msg("kmod is not a pointer"))],
    };
    out.push(Ok(first));
    let mut kmod = match first.m("next").and_then(|n| n.u64().map(|v| (n, v))) {
        Ok(n) => n,
        Err(e) if e.is_invalid_address() => return out,
        Err(e) => {
            out.push(Err(e));
            return out;
        }
    };
    let layer = k.vlayer;
    let size = match k.size_of("kmod_info") {
        Ok(s) => s,
        Err(e) => {
            out.push(Err(e));
            return out;
        }
    };
    let mut seen: FxHashSet<u64> = FxHashSet::default();
    while kmod.1 != 0 && !seen.contains(&kmod.1) && seen.len() < 1024 {
        if !layer.is_valid(kmod.1, size) {
            break;
        }
        seen.insert(kmod.1);
        out.push(Ok(kmod.0));
        match kmod.0.m("next").and_then(|n| n.u64().map(|v| (n, v))) {
            Ok(n) => kmod = n,
            Err(e) if e.is_invalid_address() => return out,
            Err(e) => {
                out.push(Err(e));
                return out;
            }
        }
    }
    out
}

impl Plugin for Lsmod {
    fn name(&self) -> &'static str {
        "mac.lsmod.Lsmod"
    }
    fn description(&self) -> &'static str {
        "Lists loaded kernel modules."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![Column::new("Offset", ColType::Hex), Column::new("Name", ColType::Str), Column::new("Size", ColType::Int)])?;
        for m in list_modules(k) {
            let m = m?;
            let name = array_to_string(&m.m("name")?, None)?;
            let size = m.m("size")?.int()?;
            out.row(0, vec![Value::Int(m.addr as i128), Value::Str(name), Value::Int(size)])?;
        }
        Ok(())
    }
}
