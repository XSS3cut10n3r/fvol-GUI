//! windows.info.Info (python `plugins/windows/info.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::layers::{Layer, metadata};
use crate::objects::{Obj, Space};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::{WinExt, kdbg, pe};
use crate::util::time::{asctime, py_str};
use std::sync::Arc;

pub struct Info;

/// python `Info.get_depends(context, layer_name)`: (depth, layer) for the layer tree.
pub fn get_depends(layer: &dyn Layer, index: usize, out: &mut Vec<(usize, String, &'static str)>) {
    out.push((index, layer.name().to_string(), layer.class_name()));
    for d in layer.dependencies() {
        get_depends_arc(&d, index + 1, out);
    }
}

fn get_depends_arc(layer: &Arc<dyn Layer>, index: usize, out: &mut Vec<(usize, String, &'static str)>) {
    get_depends(layer.as_ref(), index, out)
}

/// python `Info.get_kdbg_structure`: `_KDDEBUGGER_DATA64` (from the `windows/kdbg` ISF, with
/// the kernel's native types) at the kernel's `KdDebuggerDataBlock`.
pub fn get_kdbg_structure(ctx: &Context, k: &WinKernel) -> Result<Obj> {
    let kdbg_off = k.get_symbol("KdDebuggerDataBlock")?.address;
    let t = ctx.load_isf_with("windows/kdbg", Some(k.table), &[])?;
    Obj::named(Space::on(k.vlayer, t), "_KDDEBUGGER_DATA64", k.base.wrapping_add(kdbg_off))
}

/// python `Info.get_kuser_structure`.
pub fn get_kuser_structure(k: &WinKernel) -> Result<Obj> {
    let addr = if k.layer.bits_per_register() == 32 { 0xFFDF_0000 } else { 0xFFFF_F780_0000_0000 };
    k.object_abs("_KUSER_SHARED_DATA", addr)
}

/// python `Info.get_version_structure`.
pub fn get_version_structure(k: &WinKernel) -> Result<Obj> {
    k.object("_DBGKD_GET_VERSION64", k.get_symbol("KdVersionBlock")?.address)
}

/// python `Info.get_ntheader_structure`: the kernel's NT header (from the `windows/pe` ISF).
pub fn get_ntheader_structure(ctx: &Context, k: &WinKernel) -> Result<Obj> {
    let pe_t = ctx.load_isf("windows/pe")?;
    let dos = Obj::named(Space::on(k.vlayer, pe_t), "_IMAGE_DOS_HEADER", k.base)?;
    pe::get_nt_header(&dos)
}

fn py_bool(b: bool) -> &'static str {
    if b { "True" } else { "False" }
}

impl Plugin for Info {
    fn name(&self) -> &'static str {
        "windows.info.Info"
    }
    fn description(&self) -> &'static str {
        "Show OS & kernel details of the memory sample being analyzed."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("Variable", ColType::Str), Column::new("Value", ColType::Str)])?;
        let k = ctx.windows_kernel()?;
        let mut row = |a: &str, b: String| out.row(0, vec![Value::str(a), Value::Str(b)]);
        let kdbg = get_kdbg_structure(ctx, k)?;
        row("Kernel Base", format!("{:#x}", k.base))?;
        row("DTB", format!("{:#x}", k.dtb))?;
        row("Symbols", k.table.isf_url().to_string())?;
        row("Is64Bit", py_bool(k.table.is_64bit()).into())?;
        row("IsPAE", py_bool(metadata(k.vlayer).pae.unwrap_or(false)).into())?;
        // python get_depends(kernel.layer_name): the kernel layer, then its memory_layer
        // subtree (container stack), then swap layers
        row(k.vlayer.name(), format!("0 {}", k.vlayer.class_name()))?;
        for e in ctx.physical_listing()? {
            row(&e.name, format!("{} {}", e.depth + 1, e.class))?;
        }
        for swap in k.vlayer.dependencies().iter().skip(1) {
            let mut deps = Vec::new();
            get_depends(swap.as_ref(), 1, &mut deps);
            for (i, name, class) in deps {
                row(&name, format!("{i} {class}"))?;
            }
        }
        if kdbg.path("Header.OwnerTag")?.u64()? == 0x4742444B {
            row("KdDebuggerDataBlock", format!("{:#x}", kdbg.addr))?;
            row("NTBuildLab", kdbg::get_build_lab(&kdbg)?)?;
            row("CSDVersion", kdbg::get_csdversion(&kdbg)?.to_string())?;
        }
        let vers = get_version_structure(k)?;
        row("KdVersionBlock", format!("{:#x}", vers.addr))?;
        row("Major/Minor", format!("{}.{}", vers.m("MajorVersion")?.int()?, vers.m("MinorVersion")?.int()?))?;
        row("MachineType", vers.m("MachineType")?.int()?.to_string())?;
        let cpu = k.object("unsigned int", k.get_symbol("KeNumberProcessors")?.address)?;
        row("KeNumberProcessors", cpu.int()?.to_string())?;
        let kuser = get_kuser_structure(k)?;
        let st = match kuser.m("SystemTime")?.get_time()? {
            Value::DateTime(d) => py_str(&d),
            Value::NotApplicable => "N/A".into(),
            _ => "-".into(),
        };
        row("SystemTime", st)?;
        row("NtSystemRoot", kuser.m("NtSystemRoot")?.read_string(260, "utf-16", "replace")?)?;
        row("NtProductType", kuser.m("NtProductType")?.description()?.to_string())?;
        row("NtMajorVersion", kuser.m("NtMajorVersion")?.int()?.to_string())?;
        row("NtMinorVersion", kuser.m("NtMinorVersion")?.int()?.to_string())?;
        let nt = get_ntheader_structure(ctx, k)?;
        row("PE MajorOperatingSystemVersion", nt.path("OptionalHeader.MajorOperatingSystemVersion")?.int()?.to_string())?;
        row("PE MinorOperatingSystemVersion", nt.path("OptionalHeader.MinorOperatingSystemVersion")?.int()?.to_string())?;
        row("PE Machine", nt.path("FileHeader.Machine")?.int()?.to_string())?;
        row("PE TimeDateStamp", asctime(nt.path("FileHeader.TimeDateStamp")?.int()? as i64))?;
        Ok(())
    }
}
