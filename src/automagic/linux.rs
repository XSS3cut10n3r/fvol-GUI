//! Linux automagic (python `automagic/linux.py`: LinuxIntelStacker, LinuxIntelVMCOREINFOStacker,
//! LinuxSymbolFinder) producing the [`LinuxKernel`] handle behind `Context::linux_kernel()`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! python runs, for a linux plugin, the container stackers, then `LinuxIntelVMCOREINFOStacker`
//! (stack_order 34) and `LinuxIntelStacker` (35) on the physical layer; the first that stacks
//! wins. `LinuxSymbolFinder` then loads the kernel ISF matching the stacker's `kernel_banner`
//! with `symbol_mask = layer.address_mask`, and `KernelModule` makes the kernel module with
//! `offset = kernel_virtual_offset`. The same decisions are made here, streaming the scans in
//! python's hit order and stopping at the first usable hit (python scans everything first).
//! Results are cached per image (see [`crate::automagic::cache`]), so warm runs do no scanning.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::scan::{BytesScanner, FnScanner, MultiStringScanner, find, scan_each};
use crate::layers::{IntelLayer, Layer, PagingMode, PteFlavor};
use crate::objects::{LayerRef, Module};
use crate::symbols::linux::vmcoreinfo::{VmValue, search_vmcoreinfo_elf_note};
use crate::symbols::linux::{register_kernel, virtual_to_physical_address_i};
use crate::symbols::{IsfLocation, TableRef, Ty};
use crate::util::trace::span;

/// The Linux kernel (python `context.modules[config["kernel"]]` for linux plugins plus its
/// layers). Derefs to the kernel [`Module`] (offset = python `kernel_virtual_offset`, i.e. the
/// virtual ASLR shift; the symbol table has python's `symbol_mask` = layer address mask).
pub struct LinuxKernel {
    /// The kernel module (virtual layer, kernel symbol table, base = aslr_shift).
    pub module: Module,
    /// The kernel virtual layer (python `layer_name`, `LinuxIntel32e` / `Intel32e` / ...).
    pub layer: &'static IntelLayer,
    /// Same layer as `&dyn Layer`.
    pub vlayer: LayerRef,
    /// The physical layer (python `memory_layer`).
    pub phys: LayerRef,
    /// The kernel symbol table.
    pub table: TableRef,
    /// Physical KASLR shift.
    pub kaslr_shift: u64,
    /// Virtual ASLR shift (python `kernel_virtual_offset`).
    pub aslr_shift: u64,
    /// python `page_map_offset`.
    pub dtb: u64,
    /// The matched `linux_banner`.
    pub banner: Vec<u8>,
    /// Which python stacker produced the layer (`"LinuxIntelVMCOREINFOStacker"` or
    /// `"LinuxIntelStacker"`).
    pub stacker: &'static str,
}

impl std::ops::Deref for LinuxKernel {
    type Target = Module;
    fn deref(&self) -> &Module {
        &self.module
    }
}

/// Everything the Linux automagic determines for an image (cacheable).
#[derive(Clone, Debug, PartialEq)]
pub struct LinuxAutomagic {
    pub stacker: &'static str,
    pub mode: PagingMode,
    pub flavor: PteFlavor,
    pub dtb: u64,
    pub aslr_shift: u64,
    pub kaslr_shift: u64,
    pub banner: Vec<u8>,
    pub isf: IsfLocation,
}

const VMCOREINFO_STACKER: &str = "LinuxIntelVMCOREINFOStacker";
const INTEL_STACKER: &str = "LinuxIntelStacker";

// ------------------------------------------------------------------------------------------
// LinuxIntelVMCOREINFOStacker
// ------------------------------------------------------------------------------------------

/// python `LinuxIntelVMCOREINFOStacker.stack`. `Err` = python raised (the stacker fails).
pub fn vmcoreinfo_stack(phys: &dyn Layer, banners: &[(Vec<u8>, IsfLocation)]) -> Result<Option<LinuxAutomagic>> {
    let mut found = None;
    search_vmcoreinfo_elf_note(phys, |_off, vmci| {
        // _vmcoreinfo_find_aslr
        let (Some(phys_base), Some(kerneloffset)) = (vmci.get("NUMBER(phys_base)"), vmci.get("KERNELOFFSET")) else { return true };
        let (VmValue::Int(phys_base), VmValue::Int(kerneloffset)) = (phys_base, kerneloffset) else { return true };
        let aslr_shift = *kerneloffset;
        let kaslr_shift = phys_base + aslr_shift;
        // _vmcoreinfo_get_dtb
        let Some(VmValue::Int(dtb_vaddr)) = vmci.get("SYMBOL(swapper_pg_dir)") else { return true };
        let dtb = virtual_to_physical_address_i(*dtb_vaddr) - aslr_shift + kaslr_shift;
        // _vmcoreinfo_is_32bit
        let is_pae = matches!(vmci.get("CONFIG_X86_PAE"), Some(VmValue::Str(s)) if s == "y");
        let is_32bit = is_pae || *dtb_vaddr <= 1i128 << 32;
        let mode = match (is_32bit, is_pae) {
            (true, true) => PagingMode::Pae,
            (true, false) => PagingMode::Intel32,
            _ => PagingMode::Intel32e,
        };
        let uts_release = match vmci.get("OSRELEASE") {
            Some(VmValue::Str(s)) => s.clone(),
            Some(VmValue::Int(i)) => i.to_string(),
            None => return true,
        };
        let prefix = format!("Linux version {uts_release} (").into_bytes();
        let valid: Vec<&(Vec<u8>, IsfLocation)> = banners.iter().filter(|(b, _)| !b.is_empty() && b.starts_with(&prefix)).collect();
        let hit: Option<usize> = match valid.len() {
            0 => None,
            1 => {
                let _t = span("linux vmcoreinfo: banner scan (bytes)");
                let mut h = None;
                scan_each(phys, &BytesScanner::new(&valid[0].0), None, |_| {
                    h = Some(0);
                    false
                });
                h
            }
            _ => {
                let _t = span("linux vmcoreinfo: banner scan (multi)");
                let pats: Vec<&[u8]> = valid.iter().map(|(b, _)| b.as_slice()).collect();
                let mss = MultiStringScanner::new(&pats);
                let mut h = None;
                scan_each(phys, &mss, None, |(_, idx)| {
                    h = Some(idx as usize);
                    false
                });
                h
            }
        };
        match hit {
            Some(i) => {
                let (banner, isf) = valid[i].clone();
                found = Some(LinuxAutomagic {
                    stacker: VMCOREINFO_STACKER,
                    mode,
                    flavor: PteFlavor::Generic,
                    dtb: dtb as u64,
                    aslr_shift: aslr_shift as u64,
                    kaslr_shift: kaslr_shift as u64,
                    banner,
                    isf,
                });
                false
            }
            None => true,
        }
    })?;
    Ok(found)
}

// ------------------------------------------------------------------------------------------
// LinuxIntelStacker
// ------------------------------------------------------------------------------------------

/// The fixed python regex `rb"swapper(\/0|\x00\x00)\x00\x00\x00\x00\x00\x00"` (15 bytes; the
/// two alternatives have equal length and matches cannot overlap, so `re.finditer` reports
/// every occurrence).
pub fn swapper_matches(data: &[u8], mut f: impl FnMut(usize) -> bool) {
    let mut pos = 0usize;
    while let Some(i) = find(&data[pos..], b"swapper") {
        let at = pos + i;
        let tail = &data[at + 7..];
        let ok = tail.len() >= 8 && ((tail[0] == b'/' && tail[1] == b'0') || (tail[0] == 0 && tail[1] == 0)) && tail[2..8] == [0u8; 6];
        if ok {
            if !f(at) {
                return;
            }
            pos = at + 15;
        } else {
            pos = at + 1;
        }
    }
}

/// python `LinuxIntelStacker.find_aslr(context, table, layer)`: (kaslr_shift, aslr_shift) as
/// python ints. `Err` = python raised.
pub fn find_aslr(phys: LayerRef, table: TableRef) -> Result<(i128, i128)> {
    let init_task_json = table.get_symbol("init_task")?.address as i128;
    let module = Module::new(phys, table, 0);
    let comm = table.offset_of("task_struct", "comm")? as i128;
    let scanner = FnScanner::new(|data: &[u8], off: u64, hits: &mut Vec<u64>| {
        swapper_matches(data, |i| {
            if (i as u64) < crate::layers::scan::DEFAULT_CHUNK_SIZE {
                hits.push(off + i as u64);
                true
            } else {
                false
            }
        })
    });
    let mut result: Option<Result<(i128, i128)>> = None;
    let _t = span("linux find_aslr: swapper scan");
    scan_each(phys, &scanner, None, |offset| {
        let r = (|| -> Result<Option<(i128, i128)>> {
            let init_task_address = offset as i128 - comm;
            let t = module.object_abs("task_struct", init_task_address as u64)?;
            if t.m("pid")?.int()? != 0 {
                return Ok(None);
            }
            if t.has_member("state") && t.m("state")?.cast("unsigned int")?.int()? != 0 {
                return Ok(None);
            }
            let active_mm = t.m("active_mm")?.cast("long unsigned int")?.int()?;
            if active_mm == table.get_symbol("init_mm")?.address as i128 {
                let tasks = t.m("tasks")?;
                let next = tasks.m("next")?.cast("long unsigned int")?.int()?;
                let prev = tasks.m("prev")?.cast("long unsigned int")?.int()?;
                if next == prev {
                    return Ok(None);
                }
            }
            let files = t.m("files")?.raw_u64()? as i128;
            let aslr_shift = files - table.get_symbol("init_files")?.address as i128;
            let kaslr_shift = init_task_address - virtual_to_physical_address_i(init_task_json);
            if aslr_shift & 0xFFF != 0 || kaslr_shift & 0xFFF != 0 {
                return Ok(None);
            }
            Ok(Some((kaslr_shift, aslr_shift)))
        })();
        match r {
            Ok(None) => true,
            Ok(Some(v)) => {
                result = Some(Ok(v));
                false
            }
            Err(e) => {
                result = Some(Err(e));
                false
            }
        }
    });
    result.unwrap_or(Ok((0, 0)))
}

/// python `LinuxIntelStacker.stack`. `Err` = python raised (the stacker fails).
pub fn intel_stack(phys: LayerRef, banners: &[(Vec<u8>, IsfLocation)]) -> Result<Option<LinuxAutomagic>> {
    let pats: Vec<&[u8]> = banners.iter().map(|(b, _)| b.as_slice()).collect();
    let mss = MultiStringScanner::new(&pats);
    let mut out: Option<Result<LinuxAutomagic>> = None;
    let _t = span("linux intel stacker: banner scan");
    scan_each(phys, &mss, None, |(_, idx)| {
        let (banner, isf) = &banners[idx as usize];
        let r = (|| -> Result<Option<LinuxAutomagic>> {
            let table = crate::symbols::load_location(isf, "LintelStacker", None, 0)?;
            let (kaslr_shift, aslr_shift) = find_aslr(phys, table)?;
            let (mode, sym) = if table.has_symbol("init_top_pgt") {
                (PagingMode::Intel32e, "init_top_pgt")
            } else if table.has_symbol("init_level4_pgt") {
                (PagingMode::Intel32e, "init_level4_pgt")
            } else if table.has_symbol("pkmap_count") && {
                match table.get_symbol("pkmap_count")?.ty {
                    Some(Ty::Array { count, .. }) => count == 512 || count == 2048,
                    _ => return Err(Error::msg("AttributeError: pkmap_count type has no count")),
                }
            } {
                (PagingMode::Pae, "swapper_pg_dir")
            } else {
                (PagingMode::Intel32, "swapper_pg_dir")
            };
            let dtb = virtual_to_physical_address_i(table.get_symbol(sym)?.address as i128 + kaslr_shift);
            if dtb == 0 {
                return Ok(None);
            }
            Ok(Some(LinuxAutomagic {
                stacker: INTEL_STACKER,
                mode,
                flavor: PteFlavor::Linux,
                dtb: dtb as u64,
                aslr_shift: aslr_shift as u64,
                kaslr_shift: kaslr_shift as u64,
                banner: banner.clone(),
                isf: isf.clone(),
            }))
        })();
        match r {
            Ok(None) => true,
            Ok(Some(a)) => {
                out = Some(Ok(a));
                false
            }
            Err(e) => {
                out = Some(Err(e));
                false
            }
        }
    });
    out.transpose()
}

/// Run the Linux stackers on the physical layer (python `LayerStacker.stack_layer` restricted
/// to the Linux stackers, which only ever stack directly on the physical layer). `allow`
/// filters stackers by python class name (`--stackers`).
pub fn run(phys: LayerRef, banners: &[(Vec<u8>, IsfLocation)], allow: &dyn Fn(&str) -> bool) -> Option<LinuxAutomagic> {
    // "Never stack on top of an intel layer"; no banners -> nothing to do
    if phys.as_intel().is_some() || banners.is_empty() {
        return None;
    }
    if allow(VMCOREINFO_STACKER) {
        let _t = span("linux vmcoreinfo stacker");
        if let Ok(Some(a)) = vmcoreinfo_stack(phys, banners) {
            return Some(a);
        }
    }
    if allow(INTEL_STACKER) {
        let _t = span("linux intel stacker");
        if let Ok(Some(a)) = intel_stack(phys, banners) {
            return Some(a);
        }
    }
    None
}

// ------------------------------------------------------------------------------------------
// cache + Context entry point
// ------------------------------------------------------------------------------------------

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// Cache identity of an ISF location: (kind, a, b, stamp).
fn isf_key(loc: &IsfLocation) -> Option<(String, String, String, String)> {
    use crate::util::paths::file_stamp;
    let st = |p: &std::path::Path| file_stamp(p).map(|(s, m)| format!("{s}:{m}"));
    match loc {
        IsfLocation::File(p) => Some(("file".into(), p.to_string_lossy().into_owned(), String::new(), st(p)?)),
        IsfLocation::Zip { zip, member } => Some(("zip".into(), zip.to_string_lossy().into_owned(), member.clone(), st(zip)?)),
        IsfLocation::Embedded { rel, top, data } => Some(("embedded".into(), rel.to_string(), top.to_string(), data.len().to_string())),
    }
}

fn isf_from_key(kind: &str, a: &str, b: &str, stamp: &str) -> Option<IsfLocation> {
    let loc = match kind {
        "file" => IsfLocation::File(a.into()),
        "zip" => IsfLocation::Zip { zip: a.into(), member: b.to_string() },
        "embedded" => {
            let top = b == "true";
            let &(rel, _, data) = crate::symbols::embedded::FILES.iter().find(|(r, t, _)| *r == a && *t == top)?;
            IsfLocation::Embedded { rel, top, data }
        }
        _ => return None,
    };
    // the ISF must be unchanged
    (isf_key(&loc)?.3 == stamp).then_some(loc)
}

fn mode_name(m: PagingMode) -> &'static str {
    match m {
        PagingMode::Intel32 => "Intel32",
        PagingMode::Pae => "Pae",
        PagingMode::Intel32e => "Intel32e",
        PagingMode::La57 => "La57",
    }
}

/// The cache "kind": depends on the symbol search path and the `--stackers` filter.
fn cache_kind(ctx: &Context) -> String {
    use crate::util::fxhash::FxHasher;
    use std::hash::Hasher;
    let mut h = FxHasher::default();
    for r in &ctx.symbol_path().roots {
        h.write(format!("{r:?}").as_bytes());
    }
    if let Some(s) = &ctx.opts.stackers {
        for x in s {
            h.write(x.as_bytes());
            h.write_u8(0);
        }
    }
    format!("linux-{:016x}", h.finish())
}

fn load_cached(image: &std::path::Path, kind: &str) -> Option<LinuxAutomagic> {
    use crate::automagic::cache::get;
    let kv = crate::automagic::cache::load(image, kind)?;
    let num = |k: &str| get(&kv, k).and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok());
    Some(LinuxAutomagic {
        stacker: match get(&kv, "stacker")? {
            VMCOREINFO_STACKER => VMCOREINFO_STACKER,
            INTEL_STACKER => INTEL_STACKER,
            _ => return None,
        },
        mode: match get(&kv, "mode")? {
            "Intel32" => PagingMode::Intel32,
            "Pae" => PagingMode::Pae,
            "Intel32e" => PagingMode::Intel32e,
            "La57" => PagingMode::La57,
            _ => return None,
        },
        flavor: match get(&kv, "flavor")? {
            "Generic" => PteFlavor::Generic,
            "Linux" => PteFlavor::Linux,
            _ => return None,
        },
        dtb: num("dtb")?,
        aslr_shift: num("aslr")?,
        kaslr_shift: num("kaslr")?,
        banner: unhex(get(&kv, "banner")?)?,
        isf: isf_from_key(get(&kv, "isf_kind")?, get(&kv, "isf_a")?, get(&kv, "isf_b")?, get(&kv, "isf_stamp")?)?,
    })
}

fn store_cached(image: &std::path::Path, kind: &str, a: &LinuxAutomagic) {
    let Some((ik, ia, ib, st)) = isf_key(&a.isf) else { return };
    crate::automagic::cache::store(
        image,
        kind,
        &[
            ("stacker", a.stacker.to_string()),
            ("mode", mode_name(a.mode).to_string()),
            ("flavor", format!("{:?}", a.flavor)),
            ("dtb", format!("{:#x}", a.dtb)),
            ("aslr", format!("{:#x}", a.aslr_shift)),
            ("kaslr", format!("{:#x}", a.kaslr_shift)),
            ("banner", hex(&a.banner)),
            ("isf_kind", ik),
            ("isf_a", ia),
            ("isf_b", ib),
            ("isf_stamp", st),
        ],
    );
}

/// Run the Linux automagic for `ctx` (called once by `Context::linux_kernel`).
pub fn init(ctx: &Context) -> Result<LinuxKernel> {
    let _t = span("linux kernel init (total)");
    let (phys_arc, phys) = ctx.physical_arc()?;
    let image = ctx.image_path()?;
    let kind = cache_kind(ctx);
    let am = match load_cached(&image, &kind) {
        Some(a) => a,
        None => {
            let banners = {
                let _t = span("linux banners (identifier index)");
                crate::symbols::store::identifier_index(ctx.symbol_path()).dictionary("linux")
            };
            let stackers = ctx.opts.stackers.clone().filter(|s| !s.is_empty());
            let allow = |name: &str| stackers.as_ref().is_none_or(|s| s.iter().any(|x| x == name));
            let a = run(*phys, &banners, &allow)
                .ok_or_else(|| Error::Unsatisfied("Unable to validate the plugin requirements: no Linux kernel found".into()))?;
            store_cached(&image, &kind, &a);
            a
        }
    };
    let banner_str: String = am.banner.iter().map(|&b| b as char).collect();
    let layer = IntelLayer::new("layer_name", phys_arc.clone(), am.dtb, am.mode, am.flavor)
        .with_os("Linux")
        .with_kernel_virtual_offset(Some(am.aslr_shift))
        .with_kernel_banner(Some(banner_str));
    let layer: &'static IntelLayer = Box::leak(Box::new(layer));
    let vlayer: LayerRef = layer;
    let table = {
        let _t = span("linux kernel isf load");
        crate::symbols::load_location(&am.isf, "symbol_table_name", None, vlayer.address_mask())?
    };
    let module = Module::new(vlayer, table, am.aslr_shift);
    register_kernel(module);
    Ok(LinuxKernel {
        module,
        layer,
        vlayer,
        phys: *phys,
        table,
        kaslr_shift: am.kaslr_shift,
        aslr_shift: am.aslr_shift,
        dtb: am.dtb,
        banner: am.banner,
        stacker: am.stacker,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swapper_regex() {
        let mut d = vec![0u8; 64];
        d[3..10].copy_from_slice(b"swapper");
        d[10..12].copy_from_slice(b"/0");
        d[30..37].copy_from_slice(b"swapper");
        d[37] = b'/';
        d[38] = b'1';
        let mut v = Vec::new();
        swapper_matches(&d, |i| {
            v.push(i);
            true
        });
        assert_eq!(v, vec![3]);
        let mut d = b"swapper\x00\x00\x00\x00\x00\x00\x00\x00swapper/0\x00\x00\x00\x00\x00\x00".to_vec();
        d.push(1);
        let mut v = Vec::new();
        swapper_matches(&d, |i| {
            v.push(i);
            true
        });
        assert_eq!(v, vec![0, 15]);
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(unhex(&hex(b"Linux version\n\x00")).unwrap(), b"Linux version\n\x00");
    }
}
