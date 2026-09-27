//! windows.registry.hivelist.HiveList (python `plugins/windows/registry/hivelist.py`), plus
//! the shared hive helpers other plugins use: [`list_hive_objects`] (python
//! `HiveList.list_hive_objects`), [`list_hives`] (python `HiveList.list_hives`, yielding
//! [`RegistryHive`] layers) and [`registry_process`] (python
//! `RegistryHive._find_registry_process`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! let k = ctx.windows_kernel()?;
//! for h in list_hives(ctx, k, None, None) {
//!     let hive = h?;                     // an Err is where python raised (stop there)
//!     if hive.get_name().rsplit('\\').next().unwrap().eq_ignore_ascii_case("SYSTEM") { ... }
//! }
//! ```

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::layers::registry::{RegistryHive, RegistryProcess};
use crate::layers::{Layer, LayerExt};
use crate::objects::{LayerRef, Obj};
use crate::plugins::windows::pslist::sanitize_filename;
use crate::plugins::{Config, Plugin, Requirement, ReqKind};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;
use crate::symbols::windows::registry::cmhive_get_name;
use crate::util::{FxHashMap, FxHashSet};
use std::io::Write;
use std::sync::Mutex;

pub struct HiveList;

/// A clonable copy of an [`Error`] (for memoized results).
fn clone_err(e: &Error) -> Error {
    match e {
        Error::InvalidAddress { addr } => Error::InvalidAddress { addr: *addr },
        Error::Swapped { addr } => Error::Swapped { addr: *addr },
        Error::Symbol(s) => Error::Symbol(s.clone()),
        Error::Unsatisfied(s) => Error::Unsatisfied(s.clone()),
        Error::Layer(s) => Error::Layer(s.clone()),
        Error::Io(e) => Error::Msg(e.to_string()),
        Error::Msg(s) => Error::Msg(s.clone()),
    }
}

static REG_PROC: Mutex<Option<FxHashMap<usize, std::result::Result<RegistryProcess, String>>>> = Mutex::new(None);

/// python `RegistryHive._find_registry_process()` + `add_process_layer()`: the layer of the
/// `Registry` process (Win10 17063+), memoized per kernel layer. `RegistryProcess::Invalid`
/// = python raised InvalidAddressException while walking (the hive is then skipped).
pub fn registry_process(k: &WinKernel) -> Result<RegistryProcess> {
    let key = k.vlayer as *const dyn Layer as *const u8 as usize;
    if let Some(r) = REG_PROC.lock().unwrap().get_or_insert_with(Default::default).get(&key) {
        return r.clone().map_err(Error::Msg);
    }
    let r = find_registry_process(k);
    let stored = match &r {
        Ok(v) => Ok(*v),
        Err(e) => Err(e.to_string()),
    };
    REG_PROC.lock().unwrap().get_or_insert_with(Default::default).insert(key, stored);
    r
}

fn find_registry_process(k: &WinKernel) -> Result<RegistryProcess> {
    if k.base == 0 {
        // python ValueError, caught by RegistryHive.__init__
        return Ok(RegistryProcess::None);
    }
    let r = (|| -> Result<Option<LayerRef>> {
        let aph = k.get_symbol("PsActiveProcessHead")?.address;
        let list_entry = k.object("_LIST_ENTRY", aph)?;
        let reloff = k.offset_of("_EPROCESS", "ActiveProcessLinks")?;
        let eproc = k.object_abs("_EPROCESS", list_entry.addr.wrapping_sub(reloff))?;
        for p in eproc.m("ActiveProcessLinks")?.list_of("_EPROCESS", "ActiveProcessLinks") {
            let p = p?;
            if p.image_file_name_str()? == "Registry" && p.m("InheritedFromUniqueProcessId")?.int()? == 4 {
                return Ok(Some(p.add_process_layer()?));
            }
        }
        Ok(None)
    })();
    match r {
        Ok(Some(l)) => Ok(RegistryProcess::Found(l)),
        Ok(None) => Ok(RegistryProcess::None),
        Err(Error::InvalidAddress { addr }) | Err(Error::Swapped { addr }) => Ok(RegistryProcess::Invalid(addr)),
        Err(e) => Err(e),
    }
}

type HiveMemo = std::result::Result<&'static RegistryHive, Error>;
static HIVES: Mutex<Option<FxHashMap<(usize, u64), HiveMemo>>> = Mutex::new(None);

/// python `registry.RegistryHive(context, config, name="hive0x...")` for the kernel's layer,
/// memoized (every plugin sees the same layer object for a hive). `Err(InvalidAddress)` is what
/// python's `list_hives` skips; other errors propagate.
pub fn hive_at(k: &WinKernel, hive_offset: u64) -> Result<&'static RegistryHive> {
    let key = (k.vlayer as *const dyn Layer as *const u8 as usize, hive_offset);
    if let Some(r) = HIVES.lock().unwrap().get_or_insert_with(Default::default).get(&key) {
        return match r {
            Ok(h) => Ok(*h),
            Err(e) => Err(clone_err(e)),
        };
    }
    let r = RegistryHive::new(k.vlayer, k.table, hive_offset, || registry_process(k)).map(RegistryHive::leak);
    let stored = match &r {
        Ok(h) => Ok(*h),
        Err(e) => Err(clone_err(e)),
    };
    HIVES.lock().unwrap().get_or_insert_with(Default::default).insert(key, stored);
    r
}

/// python `HiveGenerator` + the filter / validity checks of `list_hive_objects` for one walk
/// direction. Returns the offset of the first invalid hive (python `hg.invalid`).
fn walk_hives(
    k: &WinKernel,
    cmhive: &Obj,
    forward: bool,
    filter: Option<&str>,
    seen: &mut FxHashSet<u64>,
    out: &mut Vec<Result<Obj>>,
) -> std::result::Result<Option<u64>, ()> {
    let links = match cmhive.m("HiveList") {
        Ok(l) => l,
        Err(e) => {
            out.push(Err(e));
            return Err(());
        }
    };
    for h in links.to_list("_CMHIVE", "HiveList", forward, true, None) {
        let hive = match h {
            Ok(h) => h,
            Err(e) => {
                out.push(Err(e));
                return Err(());
            }
        };
        if !crate::symbols::windows::registry::cmhive_is_valid(&hive) {
            return Ok(Some(hive.addr));
        }
        if !seen.insert(hive.addr) {
            // python breaks out of the consumer loop: the generator's `invalid` stays None
            return Ok(None);
        }
        if filter_ok(&hive, filter) && k.vlayer.is_valid(hive.addr, 1) {
            out.push(Ok(hive));
        }
    }
    Ok(None)
}

fn filter_ok(hive: &Obj, filter: Option<&str>) -> bool {
    match filter {
        None => true,
        Some(f) => cmhive_get_name(hive).unwrap_or_default().to_lowercase().contains(&f.to_lowercase()),
    }
}

/// python `HiveList.list_hive_objects(context, layer_name, symbol_table, filter_string)`:
/// the `_CMHIVE` objects of `CmpHiveListHead` (forward, then backward if the forward walk hit
/// an invalid hive, then a pool scan if both walks stopped at different places). A trailing
/// `Err` is where python raised.
pub fn list_hive_objects(ctx: &Context, k: &WinKernel, filter: Option<&str>) -> Vec<Result<Obj>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        if k.base == 0 {
            return Err(Error::msg("ValueError: Intel layer does not have an associated kernel virtual offset, failing"));
        }
        let list_head = k.get_symbol("CmpHiveListHead")?.address;
        let list_entry = k.object("_LIST_ENTRY", list_head)?;
        let reloff = k.offset_of("_CMHIVE", "HiveList")?;
        let cmhive = k.object_abs("_CMHIVE", list_entry.addr.wrapping_sub(reloff))?;
        let mut seen = FxHashSet::default();
        let Ok(forward_invalid) = walk_hives(k, &cmhive, true, filter, &mut seen, &mut out) else { return Ok(()) };
        let Some(forward_invalid) = forward_invalid.filter(|v| *v != 0) else { return Ok(()) };
        let Ok(backward_invalid) = walk_hives(k, &cmhive, false, filter, &mut seen, &mut out) else { return Ok(()) };
        let Some(backward_invalid) = backward_invalid.filter(|v| *v != 0) else { return Ok(()) };
        if forward_invalid == backward_invalid {
            return Ok(());
        }
        // revert to scanning, walking the list both ways from each found hive
        for hive in super::hivescan::scan_hives(ctx, k) {
            let hive = hive?;
            let r = (|| -> Result<()> {
                let flink = hive.m("HiveList")?.m("Flink")?.u64()?;
                if flink == 0 {
                    return Ok(());
                }
                let start = k.object_abs("_CMHIVE", flink.wrapping_sub(reloff))?;
                for forward in [true, false] {
                    for lh in start.m("HiveList")?.to_list("_CMHIVE", "HiveList", forward, true, None) {
                        let lh = lh?;
                        if !crate::symbols::windows::registry::cmhive_is_valid(&lh) || seen.contains(&lh.addr) {
                            continue;
                        }
                        seen.insert(lh.addr);
                        if filter_ok(&lh, filter) && k.vlayer.is_valid(lh.addr, 1) {
                            out.push(Ok(lh));
                        }
                    }
                }
                Ok(())
            })();
            match r {
                Ok(()) => {}
                Err(e) if e.is_invalid_address() => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

/// python `HiveList.list_hives(context, base_config_path, kernel_module_name, filter_string,
/// hive_offsets)`: the hive layers (hives whose construction hits an invalid address are
/// skipped, like python). A trailing `Err` is where python raised.
pub fn list_hives(ctx: &Context, k: &WinKernel, filter: Option<&str>, hive_offsets: Option<&[u64]>) -> Vec<Result<&'static RegistryHive>> {
    let offsets: Vec<u64> = match hive_offsets {
        Some(o) => o.to_vec(),
        None => {
            let mut v = Vec::new();
            for h in list_hive_objects(ctx, k, filter) {
                match h {
                    Ok(h) => v.push(h.addr),
                    // python computes the offsets eagerly: an error surfaces before any hive
                    Err(e) => return vec![Err(e)],
                }
            }
            v
        }
    };
    let mut out = Vec::with_capacity(offsets.len());
    for off in offsets {
        match hive_at(k, off) {
            Ok(h) => out.push(Ok(h)),
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => {
                out.push(Err(e));
                break;
            }
        }
    }
    out
}

/// python `HiveList._sanitize_hive_name`.
fn sanitize_hive_name(name: &str) -> String {
    name.rsplit('\\').next().unwrap_or("").replace(' ', "_").replace(['.', '[', ']'], "")
}

/// python's `--dump` body: returns the output file name.
fn dump_hive(ctx: &Context, k: &WinKernel, hive: &'static RegistryHive) -> Result<String> {
    const CHUNK: u64 = 0x500000;
    let maxaddr = hive.hive().m("Storage")?.at(0)?.m("Length")?.u64()?;
    let hive_name = sanitize_hive_name(hive.get_name());
    let (mut f, name) = ctx.create_output_file(&sanitize_filename(&format!("registry.{hive_name}.{:#x}.hive", hive.hive_offset())))?;
    let bb = hive.hive().m("BaseBlock")?.u64()?;
    let head = k.vlayer.read_vec(bb, 1 << 12)?;
    f.write_all(&head)?;
    let mut buf = vec![0u8; CHUNK.min(maxaddr) as usize];
    let mut i = 0u64;
    while i < maxaddr {
        let n = CHUNK.min(maxaddr - i) as usize;
        hive.read_padded(i, &mut buf[..n]);
        // the same bytes after the header, all-zero pages (unmapped cells) left as holes
        crate::cli::files::write_sparse(&f, &buf[..n], head.len() as u64 + i)?;
        i += CHUNK;
    }
    Ok(name)
}

impl Plugin for HiveList {
    fn name(&self) -> &'static str {
        "windows.registry.hivelist.HiveList"
    }
    fn description(&self) -> &'static str {
        "Lists the registry hives present in a particular memory image."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("filter", "String to filter hive names returned", ReqKind::Str).optional(),
            Requirement::flag("dump", "Extract listed registry hives"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("Offset", ColType::Hex), Column::new("FileFullPath", ColType::Str), Column::new("File output", ColType::Str)])?;
        let k = ctx.windows_kernel()?;
        let dump = cfg.get_bool("dump");
        let filter = cfg.get_str("filter");
        for h in list_hive_objects(ctx, k, filter) {
            let h = h?;
            let mut file_output = Value::SStr("Disabled");
            if dump {
                // python: next(list_hives(hive_offsets=[offset])) -- a skipped hive raises
                // StopIteration inside the generator (RuntimeError)
                let hive = match hive_at(k, h.addr) {
                    Ok(hive) => hive,
                    Err(e) if e.is_invalid_address() => return Err(Error::msg("RuntimeError: generator raised StopIteration")),
                    Err(e) => return Err(e),
                };
                file_output = Value::Str(dump_hive(ctx, k, hive)?);
            }
            out.row(0, vec![Value::Int(h.addr as i128), Value::Str(cmhive_get_name(&h).unwrap_or_default()), file_output])?;
        }
        Ok(())
    }
}
