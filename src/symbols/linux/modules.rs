//! python `symbols/linux/utilities/modules.py`: `Modules` (kernel module utilities),
//! `ModuleInfo`, and the module gatherers (`ModuleGathererLsmod`, `...SysFs`, `...Scanner`,
//! `...Kernel`, `ModuleGatherers.all_gatherers_identifier`). `ModuleExtract` (the ELF
//! rebuilder) is not ported here.
//!
//! For plugin porters (python -> rust):
//!   * `Modules.list_modules(ctx, kernel)` -> [`list_modules`]`(k)`
//!   * `Modules.run_modules_scanners(ctx, kernel, ModuleGatherers.all_gatherers_identifier)` ->
//!     [`run_modules_scanners`]`(k, &ALL_GATHERERS)` (flatten=True) /
//!     [`run_modules_scanners_by_gatherer`] (flatten=False)
//!   * `Modules.module_lookup_by_address(ctx, kernel, modules, addr)` ->
//!     [`module_lookup_by_address`]`(k, &modules, addr)`
//!   * `Modules.get_modules_memory_boundaries` / `get_hidden_modules` / `get_kset_modules` /
//!     `get_load_parameters` / `get_module_info_for_module` -> same names.
//!
//! Functions take the kernel [`Module`] (`&LinuxKernel` derefs to it: pass `k`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use super::constants::KERNEL_NAME;
use super::module::{ModuleExt, module_is_valid_checked};
use super::LinuxExt;
use crate::error::{Error, Result};
use crate::objects::util::{array_to_string, pointer_to_string};
use crate::objects::{Module, Obj};

/// python `ModuleInfo(offset, name, start, end)` (addresses masked with the kernel layer's
/// address mask).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleInfo {
    /// `module.vol.offset` (the kernel's `_text` for the kernel entry).
    pub offset: u64,
    pub name: String,
    pub start: u64,
    pub end: u64,
}

/// python module gatherer classes (`ModuleGathererInterface` subclasses).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gatherer {
    /// `ModuleGathererLsmod`: the `modules` list.
    Lsmod,
    /// `ModuleGathererSysFs`: `/sys/module` kset objects.
    SysFs,
    /// `ModuleGathererScanner`: memory scan of the module allocation area.
    Scanner,
    /// `ModuleGathererKernel`: a [`ModuleInfo`] for the kernel itself.
    Kernel,
}

/// python `ModuleGatherers.all_gatherers_identifier`.
pub const ALL_GATHERERS: [Gatherer; 4] = [Gatherer::Lsmod, Gatherer::SysFs, Gatherer::Scanner, Gatherer::Kernel];

impl Gatherer {
    /// python `gatherer.name`.
    pub fn name(self) -> &'static str {
        match self {
            Gatherer::Lsmod => "Lsmod",
            Gatherer::SysFs => "SysFs",
            Gatherer::Scanner => "Scanner",
            Gatherer::Kernel => "kernel",
        }
    }

    /// python `gatherer.gather_modules(context, kernel_module_name)` (collected; `Err` where
    /// python raises).
    pub fn gather_modules(self, vm: &Module) -> Result<Vec<Gathered>> {
        match self {
            Gatherer::Lsmod => list_modules(vm).into_iter().map(|m| m.map(Gathered::Module)).collect(),
            Gatherer::SysFs => {
                let mut out = Vec::new();
                for (_, m_offset) in get_kset_modules(vm)? {
                    out.push(Gathered::Module(vm.object_abs("module", m_offset)?));
                }
                Ok(out)
            }
            Gatherer::Scanner => {
                let bounds = get_modules_memory_boundaries(vm)?;
                get_hidden_modules(vm, &[], bounds).into_iter().map(|m| m.map(Gathered::Module)).collect()
            }
            Gatherer::Kernel => {
                let mask = vm.layer().address_mask();
                let start = vm.object_from_symbol("_text")?.addr & mask;
                let end = vm.object_from_symbol("_etext")?.addr & mask;
                Ok(vec![Gathered::Info(ModuleInfo { offset: start, name: KERNEL_NAME.to_string(), start, end })])
            }
        }
    }
}

/// What a gatherer yields: a `module` object or (kernel gatherer) a ready [`ModuleInfo`].
#[derive(Clone, Debug)]
pub enum Gathered {
    Module(Obj),
    Info(ModuleInfo),
}

/// python `Modules.list_modules(context, vmlinux_module_name)`: the `modules` list (python's
/// lazy generator collected; a trailing `Err` means python raised there).
pub fn list_modules(vm: &Module) -> Vec<Result<Obj>> {
    let head = match vm.object_from_symbol("modules").and_then(|m| m.cast("list_head")) {
        Ok(h) => h,
        Err(e) => return vec![Err(e)],
    };
    let sym = format!("{}!module", vm.symbol_table_name());
    let mut out = Vec::new();
    for m in head.to_list(&sym, "list", true, true, None) {
        let stop = m.is_err();
        out.push(m);
        if stop {
            break;
        }
    }
    out
}

/// python `Modules.get_module_info_for_module(address_mask, module)`: `Ok(None)` when the name
/// is smeared.
pub fn get_module_info_for_module(address_mask: u64, module: &Obj) -> Result<Option<ModuleInfo>> {
    let name = match module.m("name").and_then(|n| array_to_string(&n, None)) {
        Ok(n) => n,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    let start = module.get_module_base()? & address_mask;
    let end = (start as i128 + module.get_core_size()?) as u64;
    Ok(Some(ModuleInfo { offset: module.addr, name, start, end }))
}

/// Validate `caller_wanted_gatherers` like python (non-empty, unique names).
fn check_gatherers(gatherers: &[Gatherer]) -> Result<()> {
    if gatherers.is_empty() {
        return Err(Error::msg("ValueError: `caller_wanted_gatherers` must have at least one gatherer."));
    }
    for (i, g) in gatherers.iter().enumerate() {
        if gatherers[..i].iter().any(|o| o.name() == g.name()) {
            return Err(Error::msg(format!("ValueError: {g:?} has a name {} which has already been processed. Names must be unique.", g.name())));
        }
    }
    Ok(())
}

/// python `Modules.run_modules_scanners(context, kernel, gatherers, flatten=False)`: per
/// gatherer (in order) its [`ModuleInfo`]s.
pub fn run_modules_scanners_by_gatherer(vm: &Module, gatherers: &[Gatherer]) -> Result<Vec<(&'static str, Vec<ModuleInfo>)>> {
    check_gatherers(gatherers)?;
    let mask = vm.layer().address_mask();
    let mut out = Vec::with_capacity(gatherers.len());
    for g in gatherers {
        let mut infos = Vec::new();
        for m in g.gather_modules(vm)? {
            let info = match m {
                Gathered::Info(i) => Some(i),
                Gathered::Module(m) => get_module_info_for_module(mask, &m)?,
            };
            if let Some(i) = info {
                infos.push(i);
            }
        }
        out.push((g.name(), infos));
    }
    Ok(out)
}

/// python `Modules.run_modules_scanners(context, kernel, gatherers)` (flatten=True):
/// de-duplicated (by start address) list over all gatherers.
pub fn run_modules_scanners(vm: &Module, gatherers: &[Gatherer]) -> Result<Vec<ModuleInfo>> {
    Ok(flatten_run_modules_results(run_modules_scanners_by_gatherer(vm, gatherers)?, true))
}

/// python `Modules.flatten_run_modules_results(run_results, deduplicate)`.
pub fn flatten_run_modules_results(run_results: Vec<(&'static str, Vec<ModuleInfo>)>, deduplicate: bool) -> Vec<ModuleInfo> {
    let mut seen = crate::util::FxHashSet::default();
    let mut out = Vec::new();
    for (_, modules) in run_results {
        for m in modules {
            if deduplicate && seen.contains(&m.start) {
                continue;
            }
            seen.insert(m.start);
            out.push(m);
        }
    }
    out
}

/// python `Modules.module_lookup_by_address(context, kernel, modules, target_address)`:
/// (first module containing the address, symbol name). python's quirk is kept: the symbol of a
/// non-kernel match is looked up in the `module` struct at the offset of the *last* entry of
/// `modules` (the loop variable leaks).
pub fn module_lookup_by_address(vm: &Module, modules: &[ModuleInfo], target_address: u64) -> Result<(Option<ModuleInfo>, Option<String>)> {
    let mask = vm.layer().address_mask();
    if modules.is_empty() {
        return Err(Error::msg("ValueError: Empty list sent to `module_lookup_by_address`"));
    }
    let mut first: Option<&ModuleInfo> = None;
    let mut n_matches = 0usize;
    for m in modules {
        if m.start != m.start & mask {
            return Err(Error::msg("ValueError: Modules list must be gathered from `run_modules_scanners` to be used in this function"));
        }
        if m.start <= target_address && target_address < m.end {
            n_matches += 1;
            if first.is_none() {
                first = Some(m);
            }
        }
    }
    let _ = n_matches; // python warns on overlaps (stderr only)
    let Some(matched) = first else { return Ok((None, None)) };
    let mut symbol_name: Option<String> = if matched.name == KERNEL_NAME {
        vm.symbols_at(target_address, 0).first().map(|s| format!("{}!{}", vm.symbol_table_name(), s))
    } else {
        let last = modules.last().unwrap();
        let module = vm.object_abs("module", last.offset)?;
        module.get_symbol_by_address(target_address)?
    };
    if let Some(s) = &symbol_name {
        if s.contains('!') {
            symbol_name = s.split('!').nth(1).map(str::to_string);
        }
    }
    if symbol_name.as_deref() == Some("") {
        // python: `if symbol_name and ...` leaves "" untouched
    }
    Ok((Some(matched.clone()), symbol_name))
}

/// python `Modules.mask_mods_list(context, layer_name, mods)` (deprecated): (name, start, end).
pub fn mask_mods_list(mask: u64, mods: &[Obj]) -> Result<Vec<(String, u64, u64)>> {
    let mut out = Vec::with_capacity(mods.len());
    for m in mods {
        let name = array_to_string(&m.m("name")?, None)?;
        let start = m.get_module_base()? & mask;
        let end = ((m.get_module_base()? & mask) as i128 + m.get_core_size()?) as u64;
        out.push((name, start, end));
    }
    Ok(out)
}

/// python `Modules.lookup_module_address(context, kernel, handlers, target_address)`
/// (deprecated): (module name or "UNKNOWN", symbol name or "N/A").
pub fn lookup_module_address(vm: &Module, handlers: &[(String, u64, u64)], target_address: u64) -> (String, String) {
    let mut mod_name = "UNKNOWN".to_string();
    let mut symbol_name = "N/A".to_string();
    for (name, start, end) in handlers {
        if *start <= target_address && target_address <= *end {
            mod_name = name.clone();
            if name == KERNEL_NAME {
                if let Some(s) = vm.symbols_at(target_address, 0).first() {
                    // python: symbols[0].split("!")[1] of "<table>!<name>"
                    let full = format!("{}!{}", vm.symbol_table_name(), s);
                    symbol_name = full.split('!').nth(1).unwrap_or("").to_string();
                }
            }
            break;
        }
    }
    (mod_name, symbol_name)
}

/// python `Modules.get_modules_memory_boundaries(context, vmlinux_module_name)`: the module
/// allocation area (min, max) as read (not masked).
pub fn get_modules_memory_boundaries(vm: &Module) -> Result<(u64, u64)> {
    if vm.has_symbol("mod_tree") {
        let mt = vm.object_from_symbol("mod_tree")?;
        return Ok((mt.m("addr_min")?.u64()?, mt.m("addr_max")?.u64()?));
    }
    if vm.has_symbol("module_addr_min") {
        let lo = vm.object_from_symbol("module_addr_min").map_err(|_| Error::msg("Your ISF symbols lack type information. You may need to update theISF using the latest version of dwarf2json"))?;
        let hi = vm.object_from_symbol("module_addr_max")?;
        return Ok((lo.u64()?, hi.u64()?));
    }
    Err(Error::msg("Cannot find the module memory allocation area. Unsupported kernel"))
}

/// python `Modules.get_module_address_alignment(context, vmlinux_module_name)` (pointer size).
pub fn get_module_address_alignment(vm: &Module) -> Result<u64> {
    Ok(vm.table().size_of(vm.get_type("pointer")?))
}

/// python `Modules.validate_alignment_patterns(addresses, address_alignment)`.
pub fn validate_alignment_patterns(addresses: &[u64], address_alignment: u64) -> bool {
    addresses.iter().all(|a| a % address_alignment == 0)
}

/// python `Modules.get_hidden_modules(context, kernel, known_module_addresses,
/// modules_memory_boundaries)`: every valid `module` struct in `[min, max)` (stepping by the
/// module alignment) whose `mkobj.mod` points back at itself, except the known addresses.
/// Collected in python order; a trailing `Err` means python raised there. The self-reference
/// pre-filter scans the valid pages of the area in parallel.
pub fn get_hidden_modules(vm: &Module, known_module_addresses: &[u64], bounds: (u64, u64)) -> Vec<Result<Obj>> {
    let r = (|| -> Result<Vec<u64>> {
        let (lo, hi) = bounds;
        let mut align = get_module_address_alignment(vm)?;
        if !validate_alignment_patterns(known_module_addresses, align) {
            align = 1;
        }
        let off = vm.offset_of("module", "mkobj")? + vm.offset_of("module_kobject", "mod")?;
        let modk = vm.get_type("module_kobject")?;
        let mod_size = match modk {
            crate::symbols::Ty::Struct(ut) => {
                let t = vm.table();
                let m = t.member(ut, "mod").ok_or_else(|| Error::Symbol("AttributeError: module_kobject has no attribute: mod".into()))?;
                t.size_of(m.ty)
            }
            _ => return Err(Error::Symbol("module_kobject".into())),
        };
        Ok(scan_self_referential(vm, lo, hi, align, off, mod_size))
    })();
    let hits = match r {
        Ok(h) => h,
        Err(e) => return vec![Err(e)],
    };
    let mut out = Vec::new();
    for a in hits {
        if known_module_addresses.contains(&a) {
            continue;
        }
        let module = match vm.object_abs("module", a) {
            Ok(m) => m,
            Err(e) => {
                out.push(Err(e));
                break;
            }
        };
        match module_is_valid_checked(&module) {
            Ok(true) => out.push(Ok(module)),
            Ok(false) => {}
            Err(e) => {
                out.push(Err(e));
                break;
            }
        }
    }
    out
}

/// The `get_hidden_modules` pre-filter: every `a` in `range(lo, hi, align)` where the
/// `mod_size`-byte little-endian value at `a + off` is readable and equals `a`. Ascending.
fn scan_self_referential(vm: &Module, lo: u64, hi: u64, align: u64, off: u64, mod_size: u64) -> Vec<u64> {
    if hi <= lo || align == 0 || mod_size == 0 || mod_size > 8 {
        return Vec::new();
    }
    let layer = vm.layer();
    let mask = layer.address_mask();
    // chunks of the address range, a multiple of `align` so chunk starts stay on the grid
    const CHUNK: u64 = 1 << 22;
    let step = (CHUNK / align).max(1) * align;
    let n = (hi - lo).div_ceil(step);
    let parts = crate::util::par::par_map(n as usize, |i| {
        let cstart = lo + i as u64 * step;
        let cend = cstart.saturating_add(step).min(hi);
        let mut hits = Vec::new();
        // bytes needed: [cstart + off, (cend - 1) + off + mod_size)
        let vstart = cstart.wrapping_add(off) & mask;
        let vlen = (cend - cstart) + mod_size - 1;
        // merged valid virtual runs
        let mut runs: Vec<(u64, u64)> = Vec::new();
        layer.mapping(vstart, vlen, &mut |m| {
            match runs.last_mut() {
                Some(r) if r.1 == m.offset => r.1 += m.len,
                _ => runs.push((m.offset, m.offset + m.len)),
            }
            true
        });
        let mut buf = Vec::new();
        for (rs, re) in runs {
            // candidate addresses a with [a+off, a+off+mod_size) inside [rs, re)
            let first_v = rs;
            let last_v = match re.checked_sub(mod_size) {
                Some(v) if v >= first_v => v,
                _ => continue,
            };
            // map virtual positions back to candidate addresses: a = cstart + (v - vstart)
            let d0 = first_v - vstart;
            let d1 = last_v - vstart;
            // first grid point >= d0
            let k0 = d0.div_ceil(align) * align;
            if k0 > d1 {
                continue;
            }
            buf.resize((re - rs) as usize, 0);
            if layer.read(rs, &mut buf).is_err() {
                // fall back to exact per-candidate reads
                let mut d = k0;
                while d <= d1 {
                    let a = cstart + d;
                    if a < cend {
                        let mut b = [0u8; 8];
                        if layer.read(vstart + d, &mut b[..mod_size as usize]).is_ok() && u64::from_le_bytes(b) == a {
                            hits.push(a);
                        }
                    }
                    d += align;
                }
                continue;
            }
            let mut d = k0;
            while d <= d1 {
                let a = cstart + d;
                if a >= cend {
                    break;
                }
                let p = (vstart + d - rs) as usize;
                let mut b = [0u8; 8];
                b[..mod_size as usize].copy_from_slice(&buf[p..p + mod_size as usize]);
                if u64::from_le_bytes(b) == a {
                    hits.push(a);
                }
                d += align;
            }
        }
        hits
    });
    parts.into_iter().flatten().collect()
}

/// python `Modules.get_kset_modules(context, vmlinux_name)`: `/sys/module` entries with a
/// reference count > 2, as an insertion-ordered map name -> `module_kobject.mod` pointer value.
pub fn get_kset_modules(vm: &Module) -> Result<Vec<(String, u64)>> {
    let module_kset = match vm.object_from_symbol("module_kset") {
        Ok(k) => Some(k),
        Err(Error::Symbol(_)) => None,
        Err(e) => return Err(e),
    };
    let module_kset = match module_kset {
        Some(k) if k.u64()? != 0 => k,
        _ => {
            return Err(Error::msg(
                "TypeError: This plugin requires the module_kset structure. This structure is not present in the supplied symbol table. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt.",
            ));
        }
    };
    let mut ret: Vec<(String, u64)> = Vec::new();
    let kobj_off = vm.offset_of("module_kobject", "kobj")?;
    let sym = format!("{}!kobject", vm.symbol_table_name());
    for kobj in module_kset.m("list")?.to_list(&sym, "entry", true, true, None) {
        let kobj = kobj?;
        let mod_kobj = vm.object_abs("module_kobject", kobj.addr.wrapping_sub(kobj_off))?;
        let modv = mod_kobj.m("mod")?.u64()?;
        let name_ptr = kobj.m("name")?;
        let name = match pointer_to_string(&name_ptr, 32) {
            Ok(n) => n,
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => return Err(e),
        };
        if name_ptr.u64()? != 0 && kobj.reference_count()? > 2 {
            match ret.iter_mut().find(|(n, _)| *n == name) {
                Some(e) => e.1 = modv,
                None => ret.push((name, modv)),
            }
        }
    }
    Ok(ret)
}

/// A decoded module load parameter value (python `Optional[Union[str, int]]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamValue {
    None,
    Str(String),
    Int(i128),
}

impl std::fmt::Display for ParamValue {
    /// python `str(value)` / f-string formatting.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParamValue::None => f.write_str("None"),
            ParamValue::Str(s) => f.write_str(s),
            ParamValue::Int(i) => write!(f, "{i}"),
        }
    }
}

/// python `Modules._get_param_handlers(context, vmlinux_name)`: (int handler address -> type
/// name, getters by name).
pub struct ParamHandlers {
    /// python `int_handlers` (dict: later duplicates overwrite).
    pub int_handlers: Vec<(u64, &'static str)>,
    /// python `getters` (name -> absolute address or None).
    pub getters: Vec<(&'static str, Option<u64>)>,
}

impl ParamHandlers {
    fn getter(&self, name: &str) -> Option<u64> {
        self.getters.iter().find(|g| g.0 == name).and_then(|g| g.1)
    }
    fn int_handler(&self, addr: u64) -> Option<&'static str> {
        self.int_handlers.iter().find(|h| h.0 == addr).map(|h| h.1)
    }
}

/// python `Modules._get_param_handlers`.
pub fn get_param_handlers(vm: &Module) -> ParamHandlers {
    const PAIRS: [(&str, &str); 10] = [
        ("param_get_invbool", "int"),
        ("param_get_bool", "int"),
        ("param_get_int", "int"),
        ("param_get_ulong", "long unsigned int"),
        ("param_get_ullong", "long long unsigned int"),
        ("param_get_long", "long int"),
        ("param_get_uint", "unsigned int"),
        ("param_get_ushort", "short unsigned int"),
        ("param_get_short", "short int"),
        ("param_get_byte", "char"),
    ];
    let mut int_handlers: Vec<(u64, &'static str)> = Vec::new();
    for (sym, ty) in PAIRS {
        let Ok(a) = vm.symbol_addr(sym) else { continue };
        match int_handlers.iter_mut().find(|h| h.0 == a) {
            Some(h) => h.1 = ty,
            None => int_handlers.push((a, ty)),
        }
    }
    let getters = ["param_get_string", "param_array_get", "param_get_charp", "param_get_bool", "param_get_invbool"].into_iter().map(|n| (n, vm.symbol_addr(n).ok())).collect();
    ParamHandlers { int_handlers, getters }
}

/// python `Modules._get_param_val(context, vmlinux_name, int_handlers, getters, module, param)`.
pub fn get_param_val(vm: &Module, h: &ParamHandlers, param: &Obj) -> Result<ParamValue> {
    let func = (|| -> Result<u64> {
        if param.has_member("get") { param.m("get")?.u64() } else { param.m("ops")?.m("get")?.u64() }
    })();
    let param_func = match func {
        Ok(v) => v,
        Err(e) if e.is_invalid_address() => return Ok(ParamValue::None),
        Err(e) => return Err(e),
    };
    if param_func == 0 {
        return Ok(ParamValue::None);
    }
    if Some(param_func) == h.getter("param_array_get") {
        let array = param.m("arr")?.deref()?;
        let num = array.m("num")?;
        let max_index = if num.u64()? != 0 { num.deref()?.int()? } else { array.m("max")?.int()? };
        if max_index > 32 {
            return Ok(ParamValue::None);
        }
        let mut vals = Vec::new();
        let elem = array.m("elem")?.u64()?;
        let elemsize = array.m("elemsize")?.int()?;
        for i in 0..max_index.max(0) {
            let kp = vm.object_abs("kernel_param", (elem as i128 + elemsize * i) as u64)?;
            vals.push(get_param_val(vm, h, &kp)?);
        }
        if vals.is_empty() {
            return Ok(ParamValue::None);
        }
        return Ok(ParamValue::Str(vals.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")));
    }
    let is_string = Some(param_func) == h.getter("param_get_string");
    if is_string || Some(param_func) == h.getter("param_get_charp") {
        let r = (|| -> Result<String> {
            let s = param.m("str")?;
            let count = if is_string { s.m("maxlen")?.int()? } else { 256 };
            if count < 1 {
                return Err(Error::msg("ValueError: pointer_to_string requires a positive count"));
            }
            pointer_to_string(&s, count as u64)
        })();
        return match r {
            Ok(s) => Ok(ParamValue::Str(s)),
            Err(e) if e.is_invalid_address() => Ok(ParamValue::None),
            Err(e) => Err(e),
        };
    }
    if let Some(ty) = h.int_handler(param_func) {
        let arg = param.m("arg")?.u64()?;
        let v = match vm.object(ty, arg).and_then(|o| o.int()) {
            Ok(v) => v,
            Err(e) if e.is_invalid_address() => return Ok(ParamValue::None),
            Err(e) => return Err(e),
        };
        if Some(param_func) == h.getter("param_get_bool") {
            return Ok(ParamValue::Str(if v == 0 { "N" } else { "Y" }.into()));
        } else if Some(param_func) == h.getter("param_get_invbool") {
            return Ok(ParamValue::Str(if v == 0 { "Y" } else { "N" }.into()));
        }
        return Ok(ParamValue::Int(v));
    }
    // unknown handler (python logs it)
    Ok(ParamValue::None)
}

/// python `Modules.get_load_parameters(context, vmlinux_name, module)`: (name, value) per
/// parameter; a trailing `Err` means python raised there.
pub fn get_load_parameters(vm: &Module, module: &Obj) -> Vec<Result<(String, ParamValue)>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        if !module.has_member("kp") {
            return Ok(());
        }
        let num_kp = module.m("num_kp")?.int()?;
        if num_kp > 128 {
            return Ok(());
        }
        let h = get_param_handlers(vm);
        let kp = module.m("kp")?.deref()?.addr;
        let kparam = vm.get_type("kernel_param")?;
        let arr = vm.object_abs("kernel_param", kp)?.cast_array(num_kp.max(0) as u64, kparam);
        for i in 0..arr.count() {
            let r = arr.at(i).and_then(|p| Ok((p, pointer_to_string(&p.m("name")?, 32)?)));
            let (param, name) = match r {
                Ok(v) => v,
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            };
            let value = get_param_val(vm, &h, &param)?;
            out.push(Ok((name, value)));
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Context, GlobalOptions};

    fn ctx() -> Context {
        let image = std::env::var("RSVOL_BENCH_IMAGE").unwrap();
        Context::new(GlobalOptions { file: Some(image), symbol_dirs: vec!["/home/user/rs-vol/testdata/symbols".into()], ..Default::default() }).unwrap()
    }

    /// Time each module gatherer and print what it finds:
    /// `RSVOL_BENCH_IMAGE=<img> cargo test --profile fast gatherers_report -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn gatherers_report() {
        let ctx = ctx();
        let k = ctx.linux_kernel().unwrap();
        let t = std::time::Instant::now();
        let n = k.symbols_at(k.symbol_addr("_text").unwrap(), 0).len();
        eprintln!("symbols_at first call: {n} in {:?}", t.elapsed());
        let t = std::time::Instant::now();
        let b = get_modules_memory_boundaries(k).unwrap();
        eprintln!("bounds {:#x}..{:#x} ({} MiB)", b.0, b.1, (b.1 - b.0) >> 20);
        for g in ALL_GATHERERS {
            let t = std::time::Instant::now();
            let r = g.gather_modules(k).unwrap();
            eprintln!("{}: {} modules in {:?}", g.name(), r.len(), t.elapsed());
        }
        let t2 = std::time::Instant::now();
        let all = run_modules_scanners(k, &ALL_GATHERERS).unwrap();
        eprintln!("run_modules_scanners: {} in {:?} (total {:?})", all.len(), t2.elapsed(), t.elapsed());
        for m in all.iter().take(3) {
            eprintln!("  {:#x} {} {:#x}-{:#x}", m.offset, m.name, m.start, m.end);
        }
        let lsmod: Vec<Obj> = list_modules(k).into_iter().map(|m| m.unwrap()).collect();
        for m in lsmod.iter().take(60) {
            let params: Vec<String> = get_load_parameters(k, m).into_iter().map(|p| {
                let (n, v) = p.unwrap();
                format!("{n}={v}")
            }).collect();
            println!("LSMOD\t{:#x}\t{}\t{:#x}\t{}", m.addr, m.get_name().unwrap().unwrap(), m.get_core_size().unwrap() + m.get_init_size().unwrap(), params.join(", "));
        }
    }
}
