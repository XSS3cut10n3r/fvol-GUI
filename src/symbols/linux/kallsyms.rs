//! python `symbols/linux/kallsyms.py`: the Kallsyms API (`KASConfig`, `KASSymbol`,
//! `Kallsyms`): kernel core symbols decompressed from the `kallsyms_*` tables, module symbols,
//! ftrace and BPF symbols, address -> symbol and name -> symbol lookups.
//!
//! For plugin porters:
//!   * `kallsyms.Kallsyms(context, layer_name, module_name)` -> [`Kallsyms::get`]`(k)?` (built
//!     once per kernel and cached; `Sync`, so lookups can run on all cores).
//!   * `kas.lookup_address(addr)` -> [`Kallsyms::lookup_address`]`(addr)?` (`Option<KasSymbol>`).
//!   * `get_core_symbols()` / `get_modules_symbols()` / `get_ftrace_symbols()` /
//!     `get_bpf_symbols()` / `get_all_symbols()` / `lookup_name()` -> same names; generators are
//!     collected into `Vec<Result<KasSymbol>>` where a trailing `Err` marks where python raised
//!     (e.g. python's `TypeError: pointer_to_string takes a Pointer` from
//!     `get_modules_symbols()` on kernels whose `kernel_symbol` has `name_offset`).
//!
//! Speed: the core symbol address table (`kallsyms_offsets`) is read once into a flat array
//! and searched in memory with python's exact binary search / alias rules; names are expanded
//! on demand through a one-page read cache; module symbol tables and the ftrace lists are
//! flattened once per module / kernel.
//!
//! python quirks kept on purpose (they decide the output): module memory boundaries use the
//! *addresses* of `module_addr_min/max` on kernels without `mod_tree`, `_mod_tree_comp` reads
//! the `module_memory` at `latch_tree_node + mtn + mod` offsets, `latch_tree_root.find` indexes
//! the rb-node by `idx * sizeof(pointer)`, the ftrace trampoline range is not masked,
//! `get_core_symbols` advances `current_offset` by `compressed_length + 1` even for 2-byte
//! lengths. One quirk cannot be reproduced deterministically: for "big" symbols (length byte
//! with the top bit set) python's `_get_symbol_offset` takes the upper length byte from the
//! shared `kallsyms_names` stream position left by the previous expansion; here it is read from
//! the byte after the length byte (the kernel's value). No such symbols exist in the kernels
//! we test.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use super::constants::{KSYM_NAME_LEN, nm_type_desc};
use super::module::{ElfSym, ModuleExt};
use super::modules::list_modules;
use super::{LinuxExt, container_of};
use crate::error::{Error, Result};
use crate::layers::{Layer, LayerExt};
use crate::objects::util::{array_to_string, pointer_to_string};
use crate::objects::{LayerRef, Module, Obj};
use crate::util::FxHashMap;
use std::borrow::Cow;
use std::sync::{Arc, Mutex, OnceLock};

/// Largest plausible `kallsyms_num_syms`. Real kernels have well under a million core symbols;
/// a value above this is corruption (a smeared / garbage `kallsyms_num_syms`). python has no
/// such bound -- `get_core_symbols` does `for sym_idx in range(self._kallsyms_num_syms)`, so a
/// corrupted count of, say, 1.8 billion makes python loop billions of times and hang forever.
/// fastvol gives up on the affected enumeration instead (never hang on malformed memory;
/// where python would hang forever, stop cleanly). Used by every count-driven loop below.
const MAX_PLAUSIBLE_SYMS: u64 = 16 << 20;

/// A reproducible copy of an [`Error`] (errors are cached by lazily built tables and re-raised
/// on every use, like python re-evaluating a failing cached property).
fn clone_err(e: &Error) -> Error {
    match e {
        Error::InvalidAddress { addr } => Error::InvalidAddress { addr: *addr },
        Error::Swapped { addr } => Error::Swapped { addr: *addr },
        Error::Symbol(s) => Error::Symbol(s.clone()),
        Error::Unsatisfied(s) => Error::Unsatisfied(s.clone()),
        Error::Layer(s) => Error::Layer(s.clone()),
        Error::Io(e) => Error::msg(e.to_string()),
        Error::Msg(s) => Error::Msg(s.clone()),
    }
}

fn clone_res<T: Clone>(r: &Result<T>) -> Result<T> {
    match r {
        Ok(v) => Ok(v.clone()),
        Err(e) => Err(clone_err(e)),
    }
}

fn type_error(what: &str) -> Error {
    Error::msg(format!("TypeError: {what}"))
}

/// python truthiness of an optional address.
#[inline]
fn truthy(v: Option<u64>) -> bool {
    v.is_some_and(|v| v != 0)
}

/// python `KASConfig` (addresses already include the KASLR shift; `None` when the ISF lacks
/// the symbol).
#[derive(Clone, Debug, Default)]
pub struct KasConfig {
    pub num_syms_address: Option<u64>,
    pub names_address: Option<u64>,
    pub token_table_address: Option<u64>,
    pub token_index_address: Option<u64>,
    pub offsets_address: Option<u64>,
    pub relative_base_address: Option<u64>,
    pub stext: Option<u64>,
    pub markers_address: Option<u64>,
    pub addresses_address: Option<u64>,
    pub sinittext: Option<u64>,
    pub einittext: Option<u64>,
    pub etext: Option<u64>,
    pub end: Option<u64>,
    pub mod_tree: Option<u64>,
    pub module_addr_min: Option<u64>,
    pub module_addr_max: Option<u64>,
    pub start_ksymtab: Option<u64>,
    pub stop_ksymtab: Option<u64>,
    pub bpf_tree_address: Option<u64>,
    pub seqs_of_names_address: Option<u64>,
    pub num_syms_type_size: u64,
    pub markers_type_size: u64,
    pub kernel_symbol_size: u64,
}

impl KasConfig {
    /// python `KASConfig.new_from_isf(context, layer_name, module_name)`.
    pub fn new_from_isf(vm: &Module) -> Result<KasConfig> {
        let t = vm.table();
        let ns = t.get_symbol("kallsyms_num_syms")?;
        let num_syms_type_size = match ns.ty {
            Some(ty) => t.size_of(ty),
            None => return Err(Error::msg("AttributeError: 'NoneType' object has no attribute 'size'")),
        };
        let kernel_symbol_size = t.size_of(t.get_type("kernel_symbol")?);
        let a = |n: &str| if vm.has_symbol(n) { vm.symbol_addr(n).ok() } else { None };
        Ok(KasConfig {
            num_syms_address: a("kallsyms_num_syms"),
            names_address: a("kallsyms_names"),
            token_table_address: a("kallsyms_token_table"),
            token_index_address: a("kallsyms_token_index"),
            offsets_address: a("kallsyms_offsets"),
            relative_base_address: a("kallsyms_relative_base"),
            markers_address: a("kallsyms_markers"),
            addresses_address: a("kallsyms_addresses"),
            sinittext: a("_sinittext"),
            einittext: a("_einittext"),
            stext: a("_stext"),
            etext: a("_etext"),
            end: a("_end"),
            mod_tree: a("mod_tree"),
            module_addr_min: a("module_addr_min"),
            module_addr_max: a("module_addr_max"),
            start_ksymtab: a("__start___ksymtab"),
            stop_ksymtab: a("__stop___ksymtab"),
            bpf_tree_address: a("bpf_tree"),
            seqs_of_names_address: a("kallsyms_seqs_of_names"),
            num_syms_type_size,
            markers_type_size: num_syms_type_size,
            kernel_symbol_size,
        })
    }
}

/// python `KASSymbol`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KasSymbol {
    pub name: String,
    /// nm-style type letter (python `type`, may be None).
    pub type_: Option<Cow<'static, str>>,
    pub address: u64,
    /// python `size` (None when the core symbol position could not be computed).
    pub size: Option<i128>,
    /// python `module_name` (None when a module name is unreadable).
    pub module_name: Option<Cow<'static, str>>,
    /// python `exported` (True / False / None).
    pub exported: Option<bool>,
    /// python `subsystem`: "core", "module", "ftrace", "bpf" (or None).
    pub subsystem: Option<&'static str>,
}

impl KasSymbol {
    /// python `set_exported_from_type()`.
    pub fn set_exported_from_type(&mut self) {
        self.exported = match self.type_.as_deref() {
            Some(t) if !t.is_empty() => Some(py_isupper(t) || matches!(t, "u" | "v" | "w")),
            _ => None,
        };
    }
    /// python `type_description`.
    pub fn type_description(&self) -> Option<&'static str> {
        let t = self.type_.as_deref()?;
        if let Some(d) = nm_type_desc(t) {
            return Some(d);
        }
        if t.is_empty() {
            return None;
        }
        nm_type_desc(&t.to_lowercase())
    }
}

/// python `str.isupper()`.
fn py_isupper(s: &str) -> bool {
    let mut cased = false;
    for c in s.chars() {
        if c.is_lowercase() {
            return false;
        }
        if c.is_uppercase() {
            cased = true;
        }
    }
    cased
}

/// python `KASSymbolBasic`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KasSymbolBasic {
    pub name: String,
    pub type_: Option<Cow<'static, str>>,
}

/// `c` (ASCII) as a one-character static string (no allocation per symbol type letter).
fn ascii_str(c: u8) -> &'static str {
    static ASCII: [u8; 128] = {
        let mut a = [0u8; 128];
        let mut i = 0;
        while i < 128 {
            a[i] = i as u8;
            i += 1;
        }
        a
    };
    let c = (c & 0x7f) as usize;
    std::str::from_utf8(&ASCII[c..c + 1]).unwrap_or("")
}

/// One-page read cache over a layer for byte-at-a-time decoding (python `_KallsymsIO`).
struct PageReader {
    layer: LayerRef,
    page: u64,
    loaded: bool,
    valid: bool,
    data: Box<[u8; 4096]>,
}

impl PageReader {
    fn new(layer: LayerRef) -> PageReader {
        PageReader { layer, page: 0, loaded: false, valid: false, data: Box::new([0u8; 4096]) }
    }
    /// python `layer.read(addr, 1)`.
    #[inline]
    fn byte(&mut self, addr: u64) -> Result<u8> {
        let p = addr & !0xfff;
        if !self.loaded || p != self.page {
            self.page = p;
            self.loaded = true;
            self.valid = self.layer.read(p, &mut self.data[..]).is_ok();
        }
        if self.valid { Ok(self.data[(addr & 0xfff) as usize]) } else { self.layer.read_u8(addr) }
    }
}

/// A module's symbol table flattened for address lookups (`_find_address_in_module_symbols`).
struct ModSymTable {
    /// python `get_module_address_boundaries()`.
    bounds: Result<Option<(u64, u64)>>,
    /// named symbols in index order: (start, end, index); `end` is `start + st_size` unmasked
    entries: Vec<(u64, u128, u64)>,
    /// where python's loop would raise (after `entries`)
    tail: Option<Error>,
    /// `get_symbols()` (python iterates it after the bounds check)
    symtab: Option<super::module::ModuleSymtab>,
}

/// One ftrace module function (python `_ftrace_mod_get_symbols`).
#[derive(Clone)]
struct FtraceFunc {
    name: String,
    addr: u64,
    size: i128,
    /// index into `Ftrace::maps`
    map: usize,
}

struct Ftrace {
    /// `has_type(ftrace_mod_map) and has_type(ftrace_mod_func)`
    mod_supported: bool,
    funcs: Vec<FtraceFunc>,
    funcs_tail: Option<Error>,
    /// per mod_map: `array_to_string(mod_map.mod.name)` (evaluated on a match only)
    maps: Vec<Result<String>>,
    /// trampolines: (trampoline, trampoline_size)
    tramps: Vec<(u64, i128)>,
    tramps_tail: Option<Error>,
}

/// python `Kallsyms` (see the module docs). Obtain with [`Kallsyms::get`].
pub struct Kallsyms {
    vm: Module,
    layer: LayerRef,
    mask: u64,
    /// python `_kas_config`.
    pub cfg: KasConfig,
    long_size: u64,
    /// python `_kallsyms_num_syms` (None when unreadable).
    pub num_syms: Option<u64>,
    relative_base: Option<u64>,
    token_index: Vec<Option<u64>>,
    /// the 256 decoded tokens of `kallsyms_token_table` (read once; see [`Token`])
    tokens: OnceLock<Vec<Token>>,
    /// flat `_get_symbol_address_by_index` table
    addrs: OnceLock<Result<AddrTable>>,
    mod_bounds: OnceLock<Result<(u64, u64)>>,
    module_region: OnceLock<Result<Vec<(Obj, u64, u64)>>>,
    mod_tables: Mutex<FxHashMap<u64, Arc<ModSymTable>>>,
    ftrace: OnceLock<Result<Arc<Ftrace>>>,
}

const NONE_ADDR: u64 = u64::MAX;

/// One `kallsyms_token_table` entry as python's byte-by-byte `_expand_symbol` reads it.
enum Token {
    /// `token_index[i]` is None (python raises a TypeError when the token is used)
    NoIndex,
    /// the bytes before the NUL; `tail`: the read error python hits after them (no NUL);
    /// `ascii`: every byte is ASCII (decoded without a per-byte check)
    Bytes { bytes: Vec<u8>, tail: Option<Error>, ascii: bool },
    /// no NUL within the first MiB: expanded byte by byte from memory
    Uncached(u64),
}

/// Tokens longer than this are not cached ([`Token::Uncached`]).
const MAX_TOKEN: usize = 1 << 20;

/// Every `_get_symbol_address_by_index(i)` (`NONE_ADDR` = python None), plus, when all are
/// readable, the alias-run starts and next-greater indices that make python's
/// `_get_symbol_pos` O(log n).
struct AddrTable {
    addrs: Vec<u64>,
    /// no `NONE_ADDR` entries (`run_start` / `next_greater` are valid)
    complete: bool,
    /// first index of the run of equal consecutive addresses containing `i`
    run_start: Vec<u32>,
    /// nearest `j > i` with `addrs[j] > addrs[i]` (`u32::MAX`: none)
    next_greater: Vec<u32>,
}

impl AddrTable {
    fn new(addrs: Vec<u64>) -> AddrTable {
        let n = addrs.len();
        let complete = !addrs.contains(&NONE_ADDR) && n < u32::MAX as usize;
        let (mut run_start, mut next_greater) = (Vec::new(), Vec::new());
        if complete {
            run_start = vec![0u32; n];
            let mut sorted = true;
            for i in 1..n {
                run_start[i] = if addrs[i - 1] == addrs[i] { run_start[i - 1] } else { i as u32 };
                sorted &= addrs[i - 1] <= addrs[i];
            }
            next_greater = vec![u32::MAX; n];
            if sorted {
                // (the kernel sorts them) the next greater is the end of the equal run
                for i in (0..n.saturating_sub(1)).rev() {
                    next_greater[i] = if addrs[i + 1] > addrs[i] { i as u32 + 1 } else { next_greater[i + 1] };
                }
                return AddrTable { addrs, complete, run_start, next_greater };
            }
            let mut stack: Vec<u32> = Vec::new();
            for i in (0..n).rev() {
                while let Some(&top) = stack.last() {
                    if addrs[top as usize] <= addrs[i] {
                        stack.pop();
                    } else {
                        break;
                    }
                }
                if let Some(&top) = stack.last() {
                    next_greater[i] = top;
                }
                stack.push(i as u32);
            }
        }
        AddrTable { addrs, complete, run_start, next_greater }
    }
}

static CACHE: Mutex<Vec<(usize, usize, &'static Kallsyms)>> = Mutex::new(Vec::new());

impl Kallsyms {
    /// python `Kallsyms(context, layer_name=vmlinux.layer_name, module_name=kernel)`, cached per
    /// kernel (table + layer). `Err` where python's constructor raises.
    pub fn get(vm: &Module) -> Result<&'static Kallsyms> {
        let key = (vm.table() as *const _ as *const u8 as usize, vm.layer() as *const dyn Layer as *const u8 as usize);
        if let Some(k) = CACHE.lock().unwrap().iter().find(|c| (c.0, c.1) == key) {
            return Ok(k.2);
        }
        let k: &'static Kallsyms = Box::leak(Box::new(Kallsyms::new(vm)?));
        let mut g = CACHE.lock().unwrap();
        if let Some(c) = g.iter().find(|c| (c.0, c.1) == key) {
            return Ok(c.2);
        }
        g.push((key.0, key.1, k));
        Ok(k)
    }

    /// python `Kallsyms.__init__` + `_bootstrap()` (uncached; prefer [`Kallsyms::get`]).
    pub fn new(vm: &Module) -> Result<Kallsyms> {
        let cfg = KasConfig::new_from_isf(vm)?;
        let layer = vm.layer();
        let mask = layer.address_mask();
        let long_size = match layer.as_intel() {
            Some(i) => i.bits_per_register() as u64 / 8,
            None => {
                if vm.table().is_64bit() {
                    8
                } else {
                    4
                }
            }
        };
        let read_int = |addr: Option<u64>, size: u64| -> Result<Option<u64>> {
            let a = addr.ok_or_else(|| type_error("unsupported operand type(s) for +: 'NoneType' and 'int'"))?;
            let mut b = [0u8; 8];
            let n = (size as usize).min(8);
            match layer.read(a, &mut b[..n]) {
                Ok(()) => Ok(Some(u64::from_le_bytes(b))),
                Err(e) if e.is_invalid_address() => Ok(None),
                Err(e) => Err(e),
            }
        };
        let num_syms = read_int(cfg.num_syms_address, cfg.num_syms_type_size)?;
        let relative_base = if truthy(cfg.relative_base_address) {
            let v = read_int(cfg.relative_base_address, long_size)?.ok_or_else(|| type_error("unsupported operand type(s) for &: 'NoneType' and 'int'"))?;
            Some(v & mask)
        } else {
            None
        };
        let tia = cfg.token_index_address.ok_or_else(|| type_error("unsupported operand type(s) for +: 'NoneType' and 'int'"))?;
        let mut token_index = Vec::with_capacity(256);
        for i in 0..256u64 {
            token_index.push(read_int(Some(tia.wrapping_add(i * 2)), 2)?);
        }
        Ok(Kallsyms {
            vm: *vm,
            layer,
            mask,
            cfg,
            long_size,
            num_syms,
            relative_base,
            token_index,
            tokens: OnceLock::new(),
            addrs: OnceLock::new(),
            mod_bounds: OnceLock::new(),
            module_region: OnceLock::new(),
            mod_tables: Mutex::new(FxHashMap::default()),
            ftrace: OnceLock::new(),
        })
    }

    /// The kernel module this instance works on.
    pub fn vmlinux(&self) -> &Module {
        &self.vm
    }

    fn num_syms(&self) -> Result<u64> {
        self.num_syms.ok_or_else(|| type_error("'NoneType' object cannot be interpreted as an integer"))
    }

    // ------------------------------------------------------------------ core addresses

    /// python `_get_symbol_address_by_index(index)` read directly from memory.
    fn read_symbol_address(&self, index: u64) -> Result<Option<u64>> {
        if truthy(self.cfg.offsets_address) {
            let a = self.cfg.offsets_address.unwrap().wrapping_add(index.wrapping_mul(4));
            let v = match self.layer.read_i32(a) {
                Ok(v) => v as i64,
                Err(e) if e.is_invalid_address() => return Ok(None),
                Err(e) => return Err(e),
            };
            if v < 0 {
                let rb = self.relative_base.ok_or_else(|| type_error("unsupported operand type(s) for -: 'NoneType' and 'int'"))?;
                return Ok(Some((rb as i128 - 1 - v as i128) as u64));
            }
            Ok(Some(v as u64 & self.mask))
        } else if truthy(self.cfg.addresses_address) {
            let a = self.cfg.addresses_address.unwrap().wrapping_add(index.wrapping_mul(self.long_size));
            let mut b = [0u8; 8];
            match self.layer.read(a, &mut b[..self.long_size.min(8) as usize]) {
                Ok(()) => Ok(Some(u64::from_le_bytes(b) & self.mask)),
                Err(e) if e.is_invalid_address() => Ok(None),
                Err(e) => Err(e),
            }
        } else {
            Err(Error::msg("Unsupported kernel"))
        }
    }

    /// The flat address table (built once; `None` when `num_syms` is unknown or implausible).
    fn addr_table(&self) -> Option<&Result<AddrTable>> {
        let n = self.num_syms?;
        if n > MAX_PLAUSIBLE_SYMS {
            return None;
        }
        Some(self.addrs.get_or_init(|| {
            let n = n as usize;
            let mut v = vec![NONE_ADDR; n];
            // fast path: the whole offsets array, straight from the image pages when they are
            // image-backed, else with one read
            if truthy(self.cfg.offsets_address) && self.relative_base.is_some() {
                let base = self.cfg.offsets_address.unwrap();
                // python: `relative_base - 1 - offset` for a negative offset (the u64
                // wrapping arithmetic is the i128 result truncated)
                let rb = self.relative_base.unwrap();
                let addr_of = |x: i32| if x < 0 { rb.wrapping_sub(1).wrapping_sub(x as i64 as u64) } else { x as u64 & self.mask };
                let mut done = 0usize;
                while done < n {
                    let a = base.wrapping_add(done as u64 * 4);
                    let k = ((0x1000 - (a & 0xfff) as usize) / 4).min(n - done);
                    let Some(page) = (a & 3 == 0).then(|| self.layer.slice(a, k * 4)).flatten() else { break };
                    for (slot, c) in v[done..done + k].iter_mut().zip(page.chunks_exact(4)) {
                        *slot = addr_of(i32::from_le_bytes([c[0], c[1], c[2], c[3]]));
                    }
                    done += k;
                }
                if done == n {
                    return Ok(AddrTable::new(v));
                }
                let mut raw = vec![0u8; n * 4];
                if self.layer.read(base, &mut raw).is_ok() {
                    for (slot, c) in v.iter_mut().zip(raw.chunks_exact(4)) {
                        *slot = addr_of(i32::from_le_bytes([c[0], c[1], c[2], c[3]]));
                    }
                    return Ok(AddrTable::new(v));
                }
                v.fill(NONE_ADDR);
            }
            for (i, slot) in v.iter_mut().enumerate() {
                if let Some(a) = self.read_symbol_address(i as u64)? {
                    *slot = a;
                }
            }
            Ok(AddrTable::new(v))
        }))
    }

    /// python `_get_symbol_address_by_index(index)`.
    pub fn get_symbol_address_by_index(&self, index: u64) -> Result<Option<u64>> {
        if let Some(t) = self.addr_table() {
            match t {
                Ok(t) => {
                    if let Some(&a) = t.addrs.get(index as usize) {
                        return Ok(if a == NONE_ADDR { None } else { Some(a) });
                    }
                }
                Err(e) => return Err(clone_err(e)),
            }
        }
        self.read_symbol_address(index)
    }

    /// python `_get_symbol_pos(address)`: (position, size), `None` where python returns
    /// `(None, None)`.
    pub fn get_symbol_pos(&self, address: u64) -> Result<Option<(u64, i128)>> {
        let n = self.num_syms()?;
        if let Some(Ok(t)) = self.addr_table() {
            if t.complete && t.addrs.len() as u64 == n && n > 0 {
                // python's exact probe sequence, then the precomputed alias / next rules
                let a = &t.addrs;
                let (mut low, mut high) = (0usize, n as usize);
                while high - low > 1 {
                    let mid = low + (high - low) / 2;
                    if a[mid] <= address {
                        low = mid;
                    } else {
                        high = mid;
                    }
                }
                let low = t.run_start[low] as usize;
                let start = a[low];
                let mut end = match t.next_greater[low] {
                    u32::MAX => 0,
                    j => a[j as usize],
                };
                if end == 0 {
                    end = self.section_end(address)?;
                }
                return Ok(Some((low as u64, end as i128 - start as i128)));
            }
        }
        let at = |i: u64| self.get_symbol_address_by_index(i);
        let (mut low, mut high) = (0u64, n);
        while high.saturating_sub(low) > 1 && high > low {
            let mid = low + (high - low) / 2;
            match at(mid)? {
                None => return Ok(None),
                Some(a) if a <= address => low = mid,
                Some(_) => high = mid,
            }
        }
        while low > 0 {
            let prev = match at(low - 1)? {
                None => return Ok(None),
                Some(a) => a,
            };
            if Some(prev) == at(low)? {
                low -= 1;
            } else {
                break;
            }
        }
        let Some(start) = at(low)? else { return Ok(None) };
        let mut end = 0u64;
        let mut idx = low + 1;
        while idx < n {
            match at(idx)? {
                None => return Ok(None),
                Some(a) if a > start => {
                    end = a;
                    break;
                }
                Some(_) => {}
            }
            idx += 1;
        }
        if end == 0 {
            end = self.section_end(address)?;
        }
        Ok(Some((low, end as i128 - start as i128)))
    }

    /// `_get_symbol_pos`'s end of section when no next symbol exists.
    fn section_end(&self, address: u64) -> Result<u64> {
        let e = if self.is_kernel_inittext(address) {
            self.cfg.einittext
        } else if self.cfg.end.is_some() {
            self.cfg.end
        } else {
            self.cfg.etext
        };
        e.ok_or_else(|| type_error("unsupported operand type(s) for -: 'NoneType' and 'int'"))
    }

    /// python `_get_symbol_offset(index)`: offset of the symbol in the compressed stream.
    pub fn get_symbol_offset(&self, index: u64) -> Result<u64> {
        let names = self.cfg.names_address.ok_or_else(|| type_error("unsupported operand type(s) for +: 'NoneType' and 'int'"))?;
        let markers = self.cfg.markers_address.ok_or_else(|| type_error("unsupported operand type(s) for +: 'NoneType' and 'int'"))?;
        let mts = self.cfg.markers_type_size;
        let ptr = markers.wrapping_add((index >> 8).wrapping_mul(mts));
        let mut b = [0u8; 8];
        let pos = match self.layer.read(ptr, &mut b[..mts.min(8) as usize]) {
            Ok(()) => u64::from_le_bytes(b),
            Err(e) if e.is_invalid_address() => return Err(type_error("unsupported operand type(s) for +: 'int' and 'NoneType'")),
            Err(e) => return Err(e),
        };
        let mut rd = PageReader::new(self.layer);
        let mut name_addr = names.wrapping_add(pos);
        for _ in 0..(index & 0xFF) {
            let mut len = match rd.byte(name_addr) {
                Ok(v) => v as u64,
                Err(e) if e.is_invalid_address() => return Err(type_error("unsupported operand type(s) for &: 'NoneType' and 'int'")),
                Err(e) => return Err(e),
            };
            if len & 0x80 != 0 {
                // see the module docs: python reads the stream's current position here
                let upper = rd.byte(name_addr.wrapping_add(1))? as u64;
                len = (upper << 7) | (len & 0x7F);
            }
            name_addr = name_addr.wrapping_add(len + 1);
        }
        Ok(name_addr.wrapping_sub(names))
    }

    /// python `_expand_symbol(offset)` (no filters): the symbol and its compressed length.
    pub fn expand_symbol(&self, offset: u64) -> Result<(KasSymbolBasic, u64)> {
        let mut names = PageReader::new(self.layer);
        let mut tokens = PageReader::new(self.layer);
        self.expand_with(&mut names, &mut tokens, offset)
    }

    /// The decoded token table (built on first use).
    fn token_table(&self) -> &[Token] {
        self.tokens.get_or_init(|| {
            let tt = self.cfg.token_table_address;
            let mut rd = PageReader::new(self.layer);
            self.token_index
                .iter()
                .map(|ti| {
                    let (Some(ti), Some(tt)) = (*ti, tt) else { return Token::NoIndex };
                    let start = tt.wrapping_add(ti);
                    let mut bytes = Vec::new();
                    loop {
                        if bytes.len() >= MAX_TOKEN {
                            return Token::Uncached(start);
                        }
                        match rd.byte(start.wrapping_add(bytes.len() as u64)) {
                            Ok(0) => return Token::Bytes { ascii: bytes.is_ascii(), bytes, tail: None },
                            Ok(c) => bytes.push(c),
                            Err(e) => return Token::Bytes { ascii: bytes.is_ascii(), bytes, tail: Some(e) },
                        }
                    }
                })
                .collect()
        })
    }

    fn expand_with(&self, names: &mut PageReader, tokens: &mut PageReader, offset: u64) -> Result<(KasSymbolBasic, u64)> {
        let base = self.cfg.names_address.ok_or_else(|| type_error("unsupported operand type(s) for +: 'NoneType' and 'int'"))?;
        let tt = self.cfg.token_table_address.ok_or_else(|| type_error("unsupported operand type(s) for +: 'NoneType' and 'int'"))?;
        let mut pos = base.wrapping_add(offset);
        let mut len = names.byte(pos)? as u64;
        pos = pos.wrapping_add(1);
        if len & 0x80 != 0 {
            let upper = names.byte(pos)? as u64;
            pos = pos.wrapping_add(1);
            len = (upper << 7) | (len & 0x7F);
        }
        let table = self.token_table();
        let mut sym_type: Option<Cow<'static, str>> = None;
        let mut name = String::with_capacity((len as usize * 4).min(256));
        let push = |sym_type: &mut Option<Cow<'static, str>>, name: &mut String, c: u8| -> Result<()> {
            if c >= 0x80 {
                return Err(Error::msg("UnicodeDecodeError: 'utf-8' codec can't decode byte"));
            }
            if sym_type.is_none() {
                *sym_type = Some(Cow::Borrowed(ascii_str(c)));
            } else {
                name.push(c as char);
            }
            Ok(())
        };
        for _ in 0..len {
            let tii = names.byte(pos)?;
            pos = pos.wrapping_add(1);
            match &table[tii as usize] {
                Token::NoIndex => return Err(type_error("unsupported operand type(s) for +: 'int' and 'NoneType'")),
                Token::Bytes { bytes, tail, ascii } => {
                    if *ascii {
                        let mut bs = &bytes[..];
                        if sym_type.is_none() {
                            if let Some((&c, rest)) = bs.split_first() {
                                sym_type = Some(Cow::Borrowed(ascii_str(c)));
                                bs = rest;
                            }
                        }
                        name.push_str(std::str::from_utf8(bs).unwrap_or_default());
                    } else {
                        for &c in bytes {
                            push(&mut sym_type, &mut name, c)?;
                        }
                    }
                    if let Some(e) = tail {
                        return Err(clone_err(e));
                    }
                }
                Token::Uncached(start) => {
                    let _ = tt;
                    let mut tpos = *start;
                    loop {
                        let c = tokens.byte(tpos)?;
                        tpos = tpos.wrapping_add(1);
                        if c == 0 {
                            break;
                        }
                        push(&mut sym_type, &mut name, c)?;
                    }
                }
            }
        }
        Ok((KasSymbolBasic { name, type_: sym_type }, len))
    }

    fn is_kernel_inittext(&self, addr: u64) -> bool {
        match (self.cfg.sinittext, self.cfg.einittext) {
            (Some(s), Some(e)) if s != 0 && e != 0 => s <= addr && addr < e,
            _ => false,
        }
    }

    fn is_kernel_text(&self, addr: u64) -> Result<bool> {
        let s = self.cfg.stext.ok_or_else(|| type_error("'<=' not supported between instances of 'NoneType' and 'int'"))?;
        if s > addr {
            return Ok(false);
        }
        let e = self.cfg.etext.ok_or_else(|| type_error("'<' not supported between instances of 'int' and 'NoneType'"))?;
        Ok(addr < e)
    }

    fn is_core_ksym_addr(&self, addr: u64) -> Result<bool> {
        Ok(self.is_kernel_text(addr)? || self.is_kernel_inittext(addr))
    }

    // ------------------------------------------------------------------ lookups

    /// python `lookup_address(address)`: core, then modules, BPF and ftrace symbols.
    pub fn lookup_address(&self, address: u64) -> Result<Option<KasSymbol>> {
        let address = address & self.mask;
        if let Some(s) = self.core_lookup_address(address)? {
            return Ok(Some(s));
        }
        if let Some(s) = self.module_lookup_address(address, None)? {
            return Ok(Some(s));
        }
        if let Some(s) = self.bpf_lookup_address(address)? {
            return Ok(Some(s));
        }
        self.ftrace_lookup_address(address)
    }

    /// python `core_lookup_address(address)`.
    pub fn core_lookup_address(&self, address: u64) -> Result<Option<KasSymbol>> {
        let address = address & self.mask;
        if !self.is_core_ksym_addr(address)? {
            return Ok(None);
        }
        let Some((pos, size)) = self.get_symbol_pos(address)? else { return Ok(None) };
        let offset = self.get_symbol_offset(pos)?;
        let sym_address = self.get_symbol_address_by_index(pos)?;
        let (basic, _) = self.expand_symbol(offset)?;
        let address = sym_address.ok_or_else(|| type_error("address is None"))?;
        let mut s = KasSymbol { name: basic.name, type_: basic.type_, address, size: Some(size), module_name: Some("kernel".into()), exported: None, subsystem: Some("core") };
        s.set_exported_from_type();
        Ok(Some(s))
    }

    /// python `_get_modules_memory_boundaries()` (masked).
    fn modules_memory_boundaries(&self) -> Result<(u64, u64)> {
        clone_res(self.mod_bounds.get_or_init(|| {
            let (lo, hi) = if truthy(self.cfg.mod_tree) {
                let mt = self.vm.object_abs("mod_tree_root", self.cfg.mod_tree.unwrap())?;
                (mt.m("addr_min")?.u64()?, mt.m("addr_max")?.u64()?)
            } else if truthy(self.cfg.module_addr_min) && truthy(self.cfg.module_addr_max) {
                (self.cfg.module_addr_min.unwrap(), self.cfg.module_addr_max.unwrap())
            } else {
                return Err(Error::msg("Cannot find the module memory allocation area. Unsupported kernel"));
            };
            Ok((lo & self.mask, hi & self.mask))
        }))
    }

    fn is_module_ksym_address(&self, address: u64) -> Result<bool> {
        let (lo, hi) = self.modules_memory_boundaries()?;
        Ok(lo <= address && address <= hi)
    }

    /// python `module_lookup_address(address, module=None)`.
    pub fn module_lookup_address(&self, address: u64, module: Option<Obj>) -> Result<Option<KasSymbol>> {
        if !self.is_module_ksym_address(address)? {
            return Ok(None);
        }
        let mut module = match module {
            Some(m) => Some(m),
            None => self.get_module_by_address(address)?,
        };
        if module.is_none() {
            let region = self.module_memory_region()?;
            for (m, lo, hi) in region.iter() {
                if *lo <= address && address < *hi {
                    module = Some(*m);
                    break;
                }
            }
        }
        let Some(module) = module else { return Ok(None) };
        self.find_address_in_module_symbols(&module, address)
    }

    /// python `_module_memory_region` (cached property).
    fn module_memory_region(&self) -> Result<&Vec<(Obj, u64, u64)>> {
        let r = self.module_region.get_or_init(|| {
            let mut out = Vec::new();
            for m in list_modules(&self.vm) {
                let m = m?;
                let (lo, hi) = m.get_module_address_boundaries()?.ok_or_else(|| type_error("cannot unpack non-iterable NoneType object"))?;
                out.push((m, lo, hi));
            }
            Ok(out)
        });
        match r {
            Ok(v) => Ok(v),
            Err(e) => Err(clone_err(e)),
        }
    }

    fn get_module_by_address(&self, address: u64) -> Result<Option<Obj>> {
        if !self.is_module_ksym_address(address)? {
            return Ok(None);
        }
        self.search_module_by_address(address)
    }

    /// python `_search_module_by_address(address)` (`mod_tree` latch tree).
    fn search_module_by_address(&self, address: u64) -> Result<Option<Obj>> {
        if !truthy(self.cfg.mod_tree) {
            return Ok(None);
        }
        let vm = &self.vm;
        let root = vm.object_abs("mod_tree_root", self.cfg.mod_tree.unwrap())?.m("root")?;
        let t = vm.table();
        let mut comp = |key: u64, lt: &Obj| -> Result<Option<i64>> {
            // python `_mod_tree_comp` (reads `module_memory` at lt_node + mtn + mod offsets)
            if t.user_type("module_memory").is_none() {
                return Ok(None);
            }
            let mtn_off = vm.offset_of("module_memory", "mtn")?;
            if !t.has_type("mod_tree_node") {
                return Ok(None);
            }
            let mod_off = vm.offset_of("mod_tree_node", "mod")?;
            let mm = vm.object_abs("module_memory", lt.addr.wrapping_add(mtn_off).wrapping_add(mod_off))?;
            let start = mm.m("base")?.u64()?;
            let end = start as i128 + mm.m("size")?.int()?;
            Ok(Some(if (key as i128) < start as i128 {
                -1
            } else if key as i128 >= end {
                1
            } else {
                0
            }))
        };
        let Some(lt) = root.find(address, &mut comp)? else { return Ok(None) };
        let mtn = container_of(lt.addr, "mod_tree_node", "node", vm)?.ok_or_else(|| Error::msg("AttributeError: 'NoneType' object has no attribute 'mod'"))?;
        let mp = mtn.m("mod")?;
        mp.u64()?;
        if !mp.is_readable() {
            return Ok(None);
        }
        Ok(Some(mp.deref()?))
    }

    fn mod_table(&self, module: &Obj) -> Arc<ModSymTable> {
        if let Some(t) = self.mod_tables.lock().unwrap().get(&module.addr) {
            return t.clone();
        }
        let bounds = module.get_module_address_boundaries();
        let mut entries = Vec::new();
        let mut tail = None;
        let mut symtab = None;
        if let Ok(Some(_)) = bounds {
            match module.get_symbols() {
                Ok(Some(tab)) => {
                    symtab = Some(tab);
                    for i in 0..tab.count {
                        let s = tab.sym(i);
                        if !s.has_name() {
                            continue;
                        }
                        let r = s.st_value().and_then(|v| Ok((v & self.mask, s.st_size()?)));
                        match r {
                            Ok((start, size)) => entries.push((start, start as u128 + size as u128, i)),
                            Err(e) => {
                                tail = Some(e);
                                break;
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => tail = Some(e),
            }
        }
        let t = Arc::new(ModSymTable { bounds, entries, tail, symtab });
        self.mod_tables.lock().unwrap().insert(module.addr, t.clone());
        t
    }

    /// python `_find_address_in_module_symbols(module, address)`.
    fn find_address_in_module_symbols(&self, module: &Obj, address: u64) -> Result<Option<KasSymbol>> {
        let t = self.mod_table(module);
        let (lo, hi) = match &t.bounds {
            Ok(Some(b)) => *b,
            Ok(None) => return Ok(None),
            Err(e) => return Err(clone_err(e)),
        };
        if !(lo <= address && address < hi) {
            return Ok(None);
        }
        for &(start, end, idx) in &t.entries {
            if start <= address && (address as u128) < end {
                let sym = t.symtab.unwrap().sym(idx);
                return self.elfsym_to_kassymbol(module, &sym, idx, Some("module"));
            }
        }
        match &t.tail {
            Some(e) => Err(clone_err(e)),
            None => Ok(None),
        }
    }

    /// python `_elfsym_to_kassymbol(module, elf_sym, index, subsystem)`.
    fn elfsym_to_kassymbol(&self, module: &Obj, sym: &ElfSym, idx: u64, subsystem: Option<&'static str>) -> Result<Option<KasSymbol>> {
        let name = match sym.get_name() {
            Some(n) if !n.is_empty() => n,
            _ => return Ok(None),
        };
        let address = sym.st_value()? & self.mask;
        let type_ = module.get_symbol_type(sym, idx)?.map(Cow::Owned);
        let size = sym.st_size()? as i128;
        let module_name = module.get_name()?.map(Cow::Owned);
        let mut s = KasSymbol { name, type_, address, size: Some(size), module_name, exported: Some(false), subsystem };
        s.set_exported_from_type();
        Ok(Some(s))
    }

    /// python `bpf_lookup_address(address)`.
    pub fn bpf_lookup_address(&self, address: u64) -> Result<Option<KasSymbol>> {
        let vm = &self.vm;
        let (start, name, size) = if vm.has_type("bpf_ksym") {
            let Some(k) = self.find_bpf_ksym(address)? else { return Ok(None) };
            let s = k.m("start")?.u64()?;
            let e = k.m("end")?.u64()?;
            let name = array_to_string(&k.m("name")?, None)?;
            (s, name, e as i128 - s as i128)
        } else if vm.has_type("latch_tree_root") && vm.table().user_type("bpf_prog_aux").is_some_and(|u| vm.table().member(u, "ksym_tnode").is_some()) {
            let Some(prog) = self.find_bpf_prog(address)? else { return Ok(None) };
            // python calls the non-existent `get_addr_region()`
            let _ = prog;
            return Err(Error::msg("AttributeError: 'bpf_prog' object has no attribute 'get_addr_region'"));
        } else {
            return Ok(None);
        };
        let mut s = KasSymbol { name, type_: Some("t".into()), address: start & self.mask, size: Some(size), module_name: Some("bpf".into()), exported: None, subsystem: Some("bpf") };
        s.set_exported_from_type();
        Ok(Some(s))
    }

    /// python `_find_bpf_prog(address)` (kernels < 5.7).
    fn find_bpf_prog(&self, address: u64) -> Result<Option<Obj>> {
        if !truthy(self.cfg.bpf_tree_address) {
            return Ok(None);
        }
        let vm = &self.vm;
        let root = vm.object_abs("latch_tree_root", self.cfg.bpf_tree_address.unwrap())?;
        let mask = self.mask;
        let mut comp = |key: u64, lt: &Obj| -> Result<Option<i64>> {
            let aux = container_of(lt.addr, "bpf_prog_aux", "ksym_tnode", vm)?.ok_or_else(|| Error::msg("AttributeError: 'NoneType' object has no attribute 'prog'"))?;
            let prog = aux.m("prog")?.deref()?;
            let (s, e) = prog.get_address_region()?;
            let (s, e) = (s & mask, e & mask);
            Ok(Some(if key < s {
                -1
            } else if key > e {
                1
            } else {
                0
            }))
        };
        let Some(lt) = root.find(address, &mut comp)? else { return Ok(None) };
        let aux = container_of(lt.addr, "bpf_prog_aux", "ksym_tnode", vm)?.ok_or_else(|| Error::msg("AttributeError: 'NoneType' object has no attribute 'prog'"))?;
        Ok(Some(aux.m("prog")?.deref()?))
    }

    /// python `_find_bpf_ksym(address)` (kernels >= 5.7).
    fn find_bpf_ksym(&self, address: u64) -> Result<Option<Obj>> {
        if !truthy(self.cfg.bpf_tree_address) {
            return Ok(None);
        }
        let vm = &self.vm;
        let root = vm.object_abs("latch_tree_root", self.cfg.bpf_tree_address.unwrap())?;
        let mask = self.mask;
        let mut comp = |key: u64, lt: &Obj| -> Result<Option<i64>> {
            let k = container_of(lt.addr, "bpf_ksym", "tnode", vm)?.ok_or_else(|| Error::msg("AttributeError: 'NoneType' object has no attribute 'start'"))?;
            let s = k.m("start")?.u64()? & mask;
            let e = k.m("end")?.u64()? & mask;
            Ok(Some(if key < s {
                -1
            } else if key > e {
                1
            } else {
                0
            }))
        };
        let Some(lt) = root.find(address, &mut comp)? else { return Ok(None) };
        container_of(lt.addr, "bpf_ksym", "tnode", vm)
    }

    fn ftrace(&self) -> Result<Arc<Ftrace>> {
        clone_res(self.ftrace.get_or_init(|| self.build_ftrace().map(Arc::new)))
    }

    fn build_ftrace(&self) -> Result<Ftrace> {
        let vm = &self.vm;
        let tn = vm.symbol_table_name();
        let mut f = Ftrace { mod_supported: false, funcs: Vec::new(), funcs_tail: None, maps: Vec::new(), tramps: Vec::new(), tramps_tail: None };
        if vm.has_type("ftrace_mod_map") && vm.has_type("ftrace_mod_func") {
            f.mod_supported = true;
            let r = (|| -> Result<()> {
                let head = vm.object_from_symbol("ftrace_mod_maps")?;
                let map_sym = format!("{tn}!ftrace_mod_map");
                let func_sym = format!("{tn}!ftrace_mod_func");
                for mod_map in head.to_list(&map_sym, "list", true, true, None) {
                    let mod_map = mod_map?;
                    let map_idx = f.maps.len();
                    f.maps.push(mod_map.m("mod").and_then(|m| m.m("name")).and_then(|n| array_to_string(&n, None)));
                    for func in mod_map.m("funcs")?.to_list(&func_sym, "list", true, true, None) {
                        let func = func?;
                        let name = pointer_to_string(&func.m("name")?, KSYM_NAME_LEN)?;
                        let addr = func.m("ip")?.u64()? & self.mask;
                        let size = func.m("size")?.int()?;
                        f.funcs.push(FtraceFunc { name, addr, size, map: map_idx });
                    }
                }
                Ok(())
            })();
            if let Err(e) = r {
                f.funcs_tail = Some(e);
            }
        }
        if vm.has_type("ftrace_ops") && vm.has_symbol("ftrace_ops_trampoline_list") {
            let r = (|| -> Result<()> {
                let head = vm.object_from_symbol("ftrace_ops_trampoline_list")?;
                let ops_sym = format!("{tn}!ftrace_ops");
                for op in head.to_list(&ops_sym, "list", true, true, None) {
                    let op = op?;
                    let a = op.m("trampoline")?.u64()?;
                    let s = op.m("trampoline_size")?.int()?;
                    f.tramps.push((a, s));
                }
                Ok(())
            })();
            if let Err(e) = r {
                f.tramps_tail = Some(e);
            }
        }
        Ok(f)
    }

    fn ftrace_func_symbol(f: &Ftrace, func: &FtraceFunc) -> Result<KasSymbol> {
        let module_name = clone_res(&f.maps[func.map])?;
        let mut s = KasSymbol { name: func.name.clone(), type_: Some("T".into()), address: func.addr, size: Some(func.size), module_name: Some(Cow::Owned(module_name)), exported: None, subsystem: Some("ftrace") };
        s.set_exported_from_type();
        Ok(s)
    }

    fn ftrace_tramp_symbol(a: u64, size: i128) -> KasSymbol {
        let mut s = KasSymbol {
            name: "ftrace_trampoline".into(),
            type_: Some("t".into()),
            address: a,
            size: Some(size),
            module_name: Some("__builtin__ftrace".into()),
            exported: None,
            subsystem: Some("ftrace"),
        };
        s.set_exported_from_type();
        s
    }

    /// python `ftrace_lookup_address(address)`.
    pub fn ftrace_lookup_address(&self, address: u64) -> Result<Option<KasSymbol>> {
        let f = self.ftrace()?;
        if f.mod_supported {
            for func in &f.funcs {
                if func.addr as i128 <= address as i128 && (address as i128) < func.addr as i128 + func.size {
                    return Self::ftrace_func_symbol(&f, func).map(Some);
                }
            }
            if let Some(e) = &f.funcs_tail {
                return Err(clone_err(e));
            }
        }
        for &(a, s) in &f.tramps {
            if a as i128 <= address as i128 && (address as i128) < a as i128 + s {
                return Ok(Some(Self::ftrace_tramp_symbol(a, s)));
            }
        }
        if let Some(e) = &f.tramps_tail {
            return Err(clone_err(e));
        }
        Ok(None)
    }

    // ------------------------------------------------------------------ enumeration

    /// python `_get_symbol(offset, index)` (no filters).
    fn get_symbol_at(&self, names: &mut PageReader, tokens: &mut PageReader, offset: u64, index: u64) -> Result<(KasSymbol, u64)> {
        let (basic, len) = self.expand_with(names, tokens, offset)?;
        let sym_addr = self.get_symbol_address_by_index(index)?;
        let a = sym_addr.ok_or_else(|| type_error("'<=' not supported between instances of 'int' and 'NoneType'"))?;
        let size = self.get_symbol_pos(a)?.map(|p| p.1);
        let mut s = KasSymbol { name: basic.name, type_: basic.type_, address: a, size, module_name: Some("kernel".into()), exported: None, subsystem: Some("core") };
        s.set_exported_from_type();
        Ok((s, len))
    }

    /// python `get_core_symbols()`: every kernel core symbol in kallsyms order (a trailing
    /// `Err` marks where python raised).
    pub fn get_core_symbols(&self) -> Vec<Result<KasSymbol>> {
        let mut out = Vec::new();
        self.for_each_core_symbol(&mut |r| {
            out.push(r);
            true
        });
        out
    }

    /// Streaming [`get_core_symbols`](Self::get_core_symbols): `f` gets each symbol (or the
    /// `Err` python raises, after which nothing follows) in kallsyms order on the calling thread
    /// while the next ones are expanded on all cores; `f` returns false to stop.
    pub fn for_each_core_symbol(&self, f: &mut dyn FnMut(Result<KasSymbol>) -> bool) {
        self.for_each_core_block(
            &Vec::new,
            &|v: &mut Vec<Result<KasSymbol>>, r| {
                let ok = r.is_ok();
                v.push(r);
                ok
            },
            &mut |v| v.into_iter().all(|r| f(r)),
        );
    }

    /// [`for_each_core_symbol`](Self::for_each_core_symbol) with the per-symbol work done where
    /// the symbol was expanded: the symbols (or the `Err` python raises, after which nothing
    /// follows) go in kallsyms order through `push` into blocks made by `new_block`, on the
    /// worker threads; `push` returns false to stop after that symbol (python raised there).
    /// `emit` gets the blocks in order on the calling thread and returns false to stop.
    ///
    /// The symbols' stream offsets come from one pass over the length bytes; chunks of symbols
    /// are then expanded in parallel. python's `continue` on an unreadable symbol does not
    /// advance the stream offset, so from the first such symbol on the walk continues
    /// sequentially (the chunks before it are exactly what the sequential walk yields).
    pub fn for_each_core_block<B: Send>(&self, new_block: &(dyn Fn() -> B + Sync), push: &(dyn Fn(&mut B, Result<KasSymbol>) -> bool + Sync), emit: &mut dyn FnMut(B) -> bool) {
        /// symbols per block of the sequential walk
        const SEQ_BLOCK: usize = 2048;
        let n = match self.num_syms() {
            Ok(n) => n,
            Err(e) => {
                let mut b = new_block();
                push(&mut b, Err(e));
                emit(b);
                return;
            }
        };
        // A corrupted `kallsyms_num_syms` (e.g. 1.8 billion) must not drive the sequential walk
        // below `for idx in start..n`, which python does unbounded (`range(num_syms)`) and would
        // hang on forever. `core_offsets`/`addr_table` already give up at this bound; core
        // enumeration does too, skipping what cannot be trusted instead of looping billions of
        // times. Real kernels never come close (< ~10^6 symbols).
        if n > MAX_PLAUSIBLE_SYMS {
            return;
        }
        let (mut start, mut off) = (0u64, 0u64);
        // the address and token tables every symbol needs are built (once, single-threaded)
        // while the length bytes are walked
        let offsets = if crate::util::par::threads() > 1 {
            std::thread::scope(|s| {
                s.spawn(|| {
                    let _t = crate::util::trace::span("kallsyms: address + token tables");
                    let _ = self.addr_table();
                    let _ = self.token_table();
                });
                let _t = crate::util::trace::span("kallsyms: core offsets");
                self.core_offsets(n)
            })
        } else {
            self.core_offsets(n)
        };
        if let Some(offsets) = offsets {
            // big enough that a formatted block (~100 bytes a row) is handed to the output
            // without another copy, small enough to keep all cores busy
            const CHUNK: usize = 4096;
            let chunks = offsets.len().div_ceil(CHUNK);
            let mut done = false;
            let mut resume: Option<usize> = None;
            let mut panicked = None;
            let threads = crate::util::par::threads();
            crate::util::par::par_map_stream(
                chunks,
                4 * threads,
                // (block, stopped, first unreadable symbol)
                // (block, stopped, first unreadable symbol, panic): a panic is caught on the
                // worker and resumed on the calling thread after the block's symbols (an
                // uncaught worker panic would leave the stream waiting forever)
                |c| {
                    let mut b = new_block();
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> (bool, Option<usize>) {
                        let mut names = PageReader::new(self.layer);
                        let mut tokens = PageReader::new(self.layer);
                        let lo = c * CHUNK;
                        let hi = (lo + CHUNK).min(offsets.len());
                        for (i, &off) in offsets.iter().enumerate().take(hi).skip(lo) {
                            let r = match self.get_symbol_at(&mut names, &mut tokens, off, i as u64) {
                                Ok((s, _)) => Ok(s),
                                Err(e) if e.is_invalid_address() => return (false, Some(i)),
                                Err(e) => Err(e),
                            };
                            if !push(&mut b, r) {
                                return (true, None);
                            }
                        }
                        (false, None)
                    }));
                    match r {
                        Ok((stopped, invalid)) => (b, stopped, invalid, None),
                        Err(p) => (b, true, None, Some(p)),
                    }
                },
                |_, (b, stopped, invalid, p)| {
                    let emitted = emit(b);
                    if !emitted || stopped {
                        // (a stop inside the block: python never got to the panic)
                        if emitted {
                            panicked = p;
                        }
                        done = true;
                        return false;
                    }
                    if let Some(i) = invalid {
                        resume = Some(i);
                        return false;
                    }
                    true
                },
            );
            if let Some(p) = panicked {
                std::panic::resume_unwind(p);
            }
            match resume {
                _ if done => return,
                None => return,
                Some(i) => {
                    start = i as u64;
                    off = offsets[i];
                }
            }
        }
        // python's sequential walk (from the first unreadable symbol, or from the start when
        // the length bytes could not all be read)
        let mut names = PageReader::new(self.layer);
        let mut tokens = PageReader::new(self.layer);
        let mut b = new_block();
        let mut in_block = 0usize;
        for idx in start..n {
            let r = match self.get_symbol_at(&mut names, &mut tokens, off, idx) {
                Ok((s, len)) => {
                    off += len + 1;
                    Ok(s)
                }
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => Err(e),
            };
            let failed = r.is_err();
            if !push(&mut b, r) || failed {
                emit(b);
                return;
            }
            in_block += 1;
            if in_block == SEQ_BLOCK {
                in_block = 0;
                if !emit(std::mem::replace(&mut b, new_block())) {
                    return;
                }
            }
        }
        if in_block > 0 {
            emit(b);
        }
    }

    /// The stream offset of every core symbol from the length bytes (`None`: a length byte is
    /// unreadable, or no `kallsyms_names`).
    fn core_offsets(&self, n: u64) -> Option<Vec<u64>> {
        let names_base = self.cfg.names_address?;
        if n > MAX_PLAUSIBLE_SYMS {
            return None;
        }
        let mut rd = PageReader::new(self.layer);
        let mut offsets = Vec::with_capacity(n as usize);
        let mut off = 0u64;
        for _ in 0..n {
            let mut len = rd.byte(names_base.wrapping_add(off)).ok()? as u64;
            if len & 0x80 != 0 {
                let upper = rd.byte(names_base.wrapping_add(off + 1)).ok()? as u64;
                len = (upper << 7) | (len & 0x7F);
            }
            offsets.push(off);
            off += len + 1;
        }
        Some(offsets)
    }

    /// python `_is_symbol_exported(name, address, module)`: `Ok(None)` where python returns None.
    fn is_symbol_exported(&self, name: &str, address: u64, module: Option<&Obj>) -> Result<Option<bool>> {
        let ks = self.cfg.kernel_symbol_size;
        let found = match module {
            Some(m) => {
                let num_syms = m.m("num_syms")?.int()?;
                if num_syms <= 0 {
                    return Ok(Some(false));
                }
                let start = m.m("syms")?.u64()?;
                let stop = (start as i128 + num_syms * ks as i128) as u64;
                self.find_exported_symbol_in_range(name, start, stop)?
            }
            None => {
                let s = self.cfg.start_ksymtab.ok_or_else(|| type_error("unsupported operand type(s) for -: 'NoneType' and 'NoneType'"))?;
                let e = self.cfg.stop_ksymtab.ok_or_else(|| type_error("unsupported operand type(s) for -: 'NoneType' and 'int'"))?;
                self.find_exported_symbol_in_range(name, s, e)?
            }
        };
        match found {
            Some(k) => Ok(Some(k.get_value()? == Some(address))),
            None => Ok(None),
        }
    }

    /// python `_find_exported_symbol_in_range` + `_search_kernel_symbol_object_by_name`.
    fn find_exported_symbol_in_range(&self, name: &str, start: u64, stop: u64) -> Result<Option<Obj>> {
        let ks = self.cfg.kernel_symbol_size as i128;
        let mut num_elems = (stop as i128 - start as i128).div_euclid(ks);
        let mut base = start as i128;
        while num_elems > 0 {
            let pivot = base + (num_elems / 2) * ks;
            let k = self.vm.object_abs("kernel_symbol", pivot as u64)?;
            let other = k.get_name()?;
            let Some(other) = other else { return Err(type_error("'>' not supported between instances of 'NoneType' and 'int'")) };
            match name.cmp(other.as_str()) {
                std::cmp::Ordering::Equal => return Ok(Some(k)),
                std::cmp::Ordering::Greater => {
                    base = pivot + ks;
                    num_elems -= 1;
                }
                std::cmp::Ordering::Less => {}
            }
            num_elems /= 2;
        }
        Ok(None)
    }

    /// python `get_modules_symbols(name=None)`: module symbols (optionally only `name`).
    pub fn get_modules_symbols(&self, name: Option<&str>) -> Vec<Result<KasSymbol>> {
        let mut out = Vec::new();
        let r = (|| -> Result<()> {
            for module in list_modules(&self.vm) {
                let module = module?;
                let module_name = array_to_string(&module.m("name")?, None)?;
                let Some(tab) = module.get_symbols()? else { continue };
                for idx in 0..tab.count {
                    let sym = tab.sym(idx);
                    let Some(sym_name) = sym.get_name() else { continue };
                    if sym_name.is_empty() {
                        continue;
                    }
                    if let Some(n) = name {
                        if !n.is_empty() && n != sym_name {
                            continue;
                        }
                    }
                    let address = sym.st_value()? & self.mask;
                    let size = sym.st_size()? as i128;
                    let sym_type = module.get_symbol_type(&sym, idx)?;
                    let exported = self.is_symbol_exported(&sym_name, address, Some(&module))?;
                    let t = sym_type.ok_or_else(|| Error::msg("AttributeError: 'NoneType' object has no attribute 'lower'"))?;
                    let t = if exported == Some(true) { t.to_uppercase() } else { t.to_lowercase() };
                    out.push(Ok(KasSymbol { name: sym_name, type_: Some(Cow::Owned(t)), address, size: Some(size), module_name: Some(Cow::Owned(module_name.clone())), exported, subsystem: Some("module") }));
                }
            }
            Ok(())
        })();
        if let Err(e) = r {
            out.push(Err(e));
        }
        out
    }

    /// python `get_ftrace_symbols()`.
    pub fn get_ftrace_symbols(&self) -> Vec<Result<KasSymbol>> {
        let mut out = Vec::new();
        let f = match self.ftrace() {
            Ok(f) => f,
            Err(e) => return vec![Err(e)],
        };
        if f.mod_supported {
            for func in &f.funcs {
                match Self::ftrace_func_symbol(&f, func) {
                    Ok(s) => out.push(Ok(s)),
                    Err(e) => {
                        out.push(Err(e));
                        return out;
                    }
                }
            }
            if let Some(e) = &f.funcs_tail {
                out.push(Err(clone_err(e)));
                return out;
            }
        }
        for &(a, s) in &f.tramps {
            out.push(Ok(Self::ftrace_tramp_symbol(a, s)));
        }
        if let Some(e) = &f.tramps_tail {
            out.push(Err(clone_err(e)));
        }
        out
    }

    /// python `get_bpf_symbols()`.
    pub fn get_bpf_symbols(&self) -> Vec<Result<KasSymbol>> {
        let vm = &self.vm;
        let (list_type, member, is_ksym) = if vm.has_type("bpf_ksym") {
            ("bpf_ksym", "lnode", true)
        } else if vm.has_type("bpf_prog_aux") {
            ("bpf_prog_aux", "ksym_lnode", false)
        } else {
            return Vec::new();
        };
        let head = match vm.object_from_symbol("bpf_kallsyms") {
            Ok(h) => h,
            Err(Error::Symbol(_)) => return Vec::new(),
            Err(e) => return vec![Err(e)],
        };
        let sym = format!("{}!{list_type}", vm.symbol_table_name());
        let mut out = Vec::new();
        for elem in head.to_list(&sym, member, true, true, None) {
            let elem = match elem {
                Ok(e) => e,
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            };
            let r = (|| -> Result<(String, u64, i128)> {
                if is_ksym {
                    let name = array_to_string(&elem.m("name")?, None)?;
                    let s = elem.m("start")?.u64()?;
                    let e = elem.m("end")?.u64()?;
                    Ok((name, s, e as i128 - s as i128))
                } else {
                    let prog = elem.m("prog")?.deref()?;
                    let name = prog.get_name()?.ok_or_else(|| Error::msg("name is None"))?;
                    let a = prog.m("bpf_func")?.u64()?;
                    let (s, e) = prog.get_address_region()?;
                    Ok((name, a, e as i128 - s as i128))
                }
            })();
            let (name, addr, size) = match r {
                Ok(v) => v,
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            };
            let mut s = KasSymbol { name, type_: Some("t".into()), address: addr & self.mask, size: Some(size), module_name: Some("bpf".into()), exported: None, subsystem: Some("bpf") };
            s.set_exported_from_type();
            out.push(Ok(s));
        }
        out
    }

    /// python `get_all_symbols()`: core, modules, ftrace, BPF.
    pub fn get_all_symbols(&self) -> Vec<Result<KasSymbol>> {
        let mut out = Vec::new();
        for part in [0, 1, 2, 3] {
            let v = match part {
                0 => self.get_core_symbols(),
                1 => self.get_modules_symbols(None),
                2 => self.get_ftrace_symbols(),
                _ => self.get_bpf_symbols(),
            };
            let failed = v.last().is_some_and(|r| r.is_err());
            out.extend(v);
            if failed {
                break;
            }
        }
        out
    }

    // ------------------------------------------------------------------ name lookups

    /// python `_get_symbol_seq(index)` (kernels >= 6.2).
    fn get_symbol_seq(&self, index: u64) -> Result<u64> {
        let base = self.cfg.seqs_of_names_address.ok_or_else(|| type_error("offset is None"))?;
        let n = self.num_syms()?;
        let mut seq = 0u64;
        for i in 0..3 {
            let j = 3 * index + i;
            if j >= 3 * n {
                return Err(Error::msg("IndexError: array index out of range"));
            }
            seq = (seq << 8) | self.layer.read_u8(base.wrapping_add(j) & self.mask)? as u64;
        }
        Ok(seq)
    }

    fn get_symbol_by_index(&self, index: u64) -> Result<KasSymbolBasic> {
        let seq = self.get_symbol_seq(index)?;
        let off = self.get_symbol_offset(seq)?;
        Ok(self.expand_symbol(off)?.0)
    }

    /// python `_lookup_name_index(name)`.
    fn lookup_name_index(&self, name: &str) -> Result<Option<u64>> {
        let n = self.num_syms()? as i128;
        let (mut low, mut high) = (0i128, n - 1);
        let mut mid = 0i128;
        while low <= high {
            mid = (low + high).div_euclid(2);
            let b = self.get_symbol_by_index(mid as u64)?;
            match name.cmp(b.name.as_str()) {
                std::cmp::Ordering::Greater => low = mid + 1,
                std::cmp::Ordering::Less => high = mid - 1,
                std::cmp::Ordering::Equal => break,
            }
        }
        if low > high {
            return Ok(None);
        }
        let mut low = mid;
        while low != 0 {
            let b = self.get_symbol_by_index((low - 1) as u64)?;
            if name != b.name {
                return Ok(Some(low as u64));
            }
            low -= 1;
        }
        Ok(None)
    }

    /// python `lookup_name(name)`: core symbols (fast path on kernels >= 6.2), then modules.
    pub fn lookup_name(&self, name: &str) -> Result<Option<KasSymbol>> {
        let core = if truthy(self.cfg.seqs_of_names_address) {
            match self.lookup_name_index(name)? {
                None | Some(0) => None,
                Some(index) => {
                    let seq = self.get_symbol_seq(index)?;
                    let off = self.get_symbol_offset(seq)?;
                    let (basic, _) = self.expand_symbol(off)?;
                    let a = self.get_symbol_address_by_index(seq)?.ok_or_else(|| type_error("'<=' not supported"))?;
                    let size = self.get_symbol_pos(a)?.map(|p| p.1);
                    let mut s = KasSymbol { name: basic.name, type_: basic.type_, address: a, size, module_name: Some("kernel".into()), exported: None, subsystem: Some("core") };
                    s.set_exported_from_type();
                    Some(s)
                }
            }
        } else {
            let n = self.num_syms()?;
            // implausible count = corruption; python scans `range(num_syms)` unbounded and hangs.
            if n > MAX_PLAUSIBLE_SYMS {
                return Ok(None);
            }
            let mut names = PageReader::new(self.layer);
            let mut tokens = PageReader::new(self.layer);
            let mut off = 0u64;
            let mut found = None;
            // with a complete address table and a known section end, `_get_symbol`'s address /
            // size computation cannot raise, so only the names need expanding until the match
            let cheap = matches!(self.addr_table(), Some(Ok(t)) if t.complete && t.addrs.len() as u64 == n) && (self.cfg.end.is_some() || self.cfg.etext.is_some());
            for idx in 0..n {
                if cheap {
                    let (b, len) = self.expand_with(&mut names, &mut tokens, off)?;
                    if b.name == name {
                        found = Some(self.get_symbol_at(&mut names, &mut tokens, off, idx)?.0);
                        break;
                    }
                    off += len + 1;
                    continue;
                }
                let (s, len) = self.get_symbol_at(&mut names, &mut tokens, off, idx)?;
                if s.name == name {
                    found = Some(s);
                    break;
                }
                off += len + 1;
            }
            found
        };
        if core.is_some() {
            return Ok(core);
        }
        for s in self.get_modules_symbols(Some(name)) {
            let s = s?;
            if s.name == name {
                return Ok(Some(s));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Context, GlobalOptions};

    fn ctx() -> Context {
        let image = crate::util::env::var("BENCH_IMAGE").unwrap();
        Context::new(GlobalOptions { file: Some(image), symbol_dirs: vec![crate::util::testdata::path("testdata/symbols")], ..Default::default() }).unwrap()
    }

    /// Render python's `linux.kallsyms.Kallsyms` (no options) text output from this API, to
    /// diff against the python reference:
    /// `FASTVOL_BENCH_IMAGE=<img> FASTVOL_TEST_OUT=<file> cargo test --profile fast
    /// kallsyms_like_plugin -- --ignored`.
    #[test]
    #[ignore]
    fn kallsyms_like_plugin() {
        use std::io::Write;
        let ctx = ctx();
        let k = ctx.linux_kernel().unwrap();
        let kas = Kallsyms::get(k).unwrap();
        let t0 = std::time::Instant::now();
        let mut f = std::io::BufWriter::new(std::fs::File::create(crate::util::env::var("TEST_OUT").unwrap()).unwrap());
        writeln!(f, "Volatility 3 Framework 2.28.2\n\nAddr\tType\tSize\tExported\tSubSystem\tModuleName\tSymbolName\tDescription\n").unwrap();
        let mut n = 0;
        'outer: for part in 0..4 {
            let v = match part {
                0 => kas.get_core_symbols(),
                1 => kas.get_modules_symbols(None),
                2 => kas.get_ftrace_symbols(),
                _ => kas.get_bpf_symbols(),
            };
            eprintln!("part {part}: {} items at {:?}", v.len(), t0.elapsed());
            for s in v {
                let s = match s {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("python raised: {e}");
                        break 'outer;
                    }
                };
                let size = match s.size {
                    Some(z) if z > 0 => z.to_string(),
                    _ => "-".into(),
                };
                let exported = match s.exported {
                    Some(true) => "True",
                    Some(false) => "False",
                    None => "-",
                };
                writeln!(
                    f,
                    "{:#x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    s.address,
                    s.type_.as_deref().filter(|t| !t.is_empty()).unwrap_or("-"),
                    size,
                    exported,
                    s.subsystem.unwrap_or("-"),
                    s.module_name.as_deref().unwrap_or("-"),
                    s.name,
                    s.type_description().unwrap_or("-")
                )
                .unwrap();
                n += 1;
            }
        }
        eprintln!("{n} rows in {:?}", t0.elapsed());
    }

    /// Count "big" kallsyms names (2-byte lengths) in the image's kernel.
    #[test]
    #[ignore]
    fn kallsyms_big_symbols() {
        let ctx = ctx();
        let k = ctx.linux_kernel().unwrap();
        let kas = Kallsyms::get(k).unwrap();
        let names = kas.cfg.names_address.unwrap();
        let mut off = 0u64;
        let mut big = 0;
        for _ in 0..kas.num_syms.unwrap() {
            let b = k.vlayer.read_u8(names + off).unwrap() as u64;
            let len = if b & 0x80 != 0 {
                big += 1;
                let u = k.vlayer.read_u8(names + off + 1).unwrap() as u64;
                off += 1;
                (u << 7) | (b & 0x7f)
            } else {
                b
            };
            off += len + 1;
        }
        eprintln!("num_syms {} big {big}", kas.num_syms.unwrap());
    }
}


#[cfg(test)]
mod tests_lookup {
    use super::*;
    use crate::context::{Context, GlobalOptions};

    /// `lookup_name` / `lookup_address` agree with the ISF for a few kernel symbols:
    /// `FASTVOL_BENCH_IMAGE=<img> cargo test --profile fast kallsyms_lookup_name -- --ignored`.
    #[test]
    #[ignore]
    fn kallsyms_lookup_name() {
        let image = crate::util::env::var("BENCH_IMAGE").unwrap();
        let ctx = Context::new(GlobalOptions { file: Some(image), symbol_dirs: vec![crate::util::testdata::path("testdata/symbols")], ..Default::default() }).unwrap();
        let k = ctx.linux_kernel().unwrap();
        let kas = Kallsyms::get(k).unwrap();
        let mask = k.vlayer.address_mask();
        for name in ["init_task", "schedule", "do_syscall_64", "rescuer_thread", "kthread_worker_fn"] {
            let t = std::time::Instant::now();
            let s = kas.lookup_name(name).unwrap().unwrap();
            let isf = k.symbol_addr(name).unwrap() & mask;
            eprintln!("{name}: {:#x} (isf {isf:#x}) type {:?} size {:?} in {:?}", s.address, s.type_, s.size, t.elapsed());
            assert_eq!(s.address, isf);
            if matches!(s.type_.as_deref(), Some("t" | "T")) {
                // lookup_address only resolves kernel text
                let back = kas.lookup_address(s.address).unwrap().unwrap();
                assert_eq!(back.address, s.address);
            }
        }
        assert!(kas.lookup_name("fastvol_no_such_symbol").unwrap().is_none());
    }
}

#[cfg(test)]
mod tests_addr_table {
    use super::*;

    /// `run_start` / `next_greater` against their definitions, for sorted address lists (the
    /// kernel's, fast path) and unsorted ones (the monotonic stack).
    #[test]
    fn runs_and_next_greater() {
        let mut x: u64 = 7;
        let mut lists: Vec<Vec<u64>> = vec![vec![], vec![5], vec![3, 3, 3], vec![1, 2, 2, 2, 5, 5, 9], vec![9, 1, 1, 4, 2, 2, 8, 8, 3]];
        for len in [10usize, 100, 1000] {
            let mut sorted = Vec::new();
            let mut unsorted = Vec::new();
            let mut a = 0x1000u64;
            for _ in 0..len {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                a += (x >> 61) & 3; // runs of equal addresses
                sorted.push(a);
                unsorted.push((x >> 40) & 15);
            }
            lists.push(sorted);
            lists.push(unsorted);
        }
        for addrs in lists {
            let t = AddrTable::new(addrs.clone());
            assert!(t.complete);
            for i in 0..addrs.len() {
                let mut rs = i;
                while rs > 0 && addrs[rs - 1] == addrs[i] {
                    rs -= 1;
                }
                assert_eq!(t.run_start[i] as usize, rs, "{addrs:?} run_start[{i}]");
                let ng = (i + 1..addrs.len()).find(|&j| addrs[j] > addrs[i]).map_or(u32::MAX, |j| j as u32);
                assert_eq!(t.next_greater[i], ng, "{addrs:?} next_greater[{i}]");
            }
        }
        assert!(!AddrTable::new(vec![1, NONE_ADDR]).complete);
    }
}

#[cfg(test)]
mod tests_robustness {
    //! Regression: a corrupted `kallsyms_num_syms` must not drive an unbounded loop.
    //!
    //! Found by the fuzzer (`bench/scripts/fuzz_images.py`): a noble-lime mutant whose
    //! `kallsyms_num_syms` was garbaged to 1,852,554,667 made `linux.kallsyms.Kallsyms` hang
    //! (the timeout fired). python has no bound either -- `get_core_symbols` does
    //! `for sym_idx in range(self._kallsyms_num_syms)` -- so it would loop ~1.8 billion times
    //! and hang forever; fastvol gives up on the enumeration at [`MAX_PLAUSIBLE_SYMS`] instead.
    use super::*;
    use crate::layers::FileLayer;
    use crate::objects::Module;
    use crate::symbols::TableRef;
    use crate::symbols::isf::{BuildOptions, build_blob};
    use crate::symbols::table::{Blob, SymbolTable};

    // Minimal Linux-ish ISF with just the symbols/types Kallsyms::new touches.
    const ISF: &str = r#"{
      "metadata": {"format": "6.2.0"},
      "enums": {},
      "base_types": {
        "unsigned int": {"kind": "int", "size": 4, "signed": false, "endian": "little"},
        "unsigned long": {"kind": "int", "size": 8, "signed": false, "endian": "little"},
        "pointer": {"kind": "int", "size": 8, "signed": false, "endian": "little"},
        "unsigned char": {"kind": "char", "size": 1, "signed": false, "endian": "little"},
        "void": {"kind": "void", "size": 0, "signed": false, "endian": "little"}
      },
      "user_types": {
        "kernel_symbol": {"kind": "struct", "size": 16, "fields": {
          "value_offset": {"offset": 0, "type": {"kind": "base", "name": "unsigned int"}},
          "name_offset": {"offset": 4, "type": {"kind": "base", "name": "unsigned int"}}
        }}
      },
      "symbols": {
        "kallsyms_num_syms":    {"address": 256,  "type": {"kind": "base", "name": "unsigned int"}},
        "kallsyms_token_index": {"address": 512,  "type": {"kind": "base", "name": "unsigned char"}},
        "kallsyms_token_table": {"address": 2048, "type": {"kind": "base", "name": "unsigned char"}},
        "kallsyms_names":       {"address": 4096, "type": {"kind": "base", "name": "unsigned char"}}
      }
    }"#;

    fn leak_table() -> TableRef {
        let blob = build_blob(ISF.as_bytes(), &BuildOptions::default()).expect("build_blob");
        let t = SymbolTable::from_blob(Blob::Owned(blob), "t", "u").expect("from_blob");
        Box::leak(Box::new(t))
    }

    fn leak_layer() -> LayerRef {
        // a tiny raw image: every kallsyms symbol address is readable (all zeros)
        // one file per call: the tests run concurrently and each removes its file
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let k = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("fastvol-kallsyms-fuzz-{}-{k}", std::process::id()));
        std::fs::write(&p, vec![0u8; 8192]).unwrap();
        let l = FileLayer::open(&p).unwrap();
        let _ = std::fs::remove_file(&p); // the mmap keeps the mapping alive
        Box::leak(Box::new(l))
    }

    /// An implausibly large `num_syms` makes core enumeration and `lookup_name` return
    /// immediately (bounded) instead of looping billions of times.
    #[test]
    fn huge_num_syms_does_not_hang() {
        let vm = Module::new(leak_layer(), leak_table(), 0);
        let mut kas = Kallsyms::new(&vm).expect("Kallsyms::new");
        // the exact value the fuzzer's mutant produced, plus the extremes
        for n in [1_852_554_667u64, MAX_PLAUSIBLE_SYMS + 1, 1u64 << 40, u64::MAX] {
            kas.num_syms = Some(n);
            let t = std::time::Instant::now();
            let mut rows = 0usize;
            kas.for_each_core_symbol(&mut |r| {
                rows += r.is_ok() as usize;
                rows < 1_000_000 // stop early if the guard ever regresses, so the test can't hang
            });
            assert_eq!(rows, 0, "num_syms={n}: core enumeration should be skipped, not looped");
            assert!(kas.lookup_name("fastvol_no_such_symbol").unwrap().is_none());
            assert!(t.elapsed() < std::time::Duration::from_secs(5), "num_syms={n}: took too long");
        }
    }

    /// A zero-filled image of `size` bytes with a table whose symbol addresses are
    /// `kallsyms_addresses` at 8192 (so symbol `i` is readable iff `8192 + 8 * i < size`) and
    /// `_end` set: every symbol has an empty name, address 0 and a size.
    fn zero_kallsyms(size: usize) -> Module {
        let isf = ISF.replace(
            "\"kallsyms_names\":",
            "\"kallsyms_addresses\": {\"address\": 8192, \"type\": {\"kind\": \"base\", \"name\": \"unsigned long\"}},
             \"_end\": {\"address\": 1048576, \"type\": {\"kind\": \"base\", \"name\": \"unsigned char\"}},
             \"kallsyms_names\":",
        );
        let blob = build_blob(isf.as_bytes(), &BuildOptions::default()).expect("build_blob");
        let t: TableRef = Box::leak(Box::new(SymbolTable::from_blob(Blob::Owned(blob), "t", "u").expect("from_blob")));
        let p = std::env::temp_dir().join(format!("fastvol-kallsyms-blocks-{}-{size}", std::process::id()));
        std::fs::write(&p, vec![0u8; size]).unwrap();
        let l = FileLayer::open(&p).unwrap();
        let _ = std::fs::remove_file(&p);
        Module::new(Box::leak(Box::new(l)), t, 0)
    }

    /// `for_each_core_block` yields exactly `for_each_core_symbol`'s stream, in order, in
    /// blocks, on the parallel path (several chunks) and on the sequential one (the length
    /// bytes run past the image), with python's stop at the first failing symbol; `push` and
    /// `emit` stop it where they return false.
    #[test]
    fn core_blocks_match_the_symbol_stream() {
        // symbols 0..5000 have readable addresses; symbol 5000 raises
        let vm = zero_kallsyms(8192 + 5000 * 8);
        let mut kas = Kallsyms::new(&vm).expect("Kallsyms::new");
        for n in [6000u64, 60_000] {
            kas.num_syms = Some(n);
            kas.addrs = OnceLock::new();
            let mut stream: Vec<Option<KasSymbol>> = Vec::new();
            kas.for_each_core_symbol(&mut |r| {
                stream.push(r.ok());
                true
            });
            assert_eq!(stream.len(), 5001, "num_syms={n}");
            assert!(stream[..5000].iter().all(|s| s.as_ref().is_some_and(|s| s.module_name.as_deref() == Some("kernel") && s.type_.is_none())));
            assert!(stream[5000].is_none());
            let mut blocks: Vec<Vec<Option<KasSymbol>>> = Vec::new();
            kas.for_each_core_block(
                &Vec::new,
                &|b: &mut Vec<Option<KasSymbol>>, r| {
                    let ok = r.is_ok();
                    b.push(r.ok());
                    ok
                },
                &mut |b| {
                    blocks.push(b);
                    true
                },
            );
            assert!(blocks.len() >= 2 && blocks.iter().all(|b| !b.is_empty() && b.len() <= 4096), "num_syms={n}");
            assert_eq!(blocks.concat(), stream, "num_syms={n}");
            // emit stops after the first block
            let mut got = 0;
            kas.for_each_core_block(&Vec::new, &|b: &mut Vec<bool>, r| {
                b.push(r.is_ok());
                true
            }, &mut |_| {
                got += 1;
                false
            });
            assert_eq!(got, 1, "num_syms={n}");
            // push stops after symbol 100
            let mut seen = Vec::new();
            kas.for_each_core_block(&Vec::new, &|b: &mut Vec<usize>, _| {
                b.push(0);
                b.len() < 101
            }, &mut |b| {
                seen.push(b.len());
                true
            });
            assert_eq!(seen, vec![101], "num_syms={n}");
            // a panic in `push` on a worker comes back here (the stream does not hang)
            let pushes = std::sync::atomic::AtomicUsize::new(0);
            let mut got = 0usize;
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                kas.for_each_core_block(
                    &Vec::new,
                    &|b: &mut Vec<u8>, _| {
                        if pushes.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 3000 {
                            panic!("boom");
                        }
                        b.push(0);
                        true
                    },
                    &mut |b| {
                        got += b.len();
                        true
                    },
                )
            }));
            assert!(r.is_err(), "num_syms={n}");
            assert!(got < n as usize, "num_syms={n}");
        }
    }

    /// A plausible count does not trip the guard: `num_syms = 0` enumerates zero symbols
    /// through the normal path (no wholesale skip), and the bound is far above any real kernel.
    #[test]
    fn plausible_num_syms_is_allowed() {
        assert!(MAX_PLAUSIBLE_SYMS >= 1 << 20, "bound must exceed any real kernel");
        let vm = Module::new(leak_layer(), leak_table(), 0);
        let mut kas = Kallsyms::new(&vm).expect("Kallsyms::new");
        kas.num_syms = Some(0);
        let mut rows = 0usize;
        kas.for_each_core_symbol(&mut |_| {
            rows += 1;
            true
        });
        assert_eq!(rows, 0);
    }
}
