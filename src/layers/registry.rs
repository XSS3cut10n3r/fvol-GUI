//! python `framework/layers/registry.py`: the `RegistryHive` layer. Addresses are registry
//! cell indexes (hive-relative offsets; bit 31 selects the volatile storage) translated
//! through the hive's cell map `_HHIVE.Storage[v].Map.Directory[d].Table[t]` onto the kernel
//! virtual layer (or, on Win10 17063+, the `Registry` process' layer).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Semantics mirrored from python:
//! * `read` first translates EVERY page of the range (python builds the whole `mapping()` list
//!   before reading), so a translation failure (`RegistryInvalidIndex`, or an invalid address
//!   in the cell map) wins over an unreadable data page earlier in the range.
//! * Translation failures that are python `RegistryException`s are `Error::Layer` values
//!   starting with `"Registry"` ([`is_registry_exception`]); they are NOT
//!   `is_invalid_address()`, exactly like python where `RegistryException` is a
//!   `LayerException` but not an `InvalidAddressException`.
//! * Per-page translations are cached (the memory image is immutable), lock-free.
//!
//! The key/value API (python `CM_KEY_NODE` / `CM_KEY_VALUE` extensions) lives in
//! [`crate::symbols::windows::registry`]; hive enumeration in
//! `crate::plugins::windows::registry::hivelist`.

use crate::error::{Error, Result};
use crate::layers::{Layer, LayerExt, Mapping, address_mask_for};
use crate::objects::{Field, LayerRef, Obj, Space};
use crate::symbols::{TableRef, Ty};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

const PAGE: u64 = 0x1000;

/// python `RegistryInvalidIndex` (a `RegistryException`).
pub fn registry_invalid_index(layer: &str, msg: &str) -> Error {
    Error::Layer(format!("RegistryInvalidIndex: {layer}: {msg}"))
}

/// python `RegistryFormatException` (a `RegistryException`).
pub fn registry_format(layer: &str, msg: &str) -> Error {
    Error::Layer(format!("RegistryFormatException: {layer}: {msg}"))
}

/// True for python `RegistryException` (and subclasses) raised by the hive layer.
#[inline]
pub fn is_registry_exception(e: &Error) -> bool {
    matches!(e, Error::Layer(s) if s.starts_with("Registry"))
}

/// True for the errors python registry code catches as
/// `(InvalidAddressException, RegistryException)`.
#[inline]
pub fn is_invalid_or_registry(e: &Error) -> bool {
    e.is_invalid_address() || is_registry_exception(e)
}

fn fail_addr(e: &Error) -> u64 {
    match e {
        Error::InvalidAddress { addr } | Error::Swapped { addr } => *addr,
        _ => 0,
    }
}

/// Pre-resolved kernel types used by the hive layer and the key/value extensions.
#[derive(Clone, Copy)]
pub struct HiveTypes {
    pub cell_data: Ty,
    pub key_node: Ty,
    pub key_value: Ty,
    pub key_index: Ty,
    pub key_security: Ty,
    pub big_data: Ty,
    /// `_CELL_DATA.u.KeyNode` etc. (offset within the cell data; 0 in practice)
    pub off_key_node: u64,
    pub off_key_value: u64,
    pub off_key_index: u64,
    pub off_key_security: u64,
    pub off_big_data: u64,
    pub off_key_list: u64,
    // _CM_KEY_NODE
    pub kn_subkey_lists: u64,
    pub kn_value_list_count: u64,
    pub kn_value_list_list: u64,
    pub kn_name_length: u64,
    pub kn_name: u64,
    pub kn_parent: u64,
    pub kn_last_write: u64,
    pub kn_class: u64,
    pub kn_class_length: u64,
    // _CM_KEY_VALUE
    pub kv_name_length: u64,
    pub kv_name: u64,
    pub kv_data_length: u64,
    pub kv_data: u64,
    pub kv_type: u64,
    // _CM_KEY_INDEX
    pub ki_count: u64,
    pub ki_list: u64,
    // _CM_BIG_DATA
    pub bd_count: u64,
    pub bd_list: u64,
}

impl HiveTypes {
    fn new(t: TableRef) -> Result<HiveTypes> {
        let fp = |p: &str| Field::path(t, "_CELL_DATA", p);
        let kn = |m: &str| t.offset_of("_CM_KEY_NODE", m);
        let kv = |m: &str| t.offset_of("_CM_KEY_VALUE", m);
        let vl = t.offset_of("_CM_KEY_NODE", "ValueList")?;
        Ok(HiveTypes {
            cell_data: t.get_type("_CELL_DATA")?,
            key_node: fp("u.KeyNode")?.ty,
            key_value: fp("u.KeyValue")?.ty,
            key_index: fp("u.KeyIndex")?.ty,
            key_security: fp("u.KeySecurity")?.ty,
            big_data: fp("u.ValueData")?.ty,
            off_key_node: fp("u.KeyNode")?.offset,
            off_key_value: fp("u.KeyValue")?.offset,
            off_key_index: fp("u.KeyIndex")?.offset,
            off_key_security: fp("u.KeySecurity")?.offset,
            off_big_data: fp("u.ValueData")?.offset,
            off_key_list: fp("u.KeyList")?.offset,
            kn_subkey_lists: kn("SubKeyLists")?,
            kn_value_list_count: vl + t.offset_of("_CHILD_LIST", "Count")?,
            kn_value_list_list: vl + t.offset_of("_CHILD_LIST", "List")?,
            kn_name_length: kn("NameLength")?,
            kn_name: kn("Name")?,
            kn_parent: kn("Parent")?,
            kn_last_write: kn("LastWriteTime")?,
            kn_class: kn("Class")?,
            kn_class_length: kn("ClassLength")?,
            kv_name_length: kv("NameLength")?,
            kv_name: kv("Name")?,
            kv_data_length: kv("DataLength")?,
            kv_data: kv("Data")?,
            kv_type: kv("Type")?,
            ki_count: t.offset_of("_CM_KEY_INDEX", "Count")?,
            ki_list: t.offset_of("_CM_KEY_INDEX", "List")?,
            bd_count: t.offset_of("_CM_BIG_DATA", "Count")?,
            bd_list: t.offset_of("_CM_BIG_DATA", "List")?,
        })
    }
}

/// How `_HMAP_ENTRY.get_block_offset()` is computed for this kernel.
#[derive(Clone, Copy)]
enum EntryKind {
    /// `(PermanentBinAddress ^ (PermanentBinAddress & 0xF)) + BlockOffset`
    Pba { pba: Field, bo: Field },
    /// `BlockAddress` (older kernels, python's AttributeError fallback)
    BlockAddress(Field),
}

/// Cached translations of one `_HMAP_TABLE` (512 pages).
struct TableCache {
    /// The `_HMAP_TABLE` object, or the failing address of the directory pointer read.
    table: std::result::Result<Obj, u64>,
    /// Block offset per entry (valid when `state == 1`), or the failing address (`state == 2`).
    vals: Box<[AtomicU64]>,
    state: Box<[AtomicU8]>,
}

struct StorageMap {
    /// python `Storage[v].Map` pointer object (on the kernel layer).
    map_ptr: Obj,
    /// `Storage[v].Map.Directory` array object, or the failing address.
    dir: OnceLock<std::result::Result<Obj, u64>>,
    /// Per directory index (1024).
    tables: Box<[OnceLock<TableCache>]>,
}

/// python `RegistryHive` (a `LinearlyMappedLayer`).
pub struct RegistryHive {
    name: String,
    hive_offset: u64,
    /// python `config["base_layer"]` (the kernel virtual layer): `dependencies[0]`.
    kernel_layer: LayerRef,
    /// python `self._base_layer`: where the cell data is read from (kernel layer or the
    /// Registry process layer).
    base: LayerRef,
    table: TableRef,
    cmhive: Obj,
    hive: Obj,
    cmhive_name: Option<String>,
    base_block: Obj,
    maxaddr_nv: u64,
    maxaddr_v: u64,
    maxaddr: u64,
    entry: EntryKind,
    storage: [StorageMap; 2],
    root_cell: OnceLock<u64>,
    /// Pre-resolved types/offsets for the key/value extensions.
    pub types: HiveTypes,
    /// Set once the layer is leaked (`'static`): the space hive objects live in.
    space: OnceLock<&'static Space>,
}

/// Result of python `RegistryHive._find_registry_process` (memoized per kernel layer).
#[derive(Clone, Copy)]
pub enum RegistryProcess {
    /// The process layer of the `Registry` process.
    Found(LayerRef),
    /// Not found (or python's ValueError: no kernel virtual offset).
    None,
    /// python raised InvalidAddressException while walking the process list.
    Invalid(u64),
}

impl RegistryHive {
    /// python `RegistryHive.__init__`. `registry_proc` is the (memoized) result of
    /// `_find_registry_process` (see `plugins::windows::registry::hivelist`). An
    /// `InvalidAddress` error is what python's `list_hives` skips; a `RegistryFormatException`
    /// (bad signature) propagates.
    pub fn new(kernel_layer: LayerRef, table: TableRef, hive_offset: u64, registry_proc: impl FnOnce() -> Result<RegistryProcess>) -> Result<RegistryHive> {
        let name = format!("hive{hive_offset:#x}");
        let ksp = Space::on(kernel_layer, table);
        let cmhive = Obj::named(ksp, "_CMHIVE", hive_offset)?;
        let cmhive_name = crate::symbols::windows::registry::cmhive_get_name(&cmhive);
        let hive = cmhive.m("Hive")?;
        if hive.m("Signature")?.int()? != 0xBEE0_BEE0 {
            return Err(registry_format(&name, &format!("Registry hive at {hive_offset} does not have a valid signature")));
        }
        let mut base = kernel_layer;
        match registry_proc()? {
            RegistryProcess::Found(l) => base = l,
            RegistryProcess::None => {}
            RegistryProcess::Invalid(a) => return Err(Error::invalid(a)),
        }
        let base_block = hive.m("BaseBlock")?.deref()?;
        let storage = hive.m("Storage")?;
        let lens = (|| -> Result<(u64, u64)> {
            let a = storage.at(0)?.m("Length")?.u64()?;
            let b = storage.at(1)?.m("Length")?.u64()?;
            Ok((a, b))
        })();
        let (maxaddr_nv, maxaddr_v) = match lens {
            Ok(v) => v,
            Err(e) if e.is_invalid_address() => (0x7FFF_FFFF, 0x7FFF_FFFF),
            Err(e) => return Err(e),
        };
        let entry = if table.offset_of("_HMAP_ENTRY", "PermanentBinAddress").is_ok() && table.offset_of("_HMAP_ENTRY", "BlockOffset").is_ok() {
            EntryKind::Pba { pba: Field::new(table, "_HMAP_ENTRY", "PermanentBinAddress")?, bo: Field::new(table, "_HMAP_ENTRY", "BlockOffset")? }
        } else {
            EntryKind::BlockAddress(Field::new(table, "_HMAP_ENTRY", "BlockAddress")?)
        };
        let mk = |i: u64| -> Result<StorageMap> {
            Ok(StorageMap { map_ptr: storage.at(i)?.m("Map")?, dir: OnceLock::new(), tables: (0..1024).map(|_| OnceLock::new()).collect() })
        };
        Ok(RegistryHive {
            name,
            hive_offset,
            kernel_layer,
            base,
            table,
            cmhive,
            hive,
            cmhive_name,
            base_block,
            maxaddr_nv,
            maxaddr_v,
            maxaddr: 0x8000_0000 | maxaddr_v,
            entry,
            storage: [mk(0)?, mk(1)?],
            root_cell: OnceLock::new(),
            types: HiveTypes::new(table)?,
            space: OnceLock::new(),
        })
    }

    /// Leak the layer (layers live for the whole run) and bind its object space.
    pub fn leak(self) -> &'static RegistryHive {
        let h: &'static RegistryHive = Box::leak(Box::new(self));
        let l: LayerRef = h;
        let _ = h.space.set(Space::on(l, h.table));
        h
    }

    /// The space objects on this hive live in (layer = native layer = this hive, kernel table).
    #[inline]
    pub fn space(&self) -> &'static Space {
        self.space.get().expect("RegistryHive used before leak()")
    }

    /// This hive as a `&dyn Layer`.
    #[inline]
    pub fn as_layer(&'static self) -> LayerRef {
        self
    }

    /// python `hive.hive_offset`.
    #[inline]
    pub fn hive_offset(&self) -> u64 {
        self.hive_offset
    }

    /// python `hive.hive` (`_CMHIVE.Hive`, an `_HHIVE` on the kernel layer).
    #[inline]
    pub fn hive(&self) -> Obj {
        self.hive
    }

    /// The `_CMHIVE` object on the kernel layer.
    #[inline]
    pub fn cmhive(&self) -> Obj {
        self.cmhive
    }

    /// python `hive._base_block` (the dereferenced `BaseBlock`).
    #[inline]
    pub fn base_block(&self) -> Obj {
        self.base_block
    }

    /// python `hive.get_name()`: the `_CMHIVE` name or `"[NONAME]"`.
    pub fn get_name(&self) -> &str {
        match &self.cmhive_name {
            Some(s) if !s.is_empty() => s,
            _ => "[NONAME]",
        }
    }

    /// python `hive._cmhive_name` (None when no name could be read).
    pub fn cmhive_name(&self) -> Option<&str> {
        self.cmhive_name.as_deref()
    }

    /// python `hive.dependencies[0]` (the kernel virtual layer the hive was built on).
    #[inline]
    pub fn kernel_layer(&self) -> LayerRef {
        self.kernel_layer
    }

    /// python `hive._base_layer` (where cell data is read from).
    #[inline]
    pub fn base_layer(&self) -> LayerRef {
        self.base
    }

    /// The kernel symbol table the hive's objects use.
    #[inline]
    pub fn table(&self) -> TableRef {
        self.table
    }

    /// python `hive.maximum_address`.
    #[inline]
    pub fn maximum_address(&self) -> u64 {
        self.maxaddr
    }

    /// python `hive._get_hive_maxaddr(volatile)`.
    #[inline]
    pub fn hive_maxaddr(&self, volatile: bool) -> u64 {
        if volatile { self.maxaddr_v } else { self.maxaddr_nv }
    }

    /// python `hive.root_cell_offset`.
    pub fn root_cell_offset(&self) -> u64 {
        *self.root_cell.get_or_init(|| {
            let r = (|| -> Result<Option<u64>> {
                let sig = self.base_block.m("Signature")?.read_string(4, "latin-1", "strict")?;
                if sig == "regf" { Ok(Some(self.base_block.m("RootCell")?.u64()?)) } else { Ok(None) }
            })();
            match r {
                Ok(Some(v)) => v,
                _ => 0x20,
            }
        })
    }

    /// python `hive.get_cell(cell_offset)`: the `_CELL_DATA` at `cell_offset + 4` (the HCELL
    /// size is skipped).
    #[inline]
    pub fn get_cell(&self, cell_offset: u64) -> Obj {
        Obj::new(self.space(), self.types.cell_data, cell_offset.wrapping_add(4))
    }

    /// python `hive.get_node(cell_offset)`: the cell interpreted by its 2-byte signature
    /// (`nk` key node, `sk` security, `vk` value, `db` big data, `lf`/`lh`/`ri` key index),
    /// or the raw `_CELL_DATA` (unknown signature / unreadable).
    pub fn get_node(&self, cell_offset: u64) -> Obj {
        let cell = self.get_cell(cell_offset);
        let mut sig = [0u8; 2];
        if self.read(cell.addr, &mut sig).is_err() {
            return cell;
        }
        let t = &self.types;
        let (off, ty) = match &sig {
            b"nk" => (t.off_key_node, t.key_node),
            b"sk" => (t.off_key_security, t.key_security),
            b"vk" => (t.off_key_value, t.key_value),
            b"db" => (t.off_big_data, t.big_data),
            b"lf" | b"lh" | b"ri" => (t.off_key_index, t.key_index),
            _ => return cell,
        };
        Obj::new(self.space(), ty, cell.addr.wrapping_add(off))
    }

    /// python `_translate(offset)`: the address in the base layer for a cell index.
    pub fn translate_cell(&self, offset: u64) -> Result<u64> {
        let volatile = (offset >> 31) & 1;
        let max = if volatile == 1 { self.maxaddr_v } else { self.maxaddr_nv };
        if offset & 0x7FFF_FFFF > max {
            return Err(registry_invalid_index(&self.name, "Mapping request for value greater than maxaddr"));
        }
        let dir_index = ((offset >> 21) & 0x3FF) as usize;
        let table_index = ((offset >> 12) & 0x1FF) as usize;
        let base = self.block_offset(volatile as usize, dir_index, table_index)?;
        Ok(base.wrapping_add(offset & 0xFFF))
    }

    fn block_offset(&self, v: usize, d: usize, t: usize) -> Result<u64> {
        let st = &self.storage[v];
        let tc = st.tables[d].get_or_init(|| {
            let table = (|| -> Result<Obj> {
                let dir = match st.dir.get_or_init(|| st.map_ptr.m("Directory").map_err(|e| fail_addr(&e))) {
                    Ok(o) => *o,
                    Err(a) => return Err(Error::invalid(*a)),
                };
                dir.at(d as u64)?.m("Table")
            })()
            .map_err(|e| fail_addr(&e));
            let n = if table.is_ok() { 512 } else { 0 };
            TableCache { table, vals: (0..n).map(|_| AtomicU64::new(0)).collect(), state: (0..n).map(|_| AtomicU8::new(0)).collect() }
        });
        let table = match tc.table {
            Ok(o) => o,
            Err(a) => return Err(Error::invalid(a)),
        };
        match tc.state[t].load(Ordering::Acquire) {
            1 => return Ok(tc.vals[t].load(Ordering::Relaxed)),
            2 => return Err(Error::invalid(tc.vals[t].load(Ordering::Relaxed))),
            _ => {}
        }
        let r = (|| -> Result<u64> {
            let entry = table.at(t as u64)?;
            match self.entry {
                EntryKind::Pba { pba, bo } => {
                    let p = entry.f(&pba).int()? as u64;
                    let b = entry.f(&bo).int()? as u64;
                    Ok((p ^ (p & 0xF)).wrapping_add(b))
                }
                EntryKind::BlockAddress(ba) => Ok(entry.f(&ba).int()? as u64),
            }
        })();
        match &r {
            Ok(v) => {
                tc.vals[t].store(*v, Ordering::Relaxed);
                tc.state[t].store(1, Ordering::Release);
            }
            Err(e) if e.is_invalid_address() => {
                tc.vals[t].store(fail_addr(e), Ordering::Relaxed);
                tc.state[t].store(2, Ordering::Release);
            }
            Err(_) => {}
        }
        r
    }

    /// Iterate python's `mapping()` chunks of `[addr, addr+len)`: `(offset, chunk_len)`.
    #[inline]
    fn chunks(addr: u64, len: u64, mut f: impl FnMut(u64, u64) -> bool) {
        let mut cur = addr;
        let mut remaining = len;
        let mut chunk = PAGE - (addr & (PAGE - 1));
        while remaining > 0 {
            let c = chunk.min(remaining).min(PAGE);
            if !f(cur, c) {
                return;
            }
            cur = cur.wrapping_add(c);
            remaining -= c;
            chunk = PAGE;
        }
    }
}

impl Layer for RegistryHive {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_address(&self) -> u64 {
        self.maxaddr
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        let len = buf.len() as u64;
        if len == 0 {
            return Ok(());
        }
        if len <= PAGE - (addr & (PAGE - 1)) {
            let t = self.translate_cell(addr)?;
            return self.base.read(t, buf);
        }
        // python computes the whole mapping first: translation errors take precedence.
        // Runs contiguous in the base layer are coalesced into one read.
        let mut runs: Vec<(u64, usize, usize)> = Vec::new();
        let mut err = None;
        let mut done = 0usize;
        Self::chunks(addr, len, |cur, c| match self.translate_cell(cur) {
            Ok(t) => {
                match runs.last_mut() {
                    Some(last) if last.0.wrapping_add(last.2 as u64) == t => last.2 += c as usize,
                    _ => runs.push((t, done, c as usize)),
                }
                done += c as usize;
                true
            }
            Err(e) => {
                err = Some(e);
                false
            }
        });
        if let Some(e) = err {
            return Err(e);
        }
        for (t, off, n) in runs {
            self.base.read(t, &mut buf[off..off + n])?;
        }
        Ok(())
    }

    fn read_padded(&self, addr: u64, buf: &mut [u8]) {
        let len = buf.len() as u64;
        let mut done = 0usize;
        Self::chunks(addr, len, |cur, c| {
            let c = c as usize;
            match self.translate_cell(cur) {
                Ok(t) => self.base.read_padded(t, &mut buf[done..done + c]),
                Err(_) => buf[done..done + c].fill(0),
            }
            done += c;
            true
        });
    }

    fn is_valid(&self, addr: u64, len: u64) -> bool {
        let mut ok = true;
        Self::chunks(addr, len, |cur, c| {
            ok = match self.translate_cell(cur) {
                Ok(t) => self.base.is_valid(t, c),
                Err(_) => false,
            };
            ok
        });
        ok
    }

    fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
        let mut pending: Option<Mapping> = None;
        let mut stopped = false;
        Self::chunks(addr, len, |cur, c| {
            if let Ok(t) = self.translate_cell(cur) {
                match &mut pending {
                    Some(p) if p.offset.wrapping_add(p.len) == cur && p.mapped.wrapping_add(p.len) == t => p.len += c,
                    _ => {
                        if let Some(p) = pending.take() {
                            if !f(p) {
                                stopped = true;
                                return false;
                            }
                        }
                        pending = Some(Mapping { offset: cur, len: c, mapped: t });
                    }
                }
            }
            true
        });
        if !stopped {
            if let Some(p) = pending {
                f(p);
            }
        }
    }

    fn translate(&self, addr: u64) -> Option<(u64, u64)> {
        self.translate_cell(addr).ok().map(|t| (t, PAGE - (addr & (PAGE - 1))))
    }

    fn class_name(&self) -> &'static str {
        "RegistryHive"
    }

    fn address_mask(&self) -> u64 {
        address_mask_for(self.maxaddr) | 0x8000_0000
    }

    fn as_registry_hive(&self) -> Option<&RegistryHive> {
        Some(self)
    }
}

/// The registry hive an object lives on (python `context.layers[obj.vol.layer_name]` being a
/// `RegistryHive`), or None.
#[inline]
pub fn hive_of(o: &Obj) -> Option<&'static RegistryHive> {
    let l: LayerRef = o.layer();
    l.as_registry_hive()
}

/// Convenience: `layer.read_vec` on a hive (python `hive.read(offset, length)`).
pub fn hive_read(h: &RegistryHive, addr: u64, len: usize) -> Result<Vec<u8>> {
    h.read_vec(addr, len)
}
