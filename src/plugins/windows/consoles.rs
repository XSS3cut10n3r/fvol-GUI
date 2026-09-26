//! windows.consoles.Consoles (python `plugins/windows/consoles.py`), plus the helpers
//! `windows.cmdscan.CmdScan` shares with it: conhost process discovery, conhost symbol table
//! selection (with a minimal `verinfo` port), the registry lookup of console settings and a
//! CPython `set` emulation ([`PySet`]) that reproduces python's scan order.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::layers::scan::{BytesScanner, scan, scan_each_progressive};
use crate::layers::LayerExt;
use crate::objects::util::array_to_string;
use crate::objects::{LayerRef, Obj, Space};
use crate::plugins::windows::registry::hivelist::list_hives;
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::windows::consoles::{ConsoleExt, Screen};
use crate::symbols::windows::prelude::*;
use crate::symbols::windows::registry::{RegData, RegExt};

pub struct Consoles;

// ------------------------------------------------------------------------------------------
// CPython set emulation
// ------------------------------------------------------------------------------------------

/// An element python may put in the `max_history` / `max_buffers` sets: ints from the CLI and
/// the registry (`REG_DWORD`/`REG_QWORD`), or the `bytes` `decode_data()` returns for other
/// value types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetElem {
    Int(i128),
    Bytes(Vec<u8>),
}

/// CPython's `hash(int)`: `sign * (|v| mod (2**61 - 1))`, with -1 mapped to -2.
pub fn py_hash_int(v: i128) -> i64 {
    const P: u128 = (1u128 << 61) - 1;
    let m = (v.unsigned_abs() % P) as i64;
    let h = if v < 0 { -m } else { m };
    if h == -1 { -2 } else { h }
}

/// A python `set` of ints with CPython 3.14's exact iteration order (`setobject.c`: open
/// addressing on `hash & mask`, `LINEAR_PROBES` = 9 then perturbation, a table of 8 slots grown
/// to the smallest power of two > `used * 4` when `fill * 5 >= mask * 3`, iteration in slot
/// order). Python iterates `max_history` this way, and the order decides which scan hits come
/// first. `bytes` elements (whose hash is randomized per python process, so python's order is
/// not reproducible) are kept apart and iterated last.
#[derive(Clone, Debug)]
pub struct PySet {
    table: Vec<Option<(i64, i128)>>,
    fill: usize,
    used: usize,
    other: Vec<Vec<u8>>,
}

const LINEAR_PROBES: usize = 9;
const PERTURB_SHIFT: u32 = 5;

impl Default for PySet {
    fn default() -> Self {
        PySet { table: vec![None; 8], fill: 0, used: 0, other: Vec::new() }
    }
}

impl PySet {
    /// python `set(values)`.
    pub fn from_ints(values: &[i128]) -> PySet {
        let mut s = PySet::default();
        for &v in values {
            s.add_int(v);
        }
        s
    }

    /// python `s.add(value)`.
    pub fn add(&mut self, e: SetElem) {
        match e {
            SetElem::Int(v) => self.add_int(v),
            SetElem::Bytes(b) => {
                if !self.other.contains(&b) {
                    self.other.push(b)
                }
            }
        }
    }

    /// `set_add_entry` for an int key.
    pub fn add_int(&mut self, key: i128) {
        let hash = py_hash_int(key);
        let mask = self.table.len() - 1;
        let mut i = (hash as u64 as usize) & mask;
        let mut perturb = hash as u64;
        loop {
            let probes = if i + LINEAR_PROBES <= mask { LINEAR_PROBES } else { 0 };
            for j in 0..=probes {
                match self.table[i + j] {
                    None => {
                        self.table[i + j] = Some((hash, key));
                        self.fill += 1;
                        self.used += 1;
                        if self.fill * 5 >= mask * 3 {
                            self.resize(if self.used > 50000 { self.used * 2 } else { self.used * 4 });
                        }
                        return;
                    }
                    Some((h, k)) if h == hash && k == key => return,
                    _ => {}
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb as usize)) & mask;
        }
    }

    /// `set_table_resize(so, minused)` (no dummies: nothing is ever removed).
    fn resize(&mut self, minused: usize) {
        let mut newsize = 8usize;
        while newsize <= minused {
            newsize <<= 1;
        }
        let old = std::mem::replace(&mut self.table, vec![None; newsize]);
        let mask = newsize - 1;
        for (hash, key) in old.into_iter().flatten() {
            // set_insert_clean
            let mut i = (hash as u64 as usize) & mask;
            let mut perturb = hash as u64;
            'probe: loop {
                if self.table[i].is_none() {
                    self.table[i] = Some((hash, key));
                    break;
                }
                if i + LINEAR_PROBES <= mask {
                    for j in 1..=LINEAR_PROBES {
                        if self.table[i + j].is_none() {
                            self.table[i + j] = Some((hash, key));
                            break 'probe;
                        }
                    }
                }
                perturb >>= PERTURB_SHIFT;
                i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb as usize)) & mask;
            }
        }
    }

    /// The elements in python iteration order.
    pub fn elems(&self) -> Vec<SetElem> {
        let mut v: Vec<SetElem> = self.table.iter().flatten().map(|&(_, k)| SetElem::Int(k)).collect();
        v.extend(self.other.iter().cloned().map(SetElem::Bytes));
        v
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.used + self.other.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Marker prefix of [`py_exception`] errors.
const PY_RAISE: &str = "\u{1}python exception: ";

/// A python exception that is not a volatility exception (`struct.error`,
/// `NotImplementedError`, `UnboundLocalError`, `TypeError` ...): python crashes with a
/// traceback there. Carried as an error value (so rows before it are still emitted in
/// order), then turned into the plugin panic rsvol uses for it by [`raise`].
pub fn py_exception(msg: impl Into<String>) -> Error {
    Error::Msg(format!("{PY_RAISE}{}", msg.into()))
}

/// Pass volatility errors through; panic (python's uncaught exception) for [`py_exception`]s.
pub fn raise(e: Error) -> Error {
    if let Error::Msg(s) = &e {
        if let Some(m) = s.strip_prefix(PY_RAISE) {
            panic!("{m}");
        }
    }
    e
}

/// python `struct.pack("H", value)` (the scan needle for a CommandHistorySize value).
pub fn pack_h(v: &SetElem) -> Result<[u8; 2]> {
    match v {
        SetElem::Int(i) if (0..=0xFFFF).contains(i) => Ok((*i as u16).to_le_bytes()),
        SetElem::Int(_) => Err(py_exception("struct.error: 'H' format requires 0 <= number <= 65535")),
        SetElem::Bytes(_) => Err(py_exception("struct.error: required argument is not an integer")),
    }
}

/// The config value of a `ListRequirement(int)` with python's default when absent.
pub fn config_ints(cfg: &Config, name: &str, default: i128) -> Vec<i128> {
    match cfg.get(name) {
        Some(ConfigValue::List(l)) => l.iter().filter_map(|v| if let ConfigValue::Int(i) = v { Some(*i) } else { None }).collect(),
        Some(ConfigValue::Int(i)) => vec![*i],
        _ => vec![default],
    }
}

// ------------------------------------------------------------------------------------------
// registry
// ------------------------------------------------------------------------------------------

/// python `Consoles.get_console_settings_from_registry(...)`: adds every `HistoryBufferSize`
/// of a `Console` key to `max_history` and every `NumberOfHistoryBuffers` to `max_buffers`.
/// `max_buffers = None` is cmdscan's `max_buffers=[]` (a list: `.add` raises AttributeError,
/// which skips the rest of that hive). Any error inside a hive skips the rest of the hive
/// (python `except Exception: continue`); errors listing the hives propagate.
pub fn get_console_settings_from_registry(ctx: &Context, k: &WinKernel, max_history: &mut PySet, mut max_buffers: Option<&mut PySet>) -> Result<()> {
    let _t = crate::util::trace::span("consoles: registry settings");
    for hive in list_hives(ctx, k, None, None) {
        let hive = hive?;
        let _ = (|| -> Result<()> {
            let key = hive.get_key_node("Console")?;
            for value in key.get_values() {
                let val_name = value.get_name()?;
                let data = |v: RegData| match v {
                    RegData::Int(i) => SetElem::Int(i as i128),
                    RegData::Bytes(b) => SetElem::Bytes(b),
                };
                if val_name == "HistoryBufferSize" {
                    max_history.add(data(value.decode_data()?));
                } else if val_name == "NumberOfHistoryBuffers" {
                    match max_buffers.as_deref_mut() {
                        Some(s) => s.add(data(value.decode_data()?)),
                        None => return Err(Error::Symbol("AttributeError: 'list' object has no attribute 'add'".into())),
                    }
                }
            }
            Ok(())
        })();
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------
// conhost processes / symbol table
// ------------------------------------------------------------------------------------------

/// A conhost.exe process (python `find_conhost_proc` yields it with its process layer).
#[derive(Clone, Copy)]
pub struct ConhostProc {
    pub proc: Obj,
    pub layer: LayerRef,
}

/// python `PsList.list_processes(filter_func=_conhost_proc_filter)` followed by
/// `Consoles.find_conhost_proc`: the conhost.exe processes (consoles compares the name
/// case-insensitively, cmdscan's filter is case-sensitive) with their process layers;
/// processes whose layer cannot be built (invalid address) are skipped. A trailing `Err` is
/// where python raised.
pub fn find_conhost_procs(k: &WinKernel, case_insensitive: bool) -> Vec<Result<ConhostProc>> {
    let filter = |p: &Obj| -> Result<bool> {
        let name = array_to_string(&p.m("ImageFileName")?, None)?;
        Ok(if case_insensitive { name.to_lowercase() != "conhost.exe" } else { name != "conhost.exe" })
    };
    let mut out = Vec::new();
    for p in crate::plugins::windows::pslist::list_processes(k, &filter) {
        let proc = match p {
            Ok(p) => p,
            Err(e) => {
                out.push(Err(e));
                break;
            }
        };
        let r = (|| -> Result<Option<ConhostProc>> {
            if array_to_string(&proc.m("ImageFileName")?, None)?.to_lowercase() != "conhost.exe" {
                return Ok(None);
            }
            proc.m("UniqueProcessId")?.int()?;
            Ok(Some(ConhostProc { proc, layer: proc.add_process_layer()? }))
        })();
        match r {
            Ok(Some(c)) => out.push(Ok(c)),
            Ok(None) => {}
            Err(e) if e.is_invalid_address() => {}
            Err(e) => {
                out.push(Err(e));
                break;
            }
        }
    }
    out
}

/// python `Consoles.find_conhostexe(proc)`: (base, size) of the first VAD mapping a file
/// whose name ends with "conhost.exe" (case-insensitive); None when there is none.
pub fn find_conhostexe(proc: &Obj) -> Result<Option<(u64, i128)>> {
    for v in proc.get_vad_root()?.traverse() {
        let vad = v?;
        if let Value::Str(f) = vad.get_file_name() {
            if f.to_lowercase().ends_with("conhost.exe") {
                let base = vad.get_start()?;
                let size = vad.get_end()? as i128 - vad.get_start()? as i128 + 1;
                return Ok(Some((base, size)));
            }
        }
    }
    Ok(None)
}

/// python `version_dict` of `determine_conhost_version` (x64).
const VERSION_DICT: [((i128, i128, i128, i128), &str); 12] = [
    ((10, 0, 17763, 1), "consoles-win10-17763-x64"),
    ((10, 0, 17763, 3232), "consoles-win10-17763-3232-x64"),
    ((10, 0, 18362, 0), "consoles-win10-18362-x64"),
    ((10, 0, 19041, 0), "consoles-win10-19041-x64"),
    ((10, 0, 20348, 1), "consoles-win10-20348-x64"),
    ((10, 0, 20348, 1970), "consoles-win10-20348-1970-x64"),
    ((10, 0, 20348, 2461), "consoles-win10-20348-2461-x64"),
    ((10, 0, 20348, 2520), "consoles-win10-20348-2461-x64"),
    ((10, 0, 22000, 0), "consoles-win10-22000-x64"),
    ((10, 0, 22621, 1), "consoles-win10-22621-x64"),
    ((10, 0, 22621, 3527), "consoles-win10-22621-3527-x64"),
    ((10, 0, 25398, 0), "consoles-win10-22000-x64"),
];

fn is_attribute_or_type_error(e: &Error) -> bool {
    match e {
        Error::Symbol(s) | Error::Msg(s) => s.starts_with("AttributeError") || s.starts_with("TypeError"),
        _ => false,
    }
}

/// python `Consoles.determine_conhost_version(...)`: the consoles ISF file name for this
/// kernel (and, for builds with several conhost layouts, conhost.exe's version resource).
pub fn determine_conhost_version(ctx: &Context, k: &WinKernel, conhost_layer: LayerRef, conhost_base: u64) -> Result<&'static str> {
    let is_64bit = k.table.is_64bit();
    let vers = crate::plugins::windows::info::get_version_structure(k)?;
    let kuser = crate::plugins::windows::info::get_kuser_structure(k)?;
    let (vers_minor_version, nt_major_version, nt_minor_version) =
        match (|| -> Result<(i128, i128, i128)> { Ok((vers.m("MinorVersion")?.int()?, kuser.m("NtMajorVersion")?.int()?, kuser.m("NtMinorVersion")?.int()?)) })() {
            Ok(v) => v,
            Err(_) => return Err(Error::msg("Kernel Debug Structure missing VERSION/KUSER structure, unable to determine Windows version!")),
        };
    // python's debug f-string also reads MajorVersion (unguarded)
    let vers_major = vers.m("MajorVersion")?.int()?;
    let version_dict: &[((i128, i128, i128, i128), &str)] = if is_64bit { &VERSION_DICT } else { &[] };
    let mut conhost_mod_version: i128 = 0;
    if version_dict.iter().any(|&((a, b, c, d), _)| (a, b, c) == (nt_major_version, nt_minor_version, vers_minor_version) && d != 0) {
        match get_version_information(ctx, conhost_layer, conhost_base) {
            Ok((_, _, _, build)) => conhost_mod_version = build,
            Err(e) if e.is_invalid_address() || is_attribute_or_type_error(&e) => {
                if let Some(ver) = find_version_info(k.phys, "CONHOST.EXE")? {
                    conhost_mod_version = ver.3;
                }
            }
            Err(e) => return Err(e),
        }
    }
    let want = (nt_major_version, nt_minor_version, vers_minor_version, conhost_mod_version);
    if let Some(&(_, f)) = version_dict.iter().find(|(v, _)| *v == want) {
        return Ok(f);
    }
    let mut current: Vec<&((i128, i128, i128, i128), &str)> = version_dict
        .iter()
        .filter(|((a, b, c, d), _)| *a == nt_major_version && *b == nt_minor_version && *c <= vers_minor_version && *d <= conhost_mod_version)
        .collect();
    current.sort_by_key(|(v, _)| *v);
    match current.last() {
        Some((v, _)) => Ok(version_dict.iter().find(|(w, _)| w == v).map(|(_, f)| *f).unwrap_or("")),
        None => Err(py_exception(format!(
            "NotImplementedError: This version of Windows is not supported: {nt_major_version}.{nt_minor_version} {vers_major}.{vers_minor_version}!"
        ))),
    }
}

/// python `Consoles.create_conhost_symbol_table(...)`: the consoles ISF bound to the kernel
/// table (`nt_symbols`).
pub fn create_conhost_symbol_table(ctx: &Context, k: &WinKernel, conhost_layer: LayerRef, conhost_base: u64) -> Result<TableRef> {
    let file = determine_conhost_version(ctx, k, conhost_layer, conhost_base)?;
    ctx.load_isf_with(&format!("windows/consoles/{file}"), None, &[("nt_symbols", k.table.name())])
}

// ------------------------------------------------------------------------------------------
// minimal verinfo (only reached for builds 17763 / 20348 / 22621)
// ------------------------------------------------------------------------------------------
// TODO(dedupe): owned by W2b (verinfo)

/// python `VerInfo.find_version_info(context, layer_name, filename)`: find
/// `"OriginalFilename\0" + filename` (utf-16be, python's choice) in the physical layer and
/// read the file version after the `VS_FIXEDFILEINFO` signature within the 0x500 bytes
/// before it (python's `find(sig) + 4 >= 0` is always true: without a signature the words at
/// offset 3 are used).
pub fn find_version_info(layer: LayerRef, filename: &str) -> Result<Option<(i128, i128, i128, i128)>> {
    let needle: Vec<u8> = format!("OriginalFilename\0{filename}").encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    let mut first = None;
    scan_each_progressive(layer, &BytesScanner::new(&needle), |h| *h, |h| {
        first = Some(h);
        false
    });
    let Some(offset) = first else { return Ok(None) };
    if offset < 0x500 {
        return Err(Error::invalid(offset.wrapping_sub(0x500)));
    }
    let data = layer.read_vec(offset - 0x500, 0x500)?;
    let at = crate::layers::scan::find(&data, b"\xbd\x04\xef\xfe").map(|i| i as i64).unwrap_or(-1) + 4;
    let s = data.get(at as usize..at as usize + 20).filter(|s| s.len() == 20).ok_or_else(|| py_exception("struct.error: unpack requires a buffer of 20 bytes"))?;
    let w = |o: usize| u16::from_le_bytes([s[o], s[o + 1]]) as i128;
    // "<IHHHHHHHH": struct_version, FV2, FV1, FV4, FV3, ...
    Ok(Some((w(6), w(4), w(10), w(8))))
}

/// python `VerInfo.get_version_information(context, pe_table, layer, base)`: rebuild the PE
/// (`dos_header.reconstruct()`), then what `pefile` does to find `VS_FIXEDFILEINFO[0]` in the
/// resource directory; returns the product version. No version resource -> an
/// `AttributeError` (python: `pe.VS_FIXEDFILEINFO` missing).
pub fn get_version_information(ctx: &Context, layer: LayerRef, base: u64) -> Result<(i128, i128, i128, i128)> {
    let pe_table = ctx.load_isf("windows/pe")?;
    let dos = Obj::named(Space::on(layer, pe_table), "_IMAGE_DOS_HEADER", base)?;
    let (pieces, err) = crate::symbols::windows::pe::reconstruct(&dos);
    match err {
        // python: ValueError (bad signatures, sizes) is not caught by consoles
        Some(e) if e.is_invalid_address() => return Err(e),
        Some(e) => return Err(py_exception(format!("ValueError: {e}"))),
        None => {}
    }
    // io.BytesIO: seek + write
    let size = pieces.iter().map(|(o, d)| *o as usize + d.len()).max().unwrap_or(0);
    let mut data = vec![0u8; size];
    for (o, d) in &pieces {
        data[*o as usize..*o as usize + d.len()].copy_from_slice(d);
    }
    let fixed = pefile::first_fixed_file_info(&data).ok_or_else(|| Error::Symbol("AttributeError: 'PE' object has no attribute 'VS_FIXEDFILEINFO'".into()))?;
    let (ms, ls) = (fixed.0 as i128, fixed.1 as i128);
    Ok((ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF))
}

/// The part of `pefile` that `pefile.PE(data=..., fast_load=True)` +
/// `parse_data_directories([RESOURCE])` + `VS_FIXEDFILEINFO[0]` need, on a reconstructed
/// image (sections at `PointerToRawData == VirtualAddress`).
mod pefile {
    const MAX_RESOURCE_DEPTH: u32 = 32;
    const MAX_ALLOWED_ENTRIES: u32 = 4096;
    const MAX_RESOURCE_ENTRIES: u32 = 0x8000;
    const RT_VERSION: u32 = 16;

    struct Section {
        va: u64,
        raw_ptr: u64,
        raw_size: u64,
        vsize: u64,
        next_va: Option<u64>,
    }

    struct Pe<'a> {
        data: &'a [u8],
        sections: Vec<Section>,
        total_entries: u32,
        fixed: Vec<(u32, u32)>,
    }

    struct Entry {
        id: u32,
        dir: Option<Vec<Entry>>,
        data: Option<(u32, u32)>,
    }

    fn u16_at(d: &[u8], o: usize) -> Option<u32> {
        d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as u32)
    }
    fn u32_at(d: &[u8], o: usize) -> Option<u32> {
        d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    impl<'a> Pe<'a> {
        fn section(&self, rva: u64) -> Option<&Section> {
            self.sections.iter().find(|s| {
                let mut size = if (self.data.len() as u64).saturating_sub(s.raw_ptr) < s.raw_size { s.vsize } else { s.raw_size.max(s.vsize) };
                if let Some(n) = s.next_va {
                    if n > s.va && s.va + size > n {
                        size = n - s.va;
                    }
                }
                s.va <= rva && rva < s.va + size
            })
        }
        /// pefile `get_data(rva, length)` (None = PEFormatError).
        fn get_data(&self, rva: u64, len: u64) -> Option<&'a [u8]> {
            let n = self.data.len() as u64;
            match self.section(rva) {
                Some(s) => {
                    let off = rva - s.va + s.raw_ptr;
                    let end = (off + len).min(s.raw_ptr + s.raw_size).min(n);
                    Some(if off >= end { &[] } else { &self.data[off as usize..end as usize] })
                }
                None if rva < n => Some(&self.data[rva as usize..(rva + len).min(n) as usize]),
                None => None,
            }
        }
        fn offset_from_rva(&self, rva: u64) -> Option<u64> {
            match self.section(rva) {
                Some(s) => Some(rva - s.va + s.raw_ptr),
                None if rva < self.data.len() as u64 => Some(rva),
                None => None,
            }
        }

        /// `parse_resources_directory`
        fn parse_dir(&mut self, rva: u64, base_rva: u64, level: u32, dirs: &mut Vec<u64>) -> Option<Vec<Entry>> {
            if level > MAX_RESOURCE_DEPTH {
                return None;
            }
            let d = self.get_data(rva, 16)?;
            if d.len() < 16 {
                return None;
            }
            let n = u16_at(d, 12)? + u16_at(d, 14)?;
            if n > MAX_ALLOWED_ENTRIES {
                return None;
            }
            self.total_entries += n;
            if self.total_entries > MAX_RESOURCE_ENTRIES {
                return None;
            }
            let mut rva = rva + 16;
            let mut entries: Vec<Entry> = Vec::new();
            let mut last_name: Option<(u64, u64)> = None;
            for _ in 0..n {
                let Some(e) = self.get_data(rva, 8).filter(|e| e.len() >= 8) else { break };
                let (name, off) = (u32_at(e, 0)?, u32_at(e, 4)?);
                if name & 0x8000_0000 != 0 {
                    let ustr = base_rva + (name & 0x7FFF_FFFF) as u64;
                    let len = self.get_data(ustr, 2).filter(|b| b.len() >= 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as u64).unwrap_or(0);
                    if let Some((b, e)) = last_name {
                        if b < ustr && e >= ustr {
                            break;
                        }
                    }
                    last_name = Some((ustr, ustr + len));
                }
                let target = base_rva + (off & 0x7FFF_FFFF) as u64;
                let entry = if off & 0x8000_0000 != 0 {
                    if dirs.contains(&target) {
                        break;
                    }
                    dirs.push(target);
                    let sub = self.parse_dir(target, base_rva, level + 1, dirs);
                    dirs.pop();
                    let Some(sub) = sub else { break };
                    Entry { id: name & 0xFFFF, dir: Some(sub), data: None }
                } else {
                    let Some(de) = self.get_data(target, 16).filter(|b| b.len() >= 16) else { break };
                    Entry { id: name & 0xFFFF, dir: None, data: Some((u32_at(de, 0)?, u32_at(de, 4)?)) }
                };
                let is_version = level == 0 && entry.id == RT_VERSION;
                entries.push(entry);
                if is_version {
                    let langs: Vec<(u32, u32)> = entries
                        .last()
                        .and_then(|e| e.dir.as_ref())
                        .and_then(|d| d.first())
                        .and_then(|e| e.dir.as_ref())
                        .map(|d| d.iter().filter_map(|l| l.data).collect())
                        .unwrap_or_default();
                    for (data_rva, size) in langs {
                        self.parse_version_information(data_rva as u64, size as u64);
                    }
                }
                rva += 8;
            }
            Some(entries)
        }

        /// `parse_version_information` up to `VS_FIXEDFILEINFO`.
        fn parse_version_information(&mut self, rva: u64, size: u64) {
            let Some(start) = self.offset_from_rva(rva) else { return };
            let n = self.data.len() as u64;
            let raw = &self.data[start.min(n) as usize..(start + size).min(n) as usize];
            if raw.len() < 6 {
                return;
            }
            let ustr = rva + 6;
            let section_end = self.section(ustr).map(|s| s.va + s.raw_size.max(s.vsize));
            let max_chars = match section_end {
                Some(e) => e.saturating_sub(ustr) >> 1,
                None => 1 << 16,
            };
            if max_chars == 0 {
                return;
            }
            let Some(first) = self.get_data(ustr, 2) else { return };
            let _ = first;
            let Some(bytes) = self.get_data(ustr, max_chars * 2) else { return };
            let mut name = Vec::new();
            for c in bytes.chunks_exact(2) {
                let u = u16::from_le_bytes([c[0], c[1]]);
                if u == 0 {
                    break;
                }
                name.push(u);
            }
            if String::from_utf16_lossy(&name) != "VS_VERSION_INFO" || name.len() != 15 {
                return;
            }
            // dword_align(6 + 2 * (15 + 1), OffsetToData)
            let fixed_off = (((6 + 32 + rva + 3) & 0xFFFF_FFFC) - (rva & 0xFFFF_FFFC)) as usize;
            let Some(f) = raw.get(fixed_off..fixed_off + 52) else { return };
            self.fixed.push((u32_at(f, 16).unwrap_or(0), u32_at(f, 20).unwrap_or(0)));
        }
    }

    /// `(ProductVersionMS, ProductVersionLS)` of the first `VS_FIXEDFILEINFO`, if any.
    pub fn first_fixed_file_info(data: &[u8]) -> Option<(u32, u32)> {
        let lfanew = u32_at(data, 0x3c)? as usize;
        let nt = lfanew;
        if u32_at(data, nt)? != 0x4550 {
            return None;
        }
        let nsec = u16_at(data, nt + 6)? as usize;
        let opt_size = u16_at(data, nt + 20)? as usize;
        let opt = nt + 24;
        let magic = u16_at(data, opt)?;
        let (nrva_off, dd_off) = match magic {
            0x20b => (108, 112),
            0x10b => (92, 96),
            _ => return None,
        };
        let nrva = u32_at(data, opt + nrva_off)?.min(0x10);
        if nrva <= 2 {
            return None;
        }
        let res_rva = u32_at(data, opt + dd_off + 16)? as u64;
        if res_rva == 0 {
            return None;
        }
        let mut sections = Vec::new();
        let sec0 = opt + opt_size;
        for i in 0..nsec {
            let s = sec0 + i * 40;
            let Some(h) = data.get(s..s + 40) else { break };
            sections.push(Section {
                vsize: u32_at(h, 8)? as u64,
                va: u32_at(h, 12)? as u64,
                raw_size: u32_at(h, 16)? as u64,
                raw_ptr: u32_at(h, 20)? as u64,
                next_va: None,
            });
        }
        for i in 0..sections.len() {
            sections[i].next_va = sections.get(i + 1).map(|s| s.va);
        }
        let mut pe = Pe { data, sections, total_entries: 0, fixed: Vec::new() };
        let mut dirs = vec![res_rva];
        pe.parse_dir(res_rva, res_rva, 0, &mut dirs);
        pe.fixed.first().copied()
    }
}

// ------------------------------------------------------------------------------------------
// plugin
// ------------------------------------------------------------------------------------------

/// A property value (python's `console_property["data"]`).
#[derive(Clone, Debug)]
pub enum Data {
    Str(String),
    Int(i128),
    None,
}

impl Data {
    fn opt(s: Option<String>) -> Data {
        s.map(Data::Str).unwrap_or(Data::None)
    }
    /// consoles: `str(data) if data else NotAvailableValue()`.
    pub fn consoles_value(self) -> Value {
        match self {
            Data::Str(s) if !s.is_empty() => Value::Str(s),
            Data::Int(i) if i != 0 => Value::Str(i.to_string()),
            _ => Value::NotAvailable,
        }
    }
    /// cmdscan: `str(data)`.
    pub fn cmdscan_value(self) -> Value {
        match self {
            Data::Str(s) => Value::Str(s),
            Data::Int(i) => Value::Str(i.to_string()),
            Data::None => Value::SStr("None"),
        }
    }
}

/// One row of a console/history structure (python's property dicts).
#[derive(Clone, Debug)]
pub struct Prop {
    pub level: usize,
    pub name: String,
    pub address: Option<u64>,
    pub data: Data,
}

/// python `hex(v)`.
pub fn py_hex(v: i128) -> String {
    if v < 0 { format!("-{:#x}", v.unsigned_abs()) } else { format!("{v:#x}") }
}

/// What one conhost process produced: the found structures (address, properties) in python
/// order, a trailing `Err` where python raised, and the last scanned candidate (python's
/// `console_info` / `command_history` after the loop).
pub struct ProcResult {
    pub found: Vec<Result<(u64, Vec<Prop>)>>,
    pub last_candidate: Option<u64>,
}

/// The properties python collects for a `_CONSOLE_INFORMATION` candidate. `Ok(None)` = not
/// valid for any `max_buffers` value; `Err` = python's exception (PagedInvalidAddress ->
/// candidate skipped, anything else propagates).
fn console_properties(ci: &Obj, max_buffers: &[SetElem]) -> Result<Option<Vec<Prop>>> {
    let mut valid = false;
    for mb in max_buffers {
        valid |= match mb {
            SetElem::Int(v) => ci.console_info_is_valid(*v)?,
            SetElem::Bytes(_) => {
                let c = ci.m("HistoryBufferCount")?.int()?;
                if c < 1 {
                    false
                } else {
                    return Err(py_exception("TypeError: '>' not supported between instances of 'int' and 'bytes'"));
                }
            }
        };
    }
    if !valid {
        return Ok(None);
    }
    let mut p: Vec<Prop> = Vec::with_capacity(64);
    let push = |p: &mut Vec<Prop>, level: usize, name: String, address: Option<u64>, data: Data| p.push(Prop { level, name, address, data });
    const CI: &str = "_CONSOLE_INFORMATION";
    push(&mut p, 0, CI.into(), Some(ci.addr), Data::Str(String::new()));
    for m in ["ScreenX", "ScreenY", "CommandHistorySize", "HistoryBufferCount", "HistoryBufferMax"] {
        let o = ci.m(m)?;
        let v = o.int()?;
        push(&mut p, 1, format!("{CI}.{m}"), Some(o.addr), Data::Int(v));
    }
    let title = ci.m("Title")?;
    title.u64()?;
    push(&mut p, 1, format!("{CI}.Title"), Some(title.addr), Data::Str(ci.get_title()));
    let otitle = ci.m("OriginalTitle")?;
    otitle.u64()?;
    push(&mut p, 1, format!("{CI}.OriginalTitle"), Some(otitle.addr), Data::Str(ci.get_original_title()));

    // debug f-string reads ConsoleProcessList first
    let cpl = ci.m("ConsoleProcessList")?;
    if cpl.is_pointer() {
        cpl.u64()?;
    }
    let pc = ci.m("ProcessCount")?;
    let pcv = pc.int()?;
    push(&mut p, 1, format!("{CI}.ProcessCount"), Some(pc.addr), Data::Int(pcv));
    push(&mut p, 1, format!("{CI}.ConsoleProcessList"), Some(cpl.addr), Data::Str(String::new()));
    for (index, attached) in ci.get_processes()?.enumerate() {
        let attached = attached?;
        let cp = attached.m("ConsoleProcess")?;
        let target = cp.deref()?;
        push(&mut p, 2, format!("{CI}.ConsoleProcessList.ConsoleProcess_{index}"), Some(target.addr), Data::Str(String::new()));
        let pid = target.m("ProcessId")?;
        let pidv = pid.int()?;
        push(&mut p, 2, format!("{CI}.ConsoleProcessList.ConsoleProcess_{index}_ProcessId"), Some(pid.addr), Data::Int(pidv));
        let ph = target.m("ProcessHandle")?;
        let phv = ph.int()?;
        push(&mut p, 2, format!("{CI}.ConsoleProcessList.ConsoleProcess_{index}_ProcessHandle"), Some(ph.addr), Data::Str(py_hex(phv)));
    }

    // debug f-string reads ExeAliasList
    let eal = ci.m("ExeAliasList")?;
    let eal_true = if eal.is_pointer() { eal.u64()? != 0 } else { true };
    push(&mut p, 1, format!("{CI}.ExeAliasList"), Some(eal.addr), Data::Str(String::new()));
    if eal_true {
        for (index, exe_alias_list) in ci.get_exe_aliases()?.enumerate() {
            let exe_alias_list = exe_alias_list?;
            let _ = (|| -> Result<()> {
                push(&mut p, 2, format!("{CI}.ExeAliasList.AliasList_{index}"), Some(exe_alias_list.addr), Data::Str(String::new()));
                let exe_name = exe_alias_list.m("ExeName")?;
                if exe_name.is_pointer() {
                    exe_name.u64()?;
                }
                let name = exe_alias_list.get_exename()?;
                push(&mut p, 2, format!("{CI}.ExeAliasList.AliasList_{index}.ExeName"), Some(exe_name.addr), Data::opt(name));
                for (alias_index, alias) in exe_alias_list.get_aliases()?.enumerate() {
                    let alias = alias?;
                    let src = alias.m("Source")?;
                    let s = alias.get_source()?;
                    push(&mut p, 3, format!("{CI}.ExeAliasList.AliasList_{index}.Alias_{alias_index}.Source"), Some(src.addr), Data::opt(s));
                    let tgt = alias.m("Target")?;
                    let t = alias.get_target()?;
                    push(&mut p, 3, format!("{CI}.ExeAliasList.AliasList_{index}.Alias_{alias_index}.Target"), Some(tgt.addr), Data::opt(t));
                }
                Ok(())
            })();
        }
    }

    // debug f-string reads HistoryList
    let hl = ci.m("HistoryList")?;
    if hl.is_pointer() {
        hl.u64()?;
    }
    push(&mut p, 1, format!("{CI}.HistoryList"), Some(hl.addr), Data::Str(String::new()));
    for (index, history) in ci.get_histories()?.enumerate() {
        let history = history?;
        let _ = (|| -> Result<()> {
            let h = format!("{CI}.HistoryList.CommandHistory_{index}");
            push(&mut p, 2, h.clone(), Some(history.addr), Data::Str(String::new()));
            let app = history.m("Application")?;
            let a = history.get_application()?;
            push(&mut p, 2, format!("{h}_Application"), Some(app.addr), Data::opt(a));
            let ph = history.m("ConsoleProcessHandle")?.m("ProcessHandle")?;
            let phv = ph.int()?;
            push(&mut p, 2, format!("{h}_ProcessHandle"), Some(ph.addr), Data::Str(py_hex(phv)));
            push(&mut p, 2, format!("{h}_CommandCount"), None, Data::Int(history.command_count()?));
            let ld = history.m("LastDisplayed")?;
            let ldv = ld.int()?;
            push(&mut p, 2, format!("{h}_LastDisplayed"), Some(ld.addr), Data::Int(ldv));
            for c in history.get_commands()? {
                let (cmd_index, cmd) = c?;
                if let Ok(s) = cmd.get_command_string() {
                    push(&mut p, 3, format!("{h}_Command_{cmd_index}"), Some(cmd.addr), Data::opt(s));
                }
            }
            Ok(())
        })();
    }

    let _ = (|| -> Result<()> {
        let csb = ci.m("CurrentScreenBuffer")?;
        csb.u64()?;
        push(&mut p, 1, format!("{CI}.CurrentScreenBuffer"), Some(csb.addr), Data::Str(String::new()));
        for (screen_index, screen) in ci.get_screens().into_iter().enumerate() {
            let screen: Screen = screen?;
            let _ = (|| -> Result<()> {
                push(&mut p, 2, format!("{CI}.ScreenBuffer_{screen_index}"), Some(screen.ptr.u64()?), Data::Str(String::new()));
                push(&mut p, 2, format!("{CI}.ScreenBuffer_{screen_index}.ScreenX"), None, Data::Int(screen.screen_x()?));
                push(&mut p, 2, format!("{CI}.ScreenBuffer_{screen_index}.ScreenY"), None, Data::Int(screen.screen_y()?));
                let dump = screen.get_buffer(true, true)?.join("\n");
                push(&mut p, 2, format!("{CI}.ScreenBuffer_{screen_index}.Dump"), None, Data::Str(dump));
                Ok(())
            })();
        }
        Ok(())
    })();
    Ok(Some(p))
}

/// python `Consoles.get_console_info` for one conhost process (after its conhost.exe VAD and
/// the symbol table are known).
fn console_info_for(c: &ConhostProc, table: TableRef, base: u64, size: i128, max_history: &[SetElem], max_buffers: &[SetElem]) -> ProcResult {
    let mut res = ProcResult { found: Vec::new(), last_candidate: None };
    let sp = Space::on(c.layer, table);
    let r = (|| -> Result<()> {
        let ci_ty = table.get_type("_CONSOLE_INFORMATION")?;
        let chs = table.offset_of("_CONSOLE_INFORMATION", "CommandHistorySize")?;
        for v in max_history {
            let needle = pack_h(v)?;
            let hits = if size > 0 { scan(c.layer, &BytesScanner::new(&needle), Some(&[(base, size as u64)])) } else { Vec::new() };
            for address in hits {
                let ci = Obj::new(sp, ci_ty, address.wrapping_sub(chs));
                res.last_candidate = Some(ci.addr);
                match console_properties(&ci, max_buffers) {
                    Ok(Some(props)) => res.found.push(Ok((ci.addr, props))),
                    Ok(None) => {}
                    Err(e) if e.is_invalid_address() => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    })();
    if let Err(e) = r {
        res.found.push(Err(e));
    }
    res
}

/// Emit a process's rows (python `_generator`): the found structures' properties, or (none
/// found) one "not found" row whose ConsoleInfo is `not_found_addr` (python's leftover
/// candidate variable, N/A when None).
pub fn emit_rows(
    out: &mut dyn RowSink,
    proc: &Obj,
    found: Vec<Result<(u64, Vec<Prop>)>>,
    not_found_addr: Option<u64>,
    top: &str,
    not_found: &str,
    value: fn(Data) -> Value,
) -> Result<()> {
    let pid = proc.m("UniqueProcessId")?.int()?;
    let name = array_to_string(&proc.m("ImageFileName")?, None)?;
    let mut any = false;
    for f in found {
        let (addr, props) = f.map_err(raise)?;
        any = true;
        for p in props {
            out.row(
                p.level,
                vec![
                    Value::Int(pid),
                    Value::Str(name.clone()),
                    Value::Int(addr as i128),
                    Value::Str(p.name),
                    p.address.map(|a| Value::Int(a as i128)).unwrap_or(Value::NotApplicable),
                    value(p.data),
                ],
            )?;
        }
    }
    if !any {
        out.row(
            0,
            vec![
                Value::Int(pid),
                Value::Str(name),
                not_found_addr.map(|a| Value::Int(a as i128)).unwrap_or(Value::NotApplicable),
                Value::Str(top.into()),
                Value::NotApplicable,
                Value::Str(not_found.into()),
            ],
        )?;
    }
    Ok(())
}

/// The column layout shared by consoles and cmdscan.
pub fn columns() -> Vec<Column> {
    vec![
        Column::new("PID", ColType::Int),
        Column::new("Process", ColType::Str),
        Column::new("ConsoleInfo", ColType::Hex),
        Column::new("Property", ColType::Str),
        Column::new("Address", ColType::Hex),
        Column::new("Data", ColType::Str),
    ]
}

/// The conhost processes with their conhost.exe VAD, and the conhost symbol table built from
/// the first one that has it (python creates it lazily at that process). The outer `Err` is a
/// failure before any process; per-process `Err`s are where python raised.
pub struct Conhosts {
    pub procs: Vec<Result<(ConhostProc, Option<(u64, i128)>)>>,
    pub table: Option<Result<TableRef>>,
}

/// python `find_conhost_proc` + `find_conhostexe` for every process (in parallel; they are
/// independent) and `create_conhost_symbol_table` for the first one with a conhost.exe base.
pub fn conhosts(ctx: &Context, k: &WinKernel, case_insensitive: bool) -> Conhosts {
    let _t = crate::util::trace::span("consoles: conhost processes + symbol table");
    let found = find_conhost_procs(k, case_insensitive);
    let exes: Vec<Option<Result<Option<(u64, i128)>>>> = crate::util::par::par_map(found.len(), |i| match &found[i] {
        Ok(c) => Some(find_conhostexe(&c.proc)),
        Err(_) => None,
    });
    let mut procs = Vec::with_capacity(found.len());
    let mut table = None;
    for (f, e) in found.into_iter().zip(exes) {
        let c = match f {
            Ok(c) => c,
            Err(e) => {
                procs.push(Err(e));
                break;
            }
        };
        match e {
            Some(Ok(exe)) => {
                let exe = exe.filter(|(b, _)| *b != 0);
                if let (Some((base, _)), None) = (exe, &table) {
                    let t = create_conhost_symbol_table(ctx, k, c.layer, base);
                    let failed = t.is_err();
                    table = Some(t);
                    procs.push(Ok((c, exe)));
                    if failed {
                        break;
                    }
                    continue;
                }
                procs.push(Ok((c, exe)));
            }
            Some(Err(e)) => {
                procs.push(Err(e));
                break;
            }
            None => {}
        }
    }
    Conhosts { procs, table }
}

impl Plugin for Consoles {
    fn name(&self) -> &'static str {
        "windows.consoles.Consoles"
    }
    fn description(&self) -> &'static str {
        "Looks for Windows console buffers"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::flag("no_registry", "Don't search the registry for possible values of CommandHistorySize and HistoryBufferMax"),
            Requirement::new("max_history", "CommandHistorySize values to search for.", ReqKind::ListInt)
                .optional()
                .default(ConfigValue::List(vec![ConfigValue::Int(50)])),
            Requirement::new("max_buffers", "HistoryBufferMax values to search for.", ReqKind::ListInt)
                .optional()
                .default(ConfigValue::List(vec![ConfigValue::Int(4)])),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(columns())?;
        let k = ctx.windows_kernel()?;
        let mut max_history = PySet::from_ints(&config_ints(cfg, "max_history", 50));
        let mut max_buffers = PySet::from_ints(&config_ints(cfg, "max_buffers", 4));
        if !cfg.get_bool("no_registry") {
            get_console_settings_from_registry(ctx, k, &mut max_history, Some(&mut max_buffers))?;
        }
        let (max_history, max_buffers) = (max_history.elems(), max_buffers.elems());
        let ch = conhosts(ctx, k, true);
        let table = match &ch.table {
            Some(Ok(t)) => Some(*t),
            _ => None,
        };
        // per process work in parallel, rows in python order
        let _t = crate::util::trace::span("consoles: console info");
        let results: Vec<Option<ProcResult>> = crate::util::par::par_map(ch.procs.len(), |i| match (&ch.procs[i], table) {
            (Ok((c, Some((base, size)))), Some(t)) => Some(console_info_for(c, t, *base, *size, &max_history, &max_buffers)),
            _ => None,
        });
        let mut table_err = match ch.table {
            Some(Err(e)) => Some(e),
            _ => None,
        };
        for (p, r) in ch.procs.into_iter().zip(results) {
            let (c, exe) = p.map_err(raise)?;
            if exe.is_none() {
                continue;
            }
            if let Some(e) = table_err.take() {
                return Err(raise(e));
            }
            if let Some(r) = r {
                emit_rows(out, &c.proc, r.found, r.last_candidate, "_CONSOLE_INFORMATION", "Console Information Not Found", Data::consoles_value)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(v: &[i128]) -> Vec<i128> {
        PySet::from_ints(v).elems().into_iter().map(|e| if let SetElem::Int(i) = e { i } else { 0 }).collect()
    }

    /// Expected orders produced by CPython 3.14 (`list(set(values))`).
    #[test]
    fn cpython_set_order() {
        assert_eq!(order(&[50]), vec![50]);
        assert_eq!(order(&[50, 25, 8, 9, 1000, 17]), vec![8, 9, 1000, 17, 50, 25]);
        assert_eq!(order(&(1..=40).rev().step_by(3).collect::<Vec<_>>()), vec![1, 34, 4, 37, 7, 40, 10, 13, 16, 19, 22, 25, 28, 31]);
        assert_eq!(order(&[-1, -2, 5, 1 << 40, 1 << 62]), vec![1 << 40, 1 << 62, 5, -2, -1]);
        assert_eq!(order(&[50, 50, 4]), vec![50, 4]);
    }

    /// Random lists (ints in [0, 70000], and mixes of negatives, u32 values, multiples of 8 and
    /// values around 2**61 - 1) with the order `list(set(values))` has in CPython 3.14.
    #[test]
    fn cpython_set_order_random() {
        let cases: &[(&[i128], &[i128])] = &[
        (&[42445, 19772], &[19772, 42445]),
        (&[1, 0], &[0, 1]),
        (&[11265, 56838, 54810], &[11265, 54810, 56838]),
        (&[-4, -2, 3687093963], &[3687093963, -4, -2]),
        (&[15439, 40433, 23688, 13507, 24624], &[13507, 23688, 15439, 24624, 40433]),
        (&[3058492450, 464, 248, 2305843009213693948, 2305843009213693951], &[2305843009213693951, 3058492450, 464, 248, 2305843009213693948]),
        (&[5138, 10173, 41123, 44580, 45898, 65100], &[41123, 44580, 45898, 65100, 5138, 10173]),
        (&[4, 56, 392, -5, 253207296, 2305843009213693949], &[253207296, 4, 392, 56, -5, 2305843009213693949]),
        (&[52644, 36416, 17947, 56429, 36493, 54433, 47024], &[36416, 54433, 52644, 56429, 36493, 47024, 17947]),
        (&[5, 2305843009213693948, 783156687, 1, 2, 2, -2], &[1, 2, 5, 783156687, 2305843009213693948, -2]),
        (&[13419, 30, 19826, 13299, 47659, 3342, 9216, 27256, 49313], &[9216, 49313, 47659, 13419, 3342, 19826, 13299, 27256, 30]),
        (&[352, 2305843009213693951, 144, 16, -3, 2226497560, 2159067275, 2305843009213693949, 24], &[352, 2305843009213693951, 2159067275, 144, 16, 2305843009213693949, 2226497560, 24, -3]),
        (&[61897, 33970, 25381, 45125, 58619, 45812, 47793, 10556, 28896, 13389, 29733, 61614], &[28896, 45125, 25381, 29733, 61897, 13389, 61614, 47793, 33970, 45812, 58619, 10556]),
        (&[-2, 2762235647, 440, -4, 2305843009213693952, 4210381974, 2790331461, 120232146, 1400113410, -5, 3335068562, -3], &[2305843009213693952, 1400113410, 2790331461, 120232146, 3335068562, 4210381974, 440, -5, -4, -3, -2, 2762235647]),
        (&[42727, 67941, 69563, 63240, 13907, 7447, 32570, 25074, 36296, 5531, 12811, 66547, 59267, 3652, 8305, 58097, 42678, 66263, 67130, 26136], &[59267, 63240, 12811, 7447, 26136, 5531, 42678, 67130, 32570, 69563, 3652, 36296, 13907, 66263, 67941, 42727, 8305, 25074, 66547, 58097]),
        (&[4043716558, 2305843009213693951, 72, 2835780143, 4090974082, 2305843009213693953, 424, 2305843009213693952, 392, 4126495981, 361040387, 432, 328, -5, 224, 2305843009213693952, 2670196012, 4162737373, 4003969892, -1], &[2305843009213693951, 2305843009213693952, 4090974082, 2305843009213693953, 361040387, 392, 424, 2670196012, 2835780143, 432, 72, 328, 4043716558, 4162737373, 224, 4003969892, 4126495981, -5, -1]),
        (&[32826, 4843, 2011, 2416, 66277, 24832, 67401, 62227, 32201, 58596, 13930, 56646, 64880, 51522, 66412, 40341, 28204, 30089, 44918, 26034, 18313, 53044, 45554, 7128, 17015, 1868, 9269, 33501, 56458, 21397, 7261, 11073, 49922], &[24832, 49922, 30089, 18313, 56458, 62227, 40341, 21397, 28204, 26034, 53044, 9269, 32826, 11073, 51522, 56646, 67401, 32201, 1868, 7128, 2011, 33501, 7261, 58596, 66277, 13930, 4843, 66412, 2416, 64880, 45554, 44918, 17015]),
        (&[1258676654, 264, 1389567515, 0, 2, -4, 96611647, 392, 2305843009213693948, 3, -5, 2305843009213693948, 2305843009213693953, 3475568222, 2305843009213693954, 2936454391, 336, 4, 2305843009213693953, -1, 3, 512, 88, 112, 3763015118, 456, -3, 2305843009213693954, -4, 432, 48, 2305843009213693950, 2305843009213693954], &[0, 512, 2, 3, 2305843009213693953, 2305843009213693954, 4, 264, 392, 1389567515, 1258676654, 432, 48, 96611647, 456, 3763015118, 336, 88, 3475568222, -4, 112, 2305843009213693950, 2936454391, -5, 2305843009213693948, -3, -1]),
        (&[3802, 52434, 26664, 10561, 6484, 53855, 59095, 18162, 37513, 63645, 6419, 16686, 22382, 61890, 54377, 45044, 36929, 39029, 33520, 34100, 53242, 31282, 39431, 63331, 51690, 15694, 21932, 21188, 9852, 27246, 65615, 65152, 28839, 59373, 43625, 58977, 56023, 18297, 25219, 31992, 11890, 22897, 44820, 11939, 41849, 31342, 48274, 33863, 26495, 2632], &[65152, 25219, 41849, 39431, 37513, 48274, 6419, 44820, 63645, 11939, 28839, 26664, 21932, 16686, 31282, 34100, 10561, 61890, 36929, 21188, 33863, 2632, 15694, 65615, 52434, 6484, 59095, 56023, 3802, 53855, 58977, 63331, 54377, 51690, 43625, 59373, 22382, 27246, 33520, 22897, 18162, 11890, 45044, 39029, 31342, 31992, 18297, 53242, 9852, 26495]),
        (&[208, 504, 3644847894, 1, 2305843009213693952, 314124801, -4, 5, -5, 128, 3, 2503497687, 304, 3795780556, 416, 2305843009213693953, 1104906638, 2, 2168436173, 472, 2305843009213693949, 2554655862, -5, -3, 4001172194, 2305843009213693950, 0, 2305843009213693950, 384, 480, 192, 2305843009213693948, 1993082227, -4, -1, 4051228543, 392, 3499540438, 3171781886, 0, 2305843009213693949, 488, 104, 2305843009213693951, 2305843009213693951, 296, 256, 1887199037, 64, -2], &[128, 2305843009213693952, 1, 314124801, 3, 5, 2305843009213693953, 2, 0, 384, 392, 2305843009213693951, 256, 1104906638, 3644847894, 416, 296, 304, 1887199037, 192, 64, 3795780556, 2168436173, 208, 3499540438, 2503497687, 472, 3171781886, 480, 4001172194, 488, 104, 2305843009213693948, -3, 1993082227, 2554655862, -1, 504, -2, -5, -4, 2305843009213693949, 2305843009213693950, 4051228543]),
        (&[588, 62228, 30292, 58759, 49004, 5290, 38492, 30525, 15625, 6604, 24847, 25449, 9845, 48789, 67196, 23299, 58866, 34071, 830, 13864, 45835, 28527, 4909, 48327, 44566, 18529, 5788, 26735, 33412, 5011, 26665, 1491, 42893, 53607, 48733, 24267, 40920, 10215, 26661, 4124, 64962, 63374, 8293, 53499, 13289, 51812, 20257, 69992, 11947, 21455, 52136, 35542, 53711, 37132, 40317, 54767, 6731, 40941, 46816, 54274, 54584, 2387, 47681, 25847, 51213, 53080, 26695, 770, 56906, 20521], &[54274, 23299, 33412, 770, 58759, 15625, 45835, 37132, 42893, 63374, 24847, 51213, 5011, 62228, 48789, 44566, 34071, 5788, 4124, 20257, 26661, 13864, 26665, 5290, 11947, 52136, 4909, 20521, 54584, 30525, 830, 47681, 64962, 48327, 26695, 56906, 24267, 588, 6604, 6731, 21455, 53711, 1491, 30292, 2387, 35542, 40920, 53080, 38492, 48733, 46816, 18529, 51812, 8293, 53607, 10215, 25449, 13289, 69992, 49004, 40941, 28527, 26735, 54767, 58866, 9845, 25847, 53499, 67196, 40317]),
        (&[388643082, 2305843009213693953, 3982412036, 0, 1, 1350878783, 3635051491, -5, -3, 2305843009213693951, 3341854667, 1578185763, 2305843009213693949, 2032459486, 2305843009213693954, 128, 343459769, 3681088117, 224, 160, 616638316, 4, 160, 5, 5, 264, 4, 48, 2305843009213693950, 2305843009213693949, 48, 963184921, -2, -2, 5, 2305843009213693952, -2, 1, 2305843009213693949, 4, 2305843009213693953, 224, 120, -5, 160, 3780279012, 1, 1, 4, -4, -5, 2305843009213693954, -4, 2715532681, 296, 352, -5, 2305843009213693950, -5, 48, 184, 4053890304, -2, 2, 1, 885264835, 1, 2305843009213693954, 472, 992242503], &[0, 1, 2305843009213693953, 2305843009213693951, 3982412036, 2305843009213693954, 128, 4, 5, 264, 388643082, 2305843009213693952, 2715532681, 2, 963184921, 160, 1578185763, 296, 4053890304, 48, 184, 343459769, 1350878783, 885264835, 992242503, 3341854667, 472, 2032459486, 224, 352, 3635051491, 3780279012, 616638316, -3, 3681088117, -2, 120, -5, -4, 2305843009213693949, 2305843009213693950]),
        ];
        for (values, expected) in cases {
            assert_eq!(&order(values)[..], *expected, "set({values:?})");
        }
    }

    #[test]
    fn hash_and_pack() {
        assert_eq!(py_hash_int(-1), -2);
        assert_eq!(py_hash_int((1 << 61) - 1), 0);
        assert_eq!(py_hash_int(-((1 << 61) + 5)), -6);
        assert_eq!(pack_h(&SetElem::Int(50)).unwrap(), [50, 0]);
        assert!(pack_h(&SetElem::Int(65536)).is_err());
        assert!(pack_h(&SetElem::Int(-1)).is_err());
        assert_eq!(py_hex(0x90), "0x90");
        assert_eq!(py_hex(-5), "-0x5");
    }
}
