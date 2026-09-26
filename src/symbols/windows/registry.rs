//! python `symbols/windows/extensions/registry.py`: `CMHIVE`, `CM_KEY_NODE`, `CM_KEY_VALUE`
//! (subkey lists, value lists, big data, value decoding) as the [`RegExt`] trait on [`Obj`].
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Objects must live on a [`RegistryHive`] layer (python raises `TypeError` otherwise; here an
//! `Error::Msg("TypeError: ...")`). Hive enumeration / key lookup:
//!
//! ```ignore
//! use crate::plugins::windows::registry::hivelist::list_hives;
//! use crate::symbols::windows::registry::RegExt;
//! for hive in list_hives(k, None, None) {
//!     let hive = hive?;                                   // trailing Err = python raised
//!     let path = hive.get_key("ControlSet001\\Services")?;   // Vec of nodes root..key (KeyError: is_key_error)
//!     for sub in path.last().unwrap().get_subkeys() { let sub = sub?; let n = sub.get_name()?; }
//!     for v in node.get_values() { let data = v.decode_data()?; }
//! }
//! ```
//!
//! Error classes (python exception -> rust):
//! * `InvalidAddressException` -> `e.is_invalid_address()`
//! * `RegistryException` -> [`is_registry_exception`] (`Error::Layer("Registry...")`)
//! * `KeyError` from `get_key` -> [`is_key_error`]
//! * `ValueError` from `decode_data` -> [`is_value_error`]

use crate::error::{Error, Result};
use crate::layers::registry::RegistryHive;
pub use crate::layers::registry::{hive_of, is_invalid_or_registry, is_registry_exception};
use crate::layers::{Layer, LayerExt};
use crate::objects::Obj;
use crate::renderers::Value;
use crate::symbols::windows::WinExt;
use crate::symbols::{StrEnc, StrErrors};

/// python `BIG_DATA_MAXLEN`.
pub const BIG_DATA_MAXLEN: u64 = 0x3FD8;

/// python `RegValueTypes`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegValueType {
    None,
    Sz,
    ExpandSz,
    Binary,
    Dword,
    DwordBigEndian,
    Link,
    MultiSz,
    ResourceList,
    FullResourceDescriptor,
    ResourceRequirementsList,
    Qword,
    Unknown,
}

impl RegValueType {
    /// python `RegValueTypes(value)` (unknown values -> `REG_UNKNOWN`).
    pub fn from_int(v: i128) -> RegValueType {
        use RegValueType::*;
        match v {
            0 => None,
            1 => Sz,
            2 => ExpandSz,
            3 => Binary,
            4 => Dword,
            5 => DwordBigEndian,
            6 => Link,
            7 => MultiSz,
            8 => ResourceList,
            9 => FullResourceDescriptor,
            10 => ResourceRequirementsList,
            11 => Qword,
            _ => Unknown,
        }
    }
    /// python `RegValueTypes(x).name`.
    pub fn name(self) -> &'static str {
        use RegValueType::*;
        match self {
            None => "REG_NONE",
            Sz => "REG_SZ",
            ExpandSz => "REG_EXPAND_SZ",
            Binary => "REG_BINARY",
            Dword => "REG_DWORD",
            DwordBigEndian => "REG_DWORD_BIG_ENDIAN",
            Link => "REG_LINK",
            MultiSz => "REG_MULTI_SZ",
            ResourceList => "REG_RESOURCE_LIST",
            FullResourceDescriptor => "REG_FULL_RESOURCE_DESCRIPTOR",
            ResourceRequirementsList => "REG_RESOURCE_REQUIREMENTS_LIST",
            Qword => "REG_QWORD",
            Unknown => "REG_UNKNOWN",
        }
    }
}

/// python `RegKeyFlags`.
pub mod key_flags {
    pub const KEY_IS_VOLATILE: u64 = 0x01;
    pub const KEY_HIVE_EXIT: u64 = 0x02;
    pub const KEY_HIVE_ENTRY: u64 = 0x04;
    pub const KEY_NO_DELETE: u64 = 0x08;
    pub const KEY_SYM_LINK: u64 = 0x10;
    pub const KEY_COMP_NAME: u64 = 0x20;
    pub const KEY_PREFEF_HANDLE: u64 = 0x40;
    pub const KEY_VIRT_MIRRORED: u64 = 0x80;
    pub const KEY_VIRT_TARGET: u64 = 0x100;
    pub const KEY_VIRTUAL_STORE: u64 = 0x200;
}

/// The value python's `CM_KEY_VALUE.decode_data()` returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegData {
    Int(u64),
    Bytes(Vec<u8>),
}

impl RegData {
    /// The bytes (python `bytes` result), None for ints.
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            RegData::Bytes(b) => Some(b),
            RegData::Int(_) => None,
        }
    }
}

/// python `KeyError` text marker.
const KEY_ERROR: &str = "KeyError: ";
/// python `ValueError` text marker.
const VALUE_ERROR: &str = "ValueError: ";

/// python `KeyError(msg)`.
pub fn key_error(msg: impl Into<String>) -> Error {
    Error::Msg(format!("{KEY_ERROR}{}", msg.into()))
}
/// True for a python `KeyError` (e.g. `get_key` did not find the key).
pub fn is_key_error(e: &Error) -> bool {
    matches!(e, Error::Msg(s) if s.starts_with(KEY_ERROR))
}
/// python `ValueError(msg)`.
pub fn value_error(msg: impl Into<String>) -> Error {
    Error::Msg(format!("{VALUE_ERROR}{}", msg.into()))
}
/// True for a python `ValueError` (e.g. `decode_data` size mismatch).
pub fn is_value_error(e: &Error) -> bool {
    matches!(e, Error::Msg(s) if s.starts_with(VALUE_ERROR))
}

fn type_error(what: &str) -> Error {
    Error::Msg(format!("TypeError: {what} was not instantiated on a RegistryHive layer"))
}

/// python `CMHIVE.get_name()`: the first non-empty of FileFullPath, FileUserName,
/// HiveRootPath (errors suppressed), else None.
pub fn cmhive_get_name(cmhive: &Obj) -> Option<String> {
    for attr in ["FileFullPath", "FileUserName", "HiveRootPath"] {
        let r = (|| -> Result<Option<String>> {
            let name = cmhive.m(attr)?;
            if name.m("Length")?.int()? > 0 {
                return Ok(Some(name.get_string()?));
            }
            Ok(None)
        })();
        if let Ok(Some(s)) = r {
            return Some(s);
        }
    }
    None
}

/// python `CMHIVE.is_valid()`: `Hive.Signature == 0xBEE0BEE0` (False on invalid addresses).
pub fn cmhive_is_valid(cmhive: &Obj) -> bool {
    match cmhive.m("Hive").and_then(|h| h.m("Signature")).and_then(|s| s.int()) {
        Ok(v) => v == 0xBEE0_BEE0,
        Err(_) => false,
    }
}

/// python `str.casefold()` for registry name comparisons.
pub fn casefold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'A'..='Z' => out.push(c.to_ascii_lowercase()),
            c if c.is_ascii() => out.push(c),
            'ß' | 'ẞ' => out.push_str("ss"),
            'µ' => out.push('μ'),
            'ſ' => out.push('s'),
            c => out.extend(c.to_lowercase()),
        }
    }
    out
}

#[inline]
fn latin1_cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    b[..end].iter().map(|&x| x as char).collect()
}

/// python `layer.read(offset, length)` on a hive with python's error precedence (every page is
/// translated before any data is read) and without allocating before the range is known to
/// translate (garbage lengths fail at the hive's maximum address first).
pub fn hive_read(h: &RegistryHive, addr: u64, len: u64) -> Result<Vec<u8>> {
    if len <= 0x1000 {
        let mut v = vec![0u8; len as usize];
        h.read(addr, &mut v)?;
        return Ok(v);
    }
    // translate everything first (cached), like python's mapping() list
    let mut cur = addr;
    let mut remaining = len;
    let mut chunk = 0x1000 - (addr & 0xfff);
    while remaining > 0 {
        let c = chunk.min(remaining).min(0x1000);
        h.translate_cell(cur)?;
        cur = cur.wrapping_add(c);
        remaining -= c;
        chunk = 0x1000;
    }
    let mut v = vec![0u8; len as usize];
    h.read(addr, &mut v)?;
    Ok(v)
}

/// Registry extensions on [`Obj`] (python `CM_KEY_NODE` / `CM_KEY_VALUE` methods).
pub trait RegExt {
    /// python `CM_KEY_NODE.get_subkeys()`: lazy; yields `Err` once where python raises.
    fn get_subkeys(&self) -> SubkeyIter;
    /// python `CM_KEY_NODE.get_values()`: lazy, never raises (stops on errors like python).
    fn get_values(&self) -> ValueIter;
    /// python `CM_KEY_NODE.get_name()` / `CM_KEY_VALUE.get_name()` (latin-1, cut at NUL).
    fn get_name(&self) -> Result<String>;
    /// python `CM_KEY_NODE.get_key_path()`.
    fn get_key_path(&self) -> Result<String>;
    /// python `CM_KEY_NODE.get_volatile()`.
    fn get_volatile(&self) -> Result<bool>;
    /// python `CM_KEY_VALUE.get_type()`.
    fn get_value_type(&self) -> Result<RegValueType>;
    /// python `CM_KEY_VALUE.decode_data()`.
    fn decode_data(&self) -> Result<RegData>;
    /// python `conversion.wintime_to_datetime(node.LastWriteTime.QuadPart)`.
    fn last_write_time(&self) -> Result<Value>;
    /// True for `_CM_KEY_NODE` objects (python `node.vol.type_name.endswith("!_CM_KEY_NODE")`).
    fn is_key_node(&self) -> bool;
    /// True for `_CM_KEY_VALUE` objects (python `isinstance(node, CM_KEY_VALUE)`).
    fn is_key_value(&self) -> bool;
    /// python `CM_KEY_BODY.get_full_key_name()` on a `_CM_KEY_BODY` (a kernel object, e.g. a
    /// handle's body): `None` where python returns None (a loop in the `ParentKcb` chain, or
    /// more than 128 levels).
    fn get_full_key_name(&self) -> Result<Option<String>>;
}

fn is_named(o: &Obj, name: &str) -> bool {
    o.struct_name() == Some(name)
}

/// (NameLength offset, Name offset) for key nodes / values.
fn name_offsets(o: &Obj) -> Result<(u64, u64)> {
    if let Some(h) = hive_of(o) {
        let t = &h.types;
        if o.ty == t.key_node {
            return Ok((t.kn_name_length, t.kn_name));
        }
        if o.ty == t.key_value {
            return Ok((t.kv_name_length, t.kv_name));
        }
    }
    Ok((o.member_offset("NameLength")?, o.member_offset("Name")?))
}

impl RegExt for Obj {
    fn get_subkeys(&self) -> SubkeyIter {
        match hive_of(self) {
            Some(h) => SubkeyIter { hive: Some(h), node: *self, next_index: 0, stack: Vec::new(), failed: None },
            None => SubkeyIter { hive: None, node: *self, next_index: 2, stack: Vec::new(), failed: Some(type_error("CM_KEY_NODE")) },
        }
    }

    fn get_values(&self) -> ValueIter {
        let Some(h) = hive_of(self) else { return ValueIter { hive: None, list: 0, count: 0, i: 0 } };
        let t = &h.types;
        let mask = self.sp.layer_mask;
        let r = (|| -> Result<(u64, u64)> {
            let list = h.read_u32(self.addr.wrapping_add(t.kn_value_list_list) & mask)? as u64;
            let child = h.get_cell(list);
            let count = h.read_u32(self.addr.wrapping_add(t.kn_value_list_count) & mask)? as u64;
            Ok((child.addr.wrapping_add(t.off_key_list) & mask, count))
        })();
        match r {
            Ok((list, count)) => ValueIter { hive: Some(h), list, count, i: 0 },
            Err(_) => ValueIter { hive: None, list: 0, count: 0, i: 0 },
        }
    }

    fn get_name(&self) -> Result<String> {
        let (lo, no) = name_offsets(self)?;
        let mask = self.sp.layer_mask;
        let layer = self.layer();
        let n = layer.read_u16(self.addr.wrapping_add(lo) & mask)? as u64;
        if n == 0 {
            return Ok(String::new());
        }
        let a = self.addr.wrapping_add(no) & mask;
        let data = match layer.as_registry_hive() {
            Some(h) => hive_read(h, a, n)?,
            None => layer.read_vec(a, n as usize)?,
        };
        Ok(latin1_cstr(&data))
    }

    fn get_key_path(&self) -> Result<String> {
        let reg = hive_of(self).ok_or_else(|| Error::Msg("TypeError: Key was not instantiated on a RegistryHive layer".into()))?;
        let root = reg.root_cell_offset().wrapping_add(4);
        let t = &reg.types;
        // python recurses into the parent first (all Parent reads), then appends names from the
        // top down.
        let mut chain = vec![*self];
        let mut cur = *self;
        while cur.addr != root {
            if chain.len() > 990 {
                return Err(Error::msg("RecursionError: maximum recursion depth exceeded"));
            }
            let parent = reg.read_u32(cur.addr.wrapping_add(t.kn_parent) & cur.sp.layer_mask)? as u64;
            let p = reg.get_node(parent);
            if p.ty != t.key_node {
                return Err(Error::Symbol(format!("AttributeError: '{}' object has no attribute 'get_key_path'", p.type_name())));
            }
            chain.push(p);
            cur = p;
        }
        let mut out = reg.get_name().rsplit('\\').next().unwrap_or("").to_string();
        for n in chain.iter().rev().skip(1) {
            out.push('\\');
            out.push_str(&n.get_name()?);
        }
        Ok(out)
    }

    fn get_volatile(&self) -> Result<bool> {
        if hive_of(self).is_none() {
            return Err(type_error("CM_KEY_NODE"));
        }
        Ok(self.addr & 0x8000_0000 != 0)
    }

    fn get_value_type(&self) -> Result<RegValueType> {
        let off = match hive_of(self) {
            Some(h) if self.ty == h.types.key_value => h.types.kv_type,
            _ => self.member_offset("Type")?,
        };
        Ok(RegValueType::from_int(self.layer().read_u32(self.addr.wrapping_add(off) & self.sp.layer_mask)? as i128))
    }

    fn decode_data(&self) -> Result<RegData> {
        let mask = self.sp.layer_mask;
        let (dl_off, data_off) = match hive_of(self) {
            Some(h) if self.ty == h.types.key_value => (h.types.kv_data_length, h.types.kv_data),
            _ => (self.member_offset("DataLength")?, self.member_offset("Data")?),
        };
        let mut datalen = self.layer().read_u32(self.addr.wrapping_add(dl_off) & mask)? as u64;
        let layer = hive_of(self).ok_or_else(|| type_error("Key value"))?;
        let data_field = self.addr.wrapping_add(data_off) & mask;
        let mut data: Vec<u8>;
        if datalen & 0x8000_0000 != 0 {
            datalen &= 0x7FFF_FFFF;
            if datalen > 4 {
                return Err(value_error(format!("Unable to read inline registry value with excessive length: {datalen}")));
            }
            data = hive_read(layer, data_field, datalen)?;
        } else if layer.hive().m("Version")?.int()? == 5 && datalen > 0x4000 {
            // big data: a list of cells holding the data blocks
            let t = &layer.types;
            let dv = layer.read_u32(data_field)? as u64;
            let node = layer.get_node(dv);
            let big = node.addr; // .cast("_CM_BIG_DATA")
            let count = layer.read_u16(big.wrapping_add(t.bd_count) & mask)? as u64;
            data = Vec::new();
            for i in 0..count {
                let list = layer.read_u32(big.wrapping_add(t.bd_list) & mask)? as u64;
                let cell = layer.get_cell(list.wrapping_add(i * 4));
                let block_offset = layer.read_u32(cell.addr)? as u64;
                if block_offset < layer.maximum_address() {
                    let amount = BIG_DATA_MAXLEN.min(datalen);
                    let at = layer.get_cell(block_offset).addr;
                    if let Ok(d) = hive_read(layer, at, amount) {
                        data.extend_from_slice(&d);
                    }
                    datalen -= amount;
                }
            }
        } else {
            let dv = layer.read_u32(data_field)? as u64;
            data = match hive_read(layer, dv + 4, datalen) {
                Ok(d) => d,
                Err(e) if is_invalid_or_registry(&e) => vec![0u8; datalen as usize],
                Err(e) => return Err(e),
            };
        }
        let ty = self.get_value_type()?;
        let mismatch = |o: &Obj| -> Error {
            match o.get_name() {
                Ok(n) => value_error(format!("Size of data does not match the type of registry value {n}")),
                Err(e) => e,
            }
        };
        match ty {
            RegValueType::Dword => {
                if data.len() != 4 {
                    return Err(mismatch(self));
                }
                Ok(RegData::Int(u32::from_le_bytes(data[..4].try_into().unwrap()) as u64))
            }
            RegValueType::DwordBigEndian => {
                if data.len() != 4 {
                    return Err(mismatch(self));
                }
                Ok(RegData::Int(u32::from_be_bytes(data[..4].try_into().unwrap()) as u64))
            }
            RegValueType::Qword => {
                if data.len() != 8 {
                    return Err(mismatch(self));
                }
                Ok(RegData::Int(u64::from_le_bytes(data[..8].try_into().unwrap())))
            }
            RegValueType::None => Ok(RegData::Bytes(Vec::new())),
            _ => Ok(RegData::Bytes(data)),
        }
    }

    fn last_write_time(&self) -> Result<Value> {
        let off = match hive_of(self) {
            Some(h) if self.ty == h.types.key_node => h.types.kn_last_write,
            _ => self.member_offset("LastWriteTime")?,
        };
        let q = self.layer().read_i64(self.addr.wrapping_add(off) & self.sp.layer_mask)?;
        Ok(crate::util::time::wintime_to_datetime(q as i128))
    }

    fn is_key_node(&self) -> bool {
        match hive_of(self) {
            Some(h) => self.ty == h.types.key_node,
            None => is_named(self, "_CM_KEY_NODE"),
        }
    }

    fn is_key_value(&self) -> bool {
        match hive_of(self) {
            Some(h) => self.ty == h.types.key_value,
            None => is_named(self, "_CM_KEY_VALUE"),
        }
    }

    fn get_full_key_name(&self) -> Result<Option<String>> {
        const KEY_HIVE_ENTRY: i128 = key_flags::KEY_HIVE_ENTRY as i128;
        // _skip_key_hive_entry_path: `_CM_KEY_BODY.Trans` appeared in Win10 14393
        let has_trans = self.has_member("Trans");
        let mut output: Vec<String> = Vec::new();
        let mut seen = crate::util::FxHashSet::default();
        let mut kcb = self.m("KeyControlBlock")?;
        loop {
            let parent = kcb.m("ParentKcb")?;
            if parent.u64()? == 0 {
                break;
            }
            if !seen.insert(parent.addr) {
                return Ok(None);
            }
            if output.len() > 128 {
                return Ok(None);
            }
            // `kcb.NameBlock.Name is None` is never true
            if has_trans && KEY_HIVE_ENTRY & kcb.m("Flags")?.int()? == KEY_HIVE_ENTRY {
                kcb = kcb.m("ParentKcb")?;
                if kcb.u64()? == 0 {
                    break;
                }
            }
            let nb = kcb.m("NameBlock")?;
            let len = nb.m("NameLength")?.u64()?;
            output.push(nb.m("Name")?.cast_string(len, StrEnc::Utf8, StrErrors::Replace).string()?);
            kcb = kcb.m("ParentKcb")?;
        }
        output.reverse();
        Ok(Some(output.join("\\")))
    }
}

/// Lazy `CM_KEY_NODE.get_subkeys()` (python generator order: both `SubKeyLists`, each walked
/// depth-first through `ri` index roots and `lf`/`lh` leaves).
pub struct SubkeyIter {
    hive: Option<&'static RegistryHive>,
    node: Obj,
    next_index: u8,
    stack: Vec<(Vec<u32>, usize)>,
    failed: Option<Error>,
}

enum Expand {
    Yield(Obj),
    List(Vec<u32>),
    Nothing,
    Fail(Error),
}

impl SubkeyIter {
    /// python `_get_subkeys_recursive(hive, node)` for one node (the part before recursing).
    fn expand(h: &RegistryHive, node: Obj) -> Expand {
        let mut sig = [0u8; 2];
        if h.read(node.addr, &mut sig).is_err() {
            return Expand::Nothing;
        }
        let jump: u64 = match &sig {
            b"ri" => 1,
            b"lh" | b"lf" => 2,
            _ => {
                return if node.ty == h.types.key_node { Expand::Yield(node) } else { Expand::Nothing };
            }
        };
        let t = &h.types;
        let mask = node.sp.layer_mask;
        let count = match h.read_u16(node.addr.wrapping_add(t.ki_count) & mask) {
            Ok(c) => c as u64,
            Err(e) => return Expand::Fail(e),
        };
        let list = node.addr.wrapping_add(t.ki_list) & mask;
        // python: node.List[::listjump] reads every selected element (4 bytes each)
        let total = count * jump * 4;
        let mut v = Vec::with_capacity(count as usize);
        if total > 0 && list.checked_add(total).is_some_and(|e| e <= 0x1_0000_0000) {
            if let Ok(raw) = hive_read(h, list, total) {
                for i in 0..count {
                    let o = (i * jump * 4) as usize;
                    v.push(u32::from_le_bytes(raw[o..o + 4].try_into().unwrap()));
                }
                return Expand::List(v);
            }
        }
        for i in 0..count {
            match h.read_u32(list.wrapping_add(i * jump * 4) & mask) {
                Ok(x) => v.push(x),
                Err(e) => return Expand::Fail(e),
            }
        }
        Expand::List(v)
    }
}

impl Iterator for SubkeyIter {
    type Item = Result<Obj>;
    fn next(&mut self) -> Option<Result<Obj>> {
        if let Some(e) = self.failed.take() {
            self.next_index = 2;
            self.stack.clear();
            self.hive = None;
            return Some(Err(e));
        }
        let h = self.hive?;
        loop {
            let expanded = if let Some((offs, pos)) = self.stack.last_mut() {
                if *pos >= offs.len() {
                    self.stack.pop();
                    continue;
                }
                let off = offs[*pos] as u64;
                *pos += 1;
                if off & 0x7FFF_FFFF > h.maximum_address() {
                    continue;
                }
                Self::expand(h, h.get_node(off))
            } else if self.next_index < 2 {
                let idx = self.next_index as u64;
                self.next_index += 1;
                let t = &h.types;
                let a = self.node.addr.wrapping_add(t.kn_subkey_lists + 4 * idx) & self.node.sp.layer_mask;
                match h.read_u32(a) {
                    Ok(v) => {
                        let cell = h.get_cell(v as u64);
                        let ki = Obj::new(h.space(), t.key_index, cell.addr.wrapping_add(t.off_key_index));
                        Self::expand(h, ki)
                    }
                    Err(e) => Expand::Fail(e),
                }
            } else {
                self.hive = None;
                return None;
            };
            match expanded {
                Expand::Yield(o) => return Some(Ok(o)),
                Expand::List(v) => {
                    if self.stack.len() >= 990 {
                        self.hive = None;
                        return Some(Err(Error::msg("RecursionError: maximum recursion depth exceeded")));
                    }
                    self.stack.push((v, 0));
                }
                Expand::Nothing => {}
                Expand::Fail(e) => {
                    self.hive = None;
                    self.stack.clear();
                    return Some(Err(e));
                }
            }
        }
    }
}

/// Lazy `CM_KEY_NODE.get_values()`: the `vk` cells of the value list; stops silently at the
/// first unreadable list entry (python catches and returns).
pub struct ValueIter {
    hive: Option<&'static RegistryHive>,
    list: u64,
    count: u64,
    i: u64,
}

impl Iterator for ValueIter {
    type Item = Obj;
    fn next(&mut self) -> Option<Obj> {
        let h = self.hive?;
        while self.i < self.count {
            let a = self.list.wrapping_add(self.i * 4) & 0xFFFF_FFFF;
            self.i += 1;
            let v = match h.read_u32(a) {
                Ok(v) => v,
                Err(_) => {
                    self.hive = None;
                    return None;
                }
            };
            if v != 0 {
                let node = h.get_node(v as u64);
                if node.ty == h.types.key_value {
                    return Some(node);
                }
            }
        }
        self.hive = None;
        None
    }
}

impl RegistryHive {
    /// python `hive.get_key(key, return_list=True)`: the nodes from the root to `key`
    /// (case-insensitive, `\` separated, trailing `\` ignored). Not found -> [`is_key_error`];
    /// root not a key node -> `RegistryFormatException`; read errors propagate like python.
    pub fn get_key(&self, key: &str) -> Result<Vec<Obj>> {
        let root = self.get_node(self.root_cell_offset());
        if root.ty != self.types.key_node {
            return Err(crate::layers::registry::registry_format(
                self.name(),
                &format!("Encountered {} instead of _CM_KEY_NODE", root.full_type_name()),
            ));
        }
        let key = key.strip_suffix('\\').unwrap_or(key);
        let parts: Vec<&str> = key.split('\\').collect();
        let mut nodes = vec![root];
        let mut found: Vec<&str> = Vec::new();
        let mut i = 0;
        while i < parts.len() {
            let want = casefold(parts[i]);
            let mut hit = None;
            for sub in nodes.last().unwrap().get_subkeys() {
                let sub = sub?;
                if casefold(&sub.get_name()?) == want {
                    hit = Some(sub);
                    break;
                }
            }
            match hit {
                Some(s) => {
                    nodes.push(s);
                    found.push(parts[i]);
                    i += 1;
                }
                None => return Err(key_error(format!("Key {} not found under {}", parts[i], found.join("\\")))),
            }
        }
        Ok(nodes)
    }

    /// python `hive.get_key(key)`: the node for `key`.
    pub fn get_key_node(&self, key: &str) -> Result<Obj> {
        Ok(*self.get_key(key)?.last().unwrap())
    }

    /// python `hive.read(offset, length)` (strict).
    pub fn read_bytes(&self, addr: u64, len: u64) -> Result<Vec<u8>> {
        hive_read(self, addr, len)
    }
}
