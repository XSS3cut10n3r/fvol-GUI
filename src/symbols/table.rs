//! Symbol tables (python `IntermediateSymbolTable` / ISF delegates) stored as ONE flat,
//! position-independent blob: string pool + fixed-size records + precomputed open-addressing
//! hash indexes. The same bytes are what the binary cache stores, so a warm load is an mmap
//! plus a header check -- no parsing, no hashing, no allocation.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Types are small `Copy` values ([`Ty`]); nested references (array elements, pointer targets)
//! are [`TypeIdx`] indexes into the table's node array (or into the runtime node store for
//! types created at run time, e.g. `cast("array", count=n, subtype=...)`).

use crate::error::{Error, Result};
use crate::util::fxhash::hash_bytes;
use crate::util::json::Json;
use crate::util::mmap::Mmap;
use std::sync::atomic::{AtomicPtr, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

/// Index of a type node. High bit set = runtime-created node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TypeIdx(pub u32);

impl TypeIdx {
    pub const RUNTIME: u32 = 0x8000_0000;
}

/// Kind of a primitive (python object class for native types).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrimKind {
    /// `objects.Integer`
    Int,
    /// `objects.Char` (an int)
    Char,
    /// `objects.Boolean` (an int)
    Bool,
    /// `objects.Float`
    Float,
    /// base kind "void" with a non-"void" name (python maps it to Integer)
    Void,
}

/// A primitive's data format (python `DataFormatInfo(length, byteorder, signed)`) plus the
/// index of its base type (for `vol.type_name`; `NO_NAME` if synthetic).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Prim {
    pub size: u8,
    pub signed: bool,
    pub big_endian: bool,
    pub kind: PrimKind,
    pub name: u16,
}

impl Prim {
    pub const NO_NAME: u16 = u16::MAX;
    /// Decode an integer of this format from `b` (len == size) with python semantics
    /// (`int.from_bytes(data, byteorder, signed)`), as i128.
    #[inline(always)]
    pub fn decode_int(&self, b: &[u8]) -> i128 {
        let n = (self.size as usize).min(16).min(b.len());
        let mut raw: u128 = 0;
        if self.big_endian {
            for &x in &b[..n] {
                raw = (raw << 8) | x as u128;
            }
        } else {
            for (i, &x) in b[..n].iter().enumerate() {
                raw |= (x as u128) << (8 * i);
            }
        }
        if self.signed && n > 0 && n < 16 {
            let shift = 128 - 8 * n as u32;
            ((raw << shift) as i128) >> shift
        } else {
            raw as i128
        }
    }
    pub(crate) fn pack(&self) -> u32 {
        self.size as u32
            | (self.signed as u32) << 8
            | (self.big_endian as u32) << 9
            | (self.kind as u32) << 10
            | (self.name as u32) << 16
    }
    fn unpack(v: u32) -> Prim {
        Prim {
            size: v as u8,
            signed: v & (1 << 8) != 0,
            big_endian: v & (1 << 9) != 0,
            kind: match (v >> 10) & 7 {
                0 => PrimKind::Int,
                1 => PrimKind::Char,
                2 => PrimKind::Bool,
                3 => PrimKind::Float,
                _ => PrimKind::Void,
            },
            name: (v >> 16) as u16,
        }
    }
}

/// String decoding for `Ty::String` (python `objects.String(encoding, errors)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StrEnc {
    Utf8,
    Utf16Le,
    Utf16Be,
    Latin1,
    Ascii,
    /// python "utf-16": BOM sniffing, little endian by default
    Utf16,
}

/// python `errors=` for string decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StrErrors {
    Strict,
    Replace,
    Ignore,
    BackslashReplace,
}

/// A type (python ObjectTemplate), as a small `Copy` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ty {
    /// `void` (size 0)
    Void,
    /// `function` (python Void; size 0)
    Function,
    /// Integer / Char / Boolean / (Void-kind base) primitive
    Int(Prim),
    /// Float primitive
    Float(Prim),
    /// Pointer with its data format and target type.
    Pointer { prim: Prim, target: TypeIdx },
    /// Array of `count` elements.
    Array { count: u32, elem: TypeIdx },
    /// Enumeration (index into the table's enums).
    Enum(u32),
    /// python BitField: `(base & ((1 << end) - 1)) >> start`.
    BitField { start: u8, end: u8, base: Prim },
    /// struct / union / class (index into the table's user types).
    Struct(u32),
    /// python `objects.String(max_length, encoding, errors)`.
    String { max_len: u32, enc: StrEnc, errors: StrErrors },
    /// python `objects.Bytes(length)`.
    Bytes(u32),
    /// A reference to a type that does not exist in this table (error on use). Holds the
    /// node index where the name is recorded.
    Unresolved(TypeIdx),
}

// ---------------------------------------------------------------------------------------------
// Blob layout
// ---------------------------------------------------------------------------------------------

pub(crate) const MAGIC: &[u8; 8] = b"RSVOLIS1";
/// Bump when the blob layout or the builder semantics change (invalidates caches).
pub(crate) const BLOB_VERSION: u32 = 5;

/// Section indexes in the header.
pub(crate) mod sec {
    pub const STRINGS: usize = 0;
    pub const NODES: usize = 1;
    pub const UTYPES: usize = 2;
    pub const MEMBERS: usize = 3;
    pub const MHASH: usize = 4;
    pub const ENUMS: usize = 5;
    pub const CONSTS: usize = 6;
    pub const SYMBOLS: usize = 7;
    pub const BASES: usize = 8;
    pub const H_UTYPES: usize = 9;
    pub const H_SYMBOLS: usize = 10;
    pub const H_ENUMS: usize = 11;
    pub const H_BASES: usize = 12;
    pub const META: usize = 13;
    pub const CDATA: usize = 14;
    pub const N: usize = 15;
}

/// Record sizes.
pub(crate) const NODE_SZ: usize = 16;
pub(crate) const UTYPE_SZ: usize = 32; // name(8) kind(4) size(4) mstart(4) mcount(4) hstart(4) hlen(4)
pub(crate) const MEMBER_SZ: usize = 32; // name(8) offset(8, i64: ISF offsets may be negative) ty(16)
pub(crate) const ENUM_SZ: usize = 32; // name(8) base prim(4) size(4) cstart(4) ccount(4) pad(8)
pub(crate) const CONST_SZ: usize = 16; // name(8) value(8)
pub(crate) const SYMBOL_SZ: usize = 32; // name(8) address(8) type(4) flags(4) cdata(8)
pub(crate) const BASE_SZ: usize = 16; // name(8) prim(4) kindcode(4)
/// header: magic(8) version(4) nsec(4) + N * (off u64, len u64) + format(3*u32) + pad
pub(crate) const HDR_SZ: usize = 16 + sec::N * 16 + 16;

/// Returned for out-of-range record indexes (corrupt input must not panic).
static ZERO_REC: [u8; 32] = [0; 32];

/// User type kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserKind {
    Struct,
    Union,
    Class,
}

/// Serialize a Ty into 16 bytes.
pub(crate) fn ty_encode(t: &Ty) -> [u8; 16] {
    let mut b = [0u8; 16];
    let (k, x, y, z): (u8, u32, u32, u32) = match *t {
        Ty::Void => (0, 0, 0, 0),
        Ty::Function => (1, 0, 0, 0),
        Ty::Int(p) => (2, p.pack(), 0, 0),
        Ty::Float(p) => (3, p.pack(), 0, 0),
        Ty::Pointer { prim, target } => (4, prim.pack(), target.0, 0),
        Ty::Array { count, elem } => (5, count, elem.0, 0),
        Ty::Enum(i) => (6, i, 0, 0),
        Ty::BitField { start, end, base } => (7, base.pack(), start as u32, end as u32),
        Ty::Struct(i) => (8, i, 0, 0),
        Ty::String { max_len, enc, errors } => (9, max_len, enc as u32, errors as u32),
        Ty::Bytes(n) => (10, n, 0, 0),
        Ty::Unresolved(i) => (11, i.0, 0, 0),
    };
    b[0] = k;
    b[4..8].copy_from_slice(&x.to_le_bytes());
    b[8..12].copy_from_slice(&y.to_le_bytes());
    b[12..16].copy_from_slice(&z.to_le_bytes());
    b
}

#[inline(always)]
pub(crate) fn ty_decode(b: &[u8]) -> Ty {
    let x = u32::from_le_bytes(b[4..8].try_into().unwrap());
    let y = u32::from_le_bytes(b[8..12].try_into().unwrap());
    let z = u32::from_le_bytes(b[12..16].try_into().unwrap());
    match b[0] {
        0 => Ty::Void,
        1 => Ty::Function,
        2 => Ty::Int(Prim::unpack(x)),
        3 => Ty::Float(Prim::unpack(x)),
        4 => Ty::Pointer { prim: Prim::unpack(x), target: TypeIdx(y) },
        5 => Ty::Array { count: x, elem: TypeIdx(y) },
        6 => Ty::Enum(x),
        7 => Ty::BitField { start: y as u8, end: z as u8, base: Prim::unpack(x) },
        8 => Ty::Struct(x),
        9 => Ty::String {
            max_len: x,
            enc: match y {
                0 => StrEnc::Utf8,
                1 => StrEnc::Utf16Le,
                2 => StrEnc::Utf16Be,
                3 => StrEnc::Latin1,
                4 => StrEnc::Ascii,
                _ => StrEnc::Utf16,
            },
            errors: match z {
                0 => StrErrors::Strict,
                1 => StrErrors::Replace,
                2 => StrErrors::Ignore,
                _ => StrErrors::BackslashReplace,
            },
        },
        10 => Ty::Bytes(x),
        _ => Ty::Unresolved(TypeIdx(x)),
    }
}

/// Backing storage of a table blob.
pub(crate) enum Blob {
    Owned(Vec<u8>),
    Mapped(Mmap),
    #[allow(dead_code)]
    Static(&'static [u8]),
}

impl Blob {
    #[inline(always)]
    fn bytes(&self) -> &[u8] {
        match self {
            Blob::Owned(v) => v,
            Blob::Mapped(m) => m.as_slice(),
            Blob::Static(s) => s,
        }
    }
}

/// Append-only store of runtime-created type nodes, readable without locks.
struct RuntimeNodes {
    segs: [AtomicPtr<Ty>; 24],
    len: Mutex<(usize, crate::util::FxHashMap<Ty, u32>)>,
}

impl RuntimeNodes {
    fn new() -> RuntimeNodes {
        RuntimeNodes { segs: std::array::from_fn(|_| AtomicPtr::new(std::ptr::null_mut())), len: Mutex::new((0, Default::default())) }
    }
    #[inline]
    fn locate(i: usize) -> (usize, usize) {
        // segment k holds 64 << k entries, starting at 64 * ((1 << k) - 1)
        let q = i / 64 + 1;
        let k = (usize::BITS - 1 - q.leading_zeros()) as usize;
        (k, i - 64 * ((1 << k) - 1))
    }
    fn get(&self, i: usize) -> Option<Ty> {
        let (k, j) = Self::locate(i);
        let p = self.segs.get(k)?.load(Ordering::Acquire);
        if p.is_null() {
            return None;
        }
        // entries below the published length are initialised before the pointer is shared
        Some(unsafe { *p.add(j) })
    }
    fn intern(&self, t: Ty) -> u32 {
        let mut g = self.len.lock().unwrap();
        if let Some(&i) = g.1.get(&t) {
            return i;
        }
        let i = g.0;
        let (k, j) = Self::locate(i);
        let mut p = self.segs[k].load(Ordering::Acquire);
        if p.is_null() {
            let seg: Box<[Ty]> = vec![Ty::Void; 64 << k].into_boxed_slice();
            p = Box::into_raw(seg) as *mut Ty;
            unsafe { *p.add(j) = t };
            self.segs[k].store(p, Ordering::Release);
        } else {
            unsafe { *p.add(j) = t };
        }
        g.0 += 1;
        g.1.insert(t, i as u32);
        i as u32
    }
}

/// A symbol (python `SymbolInterface`).
#[derive(Clone, Copy, Debug)]
pub struct Symbol<'a> {
    pub name: &'a str,
    /// Address relative to the module base (masked by the table's symbol mask if any).
    pub address: u64,
    /// The symbol's type, if the ISF records one.
    pub ty: Option<Ty>,
    /// Decoded `constant_data` (e.g. the linux banner), if any.
    pub constant_data: Option<&'a [u8]>,
}

/// One member of a struct.
#[derive(Clone, Copy, Debug)]
pub struct Member<'a> {
    pub name: &'a str,
    pub offset: u64,
    pub ty: Ty,
}

/// Windows PDB identification from the ISF metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdbInfo {
    pub guid: String,
    pub age: u32,
    pub database: String,
    pub machine_type: Option<u32>,
}

/// A loaded symbol table.
pub struct SymbolTable {
    name: String,
    blob: Blob,
    secs: [(usize, usize); sec::N],
    format: (u32, u32, u32),
    runtime: RuntimeNodes,
    url: String,
    symbol_mask: u64,
    meta_json: OnceLock<Json<'static>>,
    table_mapping: Vec<(String, String)>,
    by_addr: OnceLock<Vec<(u64, u32)>>,
    /// per user type: 0 = not yet validated, 1 = valid, 2 = corrupt (see `validate_type`)
    checked: Box<[AtomicU8]>,
}

// ----- raw little-endian readers -----
#[inline(always)]
fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
#[inline(always)]
fn rd64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

impl SymbolTable {
    /// Wrap a blob (from the builder or the cache). Validates the header and section bounds.
    pub(crate) fn from_blob(blob: Blob, name: &str, url: &str) -> Result<SymbolTable> {
        let b = blob.bytes();
        if b.len() < HDR_SZ || &b[..8] != MAGIC || rd32(b, 8) != BLOB_VERSION || rd32(b, 12) as usize != sec::N {
            return Err(Error::msg("bad symbol table blob"));
        }
        let mut secs = [(0usize, 0usize); sec::N];
        for (i, s) in secs.iter_mut().enumerate() {
            let off = rd64(b, 16 + i * 16) as usize;
            let len = rd64(b, 24 + i * 16) as usize;
            if off.checked_add(len).is_none_or(|e| e > b.len()) {
                return Err(Error::msg("corrupt symbol table blob"));
            }
            *s = (off, len);
        }
        let fo = 16 + sec::N * 16;
        let format = (rd32(b, fo), rd32(b, fo + 4), rd32(b, fo + 8));
        // Validation is lazy (a 27 MB kernel blob would be faulted in and checked on every
        // load): names are UTF-8-checked when returned as &str, and each user type's member
        // index is checked the first time `member()` probes it.
        let ntypes = secs[sec::UTYPES].1 / UTYPE_SZ;
        let checked = (0..ntypes).map(|_| AtomicU8::new(0)).collect();
        Ok(SymbolTable {
            name: name.to_string(),
            blob,
            secs,
            format,
            runtime: RuntimeNodes::new(),
            url: url.to_string(),
            symbol_mask: 0,
            meta_json: OnceLock::new(),
            table_mapping: Vec::new(),
            by_addr: OnceLock::new(),
            checked,
        })
    }

    /// Check user type `ut`'s member range, hash slots and member name ranges (what `member()`
    /// reads without bounds checks). Memoized per type.
    #[cold]
    fn validate_type(&self, ut: usize) -> bool {
        let b = self.b();
        let (uo, ul) = self.secs[sec::UTYPES];
        let (mo, ml) = self.secs[sec::MEMBERS];
        let (ho, hl) = self.secs[sec::MHASH];
        let sl = self.secs[sec::STRINGS].1;
        let (nmembers, nslots) = (ml / MEMBER_SZ, hl / 4);
        let ok = (ut + 1) * UTYPE_SZ <= ul && {
            let r = &b[uo + ut * UTYPE_SZ..uo + (ut + 1) * UTYPE_SZ];
            let (ms, mc, hs, hn) = (rd32(r, 16) as usize, rd32(r, 20) as usize, rd32(r, 24) as usize, rd32(r, 28) as usize);
            ms.checked_add(mc).is_some_and(|e| e <= nmembers)
                && hs.checked_add(hn).is_some_and(|e| e <= nslots)
                && (hn == 0 || hn.is_power_of_two())
                && b[ho + hs * 4..ho + (hs + hn) * 4].chunks_exact(4).all(|v| (u32::from_le_bytes(v.try_into().unwrap()) as usize) <= mc)
                && b[mo + ms * MEMBER_SZ..mo + (ms + mc) * MEMBER_SZ].chunks_exact(MEMBER_SZ).all(|m| {
                    let (off, len) = (rd32(m, 0) as usize, rd32(m, 4) as usize);
                    off.checked_add(len).is_some_and(|e| e <= sl)
                })
        };
        if let Some(c) = self.checked.get(ut) {
            c.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
        }
        ok
    }

    /// Table name (python symbol table name; informational).
    pub fn name(&self) -> &str {
        &self.name
    }
    pub(crate) fn set_name(&mut self, name: &str) {
        self.name = name.to_string();
    }
    /// python `config["isf_url"]` (where the ISF was loaded from).
    pub fn isf_url(&self) -> &str {
        &self.url
    }
    #[allow(dead_code)]
    pub(crate) fn set_url(&mut self, url: &str) {
        self.url = url.to_string();
    }
    /// python `symbol_mask` (0 = no masking).
    pub fn symbol_mask(&self) -> u64 {
        self.symbol_mask
    }
    /// python `table_mapping`: names used as `prefix!Type` inside this ISF -> registered table
    /// names (e.g. `"nt_symbols"` -> the kernel table).
    pub fn set_table_mapping(&mut self, mapping: &[(&str, &str)]) {
        self.table_mapping = mapping.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
    }
    /// Map an ISF table prefix through `table_mapping`.
    pub fn map_table_name<'a>(&'a self, prefix: &'a str) -> &'a str {
        self.table_mapping.iter().find(|(a, _)| a == prefix).map(|(_, b)| b.as_str()).unwrap_or(prefix)
    }
    pub(crate) fn set_symbol_mask(&mut self, m: u64) {
        self.symbol_mask = m;
    }
    /// ISF `metadata.format` as (major, minor, patch).
    pub fn format(&self) -> (u32, u32, u32) {
        self.format
    }
    /// The raw blob (for the cache writer).
    #[allow(dead_code)]
    pub(crate) fn blob_bytes(&self) -> &[u8] {
        self.blob.bytes()
    }

    #[inline(always)]
    fn b(&self) -> &[u8] {
        self.blob.bytes()
    }
    #[inline(always)]
    fn sec(&self, s: usize) -> &[u8] {
        let (o, l) = self.secs[s];
        &self.b()[o..o + l]
    }
    #[inline(always)]
    fn str_at(&self, off: u32, len: u32) -> &str {
        let pool = self.sec(sec::STRINGS);
        pool.get(off as usize..(off as usize).saturating_add(len as usize)).and_then(|n| std::str::from_utf8(n).ok()).unwrap_or("")
    }
    #[inline(always)]
    fn name_eq(&self, rec: &[u8], name: &[u8]) -> bool {
        let (off, len) = (rd32(rec, 0) as usize, rd32(rec, 4) as usize);
        len == name.len() && self.sec(sec::STRINGS).get(off..off.saturating_add(len)) == Some(name)
    }
    #[inline(always)]
    fn rec_str(&self, rec: &[u8]) -> &str {
        self.str_at(rd32(rec, 0), rd32(rec, 4))
    }

    /// Look up `name` in hash index `h` over record section `rs` of size `rsz`.
    #[inline]
    fn lookup(&self, h: usize, rs: usize, rsz: usize, name: &str) -> Option<u32> {
        let idx = self.sec(h);
        let nslots = idx.len() / 4;
        if nslots == 0 {
            return None;
        }
        let recs = self.sec(rs);
        let mask = nslots - 1;
        let mut i = hash_bytes(name.as_bytes()) as usize & mask;
        for _ in 0..nslots {
            let v = rd32(idx, i * 4);
            if v == 0 {
                return None;
            }
            let r = (v - 1) as usize;
            let rec = recs.get(r * rsz..(r + 1) * rsz)?;
            if self.name_eq(rec, name.as_bytes()) {
                return Some(r as u32);
            }
            i = (i + 1) & mask;
        }
        None
    }

    // ------------------------------------------------------------------ nodes

    /// Resolve a node index to its type.
    #[inline]
    pub fn node(&self, i: TypeIdx) -> Ty {
        if i.0 & TypeIdx::RUNTIME != 0 {
            return self.runtime.get((i.0 & !TypeIdx::RUNTIME) as usize).unwrap_or(Ty::Void);
        }
        let n = self.sec(sec::NODES);
        let o = i.0 as usize * NODE_SZ;
        if o + NODE_SZ > n.len() {
            return Ty::Void;
        }
        ty_decode(&n[o..o + NODE_SZ])
    }

    /// Intern a runtime type (for arrays/pointers created at run time) and return its index.
    pub fn intern(&self, t: Ty) -> TypeIdx {
        TypeIdx(self.runtime.intern(t) | TypeIdx::RUNTIME)
    }

    /// Name recorded for an unresolved reference.
    pub fn unresolved_name(&self, i: TypeIdx) -> &str {
        let n = self.sec(sec::NODES);
        let o = i.0 as usize * NODE_SZ;
        if o + NODE_SZ > n.len() {
            return "";
        }
        self.str_at(rd32(n, o + 4), rd32(n, o + 8))
    }

    // ------------------------------------------------------------------ user types

    fn utype_rec(&self, i: u32) -> &[u8] {
        let s = self.sec(sec::UTYPES);
        s.get(i as usize * UTYPE_SZ..(i as usize + 1) * UTYPE_SZ).unwrap_or(&ZERO_REC)
    }
    /// Number of user types.
    pub fn user_type_count(&self) -> usize {
        self.sec(sec::UTYPES).len() / UTYPE_SZ
    }
    /// Name of user type `i`.
    pub fn user_type_name(&self, i: u32) -> &str {
        self.rec_str(self.utype_rec(i))
    }
    /// Size of user type `i`.
    pub fn user_type_size(&self, i: u32) -> u64 {
        rd32(self.utype_rec(i), 12) as u64
    }
    /// struct / union / class.
    pub fn user_type_kind(&self, i: u32) -> UserKind {
        match rd32(self.utype_rec(i), 8) {
            1 => UserKind::Union,
            2 => UserKind::Class,
            _ => UserKind::Struct,
        }
    }
    /// Index of a user type by name.
    #[inline]
    pub fn user_type(&self, name: &str) -> Option<u32> {
        self.lookup(sec::H_UTYPES, sec::UTYPES, UTYPE_SZ, name)
    }
    /// Look up a member of user type `ut` (hashed; ~20ns).
    #[inline]
    pub fn member(&self, ut: u32, name: &str) -> Option<Member<'_>> {
        let b = self.b();
        let (uo, ul) = self.secs[sec::UTYPES];
        let ut = ut as usize;
        if (ut + 1) * UTYPE_SZ > ul {
            return None;
        }
        match self.checked.get(ut).map(|c| c.load(Ordering::Relaxed)) {
            Some(1) => {}
            Some(0) => {
                if !self.validate_type(ut) {
                    return None;
                }
            }
            _ => return None,
        }
        // SAFETY: `validate_type` checked this user type's member range, hash range (power of
        // two, slot values <= member count) and its member name ranges, so all reads below
        // stay inside the blob.
        unsafe {
            let base = b.as_ptr();
            let rd = |p: *const u8, o: usize| -> usize { u32::from_le((p.add(o) as *const u32).read_unaligned()) as usize };
            let r = base.add(uo + ut * UTYPE_SZ);
            let (mstart, hstart, hlen) = (rd(r, 16), rd(r, 24), rd(r, 28));
            if hlen == 0 {
                return None;
            }
            let hs = base.add(self.secs[sec::MHASH].0 + hstart * 4);
            let ms = base.add(self.secs[sec::MEMBERS].0);
            let pool = base.add(self.secs[sec::STRINGS].0);
            let nb = name.as_bytes();
            let mask = hlen - 1;
            let mut i = hash_bytes(nb) as usize & mask;
            for _ in 0..hlen {
                let v = rd(hs, i * 4);
                if v == 0 {
                    return None;
                }
                let rec = ms.add((mstart + v - 1) * MEMBER_SZ);
                let (off, len) = (rd(rec, 0), rd(rec, 4));
                if len == nb.len() {
                    let s = std::slice::from_raw_parts(pool.add(off), len);
                    if s == nb {
                        // byte-equal to a valid &str, hence valid UTF-8
                        let n = std::str::from_utf8_unchecked(s);
                        return Some(Member { name: n, offset: u64::from_le((rec.add(8) as *const u64).read_unaligned()), ty: ty_decode(std::slice::from_raw_parts(rec.add(16), 16)) });
                    }
                }
                i = (i + 1) & mask;
            }
            None
        }
    }
    /// All members of user type `ut` in ISF order.
    pub fn members(&self, ut: u32) -> impl Iterator<Item = Member<'_>> + '_ {
        let r = self.utype_rec(ut);
        let ms = self.sec(sec::MEMBERS);
        // clamped to the section: a corrupt count must not become a 4-billion-step loop
        let n = (ms.len() / MEMBER_SZ) as u64;
        let mstart = (rd32(r, 16) as u64).min(n);
        let mend = (mstart + rd32(r, 20) as u64).min(n);
        (mstart..mend).map(move |mi| {
            let rec = ms.get(mi as usize * MEMBER_SZ..(mi as usize + 1) * MEMBER_SZ).unwrap_or(&ZERO_REC);
            Member { name: self.rec_str(rec), offset: rd64(rec, 8), ty: ty_decode(&rec[16..32]) }
        })
    }
    /// Iterate user type names (ISF order).
    pub fn user_type_names(&self) -> impl Iterator<Item = &str> + '_ {
        (0..self.user_type_count() as u32).map(move |i| self.user_type_name(i))
    }

    // ------------------------------------------------------------------ base types

    fn base_rec(&self, i: u32) -> &[u8] {
        let s = self.sec(sec::BASES);
        s.get(i as usize * BASE_SZ..(i as usize + 1) * BASE_SZ).unwrap_or(&ZERO_REC[..BASE_SZ])
    }
    /// Number of native base types.
    pub fn base_type_count(&self) -> usize {
        self.sec(sec::BASES).len() / BASE_SZ
    }
    /// Name of base type `i`.
    pub fn base_type_name(&self, i: u32) -> &str {
        self.rec_str(self.base_rec(i))
    }
    /// The primitive type of native `i` (or Pointer / Void for those names).
    pub fn base_type_ty(&self, i: u32) -> Ty {
        let r = self.base_rec(i);
        let p = Prim::unpack(rd32(r, 8));
        match rd32(r, 12) {
            1 => Ty::Pointer { prim: p, target: self.void_idx() },
            2 => Ty::Void,
            3 => Ty::Float(p),
            _ => Ty::Int(p),
        }
    }
    /// Native base type by name.
    pub fn base_type(&self, name: &str) -> Option<u32> {
        self.lookup(sec::H_BASES, sec::BASES, BASE_SZ, name)
    }
    /// Node index of `void` (always node 0).
    #[inline(always)]
    pub fn void_idx(&self) -> TypeIdx {
        TypeIdx(0)
    }

    // ------------------------------------------------------------------ enums

    fn enum_rec(&self, i: u32) -> &[u8] {
        let s = self.sec(sec::ENUMS);
        s.get(i as usize * ENUM_SZ..(i as usize + 1) * ENUM_SZ).unwrap_or(&ZERO_REC)
    }
    pub fn enum_count(&self) -> usize {
        self.sec(sec::ENUMS).len() / ENUM_SZ
    }
    /// Enum index by name.
    pub fn enumeration(&self, name: &str) -> Option<u32> {
        self.lookup(sec::H_ENUMS, sec::ENUMS, ENUM_SZ, name)
    }
    pub fn enum_name(&self, i: u32) -> &str {
        self.rec_str(self.enum_rec(i))
    }
    /// The enum's base integer format.
    pub fn enum_base(&self, i: u32) -> Prim {
        Prim::unpack(rd32(self.enum_rec(i), 8))
    }
    /// The enum's constants in ISF order.
    pub fn enum_constants(&self, i: u32) -> impl Iterator<Item = (&str, i64)> + '_ {
        let r = self.enum_rec(i);
        let s = self.sec(sec::CONSTS);
        let n = (s.len() / CONST_SZ) as u64;
        let cs = (rd32(r, 16) as u64).min(n);
        let ce = (cs + rd32(r, 20) as u64).min(n);
        (cs..ce).map(move |ci| {
            let rec = s.get(ci as usize * CONST_SZ..(ci as usize + 1) * CONST_SZ).unwrap_or(&ZERO_REC[..CONST_SZ]);
            (self.rec_str(rec), rd64(rec, 8) as i64)
        })
    }
    /// python `Enumeration.lookup(value)`: the FIRST constant name with this value.
    pub fn enum_lookup(&self, i: u32, value: i128) -> Option<&str> {
        self.enum_constants(i).find(|(_, v)| *v as i128 == value).map(|(n, _)| n)
    }
    /// Value of a named constant (python `enum.CONSTANT` attribute access).
    pub fn enum_value(&self, i: u32, name: &str) -> Option<i64> {
        self.enum_constants(i).find(|(n, _)| *n == name).map(|(_, v)| v)
    }

    // ------------------------------------------------------------------ symbols

    fn sym_rec(&self, i: u32) -> &[u8] {
        let s = self.sec(sec::SYMBOLS);
        s.get(i as usize * SYMBOL_SZ..(i as usize + 1) * SYMBOL_SZ).unwrap_or(&ZERO_REC)
    }
    pub fn symbol_count(&self) -> usize {
        self.sec(sec::SYMBOLS).len() / SYMBOL_SZ
    }
    fn sym_at(&self, i: u32) -> Symbol<'_> {
        let r = self.sym_rec(i);
        let mut address = rd64(r, 8);
        if self.symbol_mask != 0 {
            address &= self.symbol_mask;
        }
        let t = rd32(r, 16);
        let flags = rd32(r, 20);
        let cdata = if flags & 1 != 0 {
            let (o, l) = (rd32(r, 24) as usize, rd32(r, 28) as usize);
            self.sec(sec::CDATA).get(o..o.saturating_add(l))
        } else {
            None
        };
        Symbol {
            name: self.rec_str(r),
            address,
            ty: if t == u32::MAX { None } else { Some(self.node(TypeIdx(t))) },
            constant_data: cdata,
        }
    }
    /// python `get_symbol(name)`.
    pub fn get_symbol(&self, name: &str) -> Result<Symbol<'_>> {
        match self.lookup(sec::H_SYMBOLS, sec::SYMBOLS, SYMBOL_SZ, name) {
            Some(i) => Ok(self.sym_at(i)),
            None => Err(Error::Symbol(format!("Unknown symbol: {name}"))),
        }
    }
    /// python `has_symbol(name)`.
    pub fn has_symbol(&self, name: &str) -> bool {
        self.lookup(sec::H_SYMBOLS, sec::SYMBOLS, SYMBOL_SZ, name).is_some()
    }
    /// All symbols in ISF order.
    pub fn symbols(&self) -> impl Iterator<Item = Symbol<'_>> + '_ {
        (0..self.symbol_count() as u32).map(move |i| self.sym_at(i))
    }
    /// Symbol names with `offset <= address <= offset + size` (python
    /// `get_symbols_by_location`), sorted by (address, name) like python.
    pub fn symbols_at(&self, offset: u64, size: u64) -> Vec<&str> {
        let idx = self.by_addr.get_or_init(|| {
            let _t = crate::util::trace::span("symbol address index");
            let mask = if self.symbol_mask != 0 { self.symbol_mask } else { u64::MAX };
            let mut v: Vec<(u64, u32)> = (0..self.symbol_count() as u32).map(|i| (rd64(self.sym_rec(i), 8) & mask, i)).collect();
            // sort by address (cheap integer keys), then order equal-address runs by name like
            // python's (address, name) tuples (names are unique: the result is deterministic)
            v.sort_unstable_by_key(|e| e.0);
            let mut i = 0;
            while i < v.len() {
                let mut j = i + 1;
                while j < v.len() && v[j].0 == v[i].0 {
                    j += 1;
                }
                if j - i > 1 {
                    // raw name bytes (byte order == str order), resolved once per element: some
                    // runs are large (e.g. thousands of symbols at address 0)
                    let pool = self.sec(sec::STRINGS);
                    let name = |e: &(u64, u32)| {
                        let r = self.sym_rec(e.1);
                        let (o, l) = (rd32(r, 0) as usize, rd32(r, 4) as usize);
                        pool.get(o..o.saturating_add(l)).unwrap_or(&[])
                    };
                    let mut run: Vec<(&[u8], (u64, u32))> = v[i..j].iter().map(|e| (name(e), *e)).collect();
                    run.sort_unstable_by(|a, b| a.0.cmp(b.0));
                    for (k, (_, e)) in run.into_iter().enumerate() {
                        v[i + k] = e;
                    }
                }
                i = j;
            }
            v
        });
        let start = idx.partition_point(|e| e.0 < offset);
        let end_addr = offset.saturating_add(size);
        idx[start..].iter().take_while(|e| e.0 <= end_addr).map(|e| self.sym_at(e.1).name).collect()
    }

    // ------------------------------------------------------------------ types by name

    /// python `get_type(name)`: user types first, then natives (`pointer`, `void`,
    /// `unsigned long`, ...). The parametric natives `array`, `string`, `bytes`, `enum`,
    /// `bitfield` return their python defaults (count/length 0).
    pub fn get_type(&self, name: &str) -> Result<Ty> {
        if let Some(i) = self.user_type(name) {
            return Ok(Ty::Struct(i));
        }
        match name {
            "void" => return Ok(Ty::Void),
            "function" => return Ok(Ty::Function),
            _ => {}
        }
        if let Some(i) = self.base_type(name) {
            return Ok(self.base_type_ty(i));
        }
        match name {
            "array" => Ok(Ty::Array { count: 0, elem: self.void_idx() }),
            "string" => Ok(Ty::String { max_len: 0, enc: StrEnc::Utf8, errors: StrErrors::Strict }),
            "bytes" => Ok(Ty::Bytes(0)),
            "bitfield" => Ok(Ty::BitField { start: 0, end: 0, base: Prim { size: 0, signed: false, big_endian: false, kind: PrimKind::Int, name: Prim::NO_NAME } }),
            _ => Err(Error::Symbol(format!("Unknown symbol: {name}"))),
        }
    }
    /// python `has_type(name)`.
    pub fn has_type(&self, name: &str) -> bool {
        self.get_type(name).is_ok()
    }

    /// python `template.size`.
    pub fn size_of(&self, t: Ty) -> u64 {
        match t {
            Ty::Void | Ty::Function | Ty::Unresolved(_) => 0,
            Ty::Int(p) | Ty::Float(p) => p.size as u64,
            Ty::Pointer { prim, .. } => prim.size as u64,
            Ty::Array { count, elem } => count as u64 * self.size_of(self.node(elem)),
            Ty::Enum(i) => self.enum_base(i).size as u64,
            Ty::BitField { base, .. } => base.size as u64,
            Ty::Struct(i) => self.user_type_size(i),
            Ty::String { max_len, .. } => max_len as u64,
            Ty::Bytes(n) => n as u64,
        }
    }

    /// python `vol.type_name` without the table prefix (`"_EPROCESS"`, `"unsigned long"`,
    /// `"pointer"`, `"array"`, `"string"`, the enum name, ...).
    pub fn type_name(&self, t: Ty) -> String {
        match t {
            Ty::Void => "void".into(),
            Ty::Function => "function".into(),
            Ty::Int(p) | Ty::Float(p) => {
                if (p.name as usize) < self.base_type_count() {
                    self.base_type_name(p.name as u32).to_string()
                } else {
                    "int".into()
                }
            }
            Ty::Pointer { .. } => "pointer".into(),
            Ty::Array { .. } => "array".into(),
            Ty::Enum(i) => self.enum_name(i).to_string(),
            Ty::BitField { .. } => "bitfield".into(),
            Ty::Struct(i) => self.user_type_name(i).to_string(),
            Ty::String { .. } => "string".into(),
            Ty::Bytes(_) => "bytes".into(),
            Ty::Unresolved(i) => self.unresolved_name(i).to_string(),
        }
    }

    /// python `get_type(type_name).relative_child_offset(member)`.
    pub fn offset_of(&self, type_name: &str, member: &str) -> Result<u64> {
        let ut = self.user_type(type_name).ok_or_else(|| Error::Symbol(format!("Unknown symbol: {type_name}")))?;
        self.member(ut, member)
            .map(|m| m.offset)
            .ok_or_else(|| Error::Symbol(format!("Member not present in template: {member}")))
    }

    /// python `symbols.symbol_table_is_64bit` (`get_type("pointer").size == 8`).
    pub fn is_64bit(&self) -> bool {
        matches!(self.get_type("pointer"), Ok(Ty::Pointer { prim, .. }) if prim.size == 8)
    }

    /// The natives (base types) as a list (for loading other tables with these natives).
    pub fn natives(&self) -> Vec<(String, Ty)> {
        (0..self.base_type_count() as u32).map(|i| (self.base_type_name(i).to_string(), self.base_type_ty(i))).collect()
    }

    // ------------------------------------------------------------------ metadata

    /// The ISF `metadata` object.
    pub fn metadata(&self) -> &Json<'static> {
        self.meta_json.get_or_init(|| {
            let s = self.sec(sec::META);
            Json::parse(s).map(|j| j.into_owned()).unwrap_or(Json::Null)
        })
    }
    /// `metadata.windows.pdb` (GUID upper-case as stored, age, database).
    pub fn pdb_info(&self) -> Option<PdbInfo> {
        let pdb = self.metadata().path(&["windows", "pdb"])?;
        Some(PdbInfo {
            guid: pdb.get("GUID")?.as_str()?.to_string(),
            age: pdb.get("age")?.as_u64()? as u32,
            database: pdb.get("database")?.as_str()?.to_string(),
            machine_type: pdb.get("machine_type").and_then(|m| m.as_u64()).map(|m| m as u32),
        })
    }
    /// python `WindowsIdentifier` / `LinuxIdentifier` / `MacIdentifier` for this table:
    /// (operating system, identifier bytes).
    pub fn identifier(&self) -> Option<(&'static str, Vec<u8>)> {
        if let Some(p) = self.pdb_info() {
            if !p.guid.is_empty() && p.age != 0 && !p.database.is_empty() {
                return Some(("windows", format!("{}|{}|{}", p.database, p.guid.to_uppercase(), p.age).into_bytes()));
            }
        }
        // python checks windows, then mac ("version" constant_data), then linux
        for (os, sym) in [("mac", "version"), ("linux", "linux_banner")] {
            if let Ok(s) = self.get_symbol(sym) {
                if let Some(cd) = s.constant_data {
                    if !cd.is_empty() {
                        return Some((os, cd.to_vec()));
                    }
                }
            }
        }
        None
    }
}

impl std::fmt::Debug for SymbolTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymbolTable({} @ {})", self.name, self.url)
    }
}
