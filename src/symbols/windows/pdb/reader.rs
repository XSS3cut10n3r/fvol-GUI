// Derived from Volatility 3 (Volatility Software License 1.0): framework/symbols/windows/pdbconv.py
//! PDB -> ISF conversion (python `PdbReader`).
//!
//! This reproduces the python converter's behaviour exactly, quirks included (the type
//! handler table, `LF_ARGLIST` parsed as an `LF_ENUM`, pascal names for `*_ST` leaves, masked
//! member offsets, the `pointer`/`pointerNN` base type dance, python negative list indexing,
//! `bisect` on the OMAP table, `name_strip`...). Anything python raises on is an error here.
//!
//! Implementation notes (speed):
//!   * streams are parsed straight from the (usually borrowed) byte slices; names are
//!     `(offset, len)` references into the stream, never copied;
//!   * types live in a flat `Vec` indexed by `type index - 0x1000`;
//!   * the JSON of a member type depends only on `(type index, "pointer" base known yet)`, so
//!     each pair is resolved and rendered exactly once into a cache and then memcpy'd;
//!   * the output is streamed into one pre-sized buffer, keys are sorted by sorting indices.

use super::json::JsonWriter;
use super::msf::{Msf, Paged, Stream};
use super::scan::find_byte;
use super::{PErr, PResult};
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

// ---- LEAF_TYPE values used by the converter (volatility3 symbols/windows/pdb.json) ----
const LF_MODIFIER: u16 = 0x1001;
const LF_POINTER: u16 = 0x1002;
const LF_ARRAY_ST: u16 = 0x1003;
const LF_CLASS_ST: u16 = 0x1004;
const LF_STRUCTURE_ST: u16 = 0x1005;
const LF_PROCEDURE: u16 = 0x1008;
const LF_ARGLIST: u16 = 0x1201;
const LF_FIELDLIST: u16 = 0x1203;
const LF_BITFIELD: u16 = 0x1205;
const LF_MEMBER_ST: u16 = 0x1405;
const LF_ST_MAX: u16 = 0x1500;
const LF_ENUMERATE: u16 = 0x1502;
const LF_ARRAY: u16 = 0x1503;
const LF_CLASS: u16 = 0x1504;
const LF_STRUCTURE: u16 = 0x1505;
const LF_UNION: u16 = 0x1506;
const LF_ENUM: u16 = 0x1507;
const LF_MEMBER: u16 = 0x150d;
const LF_STRIDED_ARRAY: u16 = 0x1516;
const LF_INTERFACE: u16 = 0x1519;
const LF_FUNC_ID: u16 = 0x1601;
const LF_BUILDINFO: u16 = 0x1603;
const LF_STRING_ID: u16 = 0x1605;
const LF_UDT_SRC_LINE: u16 = 0x1606;
const LF_UDT_MOD_SRC_LINE: u16 = 0x1607;
const LF_CLASS_VS19: u16 = 0x1608;
const LF_STRUCTURE_VS19: u16 = 0x1609;
const LF_CHAR: u16 = 0x8000;

/// Python's recursion limit analogue (malformed, cyclic type graphs).
const MAX_DEPTH: u32 = 1000;

/// Whether `v` is a member of the LEAF_TYPE enumeration (python `lookup()` raises
/// `ValueError` otherwise).
fn leaf_in_enum(v: u16) -> bool {
    matches!(v,
        0x1..=0x16 | 0xf0..=0xff | 0x200..=0x20c | 0x400..=0x40d | 0x1000..=0x1011
        | 0x1200..=0x120a | 0x1400..=0x140f | 0x1500..=0x151d | 0x1601..=0x1609
        | 0x8000..=0x8010 | 0x8017..=0x801c)
}

/// python `PdbReader.type_handlers`: the pdb.json structure used to parse a leaf.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum H {
    Struct,
    StructVs19,
    Member,
    Array,
    Enumerate,
    Enum,
    Union,
    StringId,
    FuncId,
    Modifier,
    Pointer,
    Procedure,
    FieldList,
    Bitfield,
    UdtSrcLine,
    UdtModSrcLine,
    BuildInfo,
}

fn handler(leaf: u16) -> Option<H> {
    Some(match leaf {
        LF_CLASS | LF_CLASS_ST | LF_STRUCTURE | LF_STRUCTURE_ST | LF_INTERFACE => H::Struct,
        LF_CLASS_VS19 | LF_STRUCTURE_VS19 => H::StructVs19,
        LF_MEMBER | LF_MEMBER_ST => H::Member,
        LF_ARRAY | LF_ARRAY_ST | LF_STRIDED_ARRAY => H::Array,
        LF_ENUMERATE => H::Enumerate,
        LF_ARGLIST | LF_ENUM => H::Enum,
        LF_UNION => H::Union,
        LF_STRING_ID => H::StringId,
        LF_FUNC_ID => H::FuncId,
        LF_MODIFIER => H::Modifier,
        LF_POINTER => H::Pointer,
        LF_PROCEDURE => H::Procedure,
        LF_FIELDLIST => H::FieldList,
        LF_BITFIELD => H::Bitfield,
        LF_UDT_SRC_LINE => H::UdtSrcLine,
        LF_UDT_MOD_SRC_LINE => H::UdtModSrcLine,
        LF_BUILDINFO => H::BuildInfo,
        _ => return None,
    })
}

// ---- base types ----
struct BaseDef {
    name: &'static str,
    kind: &'static str,
    signed: bool,
    size: i64,
}

const fn b(name: &'static str, kind: &'static str, signed: bool, size: i64) -> BaseDef {
    BaseDef { name, kind, signed, size }
}

/// All base types the converter can emit (python `primitives` + `indirections` + "pointer",
/// whose size is decided at run time).
static BASES: [BaseDef; 28] = [
    b("void", "void", true, 0),
    b("HRESULT", "int", false, 4),
    b("char", "char", true, 1),
    b("unsigned char", "char", false, 1),
    b("int8", "int", true, 1),
    b("uint8", "int", false, 1),
    b("wchar", "int", true, 2),
    b("short", "int", true, 2),
    b("unsigned short", "int", false, 2),
    b("long", "int", true, 4),
    b("unsigned long", "int", false, 4),
    b("int", "int", true, 4),
    b("unsigned int", "int", false, 4),
    b("long long", "int", true, 8),
    b("unsigned long long", "int", false, 8),
    b("int128", "int", true, 16),
    b("uint128", "int", false, 16),
    b("f16", "float", true, 2),
    b("f32", "float", true, 4),
    b("f32pp", "float", true, 4),
    b("f48", "float", true, 6),
    b("double", "float", true, 8),
    b("f80", "float", true, 10),
    b("f128", "float", true, 16),
    b("pointer16", "int", false, 2),
    b("pointer32", "int", false, 4),
    b("pointer64", "int", false, 8),
    b("pointer", "int", false, 0),
];
const POINTER: u8 = 27;

/// python `primitives[index & 0xff]`.
fn prim_id(low: i64) -> Option<u8> {
    Some(match low {
        0x03 => 0,
        0x08 => 1,
        0x10 | 0x70 => 2,
        0x20 => 3,
        0x68 => 4,
        0x69 => 5,
        0x71 => 6,
        0x11 | 0x72 => 7,
        0x21 | 0x73 => 8,
        0x12 => 9,
        0x22 => 10,
        0x74 => 11,
        0x75 => 12,
        0x13 | 0x76 => 13,
        0x23 | 0x77 => 14,
        0x14 | 0x78 => 15,
        0x24 | 0x79 => 16,
        0x46 => 17,
        0x40 => 18,
        0x45 => 19,
        0x44 => 20,
        0x41 => 21,
        0x42 => 22,
        0x43 => 23,
        _ => return None,
    })
}

/// python `indirections[index & 0xf00]`.
fn ind_id(ind: i64) -> Option<u8> {
    Some(match ind {
        0x100 => 24,
        0x400 => 25,
        0x600 => 26,
        _ => return None,
    })
}

fn key_error(what: impl std::fmt::Display) -> PErr {
    PErr::Other(format!("KeyError: {what}"))
}

fn index_error() -> PErr {
    PErr::Other("IndexError: list index out of range".into())
}

fn recursion_error() -> PErr {
    PErr::Other("RecursionError: maximum recursion depth exceeded".into())
}

// ---- names ----

/// A name: `(offset, len)` into its stream, or into the synthetic arena when `len & SYN`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Name(u32, u32);
const SYN: u32 = 1 << 31;

impl Name {
    const EMPTY: Name = Name(0, 0);
    #[inline]
    fn is_empty(self) -> bool {
        self.1 & !SYN == 0
    }
}

#[derive(Clone, Copy)]
struct Names<'d> {
    data: &'d [u8],
    syn: &'d [u8],
}

impl<'d> Names<'d> {
    #[inline]
    fn get(&self, n: Name) -> &'d [u8] {
        let len = (n.1 & !SYN) as usize;
        let start = n.0 as usize;
        if n.1 & SYN != 0 { &self.syn[start..start + len] } else { &self.data[start..start + len] }
    }
}

#[inline]
fn nonempty(n: Option<Name>) -> Option<Name> {
    n.filter(|n| !n.is_empty())
}

// ---- parsed info-stream records ----

#[derive(Clone, Copy)]
struct Ty {
    leaf: u16,
    h: H,
    name: Option<Name>,
    /// Offset of the parsed structure (record + 2) in the stream.
    obj: u64,
    /// Value decoded by `determine_extended_value` (size / offset / value).
    ext: i64,
    /// LF_FIELDLIST: range of its entries in `subs`.
    list: (u32, u32),
}

#[derive(Clone, Copy)]
struct Sub {
    h: H,
    name: Option<Name>,
    obj: u64,
    ext: i64,
}

/// python `_read_info_stream` parser state.
struct Parser<'x, 'a> {
    s: &'x Stream<'a>,
    subs: Vec<Sub>,
    keep_subs: bool,
}

#[inline]
fn nul_len(b: &[u8]) -> usize {
    find_byte(b, 0).unwrap_or(b.len())
}

/// python `PdbReader.parse_string` on stream `s` at `pos`.
#[inline]
fn parse_string(s: &Stream, pos: u64, pascal: bool, size: i64) -> PResult<Name> {
    if !pascal {
        if size <= 0 {
            return Ok(Name::EMPTY);
        }
        let b = s.read(pos, size as u64)?;
        Ok(Name(pos as u32, nul_len(b) as u32))
    } else {
        let l = s.u8(s.m(pos))? as u64;
        let sp = s.m(pos + 1);
        if l == 0 {
            return Ok(Name::EMPTY);
        }
        let b = s.read(sp, l)?;
        Ok(Name(sp as u32, nul_len(b) as u32))
    }
}

impl<'x, 'a> Parser<'x, 'a> {
    /// python `determine_extended_value`: returns (name, value, excess).
    fn extended_value(&self, leaf: u16, vpos: u64, length: i64) -> PResult<(Name, i64, i64)> {
        let s = self.s;
        let v = s.u16(vpos)?;
        let (value, vp, vlen, excess) = if v >= LF_CHAR {
            let o = vpos + 2;
            match v {
                0x8000 => (s.i8(o)? as i64, o, 1, 1),
                0x8001 => (s.i16(o)? as i64, o, 2, 2),
                0x8002 => (s.u16(o)? as i64, o, 2, 2),
                0x8003 => (s.i32(o)? as i64, o, 4, 4),
                0x8004 => (s.u32(o)? as i64, o, 4, 4),
                _ => return Err(PErr::Other("TypeError: Unexpected extended value type".into())),
            }
        } else {
            (v as i64, vpos, 2u64, 0i64)
        };
        let name = parse_string(s, vp + vlen, leaf < LF_ST_MAX, length - excess)?;
        Ok((name, value, excess))
    }

    /// python `consume_padding`.
    #[inline]
    fn padding(&self, off: u64) -> PResult<i64> {
        let v = self.s.u8(off)?;
        Ok(if v & 0xf0 == 0xf0 { (v & 0x0f) as i64 } else { 0 })
    }

    /// python `consume_type`: returns the record and the number of bytes consumed.
    fn consume(&mut self, off: u64, length: i64, depth: u32) -> PResult<(Ty, i64)> {
        if depth > MAX_DEPTH {
            return Err(recursion_error());
        }
        let s = self.s;
        let leaf = s.u16(off)?;
        let mut consumed: i64 = 2;
        let remaining = length - 2;
        let h = match handler(leaf) {
            Some(h) => h,
            None if leaf_in_enum(leaf) => {
                return Err(PErr::Other(format!("TypeError: Unhandled leaf_type: {leaf:#x}")));
            }
            None => {
                return Err(PErr::Value(format!(
                    "The value of the enumeration is outside the possible choices ({leaf:#x})"
                )));
            }
        };
        let obj = off + 2;
        let mut ty = Ty { leaf, h, name: None, obj, ext: 0, list: (0, 0) };
        match h {
            H::FieldList => {
                let start = self.subs.len();
                let mut sub_length = remaining;
                let mut sub_offset = obj;
                while length > consumed {
                    let (sub, mut sc) = self.consume(sub_offset, sub_length, depth + 1)?;
                    // sc >= 1 for every handler, so this always progresses
                    sc += self.padding(sub_offset + sc as u64)?;
                    sub_length -= sc;
                    sub_offset += sc as u64;
                    consumed += sc;
                    if self.keep_subs {
                        self.subs.push(Sub { h: sub.h, name: sub.name, obj: sub.obj, ext: sub.ext });
                    }
                }
                if depth == 0 && self.keep_subs {
                    ty.list = (start as u32, self.subs.len() as u32);
                } else {
                    // nested lists are never looked into by the converter
                    self.subs.truncate(start);
                }
            }
            H::BuildInfo => {
                let count = s.u16(s.m(obj))? as i64;
                consumed += count * 4;
            }
            H::Struct | H::StructVs19 | H::Member | H::Array | H::Enumerate => {
                // (vol.size, value offset, name offset)
                let (vsize, voff, noff): (i64, u64, u64) = match h {
                    H::Struct => (18, 16, 18),
                    H::StructVs19 => (20, 18, 20),
                    H::Member => (8, 6, 8),
                    H::Array => (10, 8, 10),
                    _ => (4, 2, 4),
                };
                let name_offset = s.m(obj + noff) as i64 - obj as i64;
                let (name, value, excess) =
                    self.extended_value(leaf, s.m(obj + voff), remaining - name_offset)?;
                ty.ext = value;
                ty.name = Some(name);
                consumed += vsize + (name.1 as i64) + 1 + excess;
            }
            H::Enum | H::Union | H::StringId | H::FuncId => {
                let noff: u64 = match h {
                    H::Enum => 12,
                    H::Union => 10,
                    H::StringId => 4,
                    _ => 8,
                };
                let npos = s.m(obj + noff);
                let name_offset = npos as i64 - obj as i64;
                ty.name = Some(parse_string(s, npos, leaf < LF_ST_MAX, remaining - name_offset)?);
                consumed += remaining;
            }
            _ => consumed += remaining,
        }
        Ok((ty, consumed))
    }
}

/// Result of reading an info stream (TPI or IPI).
struct Info {
    types: Vec<Ty>,
    subs: Vec<Sub>,
    syn: Vec<u8>,
}

/// python `_read_info_stream`.
fn read_info_stream(s: &Stream, what: &str, keep_subs: bool) -> PResult<Info> {
    let header_size = s.u32(s.m(4))? as u64;
    let index_min = s.u32(s.m(8))?;
    let index_max = s.u32(s.m(12))?;
    if !(56..1024).contains(&header_size) {
        return Err(PErr::Value(format!("{what} Stream Header size outside normal bounds")));
    }
    if index_min < 4096 {
        return Err(PErr::Value(format!("Minimum {what} index is 4096, found: {index_min}")));
    }
    if index_max < index_min {
        return Err(PErr::Value(format!(
            "Maximum {what} index is smaller than minimum TPI index, found: {index_max} < {index_min} "
        )));
    }
    let size = s.size;
    let cap = ((index_max - index_min) as u64).min(size / 4) as usize;
    let mut p = Parser { s, subs: Vec::with_capacity(if keep_subs { cap * 2 } else { 0 }), keep_subs };
    let mut types = Vec::with_capacity(cap);
    let mut syn = Vec::new();
    let mut offset = header_size;
    while size > offset {
        let length = s.u16(offset)? as i64;
        offset += 2;
        let (mut ty, _) = p.consume(offset, length, 0)?;
        if let Some(n) = ty.name {
            let nb = &s.bytes()[n.0 as usize..(n.0 + n.1) as usize];
            let tag = if nb == b"<unnamed-tag>" || nb == b"__unnamed" {
                Some("__unnamed_")
            } else if nb == b"<anonymous-tag>" || nb == b"__anonymous" {
                Some("__anonymous_")
            } else {
                None
            };
            if let Some(tag) = tag {
                let start = syn.len();
                syn.extend_from_slice(tag.as_bytes());
                syn.extend_from_slice(format!("{:x}", types.len() + 0x1000).as_bytes());
                ty.name = Some(Name(start as u32, (syn.len() - start) as u32 | SYN));
            }
        }
        types.push(ty);
        offset += length as u64;
    }
    if offset != size {
        return Err(PErr::Value("Type values did not fill the TPI stream correctly".into()));
    }
    Ok(Info { types, subs: p.subs, syn })
}

// ---- tiny FxHash for the name -> type index map ----
#[derive(Default)]
struct Fx(u64);
impl Hasher for Fx {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        const K: u64 = 0x517c_c1b7_2722_0a95;
        let mut h = self.0;
        let mut c = bytes.chunks_exact(8);
        for w in &mut c {
            h = (h.rotate_left(5) ^ u64::from_le_bytes(w.try_into().unwrap())).wrapping_mul(K);
        }
        for &x in c.remainder() {
            h = (h.rotate_left(5) ^ x as u64).wrapping_mul(K);
        }
        self.0 = h;
    }
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.0 = (self.0.rotate_left(5) ^ i as u64).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.0 = (self.0.rotate_left(5) ^ i as u64).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}
type FxMap<K, V> = HashMap<K, V, BuildHasherDefault<Fx>>;

// ---- type processing ----

#[derive(Clone, Copy)]
enum BaseRef {
    Prim(u8),
    Named(Name),
}

struct Field {
    name: Name,
    offset: i64,
    entry: u32,
}

struct UserType {
    name: Name,
    union: bool,
    size: i64,
    fields: (u32, u32),
}

struct EnumDef {
    name: Name,
    base: BaseRef,
    size: i64,
    consts: (u32, u32),
}

/// A rendered member type: `rendered[start..end]`, plus a deferred error (python raises it
/// in `replace_forward_references` / `json.dumps` only if the member survives).
struct Entry {
    start: u32,
    end: u32,
    soft: u32,
}
const NO_SOFT: u32 = u32::MAX;

struct Conv<'x, 'a> {
    s: &'x Stream<'a>,
    types: &'x [Ty],
    subs: &'x [Sub],
    names: Names<'x>,
    refs: FxMap<&'x [u8], u32>,
    bases: u32,
    ptr_size: Option<i64>,
    /// `(type index) * 2 + pointer-known` -> entry + 1
    cache: Vec<u32>,
    entries: Vec<Entry>,
    rendered: JsonWriter,
    soft: Vec<PErr>,
    fields: Vec<Field>,
    consts: Vec<(Name, i64)>,
    user: Vec<UserType>,
    enums: Vec<EnumDef>,
}

/// Depth of a member's `"type"` object in the ISF (`{ user_types: { T: { fields: { f: { type`).
const TYPE_DEPTH: usize = 5;

impl<'x, 'a> Conv<'x, 'a> {
    #[inline]
    fn ty(&self, index: i64) -> PResult<&'x Ty> {
        self.types.get((index - 0x1000) as usize).ok_or_else(index_error)
    }

    #[inline]
    fn u32m(&self, off: u64) -> PResult<i64> {
        Ok(self.s.u32(self.s.m(off))? as i64)
    }

    /// `value.properties.forward_reference`
    fn fwd(&self, t: &Ty) -> PResult<bool> {
        let prop = match t.h {
            H::StructVs19 => 0,
            _ => 2,
        };
        let p = self.s.m(t.obj + prop);
        Ok((self.s.u16(self.s.m(p))? >> 7) & 1 != 0)
    }

    /// python `get_size_from_index`.
    fn get_size(&self, index: i64, rd: u32) -> PResult<i64> {
        if rd > MAX_DEPTH {
            return Err(recursion_error());
        }
        let result = if index < 0x1000 {
            if index & 0xf00 != 0 {
                BASES[ind_id(index & 0xf00).ok_or_else(|| key_error(index & 0xf00))? as usize].size
            } else {
                BASES[prim_id(index & 0xff).ok_or_else(|| key_error(index & 0xff))? as usize].size
            }
        } else {
            let t = self.ty(index)?;
            match t.leaf {
                LF_UNION | LF_CLASS | LF_CLASS_ST | LF_STRUCTURE | LF_STRUCTURE_ST | LF_INTERFACE
                | LF_CLASS_VS19 | LF_STRUCTURE_VS19 => {
                    if !self.fwd(t)? {
                        if t.leaf == LF_UNION { self.s.u16(self.s.m(t.obj + 8))? as i64 } else { t.ext }
                    } else {
                        -1
                    }
                }
                LF_ARRAY | LF_ARRAY_ST | LF_STRIDED_ARRAY => t.ext,
                LF_MODIFIER => self.get_size(self.u32m(t.obj)?, rd + 1)?,
                LF_ENUM | LF_ARGLIST => self.get_size(self.u32m(t.obj + 4)?, rd + 1)?,
                LF_MEMBER => self.get_size(self.u32m(t.obj + 2)?, rd + 1)?,
                LF_BITFIELD => self.get_size(self.u32m(t.obj)?, rd + 1)?,
                LF_POINTER => {
                    let attr = self.u32m(t.obj + 4)?;
                    let size = (attr >> 13) & 0x3f;
                    if size == 0 {
                        return match attr & 0x1f {
                            0x0a => Ok(4),
                            0x0c => Ok(8),
                            _ => Err(PErr::Value("Pointer size could not be determined".into())),
                        };
                    }
                    size
                }
                LF_PROCEDURE => {
                    return Err(PErr::Value("LF_PROCEDURE size could not be identified".into()));
                }
                other => {
                    return Err(PErr::Value(format!(
                        "Unable to determine size of leaf_type {other:#x}"
                    )));
                }
            }
        };
        if result <= 0 {
            return Err(PErr::Value(format!("Invalid size identified: {index}")));
        }
        Ok(result)
    }

    /// python `replace_forward_references` for one `ForwardArrayCount`.
    fn array_count(&self, size: i64, element_type: i64) -> PResult<i64> {
        let mut e = element_type;
        let mut guard = 0usize;
        loop {
            if e > 0x1000 {
                let t = self.ty(e)?;
                match nonempty(t.name) {
                    None if t.leaf == LF_MODIFIER => {
                        guard += 1;
                        if guard > self.types.len() {
                            return Err(PErr::Other("modifier loop in array element type".into()));
                        }
                        e = self.u32m(t.obj)?;
                        continue;
                    }
                    Some(n) => {
                        let key = self.names.get(n);
                        e = *self.refs.get(key).ok_or_else(|| key_error("type reference"))? as i64 + 0x1000;
                    }
                    None => {}
                }
            }
            break;
        }
        Ok(size.div_euclid(self.get_size(e, 0)?))
    }

    fn write_base_ref(&mut self, prim: u8, depth: usize) {
        let w = &mut self.rendered;
        let mut f = w.begin_obj();
        w.key(&mut f, depth, "kind");
        w.str("base");
        w.key(&mut f, depth, "name");
        w.str(BASES[prim as usize].name);
        w.end_obj(f, depth);
    }

    fn write_named(&mut self, kind: &str, name: Name, depth: usize) {
        let w = &mut self.rendered;
        let mut f = w.begin_obj();
        w.key(&mut f, depth, "kind");
        w.str(kind);
        w.key(&mut f, depth, "name");
        w.str_latin1(self.names.get(name));
        w.end_obj(f, depth);
    }

    /// python `get_type_from_index`, rendering the resulting JSON value (an object at nesting
    /// level `depth`) into `self.rendered`, with the same side effects on the base types.
    fn render(&mut self, index: i64, depth: usize, rd: u32, soft: &mut Option<PErr>) -> PResult<()> {
        if rd > MAX_DEPTH {
            return Err(recursion_error());
        }
        if index < 0x1000 {
            let prim = prim_id(index & 0xff).ok_or_else(|| key_error(index & 0xff))?;
            self.bases |= 1 << prim;
            let ind = index & 0xf00;
            if ind == 0 {
                self.write_base_ref(prim, depth);
                return Ok(());
            }
            let pid = ind_id(ind).ok_or_else(|| key_error(ind))?;
            let mut f = self.rendered.begin_obj();
            if self.ptr_size != Some(BASES[pid as usize].size) {
                self.bases |= 1 << pid;
                self.rendered.key(&mut f, depth, "base");
                self.rendered.str(BASES[pid as usize].name);
            }
            self.rendered.key(&mut f, depth, "kind");
            self.rendered.str("pointer");
            self.rendered.key(&mut f, depth, "subtype");
            self.write_base_ref(prim, depth + 1);
            self.rendered.end_obj(f, depth);
            return Ok(());
        }
        let t = *self.ty(index)?;
        match t.leaf {
            LF_MODIFIER => {
                let sub = self.u32m(t.obj)?;
                self.render(sub, depth, rd + 1, soft)
            }
            LF_ARRAY | LF_ARRAY_ST | LF_STRIDED_ARRAY => {
                let elem = self.u32m(t.obj)?;
                let count = match self.array_count(t.ext, elem) {
                    Ok(c) => c,
                    Err(e) => {
                        soft.get_or_insert(e);
                        0
                    }
                };
                let mut f = self.rendered.begin_obj();
                self.rendered.key(&mut f, depth, "count");
                self.rendered.int(count);
                self.rendered.key(&mut f, depth, "kind");
                self.rendered.str("array");
                self.rendered.key(&mut f, depth, "subtype");
                self.render(elem, depth + 1, rd + 1, soft)?;
                self.rendered.end_obj(f, depth);
                Ok(())
            }
            LF_BITFIELD => {
                let underlying = self.u32m(t.obj)?;
                let length = self.s.u8(self.s.m(t.obj + 4))?;
                let position = self.s.u8(self.s.m(t.obj + 5))?;
                let mut f = self.rendered.begin_obj();
                self.rendered.key(&mut f, depth, "bit_length");
                self.rendered.int(length as i64);
                self.rendered.key(&mut f, depth, "bit_position");
                self.rendered.int(position as i64);
                self.rendered.key(&mut f, depth, "kind");
                self.rendered.str("bitfield");
                self.rendered.key(&mut f, depth, "type");
                self.render(underlying, depth + 1, rd + 1, soft)?;
                self.rendered.end_obj(f, depth);
                Ok(())
            }
            LF_POINTER => {
                let size = self.get_size(index, rd + 1)?;
                match self.ptr_size {
                    None => {
                        self.ptr_size = Some(size);
                        self.bases |= 1 << POINTER;
                    }
                    Some(p) if p != size => {
                        return Err(PErr::Value("Native pointers with different sizes!".into()));
                    }
                    _ => {}
                }
                let sub = self.u32m(t.obj)?;
                let mut f = self.rendered.begin_obj();
                self.rendered.key(&mut f, depth, "kind");
                self.rendered.str("pointer");
                self.rendered.key(&mut f, depth, "subtype");
                self.render(sub, depth + 1, rd + 1, soft)?;
                self.rendered.end_obj(f, depth);
                Ok(())
            }
            LF_PROCEDURE => {
                let mut f = self.rendered.begin_obj();
                self.rendered.key(&mut f, depth, "kind");
                self.rendered.str("function");
                self.rendered.end_obj(f, depth);
                Ok(())
            }
            LF_UNION => {
                self.write_named("union", t.name.unwrap_or(Name::EMPTY), depth);
                Ok(())
            }
            LF_ENUM => {
                self.write_named("enum", t.name.unwrap_or(Name::EMPTY), depth);
                Ok(())
            }
            LF_FIELDLIST => {
                // The raw field list itself: json.dumps can only serialise it when empty.
                if t.list.1 > t.list.0 {
                    soft.get_or_insert(PErr::Other(
                        "TypeError: Object of type StructType is not JSON serializable".into(),
                    ));
                }
                self.rendered.buf.extend_from_slice(b"[]");
                Ok(())
            }
            _ => match nonempty(t.name) {
                Some(n) => {
                    self.write_named("struct", n, depth);
                    Ok(())
                }
                None => Err(PErr::Value("No name for structure that should be named".into())),
            },
        }
    }

    /// Resolves (once per `(index, pointer state)`) the type of a structure member.
    fn member_type(&mut self, index: i64) -> PResult<u32> {
        let key = (index as usize) * 2 + self.ptr_size.is_some() as usize;
        if let Some(&e) = self.cache.get(key)
            && e != 0
        {
            return Ok(e - 1);
        }
        let start = self.rendered.buf.len();
        let mut soft = None;
        self.render(index, TYPE_DEPTH, 0, &mut soft)?;
        let id = self.entries.len() as u32;
        let soft = match soft {
            Some(e) => {
                self.soft.push(e);
                (self.soft.len() - 1) as u32
            }
            None => NO_SOFT,
        };
        self.entries.push(Entry { start: start as u32, end: self.rendered.buf.len() as u32, soft });
        if let Some(slot) = self.cache.get_mut(key) {
            *slot = id + 1;
        }
        Ok(id)
    }

    /// python `convert_fields`.
    fn convert_fields(&mut self, fields: i64) -> PResult<(u32, u32)> {
        let len = self.types.len() as i64;
        let idx = if fields < 0 { fields + len } else { fields };
        if idx < 0 || idx >= len {
            return Err(index_error());
        }
        let t = self.types[idx as usize];
        let start = self.fields.len() as u32;
        if t.h != H::FieldList {
            // python: "Fields structure did not contain a list of fields" (warning only)
            return Ok((start, start));
        }
        for k in t.list.0..t.list.1 {
            let sub = self.subs[k as usize];
            if sub.h != H::Member {
                return Err(PErr::Other("AttributeError: field has no offset".into()));
            }
            let ft = self.u32m(sub.obj + 2)?;
            let entry = self.member_type(ft)?;
            self.fields.push(Field { name: sub.name.unwrap_or(Name::EMPTY), offset: sub.ext, entry });
        }
        Ok((start, self.fields.len() as u32))
    }

    /// `get_type_from_index(value.subtype_index)` of an enumeration, reduced to what the
    /// converter uses (`base["name"]`) plus its side effects.
    fn enum_base(&mut self, mut index: i64) -> PResult<BaseRef> {
        for _ in 0..=MAX_DEPTH {
            if index < 0x1000 {
                let prim = prim_id(index & 0xff).ok_or_else(|| key_error(index & 0xff))?;
                self.bases |= 1 << prim;
                if index & 0xf00 != 0 {
                    return Err(key_error("name"));
                }
                return Ok(BaseRef::Prim(prim));
            }
            let t = self.ty(index)?;
            match t.leaf {
                LF_MODIFIER => index = self.u32m(t.obj)?,
                LF_UNION | LF_ENUM => return Ok(BaseRef::Named(t.name.unwrap_or(Name::EMPTY))),
                LF_FIELDLIST => {
                    return Err(PErr::Value("Invalid base type returned for Enumeration".into()));
                }
                LF_ARRAY | LF_ARRAY_ST | LF_STRIDED_ARRAY | LF_BITFIELD | LF_POINTER
                | LF_PROCEDURE => return Err(key_error("name")),
                _ => {
                    return match nonempty(t.name) {
                        Some(n) => Ok(BaseRef::Named(n)),
                        None => Err(PErr::Value("No name for structure that should be named".into())),
                    };
                }
            }
        }
        Err(recursion_error())
    }

    /// `get_type_from_index(value.fields)` of an enumeration: must end up at a field list.
    fn enum_list(&self, mut index: i64) -> PResult<usize> {
        for _ in 0..=MAX_DEPTH {
            if index < 0x1000 {
                return Err(PErr::Value("Enumeration fields type not a list".into()));
            }
            let t = self.ty(index)?;
            match t.leaf {
                LF_MODIFIER => index = self.u32m(t.obj)?,
                LF_FIELDLIST => return Ok((index - 0x1000) as usize),
                _ => return Err(PErr::Value("Enumeration fields type not a list".into())),
            }
        }
        Err(recursion_error())
    }

    /// python `process_types`.
    fn process(&mut self) -> PResult<()> {
        for i in 0..self.types.len() {
            let t = self.types[i];
            match t.leaf {
                LF_CLASS | LF_CLASS_ST | LF_STRUCTURE | LF_STRUCTURE_ST | LF_INTERFACE
                | LF_CLASS_VS19 | LF_STRUCTURE_VS19 => {
                    if self.fwd(&t)? {
                        continue;
                    }
                    let Some(name) = nonempty(t.name) else { continue };
                    let fields = self.u32m(t.obj + 4)? - 0x1000;
                    let fields = self.convert_fields(fields)?;
                    self.user.push(UserType { name, union: false, size: t.ext, fields });
                }
                LF_UNION => {
                    if self.fwd(&t)? {
                        continue;
                    }
                    let Some(name) = nonempty(t.name) else { continue };
                    let size = self.s.u16(self.s.m(t.obj + 8))? as i64;
                    let fields = self.u32m(t.obj + 4)? - 0x1000;
                    let fields = self.convert_fields(fields)?;
                    self.user.push(UserType { name, union: true, size, fields });
                }
                LF_ENUM => {
                    if self.fwd(&t)? {
                        continue;
                    }
                    let Some(name) = nonempty(t.name) else { continue };
                    let subtype = self.u32m(t.obj + 4)?;
                    let base = self.enum_base(subtype)?;
                    let list = self.enum_list(self.u32m(t.obj + 8)?)?;
                    let size = self.get_size(subtype, 0)?;
                    let l = self.types[list].list;
                    let start = self.consts.len() as u32;
                    for k in l.0..l.1 {
                        let sub = self.subs[k as usize];
                        if sub.h != H::Enumerate {
                            return Err(PErr::Other("AttributeError: enumerate has no value".into()));
                        }
                        self.consts.push((sub.name.unwrap_or(Name::EMPTY), sub.ext));
                    }
                    self.enums.push(EnumDef { name, base, size, consts: (start, self.consts.len() as u32) });
                }
                _ => {}
            }
        }
        Ok(())
    }
}

// ---- DBI / sections / symbols ----

struct Dbi<'a> {
    stream: Paged<'a>,
    /// `VirtualAddress` of every section header (None: unreadable, python raises on access).
    section_vas: Vec<Option<u32>>,
    num_sections: usize,
    omap: Vec<(u32, u32)>,
}

impl<'a> Dbi<'a> {
    /// python `read_dbi_stream`.
    fn read(msf: &Msf<'a>) -> PResult<Dbi<'a>> {
        let stream = msf.paged(3).ok_or_else(|| PErr::Value("No DBI stream available".into()))?;
        let s = &stream;
        let u = |o: u64| -> PResult<u64> { Ok(s.u32(s.m(o))? as u64) };
        let dbg = 64 + u(24)? + u(28)? + u(32)? + u(36)? + u(40)? + u(52)?;
        let sn = |o: u64| -> PResult<i64> { Ok(s.i16(s.m(dbg + o))? as i64) };
        let paged_or_key_error =
            |n: i64| -> PResult<Paged<'a>> { msf.paged(n).ok_or_else(|| key_error(format!("stream{n}"))) };
        let orig = sn(20)?;
        let (omap_from, hdr) = if orig != -1 { (sn(8)?, -1) } else { (-1, sn(10)?) };
        let mut dbi = Dbi { stream, section_vas: Vec::new(), num_sections: 0, omap: Vec::new() };
        let vas = |sec: &Paged| -> Vec<Option<u32>> {
            let n = sec.size.div_ceil(40);
            (0..n).map(|i| sec.u32(sec.m(i * 40 + 12)).ok()).collect()
        };
        if orig != -1 {
            let sec = paged_or_key_error(orig)?;
            dbi.section_vas = vas(&sec);
            dbi.num_sections = dbi.section_vas.len();
            if omap_from != -1 {
                let om = msf.stream(omap_from)?.ok_or_else(|| key_error(format!("stream{omap_from}")))?;
                let data = om.read(0, om.size)?;
                let le = |b: &[u8]| b.iter().rev().fold(0u32, |a, &x| (a << 8) | x as u32);
                dbi.omap = data
                    .chunks(8)
                    .map(|c| (le(&c[..c.len().min(4)]), le(if c.len() > 4 { &c[4..] } else { &[] })))
                    .collect();
            }
        } else {
            if hdr != -1 {
                let sec = paged_or_key_error(hdr)?;
                dbi.section_vas = vas(&sec);
                dbi.num_sections = dbi.section_vas.len();
            }
        }
        Ok(dbi)
    }

    fn u32(&self, off: u64) -> PResult<u32> {
        self.stream.u32(self.stream.m(off))
    }

    /// `self._sections[i].VirtualAddress` (python list indexing, `i >= -1`).
    fn section_va(&self, i: i64) -> PResult<i64> {
        let i = if i < 0 { i + self.num_sections as i64 } else { i };
        if i < 0 || i as usize >= self.num_sections {
            return Err(index_error());
        }
        match self.section_vas[i as usize] {
            Some(va) => Ok(va as i64),
            None => Err(PErr::Invalid(i as u64 * 40 + 12)),
        }
    }

    /// python `omap_lookup`.
    fn omap_lookup(&self, address: i64) -> PResult<i64> {
        let m = &self.omap;
        // bisect_right(m, (address, -1)): (address, -1) < (s, t) <=> address <= s  (t >= 0)
        let (mut lo, mut hi) = (0usize, m.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            if address <= m[mid].0 as i64 { hi = mid } else { lo = mid + 1 }
        }
        let mut pos = lo as i64;
        if pos as usize >= m.len() {
            return Err(index_error());
        }
        if m[pos as usize].0 as i64 > address {
            pos -= 1;
        }
        let e = if pos < 0 { m[m.len() - 1] } else { m[pos as usize] };
        if e.1 == 0 {
            return Ok(0);
        }
        Ok(e.1 as i64 + (address - e.0 as i64))
    }
}

#[inline]
fn py_isnumeric(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&c| c.is_ascii_digit() || matches!(c, 0xb2 | 0xb3 | 0xb9 | 0xbc | 0xbd | 0xbe))
}

/// python `name_strip`, returning a sub-range `(start, len)` of `name`.
fn name_strip(name: &[u8]) -> PResult<(usize, usize)> {
    let skip = matches!(name.first(), Some(b'_' | b'@' | 0x7f)) as usize;
    let new = &name[skip..];
    let Some(at) = find_byte(new, b'@') else { return Ok((skip, new.len())) };
    let (a, bb) = (&new[..at], &new[at + 1..]);
    if find_byte(bb, b'@').is_some() {
        // three or more parts: keep the stripped name
        return Ok((skip, new.len()));
    }
    if py_isnumeric(bb) {
        let Some(&first) = a.first() else {
            return Err(PErr::Other("IndexError: string index out of range".into()));
        };
        if first != b'?' {
            return Ok((skip, a.len()));
        }
    }
    Ok((0, name.len()))
}

/// A public symbol: its full (linkage) name is `arena[off..off + len]`, the stripped name
/// `arena[off + st..off + st + slen]`.
struct Sym {
    off: u32,
    len: u32,
    st: u32,
    slen: u32,
    addr: i64,
}

/// Parsed symbols, their names copied into a compact arena (good locality for sorting and
/// writing), and the output order.
struct SymTable {
    arena: Vec<u8>,
    syms: Vec<Sym>,
    order: Vec<u32>,
}

impl SymTable {
    #[inline]
    fn stripped(&self, s: &Sym) -> &[u8] {
        &self.arena[(s.off + s.st) as usize..(s.off + s.st + s.slen) as usize]
    }
    #[inline]
    fn full(&self, s: &Sym) -> &[u8] {
        &self.arena[s.off as usize..(s.off + s.len) as usize]
    }
}

/// python `read_symbol_stream` (+ sorting the resulting dict's keys).
fn read_symbols(dbi: &Dbi, sym: &Stream) -> PResult<SymTable> {
    let s = sym;
    let n_sections = dbi.num_sections as i64;
    let mut syms = Vec::with_capacity((s.size / 48) as usize);
    let mut arena = Vec::with_capacity((s.size / 2) as usize);
    let max = s.size;
    let mut off = 0u64;
    while off < max {
        let length = s.u16(s.m(off))? as i64;
        let leaf = s.u16(s.m(off + 2))?;
        let segment = s.u16(s.m(off + 12))? as i64;
        if segment < n_sections && matches!(leaf, 0x1009 | 0x110e | 0x1127) {
            let name = parse_string(s, s.m(off + 14), leaf == 0x1009, length - 14 + 2)?;
            let mut address = dbi.section_va(segment - 1)? + s.u32(s.m(off + 8))? as i64;
            if !name.is_empty() {
                if !dbi.omap.is_empty() {
                    address = dbi.omap_lookup(address)?;
                }
                let nb = &s.bytes()[name.0 as usize..(name.0 + name.1) as usize];
                let (st, slen) = name_strip(nb)?;
                let a = arena.len() as u32;
                arena.extend_from_slice(nb);
                syms.push(Sym { off: a, len: nb.len() as u32, st: st as u32, slen: slen as u32, addr: address });
            }
        }
        off += length as u64 + 2;
    }
    let mut table = SymTable { arena, syms, order: Vec::new() };
    // compact (start, len) keys: the sort touches 8 bytes per symbol instead of a whole Sym
    let keys: Vec<(u32, u32)> = table.syms.iter().map(|s| (s.off + s.st, s.slen)).collect();
    let arena = &table.arena;
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(4);
    table.order = sort_last_par(
        keys.len(),
        |i| {
            let (a, l) = keys[i];
            &arena[a as usize..(a + l) as usize]
        },
        threads,
    )
    .ok_or_else(|| PErr::Other("symbol sort thread panicked".into()))?;
    Ok(table)
}

// ---- entry point ----

/// The `database` value of the metadata.
pub(crate) enum DbName<'n> {
    Given(&'n str),
    FromIpi,
}

/// The `metadata` block values.
struct Meta<'m> {
    datetime: &'m str,
    version: &'m str,
    guid: [u8; 16],
    age: u32,
    given: Option<&'m str>,
    ipi_name: Option<Vec<u8>>,
    machine: u16,
}

/// python `PdbReader(ctx, location, database_name).get_json()` followed by
/// `json.dumps(..., indent=2, sort_keys=True)`.
///
/// The symbol stream (independent of the type stream) is parsed and sorted on a second
/// thread while this one parses and processes the types; everything is then written once,
/// straight into a single pre-sized output buffer.
pub(crate) fn convert(pdb: &[u8], database: DbName, datetime: &str, version: &str) -> PResult<Vec<u8>> {
    let timing = cfg!(test) && std::env::var_os("RSVOL_PDB_TIMING").is_some();
    let t0 = std::time::Instant::now();
    let phase = |name: &str| {
        if timing {
            eprintln!("  {name:>10}: {:?}", t0.elapsed());
        }
    };
    let msf = Msf::open(pdb)?;
    phase("msf");

    // read_pdb_info_stream: DBI first, then the IPI (only without a database name)
    let dbi = Dbi::read(&msf)?;
    phase("dbi");
    let mut ipi_name: Option<Vec<u8>> = None;
    let given = match database {
        DbName::Given(n) => Some(n),
        DbName::FromIpi => {
            ipi_name = read_ipi_database_name(&msf)?;
            None
        }
    };
    let info = msf.paged(1).ok_or_else(|| PErr::Value("No PDB Info Stream available".into()))?;
    let guid_off = info.m(12);
    let mut guid = [0u8; 16];
    for (i, x) in guid.iter_mut().enumerate() {
        *x = info.u8(info.m(guid_off + i as u64))?;
    }
    let meta = Meta {
        datetime,
        version,
        guid,
        age: dbi.u32(8)?,
        given,
        ipi_name,
        machine: dbi.stream.u16(dbi.stream.m(58))?,
    };
    let tpi = msf.stream(2)?.ok_or_else(|| PErr::Value("No TPI stream available".into()))?;
    phase("ipi+info");

    // read_symbol_stream
    let sym_work = || -> PResult<SymTable> {
        let symrec_n = dbi.stream.u16(dbi.stream.m(20))? as i64;
        let symrec = msf.stream(symrec_n)?.ok_or_else(|| PErr::Value("No SymRec stream available".into()))?;
        let t = read_symbols(&dbi, &symrec)?;
        phase("symbols");
        Ok(t)
    };
    let sequential = cfg!(test) && std::env::var_os("RSVOL_PDB_SEQ").is_some();
    if sequential {
        return types_and_output(&tpi, &meta, sym_work, &phase);
    }
    std::thread::scope(|scope| {
        let job = std::cell::Cell::new(Some(scope.spawn(sym_work)));
        let join = || match job.take() {
            Some(j) => j.join().unwrap_or_else(|_| Err(PErr::Other("symbol thread panicked".into()))),
            None => Err(PErr::Other("symbol thread already joined".into())),
        };
        let r = types_and_output(&tpi, &meta, join, &phase);
        // always join (an unjoined panicked scoped thread would make `scope` panic)
        if let Some(j) = job.take() {
            let _ = j.join();
        }
        r
    })
}

/// read_tpi_stream + process_types, then the whole JSON document (`get_syms` supplies the
/// symbols once the types are done: python reads the TPI first, so its errors win).
fn types_and_output(
    tpi: &Stream,
    meta: &Meta,
    get_syms: impl FnOnce() -> PResult<SymTable>,
    phase: &dyn Fn(&str),
) -> PResult<Vec<u8>> {
    let Info { types, subs, syn } = read_info_stream(tpi, "TPI", true)?;
    phase("tpi");
    let names = Names { data: tpi.bytes(), syn: &syn };
    let mut refs: FxMap<&[u8], u32> = FxMap::default();
    refs.reserve(types.len() / 4);
    for (i, t) in types.iter().enumerate() {
        if let Some(n) = nonempty(t.name) {
            refs.insert(names.get(n), i as u32);
        }
    }
    let mut conv = Conv {
        s: tpi,
        types: &types,
        subs: &subs,
        names,
        refs,
        bases: 0,
        ptr_size: None,
        cache: vec![0u32; (types.len() + 0x1000) * 2],
        entries: Vec::new(),
        rendered: JsonWriter::with_capacity(1 << 20),
        soft: Vec::new(),
        fields: Vec::new(),
        consts: Vec::new(),
        user: Vec::new(),
        enums: Vec::new(),
    };
    conv.process()?;
    phase("process");
    let syms = get_syms()?;
    phase("joined");

    // generous size estimate: untouched capacity costs nothing
    let field_bytes: usize = conv
        .fields
        .iter()
        .map(|f| {
            let e = &conv.entries[f.entry as usize];
            (e.end - e.start) as usize + 64 + 6 * (f.name.1 & !SYN) as usize
        })
        .sum();
    let est = (1 << 16)
        + (conv.consts.len() * 48 + conv.enums.len() * 128)
            + (syms.syms.len() * 72 + syms.arena.len() * 12)
            + (conv.user.len() * 128 + field_bytes);
    let mut w = JsonWriter::with_capacity(est);
    let mut sb = SortBuf::default();

    w.buf.extend_from_slice(b"{\n  \"base_types\": ");
    write_base_types(&conv, &mut w);
    w.buf.extend_from_slice(b",\n  \"enums\": ");
    write_enums(&conv, &mut w, &mut sb);
    w.buf.extend_from_slice(b",\n  \"metadata\": ");
    write_metadata(meta, &mut w);
    w.buf.extend_from_slice(b",\n  \"symbols\": ");
    write_symbols(&syms, &mut w);
    phase("json-syms");
    w.buf.extend_from_slice(b",\n  \"user_types\": ");
    write_user_types(&mut conv, &mut w, &mut sb)?;
    w.buf.extend_from_slice(b"\n}");
    phase("json");
    Ok(w.buf)
}

fn write_base_types(conv: &Conv, w: &mut JsonWriter) {
    let mut ids: Vec<usize> = (0..BASES.len()).filter(|&i| conv.bases & (1 << i) != 0).collect();
    ids.sort_by_key(|&i| BASES[i].name);
    let mut f = w.begin_obj();
    for i in ids {
        let d = &BASES[i];
        w.key(&mut f, 1, d.name);
        w.buf.extend_from_slice(b"{\n      \"endian\": \"little\",\n      \"kind\": ");
        w.str(d.kind);
        w.buf.extend_from_slice(b",\n      \"signed\": ");
        w.boolean(d.signed);
        w.buf.extend_from_slice(b",\n      \"size\": ");
        w.int(if i == POINTER as usize { conv.ptr_size.unwrap_or(0) } else { d.size });
        w.buf.extend_from_slice(b"\n    }");
    }
    w.end_obj(f, 1);
}

fn write_enums(conv: &Conv, w: &mut JsonWriter, sb: &mut SortBuf) {
    sort_last(sb, conv.enums.len(), |i| conv.names.get(conv.enums[i].name));
    let order = std::mem::take(&mut sb.order);
    let mut f = w.begin_obj();
    for &i in &order {
        let e = &conv.enums[i as usize];
        w.key_latin1(&mut f, 1, conv.names.get(e.name));
        w.buf.extend_from_slice(b"{\n      \"base\": ");
        match e.base {
            BaseRef::Prim(p) => w.str(BASES[p as usize].name),
            BaseRef::Named(n) => w.str_latin1(conv.names.get(n)),
        }
        w.buf.extend_from_slice(b",\n      \"constants\": ");
        let consts = &conv.consts[e.consts.0 as usize..e.consts.1 as usize];
        sort_last(sb, consts.len(), |k| conv.names.get(consts[k].0));
        let mut c = w.begin_obj();
        for &k in &sb.order {
            w.key_latin1(&mut c, 3, conv.names.get(consts[k as usize].0));
            w.int(consts[k as usize].1);
        }
        w.end_obj(c, 3);
        w.buf.extend_from_slice(b",\n      \"size\": ");
        w.int(e.size);
        w.buf.extend_from_slice(b"\n    }");
    }
    w.end_obj(f, 1);
}

fn write_metadata(m: &Meta, w: &mut JsonWriter) {
    w.buf.extend_from_slice(b"{\n    \"format\": \"6.1.0\",\n    \"producer\": {\n      \"datetime\": ");
    w.str(m.datetime);
    w.buf.extend_from_slice(b",\n      \"name\": \"volatility3\",\n      \"version\": ");
    w.str(m.version);
    w.buf.extend_from_slice(b"\n    },\n    \"windows\": {\n      \"pdb\": {\n        \"GUID\": \"");
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for i in [3usize, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15] {
        w.buf.push(HEX[(m.guid[i] >> 4) as usize]);
        w.buf.push(HEX[(m.guid[i] & 15) as usize]);
    }
    w.buf.extend_from_slice(b"\",\n        \"age\": ");
    w.int(m.age as i64);
    w.buf.extend_from_slice(b",\n        \"database\": ");
    match (m.given, &m.ipi_name) {
        (Some(n), _) if !n.is_empty() => w.str(n),
        (None, Some(n)) if !n.is_empty() => w.str_latin1(n),
        _ => w.str("unknown.pdb"),
    }
    w.buf.extend_from_slice(b",\n        \"machine_type\": ");
    w.int(m.machine as i64);
    w.buf.extend_from_slice(b"\n      }\n    }\n  }");
}

fn write_symbols(t: &SymTable, w: &mut JsonWriter) {
    if t.order.is_empty() {
        w.buf.extend_from_slice(b"{}");
        return;
    }
    w.buf.push(b'{');
    for (k, &i) in t.order.iter().enumerate() {
        let sy = &t.syms[i as usize];
        w.buf.extend_from_slice(if k == 0 { b"\n    " } else { b",\n    " });
        w.str_latin1(t.stripped(sy));
        w.buf.extend_from_slice(b": {\n      \"address\": ");
        w.int(sy.addr);
        if sy.st != 0 || sy.slen != sy.len {
            w.buf.extend_from_slice(b",\n      \"linkage_name\": ");
            w.str_latin1(t.full(sy));
        }
        w.buf.extend_from_slice(b"\n    }");
    }
    w.buf.extend_from_slice(b"\n  }");
}

fn write_user_types(conv: &mut Conv, w: &mut JsonWriter, sb: &mut SortBuf) -> PResult<()> {
    sort_last(sb, conv.user.len(), |i| conv.names.get(conv.user[i].name));
    let order = std::mem::take(&mut sb.order);
    let mut f = w.begin_obj();
    for &i in &order {
        let u = &conv.user[i as usize];
        w.key_latin1(&mut f, 1, conv.names.get(u.name));
        w.buf.extend_from_slice(b"{\n      \"fields\": ");
        let fields = &conv.fields[u.fields.0 as usize..u.fields.1 as usize];
        sort_last(sb, fields.len(), |k| conv.names.get(fields[k].name));
        if sb.order.is_empty() {
            w.buf.extend_from_slice(b"{}");
        } else {
            w.buf.push(b'{');
            for (n, &k) in sb.order.iter().enumerate() {
                let fd = &fields[k as usize];
                let e = &conv.entries[fd.entry as usize];
                if e.soft != NO_SOFT {
                    return Err(conv.soft.swap_remove(e.soft as usize));
                }
                w.buf.extend_from_slice(if n == 0 { b"\n        " } else { b",\n        " });
                w.str_latin1(conv.names.get(fd.name));
                w.buf.extend_from_slice(b": {\n          \"offset\": ");
                w.int(fd.offset);
                w.buf.extend_from_slice(b",\n          \"type\": ");
                w.buf.extend_from_slice(&conv.rendered.buf[e.start as usize..e.end as usize]);
                w.buf.extend_from_slice(b"\n        }");
            }
            w.buf.extend_from_slice(b"\n      }");
        }
        w.buf.extend_from_slice(if u.union {
            b",\n      \"kind\": \"union\",\n      \"size\": "
        } else {
            b",\n      \"kind\": \"struct\",\n      \"size\": "
        });
        w.int(u.size);
        w.buf.extend_from_slice(b"\n    }");
    }
    w.end_obj(f, 1);
    Ok(())
}

/// Sort scratch space reused across the many small sorts.
#[derive(Default)]
struct SortBuf {
    keys: Vec<u128>,
    order: Vec<u32>,
}

/// Fills `sb.order` with the indices `0..n` sorted by `key` (bytes), keeping only the last
/// index of every key (python dict assignment semantics + `sort_keys=True`).
fn sort_last<'n>(sb: &mut SortBuf, n: usize, key: impl Fn(usize) -> &'n [u8]) {
    sort_last_ids(sb, n, None, key)
}

/// [`sort_last`] over the indices `ids` (increasing) instead of `0..n`.
fn sort_last_ids<'n>(sb: &mut SortBuf, n: usize, ids: Option<&[u32]>, key: impl Fn(usize) -> &'n [u8]) {
    // MSD refinement over 8-byte big-endian chunks of the names: every level sorts packed
    // `(chunk << 64) | index` integers, and only runs sharing a chunk descend to the next
    // chunk. Names never contain NUL, so zero padding preserves the byte order, and a run
    // whose names all end within the current chunk consists of identical names: python's
    // dict keeps the last assignment, i.e. the highest index.
    #[inline]
    fn chunk(s: &[u8], depth: usize) -> u64 {
        let start = depth * 8;
        if s.len() >= start + 8 {
            u64::from_be_bytes(s[start..start + 8].try_into().unwrap())
        } else {
            let mut b = [0u8; 8];
            if s.len() > start {
                b[..s.len() - start].copy_from_slice(&s[start..]);
            }
            u64::from_be_bytes(b)
        }
    }
    fn refine<'n>(v: &mut [u128], depth: usize, key: &impl Fn(usize) -> &'n [u8], out: &mut Vec<u32>) {
        if !v.is_sorted() {
            v.sort_unstable();
        }
        let mut i = 0;
        while i < v.len() {
            let c = v[i] >> 64;
            let mut j = i + 1;
            while j < v.len() && v[j] >> 64 == c {
                j += 1;
            }
            if j - i == 1 {
                out.push(v[i] as u64 as u32);
            } else if v[i..j].iter().all(|&x| key(x as u64 as usize).len() <= (depth + 1) * 8) {
                out.push(v[j - 1] as u64 as u32);
            } else if depth >= 64 {
                // pathological shared prefixes: finish with a comparison sort
                let run = &mut v[i..j];
                run.sort_unstable_by(|a, b| key(*a as u64 as usize).cmp(key(*b as u64 as usize)).then(a.cmp(b)));
                for k in 0..run.len() {
                    let cur = run[k] as u64 as usize;
                    if k + 1 < run.len() && key(run[k + 1] as u64 as usize) == key(cur) {
                        continue;
                    }
                    out.push(cur as u32);
                }
            } else {
                for x in &mut v[i..j] {
                    let idx = *x as u64;
                    *x = ((chunk(key(idx as usize), depth + 1) as u128) << 64) | idx as u128;
                }
                refine(&mut v[i..j], depth + 1, key, out);
            }
            i = j;
        }
    }
    let v = &mut sb.keys;
    v.clear();
    match ids {
        Some(ids) => v.extend(ids.iter().map(|&i| ((chunk(key(i as usize), 0) as u128) << 64) | i as u128)),
        None => v.extend((0..n).map(|i| ((chunk(key(i), 0) as u128) << 64) | i as u128)),
    }
    sb.order.clear();
    refine(v, 0, &key, &mut sb.order);
}

/// [`sort_last`] for large inputs: indices are bucketed by first byte (a stable counting
/// pass), contiguous bucket ranges are sorted on up to `threads` threads, and the results
/// are concatenated in bucket order.
fn sort_last_par<'n>(n: usize, key: impl Fn(usize) -> &'n [u8] + Sync, threads: usize) -> Option<Vec<u32>> {
    if n < 16384 || threads <= 1 {
        let mut sb = SortBuf::default();
        sort_last(&mut sb, n, &key);
        return Some(sb.order);
    }
    // bucket 0: empty names (they sort first), 1 + b: names starting with byte b
    let bucket = |i: usize| key(i).first().map_or(0, |&b| b as usize + 1);
    let mut start = [0usize; 258];
    for i in 0..n {
        start[bucket(i) + 1] += 1;
    }
    for b in 0..257 {
        start[b + 1] += start[b];
    }
    let mut fill = start;
    let mut ids = vec![0u32; n];
    for i in 0..n {
        let b = bucket(i);
        ids[fill[b]] = i as u32;
        fill[b] += 1;
    }
    // split into `threads` groups of whole buckets holding ~n/threads ids each
    let mut cuts = vec![0usize];
    for b in 1..=257 {
        let target = n * cuts.len() / threads;
        if start[b] >= target && cuts.len() < threads && start[b] > *cuts.last().unwrap() {
            cuts.push(start[b]);
        }
    }
    cuts.push(n);
    let ids = &ids;
    let key = &key;
    let parts: Option<Vec<Vec<u32>>> = std::thread::scope(|scope| {
        let jobs: Vec<_> = cuts
            .windows(2)
            .skip(1)
            .map(|w| {
                let (a, b) = (w[0], w[1]);
                scope.spawn(move || {
                    let mut sb = SortBuf::default();
                    sort_last_ids(&mut sb, 0, Some(&ids[a..b]), key);
                    sb.order
                })
            })
            .collect();
        let mut sb = SortBuf::default();
        sort_last_ids(&mut sb, 0, Some(&ids[cuts[0]..cuts[1]]), key);
        let mut parts = vec![sb.order];
        // join every helper (an unjoined panicked scoped thread would make `scope` panic)
        let results: Vec<Option<Vec<u32>>> = jobs.into_iter().map(|j| j.join().ok()).collect();
        for r in results {
            parts.push(r?);
        }
        Some(parts)
    });
    let parts = parts?;
    let mut out = Vec::with_capacity(n);
    for p in parts {
        out.extend_from_slice(&p);
    }
    Some(out)
}

/// python `read_ipi_stream`: the last (in first-insertion order) type name ending in ".pdb",
/// stripped of its directory. `ValueError`s leave the name unset.
fn read_ipi_database_name(msf: &Msf) -> PResult<Option<Vec<u8>>> {
    let Some(ipi) = msf.stream(4)? else { return Ok(None) };
    let info = match read_info_stream(&ipi, "IPI", false) {
        Ok(i) => i,
        Err(PErr::Value(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    let names = Names { data: ipi.bytes(), syn: &info.syn };
    let mut seen: FxMap<&[u8], ()> = FxMap::default();
    let mut last: Option<&[u8]> = None;
    for t in &info.types {
        if let Some(n) = nonempty(t.name) {
            let nb = names.get(n);
            if nb.ends_with(b".pdb") && seen.insert(nb, ()).is_none() {
                last = Some(nb);
            }
        }
    }
    Ok(last.map(|n| n.rsplit(|&c| c == b'\\').next().unwrap_or(n).to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_like_python() {
        let s = |n: &str| -> String {
            let (a, l) = name_strip(n.as_bytes()).unwrap();
            n[a..a + l].to_string()
        };
        assert_eq!(s("_foo"), "foo");
        assert_eq!(s("_foo@12"), "foo");
        assert_eq!(s("foo@12"), "foo");
        assert_eq!(s("@foo@12"), "foo");
        assert_eq!(s("_foo@bar"), "_foo@bar");
        assert_eq!(s("?foo@12"), "?foo@12");
        assert_eq!(s("_?foo@12"), "_?foo@12");
        assert_eq!(s("_a@b@c"), "a@b@c");
        assert_eq!(s("\x7fX_NULL_THUNK"), "X_NULL_THUNK");
        assert_eq!(s("_x@"), "_x@");
        assert_eq!(s(""), "");
        assert!(name_strip(b"_@12").is_err());
        assert_eq!(name_strip(b"_a@\xb2").unwrap(), (1, 1));
    }

    #[test]
    fn omap_bisect() {
        let dbi = |omap: Vec<(u32, u32)>| Dbi {
            stream: unreachable_stream(),
            section_vas: Vec::new(),
            num_sections: 0,
            omap,
        };
        let d = dbi(vec![(0x1000, 0x5000), (0x2000, 0), (0x3000, 0x9000)]);
        assert_eq!(d.omap_lookup(0x1000).unwrap(), 0x5000);
        assert_eq!(d.omap_lookup(0x1010).unwrap(), 0x5010);
        assert_eq!(d.omap_lookup(0x2010).unwrap(), 0);
        assert_eq!(d.omap_lookup(0x3000).unwrap(), 0x9000);
        assert!(d.omap_lookup(0x3001).is_err()); // python IndexError
        // before the first entry: python wraps to the last entry
        assert_eq!(d.omap_lookup(0x10).unwrap(), 0x9000 + 0x10 - 0x3000);
    }

    fn unreachable_stream() -> Paged<'static> {
        Paged::test_new()
    }

    /// `RSVOL_PDB=<file.pdb> cargo test --release bench_symbol_stages -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench_symbol_stages() {
        let pdb = std::fs::read(std::env::var("RSVOL_PDB").expect("RSVOL_PDB")).unwrap();
        let msf = Msf::open(&pdb).unwrap();
        let dbi = Dbi::read(&msf).unwrap();
        let n = dbi.stream.u16(dbi.stream.m(20)).unwrap() as i64;
        let best = |f: &mut dyn FnMut()| {
            let mut b = std::time::Duration::MAX;
            for _ in 0..30 {
                let t = std::time::Instant::now();
                f();
                b = b.min(t.elapsed());
            }
            b
        };
        let t_mat = best(&mut || {
            std::hint::black_box(msf.stream(n).unwrap());
        });
        let symrec = msf.stream(n).unwrap().unwrap();
        let t_all = best(&mut || {
            std::hint::black_box(read_symbols(&dbi, &symrec).unwrap());
        });
        let table = read_symbols(&dbi, &symrec).unwrap();
        let keys: Vec<(u32, u32)> = table.syms.iter().map(|s| (s.off + s.st, s.slen)).collect();
        let arena = &table.arena;
        let mut sb = SortBuf::default();
        let t_sort = best(&mut || {
            sort_last(&mut sb, keys.len(), |i| {
                let (a, l) = keys[i];
                &arena[a as usize..(a + l) as usize]
            })
        });
        let seq = sb.order.clone();
        let mut par = Vec::new();
        let t_psort = best(&mut || {
            par = sort_last_par(
                keys.len(),
                |i| {
                    let (a, l) = keys[i];
                    &arena[a as usize..(a + l) as usize]
                },
                4,
            )
            .unwrap();
        });
        assert_eq!(seq, par);
        eprintln!("parallel sort (4 threads) {t_psort:?}");
        let mut w = JsonWriter::with_capacity(8 << 20);
        let t_write = best(&mut || {
            w.buf.clear();
            write_symbols(&table, &mut w);
        });
        eprintln!(
            "materialize {t_mat:?}  parse+sort {t_all:?}  sort {t_sort:?}  write(warm buf) {t_write:?}  ({} syms)",
            table.syms.len()
        );
    }
}
