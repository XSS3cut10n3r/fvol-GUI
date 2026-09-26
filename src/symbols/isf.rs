//! ISF (intermediate symbol format) JSON -> flat symbol table blob.
//! python `symbols/intermed.py` (`IntermediateSymbolTable` and its version delegates).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Version-dependent behaviour (python `_closest_version` picks the delegate):
//!   * `>= 2.1.0` symbols carry types; `>= 4.1.0` symbols carry `constant_data`;
//!   * `>= 4.0.0` natives come from the ISF `base_types`, older files pick the python x86/x64
//!     std-ctypes table whose sizes match (quirks included, e.g. signed `unsigned long long`);
//!   * `>= 6.2.0` anonymous struct/union members are flattened into their parent;
//!   * formats older than 2.0.0 are rejected like python.

use super::table::*;
use crate::error::{Error, Result};
use crate::util::fxhash::{FxHashMap, hash_bytes};
use crate::util::json::{Json, Kind, Parser};
use std::borrow::Cow;

/// A native type definition (python NativeTable entry).
#[derive(Clone, Debug)]
pub struct NativeDef {
    pub name: String,
    pub ty: Ty,
}

/// Build options.
#[derive(Clone, Debug, Default)]
pub struct BuildOptions {
    /// Use these natives instead of the ISF's own (python `native_types=` argument).
    pub natives: Option<Vec<(String, Ty)>>,
}

#[derive(Clone, Debug, Default)]
struct Desc<'a> {
    kind: Cow<'a, str>,
    name: Option<Cow<'a, str>>,
    base: Option<Cow<'a, str>>,
    count: i128,
    bit_position: i128,
    bit_length: i128,
    /// subtype (pointer/array) or type (bitfield)
    sub: Option<u32>,
}

#[derive(Default)]
struct BaseDef<'a> {
    kind: Cow<'a, str>,
    size: Option<i128>,
    length: Option<i128>,
    signed: bool,
    endian: Cow<'a, str>,
}

struct EnumDef<'a> {
    name: Cow<'a, str>,
    base: Cow<'a, str>,
    constants: Vec<(Cow<'a, str>, i128)>,
}

struct FieldDef<'a> {
    name: Cow<'a, str>,
    offset: i128,
    anonymous: bool,
    ty: Option<u32>,
}

struct UserDef<'a> {
    name: Cow<'a, str>,
    kind: Cow<'a, str>,
    size: i128,
    fields: Vec<FieldDef<'a>>,
}

struct SymDef<'a> {
    name: Cow<'a, str>,
    address: i128,
    ty: Option<u32>,
    constant_data: Option<Cow<'a, str>>,
}

#[derive(Default)]
struct Parsed<'a> {
    metadata: Option<Json<'a>>,
    bases: Vec<(Cow<'a, str>, BaseDef<'a>)>,
    enums: Vec<EnumDef<'a>>,
    users: Vec<UserDef<'a>>,
    symbols: Vec<SymDef<'a>>,
    descs: Vec<Desc<'a>>,
    has: [bool; 5],
}

fn parse_desc<'a>(p: &mut Parser<'a>, descs: &mut Vec<Desc<'a>>) -> Result<u32> {
    let mut d = Desc::default();
    p.object(|p, k| {
        match k.as_ref() {
            "kind" => d.kind = p.str()?,
            "name" => d.name = Some(p.str()?),
            "base" => {
                if p.peek_kind()? == Kind::Str {
                    d.base = Some(p.str()?)
                } else {
                    p.skip()?
                }
            }
            "count" => d.count = p.int()?,
            "bit_position" => d.bit_position = p.int()?,
            "bit_length" => d.bit_length = p.int()?,
            "subtype" | "type" => d.sub = Some(parse_desc(p, descs)?),
            _ => p.skip()?,
        }
        Ok(())
    })?;
    descs.push(d);
    Ok(descs.len() as u32 - 1)
}

fn parse<'a>(buf: &'a [u8]) -> Result<Parsed<'a>> {
    let mut p = Parser::new(buf);
    let mut out = Parsed::default();
    p.object(|p, k| {
        match k.as_ref() {
            "metadata" => {
                out.has[0] = true;
                out.metadata = Some(p.value()?);
            }
            "base_types" => {
                out.has[1] = true;
                p.object(|p, name| {
                    let mut b = BaseDef::default();
                    p.object(|p, k| {
                        match k.as_ref() {
                            "kind" => b.kind = p.str()?,
                            "size" => b.size = Some(p.int()?),
                            "length" => b.length = Some(p.int()?),
                            "signed" => b.signed = p.bool()?,
                            "endian" => b.endian = p.str()?,
                            _ => p.skip()?,
                        }
                        Ok(())
                    })?;
                    out.bases.push((name, b));
                    Ok(())
                })?;
            }
            "enums" => {
                out.has[2] = true;
                p.object(|p, name| {
                    let mut e = EnumDef { name, base: Cow::Borrowed(""), constants: Vec::new() };
                    p.object(|p, k| {
                        match k.as_ref() {
                            "base" => e.base = p.str()?,
                            "constants" => p.object(|p, cn| {
                                let v = p.int()?;
                                e.constants.push((cn, v));
                                Ok(())
                            })?,
                            _ => p.skip()?,
                        }
                        Ok(())
                    })?;
                    out.enums.push(e);
                    Ok(())
                })?;
            }
            "user_types" => {
                out.has[3] = true;
                let descs = &mut out.descs;
                let users = &mut out.users;
                p.object(|p, name| {
                    let mut u = UserDef { name, kind: Cow::Borrowed("struct"), size: 0, fields: Vec::new() };
                    let mut size = None;
                    let mut length = None;
                    p.object(|p, k| {
                        match k.as_ref() {
                            "kind" => u.kind = p.str()?,
                            "size" => size = Some(p.int()?),
                            "length" => length = Some(p.int()?),
                            "fields" => {
                                if p.peek_kind()? != Kind::Obj {
                                    p.skip()?;
                                    return Ok(());
                                }
                                p.object(|p, fname| {
                                    let mut f = FieldDef { name: fname, offset: 0, anonymous: false, ty: None };
                                    p.object(|p, k| {
                                        match k.as_ref() {
                                            "offset" => f.offset = p.int()?,
                                            "anonymous" => f.anonymous = p.bool()?,
                                            "type" => f.ty = Some(parse_desc(p, descs)?),
                                            _ => p.skip()?,
                                        }
                                        Ok(())
                                    })?;
                                    u.fields.push(f);
                                    Ok(())
                                })?
                            }
                            _ => p.skip()?,
                        }
                        Ok(())
                    })?;
                    u.size = size.or(length).unwrap_or(0);
                    users.push(u);
                    Ok(())
                })?;
            }
            "symbols" => {
                out.has[4] = true;
                let descs = &mut out.descs;
                let syms = &mut out.symbols;
                p.object(|p, name| {
                    let mut s = SymDef { name, address: 0, ty: None, constant_data: None };
                    if p.peek_kind()? != Kind::Obj {
                        p.skip()?;
                        return Ok(());
                    }
                    p.object(|p, k| {
                        match k.as_ref() {
                            "address" => s.address = p.int()?,
                            "type" => s.ty = Some(parse_desc(p, descs)?),
                            "constant_data" => {
                                if p.peek_kind()? == Kind::Str {
                                    s.constant_data = Some(p.str()?)
                                } else {
                                    p.skip()?
                                }
                            }
                            _ => p.skip()?,
                        }
                        Ok(())
                    })?;
                    syms.push(s);
                    Ok(())
                })?;
            }
            _ => p.skip()?,
        }
        Ok(())
    })?;
    Ok(out)
}

/// python delegate versions: (major, minor, patch)
const HANDLERS: [(u32, u32, u32); 8] = [(0, 0, 1), (2, 0, 0), (2, 1, 0), (4, 0, 0), (4, 1, 0), (6, 0, 0), (6, 1, 0), (6, 2, 0)];

/// python `_closest_version`.
pub fn closest_version(format: &str) -> Result<(u32, u32, u32)> {
    let parts: Vec<&str> = format.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::msg(format!("Invalid ISF format version: {format}")));
    }
    let v: Vec<u32> = parts.iter().map(|x| x.trim().parse::<u32>()).collect::<std::result::Result<_, _>>().map_err(|_| Error::msg(format!("Invalid ISF format version: {format}")))?;
    HANDLERS
        .iter()
        .filter(|h| h.0 == v[0] && h.1 >= v[1])
        .max()
        .copied()
        .ok_or_else(|| Error::msg(format!("No Intermediate Format interface versions support file interface version: {format}")))
}

fn std_ctypes(ptr_size: u8) -> Vec<(&'static str, PrimKind, u8, bool, bool)> {
    // (name, kind, size, signed, big_endian) -- python native.std_ctypes (+ pointer); note the
    // python quirks: "unsigned long long" is signed, "byte" is Bytes (treated as Int here).
    vec![
        ("int", PrimKind::Int, 4, true, false),
        ("long", PrimKind::Int, 4, true, false),
        ("unsigned long", PrimKind::Int, 4, false, false),
        ("unsigned int", PrimKind::Int, 4, false, false),
        ("char", PrimKind::Int, 1, true, false),
        ("byte", PrimKind::Int, 1, true, false),
        ("unsigned char", PrimKind::Int, 1, false, false),
        ("unsigned short int", PrimKind::Int, 2, false, false),
        ("unsigned short", PrimKind::Int, 2, false, false),
        ("unsigned be short", PrimKind::Int, 2, false, true),
        ("short", PrimKind::Int, 2, true, false),
        ("long long", PrimKind::Int, 8, true, false),
        ("unsigned long long", PrimKind::Int, 8, true, false),
        ("float", PrimKind::Float, 4, true, false),
        ("double", PrimKind::Float, 8, true, false),
        ("wchar", PrimKind::Int, 2, false, false),
        ("pointer", PrimKind::Int, ptr_size, false, false),
    ]
}

/// Base type record kinds in the blob: 0 int-like, 1 pointer, 2 void, 3 float.
fn base_code(t: &Ty) -> u32 {
    match t {
        Ty::Pointer { .. } => 1,
        Ty::Void => 2,
        Ty::Float(_) => 3,
        _ => 0,
    }
}

/// String pool writer. Repeated names (member names) are interned with their hash cached;
/// unique names are appended directly.
struct Writer<'p> {
    strings: Vec<u8>,
    interned: FxHashMap<&'p str, (u32, u32, u64)>,
}

impl<'p> Writer<'p> {
    /// Intern a repeated name: (offset, len, hash).
    #[inline]
    fn intern(&mut self, s: &'p str) -> (u32, u32, u64) {
        if let Some(&r) = self.interned.get(s) {
            return r;
        }
        let r = (self.strings.len() as u32, s.len() as u32, hash_bytes(s.as_bytes()));
        self.strings.extend_from_slice(s.as_bytes());
        self.interned.insert(s, r);
        r
    }
    /// Append bytes: (offset, len).
    #[inline]
    fn raw(&mut self, b: &[u8]) -> (u32, u32) {
        let r = (self.strings.len() as u32, b.len() as u32);
        self.strings.extend_from_slice(b);
        r
    }
}

/// Build an open-addressing index (u32 slots holding record index + 1) from precomputed
/// hashes, appending the little-endian slots to `out`; returns the slot count.
fn index_into(hashes: &[u64], out: &mut Vec<u8>) -> usize {
    let n = hashes.len();
    if n == 0 {
        return 0;
    }
    let slots = (n * 2).next_power_of_two().max(4);
    let mut t = vec![0u32; slots];
    let mask = slots - 1;
    for (i, &h) in hashes.iter().enumerate() {
        let mut j = h as usize & mask;
        while t[j] != 0 {
            j = (j + 1) & mask;
        }
        t[j] = i as u32 + 1;
    }
    out.reserve(slots * 4);
    for x in t {
        out.extend_from_slice(&x.to_le_bytes());
    }
    slots
}

fn put32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// Lenient base64 decode (python `base64.b64decode` without validation: ignores characters
/// outside the alphabet, stops at padding).
pub fn b64decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in s.as_bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => continue,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

struct Resolver<'p, 'a> {
    parsed: &'p Parsed<'a>,
    natives: Vec<NativeDef>,
    native_idx: FxHashMap<String, usize>,
    utype_idx: FxHashMap<&'p str, u32>,
    enum_idx: FxHashMap<&'p str, u32>,
    nodes: Vec<Ty>,
    node_idx: FxHashMap<Ty, u32>,
    /// unresolved names: node index -> name
    unresolved: Vec<(u32, String)>,
    desc_memo: Vec<Option<Ty>>,
}

impl<'p, 'a> Resolver<'p, 'a> {
    fn node(&mut self, t: Ty) -> TypeIdx {
        if let Some(&i) = self.node_idx.get(&t) {
            return TypeIdx(i);
        }
        let i = self.nodes.len() as u32;
        self.nodes.push(t);
        self.node_idx.insert(t, i);
        TypeIdx(i)
    }
    fn unresolved(&mut self, name: &str) -> Ty {
        // unresolved names get their own node so the name can be recovered
        let i = self.nodes.len() as u32;
        let t = Ty::Unresolved(TypeIdx(i));
        self.nodes.push(t);
        self.unresolved.push((i, name.to_string()));
        t
    }
    fn native(&self, name: &str) -> Option<Ty> {
        self.native_idx.get(name).map(|&i| self.natives[i].ty)
    }
    fn is_native_type(&self, name: &str) -> bool {
        self.native_idx.contains_key(name) || matches!(name, "enum" | "array" | "bitfield" | "void" | "string" | "bytes" | "function")
    }
    fn int_prim(&self, t: Ty) -> Option<Prim> {
        match t {
            Ty::Int(p) | Ty::Float(p) => Some(p),
            Ty::Enum(i) => {
                let e = &self.parsed.enums[i as usize];
                match self.native(&e.base) {
                    Some(Ty::Int(p)) => Some(p),
                    _ => None,
                }
            }
            Ty::Pointer { prim, .. } => Some(prim),
            _ => None,
        }
    }
    /// python `_interdict_to_template`.
    fn desc(&mut self, di: u32) -> Ty {
        if let Some(t) = self.desc_memo[di as usize] {
            return t;
        }
        let t = self.desc_uncached(di);
        self.desc_memo[di as usize] = Some(t);
        t
    }
    fn desc_uncached(&mut self, di: u32) -> Ty {
        let parsed = self.parsed;
        let d = &parsed.descs[di as usize];
        let mut type_name: &str = &d.kind;
        if type_name == "base" {
            type_name = d.name.as_deref().unwrap_or("");
        }
        if self.is_native_type(type_name) {
            match type_name {
                "void" => return Ty::Void,
                "function" => return Ty::Function,
                "array" => {
                    let elem = match d.sub {
                        Some(s) => self.desc(s),
                        None => Ty::Void,
                    };
                    let elem = self.node(elem);
                    return Ty::Array { count: d.count.clamp(0, u32::MAX as i128) as u32, elem };
                }
                "pointer" => {
                    let mut prim = match self.native("pointer") {
                        Some(Ty::Pointer { prim, .. }) => prim,
                        Some(Ty::Int(p)) => p,
                        _ => Prim { size: 8, signed: false, big_endian: false, kind: PrimKind::Int, name: Prim::NO_NAME },
                    };
                    if let Some(base) = d.base.as_deref().filter(|b| !b.is_empty()) {
                        if let Some(bp) = self.native(base).and_then(|t| self.int_prim(t)) {
                            let name = prim.name;
                            prim = bp;
                            prim.name = name;
                        }
                    }
                    let target = match d.sub {
                        Some(s) => self.desc(s),
                        None => Ty::Void,
                    };
                    let target = self.node(target);
                    return Ty::Pointer { prim, target };
                }
                "enum" => {
                    let name = d.name.as_deref().unwrap_or("");
                    return match self.enum_idx.get(name) {
                        Some(&i) => Ty::Enum(i),
                        None => self.unresolved(name),
                    };
                }
                "bitfield" => {
                    let base = match d.sub {
                        Some(s) => self.desc(s),
                        None => Ty::Void,
                    };
                    let start = d.bit_position.clamp(0, 255) as u8;
                    let end = (d.bit_position + d.bit_length).clamp(0, 255) as u8;
                    return match self.int_prim(base) {
                        Some(p) => Ty::BitField { start, end, base: p },
                        None => self.unresolved("bitfield"),
                    };
                }
                "string" => return Ty::String { max_len: 0, enc: StrEnc::Utf8, errors: StrErrors::Strict },
                "bytes" => return Ty::Bytes(0),
                _ => {
                    return match self.native(type_name) {
                        Some(t) => t,
                        None => Ty::Void,
                    };
                }
            }
        }
        if matches!(&*d.kind, "struct" | "union" | "class") {
            let name = d.name.as_deref().unwrap_or("");
            if !name.contains('!') {
                if let Some(&i) = self.utype_idx.get(name) {
                    return Ty::Struct(i);
                }
            }
            return self.unresolved(name);
        }
        self.unresolved(type_name)
    }
}

/// Parse ISF JSON and build a table blob.
pub fn build_blob(json: &[u8], opts: &BuildOptions) -> Result<Vec<u8>> {
    let parsed = parse(json)?;
    if !(parsed.has[0] && parsed.has[1] && parsed.has[2] && parsed.has[3] && parsed.has[4]) {
        return Err(Error::msg("Malformed JSON file provided"));
    }
    let metadata = parsed.metadata.as_ref().filter(|m| m.truthy()).ok_or_else(|| Error::msg("Invalid ISF file attempted to be parsed"))?;
    let format = metadata.get("format").and_then(|f| f.as_str()).unwrap_or("0.0.0").to_string();
    let version = closest_version(&format)?;
    if version < (2, 0, 0) {
        return Err(Error::msg(format!("ISF version {format} is no longer supported")));
    }
    let fparts: Vec<u32> = format.split('.').map(|x| x.parse().unwrap_or(0)).collect();

    // ---- natives
    let mut natives: Vec<NativeDef> = Vec::new();
    if let Some(ov) = &opts.natives {
        for (n, t) in ov {
            natives.push(NativeDef { name: n.clone(), ty: *t });
        }
    } else if version >= (4, 0, 0) {
        for (name, b) in &parsed.bases {
            if name == "void" {
                continue;
            }
            let size = b.size.unwrap_or(0).clamp(0, 255) as u8;
            let kind = match &*b.kind {
                "int" => PrimKind::Int,
                "float" => PrimKind::Float,
                "void" => PrimKind::Void,
                "bool" => PrimKind::Bool,
                "char" => PrimKind::Char,
                _ => return Err(Error::msg("Unsupported base kind")),
            };
            let prim = Prim { size, signed: b.signed, big_endian: b.endian == "big", kind, name: natives.len() as u16 };
            let ty = if name == "pointer" {
                Ty::Pointer { prim, target: TypeIdx(0) }
            } else if kind == PrimKind::Float {
                Ty::Float(prim)
            } else {
                Ty::Int(prim)
            };
            natives.push(NativeDef { name: name.to_string(), ty });
        }
    } else {
        // choose x64 (checked first, sorted order) or x86 std-ctypes by matching sizes
        let mut chosen = None;
        for ptr in [8u8, 4u8] {
            let table = std_ctypes(ptr);
            let mut ok = true;
            for (name, b) in &parsed.bases {
                let jsize = b.size.or(b.length).unwrap_or(0);
                let nsize = match &**name {
                    "void" | "function" | "array" | "enum" | "bitfield" | "string" | "bytes" => Some(0),
                    n => table.iter().find(|e| e.0 == n).map(|e| e.2 as i128),
                };
                match nsize {
                    Some(s) if s == jsize => {}
                    Some(_) => {
                        ok = false;
                        break;
                    }
                    None => return Err(Error::msg(format!("Unknown native type {name}"))),
                }
            }
            if ok {
                chosen = Some(table);
                break;
            }
        }
        let table = chosen.ok_or_else(|| Error::msg("Native table not provided"))?;
        for (i, (name, kind, size, signed, big)) in table.into_iter().enumerate() {
            let prim = Prim { size, signed, big_endian: big, kind, name: i as u16 };
            let ty = if name == "pointer" {
                Ty::Pointer { prim, target: TypeIdx(0) }
            } else if kind == PrimKind::Float {
                Ty::Float(prim)
            } else {
                Ty::Int(prim)
            };
            natives.push(NativeDef { name: name.to_string(), ty });
        }
    }
    // renumber prim names to the natives order (override lists may carry foreign indexes)
    for (i, n) in natives.iter_mut().enumerate() {
        n.ty = match n.ty {
            Ty::Int(mut p) => {
                p.name = i as u16;
                Ty::Int(p)
            }
            Ty::Float(mut p) => {
                p.name = i as u16;
                Ty::Float(p)
            }
            Ty::Pointer { mut prim, .. } => {
                prim.name = i as u16;
                Ty::Pointer { prim, target: TypeIdx(0) }
            }
            t => t,
        };
    }
    let native_idx: FxHashMap<String, usize> = natives.iter().enumerate().map(|(i, n)| (n.name.clone(), i)).collect();

    let mut r = Resolver {
        parsed: &parsed,
        natives,
        native_idx,
        utype_idx: parsed.users.iter().enumerate().map(|(i, u)| (u.name.as_ref(), i as u32)).collect(),
        enum_idx: parsed.enums.iter().enumerate().map(|(i, e)| (e.name.as_ref(), i as u32)).collect(),
        nodes: Vec::new(),
        node_idx: FxHashMap::default(),
        unresolved: Vec::new(),
        desc_memo: vec![None; parsed.descs.len()],
    };
    r.node(Ty::Void); // node 0 = void

    // ---- user types (with v6.2 anonymous flattening)
    let flatten = version >= (6, 2, 0);
    let parsed_ref: &Parsed = &parsed;
    let mut members_per_type: Vec<Vec<(&str, u64, Ty)>> = Vec::with_capacity(parsed.users.len());
    for u in &parsed_ref.users {
        let mut members: Vec<(&str, u64, Ty)> = Vec::with_capacity(u.fields.len());
        let needs_flatten = flatten && u.fields.iter().any(|f| f.anonymous);
        if !needs_flatten {
            // common case: JSON object keys are unique -> fields map 1:1 to members
            for f in &u.fields {
                let ty = match f.ty {
                    Some(t) => r.desc(t),
                    None => Ty::Void,
                };
                members.push((f.name.as_ref(), f.offset.clamp(0, u32::MAX as i128) as u64, ty));
            }
            members_per_type.push(members);
            continue;
        }
        let mut pos: FxHashMap<&str, usize> = FxHashMap::default();
        let mut stack: Vec<(&[FieldDef], usize, i128)> = vec![(&u.fields, 0, 0)];
        let mut depth_guard = 0;
        while let Some((fields, i, parent_off)) = stack.pop() {
            if i >= fields.len() {
                continue;
            }
            stack.push((fields, i + 1, parent_off));
            let f = &fields[i];
            let new_off = parent_off + f.offset;
            if f.anonymous {
                let sub = f.ty.and_then(|t| parsed_ref.descs[t as usize].name.as_deref()).and_then(|n| r.utype_idx.get(n).copied());
                if let Some(si) = sub {
                    depth_guard += 1;
                    if depth_guard < 100_000 {
                        stack.push((&parsed_ref.users[si as usize].fields, 0, new_off));
                    }
                }
                continue;
            }
            let ty = match f.ty {
                Some(t) => r.desc(t),
                None => Ty::Void,
            };
            let off = new_off.clamp(0, u32::MAX as i128) as u64;
            let name: &str = f.name.as_ref();
            match pos.get(name) {
                Some(&k) => members[k] = (name, off, ty),
                None => {
                    pos.insert(name, members.len());
                    members.push((name, off, ty));
                }
            }
        }
        members_per_type.push(members);
    }

    // ---- symbols
    let sym_types = version >= (2, 1, 0);
    let sym_cdata = version >= (4, 1, 0);
    let mut sym_ty: Vec<u32> = Vec::with_capacity(parsed.symbols.len());
    for s in &parsed.symbols {
        let t = match (sym_types, s.ty) {
            (true, Some(d)) => {
                let t = r.desc(d);
                r.node(t).0
            }
            _ => u32::MAX,
        };
        sym_ty.push(t);
    }

    // ---- enum prims
    let enum_prims: Vec<Prim> = parsed
        .enums
        .iter()
        .map(|e| match r.native(&e.base) {
            Some(Ty::Int(p)) => p,
            Some(Ty::Pointer { prim, .. }) => prim,
            _ => Prim { size: 4, signed: true, big_endian: false, kind: PrimKind::Int, name: Prim::NO_NAME },
        })
        .collect();

    // ---- serialize
    let mut w = Writer { strings: Vec::with_capacity(json.len() / 4), interned: FxHashMap::default() };
    let mut sections: Vec<Vec<u8>> = vec![Vec::new(); sec::N];

    // nodes
    {
        let unresolved: FxHashMap<u32, (u32, u32)> = r.unresolved.iter().map(|(i, n)| (*i, w.raw(n.as_bytes()))).collect();
        let out = &mut sections[sec::NODES];
        out.reserve(r.nodes.len() * NODE_SZ);
        for (i, t) in r.nodes.iter().enumerate() {
            let mut enc = ty_encode(t);
            if let Some(&(o, l)) = unresolved.get(&(i as u32)) {
                enc[4..8].copy_from_slice(&o.to_le_bytes());
                enc[8..12].copy_from_slice(&l.to_le_bytes());
            }
            out.extend_from_slice(&enc);
        }
    }
    // user types + members + member hashes
    {
        let total_members: usize = members_per_type.iter().map(|m| m.len()).sum();
        let mut ut = Vec::with_capacity(parsed_ref.users.len() * UTYPE_SZ);
        let mut ms = Vec::with_capacity(total_members * MEMBER_SZ);
        let mut mh: Vec<u8> = Vec::with_capacity(total_members * 16);
        let mut hashes: Vec<u64> = Vec::new();
        let mut type_hashes: Vec<u64> = Vec::with_capacity(parsed_ref.users.len());
        let mut mcount_total = 0u32;
        for (u, members) in parsed_ref.users.iter().zip(&members_per_type) {
            let (no, nl) = w.raw(u.name.as_bytes());
            type_hashes.push(hash_bytes(u.name.as_bytes()));
            let kind = match &*u.kind {
                "union" => 1u32,
                "class" => 2,
                _ => 0,
            };
            hashes.clear();
            let hstart = (mh.len() / 4) as u32;
            let mstart = ms.len();
            for (name, off, ty) in members {
                let (mo, ml, h) = w.intern(name);
                hashes.push(h);
                ms.extend_from_slice(&mo.to_le_bytes());
                ms.extend_from_slice(&ml.to_le_bytes());
                ms.extend_from_slice(&(*off as u32).to_le_bytes());
                ms.extend_from_slice(&0u32.to_le_bytes());
                ms.extend_from_slice(&ty_encode(ty));
            }
            debug_assert_eq!(ms.len() - mstart, members.len() * MEMBER_SZ);
            let hlen = index_into(&hashes, &mut mh) as u32;
            put32(&mut ut, no);
            put32(&mut ut, nl);
            put32(&mut ut, kind);
            put32(&mut ut, u.size.clamp(0, u32::MAX as i128) as u32);
            put32(&mut ut, mcount_total);
            put32(&mut ut, members.len() as u32);
            put32(&mut ut, hstart);
            put32(&mut ut, hlen);
            mcount_total += members.len() as u32;
        }
        sections[sec::UTYPES] = ut;
        sections[sec::MEMBERS] = ms;
        sections[sec::MHASH] = mh;
        index_into(&type_hashes, &mut sections[sec::H_UTYPES]);
    }
    // enums
    {
        let mut es = Vec::with_capacity(parsed_ref.enums.len() * ENUM_SZ);
        let mut cs = Vec::new();
        let mut hashes = Vec::with_capacity(parsed_ref.enums.len());
        let mut ccount = 0u32;
        for (e, p) in parsed_ref.enums.iter().zip(&enum_prims) {
            let (no, nl) = w.raw(e.name.as_bytes());
            hashes.push(hash_bytes(e.name.as_bytes()));
            put32(&mut es, no);
            put32(&mut es, nl);
            put32(&mut es, p.pack());
            put32(&mut es, p.size as u32);
            put32(&mut es, ccount);
            put32(&mut es, e.constants.len() as u32);
            put64(&mut es, 0);
            for (cn, v) in &e.constants {
                let (co, cl, _) = w.intern(cn);
                put32(&mut cs, co);
                put32(&mut cs, cl);
                put64(&mut cs, *v as i64 as u64);
            }
            ccount += e.constants.len() as u32;
        }
        sections[sec::ENUMS] = es;
        sections[sec::CONSTS] = cs;
        index_into(&hashes, &mut sections[sec::H_ENUMS]);
    }
    // symbols
    {
        let mut ss = Vec::with_capacity(parsed_ref.symbols.len() * SYMBOL_SZ);
        let mut cdata: Vec<u8> = Vec::new();
        let mut hashes = Vec::with_capacity(parsed_ref.symbols.len());
        for (s, t) in parsed_ref.symbols.iter().zip(&sym_ty) {
            let (no, nl) = w.raw(s.name.as_bytes());
            hashes.push(hash_bytes(s.name.as_bytes()));
            put32(&mut ss, no);
            put32(&mut ss, nl);
            put64(&mut ss, s.address as u64);
            put32(&mut ss, *t);
            match (sym_cdata, &s.constant_data) {
                (true, Some(cd)) => {
                    let bytes = b64decode(cd);
                    let (co, cl) = (cdata.len() as u32, bytes.len() as u32);
                    cdata.extend_from_slice(&bytes);
                    put32(&mut ss, 1);
                    put32(&mut ss, co);
                    put32(&mut ss, cl);
                }
                _ => {
                    put32(&mut ss, 0);
                    put64(&mut ss, 0);
                }
            }
        }
        sections[sec::SYMBOLS] = ss;
        sections[sec::CDATA] = cdata;
        index_into(&hashes, &mut sections[sec::H_SYMBOLS]);
    }
    // natives / base types
    {
        let mut bs = Vec::new();
        let mut hashes = Vec::new();
        for n in &r.natives {
            let (no, nl) = w.raw(n.name.as_bytes());
            hashes.push(hash_bytes(n.name.as_bytes()));
            put32(&mut bs, no);
            put32(&mut bs, nl);
            let prim = match n.ty {
                Ty::Int(p) | Ty::Float(p) => p,
                Ty::Pointer { prim, .. } => prim,
                _ => Prim { size: 0, signed: false, big_endian: false, kind: PrimKind::Void, name: Prim::NO_NAME },
            };
            put32(&mut bs, prim.pack());
            put32(&mut bs, base_code(&n.ty));
        }
        sections[sec::BASES] = bs;
        index_into(&hashes, &mut sections[sec::H_BASES]);
    }
    sections[sec::META] = metadata.to_string_compact().into_bytes();
    sections[sec::STRINGS] = std::mem::take(&mut w.strings);

    // ---- assemble
    let mut out = Vec::with_capacity(HDR_SZ + sections.iter().map(|s| s.len() + 8).sum::<usize>());
    out.extend_from_slice(MAGIC);
    put32(&mut out, BLOB_VERSION);
    put32(&mut out, sec::N as u32);
    let table_pos = out.len();
    out.resize(HDR_SZ, 0);
    let fo = 16 + sec::N * 16;
    for (i, v) in fparts.iter().take(3).enumerate() {
        out[fo + i * 4..fo + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    for (i, s) in sections.iter().enumerate() {
        while out.len() % 8 != 0 {
            out.push(0);
        }
        let off = out.len() as u64;
        out.extend_from_slice(s);
        let p = table_pos + i * 16;
        out[p..p + 8].copy_from_slice(&off.to_le_bytes());
        out[p + 8..p + 16].copy_from_slice(&(s.len() as u64).to_le_bytes());
    }
    Ok(out)
}

/// Parse ISF JSON bytes into a ready table (no caching).
pub fn load_table(json: &[u8], name: &str, url: &str, opts: &BuildOptions) -> Result<SymbolTable> {
    let blob = build_blob(json, opts)?;
    SymbolTable::from_blob(Blob::Owned(blob), name, url)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISF: &str = r#"{
      "metadata": {"format": "6.2.0", "windows": {"pdb": {"GUID": "ABC", "age": 1, "database": "x.pdb"}}},
      "base_types": {
        "unsigned long": {"kind": "int", "size": 4, "signed": false, "endian": "little"},
        "long": {"kind": "int", "size": 4, "signed": true, "endian": "little"},
        "unsigned char": {"kind": "char", "size": 1, "signed": false, "endian": "little"},
        "pointer": {"kind": "int", "size": 8, "signed": false, "endian": "little"},
        "void": {"kind": "void", "size": 0, "signed": false, "endian": "little"}
      },
      "enums": {"E": {"base": "long", "size": 4, "constants": {"A": 1, "B": 2, "C": 1}}},
      "user_types": {
        "_S": {"kind": "struct", "size": 24, "fields": {
            "a": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
            "p": {"offset": 8, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_S"}}},
            "anon": {"offset": 16, "anonymous": true, "type": {"kind": "union", "name": "_U"}},
            "arr": {"offset": 16, "type": {"kind": "array", "count": 4, "subtype": {"kind": "base", "name": "unsigned char"}}},
            "bf": {"offset": 20, "type": {"kind": "bitfield", "bit_position": 3, "bit_length": 5, "type": {"kind": "base", "name": "unsigned long"}}},
            "e": {"offset": 20, "type": {"kind": "enum", "name": "E"}},
            "missing": {"offset": 0, "type": {"kind": "struct", "name": "_NOPE"}}
        }},
        "_U": {"kind": "union", "size": 4, "fields": {"x": {"offset": 0, "type": {"kind": "base", "name": "long"}}, "y": {"offset": 2, "type": {"kind": "base", "name": "long"}}}}
      },
      "symbols": {"sym1": {"address": 4096, "type": {"kind": "struct", "name": "_S"}}, "linux_banner": {"address": 1, "constant_data": "TGludXggdmVyc2lvbg=="}}
    }"#;

    #[test]
    fn build_and_query() {
        let t = load_table(ISF.as_bytes(), "t", "file:///x", &BuildOptions::default()).unwrap();
        let s = t.user_type("_S").unwrap();
        assert_eq!(t.user_type_size(s), 24);
        let names: Vec<&str> = t.members(s).map(|m| m.name).collect();
        assert_eq!(names, vec!["a", "p", "x", "y", "arr", "bf", "e", "missing"]);
        let x = t.member(s, "x").unwrap();
        assert_eq!(x.offset, 16);
        let y = t.member(s, "y").unwrap();
        assert_eq!(y.offset, 18);
        match t.member(s, "p").unwrap().ty {
            Ty::Pointer { prim, target } => {
                assert_eq!(prim.size, 8);
                assert_eq!(t.node(target), Ty::Struct(s));
            }
            other => panic!("{other:?}"),
        }
        match t.member(s, "arr").unwrap().ty {
            Ty::Array { count, elem } => {
                assert_eq!(count, 4);
                assert!(matches!(t.node(elem), Ty::Int(p) if p.size == 1 && !p.signed));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(t.member(s, "bf").unwrap().ty, Ty::BitField { start: 3, end: 8, .. }));
        let e = t.enumeration("E").unwrap();
        assert_eq!(t.enum_lookup(e, 1), Some("A"));
        assert_eq!(t.enum_lookup(e, 3), None);
        assert!(matches!(t.member(s, "missing").unwrap().ty, Ty::Unresolved(_)));
        assert_eq!(t.type_name(t.member(s, "missing").unwrap().ty), "_NOPE");
        let sym = t.get_symbol("sym1").unwrap();
        assert_eq!(sym.address, 4096);
        assert_eq!(sym.ty, Some(Ty::Struct(s)));
        assert_eq!(t.get_symbol("linux_banner").unwrap().constant_data, Some(&b"Linux version"[..]));
        assert!(t.get_symbol("nope").is_err());
        assert!(t.is_64bit());
        assert_eq!(t.pdb_info().unwrap().guid, "ABC");
        assert_eq!(t.type_name(t.member(s, "a").unwrap().ty), "unsigned long");
        assert_eq!(t.symbols_at(4096, 0), vec!["sym1"]);
    }

    #[test]
    fn versions() {
        assert_eq!(closest_version("6.1.0").unwrap(), (6, 2, 0));
        assert_eq!(closest_version("4.0.0").unwrap(), (4, 1, 0));
        assert_eq!(closest_version("2.0.0").unwrap(), (2, 1, 0));
        assert!(closest_version("6.3.0").is_err());
        assert!(closest_version("5.0.0").is_err());
    }

    /// `cargo test --release isf_bench -- --ignored --nocapture` (`RSVOL_BENCH_JSON=path`)
    #[test]
    #[ignore]
    fn isf_bench() {
        let path = std::env::var("RSVOL_BENCH_JSON")
            .unwrap_or_else(|_| "/tmp/claude-1000/-home-user-rs-vol/c12d8bb7-14a2-4f12-b8c0-878249a94793/scratchpad/nt.json".into());
        let data = std::fs::read(&path).unwrap();
        let mb = data.len() as f64 / 1e6;
        let best = |f: &mut dyn FnMut()| -> f64 {
            let mut b = f64::MAX;
            for _ in 0..15 {
                let t = std::time::Instant::now();
                f();
                b = b.min(t.elapsed().as_secs_f64());
            }
            b
        };
        let d_utf8 = best(&mut || assert!(std::str::from_utf8(&data).is_ok()));
        let d0 = best(&mut || {
            let mut p = Parser::new(&data);
            p.skip().unwrap();
        });
        let d1 = best(&mut || drop(Json::parse(&data).unwrap()));
        let d2 = best(&mut || drop(parse(&data).unwrap()));
        let mut blen = 0;
        let d3 = best(&mut || blen = build_blob(&data, &BuildOptions::default()).unwrap().len());
        println!(
            "{mb:.1}MB (best of 15): utf8 {:.2}ms | skip {:.2}ms ({:.0} MB/s) | dom {:.2}ms ({:.0} MB/s) | isf-parse {:.2}ms ({:.0} MB/s) | build_blob {:.2}ms ({:.0} MB/s) blob {}KB",
            d_utf8 * 1e3,
            d0 * 1e3,
            mb / d0,
            d1 * 1e3,
            mb / d1,
            d2 * 1e3,
            mb / d2,
            d3 * 1e3,
            mb / d3,
            blen / 1024
        );
    }
}
