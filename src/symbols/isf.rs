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
use crate::util::json::{Json, Kind, dict_dedupe, dict_dedupe_hashed};
use crate::util::jsonidx::{Ev, Index, Pull};
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
    /// the fused builder's descriptor identity (entry of its `{` in the structural index)
    id: u32,
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
    /// `hash_bytes` of the enum / user type / symbol names (from the duplicate-key check)
    enum_hashes: Vec<u64>,
    user_hashes: Vec<u64>,
    sym_hashes: Vec<u64>,
}

fn parse_desc<'a, P: Pull<'a>>(p: &mut P, descs: &mut Vec<Desc<'a>>) -> Result<u32> {
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

/// One `base_types` member value.
fn parse_base<'a, P: Pull<'a>>(p: &mut P) -> Result<BaseDef<'a>> {
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
    Ok(b)
}

/// One `enums` member value.
fn parse_enum<'a, P: Pull<'a>>(p: &mut P, name: Cow<'a, str>) -> Result<EnumDef<'a>> {
    let mut e = EnumDef { name, base: Cow::Borrowed(""), constants: Vec::new() };
    p.object(|p, k| {
        match k.as_ref() {
            "base" => e.base = p.str()?,
            "constants" => {
                e.constants.clear();
                p.object(|p, cn| {
                    let v = p.int()?;
                    e.constants.push((cn, v));
                    Ok(())
                })?;
                dict_dedupe(&mut e.constants, |c| &c.0);
            }
            _ => p.skip()?,
        }
        Ok(())
    })?;
    Ok(e)
}

/// One `user_types` member value.
fn parse_user<'a, P: Pull<'a>>(p: &mut P, name: Cow<'a, str>, descs: &mut Vec<Desc<'a>>) -> Result<UserDef<'a>> {
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
                u.fields.clear();
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
                })?;
                dict_dedupe(&mut u.fields, |f| &f.name)
            }
            _ => p.skip()?,
        }
        Ok(())
    })?;
    u.size = size.or(length).unwrap_or(0);
    Ok(u)
}

/// One `symbols` member value (`None`: not an object, skipped like python's delegate).
fn parse_symbol<'a, P: Pull<'a>>(p: &mut P, name: Cow<'a, str>, descs: &mut Vec<Desc<'a>>) -> Result<Option<SymDef<'a>>> {
    let mut s = SymDef { name, address: 0, ty: None, constant_data: None };
    if p.peek_kind()? != Kind::Obj {
        p.skip()?;
        return Ok(None);
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
    Ok(Some(s))
}

/// Section indexes (`Parsed::has`).
const S_META: usize = 0;
const S_BASES: usize = 1;
const S_ENUMS: usize = 2;
const S_USERS: usize = 3;
const S_SYMBOLS: usize = 4;

fn section_of(key: &str) -> Option<usize> {
    Some(match key {
        "metadata" => S_META,
        "base_types" => S_BASES,
        "enums" => S_ENUMS,
        "user_types" => S_USERS,
        "symbols" => S_SYMBOLS,
        _ => return None,
    })
}

/// Parse one top-level member (`key` known) into `out` (python dict semantics: a repeated
/// section replaces the earlier one).
fn parse_section<'a, P: Pull<'a>>(p: &mut P, key: &str, out: &mut Parsed<'a>) -> Result<()> {
    match section_of(key) {
        Some(S_META) => {
            out.has[S_META] = true;
            out.metadata = Some(p.value()?);
        }
        Some(S_BASES) => {
            out.has[S_BASES] = true;
            out.bases.clear();
            let bases = &mut out.bases;
            p.object(|p, name| {
                let b = parse_base(p)?;
                bases.push((name, b));
                Ok(())
            })?;
            dict_dedupe(bases, |b| &b.0);
        }
        Some(S_ENUMS) => {
            out.has[S_ENUMS] = true;
            out.enums.clear();
            let enums = &mut out.enums;
            p.object(|p, name| {
                enums.push(parse_enum(p, name)?);
                Ok(())
            })?;
            dict_dedupe_hashed(enums, |e| &e.name, Some(&mut out.enum_hashes));
        }
        Some(S_USERS) => {
            out.has[S_USERS] = true;
            out.users.clear();
            let descs = &mut out.descs;
            let users = &mut out.users;
            p.object(|p, name| {
                users.push(parse_user(p, name, descs)?);
                Ok(())
            })?;
            dict_dedupe_hashed(users, |u| &u.name, Some(&mut out.user_hashes));
        }
        Some(_) => {
            out.has[S_SYMBOLS] = true;
            out.symbols.clear();
            let descs = &mut out.descs;
            let syms = &mut out.symbols;
            p.object(|p, name| {
                if let Some(s) = parse_symbol(p, name, descs)? {
                    syms.push(s);
                }
                Ok(())
            })?;
            dict_dedupe_hashed(syms, |s| &s.name, Some(&mut out.sym_hashes));
        }
        None => p.skip()?,
    }
    Ok(())
}

/// The whole document, sequentially, through any pull parser.
fn parse_seq<'a, P: Pull<'a>>(p: &mut P) -> Result<Parsed<'a>> {
    let mut out = Parsed::default();
    p.object(|p, k| parse_section(p, &k, &mut out))?;
    Ok(out)
}

/// Documents below this size are parsed on the calling thread.
const PAR_PARSE_MIN: usize = 1 << 20;

/// Parse ISF JSON: stage 1 structural index, then the members of the big top-level objects
/// (`user_types`, `symbols`, `enums`) in parallel ranges (see [`parse_parallel`]).
fn parse<'a>(buf: &'a [u8]) -> Result<Parsed<'a>> {
    let par = buf.len() >= PAR_PARSE_MIN && crate::util::par::threads() > 1;
    let idx = {
        let _t = crate::util::trace::span("isf parse: stage 1");
        Index::build_with(buf, par)?
    };
    if par {
        let _t = crate::util::trace::span("isf parse: stage 2 (parallel)");
        if let Some(p) = parse_parallel(buf, &idx) {
            return Ok(p);
        }
    }
    // small documents, unusual shapes, and every invalid document (for its error)
    parse_seq(&mut idx.walker(buf))
}

/// A top-level member found by [`Index::top_events`].
struct TopMember<'a> {
    key: Cow<'a, str>,
    /// entry of the value
    value: usize,
    /// for `{...}` / `[...]` values: entry of the closing bracket
    close: Option<usize>,
    /// for `{...}` values: range of member-key entries in `keys2`
    members: std::ops::Range<usize>,
    is_obj: bool,
}

/// Per-range parse output of one big section.
enum Part<'a> {
    Enums(Vec<EnumDef<'a>>),
    Users(Vec<UserDef<'a>>, Vec<Desc<'a>>),
    Syms(Vec<SymDef<'a>>, Vec<Desc<'a>>),
}

/// The members of the top-level objects parsed on all cores. `None` when the document is not
/// a plain `{"section": ..., ...}` object whose structure the events describe exactly (the
/// caller then parses sequentially, which also produces the error of an invalid document).
fn parse_parallel<'a>(buf: &'a [u8], idx: &Index) -> Option<Parsed<'a>> {
    let w = idx.walker(buf);
    if w.ch(0) != b'{' {
        return None;
    }
    let ev = idx.top_events(buf);
    // ---- top-level members from the events
    let mut members: Vec<TopMember<'a>> = Vec::new();
    let mut keys2: Vec<u32> = Vec::new();
    let mut k = 0;
    while k < ev.len() {
        let (e, kind) = ev[k];
        if kind != Ev::TopKey {
            return None;
        }
        let e = e as usize;
        if w.ch(e + 2) != b':' {
            return None;
        }
        let key = w.string_at(e).ok()?;
        let value = e + 3;
        k += 1;
        let mut m = TopMember { key, value, close: None, members: keys2.len()..keys2.len(), is_obj: false };
        if ev.get(k).is_some_and(|&(x, t)| t == Ev::Open1 && x as usize == value) {
            m.is_obj = w.ch(value) == b'{';
            k += 1;
            let start = keys2.len();
            while k < ev.len() && ev[k].1 == Ev::Key2 {
                if m.is_obj {
                    keys2.push(ev[k].0);
                }
                k += 1;
            }
            match ev.get(k) {
                Some(&(x, Ev::Close1)) => m.close = Some(x as usize),
                _ => return None,
            }
            k += 1;
            m.members = start..keys2.len();
        }
        members.push(m);
    }
    if members.is_empty() || members[0].value != 4 {
        return None;
    }
    // a member object's first key follows its '{' directly
    for m in &members {
        if m.is_obj && !m.members.is_empty() && keys2[m.members.start] as usize != m.value + 1 {
            return None;
        }
    }
    // entry after member i's value must be ',' + member i+1's key, or the root's '}'
    let sep_ok = |i: usize, end: usize| -> bool {
        match members.get(i + 1) {
            Some(n) => w.ch(end) == b',' && end + 1 == n.value - 3,
            None => w.ch(end) == b'}',
        }
    };

    // ---- sections: small ones (and scalar-valued members) sequentially, big ones in ranges
    let mut out = Parsed::default();
    let threads = crate::util::par::threads();
    // (member index, entry range in keys2) work items for the big object sections
    let mut items: Vec<(usize, std::ops::Range<usize>)> = Vec::new();
    for (mi, m) in members.iter().enumerate() {
        let big = m.is_obj && matches!(section_of(&m.key), Some(S_ENUMS | S_USERS | S_SYMBOLS)) && m.members.len() >= 256;
        if !big {
            continue;
        }
        let (a, b) = (m.members.start, m.members.end);
        let bytes = w.pos_of(m.close.unwrap_or(m.value)) - w.pos_of(m.value);
        let per = (bytes / (threads * 4)).max(64 << 10);
        let mut s = a;
        while s < b {
            let lim = w.pos_of(keys2[s] as usize) + per;
            let mut e = s + 1;
            // byte-balanced ranges (binary search on the member start positions)
            let mut hi = b;
            while e < hi {
                let mid = (e + hi) / 2;
                if w.pos_of(keys2[mid] as usize) <= lim {
                    e = mid + 1;
                } else {
                    hi = mid;
                }
            }
            items.push((mi, s..e));
            s = e;
        }
    }
    // parse every range: each member = key string, ':', value, then ',' before the next member
    // key or the section's closing '}' after the last one
    let run = |it: usize| -> Option<Part<'a>> {
        let (mi, r) = (&items[it].0, items[it].1.clone());
        let m = &members[*mi];
        let mut p = idx.walker(buf);
        let sec = section_of(&m.key)?;
        let mut descs = Vec::new();
        let mut enums = Vec::new();
        let mut users = Vec::new();
        let mut syms = Vec::new();
        for j in r {
            let ke = keys2[j] as usize;
            if p.ch(ke + 2) != b':' {
                return None;
            }
            let name = p.string_at(ke).ok()?;
            p.seek(ke + 3);
            match sec {
                S_ENUMS => enums.push(parse_enum(&mut p, name).ok()?),
                S_USERS => users.push(parse_user(&mut p, name, &mut descs).ok()?),
                _ => {
                    if let Some(s) = parse_symbol(&mut p, name, &mut descs).ok()? {
                        syms.push(s);
                    }
                }
            }
            let at = p.entry();
            let ok = if j + 1 < m.members.end { p.ch(at) == b',' && at + 1 == keys2[j + 1] as usize } else { Some(at) == m.close };
            if !ok {
                return None;
            }
        }
        Some(match sec {
            S_ENUMS => Part::Enums(enums),
            S_USERS => Part::Users(users, descs),
            _ => Part::Syms(syms, descs),
        })
    };
    let parts: Vec<Option<Part<'a>>> = crate::util::par::par_map(items.len(), run);
    let mut parts = parts.into_iter();
    let mut item = 0;
    for (mi, m) in members.iter().enumerate() {
        let sec = section_of(&m.key);
        let big = item < items.len() && items[item].0 == mi;
        if !big {
            // sequential member (small section, scalar value, unknown key, or a big one whose
            // value is not an object -- parse_section then fails like the byte parser)
            let mut p = idx.walker(buf);
            p.seek(m.value);
            parse_section(&mut p, &m.key, &mut out).ok()?;
            let end = p.entry();
            if m.close.is_some_and(|c| end != c + 1) || !sep_ok(mi, end) {
                return None;
            }
            continue;
        }
        let sec = sec?;
        out.has[sec] = true;
        match sec {
            S_ENUMS => out.enums.clear(),
            S_USERS => out.users.clear(),
            _ => out.symbols.clear(),
        }
        while item < items.len() && items[item].0 == mi {
            match parts.next()?? {
                Part::Enums(v) => out.enums.extend(v),
                Part::Users(mut v, d) => {
                    let base = out.descs.len() as u32;
                    rebase_descs(&mut out.descs, d, base);
                    for u in &mut v {
                        for f in &mut u.fields {
                            if let Some(t) = &mut f.ty {
                                *t += base;
                            }
                        }
                    }
                    out.users.extend(v);
                }
                Part::Syms(mut v, d) => {
                    let base = out.descs.len() as u32;
                    rebase_descs(&mut out.descs, d, base);
                    for s in &mut v {
                        if let Some(t) = &mut s.ty {
                            *t += base;
                        }
                    }
                    out.symbols.extend(v);
                }
            }
            item += 1;
        }
        match sec {
            S_ENUMS => dict_dedupe_hashed(&mut out.enums, |e| &e.name, Some(&mut out.enum_hashes)),
            S_USERS => dict_dedupe_hashed(&mut out.users, |u| &u.name, Some(&mut out.user_hashes)),
            _ => dict_dedupe_hashed(&mut out.symbols, |s| &s.name, Some(&mut out.sym_hashes)),
        }
        if !sep_ok(mi, m.close? + 1) {
            return None;
        }
    }
    Some(out)
}

/// Append a range's descriptors, shifting their `sub` references by `base`.
fn rebase_descs<'a>(all: &mut Vec<Desc<'a>>, mut d: Vec<Desc<'a>>, base: u32) {
    if base != 0 {
        for x in &mut d {
            if let Some(s) = &mut x.sub {
                *s += base;
            }
        }
    }
    if all.is_empty() {
        *all = d;
    } else {
        all.extend(d);
    }
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
    // the fused parallel builder handles every well-formed ISF without repeated names; the
    // two-step reference path (parse everything, then resolve) takes the rest and produces
    // the errors of invalid documents
    if let Some(blob) = fast::build(json, opts)? {
        return Ok(blob);
    }
    let parsed = parse(json)?;
    let _t = crate::util::trace::span("isf build (resolve + serialize)");
    build_from(parsed, json.len(), opts)
}

/// Checks shared by both builders: all sections present, metadata, format. Returns the
/// closest delegate version and the file's own format triple.
fn check_header(has: &[bool; 5], metadata: Option<&Json>) -> Result<((u32, u32, u32), Vec<u32>)> {
    if !has.iter().all(|&h| h) {
        return Err(Error::msg("Malformed JSON file provided"));
    }
    let metadata = metadata.filter(|m| m.truthy()).ok_or_else(|| Error::msg("Invalid ISF file attempted to be parsed"))?;
    let format = metadata.get("format").and_then(|f| f.as_str()).unwrap_or("0.0.0").to_string();
    let version = closest_version(&format)?;
    if version < (2, 0, 0) {
        return Err(Error::msg(format!("ISF version {format} is no longer supported")));
    }
    let fparts: Vec<u32> = format.split('.').map(|x| x.parse().unwrap_or(0)).collect();
    Ok((version, fparts))
}

/// The natives (python NativeTable) of an ISF: the override list, the ISF's own base types
/// (>= 4.0.0), or the std-ctypes table whose sizes match.
fn make_natives(version: (u32, u32, u32), bases: &[(Cow<'_, str>, BaseDef<'_>)], opts: &BuildOptions) -> Result<Vec<NativeDef>> {
    let mut natives: Vec<NativeDef> = Vec::new();
    if let Some(ov) = &opts.natives {
        for (n, t) in ov {
            natives.push(NativeDef { name: n.clone(), ty: *t });
        }
    } else if version >= (4, 0, 0) {
        for (name, b) in bases {
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
            for (name, b) in bases {
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
    Ok(natives)
}

/// A user type ready to serialize.
struct UserOut<'s> {
    name: Cow<'s, str>,
    /// 0 struct, 1 union, 2 class
    kind: u32,
    size: i128,
    members: Vec<(Cow<'s, str>, u64, Ty)>,
    hash: u64,
}

/// An enumeration ready to serialize.
struct EnumOut<'s> {
    name: Cow<'s, str>,
    prim: Prim,
    constants: Vec<(Cow<'s, str>, i128)>,
    hash: u64,
}

/// A symbol ready to serialize (`ty`: node index or `u32::MAX`).
struct SymOut<'s> {
    name: Cow<'s, str>,
    address: i128,
    ty: u32,
    constant_data: Option<Cow<'s, str>>,
    hash: u64,
}

/// Everything the serializer writes, in blob order.
struct Out<'s> {
    fparts: Vec<u32>,
    sym_cdata: bool,
    nodes: Vec<Ty>,
    unresolved: Vec<(u32, String)>,
    users: Vec<UserOut<'s>>,
    enums: Vec<EnumOut<'s>>,
    syms: Vec<SymOut<'s>>,
    natives: Vec<NativeDef>,
    meta: String,
}

fn user_kind_code(kind: &str) -> u32 {
    match kind {
        "union" => 1,
        "class" => 2,
        _ => 0,
    }
}

fn enum_prim(natives: &[NativeDef], native_idx: &FxHashMap<String, usize>, base: &str) -> Prim {
    match native_idx.get(base).map(|&i| natives[i].ty) {
        Some(Ty::Int(p)) => p,
        Some(Ty::Pointer { prim, .. }) => prim,
        _ => Prim { size: 4, signed: true, big_endian: false, kind: PrimKind::Int, name: Prim::NO_NAME },
    }
}

/// The reference builder's resolution step (after [`parse`]).
fn build_from(parsed: Parsed<'_>, json_len: usize, opts: &BuildOptions) -> Result<Vec<u8>> {
    let (version, fparts) = check_header(&parsed.has, parsed.metadata.as_ref())?;
    let meta = parsed.metadata.as_ref().map(|m| m.to_string_compact()).unwrap_or_default();
    let natives = make_natives(version, &parsed.bases, opts)?;
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
    let mut users: Vec<UserOut> = Vec::with_capacity(parsed.users.len());
    for (ui, u) in parsed_ref.users.iter().enumerate() {
        let mut members: Vec<(Cow<str>, u64, Ty)> = Vec::with_capacity(u.fields.len());
        let needs_flatten = flatten && u.fields.iter().any(|f| f.anonymous);
        if !needs_flatten {
            // common case: JSON object keys are unique -> fields map 1:1 to members
            for f in &u.fields {
                let ty = match f.ty {
                    Some(t) => r.desc(t),
                    None => Ty::Void,
                };
                // negative offsets are legal (python adds them to the parent offset): stored as
                // two's complement i64 and applied with wrapping arithmetic
                members.push((Cow::Borrowed(f.name.as_ref()), f.offset.clamp(i64::MIN as i128, i64::MAX as i128) as i64 as u64, ty));
            }
        } else {
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
                let off = new_off.clamp(i64::MIN as i128, i64::MAX as i128) as i64 as u64;
                let name: &str = f.name.as_ref();
                match pos.get(name) {
                    Some(&k) => members[k] = (Cow::Borrowed(name), off, ty),
                    None => {
                        pos.insert(name, members.len());
                        members.push((Cow::Borrowed(name), off, ty));
                    }
                }
            }
        }
        let hash = parsed_ref.user_hashes.get(ui).copied().unwrap_or_else(|| hash_bytes(u.name.as_bytes()));
        users.push(UserOut { name: Cow::Borrowed(u.name.as_ref()), kind: user_kind_code(&u.kind), size: u.size, members, hash });
    }

    // ---- symbols
    let sym_types = version >= (2, 1, 0);
    let mut syms: Vec<SymOut> = Vec::with_capacity(parsed.symbols.len());
    for (si, s) in parsed.symbols.iter().enumerate() {
        let t = match (sym_types, s.ty) {
            (true, Some(d)) => {
                let t = r.desc(d);
                r.node(t).0
            }
            _ => u32::MAX,
        };
        let hash = parsed_ref.sym_hashes.get(si).copied().unwrap_or_else(|| hash_bytes(s.name.as_bytes()));
        syms.push(SymOut { name: Cow::Borrowed(s.name.as_ref()), address: s.address, ty: t, constant_data: s.constant_data.as_deref().map(Cow::Borrowed), hash });
    }

    // ---- enums
    let enums: Vec<EnumOut> = parsed
        .enums
        .iter()
        .enumerate()
        .map(|(ei, e)| EnumOut {
            name: Cow::Borrowed(e.name.as_ref()),
            prim: enum_prim(&r.natives, &r.native_idx, &e.base),
            constants: e.constants.iter().map(|(n, v)| (Cow::Borrowed(n.as_ref()), *v)).collect(),
            hash: parsed_ref.enum_hashes.get(ei).copied().unwrap_or_else(|| hash_bytes(e.name.as_bytes())),
        })
        .collect();

    let out = Out {
        fparts,
        sym_cdata: version >= (4, 1, 0),
        nodes: std::mem::take(&mut r.nodes),
        unresolved: std::mem::take(&mut r.unresolved),
        users,
        enums,
        syms,
        natives: std::mem::take(&mut r.natives),
        meta,
    };
    Ok(serialize(&out, json_len))
}

/// Write the blob (see `table.rs` for the layout).
fn serialize(o: &Out<'_>, json_len: usize) -> Vec<u8> {
    let _t = crate::util::trace::span("isf serialize");
    let mut w = Writer { strings: Vec::with_capacity(json_len / 4), interned: FxHashMap::default() };
    let mut sections: Vec<Vec<u8>> = vec![Vec::new(); sec::N];

    // nodes
    {
        let unresolved: FxHashMap<u32, (u32, u32)> = o.unresolved.iter().map(|(i, n)| (*i, w.raw(n.as_bytes()))).collect();
        let out = &mut sections[sec::NODES];
        out.reserve(o.nodes.len() * NODE_SZ);
        for (i, t) in o.nodes.iter().enumerate() {
            let mut enc = ty_encode(t);
            if let Some(&(off, l)) = unresolved.get(&(i as u32)) {
                enc[4..8].copy_from_slice(&off.to_le_bytes());
                enc[8..12].copy_from_slice(&l.to_le_bytes());
            }
            out.extend_from_slice(&enc);
        }
    }
    // user types + members + member hashes
    {
        let total_members: usize = o.users.iter().map(|u| u.members.len()).sum();
        let mut ut = Vec::with_capacity(o.users.len() * UTYPE_SZ);
        let mut ms = Vec::with_capacity(total_members * MEMBER_SZ);
        let mut mh: Vec<u8> = Vec::with_capacity(total_members * 16);
        let mut hashes: Vec<u64> = Vec::new();
        let mut type_hashes: Vec<u64> = Vec::with_capacity(o.users.len());
        let mut mcount_total = 0u32;
        for u in &o.users {
            let (no, nl) = w.raw(u.name.as_bytes());
            type_hashes.push(u.hash);
            hashes.clear();
            let hstart = (mh.len() / 4) as u32;
            for (name, off, ty) in &u.members {
                let (mo, ml, h) = w.intern(name);
                hashes.push(h);
                ms.extend_from_slice(&mo.to_le_bytes());
                ms.extend_from_slice(&ml.to_le_bytes());
                // offset: i64 (two's complement) over the offset + pad words
                ms.extend_from_slice(&off.to_le_bytes());
                ms.extend_from_slice(&ty_encode(ty));
            }
            let hlen = index_into(&hashes, &mut mh) as u32;
            put32(&mut ut, no);
            put32(&mut ut, nl);
            put32(&mut ut, u.kind);
            put32(&mut ut, u.size.clamp(0, u32::MAX as i128) as u32);
            put32(&mut ut, mcount_total);
            put32(&mut ut, u.members.len() as u32);
            put32(&mut ut, hstart);
            put32(&mut ut, hlen);
            mcount_total += u.members.len() as u32;
        }
        sections[sec::UTYPES] = ut;
        sections[sec::MEMBERS] = ms;
        sections[sec::MHASH] = mh;
        index_into(&type_hashes, &mut sections[sec::H_UTYPES]);
    }
    // enums
    {
        let mut es = Vec::with_capacity(o.enums.len() * ENUM_SZ);
        let mut cs = Vec::new();
        let mut hashes = Vec::with_capacity(o.enums.len());
        let mut ccount = 0u32;
        for e in &o.enums {
            let (no, nl) = w.raw(e.name.as_bytes());
            hashes.push(e.hash);
            put32(&mut es, no);
            put32(&mut es, nl);
            put32(&mut es, e.prim.pack());
            put32(&mut es, e.prim.size as u32);
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
        let mut ss = Vec::with_capacity(o.syms.len() * SYMBOL_SZ);
        let mut cdata: Vec<u8> = Vec::new();
        let mut hashes = Vec::with_capacity(o.syms.len());
        for s in &o.syms {
            let (no, nl) = w.raw(s.name.as_bytes());
            hashes.push(s.hash);
            put32(&mut ss, no);
            put32(&mut ss, nl);
            put64(&mut ss, s.address as u64);
            put32(&mut ss, s.ty);
            match (o.sym_cdata, &s.constant_data) {
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
        for n in &o.natives {
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
    sections[sec::META] = o.meta.as_bytes().to_vec();
    sections[sec::STRINGS] = std::mem::take(&mut w.strings);

    // ---- assemble
    let mut out = Vec::with_capacity(HDR_SZ + sections.iter().map(|s| s.len() + 8).sum::<usize>());
    out.extend_from_slice(MAGIC);
    put32(&mut out, BLOB_VERSION);
    put32(&mut out, sec::N as u32);
    let table_pos = out.len();
    out.resize(HDR_SZ, 0);
    let fo = 16 + sec::N * 16;
    for (i, v) in o.fparts.iter().take(3).enumerate() {
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
    out
}

/// Slot count of an [`index_into`] table for `n` keys.
fn index_slots(n: usize) -> usize {
    if n == 0 { 0 } else { (n * 2).next_power_of_two().max(4) }
}

/// [`index_into`] writing straight into a zeroed region of `index_slots(n) * 4` bytes.
fn index_into_region(n: usize, hash: impl Fn(usize) -> u64, region: &mut [u8]) {
    let slots = region.len() / 4;
    if slots == 0 {
        return;
    }
    let mask = slots - 1;
    for i in 0..n {
        let mut j = hash(i) as usize & mask;
        while region[j * 4..j * 4 + 4] != [0, 0, 0, 0] {
            j = (j + 1) & mask;
        }
        region[j * 4..j * 4 + 4].copy_from_slice(&(i as u32 + 1).to_le_bytes());
    }
}

/// A raw pointer to the blob being filled, shared by the fill tasks (each writes disjoint
/// byte ranges).
#[derive(Clone, Copy)]
struct BlobPtr(*mut u8, usize);
// SAFETY: tasks write disjoint ranges of the buffer, which outlives the scoped threads
unsafe impl Send for BlobPtr {}
unsafe impl Sync for BlobPtr {}

impl BlobPtr {
    /// The byte range `[off, off + len)` of the blob.
    ///
    /// SAFETY: the caller guarantees no other live slice overlaps this range.
    #[allow(clippy::mut_from_ref)]
    unsafe fn slice(&self, off: usize, len: usize) -> &mut [u8] {
        assert!(off + len <= self.1);
        unsafe { std::slice::from_raw_parts_mut(self.0.add(off), len) }
    }
}

/// [`serialize`] in two passes: a sequential layout pass (string pool interning in blob order,
/// every section's size and offset), then all sections written in parallel into one
/// preallocated buffer (no per-section vectors, no assembly copy). Same bytes.
fn serialize_fast(o: &Out<'_>) -> Vec<u8> {
    let _t = crate::util::trace::span("isf serialize");
    let nu = o.users.len();
    let total_members: usize = o.users.iter().map(|u| u.members.len()).sum();
    let threads = crate::util::par::threads();
    let par = threads > 1 && total_members + o.syms.len() + o.nodes.len() > 30_000;
    // user ranges (by member count) for the parallel passes
    let uranges: Vec<std::ops::Range<usize>> = {
        let per = (total_members / (threads * 4)).max(2048);
        let mut v = Vec::new();
        let (mut s, mut acc) = (0, 0);
        for (i, u) in o.users.iter().enumerate() {
            acc += u.members.len() + 1;
            if acc >= per {
                v.push(s..i + 1);
                s = i + 1;
                acc = 0;
            }
        }
        if s < nu || v.is_empty() {
            v.push(s..nu);
        }
        v
    };
    let mfirst_of: Vec<u32> = {
        let mut v = Vec::with_capacity(nu + 1);
        let mut acc = 0u32;
        for u in &o.users {
            v.push(acc);
            acc += u.members.len() as u32;
        }
        v.push(acc);
        v
    };
    // ---- member name hashes (parallel)
    let _ts = crate::util::trace::span("isf serialize: member hashes");
    let mut mhash: Vec<u64> = vec![0; total_members];
    {
        let mp = BlobPtr(mhash.as_mut_ptr() as *mut u8, total_members * 8);
        let job = |r: &std::ops::Range<usize>| {
            for i in r.clone() {
                let base = mfirst_of[i] as usize;
                for (k, m) in o.users[i].members.iter().enumerate() {
                    let h = hash_bytes(m.0.as_bytes());
                    // SAFETY: member slots of disjoint user ranges are disjoint
                    unsafe { mp.slice((base + k) * 8, 8) }.copy_from_slice(&h.to_ne_bytes());
                }
            }
        };
        if par {
            crate::util::pool::for_each(uranges.len(), &|i| job(&uranges[i]));
        } else {
            uranges.iter().for_each(job);
        }
    }

    drop(_ts);
    let _ts = crate::util::trace::span("isf serialize: layout");
    // ---- layout pass: the string pool in blob order (member / constant names interned)
    let mut pool: u64 = 0;
    let mut take = |len: usize| -> u32 {
        let off = pool as u32;
        pool += len as u64;
        off
    };
    // intern table over first occurrences: open addressing on the precomputed hashes
    struct Interned<'n> {
        slots: Vec<u32>,
        first: Vec<(&'n str, u32, u64)>,
    }
    impl<'n> Interned<'n> {
        fn find_or_add(&mut self, name: &'n str, h: u64, take: &mut impl FnMut(usize) -> u32) -> (u32, bool) {
            if self.first.len() * 2 >= self.slots.len() {
                let n = (self.slots.len() * 2).max(1024);
                let mut slots = vec![0u32; n];
                for (i, &(_, _, fh)) in self.first.iter().enumerate() {
                    let mut j = fh as usize & (n - 1);
                    while slots[j] != 0 {
                        j = (j + 1) & (n - 1);
                    }
                    slots[j] = i as u32 + 1;
                }
                self.slots = slots;
            }
            let mask = self.slots.len() - 1;
            let mut j = h as usize & mask;
            loop {
                match self.slots[j] {
                    0 => {
                        let off = take(name.len());
                        self.first.push((name, off, h));
                        self.slots[j] = self.first.len() as u32;
                        return (off, true);
                    }
                    x => {
                        let (fname, off, fh) = self.first[x as usize - 1];
                        if fh == h && fname == name {
                            return (off, false);
                        }
                        j = (j + 1) & mask;
                    }
                }
            }
        }
    }
    let mut interned = Interned { slots: Vec::new(), first: Vec::new() };
    let unres_off: Vec<u32> = o.unresolved.iter().map(|(_, n)| take(n.len())).collect();
    let mut user_off: Vec<u32> = Vec::with_capacity(nu);
    let mut member_off: Vec<u32> = Vec::with_capacity(total_members);
    let mut member_new: Vec<bool> = Vec::with_capacity(total_members);
    for (i, u) in o.users.iter().enumerate() {
        user_off.push(take(u.name.len()));
        let base = mfirst_of[i] as usize;
        for (k, m) in u.members.iter().enumerate() {
            let (off, new) = interned.find_or_add(&m.0, mhash[base + k], &mut take);
            member_off.push(off);
            member_new.push(new);
        }
    }
    let mut enum_off: Vec<u32> = Vec::with_capacity(o.enums.len());
    let mut const_off: Vec<(u32, bool)> = Vec::new();
    for e in &o.enums {
        enum_off.push(take(e.name.len()));
        for (cn, _) in &e.constants {
            const_off.push(interned.find_or_add(cn, hash_bytes(cn.as_bytes()), &mut take));
        }
    }
    let sym_off: Vec<u32> = o.syms.iter().map(|s| take(s.name.len())).collect();
    let native_off: Vec<u32> = o.natives.iter().map(|n| take(n.name.len())).collect();
    let pool_len = pool as usize;
    // constant data (few symbols)
    let mut cdata: Vec<(usize, Vec<u8>)> = Vec::new();
    if o.sym_cdata {
        for (i, s) in o.syms.iter().enumerate() {
            if let Some(cd) = &s.constant_data {
                cdata.push((i, b64decode(cd)));
            }
        }
    }
    let cdata_len: usize = cdata.iter().map(|c| c.1.len()).sum();
    let hstart_of: Vec<u32> = {
        let mut v = Vec::with_capacity(nu + 1);
        let mut acc = 0u32;
        for u in &o.users {
            v.push(acc);
            acc += index_slots(u.members.len()) as u32;
        }
        v.push(acc);
        v
    };
    let nconsts: usize = o.enums.iter().map(|e| e.constants.len()).sum();
    let mut sizes = [0usize; sec::N];
    sizes[sec::STRINGS] = pool_len;
    sizes[sec::NODES] = o.nodes.len() * NODE_SZ;
    sizes[sec::UTYPES] = nu * UTYPE_SZ;
    sizes[sec::MEMBERS] = total_members * MEMBER_SZ;
    sizes[sec::MHASH] = hstart_of[nu] as usize * 4;
    sizes[sec::ENUMS] = o.enums.len() * ENUM_SZ;
    sizes[sec::CONSTS] = nconsts * CONST_SZ;
    sizes[sec::SYMBOLS] = o.syms.len() * SYMBOL_SZ;
    sizes[sec::BASES] = o.natives.len() * BASE_SZ;
    sizes[sec::H_UTYPES] = index_slots(nu) * 4;
    sizes[sec::H_SYMBOLS] = index_slots(o.syms.len()) * 4;
    sizes[sec::H_ENUMS] = index_slots(o.enums.len()) * 4;
    sizes[sec::H_BASES] = index_slots(o.natives.len()) * 4;
    sizes[sec::META] = o.meta.len();
    sizes[sec::CDATA] = cdata_len;
    let mut offs = [0usize; sec::N];
    let mut total = HDR_SZ;
    for i in 0..sec::N {
        total = total.next_multiple_of(8);
        offs[i] = total;
        total += sizes[i];
    }
    drop(_ts);
    let _ts = crate::util::trace::span("isf serialize: fill");
    let mut blob = vec![0u8; total];
    blob[..8].copy_from_slice(MAGIC);
    blob[8..12].copy_from_slice(&BLOB_VERSION.to_le_bytes());
    blob[12..16].copy_from_slice(&(sec::N as u32).to_le_bytes());
    for i in 0..sec::N {
        let p = 16 + i * 16;
        blob[p..p + 8].copy_from_slice(&(offs[i] as u64).to_le_bytes());
        blob[p + 8..p + 16].copy_from_slice(&(sizes[i] as u64).to_le_bytes());
    }
    let fo = 16 + sec::N * 16;
    for (i, v) in o.fparts.iter().take(3).enumerate() {
        blob[fo + i * 4..fo + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }

    // ---- fill (parallel tasks over disjoint byte ranges)
    let bp = BlobPtr(blob.as_mut_ptr(), total);
    let ps = offs[sec::STRINGS];
    let sranges: Vec<std::ops::Range<usize>> = {
        let per = (o.syms.len() / (threads * 2)).max(4096);
        (0..o.syms.len()).step_by(per.max(1)).map(|s| s..(s + per).min(o.syms.len())).collect()
    };
    let nranges: Vec<std::ops::Range<usize>> = {
        let per = (o.nodes.len() / threads).max(8192);
        (0..o.nodes.len()).step_by(per.max(1)).map(|s| s..(s + per).min(o.nodes.len())).collect()
    };
    enum Task {
        HSymbols,
        Misc,
        Users(usize),
        Syms(usize),
        Nodes(usize),
    }
    let mut tasks = vec![Task::HSymbols, Task::Misc];
    tasks.extend((0..uranges.len()).map(Task::Users));
    tasks.extend((0..sranges.len()).map(Task::Syms));
    tasks.extend((0..nranges.len()).map(Task::Nodes));
    // SAFETY (all tasks): each writes only its own sections / sub-ranges, fixed by the layout
    let run = |t: usize| unsafe {
        match tasks[t] {
            Task::HSymbols => index_into_region(o.syms.len(), |i| o.syms[i].hash, bp.slice(offs[sec::H_SYMBOLS], sizes[sec::H_SYMBOLS])),
            Task::Misc => {
                for ((_, n), &off) in o.unresolved.iter().zip(&unres_off) {
                    bp.slice(ps + off as usize, n.len()).copy_from_slice(n.as_bytes());
                }
                // enums + constants
                let (eo, co) = (offs[sec::ENUMS], offs[sec::CONSTS]);
                let (mut ci, mut ccount) = (0usize, 0u32);
                for (i, e) in o.enums.iter().enumerate() {
                    bp.slice(ps + enum_off[i] as usize, e.name.len()).copy_from_slice(e.name.as_bytes());
                    let r = bp.slice(eo + i * ENUM_SZ, ENUM_SZ);
                    r[0..4].copy_from_slice(&enum_off[i].to_le_bytes());
                    r[4..8].copy_from_slice(&(e.name.len() as u32).to_le_bytes());
                    r[8..12].copy_from_slice(&e.prim.pack().to_le_bytes());
                    r[12..16].copy_from_slice(&(e.prim.size as u32).to_le_bytes());
                    r[16..20].copy_from_slice(&ccount.to_le_bytes());
                    r[20..24].copy_from_slice(&(e.constants.len() as u32).to_le_bytes());
                    for (cn, v) in &e.constants {
                        let (off, new) = const_off[ci];
                        if new {
                            bp.slice(ps + off as usize, cn.len()).copy_from_slice(cn.as_bytes());
                        }
                        let c = bp.slice(co + ci * CONST_SZ, CONST_SZ);
                        c[0..4].copy_from_slice(&off.to_le_bytes());
                        c[4..8].copy_from_slice(&(cn.len() as u32).to_le_bytes());
                        c[8..16].copy_from_slice(&(*v as i64 as u64).to_le_bytes());
                        ci += 1;
                    }
                    ccount += e.constants.len() as u32;
                }
                // natives
                let bo = offs[sec::BASES];
                for (i, n) in o.natives.iter().enumerate() {
                    bp.slice(ps + native_off[i] as usize, n.name.len()).copy_from_slice(n.name.as_bytes());
                    let prim = match n.ty {
                        Ty::Int(p) | Ty::Float(p) => p,
                        Ty::Pointer { prim, .. } => prim,
                        _ => Prim { size: 0, signed: false, big_endian: false, kind: PrimKind::Void, name: Prim::NO_NAME },
                    };
                    let r = bp.slice(bo + i * BASE_SZ, BASE_SZ);
                    r[0..4].copy_from_slice(&native_off[i].to_le_bytes());
                    r[4..8].copy_from_slice(&(n.name.len() as u32).to_le_bytes());
                    r[8..12].copy_from_slice(&prim.pack().to_le_bytes());
                    r[12..16].copy_from_slice(&base_code(&n.ty).to_le_bytes());
                }
                index_into_region(o.natives.len(), |i| hash_bytes(o.natives[i].name.as_bytes()), bp.slice(offs[sec::H_BASES], sizes[sec::H_BASES]));
                index_into_region(o.enums.len(), |i| o.enums[i].hash, bp.slice(offs[sec::H_ENUMS], sizes[sec::H_ENUMS]));
                index_into_region(nu, |i| o.users[i].hash, bp.slice(offs[sec::H_UTYPES], sizes[sec::H_UTYPES]));
                bp.slice(offs[sec::META], o.meta.len()).copy_from_slice(o.meta.as_bytes());
                // constant data, in symbol order
                let mut at = offs[sec::CDATA];
                for (_, d) in &cdata {
                    bp.slice(at, d.len()).copy_from_slice(d);
                    at += d.len();
                }
            }
            Task::Users(r) => {
                let (uo, mo, ho) = (offs[sec::UTYPES], offs[sec::MEMBERS], offs[sec::MHASH]);
                for i in uranges[r].clone() {
                    let u = &o.users[i];
                    bp.slice(ps + user_off[i] as usize, u.name.len()).copy_from_slice(u.name.as_bytes());
                    let base = mfirst_of[i] as usize;
                    for (k, (name, off, ty)) in u.members.iter().enumerate() {
                        let g = base + k;
                        if member_new[g] {
                            bp.slice(ps + member_off[g] as usize, name.len()).copy_from_slice(name.as_bytes());
                        }
                        let m = bp.slice(mo + g * MEMBER_SZ, MEMBER_SZ);
                        m[0..4].copy_from_slice(&member_off[g].to_le_bytes());
                        m[4..8].copy_from_slice(&(name.len() as u32).to_le_bytes());
                        m[8..16].copy_from_slice(&off.to_le_bytes());
                        m[16..32].copy_from_slice(&ty_encode(ty));
                    }
                    let n = u.members.len();
                    let hs = hstart_of[i] as usize;
                    let hl = hstart_of[i + 1] as usize - hs;
                    index_into_region(n, |k| mhash[base + k], bp.slice(ho + hs * 4, hl * 4));
                    let t = bp.slice(uo + i * UTYPE_SZ, UTYPE_SZ);
                    for (w, v) in [user_off[i], u.name.len() as u32, u.kind, u.size.clamp(0, u32::MAX as i128) as u32, base as u32, n as u32, hs as u32, hl as u32].iter().enumerate() {
                        t[w * 4..w * 4 + 4].copy_from_slice(&v.to_le_bytes());
                    }
                }
            }
            Task::Syms(r) => {
                let so = offs[sec::SYMBOLS];
                // this range's first constant-data offset
                let first = sranges[r].start;
                let k0 = cdata.partition_point(|c| c.0 < first);
                let mut coff: u32 = cdata[..k0].iter().map(|c| c.1.len() as u32).sum();
                let mut k = k0;
                for i in sranges[r].clone() {
                    let s = &o.syms[i];
                    bp.slice(ps + sym_off[i] as usize, s.name.len()).copy_from_slice(s.name.as_bytes());
                    let rec = bp.slice(so + i * SYMBOL_SZ, SYMBOL_SZ);
                    rec[0..4].copy_from_slice(&sym_off[i].to_le_bytes());
                    rec[4..8].copy_from_slice(&(s.name.len() as u32).to_le_bytes());
                    rec[8..16].copy_from_slice(&(s.address as u64).to_le_bytes());
                    rec[16..20].copy_from_slice(&s.ty.to_le_bytes());
                    if k < cdata.len() && cdata[k].0 == i {
                        let l = cdata[k].1.len() as u32;
                        rec[20..24].copy_from_slice(&1u32.to_le_bytes());
                        rec[24..28].copy_from_slice(&coff.to_le_bytes());
                        rec[28..32].copy_from_slice(&l.to_le_bytes());
                        coff += l;
                        k += 1;
                    }
                }
            }
            Task::Nodes(r) => {
                let no = offs[sec::NODES];
                for i in nranges[r].clone() {
                    bp.slice(no + i * NODE_SZ, NODE_SZ).copy_from_slice(&ty_encode(&o.nodes[i]));
                }
                // unresolved holders carry their name (pool offset, length)
                let lo = o.unresolved.partition_point(|u| (u.0 as usize) < nranges[r].start);
                for (j, (ni, n)) in o.unresolved.iter().enumerate().skip(lo) {
                    if *ni as usize >= nranges[r].end {
                        break;
                    }
                    let e = bp.slice(no + *ni as usize * NODE_SZ, NODE_SZ);
                    e[4..8].copy_from_slice(&unres_off[j].to_le_bytes());
                    e[8..12].copy_from_slice(&(n.len() as u32).to_le_bytes());
                }
            }
        }
    };
    if par {
        crate::util::pool::for_each(tasks.len(), &run);
    } else {
        (0..tasks.len()).for_each(run);
    }
    blob
}

/// Parse ISF JSON bytes into a ready table (no caching).
pub fn load_table(json: &[u8], name: &str, url: &str, opts: &BuildOptions) -> Result<SymbolTable> {
    let blob = build_blob(json, opts)?;
    SymbolTable::from_blob(Blob::Owned(blob), name, url)
}

// ---------------------------------------------------------------------------------------------
// The fused parallel builder
// ---------------------------------------------------------------------------------------------

/// Parse + resolve in one pass per range of `user_types` / `symbols` / `enums` members, on all
/// cores, straight from the structural index: no document-wide descriptor list, no separate
/// resolution walk. Type nodes are created in per-range tables and replayed into the global
/// table in the reference builder's order (all user types in order, then all symbols), so the
/// blob is byte-identical to [`build_from`]'s.
///
/// Handles well-formed ISFs whose sections each appear once with unique member names; returns
/// `None` for anything else (repeated names or sections, unexpected shapes, invalid JSON), and
/// the caller takes the reference path, which also produces the errors.
mod fast {
    use super::*;
    use crate::util::jsonidx::Walker;
    use std::ops::Range;

    /// A member of the root object.
    struct Member<'a> {
        key: Cow<'a, str>,
        /// entry of the value
        value: usize,
        /// `{...}` / `[...]` values: entry of the closing bracket
        close: Option<usize>,
        /// `{...}` values: range of member-key entries in `keys2`
        keys: Range<usize>,
        is_obj: bool,
    }

    /// A node creation in a range's local table (replayed in order into the global table).
    enum LNode<'a> {
        /// python-less "unresolved name" holder of the descriptor at this entry
        Holder(u32, Cow<'a, str>),
        /// an interned type (its references are local indexes)
        Value(Ty),
    }

    #[derive(Default)]
    struct Local<'a> {
        nodes: Vec<LNode<'a>>,
        by_value: FxHashMap<Ty, u32>,
        holders: FxHashMap<u32, Ty>,
    }

    impl<'a> Local<'a> {
        /// `Resolver::node`: intern by value.
        fn node(&mut self, t: Ty) -> TypeIdx {
            if let Some(&i) = self.by_value.get(&t) {
                return TypeIdx(i);
            }
            let i = self.nodes.len() as u32;
            self.nodes.push(LNode::Value(t));
            self.by_value.insert(t, i);
            TypeIdx(i)
        }
        /// `Resolver::unresolved`, memoized per descriptor (the reference memoizes every
        /// descriptor's result).
        fn unresolved(&mut self, id: u32, name: &str) -> Ty {
            if let Some(&t) = self.holders.get(&id) {
                return t;
            }
            let i = self.nodes.len() as u32;
            self.nodes.push(LNode::Holder(id, Cow::Owned(name.to_string())));
            let t = Ty::Unresolved(TypeIdx(i));
            self.holders.insert(id, t);
            t
        }
    }

    /// Shared, read-only resolution context.
    struct Ctx<'a, 's> {
        natives: &'s [NativeDef],
        native_idx: &'s FxHashMap<&'s str, usize>,
        utype_idx: &'s FxHashMap<&'s str, u32>,
        enum_idx: &'s FxHashMap<&'s str, u32>,
        enum_bases: &'s [Cow<'a, str>],
        /// value entry of every user type (random access for anonymous flattening)
        user_values: &'s [u32],
        flatten: bool,
        sym_types: bool,
    }

    /// A field as read (its type descriptor in the range's arena).
    struct FieldTmp<'a> {
        name: Cow<'a, str>,
        offset: i128,
        anonymous: bool,
        ty: Option<u32>,
    }

    /// Read a descriptor object into `arena` (the reference `parse_desc`, plus its identity:
    /// the entry of its `{`).
    fn read_desc<'a>(w: &mut Walker<'_, 'a>, arena: &mut Vec<Desc<'a>>) -> Result<u32> {
        let id = w.entry() as u32;
        let mut d = Desc::default();
        w.object(|w, k| {
            match k.as_ref() {
                "kind" => d.kind = w.str()?,
                "name" => d.name = Some(w.str()?),
                "base" => {
                    if w.peek_kind()? == Kind::Str {
                        d.base = Some(w.str()?)
                    } else {
                        w.skip()?
                    }
                }
                "count" => d.count = w.int()?,
                "bit_position" => d.bit_position = w.int()?,
                "bit_length" => d.bit_length = w.int()?,
                "subtype" | "type" => d.sub = Some(read_desc(w, arena)?),
                _ => w.skip()?,
            }
            Ok(())
        })?;
        d.id = id;
        arena.push(d);
        Ok(arena.len() as u32 - 1)
    }

    /// A `user_types` member value: (kind, size, fields) like the reference `parse_user`.
    fn read_user<'a>(w: &mut Walker<'_, 'a>, arena: &mut Vec<Desc<'a>>) -> Result<(Cow<'a, str>, i128, Vec<FieldTmp<'a>>)> {
        let mut kind = Cow::Borrowed("struct");
        let mut fields: Vec<FieldTmp<'a>> = Vec::new();
        let mut size = None;
        let mut length = None;
        w.object(|w, k| {
            match k.as_ref() {
                "kind" => kind = w.str()?,
                "size" => size = Some(w.int()?),
                "length" => length = Some(w.int()?),
                "fields" => {
                    if w.peek_kind()? != Kind::Obj {
                        w.skip()?;
                        return Ok(());
                    }
                    fields.clear();
                    w.object(|w, fname| {
                        let mut f = FieldTmp { name: fname, offset: 0, anonymous: false, ty: None };
                        w.object(|w, k| {
                            match k.as_ref() {
                                "offset" => f.offset = w.int()?,
                                "anonymous" => f.anonymous = w.bool()?,
                                "type" => f.ty = Some(read_desc(w, arena)?),
                                _ => w.skip()?,
                            }
                            Ok(())
                        })?;
                        fields.push(f);
                        Ok(())
                    })?;
                    dict_dedupe(&mut fields, |f| &f.name)
                }
                _ => w.skip()?,
            }
            Ok(())
        })?;
        Ok((kind, size.or(length).unwrap_or(0), fields))
    }

    impl<'a, 's> Ctx<'a, 's> {
        fn native(&self, name: &str) -> Option<Ty> {
            self.native_idx.get(name).map(|&i| self.natives[i].ty)
        }
        fn is_native_type(&self, name: &str) -> bool {
            self.native_idx.contains_key(name) || matches!(name, "enum" | "array" | "bitfield" | "void" | "string" | "bytes" | "function")
        }
        fn int_prim(&self, t: Ty) -> Option<Prim> {
            match t {
                Ty::Int(p) | Ty::Float(p) => Some(p),
                Ty::Enum(i) => match self.native(self.enum_bases.get(i as usize)?) {
                    Some(Ty::Int(p)) => Some(p),
                    _ => None,
                },
                Ty::Pointer { prim, .. } => Some(prim),
                _ => None,
            }
        }

        /// The reference `Resolver::desc_uncached` over the arena.
        fn resolve(&self, arena: &[Desc<'a>], di: u32, l: &mut Local<'a>) -> Ty {
            let d = &arena[di as usize];
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
                            Some(s) => self.resolve(arena, s, l),
                            None => Ty::Void,
                        };
                        let elem = l.node(elem);
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
                            Some(s) => self.resolve(arena, s, l),
                            None => Ty::Void,
                        };
                        let target = l.node(target);
                        return Ty::Pointer { prim, target };
                    }
                    "enum" => {
                        let name = d.name.as_deref().unwrap_or("");
                        return match self.enum_idx.get(name) {
                            Some(&i) => Ty::Enum(i),
                            None => l.unresolved(d.id, name),
                        };
                    }
                    "bitfield" => {
                        let base = match d.sub {
                            Some(s) => self.resolve(arena, s, l),
                            None => Ty::Void,
                        };
                        let start = d.bit_position.clamp(0, 255) as u8;
                        let end = (d.bit_position + d.bit_length).clamp(0, 255) as u8;
                        return match self.int_prim(base) {
                            Some(p) => Ty::BitField { start, end, base: p },
                            None => l.unresolved(d.id, "bitfield"),
                        };
                    }
                    "string" => return Ty::String { max_len: 0, enc: StrEnc::Utf8, errors: StrErrors::Strict },
                    "bytes" => return Ty::Bytes(0),
                    _ => return self.native(type_name).unwrap_or(Ty::Void),
                }
            }
            if matches!(&*d.kind, "struct" | "union" | "class") {
                let name = d.name.as_deref().unwrap_or("");
                if !name.contains('!') {
                    if let Some(&i) = self.utype_idx.get(name) {
                        return Ty::Struct(i);
                    }
                }
                return l.unresolved(d.id, name);
            }
            l.unresolved(d.id, type_name)
        }

        /// A user type's members (reference: the user-type loop of `build_from`), types in
        /// local node indexes.
        fn members(&self, w: &mut Walker<'_, 'a>, fields: &[FieldTmp<'a>], arena: &[Desc<'a>], l: &mut Local<'a>) -> Result<Vec<(Cow<'a, str>, u64, Ty)>> {
            let mut members: Vec<(Cow<'a, str>, u64, Ty)> = Vec::with_capacity(fields.len());
            let needs_flatten = self.flatten && fields.iter().any(|f| f.anonymous);
            if !needs_flatten {
                for f in fields {
                    let ty = match f.ty {
                        Some(t) => self.resolve(arena, t, l),
                        None => Ty::Void,
                    };
                    members.push((f.name.clone(), f.offset.clamp(i64::MIN as i128, i64::MAX as i128) as i64 as u64, ty));
                }
                return Ok(members);
            }
            // anonymous members: depth-first over the anonymous sub-types' fields (each read
            // from its own member value), last name wins at its first position
            struct Frame<'a> {
                fields: Vec<FieldTmp<'a>>,
                arena: Vec<Desc<'a>>,
            }
            let mut frames: Vec<Frame<'a>> = Vec::new();
            // (frame: usize::MAX = the type's own fields, field index, parent offset)
            let mut stack: Vec<(usize, usize, i128)> = vec![(usize::MAX, 0, 0)];
            let mut pos: FxHashMap<Cow<'a, str>, usize> = FxHashMap::default();
            let mut depth_guard = 0;
            while let Some((fr, i, parent_off)) = stack.pop() {
                let (flist, ar): (&[FieldTmp<'a>], &[Desc<'a>]) = if fr == usize::MAX { (fields, arena) } else { (&frames[fr].fields, &frames[fr].arena) };
                if i >= flist.len() {
                    continue;
                }
                stack.push((fr, i + 1, parent_off));
                let f = &flist[i];
                let new_off = parent_off + f.offset;
                if f.anonymous {
                    let sub = f.ty.and_then(|t| ar[t as usize].name.as_deref()).and_then(|n| self.utype_idx.get(n).copied());
                    if let Some(si) = sub {
                        depth_guard += 1;
                        if depth_guard < 100_000 {
                            let mut sub_arena = Vec::new();
                            w.seek(self.user_values[si as usize] as usize);
                            let (_, _, sub_fields) = read_user(w, &mut sub_arena)?;
                            frames.push(Frame { fields: sub_fields, arena: sub_arena });
                            stack.push((frames.len() - 1, 0, new_off));
                        }
                    }
                    continue;
                }
                let ty = match f.ty {
                    Some(t) => self.resolve(ar, t, l),
                    None => Ty::Void,
                };
                let off = new_off.clamp(i64::MIN as i128, i64::MAX as i128) as i64 as u64;
                let name = f.name.clone();
                match pos.get(&name) {
                    Some(&k) => members[k] = (name, off, ty),
                    None => {
                        pos.insert(name.clone(), members.len());
                        members.push((name, off, ty));
                    }
                }
            }
            Ok(members)
        }
    }

    /// Output of one work item.
    enum Part<'a> {
        Users(Vec<UserOut<'a>>, Local<'a>),
        Syms(Vec<SymOut<'a>>, Local<'a>),
    }

    /// Remap a local type (references into the range's table) to the global table.
    fn remap(t: Ty, m: &[u32]) -> Ty {
        match t {
            Ty::Pointer { prim, target } => Ty::Pointer { prim, target: TypeIdx(m[target.0 as usize]) },
            Ty::Array { count, elem } => Ty::Array { count, elem: TypeIdx(m[elem.0 as usize]) },
            Ty::Unresolved(h) => Ty::Unresolved(TypeIdx(m[h.0 as usize])),
            t => t,
        }
    }

    /// Byte-balanced ranges over `keys` (member-key entries, in order).
    fn ranges(w: &Walker, keys: &[u32], total_bytes: usize, threads: usize) -> Vec<Range<usize>> {
        let per = (total_bytes / (threads * 4)).max(64 << 10);
        let mut out = Vec::new();
        let mut s = 0;
        while s < keys.len() {
            let lim = w.pos_of(keys[s] as usize) + per;
            let (mut e, mut hi) = (s + 1, keys.len());
            while e < hi {
                let mid = (e + hi) / 2;
                if w.pos_of(keys[mid] as usize) <= lim {
                    e = mid + 1;
                } else {
                    hi = mid;
                }
            }
            out.push(s..e);
            s = e;
        }
        out
    }

    /// Names of a section's members (key strings), their hashes, and whether one repeats.
    fn names<'a>(w: &Walker<'_, 'a>, keys: &[u32]) -> Option<(Vec<Cow<'a, str>>, Vec<u64>)> {
        let mut names = Vec::with_capacity(keys.len());
        let mut hashes = Vec::with_capacity(keys.len());
        for &k in keys {
            let n = w.string_at(k as usize).ok()?;
            hashes.push(hash_bytes(n.as_bytes()));
            names.push(n);
        }
        (!has_repeats(&names, &hashes)).then_some((names, hashes))
    }

    /// Whether any name repeats (open addressing on the precomputed hashes).
    fn has_repeats(names: &[Cow<'_, str>], hashes: &[u64]) -> bool {
        let n = names.len();
        if n < 2 {
            return false;
        }
        let mask = (2 * n).next_power_of_two() - 1;
        let mut table = vec![u32::MAX; mask + 1];
        for (i, &h) in hashes.iter().enumerate() {
            let mut j = h as usize & mask;
            loop {
                match table[j] {
                    u32::MAX => {
                        table[j] = i as u32;
                        break;
                    }
                    x if hashes[x as usize] == h && names[x as usize] == names[i] => return true,
                    _ => j = (j + 1) & mask,
                }
            }
        }
        false
    }

    /// Parse the members `keys[r]` of a big section: each member = key, ':', value, then ','
    /// before the next key, or the section's closing '}' (`close`) after the last one.
    fn each_member<'d, 'a>(w: &mut Walker<'d, 'a>, keys: &[u32], r: Range<usize>, close: usize, mut f: impl FnMut(&mut Walker<'d, 'a>, usize, Cow<'a, str>) -> Result<()>) -> Option<()> {
        for j in r {
            let ke = keys[j] as usize;
            if w.ch(ke + 2) != b':' {
                return None;
            }
            let name = w.string_at(ke).ok()?;
            w.seek(ke + 3);
            f(w, j, name).ok()?;
            let at = w.entry();
            let ok = match keys.get(j + 1) {
                Some(&next) => w.ch(at) == b',' && at + 1 == next as usize,
                None => at == close,
            };
            if !ok {
                return None;
            }
        }
        Some(())
    }

    pub(super) fn build(json: &[u8], opts: &BuildOptions) -> Result<Option<Vec<u8>>> {
        Ok(build_opt(json, opts))
    }

    fn build_opt(json: &[u8], opts: &BuildOptions) -> Option<Vec<u8>> {
        let threads = crate::util::par::threads();
        let par = json.len() >= PAR_PARSE_MIN && threads > 1;
        let idx = {
            let _t = crate::util::trace::span("isf: stage 1");
            Index::build_with(json, par).ok()?
        };
        let _t = crate::util::trace::span("isf: build (fused)");
        let w = idx.walker(json);
        if w.ch(0) != b'{' {
            return None;
        }
        // ---- the root object's members from the structure events
        let _tp = crate::util::trace::span("isf: top events + small sections");
        let ev = idx.top_events(json);
        let mut members: Vec<Member> = Vec::new();
        let mut keys2: Vec<u32> = Vec::new();
        let mut k = 0;
        while k < ev.len() {
            let (e, kind) = ev[k];
            if kind != Ev::TopKey {
                return None;
            }
            let e = e as usize;
            if w.ch(e + 2) != b':' {
                return None;
            }
            let key = w.string_at(e).ok()?;
            let value = e + 3;
            k += 1;
            let mut m = Member { key, value, close: None, keys: keys2.len()..keys2.len(), is_obj: false };
            if ev.get(k).is_some_and(|&(x, t)| t == Ev::Open1 && x as usize == value) {
                m.is_obj = w.ch(value) == b'{';
                k += 1;
                let start = keys2.len();
                while k < ev.len() && ev[k].1 == Ev::Key2 {
                    if m.is_obj {
                        keys2.push(ev[k].0);
                    }
                    k += 1;
                }
                match ev.get(k) {
                    Some(&(x, Ev::Close1)) => m.close = Some(x as usize),
                    _ => return None,
                }
                k += 1;
                m.keys = start..keys2.len();
            }
            members.push(m);
        }
        if members.is_empty() || members[0].value != 4 {
            return None;
        }
        for m in &members {
            if m.is_obj {
                let first_ok = match m.keys.clone().next() {
                    Some(j) => keys2[j] as usize == m.value + 1,
                    None => m.close == Some(m.value + 1),
                };
                if !first_ok {
                    return None;
                }
            }
        }
        // entry after member i's value: ',' + member i+1's key, or the root's '}'
        let sep_ok = |i: usize, end: usize| -> bool {
            match members.get(i + 1) {
                Some(n) => w.ch(end) == b',' && end + 1 == n.value - 3,
                None => w.ch(end) == b'}',
            }
        };

        // ---- small members sequentially; the big sections are located
        let mut seen = [false; 5];
        let mut metadata: Option<Json> = None;
        let mut bases: Vec<(Cow<str>, BaseDef)> = Vec::new();
        let mut big: [Option<usize>; 5] = [None; 5];
        for (mi, m) in members.iter().enumerate() {
            let sec = section_of(&m.key);
            if let Some(s) = sec {
                if seen[s] {
                    return None; // a repeated section: reference path
                }
                seen[s] = true;
            }
            let mut p = idx.walker(json);
            p.seek(m.value);
            match sec {
                Some(S_META) => metadata = Some(p.value().ok()?),
                Some(S_BASES) => {
                    p.object(|p, name| {
                        let b = parse_base(p)?;
                        bases.push((name, b));
                        Ok(())
                    })
                    .ok()?;
                    dict_dedupe(&mut bases, |b| &b.0);
                }
                Some(s) => {
                    if !m.is_obj {
                        return None;
                    }
                    big[s] = Some(mi);
                    if !sep_ok(mi, m.close? + 1) {
                        return None;
                    }
                    continue;
                }
                None => p.skip().ok()?,
            }
            let end = p.entry();
            if m.close.is_some_and(|c| end != c + 1) || !sep_ok(mi, end) {
                return None;
            }
        }
        let (version, fparts) = check_header(&seen, metadata.as_ref()).ok()?;
        let natives = make_natives(version, &bases, opts).ok()?;
        let native_idx: FxHashMap<&str, usize> = natives.iter().enumerate().map(|(i, n)| (n.name.as_str(), i)).collect();
        let (mu, me, ms) = (&members[big[S_USERS]?], &members[big[S_ENUMS]?], &members[big[S_SYMBOLS]?]);
        let (ukeys, ekeys, skeys) = (&keys2[mu.keys.clone()], &keys2[me.keys.clone()], &keys2[ms.keys.clone()]);

        drop(_tp);
        let _tp = crate::util::trace::span("isf: names + enums");
        // ---- names of the user types and enums (resolution needs them up front)
        let (unames, uhashes) = names(&w, ukeys)?;
        let (enames, ehashes) = names(&w, ekeys)?;
        let utype_idx: FxHashMap<&str, u32> = unames.iter().enumerate().map(|(i, n)| (n.as_ref(), i as u32)).collect();
        let enum_idx: FxHashMap<&str, u32> = enames.iter().enumerate().map(|(i, n)| (n.as_ref(), i as u32)).collect();
        let user_values: Vec<u32> = ukeys.iter().map(|&k| k + 3).collect();

        // ---- enums (their base types are needed to resolve bitfields of enum type)
        let eranges = if par { ranges(&w, ekeys, w.pos_of(me.close?) - w.pos_of(me.value), threads) } else { vec![0..ekeys.len()] };
        let run_enums = |i: usize| -> Option<Vec<EnumDef>> {
            let mut p = idx.walker(json);
            let mut v = Vec::with_capacity(eranges[i].len());
            each_member(&mut p, ekeys, eranges[i].clone(), me.close?, |p, _, name| {
                v.push(parse_enum(p, name)?);
                Ok(())
            })?;
            Some(v)
        };
        let eparts = if eranges.len() > 1 { crate::util::pool::map(eranges.len(), run_enums) } else { (0..eranges.len()).map(run_enums).collect() };
        let mut edefs: Vec<EnumDef> = Vec::with_capacity(ekeys.len());
        for p in eparts {
            edefs.extend(p?);
        }
        let enum_bases: Vec<Cow<str>> = edefs.iter().map(|e| e.base.clone()).collect();

        drop(_tp);
        let _tp = crate::util::trace::span("isf: parse + resolve ranges");
        // ---- user types and symbols: parse + resolve per range
        let ctx = Ctx {
            natives: &natives,
            native_idx: &native_idx,
            utype_idx: &utype_idx,
            enum_idx: &enum_idx,
            enum_bases: &enum_bases,
            user_values: &user_values,
            flatten: version >= (6, 2, 0),
            sym_types: version >= (2, 1, 0),
        };
        let (uranges, sranges) = if par {
            (ranges(&w, ukeys, w.pos_of(mu.close?) - w.pos_of(mu.value), threads), ranges(&w, skeys, w.pos_of(ms.close?) - w.pos_of(ms.value), threads))
        } else {
            (vec![0..ukeys.len()], vec![0..skeys.len()])
        };
        let nu = uranges.len();
        let run = |i: usize| -> Option<Part> {
            let mut p = idx.walker(json);
            let mut l = Local::default();
            let mut arena: Vec<Desc> = Vec::new();
            if i < nu {
                let r = uranges[i].clone();
                let mut out = Vec::with_capacity(r.len());
                let mut side = idx.walker(json);
                each_member(&mut p, ukeys, r, mu.close?, |p, j, name| {
                    arena.clear();
                    let (kind, size, fields) = read_user(p, &mut arena)?;
                    let members = ctx.members(&mut side, &fields, &arena, &mut l)?;
                    out.push(UserOut { name, kind: user_kind_code(&kind), size, members, hash: uhashes[j] });
                    Ok(())
                })?;
                Some(Part::Users(out, l))
            } else {
                let r = sranges[i - nu].clone();
                let mut out = Vec::with_capacity(r.len());
                each_member(&mut p, skeys, r, ms.close?, |p, _, name| {
                    if p.peek_kind()? != Kind::Obj {
                        return p.skip(); // not a symbol (python's delegate skips it)
                    }
                    arena.clear();
                    let mut address = 0i128;
                    let mut ty = None;
                    let mut constant_data = None;
                    p.object(|p, k| {
                        match k.as_ref() {
                            "address" => address = p.int()?,
                            "type" => ty = Some(read_desc(p, &mut arena)?),
                            "constant_data" => {
                                if p.peek_kind()? == Kind::Str {
                                    constant_data = Some(p.str()?)
                                } else {
                                    p.skip()?
                                }
                            }
                            _ => p.skip()?,
                        }
                        Ok(())
                    })?;
                    let t = match (ctx.sym_types, ty) {
                        (true, Some(d)) => {
                            let t = ctx.resolve(&arena, d, &mut l);
                            l.node(t).0
                        }
                        _ => u32::MAX,
                    };
                    let hash = hash_bytes(name.as_bytes());
                    out.push(SymOut { name, address, ty: t, constant_data, hash });
                    Ok(())
                })?;
                Some(Part::Syms(out, l))
            }
        };
        let n_items = nu + sranges.len();
        let parts: Vec<Option<Part>> = if n_items > 1 && par { crate::util::pool::map(n_items, run) } else { (0..n_items).map(run).collect() };

        drop(_tp);
        // ---- replay the node creations: user types in order, then symbols
        let _tr = crate::util::trace::span("isf: node replay");
        let mut g = Global::default();
        let mut users: Vec<UserOut> = Vec::with_capacity(ukeys.len());
        let mut syms: Vec<SymOut> = Vec::with_capacity(skeys.len());
        let mut m: Vec<u32> = Vec::new();
        for part in parts {
            match part? {
                Part::Users(v, l) => {
                    g.replay(&l, &mut m);
                    for mut u in v {
                        for mem in &mut u.members {
                            mem.2 = remap(mem.2, &m);
                        }
                        users.push(u);
                    }
                }
                Part::Syms(v, l) => {
                    g.replay(&l, &mut m);
                    for mut s in v {
                        if s.ty != u32::MAX {
                            s.ty = m[s.ty as usize];
                        }
                        syms.push(s);
                    }
                }
            }
        }
        drop(_tr);
        // symbol names must be unique too (python dict semantics otherwise: reference path)
        let snames: Vec<Cow<str>> = syms.iter().map(|s| Cow::Borrowed(s.name.as_ref())).collect();
        let shashes: Vec<u64> = syms.iter().map(|s| s.hash).collect();
        if has_repeats(&snames, &shashes) {
            return None;
        }
        drop(snames);
        let enums: Vec<EnumOut> = edefs
            .into_iter()
            .zip(ehashes)
            .map(|(e, hash)| EnumOut { prim: enum_prim_by(&natives, &native_idx, &e.base), name: e.name, constants: e.constants, hash })
            .collect();
        let meta = metadata.as_ref().map(|m| m.to_string_compact()).unwrap_or_default();
        let out = Out { fparts, sym_cdata: version >= (4, 1, 0), nodes: g.nodes, unresolved: g.unresolved, users, enums, syms, natives: natives.clone(), meta };
        drop(_t);
        // a big index is freed off the critical path (unmapping tens of MB)
        drop((run, run_enums, w));
        if json.len() >= PAR_PARSE_MIN {
            crate::util::bg::spawn(move || drop(idx));
        }
        Some(serialize_fast(&out))
    }

    /// The global node table being replayed into.
    struct Global {
        nodes: Vec<Ty>,
        node_idx: FxHashMap<Ty, u32>,
        holders: FxHashMap<u32, u32>,
        unresolved: Vec<(u32, String)>,
    }

    impl Default for Global {
        fn default() -> Global {
            // node 0 = void, like the reference resolver
            let mut node_idx = FxHashMap::default();
            node_idx.insert(Ty::Void, 0);
            Global { nodes: vec![Ty::Void], node_idx, holders: FxHashMap::default(), unresolved: Vec::new() }
        }
    }

    impl Global {
        /// Replay a range's node creations in order; `m` becomes its local -> global map.
        fn replay(&mut self, l: &Local<'_>, m: &mut Vec<u32>) {
            m.clear();
            for ln in &l.nodes {
                let g = match ln {
                    LNode::Holder(id, name) => match self.holders.get(id) {
                        Some(&i) => i,
                        None => {
                            let i = self.nodes.len() as u32;
                            self.nodes.push(Ty::Unresolved(TypeIdx(i)));
                            self.unresolved.push((i, name.to_string()));
                            self.holders.insert(*id, i);
                            i
                        }
                    },
                    LNode::Value(t) => {
                        let t = remap(*t, m);
                        match self.node_idx.get(&t) {
                            Some(&i) => i,
                            None => {
                                let i = self.nodes.len() as u32;
                                self.nodes.push(t);
                                self.node_idx.insert(t, i);
                                i
                            }
                        }
                    }
                };
                m.push(g);
            }
        }
    }

    fn enum_prim_by(natives: &[NativeDef], native_idx: &FxHashMap<&str, usize>, base: &str) -> Prim {
        match native_idx.get(base).map(|&i| natives[i].ty) {
            Some(Ty::Int(p)) => p,
            Some(Ty::Pointer { prim, .. }) => prim,
            _ => Prim { size: 4, signed: true, big_endian: false, kind: PrimKind::Int, name: Prim::NO_NAME },
        }
    }
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

    /// A corrupted cache blob (bit rot, truncation) must load as an error or answer queries
    /// without panicking: validation is lazy (per user type on first `member()` probe).
    #[test]
    fn corrupt_blob_is_safe() {
        use crate::symbols::table::Blob;
        let blob = build_blob(ISF.as_bytes(), &BuildOptions::default()).unwrap();
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut loaded = 0;
        for round in 0..3000 {
            let mut b = blob.clone();
            if round % 50 == 0 {
                let cut = next() as usize % b.len();
                b.truncate(cut);
            } else {
                for _ in 0..1 + round % 8 {
                    let i = next() as usize % b.len();
                    b[i] = next() as u8;
                }
            }
            let Ok(t) = SymbolTable::from_blob(Blob::Owned(b), "t", "u") else { continue };
            loaded += 1;
            for i in 0..t.user_type_count() as u32 + 2 {
                let _ = t.user_type_name(i);
                let _ = t.user_type_size(i);
                for n in ["a", "p", "x", "y", "arr", "bf", "e", "missing", "zz"] {
                    if let Some(m) = t.member(i, n) {
                        let _ = t.type_name(m.ty);
                        let _ = t.size_of(m.ty);
                    }
                }
                for m in t.members(i) {
                    let _ = (m.name.len(), t.type_name(m.ty));
                }
            }
            for n in ["_S", "_U", "E", "nope"] {
                let _ = t.user_type(n);
                let _ = t.enumeration(n);
                let _ = t.get_type(n);
            }
            for s in ["sym1", "linux_banner", "nope"] {
                let _ = t.get_symbol(s);
            }
            let _ = t.symbols_at(4096, 0);
            let _ = (t.is_64bit(), t.pdb_info(), t.metadata());
        }
        assert!(loaded > 1000, "{loaded}");
    }

    /// python's `json.loads` builds dicts: a repeated key keeps the position of its first
    /// occurrence and the value of its last one (windows/mbr.json repeats enum constants).
    /// Checked at every level of the ISF, plus a repeated top-level section.
    #[test]
    fn duplicate_keys_like_python_dicts() {
        let many: String = (0..20).map(|i| format!(r#""c{i}": {i}, "#)).collect();
        let isf = format!(
            r#"{{
          "metadata": {{"format": "4.1.0", "format": "6.2.0"}},
          "base_types": {{
            "long": {{"kind": "int", "size": 2, "signed": true, "endian": "little"}},
            "pointer": {{"kind": "int", "size": 8, "signed": false, "endian": "little"}},
            "long": {{"kind": "int", "size": 4, "signed": true, "endian": "little"}}
          }},
          "enums": {{
            "E": {{"base": "long", "size": 4, "constants": {{"H": 132, "N": 134, "N": 135, "H": 160, "X": 7, "H": 161}}}},
            "Big": {{"base": "long", "size": 4, "constants": {{{many}"c3": 99, "c0": -1}}}},
            "E": {{"base": "long", "size": 4, "constants": {{"H": 1, "N": 2}}, "constants": {{"Z": 5, "H": 161}}}}
          }},
          "user_types": {{
            "_A": {{"kind": "struct", "size": 8, "fields": {{
                "a": {{"offset": 0, "type": {{"kind": "base", "name": "long"}}}},
                "b": {{"offset": 4, "type": {{"kind": "base", "name": "long"}}}},
                "a": {{"offset": 2, "type": {{"kind": "base", "name": "long"}}}}
            }}}},
            "_B": {{"kind": "struct", "size": 4, "fields": {{}}}},
            "_A": {{"kind": "struct", "size": 16, "fields": {{
                "x": {{"offset": 0, "type": {{"kind": "base", "name": "long"}}}},
                "a": {{"offset": 8, "type": {{"kind": "base", "name": "long"}}}},
                "x": {{"offset": 12, "type": {{"kind": "base", "name": "long"}}}}
            }}}}
          }},
          "symbols": {{"s1": {{"address": 1}}, "s2": {{"address": 2}}, "s1": {{"address": 3}}}},
          "symbols": {{"s3": {{"address": 4}}, "s1": {{"address": 5}}, "s3": {{"address": 6}}}}
        }}"#
        );
        let t = load_table(isf.as_bytes(), "dups", "file:///dups", &BuildOptions::default()).unwrap();
        assert_eq!(t.format(), (6, 2, 0));
        assert_eq!(t.size_of(t.get_type("long").unwrap()), 4);
        let e = t.enumeration("E").unwrap();
        assert_eq!(t.enum_constants(e).collect::<Vec<_>>(), [("Z", 5), ("H", 161)]);
        let b = t.enumeration("Big").unwrap();
        let big: Vec<(&str, i64)> = t.enum_constants(b).collect();
        assert_eq!(big.len(), 20);
        assert_eq!((big[0], big[3], big[19]), (("c0", -1), ("c3", 99), ("c19", 19)));
        assert_eq!(t.enum_lookup(b, 3), None);
        assert_eq!(t.user_type_names().collect::<Vec<_>>(), ["_A", "_B"]);
        let a = t.user_type("_A").unwrap();
        assert_eq!(t.user_type_size(a), 16);
        assert_eq!(t.members(a).map(|m| (m.name, m.offset)).collect::<Vec<_>>(), [("x", 12), ("a", 8)]);
        assert_eq!(t.symbols().map(|s| (s.name, s.address)).collect::<Vec<_>>(), [("s3", 6), ("s1", 5)]);

        // the bundled windows/mbr.json (python: "Hibernation" = 161 at the position of its first
        // key (132), "NTFS Volume Set" = 135)
        let mbr = load_table(include_bytes!("../../data/isf/windows/mbr.json"), "mbr", "file:///mbr", &BuildOptions::default()).unwrap();
        let pt = mbr.enumeration("PartitionTypes").unwrap();
        let consts: Vec<(&str, i64)> = mbr.enum_constants(pt).collect();
        assert_eq!(consts.iter().filter(|c| c.0 == "Hibernation" || c.0 == "NTFS Volume Set").copied().collect::<Vec<_>>(), [("Hibernation", 161), ("NTFS Volume Set", 135)]);
        assert_eq!(mbr.enum_lookup(pt, 132), None);
    }

    #[test]
    fn versions() {
        assert_eq!(closest_version("6.1.0").unwrap(), (6, 2, 0));
        assert_eq!(closest_version("4.0.0").unwrap(), (4, 1, 0));
        assert_eq!(closest_version("2.0.0").unwrap(), (2, 1, 0));
        assert!(closest_version("6.3.0").is_err());
        assert!(closest_version("5.0.0").is_err());
    }

    /// The blob of the reference byte parser (`util::json::Parser`, one pass, no index).
    fn build_blob_ref(json: &[u8], opts: &BuildOptions) -> Result<Vec<u8>> {
        let parsed = parse_seq(&mut crate::util::json::Parser::new(json))?;
        build_from(parsed, json.len(), opts)
    }

    /// The indexed parser, serial.
    fn build_blob_serial(json: &[u8], opts: &BuildOptions) -> Result<Vec<u8>> {
        let idx = Index::build_with(json, false)?;
        let parsed = parse_seq(&mut idx.walker(json))?;
        build_from(parsed, json.len(), opts)
    }

    /// Every ISF shipped with volatility3 builds the same blob through the indexed parser
    /// (serial and parallel) as through the reference byte parser.
    #[test]
    fn indexed_parser_equals_reference_on_shipped_isfs() {
        let mut n = 0;
        for &(rel, _, data) in crate::symbols::embedded::FILES {
            let json = if rel.ends_with(".xz") { crate::codecs::xz::decompress(data).unwrap() } else { data.to_vec() };
            let a = build_blob_ref(&json, &BuildOptions::default());
            let b = build_blob_serial(&json, &BuildOptions::default());
            let c = build_blob(&json, &BuildOptions::default());
            match (&a, &b, &c) {
                (Ok(a), Ok(b), Ok(c)) => {
                    assert!(a == b && a == c, "{rel}");
                    n += 1;
                }
                (Err(_), Err(_), Err(_)) => {}
                _ => panic!("{rel}: ref {:?} serial {:?} parallel {:?}", a.as_ref().err(), b.as_ref().err(), c.as_ref().err()),
            }
        }
        assert!(n > 50, "{n}");
    }

    /// Big synthetic ISFs (parallel section ranges) with repeated keys everywhere, escapes,
    /// odd whitespace, a repeated big section and unknown members: identical blobs; and
    /// damaged copies never panic, and when the indexed parser accepts one the reference
    /// parser builds the same blob.
    #[test]
    fn parallel_parse_equals_reference() {
        let mut j = String::from("{\n  \"metadata\": {\"format\": \"6.2.0\", \"x\": [1, 2, {\"y\": null}]},\n  \"junk\": {\"a\": [\"b\", {\"c\": 1}]},\n  \"base_types\": {\"long\": {\"kind\": \"int\", \"size\": 4, \"signed\": true, \"endian\": \"little\"}, \"pointer\": {\"kind\": \"int\", \"size\": 8, \"signed\": false, \"endian\": \"little\"}},\n");
        let mut e = String::from("  \"enums\": {\n");
        for i in 0..3000 {
            e.push_str(&format!("    \"E{}\": {{\"base\": \"long\", \"constants\": {{\"A\": {i}, \"B\": -1, \"A\": 7}}}},\n", i % 2900));
        }
        e.push_str("    \"Elast\": {\"base\": \"long\", \"constants\": {}}\n  },\n");
        j.push_str(&e);
        j.push_str("  \"symbols\": {\"early\": {\"address\": 1}},\n");
        j.push_str("  \"user_types\": {\n");
        for i in 0..5000 {
            j.push_str(&format!(
                "    \"_T{}\": {{\"kind\": \"struct\", \"size\": {}, \"fields\": {{\"a\\u0041\": {{\"offset\": 0, \"type\": {{\"kind\": \"pointer\", \"subtype\": {{\"kind\": \"struct\", \"name\": \"_T{}\"}}}}}}, \"b\": {{\"offset\": 8, \"type\": {{\"kind\": \"array\", \"count\": 3, \"subtype\": {{\"kind\": \"base\", \"name\": \"long\"}}}}}}, \"u\": {{\"offset\": 12, \"anonymous\": true, \"type\": {{\"kind\": \"union\", \"name\": \"_T{}\"}}}}}}}},\n",
                i % 4800,
                16 + i,
                (i * 7) % 5000,
                (i + 1) % 5000
            ));
        }
        j.push_str("    \"_Tlast\": {\"kind\": \"union\", \"size\": 4, \"fields\": {\"z\": {\"offset\": 0, \"type\": {\"kind\": \"bitfield\", \"bit_position\": 1, \"bit_length\": 3, \"type\": {\"kind\": \"base\", \"name\": \"long\"}}}}}\n  },\n");
        j.push_str("  \"symbols\": {\n");
        for i in 0..20000 {
            j.push_str(&format!("    \"s{}\": {{\"address\": {}, \"type\": {{\"kind\": \"struct\", \"name\": \"_T{}\"}}}},\n", i % 19000, i * 16, i % 5000));
        }
        j.push_str("    \"x\": 5,\n    \"linux_banner\": {\"address\": 4, \"constant_data\": \"TGludXg=\"}\n  }\n}\n");
        let json = j.into_bytes();
        assert!(json.len() > PAR_PARSE_MIN);
        let opts = BuildOptions::default();
        let a = build_blob_ref(&json, &opts).unwrap();
        assert_eq!(build_blob_serial(&json, &opts).unwrap(), a);
        let idx = Index::build(&json).unwrap();
        assert!(parse_parallel(&json, &idx).is_some() || crate::util::par::threads() == 1, "the parallel path must handle this document");
        assert_eq!(build_blob(&json, &opts).unwrap(), a);
        // damage: flip bytes at spread positions
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        for round in 0..24 {
            let mut d = json.clone();
            for _ in 0..1 + round % 3 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let i = x as usize % d.len();
                d[i] = b"{}[]:,\"\\ 0a-\n"[(x >> 40) as usize % 13];
            }
            if let Ok(b) = build_blob(&d, &opts) {
                assert_eq!(build_blob_ref(&d, &opts).ok(), Some(b), "round {round}");
            }
        }
    }

    /// A big ISF with unique names (the fused builder's domain) exercising everything the
    /// resolver does across parallel ranges: anonymous members whose types live in other
    /// ranges (before and after), unresolved and `!`-qualified names, enum-based bitfields,
    /// pointer base overrides, unknown kinds, symbols with and without types / data; for
    /// several format versions (flattening, typed symbols, std-ctypes natives).
    fn unique_isf(format: &str, n_types: usize, n_syms: usize) -> Vec<u8> {
        let mut j = format!("{{\n  \"metadata\": {{\"format\": \"{format}\", \"producer\": {{\"name\": \"t\"}}}},\n");
        j.push_str("  \"base_types\": {\n    \"long\": {\"kind\": \"int\", \"size\": 4, \"signed\": true, \"endian\": \"little\"},\n    \"unsigned char\": {\"kind\": \"char\", \"size\": 1, \"signed\": false, \"endian\": \"little\"},\n    \"pointer\": {\"kind\": \"int\", \"size\": 8, \"signed\": false, \"endian\": \"little\"},\n    \"void\": {\"kind\": \"void\", \"size\": 0, \"signed\": false, \"endian\": \"little\"}\n  },\n");
        j.push_str("  \"enums\": {\n");
        for i in 0..400 {
            j.push_str(&format!("    \"E{i}\": {{\"base\": \"{}\", \"size\": 4, \"constants\": {{\"A{i}\": {i}, \"B\": -1, \"A{i}\": 7}}}},\n", if i % 3 == 0 { "long" } else { "unsigned char" }));
        }
        j.push_str("    \"Elast\": {\"base\": \"nope\", \"constants\": {}}\n  },\n");
        j.push_str("  \"user_types\": {\n");
        for i in 0..n_types {
            let other = (i * 7919 + 13) % n_types;
            let anon = (i * 104729 + 5) % n_types;
            let mut f = format!(
                "\"a\": {{\"offset\": 0, \"type\": {{\"kind\": \"pointer\", \"subtype\": {{\"kind\": \"struct\", \"name\": \"_T{other}\"}}}}}}, \
                 \"b\": {{\"offset\": 8, \"type\": {{\"kind\": \"array\", \"count\": {}, \"subtype\": {{\"kind\": \"base\", \"name\": \"long\"}}}}}}, \
                 \"c\": {{\"offset\": 12, \"type\": {{\"kind\": \"bitfield\", \"bit_position\": {}, \"bit_length\": 3, \"type\": {{\"kind\": \"enum\", \"name\": \"E{}\"}}}}}}, \
                 \"d\": {{\"offset\": -4, \"type\": {{\"kind\": \"pointer\", \"base\": \"long\", \"subtype\": {{\"kind\": \"struct\", \"name\": \"_MISSING{}\"}}}}}}, \
                 \"e\": {{\"offset\": 16, \"type\": {{\"kind\": \"union\", \"name\": \"mod!_X\"}}}}, \
                 \"f\": {{\"offset\": 20, \"type\": {{\"kind\": \"weird\", \"name\": \"q\"}}}}, \
                 \"g\": {{\"offset\": 24, \"type\": {{\"kind\": \"enum\", \"name\": \"NOENUM\"}}}}, \
                 \"h\": {{\"offset\": 28, \"type\": {{\"kind\": \"bitfield\", \"bit_position\": 0, \"bit_length\": 1, \"type\": {{\"kind\": \"struct\", \"name\": \"_T0\"}}}}}}, \
                 \"i\": {{\"offset\": 32}}",
                i % 5,
                i % 29,
                i % 410,
                i % 97
            );
            if i % 4 == 1 {
                f.push_str(&format!(", \"u\": {{\"offset\": 40, \"anonymous\": true, \"type\": {{\"kind\": \"union\", \"name\": \"_T{anon}\"}}}}, \"a\": {{\"offset\": 48, \"type\": {{\"kind\": \"base\", \"name\": \"void\"}}}}"));
            }
            if i % 9 == 2 {
                f.push_str(", \"v\": {\"offset\": 56, \"anonymous\": true, \"type\": {\"kind\": \"struct\", \"name\": \"_NOSUCH\"}}");
            }
            let kind = ["struct", "union", "class"][i % 3];
            j.push_str(&format!("    \"_T{i}\": {{\"fields\": {{{f}}}, \"kind\": \"{kind}\", \"size\": {}}}", 64 + i));
            j.push_str(if i + 1 < n_types { ",\n" } else { "\n" });
        }
        j.push_str("  },\n  \"symbols\": {\n");
        for i in 0..n_syms {
            let v = match i % 5 {
                0 => format!("{{\"address\": {}}}", i * 16),
                1 => format!("{{\"address\": {}, \"type\": {{\"kind\": \"struct\", \"name\": \"_T{}\"}}}}", i * 16, i % n_types),
                2 => format!("{{\"address\": {}, \"type\": {{\"kind\": \"pointer\", \"subtype\": {{\"kind\": \"struct\", \"name\": \"_GONE{}\"}}}}}}", i, i % 11),
                3 => format!("{{\"type\": {{\"kind\": \"array\", \"count\": 2, \"subtype\": {{\"kind\": \"base\", \"name\": \"unsigned char\"}}}}, \"address\": {i}, \"constant_data\": \"TGludXggdmVyc2lvbg==\"}}"),
                _ => "5".to_string(),
            };
            j.push_str(&format!("    \"sym{i}\": {v}"));
            j.push_str(if i + 1 < n_syms { ",\n" } else { "\n" });
        }
        j.push_str("  }\n}\n");
        j.into_bytes()
    }

    /// The fused builder (serial and parallel) builds exactly the reference blob.
    #[test]
    fn fused_builder_equals_reference() {
        for (format, nt, ns) in [("6.2.0", 9000, 40000), ("6.1.0", 3000, 5000), ("4.1.0", 800, 700), ("2.1.0", 300, 300), ("6.2.0", 3, 2)] {
            let json = unique_isf(format, nt, ns);
            let opts = BuildOptions::default();
            let a = build_blob_ref(&json, &opts).unwrap();
            let b = fast::build(&json, &opts).unwrap().expect("fused path taken");
            assert!(a == b, "{format}: fused blob differs");
            let t = SymbolTable::from_blob(Blob::Owned(b), "t", "u").unwrap();
            assert_eq!(t.user_type_count(), nt);
            // natives override (python native_types=)
            let opts = BuildOptions { natives: Some(t.natives()) };
            assert!(build_blob_ref(&json, &opts).unwrap() == fast::build(&json, &opts).unwrap().unwrap(), "{format}: natives override");
        }
        // the 2.0.0 delegate (std ctypes by size) with matching base types
        let json = unique_isf("2.0.0", 200, 100);
        assert!(build_blob_ref(&json, &BuildOptions::default()).ok() == fast::build(&json, &BuildOptions::default()).unwrap());
    }

    /// Every ISF on this machine (testdata, python's cache): fused == reference.
    /// `cargo test --release fused_on_all_isfs -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn fused_on_all_isfs() {
        let mut files = Vec::new();
        for root in ["/home/user/rs-vol/testdata/symbols", &format!("{}/.cache/volatility3/symbols", std::env::var("HOME").unwrap())] {
            let mut stack = vec![std::path::PathBuf::from(root)];
            while let Some(d) = stack.pop() {
                for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if p.to_string_lossy().ends_with(".json") || p.to_string_lossy().ends_with(".json.xz") {
                        files.push(p);
                    }
                }
            }
        }
        files.sort();
        let mut n = 0;
        for f in &files {
            let raw = std::fs::read(f).unwrap();
            let json = if f.to_string_lossy().ends_with(".xz") { crate::codecs::xz::decompress(&raw).unwrap() } else { raw };
            let opts = BuildOptions::default();
            let t = std::time::Instant::now();
            let fast = fast::build(&json, &opts).unwrap();
            let tf = t.elapsed();
            let t = std::time::Instant::now();
            let reference = build_blob_ref(&json, &opts).ok();
            let tr = t.elapsed();
            assert!(fast.is_none() || fast == reference, "{}", f.display());
            n += fast.is_some() as usize;
            println!("{}: {} ({:.1} ms fused, {:.1} ms reference)", f.display(), if fast.is_some() { "fused" } else { "fallback" }, tf.as_secs_f64() * 1e3, tr.as_secs_f64() * 1e3);
        }
        println!("{n}/{} took the fused path", files.len());
    }

    /// `RSVOL_BENCH_JSON=path cargo test --release isf_parse_bench -- --ignored --nocapture`
    /// (compare with bench/refbench/isf_json_bench.sh: simdjson, yyjson, python json).
    #[test]
    #[ignore]
    fn isf_parse_bench() {
        let path = std::env::var("RSVOL_BENCH_JSON").expect("RSVOL_BENCH_JSON");
        let data = std::fs::read(&path).unwrap();
        let mb = data.len() as f64 / 1e6;
        let best = |f: &mut dyn FnMut()| -> f64 {
            let mut b = f64::MAX;
            for _ in 0..20 {
                let t = std::time::Instant::now();
                f();
                b = b.min(t.elapsed().as_secs_f64());
            }
            b
        };
        let row = |name: &str, t: f64| println!("  {name:44} {:8.2} ms {:7.0} MB/s", t * 1e3, mb / t);
        println!("{path}: {mb:.1} MB, best of 20, {} threads", crate::util::par::threads());
        row("byte parser: skip whole document", best(&mut || crate::util::json::Parser::new(&data).skip().unwrap()));
        row("byte parser: DOM (Json::parse)", best(&mut || drop(Json::parse(&data).unwrap())));
        row("byte parser: ISF parse (old)", best(&mut || drop(parse_seq(&mut crate::util::json::Parser::new(&data)).unwrap())));
        row("stage 1, 1 thread", best(&mut || drop(Index::build_with(&data, false).unwrap())));
        row("stage 1, parallel", best(&mut || drop(Index::build_with(&data, true).unwrap())));
        let idx1 = Index::build_with(&data, false).unwrap();
        row("stage 2 walk only: DOM, 1 thread", best(&mut || drop(idx1.walker(&data).value().unwrap())));
        row("stage 2 walk only: ISF parse, 1 thread", best(&mut || drop(parse_seq(&mut idx1.walker(&data)).unwrap())));
        row("indexed ISF parse, 1 thread (stage 1+2)", best(&mut || {
            let idx = Index::build_with(&data, false).unwrap();
            drop(parse_seq(&mut idx.walker(&data)).unwrap());
        }));
        row("indexed DOM, 1 thread (stage 1+2)", best(&mut || {
            let idx = Index::build_with(&data, false).unwrap();
            drop(idx.walker(&data).value().unwrap());
        }));
        row("indexed ISF parse, parallel (parse())", best(&mut || drop(parse(&data).unwrap())));
        row("build_blob, old parser", best(&mut || drop(build_blob_ref(&data, &BuildOptions::default()).unwrap())));
        row("parse() + resolve + serialize", best(&mut || {
            let parsed = parse(&data).unwrap();
            drop(build_from(parsed, data.len(), &BuildOptions::default()).unwrap());
        }));
        row("build_blob (fused builder)", best(&mut || drop(build_blob(&data, &BuildOptions::default()).unwrap())));
        assert_eq!(build_blob(&data, &BuildOptions::default()).unwrap(), build_blob_ref(&data, &BuildOptions::default()).unwrap());
    }
}
