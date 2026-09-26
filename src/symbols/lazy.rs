//! Lazy symbol tables: a big ISF (a 46-64 MB dwarf2json kernel ISF, a Windows kernel's PDB
//! ISF) is usable as soon as its structure is known, without building the whole binary table
//! first. A plugin touches a few dozen of a kernel's 10-15k types and 200-300k symbols; only
//! those are resolved, on first use, through the same [`SymbolTable`](super::SymbolTable) API.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Building a lazy table ([`LazyCore::index`]) never makes the document-wide structural index
//! the full builder makes (a 40 MB position array for a 64 MB ISF, and a walk over it): one
//! SIMD pass finds the root's structure and the member keys of its big sections, the root and
//! the small sections go through the fused builder's own checks ([`fast::root`]), and every
//! member of the big sections is parsed exactly as the fused builder parses it, each range of
//! members through a small local index of its own bytes (L2-resident, on all cores). So a lazy
//! table exists only for documents the fused builder accepts, with the same content; anything
//! else (repeated names or sections, odd shapes, invalid JSON) makes `build` give the JSON back
//! and the caller builds eagerly, which also produces the errors. Nothing is resolved or
//! serialized:
//!
//! * the natives, enums and metadata are written into a small skeleton blob, the same records
//!   the full blob holds (the table serves them from there unchanged);
//! * user types and symbols keep their ordinals (ISF order, python's dict order): name -> ordinal
//!   indexes over the member keys, and per-ordinal records resolved on first access
//!   ([`UserRec`], [`SymRec`]) by the fused builder's own resolver ([`fast::Ctx`]);
//! * type nodes (pointer targets, array elements, unresolved-name holders) are interned by value
//!   in a node store of their own (node 0 = `void`), holders once per descriptor, like the full
//!   builder: node numbers differ from the full blob's, the types they describe do not.
//!
//! The full blob is built later, off the critical path (see `store::finish_deferred`).

use super::isf::{BuildOptions, Desc, EnumDef, NativeDef, b64decode, fast, user_kind_code};
use super::table::{RuntimeNodes, Ty, TypeIdx};
use crate::util::fxhash::{FxHashMap, hash_bytes};
use crate::util::jsonidx::{Index, Pull, Walker, shallow, string_value};
use std::borrow::Cow;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// The JSON of a lazy table, kept for the table's life (records are parsed from it on demand).
pub(crate) enum JsonBuf {
    Owned(Vec<u8>),
    Static(&'static [u8]),
    Mapped(crate::util::mmap::MapWindow),
    /// JSON also held elsewhere (a converted PDB's, until its file is written)
    Shared(Arc<Vec<u8>>),
}

impl std::ops::Deref for JsonBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            JsonBuf::Owned(v) => v,
            JsonBuf::Static(s) => s,
            JsonBuf::Mapped(m) => m.as_slice(),
            JsonBuf::Shared(v) => v,
        }
    }
}

/// name -> ordinal over a section's member keys: open addressing (ordinal + 1, 0 = empty) on
/// the key hashes; candidates are confirmed by comparing the key text.
struct NameIndex {
    slots: Box<[u32]>,
}

/// `n` zeroed atomics (zeroed pages straight from the allocator).
fn zeroed_atomic(n: usize) -> Vec<AtomicU32> {
    let v: Vec<u32> = vec![0; n];
    // SAFETY: AtomicU32 has the size, alignment and bit validity of u32
    unsafe { std::mem::transmute::<Vec<u32>, Vec<AtomicU32>>(v) }
}

impl NameIndex {
    /// Insert `hashes` (ordinal order) in parallel; `same(a, b)` compares two ordinals' names.
    /// `None` if a name repeats.
    fn build(hashes: &[u64], same: impl Fn(u32, u32) -> bool + Sync) -> Option<NameIndex> {
        let n = hashes.len();
        let nslots = if n == 0 { 0 } else { (2 * n).next_power_of_two() };
        // filled with CAS so ranges insert in parallel
        let slots = zeroed_atomic(nslots);
        let mask = nslots.wrapping_sub(1);
        let dup = std::sync::atomic::AtomicBool::new(false);
        let insert = |r: std::ops::Range<usize>| {
            for i in r {
                let h = hashes[i];
                let mut j = h as usize & mask;
                loop {
                    match slots[j].compare_exchange(0, i as u32 + 1, Ordering::Relaxed, Ordering::Relaxed) {
                        Ok(_) => break,
                        Err(o) => {
                            let o = o - 1;
                            if hashes[o as usize] == h && same(o, i as u32) {
                                dup.store(true, Ordering::Relaxed);
                                return;
                            }
                            j = (j + 1) & mask;
                        }
                    }
                }
            }
        };
        const PER: usize = 16384;
        if n > 2 * PER && crate::util::par::threads() > 1 {
            let k = n.div_ceil(PER);
            crate::util::pool::for_each(k, &|c| insert(c * PER..((c + 1) * PER).min(n)));
        } else {
            insert(0..n);
        }
        if dup.load(Ordering::Relaxed) {
            return None;
        }
        // SAFETY: as above, back to plain integers (no more concurrent access)
        let slots: Vec<u32> = unsafe { std::mem::transmute::<Vec<AtomicU32>, Vec<u32>>(slots) };
        Some(NameIndex { slots: slots.into_boxed_slice() })
    }

    #[inline]
    fn find(&self, name: &str, is: impl Fn(u32) -> bool) -> Option<u32> {
        let n = self.slots.len();
        if n == 0 {
            return None;
        }
        let mask = n - 1;
        let mut j = hash_bytes(name.as_bytes()) as usize & mask;
        loop {
            match self.slots[j] {
                0 => return None,
                v => {
                    if is(v - 1) {
                        return Some(v - 1);
                    }
                    j = (j + 1) & mask;
                }
            }
        }
    }
}

/// A resolved user type.
pub(crate) struct UserRec {
    /// 0 struct, 1 union, 2 class (blob encoding)
    pub kind: u32,
    /// the blob's size field (clamped to u32)
    pub size: u32,
    /// member names, concatenated
    names: String,
    /// (name offset, name length, offset, type), ISF order
    members: Box<[(u32, u32, u64, Ty)]>,
    /// member hash index: member index + 1, 0 = empty; power of two (or empty)
    slots: Box<[u32]>,
}

impl UserRec {
    fn empty() -> UserRec {
        UserRec { kind: 0, size: 0, names: String::new(), members: Box::new([]), slots: Box::new([]) }
    }
    #[inline]
    fn name(&self, m: &(u32, u32, u64, Ty)) -> &str {
        &self.names[m.0 as usize..(m.0 + m.1) as usize]
    }
    /// Member `name`: (name, offset, type).
    #[inline]
    pub fn member(&self, name: &str) -> Option<(&str, u64, Ty)> {
        let n = self.slots.len();
        if n == 0 {
            return None;
        }
        let mask = n - 1;
        let mut j = hash_bytes(name.as_bytes()) as usize & mask;
        for _ in 0..n {
            match self.slots[j] {
                0 => return None,
                v => {
                    let m = &self.members[v as usize - 1];
                    if self.name(m) == name {
                        return Some((self.name(m), m.2, m.3));
                    }
                    j = (j + 1) & mask;
                }
            }
        }
        None
    }
    /// All members in ISF order: (name, offset, type).
    pub fn members(&self) -> impl Iterator<Item = (&str, u64, Ty)> + '_ {
        self.members.iter().map(move |m| (self.name(m), m.2, m.3))
    }
}

/// A resolved symbol.
pub(crate) struct SymRec {
    /// `address as u64` (unmasked)
    pub address: u64,
    /// node of the symbol's type, `u32::MAX` = none
    pub ty: u32,
    /// decoded `constant_data` (format >= 4.1.0)
    pub cdata: Option<Box<[u8]>>,
}

pub(crate) struct LazyCore {
    json: JsonBuf,
    /// natives, enums, metadata (see the module docs)
    pub skeleton: Arc<Vec<u8>>,
    /// positions of the user type keys (opening quotes), ordinal order; one past the last
    /// type's value: `uend`
    ukeys: Box<[u32]>,
    /// length of each user type's name ([`NAME_DECODED`]: see `escaped`)
    ulen: Box<[u32]>,
    uend: u32,
    /// positions of all `symbols` member keys, and of the symbols' (the members whose value
    /// is an object) in ordinal order; one past the last member's value: `send`
    sall: Box<[u32]>,
    skeys: Box<[u32]>,
    /// length of each symbol's name
    slen: Box<[u32]>,
    send: u32,
    unames: NameIndex,
    /// symbol names: slots hold `sall` indexes (see `sord`)
    snames: NameIndex,
    /// `sall` index -> symbol ordinal (u32::MAX: not a symbol); `None` = the identity (every
    /// member of `symbols` is a symbol)
    sord: Option<Box<[u32]>>,
    /// key position -> name, for keys whose text is not the name as is (escapes, invalid
    /// UTF-8)
    escaped: FxHashMap<u32, Box<str>>,
    enum_idx: FxHashMap<Box<str>, u32>,
    enum_bases: Box<[Box<str>]>,
    natives: Vec<NativeDef>,
    native_idx: FxHashMap<String, usize>,
    flatten: bool,
    sym_types: bool,
    sym_cdata: bool,
    users: Box<[OnceLock<Box<UserRec>>]>,
    syms: Box<[OnceLock<Box<SymRec>>]>,
    /// every symbol's address (`address as u64`, unmasked), ordinal order
    addrs: Box<[u64]>,
    nodes: RuntimeNodes,
    /// (descriptor id -> holder node, holder node -> unresolved name)
    holders: Mutex<(FxHashMap<u32, u32>, FxHashMap<u32, &'static str>)>,
}

/// Records of a lazy table go into its node store.
struct LazySink<'c>(&'c LazyCore);

impl fast::Sink for LazySink<'_> {
    fn node(&mut self, t: Ty) -> TypeIdx {
        TypeIdx(self.0.nodes.intern(t))
    }
    fn unresolved(&mut self, id: u32, name: &str) -> Ty {
        let mut g = self.0.holders.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&n) = g.0.get(&id) {
            return Ty::Unresolved(TypeIdx(n));
        }
        let n = self.0.nodes.push_holder();
        g.0.insert(id, n);
        // holders are few (a handful per resolved type at most) and live as long as the table
        g.1.insert(n, Box::leak(name.to_string().into_boxed_str()));
        Ty::Unresolved(TypeIdx(n))
    }
}

impl fast::Names for LazyCore {
    fn utype(&self, name: &str) -> Option<u32> {
        self.user_type(name)
    }
    fn enumeration(&self, name: &str) -> Option<u32> {
        self.enum_idx.get(name).copied()
    }
    fn enum_base(&self, i: u32) -> Option<&str> {
        self.enum_bases.get(i as usize).map(|b| &**b)
    }
}

/// Validation output of one range of a big section (the per-key results are written in place).
enum Checked<'a> {
    /// the decoded names of keys that are not their text as is: (key position, name)
    Esc(Vec<(u32, Box<str>)>),
    /// the enumerations (parsed)
    Enums(Vec<EnumDef<'a>>),
}

/// `slen` marker of a `symbols` member whose value is not an object (not a symbol).
const NOT_SYMBOL: u32 = u32::MAX - 1;

/// A slice the range tasks of the index pass write at disjoint indexes.
struct Shared<T>(*mut T, usize);
// SAFETY: tasks write disjoint indexes (each key belongs to one range) of a slice that outlives
// them; nothing reads it until they are all done
unsafe impl<T: Send> Send for Shared<T> {}
unsafe impl<T: Send> Sync for Shared<T> {}

impl<T> Shared<T> {
    fn new(v: &mut [T]) -> Shared<T> {
        Shared(v.as_mut_ptr(), v.len())
    }
    #[inline]
    fn set(&self, i: usize, x: T) {
        assert!(i < self.1);
        // SAFETY: in bounds; see the Sync impl
        unsafe { *self.0.add(i) = x }
    }
}

/// Ranges of about `per` bytes over `keys` (sorted positions).
fn byte_ranges(keys: &[u32], per: usize) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut s = 0;
    while s < keys.len() {
        let lim = keys[s] as usize + per;
        let e = s + 1 + keys[s + 1..].partition_point(|&k| (k as usize) <= lim);
        out.push(s..e);
        s = e;
    }
    out
}

/// The eager part of a lazy table, from [`LazyCore::index`].
struct Indexed {
    skeleton: Vec<u8>,
    ukeys: Box<[u32]>,
    ulen: Box<[u32]>,
    uend: u32,
    sall: Box<[u32]>,
    skeys: Box<[u32]>,
    slen: Box<[u32]>,
    send: u32,
    unames: NameIndex,
    snames: NameIndex,
    sord: Option<Box<[u32]>>,
    addrs: Box<[u64]>,
    escaped: FxHashMap<u32, Box<str>>,
    enum_idx: FxHashMap<Box<str>, u32>,
    enum_bases: Box<[Box<str>]>,
    natives: Vec<NativeDef>,
    version: (u32, u32, u32),
}

impl LazyCore {
    /// A lazy table over `json` (see the module docs); `Err(json)` when the fused builder would
    /// not take this document (the caller builds eagerly) or `opts` override the natives.
    pub(crate) fn build(json: JsonBuf, opts: &BuildOptions) -> Result<LazyCore, JsonBuf> {
        if opts.natives.is_some() {
            return Err(json);
        }
        let _t = crate::util::trace::span("isf lazy index");
        let Some(x) = Self::index(&json, opts) else { return Err(json) };
        let native_idx = x.natives.iter().enumerate().map(|(i, n)| (n.name.clone(), i)).collect();
        let nodes = RuntimeNodes::new();
        nodes.intern(Ty::Void); // node 0 = void, like the full blob
        let (nu, ns) = (x.ukeys.len(), x.skeys.len());
        Ok(LazyCore {
            json,
            skeleton: Arc::new(x.skeleton),
            ukeys: x.ukeys,
            ulen: x.ulen,
            uend: x.uend,
            sall: x.sall,
            skeys: x.skeys,
            slen: x.slen,
            send: x.send,
            unames: x.unames,
            snames: x.snames,
            sord: x.sord,
            escaped: x.escaped,
            enum_idx: x.enum_idx,
            enum_bases: x.enum_bases,
            natives: x.natives,
            native_idx,
            flatten: x.version >= (6, 2, 0),
            sym_types: x.version >= (2, 1, 0),
            sym_cdata: x.version >= (4, 1, 0),
            users: (0..nu).map(|_| OnceLock::new()).collect(),
            syms: (0..ns).map(|_| OnceLock::new()).collect(),
            addrs: x.addrs,
            nodes,
            holders: Mutex::new(Default::default()),
        })
    }

    /// The index (see the module docs): `None` if the fused builder would not take `json`.
    ///
    /// 1. [`shallow`]: the root's container values and the member keys of its objects, from
    ///    one SIMD pass (no index);
    /// 2. a stage-1 index of everything but the bodies of `user_types`, `enums` and `symbols`
    ///    (the root and the small sections), checked by the fused builder's own root code
    ///    ([`fast::root`]: those three sections look empty there);
    /// 3. every member of the three sections parsed exactly as the fused builder does, each
    ///    range of members through a local stage-1 index of its bytes (in parallel):
    ///    [`fast::each_member_local`]. Together with the whitespace check between each
    ///    section's `{` and its first key, every byte of the document goes through stage 1
    ///    and the member checks, so exactly the fused builder's documents are accepted.
    fn index(json: &[u8], opts: &BuildOptions) -> Option<Indexed> {
        let sh = {
            let _t = crate::util::trace::span("isf lazy: shallow pass");
            shallow(json)?
        };
        // ---- the big sections: containers whose root key is user_types / enums / symbols
        let _t = crate::util::trace::span("isf lazy: skeleton");
        let mut big: [Option<(u32, u32)>; 3] = [None; 3];
        for &(o, c) in &sh.containers {
            // the root key: the last depth-1 string before the value
            let k = sh.d1[..sh.d1.partition_point(|&p| p < o)].last()?;
            let body = json.get(*k as usize + 1..o as usize)?;
            let close = body.iter().position(|&b| b == b'"')?;
            let s = match &body[..close] {
                b"user_types" => 0,
                b"enums" => 1,
                b"symbols" => 2,
                name if name.contains(&b'\\') => return None, // a key spelled with escapes
                _ => continue,
            };
            if json[o as usize] != b'{' || big[s].is_some() {
                return None; // not an object, or a repeated section: the reference path decides
            }
            big[s] = Some((o, c));
        }
        let big = [big[0]?, big[1]?, big[2]?];
        // the document without the three bodies
        let mut order = big;
        order.sort_unstable();
        let mut ranges = Vec::with_capacity(4);
        let mut at = 0usize;
        for &(o, c) in &order {
            ranges.push((at, o as usize + 1));
            at = c as usize;
        }
        ranges.push((at, json.len()));
        let skel = Index::build_ranges(json, &ranges).ok()?;
        let root = fast::root(json, &skel, opts)?;
        for (s, (value, sec)) in root.big.iter().enumerate() {
            // the same containers, empty in the skeleton
            if skel.pos.get(*value).copied() != Some(big[s].0) || skel.pos.get(sec.close).copied() != Some(big[s].1) || !sec.keys.is_empty() {
                return None;
            }
        }
        // each section's keys; only whitespace between its '{' and its first key
        let keys_of = |s: usize| -> Option<&[u32]> {
            let (o, c) = big[s];
            let k = &sh.keys[sh.keys.partition_point(|&p| p <= o)..sh.keys.partition_point(|&p| p < c)];
            let first = k.first().copied().unwrap_or(c);
            json[o as usize + 1..first as usize].iter().all(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r')).then_some(k)
        };
        let (uk, ek, sk) = (keys_of(0)?, keys_of(1)?, keys_of(2)?);
        let (uclose, eclose, sclose) = (big[0].1 as usize, big[1].1 as usize, big[2].1 as usize);
        drop(_t);

        // ---- every member, parsed like the fused builder does, through local indexes
        let _t = crate::util::trace::span("isf lazy: members");
        const PER: usize = 256 << 10;
        let (ur, er, sr) = (byte_ranges(uk, PER), byte_ranges(ek, PER), byte_ranges(sk, PER));
        let (nu, ne) = (ur.len(), er.len());
        // the symbol name index is filled during the pass: key indexes (into `sk`)
        // compare-and-swapped into shared slots; a repeated name ends the lazy path
        let nslots = if sk.is_empty() { 0 } else { (2 * sk.len()).next_power_of_two() };
        let stab = zeroed_atomic(nslots);
        let sdup = std::sync::atomic::AtomicBool::new(false);
        let sinsert = |ki: u32, h: u64, name: &str| {
            let mask = nslots - 1;
            let mut j = h as usize & mask;
            loop {
                match stab[j].compare_exchange(0, ki + 1, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => return,
                    Err(o) => {
                        if string_value(json, sk[(o - 1) as usize] as usize).is_none_or(|n| n == name) {
                            sdup.store(true, Ordering::Relaxed);
                            return;
                        }
                        j = (j + 1) & mask;
                    }
                }
            }
        };
        // per-key results, written in place by the ranges (disjoint key indexes)
        let mut uhash_v = vec![0u64; uk.len()];
        let mut ulen_v = vec![0u32; uk.len()];
        let mut slen_v = vec![NOT_SYMBOL; sk.len()];
        let mut addr_v = vec![0u64; sk.len()];
        let (uh, ul, sl, sa) = (Shared::new(&mut uhash_v), Shared::new(&mut ulen_v), Shared::new(&mut slen_v), Shared::new(&mut addr_v));
        let run = |i: usize| -> Option<Checked> {
            thread_local! {
                static POS: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
            }
            POS.with(|pos| {
                let pos = &mut *pos.borrow_mut();
                let mut arena: Vec<Desc> = Vec::new();
                // keys whose name is not their text as is (escapes, invalid UTF-8): decoded
                let mut esc: Vec<(u32, Box<str>)> = Vec::new();
                let mut len_of = |p: u32, name: Cow<str>| match name {
                    Cow::Owned(n) => {
                        esc.push((p, n.into_boxed_str()));
                        NAME_DECODED
                    }
                    Cow::Borrowed(b) => b.len() as u32,
                };
                if i < nu {
                    fast::each_member_local(json, uk, ur[i].clone(), uclose, pos, |p, j, name| {
                        arena.clear();
                        fast::read_user(p, &mut arena)?;
                        uh.set(j, hash_bytes(name.as_bytes()));
                        ul.set(j, len_of(uk[j], name));
                        Ok(())
                    })?;
                    Some(Checked::Esc(esc))
                } else if i < nu + ne {
                    let mut out = Vec::with_capacity(er[i - nu].len());
                    fast::each_member_local(json, ek, er[i - nu].clone(), eclose, pos, |p, _, name| {
                        out.push(super::isf::parse_enum(p, name)?);
                        Ok(())
                    })?;
                    Some(Checked::Enums(out))
                } else {
                    fast::each_member_local(json, sk, sr[i - nu - ne].clone(), sclose, pos, |p, j, name| {
                        if p.peek_kind()? != crate::util::json::Kind::Obj {
                            return p.skip(); // not a symbol (python's delegate skips it)
                        }
                        arena.clear();
                        let (address, _, _) = fast::read_symbol(p, &mut arena)?;
                        sinsert(j as u32, hash_bytes(name.as_bytes()), &name);
                        sa.set(j, address as u64);
                        sl.set(j, len_of(sk[j], name));
                        Ok(())
                    })?;
                    Some(Checked::Esc(esc))
                }
            })
        };
        let par = crate::util::par::threads() > 1;
        // the enums first (small): the skeleton blob is written from them while the user types
        // and symbols are checked
        let eparts: Vec<Option<Checked>> = if ne > 1 && par { crate::util::pool::map(ne, |i| run(nu + i)) } else { (0..ne).map(|i| run(nu + i)).collect() };
        let mut edefs: Vec<EnumDef> = Vec::with_capacity(ek.len());
        for p in eparts {
            match p? {
                Checked::Enums(v) => edefs.extend(v),
                _ => return None,
            }
        }
        let mut enum_idx: FxHashMap<Box<str>, u32> = FxHashMap::default();
        for (i, e) in edefs.iter().enumerate() {
            if enum_idx.insert(Box::from(e.name.as_ref()), i as u32).is_some() {
                return None;
            }
        }
        let ehashes: Vec<u64> = edefs.iter().map(|e| hash_bytes(e.name.as_bytes())).collect();
        let enum_bases: Box<[Box<str>]> = edefs.iter().map(|e| Box::from(e.base.as_ref())).collect();
        let fast::Root { version, fparts, metadata, natives, .. } = root;
        let items: Vec<usize> = (0..nu).chain(nu + ne..nu + ne + sr.len()).collect();
        let (skeleton, parts) = std::thread::scope(|sc| {
            let natives = &natives;
            let skel = sc.spawn(move || fast::skeleton_blob(version, fparts, metadata.as_ref(), natives.clone(), edefs, ehashes));
            let parts: Vec<Option<Checked>> = if items.len() > 1 && par { crate::util::pool::map(items.len(), |k| run(items[k])) } else { items.iter().map(|&i| run(i)).collect() };
            (skel.join().ok(), parts)
        });
        let skeleton = skeleton?;
        let mut escaped: FxHashMap<u32, Box<str>> = FxHashMap::default();
        for p in parts {
            match p? {
                Checked::Esc(v) => escaped.extend(v),
                Checked::Enums(_) => return None,
            }
        }
        drop(_t);
        let _t = crate::util::trace::span("isf lazy: names");
        // names are unique (python dict semantics otherwise: the reference path)
        let key = |p: u32, len: u32| -> &str { name_at(json, &escaped, p, len) };
        let unames = NameIndex::build(&uhash_v, |a, b| key(uk[a as usize], ulen_v[a as usize]) == key(uk[b as usize], ulen_v[b as usize]))?;
        if sdup.load(Ordering::Relaxed) {
            return None;
        }
        // SAFETY: AtomicU32 has the size, alignment and bit validity of u32
        let snames = NameIndex { slots: unsafe { std::mem::transmute::<Vec<AtomicU32>, Vec<u32>>(stab) }.into_boxed_slice() };
        // the symbols: every member of `symbols` (the usual case), or those whose value is an
        // object (then a key index -> ordinal map)
        let (skeys, slen, addrs, sord): (Vec<u32>, Vec<u32>, Vec<u64>, Option<Box<[u32]>>) = if slen_v.iter().all(|&l| l != NOT_SYMBOL) {
            (sk.to_vec(), slen_v, addr_v, None)
        } else {
            let mut m = vec![u32::MAX; sk.len()];
            let (mut k, mut l, mut a) = (Vec::new(), Vec::new(), Vec::new());
            for j in 0..sk.len() {
                if slen_v[j] != NOT_SYMBOL {
                    m[j] = k.len() as u32;
                    k.push(sk[j]);
                    l.push(slen_v[j]);
                    a.push(addr_v[j]);
                }
            }
            (k, l, a, Some(m.into_boxed_slice()))
        };
        let ulen = ulen_v;
        Some(Indexed {
            skeleton,
            ukeys: uk.into(),
            ulen: ulen.into_boxed_slice(),
            uend: uclose as u32 + 1,
            sall: sk.into(),
            skeys: skeys.into_boxed_slice(),
            slen: slen.into_boxed_slice(),
            send: sclose as u32 + 1,
            unames,
            snames,
            sord,
            addrs: addrs.into_boxed_slice(),
            escaped,
            enum_idx,
            enum_bases,
            natives,
            version,
        })
    }

    /// The JSON the table reads from.
    pub(crate) fn json(&self) -> &[u8] {
        &self.json
    }

    /// What `store::extract_identifier` reads from an ISF, from this table: (the
    /// `metadata.windows.pdb` GUID, database and age; the `constant_data` string of the
    /// `version` symbol; that of `linux_banner`), with the same semantics (a symbol's value
    /// parsed as a python dict, whatever the format version).
    pub(crate) fn identifier_fields(&self) -> (Option<(String, String, u64)>, Option<String>, Option<String>) {
        let win = super::table::SymbolTable::from_blob(super::table::Blob::Shared(self.skeleton.clone()), "", "").ok().and_then(|t| {
            let pdb = t.metadata().path(&["windows", "pdb"])?;
            let guid = pdb.get("GUID").and_then(|g| g.as_str()).unwrap_or("").to_string();
            let db = pdb.get("database").and_then(|g| g.as_str()).unwrap_or("").to_string();
            let age = pdb.get("age").and_then(|g| g.as_u64()).unwrap_or(0);
            Some((guid, db, age))
        });
        let cdata = |name: &str| -> Option<String> {
            let o = self.find_symbol(name)? as usize;
            self.with_member(self.skeys[o], self.sym_end(o), |w| {
                let v = w.value().ok()?;
                v.get("constant_data").and_then(|c| c.as_str()).map(str::to_string)
            })
        };
        (win, cdata("version"), cdata("linux_banner"))
    }

    /// The name of the member key at position `p` whose name is `len` bytes.
    #[inline]
    fn key_str(&self, p: u32, len: u32) -> &str {
        name_at(&self.json, &self.escaped, p, len)
    }

    fn ctx(&self) -> fast::Ctx<'_, LazyCore> {
        fast::Ctx { natives: &self.natives, native_idx: &self.native_idx, names: self, flatten: self.flatten }
    }

    /// Parse the member value of the key at `start` (its bytes end at `end`) with `f`, through
    /// a local index (validated when the table was built).
    fn with_member<'s, R>(&'s self, start: u32, end: u32, f: impl FnOnce(&mut Walker<'_, 's>) -> Option<R>) -> Option<R> {
        thread_local! {
            static POS: std::cell::Cell<Vec<u32>> = const { std::cell::Cell::new(Vec::new()) };
        }
        let (start, end) = (start as usize, end as usize);
        let part = self.json.get(start..end)?;
        // one reused position buffer per thread, sized for the member (entries <= bytes)
        let mut pos = POS.with(|p| p.take());
        pos.reserve(part.len() + 64);
        let idx = Index::build_serial_reusing(part, pos).ok()?;
        let mut w = idx.walker(part).with_base(start);
        w.seek(3);
        let r = f(&mut w);
        POS.with(|p| p.set(idx.recycle()));
        r
    }

    /// Fields of user type `i` (anonymous members, record building).
    fn user_fields(&self, i: u32) -> Option<(Cow<'_, str>, i128, Vec<fast::FieldTmp<'_>>, Vec<Desc<'_>>)> {
        let start = *self.ukeys.get(i as usize)?;
        let end = self.ukeys.get(i as usize + 1).copied().unwrap_or(self.uend);
        self.with_member(start, end, |w| {
            let mut arena = Vec::new();
            let (kind, size, fields) = fast::read_user(w, &mut arena).ok()?;
            Some((kind, size, fields, arena))
        })
    }

    // ---------------------------------------------------------------- nodes

    #[inline]
    pub(crate) fn node(&self, i: TypeIdx) -> Ty {
        self.nodes.get(i.0 as usize).unwrap_or(Ty::Void)
    }

    pub(crate) fn unresolved_name(&self, i: TypeIdx) -> &str {
        self.holders.lock().unwrap_or_else(|e| e.into_inner()).1.get(&i.0).copied().unwrap_or("")
    }

    // ---------------------------------------------------------------- user types

    pub(crate) fn user_type_count(&self) -> usize {
        self.ukeys.len()
    }

    #[inline]
    pub(crate) fn user_type(&self, name: &str) -> Option<u32> {
        self.unames.find(name, |o| self.key_str(self.ukeys[o as usize], self.ulen[o as usize]) == name)
    }

    pub(crate) fn user_type_name(&self, i: u32) -> &str {
        self.ukeys.get(i as usize).map_or("", |&k| self.key_str(k, self.ulen[i as usize]))
    }

    /// User type `i`, resolved on first use.
    #[inline]
    pub(crate) fn user(&self, i: u32) -> Option<&UserRec> {
        let slot = self.users.get(i as usize)?;
        Some(slot.get_or_init(|| Box::new(self.make_user(i).unwrap_or_else(UserRec::empty))))
    }

    fn make_user(&self, i: u32) -> Option<UserRec> {
        // validated when the table was built: this cannot fail
        let (kind, size, fields, arena) = self.user_fields(i)?;
        let mut sub = |si: u32| -> crate::error::Result<(Vec<fast::FieldTmp<'_>>, Vec<Desc<'_>>)> {
            let (_, _, f, a) = self.user_fields(si).ok_or_else(|| crate::error::Error::msg("user type"))?;
            Ok((f, a))
        };
        let members = self.ctx().members(&mut sub, &fields, &arena, &mut LazySink(self)).ok()?;
        let mut names = String::with_capacity(members.iter().map(|m| m.0.len()).sum());
        let mut recs = Vec::with_capacity(members.len());
        for (n, off, ty) in &members {
            recs.push((names.len() as u32, n.len() as u32, *off, *ty));
            names.push_str(n);
        }
        // the blob's member index: (2n).next_power_of_two() slots (at least 4), linear probing
        let nslots = if recs.is_empty() { 0 } else { (recs.len() * 2).next_power_of_two().max(4) };
        let mut slots = vec![0u32; nslots];
        for (k, m) in recs.iter().enumerate() {
            let mut j = hash_bytes(&names.as_bytes()[m.0 as usize..(m.0 + m.1) as usize]) as usize & (nslots - 1);
            while slots[j] != 0 {
                j = (j + 1) & (nslots - 1);
            }
            slots[j] = k as u32 + 1;
        }
        Some(UserRec { kind: user_kind_code(&kind), size: size.clamp(0, u32::MAX as i128) as u32, names, members: recs.into_boxed_slice(), slots: slots.into_boxed_slice() })
    }

    // ---------------------------------------------------------------- symbols

    pub(crate) fn symbol_count(&self) -> usize {
        self.skeys.len()
    }

    #[inline]
    pub(crate) fn find_symbol(&self, name: &str) -> Option<u32> {
        let ord = |ki: u32| -> Option<u32> {
            match &self.sord {
                None => Some(ki),
                Some(m) => m.get(ki as usize).copied().filter(|&o| o != u32::MAX),
            }
        };
        let ki = self.snames.find(name, |ki| ord(ki).is_some_and(|o| self.symbol_name(o) == name))?;
        ord(ki)
    }

    pub(crate) fn symbol_name(&self, i: u32) -> &str {
        self.skeys.get(i as usize).map_or("", |&k| self.key_str(k, self.slen[i as usize]))
    }

    /// Where the member value of symbol `i` ends (the next member's key, or past the section).
    fn sym_end(&self, i: usize) -> u32 {
        let k = self.skeys[i];
        let j = self.sall.partition_point(|&p| p <= k);
        self.sall.get(j).copied().unwrap_or(self.send)
    }

    /// Symbol `i`, resolved on first use.
    #[inline]
    pub(crate) fn sym(&self, i: u32) -> Option<&SymRec> {
        let slot = self.syms.get(i as usize)?;
        Some(slot.get_or_init(|| Box::new(self.make_sym(i).unwrap_or(SymRec { address: 0, ty: u32::MAX, cdata: None }))))
    }

    fn make_sym(&self, i: u32) -> Option<SymRec> {
        let i = i as usize;
        self.with_member(self.skeys[i], self.sym_end(i), |w| {
            let mut arena = Vec::new();
            let (address, ty, cd) = fast::read_symbol(w, &mut arena).ok()?;
            let ty = match (self.sym_types, ty) {
                (true, Some(d)) => {
                    let mut sink = LazySink(self);
                    let t = self.ctx().resolve(&arena, d, &mut sink);
                    fast::Sink::node(&mut sink, t).0
                }
                _ => u32::MAX,
            };
            let cdata = if self.sym_cdata { cd.map(|c| b64decode(&c).into_boxed_slice()) } else { None };
            Some(SymRec { address: address as u64, ty, cdata })
        })
    }

    /// Every symbol's address (`address as u64`, unmasked), ordinal order (read by the index
    /// pass: address lookups and whole-table scans resolve no symbol).
    #[inline]
    pub(crate) fn addrs(&self) -> &[u64] {
        &self.addrs
    }
}

/// [`LazyCore`] name lengths: the name is not the key's text as is (escapes, invalid UTF-8) but
/// decoded, kept in `LazyCore::escaped`.
const NAME_DECODED: u32 = u32::MAX;

/// The name of the member key whose opening quote is at `p` and whose name is `len` bytes long
/// ([`NAME_DECODED`]: in `escaped`). The text was validated when the table was built.
#[inline]
fn name_at<'j>(json: &'j [u8], escaped: &'j FxHashMap<u32, Box<str>>, p: u32, len: u32) -> &'j str {
    if len == NAME_DECODED {
        return escaped.get(&p).map(|s| &**s).unwrap_or("");
    }
    let (a, b) = (p as usize + 1, p as usize + 1 + len as usize);
    json.get(a..b).and_then(|t| std::str::from_utf8(t).ok()).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::isf::build_blob;
    use crate::symbols::{Symbol, SymbolTable};

    /// `RSVOL_BENCH_JSON=path cargo test --profile fast lazy_index_bench -- --ignored --nocapture`:
    /// the lazy index's phases against the full build (best of N, in process).
    #[test]
    #[ignore]
    fn lazy_index_bench() {
        let path = std::env::var("RSVOL_BENCH_JSON").expect("RSVOL_BENCH_JSON");
        let raw = std::fs::read(&path).unwrap();
        let data = if path.ends_with(".xz") { crate::codecs::xz::decompress(&raw).unwrap() } else { raw };
        let data: &'static [u8] = Box::leak(data.into_boxed_slice());
        let n: usize = std::env::var("RSVOL_BENCH_N").ok().and_then(|v| v.parse().ok()).unwrap_or(15);
        let best = |f: &mut dyn FnMut()| -> f64 {
            let mut b = f64::MAX;
            for _ in 0..n {
                let t = std::time::Instant::now();
                f();
                b = b.min(t.elapsed().as_secs_f64());
            }
            b * 1e3
        };
        let opts = BuildOptions::default();
        println!("{path}: {:.1} MB, {} threads, best of {n}", data.len() as f64 / 1e6, crate::util::par::threads());
        println!("  stage 1 (parallel)          {:7.2} ms", best(&mut || drop(Index::build_with(data, true).unwrap())));
        println!("  shallow pass                {:7.2} ms", best(&mut || drop(shallow(data).unwrap())));
        println!("  lazy index (total)          {:7.2} ms", best(&mut || drop(LazyCore::build(JsonBuf::Static(data), &opts).ok().unwrap())));
        println!("  full build                  {:7.2} ms", best(&mut || drop(build_blob(data, &opts).unwrap())));
        // the member pass alone: local stage 1 only, then with the member parse
        let sh = shallow(data).unwrap();
        let (o, c) = *sh.containers.iter().max_by_key(|(o, c)| c - o).unwrap();
        let keys: Vec<u32> = sh.keys.iter().copied().filter(|&k| k > o && k < c).collect();
        let rs = byte_ranges(&keys, 256 << 10);
        let stage1 = |i: usize| {
            let r = rs[i].clone();
            let end = keys.get(r.end).map_or(c as usize + 1, |&k| k as usize);
            drop(Index::build_serial_reusing(&data[keys[r.start] as usize..end], Vec::new()).unwrap());
        };
        println!("  biggest section: {} members, {:.1} MB", keys.len(), (c - o) as f64 / 1e6);
        println!("    local stage 1 only        {:7.2} ms", best(&mut || crate::util::pool::for_each(rs.len(), &stage1)));
        let parse = |i: usize| {
            let mut pos = Vec::new();
            let mut arena = Vec::new();
            fast::each_member_local(data, &keys, rs[i].clone(), c as usize, &mut pos, |p, _, _| {
                arena.clear();
                if p.peek_kind()? == crate::util::json::Kind::Obj {
                    // user types and symbols: whichever this section is
                    let mut q = p.clone();
                    if fast::read_symbol(&mut q, &mut arena).is_ok() {
                        *p = q;
                        return Ok(());
                    }
                    arena.clear();
                    fast::read_user(p, &mut arena).map(drop)
                } else {
                    p.skip()
                }
            })
            .unwrap();
        };
        println!("    + member parse            {:7.2} ms", best(&mut || crate::util::pool::for_each(rs.len(), &parse)));
    }

    /// Two types are the same type (pointer targets and array elements compared as the types
    /// they describe: node numbers differ between a lazy and a full table).
    fn same_ty(a: &SymbolTable, ta: Ty, b: &SymbolTable, tb: Ty, depth: u32) -> bool {
        if depth > 64 {
            return true;
        }
        match (ta, tb) {
            (Ty::Pointer { prim: pa, target: xa }, Ty::Pointer { prim: pb, target: xb }) => pa == pb && same_ty(a, a.node(xa), b, b.node(xb), depth + 1),
            (Ty::Array { count: ca, elem: ea }, Ty::Array { count: cb, elem: eb }) => ca == cb && same_ty(a, a.node(ea), b, b.node(eb), depth + 1),
            (Ty::Unresolved(ia), Ty::Unresolved(ib)) => a.unresolved_name(ia) == b.unresolved_name(ib),
            (x, y) => x == y,
        }
    }

    /// Everything a plugin can ask `lazy` answers exactly as `full` does.
    fn assert_same(full: &SymbolTable, lazy: &SymbolTable, what: &str) {
        assert!(lazy.is_lazy() && !full.is_lazy());
        assert_eq!(full.format(), lazy.format(), "{what}: format");
        assert_eq!(full.metadata(), lazy.metadata(), "{what}: metadata");
        assert_eq!(full.user_type_count(), lazy.user_type_count(), "{what}: user types");
        for i in 0..full.user_type_count() as u32 {
            let n = full.user_type_name(i);
            assert_eq!(n, lazy.user_type_name(i), "{what}: user type {i}");
            assert_eq!(lazy.user_type(n), Some(i), "{what}: lookup {n}");
            assert_eq!(full.user_type_size(i), lazy.user_type_size(i), "{what}: size of {n}");
            assert_eq!(full.user_type_kind(i), lazy.user_type_kind(i), "{what}: kind of {n}");
            let (fm, lm): (Vec<_>, Vec<_>) = (full.members(i).collect(), lazy.members(i).collect());
            assert_eq!(fm.len(), lm.len(), "{what}: members of {n}");
            for (x, y) in fm.iter().zip(&lm) {
                assert!(x.name == y.name && x.offset == y.offset && same_ty(full, x.ty, lazy, y.ty, 0), "{what}: {n}.{} {:?} vs {:?}", x.name, x.ty, y.ty);
                let z = lazy.member(i, x.name).expect("member lookup");
                assert!(z.offset == x.offset && same_ty(full, x.ty, lazy, z.ty, 0), "{what}: {n}.{} lookup", x.name);
                assert_eq!(full.type_name(x.ty), lazy.type_name(y.ty), "{what}: {n}.{} type name", x.name);
                assert_eq!(full.size_of(x.ty), lazy.size_of(y.ty), "{what}: {n}.{} size", x.name);
            }
            assert!(lazy.member(i, "no such member \u{1}").is_none());
        }
        assert_eq!(full.symbol_count(), lazy.symbol_count(), "{what}: symbols");
        let fs: Vec<Symbol> = full.symbols().collect();
        let ls: Vec<Symbol> = lazy.symbols().collect();
        for (x, y) in fs.iter().zip(&ls) {
            assert!(x.name == y.name && x.address == y.address && x.constant_data == y.constant_data, "{what}: symbol {}", x.name);
            match (x.ty, y.ty) {
                (Some(p), Some(q)) => assert!(same_ty(full, p, lazy, q, 0), "{what}: type of symbol {}", x.name),
                (None, None) => {}
                _ => panic!("{what}: type of symbol {}", x.name),
            }
            let g = lazy.get_symbol(x.name).unwrap();
            assert_eq!((g.name, g.address), (x.name, x.address), "{what}: get_symbol {}", x.name);
        }
        assert!(lazy.get_symbol("no such symbol \u{1}").is_err() && !lazy.has_symbol("no such symbol \u{1}"));
        assert!(full.symbol_names_addrs().eq(lazy.symbol_names_addrs()), "{what}: names + addresses");
        // distinct addresses (many symbols can share one: every offset would list them all)
        let mut offs: Vec<u64> = fs.iter().step_by(7).map(|s| s.address).collect();
        offs.sort_unstable();
        offs.dedup();
        assert_eq!(full.symbols_at_exact_many(&offs), lazy.symbols_at_exact_many(&offs), "{what}: symbols_at_exact_many");
        for &o in offs.iter().take(20) {
            assert_eq!(full.symbols_at_exact(o), lazy.symbols_at_exact(o), "{what}: symbols_at_exact");
            assert_eq!(full.symbols_at(o, 64), lazy.symbols_at(o, 64), "{what}: symbols_at");
        }
        assert_eq!(full.natives(), lazy.natives(), "{what}: natives");
        assert_eq!(full.enum_count(), lazy.enum_count(), "{what}: enums");
        for i in 0..full.enum_count() as u32 {
            assert_eq!(full.enum_name(i), lazy.enum_name(i));
            assert_eq!(full.enum_base(i), lazy.enum_base(i));
            assert!(full.enum_constants(i).eq(lazy.enum_constants(i)), "{what}: enum {}", full.enum_name(i));
        }
        for n in full.user_type_names().chain(["pointer", "void", "unsigned long", "long", "array", "string", "nope"]) {
            match (full.get_type(n), lazy.get_type(n)) {
                (Ok(x), Ok(y)) => assert!(same_ty(full, x, lazy, y, 0), "{what}: get_type {n}"),
                (Err(_), Err(_)) => {}
                _ => panic!("{what}: get_type {n}"),
            }
        }
        assert_eq!(full.is_64bit(), lazy.is_64bit());
        assert_eq!(full.identifier(), lazy.identifier());
        assert_eq!(full.pdb_info(), lazy.pdb_info());
    }

    fn tables(json: &[u8]) -> Option<(SymbolTable, SymbolTable)> {
        let opts = BuildOptions::default();
        let full = SymbolTable::from_blob(super::super::table::Blob::Owned(build_blob(json, &opts).ok()?), "t", "u").unwrap();
        let core = LazyCore::build(JsonBuf::Owned(json.to_vec()), &opts).ok()?;
        // the identifier index reads the identifier of a lazily indexed ISF from its table
        let (win, mac, linux) = core.identifier_fields();
        assert_eq!(crate::symbols::store::identifier_from(win, mac, linux), crate::symbols::store::extract_identifier(json), "identifier");
        Some((full, SymbolTable::from_lazy(Arc::new(core), "t", "u").unwrap()))
    }

    /// Synthetic ISFs exercising everything the resolver does (anonymous members across
    /// ranges, unresolved and qualified names, enum bitfields, symbols with and without types
    /// and data, non-symbol members) for several format versions: identical answers.
    #[test]
    fn lazy_equals_full_synthetic() {
        use crate::symbols::isf::tests::{ISF, unique_isf};
        let (f, l) = tables(ISF.as_bytes()).expect("lazy path");
        assert_same(&f, &l, "ISF");
        for (format, nt, ns) in [("6.2.0", 9000, 40000), ("6.1.0", 3000, 5000), ("4.1.0", 800, 700), ("2.1.0", 300, 300), ("2.0.0", 200, 100), ("6.2.0", 3, 2)] {
            let json = unique_isf(format, nt, ns);
            let (f, l) = tables(&json).expect("lazy path");
            assert_same(&f, &l, format);
        }
    }

    /// Type, member, symbol and enum names spelled with escapes or holding invalid UTF-8 (the
    /// names decoded like the full builder decodes them), across parallel ranges.
    #[test]
    fn lazy_equals_full_escaped_names() {
        use crate::symbols::isf::tests::unique_isf;
        let mut json = unique_isf("6.2.0", 3000, 9000);
        let text = |j: &[u8], a: &[u8], b: &[u8]| -> Vec<u8> {
            let mut out = Vec::with_capacity(j.len());
            let mut i = 0;
            while i < j.len() {
                if j[i..].starts_with(a) {
                    out.extend_from_slice(b);
                    i += a.len();
                } else {
                    out.push(j[i]);
                    i += 1;
                }
            }
            out
        };
        // a type name, its references and a symbol name with escapes; a member name with an
        // escaped quote; a type and a symbol whose names hold a byte that is not UTF-8
        json = text(&json, b"\"_T17\"", b"\"_T\\u00317\"");
        json = text(&json, b"\"sym23\"", b"\"sym\\u00e923\"");
        json = text(&json, b"\"e\": {\"offset\": 16", b"\"e\\\"q\": {\"offset\": 16");
        json = text(&json, b"\"_T29\": {", b"\"_T\xff29\": {");
        json = text(&json, b"\"sym31\": {", b"\"sym\xfe31\": {");
        let (f, l) = tables(&json).expect("lazy path");
        assert_same(&f, &l, "escaped names");
        assert!(l.user_type("_T17").is_some() && l.get_symbol("sym\u{e9}23").is_ok());
        assert!(l.user_type("_T\u{fffd}29").is_some() && l.get_symbol("sym\u{fffd}31").is_ok());
    }

    /// Every ISF shipped with volatility3: where the lazy table exists it answers like the full
    /// table, and it exists wherever the fused builder builds one.
    #[test]
    fn lazy_equals_full_shipped() {
        let mut n = 0;
        for &(rel, _, data) in crate::symbols::embedded::FILES {
            let json = if rel.ends_with(".xz") { crate::codecs::xz::decompress(data).unwrap() } else { data.to_vec() };
            let fused = crate::symbols::isf::fast::prepare(&json, &BuildOptions::default()).is_some();
            match tables(&json) {
                Some((f, l)) => {
                    assert_same(&f, &l, rel);
                    n += 1;
                }
                None => assert!(!fused || LazyCore::build(JsonBuf::Owned(json.clone()), &BuildOptions::default()).is_err(), "{rel}"),
            }
        }
        assert!(n > 50, "{n}");
    }

    /// Damaged documents: whenever the lazy index accepts one, the full builder does too and
    /// both answer the same (the lazy table never accepts a document the full builder
    /// rejects).
    #[test]
    fn lazy_never_accepts_more() {
        use crate::symbols::isf::tests::unique_isf;
        let json = unique_isf("6.2.0", 3000, 6000);
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut accepted = 0;
        for round in 0..400 {
            let mut d = json.clone();
            for _ in 0..1 + round % 3 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let i = x as usize % d.len();
                d[i] = b"{}[]:,\"\\ 0a-\n\x01tf"[(x >> 40) as usize % 16];
            }
            if let Ok(core) = LazyCore::build(JsonBuf::Owned(d.clone()), &BuildOptions::default()) {
                accepted += 1;
                let blob = build_blob(&d, &BuildOptions::default()).unwrap_or_else(|e| panic!("round {round}: lazy accepted, full rejected: {e}"));
                let full = SymbolTable::from_blob(super::super::table::Blob::Owned(blob), "t", "u").unwrap();
                assert_same(&full, &SymbolTable::from_lazy(Arc::new(core), "t", "u").unwrap(), &format!("round {round}"));
            }
        }
        assert!(accepted > 20, "{accepted}");
    }

    /// Every ISF on this machine (testdata, python's cache): lazy == full.
    /// `cargo test --profile fast lazy_equals_full_on_all_isfs -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn lazy_equals_full_on_all_isfs() {
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
        if let Ok(only) = std::env::var("RSVOL_TEST_ISF_FILTER") {
            files.retain(|f| f.to_string_lossy().contains(&only));
        }
        let rss = || std::fs::read_to_string("/proc/self/statm").ok().and_then(|s| s.split(' ').nth(1).and_then(|x| x.parse::<u64>().ok())).unwrap_or(0) * 4096 >> 20;
        let (mut n, mut skipped) = (0, 0);
        for f in &files {
            let Ok(raw) = std::fs::read(f) else { continue };
            let json = if f.to_string_lossy().ends_with(".xz") {
                match crate::codecs::xz::decompress(&raw) {
                    Ok(j) => j,
                    Err(_) => continue,
                }
            } else {
                raw
            };
            let fused = crate::symbols::isf::fast::prepare(&json, &BuildOptions::default()).is_some();
            let r0 = rss();
            match tables(&json) {
                Some((full, lazy)) => {
                    let r1 = rss();
                    assert_same(&full, &lazy, &f.to_string_lossy());
                    eprintln!("  rss before {r0} MB, tables {r1} MB, compared {} MB", rss());
                    n += 1;
                    let rss = std::fs::read_to_string("/proc/self/statm").ok().and_then(|s| s.split(' ').nth(1).and_then(|x| x.parse::<u64>().ok())).unwrap_or(0) * 4096;
                    eprintln!("ok {} ({:.1} MB json, rss {} MB)", f.display(), json.len() as f64 / 1e6, rss >> 20);
                }
                None => {
                    assert!(!fused, "{}: fused builder took it, the lazy index did not", f.display());
                    skipped += 1;
                }
            }
        }
        println!("{n} ISFs identical, {skipped} not taken by either fast path, of {}", files.len());
    }
}
