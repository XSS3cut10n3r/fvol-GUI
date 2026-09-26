//! Table-driven decoder/formatter for fixed-width (32-bit) ARM instruction specs.
//!
//! A spec is a text (grammar in bench/scripts/arm_spec.py) listing instruction *classes*
//! (mask/value + mnemonic + operand template) in priority order, lookup tables and
//! hand-written handler classes.  It is compiled once, lazily, into flat arrays that reference
//! the spec text itself for every string (no copies), plus a decision tree that maps an
//! instruction word to the short, priority-ordered list of classes that can match it.
//!
//! Decoding an instruction = walk the tree (a few indexed loads), test the candidates'
//! mask/value, check the class constraints, then append the text of each template op.

/// Hand-written formatting for families whose printing depends on value comparisons:
/// appends the text (mnemonic, TAB, operands) and returns `Res::Ok`, or returns
/// `Res::Invalid` / `Res::Other` (not handled: try the next class).
pub(crate) type Handler = fn(u32, u64, &mut String) -> Res;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Res {
    Ok,
    Other,
    Invalid,
}

/// Substring of the spec text.
#[derive(Clone, Copy, Default, Debug)]
struct SRef {
    off: u32,
    len: u32,
}

/// Table entry / exception codes.
const E_OTHER: u32 = u32::MAX;
const E_INVALID: u32 = u32::MAX - 1;

/// Integer-valued operand field: concatenated bit segments (LSB first), optional sign
/// extension, scale and base; or a generic linear combination of single bits.
#[derive(Clone, Copy, Default, Debug)]
struct Field {
    segs: [(u8, u8); 4],
    nseg: u8,
    width: u8,
    signed: bool,
    scale: i64,
    base: i64,
    /// generic linear form: range in `Engine::lin` (len 0 = segment form)
    lin_off: u32,
    lin_len: u32,
}

impl Field {
    #[inline(always)]
    fn raw(&self, w: u32) -> u64 {
        let mut v: u64 = 0;
        let mut sh = 0u32;
        for i in 0..self.nseg as usize {
            let (lsb, n) = self.segs[i];
            let x = (w >> lsb) as u64 & ((1u64 << n) - 1);
            v |= x << sh;
            sh += n as u32;
        }
        v
    }

    #[inline(always)]
    fn eval(&self, w: u32, lin: &[(u8, i64)]) -> i64 {
        if self.lin_len != 0 {
            let mut v = self.base;
            let s = self.lin_off as usize;
            for &(b, c) in &lin[s..s + self.lin_len as usize] {
                if (w >> b) & 1 != 0 {
                    v = v.wrapping_add(c);
                }
            }
            return v;
        }
        let mut x = self.raw(w) as i64;
        if self.signed && self.width > 0 && self.width < 64 {
            let sh = 64 - self.width as u32;
            x = (x << sh) >> sh;
        }
        self.base.wrapping_add(x.wrapping_mul(self.scale))
    }
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Lit(SRef),
    Reg { cls: u8, sp31: u8, field: Field, suffix: SRef, exc_off: u32, exc_len: u32 },
    Num { prefix: SRef, style: u8, pc: u8, field: Field, exc_off: u32, exc_len: u32 },
    Tab { table: u32, idx_off: u32, nbits: u8, np31: u8 },
}

#[derive(Clone, Debug)]
enum Table {
    Dense(Vec<u32>),
    Gen { generator: Gen, rules: Vec<(u32, u32, u32)>, default: u32 },
}

#[derive(Clone, Copy, Debug)]
enum Gen {
    Const,
    Sysreg(u8),
    Bitmask { lsb: u8, size: u8, style: u8 },
}

#[derive(Clone, Copy, Debug)]
struct Class {
    mask: u32,
    value: u32,
    /// handler index (u32::MAX = none)
    handler: u32,
    mnem: SRef,
    prog_off: u32,
    prog_len: u32,
    cons_off: u32,
    cons_len: u32,
}

/// Constraint: kind 0 = tie (bit a == bit b, else OTHER), 1 = neq (5-bit fields at a, b differ,
/// else INVALID), 2 = neq31 (like neq unless the value is 31).
#[derive(Clone, Copy, Debug)]
struct Cons {
    kind: u8,
    a: u8,
    b: u8,
    /// field width (neq kinds)
    w: u8,
}

pub(crate) struct Engine {
    text: &'static str,
    classes: Vec<Class>,
    ops: Vec<Op>,
    lin: Vec<(u8, i64)>,
    exc: Vec<(u64, u32)>,
    idx_bits: Vec<u8>,
    cons: Vec<Cons>,
    tables: Vec<Table>,
    /// table entries (SRef) addressed by index
    ents: Vec<SRef>,
    handlers: Vec<Handler>,
    tree: Vec<u32>,
    /// class ids referenced by tree leaves
    leaf: Vec<u32>,
    /// 32-bit ARM condition folding (spec record "F cond"): a conditional word no class
    /// matches is rendered as its AL (0b1110) twin with the condition suffix inserted into the
    /// mnemonic (before the first '.', e.g. "vaddeq.f32").
    fold_cond: bool,
    // compile-time only
    table_names: std::collections::HashMap<&'static str, u32>,
    prog_cache: std::collections::HashMap<&'static str, (u32, u32)>,
}

// number styles
const ST_S64: u8 = 0;
const ST_U64: u8 = 1;
const ST_S32: u8 = 2;
const ST_U32: u8 = 3;
const ST_DEC: u8 = 4;
const ST_SDEC: u8 = 5;
const ST_SX16: u8 = 6;
const ST_SX16OR64: u8 = 7;

fn style_of(s: &str) -> Option<u8> {
    Some(match s {
        "S64" => ST_S64,
        "U64" => ST_U64,
        "S32" => ST_S32,
        "U32" => ST_U32,
        "DEC" => ST_DEC,
        "SDEC" => ST_SDEC,
        "SX16" => ST_SX16,
        "SX16OR64" => ST_SX16OR64,
        _ => return None,
    })
}

// ------------------------------------------------------------------------------------------
// number formatting (capstone's rules: hex above 9, "-0x.." for negatives when signed)

const HEX: &[u8; 16] = b"0123456789abcdef";

#[inline]
pub(crate) fn push_hex(out: &mut String, mut v: u64) {
    let mut buf = [0u8; 16];
    let mut i = 16;
    loop {
        i -= 1;
        buf[i] = HEX[(v & 15) as usize];
        v >>= 4;
        if v == 0 {
            break;
        }
    }
    for &c in &buf[i..] {
        out.push(c as char);
    }
}

#[inline]
pub(crate) fn push_dec(out: &mut String, mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = 20;
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for &c in &buf[i..] {
        out.push(c as char);
    }
}

#[inline]
fn push_thresh(out: &mut String, v: u64) {
    if v > 9 {
        out.push_str("0x");
        push_hex(out, v);
    } else {
        push_dec(out, v);
    }
}

#[inline]
fn push_signed(out: &mut String, v: i64) {
    if v < 0 {
        out.push('-');
    }
    push_thresh(out, v.unsigned_abs());
}

pub(crate) fn push_num(out: &mut String, v: i64, style: u8) {
    match style {
        ST_S64 => push_signed(out, v),
        ST_U64 => push_thresh(out, v as u64),
        ST_S32 => push_signed(out, v as i32 as i64),
        ST_U32 => push_thresh(out, v as u32 as u64),
        ST_DEC => push_dec(out, v as u32 as u64),
        ST_SDEC => {
            let x = v as i32;
            if x < 0 {
                out.push('-');
            }
            push_dec(out, x.unsigned_abs() as u64);
        }
        ST_SX16 => push_thresh(out, v as i16 as i32 as u32 as u64),
        ST_SX16OR64 => {
            if (v as u64 & 0xFFFF) == (v as u64 & 0xFFFF_FFFF) {
                push_thresh(out, v as i16 as i32 as u32 as u64)
            } else {
                push_thresh(out, v as u64)
            }
        }
        _ => push_signed(out, v),
    }
}

/// AArch64 DecodeBitMasks(N, imms, immr, immediate = TRUE) for `regsize` bits.
pub(crate) fn decode_bitmask(n: u32, immr: u32, imms: u32, regsize: u32) -> Option<u64> {
    let x = (n << 6) | (!imms & 0x3F);
    if x == 0 {
        return None;
    }
    let len = 31 - x.leading_zeros();
    if len < 1 || (regsize == 32 && n != 0) {
        return None;
    }
    let esize = 1u32 << len;
    let levels = esize - 1;
    let s = imms & levels;
    let r = immr & levels;
    if s == levels {
        return None;
    }
    let emask: u64 = if esize == 64 { u64::MAX } else { (1u64 << esize) - 1 };
    let welem: u64 = (1u64 << (s + 1)) - 1;
    let rot = if r == 0 { welem } else { ((welem >> r) | (welem << (esize - r))) & emask };
    let mut v = 0u64;
    let mut i = 0;
    while i < regsize {
        v |= rot << i;
        i += esize;
    }
    Some(v)
}

// ------------------------------------------------------------------------------------------
// spec compilation

fn parse_hex(s: &str) -> Option<u32> {
    u32::from_str_radix(s, 16).ok()
}

impl Engine {
    fn sref(&self, s: &str) -> SRef {
        let base = self.text.as_ptr() as usize;
        let p = s.as_ptr() as usize;
        debug_assert!(p >= base && p + s.len() <= base + self.text.len());
        SRef { off: (p - base) as u32, len: s.len() as u32 }
    }

    #[inline(always)]
    fn s(&self, r: SRef) -> &'static str {
        let t: &'static str = self.text;
        t.get(r.off as usize..(r.off + r.len) as usize).unwrap_or("")
    }

    fn entry(&mut self, s: &'static str) -> u32 {
        match s {
            "!O" => E_OTHER,
            "!I" => E_INVALID,
            _ => {
                let r = self.sref(s);
                self.ents.push(r);
                (self.ents.len() - 1) as u32
            }
        }
    }

    fn parse_field(&mut self, s: &'static str) -> Option<Field> {
        let mut f = Field { scale: 1, ..Default::default() };
        // base: trailing [+-]digits after the core
        let bytes = s.as_bytes();
        let mut core_end = s.len();
        let mut i = s.len();
        while i > 0 && bytes[i - 1].is_ascii_digit() {
            i -= 1;
        }
        if i > 0 && i < s.len() && (bytes[i - 1] == b'+' || bytes[i - 1] == b'-') {
            // make sure this is not part of a segment like "5:19" (':' precedes digits there)
            let v: i64 = s[i..].parse().ok()?;
            f.base = if bytes[i - 1] == b'-' { -v } else { v };
            core_end = i - 1;
        }
        let core = &s[..core_end];
        if let Some(rest) = core.strip_prefix('L') {
            f.lin_off = self.lin.len() as u32;
            for item in rest.split(',').filter(|x| !x.is_empty()) {
                let (b, c) = item.split_once(':')?;
                self.lin.push((b.parse().ok()?, c.parse().ok()?));
            }
            f.lin_len = self.lin.len() as u32 - f.lin_off;
            if f.lin_len == 0 {
                // constant: represent as an empty segment field
                f.nseg = 0;
            }
            return Some(f);
        }
        let mut core = core;
        if let Some(r) = core.strip_prefix('s') {
            f.signed = true;
            core = r;
        }
        if let Some((c, sc)) = core.split_once('*') {
            f.scale = sc.parse().ok()?;
            core = c;
        }
        for seg in core.split(',') {
            let (a, n) = seg.split_once(':')?;
            if f.nseg as usize >= f.segs.len() {
                return None;
            }
            let a: u8 = a.parse().ok()?;
            let n: u8 = n.parse().ok()?;
            if a > 31 || n == 0 || n > 32 {
                return None;
            }
            f.segs[f.nseg as usize] = (a, n);
            f.nseg += 1;
            f.width += n;
        }
        Some(f)
    }

    fn parse_exc(&mut self, s: &str) -> Option<(u32, u32)> {
        let off = self.exc.len() as u32;
        if s != "-" {
            for item in s.split(',') {
                let (k, v) = item.split_once('=')?;
                let k: u64 = k.parse().ok()?;
                let v = if v == "O" { E_OTHER } else { E_INVALID };
                self.exc.push((k, v));
            }
        }
        Some((off, self.exc.len() as u32 - off))
    }

    fn parse_atom(&mut self, a: &'static str) -> Option<Op> {
        let f: Vec<&'static str> = a.split(' ').collect();
        match f[0] {
            "r" if f.len() == 6 => {
                let cls = f[1].as_bytes().first().copied()?;
                let sp31 = f[2].as_bytes().first().copied()?;
                let field = self.parse_field(f[3])?;
                let suffix = if f[4] == "-" { SRef::default() } else { self.sref(f[4]) };
                let (exc_off, exc_len) = self.parse_exc(f[5])?;
                Some(Op::Reg { cls, sp31, field, suffix, exc_off, exc_len })
            }
            "n" if f.len() == 6 => {
                let prefix = if f[1] == "-" { SRef::default() } else { self.sref(f[1]) };
                let style = style_of(f[2])?;
                let pc: u8 = f[3].parse().ok()?;
                let field = self.parse_field(f[4])?;
                let (exc_off, exc_len) = self.parse_exc(f[5])?;
                Some(Op::Num { prefix, style, pc, field, exc_off, exc_len })
            }
            "t" if f.len() == 3 => {
                let table = *self.table_names.get(f[1])?;
                let idx_off = self.idx_bits.len() as u32;
                let (bits, p31) = match f[2].split_once('/') {
                    Some((b, p)) => (b, p),
                    None => (f[2], ""),
                };
                let mut nbits = 0u8;
                if bits != "-" {
                    for b in bits.split(',') {
                        self.idx_bits.push(b.parse().ok()?);
                        nbits += 1;
                    }
                }
                let mut np31 = 0u8;
                for b in p31.split(',').filter(|x| !x.is_empty()) {
                    // pseudo bit "register field == all ones": lsb | width << 5
                    let (a, wd) = match b.split_once(':') {
                        Some((a, wd)) => (a.parse::<u8>().ok()?, wd.parse::<u8>().ok()?),
                        None => (b.parse::<u8>().ok()?, 5),
                    };
                    if a > 31 || wd == 0 || wd > 5 {
                        return None;
                    }
                    self.idx_bits.push(a | (wd << 5));
                    np31 += 1;
                }
                Some(Op::Tab { table, idx_off, nbits, np31 })
            }
            _ => None,
        }
    }

    /// Compile a spec. `handlers` maps handler names (H records) to functions.
    pub(crate) fn compile(text: &'static str, handlers: &[(&str, Handler)]) -> Engine {
        let mut e = Engine {
            text,
            classes: Vec::new(),
            ops: Vec::new(),
            lin: Vec::new(),
            exc: Vec::new(),
            idx_bits: Vec::new(),
            cons: Vec::new(),
            tables: Vec::new(),
            ents: Vec::new(),
            handlers: Vec::new(),
            tree: Vec::new(),
            leaf: Vec::new(),
            fold_cond: false,
            table_names: std::collections::HashMap::new(),
            prog_cache: std::collections::HashMap::new(),
        };
        for line in text.split('\n') {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            e.line(line, handlers);
        }
        e.table_names = Default::default();
        e.prog_cache = Default::default();
        e.build_tree();
        e
    }
}

impl Engine {
    fn line(&mut self, line: &'static str, handlers: &[(&str, Handler)]) {
        let f: Vec<&'static str> = line.split('\t').collect();
        let e = self;
        match f[0] {
            "F" if f.len() >= 2 && f[1] == "cond" => e.fold_cond = true,
            "T" if f.len() >= 4 => {
                let mut v = Vec::new();
                for x in f[3].split('|') {
                    let id = e.entry(x);
                    v.push(id);
                }
                e.table_names.insert(f[1], e.tables.len() as u32);
                e.tables.push(Table::Dense(v));
            }
            "G" if f.len() >= 6 => {
                let args: Vec<&str> = f[4].split(' ').collect();
                let (generator, default) = match f[3] {
                    "const" => (Gen::Const, if args.first() == Some(&"!I") { E_INVALID } else { E_OTHER }),
                    "sysreg" => (Gen::Sysreg(args.first().and_then(|x| x.parse().ok()).unwrap_or(5)), 0),
                    "bitmask" => {
                        let lsb = args.first().and_then(|x| x.parse().ok()).unwrap_or(10);
                        let size = args.get(1).and_then(|x| x.parse().ok()).unwrap_or(64);
                        let style = args.get(2).and_then(|x| style_of(x)).unwrap_or(ST_U64);
                        (Gen::Bitmask { lsb, size, style }, 0)
                    }
                    _ => (Gen::Const, E_INVALID),
                };
                let mut rules = Vec::new();
                if f[5] != "-" {
                    for r in f[5].split('|') {
                        let Some((mv, res)) = r.split_once('=') else { continue };
                        let Some((m, v)) = mv.split_once(':') else { continue };
                        let (Some(m), Some(v)) = (parse_hex(m), parse_hex(v)) else { continue };
                        let id = e.entry(res);
                        rules.push((m, v, id));
                    }
                }
                e.table_names.insert(f[1], e.tables.len() as u32);
                e.tables.push(Table::Gen { generator, rules, default });
            }
            "H" if f.len() >= 4 => {
                let (Some(mask), Some(value)) = (parse_hex(f[1]), parse_hex(f[2])) else { return };
                let Some(h) = handlers.iter().find(|(n, _)| *n == f[3]).map(|x| x.1) else { return };
                e.handlers.push(h);
                e.classes.push(Class {
                    mask,
                    value,
                    handler: (e.handlers.len() - 1) as u32,
                    mnem: SRef::default(),
                    prog_off: 0,
                    prog_len: 0,
                    cons_off: 0,
                    cons_len: 0,
                });
            }
            "C" if f.len() >= 6 => {
                let (Some(mask), Some(value)) = (parse_hex(f[1]), parse_hex(f[2])) else { return };
                let mnem = e.sref(f[3]);
                let (prog_off, prog_len) = match e.prog_cache.get(f[4]) {
                    Some(&p) => p,
                    None => {
                        let off = e.ops.len() as u32;
                        if f[4] != "-" {
                            for (i, part) in f[4].split('%').enumerate() {
                                if i % 2 == 0 {
                                    if !part.is_empty() {
                                        let r = e.sref(part);
                                        e.ops.push(Op::Lit(r));
                                    }
                                } else {
                                    match e.parse_atom(part) {
                                        Some(op) => e.ops.push(op),
                                        None => {
                                            // malformed atom: make the class unusable
                                            e.ops.truncate(off as usize);
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        let p = (off, e.ops.len() as u32 - off);
                        e.prog_cache.insert(f[4], p);
                        p
                    }
                };
                let cons_off = e.cons.len() as u32;
                if f[5] != "-" {
                    for c in f[5].split(' ') {
                        let Some((kind, arg)) = c.split_once(':') else { continue };
                        match kind {
                            "tie" => {
                                for pr in arg.split(',') {
                                    let Some((a, b)) = pr.split_once('=') else { continue };
                                    let (Ok(a), Ok(b)) = (a.parse::<u8>(), b.parse::<u8>()) else { continue };
                                    e.cons.push(Cons { kind: 0, a: a & 31, b: b & 31, w: 1 });
                                }
                            }
                            "neq" | "neq31" => {
                                let xs: Vec<u8> = arg.split(',').filter_map(|x| x.parse().ok()).collect();
                                if xs.len() < 2 {
                                    continue;
                                }
                                let (a, b, wd) = (xs[0], xs[1], xs.get(2).copied().unwrap_or(5));
                                if wd == 0 || wd > 5 || a as u32 + wd as u32 > 32 || b as u32 + wd as u32 > 32 {
                                    continue;
                                }
                                e.cons.push(Cons { kind: if kind == "neq" { 1 } else { 2 }, a, b, w: wd });
                            }
                            _ => {}
                        }
                    }
                }
                let cons_len = e.cons.len() as u32 - cons_off;
                e.classes.push(Class {
                    mask,
                    value,
                    handler: u32::MAX,
                    mnem,
                    prog_off,
                    prog_len,
                    cons_off,
                    cons_len,
                });
            }
            _ => {}
        }
    }
}

// ------------------------------------------------------------------------------------------
// decision tree

/// Tree node encoding in `Engine::tree`:
///   split: [0x8000_0000 | lsb << 8 | width, child_0, ..., child_{2^width - 1}]
///   leaf : [count, offset into `leaf`]
const LEAF_MAX: usize = 3;

impl Engine {
    fn build_tree(&mut self) {
        let all: Vec<u32> = (0..self.classes.len() as u32).collect();
        let mut memo: std::collections::HashMap<Vec<u32>, u32> = std::collections::HashMap::new();
        self.tree.clear();
        self.leaf.clear();
        self.node(&all, 0, 0, &mut memo);
    }

    fn node(&mut self, set: &[u32], known: u32, depth: u32, memo: &mut std::collections::HashMap<Vec<u32>, u32>) -> u32 {
        if let Some(&n) = memo.get(set) {
            return n;
        }
        let split = if set.len() <= LEAF_MAX || depth >= 16 { None } else { self.best_split(set, known) };
        let here = self.tree.len() as u32;
        match split {
            None => {
                self.tree.push(set.len() as u32);
                self.tree.push(self.leaf.len() as u32);
                self.leaf.extend_from_slice(set);
            }
            Some((lsb, width)) => {
                let n = 1usize << width;
                self.tree.push(0x8000_0000 | (lsb << 8) | width);
                let base = self.tree.len();
                self.tree.resize(base + n, 0);
                let wmask = (((1u64 << width) - 1) as u32) << lsb;
                for v in 0..n as u32 {
                    let bits = v << lsb;
                    let sub: Vec<u32> = set
                        .iter()
                        .copied()
                        .filter(|&c| {
                            let k = &self.classes[c as usize];
                            let m = k.mask & wmask;
                            (bits & m) == (k.value & m)
                        })
                        .collect();
                    let child = self.node(&sub, known | wmask, depth + 1, memo);
                    self.tree[base + v as usize] = child;
                }
            }
        }
        memo.insert(set.to_vec(), here);
        here
    }

    /// Choose a bit window (lsb, width <= 6) minimizing the average child size.
    fn best_split(&self, set: &[u32], known: u32) -> Option<(u32, u32)> {
        // per-bit count of classes that fix the bit
        let mut fixed = [0u32; 32];
        for &c in set {
            let m = self.classes[c as usize].mask;
            for (b, f) in fixed.iter_mut().enumerate() {
                *f += (m >> b) & 1;
            }
        }
        let n = set.len() as f64;
        let mut best: Option<(f64, u32, u32)> = None;
        for lsb in 0..32u32 {
            for width in 1..=6u32 {
                if lsb + width > 32 {
                    break;
                }
                let wmask = (((1u64 << width) - 1) as u32) << lsb;
                if known & wmask != 0 {
                    break;
                }
                // quick reject: every bit must be fixed by at least a quarter of the classes
                if (lsb..lsb + width).any(|b| (fixed[b as usize] as f64) < n * 0.25) {
                    break;
                }
                // exact average child size
                let mut total = 0f64;
                for &c in set {
                    let free = (!self.classes[c as usize].mask & wmask).count_ones();
                    total += (1u64 << free) as f64;
                }
                let avg = total / (1u64 << width) as f64;
                let score = avg + 0.02 * (1u64 << width) as f64;
                if avg < n * 0.9 && best.is_none_or(|b| score < b.0) {
                    best = Some((score, lsb, width));
                }
            }
        }
        best.map(|b| (b.1, b.2))
    }
}

// ------------------------------------------------------------------------------------------
// rendering

impl Engine {
    /// Append `mnemonic\top_str` for instruction word `w` at `addr`; false (and nothing
    /// appended) if the word is not a valid instruction.
    #[inline]
    pub(crate) fn render(&self, w: u32, addr: u64, out: &mut String) -> bool {
        match self.render_direct(w, addr, out) {
            Some(ok) => ok,
            None => {
                let c = w >> 28;
                if !self.fold_cond || c >= 14 {
                    return false;
                }
                let start = out.len();
                if self.render_direct((w & 0x0FFF_FFFF) | 0xE000_0000, addr, out) != Some(true) {
                    out.truncate(start);
                    return false;
                }
                let tail = &out[start..];
                let tab = tail.find('\t').unwrap_or(tail.len());
                let pos = tail[..tab].find('.').unwrap_or(tab);
                out.insert_str(start + pos, COND_NAMES[c as usize]);
                true
            }
        }
    }

    /// Like `render` without condition folding: None if no class claims the word.
    #[inline]
    fn render_direct(&self, w: u32, addr: u64, out: &mut String) -> Option<bool> {
        let tree = &self.tree[..];
        let mut n = 0usize;
        loop {
            let Some(&x) = tree.get(n) else { return None };
            if x & 0x8000_0000 == 0 {
                break;
            }
            let lsb = (x >> 8) & 31;
            let width = x & 0xFF;
            let v = (w >> lsb) & ((1u32 << width) - 1);
            n = tree.get(n + 1 + v as usize).copied().unwrap_or(0) as usize;
        }
        let cnt = tree.get(n).copied().unwrap_or(0) as usize;
        let off = tree.get(n + 1).copied().unwrap_or(0) as usize;
        let start = out.len();
        for &ci in self.leaf.get(off..off + cnt).unwrap_or(&[]) {
            let c = &self.classes[ci as usize];
            if w & c.mask != c.value {
                continue;
            }
            match self.render_class(c, w, addr, out) {
                Res::Ok => return Some(true),
                Res::Other => out.truncate(start),
                Res::Invalid => {
                    out.truncate(start);
                    return Some(false);
                }
            }
        }
        None
    }

    /// Index of the class that renders `w` (for debugging), if any.
    pub(crate) fn class_of(&self, w: u32, addr: u64) -> Option<usize> {
        let mut s = String::new();
        for (ci, c) in self.classes.iter().enumerate() {
            if w & c.mask != c.value {
                continue;
            }
            s.clear();
            match self.render_class(c, w, addr, &mut s) {
                Res::Ok => return Some(ci),
                Res::Other => {}
                Res::Invalid => return Some(ci),
            }
        }
        None
    }

    fn render_class(&self, c: &Class, w: u32, addr: u64, out: &mut String) -> Res {
        if c.handler != u32::MAX {
            return match self.handlers.get(c.handler as usize) {
                Some(h) => h(w, addr, out),
                None => Res::Invalid,
            };
        }
        for k in &self.cons[c.cons_off as usize..(c.cons_off + c.cons_len) as usize] {
            match k.kind {
                0 => {
                    if ((w >> k.a) ^ (w >> k.b)) & 1 != 0 {
                        return Res::Other;
                    }
                }
                _ => {
                    let ones = (1u32 << k.w) - 1;
                    let va = (w >> k.a) & ones;
                    let vb = (w >> k.b) & ones;
                    if va == vb && (k.kind == 1 || va != ones) {
                        return Res::Invalid;
                    }
                }
            }
        }
        out.push_str(self.s(c.mnem));
        out.push('\t');
        for op in &self.ops[c.prog_off as usize..(c.prog_off + c.prog_len) as usize] {
            match *op {
                Op::Lit(r) => out.push_str(self.s(r)),
                Op::Reg { cls, sp31, ref field, suffix, exc_off, exc_len } => {
                    let n = field.eval(w, &self.lin).rem_euclid(32) as u32;
                    if exc_len != 0 {
                        for &(k, v) in &self.exc[exc_off as usize..(exc_off + exc_len) as usize] {
                            if k == n as u64 {
                                return if v == E_OTHER { Res::Other } else { Res::Invalid };
                            }
                        }
                    }
                    push_reg(out, cls, sp31, n);
                    out.push_str(self.s(suffix));
                }
                Op::Num { prefix, style, pc, ref field, exc_off, exc_len } => {
                    if exc_len != 0 {
                        let key = self.exc_key(field, w);
                        for &(k, v) in &self.exc[exc_off as usize..(exc_off + exc_len) as usize] {
                            if k == key {
                                return if v == E_OTHER { Res::Other } else { Res::Invalid };
                            }
                        }
                    }
                    let mut v = field.eval(w, &self.lin);
                    match pc {
                        1 => v = v.wrapping_add(addr as i64),
                        2 => v = v.wrapping_add((addr & !0xFFF) as i64),
                        _ => {}
                    }
                    out.push_str(self.s(prefix));
                    push_num(out, v, style);
                }
                Op::Tab { table, idx_off, nbits, np31 } => {
                    let bits = &self.idx_bits[idx_off as usize..idx_off as usize + nbits as usize + np31 as usize];
                    let mut idx = 0u32;
                    for (k, &b) in bits[..nbits as usize].iter().enumerate() {
                        idx |= ((w >> b) & 1) << k;
                    }
                    for (k, &b) in bits[nbits as usize..].iter().enumerate() {
                        let ones = (1u32 << (b >> 5)) - 1;
                        if (w >> (b & 31)) & ones == ones {
                            idx |= 1 << (nbits as usize + k);
                        }
                    }
                    let Some(t) = self.tables.get(table as usize) else { return Res::Invalid };
                    let e = match t {
                        Table::Dense(v) => v.get(idx as usize).copied().unwrap_or(E_INVALID),
                        Table::Gen { generator, rules, default } => {
                            let mut e = None;
                            for &(m, v, r) in rules {
                                if idx & m == v {
                                    e = Some(r);
                                    break;
                                }
                            }
                            match e {
                                Some(r) => r,
                                None => match *generator {
                                    Gen::Const => *default,
                                    Gen::Sysreg(lsb) => {
                                        push_sysreg(out, (w >> lsb) & 0xFFFF);
                                        continue;
                                    }
                                    Gen::Bitmask { lsb, size, style } => {
                                        let imms = (w >> lsb) & 63;
                                        let immr = (w >> (lsb + 6)) & 63;
                                        let nbit = (w >> (lsb + 12)) & 1;
                                        match decode_bitmask(nbit, immr, imms, size as u32) {
                                            Some(v) => {
                                                out.push('#');
                                                push_num(out, v as i64, style);
                                                continue;
                                            }
                                            None => E_INVALID,
                                        }
                                    }
                                },
                            }
                        }
                    };
                    match e {
                        E_OTHER => return Res::Other,
                        E_INVALID => return Res::Invalid,
                        i => out.push_str(self.ents.get(i as usize).map_or("", |r| self.s(*r))),
                    }
                }
            }
        }
        Res::Ok
    }

    /// Exception key of a number field: its bits concatenated in ascending bit order.
    fn exc_key(&self, f: &Field, w: u32) -> u64 {
        let mut bits: [u8; 64] = [0; 64];
        let mut n = 0usize;
        if f.lin_len != 0 {
            for &(b, _) in &self.lin[f.lin_off as usize..(f.lin_off + f.lin_len) as usize] {
                if n < 64 {
                    bits[n] = b;
                    n += 1;
                }
            }
        } else {
            for i in 0..f.nseg as usize {
                let (lsb, w_) = f.segs[i];
                for b in lsb..lsb.saturating_add(w_) {
                    if n < 64 {
                        bits[n] = b;
                        n += 1;
                    }
                }
            }
        }
        let bits = &mut bits[..n];
        bits.sort_unstable();
        let mut key = 0u64;
        for (k, &b) in bits.iter().enumerate() {
            key |= (((w >> (b & 31)) & 1) as u64) << k;
        }
        key
    }
}

const COND_NAMES: [&str; 14] = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le"];

const ARM_GPR: [&str; 16] =
    ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "sb", "sl", "fp", "ip", "sp", "lr", "pc"];

#[inline]
fn push_reg(out: &mut String, cls: u8, sp31: u8, n: u32) {
    if cls == b'r' {
        return out.push_str(ARM_GPR[(n & 15) as usize]);
    }
    if n == 31 && (cls == b'x' || cls == b'w') {
        match (cls, sp31) {
            (b'x', b'z') => return out.push_str("xzr"),
            (b'x', b's') => return out.push_str("sp"),
            (b'w', b'z') => return out.push_str("wzr"),
            (b'w', b's') => return out.push_str("wsp"),
            _ => {}
        }
    }
    out.push(cls as char);
    push_dec(out, n as u64);
}

fn push_sysreg(out: &mut String, e: u32) {
    out.push('s');
    push_dec(out, (e >> 14) as u64);
    out.push('_');
    push_dec(out, ((e >> 11) & 7) as u64);
    out.push_str("_c");
    push_dec(out, ((e >> 7) & 15) as u64);
    out.push_str("_c");
    push_dec(out, ((e >> 3) & 15) as u64);
    out.push('_');
    push_dec(out, (e & 7) as u64);
}
