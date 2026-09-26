//! High-level IR: flags resolved, literals folded to byte sets, possessive repeats
//! expressed with atomic groups. Shared by the python-`re` front end and the YARA
//! regex / hex-string front ends.

use super::parse::{self, At, Cat, Node, Parsed, RepKind, SetItem, MAXREPEAT, MAXWIDTH};
use super::unicode_class::CpSet;
use super::{Error, FLAG_ASCII, FLAG_DOTALL, FLAG_IGNORECASE, FLAG_LOCALE, FLAG_MULTILINE, FLAG_UNICODE};

/// 256-bit byte set.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ByteSet(pub [u64; 4]);

impl std::fmt::Debug for ByteSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        let mut i = 0usize;
        while i < 256 {
            if self.contains(i as u8) {
                let mut j = i;
                while j + 1 < 256 && self.contains((j + 1) as u8) {
                    j += 1;
                }
                if j == i {
                    write!(f, "{:02x}", i)?;
                } else {
                    write!(f, "{:02x}-{:02x}", i, j)?;
                }
                i = j + 1;
                write!(f, " ")?;
            } else {
                i += 1;
            }
        }
        write!(f, "]")
    }
}

impl ByteSet {
    pub const EMPTY: ByteSet = ByteSet([0; 4]);
    pub const FULL: ByteSet = ByteSet([u64::MAX; 4]);

    #[inline]
    pub fn contains(&self, b: u8) -> bool {
        self.0[(b >> 6) as usize] >> (b & 63) & 1 != 0
    }
    #[inline]
    pub fn insert(&mut self, b: u8) {
        self.0[(b >> 6) as usize] |= 1u64 << (b & 63);
    }
    pub fn insert_range(&mut self, lo: u8, hi: u8) {
        for b in lo..=hi {
            self.insert(b);
        }
    }
    pub fn single(b: u8) -> ByteSet {
        let mut s = ByteSet::EMPTY;
        s.insert(b);
        s
    }
    pub fn union(&mut self, o: &ByteSet) {
        for i in 0..4 {
            self.0[i] |= o.0[i];
        }
    }
    pub fn intersect(&self, o: &ByteSet) -> ByteSet {
        ByteSet([self.0[0] & o.0[0], self.0[1] & o.0[1], self.0[2] & o.0[2], self.0[3] & o.0[3]])
    }
    pub fn negate(&self) -> ByteSet {
        ByteSet([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }
    pub fn len(&self) -> usize {
        self.0.iter().map(|w| w.count_ones() as usize).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.0 == [0; 4]
    }
    pub fn is_full(&self) -> bool {
        self.0 == [u64::MAX; 4]
    }
    /// Single member, if the set has exactly one byte.
    pub fn as_single(&self) -> Option<u8> {
        if self.len() == 1 { self.iter().next() } else { None }
    }
    /// Members in increasing order (bit iteration: O(members), not O(256)).
    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        ByteSetIter { words: self.0, w: 0 }
    }
    /// Boundaries of the maximal byte ranges of the set: bit `b` is set when membership
    /// changes between `b - 1` and `b` (byte -1 counts as a non-member).
    pub fn edges(&self) -> ByteSet {
        let w = self.0;
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            out[i] = w[i] ^ ((w[i] << 1) | carry);
            carry = w[i] >> 63;
        }
        ByteSet(out)
    }
    pub fn to_bools(&self) -> [bool; 256] {
        let mut out = [false; 256];
        for b in 0..256usize {
            out[b] = self.contains(b as u8);
        }
        out
    }
    /// Add the other ASCII case of every letter in the set.
    pub fn case_fold_ascii(&mut self) {
        let copy = *self;
        for b in copy.iter() {
            if b.is_ascii_alphabetic() {
                self.insert(b ^ 0x20);
            }
        }
    }
}

struct ByteSetIter {
    words: [u64; 4],
    w: usize,
}

impl Iterator for ByteSetIter {
    type Item = u8;
    #[inline]
    fn next(&mut self) -> Option<u8> {
        while self.w < 4 {
            let x = self.words[self.w];
            if x != 0 {
                self.words[self.w] = x & (x - 1);
                return Some((self.w * 64 + x.trailing_zeros() as usize) as u8);
            }
            self.w += 1;
        }
        None
    }
}

pub fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

pub fn is_space_byte(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

pub fn cat_set(c: Cat) -> ByteSet {
    let mut s = ByteSet::EMPTY;
    for b in 0..=255u8 {
        let m = match c {
            Cat::Digit | Cat::NotDigit => b.is_ascii_digit(),
            Cat::Space | Cat::NotSpace => is_space_byte(b),
            Cat::Word | Cat::NotWord => is_word_byte(b),
        };
        let neg = matches!(c, Cat::NotDigit | Cat::NotSpace | Cat::NotWord);
        if m != neg {
            s.insert(b);
        }
    }
    s
}

/// Zero-width assertions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Look {
    /// Absolute start of haystack (`\A`, non-multiline `^`).
    Start,
    /// Multiline `^`: start or after `\n`.
    StartLine,
    /// Non-multiline python `$`: end, or before a final `\n`.
    EndOrFinalNl,
    /// Multiline `$`: end or before `\n`.
    EndLine,
    /// Absolute end (`\Z`).
    End,
    /// `\b` over ASCII word bytes.
    WordB,
    /// `\B` over ASCII word bytes.
    NotWordB,
    /// `\b` / `\B` of str patterns (Unicode word characters, UTF-8 decoded).
    WordBUni,
    NotWordBUni,
}

#[derive(Clone, Debug)]
pub enum Hir {
    Empty,
    Class(ByteSet),
    /// One UTF-8 encoded character whose codepoint is in the (sorted) ranges
    /// (python str patterns).
    UClass(Box<Vec<(u32, u32)>>),
    Look(Look),
    Concat(Vec<Hir>),
    Alt(Vec<Hir>),
    Repeat { min: u32, max: Option<u32>, greedy: bool, sub: Box<Hir> },
    Capture { index: u32, sub: Box<Hir> },
    Backref { group: u32, icase: bool, unicode: bool },
    LookAround { behind: bool, negate: bool, width: u32, sub: Box<Hir> },
    Atomic(Box<Hir>),
    Cond { group: u32, yes: Box<Hir>, no: Box<Hir> },
    Fail,
}

impl Hir {
    /// Minimum width (python `getwidth()[0]` semantics), saturated.
    pub fn min_width(&self, gw: &[(u128, u128)]) -> u128 {
        match self {
            Hir::Empty | Hir::Look(_) | Hir::LookAround { .. } | Hir::Fail => 0,
            Hir::Class(_) | Hir::UClass(_) => 1,
            Hir::Concat(v) => v.iter().fold(0u128, |a, h| a.saturating_add(h.min_width(gw))).min(MAXWIDTH),
            Hir::Alt(v) => v.iter().map(|h| h.min_width(gw)).min().unwrap_or(0),
            Hir::Repeat { min, sub, .. } => sub.min_width(gw).saturating_mul(*min as u128).min(MAXWIDTH),
            Hir::Capture { sub, .. } | Hir::Atomic(sub) => sub.min_width(gw),
            Hir::Backref { group, .. } => gw.get(*group as usize).map(|w| w.0).unwrap_or(0),
            Hir::Cond { yes, no, .. } => yes.min_width(gw).min(no.min_width(gw)),
        }
    }

    /// Maximum width, None = unbounded.
    pub fn max_width(&self) -> Option<u64> {
        match self {
            Hir::Empty | Hir::Look(_) | Hir::LookAround { .. } | Hir::Fail => Some(0),
            Hir::Class(_) => Some(1),
            Hir::UClass(_) => Some(4),
            Hir::Concat(v) => {
                let mut t: u64 = 0;
                for h in v {
                    t = t.checked_add(h.max_width()?)?;
                }
                Some(t)
            }
            Hir::Alt(v) => {
                let mut t: u64 = 0;
                for h in v {
                    t = t.max(h.max_width()?);
                }
                Some(t)
            }
            Hir::Repeat { max, sub, .. } => {
                let w = sub.max_width()?;
                if w == 0 {
                    return Some(0);
                }
                w.checked_mul((*max)? as u64)
            }
            Hir::Capture { sub, .. } | Hir::Atomic(sub) => sub.max_width(),
            Hir::Backref { .. } => None,
            Hir::Cond { yes, no, .. } => Some(yes.max_width()?.max(no.max_width()?)),
        }
    }
}

/// Properties relevant to engine selection.
#[derive(Clone, Copy, Debug, Default)]
pub struct Props {
    pub has_backref: bool,
    pub has_lookaround: bool,
    pub has_atomic: bool,
    pub has_cond: bool,
    /// A repeat with optional iterations whose body can match empty (sre zero-width
    /// protection semantics differ from automata semantics).
    pub has_nullable_loop: bool,
    pub has_look: bool,
    /// Estimated NFA size after unrolling counted repeats.
    pub nfa_size: u64,
}

impl Props {
    pub fn is_regular(&self) -> bool {
        !(self.has_backref || self.has_lookaround || self.has_atomic || self.has_cond || self.has_nullable_loop)
    }
}

pub fn props(h: &Hir, gw: &[(u128, u128)]) -> Props {
    let mut p = Props::default();
    p.nfa_size = walk_props(h, gw, &mut p);
    p
}

fn walk_props(h: &Hir, gw: &[(u128, u128)], p: &mut Props) -> u64 {
    match h {
        Hir::Empty | Hir::Fail => 1,
        Hir::Class(_) | Hir::UClass(_) => 1,
        Hir::Look(_) => {
            p.has_look = true;
            1
        }
        Hir::Concat(v) => v.iter().fold(0u64, |a, x| a.saturating_add(walk_props(x, gw, p))),
        Hir::Alt(v) => v.iter().fold(v.len() as u64, |a, x| a.saturating_add(walk_props(x, gw, p))),
        Hir::Repeat { min, max, sub, .. } => {
            let s = walk_props(sub, gw, p);
            if max.map_or(true, |m| m > *min) && sub.min_width(gw) == 0 {
                p.has_nullable_loop = true;
            }
            let copies = match max {
                Some(m) => (*m as u64).max(1),
                None => (*min as u64).max(1),
            };
            s.saturating_add(1).saturating_mul(copies)
        }
        Hir::Capture { sub, .. } => walk_props(sub, gw, p).saturating_add(2),
        Hir::Backref { .. } => {
            p.has_backref = true;
            1
        }
        Hir::LookAround { sub, .. } => {
            p.has_lookaround = true;
            walk_props(sub, gw, p).saturating_add(2)
        }
        Hir::Atomic(sub) => {
            p.has_atomic = true;
            walk_props(sub, gw, p).saturating_add(2)
        }
        Hir::Cond { yes, no, .. } => {
            p.has_cond = true;
            walk_props(yes, gw, p).saturating_add(walk_props(no, gw, p)).saturating_add(2)
        }
    }
}

// ---------------------------------------------------------------------------------------
// Lowering from the python AST
// ---------------------------------------------------------------------------------------

pub struct Lowered {
    pub hir: Hir,
    pub groups: u32,
    pub names: Vec<(String, u32)>,
    pub group_widths: Vec<(u128, u128)>,
}

pub fn lower(parsed: Parsed) -> Result<Lowered, Error> {
    lower_mode(parsed, false)
}

/// Lower a parsed python str pattern (codepoint classes, Unicode categories / case
/// folding unless `re.ASCII`).
pub fn lower_str(parsed: Parsed) -> Result<Lowered, Error> {
    lower_mode(parsed, true)
}

fn lower_mode(parsed: Parsed, text: bool) -> Result<Lowered, Error> {
    let gw = parsed.group_widths.clone();
    let flags = if text { parsed.flags | FLAG_TEXT } else { parsed.flags };
    let hir = lower_seq(&parsed.nodes, flags, &gw, 0)?;
    Ok(Lowered { hir, groups: parsed.groups, names: parsed.names, group_widths: gw })
}

fn combine_flags(flags: u32, add: u32, del: u32) -> u32 {
    let type_flags = FLAG_ASCII | FLAG_LOCALE | FLAG_UNICODE;
    let mut f = flags;
    if add & type_flags != 0 {
        f &= !type_flags;
    }
    (f | add) & !del
}

/// Internal flag: lowering a str pattern.
const FLAG_TEXT: u32 = 1 << 30;

fn cat_cpset(c: Cat, unicode: bool) -> CpSet {
    use super::unicode as u;
    let (base, neg) = match c {
        Cat::Digit => (u::DIGIT, false),
        Cat::NotDigit => (u::DIGIT, true),
        Cat::Space => (u::SPACE, false),
        Cat::NotSpace => (u::SPACE, true),
        Cat::Word => (u::WORD, false),
        Cat::NotWord => (u::WORD, true),
    };
    let set = if unicode {
        CpSet::from_table(base)
    } else {
        let bs = cat_set(match c {
            Cat::Digit | Cat::NotDigit => Cat::Digit,
            Cat::Space | Cat::NotSpace => Cat::Space,
            Cat::Word | Cat::NotWord => Cat::Word,
        });
        let mut s = CpSet::default();
        for b in 0..128u8 {
            if bs.contains(b) {
                s.add(b as u32);
            }
        }
        s.normalize();
        s
    };
    if neg { set.negate() } else { set }
}

fn fold_cp(s: &CpSet, flags: u32) -> CpSet {
    if flags & FLAG_IGNORECASE == 0 {
        let mut s = s.clone();
        s.normalize();
        return s;
    }
    if flags & FLAG_UNICODE != 0 { s.fold_unicode() } else { s.fold_ascii() }
}

fn uclass(s: CpSet) -> Hir {
    let mut s = s;
    s.normalize();
    if s.ranges.is_empty() { Hir::Fail } else { Hir::UClass(Box::new(s.ranges)) }
}

/// Text-mode lowering of single-character nodes.
fn lower_text_char(n: &Node, flags: u32) -> Option<Hir> {
    let unicode = flags & FLAG_UNICODE != 0;
    Some(match n {
        Node::Lit(c) => uclass(fold_cp(&CpSet::single(*c), flags)),
        Node::NotLit(c) => uclass(fold_cp(&CpSet::single(*c), flags).negate()),
        Node::Any => {
            if flags & FLAG_DOTALL != 0 {
                uclass(CpSet { ranges: vec![(0, super::unicode_class::MAX_CP)] })
            } else {
                uclass(CpSet::single(0x0a).negate())
            }
        }
        Node::In { negate, items } => {
            let mut lits = CpSet::default();
            let mut cats = CpSet::default();
            for it in items {
                match *it {
                    SetItem::Lit(c) => lits.add(c),
                    SetItem::Range(a, b) => lits.add_range(a, b),
                    SetItem::Cat(c) => cats.union(&cat_cpset(c, unicode)),
                }
            }
            let mut all = fold_cp(&lits, flags);
            all.union(&cats);
            all.normalize();
            uclass(if *negate { all.negate() } else { all })
        }
        _ => return None,
    })
}

fn lit_set(c: u32, flags: u32) -> ByteSet {
    let c = c.min(255) as u8;
    let mut s = ByteSet::single(c);
    if flags & FLAG_IGNORECASE != 0 {
        s.case_fold_ascii();
    }
    s
}

fn lower_seq(nodes: &[Node], flags: u32, gw: &[(u128, u128)], depth: usize) -> Result<Hir, Error> {
    let mut out = Vec::with_capacity(nodes.len());
    for n in nodes {
        out.push(lower_node(n, flags, gw, depth + 1)?);
    }
    Ok(match out.len() {
        0 => Hir::Empty,
        1 => out.pop().unwrap_or(Hir::Empty),
        _ => Hir::Concat(out),
    })
}

fn lower_node(n: &Node, flags: u32, gw: &[(u128, u128)], depth: usize) -> Result<Hir, Error> {
    if depth > 2000 {
        return Err(Error::new("pattern too deeply nested", 0));
    }
    if flags & FLAG_TEXT != 0 {
        if let Some(h) = lower_text_char(n, flags) {
            return Ok(h);
        }
    }
    Ok(match n {
        Node::Lit(c) => Hir::Class(lit_set(*c, flags)),
        Node::NotLit(c) => Hir::Class(lit_set(*c, flags).negate()),
        Node::Any => {
            if flags & FLAG_DOTALL != 0 {
                Hir::Class(ByteSet::FULL)
            } else {
                Hir::Class(ByteSet::single(b'\n').negate())
            }
        }
        Node::In { negate, items } => {
            let mut lits = ByteSet::EMPTY;
            let mut cats = ByteSet::EMPTY;
            for it in items {
                match *it {
                    SetItem::Lit(c) => lits.insert(c.min(255) as u8),
                    SetItem::Range(a, b) => lits.insert_range(a.min(255) as u8, b.min(255) as u8),
                    SetItem::Cat(c) => cats.union(&cat_set(c)),
                }
            }
            if flags & FLAG_IGNORECASE != 0 {
                lits.case_fold_ascii();
            }
            lits.union(&cats);
            Hir::Class(if *negate { lits.negate() } else { lits })
        }
        Node::At(a) => Hir::Look(match a {
            At::Beginning => {
                if flags & FLAG_MULTILINE != 0 {
                    Look::StartLine
                } else {
                    Look::Start
                }
            }
            At::BeginningString => Look::Start,
            At::End => {
                if flags & FLAG_MULTILINE != 0 {
                    Look::EndLine
                } else {
                    Look::EndOrFinalNl
                }
            }
            At::EndString => Look::End,
            At::Boundary => {
                if flags & FLAG_TEXT != 0 && flags & FLAG_UNICODE != 0 {
                    Look::WordBUni
                } else {
                    Look::WordB
                }
            }
            At::NonBoundary => {
                if flags & FLAG_TEXT != 0 && flags & FLAG_UNICODE != 0 {
                    Look::NotWordBUni
                } else {
                    Look::NotWordB
                }
            }
        }),
        Node::Branch(items) => {
            let mut v = Vec::with_capacity(items.len());
            for it in items {
                v.push(lower_seq(it, flags, gw, depth + 1)?);
            }
            Hir::Alt(v)
        }
        Node::Repeat { min, max, kind, item } => {
            let sub = lower_seq(item, flags, gw, depth + 1)?;
            let min = (*min).min(u32::MAX as u64) as u32;
            let max = if *max == MAXREPEAT { None } else { Some((*max).min(u32::MAX as u64) as u32) };
            match kind {
                RepKind::Greedy => Hir::Repeat { min, max, greedy: true, sub: Box::new(sub) },
                RepKind::Lazy => Hir::Repeat { min, max, greedy: false, sub: Box::new(sub) },
                RepKind::Possessive => {
                    let simple = matches!(sub, Hir::Class(_));
                    let inner = if simple { sub } else { Hir::Atomic(Box::new(sub)) };
                    Hir::Atomic(Box::new(Hir::Repeat { min, max, greedy: true, sub: Box::new(inner) }))
                }
            }
        }
        Node::Sub { group, add, del, p } => {
            let f = combine_flags(flags, *add, *del);
            let sub = lower_seq(p, f, gw, depth + 1)?;
            match group {
                Some(g) => Hir::Capture { index: *g, sub: Box::new(sub) },
                None => sub,
            }
        }
        Node::Atomic(p) => Hir::Atomic(Box::new(lower_seq(p, flags, gw, depth + 1)?)),
        Node::Assert { behind, negate, p } => {
            let mut width = 0u32;
            if *behind {
                let groups: Vec<Option<(u128, u128)>> = gw.iter().map(|w| Some(*w)).collect();
                let (lo, hi) = parse::width(p, &groups);
                if lo > u32::MAX as u128 {
                    return Err(Error::new("looks too much behind", 0));
                }
                if lo != hi {
                    return Err(Error::new("look-behind requires fixed-width pattern", 0));
                }
                width = lo as u32;
            }
            Hir::LookAround {
                behind: *behind,
                negate: *negate,
                width,
                sub: Box::new(lower_seq(p, flags, gw, depth + 1)?),
            }
        }
        Node::Failure => Hir::Fail,
        Node::GroupRef(g) => Hir::Backref {
            group: *g,
            icase: flags & FLAG_IGNORECASE != 0,
            unicode: flags & FLAG_TEXT != 0 && flags & FLAG_UNICODE != 0,
        },
        Node::GroupRefExists { group, yes, no } => Hir::Cond {
            group: *group,
            yes: Box::new(lower_seq(yes, flags, gw, depth + 1)?),
            no: Box::new(match no {
                Some(no) => lower_seq(no, flags, gw, depth + 1)?,
                None => Hir::Empty,
            }),
        },
    })
}
