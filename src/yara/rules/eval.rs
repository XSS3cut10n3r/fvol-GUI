//! Condition virtual machine: a compact re-implementation of libyara 4.5
//! `yr_execute_code` (exec.c) for the opcodes a module-less rule set can use.
//!
//! Values are 64-bit words exactly like libyara's `YR_VALUE` union: integers,
//! doubles (bit pattern), string / regexp references (pool indices), with the
//! YR_UNDEFINED marker (`0xFFFABADAFABADAFF`) meaning "undefined" for every
//! type. Keeping the marker (instead of an `Option`) reproduces libyara's
//! corner cases bit for bit (e.g. an arithmetic result that happens to equal the
//! marker is undefined; `for` bodies add their raw value to the true-count).
//!
//! Code is a flat `Vec<Op>` per rule set; jumps are absolute indices. The only
//! state besides the value stack are the loop memory slots and an iterator
//! stack; everything lives in a reusable [`Scratch`] so evaluation does not
//! allocate after warm-up.

use super::regex::CondRegex;
use crate::yara::scan::Match;

/// YR_UNDEFINED.
pub const UNDEF: i64 = 0xFFFA_BADA_FABA_DAFFu64 as i64;

/// Tags of string / regexp references on the VM stack (libyara pushes
/// pointers; any large non-zero value that cannot collide with small integers
/// behaves the same).
pub const STR_BASE: i64 = 0x7E00_0000_0000_0000;
pub const RE_BASE: i64 = 0x7D00_0000_0000_0000;

/// Loop memory slots (YR_MAX_LOOP_NESTING * (YR_MAX_LOOP_VARS + YR_INTERNAL_LOOP_VARS)).
pub const MEM_SIZE: usize = 4 * (2 + 3);

#[inline]
pub fn is_undef(v: i64) -> bool {
    v == UNDEF
}

/// Which string an instruction refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SRef {
    /// Global string index.
    Fixed(u32),
    /// Loop memory slot holding a global string index (anonymous `$` in for-of).
    Var(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntRead {
    I8,
    I16,
    I32,
    U8,
    U16,
    U32,
    I8Be,
    I16Be,
    I32Be,
    U8Be,
    U16Be,
    U32Be,
}

impl IntRead {
    pub fn from_index(i: u8) -> IntRead {
        match i {
            0 => IntRead::I8,
            1 => IntRead::I16,
            2 => IntRead::I32,
            3 => IntRead::U8,
            4 => IntRead::U16,
            5 => IntRead::U32,
            6 => IntRead::I8Be,
            7 => IntRead::I16Be,
            8 => IntRead::I32Be,
            9 => IntRead::U8Be,
            10 => IntRead::U16Be,
            _ => IntRead::U32Be,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Op {
    /// Push a word (integer, double bits, string / regexp pool index, UNDEF).
    Push(i64),
    Pop,
    ClearM(u8),
    AddM(u8),
    IncrM(u8),
    PushM(u8),
    PopM(u8),
    /// Jump (absolute) if top is defined and false / true; the value stays.
    JFalse(u32),
    JTrue(u32),
    /// Pop; jump if defined and true.
    JTrueP(u32),
    And,
    Or,
    Not,
    Defined,
    Mod,
    Shl,
    Shr,
    BitNot,
    BitAnd,
    BitOr,
    BitXor,
    IntEq,
    IntNeq,
    IntLt,
    IntGt,
    IntLe,
    IntGe,
    IntAdd,
    IntSub,
    IntMul,
    IntDiv,
    IntMinus,
    /// Convert the integer at stack depth n (1 = top) to a double.
    IntToDbl(u8),
    DblEq,
    DblNeq,
    DblLt,
    DblGt,
    DblLe,
    DblGe,
    DblAdd,
    DblSub,
    DblMul,
    DblDiv,
    DblMinus,
    StrEq,
    StrNeq,
    StrLt,
    StrGt,
    StrLe,
    StrGe,
    Contains,
    IContains,
    StartsWith,
    IStartsWith,
    EndsWith,
    IEndsWith,
    IEquals,
    /// Pops the regexp (top) and the string.
    Matches,
    StrToBool,
    Filesize,
    Entrypoint,
    ReadInt(IntRead),
    Found(SRef),
    /// Pops the offset.
    FoundAt(SRef),
    /// Pops lower, upper bound.
    FoundIn(SRef),
    Count(SRef),
    CountIn(SRef),
    /// Pops the (1-based) index.
    Offset(SRef),
    Length(SRef),
    PushRule(u32),
    /// Pops quantifier; `set` indexes [`Program::sets`].
    OfStrings(u32),
    OfRules(u32),
    OfPercentStrings(u32),
    OfPercentRules(u32),
    /// Pops quantifier, lower, upper.
    OfFoundIn(u32),
    /// Pops quantifier, offset.
    OfFoundAt(u32),
    /// Pops lower, upper.
    IterStartIntRange,
    /// Pops n items.
    IterStartIntEnum(u32),
    /// Iterates the strings of a set.
    IterStartStringSet(u32),
    /// Pops n text-string references.
    IterStartTextStringSet(u32),
    IterNext,
    IterCondition,
    IterEnd,
    /// Discard the innermost iterator.
    IterPop,
}

/// Compiled rule-set code and constant pools.
#[derive(Default)]
pub struct Program {
    pub code: Vec<Op>,
    pub str_pool: Vec<Vec<u8>>,
    pub regex_pool: Vec<CondRegex>,
    /// String / rule sets: ranges into `set_items`.
    pub sets: Vec<(u32, u32)>,
    pub set_items: Vec<u32>,
}

impl Program {
    #[inline]
    fn set(&self, s: u32) -> &[u32] {
        match self.sets.get(s as usize) {
            Some(&(a, b)) => self.set_items.get(a as usize..b as usize).unwrap_or(&[]),
            None => &[],
        }
    }
}

enum Iter {
    IntRange { next: i64, last: i64 },
    /// Items live in `Scratch::iter_items[start..start+count]`.
    Items { start: usize, count: usize, idx: usize },
    StringSet { set: u32, idx: usize },
}

/// Reusable evaluation buffers.
#[derive(Default)]
pub struct Scratch {
    stack: Vec<i64>,
    iters: Vec<Iter>,
    iter_items: Vec<i64>,
}

/// Everything the VM reads while evaluating.
pub struct Ctx<'a> {
    pub data: &'a [u8],
    pub matches: &'a [Vec<Match>],
    /// Rule match bits (index = rule index).
    pub rule_matched: &'a [bool],
    /// Lazily computed entry point (None = not computed yet).
    pub entry_point: &'a mut Option<i64>,
}

#[inline]
fn b(v: bool) -> i64 {
    v as i64
}

#[inline]
fn f(v: i64) -> f64 {
    f64::from_bits(v as u64)
}

#[inline]
fn fw(v: f64) -> i64 {
    v.to_bits() as i64
}

fn read_int(data: &[u8], off: i64, k: IntRead) -> i64 {
    // libyara casts the offset to size_t; negative offsets are huge.
    let off = off as u64;
    let size: u64 = match k {
        IntRead::I8 | IntRead::U8 | IntRead::I8Be | IntRead::U8Be => 1,
        IntRead::I16 | IntRead::U16 | IntRead::I16Be | IntRead::U16Be => 2,
        _ => 4,
    };
    let len = data.len() as u64;
    if len < size || off > len - size {
        return UNDEF;
    }
    let o = off as usize;
    let d = &data[o..o + size as usize];
    match k {
        IntRead::I8 | IntRead::I8Be => d[0] as i8 as i64,
        IntRead::U8 | IntRead::U8Be => d[0] as i64,
        IntRead::I16 => i16::from_le_bytes([d[0], d[1]]) as i64,
        IntRead::U16 => u16::from_le_bytes([d[0], d[1]]) as i64,
        IntRead::I32 => i32::from_le_bytes([d[0], d[1], d[2], d[3]]) as i64,
        IntRead::U32 => u32::from_le_bytes([d[0], d[1], d[2], d[3]]) as i64,
        IntRead::I16Be => i16::from_be_bytes([d[0], d[1]]) as i64,
        IntRead::U16Be => u16::from_be_bytes([d[0], d[1]]) as i64,
        IntRead::I32Be => i32::from_be_bytes([d[0], d[1], d[2], d[3]]) as i64,
        IntRead::U32Be => u32::from_be_bytes([d[0], d[1], d[2], d[3]]) as i64,
    }
}

/// ss_compare: common prefix, then the shorter string is smaller, else the first
/// differing byte compared as a (signed) C `char`.
fn ss_compare(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    for (x, y) in a.iter().zip(b) {
        if x != y {
            return (*x as i8).cmp(&(*y as i8));
        }
    }
    a.len().cmp(&b.len())
}

/// ss_icompare == 0 (ASCII case-insensitive equality).
fn ss_iequals(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.eq_ignore_ascii_case(b)
}

fn contains(hay: &[u8], needle: &[u8], nocase: bool) -> bool {
    if needle.len() > hay.len() {
        return false;
    }
    if needle.is_empty() {
        return true;
    }
    hay.windows(needle.len()).any(|w| if nocase { w.eq_ignore_ascii_case(needle) } else { w == needle })
}

impl Program {
    #[inline]
    fn text(&self, v: i64) -> &[u8] {
        self.str_pool.get(v.wrapping_sub(STR_BASE) as u64 as usize).map(|s| s.as_slice()).unwrap_or(&[])
    }

    /// Run `code[start..end]`; returns the rule's final value (top of stack).
    pub fn run(&self, start: usize, end: usize, ctx: &mut Ctx<'_>, sc: &mut Scratch, mem: &mut [i64; MEM_SIZE]) -> i64 {
        sc.stack.clear();
        sc.iters.clear();
        sc.iter_items.clear();
        let st = &mut sc.stack;
        macro_rules! pop {
            () => {
                st.pop().unwrap_or(UNDEF)
            };
        }
        macro_rules! m {
            ($slot:expr) => {
                mem[($slot as usize) % MEM_SIZE]
            };
        }
        // Resolve a string reference to its match list.
        let matches_of = |r: SRef, mem: &[i64; MEM_SIZE]| -> &[Match] {
            let sid = match r {
                SRef::Fixed(s) => s as i64,
                SRef::Var(slot) => mem[slot as usize % MEM_SIZE],
            };
            if sid < 0 {
                return &[];
            }
            ctx.matches.get(sid as usize).map(|v| v.as_slice()).unwrap_or(&[])
        };
        let mut ip = start;
        let end = end.min(self.code.len());
        while ip < end {
            let op = self.code[ip];
            ip += 1;
            match op {
                Op::Push(v) => st.push(v),
                Op::Pop => {
                    pop!();
                }
                Op::ClearM(s) => m!(s) = 0,
                Op::AddM(s) => {
                    let v = pop!();
                    if !is_undef(v) {
                        m!(s) = m!(s).wrapping_add(v);
                    }
                }
                Op::IncrM(s) => m!(s) = m!(s).wrapping_add(1),
                Op::PushM(s) => st.push(m!(s)),
                Op::PopM(s) => {
                    let v = pop!();
                    m!(s) = v;
                }
                Op::JFalse(t) => {
                    let v = st.last().copied().unwrap_or(UNDEF);
                    if !is_undef(v) && v == 0 {
                        ip = t as usize;
                    }
                }
                Op::JTrue(t) => {
                    let v = st.last().copied().unwrap_or(UNDEF);
                    if !is_undef(v) && v != 0 {
                        ip = t as usize;
                    }
                }
                Op::JTrueP(t) => {
                    let v = pop!();
                    if !is_undef(v) && v != 0 {
                        ip = t as usize;
                    }
                }
                Op::And | Op::Or => {
                    let mut r2 = pop!();
                    let mut r1 = pop!();
                    if is_undef(r1) {
                        r1 = 0;
                    }
                    if is_undef(r2) {
                        r2 = 0;
                    }
                    st.push(if op == Op::And { b(r1 != 0 && r2 != 0) } else { b(r1 != 0 || r2 != 0) });
                }
                Op::Not => {
                    let v = pop!();
                    st.push(if is_undef(v) { UNDEF } else { b(v == 0) });
                }
                Op::Defined => {
                    let v = pop!();
                    st.push(b(!is_undef(v)));
                }
                Op::BitNot | Op::IntMinus | Op::DblMinus | Op::StrToBool => {
                    let v = pop!();
                    if is_undef(v) {
                        st.push(UNDEF);
                        continue;
                    }
                    st.push(match op {
                        Op::BitNot => !v,
                        Op::IntMinus => v.wrapping_neg(),
                        Op::DblMinus => fw(-f(v)),
                        _ => b(!self.text(v).is_empty()),
                    });
                }
                Op::Mod
                | Op::Shl
                | Op::Shr
                | Op::BitAnd
                | Op::BitOr
                | Op::BitXor
                | Op::IntEq
                | Op::IntNeq
                | Op::IntLt
                | Op::IntGt
                | Op::IntLe
                | Op::IntGe
                | Op::IntAdd
                | Op::IntSub
                | Op::IntMul
                | Op::IntDiv => {
                    let r2 = pop!();
                    let r1 = pop!();
                    if is_undef(r2) || is_undef(r1) {
                        st.push(UNDEF);
                        continue;
                    }
                    st.push(match op {
                        Op::Mod => {
                            if r2 == 0 || (r1 == i64::MIN && r2 == -1) {
                                UNDEF
                            } else {
                                r1 % r2
                            }
                        }
                        Op::IntDiv => {
                            if r2 == 0 || (r1 == i64::MIN && r2 == -1) {
                                UNDEF
                            } else {
                                r1 / r2
                            }
                        }
                        Op::Shl => {
                            if r2 < 0 {
                                UNDEF
                            } else if r2 < 64 {
                                r1.wrapping_shl(r2 as u32)
                            } else {
                                0
                            }
                        }
                        Op::Shr => {
                            if r2 < 0 {
                                UNDEF
                            } else if r2 < 64 {
                                r1 >> r2
                            } else {
                                0
                            }
                        }
                        Op::BitAnd => r1 & r2,
                        Op::BitOr => r1 | r2,
                        Op::BitXor => r1 ^ r2,
                        Op::IntEq => b(r1 == r2),
                        Op::IntNeq => b(r1 != r2),
                        Op::IntLt => b(r1 < r2),
                        Op::IntGt => b(r1 > r2),
                        Op::IntLe => b(r1 <= r2),
                        Op::IntGe => b(r1 >= r2),
                        Op::IntAdd => r1.wrapping_add(r2),
                        Op::IntSub => r1.wrapping_sub(r2),
                        _ => r1.wrapping_mul(r2),
                    });
                }
                Op::IntToDbl(n) => {
                    let n = n as usize;
                    if n >= 1 && n <= st.len() {
                        let i = st.len() - n;
                        let v = st[i];
                        st[i] = if is_undef(v) { UNDEF } else { fw(v as f64) };
                    }
                }
                Op::DblLt => {
                    // OP_DBL_LT: undefined operands give false (not undefined).
                    let r2 = pop!();
                    let r1 = pop!();
                    st.push(if is_undef(r1) || is_undef(r2) { 0 } else { b(f(r1) < f(r2)) });
                }
                Op::DblGt
                | Op::DblLe
                | Op::DblGe
                | Op::DblEq
                | Op::DblNeq
                | Op::DblAdd
                | Op::DblSub
                | Op::DblMul
                | Op::DblDiv => {
                    let r2 = pop!();
                    let r1 = pop!();
                    if is_undef(r2) || is_undef(r1) {
                        st.push(UNDEF);
                        continue;
                    }
                    let (x, y) = (f(r1), f(r2));
                    st.push(match op {
                        Op::DblGt => b(x > y),
                        Op::DblLe => b(x <= y),
                        Op::DblGe => b(x >= y),
                        Op::DblEq => b((x - y).abs() < f64::EPSILON),
                        Op::DblNeq => b((x - y).abs() >= f64::EPSILON),
                        Op::DblAdd => fw(x + y),
                        Op::DblSub => fw(x - y),
                        Op::DblMul => fw(x * y),
                        _ => fw(x / y),
                    });
                }
                Op::StrEq
                | Op::StrNeq
                | Op::StrLt
                | Op::StrGt
                | Op::StrLe
                | Op::StrGe
                | Op::Contains
                | Op::IContains
                | Op::StartsWith
                | Op::IStartsWith
                | Op::EndsWith
                | Op::IEndsWith
                | Op::IEquals => {
                    let r2 = pop!();
                    let r1 = pop!();
                    if is_undef(r2) || is_undef(r1) {
                        st.push(UNDEF);
                        continue;
                    }
                    let (x, y) = (self.text(r1), self.text(r2));
                    let ord = || ss_compare(x, y);
                    st.push(b(match op {
                        Op::StrEq => ord().is_eq(),
                        Op::StrNeq => ord().is_ne(),
                        Op::StrLt => ord().is_lt(),
                        Op::StrGt => ord().is_gt(),
                        Op::StrLe => ord().is_le(),
                        Op::StrGe => ord().is_ge(),
                        Op::Contains => contains(x, y, false),
                        Op::IContains => contains(x, y, true),
                        Op::StartsWith => x.starts_with(y),
                        Op::IStartsWith => x.len() >= y.len() && x[..y.len()].eq_ignore_ascii_case(y),
                        Op::EndsWith => x.ends_with(y),
                        Op::IEndsWith => x.len() >= y.len() && x[x.len() - y.len()..].eq_ignore_ascii_case(y),
                        _ => ss_iequals(x, y),
                    }));
                }
                Op::Matches => {
                    let r2 = pop!();
                    let r1 = pop!();
                    if is_undef(r2) || is_undef(r1) {
                        st.push(UNDEF);
                        continue;
                    }
                    let hit = self.regex_pool.get(r2.wrapping_sub(RE_BASE) as u64 as usize).is_some_and(|re| re.is_match(self.text(r1)));
                    st.push(b(hit));
                }
                Op::Filesize => st.push(ctx.data.len() as i64),
                Op::Entrypoint => {
                    let ep = *ctx.entry_point.get_or_insert_with(|| super::entry::entry_point_offset(ctx.data));
                    st.push(ep);
                }
                Op::ReadInt(k) => {
                    let off = pop!();
                    // libyara does not check for undefined here; UNDEF as an
                    // offset is simply out of range.
                    st.push(read_int(ctx.data, off, k));
                }
                Op::Found(r) => {
                    let ms = matches_of(r, mem);
                    st.push(b(!ms.is_empty()));
                }
                Op::FoundAt(r) => {
                    let off = pop!();
                    if is_undef(off) {
                        st.push(UNDEF);
                        continue;
                    }
                    let ms = matches_of(r, mem);
                    let mut found = false;
                    for mt in ms {
                        let o = mt.offset as i64;
                        if o == off {
                            found = true;
                            break;
                        }
                        if off < o {
                            break;
                        }
                    }
                    st.push(b(found));
                }
                Op::FoundIn(r) | Op::CountIn(r) => {
                    let hi = pop!();
                    let lo = pop!();
                    if is_undef(lo) || is_undef(hi) {
                        st.push(UNDEF);
                        continue;
                    }
                    let ms = matches_of(r, mem);
                    let mut n: i64 = 0;
                    for mt in ms {
                        let o = mt.offset as i64;
                        if o >= lo && o <= hi {
                            n += 1;
                            if matches!(op, Op::FoundIn(_)) {
                                break;
                            }
                        }
                        if o > hi {
                            break;
                        }
                    }
                    st.push(if matches!(op, Op::FoundIn(_)) { b(n > 0) } else { n });
                }
                Op::Count(r) => {
                    let n = matches_of(r, mem).len() as i64;
                    st.push(n);
                }
                Op::Offset(r) | Op::Length(r) => {
                    let idx = pop!();
                    if is_undef(idx) {
                        st.push(UNDEF);
                        continue;
                    }
                    let ms = matches_of(r, mem);
                    let v = if idx >= 1 && ((idx - 1) as u64) < ms.len() as u64 {
                        let mt = &ms[(idx - 1) as usize];
                        if matches!(op, Op::Offset(_)) {
                            mt.offset as i64
                        } else {
                            // YR_MATCH.match_length is an int32_t.
                            mt.len as i32 as i64
                        }
                    } else {
                        UNDEF
                    };
                    st.push(v);
                }
                Op::PushRule(r) => {
                    st.push(b(ctx.rule_matched.get(r as usize).copied().unwrap_or(false)));
                }
                Op::OfStrings(s) | Op::OfPercentStrings(s) | Op::OfRules(s) | Op::OfPercentRules(s) => {
                    let q = pop!();
                    let items = self.set(s);
                    let count = items.len() as i64;
                    let found: i64 = match op {
                        Op::OfStrings(_) | Op::OfPercentStrings(_) => items
                            .iter()
                            .filter(|&&sid| ctx.matches.get(sid as usize).is_some_and(|v| !v.is_empty()))
                            .count() as i64,
                        _ => items
                            .iter()
                            .filter(|&&rid| ctx.rule_matched.get(rid as usize).copied().unwrap_or(false))
                            .count() as i64,
                    };
                    let r = match op {
                        Op::OfStrings(_) | Op::OfRules(_) => of_result(q, found, count),
                        _ => {
                            if is_undef(q) || count == 0 {
                                UNDEF
                            } else {
                                b((found as f64 / count as f64) * 100.0 >= q as f64)
                            }
                        }
                    };
                    st.push(r);
                }
                Op::OfFoundIn(s) => {
                    let hi = pop!();
                    let lo = pop!();
                    let q = pop!();
                    if is_undef(lo) || is_undef(hi) {
                        st.push(UNDEF);
                        continue;
                    }
                    let items = self.set(s);
                    let mut found = 0i64;
                    for &sid in items {
                        let ms = ctx.matches.get(sid as usize).map(|v| v.as_slice()).unwrap_or(&[]);
                        for mt in ms {
                            let o = mt.offset as i64;
                            if o >= lo && o <= hi {
                                found += 1;
                                break;
                            }
                            if o > lo {
                                break;
                            }
                        }
                    }
                    st.push(of_result(q, found, items.len() as i64));
                }
                Op::OfFoundAt(s) => {
                    let at = pop!();
                    let q = pop!();
                    if is_undef(at) {
                        st.push(UNDEF);
                        continue;
                    }
                    let items = self.set(s);
                    let mut found = 0i64;
                    for &sid in items {
                        let ms = ctx.matches.get(sid as usize).map(|v| v.as_slice()).unwrap_or(&[]);
                        for mt in ms {
                            let o = mt.offset as i64;
                            if o == at {
                                found += 1;
                                break;
                            }
                            if o > at {
                                break;
                            }
                        }
                    }
                    st.push(of_result(q, found, items.len() as i64));
                }
                Op::IterStartIntRange => {
                    let last = pop!();
                    let next = pop!();
                    sc.iters.push(Iter::IntRange { next, last });
                }
                Op::IterStartIntEnum(n) | Op::IterStartTextStringSet(n) => {
                    let n = (n as usize).min(st.len());
                    let start = sc.iter_items.len();
                    let from = st.len() - n;
                    sc.iter_items.extend_from_slice(&st[from..]);
                    st.truncate(from);
                    sc.iters.push(Iter::Items { start, count: n, idx: 0 });
                }
                Op::IterStartStringSet(s) => sc.iters.push(Iter::StringSet { set: s, idx: 0 }),
                Op::IterNext => {
                    // Pushes the "exhausted" flag, then the item.
                    let (done, item) = match sc.iters.last_mut() {
                        Some(Iter::IntRange { next, last }) => {
                            if !is_undef(*next) && !is_undef(*last) && *next <= *last {
                                let v = *next;
                                *next = next.wrapping_add(1);
                                (0, v)
                            } else {
                                (1, UNDEF)
                            }
                        }
                        Some(Iter::Items { start, count, idx }) => {
                            if *idx < *count {
                                let v = sc.iter_items.get(*start + *idx).copied().unwrap_or(UNDEF);
                                *idx += 1;
                                (0, v)
                            } else {
                                (1, UNDEF)
                            }
                        }
                        Some(Iter::StringSet { set, idx }) => {
                            let items = self.set(*set);
                            if *idx < items.len() {
                                let v = items[*idx] as i64;
                                *idx += 1;
                                (0, v)
                            } else {
                                (1, UNDEF)
                            }
                        }
                        None => (1, UNDEF),
                    };
                    st.push(done);
                    st.push(item);
                }
                Op::IterCondition => {
                    let r2 = pop!(); // min expression
                    let r3 = pop!(); // true count
                    let r4 = pop!(); // body result
                    let r1 = if is_undef(r2) {
                        b(r4 != 0)
                    } else if r2 == 0 {
                        b(r4 != 1)
                    } else {
                        b(r3.wrapping_add(r4) < r2)
                    };
                    st.push(r1);
                    st.push(r4);
                }
                Op::IterEnd => {
                    let r2 = pop!(); // min expression
                    let r3 = pop!(); // true count
                    let r4 = pop!(); // iterations
                    let r1 = if r4 == 0 {
                        0
                    } else if is_undef(r2) {
                        b(r3 == r4)
                    } else if r2 == 0 {
                        b(r3 == 0)
                    } else {
                        b(r3 >= r2)
                    };
                    st.push(r1);
                }
                Op::IterPop => {
                    if let Some(Iter::Items { start, .. }) = sc.iters.pop() {
                        sc.iter_items.truncate(start);
                    }
                }
            }
        }
        st.last().copied().unwrap_or(UNDEF)
    }
}

/// OP_OF / OP_OF_FOUND_IN / OP_OF_FOUND_AT quantifier evaluation.
#[inline]
fn of_result(q: i64, found: i64, count: i64) -> i64 {
    if is_undef(q) {
        b(found >= count)
    } else if q == 0 {
        b(found == 0)
    } else {
        b(found >= q)
    }
}
