//! Compact in-memory result tables and the server-side "views" (filter / sort / compare /
//! time-range) the browser pages through.
//!
//! A table stores every cell as the exact text the CLI's quick renderer prints (so what the
//! analyst sees is what `vol` prints), concatenated into one byte arena with a u32 end offset
//! and a kind byte per cell: 5 bytes of overhead per cell, no per-cell allocation. Int and Hex
//! cells (most of a typical table) are stored as their 8-byte value instead of text and
//! formatted on demand, which halves memory for address-heavy output and makes numeric
//! sorting/filtering a plain integer compare. The browser never holds more than the visible
//! window; sorting and filtering millions of rows happens here (parallel for big tables).

use super::jsonw;
use crate::renderers::ColType;
use crate::yara::memchr::memchr2;
use std::cmp::Ordering;

/// Cell kinds.
pub const K_TEXT: u8 = 0;
/// Unreadable / Unparsable / NotAvailable: rendered "-"
pub const K_ABSENT: u8 = 1;
/// NotApplicable: rendered "N/A"
pub const K_NA: u8 = 2;
/// an Int column value, stored as 8 bytes (i64 LE), rendered in decimal
pub const K_DEC: u8 = 3;
/// a Hex column value, stored as 8 bytes (u64 LE), rendered "0x..." (lower case)
pub const K_HEX: u8 = 4;

/// Scratch space for formatting a numeric cell.
#[derive(Default)]
pub struct NumBuf(pub [u8; 24]);

fn fmt_dec(v: i64, b: &mut NumBuf) -> &[u8] {
    let mut i = b.0.len();
    let neg = v < 0;
    let mut u = v.unsigned_abs();
    loop {
        i -= 1;
        b.0[i] = b'0' + (u % 10) as u8;
        u /= 10;
        if u == 0 {
            break;
        }
    }
    if neg {
        i -= 1;
        b.0[i] = b'-';
    }
    &b.0[i..]
}

fn fmt_hex(mut u: u64, b: &mut NumBuf) -> &[u8] {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut i = b.0.len();
    loop {
        i -= 1;
        b.0[i] = H[(u & 15) as usize];
        u >>= 4;
        if u == 0 {
            break;
        }
    }
    i -= 2;
    b.0[i] = b'0';
    b.0[i + 1] = b'x';
    &b.0[i..]
}

/// Most bytes of cell text one run may keep (the rest of its rows are counted, not stored).
pub const MAX_TEXT: usize = 1 << 31;

#[derive(Default, Clone)]
pub struct Table {
    pub ncols: usize,
    pub text: Vec<u8>,
    pub ends: Vec<u32>,
    pub kinds: Vec<u8>,
    pub depth: Vec<u16>,
}

impl Table {
    pub fn new(ncols: usize) -> Table {
        Table { ncols, ..Default::default() }
    }
    #[inline]
    pub fn rows(&self) -> usize {
        self.depth.len()
    }
    #[inline]
    pub fn cell(&self, r: usize, c: usize) -> &[u8] {
        let i = r * self.ncols + c;
        let s = if i == 0 { 0 } else { self.ends[i - 1] as usize };
        &self.text[s..self.ends[i] as usize]
    }
    #[inline]
    pub fn kind(&self, r: usize, c: usize) -> u8 {
        self.kinds[r * self.ncols + c]
    }
    /// A present cell (text or number), i.e. not "-" / "N/A".
    #[inline]
    pub fn present(&self, r: usize, c: usize) -> bool {
        !matches!(self.kind(r, c), K_ABSENT | K_NA)
    }
    /// The value of a numeric (K_DEC / K_HEX) cell.
    #[inline]
    pub fn value(&self, r: usize, c: usize) -> Option<i128> {
        let k = self.kind(r, c);
        if k != K_DEC && k != K_HEX {
            return None;
        }
        let s = self.cell(r, c);
        let v = u64::from_le_bytes(s.try_into().ok()?);
        Some(if k == K_DEC { v as i64 as i128 } else { v as i128 })
    }
    /// Text as printed by the CLI ("-" / "N/A" for absent values, numbers formatted).
    #[inline]
    pub fn text<'a>(&'a self, r: usize, c: usize, buf: &'a mut NumBuf) -> &'a [u8] {
        match self.kind(r, c) {
            K_ABSENT => b"-",
            K_NA => b"N/A",
            K_DEC => match self.value(r, c) {
                Some(v) => fmt_dec(v as i64, buf),
                None => b"",
            },
            K_HEX => match self.value(r, c) {
                Some(v) => fmt_hex(v as u64, buf),
                None => b"",
            },
            _ => self.cell(r, c),
        }
    }
    /// Push a numeric cell (`kind` K_DEC or K_HEX).
    #[inline]
    pub fn push_num(&mut self, kind: u8, v: u64) {
        self.text.extend_from_slice(&v.to_le_bytes());
        self.push_cell(kind);
    }
    /// Append a batch built with the same column count.
    pub fn append(&mut self, b: &Table) {
        let base = self.text.len() as u32;
        self.text.extend_from_slice(&b.text);
        self.ends.extend(b.ends.iter().map(|e| e + base));
        self.kinds.extend_from_slice(&b.kinds);
        self.depth.extend_from_slice(&b.depth);
    }
    pub fn clear(&mut self) {
        self.text.clear();
        self.ends.clear();
        self.kinds.clear();
        self.depth.clear();
    }
    pub fn bytes(&self) -> usize {
        self.text.len() + self.ends.len() * 5 + self.depth.len() * 2
    }
    /// Start a row: returns nothing; call `push_cell` ncols times.
    #[inline]
    pub fn push_cell(&mut self, kind: u8) {
        self.ends.push(self.text.len() as u32);
        self.kinds.push(kind);
    }
}

// ------------------------------------------------------------------------------------------
// comparisons

/// ASCII case-insensitive substring test; `needle` must be lower-case.
pub fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if hay.len() < needle.len() {
        return false;
    }
    let (a, b) = (needle[0], needle[0].to_ascii_uppercase());
    let last = hay.len() - needle.len();
    let mut i = 0;
    while i <= last {
        match memchr2(a, b, &hay[i..=last]) {
            None => return false,
            Some(p) => {
                let s = i + p;
                if hay[s + 1..s + needle.len()].eq_ignore_ascii_case(&needle[1..]) {
                    return true;
                }
                i = s + 1;
            }
        }
    }
    false
}

/// Numeric key of a cell for `ty` (None: not a number / absent).
pub fn num_key(ty: ColType, s: &[u8]) -> Option<i128> {
    let t = std::str::from_utf8(s).ok()?.trim();
    match ty {
        ColType::Hex => {
            let (neg, h) = match t.strip_prefix('-') {
                Some(r) => (true, r),
                None => (false, t),
            };
            let v = i128::from_str_radix(h.strip_prefix("0x")?, 16).ok()?;
            Some(if neg { -v } else { v })
        }
        ColType::Bin => {
            let (neg, b) = match t.strip_prefix('-') {
                Some(r) => (true, r),
                None => (false, t),
            };
            let v = i128::from_str_radix(b.strip_prefix("0b")?, 2).ok()?;
            Some(if neg { -v } else { v })
        }
        ColType::Bool => match t {
            "True" => Some(1),
            "False" => Some(0),
            _ => None,
        },
        ColType::Float => t.parse::<f64>().ok().map(|f| (f * 1e6) as i128),
        _ => t.parse::<i128>().ok().or_else(|| crate::renderers::pyfmt::parse_int0(t)),
    }
}

fn is_numeric(ty: ColType) -> bool {
    matches!(ty, ColType::Int | ColType::Hex | ColType::Bin | ColType::Bool | ColType::Float)
}

/// Compare text cells: case-insensitive, then byte order.
fn cmp_text(a: &[u8], b: &[u8]) -> Ordering {
    let n = a.len().min(b.len());
    for i in 0..n {
        let (x, y) = (a[i].to_ascii_lowercase(), b[i].to_ascii_lowercase());
        if x != y {
            return x.cmp(&y);
        }
    }
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

// ------------------------------------------------------------------------------------------
// filters

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Op {
    Lt,
    Le,
    Gt,
    Ge,
}

pub enum Filter {
    /// case-insensitive substring (lower-case needle)
    Contains(Vec<u8>),
    NotContains(Vec<u8>),
    /// case-insensitive equality
    Exact(Vec<u8>),
    /// numeric (int0 / hex) comparison; falls back to text comparison for text columns
    Cmp(Op, i128),
    TextCmp(Op, Vec<u8>),
    /// python `re` pattern, case-insensitive (compiled per worker thread: the engine's scratch
    /// pool is a mutex, which 20 threads filtering millions of cells would fight over)
    Regex(String),
    /// only absent cells ("-" / "N/A")
    Absent,
    /// only present cells
    Present,
}

impl Filter {
    /// Parse a per-column filter expression:
    ///   `text` contains · `=text` equals · `!text` doesn't contain · `>n` `>=n` `<n` `<=n`
    ///   (int0 numbers, or text/time comparison on text columns) · `/re/` python regex
    ///   (case-insensitive) · `-` absent only · `!-` present only.
    pub fn parse(expr: &str, ty: ColType) -> Result<Filter, String> {
        let e = expr.trim();
        if e == "-" {
            return Ok(Filter::Absent);
        }
        if e == "!-" {
            return Ok(Filter::Present);
        }
        if e.len() >= 2 && e.starts_with('/') && e.ends_with('/') {
            let pat = &e[1..e.len() - 1];
            return crate::yara::regex::Regex::new_str(pat, crate::yara::regex::Flags::I)
                .map(|_| Filter::Regex(pat.to_string()))
                .map_err(|x| format!("invalid regular expression: {x}"));
        }
        for (p, op) in [(">=", Op::Ge), ("<=", Op::Le), (">", Op::Gt), ("<", Op::Lt)] {
            if let Some(rest) = e.strip_prefix(p) {
                let rest = rest.trim();
                if is_numeric(ty) {
                    let v = crate::renderers::pyfmt::parse_int0(rest).ok_or_else(|| format!("'{rest}' is not a number (int(x, 0) syntax: 42, 0x2a, 0o52, 0b101010)"))?;
                    return Ok(Filter::Cmp(op, v));
                }
                return Ok(Filter::TextCmp(op, rest.to_ascii_lowercase().into_bytes()));
            }
        }
        if let Some(rest) = e.strip_prefix('=') {
            return Ok(Filter::Exact(rest.trim().to_ascii_lowercase().into_bytes()));
        }
        if let Some(rest) = e.strip_prefix('!') {
            return Ok(Filter::NotContains(rest.to_ascii_lowercase().into_bytes()));
        }
        Ok(Filter::Contains(e.to_ascii_lowercase().into_bytes()))
    }

    fn test(&self, t: &Table, r: usize, c: usize, ty: ColType) -> bool {
        let present = t.present(r, c);
        match self {
            Filter::Absent => return !present,
            Filter::Present => return present,
            _ => {}
        }
        let mut nb = NumBuf::default();
        let s = t.text(r, c, &mut nb);
        match self {
            Filter::Contains(n) => contains_ci(s, n),
            Filter::NotContains(n) => !contains_ci(s, n),
            Filter::Exact(n) => s.eq_ignore_ascii_case(n),
            Filter::Cmp(op, v) => {
                if !present {
                    return false;
                }
                match t.value(r, c).or_else(|| num_key(ty, s)) {
                    Some(x) => match op {
                        Op::Lt => x < *v,
                        Op::Le => x <= *v,
                        Op::Gt => x > *v,
                        Op::Ge => x >= *v,
                    },
                    None => false,
                }
            }
            Filter::TextCmp(op, v) => {
                if !present {
                    return false;
                }
                let o = cmp_text(s, v);
                match op {
                    Op::Lt => o == Ordering::Less,
                    Op::Le => o != Ordering::Greater,
                    Op::Gt => o == Ordering::Greater,
                    Op::Ge => o != Ordering::Less,
                }
            }
            Filter::Regex(p) => REGEX.with(|cache| {
                let mut cache = cache.borrow_mut();
                if cache.as_ref().is_none_or(|(q, _)| q != p) {
                    *cache = crate::yara::regex::Regex::new_str(p, crate::yara::regex::Flags::I).ok().map(|re| (p.clone(), re));
                }
                cache.as_ref().is_some_and(|(_, re)| re.is_match(s))
            }),
            Filter::Absent | Filter::Present => unreachable!(),
        }
    }
}

thread_local! {
    static REGEX: std::cell::RefCell<Option<(String, crate::yara::regex::Regex)>> = const { std::cell::RefCell::new(None) };
}

/// A compare ("diff") against another run: rows whose key columns do (not) appear there.
pub struct CmpSpec {
    pub keys: Vec<usize>,
    /// key strings of the other table
    pub other: std::collections::HashSet<Vec<u8>>,
    /// 0 = all rows (mark uniques), 1 = only rows missing from the other run, 2 = only common rows
    pub mode: u8,
}

pub fn row_key(t: &Table, r: usize, keys: &[usize]) -> Vec<u8> {
    let mut k = Vec::with_capacity(32);
    for (i, &c) in keys.iter().enumerate() {
        if i > 0 {
            k.push(0x1f);
        }
        if c < t.ncols {
            let mut nb = NumBuf::default();
            k.extend(t.text(r, c, &mut nb).iter().map(|b| b.to_ascii_lowercase()));
        }
    }
    k
}

pub fn key_set(t: &Table, keys: &[usize]) -> std::collections::HashSet<Vec<u8>> {
    (0..t.rows()).map(|r| row_key(t, r, keys)).collect()
}

/// Everything that defines a view.
#[derive(Default)]
pub struct ViewSpec {
    /// global case-insensitive text, over `visible` columns (all when empty)
    pub q: Vec<u8>,
    pub visible: Vec<usize>,
    pub filters: Vec<(usize, Filter)>,
    /// (column, descending)
    pub sort: Vec<(usize, bool)>,
    /// (column, from, to) inclusive text range over a DateTime column
    pub range: Option<(usize, Vec<u8>, Vec<u8>)>,
    pub cmp: Option<CmpSpec>,
    /// keep tree order and show ancestors of matching rows
    pub tree: bool,
}

impl ViewSpec {
    pub fn is_identity(&self) -> bool {
        self.q.is_empty() && self.filters.is_empty() && self.sort.is_empty() && self.range.is_none() && self.cmp.is_none()
    }
}

/// Row flags in a view.
pub const M_CONTEXT: u8 = 1;
pub const M_UNIQUE: u8 = 2;

/// A materialized view: row indices (None = identity over the first `total` rows) + marks.
pub struct View {
    pub rows: Option<Vec<u32>>,
    pub marks: Vec<u8>,
    pub total: usize,
    /// table rows when the view was built
    pub built: usize,
    pub matched: usize,
}

impl View {
    pub fn row(&self, i: usize) -> usize {
        match &self.rows {
            Some(v) => v[i] as usize,
            None => i,
        }
    }
    pub fn mark(&self, i: usize) -> u8 {
        self.marks.get(i).copied().unwrap_or(0)
    }
}

fn row_matches(t: &Table, types: &[ColType], spec: &ViewSpec, r: usize) -> (bool, bool) {
    // returns (keep, unique)
    for (c, f) in &spec.filters {
        if *c >= t.ncols || !f.test(t, r, *c, types[*c]) {
            return (false, false);
        }
    }
    if let Some((c, from, to)) = &spec.range {
        if *c >= t.ncols || t.kind(r, *c) != K_TEXT {
            return (false, false);
        }
        let s = t.cell(r, *c);
        if (!from.is_empty() && s < from.as_slice()) || (!to.is_empty() && s > to.as_slice()) {
            return (false, false);
        }
    }
    if !spec.q.is_empty() {
        let mut nb = NumBuf::default();
        let mut hit_col = |c: usize| c < t.ncols && contains_ci(t.text(r, c, &mut nb), &spec.q);
        let hit = if spec.visible.is_empty() { (0..t.ncols).any(&mut hit_col) } else { spec.visible.iter().any(|&c| hit_col(c)) };
        if !hit {
            return (false, false);
        }
    }
    let mut unique = false;
    if let Some(cmp) = &spec.cmp {
        unique = !cmp.other.contains(&row_key(t, r, &cmp.keys));
        match cmp.mode {
            1 if !unique => return (false, false),
            2 if unique => return (false, false),
            _ => {}
        }
    }
    (true, unique)
}

/// Build a view over the first `t.rows()` rows.
pub fn build_view(t: &Table, types: &[ColType], spec: &ViewSpec) -> View {
    let n = t.rows();
    if spec.is_identity() {
        return View { rows: None, marks: Vec::new(), total: n, built: n, matched: n };
    }
    // filter (parallel over chunks for big tables)
    const CHUNK: usize = 1 << 15;
    let nchunks = n.div_ceil(CHUNK);
    let parts: Vec<Vec<(u32, bool)>> = crate::util::par::par_map(nchunks, |ci| {
        let (a, b) = (ci * CHUNK, ((ci + 1) * CHUNK).min(n));
        let mut v = Vec::new();
        for r in a..b {
            let (keep, unique) = row_matches(t, types, spec, r);
            if keep {
                v.push((r as u32, unique));
            }
        }
        v
    });
    let matched: usize = parts.iter().map(|p| p.len()).sum();
    let mut rows: Vec<u32> = Vec::with_capacity(matched);
    let mut marks: Vec<u8> = Vec::with_capacity(matched);
    let is_tree = spec.tree && spec.sort.is_empty() && t.depth.iter().any(|&d| d > 0);
    if is_tree {
        // include the ancestors of every kept row (as context rows), in tree order
        let mut keep = vec![0u8; n]; // 1 = match, 2 = unique match
        for p in &parts {
            for &(r, u) in p {
                keep[r as usize] = if u { 2 } else { 1 };
            }
        }
        let mut stack: Vec<(u16, u32, bool)> = Vec::new(); // (depth, row, emitted)
        for r in 0..n {
            let d = t.depth[r];
            while stack.last().is_some_and(|s| s.0 >= d) {
                stack.pop();
            }
            if keep[r] != 0 {
                for s in stack.iter_mut() {
                    if !s.2 {
                        rows.push(s.1);
                        marks.push(M_CONTEXT);
                        s.2 = true;
                    }
                }
                rows.push(r as u32);
                marks.push(if keep[r] == 2 { M_UNIQUE } else { 0 });
                stack.push((d, r as u32, true));
            } else {
                stack.push((d, r as u32, false));
            }
        }
    } else {
        for p in parts {
            for (r, u) in p {
                rows.push(r);
                marks.push(if u { M_UNIQUE } else { 0 });
            }
        }
    }
    if !spec.sort.is_empty() {
        sort_rows(t, types, &spec.sort, &mut rows, &mut marks);
    }
    let total = rows.len();
    View { rows: Some(rows), marks, total, built: n, matched }
}

/// Stable multi-column sort. Numeric columns sort by value, text case-insensitively; absent
/// values always sort last.
///
/// Every sort column is first reduced to a dense 32-bit rank per row (numbers by value, text
/// by an MSD string sort), then up to three ranks plus the row position are packed into one
/// u128 per row and sorted as plain integers (the position makes it stable).
fn sort_rows(t: &Table, types: &[ColType], sort: &[(usize, bool)], rows: &mut Vec<u32>, marks: &mut Vec<u8>) {
    const ABSENT: u32 = u32::MAX;
    let n = rows.len();
    let keys: Vec<Vec<u32>> = crate::util::par::par_map(sort.len(), |si| {
            let (c, desc) = sort[si];
            let ty = types.get(c).copied().unwrap_or(ColType::Str);
            let (mut k, distinct) = if is_numeric(ty) {
                let mut vals: Vec<(u128, u32)> = Vec::with_capacity(n);
                for (i, &r) in rows.iter().enumerate() {
                    let r = r as usize;
                    let v = match t.kind(r, c) {
                        K_DEC | K_HEX => t.value(r, c),
                        K_TEXT => num_key(ty, t.cell(r, c)),
                        _ => None,
                    };
                    // bias so that unsigned order == signed order
                    if let Some(v) = v {
                        vals.push(((v as u128) ^ (1u128 << 127), i as u32));
                    }
                }
                vals.sort_unstable();
                let mut k = vec![ABSENT; n];
                let mut cur = 0u32;
                for (j, &(v, i)) in vals.iter().enumerate() {
                    if j > 0 && v != vals[j - 1].0 {
                        cur += 1;
                    }
                    k[i as usize] = cur;
                }
                (k, if vals.is_empty() { 0 } else { cur + 1 })
            } else {
                text_ranks(t, c, rows)
            };
            if desc {
                for x in k.iter_mut() {
                    if *x != ABSENT {
                        *x = distinct - 1 - *x;
                    }
                }
            }
            k
        });
    let idx: Vec<u32> = if keys.len() <= 3 {
        let mut packed: Vec<u128> = (0..n)
            .map(|i| {
                let mut p: u128 = 0;
                for (j, k) in keys.iter().enumerate() {
                    p |= (k[i] as u128) << (96 - 32 * j);
                }
                p | i as u128
            })
            .collect();
        packed.sort_unstable();
        packed.into_iter().map(|p| p as u32).collect()
    } else {
        let mut idx: Vec<u32> = (0..n as u32).collect();
        idx.sort_unstable_by(|&a, &b| {
            for k in &keys {
                let o = k[a as usize].cmp(&k[b as usize]);
                if o != Ordering::Equal {
                    return o;
                }
            }
            a.cmp(&b)
        });
        idx
    };
    let r2: Vec<u32> = idx.iter().map(|&i| rows[i as usize]).collect();
    let m2: Vec<u8> = idx.iter().map(|&i| marks[i as usize]).collect();
    *rows = r2;
    *marks = m2;
}

/// Dense rank of every row's text in column `c` (ASCII case-insensitive order) and the number
/// of distinct values; absent cells get `u32::MAX`.
///
/// MSD string sort on 16-byte chunks: each pass is an integer sort of (chunk, length class),
/// and only runs that are equal so far and continue are refined by the next chunk. Shared
/// prefixes (paths!) and duplicate values (process names) cost a few integer passes instead of
/// long byte-by-byte comparisons.
fn text_ranks(t: &Table, c: usize, rows: &[u32]) -> (Vec<u32>, u32) {
    let n = rows.len();
    let mut order: Vec<u32> = (0..n as u32).filter(|&i| t.present(rows[i as usize] as usize, c)).collect();
    let m = order.len();
    let mut boundary = vec![false; m];
    // key of the 16-byte chunk at `depth`: (lower-cased big-endian chunk, length class)
    // length class: bytes left in this chunk (0..=16), 17 = the string continues
    let key = |i: u32, depth: usize| -> (u128, u8) {
        let mut nb = NumBuf::default();
        let s = t.text(rows[i as usize] as usize, c, &mut nb);
        let rest = s.get(depth..).unwrap_or(&[]);
        let mut k = [0u8; 16];
        for (j, b) in rest.iter().take(16).enumerate() {
            k[j] = b.to_ascii_lowercase();
        }
        (u128::from_be_bytes(k), if rest.len() > 16 { 17 } else { rest.len() as u8 })
    };
    let mut jobs: Vec<(usize, usize, usize)> = vec![(0, m, 0)];
    let mut keys: Vec<((u128, u8), u32)> = Vec::new();
    while let Some((s, e, depth)) = jobs.pop() {
        keys.clear();
        keys.extend(order[s..e].iter().map(|&i| (key(i, depth), i)));
        keys.sort_unstable();
        let mut a = 0;
        while a < keys.len() {
            let mut b = a + 1;
            while b < keys.len() && keys[b].0 == keys[a].0 {
                b += 1;
            }
            boundary[s + a] = true;
            if keys[a].0.1 == 17 && b - a > 1 {
                jobs.push((s + a, s + b, depth + 16));
            }
            a = b;
        }
        for (k, (_, i)) in keys.iter().enumerate() {
            order[s + k] = *i;
        }
    }
    let mut rank = vec![u32::MAX; n];
    let mut cur: u32 = 0;
    for (k, &i) in order.iter().enumerate() {
        if k > 0 && boundary[k] {
            cur += 1;
        }
        rank[i as usize] = cur;
    }
    (rank, if order.is_empty() { 0 } else { cur + 1 })
}

// ------------------------------------------------------------------------------------------
// time

/// Seconds since the epoch of a CLI datetime text ("YYYY-MM-DD HH:MM:SS[.ffffff][ UTC]").
pub fn parse_cli_time(s: &[u8]) -> Option<f64> {
    let s = std::str::from_utf8(s).ok()?;
    if s.len() < 19 {
        return None;
    }
    let b = s.as_bytes();
    let num = |a: usize, l: usize| -> Option<i64> { std::str::from_utf8(&b[a..a + l]).ok()?.parse::<i64>().ok() };
    if b[4] != b'-' || b[7] != b'-' || (b[10] != b' ' && b[10] != b'T') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (y, mo, d, h, mi, se) = (num(0, 4)?, num(5, 2)?, num(8, 2)?, num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let mut frac = 0.0;
    if b.len() > 20 && b[19] == b'.' {
        let end = b[20..].iter().position(|c| !c.is_ascii_digit()).map(|p| p + 20).unwrap_or(b.len());
        let digits = &s[20..end];
        if !digits.is_empty() {
            frac = digits.parse::<f64>().ok()? / 10f64.powi(digits.len() as i32);
        }
    }
    // days from civil (Howard Hinnant)
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some((days * 86400 + h * 3600 + mi * 60 + se) as f64 + frac)
}

/// Histogram of a DateTime column over a view: (min, max, counts).
pub fn histogram(t: &Table, v: &View, col: usize, buckets: usize) -> Option<(f64, f64, Vec<u32>)> {
    if col >= t.ncols {
        return None;
    }
    let mut times: Vec<f64> = Vec::new();
    for i in 0..v.total {
        if v.mark(i) & M_CONTEXT != 0 {
            continue;
        }
        let r = v.row(i);
        if r >= t.rows() || t.kind(r, col) != K_TEXT {
            continue;
        }
        if let Some(x) = parse_cli_time(t.cell(r, col)) {
            times.push(x);
        }
    }
    if times.is_empty() {
        return None;
    }
    let (mut lo, mut hi) = (f64::MAX, f64::MIN);
    for &x in &times {
        lo = lo.min(x);
        hi = hi.max(x);
    }
    let buckets = buckets.clamp(1, 2000);
    let mut counts = vec![0u32; buckets];
    let span = (hi - lo).max(1e-6);
    for &x in &times {
        let b = (((x - lo) / span) * buckets as f64) as usize;
        counts[b.min(buckets - 1)] += 1;
    }
    Some((lo, hi, counts))
}

// ------------------------------------------------------------------------------------------
// serialization

/// One row of a window as JSON: `[index, flags, cell...]`, flags = depth*4 + mark; cells are
/// strings, `null` for "-" and `0` for "N/A".
pub fn row_json(out: &mut Vec<u8>, t: &Table, r: usize, mark: u8) {
    out.push(b'[');
    out.extend_from_slice(r.to_string().as_bytes());
    out.push(b',');
    out.extend_from_slice((t.depth[r] as u32 * 4 + mark as u32).to_string().as_bytes());
    let mut nb = NumBuf::default();
    for c in 0..t.ncols {
        out.push(b',');
        match t.kind(r, c) {
            K_ABSENT => out.extend_from_slice(b"null"),
            K_NA => out.push(b'0'),
            K_DEC | K_HEX => {
                // numbers go out as strings: JS numbers can't hold 64-bit addresses
                out.push(b'"');
                out.extend_from_slice(t.text(r, c, &mut nb));
                out.push(b'"');
            }
            _ => jsonw::bytes_str(out, t.cell(r, c)),
        }
    }
    out.push(b']');
}

/// CSV field (RFC 4180 quoting).
pub fn csv_field(out: &mut Vec<u8>, s: &[u8], sep: u8) {
    if s.iter().any(|&c| c == sep || c == b'"' || c == b'\n' || c == b'\r') {
        out.push(b'"');
        for &c in s {
            if c == b'"' {
                out.push(b'"');
            }
            out.push(c);
        }
        out.push(b'"');
    } else {
        out.extend_from_slice(s);
    }
}

/// Typed JSON value of a cell for exports: numbers for numeric columns (Hex as its value,
/// like `vol -r json`), booleans, null for absent, strings otherwise.
pub fn cell_json(out: &mut Vec<u8>, t: &Table, r: usize, c: usize, ty: ColType) {
    match t.kind(r, c) {
        K_ABSENT | K_NA => out.extend_from_slice(b"null"),
        K_DEC | K_HEX => out.extend_from_slice(t.value(r, c).unwrap_or(0).to_string().as_bytes()),
        _ => {
            let s = t.cell(r, c);
            if is_numeric(ty) && ty != ColType::Float {
                if ty == ColType::Bool {
                    out.extend_from_slice(if s == b"True" { b"true" } else { b"false" });
                    return;
                }
                if let Some(v) = num_key(ty, s) {
                    out.extend_from_slice(v.to_string().as_bytes());
                    return;
                }
            }
            jsonw::bytes_str(out, s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(rows: &[(u16, &[&str])]) -> Table {
        let mut t = Table::new(rows[0].1.len());
        for (d, cells) in rows {
            for c in cells.iter() {
                let k = match *c {
                    "-" => K_ABSENT,
                    "N/A" => K_NA,
                    _ => {
                        t.text.extend_from_slice(c.as_bytes());
                        K_TEXT
                    }
                };
                t.push_cell(k);
            }
            t.depth.push(*d);
        }
        t
    }

    #[test]
    fn contains_ci_works() {
        assert!(contains_ci(b"SvcHost.exe", b"svchost"));
        assert!(contains_ci(b"abc", b"c"));
        assert!(!contains_ci(b"abc", b"abcd"));
        assert!(contains_ci(b"xxAbAbC", b"abc"));
        assert!(!contains_ci(b"", b"a"));
        assert!(contains_ci(b"", b""));
    }

    #[test]
    fn views_filter_sort_tree() {
        let types = [ColType::Int, ColType::Str, ColType::Hex];
        let t = table(&[
            (0, &["4", "System", "0x10"]),
            (1, &["344", "smss.exe", "0x2"]),
            (2, &["500", "csrss.exe", "-"]),
            (0, &["800", "explorer.exe", "0xff"]),
            (1, &["900", "cmd.exe", "0x1"]),
        ]);
        // sort by hex desc, absent last
        let v = build_view(&t, &types, &ViewSpec { sort: vec![(2, true)], ..Default::default() });
        let order: Vec<usize> = (0..v.total).map(|i| v.row(i)).collect();
        assert_eq!(order, vec![3, 0, 1, 4, 2]);
        // numeric filter
        let v = build_view(&t, &types, &ViewSpec { filters: vec![(0, Filter::parse(">=0x1f4", ColType::Int).unwrap())], ..Default::default() });
        assert_eq!(v.total, 3);
        // tree filter keeps ancestors as context
        let v = build_view(&t, &types, &ViewSpec { q: b"csrss".to_vec(), tree: true, ..Default::default() });
        let order: Vec<(usize, u8)> = (0..v.total).map(|i| (v.row(i), v.mark(i))).collect();
        assert_eq!(order, vec![(0, M_CONTEXT), (1, M_CONTEXT), (2, 0)]);
        // absent filter
        let v = build_view(&t, &types, &ViewSpec { filters: vec![(2, Filter::parse("-", ColType::Hex).unwrap())], ..Default::default() });
        assert_eq!(v.total, 1);
        // regex
        let v = build_view(&t, &types, &ViewSpec { filters: vec![(1, Filter::parse("/^(cmd|smss)\\./", ColType::Str).unwrap())], ..Default::default() });
        assert_eq!(v.total, 2);
        // compare: keys on the name column
        let other = table(&[(0, &["1", "cmd.exe", "0x0"])]);
        let spec = ViewSpec { cmp: Some(CmpSpec { keys: vec![1], other: key_set(&other, &[1]), mode: 1 }), ..Default::default() };
        let v = build_view(&t, &types, &spec);
        assert_eq!(v.total, 4);
    }

    #[test]
    fn cli_time_parse() {
        assert_eq!(parse_cli_time(b"1970-01-01 00:00:00.000000 UTC"), Some(0.0));
        assert_eq!(parse_cli_time(b"2026-09-14 02:53:44.500000 UTC"), Some(1_789_354_424.5));
        assert_eq!(parse_cli_time(b"garbage"), None);
    }

    #[test]
    fn compact_numbers_render_like_the_cli() {
        use crate::renderers::Value;
        let mut t = Table::new(1);
        let hexes: [u64; 6] = [0, 1, 0xff, 0xffff_8000_0000_0010, u64::MAX, 0x1000];
        let decs: [i64; 6] = [0, 7, -5, i64::MIN, i64::MAX, 1_000_000];
        for v in hexes {
            t.push_num(K_HEX, v);
            t.depth.push(0);
        }
        for v in decs {
            t.push_num(K_DEC, v as u64);
            t.depth.push(0);
        }
        for (r, v) in hexes.iter().map(|&v| (ColType::Hex, v as i128)).chain(decs.iter().map(|&v| (ColType::Int, v as i128))).enumerate() {
            let mut want = Vec::new();
            crate::renderers::text::render_cell(&mut want, v.0, &Value::Int(v.1), false);
            let mut nb = NumBuf::default();
            assert_eq!(t.text(r, 0, &mut nb), want.as_slice(), "row {r}");
            assert_eq!(t.value(r, 0), Some(v.1));
        }
    }

    /// `cargo test --profile fast table_bench -- --ignored --nocapture`: views over 2M rows.
    #[test]
    #[ignore]
    fn table_bench() {
        let n = 2_000_000usize;
        let t0 = std::time::Instant::now();
        let mut t = Table::new(5);
        let mut x: u64 = 0x9e3779b97f4a7c15;
        let names = ["svchost.exe", "explorer.exe", "cmd.exe", "powershell.exe", "lsass.exe", "chrome.exe"];
        for i in 0..n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            t.push_num(K_DEC, (x % 9000) as u64);
            t.push_num(K_HEX, 0xffff_8000_0000_0000 | (x & 0xffff_ffff_fff0));
            t.text.extend_from_slice(names[(x % 6) as usize].as_bytes());
            t.push_cell(K_TEXT);
            t.text.extend_from_slice(format!("\\Device\\HarddiskVolume3\\Windows\\System32\\file{i}.dll").as_bytes());
            t.push_cell(K_TEXT);
            t.text.extend_from_slice(format!("2026-09-14 02:{:02}:{:02}.000000 UTC", (x >> 8) % 60, x % 60).as_bytes());
            t.push_cell(K_TEXT);
            t.depth.push(0);
        }
        let types = [ColType::Int, ColType::Hex, ColType::Str, ColType::Str, ColType::DateTime];
        println!("build {n} rows: {:?}, {} MiB ({:.1} B/row)", t0.elapsed(), t.bytes() >> 20, t.bytes() as f64 / n as f64);
        let time = |name: &str, spec: ViewSpec| {
            let s = std::time::Instant::now();
            let v = build_view(&t, &types, &spec);
            println!("{name:<34} {:>8.1} ms  -> {} rows", s.elapsed().as_secs_f64() * 1e3, v.total);
            v
        };
        time("global text filter 'powershell'", ViewSpec { q: b"powershell".to_vec(), ..Default::default() });
        time("column filter file1234", ViewSpec { filters: vec![(3, Filter::parse("file1234", ColType::Str).unwrap())], ..Default::default() });
        time("numeric filter PID >= 0x1000", ViewSpec { filters: vec![(0, Filter::parse(">=0x1000", ColType::Int).unwrap())], ..Default::default() });
        time("regex /^(cmd|lsass)/", ViewSpec { filters: vec![(2, Filter::parse("/^(cmd|lsass)/", ColType::Str).unwrap())], ..Default::default() });
        time("sort by hex desc", ViewSpec { sort: vec![(1, true)], ..Default::default() });
        time("sort by name then time", ViewSpec { sort: vec![(2, false), (4, false)], ..Default::default() });
        let v = time("sort by path (text)", ViewSpec { sort: vec![(3, false)], ..Default::default() });
        let s = std::time::Instant::now();
        let mut out = Vec::new();
        for i in 1_000_000..1_000_256 {
            row_json(&mut out, &t, v.row(i), 0);
        }
        println!("{:<34} {:>8.3} ms  ({} bytes)", "serialize a 256-row window", s.elapsed().as_secs_f64() * 1e3, out.len());
    }

    #[test]
    fn num_keys() {
        assert_eq!(num_key(ColType::Hex, b"0xff"), Some(255));
        assert_eq!(num_key(ColType::Int, b"-5"), Some(-5));
        assert_eq!(num_key(ColType::Bin, b"0b101"), Some(5));
        assert_eq!(num_key(ColType::Bool, b"True"), Some(1));
    }
}
