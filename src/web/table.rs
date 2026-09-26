//! Compact in-memory result tables and the server-side "views" (filter / sort / compare /
//! time-range) the browser pages through.
//!
//! A table stores every cell as the exact text the CLI's quick renderer prints (so what the
//! analyst sees is what `vol` prints), concatenated into one byte arena with a u32 end offset
//! and a kind byte per cell: ~1.1 bytes of overhead per cell, no per-cell allocation. The
//! browser never holds more than the visible window; sorting and filtering millions of rows
//! happens here (parallel for big tables).

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
    /// Text as printed by the CLI ("-" / "N/A" for absent values).
    pub fn display(&self, r: usize, c: usize) -> &[u8] {
        match self.kind(r, c) {
            K_ABSENT => b"-",
            K_NA => b"N/A",
            _ => self.cell(r, c),
        }
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
    Regex(crate::yara::regex::Regex),
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
                .map(Filter::Regex)
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
        let k = t.kind(r, c);
        match self {
            Filter::Absent => return k != K_TEXT,
            Filter::Present => return k == K_TEXT,
            _ => {}
        }
        let s = t.display(r, c);
        match self {
            Filter::Contains(n) => contains_ci(s, n),
            Filter::NotContains(n) => !contains_ci(s, n),
            Filter::Exact(n) => s.eq_ignore_ascii_case(n),
            Filter::Cmp(op, v) => {
                if k != K_TEXT {
                    return false;
                }
                match num_key(ty, s) {
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
                if k != K_TEXT {
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
            Filter::Regex(re) => re.is_match(s),
            Filter::Absent | Filter::Present => unreachable!(),
        }
    }
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
            k.extend(t.display(r, c).iter().map(|b| b.to_ascii_lowercase()));
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
        let hit = if spec.visible.is_empty() {
            (0..t.ncols).any(|c| contains_ci(t.display(r, c), &spec.q))
        } else {
            spec.visible.iter().any(|&c| c < t.ncols && contains_ci(t.display(r, c), &spec.q))
        };
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
fn sort_rows(t: &Table, types: &[ColType], sort: &[(usize, bool)], rows: &mut Vec<u32>, marks: &mut Vec<u8>) {
    // precompute keys for the primary column
    enum Key {
        Num(Vec<Option<i128>>),
        Text(Vec<u64>),
    }
    let keys: Vec<Key> = sort
        .iter()
        .map(|&(c, _)| {
            let ty = types.get(c).copied().unwrap_or(ColType::Str);
            if is_numeric(ty) {
                Key::Num(rows.iter().map(|&r| if t.kind(r as usize, c) == K_TEXT { num_key(ty, t.cell(r as usize, c)) } else { None }).collect())
            } else {
                // 8-byte lower-cased big-endian prefix; ties fall back to the full compare
                Key::Text(
                    rows.iter()
                        .map(|&r| {
                            let s = t.display(r as usize, c);
                            let mut k = [0u8; 8];
                            for (i, b) in s.iter().take(8).enumerate() {
                                k[i] = b.to_ascii_lowercase();
                            }
                            u64::from_be_bytes(k)
                        })
                        .collect(),
                )
            }
        })
        .collect();
    let mut idx: Vec<u32> = (0..rows.len() as u32).collect();
    idx.sort_by(|&a, &b| {
        for (k, &(c, desc)) in keys.iter().zip(sort) {
            let o = match k {
                Key::Num(v) => match (v[a as usize], v[b as usize]) {
                    (Some(x), Some(y)) => {
                        let o = x.cmp(&y);
                        if desc { o.reverse() } else { o }
                    }
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => Ordering::Equal,
                },
                Key::Text(v) => {
                    let (ra, rb) = (rows[a as usize] as usize, rows[b as usize] as usize);
                    let (aa, ab) = (t.kind(ra, c) != K_TEXT, t.kind(rb, c) != K_TEXT);
                    match (aa, ab) {
                        (false, true) => Ordering::Less,
                        (true, false) => Ordering::Greater,
                        (true, true) => Ordering::Equal,
                        _ => {
                            let o = v[a as usize].cmp(&v[b as usize]).then_with(|| cmp_text(t.cell(ra, c), t.cell(rb, c)));
                            if desc { o.reverse() } else { o }
                        }
                    }
                }
            };
            if o != Ordering::Equal {
                return o;
            }
        }
        Ordering::Equal
    });
    let r2: Vec<u32> = idx.iter().map(|&i| rows[i as usize]).collect();
    let m2: Vec<u8> = idx.iter().map(|&i| marks[i as usize]).collect();
    *rows = r2;
    *marks = m2;
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
    for c in 0..t.ncols {
        out.push(b',');
        match t.kind(r, c) {
            K_ABSENT => out.extend_from_slice(b"null"),
            K_NA => out.push(b'0'),
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
    fn num_keys() {
        assert_eq!(num_key(ColType::Hex, b"0xff"), Some(255));
        assert_eq!(num_key(ColType::Int, b"-5"), Some(-5));
        assert_eq!(num_key(ColType::Bin, b"0b101"), Some(5));
        assert_eq!(num_key(ColType::Bool, b"True"), Some(1));
    }
}
