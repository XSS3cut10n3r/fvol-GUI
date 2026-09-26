//! Minimal read-only reader for the SQLite 3 database file format (std only, no libsqlite).
//!
//! Scope: reading ordinary rowid tables exactly as a full table scan (`SELECT ... FROM t`
//! without an index, i.e. **rowid order**) sees them. Written for python volatility3's
//! identifier cache (`~/.cache/volatility3/identifier.cache`, see
//! `plugins::generic::isfinfo`), but generic: any rowid table of any database works.
//!
//! ```ignore
//! let db = sqlite::Database::open(path)?;
//! let t = db.table("cache")?;                       // columns from the CREATE TABLE sql
//! let (loc, id) = (t.column("location").unwrap(), t.column("identifier").unwrap());
//! db.for_each_row(&t, |rowid, v| { println!("{rowid} {:?} {:?}", v[loc], v[id]); true })?;
//! ```
//!
//! Supported (file format reference: <https://www.sqlite.org/fileformat2.html>):
//!   * every page size (512..65536) and reserved-bytes-per-page setting;
//!   * table b-trees of any depth (interior pages 0x05, leaf pages 0x0d);
//!   * payloads spilling into overflow page chains;
//!   * records with every serial type (NULL, 8/16/24/32/48/64-bit big-endian integers,
//!     IEEE doubles, the constants 0 and 1, BLOBs and TEXT);
//!   * UTF-8 and UTF-16le/be databases (TEXT is always returned as UTF-8 bytes);
//!   * column names from `sqlite_master.sql` (quoted identifiers, comments, table
//!     constraints) and `INTEGER PRIMARY KEY` rowid aliases.
//!
//! Not supported / ignored: WAL mode (only the main file is read, frames still in `-wal` are
//! not seen), hot rollback journals (a crashed writer's `-journal` is not rolled back),
//! `WITHOUT ROWID` tables, indexes, views, virtual tables. Records shorter than the table
//! (columns added by `ALTER TABLE ADD COLUMN` after the row was written) yield NULL for the
//! missing columns rather than the column's DEFAULT.
//!
//! Robustness: the file is read into memory (not mmapped, so a concurrent writer truncating
//! it cannot SIGBUS us); every offset is bounds-checked and page chains / tree walks are
//! bounded by the page count, so a corrupted or hostile file yields `Err`, never a panic or
//! an endless loop.

use crate::error::{Error, Result};
use std::borrow::Cow;
use std::path::Path;

const MAGIC: &[u8; 16] = b"SQLite format 3\0";
/// Deepest table b-tree we follow (real trees are < 10 levels even for huge databases).
const MAX_DEPTH: usize = 64;

fn corrupt(what: &str) -> Error {
    Error::msg(format!("sqlite: malformed database ({what})"))
}

/// Text encoding of a database (header offset 56).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// A column value. `Text`/`Blob` borrow from the page (or from the reassembled payload of a
/// row spilling into overflow pages) where possible.
#[derive(Clone, Debug, PartialEq)]
pub enum Value<'a> {
    Null,
    Int(i64),
    Float(f64),
    /// TEXT as UTF-8 bytes (converted when the database is UTF-16; not validated otherwise).
    Text(Cow<'a, [u8]>),
    Blob(Cow<'a, [u8]>),
}

impl Value<'_> {
    /// Detach from the page buffer.
    pub fn into_owned(self) -> Value<'static> {
        match self {
            Value::Null => Value::Null,
            Value::Int(i) => Value::Int(i),
            Value::Float(f) => Value::Float(f),
            Value::Text(t) => Value::Text(Cow::Owned(t.into_owned())),
            Value::Blob(b) => Value::Blob(Cow::Owned(b.into_owned())),
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
    /// TEXT bytes (UTF-8).
    pub fn as_text(&self) -> Option<&[u8]> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }
    /// TEXT as a `str` (invalid UTF-8 replaced by U+FFFD).
    pub fn as_str_lossy(&self) -> Option<Cow<'_, str>> {
        self.as_text().map(String::from_utf8_lossy)
    }
}

/// A row with owned values (see [`Database::rows`]).
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub rowid: i64,
    pub values: Vec<Value<'static>>,
}

/// One `sqlite_master` entry.
#[derive(Clone, Debug)]
pub struct SchemaEntry {
    /// "table", "index", "view" or "trigger"
    pub kind: String,
    pub name: String,
    pub tbl_name: String,
    pub rootpage: i64,
    pub sql: Option<String>,
}

/// A rowid table: where its b-tree starts and its column names in declaration order.
#[derive(Clone, Debug)]
pub struct Table {
    pub name: String,
    pub root: u32,
    pub columns: Vec<String>,
    /// Index of the `INTEGER PRIMARY KEY` column (stored as NULL, its value is the rowid).
    pub rowid_alias: Option<usize>,
}

impl Table {
    /// Column index by name (ASCII case-insensitive, like SQL).
    pub fn column(&self, name: &str) -> Option<usize> {
        self.columns.iter().position(|c| c.eq_ignore_ascii_case(name))
    }
}

/// An SQLite database file held in memory.
pub struct Database {
    data: Vec<u8>,
    page_size: usize,
    /// page size minus the reserved bytes at the end of each page
    usable: usize,
    page_count: u32,
    pub encoding: TextEncoding,
}

impl Database {
    /// Read and validate the header of the database at `path`.
    pub fn open(path: &Path) -> Result<Database> {
        Database::from_bytes(std::fs::read(path)?)
    }

    /// Use an in-memory image of a database file.
    pub fn from_bytes(data: Vec<u8>) -> Result<Database> {
        if data.len() < 100 || &data[..16] != MAGIC {
            return Err(Error::msg("sqlite: file is not a database"));
        }
        let page_size = match u16::from_be_bytes([data[16], data[17]]) {
            1 => 65536usize,
            n => n as usize,
        };
        if !page_size.is_power_of_two() || !(512..=65536).contains(&page_size) {
            return Err(corrupt("page size"));
        }
        let usable = page_size - data[20] as usize;
        if usable < 480 {
            return Err(corrupt("reserved bytes"));
        }
        let encoding = match u32::from_be_bytes(data[56..60].try_into().unwrap()) {
            0 | 1 => TextEncoding::Utf8,
            2 => TextEncoding::Utf16Le,
            3 => TextEncoding::Utf16Be,
            _ => return Err(corrupt("text encoding")),
        };
        // the header's page count is only trusted when "version-valid-for" matches the
        // change counter (legacy writers do not maintain it); never beyond the file itself
        let file_pages = (data.len() / page_size).min(u32::MAX as usize) as u32;
        let hdr_pages = u32::from_be_bytes(data[28..32].try_into().unwrap());
        let valid = data[24..28] == data[92..96];
        let page_count = if valid && hdr_pages != 0 { hdr_pages.min(file_pages) } else { file_pages };
        Ok(Database { data, page_size, usable, page_count, encoding })
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }
    pub fn page_count(&self) -> u32 {
        self.page_count
    }

    /// Page `n` (1-based).
    fn page(&self, n: u32) -> Result<&[u8]> {
        if n == 0 || n > self.page_count {
            return Err(corrupt("page number out of range"));
        }
        let start = (n as usize - 1) * self.page_size;
        self.data.get(start..start + self.page_size).ok_or_else(|| corrupt("truncated page"))
    }

    /// The `sqlite_master` table (b-tree rooted at page 1).
    pub fn schema(&self) -> Result<Vec<SchemaEntry>> {
        let mut out = Vec::new();
        self.scan(1, |_, payload| {
            let v = decode_record(payload, self.encoding)?;
            let text = |i: usize| match v.get(i) {
                Some(Value::Text(t)) => Some(String::from_utf8_lossy(t).into_owned()),
                _ => None,
            };
            out.push(SchemaEntry {
                kind: text(0).unwrap_or_default(),
                name: text(1).unwrap_or_default(),
                tbl_name: text(2).unwrap_or_default(),
                rootpage: v.get(3).and_then(|x| x.as_int()).unwrap_or(0),
                sql: text(4),
            });
            Ok(true)
        })?;
        Ok(out)
    }

    /// Look up a rowid table by name (ASCII case-insensitive) and parse its column list.
    pub fn table(&self, name: &str) -> Result<Table> {
        let e = self
            .schema()?
            .into_iter()
            .find(|e| e.kind == "table" && e.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| Error::msg(format!("sqlite: no such table: {name}")))?;
        let sql = e.sql.as_deref().ok_or_else(|| corrupt("table without sql"))?;
        let (columns, rowid_alias, without_rowid) = parse_create_table(sql).ok_or_else(|| corrupt("CREATE TABLE sql"))?;
        if without_rowid {
            return Err(Error::msg(format!("sqlite: WITHOUT ROWID table {name} is not supported")));
        }
        let root = u32::try_from(e.rootpage).ok().filter(|&r| r != 0).ok_or_else(|| corrupt("root page"))?;
        Ok(Table { name: e.name, root, columns, rowid_alias })
    }

    /// Visit every row of `table` in rowid order: `f(rowid, values)` with exactly
    /// `table.columns.len()` values; return `false` to stop early.
    pub fn for_each_row<F>(&self, table: &Table, mut f: F) -> Result<()>
    where
        F: FnMut(i64, &[Value<'_>]) -> bool,
    {
        let n = table.columns.len();
        self.scan(table.root, |rowid, payload| {
            let mut v = decode_record(payload, self.encoding)?;
            v.resize(n, Value::Null);
            if let Some(a) = table.rowid_alias {
                v[a] = Value::Int(rowid);
            }
            Ok(f(rowid, &v))
        })
    }

    /// All rows of `table` in rowid order, with owned values.
    pub fn rows(&self, table: &Table) -> Result<Vec<Row>> {
        let mut out = Vec::new();
        self.for_each_row(table, |rowid, v| {
            out.push(Row { rowid, values: v.iter().map(|x| x.clone().into_owned()).collect() });
            true
        })?;
        Ok(out)
    }

    /// Walk the table b-tree rooted at `root` in rowid order, calling `f(rowid, payload)` with
    /// each row's complete record (overflow chains reassembled). `Ok(false)` stops the walk.
    pub fn scan<F>(&self, root: u32, mut f: F) -> Result<()>
    where
        F: FnMut(i64, &[u8]) -> Result<bool>,
    {
        // explicit stack of (page number, index of the next cell to descend into)
        let mut stack: Vec<(u32, usize)> = vec![(root, 0)];
        let mut visited: u64 = 1;
        while let Some(&mut (pgno, ref mut next)) = stack.last_mut() {
            let page = self.page(pgno)?;
            let hdr = if pgno == 1 { 100 } else { 0 };
            let kind = *page.get(hdr).ok_or_else(|| corrupt("page header"))?;
            let ncells = be16(page, hdr + 3)? as usize;
            match kind {
                0x0d => {
                    for i in 0..ncells {
                        let off = be16(page, hdr + 8 + 2 * i)? as usize;
                        let (rowid, payload) = self.leaf_cell(page, off)?;
                        if !f(rowid, &payload)? {
                            return Ok(());
                        }
                    }
                    stack.pop();
                }
                0x05 => {
                    let i = *next;
                    *next += 1;
                    let child = if i < ncells {
                        let off = be16(page, hdr + 12 + 2 * i)? as usize;
                        be32(page, off)?
                    } else if i == ncells {
                        be32(page, hdr + 8)?
                    } else {
                        stack.pop();
                        continue;
                    };
                    visited += 1;
                    if stack.len() >= MAX_DEPTH || visited > self.page_count as u64 + 1 {
                        return Err(corrupt("b-tree cycle"));
                    }
                    stack.push((child, 0));
                }
                _ => return Err(corrupt("not a table b-tree page")),
            }
        }
        Ok(())
    }

    /// Parse a table-leaf cell at `off`: (rowid, full payload).
    fn leaf_cell<'p>(&self, page: &'p [u8], off: usize) -> Result<(i64, Cow<'p, [u8]>)> {
        let (plen, n1) = varint(page, off)?;
        let (rowid, n2) = varint(page, off + n1)?;
        let start = off + n1 + n2;
        if plen > self.data.len() as u64 {
            return Err(corrupt("payload size"));
        }
        let plen = plen as usize;
        let u = self.usable;
        let x = u - 35;
        if plen <= x {
            let p = page.get(start..start + plen).ok_or_else(|| corrupt("cell out of page"))?;
            return Ok((rowid as i64, Cow::Borrowed(p)));
        }
        let m = (u - 12) * 32 / 255 - 23;
        let k = m + (plen - m) % (u - 4);
        let local = if k <= x { k } else { m };
        let mut buf = Vec::with_capacity(plen);
        buf.extend_from_slice(page.get(start..start + local).ok_or_else(|| corrupt("cell out of page"))?);
        let mut ovfl = be32(page, start + local)?;
        let mut hops = 0u32;
        while buf.len() < plen {
            hops += 1;
            if ovfl == 0 || hops > self.page_count {
                return Err(corrupt("overflow chain"));
            }
            let p = self.page(ovfl)?;
            let take = (u - 4).min(plen - buf.len());
            buf.extend_from_slice(p.get(4..4 + take).ok_or_else(|| corrupt("overflow page"))?);
            ovfl = be32(p, 0)?;
        }
        Ok((rowid as i64, Cow::Owned(buf)))
    }
}

fn be16(b: &[u8], off: usize) -> Result<u16> {
    b.get(off..off + 2).map(|s| u16::from_be_bytes([s[0], s[1]])).ok_or_else(|| corrupt("short page"))
}

fn be32(b: &[u8], off: usize) -> Result<u32> {
    b.get(off..off + 4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]])).ok_or_else(|| corrupt("short page"))
}

/// SQLite varint at `off`: (value, length in bytes). 1-9 bytes, big-endian 7-bit groups, the
/// 9th byte contributes all 8 bits.
fn varint(b: &[u8], off: usize) -> Result<(u64, usize)> {
    let mut v: u64 = 0;
    for i in 0..9 {
        let c = *b.get(off + i).ok_or_else(|| corrupt("truncated varint"))?;
        if i == 8 {
            return Ok(((v << 8) | c as u64, 9));
        }
        v = (v << 7) | (c & 0x7f) as u64;
        if c & 0x80 == 0 {
            return Ok((v, i + 1));
        }
    }
    unreachable!()
}

/// Decode a record (header of serial types, then the body) into values borrowing `payload`.
pub fn decode_record(payload: &[u8], enc: TextEncoding) -> Result<Vec<Value<'_>>> {
    let (hlen, mut i) = varint(payload, 0)?;
    let hlen = usize::try_from(hlen).ok().filter(|&h| h >= i && h <= payload.len()).ok_or_else(|| corrupt("record header"))?;
    let mut body = hlen;
    let mut out = Vec::new();
    while i < hlen {
        let (t, n) = varint(payload, i)?;
        i += n;
        let size = match t {
            0 | 8 | 9 => 0,
            1..=4 => t as usize,
            5 => 6,
            6 | 7 => 8,
            10 | 11 => return Err(corrupt("reserved serial type")),
            _ => ((t - 12) / 2).min(usize::MAX as u64 >> 1) as usize,
        };
        let d = payload.get(body..body.saturating_add(size)).ok_or_else(|| corrupt("record body"))?;
        body += size;
        out.push(match t {
            0 => Value::Null,
            1..=6 => {
                // big-endian two's complement, sign-extended from `size` bytes
                let mut v: i64 = if d[0] & 0x80 != 0 { -1 } else { 0 };
                for &c in d {
                    v = (v << 8) | c as i64;
                }
                Value::Int(v)
            }
            7 => Value::Float(f64::from_bits(u64::from_be_bytes(d.try_into().unwrap()))),
            8 => Value::Int(0),
            9 => Value::Int(1),
            t if t % 2 == 0 => Value::Blob(Cow::Borrowed(d)),
            _ => Value::Text(match enc {
                TextEncoding::Utf8 => Cow::Borrowed(d),
                TextEncoding::Utf16Le | TextEncoding::Utf16Be => {
                    let units = d.chunks_exact(2).map(|c| {
                        if enc == TextEncoding::Utf16Le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) }
                    });
                    let s: String = char::decode_utf16(units).map(|r| r.unwrap_or('\u{FFFD}')).collect();
                    Cow::Owned(s.into_bytes())
                }
            }),
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// CREATE TABLE parsing
// ---------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum Tok {
    /// bare word, as written
    Word(String),
    /// quoted identifier / string, unquoted
    Quoted(String),
    /// any other character (parentheses of nested expressions, operators, ...)
    Punct(char),
}

/// `t` is the bare word `w` (SQL keywords are ASCII case-insensitive).
fn kw(t: Option<&Tok>, w: &str) -> bool {
    matches!(t, Some(Tok::Word(x)) if x.eq_ignore_ascii_case(w))
}

/// Split SQL into tokens, skipping whitespace and comments. `None` on an unterminated quote.
fn tokenize(sql: &str) -> Option<Vec<Tok>> {
    let c: Vec<char> = sql.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch == '-' && c.get(i + 1) == Some(&'-') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
        } else if ch == '/' && c.get(i + 1) == Some(&'*') {
            i += 2;
            while i < c.len() && !(c[i] == '*' && c.get(i + 1) == Some(&'/')) {
                i += 1;
            }
            i += 2;
        } else if matches!(ch, '"' | '`' | '\'' | '[') {
            let close = if ch == '[' { ']' } else { ch };
            let mut s = String::new();
            i += 1;
            loop {
                let x = *c.get(i)?;
                i += 1;
                if x == close {
                    // a doubled quote is an escaped quote (not inside [...])
                    if close != ']' && c.get(i) == Some(&close) {
                        s.push(close);
                        i += 1;
                        continue;
                    }
                    break;
                }
                s.push(x);
            }
            out.push(Tok::Quoted(s));
        } else if ch.is_alphanumeric() || ch == '_' || ch == '$' {
            let st = i;
            while i < c.len() && (c[i].is_alphanumeric() || c[i] == '_' || c[i] == '$') {
                i += 1;
            }
            out.push(Tok::Word(c[st..i].iter().collect()));
        } else {
            out.push(Tok::Punct(ch));
            i += 1;
        }
    }
    Some(out)
}

/// Parse `CREATE TABLE name (coldef, ..., constraint, ...) [WITHOUT ROWID]`:
/// (column names, rowid-alias column, is WITHOUT ROWID). `None` if there is no column list.
fn parse_create_table(sql: &str) -> Option<(Vec<String>, Option<usize>, bool)> {
    let toks = tokenize(sql)?;
    // split the first top-level parenthesized list on its depth-1 commas
    let open = toks.iter().position(|t| *t == Tok::Punct('('))?;
    let mut segs: Vec<&[Tok]> = Vec::new();
    let mut depth = 0usize;
    let mut seg_start = open + 1;
    let mut close = None;
    for (i, t) in toks.iter().enumerate().skip(open) {
        match t {
            Tok::Punct('(') => depth += 1,
            Tok::Punct(')') => {
                depth -= 1;
                if depth == 0 {
                    segs.push(&toks[seg_start..i]);
                    close = Some(i);
                    break;
                }
            }
            Tok::Punct(',') if depth == 1 => {
                segs.push(&toks[seg_start..i]);
                seg_start = i + 1;
            }
            _ => {}
        }
    }
    let tail = &toks[close? + 1..];
    let pk_at = |seg: &[Tok]| (0..seg.len()).find(|&p| kw(seg.get(p), "PRIMARY") && kw(seg.get(p + 1), "KEY"));
    let mut cols: Vec<String> = Vec::new();
    let mut int_cols: Vec<bool> = Vec::new();
    let mut alias = None;
    let mut table_pk: Vec<&str> = Vec::new();
    for seg in segs {
        let first = seg.first()?;
        let name = match first {
            Tok::Word(w) if ["CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN"].iter().any(|k| w.eq_ignore_ascii_case(k)) => {
                // table constraint; PRIMARY KEY (a) on an INTEGER column makes it the alias
                if let Some(p) = pk_at(seg) {
                    table_pk = seg[p + 2..]
                        .iter()
                        .take_while(|t| **t != Tok::Punct(')'))
                        .filter_map(|t| match t {
                            Tok::Word(w) if !["ASC", "DESC", "COLLATE"].iter().any(|k| w.eq_ignore_ascii_case(k)) => Some(w.as_str()),
                            Tok::Quoted(q) => Some(q.as_str()),
                            _ => None,
                        })
                        .collect();
                }
                continue;
            }
            Tok::Word(w) | Tok::Quoted(w) => w.clone(),
            Tok::Punct(_) => return None,
        };
        // declared type exactly "INTEGER" + column constraint PRIMARY KEY (but not
        // PRIMARY KEY DESC, an SQLite quirk) = alias for the rowid
        let int_type = kw(seg.get(1), "INTEGER") && !matches!(seg.get(2), Some(Tok::Word(w)) if !is_constraint_kw(w));
        if int_type && pk_at(seg).is_some_and(|p| !kw(seg.get(p + 2), "DESC")) {
            alias = Some(cols.len());
        }
        int_cols.push(int_type);
        cols.push(name);
    }
    if alias.is_none() && table_pk.len() == 1 {
        alias = cols.iter().position(|c| c.eq_ignore_ascii_case(table_pk[0])).filter(|&i| int_cols[i]);
    }
    let without_rowid = (0..tail.len()).any(|i| kw(tail.get(i), "WITHOUT") && kw(tail.get(i + 1), "ROWID"));
    Some((cols, if without_rowid { None } else { alias }, without_rowid))
}

fn is_constraint_kw(w: &str) -> bool {
    ["CONSTRAINT", "PRIMARY", "NOT", "NULL", "UNIQUE", "CHECK", "DEFAULT", "COLLATE", "REFERENCES", "GENERATED", "AS"]
        .iter()
        .any(|k| w.eq_ignore_ascii_case(k))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DB: &[u8] = include_bytes!("sqlite_test.db");
    const DB16: &[u8] = include_bytes!("sqlite_test16.db");

    #[test]
    fn identifier_cache_like_table() {
        let db = Database::from_bytes(DB.to_vec()).unwrap();
        assert_eq!(db.page_size(), 512);
        let t = db.table("CACHE").unwrap();
        assert_eq!(t.columns.len(), 10);
        assert_eq!(t.column("location"), Some(0));
        assert_eq!(t.column("cached"), Some(9));
        assert_eq!(t.rowid_alias, None);
        let rows = db.rows(&t).unwrap();
        // rowid order: 1..=40 without 5 and 10 (deleted / replaced), then 41 (the replacement)
        let ids: Vec<i64> = rows.iter().map(|r| r.rowid).collect();
        let mut want: Vec<i64> = (1..=40).filter(|&i| i != 5 && i != 10).collect();
        want.push(41);
        assert_eq!(ids, want);
        let r7 = &rows[5];
        assert_eq!(r7.rowid, 7);
        let loc = r7.values[0].as_str_lossy().unwrap().into_owned();
        assert_eq!(loc, format!("file:///long/{}.json.xz", "x".repeat(1500)));
        assert_eq!(r7.values[1], Value::Blob(Cow::Owned(b"\x07\x00\xffid|7".to_vec())));
        assert_eq!(r7.values[4], Value::Int(7));
        assert_eq!(r7.values[5], Value::Int(-7000));
        assert_eq!(r7.values[6], Value::Int((1 << 40) + 7));
        assert_eq!(r7.values[7], Value::Int(490000));
        assert_eq!(r7.values[8], Value::Int(0));
        assert_eq!(r7.values[9].as_text(), Some(&b"2026-09-26 00:50:13"[..]));
        let r3 = &rows[2];
        assert_eq!(r3.values[1], Value::Null); // 3 % 3 == 0 -> None
        assert_eq!(r3.values[2], Value::Null);
        let last = rows.last().unwrap();
        assert_eq!(last.values[0].as_text(), Some(&b"file:///sym/010.json"[..]));
        assert_eq!(last.values[1], Value::Blob(Cow::Owned(b"remote".to_vec())));
        assert_eq!(last.values[4], Value::Int(0)); // DEFAULT 0 was stored by sqlite
        assert_eq!(last.values[3], Value::Null);
        // early stop
        let mut n = 0;
        db.for_each_row(&t, |_, _| {
            n += 1;
            n < 3
        })
        .unwrap();
        assert_eq!(n, 3);
        let info = db.table("database_info").unwrap();
        assert_eq!(db.rows(&info).unwrap()[0].values, vec![Value::Int(1)]);
    }

    #[test]
    fn quoted_names_alias_and_types() {
        let db = Database::from_bytes(DB.to_vec()).unwrap();
        let t = db.table("we(ird").unwrap();
        assert_eq!(t.columns, vec!["a b", "c", "d", "e"]);
        assert_eq!(t.rowid_alias, Some(0));
        let rows = db.rows(&t).unwrap();
        assert_eq!(rows[0].rowid, -9);
        assert_eq!(rows[0].values[0], Value::Int(-9));
        assert_eq!(rows[0].values[1], Value::Float(-2.25e300));
        assert_eq!(rows[0].values[2], Value::Int(123456789012));
        assert_eq!(rows[0].values[3], Value::Null);
        assert_eq!(rows[1].values[0], Value::Int(5));
        assert_eq!(rows[1].values[1], Value::Float(1.5));
        assert_eq!(rows[1].values[2].as_text(), Some(&b"txt"[..]));
        assert_eq!(rows[1].values[3], Value::Blob(Cow::Owned(vec![0, 0xff])));
    }

    #[test]
    fn utf16_database() {
        let db = Database::from_bytes(DB16.to_vec()).unwrap();
        assert_eq!(db.encoding, TextEncoding::Utf16Le);
        let t = db.table("t").unwrap();
        let rows = db.rows(&t).unwrap();
        assert_eq!(rows[0].values[0].as_str_lossy().unwrap(), "h\u{e9}llo \u{20ac}");
        assert_eq!(rows[0].values[1], Value::Int(7));
    }

    #[test]
    fn create_table_parsing() {
        let (c, a, w) = parse_create_table("CREATE TABLE x(Id integer primary key desc, \"q\"\"x\" TEXT, y) WITHOUT ROWID").unwrap();
        assert_eq!(c, vec!["Id", "q\"x", "y"]);
        assert_eq!(a, None);
        assert!(w);
        let (c, a, _) = parse_create_table("create table t (k INTEGER, v DECIMAL(10, 5) DEFAULT (1,2), PRIMARY KEY (k))").unwrap();
        assert_eq!(c, vec!["k", "v"]);
        assert_eq!(a, Some(0));
        let (_, a, _) = parse_create_table("create table t (k INT PRIMARY KEY)").unwrap();
        assert_eq!(a, None);
        assert!(parse_create_table("CREATE TABLE t AS SELECT 1").is_none());
    }

    #[test]
    fn garbage_never_panics() {
        assert!(Database::from_bytes(Vec::new()).is_err());
        assert!(Database::from_bytes(b"SQLite format 3\0".to_vec()).is_err());
        let mut x: u64 = 0x2545f4914f6cdd1d;
        for round in 0..3000 {
            let mut d = DB.to_vec();
            for _ in 0..(1 + round % 8) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let i = (x as usize) % d.len();
                d[i] = (x >> 32) as u8;
            }
            if let Ok(db) = Database::from_bytes(d) {
                if let Ok(t) = db.table("cache") {
                    let _ = db.rows(&t);
                }
                let _ = db.schema();
            }
        }
        // truncated files
        for n in (0..DB.len()).step_by(97) {
            if let Ok(db) = Database::from_bytes(DB[..n].to_vec()) {
                if let Ok(t) = db.table("cache") {
                    let _ = db.rows(&t);
                }
            }
        }
    }
}
