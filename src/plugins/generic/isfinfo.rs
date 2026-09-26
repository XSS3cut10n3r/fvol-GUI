//! isfinfo.IsfInfo (python `plugins/isfinfo.py`, plus the parts of
//! `automagic/symbol_cache.py` (`SqliteCache`, `SymbolCacheMagic`) it depends on).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Default mode lists python's identifier cache (`CACHE_PATH/identifier.cache`, an SQLite
//! database): `get_identifier_dictionary()` is a table scan (rowid order) folded into a python
//! dict (first-insertion position, last value), and the rowid order comes from python set
//! iteration (hash-randomized) when the rows were inserted. So the only way to reproduce
//! python's output is to read python's own database (`util::sqlite`). Before the plugin runs,
//! python's `SymbolCacheMagic` automagic calls `SqliteCache.update()`, which we emulate in
//! memory (python's database is never written):
//!   * local rows whose location is no longer found on the symbol path are dropped;
//!   * rows cached before `date('now', '-3 days')` whose file (local mtime) is newer than the
//!     row's `cached` timestamp, and locations not in the table yet, are (re)inserted at the
//!     end (`INSERT OR REPLACE` = new rowid), in our deterministic order instead of python's
//!     random set order, with the identifier and `len()` statistics python would store;
//!   * `-u` remote identifier-list rows are re-inserted at the end.
//! Without a readable python database (absent, corrupt, other schema version) python starts
//! from an empty table, so every ISF is "new" and listed in our order.
//!
//! `--live` walks `symbols.__path__` like python's `os.walk` (readdir order) and parses every
//! ISF. Per-file results (JSON validity, statistics, identifier) are cached in
//! `~/.cache/rsvol/isfinfo.cache` keyed by URL + file size/mtime, so warm runs parse nothing.
//!
//! Known gaps: the `hash` column (sha1 of python's `json.dumps(sort_keys=True)`) is not
//! computed for rows we insert, so they never read "True (cached)" (python only records
//! validations when `jsonschema` is installed); files python itself fails on with an uncaught
//! exception (e.g. a corrupt `.xz` in `--live`, a bad zip) make python crash, we skip them.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{RowSink, Value};
use crate::symbols::store::{ISF_EXTENSIONS, IsfLocation, Root};
use crate::util::fxhash::FxHasher;
use crate::util::sqlite;
use crate::util::{FxHashMap, FxHashSet, paths};
use std::borrow::Cow;
use std::hash::Hasher;
use std::path::{Component, Path, PathBuf};

pub struct IsfInfo;

impl Plugin for IsfInfo {
    fn name(&self) -> &'static str {
        "isfinfo.IsfInfo"
    }
    fn description(&self) -> &'static str {
        "Determines information about the currently available ISF files, or a specific one"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("filter", "String that must be present in the file URI to display the ISF", ReqKind::ListStr)
                .optional()
                .default(ConfigValue::List(Vec::new())),
            Requirement::new("isf", "Specific ISF file to process", ReqKind::Uri).optional(),
            Requirement::flag("validate", "Validate against schema if possible"),
            Requirement::flag("live", "Traverse all files, rather than use the cache"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let roots = python_symbol_roots(ctx);
        let db_path = paths::vol3_cache_dir(ctx.opts.cache_path.as_deref()).join("identifier.cache");
        let mut summaries = SummaryCache::load();
        let mut table = if ctx.opts.clear_cache {
            // python's --clear-cache deletes identifier.cache before SymbolCacheMagic runs
            Vec::new()
        } else {
            let _t = crate::util::trace::span("isfinfo read identifier.cache");
            read_identifier_cache(&db_path)
        };
        {
            let _t = crate::util::trace::span("isfinfo SqliteCache.update");
            symbol_cache_update(&mut table, &roots, &mut summaries);
        }
        out.begin(crate::cols![
            ("URI", Str),
            ("Valid", Str),
            ("Number of base_types", Int),
            ("Number of types", Int),
            ("Number of symbols", Int),
            ("Number of enums", Int),
            ("Identifying information", Str),
        ])?;
        let r = if cfg.get_bool("live") {
            live_rows(cfg, &roots, &table, &mut summaries, out)
        } else {
            cached_rows(cfg.get_bool("validate"), &table, &mut summaries, out)
        };
        summaries.save();
        r
    }
}

/// The location python's `SqliteCache.get_identifier_dictionary()` maps `identifier` to (last
/// row wins, after the `SymbolCacheMagic` update), i.e. which of several ISFs with the same
/// banner / PDB identifier python loads -- its choice depends on the history of its SQLite cache.
/// `None` when python's database has no such identifier.
pub fn python_identifier_location(ctx: &Context, identifier: &[u8]) -> Option<String> {
    let db_path = paths::vol3_cache_dir(ctx.opts.cache_path.as_deref()).join("identifier.cache");
    let mut table = if ctx.opts.clear_cache { Vec::new() } else { read_identifier_cache(&db_path) };
    let mut summaries = SummaryCache::load();
    symbol_cache_update(&mut table, &python_symbol_roots(ctx), &mut summaries);
    summaries.save();
    table
        .iter()
        .rev()
        .find(|r| matches!(&r.identifier, sqlite::Value::Blob(b) | sqlite::Value::Text(b) if b.as_ref() == identifier))
        .map(|r| r.location.clone())
}

// ---------------------------------------------------------------------------------------------
// symbol path
// ---------------------------------------------------------------------------------------------

/// python `volatility3.symbols.__path__` (`-s` dirs, volatility3/symbols,
/// volatility3/framework/symbols, CACHE_PATH/symbols) from rsvol's search path: the python
/// install directories stand in for the embedded copies when python is installed.
fn python_symbol_roots(ctx: &Context) -> Vec<Root> {
    let have_python = crate::symbols::store::python_install().is_some();
    ctx.symbol_path()
        .roots
        .iter()
        .filter(|r| !(have_python && matches!(r, Root::Embedded { .. })))
        .map(|r| match r {
            Root::Dir(d) => Root::Dir(abspath(d)),
            r => r.clone(),
        })
        .collect()
}

/// python `os.path.abspath` for an absolute path: lexical `.`/`..` removal, no symlinks.
fn abspath(p: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for c in p.components() {
        match c {
            Component::Normal(x) => out.push(x),
            Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    out
}

/// Recursively list the files under `dir` (sorted; symlinked directories are not followed,
/// like pathlib's `rglob`).
fn walk_sorted(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        match e.file_type() {
            Ok(t) if t.is_dir() => walk_sorted(&e.path(), out),
            Ok(_) => out.push(e.path()),
            Err(_) => {}
        }
    }
}

/// python `IntermediateSymbolTable.file_symbol_url("")` (what `SqliteCache.update()` treats as
/// "on disk"), deduplicated, in a deterministic order (python iterates it as a set). Root
/// directories are `resolve()`d like python. `None` when python would raise (unreadable zip).
fn file_symbol_urls(roots: &[Root]) -> Option<Vec<(String, IsfLocation)>> {
    let mut out: Vec<(String, IsfLocation)> = Vec::new();
    let mut seen = FxHashSet::default();
    let mut push = |loc: IsfLocation, out: &mut Vec<(String, IsfLocation)>| {
        let u = loc.url();
        if seen.insert(u.clone()) {
            out.push((u, loc));
        }
    };
    for root in roots {
        match root {
            Root::Dir(d) => {
                let Ok(d) = std::fs::canonicalize(d) else { continue };
                let mut files = Vec::new();
                walk_sorted(&d, &mut files);
                for ext in ISF_EXTENSIONS {
                    for f in files.iter().filter(|f| f.as_os_str().as_encoded_bytes().ends_with(ext.as_bytes())) {
                        push(IsfLocation::File(f.clone()), &mut out);
                    }
                }
                for f in files.iter().filter(|f| f.as_os_str().as_encoded_bytes().ends_with(b".zip")) {
                    let names = crate::symbols::zipfile::list(f).ok()?;
                    for name in names {
                        for ext in ISF_EXTENSIONS {
                            if name.ends_with(ext) {
                                push(IsfLocation::Zip { zip: f.clone(), member: name.clone() }, &mut out);
                            }
                        }
                    }
                }
            }
            Root::Embedded { top } => {
                for &(rel, is_top, data) in crate::symbols::embedded::FILES {
                    if is_top == *top {
                        push(IsfLocation::Embedded { rel, top: *top, data }, &mut out);
                    }
                }
            }
        }
    }
    Some(out)
}

/// python `IsfInfo.list_all_isf_files()`: `os.walk(path, followlinks=True)` over every symbol
/// directory (top-down, entries in readdir order), a URI per matching extension.
fn list_all_isf_files(roots: &[Root]) -> Vec<String> {
    fn walk(dir: &Path, depth: u32, out: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        let mut dirs = Vec::new();
        let mut files = Vec::new();
        for e in rd {
            // python: an error while iterating the directory skips the whole directory
            let Ok(e) = e else { return };
            // DirEntry.is_dir() follows symlinks
            let is_dir = match e.file_type() {
                Ok(t) if t.is_symlink() => std::fs::metadata(e.path()).map(|m| m.is_dir()).unwrap_or(false),
                Ok(t) => t.is_dir(),
                Err(_) => false,
            };
            if is_dir { dirs.push(e.file_name()) } else { files.push(e.file_name()) }
        }
        for f in files {
            let path = dir.join(&f);
            let name = f.as_encoded_bytes();
            if name.ends_with(b"zip") {
                // python would crash on an unreadable zip; we skip it
                if let Ok(members) = crate::symbols::zipfile::list(&path) {
                    for m in members {
                        for ext in ISF_EXTENSIONS {
                            if m.ends_with(ext) {
                                out.push(format!("jar:file:{}!{}", path.display(), m));
                            }
                        }
                    }
                }
            } else {
                for ext in ISF_EXTENSIONS {
                    if name.ends_with(ext.as_bytes()) {
                        out.push(paths::path_to_file_uri(&path));
                    }
                }
            }
        }
        // followlinks=True: symlink loops end when the path gets too deep
        if depth < 40 {
            for d in dirs {
                walk(&dir.join(d), depth + 1, out);
            }
        }
    }
    let mut out = Vec::new();
    for root in roots {
        match root {
            Root::Dir(d) => walk(d, 0, &mut out),
            Root::Embedded { top } => {
                for &(rel, is_top, data) in crate::symbols::embedded::FILES {
                    if is_top == *top {
                        out.push(IsfLocation::Embedded { rel, top: *top, data }.url());
                    }
                }
            }
        }
    }
    out
}

/// The ISF a URI points at (python `ResourceAccessor().open(url)`).
fn location_of(url: &str) -> IsfLocation {
    if let Some(rest) = url.strip_prefix("jar:file:") {
        let parts: Vec<&str> = rest.split('!').collect();
        if parts.len() == 2 {
            return IsfLocation::Zip { zip: PathBuf::from(parts[0]), member: parts[1].to_string() };
        }
    }
    if url.starts_with("embedded:") {
        for &(rel, top, data) in crate::symbols::embedded::FILES {
            let loc = IsfLocation::Embedded { rel, top, data };
            if loc.url() == url {
                return loc;
            }
        }
    }
    IsfLocation::Url(url.to_string())
}

// ---------------------------------------------------------------------------------------------
// python's identifier cache (SqliteCache)
// ---------------------------------------------------------------------------------------------

/// One row of python's `cache` table.
#[derive(Clone, Debug)]
struct CacheRow {
    location: String,
    identifier: sqlite::Value<'static>,
    hash: sqlite::Value<'static>,
    /// stats_base_types, stats_types, stats_enums, stats_symbols
    stats: [sqlite::Value<'static>; 4],
    /// `local = 1`
    local: bool,
    cached: sqlite::Value<'static>,
}

/// Rows of python's `cache` table in rowid order; empty when python would (re)create the
/// database (missing, corrupt, unknown schema version).
fn read_identifier_cache(path: &Path) -> Vec<CacheRow> {
    let Ok(db) = sqlite::Database::open(path) else { return Vec::new() };
    // SqliteCache._connect_storage: a schema_version other than 1 recreates the database
    if let Ok(info) = db.table("database_info") {
        let mut first: Option<sqlite::Value<'static>> = None;
        let r = db.for_each_row(&info, |_, v| {
            first = Some(v[0].clone().into_owned());
            false
        });
        if r.is_err() || first.is_some_and(|v| !matches!(v, sqlite::Value::Int(1)) && v != sqlite::Value::Float(1.0)) {
            return Vec::new();
        }
    }
    let Ok(t) = db.table("cache") else { return Vec::new() };
    let cols: Vec<Option<usize>> = [
        "location",
        "identifier",
        "hash",
        "stats_base_types",
        "stats_types",
        "stats_enums",
        "stats_symbols",
        "local",
        "cached",
    ]
    .iter()
    .map(|c| t.column(c))
    .collect();
    if cols.iter().any(|c| c.is_none()) {
        return Vec::new();
    }
    let c: Vec<usize> = cols.into_iter().flatten().collect();
    let mut rows = Vec::new();
    let r = db.for_each_row(&t, |_, v| {
        let own = |i: usize| v[c[i]].clone().into_owned();
        let location = match &v[c[0]] {
            sqlite::Value::Text(t) | sqlite::Value::Blob(t) => String::from_utf8_lossy(t).into_owned(),
            sqlite::Value::Int(i) => i.to_string(),
            _ => String::new(),
        };
        let local = matches!(v[c[7]], sqlite::Value::Int(1)) || v[c[7]] == sqlite::Value::Float(1.0);
        rows.push(CacheRow {
            location,
            identifier: own(1),
            hash: own(2),
            stats: [own(3), own(4), own(5), own(6)],
            local,
            cached: own(8),
        });
        true
    });
    if r.is_err() {
        return Vec::new();
    }
    rows
}

/// A python `datetime` as (days since 1970-01-01, microseconds of the day), naive.
type NaiveTime = (i64, i64);

/// python `datetime.datetime.fromisoformat` for the forms sqlite's `datetime()` writes
/// (`YYYY-MM-DD[ HH:MM[:SS[.ffffff]]]`, `T` separator allowed). `None` = python raises.
fn fromisoformat(s: &[u8]) -> Option<NaiveTime> {
    let num = |b: &[u8]| -> Option<i64> {
        if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(b.iter().fold(0i64, |a, &c| a * 10 + (c - b'0') as i64))
    };
    let date = s.get(..10)?;
    if date[4] != b'-' || date[7] != b'-' {
        return None;
    }
    let (y, m, d) = (num(&date[..4])?, num(&date[5..7])?, num(&date[8..10])?);
    if !(1..=12).contains(&m) || d < 1 || d > crate::util::time::days_in_month(y, m as u32) as i64 || y < 1 {
        return None;
    }
    let days = crate::util::time::days_from_civil(y, m as u32, d as u32);
    let rest = &s[10..];
    if rest.is_empty() {
        return Some((days, 0));
    }
    if !matches!(rest[0], b' ' | b'T') {
        return None;
    }
    let t = &rest[1..];
    let (hms, frac) = match t.iter().position(|&c| c == b'.') {
        Some(p) => (&t[..p], Some(&t[p + 1..])),
        None => (t, None),
    };
    let parts: Vec<&[u8]> = hms.split(|&c| c == b':').collect();
    if !(parts.len() == 2 || parts.len() == 3) || parts.iter().any(|p| p.len() != 2) {
        return None;
    }
    let h = num(parts[0])?;
    let mi = num(parts[1])?;
    let sec = if parts.len() == 3 { num(parts[2])? } else { 0 };
    if h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    let mut us = 0;
    if let Some(f) = frac {
        if !(f.len() == 3 || f.len() == 6) || (parts.len() != 3) {
            return None;
        }
        us = num(f)? * if f.len() == 3 { 1000 } else { 1 };
    }
    Some((days, ((h * 60 + mi) * 60 + sec) * 1_000_000 + us))
}

/// python `datetime.datetime.fromtimestamp(os.stat(p).st_mtime)` (local time, naive).
fn mtime_local(p: &Path) -> Option<NaiveTime> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(p).ok()?;
    let t = md.mtime() as f64 + md.mtime_nsec() as f64 * 1e-9;
    let dt = crate::util::time::fromtimestamp_local(t).ok()?;
    Some((dt.secs.div_euclid(86400), dt.secs.rem_euclid(86400) * 1_000_000 + dt.micros as i64))
}

/// The local file behind a cache location, as `SqliteCache.update()` derives it
/// (`url2pathname` for file:, the zip path for jar:file:).
fn update_pathname(location: &str) -> Option<PathBuf> {
    // urlparse: optional //netloc, then the path up to ?query / #fragment
    fn url_path(rest: &str) -> &str {
        let rest = match rest.strip_prefix("//") {
            Some(r) => r.find('/').map(|i| &r[i..]).unwrap_or(""),
            None => rest,
        };
        rest.split(['?', '#']).next().unwrap_or("")
    }
    let scheme_end = location.find(':')?;
    let scheme = location[..scheme_end].to_ascii_lowercase();
    let rest = &location[scheme_end + 1..];
    match scheme.as_str() {
        "file" => Some(PathBuf::from(paths::unquote(url_path(rest)))),
        "jar" => {
            let inner = rest.get(..5).filter(|s| s.eq_ignore_ascii_case("file:")).map(|_| &rest[5..])?;
            Some(PathBuf::from(url_path(inner).split('!').next().unwrap_or("")))
        }
        _ => None,
    }
}

/// sqlite `x < date('now', '-3 days')` for a NUMERIC-affinity column value `x`.
fn cached_before(v: &sqlite::Value<'_>, cutoff: &str) -> bool {
    match v {
        sqlite::Value::Null | sqlite::Value::Blob(_) => false,
        sqlite::Value::Int(_) | sqlite::Value::Float(_) => true,
        sqlite::Value::Text(t) => t.as_ref() < cutoff.as_bytes(),
    }
}

fn utc_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// sqlite `date(t)`.
fn sql_date(t: i64) -> String {
    let (y, m, d) = crate::util::time::civil_from_days(t.div_euclid(86400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// sqlite `datetime(t)`.
fn sql_datetime(t: i64) -> String {
    let s = t.rem_euclid(86400);
    format!("{} {:02}:{:02}:{:02}", sql_date(t), s / 3600, s / 60 % 60, s % 60)
}

/// Emulate python's `SqliteCache.update()` (run by `SymbolCacheMagic` before every plugin) on
/// the in-memory table.
fn symbol_cache_update(rows: &mut Vec<CacheRow>, roots: &[Root], summaries: &mut SummaryCache) {
    let Some(on_disk) = file_symbol_urls(roots) else { return };
    let on_disk_set: FxHashSet<&str> = on_disk.iter().map(|(u, _)| u.as_str()).collect();
    let cached_local: FxHashSet<String> = rows.iter().filter(|r| r.local).map(|r| r.location.clone()).collect();
    // missing entries
    rows.retain(|r| !(cached_local.contains(&r.location) && !on_disk_set.contains(r.location.as_str())));
    // entries not updated for 3 days whose file changed since
    let now = utc_now();
    let mut stale: FxHashSet<&str> = FxHashSet::default();
    if on_disk.iter().any(|(u, _)| cached_local.contains(u)) {
        let cutoff = sql_date(now - 3 * 86400);
        for r in rows.iter().filter(|r| r.local && cached_before(&r.cached, &cutoff)) {
            let stored = match &r.cached {
                sqlite::Value::Text(t) => fromisoformat(t),
                _ => None,
            };
            // python: fromisoformat raising aborts the rest of update()
            let Some(stored) = stored else { return };
            let ts = update_pathname(&r.location).and_then(|p| mtime_local(&p)).unwrap_or(stored);
            if let Some(&u) = on_disk_set.get(r.location.as_str()) {
                if stored < ts {
                    stale.insert(u);
                }
            }
        }
    }
    let todo: Vec<usize> =
        (0..on_disk.len()).filter(|&i| !cached_local.contains(&on_disk[i].0) || stale.contains(on_disk[i].0.as_str())).collect();
    let locs: Vec<(&str, &IsfLocation)> = todo.iter().map(|&i| (on_disk[i].0.as_str(), &on_disk[i].1)).collect();
    let sums = summaries.get(&locs);
    let cached = sqlite::Value::Text(Cow::Owned(sql_datetime(now).into_bytes()));
    fn replace(rows: &mut Vec<CacheRow>, row: CacheRow) {
        // INSERT OR REPLACE: the old row (UNIQUE location) goes, the new one gets a new rowid
        if let Some(p) = rows.iter().position(|r| r.location == row.location) {
            rows.remove(p);
        }
        rows.push(row);
    }
    for ((url, _), s) in locs.iter().zip(sums) {
        let Summary::Json { stats: Some(st), row: Some((ident, _os)) } = s else { continue };
        let local = url.starts_with("file:") || url.starts_with("jar:");
        replace(rows, CacheRow {
            location: url.to_string(),
            identifier: ident.map_or(sqlite::Value::Null, |i| sqlite::Value::Blob(Cow::Owned(i))),
            hash: sqlite::Value::Null,
            stats: [0, 1, 2, 3].map(|k| sqlite::Value::Int(st[k] as i64)),
            local,
            cached: cached.clone(),
        });
    }
    // remote identifier lists (-u), unless --offline
    if let Some(url) = crate::symbols::remote_isf_url() {
        match crate::symbols::store::remote_identifiers(&url) {
            Ok(list) => {
                for (_os, ident, location) in list {
                    replace(rows, CacheRow {
                        location,
                        identifier: sqlite::Value::Blob(Cow::Owned(ident)),
                        hash: sqlite::Value::Null,
                        stats: [0, 1, 2, 3].map(|_| sqlite::Value::Int(0)),
                        local: false,
                        cached: cached.clone(),
                    });
                }
            }
            Err(e) => eprintln!("rsvol: remote ISF list {url}: {e}"),
        }
    }
}

/// A python dict key built from an `identifier` column value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum IdKey {
    Null,
    Int(i64),
    Float(u64),
    Text(Vec<u8>),
    Blob(Vec<u8>),
}

impl IdKey {
    fn of(v: &sqlite::Value<'_>) -> IdKey {
        match v {
            sqlite::Value::Null => IdKey::Null,
            sqlite::Value::Int(i) => IdKey::Int(*i),
            // 1.0 == 1 in a python dict
            sqlite::Value::Float(f) if f.fract() == 0.0 && f.abs() < 9.0e18 => IdKey::Int(*f as i64),
            sqlite::Value::Float(f) => IdKey::Float(f.to_bits()),
            sqlite::Value::Text(t) => IdKey::Text(t.to_vec()),
            sqlite::Value::Blob(b) => IdKey::Blob(b.to_vec()),
        }
    }
    fn truthy(&self) -> bool {
        match self {
            IdKey::Null => false,
            IdKey::Int(i) => *i != 0,
            IdKey::Float(f) => f64::from_bits(*f) != 0.0,
            IdKey::Text(t) | IdKey::Blob(t) => !t.is_empty(),
        }
    }
    /// python `str(identifier)`
    fn py_str(&self) -> String {
        match self {
            IdKey::Null => "None".into(),
            IdKey::Int(i) => i.to_string(),
            IdKey::Float(f) => {
                let mut o = Vec::new();
                crate::renderers::pyfmt::push_float(&mut o, f64::from_bits(*f));
                String::from_utf8_lossy(&o).into_owned()
            }
            IdKey::Text(t) => String::from_utf8_lossy(t).into_owned(),
            IdKey::Blob(b) => {
                let mut o = Vec::new();
                crate::renderers::pyfmt::push_bytes_repr(&mut o, b);
                String::from_utf8_lossy(&o).into_owned()
            }
        }
    }
}

/// A stats column value for an `int` column (python raises TypeError for anything else).
fn stat_value(v: &sqlite::Value<'_>, location: &str) -> Result<Value> {
    match v {
        sqlite::Value::Int(i) => Ok(Value::Int(*i as i128)),
        _ => Err(Error::msg(format!("TypeError: statistics of {location} are not integers"))),
    }
}

/// `schemas.cached_validations`: the JSON list in `CACHE_PATH/valid_isf.hashcache` (python
/// reads it at import time, before `--cache-path` applies).
fn cached_validations() -> FxHashSet<String> {
    let p = paths::vol3_cache_dir(None).join("valid_isf.hashcache");
    let Ok(b) = std::fs::read(p) else { return FxHashSet::default() };
    let Ok(j) = crate::util::json::Json::parse(&b) else { return FxHashSet::default() };
    j.as_array().unwrap_or(&[]).iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
}

/// The default (non-live) listing: `cache.get_identifier_dictionary()`.
fn cached_rows(validate: bool, rows: &[CacheRow], summaries: &mut SummaryCache, out: &mut dyn RowSink) -> Result<()> {
    let mut order: Vec<(IdKey, usize)> = Vec::new();
    let mut pos: FxHashMap<IdKey, usize> = FxHashMap::default();
    for (i, r) in rows.iter().enumerate() {
        let k = IdKey::of(&r.identifier);
        match pos.get(&k) {
            Some(&p) => order[p].1 = i,
            None => {
                pos.insert(k.clone(), order.len());
                order.push((k, i));
            }
        }
    }
    order.retain(|(k, _)| k.truthy());
    // --validate re-reads every listed ISF (jsonschema is absent: valid JSON -> "Unknown")
    let checks: Vec<Summary> = if validate {
        let locs: Vec<IsfLocation> = order.iter().map(|&(_, i)| location_of(&rows[i].location)).collect();
        let refs: Vec<(&str, &IsfLocation)> = order.iter().zip(&locs).map(|(&(_, i), l)| (rows[i].location.as_str(), l)).collect();
        summaries.get(&refs)
    } else {
        Vec::new()
    };
    let mut hashes: Option<FxHashSet<String>> = None;
    let mut valid = "Unknown";
    for (n, (k, i)) in order.iter().enumerate() {
        let r = &rows[*i];
        if let sqlite::Value::Text(h) = &r.hash {
            if !h.is_empty() && hashes.get_or_insert_with(cached_validations).contains(String::from_utf8_lossy(h).as_ref()) {
                valid = "True (cached)";
            }
        }
        if validate {
            match &checks[n] {
                Summary::Unreadable => return Err(Error::msg(format!("cannot open {}", r.location))),
                Summary::BadJson => {} // python logs "Invalid ISF" and keeps `valid`
                Summary::Json { .. } => valid = "Unknown",
            }
        }
        let [base, types, enums, symbols] = &r.stats;
        out.row(0, vec![
            Value::Str(r.location.clone()),
            Value::SStr(valid),
            stat_value(base, &r.location)?,
            stat_value(types, &r.location)?,
            stat_value(symbols, &r.location)?,
            stat_value(enums, &r.location)?,
            Value::Str(k.py_str()),
        ])?;
    }
    Ok(())
}

/// `--live`: parse every ISF (or `--isf`), filtered by `--filter`.
fn live_rows(cfg: &Config, roots: &[Root], rows: &[CacheRow], summaries: &mut SummaryCache, out: &mut dyn RowSink) -> Result<()> {
    let files = match cfg.get_str("isf") {
        Some(u) => vec![u.to_string()],
        None => list_all_isf_files(roots),
    };
    let filters = cfg.get_strs("filter");
    let entries: Vec<String> = if filters.is_empty() {
        files
    } else {
        // python appends a file once per matching filter item
        files.iter().flat_map(|f| filters.iter().filter(|x| f.contains(x.as_str())).map(move |_| f.clone())).collect()
    };
    let mut by_loc: FxHashMap<&str, &sqlite::Value<'static>> = FxHashMap::default();
    for r in rows {
        by_loc.entry(r.location.as_str()).or_insert(&r.identifier);
    }
    let locs: Vec<IsfLocation> = entries.iter().map(|u| location_of(u)).collect();
    let refs: Vec<(&str, &IsfLocation)> = entries.iter().map(|u| u.as_str()).zip(&locs).collect();
    let sums = summaries.get(&refs);
    for (entry, s) in entries.iter().zip(sums) {
        // invalid JSON: python warns and skips; other failures crash python, we skip them
        let Summary::Json { stats: Some([base, types, enums, symbols]), .. } = s else { continue };
        let ident = match by_loc.get(entry.as_str()) {
            Some(sqlite::Value::Blob(b) | sqlite::Value::Text(b)) if !b.is_empty() => Value::Str(String::from_utf8_lossy(b).into_owned()),
            Some(v @ (sqlite::Value::Int(_) | sqlite::Value::Float(_))) if IdKey::of(v).truthy() => Value::Str(IdKey::of(v).py_str()),
            _ => Value::NotAvailable,
        };
        out.row(0, vec![
            Value::Str(entry.clone()),
            Value::SStr("Unknown"),
            Value::Int(base as i128),
            Value::Int(types as i128),
            Value::Int(symbols as i128),
            Value::Int(enums as i128),
            ident,
        ])?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// per-file summaries (python json.load + what update() / --live derive from it), cached
// ---------------------------------------------------------------------------------------------

const OS_NONE: u8 = 0;
const OS_WINDOWS: u8 = 1;
const OS_MAC: u8 = 2;
const OS_LINUX: u8 = 3;

/// What python learns from one ISF.
#[derive(Clone, Debug, PartialEq)]
enum Summary {
    /// opening / decompressing raised
    Unreadable,
    /// `json.load` raised UnicodeDecodeError / JSONDecodeError
    BadJson,
    /// valid JSON
    Json {
        /// `len()` of base_types, user_types, enums, symbols (0 when absent); `None` when the
        /// document is not an object or a `len()` raises TypeError
        stats: Option<[u64; 4]>,
        /// the row `SqliteCache.update()` inserts: (identifier, operating system); `None` when
        /// update() raises for this file (no row)
        row: Option<(Option<Vec<u8>>, u8)>,
    },
}

fn summarize_location(loc: &IsfLocation) -> Summary {
    match loc.read() {
        Ok(data) => summarize(&data),
        Err(_) => Summary::Unreadable,
    }
}

/// `~/.cache/rsvol/isfinfo.cache`: URL -> (file stamp, summary). Read on first use only (a
/// default run with an up-to-date python database needs no summaries at all).
struct SummaryCache {
    map: Option<FxHashMap<String, (u64, Summary)>>,
    dirty: bool,
}

const CACHE_MAGIC: &[u8; 8] = b"RSISFI01";

impl SummaryCache {
    fn path() -> PathBuf {
        paths::rsvol_cache_dir().join("isfinfo.cache")
    }

    fn load() -> SummaryCache {
        SummaryCache { map: None, dirty: false }
    }

    fn save(&self) {
        if self.dirty {
            self.save_to(&Self::path());
        }
    }

    fn read(path: &Path) -> FxHashMap<String, (u64, Summary)> {
        let mut map = FxHashMap::default();
        if let Ok(b) = std::fs::read(path) {
            if b.starts_with(CACHE_MAGIC) {
                let mut r = Reader { b: &b, i: 8 };
                while let Some(e) = r.entry() {
                    map.insert(e.0, (e.1, e.2));
                }
            }
        }
        map
    }

    #[cfg(test)]
    fn load_from(path: &Path) -> SummaryCache {
        SummaryCache { map: Some(Self::read(path)), dirty: false }
    }

    fn save_to(&self, path: &Path) {
        let mut b = CACHE_MAGIC.to_vec();
        for (url, (stamp, s)) in self.map.iter().flatten() {
            put_bytes(&mut b, url.as_bytes());
            b.extend_from_slice(&stamp.to_le_bytes());
            match s {
                Summary::Unreadable => b.push(0),
                Summary::BadJson => b.push(1),
                Summary::Json { stats, row } => {
                    b.push(2);
                    match stats {
                        Some(st) => {
                            b.push(1);
                            for v in st {
                                b.extend_from_slice(&v.to_le_bytes());
                            }
                        }
                        None => b.push(0),
                    }
                    match row {
                        None => b.push(0),
                        Some((ident, os)) => {
                            b.push(1);
                            b.push(*os);
                            match ident {
                                Some(i) => {
                                    b.push(1);
                                    put_bytes(&mut b, i);
                                }
                                None => b.push(0),
                            }
                        }
                    }
                }
            }
        }
        let _ = paths::write_atomic(path, &b);
    }

    /// Summaries for `locs` (url, location), computing the missing / outdated ones in parallel.
    fn get(&mut self, locs: &[(&str, &IsfLocation)]) -> Vec<Summary> {
        if locs.is_empty() {
            return Vec::new();
        }
        let map = self.map.get_or_insert_with(|| Self::read(&Self::path()));
        let stamps: Vec<Option<u64>> = locs.iter().map(|(u, l)| stamp(u, l)).collect();
        let mut out: Vec<Option<Summary>> = locs
            .iter()
            .zip(&stamps)
            .map(|((u, _), st)| match (map.get(*u), st) {
                (Some((s0, sum)), Some(s)) if s0 == s => Some(sum.clone()),
                _ => None,
            })
            .collect();
        let todo: Vec<usize> = (0..locs.len()).filter(|&i| out[i].is_none()).collect();
        // bounded: each item may hold a decompressed 50-200 MB ISF
        let fresh = crate::util::par::par_map_bounded(todo.len(), 8, |k| summarize_location(locs[todo[k]].1));
        for (k, s) in todo.into_iter().zip(fresh) {
            if let Some(st) = stamps[k] {
                map.insert(locs[k].0.to_string(), (st, s.clone()));
                self.dirty = true;
            }
            out[k] = Some(s);
        }
        out.into_iter().map(|s| s.unwrap_or(Summary::Unreadable)).collect()
    }
}

/// Cache identity of an ISF: URL + (size, mtime) of the file (or zip / executable) behind it.
/// `None` (never cached) for remote URLs.
fn stamp(url: &str, loc: &IsfLocation) -> Option<u64> {
    let file = match loc {
        IsfLocation::File(p) => p.clone(),
        IsfLocation::Zip { zip, .. } => zip.clone(),
        IsfLocation::Url(u) => paths::file_uri_to_path(u)?,
        IsfLocation::Embedded { .. } => std::env::current_exe().ok()?,
    };
    let (size, mtime) = paths::file_stamp(&file)?;
    let mut h = FxHasher::default();
    h.write(url.as_bytes());
    h.write_u64(size);
    h.write_u64(mtime as u64);
    Some(h.finish())
}

fn put_bytes(b: &mut Vec<u8>, s: &[u8]) {
    b.extend_from_slice(&(s.len() as u32).to_le_bytes());
    b.extend_from_slice(s);
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.i..self.i.checked_add(n)?)?;
        self.i += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        self.take(n)
    }
    fn entry(&mut self) -> Option<(String, u64, Summary)> {
        let url = String::from_utf8(self.bytes()?.to_vec()).ok()?;
        let stamp = self.u64()?;
        let s = match self.u8()? {
            0 => Summary::Unreadable,
            1 => Summary::BadJson,
            2 => {
                let stats = match self.u8()? {
                    1 => Some([self.u64()?, self.u64()?, self.u64()?, self.u64()?]),
                    _ => None,
                };
                let row = match self.u8()? {
                    1 => {
                        let os = self.u8()?;
                        let ident = match self.u8()? {
                            1 => Some(self.bytes()?.to_vec()),
                            _ => None,
                        };
                        Some((ident, os))
                    }
                    _ => None,
                };
                Summary::Json { stats, row }
            }
            _ => return None,
        };
        Some((url, stamp, s))
    }
}

// ---------------------------------------------------------------------------------------------
// python json semantics
// ---------------------------------------------------------------------------------------------

/// python `bytes.decode(json.detect_encoding(b))`: the document as UTF-8 bytes, `None` for a
/// UnicodeDecodeError.
fn py_json_text(b: &[u8]) -> Option<Cow<'_, [u8]>> {
    fn utf16(b: &[u8], le: bool) -> Option<Cow<'static, [u8]>> {
        if b.len() % 2 != 0 {
            return None;
        }
        let units = b.chunks_exact(2).map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) });
        let s: String = char::decode_utf16(units).collect::<std::result::Result<_, _>>().ok()?;
        Some(Cow::Owned(s.into_bytes()))
    }
    fn utf32(b: &[u8], le: bool) -> Option<Cow<'static, [u8]>> {
        if b.len() % 4 != 0 {
            return None;
        }
        let mut s = String::with_capacity(b.len() / 4);
        for c in b.chunks_exact(4) {
            let a = [c[0], c[1], c[2], c[3]];
            s.push(char::from_u32(if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })?);
        }
        Some(Cow::Owned(s.into_bytes()))
    }
    if b.starts_with(&[0, 0, 0xFE, 0xFF]) {
        return utf32(&b[4..], false);
    }
    if b.starts_with(&[0xFF, 0xFE, 0, 0]) {
        return utf32(&b[4..], true);
    }
    if b.starts_with(&[0xFE, 0xFF]) {
        return utf16(&b[2..], false);
    }
    if b.starts_with(&[0xFF, 0xFE]) {
        return utf16(&b[2..], true);
    }
    let b = b.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(b);
    if b.len() >= 4 {
        if b[0] == 0 {
            return if b[1] != 0 { utf16(b, false) } else { utf32(b, false) };
        }
        if b[1] == 0 {
            return if b[2] != 0 || b[3] != 0 { utf16(b, true) } else { utf32(b, true) };
        }
    } else if b.len() == 2 {
        if b[0] == 0 {
            return utf16(b, false);
        }
        if b[1] == 0 {
            return utf16(b, true);
        }
    }
    std::str::from_utf8(b).ok().map(|_| Cow::Borrowed(b))
}

/// A python str decoded from JSON: WTF-8 bytes (lone surrogates from `\uXXXX` escapes are
/// kept, as python does, as 3-byte sequences).
#[derive(Clone, Debug, PartialEq)]
struct PyStr<'a> {
    b: Cow<'a, [u8]>,
    lone_surrogate: bool,
}

impl PyStr<'_> {
    fn as_str(&self) -> Option<&str> {
        if self.lone_surrogate { None } else { std::str::from_utf8(&self.b).ok() }
    }
}

/// A JSON value with python semantics (dicts keep the first position and the last value of
/// duplicate keys).
#[derive(Clone, Debug, PartialEq)]
enum PyVal<'a> {
    Null,
    Bool(bool),
    /// canonical decimal text (python int)
    Int(String),
    Float(f64),
    Str(PyStr<'a>),
    List(Vec<PyVal<'a>>),
    Dict(Vec<(PyStr<'a>, PyVal<'a>)>),
}

impl<'a> PyVal<'a> {
    fn truthy(&self) -> bool {
        match self {
            PyVal::Null => false,
            PyVal::Bool(b) => *b,
            PyVal::Int(s) => s != "0",
            PyVal::Float(f) => *f != 0.0,
            PyVal::Str(s) => !s.b.is_empty(),
            PyVal::List(l) => !l.is_empty(),
            PyVal::Dict(d) => !d.is_empty(),
        }
    }
    /// `dict.get(key)` (`None` also for non-dicts; callers check the type first)
    fn get(&self, key: &str) -> Option<&PyVal<'a>> {
        match self {
            PyVal::Dict(d) => d.iter().find(|(k, _)| k.b.as_ref() == key.as_bytes()).map(|(_, v)| v),
            _ => None,
        }
    }
    /// python `repr(v)`; `None` for strings holding lone surrogates (not reproduced).
    fn repr(&self) -> Option<String> {
        Some(match self {
            PyVal::Null => "None".into(),
            PyVal::Bool(b) => if *b { "True" } else { "False" }.into(),
            PyVal::Int(s) => s.clone(),
            PyVal::Float(f) => {
                let mut o = Vec::new();
                crate::renderers::pyfmt::push_float(&mut o, *f);
                String::from_utf8(o).ok()?
            }
            PyVal::Str(s) => crate::renderers::pyfmt::str_repr(s.as_str()?),
            PyVal::List(l) => format!("[{}]", l.iter().map(|v| v.repr()).collect::<Option<Vec<_>>>()?.join(", ")),
            PyVal::Dict(d) => format!(
                "{{{}}}",
                d.iter().map(|(k, v)| Some(format!("{}: {}", crate::renderers::pyfmt::str_repr(k.as_str()?), v.repr()?))).collect::<Option<Vec<_>>>()?.join(", ")
            ),
        })
    }
    /// python `str(v)`
    fn py_str(&self) -> Option<String> {
        match self {
            PyVal::Str(s) => s.as_str().map(str::to_string),
            v => v.repr(),
        }
    }
}

/// `len()` of a JSON value (`None` = TypeError).
type Len = Option<u64>;

/// The top level of an ISF as far as python's cache / isfinfo look at it.
#[derive(Default)]
struct Top<'a> {
    metadata: Option<PyVal<'a>>,
    /// base_types, user_types, enums, symbols; `None` = key absent
    lens: [Option<Len>; 4],
    /// the (last) "symbols" value is an object
    symbols_dict: Option<bool>,
    version: Option<PyVal<'a>>,
    linux_banner: Option<PyVal<'a>>,
}

/// Strict JSON scanner with python `json` (C scanner, strict=True) acceptance rules.
struct Scan<'a> {
    b: &'a [u8],
    i: usize,
}

type R<T> = std::result::Result<T, ()>;

impl<'a> Scan<'a> {
    #[inline]
    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.b.get(self.i) {
            self.i += 1;
        }
    }
    #[inline]
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    #[inline]
    fn eat(&mut self, c: u8) -> R<()> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    /// A string at '"': (raw content, has escapes). Validates escapes; control characters
    /// are errors (python strict mode).
    fn string(&mut self) -> R<(&'a [u8], bool)> {
        self.eat(b'"')?;
        let st = self.i;
        let mut esc = false;
        loop {
            match *self.b.get(self.i).ok_or(())? {
                b'"' => {
                    let s = &self.b[st..self.i];
                    self.i += 1;
                    return Ok((s, esc));
                }
                b'\\' => {
                    esc = true;
                    match *self.b.get(self.i + 1).ok_or(())? {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => self.i += 2,
                        b'u' => {
                            let h = self.b.get(self.i + 2..self.i + 6).ok_or(())?;
                            if !h.iter().all(u8::is_ascii_hexdigit) {
                                return Err(());
                            }
                            self.i += 6;
                        }
                        _ => return Err(()),
                    }
                }
                0..=0x1f => return Err(()),
                _ => self.i += 1,
            }
        }
    }

    /// A number (python NUMBER_RE `-?(0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?`): (text, is float).
    fn number(&mut self) -> R<(&'a [u8], bool)> {
        let st = self.i;
        let digit = |s: &Self, k: usize| s.b.get(k).is_some_and(u8::is_ascii_digit);
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while digit(self, self.i) {
                    self.i += 1;
                }
            }
            _ => return Err(()),
        }
        let mut float = false;
        if self.peek() == Some(b'.') && digit(self, self.i + 1) {
            self.i += 1;
            while digit(self, self.i) {
                self.i += 1;
            }
            float = true;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let mut k = self.i + 1;
            if matches!(self.b.get(k), Some(b'+' | b'-')) {
                k += 1;
            }
            if digit(self, k) {
                self.i = k;
                while digit(self, self.i) {
                    self.i += 1;
                }
                float = true;
            }
        }
        Ok((&self.b[st..self.i], float))
    }

    /// A literal or number.
    fn scalar(&mut self) -> R<PyVal<'a>> {
        let rest = &self.b[self.i..];
        for (lit, v) in [
            (&b"null"[..], PyVal::Null),
            (b"true", PyVal::Bool(true)),
            (b"false", PyVal::Bool(false)),
            (b"NaN", PyVal::Float(f64::NAN)),
            (b"Infinity", PyVal::Float(f64::INFINITY)),
            (b"-Infinity", PyVal::Float(f64::NEG_INFINITY)),
        ] {
            if rest.starts_with(lit) {
                self.i += lit.len();
                return Ok(v);
            }
        }
        let (t, float) = self.number()?;
        let t = std::str::from_utf8(t).map_err(|_| ())?;
        Ok(if float {
            PyVal::Float(t.parse().map_err(|_| ())?)
        } else if t.bytes().all(|c| c == b'0' || c == b'-') {
            PyVal::Int("0".into())
        } else {
            PyVal::Int(t.to_string())
        })
    }

    /// Skip any value, validating it (iterative: no recursion limit issues).
    fn skip_value(&mut self) -> R<()> {
        let mut stack: Vec<bool> = Vec::new(); // true = object
        loop {
            self.ws();
            match self.peek().ok_or(())? {
                b'{' => {
                    self.i += 1;
                    self.ws();
                    if self.peek() == Some(b'}') {
                        self.i += 1;
                    } else {
                        self.string()?;
                        self.ws();
                        self.eat(b':')?;
                        stack.push(true);
                        continue;
                    }
                }
                b'[' => {
                    self.i += 1;
                    self.ws();
                    if self.peek() == Some(b']') {
                        self.i += 1;
                    } else {
                        stack.push(false);
                        continue;
                    }
                }
                b'"' => {
                    self.string()?;
                }
                _ => {
                    self.scalar()?;
                }
            }
            // after a complete value: close finished containers, or move to the next item
            loop {
                let Some(&obj) = stack.last() else { return Ok(()) };
                self.ws();
                match self.peek() {
                    Some(b',') => {
                        self.i += 1;
                        if obj {
                            self.ws();
                            self.string()?;
                            self.ws();
                            self.eat(b':')?;
                        }
                        break;
                    }
                    Some(b'}') if obj => {
                        self.i += 1;
                        stack.pop();
                    }
                    Some(b']') if !obj => {
                        self.i += 1;
                        stack.pop();
                    }
                    _ => return Err(()),
                }
            }
        }
    }

    /// Iterate an object's members: `f(scan, raw key, key has escapes)` must consume the value.
    fn members(&mut self, mut f: impl FnMut(&mut Self, &'a [u8], bool) -> R<()>) -> R<()> {
        self.eat(b'{')?;
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.ws();
            let (k, esc) = self.string()?;
            self.ws();
            self.eat(b':')?;
            self.ws();
            f(self, k, esc)?;
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(()),
            }
        }
    }

    /// Build a python value (small parts of the document only: metadata, a symbol entry).
    fn dom(&mut self, depth: u32) -> R<PyVal<'a>> {
        if depth > 500 {
            return Err(());
        }
        self.ws();
        match self.peek().ok_or(())? {
            b'{' => {
                let mut d: Vec<(PyStr<'a>, PyVal<'a>)> = Vec::new();
                self.members(|s, k, esc| {
                    let k = py_str_decode(k, esc);
                    let v = s.dom(depth + 1)?;
                    match d.iter_mut().find(|(x, _)| *x == k) {
                        Some(e) => e.1 = v,
                        None => d.push((k, v)),
                    }
                    Ok(())
                })?;
                Ok(PyVal::Dict(d))
            }
            b'[' => {
                self.i += 1;
                let mut l = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(PyVal::List(l));
                }
                loop {
                    l.push(self.dom(depth + 1)?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(PyVal::List(l));
                        }
                        _ => return Err(()),
                    }
                }
            }
            b'"' => {
                let (s, esc) = self.string()?;
                Ok(PyVal::Str(py_str_decode(s, esc)))
            }
            _ => self.scalar(),
        }
    }

    /// `len()` of the next value. When `members` is given, the last value of each of those
    /// object members is captured as a python value (for "symbols": "version", "linux_banner").
    fn measure(&mut self, mut capture: Option<&mut [(&str, Option<PyVal<'a>>)]>) -> R<Len> {
        match self.peek().ok_or(())? {
            b'{' => {
                // python dicts count distinct keys
                let mut keys: FxHashSet<Cow<'a, [u8]>> = FxHashSet::default();
                self.members(|s, k, esc| {
                    let key = if esc { py_str_decode(k, true).b } else { Cow::Borrowed(k) };
                    match capture.as_deref_mut().and_then(|c| c.iter_mut().find(|(n, _)| n.as_bytes() == key.as_ref())) {
                        Some(slot) => slot.1 = Some(s.dom(0)?),
                        None => s.skip_value()?,
                    }
                    keys.insert(key);
                    Ok(())
                })?;
                Ok(Some(keys.len() as u64))
            }
            b'[' => {
                self.i += 1;
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Some(0));
                }
                let mut n = 0u64;
                loop {
                    self.skip_value()?;
                    n += 1;
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Some(n));
                        }
                        _ => return Err(()),
                    }
                }
            }
            b'"' => {
                let (s, esc) = self.string()?;
                let d = py_str_decode(s, esc);
                // code points (UTF-8 lead bytes; WTF-8 lone surrogates count once too)
                Ok(Some(d.b.iter().filter(|&&c| c & 0xC0 != 0x80).count() as u64))
            }
            _ => {
                self.scalar()?;
                Ok(None)
            }
        }
    }

    /// The whole document: `Some(top)` for an object, `None` for another valid value.
    fn document(&mut self) -> R<Option<Top<'a>>> {
        self.ws();
        let mut out = None;
        if self.peek() == Some(b'{') {
            let mut top = Top::default();
            self.members(|s, k, esc| {
                let key = if esc { py_str_decode(k, true).b } else { Cow::Borrowed(k) };
                // duplicate keys: the last one wins, like a python dict
                match key.as_ref() {
                    b"metadata" => top.metadata = Some(s.dom(0)?),
                    b"base_types" => top.lens[0] = Some(s.measure(None)?),
                    b"user_types" => top.lens[1] = Some(s.measure(None)?),
                    b"enums" => top.lens[2] = Some(s.measure(None)?),
                    b"symbols" => {
                        top.symbols_dict = Some(s.peek() == Some(b'{'));
                        let mut cap = [("version", None), ("linux_banner", None)];
                        top.lens[3] = Some(s.measure(Some(&mut cap))?);
                        let [(_, v), (_, l)] = cap;
                        top.version = v;
                        top.linux_banner = l;
                    }
                    _ => s.skip_value()?,
                }
                Ok(())
            })?;
            out = Some(top);
        } else {
            self.skip_value()?;
        }
        self.ws();
        if self.i != self.b.len() {
            return Err(()); // "Extra data"
        }
        Ok(out)
    }
}

/// Decode a JSON string body like python (escapes, surrogate pairs; lone surrogates kept).
fn py_str_decode(raw: &[u8], esc: bool) -> PyStr<'_> {
    if !esc {
        return PyStr { b: Cow::Borrowed(raw), lone_surrogate: false };
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut lone = false;
    let hex = |s: &[u8]| -> u32 { s.iter().fold(0u32, |a, &c| a * 16 + (c as char).to_digit(16).unwrap_or(0)) };
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if c != b'\\' || i + 1 >= raw.len() {
            out.push(c);
            i += 1;
            continue;
        }
        let e = raw[i + 1];
        i += 2;
        let ch: u32 = match e {
            b'b' => 8,
            b'f' => 12,
            b'n' => 10,
            b'r' => 13,
            b't' => 9,
            b'u' if i + 4 <= raw.len() => {
                let mut cp = hex(&raw[i..i + 4]);
                i += 4;
                if (0xD800..0xDC00).contains(&cp) && raw.get(i..i + 2) == Some(b"\\u") && i + 6 <= raw.len() {
                    let lo = hex(&raw[i + 2..i + 6]);
                    if (0xDC00..0xE000).contains(&lo) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        i += 6;
                    }
                }
                cp
            }
            other => other as u32,
        };
        match char::from_u32(ch) {
            Some(c) => {
                let mut t = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut t).as_bytes());
            }
            None => {
                // lone surrogate: generalized UTF-8 (WTF-8)
                lone = true;
                out.extend_from_slice(&[0xE0 | (ch >> 12) as u8, 0x80 | ((ch >> 6) & 0x3F) as u8, 0x80 | (ch & 0x3F) as u8]);
            }
        }
    }
    PyStr { b: Cow::Owned(out), lone_surrogate: lone }
}

/// python 3.14 `base64.b64decode(s)` (non-strict `binascii.a2b_base64`); `None` = python
/// raises. Characters outside the alphabet are skipped and '=' does not end the input; at the
/// end a partial quad of 2-3 characters needs enough '=' after its last data character
/// ("Incorrect padding" otherwise), a single leftover character is always an error.
fn py_b64decode(s: &PyStr<'_>) -> Option<Vec<u8>> {
    if !s.b.is_ascii() {
        return None; // "string argument should contain only ASCII characters"
    }
    let mut out = Vec::with_capacity(s.b.len() * 3 / 4);
    let (mut quad, mut left, mut pads) = (0u8, 0u8, 0usize);
    for &c in s.b.iter() {
        if c == b'=' {
            pads += 1;
            continue;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        pads = 0;
        match quad {
            0 => {
                quad = 1;
                left = v;
            }
            1 => {
                quad = 2;
                out.push((left << 2) | (v >> 4));
                left = v & 0x0f;
            }
            2 => {
                quad = 3;
                out.push((left << 4) | (v >> 2));
                left = v & 0x03;
            }
            _ => {
                quad = 0;
                out.push((left << 6) | v);
                left = 0;
            }
        }
    }
    match quad {
        0 => Some(out),
        1 => None,
        q if q as usize + pads >= 4 => Some(out),
        _ => None,
    }
}

/// python `bytes(s, "latin-1")`.
fn latin1(s: &str) -> Option<Vec<u8>> {
    s.chars().map(|c| u8::try_from(c as u32).ok()).collect()
}

/// `SqliteCache.update()` for one parsed document: (identifier, os) or `Err` where python
/// raises (the file then gets no row). `stats` were already checked.
fn cache_row(top: &Top<'_>) -> R<(Option<Vec<u8>>, u8)> {
    // schemas.create_json_hash: input.get("metadata", {}).get("format", None), "schema-" + format
    let meta = match &top.metadata {
        None => None,
        Some(m @ PyVal::Dict(_)) => Some(m),
        Some(_) => return Err(()),
    };
    if let Some(f) = meta.and_then(|m| m.get("format")) {
        if f.truthy() && !matches!(f, PyVal::Str(_)) {
            return Err(());
        }
    }
    // WindowsIdentifier: json.get("metadata", {}).get("windows", {}).get("pdb", {})
    let windows = match meta.and_then(|m| m.get("windows")) {
        None => None,
        Some(w @ PyVal::Dict(_)) => Some(w),
        Some(_) => return Err(()),
    };
    if let Some(pdb) = windows.and_then(|w| w.get("pdb")).filter(|p| p.truthy()) {
        if !matches!(pdb, PyVal::Dict(_)) {
            return Err(());
        }
        let (guid, age, db) = (pdb.get("GUID"), pdb.get("age"), pdb.get("database"));
        if let (Some(guid), Some(age), Some(db)) = (guid, age, db) {
            if guid.truthy() && age.truthy() && db.truthy() {
                // "|".join([pdb_name, guid.upper(), str(age)]) then latin-1
                let PyVal::Str(g) = guid else { return Err(()) };
                let g = g.as_str().ok_or(())?.to_uppercase();
                let a = age.py_str().ok_or(())?;
                let PyVal::Str(d) = db else { return Err(()) };
                let d = d.as_str().ok_or(())?;
                return Ok((Some(latin1(&format!("{d}|{g}|{a}")).ok_or(())?), OS_WINDOWS));
            }
        }
    }
    // MacIdentifier / LinuxIdentifier: json.get("symbols", {}).get(name, {}).get("constant_data")
    if top.symbols_dict == Some(false) {
        return Err(());
    }
    for (v, os) in [(&top.version, OS_MAC), (&top.linux_banner, OS_LINUX)] {
        let cd = match v {
            None => None,
            Some(d @ PyVal::Dict(_)) => d.get("constant_data"),
            Some(_) => return Err(()),
        };
        if let Some(cd) = cd.filter(|c| c.truthy()) {
            let PyVal::Str(s) = cd else { return Err(()) };
            return Ok((Some(py_b64decode(s).ok_or(())?), os));
        }
    }
    Ok((None, OS_NONE))
}

/// Everything python derives from one ISF's bytes (after decompression).
fn summarize(data: &[u8]) -> Summary {
    let Some(text) = py_json_text(data) else { return Summary::BadJson };
    let mut s = Scan { b: &text, i: 0 };
    let top = match s.document() {
        Ok(t) => t,
        Err(()) => return Summary::BadJson,
    };
    let Some(top) = top else { return Summary::Json { stats: None, row: None } };
    let mut st = [0u64; 4];
    let mut ok = true;
    for (k, l) in top.lens.iter().enumerate() {
        match l {
            None => {}
            Some(Some(n)) => st[k] = *n,
            Some(None) => ok = false,
        }
    }
    if !ok {
        return Summary::Json { stats: None, row: None };
    }
    Summary::Json { stats: Some(st), row: cache_row(&top).ok() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sum(j: &str) -> Summary {
        summarize(j.as_bytes())
    }

    #[test]
    fn stats_and_identifiers() {
        let j = r#"{"metadata": {"format": "6.2.0", "windows": {"pdb": {"GUID": "8e33ab", "age": 1, "database": "ntkrnlmp.pdb"}}},
            "base_types": {"a": 1, "b": 2, "a": 3}, "user_types": {}, "enums": {"e": {}}, "symbols": {"x": {}, "y": {}}}"#;
        assert_eq!(sum(j), Summary::Json { stats: Some([2, 0, 1, 2]), row: Some((Some(b"ntkrnlmp.pdb|8E33AB|1".to_vec()), OS_WINDOWS)) });
        // mac before linux, python base64 semantics (junk skipped)
        let j = r#"{"symbols": {"linux_banner": {"constant_data": "TGludXg="}, "version": {"constant_data": "RGFy\nd2lu"}}}"#;
        assert_eq!(sum(j), Summary::Json { stats: Some([0, 0, 0, 2]), row: Some((Some(b"Darwin".to_vec()), OS_MAC)) });
        let j = r#"{"symbols": {"linux_banner": {"constant_data": "TGludXg="}}}"#;
        assert_eq!(sum(j), Summary::Json { stats: Some([0, 0, 0, 1]), row: Some((Some(b"Linux".to_vec()), OS_LINUX)) });
        // incorrect padding -> update() raises -> no row, but --live still lists it
        let j = r#"{"symbols": {"linux_banner": {"constant_data": "TGludXg"}}, "enums": [1, 2, 3]}"#;
        assert_eq!(sum(j), Summary::Json { stats: Some([0, 0, 3, 1]), row: None });
        // len() of a str counts code points; of a number raises
        assert_eq!(sum(r#"{"user_types": "h\u00e9\ud83d\ude00"}"#), Summary::Json { stats: Some([0, 3, 0, 0]), row: Some((None, OS_NONE)) });
        assert_eq!(sum(r#"{"user_types": 5}"#), Summary::Json { stats: None, row: None });
        // metadata not a dict: create_json_hash raises
        assert_eq!(sum(r#"{"metadata": [], "symbols": {}}"#), Summary::Json { stats: Some([0; 4]), row: None });
        // str(age) of a float, lower-case guid upper-cased
        let j = r#"{"metadata": {"windows": {"pdb": {"GUID": "ab", "age": 2.5, "database": "x.pdb"}}}}"#;
        assert_eq!(sum(j), Summary::Json { stats: Some([0; 4]), row: Some((Some(b"x.pdb|AB|2.5".to_vec()), OS_WINDOWS)) });
        // not an object
        assert_eq!(sum("[1]"), Summary::Json { stats: None, row: None });
    }

    #[test]
    fn python_json_acceptance() {
        for bad in ["", "{", "{\"a\": 1,}", "[1,]", "{} x", "[01]", "[1.]", "[\"\t\"]", "[\"\\x\"]", "{'a': 1}", "[.5]", "[-]"] {
            assert_eq!(sum(bad), Summary::BadJson, "{bad:?}");
        }
        for good in ["[NaN, Infinity, -Infinity, 1e5, -0, 0.5E-3]", " \n{}\r\n", "\u{feff}{}", "[\"\\ud800\"]"] {
            assert!(matches!(sum(good), Summary::Json { .. }), "{good:?}");
        }
        // utf-16 with BOM
        let mut b = vec![0xFF, 0xFE];
        for u in "{\"symbols\": {\"a\": 1}}".encode_utf16() {
            b.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(summarize(&b), Summary::Json { stats: Some([0, 0, 0, 1]), row: Some((None, OS_NONE)) });
        assert_eq!(summarize(b"{\"a\": \"\xff\"}"), Summary::BadJson);
    }

    #[test]
    fn b64_like_python() {
        let p = |s: &str| py_b64decode(&PyStr { b: Cow::Borrowed(s.as_bytes()), lone_surrogate: false });
        assert_eq!(p("TGludXg="), Some(b"Linux".to_vec()));
        // python 3.14.7 results
        assert_eq!(p("TGludXg=junk"), None);
        assert_eq!(p("TGludXg=j"), Some(b"Linux#".to_vec()));
        assert_eq!(p("TGlu dXg=="), Some(b"Linux".to_vec()));
        assert_eq!(p("TGludXg"), None);
        assert_eq!(p("T"), None);
        assert_eq!(p(""), Some(Vec::new()));
        assert_eq!(p("=TGl="), Some(b"Li".to_vec()));
        assert_eq!(p("TG==TG=="), Some(b"Ld\xc6".to_vec()));
        assert_eq!(p("TG=\n="), Some(b"L".to_vec()));
        assert_eq!(p("TG=l"), None);
        assert_eq!(p("TG=x="), Some(b"Ll".to_vec()));
        assert_eq!(p("AB=C="), Some(b"\x00\x10".to_vec()));
        assert_eq!(p("A="), None);
    }

    #[test]
    fn isoformat_and_paths() {
        assert_eq!(fromisoformat(b"1970-01-02 00:00:01"), Some((1, 1_000_000)));
        assert_eq!(fromisoformat(b"2026-09-26"), Some((crate::util::time::days_from_civil(2026, 9, 26), 0)));
        assert_eq!(fromisoformat(b"2026-02-30 00:00:00"), None);
        assert_eq!(fromisoformat(b"garbage"), None);
        assert_eq!(update_pathname("file:///a%20b/c.json"), Some(PathBuf::from("/a b/c.json")));
        assert_eq!(update_pathname("jar:file:/z/p.zip!x/y.json"), Some(PathBuf::from("/z/p.zip")));
        assert_eq!(update_pathname("https://x/y"), None);
        assert!(cached_before(&sqlite::Value::Text(Cow::Borrowed(b"2026-09-21 23:59:59")), "2026-09-22"));
        assert!(!cached_before(&sqlite::Value::Text(Cow::Borrowed(b"2026-09-22 00:00:00")), "2026-09-22"));
        assert_eq!(sql_datetime(86400 + 3661), "1970-01-02 01:01:01");
        assert_eq!(abspath(Path::new("/a/./b/../c/")), PathBuf::from("/a/c"));
    }

    #[test]
    fn summary_cache_roundtrip() {
        let entries = [
            Summary::Unreadable,
            Summary::BadJson,
            Summary::Json { stats: None, row: None },
            Summary::Json { stats: Some([1, 2, 3, u64::MAX]), row: Some((None, OS_NONE)) },
            Summary::Json { stats: Some([0; 4]), row: Some((Some(b"a\x00b".to_vec()), OS_LINUX)) },
        ];
        let mut map = FxHashMap::default();
        for (i, e) in entries.iter().enumerate() {
            map.insert(format!("u{i}"), (i as u64, e.clone()));
        }
        let c = SummaryCache { map: Some(map), dirty: true };
        let tmp = std::env::temp_dir().join(format!("rsvol-isfinfo-test-{}.cache", std::process::id()));
        c.save_to(&tmp);
        let back = SummaryCache::load_from(&tmp).map.unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(back.len(), entries.len());
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(&back[&format!("u{i}")], &(i as u64, e.clone()));
        }
    }
}
