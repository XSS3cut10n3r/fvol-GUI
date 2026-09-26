//! python volatility3's identifier cache: the SQLite database `CACHE_PATH/identifier.cache`
//! written by `automagic/symbol_cache.py` (`SqliteCache`), read with `util::sqlite`, and its
//! `update()` (run by the `SymbolCacheMagic` automagic before every plugin) emulated in memory.
//! python's database is never written.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! python resolves an identifier (a Linux / Mac banner, a Windows `pdb|GUID|age`) through
//! `get_identifier_dictionary(os)` / `find_location()`: a table scan in rowid order where the
//! LAST row with the identifier wins. The rowids are the history of the database: `INSERT OR
//! REPLACE` gives a (re)scanned file a new, highest rowid, and python scans new files in
//! hash-randomized set order. So among several ISFs with the same identifier (`x.json` next to
//! `x.json.xz`, one kernel in two symbol packs) only python's database says which one python
//! loads.
//!
//! `update()` as emulated by [`update`]:
//!   * "on disk" = `IntermediateSymbolTable.file_symbol_url("")` over `symbols.__path__`: each
//!     root `resolve()`d, an rglob per ISF extension, zip members as `jar:file:` URLs
//!     ([`file_symbol_urls`]);
//!   * local rows (`local = 1`) whose location is not on disk are deleted;
//!   * when some on-disk location has a local row: rows with `cached < date('now', '-3 days')`
//!     (a string comparison; `cached` is sqlite `datetime('now')`, UTC) whose file's
//!     `datetime.fromtimestamp(st_mtime)` (LOCAL time, naive) is later than `cached` (UTC,
//!     naive: python compares the two as they are) are rescanned. A `cached` value that
//!     `datetime.fromisoformat` rejects makes python's update() raise right there (the
//!     deletions stay, nothing else happens);
//!   * new and rescanned locations are read (`json.load` + the identifier processors) and
//!     `INSERT OR REPLACE`d at the end, in our deterministic order (python: set order). A file
//!     python fails to read keeps its old row (a new one gets none);
//!   * `-u` remote identifier lists (unless `--offline`) are `INSERT OR REPLACE`d at the end.
//!
//! A database python cannot open, or of another schema version, is recreated empty by python;
//! [`read`] returns `None` for it (callers decide what "empty" means for them).

use super::store::{ISF_EXTENSIONS, IsfLocation, Root, SymbolPath};
use crate::util::sqlite;
use crate::util::{FxHashMap, FxHashSet, paths};
use std::borrow::Cow;
use std::path::{Component, Path, PathBuf};

/// python's identifier cache file for `--cache-path` (`constants.CACHE_PATH` after the CLI
/// applied it, joined to `IDENTIFIERS_FILENAME`).
pub fn db_path(cache_path: Option<&str>) -> PathBuf {
    paths::vol3_cache_dir(cache_path).join("identifier.cache")
}

// ---------------------------------------------------------------------------------------------
// reading the database
// ---------------------------------------------------------------------------------------------

/// One row of python's `cache` table.
#[derive(Clone, Debug)]
pub struct CacheRow {
    pub location: String,
    pub identifier: sqlite::Value<'static>,
    pub operating_system: sqlite::Value<'static>,
    pub hash: sqlite::Value<'static>,
    /// stats_base_types, stats_types, stats_enums, stats_symbols
    pub stats: [sqlite::Value<'static>; 4],
    /// `local = 1`
    pub local: bool,
    pub cached: sqlite::Value<'static>,
}

impl CacheRow {
    /// The identifier as python's dictionary key would match a banner / PDB identifier (a
    /// `bytes` value: BLOB).
    pub fn identifier_bytes(&self) -> Option<&[u8]> {
        match &self.identifier {
            sqlite::Value::Blob(b) => Some(b),
            _ => None,
        }
    }

    /// `operating_system` as `WHERE operating_system = '<os>'` compares it.
    pub fn os(&self) -> Option<&str> {
        match &self.operating_system {
            sqlite::Value::Text(t) => std::str::from_utf8(t).ok(),
            _ => None,
        }
    }
}

/// Rows of python's `cache` table in rowid order; `None` when python would (re)create the
/// database (missing, unreadable, corrupt, another schema version, another table layout).
pub fn read(path: &Path) -> Option<Vec<CacheRow>> {
    let db = sqlite::Database::open(path).ok()?;
    // SqliteCache._connect_storage: a schema_version other than 1 recreates the database
    if let Ok(info) = db.table("database_info") {
        let mut first: Option<sqlite::Value<'static>> = None;
        let r = db.for_each_row(&info, |_, v| {
            first = v.first().map(|x| x.clone().into_owned());
            false
        });
        if r.is_err() || first.is_some_and(|v| !matches!(v, sqlite::Value::Int(1)) && v != sqlite::Value::Float(1.0)) {
            return None;
        }
    }
    let t = db.table("cache").ok()?;
    let c: Vec<usize> = [
        "location",
        "identifier",
        "hash",
        "stats_base_types",
        "stats_types",
        "stats_enums",
        "stats_symbols",
        "local",
        "cached",
        "operating_system",
    ]
    .iter()
    .map(|c| t.column(c))
    .collect::<Option<_>>()?;
    let mut rows = Vec::new();
    db.for_each_row(&t, |_, v| {
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
            operating_system: own(9),
            hash: own(2),
            stats: [own(3), own(4), own(5), own(6)],
            local,
            cached: own(8),
        });
        true
    })
    .ok()?;
    Some(rows)
}

// ---------------------------------------------------------------------------------------------
// symbol path
// ---------------------------------------------------------------------------------------------

/// python `volatility3.symbols.__path__` (`-s` dirs, volatility3/symbols,
/// volatility3/framework/symbols, CACHE_PATH/symbols) from rsvol's search path: the python
/// install directories stand in for the embedded copies when python is installed.
pub fn python_symbol_roots(sp: &SymbolPath) -> Vec<Root> {
    let have_python = super::store::python_install_cached().is_some();
    sp.roots
        .iter()
        .filter(|r| !(have_python && matches!(r, Root::Embedded { .. })))
        .map(|r| match r {
            Root::Dir(d) => Root::Dir(abspath(d)),
            r => r.clone(),
        })
        .collect()
}

/// python `os.path.abspath` for an absolute path: lexical `.`/`..` removal, no symlinks.
pub fn abspath(p: &Path) -> PathBuf {
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
pub fn file_symbol_urls(roots: &[Root]) -> Option<Vec<(String, IsfLocation)>> {
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
                    let names = super::zipfile::list(f).ok()?;
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
                for &(rel, is_top, data) in super::embedded::FILES {
                    if is_top == *top {
                        push(IsfLocation::Embedded { rel, top: *top, data }, &mut out);
                    }
                }
            }
        }
    }
    Some(out)
}

/// The ISF a URI points at (python `ResourceAccessor().open(url)`).
pub fn location_of(url: &str) -> IsfLocation {
    if let Some(rest) = url.strip_prefix("jar:file:") {
        let parts: Vec<&str> = rest.split('!').collect();
        if parts.len() == 2 {
            return IsfLocation::Zip { zip: PathBuf::from(parts[0]), member: parts[1].to_string() };
        }
    }
    if url.starts_with("embedded:") {
        for &(rel, top, data) in super::embedded::FILES {
            let loc = IsfLocation::Embedded { rel, top, data };
            if loc.url() == url {
                return loc;
            }
        }
    }
    // a file:// URL python wrote (`Path.as_uri()`) round-trips through the path
    if let Some(p) = paths::file_uri_to_path(url)
        && paths::path_to_file_uri(&p) == url
    {
        return IsfLocation::File(p);
    }
    IsfLocation::Url(url.to_string())
}

// ---------------------------------------------------------------------------------------------
// time: python datetime / sqlite date functions
// ---------------------------------------------------------------------------------------------

/// A python `datetime` as (days since 1970-01-01, microseconds of the day), naive.
pub type NaiveTime = (i64, i64);

/// python `datetime.datetime.fromisoformat` for the forms sqlite's `datetime()` writes
/// (`YYYY-MM-DD[ HH:MM[:SS[.ffffff]]]`, `T` separator allowed). `None` = python raises.
pub fn fromisoformat(s: &[u8]) -> Option<NaiveTime> {
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
pub fn mtime_local(p: &Path) -> Option<NaiveTime> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(p).ok()?;
    let t = md.mtime() as f64 + md.mtime_nsec() as f64 * 1e-9;
    let dt = crate::util::time::fromtimestamp_local(t).ok()?;
    Some((dt.secs.div_euclid(86400), dt.secs.rem_euclid(86400) * 1_000_000 + dt.micros as i64))
}

/// The local file behind a cache location, as `SqliteCache.update()` derives it
/// (`url2pathname` for file:, the zip path for jar:file:).
pub fn update_pathname(location: &str) -> Option<PathBuf> {
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
pub fn cached_before(v: &sqlite::Value<'_>, cutoff: &str) -> bool {
    match v {
        sqlite::Value::Null | sqlite::Value::Blob(_) => false,
        sqlite::Value::Int(_) | sqlite::Value::Float(_) => true,
        sqlite::Value::Text(t) => t.as_ref() < cutoff.as_bytes(),
    }
}

/// Seconds since the epoch (sqlite `'now'`).
pub fn utc_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// sqlite `date(t)`.
pub fn sql_date(t: i64) -> String {
    let (y, m, d) = crate::util::time::civil_from_days(t.div_euclid(86400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// sqlite `datetime(t)`.
pub fn sql_datetime(t: i64) -> String {
    let s = t.rem_euclid(86400);
    format!("{} {:02}:{:02}:{:02}", sql_date(t), s / 3600, s / 60 % 60, s % 60)
}

/// The first time (seconds since the epoch, UTC) at which `update()` re-examines a row
/// cached at `cached` (`cached < date(now - 3 days)` holds from then on).
pub fn rescan_window_opens(cached: NaiveTime) -> i64 {
    (cached.0 + 4) * 86400
}

// ---------------------------------------------------------------------------------------------
// SqliteCache.update()
// ---------------------------------------------------------------------------------------------

/// What python stores for one new / rescanned ISF it could read.
#[derive(Clone, Debug, PartialEq)]
pub struct Scanned {
    pub identifier: Option<Vec<u8>>,
    /// "windows" / "mac" / "linux" (the processor that found the identifier)
    pub os: Option<&'static str>,
    /// `len()` of base_types, user_types, enums, symbols (0 when not computed)
    pub stats: [i64; 4],
}

/// Facts about an emulated update.
#[derive(Debug, Default)]
pub struct Updated {
    /// URL -> location of every ISF on disk (python's `on_disk_locations`)
    pub on_disk: FxHashMap<String, IsfLocation>,
    /// Rows (by location) kept from python's database as python trusts them (not rescanned).
    pub trusted: FxHashSet<String>,
}

/// python's `SqliteCache.update()` on the in-memory `rows` (rowid order) at time `now`
/// (seconds, UTC), for the symbol path `roots` and the `-u` identifier list `remote`.
/// `process(todo)` reads the new and stale ISFs in `todo` (url, location), returning per file
/// what python stores, or `None` where python's read raises (no row / the old row stays).
pub fn update<F>(rows: &mut Vec<CacheRow>, roots: &[Root], now: i64, remote: Option<&str>, process: F) -> Updated
where
    F: FnOnce(&[(&str, &IsfLocation)]) -> Vec<Option<Scanned>>,
{
    let mut info = Updated::default();
    // file_symbol_url raising (a bad zip) aborts update() before it changes anything
    let Some(on_disk) = file_symbol_urls(roots) else {
        info.trusted = rows.iter().map(|r| r.location.clone()).collect();
        return info;
    };
    let on_disk_set: FxHashSet<&str> = on_disk.iter().map(|(u, _)| u.as_str()).collect();
    let cached_local: FxHashSet<String> = rows.iter().filter(|r| r.local).map(|r| r.location.clone()).collect();
    // missing entries
    rows.retain(|r| !(cached_local.contains(&r.location) && !on_disk_set.contains(r.location.as_str())));
    let finish = |rows: &Vec<CacheRow>, stale: &FxHashSet<&str>, mut info: Updated| {
        info.trusted = rows.iter().filter(|r| !stale.contains(r.location.as_str())).map(|r| r.location.clone()).collect();
        info.on_disk = on_disk.iter().map(|(u, l)| (u.clone(), l.clone())).collect();
        info
    };
    // entries not updated for 3 days whose file changed since
    let mut stale: FxHashSet<&str> = FxHashSet::default();
    if on_disk.iter().any(|(u, _)| cached_local.contains(u)) {
        let cutoff = sql_date(now - 3 * 86400);
        for r in rows.iter().filter(|r| r.local && cached_before(&r.cached, &cutoff)) {
            let stored = match &r.cached {
                sqlite::Value::Text(t) => fromisoformat(t),
                _ => None,
            };
            // python: fromisoformat raising aborts the rest of update()
            let Some(stored) = stored else { return finish(rows, &FxHashSet::default(), info) };
            let ts = update_pathname(&r.location).and_then(|p| mtime_local(&p)).unwrap_or(stored);
            if let Some(&u) = on_disk_set.get(r.location.as_str()) {
                if stored < ts {
                    stale.insert(u);
                }
            }
        }
    }
    let todo: Vec<(&str, &IsfLocation)> =
        on_disk.iter().filter(|(u, _)| !cached_local.contains(u) || stale.contains(u.as_str())).map(|(u, l)| (u.as_str(), l)).collect();
    let scanned = if todo.is_empty() { Vec::new() } else { process(&todo) };
    let cached = sqlite::Value::Text(Cow::Owned(sql_datetime(now).into_bytes()));
    let text = |s: Option<&str>| s.map_or(sqlite::Value::Null, |s| sqlite::Value::Text(Cow::Owned(s.as_bytes().to_vec())));
    let mut stayed = FxHashSet::default();
    let mut inserted = Vec::with_capacity(todo.len());
    for ((url, _), s) in todo.iter().zip(scanned) {
        let Some(s) = s else {
            stayed.insert(*url);
            continue;
        };
        let local = url.starts_with("file:") || url.starts_with("jar:");
        inserted.push(CacheRow {
            location: url.to_string(),
            identifier: s.identifier.map_or(sqlite::Value::Null, |i| sqlite::Value::Blob(Cow::Owned(i))),
            operating_system: text(s.os),
            hash: sqlite::Value::Null,
            stats: s.stats.map(sqlite::Value::Int),
            local,
            cached: cached.clone(),
        });
    }
    insert_or_replace(rows, inserted);
    // a stale row python failed to re-read stays as it was (and stale)
    stale.retain(|u| !stayed.contains(u));
    let rescanned: FxHashSet<&str> = todo.iter().map(|(u, _)| *u).filter(|u| !stayed.contains(u)).collect();
    // remote identifier lists (-u), unless --offline
    let mut remote_locs = FxHashSet::default();
    if let Some(url) = remote {
        match super::store::remote_identifiers(url) {
            Ok(list) => {
                let inserted = list
                    .into_iter()
                    .map(|(os, ident, location)| {
                        remote_locs.insert(location.clone());
                        CacheRow {
                            location,
                            identifier: sqlite::Value::Blob(Cow::Owned(ident)),
                            operating_system: sqlite::Value::Text(Cow::Owned(os.into_bytes())),
                            hash: sqlite::Value::Null,
                            stats: [0, 1, 2, 3].map(|_| sqlite::Value::Int(0)),
                            local: false,
                            cached: cached.clone(),
                        }
                    })
                    .collect();
                insert_or_replace(rows, inserted);
            }
            Err(e) => eprintln!("rsvol: remote ISF list {url}: {e}"),
        }
    }
    let mut info = finish(rows, &stale, info);
    info.trusted.retain(|l| !rescanned.contains(l.as_str()) && !remote_locs.contains(l));
    info
}

/// `INSERT OR REPLACE` of each of `new`, in order: a row with the same (UNIQUE) location goes,
/// the new one gets a new, highest rowid. In one pass: the old rows without the inserted
/// locations, then the inserted rows, each location at its last insertion.
fn insert_or_replace(rows: &mut Vec<CacheRow>, new: Vec<CacheRow>) {
    if new.is_empty() {
        return;
    }
    let mut last: FxHashMap<&str, usize> = FxHashMap::default();
    for (i, r) in new.iter().enumerate() {
        last.insert(r.location.as_str(), i);
    }
    rows.retain(|r| !last.contains_key(r.location.as_str()));
    let keep: Vec<bool> = new.iter().enumerate().map(|(i, r)| last[r.location.as_str()] == i).collect();
    rows.extend(new.into_iter().zip(keep).filter(|(_, k)| *k).map(|(r, _)| r));
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(location_of("file:///a%20b/c.json.xz"), IsfLocation::File(PathBuf::from("/a b/c.json.xz")));
        assert_eq!(location_of("jar:file:/z/p.zip!x/y.json"), IsfLocation::Zip { zip: PathBuf::from("/z/p.zip"), member: "x/y.json".into() });
        assert_eq!(location_of("https://h/x.json"), IsfLocation::Url("https://h/x.json".into()));
        // not what as_uri() writes: kept verbatim
        assert_eq!(location_of("file://localhost/x.json"), IsfLocation::Url("file://localhost/x.json".into()));
    }

    #[test]
    fn insert_or_replace_is_sequential_upsert() {
        let row = |l: &str, id: &str| CacheRow {
            location: l.into(),
            identifier: sqlite::Value::Blob(Cow::Owned(id.as_bytes().to_vec())),
            operating_system: sqlite::Value::Null,
            hash: sqlite::Value::Null,
            stats: [0, 1, 2, 3].map(|_| sqlite::Value::Int(0)),
            local: true,
            cached: sqlite::Value::Null,
        };
        let show = |rows: &[CacheRow]| rows.iter().map(|r| format!("{}{}", r.location, String::from_utf8_lossy(r.identifier_bytes().unwrap()))).collect::<Vec<_>>();
        let new = || vec![row("b", "1"), row("d", "2"), row("b", "3"), row("a", "4")];
        // one row at a time, as sqlite does
        let mut seq = vec![row("a", "0"), row("b", "0"), row("c", "0")];
        for n in new() {
            if let Some(p) = seq.iter().position(|r| r.location == n.location) {
                seq.remove(p);
            }
            seq.push(n);
        }
        let mut batch = vec![row("a", "0"), row("b", "0"), row("c", "0")];
        insert_or_replace(&mut batch, new());
        assert_eq!(show(&batch), show(&seq));
        assert_eq!(show(&batch), vec!["c0", "d2", "b3", "a4"]);
    }

    #[test]
    fn rescan_window() {
        // cached 2026-09-20 23:59:59: `cached < date(now - 3 days)` first holds on 2026-09-24
        let c = fromisoformat(b"2026-09-20 23:59:59").unwrap();
        let open = rescan_window_opens(c);
        assert!(!cached_before(&sqlite::Value::Text(Cow::Borrowed(b"2026-09-20 23:59:59")), &sql_date(open - 1 - 3 * 86400)));
        assert!(cached_before(&sqlite::Value::Text(Cow::Borrowed(b"2026-09-20 23:59:59")), &sql_date(open - 3 * 86400)));
        assert_eq!(sql_datetime(open), "2026-09-24 00:00:00");
    }
}
