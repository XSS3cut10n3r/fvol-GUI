//! ISF discovery (python `IntermediateSymbolTable.file_symbol_url`, `symbol_cache`,
//! `pdbutil.load_windows_symbol_table`), decompression, and the binary table cache.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Search order (python `volatility3.symbols.__path__`):
//!   1. `-s/--symbol-dirs` directories,
//!   2. `<directory of the rsvol binary>/symbols` (like a frozen python executable),
//!   3. the ISFs shipped with volatility3 (embedded in the binary: `volatility3/symbols/**`
//!      then `volatility3/framework/symbols/**`),
//!   4. python's download cache `~/.cache/volatility3/symbols` (so existing downloads are
//!      reused; new PDB conversions are written there too).
//!
//! Every loaded table is cached as a flat blob in `~/.cache/rsvol/isf/<key>.isfb`
//! (key = source URL + size + mtime + natives), so a warm load is one mmap.

use super::isf::{BuildOptions, build_blob};
use super::table::{Blob, SymbolTable};
use crate::error::{Error, Result};
use crate::util::fxhash::{FxHasher, hash_bytes};
use crate::util::json::Json;
use crate::util::mmap::Mmap;
use crate::util::paths;
use std::hash::Hasher;
use std::path::{Path, PathBuf};

/// ISF file extensions in python's preference order (`constants.ISF_EXTENSIONS`).
pub const ISF_EXTENSIONS: [&str; 4] = [".json", ".json.xz", ".json.gz", ".json.bz2"];

/// Where an ISF lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IsfLocation {
    /// A file on disk (possibly compressed, by extension).
    File(PathBuf),
    /// A member of a zip symbol pack.
    Zip { zip: PathBuf, member: String },
    /// Shipped with volatility3 and embedded in the binary.
    Embedded { rel: &'static str, top: bool, data: &'static [u8] },
    /// A location from a remote identifier list (python `-u/--remote-isf-url`), kept verbatim:
    /// `file://...` is read in place, anything else (http/https/ftp) is downloaded once and
    /// cached in `~/.cache/rsvol/remote` (python: `CACHE_PATH/data_<sha512>.cache`).
    Url(String),
}

impl IsfLocation {
    /// python-style URL (`file:///...`, `jar:file:/path!member`, or `embedded:` for shipped
    /// files, which python would report from its install directory).
    pub fn url(&self) -> String {
        match self {
            IsfLocation::File(p) => paths::path_to_file_uri(p),
            IsfLocation::Zip { zip, member } => format!("jar:file:{}!{}", zip.display(), member),
            IsfLocation::Url(u) => u.clone(),
            IsfLocation::Embedded { rel, top, .. } => {
                if *top {
                    format!("embedded:///volatility3/symbols/{rel}")
                } else {
                    format!("embedded:///volatility3/framework/symbols/{rel}")
                }
            }
        }
    }

    /// The (decompressed) JSON bytes.
    pub fn read(&self) -> Result<std::borrow::Cow<'static, [u8]>> {
        match self {
            IsfLocation::Embedded { data, .. } => Ok(std::borrow::Cow::Borrowed(*data)),
            IsfLocation::File(p) => {
                let raw = std::fs::read(p)?;
                Ok(std::borrow::Cow::Owned(decompress_by_name(&p.to_string_lossy(), raw)?))
            }
            IsfLocation::Zip { zip, member } => {
                let raw = super::zipfile::read_member(zip, member)?;
                Ok(std::borrow::Cow::Owned(decompress_by_name(member, raw)?))
            }
            IsfLocation::Url(u) => {
                let raw = std::fs::read(url_local_path(u)?)?;
                // python without python-magic: decompress by the URL path's extension
                let path = u.split(['?', '#']).next().unwrap_or(u);
                Ok(std::borrow::Cow::Owned(decompress_by_name(path, raw)?))
            }
        }
    }

    /// Cache identity: (url, size, mtime or content hash).
    fn stamp_with_url(&self, url: &str) -> Option<u64> {
        let mut h = FxHasher::default();
        h.write(url.as_bytes());
        match self {
            IsfLocation::File(p) => {
                let (s, m) = paths::file_stamp(p)?;
                h.write_u64(s);
                h.write_u64(m as u64);
            }
            IsfLocation::Zip { zip, .. } => {
                let (s, m) = paths::file_stamp(zip)?;
                h.write_u64(s);
                h.write_u64(m as u64);
            }
            IsfLocation::Url(u) => {
                let (s, m) = paths::file_stamp(&url_local_path(u).ok()?)?;
                h.write_u64(s);
                h.write_u64(m as u64);
            }
            IsfLocation::Embedded { data, .. } => {
                // embedded data only changes with the executable: its (size, mtime) is one stat
                // for all ~170 entries instead of hashing 6 MB on every index check
                h.write_u64(data.len() as u64);
                h.write_u64(embedded_stamp(data));
            }
        }
        Some(h.finish())
    }
}

/// The local file behind a URL: the path of a `file://` URL, else the download cache file
/// (fetched with curl on first use, like python's `ResourceAccessor` cache it never expires).
pub fn url_local_path(url: &str) -> Result<PathBuf> {
    if let Some(p) = paths::file_uri_to_path(url) {
        return Ok(p);
    }
    if !["http://", "https://", "ftp://"].iter().any(|s| url.starts_with(s)) {
        return Err(Error::msg(format!("URL does not reference an openable file: {url}")));
    }
    let cache = paths::rsvol_cache_dir().join("remote").join(format!("{:016x}-{}.cache", hash_bytes(url.as_bytes()), url.len()));
    if cache.is_file() {
        return Ok(cache);
    }
    let out = std::process::Command::new("curl")
        .args(["--fail", "--silent", "--show-error", "--location", "--globoff", "--connect-timeout", "30", "--output", "-", "--", url])
        .output()
        .map_err(|e| Error::msg(format!("cannot run curl: {e}")))?;
    if !out.status.success() {
        return Err(Error::msg(format!("download of {url} failed: {}", String::from_utf8_lossy(&out.stderr).trim())));
    }
    paths::write_atomic(&cache, &out.stdout)?;
    Ok(cache)
}

/// python `RemoteIdentifierFormat(url).process({}, os)` for every `constants.OS_CATEGORIES`
/// entry: (os, identifier, location) in python's insertion order. Identifiers are
/// `rstrip()`ped and lose one trailing NUL (dwarf2json banners end in "\0\n"). `additional`
/// lists are followed (unreadable ones skipped, like python's `OSError` handler).
pub fn remote_identifiers(url: &str) -> Result<Vec<(String, Vec<u8>, String)>> {
    fn load(url: &str) -> Result<Vec<u8>> {
        let path = url_local_path(url)?;
        let raw = std::fs::read(&path)?;
        let name = url.split(['?', '#']).next().unwrap_or(url);
        decompress_by_name(name, raw)
    }
    fn walk(url: &str, os: &str, depth: u32, out: &mut Vec<(String, Vec<u8>, String)>) -> Result<()> {
        let data = load(url)?;
        let j = Json::parse(&data)?;
        // python `_verify`: version in [1] (True and 1.0 compare equal to 1)
        let v1 = match j.get("version") {
            Some(Json::Int(1)) | Some(Json::Bool(true)) => true,
            Some(Json::Float(f)) => *f == 1.0,
            _ => false,
        };
        if !v1 {
            return Err(Error::msg("Unsupported version for remote identifier list format"));
        }
        if let Some(ids) = j.get(os).and_then(|o| o.as_object()) {
            for (ident, locs) in ids {
                let mut b = super::isf::b64decode(ident);
                while b.last().is_some_and(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)) {
                    b.pop();
                }
                if b.last() == Some(&0) {
                    b.pop();
                }
                for l in locs.as_array().unwrap_or(&[]) {
                    if let Some(l) = l.as_str() {
                        out.push((os.to_string(), b.clone(), l.to_string()));
                    }
                }
            }
        }
        if depth < 8
            && let Some(more) = j.get("additional").and_then(|a| a.as_array())
        {
            for m in more.iter().filter_map(|m| m.as_str()) {
                let _ = walk(m, os, depth + 1, out);
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    for os in ["windows", "mac", "linux"] {
        walk(url, os, 0, &mut out)?;
    }
    Ok(out)
}

/// Identity of the embedded ISF data: the running executable's (size, mtime); a content hash
/// only when the executable cannot be stat'ed.
fn embedded_stamp(data: &[u8]) -> u64 {
    static EXE: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    let exe = EXE.get_or_init(|| {
        let (s, m) = paths::file_stamp(paths::current_exe()?)?;
        let mut h = FxHasher::default();
        h.write_u64(s);
        h.write_u64(m as u64);
        Some(h.finish())
    });
    exe.unwrap_or_else(|| hash_bytes(data))
}

/// Decompress according to the file extension.
pub fn decompress_by_name(name: &str, raw: Vec<u8>) -> Result<Vec<u8>> {
    if name.ends_with(".xz") {
        crate::codecs::xz::decompress(&raw)
    } else if name.ends_with(".gz") {
        crate::codecs::gzip::decompress(&raw)
    } else if name.ends_with(".bz2") {
        crate::codecs::bzip2::decompress(&raw)
    } else {
        Ok(raw)
    }
}

/// A search root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Root {
    Dir(PathBuf),
    /// the embedded files (`top` = volatility3/symbols, else framework/symbols)
    Embedded { top: bool },
}

/// The symbol search path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolPath {
    pub roots: Vec<Root>,
    /// Where downloaded / converted PDB ISFs are written (python's cache symbols dir).
    pub download_dir: PathBuf,
}

impl SymbolPath {
    /// Build the search path from `-s` dirs (python order).
    pub fn new(symbol_dirs: &[String]) -> SymbolPath {
        let mut roots = Vec::new();
        for d in symbol_dirs {
            if d.is_empty() {
                continue;
            }
            let p = PathBuf::from(d);
            let p = if p.is_absolute() { p } else { std::env::current_dir().map(|c| c.join(&p)).unwrap_or(p) };
            roots.push(Root::Dir(p));
        }
        if let Some(exe) = paths::current_exe() {
            if let Some(dir) = exe.parent() {
                let s = dir.join("symbols");
                if s.is_dir() {
                    roots.push(Root::Dir(s));
                }
            }
        }
        // python's own install (volatility3/symbols, volatility3/framework/symbols) when present,
        // so lookups resolve to the same files (and URLs) as python; embedded copies otherwise
        let py = python_install_cached();
        if let Some(p) = py {
            roots.push(Root::Dir(p.join("symbols")));
        }
        roots.push(Root::Embedded { top: true });
        if let Some(p) = py {
            roots.push(Root::Dir(p.join("framework").join("symbols")));
        }
        roots.push(Root::Embedded { top: false });
        let cache_syms = paths::vol3_cache_dir(None).join("symbols");
        roots.push(Root::Dir(cache_syms.clone()));
        SymbolPath { roots, download_dir: cache_syms }
    }

    /// python `file_symbol_url(sub_path, filename)`: all matches, in search order.
    /// `filename` may contain '/' (matched against trailing path components, like rglob).
    pub fn find(&self, sub_path: &str, filename: &str) -> Vec<IsfLocation> {
        let mut out = Vec::new();
        for root in &self.roots {
            match root {
                Root::Dir(d) => dir_matches(d, sub_path, filename, &mut out),
                Root::Embedded { top } => embedded_matches(sub_path, filename, *top, false, &mut out),
            }
        }
        out
    }

    /// The first match of [`SymbolPath::find`] (what python `IntermediateSymbolTable.create`
    /// loads), without walking directory trees for the ISFs shipped with volatility3:
    ///   * `-s` dirs and `<exe dir>/symbols` keep python's rglob semantics (a walk of the
    ///     `sub_path` tree, stopping at the first root with a match);
    ///   * for a name that is embedded, python's install is not walked: its
    ///     `framework/symbols` holds exactly the embedded files (the embedded path is
    ///     stat'ed), and in `volatility3/symbols` and the download cache only the direct
    ///     path `<root>/<sub_path>/<filename>.json*` / `.zip` can override it;
    ///   * the embedded roots are looked up by file name (binary search in a compile-time
    ///     table; no index to build, no scan of the embedded files).
    ///
    /// Names that are not embedded (PDB ISFs, user files) search every root as before.
    pub fn find_first(&self, sub_path: &str, filename: &str) -> Option<IsfLocation> {
        // the shipped match of each embedded root (volatility3/symbols, framework/symbols)
        let shipped = |top: bool| -> Option<&'static str> {
            let mut v = Vec::new();
            embedded_matches(sub_path, filename, top, true, &mut v);
            match v.pop() {
                Some(IsfLocation::Embedded { rel, .. }) => Some(rel),
                _ => None,
            }
        };
        let (top_rel, fw_rel) = (shipped(true), shipped(false));
        let is_shipped = top_rel.is_some() || fw_rel.is_some();
        let py = python_install_cached();
        let mut out = Vec::new();
        for root in &self.roots {
            match root {
                Root::Embedded { top } => embedded_matches(sub_path, filename, *top, true, &mut out),
                Root::Dir(d) if is_shipped && py.is_some_and(|p| *d == p.join("symbols")) => {
                    builtin_matches(d, sub_path, filename, top_rel, &mut out)
                }
                Root::Dir(d) if is_shipped && py.is_some_and(|p| *d == p.join("framework").join("symbols")) => {
                    builtin_matches(d, sub_path, filename, fw_rel, &mut out)
                }
                Root::Dir(d) if is_shipped && *d == self.download_dir => builtin_matches(d, sub_path, filename, None, &mut out),
                Root::Dir(d) => dir_matches(d, sub_path, filename, &mut out),
            }
            if !out.is_empty() {
                return Some(out.swap_remove(0));
            }
        }
        None
    }

    /// Every ISF reachable from the search path (python `file_symbol_url("")`), including
    /// zip pack members; used to build the identifier index.
    /// A cheap fingerprint of where `os` ISFs can come from, for per-image automagic caches:
    /// the roots, the mtimes of each root and its `<os>/` directory (adding or removing an ISF
    /// there changes them; deeper directories are not stat'ed) and the `-u` list URL.
    pub fn os_fingerprint(&self, os: &str) -> u64 {
        let mut h = FxHasher::default();
        for r in &self.roots {
            h.write(format!("{r:?}").as_bytes());
            if let Root::Dir(d) = r {
                for p in [d.clone(), d.join(os)] {
                    let (s, m) = paths::file_stamp(&p).unwrap_or((0, 0));
                    h.write_u64(s);
                    h.write_u64(m as u64);
                }
            }
        }
        h.write(super::remote_isf_url().unwrap_or_default().as_bytes());
        h.finish()
    }

    pub fn all(&self) -> Vec<IsfLocation> {
        let mut out = Vec::new();
        for root in &self.roots {
            match root {
                Root::Dir(d) => {
                    if !d.is_dir() {
                        continue;
                    }
                    let files = walk_files(d);
                    for ext in ISF_EXTENSIONS {
                        for f in &files {
                            let s = f.to_string_lossy();
                            if s.ends_with(ext) {
                                out.push(IsfLocation::File(f.clone()));
                            }
                        }
                    }
                    for f in &files {
                        if f.to_string_lossy().ends_with(".zip") {
                            if let Ok(names) = super::zipfile::list(f) {
                                for name in names {
                                    if ISF_EXTENSIONS.iter().any(|e| name.ends_with(e)) {
                                        out.push(IsfLocation::Zip { zip: f.clone(), member: name });
                                    }
                                }
                            }
                        }
                    }
                }
                Root::Embedded { top } => {
                    for &(rel, is_top, data) in super::embedded::FILES {
                        if is_top == *top {
                            out.push(IsfLocation::Embedded { rel, top: *top, data });
                        }
                    }
                }
            }
        }
        out
    }
}

/// Locate a python volatility3 package directory (the one containing `framework/`):
/// `$RSVOL_VOL3_ROOT` (the package dir or a checkout containing it), else the nearest ancestor
/// of the rsvol binary holding `volatility3/volatility3/framework/symbols` or
/// `volatility3/framework/symbols`.
pub fn python_install() -> Option<PathBuf> {
    let is_pkg = |p: &Path| p.join("framework").join("symbols").is_dir();
    if let Some(r) = std::env::var_os("RSVOL_VOL3_ROOT").filter(|v| !v.is_empty()) {
        let r = PathBuf::from(r);
        for c in [r.clone(), r.join("volatility3")] {
            if is_pkg(&c) {
                return Some(c);
            }
        }
        return None;
    }
    let exe = paths::current_exe()?;
    let mut dir = exe.parent();
    for _ in 0..10 {
        let d = dir?;
        for c in [d.join("volatility3").join("volatility3"), d.join("volatility3")] {
            if is_pkg(&c) {
                return Some(c);
            }
        }
        dir = d.parent();
    }
    None
}

/// [`python_install`], computed once per process.
fn python_install_cached() -> Option<&'static Path> {
    static PY: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    PY.get_or_init(python_install).as_deref()
}

/// Relative path of embedded file `i`, from the compact name table.
fn embedded_rel(i: usize) -> &'static str {
    use super::embedded::{NAME_OFFSETS, NAMES};
    std::str::from_utf8(&NAMES[NAME_OFFSETS[i] as usize..NAME_OFFSETS[i + 1] as usize]).unwrap_or("")
}

/// Indices of the embedded files whose file name (last path component) is `name`, in
/// `FILES` order: a binary search in the compile-time sorted `BY_NAME`.
fn embedded_named(name: &str) -> &'static [u16] {
    use super::embedded::{BY_NAME, file_name_start};
    let key = |i: u16| {
        let r = embedded_rel(i as usize).as_bytes();
        &r[file_name_start(r)..]
    };
    let lo = BY_NAME.partition_point(|&i| key(i) < name.as_bytes());
    let n = BY_NAME[lo..].iter().take_while(|&&i| key(i) == name.as_bytes()).count();
    &BY_NAME[lo..lo + n]
}

/// Matches of `<sub_path>/**/<filename><ext>` among the embedded files of one root, in
/// `find` order (extension preference, then `FILES` order); only the first with `first`.
/// A match's last component equals the wanted one, so the file-name index finds them all.
fn embedded_matches(sub_path: &str, filename: &str, top: bool, first: bool, out: &mut Vec<IsfLocation>) {
    let files = super::embedded::FILES;
    for ext in ISF_EXTENSIONS {
        let want = format!("{filename}{ext}");
        for &i in embedded_named(want.rsplit('/').next().unwrap_or(&want)) {
            let rel = embedded_rel(i as usize);
            let Some(&(_, is_top, data)) = files.get(i as usize) else { continue };
            if is_top != top {
                continue;
            }
            let under = if sub_path.is_empty() { Some(rel) } else { rel.strip_prefix(sub_path).and_then(|r| r.strip_prefix('/')) };
            if let Some(r) = under
                && (r == want || (r.len() > want.len() && r.ends_with(want.as_str()) && r.as_bytes()[r.len() - want.len() - 1] == b'/'))
            {
                out.push(IsfLocation::Embedded { rel, top, data });
                if first {
                    return;
                }
            }
        }
    }
}

/// Matches of python's `rglob` for one directory root, in `find` order (a tree walk).
fn dir_matches(d: &Path, sub_path: &str, filename: &str, out: &mut Vec<IsfLocation>) {
    let base = if sub_path.is_empty() { d.to_path_buf() } else { d.join(sub_path) };
    if !base.is_dir() {
        return;
    }
    let files = walk_files(&base);
    for ext in ISF_EXTENSIONS {
        let want = format!("{filename}{ext}");
        for f in &files {
            if path_ends_with(f, &want) {
                out.push(IsfLocation::File(f.clone()));
            }
        }
    }
    let wantzip = format!("{filename}.zip");
    for f in &files {
        if path_ends_with(f, &wantzip) {
            zip_matches(f, filename, out);
        }
    }
}

/// A root of python's install (or the download cache) for a shipped name, without a walk:
/// the shipped file `<d>/<rel>` (these roots hold the embedded files) and the direct override
/// candidates `<d>/<sub_path>/<filename><ext>` and `.zip`; the leading matches in `find`
/// order (enough for `find_first`).
fn builtin_matches(d: &Path, sub_path: &str, filename: &str, rel: Option<&str>, out: &mut Vec<IsfLocation>) {
    let base = if sub_path.is_empty() { d.to_path_buf() } else { d.join(sub_path) };
    for ext in ISF_EXTENSIONS {
        let want = format!("{filename}{ext}");
        let mut found: Vec<PathBuf> = Vec::new();
        let f = base.join(&want);
        if is_file_entry(&f) {
            found.push(f);
        }
        if let Some(rel) = rel
            && rel.ends_with(want.as_str())
        {
            let f = d.join(rel);
            if !found.contains(&f) && is_file_entry(&f) {
                found.push(f);
            }
        }
        if !found.is_empty() {
            // the first extension with a match decides (later ones sort after it)
            found.sort(); // walk order
            out.extend(found.into_iter().map(IsfLocation::File));
            return;
        }
    }
    let f = base.join(format!("{filename}.zip"));
    if is_file_entry(&f) {
        zip_matches(&f, filename, out);
    }
}

/// Members of zip symbol pack `f` matching `filename` (python: `zip_match + extension`).
fn zip_matches(f: &Path, filename: &str, out: &mut Vec<IsfLocation>) {
    if let Ok(names) = super::zipfile::list(f) {
        for name in names {
            for ext in ISF_EXTENSIONS {
                if name.ends_with(&format!("{filename}{ext}")) {
                    out.push(IsfLocation::Zip { zip: f.to_path_buf(), member: name.clone() });
                }
            }
        }
    }
}

/// What [`walk_files`] would list for this path: a regular file or a symlink.
fn is_file_entry(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file() || m.file_type().is_symlink())
}

/// Recursively list regular files under `dir` (sorted for determinism).
fn walk_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(p),
                Ok(t) if t.is_file() || t.is_symlink() => out.push(p),
                _ => {}
            }
        }
    }
    out.sort();
    out
}

/// Whether `path` ends with the '/'-separated components of `tail`.
fn path_ends_with(path: &Path, tail: &str) -> bool {
    let s = path.to_string_lossy();
    s == tail || s.ends_with(&format!("/{tail}"))
}

/// Cache file for a location + options.
fn cache_file(loc: &IsfLocation, opts: &BuildOptions) -> Option<PathBuf> {
    let stamp = loc.stamp_with_url(&loc.url())?;
    let mut h = FxHasher::default();
    h.write_u64(stamp);
    h.write_u32(super::table::BLOB_VERSION);
    if let Some(n) = &opts.natives {
        for (name, ty) in n {
            h.write(name.as_bytes());
            h.write(&super::table::ty_encode(ty));
        }
    }
    Some(paths::rsvol_cache_dir().join("isf").join(format!("{:016x}.isfb", h.finish())))
}

/// Load a symbol table from `loc` (binary cache first). `name` is the table name.
pub fn load(loc: &IsfLocation, name: &str, opts: &BuildOptions) -> Result<SymbolTable> {
    let url = loc.url();
    let cf = cache_file(loc, opts);
    if let Some(cf) = &cf {
        if let Ok(f) = std::fs::File::open(cf) {
            if let Ok(m) = Mmap::map(&f) {
                if let Ok(t) = SymbolTable::from_blob(Blob::Mapped(m), name, &url) {
                    return Ok(t);
                }
            }
        }
    }
    let json = {
        let _t = crate::util::trace::span("isf read+decompress");
        loc.read()?
    };
    let blob = {
        let _t = crate::util::trace::span("isf parse+build");
        build_blob(&json, opts).map_err(|e| Error::msg(format!("{url}: {e}")))?
    };
    if let Some(cf) = &cf {
        let _t = crate::util::trace::span("isf cache write");
        let _ = paths::write_atomic(cf, &blob);
    }
    SymbolTable::from_blob(Blob::Owned(blob), name, &url)
}

/// Load an ISF by python sub_path/filename (e.g. `("windows", "pe")`), first match wins
/// (python `IntermediateSymbolTable.create`).
pub fn load_named(path: &SymbolPath, sub_path: &str, filename: &str, table_name: &str, opts: &BuildOptions) -> Result<SymbolTable> {
    let loc = path.find_first(sub_path, filename).ok_or_else(|| Error::Symbol(format!("No symbol files found at provided filename: {filename}")))?;
    load(&loc, table_name, opts)
}

// ---------------------------------------------------------------------------------------------
// Identifier index (python SqliteCache): identifier -> location
// ---------------------------------------------------------------------------------------------

/// One indexed ISF.
#[derive(Clone, Debug)]
pub struct IdentEntry {
    pub url: String,
    pub stamp: u64,
    /// "windows" / "linux" / "mac" / "" (no identifier)
    pub os: String,
    pub identifier: Vec<u8>,
}

/// Extract (os, identifier) from ISF JSON without building the table.
pub fn extract_identifier(json: &[u8]) -> Option<(String, Vec<u8>)> {
    use crate::util::json::{Kind, Parser};
    let mut p = Parser::new(json);
    let mut win: Option<(String, String, u64)> = None;
    let mut linux: Option<String> = None;
    let mut mac: Option<String> = None;
    let r = p.object(|p, k| {
        match k.as_ref() {
            "metadata" => {
                let v = p.value()?;
                if let Some(pdb) = v.path(&["windows", "pdb"]) {
                    let guid = pdb.get("GUID").and_then(|g| g.as_str()).unwrap_or("").to_string();
                    let db = pdb.get("database").and_then(|g| g.as_str()).unwrap_or("").to_string();
                    let age = pdb.get("age").and_then(|g| g.as_u64()).unwrap_or(0);
                    win = Some((guid, db, age));
                }
            }
            "symbols" => {
                p.object(|p, name| {
                    if (name == "linux_banner" || name == "version") && p.peek_kind()? == Kind::Obj {
                        let v = p.value()?;
                        if let Some(cd) = v.get("constant_data").and_then(|c| c.as_str()) {
                            if name == "linux_banner" {
                                linux = Some(cd.to_string());
                            } else {
                                mac = Some(cd.to_string());
                            }
                        }
                    } else {
                        p.skip()?;
                    }
                    Ok(())
                })?;
            }
            _ => p.skip()?,
        }
        Ok(())
    });
    if r.is_err() {
        return None;
    }
    if let Some((guid, db, age)) = win {
        if !guid.is_empty() && age != 0 && !db.is_empty() {
            return Some(("windows".into(), format!("{db}|{}|{age}", guid.to_uppercase()).into_bytes()));
        }
    }
    if let Some(m) = mac {
        let b = super::isf::b64decode(&m);
        return Some(("mac".into(), b));
    }
    if let Some(l) = linux {
        let b = super::isf::b64decode(&l);
        return Some(("linux".into(), b));
    }
    None
}

/// The identifier index over a symbol path, persisted in `~/.cache/rsvol/identifiers.cache`.
pub struct IdentifierIndex {
    pub entries: Vec<IdentEntry>,
    locations: Vec<IsfLocation>,
}

impl IdentifierIndex {
    /// Build/refresh the index: only new or modified files are (decompressed and) parsed.
    pub fn update(path: &SymbolPath) -> IdentifierIndex {
        let cache_path = paths::rsvol_cache_dir().join("identifiers.cache");
        // entries for every symbol path ever indexed are kept, so alternating `-s` dirs does
        // not rewrite (or re-extract) the cache on each run
        let mut all = read_ident_cache(&cache_path);
        let mut by_url: crate::util::FxHashMap<String, usize> =
            all.iter().enumerate().map(|(i, e)| (e.url.clone(), i)).collect();
        let mut seen = crate::util::FxHashSet::default();
        let mut locs = Vec::new();
        let mut urls = Vec::new();
        for l in path.all() {
            let u = l.url();
            if seen.insert(u.clone()) {
                urls.push(u);
                locs.push(l);
            }
        }
        let stamps: Vec<Option<u64>> = locs.iter().zip(&urls).map(|(l, u)| l.stamp_with_url(u)).collect();
        let todo: Vec<usize> = (0..locs.len())
            .filter(|&i| match (by_url.get(&urls[i]), stamps[i]) {
                (Some(&j), Some(s)) => all[j].stamp != s,
                _ => true,
            })
            .collect();
        let fresh = extract_all(&locs, &todo, |k, ident| {
            let i = todo[k];
            let (os, identifier) = ident.unwrap_or_default();
            Some(IdentEntry { url: urls[i].clone(), stamp: stamps[i]?, os, identifier })
        });
        let mut changed = false;
        for e in fresh.into_iter().flatten() {
            changed = true;
            match by_url.get(&e.url) {
                Some(&j) => all[j] = e,
                None => {
                    by_url.insert(e.url.clone(), all.len());
                    all.push(e);
                }
            }
        }
        if changed {
            write_ident_cache(&cache_path, &all);
        }
        let mut entries = Vec::with_capacity(locs.len());
        let mut locations = Vec::with_capacity(locs.len());
        for (l, u) in locs.into_iter().zip(&urls) {
            if let Some(&j) = by_url.get(u) {
                entries.push(all[j].clone());
                locations.push(l);
            }
        }
        IdentifierIndex { entries, locations }
    }

    /// python `SqliteCache.find_location(identifier, os)`: the LAST matching location.
    pub fn find(&self, identifier: &[u8], os: &str) -> Option<IsfLocation> {
        let mut found = None;
        for (i, e) in self.entries.iter().enumerate() {
            if e.os == os && e.identifier == identifier {
                found = Some(i);
            }
        }
        found.map(|i| self.locations[i].clone())
    }

    /// python `get_identifier_dictionary(os)`: identifier -> location (later entries win).
    pub fn dictionary(&self, os: &str) -> Vec<(Vec<u8>, IsfLocation)> {
        let mut map: crate::util::FxHashMap<Vec<u8>, usize> = Default::default();
        let mut order: Vec<Vec<u8>> = Vec::new();
        for (i, e) in self.entries.iter().enumerate() {
            if e.os == os && !e.identifier.is_empty() {
                if map.insert(e.identifier.clone(), i).is_none() {
                    order.push(e.identifier.clone());
                }
            }
        }
        order.into_iter().map(|id| {
            let i = map[&id];
            (id, self.locations[i].clone())
        }).collect()
    }
}

/// Rough decompressed size of an ISF location (for scheduling and the memory budget):
/// compressed files are assumed to expand ~30x (dwarf2json / pdbconv output compresses
/// 15-20x with xz).
fn estimated_json_size(loc: &IsfLocation) -> u64 {
    let (name, size) = match loc {
        IsfLocation::Embedded { data, .. } => return data.len() as u64,
        IsfLocation::File(p) => (p.to_string_lossy().into_owned(), std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)),
        IsfLocation::Zip { member, .. } => (member.clone(), 64 << 20),
        IsfLocation::Url(u) => (u.clone(), 64 << 20),
    };
    if name.ends_with(".json") { size } else { size.saturating_mul(30) }
}

/// The (decompressed) JSON of `loc`, decoded into the reusable `buf` when possible (plain and
/// `.xz` files: no per-file allocation, pages faulted in once per worker), then `f(json)`.
pub(crate) fn with_json<R>(loc: &IsfLocation, buf: &mut Vec<u8>, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
    match loc {
        IsfLocation::Embedded { data, .. } => Ok(f(data)),
        IsfLocation::File(p) => {
            let name = p.to_string_lossy();
            if name.ends_with(".xz") {
                let raw = std::fs::read(p)?;
                let n = crate::codecs::xz::decompress_reuse(&raw, buf, false)?;
                Ok(f(&buf[..n]))
            } else if name.ends_with(".json") {
                use std::io::Read;
                let mut file = std::fs::File::open(p)?;
                let len = file.metadata()?.len() as usize;
                if buf.len() < len {
                    buf.clear();
                    buf.resize(len, 0);
                }
                file.read_exact(&mut buf[..len])?;
                Ok(f(&buf[..len]))
            } else {
                Ok(f(&loc.read()?))
            }
        }
        _ => Ok(f(&loc.read()?)),
    }
}

/// Identifier extraction for `todo` (indexes into `locs`) on all cores: `make(k, identifier)`
/// builds the k-th result (`None` identifier = unreadable / not an ISF). Largest files first;
/// each worker reuses one decode buffer; the worker count keeps the decode buffers within a
/// memory budget.
fn extract_all<R: Send>(locs: &[IsfLocation], todo: &[usize], make: impl Fn(usize, Option<(String, Vec<u8>)>) -> R + Sync) -> Vec<R> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    const BUDGET: u64 = 1536 << 20;
    if todo.is_empty() {
        return Vec::new();
    }
    let est: Vec<u64> = todo.iter().map(|&i| estimated_json_size(&locs[i])).collect();
    let mut order: Vec<usize> = (0..todo.len()).collect();
    order.sort_by_key(|&k| std::cmp::Reverse(est[k]));
    let max_est = est.iter().copied().max().unwrap_or(1).max(1);
    let threads = crate::util::par::threads().min(todo.len()).min((BUDGET / max_est).max(1) as usize);
    let next = AtomicUsize::new(0);
    let work = |out: &mut Vec<(usize, R)>| {
        let mut buf = Vec::new();
        loop {
            let j = next.fetch_add(1, Ordering::Relaxed);
            let Some(&k) = order.get(j) else { break };
            let ident = with_json(&locs[todo[k]], &mut buf, extract_identifier).ok().flatten();
            out.push((k, make(k, ident)));
        }
    };
    let mut parts: Vec<Vec<(usize, R)>> = if threads <= 1 {
        let mut v = Vec::new();
        work(&mut v);
        vec![v]
    } else {
        std::thread::scope(|s| {
            let hs: Vec<_> = (1..threads)
                .map(|_| {
                    s.spawn(|| {
                        let mut v = Vec::new();
                        work(&mut v);
                        v
                    })
                })
                .collect();
            let mut v = Vec::new();
            work(&mut v);
            let mut parts: Vec<_> = hs.into_iter().map(|h| h.join().unwrap_or_default()).collect();
            parts.push(v);
            parts
        })
    };
    let mut slots: Vec<Option<R>> = (0..todo.len()).map(|_| None).collect();
    for p in parts.iter_mut() {
        for (k, r) in p.drain(..) {
            slots[k] = Some(r);
        }
    }
    // a worker that panicked lost its items: recompute them here (never silently drop entries)
    let mut buf = Vec::new();
    slots
        .into_iter()
        .enumerate()
        .map(|(k, r)| r.unwrap_or_else(|| make(k, with_json(&locs[todo[k]], &mut buf, extract_identifier).ok().flatten())))
        .collect()
}

fn read_ident_cache(path: &Path) -> Vec<IdentEntry> {
    let Ok(b) = std::fs::read(path) else { return Vec::new() };
    let mut out = Vec::new();
    let mut i = 0usize;
    let rd = |i: &mut usize, n: usize| -> Option<&[u8]> {
        let s = b.get(*i..*i + n)?;
        *i += n;
        Some(s)
    };
    if rd(&mut i, 8) != Some(b"RSVOLID1") {
        return out;
    }
    loop {
        let Some(l) = rd(&mut i, 4) else { break };
        let ul = u32::from_le_bytes(l.try_into().unwrap()) as usize;
        let Some(url) = rd(&mut i, ul) else { break };
        let Some(st) = rd(&mut i, 8) else { break };
        let Some(l) = rd(&mut i, 4) else { break };
        let ol = u32::from_le_bytes(l.try_into().unwrap()) as usize;
        let Some(os) = rd(&mut i, ol) else { break };
        let Some(l) = rd(&mut i, 4) else { break };
        let il = u32::from_le_bytes(l.try_into().unwrap()) as usize;
        let Some(id) = rd(&mut i, il) else { break };
        out.push(IdentEntry {
            url: String::from_utf8_lossy(url).into_owned(),
            stamp: u64::from_le_bytes(st.try_into().unwrap()),
            os: String::from_utf8_lossy(os).into_owned(),
            identifier: id.to_vec(),
        });
    }
    out
}

fn write_ident_cache(path: &Path, entries: &[IdentEntry]) {
    let mut b = Vec::new();
    b.extend_from_slice(b"RSVOLID1");
    for e in entries {
        b.extend_from_slice(&(e.url.len() as u32).to_le_bytes());
        b.extend_from_slice(e.url.as_bytes());
        b.extend_from_slice(&e.stamp.to_le_bytes());
        b.extend_from_slice(&(e.os.len() as u32).to_le_bytes());
        b.extend_from_slice(e.os.as_bytes());
        b.extend_from_slice(&(e.identifier.len() as u32).to_le_bytes());
        b.extend_from_slice(&e.identifier);
    }
    let _ = paths::write_atomic(path, &b);
}

/// The process-wide identifier index (python `symbol_cache.load_cache_manager()` after the
/// SymbolCacheMagic update), built/refreshed on first use for `path`.
/// `identifier_index(p).dictionary("linux")` = python `get_identifier_dictionary("linux")`.
pub fn identifier_index(path: &SymbolPath) -> &'static IdentifierIndex {
    // one index per distinct search path (a process normally has exactly one)
    type Key = (SymbolPath, Option<String>);
    static INDEX: std::sync::Mutex<Vec<(Key, &'static IdentifierIndex)>> = std::sync::Mutex::new(Vec::new());
    let remote = super::remote_isf_url();
    let mut all = INDEX.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, i)) = all.iter().find(|((p, r), _)| p == path && *r == remote) {
        return i;
    }
    let _t = crate::util::trace::span("identifier index update");
    let mut index = IdentifierIndex::update(path);
    // python SymbolCacheMagic: remote rows are (re)inserted after the local scan, so they come
    // last and win `find_location` / `get_identifier_dictionary` ties
    if let Some(url) = &remote {
        match remote_identifiers(url) {
            Ok(list) => {
                for (os, identifier, location) in list {
                    index.entries.push(IdentEntry { url: location.clone(), stamp: 0, os, identifier });
                    index.locations.push(IsfLocation::Url(location));
                }
            }
            Err(e) => eprintln!("rsvol: remote ISF list {url}: {e}"),
        }
    }
    let i: &'static IdentifierIndex = Box::leak(Box::new(index));
    all.push(((path.clone(), remote), i));
    i
}

/// Find the ISF for a Windows PDB (python `PDBUtility.load_windows_symbol_table` lookup order:
/// by name `windows/<pdb>/<GUID>-<AGE>.json*`, then by identifier, then download + convert).
pub fn find_windows_isf(path: &SymbolPath, pdb_name: &str, guid: &str, age: u32, offline: bool) -> Result<IsfLocation> {
    let pdb_name = pdb_name.trim_matches('\0');
    let filter = format!("{}/{}-{}", pdb_name, guid.to_uppercase(), age);
    // fast path: the canonical layout <root>/windows/<pdb>/<GUID>-<AGE>.json*
    for root in &path.roots {
        if let Root::Dir(d) = root {
            for ext in ISF_EXTENSIONS {
                let p = d.join("windows").join(format!("{filter}{ext}"));
                if p.is_file() {
                    return Ok(IsfLocation::File(p));
                }
            }
        }
    }
    if let Some(l) = path.find_first("windows", &filter) {
        return Ok(l);
    }
    let idx = identifier_index(path);
    let ident = format!("{}|{}|{}", pdb_name, guid.to_uppercase(), age);
    if let Some(l) = idx.find(ident.as_bytes(), "windows") {
        return Ok(l);
    }
    // download + convert (pdb agent)
    let out = super::windows::pdb::download_and_convert(pdb_name, &guid.to_uppercase(), age, &path.download_dir, offline)?;
    Ok(IsfLocation::File(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lookup cost of shipped ISFs with this machine's search path:
    ///   cargo test --release isf_lookup_timing -- --ignored --nocapture
    #[test]
    #[ignore]
    fn isf_lookup_timing() {
        // first calls in the process: search path setup, lookup, cached-blob load, register
        let t = std::time::Instant::now();
        let p0 = SymbolPath::new(&[]);
        let t1 = t.elapsed();
        // RSVOL_ISF_OLD=1: the previous lookup (every match of every root, then the first)
        let l0 = if std::env::var_os("RSVOL_ISF_OLD").is_some() {
            p0.find("windows", "pe").into_iter().next().unwrap()
        } else {
            p0.find_first("windows", "pe").unwrap()
        };
        let t2 = t.elapsed();
        let tb = load(&l0, "pe", &BuildOptions::default()).unwrap();
        let t3 = t.elapsed();
        drop(tb);
        let pe = crate::symbols::load_isf("windows", "pe", None, &[]).unwrap();
        let t4 = t.elapsed();
        println!(
            "first calls: SymbolPath::new {t1:?}, find_first +{:?}, load +{:?}, symbols::load_isf +{:?} ({})",
            t2 - t1,
            t3 - t2,
            t4 - t3,
            pe.isf_url()
        );
        let t = std::time::Instant::now();
        let path = SymbolPath::new(&[]);
        let t_new = t.elapsed();
        println!("roots: {:?}", path.roots);
        let reps = 200;
        for (sub, name) in [("windows", "pe"), ("windows", "netscan-win10-19041-x64"), ("linux", "elf"), ("generic", "qemu")] {
            let first = path.find(sub, name).into_iter().next();
            let t = std::time::Instant::now();
            for _ in 0..reps {
                std::hint::black_box(path.find(sub, name));
            }
            let t_find = t.elapsed() / reps;
            let t = std::time::Instant::now();
            for _ in 0..reps {
                std::hint::black_box(path.find_first(sub, name));
            }
            let t_first = t.elapsed() / reps;
            let t = std::time::Instant::now();
            for _ in 0..reps {
                let l = path.find(sub, name).into_iter().next().unwrap();
                std::hint::black_box(load(&l, name, &BuildOptions::default()).unwrap());
            }
            let t_old = t.elapsed() / reps;
            let t = std::time::Instant::now();
            for _ in 0..reps {
                std::hint::black_box(load_named(&path, sub, name, name, &BuildOptions::default()).unwrap());
            }
            let t_load = t.elapsed() / reps;
            println!(
                "{sub}/{name}: find (all) {t_find:?}  find_first {t_first:?}  |  find+load {t_old:?}  load_named {t_load:?}  -> {}",
                first.map(|l| l.url()).unwrap_or_default()
            );
        }
        println!("SymbolPath::new {t_new:?}");
    }

    #[test]
    fn embedded_name_tables_match_files() {
        let files = super::super::embedded::FILES;
        for (i, f) in files.iter().enumerate() {
            assert_eq!(embedded_rel(i), f.0);
            let name = f.0.rsplit('/').next().unwrap();
            assert!(embedded_named(name).contains(&(i as u16)), "{name}");
            let all: Vec<u16> = (0..files.len() as u16).filter(|&k| files[k as usize].0.rsplit('/').next() == Some(name)).collect();
            assert_eq!(embedded_named(name), &all[..]);
        }
        assert!(embedded_named("nonexistent.json").is_empty());
        assert!(embedded_named("").is_empty());
    }

    /// `find_first` == `find().first()` for every shipped ISF and some other names, with and
    /// without `-s` dirs; user dirs keep rglob semantics (any depth, first root wins).
    #[test]
    fn find_first_matches_find() {
        let tmp = std::env::temp_dir().join(format!("rsvol-isf-{}", std::process::id()));
        let user = tmp.join("user");
        let deep = tmp.join("deep");
        for (dir, rel) in [(&user, "windows/pe.json"), (&deep, "windows/sub/dir/kdbg.json.xz"), (&deep, "linux/elf.json.gz")] {
            let f = dir.join(rel);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, b"{}").unwrap();
        }
        let mut names: Vec<(String, String)> = Vec::new();
        for &(rel, _, _) in super::super::embedded::FILES {
            let stem = rel.strip_suffix(".json").unwrap_or(rel);
            let (dir, file) = stem.rsplit_once('/').unwrap_or(("", stem));
            names.push((dir.to_string(), file.to_string()));
            if let Some((top, rest)) = dir.split_once('/') {
                // nested name through a shorter sub_path (rglob over sub dirs)
                names.push((top.to_string(), format!("{rest}/{file}")));
                names.push((top.to_string(), file.to_string()));
            }
            names.push((String::new(), file.to_string()));
        }
        for n in ["pe.json", "nonexistent", "ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B3-1", "win"] {
            names.push(("windows".into(), n.into()));
        }
        let paths = [
            SymbolPath::new(&[]),
            SymbolPath::new(&[user.to_string_lossy().into_owned()]),
            SymbolPath::new(&[deep.to_string_lossy().into_owned(), user.to_string_lossy().into_owned()]),
        ];
        for path in &paths {
            for (sub, name) in &names {
                let url = |l: Option<IsfLocation>| l.map(|l| l.url());
                assert_eq!(url(path.find_first(sub, name)), url(path.find(sub, name).into_iter().next()), "{sub} / {name}");
            }
        }
        // the overrides win
        assert_eq!(paths[1].find_first("windows", "pe"), Some(IsfLocation::File(user.join("windows/pe.json"))));
        assert_eq!(paths[2].find_first("windows", "kdbg"), Some(IsfLocation::File(deep.join("windows/sub/dir/kdbg.json.xz"))));
        assert_eq!(paths[2].find_first("linux", "elf"), Some(IsfLocation::File(deep.join("linux/elf.json.gz"))));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
