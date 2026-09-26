//! ISF discovery (python `IntermediateSymbolTable.file_symbol_url`, `symbol_cache`,
//! `pdbutil.load_windows_symbol_table`), decompression, and the binary table cache.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Search order (python `volatility3.symbols.__path__`):
//!   1. `-s/--symbol-dirs` directories,
//!   2. `<directory of the rsvol binary>/symbols` (like a frozen python executable),
//!   3. the ISFs shipped with volatility3 (python's own `volatility3/symbols` and
//!      `volatility3/framework/symbols` directories when an installation is found, the copies
//!      embedded in the binary otherwise),
//!   4. python's download cache `~/.cache/volatility3/symbols` (so existing downloads are
//!      reused).
//!
//! A downloaded PDB is converted to `windows/<pdb>/<GUID>-<age>.json.xz` in the first of
//! these directories where the file can be created, like python's `download_pdb_isf`.
//!
//! Every loaded table is cached as a flat blob in `~/.cache/rsvol/isf/<key>.isfb`
//! (key = source URL + size + mtime + natives), so a warm load is one mmap.

use super::isf::{BuildOptions, build_blob};
use super::lazy::{JsonBuf, LazyCore};
use super::table::{Blob, SymbolTable};
use crate::error::{Error, Result};
use crate::util::json::Json;
use crate::util::mmap::Mmap;
use crate::util::paths;
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
    /// cached as `~/.cache/rsvol/data_<sha512>.cache` (python: `CACHE_PATH/data_<sha512>.cache`).
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

    /// Change detector for the identifier index: a fully mixing hash of (url, size, mtime)
    /// (the executable's for embedded ISFs: one stat for all ~170 entries instead of hashing
    /// 6 MB on every index check). The index file stores the URL itself.
    fn stamp_with_url(&self, url: &str) -> Option<u64> {
        Some(crate::layers::scancache::key_hash(&source_identity(self, url)?))
    }
}

/// The local file behind a URL: the path of a `file://` URL, else the download cache file
/// `data_<sha512>.cache` (fetched with curl on first use; like python's `ResourceAccessor`
/// cache it never expires, `--clear-cache` removes it).
pub fn url_local_path(url: &str) -> Result<PathBuf> {
    if let Some(p) = paths::file_uri_to_path(url) {
        return Ok(p);
    }
    if !crate::util::download::is_remote(url) {
        return Err(Error::msg(format!("URL does not reference an openable file: {url}")));
    }
    // remote lists are ignored in offline mode (see `set_remote_isf_url`)
    crate::util::download::fetch(url, false)
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

/// Identity of the embedded ISF data: the running executable's (size, mtime), exactly; a
/// content hash only when the executable cannot be stat'ed.
fn embedded_stamp(data: &[u8]) -> (u64, i128) {
    static EXE: std::sync::OnceLock<Option<(u64, i128)>> = std::sync::OnceLock::new();
    let exe = EXE.get_or_init(|| paths::file_stamp(paths::current_exe()?));
    exe.unwrap_or_else(|| (u64::MAX, crate::layers::scancache::key_hash(data) as i128))
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
    /// python's cache symbols dir (the last root; part of some cache keys).
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
    /// Returned as the full key material (hex), not a hash: callers store it and compare.
    pub fn os_fingerprint(&self, os: &str) -> String {
        let mut k: Vec<u8> = Vec::new();
        for r in &self.roots {
            let d = format!("{r:?}");
            k.extend_from_slice(&(d.len() as u64).to_le_bytes());
            k.extend_from_slice(d.as_bytes());
            if let Root::Dir(d) = r {
                for p in [d.clone(), d.join(os)] {
                    let (s, m) = paths::file_stamp(&p).unwrap_or((0, 0));
                    k.extend_from_slice(&s.to_le_bytes());
                    k.extend_from_slice(&m.to_le_bytes());
                }
            }
        }
        let remote = super::remote_isf_url().unwrap_or_default();
        k.extend_from_slice(&(remote.len() as u64).to_le_bytes());
        k.extend_from_slice(remote.as_bytes());
        paths::hex(&k)
    }

    /// python `file_symbol_url(sub_path)` without a filename: every ISF under
    /// `<root>/<sub_path>` of each root (python's `rglob("*" + ext)` per extension, then the
    /// members of the zip packs in that tree), in search order. Only the `sub_path` trees are
    /// walked (python does not look anywhere else), and the embedded roots are filtered by the
    /// compact name table (no embedded file is touched unless it matches).
    pub fn all_under(&self, sub_path: &str) -> Vec<IsfLocation> {
        let mut out = Vec::new();
        for root in &self.roots {
            match root {
                Root::Dir(d) => {
                    let base = d.join(sub_path);
                    if !base.is_dir() {
                        continue;
                    }
                    let files = walk_files(&base);
                    for ext in ISF_EXTENSIONS {
                        out.extend(files.iter().filter(|f| f.to_string_lossy().ends_with(ext)).map(|f| IsfLocation::File(f.clone())));
                    }
                    for f in files.iter().filter(|f| f.to_string_lossy().ends_with(".zip")) {
                        if let Ok(names) = super::zipfile::list(f) {
                            for name in names.into_iter().filter(|n| ISF_EXTENSIONS.iter().any(|e| n.ends_with(e))) {
                                out.push(IsfLocation::Zip { zip: f.clone(), member: name });
                            }
                        }
                    }
                }
                Root::Embedded { top } => {
                    for i in 0..super::embedded::FILES.len() {
                        let rel = embedded_rel(i);
                        if (sub_path.is_empty() || rel.strip_prefix(sub_path).is_some_and(|r| r.starts_with('/')))
                            && let Some(&(_, is_top, data)) = super::embedded::FILES.get(i)
                            && is_top == *top
                        {
                            out.push(IsfLocation::Embedded { rel, top: *top, data });
                        }
                    }
                }
            }
        }
        out
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
pub(crate) fn python_install_cached() -> Option<&'static Path> {
    static PY: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    PY.get_or_init(python_install).as_deref()
}

/// The embedded ISF `rel` (a path under volatility3/symbols or framework/symbols), found via the
/// file-name index (touches no other embedded file).
pub(crate) fn embedded_file(rel: &str) -> Option<&'static [u8]> {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    embedded_named(name).iter().find(|&&i| embedded_rel(i as usize) == rel).and_then(|&i| super::embedded::FILES.get(i as usize)).map(|f| f.2)
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

/// The exact identity of a location's source file: its URL plus (size, mtime) of the file on
/// disk (the zip for pack members, the running executable for embedded ISFs).
fn source_identity(loc: &IsfLocation, url: &str) -> Option<Vec<u8>> {
    let mut k = Vec::with_capacity(url.len() + 32);
    k.extend_from_slice(&(url.len() as u64).to_le_bytes());
    k.extend_from_slice(url.as_bytes());
    let (s, m) = match loc {
        IsfLocation::File(p) => paths::file_stamp(p)?,
        IsfLocation::Zip { zip, .. } => paths::file_stamp(zip)?,
        IsfLocation::Url(u) => paths::file_stamp(&url_local_path(u).ok()?)?,
        IsfLocation::Embedded { data, .. } => {
            k.extend_from_slice(&(data.len() as u64).to_le_bytes());
            embedded_stamp(data)
        }
    };
    k.extend_from_slice(&s.to_le_bytes());
    k.extend_from_slice(&m.to_le_bytes());
    Some(k)
}

/// Cache file of a location + options and its full key material. The file is named by a
/// fully mixing 64-bit hash of the key and carries the key itself in a trailer
/// (`blob | key | key_len u32 | ISFB_TRAILER`), verified on load: a hash collision is a miss,
/// never a wrong table.
fn cache_file(loc: &IsfLocation, url: &str, opts: &BuildOptions) -> Option<(PathBuf, Vec<u8>)> {
    let mut key = b"rsvol-isfb\0".to_vec();
    key.extend_from_slice(&super::table::BLOB_VERSION.to_le_bytes());
    key.extend_from_slice(&source_identity(loc, url)?);
    match &opts.natives {
        None => key.push(0),
        Some(n) => {
            key.push(1);
            key.extend_from_slice(&(n.len() as u64).to_le_bytes());
            for (name, ty) in n {
                key.extend_from_slice(&(name.len() as u64).to_le_bytes());
                key.extend_from_slice(name.as_bytes());
                key.extend_from_slice(&super::table::ty_encode(ty));
            }
        }
    }
    let h = crate::layers::scancache::key_hash(&key);
    Some((paths::rsvol_cache_dir().join("isf").join(format!("{h:016x}.isfb")), key))
}

const ISFB_TRAILER: &[u8; 8] = b"RSVKEY01";

/// The blob of a mapped cache file whose trailer holds exactly `key` (only the file's last
/// bytes are compared before the blob is trusted).
fn cached_blob_matches(file: &[u8], key: &[u8]) -> bool {
    let n = file.len();
    if n < 12 + key.len() || &file[n - 8..] != ISFB_TRAILER {
        return false;
    }
    let kl = u32::from_le_bytes(file[n - 12..n - 8].try_into().unwrap()) as usize;
    kl == key.len() && &file[n - 12 - kl..n - 12] == key
}

/// The bytes of a cache file for `blob` under `key`, as the parts written in order.
fn cache_file_parts<'b>(blob: &'b [u8], key: &'b [u8], len: &'b [u8; 4]) -> [&'b [u8]; 4] {
    [blob, key, len, ISFB_TRAILER]
}

#[cfg(test)]
fn cache_file_bytes(blob: &[u8], key: &[u8]) -> Vec<u8> {
    let len = (key.len() as u32).to_le_bytes();
    cache_file_parts(blob, key, &len).concat()
}

/// Blobs built in this process, by cache key: the cache file is written in the background,
/// so a second load of the same ISF (e.g. the Linux stacker's table and the kernel's, which
/// differ only in the symbol mask) shares the blob instead of rebuilding it.
static BUILT: std::sync::Mutex<Vec<(Vec<u8>, std::sync::Arc<Vec<u8>>)>> = std::sync::Mutex::new(Vec::new());

/// Blobs built in this process as lazy tables (see [`super::lazy`]), by cache key.
static LAZY_BUILT: std::sync::Mutex<Vec<(Vec<u8>, std::sync::Arc<LazyCore>)>> = std::sync::Mutex::new(Vec::new());

/// One lock per cache key: a load waits for a concurrent (speculative) load of the same table
/// instead of building it a second time.
fn key_lock(key: &[u8]) -> std::sync::Arc<std::sync::Mutex<()>> {
    static LOCKS: std::sync::Mutex<Vec<(Vec<u8>, std::sync::Arc<std::sync::Mutex<()>>)>> = std::sync::Mutex::new(Vec::new());
    let mut g = LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, l)) = g.iter().find(|(k, _)| k == key) {
        return l.clone();
    }
    let l = std::sync::Arc::new(std::sync::Mutex::new(()));
    g.push((key.to_vec(), l.clone()));
    l
}

/// The table of `loc` already in memory (built or being built in this process, or cached),
/// without building anything.
fn load_known(url: &str, cf: &Option<(PathBuf, Vec<u8>)>, name: &str) -> Option<SymbolTable> {
    let (cf, key) = cf.as_ref()?;
    let built = BUILT.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|b| b.0 == *key).map(|b| b.1.clone());
    if let Some(b) = built {
        return SymbolTable::from_blob(Blob::Shared(b), name, url).ok();
    }
    let lazy = LAZY_BUILT.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|b| b.0 == *key).map(|b| b.1.clone());
    if let Some(c) = lazy {
        return SymbolTable::from_lazy(c, name, url).ok();
    }
    let f = std::fs::File::open(cf).ok()?;
    let m = Mmap::map(&f).ok()?;
    if !cached_blob_matches(m.as_slice(), key) {
        return None;
    }
    SymbolTable::from_blob(Blob::Mapped(m), name, url).ok()
}

/// Load a symbol table from `loc` (binary cache first). `name` is the table name.
pub fn load(loc: &IsfLocation, name: &str, opts: &BuildOptions) -> Result<SymbolTable> {
    let url = loc.url();
    if let IsfLocation::File(p) = loc
        && let Some(t) = load_pending(p, name, &url, opts)
    {
        return t;
    }
    let cf = cache_file(loc, &url, opts);
    let lock = cf.as_ref().map(|(_, k)| key_lock(k));
    let _g = lock.as_ref().map(|l| l.lock().unwrap_or_else(|e| e.into_inner()));
    if let Some(t) = load_known(&url, &cf, name) {
        return Ok(t);
    }
    // the build is parallel: start the pool's workers while this thread decompresses
    crate::util::pool::warm();
    let json = match take_kept(loc, &url) {
        Some(j) => JsonBuf::Owned(j),
        None => {
            let _t = crate::util::trace::span("isf read+decompress");
            json_for_build(loc)?
        }
    };
    let json = match lazy_build(loc, &url, &cf, json, opts) {
        Ok(core) => return SymbolTable::from_lazy(core, name, &url),
        Err(j) => j,
    };
    let blob = build_remember(&url, cf, json, opts, true)?;
    SymbolTable::from_blob(Blob::Shared(blob), name, &url)
}

// ---------------------------------------------------------------------------------------------
// Lazy tables and their deferred blobs
// ---------------------------------------------------------------------------------------------

/// Whether big ISFs load as lazy tables (see [`set_lazy_tables`]).
static LAZY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn lazy_tables_on() -> bool {
    LAZY.load(std::sync::atomic::Ordering::Relaxed)
}

/// JSON documents at least this big load lazily (the kernel ISFs; the small ISFs shipped with
/// volatility3 build in well under a millisecond).
const LAZY_MIN: usize = 1 << 20;

/// Let big ISFs load as lazy tables (the one-shot CLI: its blob is written after the output,
/// see [`finish_deferred`]). `RSVOL_LAZY_ISF=0` turns them off.
pub fn set_lazy_tables(on: bool) {
    let on = on && std::env::var_os("RSVOL_LAZY_ISF").is_none_or(|v| v != "0");
    LAZY.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// A lazy table whose full blob is not cached yet: built after the output
/// ([`finish_deferred`]).
struct Deferred {
    loc: IsfLocation,
    core: std::sync::Arc<LazyCore>,
    cf: PathBuf,
    key: Vec<u8>,
}

static DEFERRED: std::sync::Mutex<Vec<Deferred>> = std::sync::Mutex::new(Vec::new());

/// A lazy table over `json` when lazy tables are on and the document qualifies (remembered
/// in-process by cache key, its blob deferred); `Err(json)` gives the JSON back for an eager
/// build.
fn lazy_build(loc: &IsfLocation, url: &str, cf: &Option<(PathBuf, Vec<u8>)>, json: JsonBuf, opts: &BuildOptions) -> std::result::Result<std::sync::Arc<LazyCore>, JsonBuf> {
    if !LAZY.load(std::sync::atomic::Ordering::Relaxed) || opts.natives.is_some() || json.len() < LAZY_MIN || matches!(loc, IsfLocation::Embedded { .. }) {
        return Err(json);
    }
    let core = std::sync::Arc::new(LazyCore::build(json, opts)?);
    lazy_register(loc, url, cf, &core);
    Ok(core)
}

/// Remember a lazy table in-process by its cache key and defer its blob.
fn lazy_register(loc: &IsfLocation, url: &str, cf: &Option<(PathBuf, Vec<u8>)>, core: &std::sync::Arc<LazyCore>) {
    crate::util::trace::note(|| format!("lazy table: {url}"));
    if let Some((cf, key)) = cf {
        LAZY_BUILT.lock().unwrap_or_else(|e| e.into_inner()).push((key.clone(), core.clone()));
        DEFERRED.lock().unwrap_or_else(|e| e.into_inner()).push(Deferred { loc: loc.clone(), core: core.clone(), cf: cf.clone(), key: key.clone() });
    }
}

/// How the blobs of lazy tables are written (`RSVOL_DEFERRED_ISFB`): `helper` (default) = a
/// detached helper process per blob, `thread` = a background thread of this process joined
/// before exit, `off` = not at all.
fn deferred_mode() -> &'static str {
    match std::env::var("RSVOL_DEFERRED_ISFB").as_deref() {
        Ok("thread") => "thread",
        Ok("off") => "off",
        _ => "helper",
    }
}

/// Write the blobs of this run's lazy tables. `main` calls this after the output is complete
/// and flushed: by default each blob is handed to a detached helper process (this binary in
/// helper mode, see [`run_helper`]), so the process exits as soon as its output is done and
/// the next run of any plugin maps the finished blob. If the helper cannot be started, the
/// blob is built on a background thread that `main` joins before exit.
pub fn finish_deferred() {
    super::windows::pdb::finish_ahead();
    // converted PDB tables first: their files are what python and the next run look for
    let writes = std::mem::take(&mut *PENDING_ISF.lock().unwrap_or_else(|e| e.into_inner()));
    for p in writes {
        if deferred_mode() != "thread" && spawn_helper_spec(&format!("X{}", p.job.encode())) {
            crate::util::trace::note(|| format!("pdb isf: helper started for {}", p.job.path.display()));
            continue;
        }
        crate::util::bg::spawn(move || {
            let _t = crate::util::trace::span("pdb isf write (deferred, in-process)");
            p.job.run_with(&p.json);
        });
    }
    let jobs = std::mem::take(&mut *DEFERRED.lock().unwrap_or_else(|e| e.into_inner()));
    let mode = deferred_mode();
    for j in jobs {
        if mode == "off" {
            continue;
        }
        if mode == "helper" && spawn_helper(&j.loc) {
            crate::util::trace::note(|| format!("isf blob: helper started for {}", j.loc.url()));
            continue;
        }
        crate::util::bg::spawn(move || {
            let _t = crate::util::trace::span("isf blob build (deferred, in-process)");
            if let Ok(blob) = super::isf::build_blob(j.core.json(), &BuildOptions::default()) {
                let len = (j.key.len() as u32).to_le_bytes();
                let _ = paths::write_atomic_parts(&j.cf, &cache_file_parts(&blob, &j.key, &len));
            }
        });
    }
}

/// The helper-mode environment variable: its value names the ISF whose blob to build.
pub const HELPER_ENV: &str = "RSVOL_ISFB_HELPER";

/// The [`HELPER_ENV`] value for `loc` (files, zip members and downloaded URLs; the shipped
/// ISFs never load lazily).
fn helper_spec(loc: &IsfLocation) -> Option<String> {
    Some(match loc {
        IsfLocation::File(p) => format!("F{}", paths::hex(p.as_os_str().as_encoded_bytes())),
        IsfLocation::Zip { zip, member } => format!("Z{}:{}", paths::hex(zip.as_os_str().as_encoded_bytes()), paths::hex(member.as_bytes())),
        IsfLocation::Url(u) => format!("U{}", paths::hex(u.as_bytes())),
        IsfLocation::Embedded { .. } => return None,
    })
}

fn parse_helper_spec(spec: &str) -> Option<IsfLocation> {
    let os = |h: &str| -> Option<PathBuf> { Some(PathBuf::from(std::ffi::OsString::from_vec(unhex(h)?))) };
    use std::os::unix::ffi::OsStringExt;
    let (kind, rest) = spec.split_at_checked(1)?;
    Some(match kind {
        "F" => IsfLocation::File(os(rest)?),
        "Z" => {
            let (z, m) = rest.split_once(':')?;
            IsfLocation::Zip { zip: os(z)?, member: String::from_utf8(unhex(m)?).ok()? }
        }
        "U" => IsfLocation::Url(String::from_utf8(unhex(rest)?).ok()?),
        _ => return None,
    })
}

/// Start the helper process for `loc`'s blob: this executable with [`HELPER_ENV`] set, stdio
/// on /dev/null, not waited for (it detaches itself, see [`run_helper`]).
fn spawn_helper(loc: &IsfLocation) -> bool {
    helper_spec(loc).is_some_and(|s| spawn_helper_spec(&s))
}

/// Start the helper process with [`HELPER_ENV`] = `spec`.
fn spawn_helper_spec(spec: &str) -> bool {
    use std::os::unix::process::CommandExt;
    let Some(exe) = paths::current_exe() else { return false };
    std::process::Command::new(exe)
        .arg0("rsvol-isfb-helper")
        .env(HELPER_ENV, spec)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

unsafe extern "C" {
    fn setsid() -> i32;
    fn flock(fd: i32, op: i32) -> i32;
    fn close_range(first: u32, last: u32, flags: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn sched_setscheduler(pid: i32, policy: i32, param: *const i32) -> i32;
    fn setpriority(which: i32, who: u32, prio: i32) -> i32;
}

/// Helper mode (`main` runs this when [`HELPER_ENV`] is set, before anything else): build and
/// write the blob of the ISF named by `spec`. Detached from the run that started it (own
/// session, no inherited descriptors, idle CPU priority); at most one helper per blob (an
/// exclusive non-blocking lock next to the blob); the blob is written through a temporary
/// file and a rename, and only if the ISF did not change while it was read. Returns the exit
/// status (nothing is printed).
///
/// A spec `X<job>` (see `pdb::IsfWrite`) first writes a converted PDB's `.json.xz` (at normal
/// priority: python and the next run look for that file), then its blob.
pub fn run_helper(spec: &std::ffi::OsStr) -> i32 {
    const SCHED_IDLE: i32 = 5;
    let idle = || {
        let param = 0i32;
        // SAFETY: plain syscalls on this process
        unsafe {
            if sched_setscheduler(0, SCHED_IDLE, &param) != 0 {
                setpriority(0, 0, 19);
            }
        }
    };
    // SAFETY: plain syscalls on this process
    unsafe {
        setsid();
        if close_range(3, u32::MAX, 0) != 0 {
            for fd in 3..1024 {
                close(fd);
            }
        }
    }
    if let Some(job) = spec.to_str().and_then(|s| s.strip_prefix('X')) {
        let Some(job) = super::windows::pdb::IsfWrite::decode(job) else { return 2 };
        setpriority_background();
        let Some((json, stamp)) = job.run() else { return 1 };
        idle();
        // (the JSON is the file's unless another run replaced the file meanwhile)
        let json = (paths::file_stamp(&job.path) == Some(stamp)).then_some(json);
        return match write_blob_locked(&IsfLocation::File(job.path), json) {
            Some(()) => 0,
            None => 1,
        };
    }
    idle();
    let Some(loc) = spec.to_str().and_then(parse_helper_spec) else { return 2 };
    match write_blob_locked(&loc, None) {
        Some(()) => 0,
        None => 1,
    }
}

/// A lower (but not idle) CPU priority: work whose result others wait for, off the output path.
fn setpriority_background() {
    // SAFETY: plain syscall on this process
    unsafe {
        setpriority(0, 0, 5);
    }
}

/// Build and write the blob of `loc` (from `json` when given: the content of the file as it
/// is now), see [`run_helper`].
fn write_blob_locked(loc: &IsfLocation, json: Option<Vec<u8>>) -> Option<()> {
    use std::os::fd::AsRawFd;
    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;
    let url = loc.url();
    let opts = BuildOptions::default();
    let (cf, key) = cache_file(loc, &url, &opts)?;
    std::fs::create_dir_all(cf.parent()?).ok()?;
    let lock_path = cf.with_extension("lock");
    let lf = std::fs::File::options().create(true).append(true).open(&lock_path).ok()?;
    // SAFETY: flock on an open descriptor
    if unsafe { flock(lf.as_raw_fd(), LOCK_EX | LOCK_NB) } != 0 {
        return Some(()); // another helper is building it
    }
    // (removing the lock file while holding it is safe: a helper that opened it too fails its
    // non-blocking lock and exits, a later one finds the blob first)
    let done = || {
        let _ = std::fs::remove_file(&lock_path);
        drop(lf);
    };
    if let Ok(f) = std::fs::File::open(&cf)
        && let Ok(m) = Mmap::map(&f)
        && cached_blob_matches(m.as_slice(), &key)
    {
        done();
        return Some(());
    }
    let json = match json {
        Some(j) => JsonBuf::Owned(j),
        None => json_for_build(loc).ok()?,
    };
    let blob = super::isf::build_blob(&json, &opts).ok()?;
    // the source must be the one the key describes (not modified while it was read)
    if cache_file(loc, &url, &opts).map(|c| c.1).as_ref() != Some(&key) {
        return None;
    }
    let len = (key.len() as u32).to_le_bytes();
    paths::write_atomic_parts(&cf, &cache_file_parts(&blob, &key, &len)).ok()?;
    done();
    Some(())
}

/// The JSON of `loc` for a build. A plain `.json` file (a dwarf2json kernel ISF is 50-100 MB)
/// is mapped, pre-faulted, from the page cache: reading it first faults in and zeroes a fresh
/// buffer of that size, then copies (28-40 ms for the 46 / 64 MB jammy / noble ISFs vs 7-10 ms
/// to map; the parse from the mapping is a little slower, net 4-9 ms per cold kernel load).
fn json_for_build(loc: &IsfLocation) -> Result<JsonBuf> {
    if let IsfLocation::File(p) = loc
        && p.as_os_str().as_encoded_bytes().ends_with(b".json")
    {
        let f = std::fs::File::open(p)?;
        let len = f.metadata()?.len() as usize;
        if len > 0
            && let Ok(m) = crate::util::mmap::MapWindow::new(&f, 0, len, true)
        {
            return Ok(JsonBuf::Mapped(m));
        }
    }
    Ok(match loc.read()? {
        std::borrow::Cow::Borrowed(b) => JsonBuf::Static(b),
        std::borrow::Cow::Owned(v) => JsonBuf::Owned(v),
    })
}

/// Build the blob of an ISF's JSON, remember it in-process ([`BUILT`]) and write its cache
/// file in the background (overlapping the plugin run; joined before exit), where the JSON is
/// freed too.
fn build_remember(url: &str, cf: Option<(PathBuf, Vec<u8>)>, json: JsonBuf, opts: &BuildOptions, parallel: bool) -> Result<std::sync::Arc<Vec<u8>>> {
    let blob = {
        let _t = crate::util::trace::span("isf parse+build");
        let b = if parallel { build_blob(&json, opts) } else { super::isf::build_blob_serial(&json, opts) };
        b.map_err(|e| Error::msg(format!("{url}: {e}")))?
    };
    let blob = std::sync::Arc::new(blob);
    if let Some((_, key)) = &cf {
        BUILT.lock().unwrap_or_else(|e| e.into_inner()).push((key.clone(), blob.clone()));
    }
    let writer = blob.clone();
    crate::util::bg::spawn(move || {
        drop(json);
        if let Some((cf, key)) = cf {
            let _t = crate::util::trace::span("isf cache write (background)");
            let len = (key.len() as u32).to_le_bytes();
            let _ = paths::write_atomic_parts(&cf, &cache_file_parts(&writer, &key, &len));
        }
    });
    Ok(blob)
}

/// The banner of the image being analysed, when a quick scan found it (see [`set_banner_hint`]).
static HINT: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);

/// A banner found in the image (`Linux version ...\n`, `Darwin Kernel Version ...`), set while
/// the identifier index runs: the index then builds exactly the ISFs whose identifier starts
/// with it (instead of guessing), and keeps no other JSON. Only a guide for speculation: the
/// automagic still decides, from the complete index, python's way.
pub fn set_banner_hint(banner: Option<Vec<u8>>) {
    *HINT.lock().unwrap_or_else(|e| e.into_inner()) = banner;
}

/// Speculative table builds done by the identifier index (see [`keep_decoded_for`]).
static SPEC_BUILDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// At most this many: a big symbol pack must not turn the index into a build farm.
const MAX_SPEC_BUILDS: usize = 3;

/// Inside the identifier index: `json` (all of `loc`) was identified as the OS whose kernel
/// ISF is loaded next. Build its table now, on this worker (the other workers keep
/// decompressing), for the first few such files; else keep the JSON (decompressed ones only)
/// so the load skips the decompression.
fn speculate(loc: &IsfLocation, identifier: &[u8], json: Vec<u8>, decoded: bool) {
    // plain JSON files load without decompression anyway: only compressed ones are worth it
    if !decoded {
        return;
    }
    match spec_decision(identifier) {
        Spec::Build => {
            let _t = crate::util::trace::span("isf speculative load (identifier index)");
            spec_build(loc, json);
        }
        Spec::Keep => keep_decoded(loc, json),
        Spec::Skip => {}
    }
}

/// What the identifier index does with a decoded ISF of the OS whose kernel table is loaded
/// next (see [`speculate`]).
enum Spec {
    Build,
    Keep,
    Skip,
}

fn spec_decision(identifier: &[u8]) -> Spec {
    use std::sync::atomic::Ordering;
    let hint = HINT.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(h) = hint {
        // the image's own banner is known: build exactly the matching ISFs, keep nothing else
        return if identifier.starts_with(&h) && SPEC_BUILDS.fetch_add(1, Ordering::Relaxed) < 2 * MAX_SPEC_BUILDS { Spec::Build } else { Spec::Skip };
    }
    if !*GUESS.lock().unwrap_or_else(|e| e.into_inner()) {
        return Spec::Skip;
    }
    if SPEC_BUILDS.fetch_add(1, Ordering::Relaxed) < MAX_SPEC_BUILDS { Spec::Build } else { Spec::Keep }
}

/// The identifier of a decoded ISF read through its lazy table (built right away instead of
/// after a separate identifier pass): for a big ISF of the OS whose kernel table is loaded next
/// (the likely kernel ISF). The lazy table is kept when [`speculate`] would build it. `Err`
/// gives the JSON back when no lazy table can be built (the caller extracts the identifier the
/// usual way).
fn lazy_identifier(loc: &IsfLocation, os: &str, json: Vec<u8>) -> std::result::Result<Option<(String, Vec<u8>)>, Vec<u8>> {
    let opts = BuildOptions::default();
    let core = match LazyCore::build(JsonBuf::Owned(json), &opts) {
        Ok(c) => std::sync::Arc::new(c),
        Err(JsonBuf::Owned(v)) => return Err(v),
        Err(_) => return Ok(None), // (never: the JSON went in owned)
    };
    let (win, mac, linux) = core.identifier_fields();
    let ident = identifier_from(win, mac, linux);
    if let Some((ios, iid)) = &ident
        && ios == os
        && matches!(spec_decision(iid), Spec::Build)
    {
        let url = loc.url();
        let cf = cache_file(loc, &url, &opts);
        let lock = cf.as_ref().map(|(_, k)| key_lock(k));
        let _g = lock.as_ref().map(|l| l.lock().unwrap_or_else(|e| e.into_inner()));
        if load_known(&url, &cf, "").is_none() {
            lazy_register(loc, &url, &cf, &core);
        }
    }
    Ok(ident)
}

/// A speculative table of `loc` from its decoded `json` (see [`speculate`]): a lazy table when
/// they are on (its blob deferred like any other), else the blob, built on this worker; nothing
/// when the table is already in memory or cached.
fn spec_build(loc: &IsfLocation, json: Vec<u8>) {
    let url = loc.url();
    let opts = BuildOptions::default();
    let cf = cache_file(loc, &url, &opts);
    let lock = cf.as_ref().map(|(_, k)| key_lock(k));
    let _g = lock.as_ref().map(|l| l.lock().unwrap_or_else(|e| e.into_inner()));
    if load_known(&url, &cf, "").is_some() {
        return;
    }
    if let Err(json) = lazy_build(loc, &url, &cf, JsonBuf::Owned(json), &opts) {
        let _ = build_remember(&url, cf, json, &opts, false);
    }
}

/// Load the table of `loc` on another thread (a speculative load: the automagic loads it next,
/// and that load waits for this one). Nothing happens if the table is in memory already.
pub fn load_in_background(loc: IsfLocation) {
    let url = loc.url();
    let cf = cache_file(&loc, &url, &BuildOptions::default());
    let known = cf.as_ref().is_some_and(|(_, key)| {
        BUILT.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|b| b.0 == *key) || LAZY_BUILT.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|b| b.0 == *key)
    });
    if known {
        return;
    }
    let _ = std::thread::Builder::new().name("rsvol-isf-spec".into()).spawn(move || {
        let _t = crate::util::trace::span("isf speculative load (background)");
        let _ = load(&loc, "", &BuildOptions::default());
    });
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

/// Extract (os, identifier) from ISF JSON without building the table (python's identifier
/// processors; the document must parse). The byte parser: in the identifier index many
/// workers extract at once while decompressing, and there a structural index's extra memory
/// traffic costs more than its faster skipping saves (measured: ~100 ms slower index).
pub fn extract_identifier(json: &[u8]) -> Option<(String, Vec<u8>)> {
    match extract_identifier_fast(json) {
        Some(r) => r,
        None => extract_identifier_with(&mut crate::util::json::Parser::new(json)),
    }
}

unsafe extern "C" {
    fn memchr(s: *const u8, c: i32, n: usize) -> *const u8;
}

/// libc `memchr` (vectorized; std does not expose one).
fn find_byte(hay: &[u8], c: u8) -> Option<usize> {
    if hay.is_empty() {
        return None;
    }
    // SAFETY: `hay` is a valid slice; memchr reads at most `hay.len()` bytes
    let p = unsafe { memchr(hay.as_ptr(), c as i32, hay.len()) };
    (!p.is_null()).then(|| p as usize - hay.as_ptr() as usize)
}

/// The byte range end of the JSON value starting at `v` (a document without backslashes:
/// strings end at the next quote), or None.
fn value_end(json: &[u8], v: usize) -> Option<usize> {
    match *json.get(v)? {
        b'"' => Some(v + 1 + find_byte(&json[v + 1..], b'"')? + 1),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut i = v;
            while i < json.len() {
                match json[i] {
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(i + 1);
                        }
                    }
                    b'"' => i += 1 + find_byte(&json[i + 1..], b'"')?,
                    _ => {}
                }
                i += 1;
            }
            None
        }
        _ => {
            let n = json[v..].iter().position(|&b| matches!(b, b',' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t')).unwrap_or(json.len() - v);
            Some(v + n)
        }
    }
}

/// [`extract_identifier`] without walking the whole document: one SIMD pass tracking bracket
/// depth and spotting the candidate member names ([`crate::util::jsonidx::ident_marks`])
/// locates the root's `metadata` / `symbols` members and the `symbols` members named
/// `linux_banner` / `version`; only those values are parsed (the same code as the byte
/// parser's path). ~4x faster than the byte parser, which skips member by member through the
/// `symbols` section (half to three quarters of a dwarf2json ISF).
/// `None` = not decidable this way (a backslash anywhere -- escapes could spell a key --,
/// unbalanced brackets, the root or a `symbols` value not an object): the byte parser decides.
fn extract_identifier_fast(json: &[u8]) -> Option<Option<(String, Vec<u8>)>> {
    let marks = crate::util::jsonidx::ident_marks(json)?;
    if marks.backslash {
        return None;
    }
    let (d1, d2) = (marks.d1, marks.d2);
    let ws = |mut i: usize| {
        while json.get(i).is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t')) {
            i += 1;
        }
        i
    };
    let root = ws(if json.starts_with(&[0xEF, 0xBB, 0xBF]) { 3 } else { 0 });
    if json.get(root) != Some(&b'{') {
        return None;
    }
    // the root's members: depth-1 strings followed by ':'
    let mut keys: Vec<(usize, &[u8], usize)> = Vec::new();
    for &p in &d1 {
        let close = p + 1 + find_byte(&json[p + 1..], b'"')?;
        let c = ws(close + 1);
        if json.get(c) == Some(&b':') {
            keys.push((p, &json[p + 1..close], ws(c + 1)));
        }
    }
    let mut win: Option<(String, String, u64)> = None;
    let mut linux: Option<String> = None;
    let mut mac: Option<String> = None;
    let parse = |v: usize| -> Option<crate::util::json::Json<'_>> {
        let end = value_end(json, v)?;
        crate::util::json::Parser::new(&json[v..end]).value().ok()
    };
    for (i, &(p, k, v)) in keys.iter().enumerate() {
        match k {
            b"metadata" => {
                let val = parse(v)?;
                if let Some(pdb) = val.path(&["windows", "pdb"]) {
                    let guid = pdb.get("GUID").and_then(|g| g.as_str()).unwrap_or("").to_string();
                    let db = pdb.get("database").and_then(|g| g.as_str()).unwrap_or("").to_string();
                    let age = pdb.get("age").and_then(|g| g.as_u64()).unwrap_or(0);
                    win = Some((guid, db, age));
                }
            }
            b"symbols" => {
                if json.get(v) != Some(&b'{') {
                    return None;
                }
                let end = keys.get(i + 1).map(|n| n.0).unwrap_or(json.len());
                let lo = d2.partition_point(|&q| q < p);
                for &q in d2[lo..].iter().take_while(|&&q| q < end) {
                    let close = q + 1 + find_byte(&json[q + 1..], b'"')?;
                    let c = ws(close + 1);
                    if json.get(c) != Some(&b':') {
                        continue; // a string value, not a member name
                    }
                    let w = ws(c + 1);
                    if json.get(w) != Some(&b'{') {
                        continue; // the byte parser skips non-object values
                    }
                    let val = parse(w)?;
                    if let Some(cd) = val.get("constant_data").and_then(|c| c.as_str()) {
                        if &json[q + 1..close] == b"linux_banner" {
                            linux = Some(cd.to_string());
                        } else {
                            mac = Some(cd.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Some(identifier_from(win, mac, linux))
}

/// [`extract_identifier`] through any pull parser.
pub fn extract_identifier_with<'a, P: crate::util::jsonidx::Pull<'a>>(p: &mut P) -> Option<(String, Vec<u8>)> {
    use crate::util::json::Kind;
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
    identifier_from(win, mac, linux)
}

/// python's identifier processors, in order: windows (metadata.windows.pdb), mac, linux.
pub(crate) fn identifier_from(win: Option<(String, String, u64)>, mac: Option<String>, linux: Option<String>) -> Option<(String, Vec<u8>)> {
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

/// `IdentEntry::os` of a file that could not be read (opening / decompressing failed), as
/// opposed to "" (read, no identifier): python's `update()` stores no row for it.
const UNREADABLE: &str = "?";

/// `IdentEntry` (os, identifier) fields of an [`extract_all`] result.
fn entry_fields(ident: std::result::Result<Option<(String, Vec<u8>)>, ()>) -> (String, Vec<u8>) {
    match ident {
        Ok(Some(x)) => x,
        Ok(None) => (String::new(), Vec::new()),
        Err(()) => (UNREADABLE.to_string(), Vec::new()),
    }
}

/// "windows" / "mac" / "linux" as a static str (python's `IdentifierProcessor`s), else None.
fn static_os(os: &str) -> Option<&'static str> {
    ["windows", "mac", "linux"].into_iter().find(|o| *o == os)
}

/// The identifier index over a symbol path: which ISF an identifier (banner, PDB) resolves to.
///
/// The index is python's identifier cache (`~/.cache/volatility3/identifier.cache`, or the one
/// under `--cache-path`) as python's `SqliteCache.update()` leaves it before a plugin runs (see
/// [`IdentifierIndex::build`]): python's rows in rowid order, then the ISFs python would (re)scan
/// in the order python inserts them, so every identifier resolves to the ISF python would load
/// (python takes the last row with the identifier; among ISFs sharing an identifier that
/// depends on its database's history). Without a usable python database (none yet, or
/// `--clear-cache`, which deletes it) the index is the database python would build from
/// scratch: every ISF on the search path, inserted in python's set order (see
/// [`super::pycache::update`]). Only the ISFs python would read are read, through rsvol's own
/// per-file index (`~/.cache/rsvol/identifiers.cache`). With `RSVOL_NO_PY_IDENT_SEED=1` rsvol
/// indexes every ISF itself, in search-path order.
pub struct IdentifierIndex {
    pub entries: Vec<IdentEntry>,
    locations: Vec<IsfLocation>,
    /// [`seed_state`] when the index was built
    seed_state: String,
    /// per entry, for an index built from python's database (or python's fresh one): python's
    /// `cached` time of a row python keeps as it is (not rescanned this time)
    py_cached: Option<Vec<Option<super::pycache::NaiveTime>>>,
    /// [`tree_stamps`] of the search path, taken before the index read it
    tree: Vec<u8>,
}

/// Where python's identifier rows come from.
#[derive(Clone, Debug)]
enum PySeed {
    /// python's database at this path (python creates it empty when missing or unusable)
    Db(PathBuf),
    /// python starts from an empty database (`--clear-cache` deletes it first)
    Fresh,
}

/// python's identifier cache as set by [`set_python_identifier_cache`] (unset: python's default).
static PY_DB: std::sync::RwLock<Option<PySeed>> = std::sync::RwLock::new(None);

/// The python identifier cache the identifier index starts from (python's `CACHE_PATH` after
/// `--cache-path`), or `None` for an empty one (`--clear-cache`: python deletes its cache
/// first). Set by `Context::new`.
pub fn set_python_identifier_cache(db: Option<PathBuf>) {
    *PY_DB.write().unwrap_or_else(|e| e.into_inner()) = Some(db.map_or(PySeed::Fresh, PySeed::Db));
}

/// Where the identifier index takes python's rows from, or `None` (`RSVOL_NO_PY_IDENT_SEED=1`:
/// rsvol's own index in search-path order).
fn py_seed() -> Option<PySeed> {
    if std::env::var_os("RSVOL_NO_PY_IDENT_SEED").is_some_and(|v| !v.is_empty() && v != "0") {
        return None;
    }
    match &*PY_DB.read().unwrap_or_else(|e| e.into_inner()) {
        Some(s) => Some(s.clone()),
        None => Some(PySeed::Db(super::pycache::db_path(None))),
    }
}

/// What the identifier index's python rows depend on: off, an empty database (`--clear-cache`,
/// or python's database absent), or the database's path and (size, mtime) -- python rewrites
/// the file whenever its update() changes a row.
fn seed_state() -> String {
    match py_seed() {
        None => "off".into(),
        Some(PySeed::Fresh) => "fresh".into(),
        Some(PySeed::Db(p)) => match paths::file_stamp(&p) {
            Some((s, m)) => format!("db\0{}\0{s}\0{m}", p.display()),
            None => "absent".into(),
        },
    }
}

/// Stamps of everything that decides which ISFs python finds on the search path: every
/// directory python's `rglob` enters under each directory root (a file added, removed or
/// renamed there changes its directory's mtime) and every `.zip` pack. Items as in
/// `idcands` (length, path, 24-byte stamp).
fn tree_stamps(path: &SymbolPath) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    let mut out = Vec::new();
    let push = |p: &Path, out: &mut Vec<u8>| {
        let b = p.as_os_str().as_bytes();
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
        out.extend_from_slice(&stamp_bytes(p));
    };
    for root in super::pycache::python_symbol_roots(path) {
        let Root::Dir(d) = root else { continue };
        let Ok(d) = std::fs::canonicalize(&d) else {
            // a root that appears later changes the answer too
            push(&d, &mut out);
            continue;
        };
        for (dir, entries) in super::pycache::rglob_dirs(&d) {
            push(&dir, &mut out);
            for (n, _) in entries.iter().filter(|(n, is_dir)| !is_dir && n.as_bytes().ends_with(b".zip")) {
                push(&dir.join(n), &mut out);
            }
        }
    }
    out
}

/// Whether every (path, stamp) item of a hex `idcands` / `idtree` value is unchanged.
fn stamps_hold(hex: &str) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Some(b) = unhex(hex) else { return false };
    let mut rest = b.as_slice();
    while !rest.is_empty() {
        let Some(n) = rest.get(..4).map(|l| u32::from_le_bytes(l.try_into().unwrap()) as usize) else { return false };
        let Some(item) = rest.get(4..4 + n + 24) else { return false };
        let p = Path::new(std::ffi::OsStr::from_bytes(&item[..n]));
        if stamp_bytes(p) != item[n..] {
            return false;
        }
        rest = &rest[4 + n + 24..];
    }
    true
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let h = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    b.chunks(2).map(|p| Some(h(p[0])? << 4 | h(p[1])?)).collect()
}

/// (size, mtime) of a file as 24 bytes (all ones when it cannot be stat'ed).
fn stamp_bytes(p: &Path) -> Vec<u8> {
    let (s, m) = paths::file_stamp(p).unwrap_or((u64::MAX, -1));
    let mut v = s.to_le_bytes().to_vec();
    v.extend_from_slice(&m.to_le_bytes());
    v
}

/// Whether a choice cached with [`IdentifierIndex::choice_deps`] still holds: the same seeding
/// state (python's database unchanged), the same ISFs on the search path (no directory of it
/// changed), every candidate ISF of the identifier unchanged, and no row python trusts due for
/// a rescan yet.
pub fn choice_deps_hold(kv: &[(String, String)]) -> bool {
    choice_deps_hold_at(kv, &seed_state(), super::pycache::utc_now())
}

/// [`choice_deps_hold`] for seeding state `state` at time `now`.
fn choice_deps_hold_at(kv: &[(String, String)], state: &str, now: i64) -> bool {
    let get = |k: &str| kv.iter().find(|(a, _)| a == k).map(|(_, b)| b.as_str());
    if get("idseed") != Some(paths::hex(state.as_bytes()).as_str()) {
        return false;
    }
    for k in ["idcands", "idtree"] {
        if let Some(c) = get(k)
            && !stamps_hold(c)
        {
            return false;
        }
    }
    if let Some(u) = get("iduntil") {
        match u.parse::<i64>() {
            Ok(u) if now < u => {}
            _ => return false,
        }
    }
    true
}

/// python's `update()` reading the new / stale ISFs `todo` (url, location): through rsvol's
/// per-file index (`identifiers.cache`, URL + size + mtime), extracting what it lacks (in
/// parallel; `on_work` first when that includes files other than the shipped ones). `None` =
/// python's read raises (the file cannot be opened / decompressed).
fn scan_for_python(todo: &[(&str, &IsfLocation)], on_work: &dyn Fn()) -> Vec<Option<super::pycache::Scanned>> {
    let cache_path = paths::rsvol_cache_dir().join("identifiers.cache");
    let mut all = read_ident_cache(&cache_path);
    let mut by_url: crate::util::FxHashMap<String, usize> = all.iter().enumerate().map(|(i, e)| (e.url.clone(), i)).collect();
    let locs: Vec<IsfLocation> = todo.iter().map(|(_, l)| (*l).clone()).collect();
    let stamps: Vec<Option<u64>> = todo.iter().map(|(u, l)| l.stamp_with_url(u)).collect();
    // a file that cannot be stat'ed cannot be opened either: no row
    let need: Vec<usize> = (0..todo.len())
        .filter(|&i| match (by_url.get(todo[i].0), stamps[i]) {
            (Some(&j), Some(s)) => all[j].stamp != s,
            (None, Some(_)) => true,
            (_, None) => false,
        })
        .collect();
    if need.iter().any(|&i| !matches!(locs[i], IsfLocation::Embedded { .. })) {
        on_work();
    }
    let fresh = extract_all(&locs, &need, |k, ident| {
        let i = need[k];
        let (os, identifier) = entry_fields(ident);
        IdentEntry { url: todo[i].0.to_string(), stamp: stamps[i].unwrap_or(0), os, identifier }
    });
    let changed = !fresh.is_empty();
    for e in fresh {
        match by_url.get(&e.url) {
            Some(&j) => all[j] = e,
            None => {
                by_url.insert(e.url.clone(), all.len());
                all.push(e);
            }
        }
    }
    let out = (0..todo.len())
        .map(|i| {
            stamps[i]?;
            let e = &all[*by_url.get(todo[i].0)?];
            match e.os.as_str() {
                UNREADABLE => None,
                "" => Some(super::pycache::Scanned { identifier: None, os: None, stats: [0; 4] }),
                os => Some(super::pycache::Scanned { identifier: Some(e.identifier.clone()), os: static_os(os), stats: [0; 4] }),
            }
        })
        .collect();
    if changed {
        // off the critical path (joined before exit)
        crate::util::bg::spawn(move || write_ident_cache(&cache_path, &all));
    }
    out
}

impl IdentifierIndex {
    /// Build the index for `path` (+ the `-u` identifier list `remote`): seeded from python's
    /// identifier cache when possible (see the type's docs), else rsvol's own. `on_work` runs
    /// first when ISFs other than the shipped ones must be read.
    pub fn build(path: &SymbolPath, remote: Option<&str>, on_work: &dyn Fn()) -> IdentifierIndex {
        let state = seed_state();
        // before the index reads the tree: a change while it does invalidates what it decides
        let tree = tree_stamps(path);
        let mut index = match Self::seeded(path, remote, on_work) {
            Some(i) => i,
            None => {
                let mut index = Self::update_with(path, on_work);
                // python SymbolCacheMagic: remote rows are (re)inserted after the local scan, so
                // they come last and win `find_location` / `get_identifier_dictionary` ties
                if let Some(url) = remote {
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
                index
            }
        };
        index.seed_state = state;
        index.tree = tree;
        index
    }

    /// The index from python's identifier cache (`None`: `RSVOL_NO_PY_IDENT_SEED=1`): python's
    /// rows after an emulated `SqliteCache.update()` (`symbols::pycache`), in rowid order; an
    /// empty database where python starts from one (`--clear-cache`; a database that is
    /// missing, unreadable or of another schema, which python recreates). The ISFs that
    /// update() would (re)scan are read through rsvol's per-file index ([`scan_for_python`]).
    fn seeded(path: &SymbolPath, remote: Option<&str>, on_work: &dyn Fn()) -> Option<IdentifierIndex> {
        use super::pycache;
        let rows = match py_seed()? {
            PySeed::Fresh => Vec::new(),
            PySeed::Db(db) => {
                let _t = crate::util::trace::span("identifier index: read python identifier.cache");
                pycache::read(&db).unwrap_or_default()
            }
        };
        let _t = crate::util::trace::span("identifier index: seeded from python's cache");
        let roots = pycache::python_symbol_roots(path);
        Some(Self::from_python_rows(rows, &roots, pycache::utc_now(), remote, |todo| scan_for_python(todo, on_work)))
    }

    /// [`IdentifierIndex::seeded`] from python's `rows` (rowid order), for the python symbol
    /// path `roots` at time `now`; `scan` reads what python's update() would (re)scan.
    fn from_python_rows(
        mut rows: Vec<super::pycache::CacheRow>,
        roots: &[Root],
        now: i64,
        remote: Option<&str>,
        scan: impl FnOnce(&[(&str, &IsfLocation)]) -> Vec<Option<super::pycache::Scanned>>,
    ) -> IdentifierIndex {
        use super::pycache;
        let info = pycache::update(&mut rows, roots, now, remote, scan);
        crate::util::trace::note(|| format!("identifier index: {} rows after python's update(), {} trusted", rows.len(), info.trusted.len()));
        let mut entries = Vec::new();
        let mut locations = Vec::new();
        let mut cached = Vec::new();
        for r in &rows {
            // only a bytes identifier with a known OS can match python's lookups
            let (Some(ident), Some(os)) = (r.identifier_bytes(), r.os().and_then(static_os)) else { continue };
            let loc = info.on_disk.get(&r.location).cloned().unwrap_or_else(|| pycache::location_of(&r.location));
            let trusted = r.local && info.trusted.contains(&r.location);
            cached.push(match &r.cached {
                crate::util::sqlite::Value::Text(t) if trusted => pycache::fromisoformat(t),
                _ => None,
            });
            entries.push(IdentEntry { url: r.location.clone(), stamp: 0, os: os.to_string(), identifier: ident.to_vec() });
            locations.push(loc);
        }
        IdentifierIndex { entries, locations, seed_state: String::new(), py_cached: Some(cached), tree: Vec::new() }
    }

    /// Whether the index is python's identifier cache (as it is, or as python would build it
    /// from scratch).
    pub fn is_seeded(&self) -> bool {
        self.py_cached.is_some()
    }

    /// Key material a cached choice for `identifier` (made from this index) depends on beyond
    /// the symbol path fingerprint, as `key=value` pairs for the automagic caches (checked by
    /// [`choice_deps_hold`]): the seeding state and the directories of the search path (a new
    /// or removed ISF anywhere can change python's choice: its rows are inserted in set order);
    /// for an index from python's database also the candidate ISFs (every location with the
    /// identifier: python rescans a modified one once its row is 3 days old, which moves it to
    /// the end) and when python would first rescan a candidate it trusts now although the file
    /// is newer than its row.
    pub fn choice_deps(&self, os: &str, identifier: &[u8]) -> Vec<(&'static str, String)> {
        use super::pycache;
        let mut out = vec![("idseed", paths::hex(self.seed_state.as_bytes())), ("idtree", paths::hex(&self.tree))];
        let Some(py_cached) = &self.py_cached else { return out };
        let mut cands: Vec<u8> = Vec::new();
        let mut until: Option<i64> = None;
        for (i, e) in self.entries.iter().enumerate() {
            if e.os != os || e.identifier != identifier {
                continue;
            }
            let file = match &self.locations[i] {
                IsfLocation::File(p) => Some(p),
                IsfLocation::Zip { zip, .. } => Some(zip),
                _ => None,
            };
            if let Some(f) = file {
                let b = f.as_os_str().as_encoded_bytes();
                cands.extend_from_slice(&(b.len() as u32).to_le_bytes());
                cands.extend_from_slice(b);
                cands.extend_from_slice(&stamp_bytes(f));
            }
            if let Some(c) = py_cached[i]
                && pycache::update_pathname(&e.url).and_then(|p| pycache::mtime_local(&p)).is_some_and(|ts| c < ts)
            {
                let t = pycache::rescan_window_opens(c);
                until = Some(until.map_or(t, |u| u.min(t)));
            }
        }
        out.push(("idcands", paths::hex(&cands)));
        if let Some(u) = until {
            out.push(("iduntil", u.to_string()));
        }
        out
    }

    /// Build/refresh the index: only new or modified files are (decompressed and) parsed.
    pub fn update(path: &SymbolPath) -> IdentifierIndex {
        Self::update_with(path, &|| {})
    }

    /// [`IdentifierIndex::update`]; `on_work` runs first when ISFs other than the shipped ones
    /// must be (re)read.
    pub fn update_with(path: &SymbolPath, on_work: &dyn Fn()) -> IdentifierIndex {
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
        // (shipped ISFs are never kernel ISFs: re-reading only those needs no hint)
        if todo.iter().any(|&i| !matches!(locs[i], IsfLocation::Embedded { .. })) {
            on_work();
        }
        let fresh = extract_all(&locs, &todo, |k, ident| {
            let i = todo[k];
            let (os, identifier) = entry_fields(ident);
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
        let mut entries = Vec::with_capacity(locs.len());
        let mut locations = Vec::with_capacity(locs.len());
        for (l, u) in locs.into_iter().zip(&urls) {
            if let Some(&j) = by_url.get(u) {
                entries.push(all[j].clone());
                locations.push(l);
            }
        }
        if changed {
            // off the critical path (joined before exit)
            crate::util::bg::spawn(move || write_ident_cache(&cache_path, &all));
        }
        IdentifierIndex { entries, locations, seed_state: String::new(), py_cached: None, tree: Vec::new() }
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
    with_json_len(loc, buf, false, |j, _| f(j))
}

/// [`with_json`]; `f` also gets `Some((n, decompressed))` when the JSON is `buf[..n]`.
/// `parallel`: decode the blocks of a multi-block `.xz` file on several threads.
fn with_json_len<R>(loc: &IsfLocation, buf: &mut Vec<u8>, parallel: bool, f: impl FnOnce(&[u8], Option<(usize, bool)>) -> R) -> Result<R> {
    let owned;
    let (json, decoded): (&[u8], Option<(usize, bool)>) = match loc {
        IsfLocation::Embedded { data, .. } => (data, None),
        IsfLocation::File(p) if p.to_string_lossy().ends_with(".xz") => {
            let raw = std::fs::read(p)?;
            let n = crate::codecs::xz::decompress_reuse(&raw, buf, parallel)?;
            (&buf[..n], Some((n, true)))
        }
        IsfLocation::File(p) if p.to_string_lossy().ends_with(".json") => {
            use std::io::Read;
            let mut file = std::fs::File::open(p)?;
            let len = file.metadata()?.len() as usize;
            if buf.len() < len {
                // fresh zero pages, not a memset of the grown buffer (the read writes them all)
                *buf = crate::codecs::try_zeroed(len)?;
            }
            file.read_exact(&mut buf[..len])?;
            (&buf[..len], Some((len, false)))
        }
        _ => {
            owned = loc.read()?;
            (&owned, None)
        }
    };
    Ok(f(json, decoded))
}

/// OS whose decompressed ISFs the identifier index keeps (see [`keep_decoded_for`]).
static KEEP_OS: std::sync::Mutex<Option<&'static str>> = std::sync::Mutex::new(None);

/// Decompressed ISFs kept by the identifier index: source identity -> JSON.
static KEPT: std::sync::Mutex<Vec<(Vec<u8>, Vec<u8>)>> = std::sync::Mutex::new(Vec::new());

/// Memory the kept JSON may use.
const KEEP_BUDGET: usize = 512 << 20;

/// While building the identifier index, keep the decompressed JSON of the ISFs identified as
/// `os` (within [`KEEP_BUDGET`]): the automagic that asked for the index loads one of them next,
/// and [`load`] then skips its decompression. `None` (once the automagic is done) stops
/// keeping and frees what is kept and the speculative builds no table uses (in the
/// background).
pub fn keep_decoded_for(os: Option<&'static str>) {
    keep_decoded_for_with(os, true)
}

/// Whether the index may build / keep ISFs without a banner hint (a few linux kernels: yes;
/// a pack of 100+ mac kernels: guessing is pointless).
static GUESS: std::sync::Mutex<bool> = std::sync::Mutex::new(true);

/// [`keep_decoded_for`]; `guess`: build or keep ISFs of `os` even without a banner hint.
pub fn keep_decoded_for_with(os: Option<&'static str>, guess: bool) {
    *GUESS.lock().unwrap_or_else(|e| e.into_inner()) = guess;
    *KEEP_OS.lock().unwrap_or_else(|e| e.into_inner()) = os;
    if os.is_none() {
        set_banner_hint(None);
        let kept = std::mem::take(&mut *KEPT.lock().unwrap_or_else(|e| e.into_inner()));
        // speculative builds nobody loaded (only the memo holds them) go too
        let unused: Vec<_> = {
            let mut b = BUILT.lock().unwrap_or_else(|e| e.into_inner());
            let (keep, drop): (Vec<_>, Vec<_>) = std::mem::take(&mut *b).into_iter().partition(|e| std::sync::Arc::strong_count(&e.1) > 1);
            *b = keep;
            drop
        };
        if !kept.is_empty() || !unused.is_empty() {
            crate::util::bg::spawn(move || drop((kept, unused)));
        }
    }
}

fn keep_decoded(loc: &IsfLocation, json: Vec<u8>) {
    let Some(id) = source_identity(loc, &loc.url()) else { return };
    let mut k = KEPT.lock().unwrap_or_else(|e| e.into_inner());
    let used: usize = k.iter().map(|e| e.1.capacity()).sum();
    if used + json.capacity() <= KEEP_BUDGET {
        k.push((id, json));
    }
}

/// The kept decompressed JSON of `loc` (taken: used once).
fn take_kept(loc: &IsfLocation, url: &str) -> Option<Vec<u8>> {
    let mut k = KEPT.lock().unwrap_or_else(|e| e.into_inner());
    if k.is_empty() {
        return None;
    }
    let id = source_identity(loc, url)?;
    let i = k.iter().position(|e| e.0 == id)?;
    Some(k.swap_remove(i).1)
}

/// Identifier extraction for `todo` (indexes into `locs`) on all cores: `make(k, identifier)`
/// builds the k-th result (`Ok(None)` = no identifier / not an ISF, `Err` = unreadable: opening
/// or decompressing failed). Largest files first;
/// each worker reuses one decode buffer; the worker count keeps the decode buffers within a
/// memory budget.
fn extract_all<R: Send>(locs: &[IsfLocation], todo: &[usize], make: impl Fn(usize, std::result::Result<Option<(String, Vec<u8>)>, ()>) -> R + Sync) -> Vec<R> {
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
    // a few big (kernel) ISFs among many small ones: their blocks decode on the cores the
    // small files leave idle (a 64 MB dwarf2json ISF is 2-3 xz blocks)
    const BIG: u64 = 32 << 20;
    let big_par = est.iter().filter(|&&e| e >= BIG).count() * 3 <= crate::util::par::threads();
    let next = AtomicUsize::new(0);
    let keep_os = *KEEP_OS.lock().unwrap_or_else(|e| e.into_inner());
    let work = |out: &mut Vec<(usize, R)>| {
        let mut buf = Vec::new();
        loop {
            let j = next.fetch_add(1, Ordering::Relaxed);
            let Some(&k) = order.get(j) else { break };
            let loc = &locs[todo[k]];
            let mut decoded = None;
            let t0 = crate::util::trace::enabled().then(std::time::Instant::now);
            let mut t1 = None;
            // a big compressed ISF in a `<os>/` directory while the automagic waits for that
            // OS's kernel table: its lazy table gives the identifier (no separate pass)
            let lazy_first = keep_os.is_some_and(|os| lazy_tables_on() && est[k] >= LAZY_MIN as u64 && loc.url().contains(&format!("/{os}/")));
            let ident = with_json_len(loc, &mut buf, big_par && est[k] >= BIG, |json, n| {
                decoded = n;
                t1 = t0.map(|_| std::time::Instant::now());
                if lazy_first && matches!(n, Some((_, true))) && json.len() >= LAZY_MIN { None } else { Some(extract_identifier(json)) }
            })
            .map_err(drop);
            let ident = match ident {
                Ok(Some(id)) => Ok(id),
                Err(()) => Err(()),
                Ok(None) => {
                    // lazy-first: the JSON is buf[..n]
                    let n = decoded.map_or(0, |d| d.0);
                    let mut v = std::mem::take(&mut buf);
                    v.truncate(n);
                    decoded = None; // the lazy table (if kept) has the JSON now
                    match lazy_identifier(loc, keep_os.unwrap_or(""), v) {
                        Ok(id) => Ok(id),
                        Err(v) => {
                            let id = extract_identifier(&v);
                            buf = v;
                            decoded = Some((n, true));
                            Ok(id)
                        }
                    }
                }
            };
            if let (Some(t0), Some(t1)) = (t0, t1)
                && est[k] >= 4 << 20
            {
                crate::util::trace::note(|| format!("identifier index: {} read+decode {:.1} ms, identifier {:.1} ms", loc.url(), (t1 - t0).as_secs_f64() * 1e3, t1.elapsed().as_secs_f64() * 1e3));
            }
            // the OS the caller is about to load a kernel ISF for: build it now or keep the JSON
            if let (Some((n, was_decoded)), Some(os), Ok(Some((ios, iid)))) = (decoded, keep_os, &ident)
                && os == ios
            {
                let mut v = std::mem::take(&mut buf);
                v.truncate(n);
                speculate(loc, iid, v, was_decoded);
            }
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
        .map(|(k, r)| r.unwrap_or_else(|| make(k, with_json(&locs[todo[k]], &mut buf, extract_identifier).map_err(drop))))
        .collect()
}

/// rsvol's per-file identifier results (`identifiers.cache`): url, stamp, os, identifier per
/// entry. Format 3 marks unreadable files (os [`UNREADABLE`]); older files are ignored.
fn read_ident_cache(path: &Path) -> Vec<IdentEntry> {
    let Ok(b) = std::fs::read(path) else { return Vec::new() };
    let mut out = Vec::new();
    let mut i = 0usize;
    let rd = |i: &mut usize, n: usize| -> Option<&[u8]> {
        let s = b.get(*i..*i + n)?;
        *i += n;
        Some(s)
    };
    if rd(&mut i, 8) != Some(b"RSVOLID3") {
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
    b.extend_from_slice(b"RSVOLID3");
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
    identifier_index_with(path, &|| {})
}

/// [`identifier_index`]; `on_work` runs when ISFs must actually be read (a cold or stale
/// index), e.g. to start a banner-hint scan only then.
pub fn identifier_index_with(path: &SymbolPath, on_work: &dyn Fn()) -> &'static IdentifierIndex {
    // one index per distinct search path, `-u` list and seeding state (a process normally has
    // exactly one; a long-running `vol serve` rebuilds it when python's database changed)
    type Key = (SymbolPath, Option<String>, String);
    static INDEX: std::sync::Mutex<Vec<(Key, &'static IdentifierIndex)>> = std::sync::Mutex::new(Vec::new());
    let remote = super::remote_isf_url();
    let state = seed_state();
    let mut all = INDEX.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, i)) = all.iter().find(|((p, r, s), _)| p == path && *r == remote && *s == state) {
        return i;
    }
    let _t = crate::util::trace::span("identifier index update");
    let index = IdentifierIndex::build(path, remote.as_deref(), on_work);
    let i: &'static IdentifierIndex = Box::leak(Box::new(index));
    all.push(((path.clone(), remote, i.seed_state.clone()), i));
    i
}

/// python's identifier of a Windows PDB: `<pdb name>|<GUID>|<age>`.
fn windows_identifier(pdb_name: &str, guid: &str, age: u32) -> String {
    format!("{}|{}|{}", pdb_name.trim_matches('\0'), guid.to_uppercase(), age)
}

/// The first steps of [`find_windows_isf`]: an ISF found by name (canonical layout
/// `<root>/windows/<pdb>/<GUID>-<AGE>.json*`, then python's rglob), or the one this process
/// converted for the PDB (its file is written after the output, see [`finish_deferred`]),
/// without the identifier index or a download. Cheap (a few stats), for speculative loading.
pub fn find_windows_isf_local(path: &SymbolPath, pdb_name: &str, guid: &str, age: u32) -> Option<IsfLocation> {
    let pdb_name = pdb_name.trim_matches('\0');
    if let Some(p) = pending_path(pdb_name, guid, age) {
        return Some(IsfLocation::File(p));
    }
    let filter = format!("{}/{}-{}", pdb_name, guid.to_uppercase(), age);
    // fast path: the canonical layout <root>/windows/<pdb>/<GUID>-<AGE>.json*
    for root in &path.roots {
        if let Root::Dir(d) = root {
            for ext in ISF_EXTENSIONS {
                let p = d.join("windows").join(format!("{filter}{ext}"));
                if p.is_file() {
                    return Some(IsfLocation::File(p));
                }
            }
        }
    }
    path.find_first("windows", &filter)
}

/// The ISF [`find_windows_isf`] returns, found without a download: python's identifier-cache
/// choice (the same memoized answer the final lookup reads), else an ISF named by the PDB.
/// For the speculative kernel table load while the kernel scan runs: with several copies of
/// one GUID on the search path it is the copy python loads, never the first one by name.
pub fn find_windows_isf_no_download(path: &SymbolPath, pdb_name: &str, guid: &str, age: u32) -> Option<IsfLocation> {
    let ident = windows_identifier(pdb_name, guid, age);
    find_location_cached(path, ident.as_bytes(), "windows").or_else(|| find_windows_isf_local(path, pdb_name, guid, age))
}

/// Bump when what a cached [`find_location_cached`] answer means changes.
const CHOICE_CACHE_VERSION: u32 = 1;

/// The cache file of the [`find_location_cached`] answer for (`path`, `identifier`, `os`) and
/// its full key material.
fn choice_file(path: &SymbolPath, identifier: &[u8], os: &str) -> (PathBuf, String) {
    let remote = super::remote_isf_url();
    let mut k: Vec<u8> = CHOICE_CACHE_VERSION.to_le_bytes().to_vec();
    for part in [os.as_bytes(), identifier, format!("{:?}", path.roots).as_bytes(), remote.as_deref().unwrap_or("").as_bytes()] {
        k.extend_from_slice(&(part.len() as u64).to_le_bytes());
        k.extend_from_slice(part);
    }
    let h = crate::layers::scancache::key_hash(&k);
    (paths::rsvol_cache_dir().join("isfchoice").join(format!("{h:016x}.{os}")), paths::hex(&k))
}

/// python `SqliteCache(CACHE_PATH/identifier.cache).find_location(identifier, os)` right after
/// the `SymbolCacheMagic` update: the location of the last row with the identifier in the
/// identifier index (see [`IdentifierIndex`]), `None` without one. The answer is kept in
/// `~/.cache/rsvol/isfchoice/` with its dependencies ([`IdentifierIndex::choice_deps`]), so a
/// later run with the same python database and search path skips building the index.
pub fn find_location_cached(path: &SymbolPath, identifier: &[u8], os: &str) -> Option<IsfLocation> {
    choice_cached(path, identifier, os).unwrap_or_else(|| choice_from_index(path, identifier, os))
}

/// The [`find_location_cached`] answer kept by an earlier run, if it still holds.
fn choice_cached(path: &SymbolPath, identifier: &[u8], os: &str) -> Option<Option<IsfLocation>> {
    let (file, key) = choice_file(path, identifier, os);
    let s = std::fs::read_to_string(&file).ok()?;
    let mut lines = s.lines();
    if lines.next().and_then(|l| l.strip_prefix("key=")) != Some(key.as_str()) {
        return None;
    }
    let kv: Vec<(String, String)> = lines.filter_map(|l| l.split_once('=')).map(|(a, b)| (a.to_string(), b.to_string())).collect();
    let loc = kv.iter().find(|(k, _)| k == "loc").map(|(_, v)| v.clone())?;
    if !choice_deps_hold(&kv) {
        return None;
    }
    Some((!loc.is_empty()).then(|| super::pycache::location_of(&unhex(&loc).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default())))
}

/// The [`find_location_cached`] answer from the identifier index (built or refreshed now when
/// needed), kept for later runs.
fn choice_from_index(path: &SymbolPath, identifier: &[u8], os: &str) -> Option<IsfLocation> {
    let (file, key) = choice_file(path, identifier, os);
    let idx = {
        // an index that has to read ISFs decompresses the one the caller loads next: it builds
        // the tables of exactly the ISFs with this identifier on the way (the load finds them)
        set_banner_hint(Some(identifier.to_vec()));
        *KEEP_OS.lock().unwrap_or_else(|e| e.into_inner()) = static_os(os);
        let idx = identifier_index(path);
        *KEEP_OS.lock().unwrap_or_else(|e| e.into_inner()) = None;
        set_banner_hint(None);
        idx
    };
    let found = idx.find(identifier, os);
    let mut s = format!("key={key}\nloc={}\n", found.as_ref().map(|l| paths::hex(l.url().as_bytes())).unwrap_or_default());
    for (k, v) in idx.choice_deps(os, identifier) {
        s.push_str(&format!("{k}={v}\n"));
    }
    // off the critical path (joined before exit)
    crate::util::bg::spawn(move || {
        let _ = paths::write_atomic(&file, s.as_bytes());
    });
    found
}

/// Find the ISF for a Windows PDB (python `PDBUtility.load_windows_symbol_table`): the location
/// python's identifier cache gives `<pdb>|<GUID>|<age>` (the last row: with the same ISF in
/// several symbol directories, the one python's database lists last), else an ISF named
/// `windows/<pdb>/<GUID>-<AGE>.json*`, else download + convert.
///
/// When the identifier index has to be built and no ISF is named by the PDB (a conversion is
/// likely next), a PDB already in python's cache is converted meanwhile, in memory. In the
/// one-shot CLI (see [`set_lazy_tables`]) the converted table's `.json.xz` is written after the
/// output (by the helper process, see [`finish_deferred`]); this run uses the JSON it holds.
pub fn find_windows_isf(path: &SymbolPath, pdb_name: &str, guid: &str, age: u32, offline: bool) -> Result<IsfLocation> {
    let ident = windows_identifier(pdb_name, guid, age);
    let local = match choice_cached(path, ident.as_bytes(), "windows") {
        Some(Some(l)) => return Ok(l),
        Some(None) => find_windows_isf_local(path, pdb_name, guid, age),
        None => {
            let local = find_windows_isf_local(path, pdb_name, guid, age);
            if local.is_none() && !offline {
                super::windows::pdb::convert_ahead(pdb_name.trim_matches('\0'), guid, age, false);
            }
            if let Some(l) = choice_from_index(path, ident.as_bytes(), "windows") {
                return Ok(l);
            }
            local
        }
    };
    if let Some(l) = local {
        return Ok(l);
    }
    let pdb_name = pdb_name.trim_matches('\0');
    // download + convert into the first writable directory of the search path, like python's
    // `download_pdb_isf` over `symbols.__path__` (the embedded roots are not directories)
    let dirs: Vec<PathBuf> = path.roots.iter().filter_map(|r| if let Root::Dir(d) = r { Some(d.clone()) } else { None }).collect();
    let defer = lazy_tables_on() && std::env::var_os("RSVOL_PDB_ISF_WRITE").is_none_or(|v| v != "sync");
    let (out, json, job) = super::windows::pdb::download_and_convert_with(pdb_name, &guid.to_uppercase(), age, &dirs, offline, defer)?;
    let loc = IsfLocation::File(out);
    match job {
        // the load that follows builds the table from this JSON (the file does not exist yet)
        Some(job) => {
            let key = (pdb_name.to_string(), guid.to_uppercase(), age);
            PENDING_ISF.lock().unwrap_or_else(|e| e.into_inner()).push(PendingIsf { key, job, json: std::sync::Arc::new(json), table: None });
        }
        // the load that follows builds the table from this JSON instead of decompressing the file
        None => keep_decoded(&loc, json),
    }
    Ok(loc)
}

/// A converted PDB table of this run whose `.json.xz` is written after the output.
struct PendingIsf {
    /// (pdb name, GUID, age)
    key: (String, String, u32),
    job: super::windows::pdb::IsfWrite,
    json: std::sync::Arc<Vec<u8>>,
    /// the table built from `json` (default options), shared by every load of it
    table: Option<PendingTable>,
}

enum PendingTable {
    Lazy(std::sync::Arc<LazyCore>),
    Blob(std::sync::Arc<Vec<u8>>),
}

/// The converted tables whose files are still to be written (see [`find_windows_isf`]).
static PENDING_ISF: std::sync::Mutex<Vec<PendingIsf>> = std::sync::Mutex::new(Vec::new());

/// The final path of the table this run converted for a PDB, while its file is pending.
fn pending_path(pdb_name: &str, guid: &str, age: u32) -> Option<PathBuf> {
    let g = PENDING_ISF.lock().unwrap_or_else(|e| e.into_inner());
    g.iter().find(|p| p.key.0 == pdb_name && p.key.1 == guid.to_uppercase() && p.key.2 == age).map(|p| p.job.path.clone())
}

/// [`load`] of a pending converted table (the file at `path` is written later): built from the
/// JSON in memory once, then shared. `None` when `path` is not pending.
fn load_pending(path: &Path, name: &str, url: &str, opts: &BuildOptions) -> Option<Result<SymbolTable>> {
    let mut g = PENDING_ISF.lock().unwrap_or_else(|e| e.into_inner());
    let p = g.iter_mut().find(|p| p.job.path == path)?;
    if opts.natives.is_some() {
        // (not how a PDB table is loaded: built as asked, not kept)
        let blob = build_blob(&p.json, opts).map_err(|e| Error::msg(format!("{url}: {e}")));
        return Some(blob.and_then(|b| SymbolTable::from_blob(Blob::Shared(std::sync::Arc::new(b)), name, url)));
    }
    if p.table.is_none() {
        let lazy = if lazy_tables_on() && p.json.len() >= LAZY_MIN { LazyCore::build(JsonBuf::Shared(p.json.clone()), opts).ok() } else { None };
        p.table = Some(match lazy {
            Some(core) => {
                crate::util::trace::note(|| format!("lazy table: {url} (converted; file pending)"));
                PendingTable::Lazy(std::sync::Arc::new(core))
            }
            None => {
                let _t = crate::util::trace::span("isf parse+build");
                match build_blob(&p.json, opts) {
                    Ok(b) => PendingTable::Blob(std::sync::Arc::new(b)),
                    Err(e) => return Some(Err(Error::msg(format!("{url}: {e}")))),
                }
            }
        });
    }
    Some(match p.table.as_ref()? {
        PendingTable::Lazy(c) => SymbolTable::from_lazy(c.clone(), name, url),
        PendingTable::Blob(b) => SymbolTable::from_blob(Blob::Shared(b.clone()), name, url),
    })
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

    /// The fast extractor agrees with the byte parser on every ISF here and on shipped ones,
    /// and on damaged copies whenever it decides (when the byte parser fails, the fast path
    /// may still decide: it only checks bracket balance, like a byte-level skip).
    #[test]
    fn fast_identifier_equals_byte_parser() {
        let byte = |j: &[u8]| extract_identifier_with(&mut crate::util::json::Parser::new(j));
        let mut docs: Vec<Vec<u8>> = crate::symbols::embedded::FILES.iter().map(|&(rel, _, data)| if rel.ends_with(".xz") { crate::codecs::xz::decompress(data).unwrap() } else { data.to_vec() }).collect();
        docs.push(br#"{"metadata": {"format": "6.2.0"}, "symbols": {"a": {"address": 1}, "version": {"address": 2, "constant_data": "RGFyd2lu"}, "linux_banner": {"constant_data": "TGludXg="}, "x": "version"}, "user_types": {"version": {"fields": {}}}}"#.to_vec());
        docs.push(br#"{"symbols": {"linux_banner": {"constant_data": "TGludXg="}}, "metadata": {"windows": {"pdb": {"GUID": "ab", "age": 1, "database": "k.pdb"}}}, "symbols": {"version": 5}}"#.to_vec());
        docs.push(br#"{"a": ["version", {"linux_banner": {"constant_data": "eA=="}}], "symbols": {"sub": {"version": {"constant_data": "eQ=="}}}}"#.to_vec());
        let mut n = 0;
        for d in &docs {
            if let Some(f) = extract_identifier_fast(d) {
                assert_eq!(f, byte(d), "{}", String::from_utf8_lossy(&d[..d.len().min(200)]));
                n += 1;
            }
        }
        assert!(n > 20, "{n}");
        // damage
        let base = &docs[docs.len() - 3];
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for i in 0..base.len() {
            for _ in 0..6 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let mut d = base.clone();
                d[i] = b"{}[]:,\" \\ab"[(x >> 33) as usize % 11];
                if let (Some(f), Some(b)) = (extract_identifier_fast(&d), byte(&d)) {
                    assert_eq!(f, Some(b), "{}", String::from_utf8_lossy(&d));
                }
            }
        }
    }

    /// Same on the ISFs of this machine (`cargo test --release fast_identifier_on_all_isfs -- --ignored`).
    #[test]
    #[ignore]
    fn fast_identifier_on_all_isfs() {
        let path = SymbolPath::new(&["/home/user/rs-vol/testdata/symbols".to_string()]);
        let mut buf = Vec::new();
        let (mut fast, mut n) = (0, 0);
        for loc in path.all() {
            let (f, b) = with_json(&loc, &mut buf, |j| (extract_identifier_fast(j), extract_identifier_with(&mut crate::util::json::Parser::new(j)))).unwrap();
            if let Some(f) = f {
                assert_eq!(f, b, "{}", loc.url());
                fast += 1;
            }
            n += 1;
        }
        println!("{fast}/{n} decided by the fast extractor");
    }

    /// Where the identifier index's CPU goes, one thread: decompression vs extraction.
    /// `cargo test --release ident_cost -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn ident_cost() {
        let path = SymbolPath::new(&["/home/user/rs-vol/testdata/symbols".to_string()]);
        let (mut td, mut te, mut bytes) = (0f64, 0f64, 0usize);
        let mut buf = Vec::new();
        for loc in path.all() {
            let IsfLocation::File(p) = &loc else { continue };
            if !p.to_string_lossy().ends_with(".xz") {
                continue;
            }
            let raw = std::fs::read(p).unwrap();
            let t = std::time::Instant::now();
            let n = crate::codecs::xz::decompress_reuse(&raw, &mut buf, false).unwrap();
            td += t.elapsed().as_secs_f64();
            let t = std::time::Instant::now();
            std::hint::black_box(extract_identifier(&buf[..n]));
            te += t.elapsed().as_secs_f64();
            bytes += n;
        }
        println!("{:.0} MB decompressed: decode {:.0} ms ({:.0} MB/s), extract {:.0} ms ({:.0} MB/s)", bytes as f64 / 1e6, td * 1e3, bytes as f64 / 1e6 / td, te * 1e3, bytes as f64 / 1e6 / te);
    }

    /// Components of the fast extractor on one document.
    /// `RSVOL_BENCH_JSON=x.json cargo test --release fast_ident_parts -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn fast_ident_parts() {
        use crate::symbols::linux::search::Needle;
        let data = std::fs::read(std::env::var("RSVOL_BENCH_JSON").unwrap()).unwrap();
        let best = |f: &mut dyn FnMut()| {
            let mut b = f64::MAX;
            for _ in 0..10 {
                let t = std::time::Instant::now();
                f();
                b = b.min(t.elapsed().as_secs_f64());
            }
            b * 1e3
        };
        let t_bs = best(&mut || { std::hint::black_box(find_byte(&data, b'\\')); });
        let mut n = 0;
        let t_n1 = best(&mut || {
            n = 0;
            Needle::new(b"\"linux_banner\"").for_each(&data, |_| {
                n += 1;
                true
            })
        });
        let t_n2 = best(&mut || {
            Needle::new(b"\"version\"").for_each(&data, |_| {
                n += 1;
                true
            })
        });
        let t_d = best(&mut || drop(std::hint::black_box(crate::util::jsonidx::ident_marks(&data))));
        let t_all = best(&mut || drop(std::hint::black_box(extract_identifier_fast(&data))));
        let t_byte = best(&mut || drop(std::hint::black_box(extract_identifier_with(&mut crate::util::json::Parser::new(&data)))));
        println!("{:.1} MB: memchr '\\\\' {t_bs:.2} ms, needle linux_banner {t_n1:.2} ms, needle version {t_n2:.2} ms, depth pass {t_d:.2} ms, fast total {t_all:.2} ms, byte parser {t_byte:.2} ms", data.len() as f64 / 1e6);
    }

    /// Identifier extraction: indexed walk vs the byte parser (same answers, speed).
    /// `RSVOL_BENCH_JSON=a.json[:b.json...] cargo test --release ident_bench -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn ident_bench() {
        for path in std::env::var("RSVOL_BENCH_JSON").unwrap().split(':') {
            let data = std::fs::read(path).unwrap();
            let best = |f: &mut dyn FnMut()| {
                let mut b = f64::MAX;
                for _ in 0..10 {
                    let t = std::time::Instant::now();
                    f();
                    b = b.min(t.elapsed().as_secs_f64());
                }
                b * 1e3
            };
            let indexed = |d: &[u8]| {
                let idx = crate::util::jsonidx::Index::build_with(d, false).ok()?;
                extract_identifier_with(&mut idx.walker(d))
            };
            let a = indexed(&data);
            let b = extract_identifier_with(&mut crate::util::json::Parser::new(&data));
            assert_eq!(a, b);
            let ti = best(&mut || drop(indexed(&data)));
            let tb = best(&mut || drop(extract_identifier_with(&mut crate::util::json::Parser::new(&data))));
            println!("{path}: {:.1} MB  indexed {ti:.2} ms  byte parser {tb:.2} ms  -> {:?}", data.len() as f64 / 1e6, a.map(|x| x.0));
        }
    }

    /// The ISF cache trailer: only the exact key matches (a colliding file name is a miss).
    #[test]
    fn isfb_key_is_verified() {
        let blob = b"RSVOLIS1 pretend blob bytes".to_vec();
        let f = cache_file_bytes(&blob, b"key-a");
        assert!(cached_blob_matches(&f, b"key-a"));
        assert!(!cached_blob_matches(&f, b"key-b"));
        assert!(!cached_blob_matches(&f, b"ey-a"));
        assert!(!cached_blob_matches(&f[..f.len() - 1], b"key-a"));
        assert!(!cached_blob_matches(&blob, b"key-a"));
        let loc = IsfLocation::File(std::env::current_exe().unwrap());
        let url = loc.url();
        let (pa, ka) = cache_file(&loc, &url, &BuildOptions::default()).unwrap();
        let (pb, kb) = cache_file(&loc, &url, &BuildOptions { natives: Some(vec![("int".into(), crate::symbols::Ty::Void)]) }).unwrap();
        assert_ne!((pa, ka), (pb, kb));
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

    /// `all_under(sub)` = python `file_symbol_url(sub)`: every ISF in `<root>/<sub>` trees
    /// (per extension, then zip members), nothing outside them; the embedded roots give what
    /// `all()` gives under `sub`.
    #[test]
    fn all_under_is_the_sub_path_trees() {
        let tmp = std::env::temp_dir().join(format!("rsvol-allunder-{}", std::process::id()));
        for rel in ["generic/vmcs/b.json", "generic/vmcs/a.json.xz", "generic/vmcs/deep/c.json", "generic/vmcs/x.txt", "other/generic/vmcs/d.json", "generic/vmcsx/e.json"] {
            let f = tmp.join(rel);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, b"{}").unwrap();
        }
        let embedded = |sub: &str| -> Vec<IsfLocation> {
            let path = SymbolPath { roots: vec![Root::Embedded { top: true }, Root::Embedded { top: false }], download_dir: PathBuf::new() };
            let want: Vec<IsfLocation> = path.all().into_iter().filter(|l| matches!(l, IsfLocation::Embedded { rel, .. } if rel.starts_with(&format!("{sub}/")))).collect();
            assert_eq!(path.all_under(sub), want, "{sub}");
            want
        };
        assert_eq!(embedded("generic/vmcs").len(), 5);
        assert!(!embedded("windows").is_empty());
        assert!(embedded("nonexistent").is_empty());
        let path = SymbolPath { roots: vec![Root::Dir(tmp.clone()), Root::Embedded { top: true }], download_dir: PathBuf::new() };
        let got = path.all_under("generic/vmcs");
        let files: Vec<IsfLocation> = ["generic/vmcs/b.json", "generic/vmcs/deep/c.json", "generic/vmcs/a.json.xz"].iter().map(|r| IsfLocation::File(tmp.join(r))).collect();
        assert_eq!(got[..3], files[..]);
        assert_eq!(got.len(), 3 + 5);
        assert!(got[3..].iter().all(|l| matches!(l, IsfLocation::Embedded { top: true, .. })));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // -- identifier index seeded from python's identifier cache ------------------------------

    use crate::symbols::pycache::{self, CacheRow, Scanned};
    use crate::util::sqlite::Value;
    use std::borrow::Cow;

    fn b64(s: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut o = String::new();
        for c in s.chunks(3) {
            let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
            for k in 0..4 {
                o.push(if k <= c.len() { A[(n >> (18 - 6 * k) & 63) as usize] as char } else { '=' });
            }
        }
        o
    }

    /// A symbol directory with Linux ISFs (`rel` -> banner); returns it canonicalized.
    fn seed_dir(name: &str, files: &[(&str, &str)]) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rsvol-seed-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for (rel, banner) in files {
            let p = d.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            let json = format!(r#"{{"symbols": {{"linux_banner": {{"constant_data": "{}"}}}}}}"#, b64(banner.as_bytes()));
            std::fs::write(&p, json).unwrap();
        }
        std::fs::canonicalize(&d).unwrap()
    }

    fn url_of(d: &Path, rel: &str) -> String {
        paths::path_to_file_uri(&d.join(rel))
    }

    fn set_mtime(p: &Path, t: i64) {
        let f = std::fs::File::options().write(true).open(p).unwrap();
        f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(t as u64)).unwrap();
    }

    fn t(s: &str) -> i64 {
        let (d, us) = pycache::fromisoformat(s.as_bytes()).unwrap();
        d * 86400 + us / 1_000_000
    }

    /// A python row for a Linux ISF (`cached` as sqlite's `datetime()` writes it).
    fn row(location: &str, banner: &str, cached: &str, local: bool) -> CacheRow {
        CacheRow {
            location: location.to_string(),
            identifier: Value::Blob(Cow::Owned(banner.as_bytes().to_vec())),
            operating_system: Value::Text(Cow::Borrowed(b"linux")),
            hash: Value::Null,
            stats: [0, 1, 2, 3].map(|_| Value::Int(0)),
            local,
            cached: Value::Text(Cow::Owned(cached.as_bytes().to_vec())),
        }
    }

    /// python's read of the ISFs update() rescans; records what was read.
    fn scanner<'a>(read: &'a std::cell::RefCell<Vec<String>>, fail: &'a [String]) -> impl FnOnce(&[(&str, &IsfLocation)]) -> Vec<Option<Scanned>> + 'a {
        move |todo| {
            todo.iter()
                .map(|(u, l)| {
                    read.borrow_mut().push(u.to_string());
                    if fail.iter().any(|f| f == u) {
                        return None;
                    }
                    let id = extract_identifier(&l.read().ok()?);
                    Some(Scanned { identifier: id.as_ref().map(|x| x.1.clone()), os: id.as_ref().and_then(|x| static_os(&x.0)), stats: [0; 4] })
                })
                .collect()
        }
    }

    fn chosen(idx: &IdentifierIndex, banner: &str) -> Option<String> {
        idx.dictionary("linux").into_iter().find(|(b, _)| b == banner.as_bytes()).map(|(_, l)| l.url())
    }

    #[test]
    fn seeded_index_follows_python_rows() {
        let d = seed_dir("order", &[("a/k.json", "Linux version 1"), ("b/k.json", "Linux version 1"), ("a/new.json", "Linux version 2")]);
        let (a, b, new) = (url_of(&d, "a/k.json"), url_of(&d, "b/k.json"), url_of(&d, "a/new.json"));
        let now = t("2026-09-26 12:00:00");
        let roots = [Root::Dir(d.clone())];
        // rsvol's own order (a/ before b/) would pick b/k.json: python's rows say a/k.json
        let rows = vec![
            row(&b, "Linux version 1", "2026-09-26 10:00:00", true),
            row(&a, "Linux version 1", "2026-09-26 10:00:01", true),
            row(&url_of(&d, "a/gone.json"), "Linux version 3", "2026-09-26 10:00:02", true),
            row("https://example.org/isf/x.json.xz", "Linux version 4", "2026-09-26 10:00:03", false),
        ];
        let read = std::cell::RefCell::new(Vec::new());
        let idx = IdentifierIndex::from_python_rows(rows, &roots, now, None, scanner(&read, &[]));
        assert_eq!(chosen(&idx, "Linux version 1"), Some(a.clone()));
        // a local row whose file is gone is dropped; a remote row stays
        assert_eq!(chosen(&idx, "Linux version 3"), None);
        assert_eq!(chosen(&idx, "Linux version 4"), Some("https://example.org/isf/x.json.xz".to_string()));
        // only the file python's cache does not cover was read
        assert_eq!(*read.borrow(), vec![new.clone()]);
        assert_eq!(chosen(&idx, "Linux version 2"), Some(new));
        assert_eq!(idx.find(b"Linux version 1", "linux").map(|l| l.url()), Some(a));
        assert!(idx.is_seeded());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn seeded_index_python_staleness() {
        let d = seed_dir("stale", &[("a/k.json", "Linux version 1"), ("b/k.json", "Linux version 1")]);
        let (pa, pb) = (d.join("a/k.json"), d.join("b/k.json"));
        let (a, b) = (url_of(&d, "a/k.json"), url_of(&d, "b/k.json"));
        let now = t("2026-09-26 12:00:00");
        let roots = [Root::Dir(d.clone())];
        set_mtime(&pb, t("2026-08-01 00:00:00"));
        let run = |cached: &str, fail: &[String]| {
            let rows = vec![row(&a, "Linux version 1", cached, true), row(&b, "Linux version 1", cached, true)];
            let read = std::cell::RefCell::new(Vec::new());
            let idx = IdentifierIndex::from_python_rows(rows, &roots, now, None, scanner(&read, fail));
            (chosen(&idx, "Linux version 1"), read.into_inner())
        };
        // a/k.json modified after it was cached, the row is older than 3 days: rescanned, and
        // the re-inserted row (new rowid) wins
        set_mtime(&pa, t("2026-09-20 00:00:00"));
        assert_eq!(run("2026-09-01 00:00:00", &[]), (Some(a.clone()), vec![a.clone()]));
        // ... unless python fails to read it: the old row stays where it was
        assert_eq!(run("2026-09-01 00:00:00", &[a.clone()]), (Some(b.clone()), vec![a.clone()]));
        // a row cached within 3 days is trusted even though the file is newer
        set_mtime(&pa, t("2026-09-26 11:00:00") + 86400);
        assert_eq!(run("2026-09-24 00:00:00", &[]), (Some(b.clone()), vec![]));
        // the window opens at midnight UTC: cached on 09-22 -> examined from 09-26 00:00
        assert_eq!(run("2026-09-22 23:59:59", &[]), (Some(a.clone()), vec![a.clone()]));
        assert_eq!(run("2026-09-23 00:00:00", &[]), (Some(b.clone()), vec![]));
        // an old row whose file is older than the row: trusted
        set_mtime(&pa, t("2026-08-01 00:00:00"));
        assert_eq!(run("2026-09-01 00:00:00", &[]), (Some(b.clone()), vec![]));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn seeded_index_update_abort_and_remote() {
        let d = seed_dir("abort", &[("a/k.json", "Linux version 1"), ("a/new.json", "Linux version 2")]);
        let a = url_of(&d, "a/k.json");
        let now = t("2026-09-26 12:00:00");
        let roots = [Root::Dir(d.clone())];
        // a `cached` value fromisoformat rejects (examined: it sorts before the cutoff) makes
        // update() raise: the deletions stand, nothing is scanned or inserted
        let rows = vec![
            row(&url_of(&d, "a/gone.json"), "Linux version 3", "2026-09-26 10:00:00", true),
            row(&a, "Linux version 1", "2026-09-01 25:00:00", true),
        ];
        let read = std::cell::RefCell::new(Vec::new());
        let idx = IdentifierIndex::from_python_rows(rows, &roots, now, None, scanner(&read, &[]));
        assert!(read.borrow().is_empty());
        assert_eq!(chosen(&idx, "Linux version 1"), Some(a.clone()));
        assert_eq!(chosen(&idx, "Linux version 2"), None);
        assert_eq!(chosen(&idx, "Linux version 3"), None);
        // an empty python database: every ISF is new
        let read = std::cell::RefCell::new(Vec::new());
        let idx = IdentifierIndex::from_python_rows(Vec::new(), &roots, now, None, scanner(&read, &[]));
        assert_eq!(read.borrow().len(), 2);
        assert_eq!(chosen(&idx, "Linux version 2"), Some(url_of(&d, "a/new.json")));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn seeded_choice_deps() {
        let d = seed_dir("deps", &[("a/k.json", "Linux version 1"), ("b/k.json", "Linux version 1")]);
        let (pa, pb) = (d.join("a/k.json"), d.join("b/k.json"));
        let now = pycache::utc_now();
        let cached = pycache::sql_datetime(now - 3600);
        // a/k.json is newer than its (recent) row: python rescans it once the row is 3 days old
        set_mtime(&pa, now + 2 * 86400);
        set_mtime(&pb, now - 30 * 86400);
        let rows = vec![row(&url_of(&d, "a/k.json"), "Linux version 1", &cached, true), row(&url_of(&d, "b/k.json"), "Linux version 1", &cached, true)];
        let read = std::cell::RefCell::new(Vec::new());
        let mut idx = IdentifierIndex::from_python_rows(rows, &[Root::Dir(d.clone())], now, None, scanner(&read, &[]));
        idx.seed_state = "state-1".into();
        let kv: Vec<(String, String)> = idx.choice_deps("linux", b"Linux version 1").into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        let until = pycache::rescan_window_opens(pycache::fromisoformat(cached.as_bytes()).unwrap());
        assert!(kv.contains(&("iduntil".to_string(), until.to_string())));
        assert!(choice_deps_hold_at(&kv, "state-1", now));
        assert!(!choice_deps_hold_at(&kv, "state-2", now));
        assert!(!choice_deps_hold_at(&kv, "state-1", until));
        // a candidate touched (python may rescan it, the choice may change)
        set_mtime(&pb, now - 29 * 86400);
        assert!(!choice_deps_hold_at(&kv, "state-1", now));
        // unseeded: only the seeding state and the search path's directories matter
        let own = IdentifierIndex { entries: Vec::new(), locations: Vec::new(), seed_state: "off".into(), py_cached: None, tree: Vec::new() };
        let kv: Vec<(String, String)> = own.choice_deps("linux", b"x").into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        assert_eq!(kv.len(), 2);
        assert!(choice_deps_hold_at(&kv, "off", now) && !choice_deps_hold_at(&kv, "absent", now));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// One kernel GUID in two symbol directories: python's database lists b/ last, so python
    /// (and the final lookup) loads b/'s copy, while the first copy by name is a/'s. The
    /// speculative kernel load must take python's choice
    /// ([`find_windows_isf_no_download`]), not the name lookup.
    #[test]
    fn windows_duplicate_guid_python_choice() {
        let d = seed_dir("wdup", &[("x.json", "Linux version 0")]);
        let json = r#"{"metadata": {"windows": {"pdb": {"GUID": "AB", "age": 1, "database": "k.pdb"}}}}"#;
        for sub in ["a", "b"] {
            let p = d.join(sub).join("windows/k.pdb/AB-1.json");
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, json).unwrap();
        }
        let (a, b) = (url_of(&d, "a/windows/k.pdb/AB-1.json"), url_of(&d, "b/windows/k.pdb/AB-1.json"));
        let win = |loc: &str| CacheRow {
            operating_system: Value::Text(Cow::Borrowed(b"windows")),
            identifier: Value::Blob(Cow::Owned(b"k.pdb|AB|1".to_vec())),
            ..row(loc, "", "2026-09-26 10:00:00", true)
        };
        let roots = [Root::Dir(d.join("a")), Root::Dir(d.join("b"))];
        let read = std::cell::RefCell::new(Vec::new());
        let idx = IdentifierIndex::from_python_rows(vec![win(&a), win(&b)], &roots, t("2026-09-26 12:00:00"), None, scanner(&read, &[]));
        assert!(read.borrow().is_empty());
        assert_eq!(idx.find(b"k.pdb|AB|1", "windows").map(|l| l.url()), Some(b));
        let sp = SymbolPath { roots: roots.to_vec(), download_dir: d.join("dl") };
        assert_eq!(find_windows_isf_local(&sp, "k.pdb", "ab", 1).map(|l| l.url()), Some(a));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A table converted this run whose `.json.xz` is written after the output: the lookup by
    /// name finds it where python finds the file, and every load of it is served from the JSON
    /// in memory (the file does not exist), sharing one table.
    #[test]
    fn pending_converted_table() {
        let d = std::env::temp_dir().join(format!("rsvol-pending-{}", std::process::id()));
        let path = d.join("windows/p.pdb/ABC-7.json.xz");
        let job = super::super::windows::pdb::IsfWrite { pdb: d.join("x"), pdb_name: "p.pdb".into(), datetime: "t".into(), tmp: path.with_extension("tmp"), path: path.clone() };
        let json = std::sync::Arc::new(super::super::isf::tests::ISF.as_bytes().to_vec());
        PENDING_ISF.lock().unwrap().push(PendingIsf { key: ("p.pdb".into(), "ABC".into(), 7), job, json, table: None });
        let sp = SymbolPath { roots: vec![Root::Dir(d.clone())], download_dir: d.clone() };
        assert_eq!(find_windows_isf_local(&sp, "p.pdb\0", "abc", 7), Some(IsfLocation::File(path.clone())));
        assert_eq!(find_windows_isf_local(&sp, "p.pdb", "abc", 8), None);
        let loc = IsfLocation::File(path.clone());
        let a = load(&loc, "a", &BuildOptions::default()).unwrap();
        let b = load(&loc, "b", &BuildOptions::default()).unwrap();
        for t in [&a, &b] {
            assert_eq!(t.get_symbol("sym1").unwrap().address, 4096);
            assert_eq!(t.pdb_info().unwrap().guid, "ABC");
        }
        assert!(!path.exists());
        PENDING_ISF.lock().unwrap().retain(|p| p.job.path != path);
    }

    /// python's database read end to end (written by the sqlite3 CLI when installed).
    #[test]
    fn seeded_index_from_sqlite_file() {
        let d = seed_dir("sqlite", &[("a/k.json", "Linux version 1"), ("b/k.json", "Linux version 1")]);
        let db = d.join("identifier.cache");
        let (a, b) = (url_of(&d, "a/k.json"), url_of(&d, "b/k.json"));
        let sql = format!(
            "CREATE TABLE database_info (schema_version INT DEFAULT 1); INSERT INTO database_info VALUES (1);
             CREATE TABLE cache (location TEXT UNIQUE NOT NULL, identifier TEXT, operating_system TEXT, hash TEXT,stats_base_types INT DEFAULT 0, stats_types INT DEFAULT 0, stats_enums INT DEFAULT 0, stats_symbols INT DEFAULT 0, local BOOL, cached DATETIME);
             INSERT INTO cache (location, identifier, operating_system, local, cached) VALUES ('{b}', CAST('Linux version 1' AS BLOB), 'linux', 1, datetime('now'));
             INSERT INTO cache (location, identifier, operating_system, local, cached) VALUES ('{a}', CAST('Linux version 1' AS BLOB), 'linux', 1, datetime('now'));
             INSERT OR REPLACE INTO cache (location, identifier, operating_system, local, cached) VALUES ('{b}', CAST('Linux version 1' AS BLOB), 'linux', 1, datetime('now'));"
        );
        let Ok(st) = std::process::Command::new("sqlite3").arg(&db).arg(&sql).status() else { return };
        assert!(st.success());
        let rows = pycache::read(&db).unwrap();
        assert_eq!(rows.iter().map(|r| r.location.as_str()).collect::<Vec<_>>(), vec![a.as_str(), b.as_str()]);
        let read = std::cell::RefCell::new(Vec::new());
        let idx = IdentifierIndex::from_python_rows(rows, &[Root::Dir(d.clone())], pycache::utc_now(), None, scanner(&read, &[]));
        assert!(read.borrow().is_empty());
        assert_eq!(chosen(&idx, "Linux version 1"), Some(b));
        // another schema version: python recreates the database
        let _ = std::process::Command::new("sqlite3").arg(&db).arg("UPDATE database_info SET schema_version = 2").status();
        assert!(pycache::read(&db).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
