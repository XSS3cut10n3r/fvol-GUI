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

    /// Change detector for the identifier index: a fully mixing hash of (url, size, mtime)
    /// (the executable's for embedded ISFs: one stat for all ~170 entries instead of hashing
    /// 6 MB on every index check). The index file stores the URL itself.
    fn stamp_with_url(&self, url: &str) -> Option<u64> {
        Some(crate::layers::scancache::key_hash(&source_identity(self, url)?))
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
    // named by a fully mixing hash of the URL; the URL itself is kept next to the download
    // and compared, so a hash collision re-downloads instead of serving another URL's file
    let base = paths::rsvol_cache_dir().join("remote").join(format!("{:016x}-{}", crate::layers::scancache::key_hash(url.as_bytes()), url.len()));
    let cache = base.with_extension("cache");
    let tag = base.with_extension("url");
    if cache.is_file() && std::fs::read(&tag).is_ok_and(|t| t == url.as_bytes()) {
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
    paths::write_atomic(&tag, url.as_bytes())?;
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

/// Load a symbol table from `loc` (binary cache first). `name` is the table name.
pub fn load(loc: &IsfLocation, name: &str, opts: &BuildOptions) -> Result<SymbolTable> {
    let url = loc.url();
    let cf = cache_file(loc, &url, opts);
    if let Some((_, key)) = &cf {
        let built = BUILT.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|b| b.0 == *key).map(|b| b.1.clone());
        if let Some(b) = built {
            return SymbolTable::from_blob(Blob::Shared(b), name, &url);
        }
    }
    if let Some((cf, key)) = &cf {
        if let Ok(f) = std::fs::File::open(cf) {
            if let Ok(m) = Mmap::map(&f) {
                if cached_blob_matches(m.as_slice(), key) {
                    if let Ok(t) = SymbolTable::from_blob(Blob::Mapped(m), name, &url) {
                        return Ok(t);
                    }
                }
            }
        }
    }
    // the build is parallel: start the pool's workers while this thread decompresses
    crate::util::pool::warm();
    let json = match take_kept(loc, &url) {
        Some(j) => std::borrow::Cow::Owned(j),
        None => {
            let _t = crate::util::trace::span("isf read+decompress");
            loc.read()?
        }
    };
    let blob = build_remember(&url, cf, json, opts, true)?;
    SymbolTable::from_blob(Blob::Shared(blob), name, &url)
}

/// Build the blob of an ISF's JSON, remember it in-process ([`BUILT`]) and write its cache
/// file in the background (overlapping the plugin run; joined before exit), where the JSON is
/// freed too.
fn build_remember(url: &str, cf: Option<(PathBuf, Vec<u8>)>, json: std::borrow::Cow<'static, [u8]>, opts: &BuildOptions, parallel: bool) -> Result<std::sync::Arc<Vec<u8>>> {
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
    use std::sync::atomic::Ordering;
    // plain JSON files load without decompression anyway: only compressed ones are worth it
    if !decoded {
        return;
    }
    let hint = HINT.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(h) = hint {
        // the image's own banner is known: build exactly the matching ISFs, keep nothing else
        if identifier.starts_with(&h) && SPEC_BUILDS.fetch_add(1, Ordering::Relaxed) < 2 * MAX_SPEC_BUILDS {
            let url = loc.url();
            let cf = cache_file(loc, &url, &BuildOptions::default());
            let known = cf.as_ref().is_some_and(|(_, key)| BUILT.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|b| b.0 == *key));
            if !known {
                let _t = crate::util::trace::span("isf speculative build (identifier index, banner hint)");
                let _ = build_remember(&url, cf, std::borrow::Cow::Owned(json), &BuildOptions::default(), false);
            }
        }
        return;
    }
    if !*GUESS.lock().unwrap_or_else(|e| e.into_inner()) {
        return;
    }
    if SPEC_BUILDS.fetch_add(1, Ordering::Relaxed) < MAX_SPEC_BUILDS {
        let url = loc.url();
        let cf = cache_file(loc, &url, &BuildOptions::default());
        let known = cf.as_ref().is_some_and(|(_, key)| BUILT.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|b| b.0 == *key));
        if !known {
            let _t = crate::util::trace::span("isf speculative build (identifier index)");
            let _ = build_remember(&url, cf, std::borrow::Cow::Owned(json), &BuildOptions::default(), false);
        }
        return;
    }
    keep_decoded(loc, json);
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
fn identifier_from(win: Option<(String, String, u64)>, mac: Option<String>, linux: Option<String>) -> Option<(String, Vec<u8>)> {
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
    with_json_len(loc, buf, |j, _| f(j))
}

/// [`with_json`]; `f` also gets `Some((n, decompressed))` when the JSON is `buf[..n]`.
fn with_json_len<R>(loc: &IsfLocation, buf: &mut Vec<u8>, f: impl FnOnce(&[u8], Option<(usize, bool)>) -> R) -> Result<R> {
    let owned;
    let (json, decoded): (&[u8], Option<(usize, bool)>) = match loc {
        IsfLocation::Embedded { data, .. } => (data, None),
        IsfLocation::File(p) if p.to_string_lossy().ends_with(".xz") => {
            let raw = std::fs::read(p)?;
            let n = crate::codecs::xz::decompress_reuse(&raw, buf, false)?;
            (&buf[..n], Some((n, true)))
        }
        IsfLocation::File(p) if p.to_string_lossy().ends_with(".json") => {
            use std::io::Read;
            let mut file = std::fs::File::open(p)?;
            let len = file.metadata()?.len() as usize;
            if buf.len() < len {
                buf.clear();
                buf.resize(len, 0);
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
/// and [`load`] then skips its decompression. `None` stops keeping and frees what is kept
/// (in the background).
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
        if !kept.is_empty() {
            crate::util::bg::spawn(move || drop(kept));
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
    let keep_os = *KEEP_OS.lock().unwrap_or_else(|e| e.into_inner());
    let work = |out: &mut Vec<(usize, R)>| {
        let mut buf = Vec::new();
        loop {
            let j = next.fetch_add(1, Ordering::Relaxed);
            let Some(&k) = order.get(j) else { break };
            let loc = &locs[todo[k]];
            let mut decoded = None;
            let ident = with_json_len(loc, &mut buf, |json, n| {
                decoded = n;
                extract_identifier(json)
            })
            .ok()
            .flatten();
            // the OS the caller is about to load a kernel ISF for: build it now or keep the JSON
            if let (Some((n, was_decoded)), Some(os), Some((ios, _))) = (decoded, keep_os, &ident)
                && os == ios
            {
                let mut v = std::mem::take(&mut buf);
                v.truncate(n);
                speculate(loc, &ident.as_ref().map(|i| i.1.clone()).unwrap_or_default(), v, was_decoded);
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
    if rd(&mut i, 8) != Some(b"RSVOLID2") {
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
    b.extend_from_slice(b"RSVOLID2");
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

/// The first steps of [`find_windows_isf`]: an ISF found by name (canonical layout
/// `<root>/windows/<pdb>/<GUID>-<AGE>.json*`, then python's rglob), without the identifier
/// index or a download. Cheap (a few stats), for speculative loading.
pub fn find_windows_isf_local(path: &SymbolPath, pdb_name: &str, guid: &str, age: u32) -> Option<IsfLocation> {
    let pdb_name = pdb_name.trim_matches('\0');
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

/// Find the ISF for a Windows PDB (python `PDBUtility.load_windows_symbol_table` lookup order:
/// by name `windows/<pdb>/<GUID>-<AGE>.json*`, then by identifier, then download + convert).
pub fn find_windows_isf(path: &SymbolPath, pdb_name: &str, guid: &str, age: u32, offline: bool) -> Result<IsfLocation> {
    if let Some(l) = find_windows_isf_local(path, pdb_name, guid, age) {
        return Ok(l);
    }
    let pdb_name = pdb_name.trim_matches('\0');
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
}
