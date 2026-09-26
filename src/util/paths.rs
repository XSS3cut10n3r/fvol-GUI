//! Well-known directories: rsvol's own cache (`~/.cache/rsvol`), python volatility3's cache
//! (`~/.cache/volatility3`, reused for downloaded symbols), and small file helpers.

use std::path::{Path, PathBuf};

/// `$XDG_CACHE_HOME` or `~/.cache`.
pub fn xdg_cache_home() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_CACHE_HOME").filter(|x| !x.is_empty()) {
        return PathBuf::from(x);
    }
    home_dir().join(".cache")
}

/// The user's home directory (`$HOME`).
pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// rsvol's cache directory (`~/.cache/rsvol`, override with `RSVOL_CACHE`). Created lazily by
/// writers; readers just try to open files in it.
pub fn rsvol_cache_dir() -> PathBuf {
    if let Some(x) = std::env::var_os("RSVOL_CACHE").filter(|x| !x.is_empty()) {
        return PathBuf::from(x);
    }
    xdg_cache_home().join("rsvol")
}

/// `--clear-cache` (python `framework.clear_cache()`: every `*.cache` file in `CACHE_PATH`,
/// downloads included, then `identifier.cache`) for rsvol's cache directory `dir`: every
/// `*.cache` file in it (identifier index, `isfinfo` summaries, downloads `data_*.cache`) and
/// the directories of the per-image and per-table caches (`automagic`, `isf`, `scan`,
/// `decompressed` images, and `remote`, where older versions kept downloads). Only these
/// entries directly inside `dir`
/// are removed, and symbolic links are removed, never followed. python's own cache
/// directory is left alone. Returns the number of entries removed.
pub fn clear_cache_dir(dir: &Path) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    let mut n = 0;
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(ft) = e.file_type() else { continue };
        // like python's glob("*.cache"), hidden names do not match
        let file = !ft.is_dir() && !name.starts_with('.') && name.ends_with(".cache");
        let subdir = matches!(name, "automagic" | "isf" | "scan" | "remote" | crate::util::resource::CACHE_SUBDIR);
        let removed = if ft.is_dir() && subdir {
            std::fs::remove_dir_all(e.path())
        } else if file || subdir {
            std::fs::remove_file(e.path())
        } else {
            continue;
        };
        n += removed.is_ok() as usize;
    }
    n
}

/// python volatility3's cache directory (`constants.CACHE_PATH`, `~/.cache/volatility3`) or the
/// `--cache-path` override.
pub fn vol3_cache_dir(cache_path: Option<&str>) -> PathBuf {
    match cache_path {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => xdg_cache_home().join("volatility3"),
    }
}

/// Lower-case hex of `b` (cache key material in text files).
pub fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 15) as usize] as char);
    }
    s
}

/// Write `data` to `path` atomically (temp file + rename), creating parent directories.
/// Errors are returned but callers writing caches usually ignore them.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    write_atomic_parts(path, &[data])
}

/// [`write_atomic`] of the concatenation of `parts` (no joined copy).
pub fn write_atomic_parts(path: &Path, parts: &[&[u8]]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        for p in parts {
            f.write_all(p)?;
        }
    }
    std::fs::rename(&tmp, path)
}

/// `std::env::current_exe()` (a readlink of /proc/self/exe), resolved once per process.
pub fn current_exe() -> Option<&'static Path> {
    static EXE: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    EXE.get_or_init(|| std::env::current_exe().ok()).as_deref()
}

/// `std::fs::canonicalize(path)` (a readlink per path component), memoized per process: the
/// image is resolved by the file layer and again for the automagic cache key.
pub fn canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    static MEMO: std::sync::Mutex<Vec<(PathBuf, PathBuf)>> = std::sync::Mutex::new(Vec::new());
    if let Some((_, c)) = MEMO.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|(p, _)| p == path) {
        return Ok(c.clone());
    }
    let c = std::fs::canonicalize(path)?;
    MEMO.lock().unwrap_or_else(|e| e.into_inner()).push((path.to_path_buf(), c.clone()));
    Ok(c)
}

/// `(size, mtime_ns)` of a file, used as cache keys.
pub fn file_stamp(path: &Path) -> Option<(u64, i128)> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path).ok()?;
    Some((md.len(), md.mtime() as i128 * 1_000_000_000 + md.mtime_nsec() as i128))
}

/// python `pathlib.Path(p).as_uri()` for an absolute path: `file://` + percent-encoded path
/// (RFC 3986 unreserved characters and `/` are kept, like `urllib.parse.quote_from_bytes`
/// with safe="/"; pathlib additionally keeps `~` and a few others).
pub fn path_to_file_uri(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    let mut s = String::from("file://");
    for &b in bytes {
        let keep = b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~');
        if keep {
            s.push(b as char);
        } else {
            s.push_str(&format!("%{b:02X}"));
        }
    }
    s
}

/// python `urllib.parse.unquote`: only `%` + two hex digits is decoded (bytewise, so a
/// multi-byte char after `%` can never split a str slice), then UTF-8 with replacement.
pub fn unquote(s: &str) -> String {
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let (Some(h), Some(l)) = (b.get(i + 1).and_then(|&c| hex(c)), b.get(i + 2).and_then(|&c| hex(c)))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `file:///p` / `file://localhost/p` -> `/p` (percent-decoded); `None` for other schemes.
pub fn file_uri_to_path(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    let rest = rest.strip_prefix("localhost").filter(|r| r.starts_with('/')).unwrap_or(rest);
    Some(PathBuf::from(unquote(rest)))
}

/// python's traceback line when `ResourceAccessor().open(url)` cannot read a local `file://`
/// URL (a strings file, a YARA rule file): urllib wraps the OSError in a URLError.
pub fn py_urlopen_error(url: &str, e: &std::io::Error) -> String {
    let path = file_uri_to_path(url).map_or_else(|| url.to_string(), |p| p.to_string_lossy().into_owned());
    let errno = e.raw_os_error().unwrap_or(0);
    // io::Error displays as "<strerror> (os error N)"
    let text = e.to_string();
    let strerror = text.strip_suffix(&format!(" (os error {errno})")).unwrap_or(&text);
    format!("urllib.error.URLError: <urlopen error [Errno {errno}] {strerror}: '{path}'>")
}

/// [`py_urlopen_error`] for a failed resource read (other errors pass through).
pub fn resource_error(url: &str, e: crate::error::Error) -> crate::error::Error {
    match e {
        crate::error::Error::Io(io) if url.starts_with("file:") => crate::error::Error::Msg(py_urlopen_error(url, &io)),
        e => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn urlopen_error_text() {
        let e = std::fs::read("/nonexistent/rsvol/strings.txt").unwrap_err();
        assert_eq!(
            py_urlopen_error("file:///nonexistent/rsvol/strings.txt", &e),
            "urllib.error.URLError: <urlopen error [Errno 2] No such file or directory: '/nonexistent/rsvol/strings.txt'>"
        );
    }
    #[test]
    fn uri() {
        assert_eq!(
            path_to_file_uri(Path::new("/home/user/.cache/volatility3/symbols/windows/ntkrnlmp.pdb/8E-1.json.xz")),
            "file:///home/user/.cache/volatility3/symbols/windows/ntkrnlmp.pdb/8E-1.json.xz"
        );
        assert_eq!(path_to_file_uri(Path::new("/a b/c")), "file:///a%20b/c");
        assert_eq!(file_uri_to_path("file:///a%20b/c"), Some(PathBuf::from("/a b/c")));
        assert_eq!(file_uri_to_path("file://localhost/x"), Some(PathBuf::from("/x")));
        assert_eq!(file_uri_to_path("http://x/y"), None);
    }

    #[test]
    fn unquote_like_python() {
        assert_eq!(unquote("/a%20b%2Fc"), "/a b/c");
        assert_eq!(unquote("%+5%zz%4"), "%+5%zz%4");
        assert_eq!(unquote("%\u{e9}%%41"), "%\u{e9}%A");
        assert_eq!(unquote("%ff"), "\u{fffd}");
        assert_eq!(unquote("%"), "%");
    }

    #[test]
    fn clear_cache_like_python() {
        let base = std::env::temp_dir().join(format!("rsvol-clear-{}", std::process::id()));
        let (dir, outside) = (base.join("rsvol"), base.join("outside"));
        let _ = std::fs::remove_dir_all(&base);
        for d in ["automagic", "isf", "remote", "decompressed", "keepdir", "dir.cache"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
            std::fs::write(dir.join(d).join("f"), b"x").unwrap();
        }
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("t.cache"), b"x").unwrap();
        for f in ["identifiers.cache", "isfinfo.cache", "data_ab.cache", ".hidden.cache", "notes.txt"] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        std::os::unix::fs::symlink(&outside, dir.join("scan")).unwrap();
        std::os::unix::fs::symlink(outside.join("t.cache"), dir.join("link.cache")).unwrap();
        assert_eq!(clear_cache_dir(&dir), 9);
        let mut left: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        left.sort();
        assert_eq!(left, [".hidden.cache", "dir.cache", "keepdir", "notes.txt"]);
        // links were removed, not followed
        assert!(outside.join("t.cache").is_file());
        assert_eq!(clear_cache_dir(&base.join("missing")), 0);
        let _ = std::fs::remove_dir_all(&base);
    }
}
