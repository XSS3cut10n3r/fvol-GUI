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
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, data)?;
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

#[cfg(test)]
mod tests {
    use super::*;
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
}
