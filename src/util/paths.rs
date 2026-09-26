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
    }
}
