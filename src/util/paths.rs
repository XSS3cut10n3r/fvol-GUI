//! Well-known directories: fastvol's own cache (`~/.cache/fastvol`), python volatility3's cache
//! (`~/.cache/volatility3`, reused for downloaded symbols), and small file helpers.

use std::path::{Path, PathBuf};

/// `$XDG_CACHE_HOME` or `~/.cache`. (Looked up once: fastvol never changes its environment, and
/// every `getenv` scans the whole environment, ~200 variables in a desktop session.)
pub fn xdg_cache_home() -> PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| match std::env::var_os("XDG_CACHE_HOME").filter(|x| !x.is_empty()) {
        Some(x) => PathBuf::from(x),
        None => home_dir().join(".cache"),
    })
    .clone()
}

/// The user's home directory (`$HOME`).
pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// The name of the cache directory under `$XDG_CACHE_HOME` before the project was renamed.
const LEGACY_CACHE_NAME: &str = "rsvol";

/// fastvol's cache directory (`~/.cache/fastvol`, override with `FASTVOL_CACHE`, or its alias
/// `RSVOL_CACHE`). Created lazily by writers; readers just try to open files in it.
pub fn cache_dir() -> PathBuf {
    cache_dir_choice().0.clone()
}

/// [`cache_dir`] and whether it is the default one (no override in the environment).
fn cache_dir_choice() -> &'static (PathBuf, bool) {
    // (called ~6 times per run: looked up once, see `xdg_cache_home`)
    static DIR: std::sync::OnceLock<(PathBuf, bool)> = std::sync::OnceLock::new();
    DIR.get_or_init(|| match crate::util::env::var_os("CACHE").filter(|x| !x.is_empty()) {
        Some(x) => (PathBuf::from(x), false),
        None => (xdg_cache_home().join("fastvol"), true),
    })
}

/// The one-time move of the cache directory of the project's former name (`~/.cache/rsvol`)
/// to the default [`cache_dir`] (`~/.cache/fastvol`), so the caches built by older versions
/// are kept: one `rename`, which does nothing (and fails) when the old directory is gone or
/// the new one already holds anything (an empty new directory is replaced). Called only on
/// the paths where the cache directory may be missing, never on a fully warm run: when a
/// cache read misses (the first readers of a run then retry the read) and before a cache
/// write. The `rename` runs at most once per process (concurrent callers wait for it), and
/// never when `FASTVOL_CACHE` (`RSVOL_CACHE`) chooses the directory. Returns whether the
/// directory was moved (by this process), i.e. whether a missed read is worth retrying.
pub fn migrate_legacy_cache() -> bool {
    if cfg!(test) {
        // (unit tests never touch the user's cache directories)
        return false;
    }
    static MOVED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *MOVED.get_or_init(|| {
        let (dir, default) = cache_dir_choice();
        if !default {
            return false;
        }
        let moved = std::fs::rename(xdg_cache_home().join(LEGACY_CACHE_NAME), dir).is_ok();
        crate::util::trace::note(|| format!("cache: moved {} to {}: {moved}", LEGACY_CACHE_NAME, dir.display()));
        moved
    })
}

/// `--clear-cache`: [`clear_cache_dir`] of [`cache_dir`] and, when that is the default one,
/// of the former project name's directory (`~/.cache/rsvol`) if it is still there (removed
/// when nothing else is left in it).
pub fn clear_cache() {
    let (dir, default) = cache_dir_choice();
    clear_cache_dir(dir);
    if *default {
        let old = xdg_cache_home().join(LEGACY_CACHE_NAME);
        clear_cache_dir(&old);
        let _ = std::fs::remove_dir(&old);
    }
}

/// `--clear-cache` (python `framework.clear_cache()`: every `*.cache` file in `CACHE_PATH`,
/// downloads included, then `identifier.cache`) for fastvol's cache directory `dir`: every
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
        let subdir = matches!(name, "automagic" | "isf" | "isfchoice" | "scan" | "remote" | crate::util::resource::CACHE_SUBDIR);
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
    // (no per-character capacity checks: this runs over every cache key of a warm run)
    let mut v = vec![0u8; b.len() * 2];
    for (o, &x) in v.chunks_exact_mut(2).zip(b) {
        o[0] = D[(x >> 4) as usize];
        o[1] = D[(x & 15) as usize];
    }
    String::from_utf8(v).unwrap_or_default()
}

/// Write `data` to `path` atomically (temp file + rename), creating parent directories.
/// Errors are returned but callers writing caches usually ignore them.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    write_atomic_parts(path, &[data])
}

/// [`write_atomic`] of the concatenation of `parts` (no joined copy).
pub fn write_atomic_parts(path: &Path, parts: &[&[u8]]) -> std::io::Result<()> {
    use std::io::Write;
    // (every caller writes a cache file: first move an old cache directory into place)
    migrate_legacy_cache();
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
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = path.as_os_str().as_bytes();
    let mut s = Vec::with_capacity(7 + bytes.len());
    s.extend_from_slice(b"file://");
    // runs of unreserved bytes are copied as they are (paths rarely need escapes)
    let mut rest = bytes;
    while !rest.is_empty() {
        let keep = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~');
        let n = rest.iter().position(|b| !keep(b)).unwrap_or(rest.len());
        s.extend_from_slice(&rest[..n]);
        if let Some(&b) = rest.get(n) {
            s.extend_from_slice(&[b'%', HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]);
            rest = &rest[n + 1..];
        } else {
            rest = &[];
        }
    }
    String::from_utf8(s).unwrap_or_default()
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
    fn file_uri_escapes_like_python() {
        use std::os::unix::ffi::OsStrExt;
        let old = |p: &Path| -> String {
            let mut s = String::from("file://");
            for &b in p.as_os_str().as_bytes() {
                if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~') {
                    s.push(b as char);
                } else {
                    s.push_str(&format!("%{b:02X}"));
                }
            }
            s
        };
        let all: Vec<u8> = (1..=255).collect();
        let paths: [&[u8]; 6] = [b"", b"/home/a b/c%d.json", b"/x/\xff\x00y", &all, b"%", b"/plain/path-1_2.3~"];
        for p in paths {
            let p = Path::new(std::ffi::OsStr::from_bytes(p));
            assert_eq!(path_to_file_uri(p), old(p));
        }
    }

    #[test]
    fn hex_is_lower_case_pairs() {
        assert_eq!(hex(b""), "");
        assert_eq!(hex(&[0, 1, 0x7f, 0x80, 0xab, 0xff]), "00017f80abff");
        let all: Vec<u8> = (0..=255).collect();
        let want: String = all.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex(&all), want);
    }

    #[test]
    fn urlopen_error_text() {
        let e = std::fs::read("/nonexistent/fastvol/strings.txt").unwrap_err();
        assert_eq!(
            py_urlopen_error("file:///nonexistent/fastvol/strings.txt", &e),
            "urllib.error.URLError: <urlopen error [Errno 2] No such file or directory: '/nonexistent/fastvol/strings.txt'>"
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
        let base = std::env::temp_dir().join(format!("fastvol-clear-{}", std::process::id()));
        let (dir, outside) = (base.join("fastvol"), base.join("outside"));
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
