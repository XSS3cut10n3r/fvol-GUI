//! Automagic: stack layers on the input file and discover OS kernels (python
//! `framework/automagic`). Everything here is lazy -- the `Context` runs it when a plugin
//! first asks for a kernel -- and results are cached per image in `~/.cache/fastvol/automagic/`
//! (key: canonical path + size + mtime), so warm runs skip all scanning. Failures ("no Linux
//! kernel in this image") are remembered too ([`cache::load_failure`]).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

pub mod linux;
pub mod mac;
pub mod windows;

use crate::error::Result;
use crate::layers::{FileLayer, Layer};
use crate::util::paths;
use std::path::Path;
use std::sync::Arc;

/// Open the image and stack container layers on it (python LayerStacker minus the OS
/// stackers; `stackers` = python `--stackers`). Returns python's `memory_layer` (the file layer
/// itself for raw images) and the python `get_depends` listing of it (names after
/// construction magic: memory_layer, base_layer, ...; depth 0 = the physical layer).
/// `path` is the local file with the image's data, `url` python's location of the image.
pub fn stack_physical(path: &Path, url: Option<&str>, offline: bool, stackers: Option<&[String]>) -> Result<Stacked> {
    let _t = crate::util::trace::span("container stacking");
    let file = Arc::new(FileLayer::open(path)?);
    crate::layers::containers::stack_with(file, &StackOptions { location: Some(path), url, offline, stackers })
}

pub use crate::layers::containers::{StackEntry, Stacked};
use crate::layers::containers::StackOptions;

/// python `--stackers` filter for an OS stacker (e.g. "WindowsIntelStacker"): true when it may
/// run.
pub fn stacker_enabled(stackers: Option<&[String]>, class: &str) -> bool {
    match stackers {
        Some(list) if !list.is_empty() => list.iter().any(|n| n == class),
        _ => true,
    }
}

/// Automagic cache key material for `--stackers`: a kernel found on one physical stack (e.g. a
/// crash dump's layer) says nothing about another (the same file read raw when
/// `--stackers=WindowsIntelStacker` leaves the crash dump stacker out). Empty by default.
pub fn stackers_key(stackers: Option<&[String]>) -> String {
    match stackers {
        Some(s) => format!("-{}", paths::hex(s.join("\0").as_bytes())),
        None => String::new(),
    }
}

/// `prefix` + the version token that follows it + `sep` (`Linux version 6.8.0-139-generic (`,
/// `Darwin Kernel Version 13.1.0:`) from the first `prefix` in `phys`, found by a quick
/// progressive scan. The first copy in memory may be console output rather than the kernel's
/// own string, so only the release is used (python's VMCOREINFO stacker matches banners the
/// same way). Only a hint for speculative work (see `symbols::store::set_banner_hint`).
pub fn banner_hint(phys: &dyn Layer, prefix: &[u8], sep: &[u8]) -> Option<Vec<u8>> {
    let _t = crate::util::trace::span("banner hint scan");
    let scanner = crate::symbols::linux::search::FastBytesScanner::new(prefix);
    let mut at = None;
    crate::layers::scan::scan_each_progressive(phys, &scanner, |h| *h, |h| {
        at = Some(h);
        false
    });
    banner_hint_at(phys, at?, prefix, sep)
}

/// [`banner_hint`] from a known occurrence of `prefix` at `at`.
pub fn banner_hint_at(phys: &dyn Layer, at: u64, prefix: &[u8], sep: &[u8]) -> Option<Vec<u8>> {
    let mut buf = [0u8; 128];
    phys.read_padded(at, &mut buf);
    let rest = &buf[prefix.len()..];
    let tok = rest.iter().position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+' | b'~')))?;
    if tok == 0 || !rest[tok..].starts_with(sep) {
        return None;
    }
    let n = prefix.len() + tok + sep.len();
    crate::util::trace::note(|| format!("banner hint at {at:#x}: {:?}", String::from_utf8_lossy(&buf[..n])));
    Some(buf[..n].to_vec())
}

/// Per-image automagic cache (tiny `key=value` text files).
///
/// A file is named by a fully mixing 64-bit hash of its key material (canonical image path,
/// size, mtime, `kind`, `CACHE_VERSION`) and starts with a `key=<hex>` line holding that
/// material, compared on load: a hash collision is a miss, never another image's result.
/// `kind` may carry arbitrary key material (e.g. a symbol path fingerprint); only a short
/// sanitized prefix of it appears in the file name.
pub mod cache {
    use super::*;

    fn key_for(image: &Path, kind: &str) -> Option<(std::path::PathBuf, String)> {
        let canon = paths::canonicalize(image).ok()?;
        let (size, mtime) = paths::file_stamp(&canon)?;
        let c = canon.to_string_lossy();
        let mut k: Vec<u8> = Vec::with_capacity(c.len() + kind.len() + 48);
        k.extend_from_slice(&CACHE_VERSION.to_le_bytes());
        k.extend_from_slice(&(c.len() as u64).to_le_bytes());
        k.extend_from_slice(c.as_bytes());
        k.extend_from_slice(&size.to_le_bytes());
        k.extend_from_slice(&mtime.to_le_bytes());
        k.extend_from_slice(&(kind.len() as u64).to_le_bytes());
        k.extend_from_slice(kind.as_bytes());
        let label: String = kind.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-').take(24).collect();
        let h = crate::layers::scancache::key_hash(&k);
        Some((cache_root().join("automagic").join(format!("{h:016x}.{label}")), paths::hex(&k)))
    }

    #[cfg(test)]
    thread_local! {
        /// a test's private cache directory (tests run concurrently: no environment changes)
        static TEST_ROOT: std::cell::RefCell<Option<std::path::PathBuf>> = const { std::cell::RefCell::new(None) };
    }

    fn cache_root() -> std::path::PathBuf {
        #[cfg(test)]
        if let Some(r) = TEST_ROOT.with(|r| r.borrow().clone()) {
            return r;
        }
        paths::cache_dir()
    }

    /// Bump when the cached automagic semantics change.
    const CACHE_VERSION: u32 = 3;

    /// Read cached `key=value` pairs for `image` / `kind` (None: absent, or another key).
    pub fn load(image: &Path, kind: &str) -> Option<Vec<(String, String)>> {
        let (f, key) = key_for(image, kind)?;
        load_at(&f, &key)
    }

    /// Store `key=value` pairs (best effort).
    pub fn store(image: &Path, kind: &str, kv: &[(&str, String)]) {
        if let Some((f, key)) = key_for(image, kind) {
            store_at(&f, &key, kv);
        }
    }

    fn load_at(f: &Path, key: &str) -> Option<Vec<(String, String)>> {
        // (the first read of a run on every OS: a missing file may mean the cache directory of
        // the project's former name is still to be moved into place, see migrate_legacy_cache)
        let read = || std::fs::read_to_string(f).ok();
        let s = read().or_else(|| paths::migrate_legacy_cache().then(read).flatten())?;
        let mut lines = s.lines();
        if lines.next()?.strip_prefix("key=")? != key {
            return None;
        }
        Some(lines.filter_map(|l| l.split_once('=')).map(|(a, b)| (a.to_string(), b.to_string())).collect())
    }

    fn store_at(f: &Path, key: &str, kv: &[(&str, String)]) {
        let mut s = format!("key={key}\n");
        for (k, v) in kv {
            s.push_str(&format!("{k}={v}\n"));
        }
        if cfg!(test) {
            let _ = paths::write_atomic(f, s.as_bytes());
        } else {
            // off the critical path (joined before exit)
            let f = f.to_path_buf();
            crate::util::bg::spawn(move || {
                let _ = paths::write_atomic(&f, s.as_bytes());
            });
        }
    }

    /// Lookup helper.
    pub fn get<'a>(kv: &'a [(String, String)], key: &str) -> Option<&'a str> {
        kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    // --------------------------------------------------------------------------------------
    // remembered failures

    /// Key material of a remembered failure of the discovery `kind`: `kind` itself and the
    /// fastvol executable (size, mtime, path), since another build may find a kernel this one
    /// could not; with `None` for the executable nothing is remembered.
    fn failure_kind(kind: &str) -> Option<String> {
        static EXE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
        let exe = EXE.get_or_init(|| {
            let p = std::env::current_exe().ok()?;
            let (size, mtime) = paths::file_stamp(&p)?;
            Some(format!("{size}:{mtime}:{}", p.to_string_lossy()))
        });
        Some(format!("none-{kind}\0{}", exe.as_deref()?))
    }

    /// A remembered failure of the kernel discovery `kind` on `image` ("no Linux kernel in
    /// this image"): the pairs stored with it ([`store_failure`]), when `deps_hold` accepts
    /// them. Timeliner runs the plugins of every OS, so without this each run repeated the
    /// discoveries of the two other OSes (full-image banner and DTB scans, 0.2-2 s).
    ///
    /// A failure is remembered per image (path, size, mtime), per `kind` (which carries what
    /// the positive result's key carries: symbol path fingerprint, `--stackers`) and per fastvol
    /// executable; `deps_hold` checks what else the discovery read (e.g. the identifier index
    /// state for every banner of the OS, [`crate::symbols::store::IdentifierIndex::os_deps`]).
    pub fn load_failure(image: &Path, kind: &str, deps_hold: impl FnOnce(&[(String, String)]) -> bool) -> Option<Vec<(String, String)>> {
        let kv = load(image, &failure_kind(kind)?)?;
        (get(&kv, "outcome") == Some("none") && deps_hold(&kv)).then_some(kv)
    }

    /// Remember that the kernel discovery `kind` found nothing on `image`: `kv` holds what the
    /// caller needs to fail the same way again (e.g. the `-v` detail) and the key material
    /// its `deps_hold` checks. Only for failures that depend on nothing but the image, `kind`
    /// and those pairs (never after an I/O error or other unexpected exception).
    pub fn store_failure(image: &Path, kind: &str, kv: &[(&str, String)]) {
        let Some(k) = failure_kind(kind) else { return };
        // one pair per line
        if kv.iter().any(|(a, b)| a.contains(['=', '\n', '\r']) || b.contains(['\n', '\r'])) {
            return;
        }
        let mut all = vec![("outcome", "none".to_string())];
        all.extend(kv.iter().map(|(a, b)| (*a, b.clone())));
        store(image, &k, &all);
    }

    /// Failures are remembered per image, kind and dependencies, and never shadow another
    /// kind's result.
    #[test]
    fn failures_are_keyed() {
        let dir = std::env::temp_dir().join(format!("fastvol-amcache-neg-{}", std::process::id()));
        let img = dir.join("image.raw");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&img, b"not a memory image").unwrap();
        TEST_ROOT.with(|r| *r.borrow_mut() = Some(dir.join("cache")));
        let r = std::panic::catch_unwind(|| {
            assert_eq!(load_failure(&img, "linux-x", |_| true), None);
            store_failure(&img, "linux-x", &[("detail", "No Linux banners found".into()), ("dep", "1".into())]);
            let kv = load_failure(&img, "linux-x", |_| true).unwrap();
            assert_eq!(get(&kv, "detail"), Some("No Linux banners found"));
            // dependencies that no longer hold: a miss
            assert_eq!(load_failure(&img, "linux-x", |kv| get(kv, "dep") == Some("2")), None);
            // another kind (symbol path, --stackers) and the positive result: separate
            assert_eq!(load_failure(&img, "linux-y", |_| true), None);
            assert_eq!(load(&img, "linux-x"), None);
            // a changed image: a miss
            std::fs::write(&img, b"another memory image").unwrap();
            assert_eq!(load_failure(&img, "linux-x", |_| true), None);
            // multi-line values are never stored (one pair per line)
            store_failure(&img, "linux-x", &[("detail", "a\nb".into())]);
            assert_eq!(load_failure(&img, "linux-x", |_| true), None);
        });
        TEST_ROOT.with(|r| *r.borrow_mut() = None);
        let _ = std::fs::remove_dir_all(&dir);
        r.unwrap();
    }

    /// A file found under a colliding name but written for another key is a miss.
    #[test]
    fn key_is_verified() {
        let dir = std::env::temp_dir().join(format!("fastvol-amcache-{}", std::process::id()));
        let f = dir.join("0123456789abcdef.win");
        store_at(&f, "aa01", &[("dtb", "0x1ad000".to_string())]);
        assert_eq!(load_at(&f, "aa01"), Some(vec![("dtb".to_string(), "0x1ad000".to_string())]));
        assert_eq!(load_at(&f, "aa02"), None);
        assert_eq!(load_at(&f, "aa0"), None);
        let _ = std::fs::remove_dir_all(&dir);
        let img = std::env::current_exe().unwrap();
        let (fa, ka) = key_for(&img, "linux-00").unwrap();
        let (fb, kb) = key_for(&img, "linux-01").unwrap();
        assert_ne!(ka, kb);
        assert_ne!(fa, fb);
        assert!(fa.file_name().unwrap().to_string_lossy().ends_with(".linux-00"));
    }
}
