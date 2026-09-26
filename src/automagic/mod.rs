//! Automagic: stack layers on the input file and discover OS kernels (python
//! `framework/automagic`). Everything here is lazy -- the `Context` runs it when a plugin
//! first asks for a kernel -- and results are cached per image in `~/.cache/rsvol/automagic/`
//! (key: canonical path + size + mtime), so warm runs skip all scanning.
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
pub fn stack_physical(path: &Path, stackers: Option<&[String]>) -> Result<(Arc<dyn Layer>, Vec<StackEntry>)> {
    let _t = crate::util::trace::span("container stacking");
    let file = Arc::new(FileLayer::open(path)?);
    let s = crate::layers::containers::stack_with(file, &StackOptions { location: Some(path), stackers })?;
    Ok((s.layer, s.layers))
}

pub use crate::layers::containers::StackEntry;
use crate::layers::containers::StackOptions;

/// python `--stackers` filter for an OS stacker (e.g. "WindowsIntelStacker"): true when it may
/// run.
pub fn stacker_enabled(stackers: Option<&[String]>, class: &str) -> bool {
    match stackers {
        Some(list) if !list.is_empty() => list.iter().any(|n| n == class),
        _ => true,
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
    let mut buf = [0u8; 128];
    phys.read_padded(at?, &mut buf);
    let rest = &buf[prefix.len()..];
    let tok = rest.iter().position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+' | b'~')))?;
    if tok == 0 || !rest[tok..].starts_with(sep) {
        return None;
    }
    let n = prefix.len() + tok + sep.len();
    crate::util::trace::note(|| format!("banner hint at {:#x}: {:?}", at.unwrap_or(0), String::from_utf8_lossy(&buf[..n])));
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
        Some((paths::rsvol_cache_dir().join("automagic").join(format!("{h:016x}.{label}")), paths::hex(&k)))
    }

    /// Bump when the cached automagic semantics change.
    const CACHE_VERSION: u32 = 2;

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
        let s = std::fs::read_to_string(f).ok()?;
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

    /// A file found under a colliding name but written for another key is a miss.
    #[test]
    fn key_is_verified() {
        let dir = std::env::temp_dir().join(format!("rsvol-amcache-{}", std::process::id()));
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
