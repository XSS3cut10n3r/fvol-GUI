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

/// Per-image automagic cache (tiny `key=value` text files).
pub mod cache {
    use super::*;
    use crate::util::fxhash::FxHasher;
    use std::hash::Hasher;

    fn file_for(image: &Path, kind: &str) -> Option<std::path::PathBuf> {
        let canon = paths::canonicalize(image).ok()?;
        let (size, mtime) = paths::file_stamp(&canon)?;
        let mut h = FxHasher::default();
        h.write(canon.to_string_lossy().as_bytes());
        h.write_u64(size);
        h.write_u64(mtime as u64);
        h.write(kind.as_bytes());
        h.write_u32(CACHE_VERSION);
        Some(paths::rsvol_cache_dir().join("automagic").join(format!("{:016x}.{kind}", h.finish())))
    }

    /// Bump when the cached automagic semantics change.
    const CACHE_VERSION: u32 = 1;

    /// Read cached `key=value` pairs for `image` / `kind`.
    pub fn load(image: &Path, kind: &str) -> Option<Vec<(String, String)>> {
        let f = file_for(image, kind)?;
        let s = std::fs::read_to_string(f).ok()?;
        Some(s.lines().filter_map(|l| l.split_once('=')).map(|(a, b)| (a.to_string(), b.to_string())).collect())
    }

    /// Store `key=value` pairs (best effort).
    pub fn store(image: &Path, kind: &str, kv: &[(&str, String)]) {
        if let Some(f) = file_for(image, kind) {
            let s: String = kv.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
            let _ = paths::write_atomic(&f, s.as_bytes());
        }
    }

    /// Lookup helper.
    pub fn get<'a>(kv: &'a [(String, String)], key: &str) -> Option<&'a str> {
        kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}
