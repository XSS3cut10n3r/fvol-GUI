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
/// stackers). The result is python's `memory_layer`; a raw image is the file layer itself.
pub fn stack_physical(path: &Path) -> Result<Arc<dyn Layer>> {
    let file = FileLayer::open(path)?;
    let base = Arc::new(file.with_name("base_layer"));
    let stacked = crate::layers::containers::stack(base.clone())?;
    let same = Arc::as_ptr(&stacked) as *const u8 == Arc::as_ptr(&base) as *const u8;
    if same {
        // raw image: the file itself is the memory layer
        return Ok(Arc::new(file.with_name("memory_layer")));
    }
    Ok(stacked)
}

/// Per-image automagic cache (tiny `key=value` text files).
pub mod cache {
    use super::*;
    use crate::util::fxhash::FxHasher;
    use std::hash::Hasher;

    fn file_for(image: &Path, kind: &str) -> Option<std::path::PathBuf> {
        let canon = std::fs::canonicalize(image).ok()?;
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
