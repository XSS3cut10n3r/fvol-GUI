//! The base layer: the input file, memory-mapped read-only (python `layers.physical.FileLayer`).
//!
//! The file is mapped twice, for two access patterns:
//!   * the default mapping ([`FileLayer::data`], [`Layer::slice`], [`Layer::read`]) serves bulk
//!     readers (scans that are not `pread`, vmscan's page sweep, dumps, container decoders): on a
//!     cold page cache a fault there reads ahead around the page (the bdi's `read_ahead_kb`,
//!     4 MiB on btrfs), which is what a sequential reader wants;
//!   * a second mapping advised `MADV_RANDOM` ([`FileLayer::data_random`],
//!     [`Layer::slice_random`], [`Layer::read_random`]) serves the translation layers: their
//!     page-table walks and every structure read made through them. A cold fault there reads
//!     only the page (on btrfs: its compressed extent), not 4 MiB around it -- measured on a
//!     cold 5 GiB image: windows.pslist 173 -> 33 ms, dlllist 1.14 -> 0.19 s, handles 1.21 ->
//!     0.26 s (crash dump: pslist 540 -> 47 ms, dlllist 2.09 -> 0.14 s). Warm, both behave the
//!     same (fault-around maps 64 KiB of cached pages either way). The advice is per mapping
//!     (VMA), so it never slows the bulk readers of the default mapping (advising the one
//!     mapping `MADV_RANDOM` made a cold vmscan 4.5x and a cold memmap --dump 4x slower; memory
//!     dumps stream through a translation layer on the default mapping: [`Layer::slice_bulk`]).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use super::{Layer, Mapping, Metadata};
use crate::error::{Error, Result};
use crate::util::mmap::{MapWindow, Mmap};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct FileLayer {
    name: String,
    /// python's layer name once the layer stacker has named it (see [`FileLayer::set_python_name`]).
    py_name: std::sync::OnceLock<String>,
    map: Arc<Mmap>,
    /// the `MADV_RANDOM` mapping (created on first use, shared by `with_name` copies; None if
    /// it could not be created: the default mapping serves then)
    rand: Arc<std::sync::OnceLock<Option<Mmap>>>,
    file: Arc<File>,
    path: PathBuf,
}

impl FileLayer {
    /// Open and map `path`. The layer is named "FileLayer" (rename with [`FileLayer::with_name`]).
    pub fn open(path: &Path) -> Result<FileLayer> {
        let f = File::open(path)?;
        let map = Mmap::map(&f)?;
        let path = crate::util::paths::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        Ok(FileLayer { name: "FileLayer".to_string(), py_name: Default::default(), map: Arc::new(map), rand: Default::default(), file: Arc::new(f), path })
    }

    /// A cheap copy of this layer (same mapping) with another name.
    pub fn with_name(&self, name: &str) -> FileLayer {
        FileLayer {
            name: name.to_string(),
            py_name: Default::default(),
            map: self.map.clone(),
            rand: self.rand.clone(),
            file: self.file.clone(),
            path: self.path.clone(),
        }
    }

    /// Name the (already shared) layer as python's construction magic does (`memory_layer`
    /// for a raw image, `base_layer` below a container); the first name set sticks.
    pub fn set_python_name(&self, name: &str) {
        let _ = self.py_name.set(name.to_string());
    }

    /// The whole file.
    #[inline(always)]
    pub fn data(&self) -> &[u8] {
        self.map.as_slice()
    }

    /// The whole file through the random-access mapping (see the module docs): for page-table
    /// walks and structure reads, never for bulk reads. The same bytes as [`FileLayer::data`].
    #[inline]
    pub fn data_random(&self) -> &[u8] {
        let m = self.rand.get_or_init(|| {
            if !random_map_enabled() || self.map.is_empty() {
                return None;
            }
            let m = Mmap::map(&self.file).ok()?;
            if m.len() != self.map.len() {
                return None; // the file changed size: keep to the one mapping
            }
            m.advise(0, m.len(), crate::util::mmap::MADV_RANDOM);
            Some(m)
        });
        match m {
            Some(m) => m.as_slice(),
            None => self.data(),
        }
    }

    /// Drop this process's page-table entries for `[off, off + len)` in both mappings
    /// (`MADV_DONTNEED`; the data stays in the page cache and a later access maps it again).
    /// Called by scan workers right after a big chunk: the entries its structure reads faulted
    /// in are torn down in parallel instead of serially at exit (mftscan: 24-27 ms of exit
    /// teardown without the CLI's exit helper, see `util::exit`) and do not pile up in a
    /// long-running process (`fvol serve`).
    pub fn release(&self, off: u64, len: u64) {
        let (Ok(off), Ok(len)) = (usize::try_from(off), usize::try_from(len)) else { return };
        self.map.advise(off, len, crate::util::mmap::MADV_DONTNEED);
        if let Some(Some(m)) = self.rand.get() {
            m.advise(off, len, crate::util::mmap::MADV_DONTNEED);
        }
    }

    /// [`Layer::slice`] through the random-access mapping.
    #[inline(always)]
    fn slice_rand(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let a = usize::try_from(addr).ok()?;
        self.data_random().get(a..a.checked_add(len)?)
    }

    #[inline(always)]
    pub fn len(&self) -> u64 {
        self.map.len() as u64
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn mmap(&self) -> &Mmap {
        &self.map
    }

    /// The open file (for windowed mappings / pread).
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Canonical path of the file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Map a private window `[off, off+len)` of the file (for scanning; see
    /// [`crate::util::mmap::MapWindow`]). None if out of range or mmap fails.
    pub fn window(&self, off: u64, len: usize) -> Option<MapWindow> {
        if off.checked_add(len as u64)? > self.len() {
            return None;
        }
        MapWindow::new(&self.file, off, len, false).ok()
    }
}

impl Layer for FileLayer {
    fn name(&self) -> &str {
        self.py_name.get().unwrap_or(&self.name)
    }

    fn max_address(&self) -> u64 {
        self.len().saturating_sub(1)
    }

    #[inline]
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        read_from(self.data(), addr, buf)
    }

    fn read_padded(&self, addr: u64, buf: &mut [u8]) {
        read_padded_from(self.data(), addr, buf)
    }

    #[inline]
    fn read_random(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        read_from(self.data_random(), addr, buf)
    }

    fn read_padded_random(&self, addr: u64, buf: &mut [u8]) {
        read_padded_from(self.data_random(), addr, buf)
    }

    #[inline]
    fn is_valid(&self, addr: u64, len: u64) -> bool {
        addr.checked_add(len).is_some_and(|end| end <= self.len())
    }

    fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
        let flen = self.len();
        if addr >= flen {
            return;
        }
        let run = len.min(flen - addr);
        if run > 0 {
            f(Mapping { offset: addr, len: run, mapped: addr });
        }
    }

    #[inline(always)]
    fn slice(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let a = usize::try_from(addr).ok()?;
        self.data().get(a..a.checked_add(len)?)
    }

    #[inline(always)]
    fn slice_random(&self, addr: u64, len: usize) -> Option<&[u8]> {
        self.slice_rand(addr, len)
    }

    fn translate(&self, addr: u64) -> Option<(u64, u64)> {
        if addr < self.len() { Some((addr, self.len() - addr)) } else { None }
    }

    fn class_name(&self) -> &'static str {
        "FileLayer"
    }

    fn own_metadata(&self) -> Metadata {
        Metadata { os: Some("Unknown".into()), architecture: Some("Unknown".into()), ..Default::default() }
    }

    fn as_file(&self) -> Option<&FileLayer> {
        Some(self)
    }
}

/// `read` of the file bytes `data` (either mapping).
#[inline]
fn read_from(data: &[u8], addr: u64, buf: &mut [u8]) -> Result<()> {
    let s = usize::try_from(addr).ok().and_then(|a| data.get(a..a.checked_add(buf.len())?));
    match s {
        Some(s) => {
            buf.copy_from_slice(s);
            Ok(())
        }
        None => {
            // first failing address (python: max+1 if the start is inside the file)
            let len = data.len() as u64;
            let first_bad = if addr > 0 && addr < len { len } else { addr };
            Err(Error::invalid(first_bad))
        }
    }
}

/// `read_padded` of the file bytes `data` (either mapping).
fn read_padded_from(data: &[u8], addr: u64, buf: &mut [u8]) {
    let len = data.len() as u64;
    if addr >= len {
        buf.fill(0);
        return;
    }
    let avail = ((len - addr) as usize).min(buf.len());
    let a = addr as usize;
    buf[..avail].copy_from_slice(&data[a..a + avail]);
    buf[avail..].fill(0);
}

/// Whether structure reads use the second, `MADV_RANDOM` mapping (`FASTVOL_NO_RANDOM_MAP=1`
/// turns it off, for A/B measurements).
fn random_map_enabled() -> bool {
    static E: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *E.get_or_init(|| crate::util::env::var_os("NO_RANDOM_MAP").is_none_or(|v| v.is_empty() || v == "0"))
}
