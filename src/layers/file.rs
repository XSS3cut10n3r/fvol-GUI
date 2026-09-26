//! The base layer: the input file, memory-mapped read-only (python `layers.physical.FileLayer`).
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
    map: Arc<Mmap>,
    file: Arc<File>,
    path: PathBuf,
}

impl FileLayer {
    /// Open and map `path`. The layer is named "FileLayer" (rename with [`FileLayer::with_name`]).
    pub fn open(path: &Path) -> Result<FileLayer> {
        let f = File::open(path)?;
        let map = Mmap::map(&f)?;
        let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        Ok(FileLayer { name: "FileLayer".to_string(), map: Arc::new(map), file: Arc::new(f), path })
    }

    /// A cheap copy of this layer (same mapping) with another name.
    pub fn with_name(&self, name: &str) -> FileLayer {
        FileLayer { name: name.to_string(), map: self.map.clone(), file: self.file.clone(), path: self.path.clone() }
    }

    /// The whole file.
    #[inline(always)]
    pub fn data(&self) -> &[u8] {
        self.map.as_slice()
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
        &self.name
    }

    fn max_address(&self) -> u64 {
        self.len().saturating_sub(1)
    }

    #[inline]
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        match self.slice(addr, buf.len()) {
            Some(s) => {
                buf.copy_from_slice(s);
                Ok(())
            }
            None => {
                // first failing address (python: max+1 if the start is inside the file)
                let first_bad = if addr > 0 && addr < self.len() { self.len() } else { addr };
                Err(Error::invalid(first_bad))
            }
        }
    }

    fn read_padded(&self, addr: u64, buf: &mut [u8]) {
        let len = self.len();
        if addr >= len {
            buf.fill(0);
            return;
        }
        let avail = ((len - addr) as usize).min(buf.len());
        let a = addr as usize;
        buf[..avail].copy_from_slice(&self.data()[a..a + avail]);
        buf[avail..].fill(0);
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
