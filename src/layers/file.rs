//! The base layer: the input file, memory-mapped read-only.

use super::{Layer, Mapping};
use crate::error::{Error, Result};
use crate::util::mmap::Mmap;
use std::fs::File;
use std::path::Path;

pub struct FileLayer {
    name: String,
    map: Mmap,
}

impl FileLayer {
    pub fn open(path: &Path) -> Result<FileLayer> {
        let f = File::open(path)?;
        let map = Mmap::map(&f)?;
        Ok(FileLayer { name: "FileLayer".to_string(), map })
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
                // first failing address
                let first_bad = if addr < self.len() { self.len() } else { addr };
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
}
