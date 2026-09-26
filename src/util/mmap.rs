//! Minimal read-only memory mapping via direct libc FFI (std already links libc, so this adds
//! no dependency).
//!
//! * [`Mmap`] – the whole file (used for random access: page-table walks, structure reads).
//! * [`MapWindow`] – a window of a file, mapped per scan work item (parallel setup/teardown
//!   of page tables makes full-image scans much faster than faulting the global mapping).

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

unsafe extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
    fn madvise(addr: *mut u8, len: usize, advice: i32) -> i32;
}

const PROT_READ: i32 = 1;
const MAP_SHARED: i32 = 1;
const MAP_POPULATE: i32 = 0x8000;
const MAP_FAILED: *mut u8 = !0usize as *mut u8;
pub const MADV_NORMAL: i32 = 0;
pub const MADV_RANDOM: i32 = 1;
pub const MADV_SEQUENTIAL: i32 = 2;
pub const MADV_WILLNEED: i32 = 3;
/// Drop the range's page-table entries (shared file mappings: the data stays in the page cache
/// and a later access maps it again).
pub const MADV_DONTNEED: i32 = 4;
pub const MADV_POPULATE_READ: i32 = 22;

/// A read-only shared mapping of an entire file.
pub struct Mmap {
    ptr: *mut u8,
    len: usize,
}

// The mapping is read-only and lives as long as the struct.
unsafe impl Send for Mmap {}
unsafe impl Sync for Mmap {}

impl Mmap {
    pub fn map(file: &File) -> io::Result<Mmap> {
        let len = file.metadata()?.len() as usize;
        if len == 0 {
            return Ok(Mmap { ptr: std::ptr::NonNull::<u8>::dangling().as_ptr(), len: 0 });
        }
        let ptr = unsafe { mmap(std::ptr::null_mut(), len, PROT_READ, MAP_SHARED, file.as_raw_fd(), 0) };
        if ptr == MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Mmap { ptr, len })
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Advise the kernel about the access pattern for `[off, off+len)`.
    pub fn advise(&self, off: usize, len: usize, advice: i32) {
        if self.len == 0 || off >= self.len {
            return;
        }
        let page = 4096;
        let start = off & !(page - 1);
        let end = (off + len).min(self.len);
        unsafe {
            madvise(self.ptr.add(start), end - start, advice);
        }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        if self.len != 0 {
            unsafe {
                munmap(self.ptr, self.len);
            }
        }
    }
}

/// A read-only mapping of a window `[off, off+len)` of a file. Used by the scanners: mapping,
/// scanning and unmapping each work item separately keeps page-table setup/teardown parallel
/// (much faster than faulting in and tearing down one huge mapping for a full-image scan).
pub struct MapWindow {
    base: *mut u8,
    map_len: usize,
    skip: usize,
    len: usize,
}

unsafe impl Send for MapWindow {}
unsafe impl Sync for MapWindow {}

impl MapWindow {
    /// Map `len` bytes of `file` starting at byte `off` (need not be page aligned).
    /// `populate` pre-faults the pages (MAP_POPULATE).
    pub fn new(file: &File, off: u64, len: usize, populate: bool) -> io::Result<MapWindow> {
        if len == 0 {
            return Ok(MapWindow { base: std::ptr::NonNull::<u8>::dangling().as_ptr(), map_len: 0, skip: 0, len: 0 });
        }
        let aligned = off & !0xfff;
        let skip = (off - aligned) as usize;
        let map_len = skip + len;
        let flags = MAP_SHARED | if populate { MAP_POPULATE } else { 0 };
        let ptr = unsafe { mmap(std::ptr::null_mut(), map_len, PROT_READ, flags, file.as_raw_fd(), aligned as i64) };
        if ptr == MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(MapWindow { base: ptr, map_len, skip, len })
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.base.add(self.skip), self.len) }
    }

    /// madvise on the whole window.
    pub fn advise(&self, advice: i32) {
        if self.map_len != 0 {
            unsafe {
                madvise(self.base, self.map_len, advice);
            }
        }
    }
}

impl Drop for MapWindow {
    fn drop(&mut self) {
        if self.map_len != 0 {
            unsafe {
                munmap(self.base, self.map_len);
            }
        }
    }
}
