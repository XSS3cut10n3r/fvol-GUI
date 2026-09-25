//! Minimal read-only memory mapping via direct libc FFI (std already links libc, so this adds
//! no dependency).

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
const MAP_FAILED: *mut u8 = !0usize as *mut u8;
pub const MADV_NORMAL: i32 = 0;
pub const MADV_RANDOM: i32 = 1;
pub const MADV_SEQUENTIAL: i32 = 2;
pub const MADV_WILLNEED: i32 = 3;

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
