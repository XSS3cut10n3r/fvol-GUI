//! Memory layers: physical containers stacked on the input file (raw, LiME, ELF core, crash
//! dump, hibernation, VMware, QEMU, AVML, Xen ...) and translation layers (Intel 32/PAE/x64/LA57,
//! with Windows / Linux / Mac PTE semantics) stacked on those.
//!
//! CONTRACT (stable, used by every other module):
//!   * Every layer implements [`Layer`] and is shared as `Arc<dyn Layer>` across threads.
//!     Layers are immutable after construction; internal caches must be thread-safe.
//!   * Addresses are u64. `max_address()` is the highest valid address (inclusive, like vol3's
//!     `maximum_address`).
//!   * `read` fails with `Error::InvalidAddress{addr}` (first failing address) if ANY byte of
//!     the range is unavailable; `read_padded` zero-fills unavailable bytes instead (vol3
//!     `read(..., pad=True)`).
//!   * `mapping` enumerates the valid runs of `[addr, addr+len)` in ascending order as
//!     (layer offset, length, offset in the lower layer). For physical container layers the
//!     lower layer is the file layer; for translation layers it is the physical layer.
//!   * `slice` is an optional zero-copy fast path: return the bytes directly when the whole
//!     range is backed by one contiguous span of the mmapped file.

pub mod containers;
pub mod file;

use crate::error::{Error, Result};
use std::sync::Arc;

/// One contiguous run returned by [`Layer::mapping`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    /// Offset in this layer.
    pub offset: u64,
    /// Length of the run.
    pub len: u64,
    /// Corresponding offset in the lower layer (`Layer::lower()`).
    pub mapped: u64,
}

pub trait Layer: Send + Sync {
    /// Layer name as volatility3 would name it where it matters for output
    /// (e.g. "memory_layer", "layer_name", "FileLayer"). Informational otherwise.
    fn name(&self) -> &str;

    /// Highest valid address (inclusive).
    fn max_address(&self) -> u64;

    /// Read `buf.len()` bytes at `addr`; error if any byte is unavailable.
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()>;

    /// Read `buf.len()` bytes at `addr`, zero-filling unavailable bytes.
    fn read_padded(&self, addr: u64, buf: &mut [u8]) {
        // Generic fallback: page-by-page. Layers should override with something faster.
        let mut done = 0usize;
        while done < buf.len() {
            let a = addr.wrapping_add(done as u64);
            let chunk = ((0x1000 - (a & 0xfff)) as usize).min(buf.len() - done);
            if self.read(a, &mut buf[done..done + chunk]).is_err() {
                buf[done..done + chunk].fill(0);
            }
            done += chunk;
        }
    }

    /// Whether every byte of `[addr, addr+len)` is available.
    fn is_valid(&self, addr: u64, len: u64) -> bool;

    /// Enumerate the valid runs of `[addr, addr+len)`, calling `f` for each in ascending order.
    /// `f` returns `false` to stop early.
    fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool);

    /// The layer this one maps onto (None for the file layer).
    fn lower(&self) -> Option<&Arc<dyn Layer>> {
        None
    }

    /// Zero-copy access to `[addr, addr+len)` if it is one contiguous span of the backing file.
    fn slice(&self, _addr: u64, _len: usize) -> Option<&[u8]> {
        None
    }

    /// Translation layers: the page table root (DTB/CR3). None for physical layers.
    fn dtb(&self) -> Option<u64> {
        None
    }

    /// Translation layers: translate a single address to (lower-layer offset, bytes remaining in
    /// that page). None when unmapped. Physical container layers map to file offsets.
    fn translate(&self, _addr: u64) -> Option<(u64, u64)> {
        None
    }
}

/// Convenience readers available on every layer.
pub trait LayerExt: Layer {
    #[inline]
    fn read_vec(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut v = vec![0u8; len];
        self.read(addr, &mut v)?;
        Ok(v)
    }
    #[inline]
    fn read_vec_padded(&self, addr: u64, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        self.read_padded(addr, &mut v);
        v
    }
    #[inline]
    fn read_array<const N: usize>(&self, addr: u64) -> Result<[u8; N]> {
        if let Some(s) = self.slice(addr, N) {
            let mut a = [0u8; N];
            a.copy_from_slice(s);
            return Ok(a);
        }
        let mut a = [0u8; N];
        self.read(addr, &mut a)?;
        Ok(a)
    }
    #[inline]
    fn read_u8(&self, addr: u64) -> Result<u8> {
        Ok(self.read_array::<1>(addr)?[0])
    }
    #[inline]
    fn read_u16(&self, addr: u64) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_array(addr)?))
    }
    #[inline]
    fn read_u32(&self, addr: u64) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_array(addr)?))
    }
    #[inline]
    fn read_u64(&self, addr: u64) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_array(addr)?))
    }
    #[inline]
    fn read_i32(&self, addr: u64) -> Result<i32> {
        Ok(i32::from_le_bytes(self.read_array(addr)?))
    }
    #[inline]
    fn read_i64(&self, addr: u64) -> Result<i64> {
        Ok(i64::from_le_bytes(self.read_array(addr)?))
    }
}

impl<T: Layer + ?Sized> LayerExt for T {}

/// Helper for implementations: error for `addr`.
#[inline]
pub fn invalid<T>(addr: u64) -> Result<T> {
    Err(Error::invalid(addr))
}
