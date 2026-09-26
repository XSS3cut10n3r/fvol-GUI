//! Memory layers: physical containers stacked on the input file (raw, LiME, ELF core, crash
//! dump, hibernation, VMware, QEMU, AVML, Xen ...) and translation layers (Intel 32/PAE/x64/LA57,
//! with Windows / Linux / Mac PTE semantics) stacked on those.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
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
//!     Runs must be exactly what python's `layer.mapping(addr, len, ignore_errors=True)`
//!     yields (adjacent runs that are contiguous in BOTH spaces coalesced): the scanners chunk
//!     virtual/segmented layers per run, exactly like python, so result sets depend on it.
//!   * `slice` is an optional zero-copy fast path: return the bytes directly when the whole
//!     range is backed by one contiguous span of the mmapped file.
//!
//! Naming (python layer names show up in `windows.info`): the translation layer is named
//! `"layer_name"`, the layer below it `"memory_layer"`, and a file below a container
//! `"base_layer"` (vmware additionally has `"meta_layer"`). `class_name()` returns the python
//! class name (`"FileLayer"`, `"LimeLayer"`, `"WindowsIntel32e"`, ...).
//!
//! Scanning: see [`scan`] (parallel, python-identical chunking and result order).

pub mod containers;
pub mod file;
pub mod intel;
pub mod scan;

pub use file::FileLayer;
pub use intel::{IntelLayer, PagingMode, PteFlavor};

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

/// Layer metadata (python `layer.metadata`, a ChainMap of the layer's own metadata, its class
/// defaults and its dependencies' metadata). `None` = not set at this level.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Metadata {
    /// "Windows", "Linux", "mac"/"Mac", "Unknown", ...
    pub os: Option<String>,
    /// "Intel32", "Intel64", "Unknown", ...
    pub architecture: Option<String>,
    /// PAE paging (python `metadata.get("pae", False)`).
    pub pae: Option<bool>,
    /// A DTB provided by a container format (crash dumps, vmware, ...).
    pub page_map_offset: Option<u64>,
    /// `mapped` (translation layers set it to true).
    pub mapped: Option<bool>,
}

impl Metadata {
    /// Fill unset fields from `lower` (ChainMap lookup order).
    pub fn chain(mut self, lower: &Metadata) -> Metadata {
        if self.os.is_none() {
            self.os = lower.os.clone();
        }
        if self.architecture.is_none() {
            self.architecture = lower.architecture.clone();
        }
        if self.pae.is_none() {
            self.pae = lower.pae;
        }
        if self.page_map_offset.is_none() {
            self.page_map_offset = lower.page_map_offset;
        }
        if self.mapped.is_none() {
            self.mapped = lower.mapped;
        }
        self
    }
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

    // ---- additions (all have defaults; containers should override class_name/metadata) ----

    /// The python class name of this layer (`"FileLayer"`, `"LimeLayer"`, `"WindowsIntel32e"`).
    fn class_name(&self) -> &'static str {
        "DataLayer"
    }

    /// Smallest valid address (python `minimum_address`; 0 for every layer we have).
    fn min_address(&self) -> u64 {
        0
    }

    /// python `address_mask`: `(1 << ceil(log2(maximum_address))) - 1`.
    fn address_mask(&self) -> u64 {
        address_mask_for(self.max_address())
    }

    /// This layer's own metadata (constructor metadata over class defaults), without the
    /// dependencies. Use [`metadata`] for the python ChainMap view.
    fn own_metadata(&self) -> Metadata {
        Metadata { os: Some("Unknown".into()), architecture: Some("Unknown".into()), ..Default::default() }
    }

    /// Layers this one depends on (python `layer.dependencies`), in python order.
    fn dependencies(&self) -> Vec<Arc<dyn Layer>> {
        self.lower().cloned().into_iter().collect()
    }

    /// Downcast helper: `Some` for the file layer (enables windowed-mmap scanning).
    fn as_file(&self) -> Option<&FileLayer> {
        None
    }

    /// Downcast helper: `Some` for Intel translation layers.
    fn as_intel(&self) -> Option<&IntelLayer> {
        None
    }
}

/// python `DataLayerInterface.address_mask` for a given `maximum_address`
/// (`(1 << ceil(log2(max))) - 1`, computed in f64 exactly like python).
pub fn address_mask_for(max: u64) -> u64 {
    if max == 0 {
        // log2(0) raises in python; treat as mask 0
        return 0;
    }
    let bits = (max as f64).log2().ceil() as u32;
    if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 }
}

/// python `layer.metadata` (ChainMap over the dependency chain).
pub fn metadata(layer: &dyn Layer) -> Metadata {
    let mut m = layer.own_metadata();
    for dep in layer.dependencies() {
        m = m.chain(&metadata(dep.as_ref()));
    }
    m
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
    /// Collect `mapping()` into a Vec.
    fn mappings(&self, addr: u64, len: u64) -> Vec<Mapping> {
        let mut v = Vec::new();
        self.mapping(addr, len, &mut |m| {
            v.push(m);
            true
        });
        v
    }
}

impl<T: Layer + ?Sized> LayerExt for T {}

/// Helper for implementations: error for `addr`.
#[inline]
pub fn invalid<T>(addr: u64) -> Result<T> {
    Err(Error::invalid(addr))
}

/// Walk down `layer`'s dependency chain and return the file layer at the bottom (if any).
pub fn base_file(layer: &dyn Layer) -> Option<&FileLayer> {
    if let Some(f) = layer.as_file() {
        return Some(f);
    }
    layer.lower().and_then(|l| base_file(l.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn masks() {
        assert_eq!(address_mask_for((1 << 48) - 1), (1 << 48) - 1);
        assert_eq!(address_mask_for(5 * 1024 * 1024 * 1024 - 1), (1 << 33) - 1);
        assert_eq!(address_mask_for((1 << 32) - 1), (1 << 32) - 1);
        assert_eq!(address_mask_for(u64::MAX), u64::MAX);
        // exact power of two: python gives a mask smaller than max
        assert_eq!(address_mask_for(1 << 20), (1 << 20) - 1);
    }
}
