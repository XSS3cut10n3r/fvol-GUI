//! FxHash: the tiny, fast, non-cryptographic hash used by rustc. Excellent for short keys
//! (symbol names, integers). NOT DoS resistant -- only use it for data we control or trust.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};

const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

/// The Fx hasher state.
#[derive(Default, Clone, Copy)]
pub struct FxHasher {
    hash: u64,
}

impl FxHasher {
    #[inline(always)]
    fn add(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(SEED);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut b = bytes;
        while b.len() >= 8 {
            self.add(u64::from_le_bytes(b[..8].try_into().unwrap()));
            b = &b[8..];
        }
        if b.len() >= 4 {
            self.add(u32::from_le_bytes(b[..4].try_into().unwrap()) as u64);
            b = &b[4..];
        }
        for &x in b {
            self.add(x as u64);
        }
    }
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i);
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }
    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

/// `BuildHasher` for [`FxHasher`].
pub type FxBuildHasher = BuildHasherDefault<FxHasher>;
/// A `HashMap` using FxHash. Create with `FxHashMap::default()`.
pub type FxHashMap<K, V> = HashMap<K, V, FxBuildHasher>;
/// A `HashSet` using FxHash. Create with `FxHashSet::default()`.
pub type FxHashSet<K> = HashSet<K, FxBuildHasher>;

/// Hash a byte string with FxHash (stable across runs and platforms; used by on-disk caches).
#[inline]
pub fn hash_bytes(b: &[u8]) -> u64 {
    let mut h = FxHasher::default();
    h.write(b);
    // final avalanche so that the low bits (used for table indexing) are well mixed
    let x = h.finish();
    let x = (x ^ (x >> 33)).wrapping_mul(0xff51afd7ed558ccd);
    x ^ (x >> 33)
}

/// Hash a u64 (well mixed, for open-addressing tables keyed by addresses).
#[inline(always)]
pub fn hash_u64(x: u64) -> u64 {
    let x = (x ^ (x >> 33)).wrapping_mul(0xff51afd7ed558ccd);
    let x = (x ^ (x >> 33)).wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^ (x >> 33)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn map_works() {
        let mut m: FxHashMap<&str, u32> = FxHashMap::default();
        m.insert("a", 1);
        m.insert("_EPROCESS", 2);
        assert_eq!(m["_EPROCESS"], 2);
        assert_ne!(hash_bytes(b"abc"), hash_bytes(b"abd"));
    }
}
