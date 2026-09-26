//! Shared utilities (core agent): fast JSON, FxHash maps, memory mapping, parallel helpers,
//! time conversions, cache/config paths.

pub mod fxhash;
pub mod json;
pub mod mmap;
pub mod par;
pub mod paths;
pub mod time;

pub use fxhash::{FxHashMap, FxHashSet};
