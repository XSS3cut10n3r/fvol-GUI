//! Shared utilities (core agent): fast JSON, FxHash maps, memory mapping, parallel helpers,
//! time conversions, cache/config paths.

pub mod bg;
pub mod download;
pub mod exit;
pub mod fxhash;
pub mod json;
pub mod jsonidx;
pub mod mmap;
pub mod par;
pub mod paths;
pub mod pool;
pub mod pyformat;
pub mod pyset;
pub mod pytar;
pub mod resource;
pub mod sqlite;
pub mod time;
pub mod trace;

pub use fxhash::{FxHashMap, FxHashSet};
