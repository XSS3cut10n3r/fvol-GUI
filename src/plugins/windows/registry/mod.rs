//! windows.registry.* plugins (python `plugins/windows/registry/`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::plugins::Plugin;

pub mod cachedump;
pub mod hashdump;
pub mod hivelist;
pub mod hivescan;
pub mod lsadump;
pub mod printkey;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&hivelist::HiveList);
    v.push(&hivescan::HiveScan);
    v.push(&printkey::PrintKey);
    v.push(&hashdump::Hashdump);
    v.push(&hashdump::HashdumpDeprecated);
    v.push(&lsadump::Lsadump);
    v.push(&lsadump::LsadumpDeprecated);
    v.push(&cachedump::Cachedump);
    v.push(&cachedump::CachedumpDeprecated);
}
