//! windows.registry.* plugins (python `plugins/windows/registry/`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::plugins::Plugin;

pub mod hivelist;
pub mod hivescan;
pub mod printkey;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&hivelist::HiveList);
    v.push(&hivescan::HiveScan);
    v.push(&printkey::PrintKey);
}
