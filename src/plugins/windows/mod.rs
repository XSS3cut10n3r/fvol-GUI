//! windows plugins.

use crate::plugins::Plugin;

pub mod info;
pub mod modules;
pub mod poolscanner;
pub mod pslist;
pub mod psscan;
pub mod registry;
pub mod shimcachemem;
pub mod vadinfo;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&info::Info);
    v.push(&modules::Modules);
    v.push(&poolscanner::PoolScanner);
    v.push(&pslist::PsList);
    v.push(&psscan::PsScan);
    v.push(&shimcachemem::ShimcacheMem);
    v.push(&vadinfo::VadInfo);
    registry::register(v);
}
