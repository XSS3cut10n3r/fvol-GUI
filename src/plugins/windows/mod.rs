//! windows plugins.

use crate::plugins::Plugin;

pub mod info;
pub mod modules;
pub mod netscan;
pub mod netstat;
pub mod poolscanner;
pub mod pslist;
pub mod psscan;
pub mod vadinfo;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&info::Info);
    v.push(&modules::Modules);
    v.push(&netscan::NetScan);
    v.push(&netstat::NetStat);
    v.push(&poolscanner::PoolScanner);
    v.push(&pslist::PsList);
    v.push(&psscan::PsScan);
    v.push(&vadinfo::VadInfo);
}
