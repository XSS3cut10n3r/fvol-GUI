//! windows plugins.

use crate::plugins::Plugin;

pub mod info;
pub mod mbrscan;
pub mod mftscan;
pub mod modules;
pub mod poolscanner;
pub mod pslist;
pub mod psscan;
pub mod vadinfo;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&info::Info);
    v.push(&mbrscan::MBRScan);
    v.push(&mftscan::MFTScan);
    v.push(&mftscan::ADS);
    v.push(&mftscan::ResidentData);
    v.push(&modules::Modules);
    v.push(&poolscanner::PoolScanner);
    v.push(&pslist::PsList);
    v.push(&psscan::PsScan);
    v.push(&vadinfo::VadInfo);
}
