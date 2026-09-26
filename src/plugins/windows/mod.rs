//! windows plugins.

use crate::plugins::Plugin;

pub mod dumpfiles;
pub mod iat;
pub mod info;
pub mod modules;
pub mod poolscanner;
pub mod pslist;
pub mod psscan;
pub mod vadinfo;
pub mod verinfo;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&dumpfiles::DumpFiles);
    v.push(&iat::IAT);
    v.push(&info::Info);
    v.push(&modules::Modules);
    v.push(&poolscanner::PoolScanner);
    v.push(&pslist::PsList);
    v.push(&psscan::PsScan);
    v.push(&vadinfo::VadInfo);
    v.push(&verinfo::VerInfo);
}
