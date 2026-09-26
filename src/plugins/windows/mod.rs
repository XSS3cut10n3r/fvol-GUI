//! windows plugins.

use crate::plugins::Plugin;

pub mod cmdline;
pub mod dlllist;
pub mod getservicesids;
pub mod getsids;
pub mod info;
pub mod modules;
pub mod poolscanner;
pub mod pslist;
pub mod psscan;
pub mod pstree;
pub mod sids;
pub mod vadinfo;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&cmdline::CmdLine);
    v.push(&dlllist::DllList);
    v.push(&getservicesids::GetServiceSIDs);
    v.push(&getsids::GetSIDs);
    v.push(&info::Info);
    v.push(&modules::Modules);
    v.push(&poolscanner::PoolScanner);
    v.push(&pslist::PsList);
    v.push(&psscan::PsScan);
    v.push(&pstree::PsTree);
    v.push(&vadinfo::VadInfo);
}
