//! windows plugins.

use crate::plugins::Plugin;

pub mod cmdline;
pub mod dlllist;
pub mod envars;
pub mod getservicesids;
pub mod getsids;
pub mod info;
pub mod joblinks;
pub mod memmap;
pub mod modules;
pub mod poolscanner;
pub mod privileges;
pub mod pslist;
pub mod psscan;
pub mod pstree;
pub mod registry;
pub mod sessions;
pub mod sids;
pub mod statistics;
pub mod vadinfo;
pub mod vadwalk;
pub mod virtmap;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&cmdline::CmdLine);
    v.push(&dlllist::DllList);
    v.push(&envars::Envars);
    v.push(&getservicesids::GetServiceSIDs);
    v.push(&getsids::GetSIDs);
    v.push(&info::Info);
    v.push(&joblinks::JobLinks);
    v.push(&memmap::Memmap);
    v.push(&modules::Modules);
    v.push(&poolscanner::PoolScanner);
    v.push(&privileges::Privs);
    v.push(&pslist::PsList);
    v.push(&psscan::PsScan);
    v.push(&pstree::PsTree);
    v.push(&sessions::Sessions);
    v.push(&statistics::Statistics);
    v.push(&vadinfo::VadInfo);
    v.push(&vadwalk::VadWalk);
    v.push(&virtmap::VirtMap);
    registry::register(v);
}
