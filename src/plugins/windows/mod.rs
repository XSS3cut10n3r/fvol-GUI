//! windows plugins.

use crate::plugins::Plugin;

<<<<<<< HEAD
pub mod deskscan;
pub mod desktops;
=======
pub mod cmdscan;
pub mod consoles;
>>>>>>> worktree-agent-ae414ad411768cfdf
pub mod info;
pub mod modules;
pub mod netscan;
pub mod netstat;
pub mod poolscanner;
pub mod pslist;
pub mod psscan;
pub mod registry;
pub mod vadinfo;
pub mod windows;
pub mod windowstations;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
<<<<<<< HEAD
    v.push(&deskscan::DeskScan);
    v.push(&desktops::Desktops);
=======
    v.push(&cmdscan::CmdScan);
    v.push(&consoles::Consoles);
>>>>>>> worktree-agent-ae414ad411768cfdf
    v.push(&info::Info);
    v.push(&modules::Modules);
    v.push(&netscan::NetScan);
    v.push(&netstat::NetStat);
    v.push(&poolscanner::PoolScanner);
    v.push(&pslist::PsList);
    v.push(&psscan::PsScan);
    v.push(&vadinfo::VadInfo);
    v.push(&windows::Windows);
    v.push(&windowstations::WindowStations);
    registry::register(v);
}
