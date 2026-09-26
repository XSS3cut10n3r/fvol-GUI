//! windows plugins.

use crate::plugins::Plugin;

pub mod deskscan;
pub mod desktops;
pub mod info;
pub mod modules;
pub mod poolscanner;
pub mod pslist;
pub mod psscan;
pub mod vadinfo;
pub mod windows;
pub mod windowstations;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&deskscan::DeskScan);
    v.push(&desktops::Desktops);
    v.push(&info::Info);
    v.push(&modules::Modules);
    v.push(&poolscanner::PoolScanner);
    v.push(&pslist::PsList);
    v.push(&psscan::PsScan);
    v.push(&vadinfo::VadInfo);
    v.push(&windows::Windows);
    v.push(&windowstations::WindowStations);
}
