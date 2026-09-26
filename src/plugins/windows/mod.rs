//! windows plugins.

use crate::plugins::Plugin;

pub mod driverirp;
pub mod driverscan;
pub mod info;
pub mod modules;
pub mod poolscanner;
pub mod pslist;
pub mod psscan;
pub mod ssdt;
pub mod vadinfo;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&driverirp::DriverIrp);
    v.push(&driverscan::DriverScan);
    v.push(&info::Info);
    v.push(&modules::Modules);
    v.push(&poolscanner::PoolScanner);
    v.push(&pslist::PsList);
    v.push(&psscan::PsScan);
    v.push(&ssdt::Ssdt);
    v.push(&vadinfo::VadInfo);
}
