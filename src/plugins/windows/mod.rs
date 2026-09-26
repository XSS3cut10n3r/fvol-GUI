//! windows plugins.

use crate::plugins::Plugin;

pub mod bigpools;
pub mod devicetree;
pub mod driverirp;
pub mod drivermodule;
pub mod driverscan;
pub mod filescan;
pub mod info;
pub mod malware;
pub mod modscan;
pub mod modules;
pub mod mutantscan;
pub mod poolscanner;
pub mod pslist;
pub mod psscan;
pub mod ssdt;
pub mod symlinkscan;
pub mod vadinfo;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&bigpools::BigPools);
    v.push(&devicetree::DeviceTree);
    v.push(&driverirp::DriverIrp);
    v.push(&drivermodule::DriverModule);
    v.push(&driverscan::DriverScan);
    v.push(&filescan::FileScan);
    v.push(&info::Info);
    v.push(&malware::drivermodule::DriverModule);
    v.push(&modscan::ModScan);
    v.push(&modules::Modules);
    v.push(&mutantscan::MutantScan);
    v.push(&poolscanner::PoolScanner);
    v.push(&pslist::PsList);
    v.push(&psscan::PsScan);
    v.push(&ssdt::Ssdt);
    v.push(&symlinkscan::SymlinkScan);
    v.push(&vadinfo::VadInfo);
}
