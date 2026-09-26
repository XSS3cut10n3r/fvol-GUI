//! windows plugins.

use crate::plugins::Plugin;

pub mod bigpools;
pub mod callbacks;
pub mod debugregisters;
pub mod devicetree;
pub mod driverirp;
pub mod drivermodule;
pub mod driverscan;
pub mod filescan;
pub mod handles;
pub mod info;
pub mod kpcrs;
pub mod malware;
pub mod modscan;
pub mod modules;
pub mod mutantscan;
pub mod orphan_kernel_threads;
pub mod poolscanner;
pub mod pslist;
pub mod psscan;
pub mod registry;
pub mod ssdt;
pub mod suspended_threads;
pub mod symlinkscan;
pub mod thrdscan;
pub mod thread_pe_symbols;
pub mod threads;
pub mod timers;
pub mod unloadedmodules;
pub mod vadinfo;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&bigpools::BigPools);
    v.push(&callbacks::Callbacks);
    v.push(&debugregisters::DebugRegisters);
    v.push(&devicetree::DeviceTree);
    v.push(&driverirp::DriverIrp);
    v.push(&drivermodule::DriverModule);
    v.push(&driverscan::DriverScan);
    v.push(&filescan::FileScan);
    v.push(&handles::Handles);
    v.push(&info::Info);
    v.push(&kpcrs::KPCRs);
    v.push(&malware::drivermodule::DriverModule);
    v.push(&modscan::ModScan);
    v.push(&modules::Modules);
    v.push(&mutantscan::MutantScan);
    v.push(&orphan_kernel_threads::Threads);
    v.push(&poolscanner::PoolScanner);
    v.push(&pslist::PsList);
    v.push(&psscan::PsScan);
    v.push(&ssdt::Ssdt);
    v.push(&suspended_threads::SuspendedThreads);
    v.push(&symlinkscan::SymlinkScan);
    v.push(&thrdscan::ThrdScan);
    v.push(&threads::Threads);
    v.push(&timers::Timers);
    v.push(&unloadedmodules::UnloadedModules);
    v.push(&vadinfo::VadInfo);
    registry::register(v);
}
