//! windows plugins.

use crate::plugins::Plugin;

pub mod crashinfo;
pub mod dumpfiles;
pub mod etwpatch;
pub mod iat;
pub mod info;
pub mod mbrscan;
pub mod mftscan;
pub mod modules;
pub mod pe_symbols;
pub mod pedump;
pub mod poolscanner;
pub mod pslist;
pub mod psscan;
pub mod registry;
pub mod truecrypt;
pub mod vadinfo;
pub mod verinfo;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&crashinfo::Crashinfo);
    v.push(&dumpfiles::DumpFiles);
    v.push(&etwpatch::EtwPatch);
    v.push(&iat::IAT);
    v.push(&info::Info);
    v.push(&mbrscan::MBRScan);
    v.push(&mftscan::MFTScan);
    v.push(&mftscan::ADS);
    v.push(&mftscan::ResidentData);
    v.push(&modules::Modules);
    v.push(&pe_symbols::PESymbols);
    v.push(&pedump::PEDump);
    v.push(&poolscanner::PoolScanner);
    v.push(&pslist::PsList);
    v.push(&psscan::PsScan);
    v.push(&truecrypt::Passphrase);
    v.push(&vadinfo::VadInfo);
    v.push(&verinfo::VerInfo);
    registry::register(v);
}
