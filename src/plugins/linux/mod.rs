//! linux plugins.

use crate::plugins::Plugin;

pub mod bash;
pub mod capabilities;
pub mod elfs;
pub mod envars;
pub mod kthreads;
pub mod library_list;
pub mod malware;
pub mod pidhashtable;
pub mod proc;
pub mod psaux;
pub mod pscallstack;
pub mod pslist;
pub mod psscan;
pub mod pstree;
pub mod ptrace;
pub mod vmaregexscan;
pub mod vmayarascan;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&bash::Bash);
    v.push(&capabilities::Capabilities);
    v.push(&elfs::Elfs);
    v.push(&envars::Envars);
    v.push(&library_list::LibraryList);
    v.push(&malware::malfind::Malfind);
    v.push(&malware::malfind::MalfindDeprecated);
    v.push(&malware::process_spoofing::ProcessSpoofing);
    v.push(&pidhashtable::PIDHashTable);
    v.push(&proc::Maps);
    v.push(&psaux::PsAux);
    v.push(&pslist::PsList);
    v.push(&psscan::PsScan);
    v.push(&pstree::PsTree);
    v.push(&ptrace::Ptrace);
    v.push(&vmaregexscan::VmaRegExScan);
    v.push(&vmayarascan::VmaYaraScan);
    v.push(&pscallstack::PsCallStack);
    v.push(&kthreads::Kthreads);
}
