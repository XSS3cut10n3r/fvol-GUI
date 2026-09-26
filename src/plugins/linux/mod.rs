//! linux plugins.

use crate::plugins::Plugin;

pub mod bash;
pub mod capabilities;
pub mod elfs;
pub mod envars;
pub mod library_list;
pub mod malware;
pub mod proc;
pub mod psaux;
pub mod pslist;
pub mod pstree;
pub mod ptrace;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&bash::Bash);
    v.push(&capabilities::Capabilities);
    v.push(&elfs::Elfs);
    v.push(&envars::Envars);
    v.push(&library_list::LibraryList);
    v.push(&malware::malfind::Malfind);
    v.push(&malware::malfind::MalfindDeprecated);
    v.push(&malware::process_spoofing::ProcessSpoofing);
    v.push(&proc::Maps);
    v.push(&psaux::PsAux);
    v.push(&pslist::PsList);
    v.push(&pstree::PsTree);
    v.push(&ptrace::Ptrace);
}
