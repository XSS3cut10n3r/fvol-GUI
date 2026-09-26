//! linux plugins.

use crate::plugins::Plugin;

pub mod capabilities;
pub mod envars;
pub mod malware;
pub mod proc;
pub mod psaux;
pub mod pslist;
pub mod pstree;
pub mod ptrace;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&capabilities::Capabilities);
    v.push(&envars::Envars);
    v.push(&malware::process_spoofing::ProcessSpoofing);
    v.push(&proc::Maps);
    v.push(&psaux::PsAux);
    v.push(&pslist::PsList);
    v.push(&pstree::PsTree);
    v.push(&ptrace::Ptrace);
}
