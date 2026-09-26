//! mac plugins.

use crate::plugins::Plugin;

pub mod bash;
pub mod malfind;
pub mod proc_maps;
pub mod psaux;
pub mod pslist;
pub mod pstree;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&bash::Bash);
    v.push(&malfind::Malfind);
    v.push(&proc_maps::Maps);
    v.push(&psaux::Psaux);
    v.push(&pslist::PsList);
    v.push(&pstree::PsTree);
}
