//! linux plugins.

use crate::plugins::Plugin;

pub mod kthreads;
pub mod pscallstack;
pub mod pslist;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&pslist::PsList);
    v.push(&pscallstack::PsCallStack);
    v.push(&kthreads::Kthreads);
}
