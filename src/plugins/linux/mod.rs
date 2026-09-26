//! linux plugins.

use crate::plugins::Plugin;

pub mod proc;
pub mod pslist;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&proc::Maps);
    v.push(&pslist::PsList);
}
