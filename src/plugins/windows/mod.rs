//! windows plugins.

use crate::plugins::Plugin;

pub mod info;
pub mod modules;
pub mod pslist;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&info::Info);
    v.push(&modules::Modules);
    v.push(&pslist::PsList);
}
