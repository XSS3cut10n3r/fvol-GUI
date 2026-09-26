//! mac plugins.

use crate::plugins::Plugin;

pub mod pslist;

pub fn register(v: &mut Vec<&'static dyn Plugin>) {
    v.push(&pslist::PsList);
}
