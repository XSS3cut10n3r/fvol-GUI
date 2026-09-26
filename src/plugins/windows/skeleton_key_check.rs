//! windows.skeleton_key_check.Skeleton_Key_Check (python `plugins/windows/skeleton_key_check.py`):
//! deprecated alias of
//! [`windows.malware.skeleton_key_check.Skeleton_Key_Check`](super::malware::skeleton_key_check).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct SkeletonKeyCheck;

impl Plugin for SkeletonKeyCheck {
    fn name(&self) -> &'static str {
        "windows.skeleton_key_check.Skeleton_Key_Check"
    }
    fn description(&self) -> &'static str {
        "Looks for signs of Skeleton Key malware"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        super::malware::skeleton_key_check::run(ctx, out)
    }
}
