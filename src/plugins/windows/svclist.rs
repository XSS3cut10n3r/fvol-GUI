//! windows.svclist.SvcList (python `plugins/windows/svclist.py`): services reachable from the
//! `Sc27` service-header list inside the services.exe image.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::windows::svcscan::{columns, plan_service_list, replay_services, with_prereq};
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct SvcList;

impl Plugin for SvcList {
    fn name(&self) -> &'static str {
        "windows.svclist.SvcList"
    }
    fn description(&self) -> &'static str {
        "Lists services contained with the services.exe doubly linked list of services"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(columns())?;
        let k = ctx.windows_kernel()?;
        let (pre, plan) = with_prereq(ctx, k, |table| plan_service_list(k, table))?;
        let enc = out.encoder();
        replay_services(plan, &pre.binary_map, enc.as_ref(), false, &mut |row| row.emit(out))
    }
}
