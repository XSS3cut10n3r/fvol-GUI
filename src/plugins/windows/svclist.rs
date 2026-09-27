//! windows.svclist.SvcList (python `plugins/windows/svclist.py`): services reachable from the
//! `Sc27` service-header list inside the services.exe image.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::windows::svcscan::{columns, run_service_plugin};
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
        run_service_plugin(ctx, k, true, out)
    }
}
