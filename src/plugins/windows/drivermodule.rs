//! windows.drivermodule.DriverModule (python `plugins/windows/drivermodule.py`): deprecated
//! alias of [`windows.malware.drivermodule.DriverModule`](super::malware::drivermodule).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct DriverModule;

impl Plugin for DriverModule {
    fn name(&self) -> &'static str {
        "windows.drivermodule.DriverModule"
    }
    fn description(&self) -> &'static str {
        "Determines if any loaded drivers were hidden by a rootkit (deprecated)."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        super::malware::drivermodule::run(ctx, out)
    }
}
