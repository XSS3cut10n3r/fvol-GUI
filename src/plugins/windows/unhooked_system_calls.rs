//! windows.unhooked_system_calls.unhooked_system_calls (python
//! `plugins/windows/unhooked_system_calls.py`): deprecated alias of
//! [`windows.malware.unhooked_system_calls.UnhookedSystemCalls`](super::malware::unhooked_system_calls).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::plugins::{Config, Plugin};
use crate::renderers::RowSink;

pub struct UnhookedSystemCalls;

impl Plugin for UnhookedSystemCalls {
    fn name(&self) -> &'static str {
        "windows.unhooked_system_calls.unhooked_system_calls"
    }
    fn description(&self) -> &'static str {
        "Detects hooked ntdll.dll stub functions in Windows processes (deprecated)."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        super::malware::unhooked_system_calls::run(ctx, out)
    }
}
