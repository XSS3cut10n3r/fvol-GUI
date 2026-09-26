//! mac.kauth_scopes.Kauth_scopes and mac.kauth_listeners.Kauth_listeners (python
//! `plugins/mac/kauth_scopes.py`, `plugins/mac/kauth_listeners.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::mac::MacKernel;
use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::pointer_to_string;
use crate::plugins::mac::lsmod::list_modules;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::{MAX_ELEMENTS, MacExt, generate_kernel_handler_info, lookup_module_address};

pub struct KauthScopes;
pub struct KauthListeners;

/// python `Kauth_scopes.list_kauth_scopes(context, kernel_module_name)`: the `kauth_scope *`
/// pointers of the `kauth_scopes` tail queue (smear-safe walk). Trailing `Err` = python raised.
pub fn list_kauth_scopes(k: &MacKernel) -> Vec<Result<Obj>> {
    match k.object_from_symbol("kauth_scopes") {
        Ok(scopes) => scopes.walk_tailq("ks_link", MAX_ELEMENTS),
        Err(e) => vec![Err(e)],
    }
}

impl Plugin for KauthScopes {
    fn name(&self) -> &'static str {
        "mac.kauth_scopes.Kauth_scopes"
    }
    fn description(&self) -> &'static str {
        "Lists kauth scopes and their status"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![
            Column::new("Name", ColType::Str),
            Column::new("IData", ColType::Hex),
            Column::new("Listeners", ColType::Int),
            Column::new("Callback Address", ColType::Hex),
            Column::new("Module", ColType::Str),
            Column::new("Symbol", ColType::Str),
        ])?;
        let handlers = generate_kernel_handler_info(k, list_modules(k))?;
        for scope in list_kauth_scopes(k) {
            let scope = scope?;
            let callback = scope.m("ks_callback")?.u64()?;
            if callback == 0 {
                continue;
            }
            let (module, symbol) = lookup_module_address(k.table, &handlers, callback as i128, Some(k.offset));
            let identifier = pointer_to_string(&scope.m("ks_identifier")?, 128)?;
            let idata = scope.m("ks_idata")?.u64()?;
            let mut listeners = 0i128;
            for l in scope.get_listeners() {
                l?;
                listeners += 1;
            }
            out.row(
                0,
                vec![
                    Value::Str(identifier),
                    Value::Int(idata as i128),
                    Value::Int(listeners),
                    Value::Int(callback as i128),
                    Value::Str(module),
                    Value::Str(symbol.to_string()),
                ],
            )?;
        }
        Ok(())
    }
}

impl Plugin for KauthListeners {
    fn name(&self) -> &'static str {
        "mac.kauth_listeners.Kauth_listeners"
    }
    fn description(&self) -> &'static str {
        "Lists kauth listeners and their status"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![
            Column::new("Name", ColType::Str),
            Column::new("IData", ColType::Hex),
            Column::new("Callback Address", ColType::Hex),
            Column::new("Module", ColType::Str),
            Column::new("Symbol", ColType::Str),
        ])?;
        let handlers = generate_kernel_handler_info(k, list_modules(k))?;
        for scope in list_kauth_scopes(k) {
            let scope = scope?;
            let scope_name = pointer_to_string(&scope.m("ks_identifier")?, 128)?;
            for listener in scope.get_listeners() {
                let listener = listener?;
                let callback = listener.m("kll_callback")?.u64()?;
                if callback == 0 {
                    continue;
                }
                let (module, symbol) = lookup_module_address(k.table, &handlers, callback as i128, Some(k.offset));
                let idata = listener.m("kll_idata")?.u64()?;
                out.row(
                    0,
                    vec![
                        Value::Str(scope_name.clone()),
                        Value::Int(idata as i128),
                        Value::Int(callback as i128),
                        Value::Str(module),
                        Value::Str(symbol.to_string()),
                    ],
                )?;
            }
        }
        Ok(())
    }
}
