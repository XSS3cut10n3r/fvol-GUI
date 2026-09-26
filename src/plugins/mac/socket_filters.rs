//! mac.socket_filters.Socket_filters (python `plugins/mac/socket_filters.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::util::pointer_to_string;
use crate::plugins::mac::lsmod::list_modules;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::{MAX_ELEMENTS, MacExt, generate_kernel_handler_info, lookup_module_address};

pub struct SocketFilters;

const MEMBERS_TO_CHECK: [&str; 15] = [
    "sf_unregistered",
    "sf_attach",
    "sf_detach",
    "sf_notify",
    "sf_getpeername",
    "sf_getsockname",
    "sf_data_in",
    "sf_data_out",
    "sf_connect_in",
    "sf_connect_out",
    "sf_bind",
    "sf_setoption",
    "sf_getoption",
    "sf_listen",
    "sf_ioctl",
];

impl Plugin for SocketFilters {
    fn name(&self) -> &'static str {
        "mac.socket_filters.Socket_filters"
    }
    fn description(&self) -> &'static str {
        "Enumerates kernel socket filters."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![
            Column::new("Filter", ColType::Hex),
            Column::new("Name", ColType::Str),
            Column::new("Member", ColType::Str),
            Column::new("Socket", ColType::Hex),
            Column::new("Handler", ColType::Hex),
            Column::new("Module", ColType::Str),
            Column::new("Symbol", ColType::Str),
        ])?;
        let handlers = generate_kernel_handler_info(k, list_modules(k))?;
        let filter_list = k.object_from_symbol("sock_filter_head")?;
        for container in filter_list.walk_tailq("sf_global_next", MAX_ELEMENTS) {
            let container = container?;
            let current = container.m("sf_filter")?;
            let filter_name = pointer_to_string(&current.m("sf_name")?, 128)?;
            // `.sfe_socket.vol.offset`: where the pointer member lives (python constructs, i.e.
            // reads, the pointer)
            let filter_socket = match container.m("sf_entry_head").and_then(|h| h.m("sfe_socket")).and_then(|s| s.u64().map(|_| s.addr)) {
                Ok(a) => a,
                Err(e) if e.is_invalid_address() => 0,
                Err(e) => return Err(e),
            };
            for member in MEMBERS_TO_CHECK {
                let check_addr = current.m(member)?.u64()?;
                if check_addr == 0 {
                    continue;
                }
                // python passes no kernel module name here: no KASLR adjustment
                let (module, symbol) = lookup_module_address(k.table, &handlers, check_addr as i128, None);
                out.row(
                    0,
                    vec![
                        Value::Int(current.addr as i128),
                        Value::Str(filter_name.clone()),
                        Value::SStr(member),
                        Value::Int(filter_socket as i128),
                        Value::Int(check_addr as i128),
                        Value::Str(module),
                        Value::Str(symbol.to_string()),
                    ],
                )?;
            }
        }
        Ok(())
    }
}
