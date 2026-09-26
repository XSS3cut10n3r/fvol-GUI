//! mac.ifconfig.Ifconfig (python `plugins/mac/ifconfig.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::util::pointer_to_string;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::net::{ifnet_sockaddr_dl, sockaddr_dl_str, sockaddr_get_address};
use crate::symbols::mac::{MAX_ELEMENTS, MacExt};

pub struct Ifconfig;

impl Plugin for Ifconfig {
    fn name(&self) -> &'static str {
        "mac.ifconfig.Ifconfig"
    }
    fn description(&self) -> &'static str {
        "Lists network interface information for all devices"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![
            Column::new("Interface", ColType::Str),
            Column::new("IP Address", ColType::Str),
            Column::new("Mac Address", ColType::Str),
            Column::new("Promiscuous", ColType::Bool),
        ])?;
        let list_head = match k.object_from_symbol("ifnet_head") {
            Ok(h) => h,
            Err(Error::Symbol(_)) => k.object_from_symbol("dlil_ifnet_head")?,
            Err(e) => return Err(e),
        };
        for ifnet in list_head.walk_tailq("if_link", MAX_ELEMENTS) {
            let ifnet = ifnet?;
            let name = pointer_to_string(&ifnet.m("if_name")?, 32)?;
            let unit = ifnet.m("if_unit")?.int()?;
            let prom = ifnet.m("if_flags")?.int()? & 0x100 == 0x100;
            let mac_addr = match ifnet_sockaddr_dl(&ifnet)? {
                None => Value::Unreadable,
                Some(sdl) => Value::Str(sockaddr_dl_str(&sdl)?),
            };
            let iface = format!("{name}{unit}");
            for ifaddr in ifnet.m("if_addrhead")?.walk_tailq("ifa_link", MAX_ELEMENTS) {
                let ip = sockaddr_get_address(&ifaddr?.m("ifa_addr")?)?;
                out.row(0, vec![Value::Str(iface.clone()), Value::Str(ip), mac_addr.clone(), Value::Bool(prom)])?;
            }
        }
        Ok(())
    }
}
