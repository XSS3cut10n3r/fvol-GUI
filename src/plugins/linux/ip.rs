//! linux.ip.Addr and linux.ip.Link (python `plugins/linux/ip.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::{LinuxExt, NetExt};

pub struct Addr;
pub struct Link;

/// python `for net_ns in net_namespace_list.to_list(net, "list"): for net_dev in
/// net_ns.dev_base_head.to_list(net_device, "dev_list")`: every `(net, net_device)` pair in
/// python order. A trailing `Err` is where python's generator raised.
pub fn net_devices(k: &LinuxKernel) -> Vec<Result<(Obj, Obj)>> {
    let mut out = Vec::new();
    let t = k.table.name();
    let (net_ty, dev_ty) = (format!("{t}!net"), format!("{t}!net_device"));
    let head = match k.object_from_symbol("net_namespace_list") {
        Ok(h) => h,
        Err(e) => return vec![Err(e)],
    };
    for ns in head.list_of(&net_ty, "list") {
        let ns = match ns.and_then(|n| n.m("dev_base_head").map(|d| (n, d))) {
            Ok(n) => n,
            Err(e) => {
                out.push(Err(e));
                return out;
            }
        };
        for d in ns.1.list_of(&dev_ty, "dev_list") {
            match d {
                Ok(d) => out.push(Ok((ns.0, d))),
                Err(e) => {
                    out.push(Err(e));
                    return out;
                }
            }
        }
    }
    out
}

/// python's TypeError from `TreeGrid._validate_values` for a `None` in a `str` column.
fn none_in_str_column(index: usize, name: &str) -> Error {
    Error::msg(format!(
        "TypeError: Values item with index {index} is the wrong type for column {name} (got <class 'NoneType'> but expected <class 'str'>)"
    ))
}

/// python `net_ns_id or renderers.NotAvailableValue()`.
fn ns_value(v: Option<i128>) -> Value {
    match v {
        Some(v) if v != 0 => Value::Int(v),
        _ => Value::NotAvailable,
    }
}

/// python `try: net_dev.get_net_namespace_id() except AttributeError: None`.
fn net_ns_id(d: &Obj) -> Result<Option<i128>> {
    match d.get_net_namespace_id() {
        Ok(v) => Ok(v),
        Err(e) if e.to_string().contains("AttributeError") => Ok(None),
        Err(e) => Err(e),
    }
}

/// python `Addr._gather_net_dev_info(net_dev)`: the IPv4 then the IPv6 address rows of a
/// device.
fn addr_rows(d: &Obj, out: &mut dyn RowSink) -> Result<()> {
    let mac = d.get_mac_address()?;
    let promisc = d.promisc()?;
    let state = d.get_operational_state()?;
    let name = d.get_device_name()?;
    let ifindex = d.m("ifindex")?.int()?;
    let ns = net_ns_id(d)?;
    let mut emit = |addr: &Obj| -> Result<()> {
        let prefix = addr.get_prefix_len()?;
        let scope = addr.get_scope_type()?;
        let ip = addr.get_address()?;
        let Some(mac) = &mac else { return Err(none_in_str_column(3, "MAC")) };
        out.row(
            0,
            vec![
                ns_value(ns),
                Value::Int(ifindex),
                Value::Str(name.clone()),
                Value::Str(mac.clone()),
                Value::Bool(promisc),
                Value::Str(ip),
                Value::Int(prefix),
                Value::Str(scope),
                state.clone(),
            ],
        )
    };
    let in_dev = d.m("ip_ptr")?.deref()?.cast("in_device")?;
    for a in in_dev.get_addresses() {
        emit(&a?)?;
    }
    let in6_dev = d.m("ip6_ptr")?.deref()?.cast("inet6_dev")?;
    for a in in6_dev.get_addresses() {
        emit(&a?)?;
    }
    Ok(())
}

/// python `Link._gather_net_dev_link_info(net_device)`.
fn link_row(d: &Obj) -> Result<Vec<Value>> {
    let mac = d.get_mac_address()?;
    let state = d.get_operational_state()?;
    let name = d.get_device_name()?;
    let mtu = d.m("mtu")?.int()?;
    let qdisc = d.get_qdisc_name()?;
    let qlen = d.get_queue_length()?;
    let ns = net_ns_id(d)?;
    // drop IFF_ like iproute2's 'ip link' (which also removes IFF_RUNNING)
    let flags: Vec<String> = d.get_flag_names()?.into_iter().filter(|f| f != "IFF_RUNNING").map(|f| f.replace("IFF_", "")).collect();
    let Some(mac) = mac else { return Err(none_in_str_column(2, "MAC")) };
    Ok(vec![
        ns_value(ns),
        Value::Str(name),
        Value::Str(mac),
        state,
        Value::Int(mtu),
        match qdisc {
            Some(q) if !q.is_empty() => Value::Str(q),
            _ => Value::NotAvailable,
        },
        Value::Int(qlen),
        Value::Str(flags.join(",")),
    ])
}

impl Plugin for Addr {
    fn name(&self) -> &'static str {
        "linux.ip.Addr"
    }
    fn description(&self) -> &'static str {
        "Lists network interface information for all devices"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("NetNS", ColType::Int),
            Column::new("Index", ColType::Int),
            Column::new("Interface", ColType::Str),
            Column::new("MAC", ColType::Str),
            Column::new("Promiscuous", ColType::Bool),
            Column::new("IP", ColType::Str),
            Column::new("Prefix", ColType::Int),
            Column::new("Scope Type", ColType::Str),
            Column::new("State", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        for nd in net_devices(k) {
            addr_rows(&nd?.1, out)?;
        }
        Ok(())
    }
}

impl Plugin for Link {
    fn name(&self) -> &'static str {
        "linux.ip.Link"
    }
    fn description(&self) -> &'static str {
        "Lists information about network interfaces similar to `ip link show`"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("NS", ColType::Int),
            Column::new("Interface", ColType::Str),
            Column::new("MAC", ColType::Str),
            Column::new("State", ColType::Str),
            Column::new("MTU", ColType::Int),
            Column::new("Qdisc", ColType::Str),
            Column::new("Qlen", ColType::Int),
            Column::new("Flags", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        for nd in net_devices(k) {
            out.row(0, link_row(&nd?.1)?)?;
        }
        Ok(())
    }
}
