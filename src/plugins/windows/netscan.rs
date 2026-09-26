//! windows.netscan.NetScan (python `plugins/windows/netscan.py`): TCP listeners / endpoints and
//! UDP endpoints found by pool scanning (`TcpL`, `TcpE`, `UdpA`, `TTcb` tags), plus python's
//! reusable classmethods ([`determine_tcpip_version`], [`create_netscan_symbol_table`],
//! [`create_netscan_constraints`], [`scan_each`]) and the per-object row generation shared
//! with `windows.netstat` ([`object_rows`]).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::plugins::windows::info::{get_kuser_structure, get_version_structure};
use crate::plugins::windows::poolscanner::{PoolConstraint, generate_pool_scan_each, pool_type};
use crate::plugins::{Config, Plugin, Requirement, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::windows::network::{self, AF_INET, AF_INET6, NetExt};
use crate::symbols::windows::versions;

pub struct NetScan;

/// python's `include-corrupt` description (shared with netstat).
pub const INCLUDE_CORRUPT_DESC: &str = "Radically eases result validation. This will show partially overwritten data. WARNING: the results are likely to include garbage and/or corrupt data. Be cautious!";

type Ver = (i128, i128, i128, i128);

const X86_VERSIONS: &[(Ver, &str)] = &[
    ((6, 0, 6000, 0), "netscan-vista-x86"),
    ((6, 0, 6001, 0), "netscan-vista-x86"),
    ((6, 0, 6002, 0), "netscan-vista-x86"),
    ((6, 0, 6003, 0), "netscan-vista-x86"),
    ((6, 1, 7600, 0), "netscan-win7-x86"),
    ((6, 1, 7601, 0), "netscan-win7-x86"),
    ((6, 1, 8400, 0), "netscan-win7-x86"),
    ((6, 2, 9200, 0), "netscan-win8-x86"),
    ((6, 3, 9600, 0), "netscan-win81-x86"),
    ((10, 0, 10240, 0), "netscan-win10-10240-x86"),
    ((10, 0, 10586, 0), "netscan-win10-10586-x86"),
    ((10, 0, 14393, 0), "netscan-win10-14393-x86"),
    ((10, 0, 15063, 0), "netscan-win10-15063-x86"),
    ((10, 0, 16299, 0), "netscan-win10-15063-x86"),
    ((10, 0, 17134, 0), "netscan-win10-17134-x86"),
    ((10, 0, 17763, 0), "netscan-win10-17134-x86"),
    ((10, 0, 18362, 0), "netscan-win10-17134-x86"),
    ((10, 0, 18363, 0), "netscan-win10-17134-x86"),
];

const X64_VERSIONS: &[(Ver, &str)] = &[
    ((6, 0, 6000, 0), "netscan-vista-x64"),
    ((6, 0, 6001, 0), "netscan-vista-sp12-x64"),
    ((6, 0, 6002, 0), "netscan-vista-sp12-x64"),
    ((6, 0, 6003, 0), "netscan-vista-sp12-x64"),
    ((6, 1, 7600, 0), "netscan-win7-x64"),
    ((6, 1, 7601, 0), "netscan-win7-x64"),
    ((6, 1, 8400, 0), "netscan-win7-x64"),
    ((6, 2, 9200, 0), "netscan-win8-x64"),
    ((6, 3, 9600, 0), "netscan-win81-x64"),
    ((6, 3, 9600, 19935), "netscan-win81-19935-x64"),
    ((10, 0, 10240, 0), "netscan-win10-x64"),
    ((10, 0, 10586, 0), "netscan-win10-x64"),
    ((10, 0, 14393, 0), "netscan-win10-x64"),
    ((10, 0, 15063, 0), "netscan-win10-15063-x64"),
    ((10, 0, 16299, 0), "netscan-win10-16299-x64"),
    ((10, 0, 17134, 0), "netscan-win10-17134-x64"),
    ((10, 0, 17763, 0), "netscan-win10-17763-x64"),
    ((10, 0, 18362, 0), "netscan-win10-18362-x64"),
    ((10, 0, 18363, 0), "netscan-win10-18363-x64"),
    ((10, 0, 19041, 0), "netscan-win10-19041-x64"),
    ((10, 0, 20348, 0), "netscan-win10-20348-x64"),
];

/// python `NetScan.determine_tcpip_version(context, kernel_module_name)`: the netscan ISF
/// file name for this kernel and whether python uses `network.win10_x64_class_types`.
pub fn determine_tcpip_version(k: &WinKernel) -> Result<(&'static str, bool)> {
    let is_64bit = k.table.is_64bit();
    let is_18363_or_later = versions::IS_WIN10_18363_OR_LATER.check(k.table);
    let vers = get_version_structure(k)?;
    let kuser = get_kuser_structure(k)?;
    let r = (|| -> Result<(i128, i128, i128)> { Ok((vers.m("MinorVersion")?.int()?, kuser.m("NtMajorVersion")?.int()?, kuser.m("NtMinorVersion")?.int()?)) })();
    let (mut vers_minor_version, nt_major_version, nt_minor_version) = match r {
        Ok(v) => v,
        Err(_) => return Err(Error::msg("Kernel Debug Structure missing VERSION/KUSER structure, unable to determine Windows version!")),
    };
    // python's (eagerly formatted) debug message reads vers.MajorVersion
    let vers_major_version = vers.m("MajorVersion")?.int()?;
    let win10_x64 = nt_major_version == 10 && is_64bit;
    let version_dict = if is_64bit { X64_VERSIONS } else { X86_VERSIONS };
    let mut tcpip_mod_version: i128 = 0;
    if vers_minor_version == 18362 && is_18363_or_later {
        vers_minor_version = 18363;
    }
    let os = (nt_major_version, nt_minor_version, vers_minor_version);
    if version_dict.iter().any(|((a, b, c, d), _)| (*a, *b, *c) == os && *d != 0) {
        if let Some(ver) = crate::plugins::windows::verinfo::find_version_info_one(k.phys, "tcpip.sys")? {
            tcpip_mod_version = ver.3 as i128;
        }
    }
    let lookup = |v: Ver| version_dict.iter().find(|(key, _)| *key == v).map(|(_, f)| *f);
    let filename = match lookup((os.0, os.1, os.2, tcpip_mod_version)) {
        Some(f) => f,
        None => {
            let mut current: Vec<Ver> =
                version_dict.iter().map(|(v, _)| *v).filter(|v| v.0 == nt_major_version && v.1 == nt_minor_version && v.3 <= tcpip_mod_version).collect();
            current.sort();
            match current.last() {
                Some(latest) => lookup(*latest).unwrap_or_default(),
                None => {
                    return Err(Error::msg(format!(
                        "This version of Windows is not supported: {nt_major_version}.{nt_minor_version} {vers_major_version}.{vers_minor_version}!"
                    )));
                }
            }
        }
    };
    Ok((filename, win10_x64))
}

/// python `NetScan.create_netscan_symbol_table(context, kernel_module_name, config_path)`:
/// the netscan ISF for this kernel (`nt_symbols` mapped to the kernel table), with its class
/// types recorded in [`network::bind_class_types`].
pub fn create_netscan_symbol_table(ctx: &Context, k: &WinKernel) -> Result<TableRef> {
    let (filename, win10_x64) = determine_tcpip_version(k)?;
    let t = ctx.load_isf_with(&format!("windows/netscan/{filename}"), None, &[("nt_symbols", k.table.name())])?;
    network::bind_class_types(t, win10_x64);
    Ok(t)
}

/// python `NetScan.create_netscan_constraints(context, symbol_table)`.
pub fn create_netscan_constraints(t: TableRef) -> Result<Vec<PoolConstraint>> {
    use pool_type::{FREE, NONPAGED};
    let name = t.name();
    let tcpl_size = t.size_of(t.get_type("_TCP_LISTENER")?);
    let tcpe_size = t.size_of(t.get_type("_TCP_ENDPOINT")?);
    let udpa_size = t.size_of(t.get_type("_UDP_ENDPOINT")?);
    let mut c = vec![
        PoolConstraint::new(b"TcpL", format!("{name}!_TCP_LISTENER")).size(Some(tcpl_size), None).page_type(NONPAGED | FREE),
        PoolConstraint::new(b"TcpE", format!("{name}!_TCP_ENDPOINT")).size(Some(tcpe_size), None).page_type(NONPAGED | FREE),
        PoolConstraint::new(b"UdpA", format!("{name}!_UDP_ENDPOINT")).size(Some(udpa_size), None).page_type(NONPAGED | FREE),
    ];
    if name.starts_with("netscan-win10-20348") {
        c.push(PoolConstraint::new(b"TTcb", format!("{name}!_TCP_ENDPOINT")).size(Some(tcpe_size), None).page_type(NONPAGED | FREE));
    }
    Ok(c)
}

/// python `NetScan.scan(context, kernel_module_name, netscan_symbol_table)`, streaming: every
/// carved network object in python's order (`Ok(false)` stops). Errors python raises midway are
/// returned after the objects found before them.
pub fn scan_each(ctx: &Context, k: &WinKernel, netscan_table: TableRef, mut f: impl FnMut(Obj) -> Result<bool>) -> Result<()> {
    let constraints = create_netscan_constraints(netscan_table)?;
    generate_pool_scan_each(ctx, k, k.table, &constraints, |hit| f(hit.object))
}

#[inline]
fn or_unreadable<T>(v: Option<T>, f: impl FnOnce(T) -> Value) -> Value {
    match v {
        Some(x) => f(x),
        None => Value::Unreadable,
    }
}

/// `get_owner_pid() or UnreadableValue()`, `get_owner_procname() or ...`,
/// `get_create_time() or ...` (python falsy values -> Unreadable).
fn owner_and_time(o: &Obj) -> Result<[Value; 3]> {
    let pid = or_unreadable(o.get_owner_pid()?.filter(|p| *p != 0), Value::Int);
    let name = or_unreadable(o.get_owner_procname()?.filter(|s| !s.is_empty()), Value::Str);
    let created = o.net_create_time()?.unwrap_or(Value::Unreadable);
    Ok([pid, name, created])
}

/// The rows python's `NetScan._generator` / `NetStat._generator` produce for one network
/// object (10 values each: Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort,
/// State, PID, Owner, Created). `show_corrupt` skips the `is_valid()` check; `netstat` enables
/// netstat's debug message formatting of an unknown TCP address family (python raises a
/// `TypeError` when it is `None`). `Err` = python raised while producing these rows.
pub fn object_rows(o: &Obj, show_corrupt: bool, netstat: bool) -> Result<Vec<Vec<Value>>> {
    if !show_corrupt && !o.net_is_valid()? {
        return Ok(Vec::new());
    }
    let off = Value::Int(o.addr as i128);
    let mut rows = Vec::new();
    match o.struct_name() {
        Some("_UDP_ENDPOINT") => {
            for (ver, laddr, _) in o.dual_stack_sockets()? {
                let port = o.m("Port")?.int()?;
                let [pid, name, created] = owner_and_time(o)?;
                rows.push(vec![
                    off.clone(),
                    Value::SStr(if ver == "v4" { "UDPv4" } else { "UDPv6" }),
                    Value::Str(laddr),
                    Value::Int(port),
                    Value::SStr("*"),
                    Value::Int(0),
                    Value::SStr(""),
                    pid,
                    name,
                    created,
                ]);
            }
        }
        Some("_TCP_ENDPOINT") => {
            let af = o.get_address_family()?;
            let proto = match af {
                Some(AF_INET) => "TCPv4",
                Some(AF_INET6) => "TCPv6",
                _ => {
                    if netstat && af.is_none() {
                        return Err(Error::msg("TypeError: unsupported format string passed to NoneType.__format__"));
                    }
                    "TCPv?"
                }
            };
            let st = o.m("State")?;
            let sv = st.int()?;
            let state = match st.ty {
                crate::symbols::Ty::Enum(i) => match st.table().enum_lookup(i, sv) {
                    Some(n) => Value::Str(n.to_string()),
                    None => Value::Unreadable,
                },
                _ => Value::Unreadable,
            };
            let laddr = or_unreadable(o.get_local_address()?, Value::Str);
            let lport = o.m("LocalPort")?.int()?;
            let raddr = or_unreadable(o.get_remote_address()?, Value::Str);
            let rport = o.m("RemotePort")?.int()?;
            let [pid, name, created] = owner_and_time(o)?;
            rows.push(vec![off, Value::SStr(proto), laddr, Value::Int(lport), raddr, Value::Int(rport), state, pid, name, created]);
        }
        Some("_TCP_LISTENER") => {
            for (ver, laddr, raddr) in o.dual_stack_sockets()? {
                let port = o.m("Port")?.int()?;
                let [pid, name, created] = owner_and_time(o)?;
                rows.push(vec![
                    off.clone(),
                    Value::SStr(if ver == "v4" { "TCPv4" } else { "TCPv6" }),
                    Value::Str(laddr),
                    Value::Int(port),
                    Value::SStr(raddr),
                    Value::Int(0),
                    Value::SStr("LISTENING"),
                    pid,
                    name,
                    created,
                ]);
            }
        }
        _ => {}
    }
    Ok(rows)
}

/// Rows of `objs` (computed in parallel, emitted in order) followed by `tail` (python raising
/// after the last object). Stops at the first error, like python.
pub fn emit_rows(objs: &[Obj], tail: Option<Error>, show_corrupt: bool, netstat: bool, out: &mut dyn FnMut(Vec<Value>) -> Result<()>) -> Result<()> {
    let rows = if objs.len() > 16 {
        crate::util::par::par_map(objs.len(), |i| object_rows(&objs[i], show_corrupt, netstat))
    } else {
        objs.iter().map(|o| object_rows(o, show_corrupt, netstat)).collect()
    };
    for r in rows {
        for row in r? {
            out(row)?;
        }
    }
    match tail {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// The TreeGrid columns of netscan / netstat.
pub fn columns() -> Vec<Column> {
    vec![
        Column::new("Offset", ColType::Hex),
        Column::new("Proto", ColType::Str),
        Column::new("LocalAddr", ColType::Str),
        Column::new("LocalPort", ColType::Int),
        Column::new("ForeignAddr", ColType::Str),
        Column::new("ForeignPort", ColType::Int),
        Column::new("State", ColType::Str),
        Column::new("PID", ColType::Int),
        Column::new("Owner", ColType::Str),
        Column::new("Created", ColType::DateTime),
    ]
}

/// python `str()` of a row value inside the timeline description; absent values print as
/// `absent` (netscan replaces them with "N/A", netstat formats them as "-").
pub fn desc_value(v: &Value, absent: &str) -> String {
    match v {
        Value::Int(i) => i.to_string(),
        Value::Str(s) => s.clone(),
        Value::SStr(s) => s.to_string(),
        Value::NotApplicable => "N/A".to_string(),
        v if v.is_absent() => absent.to_string(),
        _ => String::new(),
    }
}

/// python `generate_timeline` of netscan / netstat for one row (None when Created is not a
/// datetime).
pub fn timeline_event(r: &[Value], absent: &str) -> Option<TimelineEvent> {
    if !matches!(r[9], Value::DateTime(_)) {
        return None;
    }
    let d = |i: usize| desc_value(&r[i], absent);
    let description = format!(
        "Network connection: Process {} {} Local Address {}:{} Remote Address {}:{} State {} Protocol {} ",
        d(7),
        d(8),
        d(2),
        d(3),
        d(4),
        d(5),
        d(6),
        d(1)
    );
    Some(TimelineEvent { description, kind: TimeKind::Created, time: r[9].clone() })
}

/// python `NetScan._generator(show_corrupt_results)`.
fn rows(ctx: &Context, show_corrupt: bool, out: &mut dyn FnMut(Vec<Value>) -> Result<()>) -> Result<()> {
    let k = ctx.windows_kernel()?;
    let t = {
        let _t = crate::util::trace::span("netscan: symbol table");
        create_netscan_symbol_table(ctx, k)?
    };
    let mut objs = Vec::new();
    let tail = {
        let _t = crate::util::trace::span("netscan: scan");
        scan_each(ctx, k, t, |o| {
            objs.push(o);
            Ok(true)
        })
        .err()
    };
    crate::util::trace::note(|| format!("netscan: {} objects", objs.len()));
    let _t = crate::util::trace::span("netscan: rows");
    emit_rows(&objs, tail, show_corrupt, false, out)
}

impl Plugin for NetScan {
    fn name(&self) -> &'static str {
        "windows.netscan.NetScan"
    }
    fn description(&self) -> &'static str {
        "Scans for network objects present in a particular windows memory image."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::flag("include-corrupt", INCLUDE_CORRUPT_DESC)]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(columns())?;
        rows(ctx, cfg.get_bool("include-corrupt"), &mut |r| out.row(0, r))
    }
    fn timeline(&self, ctx: &Context, _cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        // python's generate_timeline calls _generator() without show_corrupt_results
        let mut ev = Vec::new();
        let r = rows(ctx, false, &mut |r| {
            ev.extend(timeline_event(&r, "N/A"));
            Ok(())
        });
        Some(r.map(|_| ev))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::GlobalOptions;

    /// `RSVOL_BENCH_IMG=... cargo test --profile fast net_timelines -- --ignored --nocapture`:
    /// print netscan's and netstat's timeline events (python `generate_timeline`), to diff
    /// against python's timeliner descriptions.
    #[test]
    #[ignore]
    fn net_timelines() {
        let img = std::env::var("RSVOL_BENCH_IMG").unwrap_or_else(|_| "/home/user/cbc2/task2/memory-dirty.raw".into());
        let ctx = Context::new(GlobalOptions { file: Some(img), output_dir: ".".into(), ..Default::default() }).unwrap();
        let cfg = Config::default();
        for (name, p) in [("NetScan", &NetScan as &dyn Plugin), ("NetStat", &crate::plugins::windows::netstat::NetStat)] {
            for e in p.timeline(&ctx, &cfg).unwrap().unwrap() {
                let t = match e.time {
                    Value::DateTime(d) => crate::util::time::fmt_quick(&d),
                    _ => "?".into(),
                };
                println!("TL\t{name}\t{}\t{t}", e.description);
            }
        }
    }
}
