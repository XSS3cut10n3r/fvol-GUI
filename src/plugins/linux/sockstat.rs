//! linux.sockstat.Sockstat (python `plugins/linux/sockstat.py`) and python's
//! `sockstat.SockHandlers` (per-family socket decoding, reused by `linux.sockscan`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! For plugin porters:
//!   * [`SockHandlers::new`] is python's `SockHandlers(context, vmlinux_name, task)` and
//!     [`SockHandlers::process_sock`] its `process_sock(sock)` -> [`ProcessedSock`] (the
//!     `*_sock` object, the 5 `sock_stat` fields, the `socket_filter` dict).
//!   * [`NetDevMaps`] caches python's per-`SockHandlers` network-device map per network
//!     namespace (python rebuilds it for every socket; the result only depends on the
//!     namespace id, including a failure, so the cache is exact).
//!   * [`list_sockets`] is python's `Sockstat.list_sockets` (parallel per task, python order).

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::util::array_to_string;
use crate::objects::{Module, Obj};
use crate::plugins::linux::pslist::{collect_tasks, pid_filter};
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::module::ModuleExt;
use crate::symbols::linux::utilities::files_descriptors_for_process;
use crate::symbols::linux::{LinuxExt, NetExt, container_of};
use crate::util::FxHashMap;
use std::sync::{Arc, Mutex};

pub struct Sockstat;

/// A copy of an [`Error`] (errors are cached per namespace / task and re-raised for every
/// socket, like python which recomputes them).
pub fn dup_err(e: &Error) -> Error {
    match e {
        Error::InvalidAddress { addr } => Error::InvalidAddress { addr: *addr },
        Error::Swapped { addr } => Error::Swapped { addr: *addr },
        Error::Symbol(s) => Error::Symbol(s.clone()),
        Error::Unsatisfied(s) => Error::Unsatisfied(s.clone()),
        Error::Layer(s) => Error::Layer(s.clone()),
        Error::Io(e) => Error::Msg(e.to_string()),
        Error::Msg(s) => Error::Msg(s.clone()),
    }
}

/// python `exceptions.SymbolError` (an unknown type/symbol), as opposed to an
/// `AttributeError` for a missing member (also reported as `Error::Symbol`).
pub fn is_symbol_error(e: &Error) -> bool {
    matches!(e, Error::Symbol(s) if !s.contains("AttributeError"))
}

/// python `AttributeError` (missing member / explicit raise in an extension method).
fn is_attribute_error(e: &Error) -> bool {
    matches!(e, Error::Symbol(s) | Error::Msg(s) if s.contains("AttributeError"))
}

/// One field of python's `sock_stat` tuple.
#[derive(Clone, Debug, PartialEq)]
pub enum StatVal {
    /// python `None`
    None,
    /// a python `str` / `int` value, already `str()`-formatted
    Str(String),
    /// a `renderers.NotAvailableValue()` instance (netlink port ids on kernels < 3.7.10;
    /// python would render its `str()`, an object repr with a memory address)
    NotAvailable,
}

impl StatVal {
    fn opt(o: Option<String>) -> StatVal {
        o.map_or(StatVal::None, StatVal::Str)
    }
    fn int(v: i128) -> StatVal {
        StatVal::Str(v.to_string())
    }
    fn opt_int(o: Option<i128>) -> StatVal {
        o.map_or(StatVal::None, StatVal::int)
    }
    /// python `renderers.NotAvailableValue() if field is None else str(field)`.
    pub fn to_value(&self) -> Value {
        match self {
            StatVal::Str(s) => Value::Str(s.clone()),
            _ => Value::NotAvailable,
        }
    }
    /// The `str` value (`None` for python `None` / absent values).
    pub fn as_str(&self) -> Option<&str> {
        match self {
            StatVal::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// python's `socket_filter` dict: insertion ordered, overwriting keeps the position.
#[derive(Clone, Debug, Default)]
pub struct SockFilter(pub Vec<(&'static str, String)>);

impl SockFilter {
    fn set(&mut self, k: &'static str, v: impl Into<String>) {
        let v = v.into();
        match self.0.iter_mut().find(|e| e.0 == k) {
            Some(e) => e.1 = v,
            None => self.0.push((k, v)),
        }
    }
    /// python `",".join(f"{k}={v}" for k, v in extended.items()) if extended else
    /// renderers.NotAvailableValue()`.
    pub fn to_value(&self) -> Value {
        if self.0.is_empty() {
            return Value::NotAvailable;
        }
        Value::Str(self.0.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(","))
    }
}

/// python `process_sock()` result: `(sock, sock_stat, socket_filter)`.
#[derive(Clone, Debug)]
pub struct ProcessedSock {
    /// the family's `*_sock` object (or the generic `sock`), same offset as the input
    pub sock: Obj,
    /// `(src_addr, src_port, dst_addr, dst_port, state)`
    pub stat: [StatVal; 5],
    pub filter: SockFilter,
}

/// A network namespace's `ifindex -> device name` map.
pub type NetDevMap = FxHashMap<i128, String>;

/// python `SockHandlers._build_network_devices_map(netns_id)` (`None` = python's
/// `NotAvailableValue` namespace id: every device is skipped).
pub fn build_network_devices_map(vm: &Module, netns_id: Option<i128>) -> Result<NetDevMap> {
    let mut map = NetDevMap::default();
    let t = vm.symbol_table_name();
    let (net_ty, dev_ty) = (format!("{t}!net"), format!("{t}!net_device"));
    let head = vm.object_from_symbol("net_namespace_list")?;
    for net in head.list_of(&net_ty, "list") {
        let net = net?;
        // python reads `net.get_inode()` for every device; the value is the same each time
        let mut inode: Option<i128> = None;
        for dev in net.m("dev_base_head")?.list_of(&dev_ty, "dev_list") {
            let dev = dev?;
            let Some(id) = netns_id else { continue };
            let ino = match inode {
                Some(v) => v,
                None => *inode.insert(net.net_get_inode()?),
            };
            if ino != id {
                continue;
            }
            let name = array_to_string(&dev.m("name")?, None)?;
            map.insert(dev.m("ifindex")?.int()?, name);
        }
    }
    Ok(map)
}

/// python `task.nsproxy.net_ns.get_inode()` with `AttributeError` -> `None` (python's
/// `NotAvailableValue`).
pub fn task_netns_id(task: &Obj) -> Result<Option<i128>> {
    match task.m("nsproxy")?.m("net_ns")?.net_get_inode() {
        Ok(v) => Ok(Some(v)),
        Err(e) if is_attribute_error(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Per-namespace cache of [`build_network_devices_map`] results (thread-safe).
pub struct NetDevMaps {
    vm: Module,
    cache: Mutex<FxHashMap<Option<i128>, std::result::Result<Arc<NetDevMap>, Error>>>,
}

impl NetDevMaps {
    pub fn new(vm: Module) -> NetDevMaps {
        NetDevMaps { vm, cache: Mutex::new(FxHashMap::default()) }
    }
    /// The (possibly failed) map of `netns_id`.
    pub fn get(&self, netns_id: Option<i128>) -> Result<Arc<NetDevMap>> {
        let mut g = self.cache.lock().unwrap();
        let r = g.entry(netns_id).or_insert_with(|| build_network_devices_map(&self.vm, netns_id).map(Arc::new));
        match r {
            Ok(m) => Ok(m.clone()),
            Err(e) => Err(dup_err(e)),
        }
    }
}

/// python `sockstat.SockHandlers`.
pub struct SockHandlers {
    vm: Module,
    netdevices: Arc<NetDevMap>,
}

/// python `f"{x:08x}"` of a (non-negative) int.
fn hex08(v: i128) -> String {
    if v < 0 { format!("-{:08x}", -v) } else { format!("{v:08x}") }
}

impl SockHandlers {
    /// python `SockHandlers(context, vmlinux_name, task)`: the task's network namespace id
    /// and that namespace's device map. `Err` where python's constructor raises.
    pub fn new(vm: &Module, task: &Obj) -> Result<SockHandlers> {
        let netns = task_netns_id(task)?;
        Ok(SockHandlers { vm: *vm, netdevices: Arc::new(build_network_devices_map(vm, netns)?) })
    }

    /// [`SockHandlers::new`] with the namespace map taken from `maps`.
    pub fn new_cached(maps: &NetDevMaps, task: &Obj) -> Result<SockHandlers> {
        let netns = task_netns_id(task)?;
        Ok(SockHandlers { vm: maps.vm, netdevices: maps.get(netns)? })
    }

    /// A handler with an explicit device map.
    pub fn with_netdevices(vm: &Module, netdevices: Arc<NetDevMap>) -> SockHandlers {
        SockHandlers { vm: *vm, netdevices }
    }

    /// python `process_sock(sock)`: decode a generic `sock` object with its family handler
    /// (falling back to the generic state for unsupported families or a `SymbolError`).
    /// `Err` where python raises (e.g. `InvalidAddressException`).
    pub fn process_sock(&self, sock: &Obj) -> Result<ProcessedSock> {
        let family = sock.get_family()?;
        let mut filter = SockFilter::default();
        let handled = match family.as_str() {
            "AF_UNIX" => Some(self.unix_sock(sock).map(Some)),
            "AF_INET" | "AF_INET6" => Some(self.inet_sock(sock).map(Some)),
            "AF_NETLINK" => Some(self.netlink_sock(sock).map(Some)),
            "AF_VSOCK" => Some(self.vsock_sock(sock).map(Some)),
            "AF_PACKET" => Some(self.packet_sock(sock).map(Some)),
            "AF_XDP" => Some(self.xdp_sock(sock)),
            "AF_BLUETOOTH" => Some(self.bluetooth_sock(sock).map(Some)),
            _ => None,
        };
        if let Some(r) = handled {
            let r = r.and_then(|x| match x {
                // `unix_sock, sock_stat = sock_handler(sock)` on a None result
                None => Err(Error::msg("TypeError: cannot unpack non-iterable NoneType object")),
                Some((child, stat)) => {
                    self.update_socket_filters_info(sock, &mut filter)?;
                    Ok((child, stat))
                }
            });
            match r {
                Ok((child, stat)) => return Ok(ProcessedSock { sock: child, stat, filter }),
                Err(e) if is_symbol_error(&e) => {}
                Err(e) => return Err(e),
            }
        }
        let state = sock.sock_get_state()?;
        Ok(ProcessedSock { sock: *sock, stat: [StatVal::None, StatVal::None, StatVal::None, StatVal::None, StatVal::opt(state)], filter })
    }

    /// python `_update_socket_filters_info(sock, socket_filter)`.
    fn update_socket_filters_info(&self, sock: &Obj, filter: &mut SockFilter) -> Result<()> {
        if sock.has_member("sk_filter") {
            let f = sock.m("sk_filter")?;
            if f.u64()? != 0 {
                filter.set("filter_type", "socket_filter");
                extract_socket_filter_info(&f, filter)?;
            }
        }
        if sock.has_member("sk_reuseport_cb") {
            let f = sock.m("sk_reuseport_cb")?;
            if f.u64()? != 0 {
                filter.set("filter_type", "reuseport_filter");
                extract_socket_filter_info(&f, filter)?;
            }
        }
        Ok(())
    }

    /// python `_unix_sock(sock)`.
    fn unix_sock(&self, sock: &Obj) -> Result<(Obj, [StatVal; 5])> {
        let u = sock.cast("unix_sock")?;
        let state = u.sock_get_state()?;
        let src_addr = u.unix_get_name()?;
        let src_port = u.net_get_inode()?;
        let peer = u.m("peer")?;
        let (dst_addr, dst_port) = if peer.u64()? != 0 {
            let p = peer.deref()?.cast("unix_sock")?;
            (p.unix_get_name()?, Some(p.net_get_inode()?))
        } else {
            (None, None)
        };
        Ok((u, [StatVal::opt(src_addr), StatVal::int(src_port), StatVal::opt(dst_addr), StatVal::opt_int(dst_port), StatVal::opt(state)]))
    }

    /// python `_inet_sock(sock)` (AF_INET / AF_INET6).
    fn inet_sock(&self, sock: &Obj) -> Result<(Obj, [StatVal; 5])> {
        let i = sock.cast("inet_sock")?;
        let src_addr = i.get_src_addr()?;
        let src_port = i.get_src_port()?;
        let dst_addr = i.get_dst_addr()?;
        let dst_port = i.get_dst_port()?;
        let state = i.sock_get_state()?;
        Ok((i, [StatVal::opt(src_addr), StatVal::opt_int(src_port), StatVal::opt(dst_addr), StatVal::opt_int(dst_port), StatVal::opt(state)]))
    }

    /// python `_netlink_sock(sock)`.
    fn netlink_sock(&self, sock: &Obj) -> Result<(Obj, [StatVal; 5])> {
        let n = sock.cast("netlink_sock")?;
        let groups = n.m("groups")?;
        let src_addr = if groups.u64()? != 0 { StatVal::Str(format!("groups:0x{}", hex08(groups.deref()?.int()?))) } else { StatVal::None };
        let src_port = match n.get_portid() {
            Ok(v) => StatVal::int(v),
            Err(e) if is_attribute_error(&e) => StatVal::NotAvailable,
            Err(e) => return Err(e),
        };
        let mut dst_addr = format!("group:0x{}", hex08(n.m("dst_group")?.int()?));
        let module = n.m("module")?;
        // `module and module.name`: an Array member is always truthy (non-zero count)
        if module.u64()? != 0 {
            let name = module.m("name")?;
            if !name.is_array() || name.count() > 0 {
                dst_addr = format!("{dst_addr},lkm:{}", array_to_string(&name, None)?);
            }
        }
        let dst_port = match n.get_dst_portid() {
            Ok(v) => StatVal::int(v),
            Err(e) if is_attribute_error(&e) => StatVal::NotAvailable,
            Err(e) => return Err(e),
        };
        let state = n.sock_get_state()?;
        Ok((n, [src_addr, src_port, StatVal::Str(dst_addr), dst_port, StatVal::opt(state)]))
    }

    /// python `_vsock_sock(sock)`.
    fn vsock_sock(&self, sock: &Obj) -> Result<(Obj, [StatVal; 5])> {
        let v = sock.cast("vsock_sock")?;
        let src_addr = v.m("local_addr")?.m("svm_cid")?.int()?;
        let src_port = v.m("local_addr")?.m("svm_port")?.int()?;
        let dst_addr = v.m("remote_addr")?.m("svm_cid")?.int()?;
        let dst_port = v.m("remote_addr")?.m("svm_port")?.int()?;
        let state = v.sock_get_state()?;
        Ok((v, [StatVal::int(src_addr), StatVal::int(src_port), StatVal::int(dst_addr), StatVal::int(dst_port), StatVal::opt(state)]))
    }

    /// python `_packet_sock(sock)`.
    fn packet_sock(&self, sock: &Obj) -> Result<(Obj, [StatVal; 5])> {
        let p = sock.cast("packet_sock")?;
        let ifindex = p.m("ifindex")?.int()?;
        let dev_name = if ifindex > 0 { StatVal::opt(self.netdevices.get(&ifindex).cloned()) } else { StatVal::Str("ANY".into()) };
        let state = p.sock_get_state()?;
        Ok((p, [dev_name, StatVal::None, StatVal::None, StatVal::None, StatVal::opt(state)]))
    }

    /// python `_xdp_sock(sock)` (`Ok(None)` where python returns None).
    fn xdp_sock(&self, sock: &Obj) -> Result<Option<(Obj, [StatVal; 5])>> {
        let x = sock.cast("xdp_sock")?;
        let device = x.m("dev")?;
        if device.u64()? == 0 {
            return Ok(None);
        }
        let src_addr = array_to_string(&device.m("name")?, None)?;
        let prog = device.m("xdp_prog")?;
        if prog.u64()? == 0 {
            return Ok(None);
        }
        if !prog.has_member("aux") || prog.m("aux")?.u64()? == 0 {
            return Ok(None);
        }
        let aux = prog.m("aux")?;
        let (mut dst_addr, mut dst_port) = (StatVal::None, StatVal::None);
        if aux.has_member("id") {
            dst_port = StatVal::Str(format!("ebpf_prog_id:{}", aux.m("id")?.int()?));
        }
        if aux.has_member("name") {
            let name = array_to_string(&aux.m("name")?, None)?;
            if !name.is_empty() {
                dst_addr = StatVal::Str(format!("ebpf_prog_name:{name}"));
            }
        }
        let state = x.sock_get_state()?.unwrap_or_default().replace("XSK_", "");
        Ok(Some((x, [StatVal::Str(src_addr), StatVal::None, dst_addr, dst_port, StatVal::Str(state)])))
    }

    /// python `_bluetooth_sock(sock)`.
    fn bluetooth_sock(&self, sock: &Obj) -> Result<(Obj, [StatVal; 5])> {
        let bt = sock.cast("bt_sock")?;
        // python `":".join(reversed([f"{x:02x}" for x in addr.b]))`
        let bt_addr = |addr: Obj| -> Result<String> {
            let b = addr.m("b")?.ints()?;
            Ok(b.iter().rev().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":"))
        };
        let (mut src_addr, mut src_port, mut dst_addr, mut dst_port) = (StatVal::None, StatVal::None, StatVal::None, StatVal::None);
        match bt.get_protocol()?.as_deref() {
            Some("HCI") => {
                if self.vm.has_type("hci_pinfo") {
                    let pinfo = bt.cast("hci_pinfo")?;
                    if pinfo.has_member("hdev") && self.vm.has_type("hci_dev") && pinfo.m("hdev")?.has_member("dev_name") {
                        src_addr = StatVal::Str(array_to_string(&pinfo.m("hdev")?.m("dev_name")?, None)?);
                    }
                }
            }
            Some("L2CAP") => {
                if self.vm.has_type("l2cap_pinfo") {
                    let pinfo = bt.cast("l2cap_pinfo")?;
                    let chan = pinfo.m("chan")?;
                    src_addr = StatVal::Str(bt_addr(chan.m("src")?)?);
                    dst_addr = StatVal::Str(bt_addr(chan.m("dst")?)?);
                    src_port = StatVal::int(chan.m("sport")?.int()?);
                    dst_port = StatVal::int(chan.m("psm")?.int()?);
                }
            }
            Some("RFCOMM") => {
                if self.vm.has_type("rfcomm_pinfo") {
                    let pinfo = bt.cast("rfcomm_pinfo")?;
                    src_addr = StatVal::Str(bt_addr(pinfo.m("src")?)?);
                    dst_addr = StatVal::Str(bt_addr(pinfo.m("dst")?)?);
                    src_port = StatVal::int(pinfo.m("channel")?.int()?);
                }
            }
            Some("SCO") => {
                if self.vm.has_type("sco_pinfo") {
                    let pinfo = bt.cast("sco_pinfo")?;
                    src_addr = StatVal::Str(bt_addr(pinfo.m("src")?)?);
                    dst_addr = StatVal::Str(bt_addr(pinfo.m("dst")?)?);
                }
            }
            _ => {}
        }
        let state = bt.sock_get_state()?;
        Ok((bt, [src_addr, src_port, dst_addr, dst_port, StatVal::opt(state)]))
    }
}

/// python `SockHandlers._extract_socket_filter_info(sock_filter, socket_filter)` (`sf` is the
/// `sk_filter *` / `sock_reuseport *` pointer).
fn extract_socket_filter_info(sf: &Obj, filter: &mut SockFilter) -> Result<()> {
    filter.set("bpf_filter_type", "cBPF");
    if !sf.has_member("prog") {
        return Ok(());
    }
    let prog = sf.m("prog")?;
    if prog.u64()? == 0 {
        return Ok(());
    }
    let Some(ty) = ModuleExt::get_type(&prog)? else { return Ok(()) };
    if ty.is_empty() || ty == "BPF_PROG_TYPE_UNSPEC" {
        return Ok(());
    }
    if ty != "BPF_PROG_TYPE_SOCKET_FILTER" {
        filter.set("bpf_filter_type", format!("UNK({ty})"));
        return Ok(());
    }
    filter.set("bpf_filter_type", "eBPF");
    if !prog.has_member("aux") {
        return Ok(());
    }
    let aux = prog.m("aux")?;
    if aux.u64()? == 0 {
        return Ok(());
    }
    if aux.has_member("id") {
        filter.set("bpf_filter_id", aux.m("id")?.int()?.to_string());
    }
    if aux.has_member("name") {
        let name = array_to_string(&aux.m("name")?, None)?;
        if !name.is_empty() {
            filter.set("bpf_filter_name", name);
        }
    }
    Ok(())
}

/// One socket of python `Sockstat.list_sockets`.
pub struct SocketEntry {
    pub task: Obj,
    /// `None` = python's `NotAvailableValue` namespace id
    pub netns_id: Option<i128>,
    pub fd_num: u64,
    pub family: String,
    pub sock_type: &'static str,
    pub protocol: Option<String>,
    pub fields: ProcessedSock,
}

/// Per-task state of python's per-socket `SockHandlers(...)` construction (cached: it only
/// depends on the task's namespace).
struct TaskHandlers<'a> {
    maps: &'a NetDevMaps,
    handlers: Option<std::result::Result<SockHandlers, Error>>,
}

impl TaskHandlers<'_> {
    fn get(&mut self, task: &Obj) -> Result<&SockHandlers> {
        let maps = self.maps;
        match self.handlers.get_or_insert_with(|| SockHandlers::new_cached(maps, task)) {
            Ok(h) => Ok(h),
            Err(e) => Err(dup_err(e)),
        }
    }
}

/// The socket behind one open file of `task` (python `list_sockets` loop body). `Ok(None)` =
/// skipped (`continue`), `Err` = python raised.
fn socket_of_fd(k: &LinuxKernel, fops: (u64, u64), th: &mut TaskHandlers, task: &Obj, fd_num: u64, filp: &Obj) -> Result<Option<SocketEntry>> {
    let f_op = filp.m("f_op")?;
    let f_op_v = f_op.u64()?;
    if !(f_op_v != 0 && f_op.is_readable()) {
        return Ok(None);
    }
    if f_op_v != fops.0 && f_op_v != fops.1 {
        return Ok(None);
    }
    let dentry = filp.get_dentry()?;
    if !(dentry.u64()? != 0 && dentry.is_readable()) {
        return Ok(None);
    }
    let d_inode = dentry.m("d_inode")?;
    let d_inode_v = d_inode.u64()?;
    if !(d_inode_v != 0 && d_inode.is_readable()) {
        return Ok(None);
    }
    let Some(socket_alloc) = container_of(d_inode_v, "socket_alloc", "vfs_inode", k)? else { return Ok(None) };
    let sk = socket_alloc.m("socket")?.m("sk")?;
    if !(sk.u64()? != 0 && sk.is_readable()) {
        return Ok(None);
    }
    let sock = sk.deref()?;
    let r = (|| -> Result<(&'static str, String, ProcessedSock)> {
        let sock_type = sock.sock_get_type()?;
        let family = sock.get_family()?;
        let fields = th.get(task)?.process_sock(&sock)?;
        Ok((sock_type, family, fields))
    })();
    let (sock_type, family, fields) = match r {
        Ok(x) => x,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    let protocol = fields.sock.get_protocol()?;
    let netns_id = task_netns_id(task)?;
    Ok(Some(SocketEntry { task: *task, netns_id, fd_num, family, sock_type, protocol, fields }))
}

/// python `Sockstat.list_sockets(context, kernel, filter_func)`: every socket file
/// descriptor of every task (threads included), computed per task in parallel, returned in
/// python's order. A trailing `Err` is where python's generator raised.
pub fn list_sockets(k: &LinuxKernel, filter: &dyn Fn(&Obj) -> Result<bool>) -> Vec<Result<SocketEntry>> {
    let fops = match (k.object_from_symbol("socket_file_ops"), k.object_from_symbol("sockfs_dentry_operations")) {
        (Ok(a), Ok(b)) => (a.addr, b.addr),
        (Err(e), _) | (_, Err(e)) => return vec![Err(e)],
    };
    let maps = NetDevMaps::new(k.module);
    let (tasks, tail) = collect_tasks(k, filter, true);
    let per_task = crate::util::par::par_map(tasks.len(), |i| {
        let task = &tasks[i];
        let mut th = TaskHandlers { maps: &maps, handlers: None };
        let mut out = Vec::new();
        for fd in files_descriptors_for_process(task, false) {
            let r = fd.and_then(|(fd_num, filp, _path)| socket_of_fd(k, fops, &mut th, task, fd_num, &filp));
            match r {
                Ok(Some(s)) => out.push(Ok(s)),
                Ok(None) => {}
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            }
        }
        out
    });
    let mut out = Vec::new();
    for v in per_task {
        for r in v {
            let stop = r.is_err();
            out.push(r);
            if stop {
                return out;
            }
        }
    }
    if let Some(e) = tail {
        out.push(Err(e));
    }
    out
}

impl Plugin for Sockstat {
    fn name(&self) -> &'static str {
        "linux.sockstat.Sockstat"
    }
    fn description(&self) -> &'static str {
        "Lists all network connections for all processes."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pids", "Filter results by process IDs. It takes the root PID namespace identifiers.", ReqKind::ListInt).optional(),
            Requirement::new("netns", "Filter results by network namespace. Otherwise, all of them are shown.", ReqKind::Int).optional(),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("NetNS", ColType::Int),
            Column::new("Process Name", ColType::Str),
            Column::new("PID", ColType::Int),
            Column::new("TID", ColType::Int),
            Column::new("FD", ColType::Int),
            Column::new("Sock Offset", ColType::Hex),
            Column::new("Family", ColType::Str),
            Column::new("Type", ColType::Str),
            Column::new("Proto", ColType::Str),
            Column::new("Source Addr", ColType::Str),
            Column::new("Source Port", ColType::Str),
            Column::new("Destination Addr", ColType::Str),
            Column::new("Destination Port", ColType::Str),
            Column::new("State", ColType::Str),
            Column::new("Filter", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        let pids = cfg.get_ints("pids");
        let netns_arg = cfg.get_int("netns");
        let filter = pid_filter(&pids);
        for s in list_sockets(k, &filter) {
            let s = s?;
            // python `if netns_id_arg and netns_id_arg != netns_id: continue`
            if let Some(arg) = netns_arg
                && arg != 0
                && Some(arg) != s.netns_id
            {
                continue;
            }
            let st = &s.fields.stat;
            out.row(
                0,
                vec![
                    s.netns_id.map_or(Value::NotAvailable, Value::Int),
                    Value::Str(array_to_string(&s.task.m("comm")?, None)?),
                    Value::Int(s.task.m("tgid")?.int()?),
                    Value::Int(s.task.m("pid")?.int()?),
                    Value::Int(s.fd_num as i128),
                    Value::Int(s.fields.sock.addr as i128),
                    Value::Str(s.family),
                    Value::SStr(s.sock_type),
                    s.protocol.map_or(Value::NotAvailable, Value::Str),
                    st[0].to_value(),
                    st[1].to_value(),
                    st[2].to_value(),
                    st[3].to_value(),
                    st[4].to_value(),
                    s.fields.filter.to_value(),
                ],
            )?;
        }
        Ok(())
    }
}
