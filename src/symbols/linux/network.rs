//! python `symbols/linux/extensions/network.py` (network class extensions: `net`,
//! `net_device`, `in_device`, `inet6_dev`, `in_ifaddr`, `inet6_ifaddr`, `socket`, `sock`,
//! `unix_sock`, `inet_sock`, `netlink_sock`, `vsock_sock`, `packet_sock`, `bt_sock`,
//! `xdp_sock`) as the [`NetExt`] trait on [`Obj`], plus the network constants of
//! `constants/linux` and python's address formatting (`socket.inet_ntop`,
//! `conversion.convert_ipv4/6`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Methods accept the struct or a pointer to it. Names shared by several python classes
//! dispatch on the struct name (`sock_get_state`, `get_protocol`, `get_family`,
//! `get_addresses`, ...); names that other Linux traits already use carry a prefix
//! (`net_get_inode`, `sock_get_type`, `unix_get_name`).

use super::fs::{ptr_ok, tgt};
use super::{ListIter, LinuxExt, container_of, vmlinux_of};
use crate::error::{Error, Result};
use crate::layers::{Layer, LayerExt};
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::renderers::Value;
use crate::util::FxHashSet;

/// python `IP_PROTOCOLS`.
pub fn ip_protocol(n: i128) -> Option<&'static str> {
    Some(match n {
        0 => "IP",
        1 => "ICMP",
        2 => "IGMP",
        4 => "IPIP",
        6 => "TCP",
        8 => "EGP",
        12 => "PUP",
        17 => "UDP",
        22 => "IDP",
        29 => "TP",
        33 => "DCCP",
        41 => "IPV6",
        46 => "RSVP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        92 => "MTP",
        94 => "BEETPH",
        98 => "ENCAP",
        103 => "PIM",
        108 => "COMP",
        132 => "SCTP",
        136 => "UDPLITE",
        137 => "MPLS",
        143 => "ETHERNET",
        255 => "RAW",
        262 => "MPTCP",
        _ => return None,
    })
}

/// python `IPV6_PROTOCOLS`.
pub fn ipv6_protocol(n: i128) -> Option<&'static str> {
    Some(match n {
        0 => "HOPBYHOP_OPTS",
        43 => "ROUTING",
        44 => "FRAGMENT",
        58 => "ICMPv6",
        59 => "NO_NEXT",
        60 => "DESTINATION_OPTS",
        135 => "MOBILITY",
        _ => return None,
    })
}

/// python `TCP_STATES`.
pub const TCP_STATES: [&str; 13] =
    ["", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING", "TCP_NEW_SYN_RECV"];

/// python `SOCK_TYPES`.
pub fn sock_type_name(n: i128) -> &'static str {
    match n {
        1 => "STREAM",
        2 => "DGRAM",
        3 => "RAW",
        4 => "RDM",
        5 => "SEQPACKET",
        6 => "DCCP",
        10 => "PACKET",
        _ => "",
    }
}

/// python `SOCK_FAMILY`.
pub const SOCK_FAMILY: [&str; 45] = [
    "AF_UNSPEC",
    "AF_UNIX",
    "AF_INET",
    "AF_AX25",
    "AF_IPX",
    "AF_APPLETALK",
    "AF_NETROM",
    "AF_BRIDGE",
    "AF_ATMPVC",
    "AF_X25",
    "AF_INET6",
    "AF_ROSE",
    "AF_DECnet",
    "AF_NETBEUI",
    "AF_SECURITY",
    "AF_KEY",
    "AF_NETLINK",
    "AF_PACKET",
    "AF_ASH",
    "AF_ECONET",
    "AF_ATMSVC",
    "AF_RDS",
    "AF_SNA",
    "AF_IRDA",
    "AF_PPPOX",
    "AF_WANPIPE",
    "AF_LLC",
    "AF_IB",
    "AF_MPLS",
    "AF_CAN",
    "AF_TIPC",
    "AF_BLUETOOTH",
    "AF_IUCV",
    "AF_RXRPC",
    "AF_ISDN",
    "AF_PHONET",
    "AF_IEEE802154",
    "AF_CAIF",
    "AF_ALG",
    "AF_NFC",
    "AF_VSOCK",
    "AF_KCM",
    "AF_QIPCRTR",
    "AF_SMC",
    "AF_XDP",
];

/// python `SOCKET_STATES`.
pub const SOCKET_STATES: [&str; 5] = ["FREE", "UNCONNECTED", "CONNECTING", "CONNECTED", "DISCONNECTING"];

/// python `NETLINK_PROTOCOLS`.
pub const NETLINK_PROTOCOLS: [&str; 23] = [
    "NETLINK_ROUTE",
    "NETLINK_UNUSED",
    "NETLINK_USERSOCK",
    "NETLINK_FIREWALL",
    "NETLINK_SOCK_DIAG",
    "NETLINK_NFLOG",
    "NETLINK_XFRM",
    "NETLINK_SELINUX",
    "NETLINK_ISCSI",
    "NETLINK_AUDIT",
    "NETLINK_FIB_LOOKUP",
    "NETLINK_CONNECTOR",
    "NETLINK_NETFILTER",
    "NETLINK_IP6_FW",
    "NETLINK_DNRTMSG",
    "NETLINK_KOBJECT_UEVENT",
    "NETLINK_GENERIC",
    "NETLINK_DM",
    "NETLINK_SCSITRANSPORT",
    "NETLINK_ECRYPTFS",
    "NETLINK_RDMA",
    "NETLINK_CRYPTO",
    "NETLINK_SMC",
];

/// python `ETH_PROTOCOLS`.
pub fn eth_protocol(n: i128) -> Option<&'static str> {
    Some(match n {
        0x0001 => "ETH_P_802_3",
        0x0002 => "ETH_P_AX25",
        0x0003 => "ETH_P_ALL",
        0x0004 => "ETH_P_802_2",
        0x0005 => "ETH_P_SNAP",
        0x0006 => "ETH_P_DDCMP",
        0x0007 => "ETH_P_WAN_PPP",
        0x0008 => "ETH_P_PPP_MP",
        0x0009 => "ETH_P_LOCALTALK",
        0x000C => "ETH_P_CAN",
        0x000F => "ETH_P_CANFD",
        0x0010 => "ETH_P_PPPTALK",
        0x0011 => "ETH_P_TR_802_2",
        0x0016 => "ETH_P_CONTROL",
        0x0017 => "ETH_P_IRDA",
        0x0018 => "ETH_P_ECONET",
        0x0019 => "ETH_P_HDLC",
        0x001A => "ETH_P_ARCNET",
        0x001B => "ETH_P_DSA",
        0x001C => "ETH_P_TRAILER",
        0x0060 => "ETH_P_LOOP",
        0x00F6 => "ETH_P_IEEE802154",
        0x00F7 => "ETH_P_CAIF",
        0x00F8 => "ETH_P_XDSA",
        0x00F9 => "ETH_P_MAP",
        0x0800 => "ETH_P_IP",
        0x0805 => "ETH_P_X25",
        0x0806 => "ETH_P_ARP",
        0x8035 => "ETH_P_RARP",
        0x809B => "ETH_P_ATALK",
        0x80F3 => "ETH_P_AARP",
        0x8100 => "ETH_P_8021Q",
        _ => return None,
    })
}

/// python `BLUETOOTH_STATES`.
pub const BLUETOOTH_STATES: [&str; 10] = ["", "CONNECTED", "OPEN", "BOUND", "LISTEN", "CONNECT", "CONNECT2", "CONFIG", "DISCONN", "CLOSED"];
/// python `BLUETOOTH_PROTOCOLS`.
pub const BLUETOOTH_PROTOCOLS: [&str; 8] = ["L2CAP", "HCI", "SCO", "RFCOMM", "BNEP", "CMTP", "HIDP", "AVDTP"];

/// python `NET_DEVICE_FLAGS` (kernels < 3.15), in python's dict order.
pub const NET_DEVICE_FLAGS: [(&str, i128); 19] = [
    ("IFF_UP", 0x1),
    ("IFF_BROADCAST", 0x2),
    ("IFF_DEBUG", 0x4),
    ("IFF_LOOPBACK", 0x8),
    ("IFF_POINTOPOINT", 0x10),
    ("IFF_NOTRAILERS", 0x20),
    ("IFF_RUNNING", 0x40),
    ("IFF_NOARP", 0x80),
    ("IFF_PROMISC", 0x100),
    ("IFF_ALLMULTI", 0x200),
    ("IFF_MASTER", 0x400),
    ("IFF_SLAVE", 0x800),
    ("IFF_MULTICAST", 0x1000),
    ("IFF_PORTSEL", 0x2000),
    ("IFF_AUTOMEDIA", 0x4000),
    ("IFF_DYNAMIC", 0x8000),
    ("IFF_LOWER_UP", 0x10000),
    ("IFF_DORMANT", 0x20000),
    ("IFF_ECHO", 0x40000),
];

/// python `IF_OPER_STATES(v).name` (RFC 2863).
pub fn if_oper_state(v: i128) -> Option<&'static str> {
    ["UNKNOWN", "NOTPRESENT", "DOWN", "LOWERLAYERDOWN", "TESTING", "DORMANT", "UP"].get(usize::try_from(v).ok()?).copied()
}

/// python `IFA_HOST` / `IFA_LINK` / `IFA_SITE`.
pub const IFA_HOST: i128 = 0x0010;
pub const IFA_LINK: i128 = 0x0020;
pub const IFA_SITE: i128 = 0x0040;

/// `socket.AF_INET` / `socket.AF_INET6` (Linux).
pub const AF_INET: i128 = 2;
pub const AF_INET6: i128 = 10;

/// python `socket.htons(x)` on a little-endian host (`OverflowError` outside 0..=65535).
pub fn htons(x: i128) -> Result<i128> {
    if !(0..=0xFFFF).contains(&x) {
        return Err(Error::msg("OverflowError: htons: Python int too large to convert to C 16-bit unsigned integer"));
    }
    Ok(((x & 0xFF) << 8) | (x >> 8))
}

/// python `socket.inet_ntop(AF_INET, 4 bytes)`.
pub fn inet_ntop4(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// python `socket.inet_ntop(AF_INET6, 16 bytes)` (glibc `inet_ntop6`: longest run of >= 2
/// zero words compressed, embedded IPv4 for `::a.b.c.d` and `::ffff:a.b.c.d`).
pub fn inet_ntop6(b: &[u8]) -> String {
    let w: Vec<u32> = (0..8).map(|i| ((b[2 * i] as u32) << 8) | b[2 * i + 1] as u32).collect();
    let (mut best_base, mut best_len) = (-1i32, 0i32);
    let (mut cur_base, mut cur_len) = (-1i32, 0i32);
    for (i, &x) in w.iter().enumerate() {
        if x == 0 {
            if cur_base == -1 {
                cur_base = i as i32;
                cur_len = 1;
            } else {
                cur_len += 1;
            }
        } else if cur_base != -1 {
            if best_base == -1 || cur_len > best_len {
                best_base = cur_base;
                best_len = cur_len;
            }
            cur_base = -1;
        }
    }
    if cur_base != -1 && (best_base == -1 || cur_len > best_len) {
        best_base = cur_base;
        best_len = cur_len;
    }
    if best_base != -1 && best_len < 2 {
        best_base = -1;
    }
    let mut s = String::new();
    for (i, &x) in w.iter().enumerate() {
        let i = i as i32;
        if best_base != -1 && i >= best_base && i < best_base + best_len {
            if i == best_base {
                s.push(':');
            }
            continue;
        }
        if i != 0 {
            s.push(':');
        }
        if i == 6 && best_base == 0 && (best_len == 6 || (best_len == 5 && w[5] == 0xffff)) {
            s.push_str(&inet_ntop4(&b[12..16]));
            return s;
        }
        s.push_str(&format!("{x:x}"));
    }
    if best_base != -1 && best_base + best_len == 8 {
        s.push(':');
    }
    s
}

/// python `conversion.convert_ipv4(int)` (`IPv4Address(struct.pack("<I", ip))`).
pub fn convert_ipv4(ip: u32) -> String {
    inet_ntop4(&ip.to_le_bytes())
}

/// python `ipaddress._BaseV6._string_from_ip_int` (compressed hextets).
fn v6_hextets(hextets: &[u32]) -> String {
    let (mut best_start, mut best_len) = (-1i32, 0i32);
    let (mut start, mut len) = (-1i32, 0i32);
    for (i, &h) in hextets.iter().enumerate() {
        if h == 0 {
            len += 1;
            if start == -1 {
                start = i as i32;
            }
            if len > best_len {
                best_len = len;
                best_start = start;
            }
        } else {
            len = 0;
            start = -1;
        }
    }
    let mut parts: Vec<String> = hextets.iter().map(|h| format!("{h:x}")).collect();
    if best_len > 1 {
        let end = (best_start + best_len) as usize;
        if end == parts.len() {
            parts.push(String::new());
        }
        parts.splice(best_start as usize..end, [String::new()]);
        if best_start == 0 {
            parts.insert(0, String::new());
        }
    }
    parts.join(":")
}

/// python `conversion.convert_ipv6([u32; 4])` (`str(IPv6Address(struct.pack("<IIII", ...)))`,
/// python 3.14 formatting incl. `::ffff:a.b.c.d` for IPv4-mapped addresses).
pub fn convert_ipv6(words: &[u32; 4]) -> String {
    let mut b = [0u8; 16];
    for (i, w) in words.iter().enumerate() {
        b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    let ip = u128::from_be_bytes(b);
    if ip >> 32 == 0xFFFF {
        return format!("{}:{}", v6_hextets(&[0, 0, 0, 0, 0, 0, 0, 0xffff]), inet_ntop4(&b[12..16]));
    }
    let h: Vec<u32> = (0..8).map(|i| ((ip >> (112 - 16 * i)) & 0xFFFF) as u32).collect();
    v6_hextets(&h)
}

/// Network class extensions on [`Obj`].
pub trait NetExt {
    // ---- net / socket / sock / unix_sock
    /// python `get_inode()` of `net` (namespace inode), `socket`, `sock`, `unix_sock` (socket
    /// inode number; 0 where python returns 0).
    fn net_get_inode(&self) -> Result<i128>;

    // ---- net_device
    /// python `net_device.get_device_name()`.
    fn get_device_name(&self) -> Result<String>;
    /// python `net_device.get_mac_address()`.
    fn get_mac_address(&self) -> Result<Option<String>>;
    /// python `net_device.get_flag_names()` (sorted `IFF_*` names).
    fn get_flag_names(&self) -> Result<Vec<String>>;
    /// python `net_device.promisc`.
    fn promisc(&self) -> Result<bool>;
    /// python `net_device.is_running()` / `is_carrier_ok()` / `is_dormant()` / `is_operational()`.
    fn is_running(&self) -> Result<bool>;
    fn is_carrier_ok(&self) -> Result<bool>;
    fn is_dormant(&self) -> Result<bool>;
    fn is_operational(&self) -> Result<bool>;
    /// python `net_device.get_net_namespace_id()` (None on InvalidAddressException).
    fn get_net_namespace_id(&self) -> Result<Option<i128>>;
    /// python `net_device.get_operational_state()` (`Value::Str` or `Value::Unparsable`).
    fn get_operational_state(&self) -> Result<Value>;
    /// python `net_device.get_qdisc_name()`.
    fn get_qdisc_name(&self) -> Result<Option<String>>;
    /// python `net_device.get_queue_length()`.
    fn get_queue_length(&self) -> Result<i128>;

    // ---- in_device / inet6_dev
    /// python `in_device.get_addresses()` (`in_ifaddr *` pointer objects) and
    /// `inet6_dev.get_addresses()` (`inet6_ifaddr` objects). A trailing `Err` = raised.
    fn get_addresses(&self) -> Vec<Result<Obj>>;

    // ---- in_ifaddr / inet6_ifaddr
    /// python `get_scope_type()`.
    fn get_scope_type(&self) -> Result<String>;
    /// python `get_address()`.
    fn get_address(&self) -> Result<String>;
    /// python `get_prefix_len()`.
    fn get_prefix_len(&self) -> Result<i128>;

    // ---- sockets
    /// python `get_state()` of `socket`, `sock`, `unix_sock`, `inet_sock`, `netlink_sock`,
    /// `vsock_sock`, `packet_sock`, `bt_sock` (None where python returns None), `xdp_sock`.
    fn sock_get_state(&self) -> Result<Option<String>>;
    /// python `get_protocol()` of the socket classes.
    fn get_protocol(&self) -> Result<Option<String>>;
    /// python `get_family()` of `sock` / `inet_sock`.
    fn get_family(&self) -> Result<String>;
    /// python `sock.get_type()` (`SOCK_TYPES`).
    fn sock_get_type(&self) -> Result<&'static str>;
    /// python `unix_sock.get_name()`.
    fn unix_get_name(&self) -> Result<Option<String>>;
    /// python `inet_sock.get_src_port()` / `get_dst_port()`.
    fn get_src_port(&self) -> Result<Option<i128>>;
    fn get_dst_port(&self) -> Result<Option<i128>>;
    /// python `inet_sock.get_src_addr()` / `get_dst_addr()`.
    fn get_src_addr(&self) -> Result<Option<String>>;
    fn get_dst_addr(&self) -> Result<Option<String>>;
    /// python `netlink_sock.get_portid()` / `get_dst_portid()`.
    fn get_portid(&self) -> Result<i128>;
    fn get_dst_portid(&self) -> Result<i128>;
}

/// python `net_device._get_flag_choices()` (enum `net_device_flags`, else the constant table).
fn flag_choices(d: &Obj) -> Result<Vec<(String, i128)>> {
    let vm = vmlinux_of(d)?;
    let t = vm.table();
    Ok(match t.enumeration("net_device_flags") {
        Some(e) => t.enum_constants(e).map(|(n, v)| (n.to_string(), v as i128)).collect(),
        None => NET_DEVICE_FLAGS.iter().map(|(n, v)| (n.to_string(), *v)).collect(),
    })
}

/// python `net_device._get_netdev_state_t()` choice value.
fn netdev_state(d: &Obj, name: &str) -> Result<i128> {
    let vm = vmlinux_of(d)?;
    let t = vm.table();
    let e = t.enumeration("netdev_state_t").ok_or_else(|| Error::msg("VolatilityException: Unsupported kernel or wrong ISF. Cannot find 'netdev_state_t' enumeration"))?;
    t.enum_constants(e).find(|c| c.0 == name).map(|c| c.1 as i128).ok_or_else(|| Error::msg(format!("KeyError: '{name}'")))
}

fn fmt_mac(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

/// `sock.__sk_common` (python name-mangles it to `_sock__sk_common` and strips it back).
fn sk_common(sk: &Obj) -> Result<Obj> {
    tgt(sk)?.m("__sk_common")
}

/// python `socket.get_state()` on a `socket *` pointer / object.
fn socket_state(s: &Obj) -> Result<String> {
    let idx = tgt(s)?.m("state")?.int()?;
    Ok(usize::try_from(idx).ok().and_then(|i| SOCKET_STATES.get(i)).map_or("Unknown socket state".to_string(), |s| s.to_string()))
}

/// python `getattr(obj, name)` presence for a struct member (AttributeError -> false).
fn has(o: &Obj, name: &str) -> bool {
    o.has_member(name)
}

impl NetExt for Obj {
    fn net_get_inode(&self) -> Result<i128> {
        let s = tgt(self)?;
        match s.struct_name() {
            Some("net") => {
                if s.has_member("proc_inum") {
                    s.m("proc_inum")?.int()
                } else if s.has_member("ns") && s.m("ns")?.has_member("inum") {
                    s.m("ns")?.m("inum")?.int()
                } else {
                    Err(Error::msg("AttributeError: Unable to find net_namespace inode"))
                }
            }
            Some("socket") => {
                let Ok(vm) = vmlinux_of(&s) else { return Ok(0) };
                match container_of(s.addr, "socket_alloc", "socket", &vm)? {
                    Some(sa) => sa.m("vfs_inode")?.m("i_ino")?.int(),
                    None => Ok(0),
                }
            }
            Some("unix_sock") => s.m("sk")?.net_get_inode(),
            _ => {
                // sock
                let p = s.m("sk_socket")?;
                if p.u64()? == 0 {
                    return Ok(0);
                }
                p.net_get_inode()
            }
        }
    }

    fn get_device_name(&self) -> Result<String> {
        array_to_string(&tgt(self)?.m("name")?, None)
    }

    fn get_mac_address(&self) -> Result<Option<String>> {
        let d = tgt(self)?;
        let addr_len = d.m("addr_len")?.int()?.max(0) as usize;
        if d.has_member("perm_addr") {
            let null = fmt_mac(&vec![0u8; addr_len]);
            let perm = d.m("perm_addr")?;
            let n = addr_len.min(perm.count() as usize);
            let mut b = Vec::with_capacity(n);
            for i in 0..n {
                b.push(perm.at(i as u64)?.int()? as u8);
            }
            let mac = fmt_mac(&b);
            if mac != null {
                return Ok(Some(mac));
            }
        }
        let dev_addr = d.m("dev_addr")?.u64()?;
        let hw = d.layer().read_vec_padded(dev_addr, addr_len);
        Ok(Some(fmt_mac(&hw)))
    }

    fn get_flag_names(&self) -> Result<Vec<String>> {
        let d = tgt(self)?;
        let choices = flag_choices(&d)?;
        let get = |n: &str| choices.iter().find(|c| c.0 == n).map_or(0, |c| c.1);
        let clear_flags = get("IFF_PROMISC") | get("IFF_ALLMULTI") | get("IFF_RUNNING") | get("IFF_LOWER_UP") | get("IFF_DORMANT");
        // python's `choices.get("IFF_ALLMULTI)", 0)` typo: only IFF_PROMISC is cleared
        let clear_gflags = get("IFF_PROMISC");
        let mut flags = (d.m("flags")?.int()? & !clear_flags) | (d.m("gflags")?.int()? & !clear_gflags);
        if d.is_running()? {
            if d.is_operational()? {
                flags |= get("IFF_RUNNING");
            }
            if d.is_carrier_ok()? {
                flags |= get("IFF_LOWER_UP");
            }
            if d.is_dormant()? {
                flags |= get("IFF_DORMANT");
            }
        }
        let mut names: Vec<String> = choices.iter().filter(|(_, v)| flags & v != 0).map(|(n, _)| n.clone()).collect();
        names.sort();
        Ok(names)
    }

    fn promisc(&self) -> Result<bool> {
        let d = tgt(self)?;
        let choices = flag_choices(&d)?;
        let Some(v) = choices.iter().find(|c| c.0 == "IFF_PROMISC").map(|c| c.1) else {
            return Err(Error::msg("TypeError: unsupported operand type(s) for &: 'int' and 'UnparsableValue'"));
        };
        Ok(d.m("flags")?.int()? & v != 0)
    }

    fn is_running(&self) -> Result<bool> {
        let d = tgt(self)?;
        let bit = netdev_state(&d, "__LINK_STATE_START")?;
        Ok(d.m("state")?.int()? & (1i128 << bit) != 0)
    }

    fn is_carrier_ok(&self) -> Result<bool> {
        let d = tgt(self)?;
        let bit = netdev_state(&d, "__LINK_STATE_NOCARRIER")?;
        Ok(d.m("state")?.int()? & (1i128 << bit) == 0)
    }

    fn is_dormant(&self) -> Result<bool> {
        let d = tgt(self)?;
        let bit = netdev_state(&d, "__LINK_STATE_DORMANT")?;
        Ok(d.m("state")?.int()? & (1i128 << bit) != 0)
    }

    fn is_operational(&self) -> Result<bool> {
        Ok(matches!(self.get_operational_state()?, Value::SStr("UP") | Value::SStr("UNKNOWN")))
    }

    fn get_net_namespace_id(&self) -> Result<Option<i128>> {
        let r = (|| -> Result<i128> {
            let nd_net = tgt(self)?.m("nd_net")?;
            if nd_net.has_member("net") { nd_net.m("net")?.net_get_inode() } else { nd_net.net_get_inode() }
        })();
        match r {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_operational_state(&self) -> Result<Value> {
        let v = tgt(self)?.m("operstate")?.int()?;
        Ok(if_oper_state(v).map_or(Value::Unparsable, Value::SStr))
    }

    fn get_qdisc_name(&self) -> Result<Option<String>> {
        match tgt(self).and_then(|d| array_to_string(&d.m("qdisc")?.m("ops")?.m("id")?, None)) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_queue_length(&self) -> Result<i128> {
        tgt(self)?.m("tx_queue_len")?.int()
    }

    fn get_addresses(&self) -> Vec<Result<Obj>> {
        let s = match tgt(self) {
            Ok(s) => s,
            Err(e) => return vec![Err(e)],
        };
        if s.struct_name() == Some("inet6_dev") {
            let t = s.table();
            let ok = s.has_member("addr_list") && s.m("addr_list").is_ok_and(|a| a.struct_name() == Some("list_head"));
            let ifa_ok = t.user_type("inet6_ifaddr").is_some_and(|u| t.member(u, "if_list").is_some());
            if !ok || !ifa_ok {
                return Vec::new();
            }
            let it: ListIter = match s.m("addr_list") {
                Ok(l) => l.list_of(&format!("{}!inet6_ifaddr", t.name()), "if_list"),
                Err(e) => return vec![Err(e)],
            };
            return it.collect();
        }
        // in_device
        let mut out = Vec::new();
        let mut seen = FxHashSet::default();
        let mut cur = match s.m("ifa_list").and_then(|p| p.u64().map(|_| p)) {
            Ok(p) => p,
            Err(e) if e.is_invalid_address() => return out,
            Err(e) => return vec![Err(e)],
        };
        loop {
            match cur.u64() {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            }
            if cur.addr == 0 || seen.len() > 128 || !seen.insert(cur.addr) {
                break;
            }
            out.push(Ok(cur));
            cur = match cur.m("ifa_next").and_then(|p| p.u64().map(|_| p)) {
                Ok(p) => p,
                Err(e) if e.is_invalid_address() => break,
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
            };
        }
        out
    }

    fn get_scope_type(&self) -> Result<String> {
        let a = tgt(self)?;
        if a.struct_name() == Some("inet6_ifaddr") {
            let scope = a.m("scope")?.int()?;
            return Ok(if scope & IFA_HOST != 0 {
                "host"
            } else if scope & IFA_LINK != 0 {
                "link"
            } else if scope & IFA_SITE != 0 {
                "site"
            } else {
                "global"
            }
            .into());
        }
        let t = a.table();
        let e = t.enumeration("rt_scope_t").ok_or_else(|| Error::Symbol("Unknown symbol: rt_scope_t".into()))?;
        let v = a.m("ifa_scope")?.int()?;
        let Some(name) = t.enum_lookup(e, v) else { return Ok("unknown".into()) };
        Ok(match name {
            "RT_SCOPE_UNIVERSE" => "global",
            "RT_SCOPE_NOWHERE" => "nowhere",
            "RT_SCOPE_HOST" => "host",
            "RT_SCOPE_LINK" => "link",
            "RT_SCOPE_SITE" => "site",
            _ => "unknown",
        }
        .into())
    }

    fn get_address(&self) -> Result<String> {
        let a = tgt(self)?;
        if a.struct_name() == Some("inet6_ifaddr") {
            let w = a.m("addr")?.m("in6_u")?.m("u6_addr32")?.ints()?;
            if w.len() != 4 {
                return Err(Error::msg("struct.error: pack expected 4 items"));
            }
            return Ok(convert_ipv6(&[w[0] as u32, w[1] as u32, w[2] as u32, w[3] as u32]));
        }
        Ok(convert_ipv4(a.m("ifa_address")?.int()? as u32))
    }

    fn get_prefix_len(&self) -> Result<i128> {
        let a = tgt(self)?;
        if a.struct_name() == Some("inet6_ifaddr") { a.m("prefix_len")?.int() } else { a.m("ifa_prefixlen")?.int() }
    }

    fn sock_get_state(&self) -> Result<Option<String>> {
        let s = tgt(self)?;
        match s.struct_name() {
            Some("socket") => Ok(Some(socket_state(&s)?)),
            Some("unix_sock") | Some("inet_sock") => {
                let sk = s.m("sk")?;
                if sk.sock_get_type()? == "STREAM" {
                    let idx = sk_common(&sk)?.m("skc_state")?.int()?;
                    let unknown = if s.struct_name() == Some("unix_sock") { "Unknown unix_sock stream state" } else { "Unknown inet_sock stream state" };
                    return Ok(Some(usize::try_from(idx).ok().and_then(|i| TCP_STATES.get(i)).map_or(unknown.to_string(), |x| x.to_string())));
                }
                Ok(Some(socket_state(&sk.m("sk_socket")?)?))
            }
            Some("netlink_sock") | Some("vsock_sock") | Some("packet_sock") => Ok(Some(socket_state(&s.m("sk")?.m("sk_socket")?)?)),
            Some("bt_sock") => {
                let idx = sk_common(&s.m("sk")?)?.m("skc_state")?.int()?;
                Ok(usize::try_from(idx).ok().and_then(|i| BLUETOOTH_STATES.get(i)).map(|x| x.to_string()))
            }
            Some("xdp_sock") => Ok(Some(s.m("state")?.description()?.to_string())),
            _ => {
                // sock
                if s.has_member("sk") {
                    return Ok(Some(socket_state(&s.m("sk")?.m("sk_socket")?)?));
                }
                Ok(Some(socket_state(&s.m("sk_socket")?)?))
            }
        }
    }

    fn get_protocol(&self) -> Result<Option<String>> {
        let s = tgt(self)?;
        match s.struct_name() {
            Some("inet_sock") => {
                let proto = s.m("sk")?.m("sk_protocol")?.int()?;
                let mut p = ip_protocol(proto);
                if s.get_family()? == "AF_INET6" {
                    p = ipv6_protocol(proto).or(p);
                }
                Ok(p.map(str::to_string))
            }
            Some("netlink_sock") => {
                let idx = s.m("sk")?.m("sk_protocol")?.int()?;
                Ok(Some(usize::try_from(idx).ok().and_then(|i| NETLINK_PROTOCOLS.get(i)).map_or("Unknown netlink_sock protocol".to_string(), |x| x.to_string())))
            }
            Some("packet_sock") => {
                let p = htons(s.m("num")?.int()?)?;
                Ok(if p == 0 {
                    None
                } else {
                    Some(eth_protocol(p).map_or_else(|| format!("0x{p:x}"), str::to_string))
                })
            }
            Some("bt_sock") => {
                let idx = s.m("sk")?.m("sk_protocol")?.int()?;
                Ok(usize::try_from(idx).ok().and_then(|i| BLUETOOTH_PROTOCOLS.get(i)).map(|x| x.to_string()))
            }
            // sock, unix_sock, vsock_sock, xdp_sock
            _ => Ok(None),
        }
    }

    fn get_family(&self) -> Result<String> {
        let s = tgt(self)?;
        let (sk, unknown) = if s.struct_name() == Some("inet_sock") { (s.m("sk")?, "Unknown inet_sock family") } else { (s, "Unknown socket family") };
        let idx = sk_common(&sk)?.m("skc_family")?.int()?;
        Ok(usize::try_from(idx).ok().and_then(|i| SOCK_FAMILY.get(i)).map_or(unknown.to_string(), |x| x.to_string()))
    }

    fn sock_get_type(&self) -> Result<&'static str> {
        Ok(sock_type_name(tgt(self)?.m("sk_type")?.int()?))
    }

    fn unix_get_name(&self) -> Result<Option<String>> {
        let s = tgt(self)?;
        let addr = s.m("addr")?;
        if addr.u64()? == 0 {
            return Ok(None);
        }
        let sun = addr.m("name")?.cast("sockaddr_un")?;
        Ok(Some(array_to_string(&sun.m("sun_path")?, None)?))
    }

    fn get_src_port(&self) -> Result<Option<i128>> {
        let s = tgt(self)?;
        // python evaluates getattr(self, "inet_sport", None) first (the default argument)
        let inet_sport = if has(&s, "inet_sport") { Some(s.m("inet_sport")?.int()?) } else { None };
        let v = if has(&s, "sport") { Some(s.m("sport")?.int()?) } else { inet_sport };
        v.map(htons).transpose()
    }

    fn get_dst_port(&self) -> Result<Option<i128>> {
        let s = tgt(self)?;
        let skc = sk_common(&s.m("sk")?)?;
        let v = if has(&skc, "skc_portpair") {
            skc.m("skc_portpair")?.int()? & 0xFFFF
        } else if has(&s, "dport") {
            s.m("dport")?.int()?
        } else if has(&s, "inet_dport") {
            s.m("inet_dport")?.int()?
        } else if has(&skc, "skc_dport") {
            skc.m("skc_dport")?.int()?
        } else {
            return Ok(None);
        };
        htons(v).map(Some)
    }

    fn get_src_addr(&self) -> Result<Option<String>> {
        let s = tgt(self)?;
        let skc = sk_common(&s.m("sk")?)?;
        let family = skc.m("skc_family")?.int()?;
        let (saddr, size) = if family == AF_INET {
            let a = if has(&s, "rcv_saddr") {
                s.m("rcv_saddr")?
            } else if has(&s, "inet_rcv_saddr") {
                s.m("inet_rcv_saddr")?
            } else {
                skc.m("skc_rcv_saddr")?
            };
            (a, 4usize)
        } else if family == AF_INET6 {
            (s.m("pinet6")?.m("saddr")?, 16)
        } else {
            return Ok(None);
        };
        read_addr(&s, saddr.addr, size, family)
    }

    fn get_dst_addr(&self) -> Result<Option<String>> {
        let s = tgt(self)?;
        let skc = sk_common(&s.m("sk")?)?;
        let family = skc.m("skc_family")?.int()?;
        let (daddr, size) = if family == AF_INET {
            let a = if has(&s, "daddr") && s.m("daddr")?.int()? != 0 {
                s.m("daddr")?
            } else if has(&s, "inet_daddr") && s.m("inet_daddr")?.int()? != 0 {
                s.m("inet_daddr")?
            } else {
                skc.m("skc_daddr")?
            };
            (a, 4usize)
        } else if family == AF_INET6 {
            let p = s.m("pinet6")?;
            let a = if p.has_member("daddr") { p.m("daddr")? } else { skc.m("skc_v6_daddr")? };
            (a, 16)
        } else {
            return Ok(None);
        };
        read_addr(&s, daddr.addr, size, family)
    }

    fn get_portid(&self) -> Result<i128> {
        let s = tgt(self)?;
        if s.has_member("pid") {
            s.m("pid")?.int()
        } else if s.has_member("portid") {
            s.m("portid")?.int()
        } else {
            Err(Error::msg("AttributeError: Unable to find a source port id"))
        }
    }

    fn get_dst_portid(&self) -> Result<i128> {
        let s = tgt(self)?;
        if s.has_member("dst_pid") {
            s.m("dst_pid")?.int()
        } else if s.has_member("dst_portid") {
            s.m("dst_portid")?.int()
        } else {
            Err(Error::msg("AttributeError: Unable to find a destination port id"))
        }
    }
}

/// `parent_layer.read(addr.vol.offset, size)` + `socket.inet_ntop(family, ...)` (None when
/// unreadable).
fn read_addr(s: &Obj, addr: u64, size: usize, family: i128) -> Result<Option<String>> {
    let layer: &dyn Layer = s.layer();
    let mut b = [0u8; 16];
    if layer.read(addr, &mut b[..size]).is_err() {
        return Ok(None);
    }
    Ok(Some(if family == AF_INET { inet_ntop4(&b[..4]) } else { inet_ntop6(&b) }))
}

/// python `ptr and ptr.is_readable()` (re-export for network plugin porters).
pub fn pointer_ok(p: &Obj) -> Result<bool> {
    ptr_ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_formats_like_python() {
        let mut m = [0u8; 16];
        m[10] = 0xff;
        m[11] = 0xff;
        m[12..].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(inet_ntop6(&m), "::ffff:1.2.3.4");
        let mut c = [0u8; 16];
        c[12..].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(inet_ntop6(&c), "::1.2.3.4");
        let words = |b: &[u8; 16]| -> [u32; 4] { std::array::from_fn(|i| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap())) };
        assert_eq!(convert_ipv6(&words(&c)), "::102:304");
        assert_eq!(convert_ipv6(&words(&m)), "::ffff:1.2.3.4");
        let ll = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1];
        assert_eq!(inet_ntop6(&ll), "fe80::1:0:1");
        assert_eq!(convert_ipv6(&words(&ll)), "fe80::1:0:1");
        let alt = [0x20, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0];
        assert_eq!(inet_ntop6(&alt), "2001:0:1:0:1:0:1:0");
        assert_eq!(convert_ipv6(&words(&alt)), "2001:0:1:0:1:0:1:0");
        let one = {
            let mut x = [0u8; 16];
            x[15] = 1;
            x
        };
        assert_eq!(inet_ntop6(&one), "::1");
        assert_eq!(convert_ipv6(&words(&one)), "::1");
        assert_eq!(inet_ntop6(&[0u8; 16]), "::");
        assert_eq!(convert_ipv6(&[0; 4]), "::");
        assert_eq!(convert_ipv4(0x0100_007f), "127.0.0.1");
    }
}

#[cfg(test)]
mod image_tests {
    use super::*;
    use crate::context::{Context, GlobalOptions};

    /// Prints `linux.ip.Link` + `linux.ip.Addr`-like rows for a quick check of the network
    /// helpers against python's references:
    /// `FASTVOL_BENCH_IMAGE=<image> cargo test --profile fast net_like_ip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn net_like_ip() {
        let image = crate::util::env::var("BENCH_IMAGE").unwrap();
        let opts = GlobalOptions { file: Some(image), symbol_dirs: vec![crate::util::testdata::path("testdata/symbols")], ..Default::default() };
        let ctx = Context::new(opts).unwrap();
        let k = ctx.linux_kernel().unwrap();
        let t = k.table.name().to_string();
        let head = k.object_from_symbol("net_namespace_list").unwrap();
        for ns in head.list_of(&format!("{t}!net"), "list") {
            let ns = ns.unwrap();
            for d in ns.m("dev_base_head").unwrap().list_of(&format!("{t}!net_device"), "dev_list") {
                let d = d.unwrap();
                let flags: Vec<String> = d.get_flag_names().unwrap().into_iter().filter(|f| f != "IFF_RUNNING").map(|f| f.replace("IFF_", "")).collect();
                println!(
                    "LINK\t{:?}\t{}\t{:?}\t{:?}\t{}\t{:?}\t{}\t{}",
                    d.get_net_namespace_id().unwrap(),
                    d.get_device_name().unwrap(),
                    d.get_mac_address().unwrap(),
                    d.get_operational_state().unwrap(),
                    d.m("mtu").unwrap().int().unwrap(),
                    d.get_qdisc_name().unwrap(),
                    d.get_queue_length().unwrap(),
                    flags.join(",")
                );
                let ind = d.m("ip_ptr").unwrap().deref().unwrap().cast("in_device").unwrap();
                for a in ind.get_addresses() {
                    let a = a.unwrap();
                    println!("ADDR\t{}\t{}\t{}\t{}\t{}", d.m("ifindex").unwrap().int().unwrap(), a.get_address().unwrap(), a.get_prefix_len().unwrap(), a.get_scope_type().unwrap(), d.promisc().unwrap());
                }
                let in6 = d.m("ip6_ptr").unwrap().deref().unwrap().cast("inet6_dev").unwrap();
                for a in in6.get_addresses() {
                    let a = a.unwrap();
                    println!("ADDR\t{}\t{}\t{}\t{}", d.m("ifindex").unwrap().int().unwrap(), a.get_address().unwrap(), a.get_prefix_len().unwrap(), a.get_scope_type().unwrap());
                }
            }
        }
    }
}
