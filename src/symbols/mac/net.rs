//! python mac `socket` / `inpcb` / `ifnet` / `sockaddr` / `sockaddr_dl` class extensions, plus
//! the `renderers.conversion` IP helpers they use (python `ipaddress` formatting).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Where python reads memory is mirrored: pointer / integer members are read when python
//! accesses them, and only the `InvalidAddressException`s python catches are turned into
//! `None`; anything else propagates as `Err`.

use crate::error::Result;
use crate::objects::Obj;

/// python `conversion.convert_ipv4(ip_as_integer)`: `str(IPv4Address(struct.pack("<I", ip)))`.
pub fn convert_ipv4(ip: u32) -> String {
    let b = ip.to_le_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// python `str(ipaddress.IPv6Address(packed))` for 16 packed bytes (python 3.14: compressed
/// hextets, IPv4-mapped addresses in mixed `::ffff:a.b.c.d` notation).
pub fn ipv6_to_string(b: &[u8; 16]) -> String {
    let ip = u128::from_be_bytes(*b);
    if ip >> 32 == 0xFFFF {
        let v4 = (ip as u32).to_be_bytes();
        return format!("{}:{}.{}.{}.{}", hextets_string(0xFFFF), v4[0], v4[1], v4[2], v4[3]);
    }
    hextets_string(ip)
}

/// python `_BaseV6._string_from_ip_int` (+ `_compress_hextets`).
fn hextets_string(ip: u128) -> String {
    let h: Vec<u16> = (0..8).map(|i| (ip >> (112 - 16 * i)) as u16).collect();
    // longest run of zero hextets (first one wins ties), only compressed when > 1
    let (mut best_start, mut best_len, mut start, mut len) = (-1i32, 0i32, -1i32, 0i32);
    for (i, &x) in h.iter().enumerate() {
        if x == 0 {
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
    let parts: Vec<String> = h.iter().map(|x| format!("{x:x}")).collect();
    if best_len > 1 {
        let (s, e) = (best_start as usize, (best_start + best_len) as usize);
        let head = parts[..s].join(":");
        let tail = parts[e..].join(":");
        format!("{head}::{tail}")
    } else {
        parts.join(":")
    }
}

/// python `conversion.convert_ipv6(packed_ip)` for the four `__u6_addr32` values.
pub fn convert_ipv6(words: &[u32; 4]) -> String {
    let mut b = [0u8; 16];
    for (i, w) in words.iter().enumerate() {
        b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    ipv6_to_string(&b)
}

/// python `conversion.convert_port(port_as_integer)`.
pub fn convert_port(port: i128) -> i128 {
    (port >> 8) | ((port & 0xFF) << 8)
}

/// python `sockaddr_dl.__str__()` (MAC address), `obj` a `sockaddr_dl` (or a pointer to one).
pub fn sockaddr_dl_str(obj: &Obj) -> Result<String> {
    let mut ret = String::new();
    let alen = obj.m("sdl_alen")?.int()?;
    if alen > 14 {
        return Ok(ret);
    }
    let data = obj.m("sdl_data")?;
    for i in 0..alen.max(0) {
        let idx = obj.m("sdl_nlen")?.int()? + i;
        // python Array indexing: IndexError past the end ends the loop (negative indices wrap)
        let n = data.count() as i128;
        let idx = if idx < 0 { idx + n } else { idx };
        if idx < 0 || idx >= n {
            break;
        }
        let e = data.at(idx as u64)?.cast("unsigned char")?.int()?;
        ret.push_str(&format!("{e:02X}:"));
    }
    if ret.ends_with(':') {
        ret.pop();
    }
    Ok(ret)
}

/// python `ifnet.sockaddr_dl()`: the link-level address (`None` on InvalidAddressException).
pub fn ifnet_sockaddr_dl(ifnet: &Obj) -> Result<Option<Obj>> {
    let r = if ifnet.has_member("if_lladdr") {
        ifnet.m("if_lladdr").and_then(|l| l.m("ifa_addr")).and_then(|a| a.deref()).and_then(|o| o.cast("sockaddr_dl"))
    } else {
        ifnet.m("if_addrhead").and_then(|h| h.m("tqh_first")).and_then(|f| f.m("ifa_addr")).and_then(|a| a.deref()).and_then(|o| o.cast("sockaddr_dl"))
    };
    match r {
        Ok(o) => Ok(Some(o)),
        Err(e) if e.is_invalid_address() => Ok(None),
        Err(e) => Err(e),
    }
}

/// python `sockaddr.get_address()`: IPv4 / IPv6 / link-level address string, "" for other
/// families. `sa` is a `sockaddr` (or a pointer to one).
pub fn sockaddr_get_address(sa: &Obj) -> Result<String> {
    let sa = if sa.is_pointer() { sa.deref()? } else { *sa };
    let family = sa.m("sa_family")?.int()?;
    Ok(match family {
        2 => convert_ipv4(sa.cast("sockaddr_in")?.m("sin_addr")?.m("s_addr")?.int()? as u32),
        30 => {
            let words = sa.cast("sockaddr_in6")?.m("sin6_addr")?.m("__u6_addr")?.m("__u6_addr32")?;
            let mut w = [0u32; 4];
            for (i, v) in words.ints()?.into_iter().take(4).enumerate() {
                w[i] = v as u32;
            }
            convert_ipv6(&w)
        }
        18 => sockaddr_dl_str(&sa.cast("sockaddr_dl")?)?,
        _ => String::new(),
    })
}

/// python `socket.get_inpcb()`: `so_pcb` as an `inpcb` (`None` on InvalidAddressException).
pub fn socket_get_inpcb(sock: &Obj) -> Result<Option<Obj>> {
    match sock.m("so_pcb").and_then(|p| p.deref()).and_then(|o| o.cast("inpcb")) {
        Ok(o) => Ok(Some(o)),
        Err(e) if e.is_invalid_address() => Ok(None),
        Err(e) => Err(e),
    }
}

/// python `socket.get_family()`: `so_proto.pr_domain.dom_family`.
pub fn socket_get_family(sock: &Obj) -> Result<i128> {
    sock.m("so_proto")?.m("pr_domain")?.m("dom_family")?.int()
}

/// python `socket.get_protocol_as_string()`.
pub fn socket_get_protocol_as_string(sock: &Obj) -> Result<&'static str> {
    Ok(match sock.m("so_proto")?.m("pr_protocol")?.int()? {
        6 => "TCP",
        17 => "UDP",
        _ => "",
    })
}

const TCP_STATES: [&str; 11] =
    ["CLOSED", "LISTEN", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "CLOSE_WAIT", "FIN_WAIT1", "CLOSING", "LAST_ACK", "FIN_WAIT2", "TIME_WAIT"];

/// python `inpcb.get_tcp_state()`. A negative `t_state` below -11 makes python raise
/// IndexError (a crash): returned as a `files::py_builtin` error (see `files::raise_python`).
pub fn inpcb_get_tcp_state(inpcb: &Obj) -> Result<&'static str> {
    let tcpcb = match inpcb.m("inp_ppcb").and_then(|p| p.deref()).and_then(|o| o.cast("tcpcb")) {
        Ok(t) => t,
        Err(e) if e.is_invalid_address() => return Ok(""),
        Err(e) => return Err(e),
    };
    let st = tcpcb.m("t_state")?.int()?;
    if st != 0 && st < TCP_STATES.len() as i128 {
        let idx = if st < 0 { st + TCP_STATES.len() as i128 } else { st };
        if idx < 0 {
            return Err(super::files::py_builtin("IndexError", "tuple index out of range"));
        }
        Ok(TCP_STATES[idx as usize])
    } else {
        Ok("")
    }
}

/// python `socket.get_state()`.
pub fn socket_get_state(sock: &Obj) -> Result<&'static str> {
    if sock.m("so_proto")?.m("pr_protocol")?.int()? == 6 {
        if let Some(inpcb) = socket_get_inpcb(sock)? {
            return inpcb_get_tcp_state(&inpcb);
        }
    }
    Ok("")
}

/// python `inpcb.get_ipv4_info()` / `get_ipv6_info()` result: the four tuple.
#[derive(Clone, Debug)]
pub enum ConnInfo {
    /// `[lip, lport, rip, rport]` with `s_addr` values.
    V4 { lip: u32, lport: i128, rip: u32, rport: i128 },
    /// `[lip, lport, rip, rport]` with the `__u6_addr32` arrays.
    V6 { lip: [u32; 4], lport: i128, rip: [u32; 4], rport: i128 },
}

/// python `inpcb.get_ipv4_info()`.
pub fn inpcb_get_ipv4_info(inpcb: &Obj) -> Result<Option<ConnInfo>> {
    let lip = match inpcb.m("inp_dependladdr").and_then(|a| a.m("inp46_local")).and_then(|a| a.m("ia46_addr4")).and_then(|a| a.m("s_addr")).and_then(|a| a.int()) {
        Ok(v) => v as u32,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    let lport = inpcb.m("inp_lport")?.int()?;
    let rip = match inpcb.m("inp_dependfaddr").and_then(|a| a.m("inp46_foreign")).and_then(|a| a.m("ia46_addr4")).and_then(|a| a.m("s_addr")).and_then(|a| a.int()) {
        Ok(v) => v as u32,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    let rport = inpcb.m("inp_fport")?.int()?;
    Ok(Some(ConnInfo::V4 { lip, lport, rip, rport }))
}

/// The four `__u6_addr32` words of an `in6_addr` (python keeps the array object; the words are
/// read only when converted -- `read` = false returns zeros without touching memory).
fn in6_words(addr: &Obj, read: bool) -> Result<[u32; 4]> {
    let mut w = [0u32; 4];
    if read {
        for (i, v) in addr.m("__u6_addr")?.m("__u6_addr32")?.ints()?.into_iter().take(4).enumerate() {
            w[i] = v as u32;
        }
    } else {
        addr.m("__u6_addr")?.m("__u6_addr32")?;
    }
    Ok(w)
}

/// python `inpcb.get_ipv6_info()`. The address arrays are not read by python unless they are
/// converted (never, on a Linux host: see [`convert_network_four_tuple`]), so `read_addrs`
/// selects whether to read them.
pub fn inpcb_get_ipv6_info(inpcb: &Obj, read_addrs: bool) -> Result<Option<ConnInfo>> {
    let lip = match inpcb.m("inp_dependladdr").and_then(|a| a.m("inp6_local")).and_then(|a| in6_words(&a, read_addrs)) {
        Ok(v) => v,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    let lport = inpcb.m("inp_lport")?.int()?;
    let rip = match inpcb.m("inp_dependfaddr").and_then(|a| a.m("inp6_foreign")).and_then(|a| in6_words(&a, read_addrs)) {
        Ok(v) => v,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    let rport = inpcb.m("inp_fport")?.int()?;
    Ok(Some(ConnInfo::V6 { lip, lport, rip, rport }))
}

/// python `socket.get_connection_info()`.
pub fn socket_get_connection_info(sock: &Obj) -> Result<Option<ConnInfo>> {
    let Some(inpcb) = socket_get_inpcb(sock)? else { return Ok(None) };
    if socket_get_family(sock)? == 2 { inpcb_get_ipv4_info(&inpcb) } else { inpcb_get_ipv6_info(&inpcb, false) }
}

/// python's `socket.AF_INET` / `socket.AF_INET6` on the host running volatility (Linux).
pub const HOST_AF_INET: i128 = 2;
pub const HOST_AF_INET6: i128 = 10;

/// python `conversion.convert_network_four_tuple(family, four_tuple)` with the HOST's socket
/// constants (python compares the mac family to `socket.AF_INET6`, 10 on Linux, so mac IPv6
/// sockets (family 30) give `None`).
pub fn convert_network_four_tuple(family: i128, info: &ConnInfo) -> Option<(String, i128, String, i128)> {
    match (family, info) {
        (HOST_AF_INET, ConnInfo::V4 { lip, lport, rip, rport }) => Some((convert_ipv4(*lip), convert_port(*lport), convert_ipv4(*rip), convert_port(*rport))),
        (HOST_AF_INET6, ConnInfo::V6 { lip, lport, rip, rport }) => Some((convert_ipv6(lip), convert_port(*lport), convert_ipv6(rip), convert_port(*rport))),
        _ => None,
    }
}

/// python `socket.get_converted_connection_info()`.
pub fn socket_get_converted_connection_info(sock: &Obj) -> Result<Option<(String, i128, String, i128)>> {
    match socket_get_connection_info(sock)? {
        Some(info) => {
            let family = socket_get_family(sock)?;
            Ok(convert_network_four_tuple(family, &info))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(s: [u16; 8]) -> String {
        let mut b = [0u8; 16];
        for (i, x) in s.iter().enumerate() {
            b[i * 2..i * 2 + 2].copy_from_slice(&x.to_be_bytes());
        }
        ipv6_to_string(&b)
    }

    #[test]
    fn ipv6_python_format() {
        assert_eq!(v6([0, 0, 0, 0, 0, 0, 0, 1]), "::1");
        assert_eq!(v6([0; 8]), "::");
        assert_eq!(v6([0xfe80, 1, 0, 0, 0, 0, 0, 1]), "fe80:1::1");
        assert_eq!(v6([1, 0, 0, 1, 0, 0, 0, 1]), "1:0:0:1::1");
        assert_eq!(v6([1, 0, 0, 1, 0, 0, 1, 1]), "1::1:0:0:1:1");
        assert_eq!(v6([0, 0, 1, 0, 0, 0, 0, 0]), "0:0:1::");
        assert_eq!(v6([0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304]), "::ffff:1.2.3.4");
        assert_eq!(v6([0, 0, 0, 0, 0xffff, 0, 0x0102, 0x0304]), "::ffff:0:102:304");
        assert_eq!(v6([1, 2, 3, 4, 5, 6, 7, 8]), "1:2:3:4:5:6:7:8");
        assert_eq!(v6([1, 0, 3, 4, 5, 6, 7, 8]), "1:0:3:4:5:6:7:8");
    }

    #[test]
    fn ipv4_and_port() {
        assert_eq!(convert_ipv4(0x0100_007f), "127.0.0.1");
        assert_eq!(convert_port(0x5000), 0x50);
    }
}
