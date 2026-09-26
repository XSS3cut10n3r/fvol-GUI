//! python `symbols/windows/extensions/network.py`: the `_TCP_LISTENER` / `_TCP_ENDPOINT` /
//! `_UDP_ENDPOINT` / `_LOCAL_ADDRESS` / `_LOCAL_ADDRESS_WIN10_UDP` classes of the
//! `windows/netscan/*` ISFs as the [`NetExt`] trait on [`Obj`] (dispatch on the object's struct
//! name, like python's class binding), plus glibc-exact [`inet_ntop`].
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Every method mirrors python's error handling: `Ok(None)` is python returning `None` (it
//! caught an `InvalidAddressException`), `Err` is python raising.
//!
//! ```ignore
//! use crate::symbols::windows::network::{self, NetExt};
//! let t = ctx.load_isf_with("windows/netscan/netscan-win10-19041-x64", None, &[("nt_symbols", k.table.name())])?;
//! network::bind_class_types(t, true);                // python class_types=win10_x64_class_types
//! if obj.net_is_valid()? {                           // obj: a _TCP_ENDPOINT / _TCP_LISTENER / _UDP_ENDPOINT
//!     let laddr = obj.get_local_address()?;          // Option<String>
//!     let pid = obj.get_owner_pid()?;                // Option<i128>
//!     for (ver, laddr, raddr) in obj.dual_stack_sockets()? { .. }
//! }
//! ```

use crate::error::{Error, Result};
use crate::objects::Obj;
use crate::renderers::Value;
use crate::symbols::TableRef;
use crate::symbols::Ty;
use crate::symbols::windows::WinExt;
use crate::util::time::{wintime_to_datetime, year};
use std::fmt::Write as _;
use std::sync::Mutex;

/// Microsoft's `AF_INET` (what is found in memory).
pub const AF_INET: i128 = 2;
/// Microsoft's `AF_INET6` (0x17; python's `socket.AF_INET6` is 0x1e on Linux).
pub const AF_INET6: i128 = 0x17;

/// python `network.inaddr_any` (`inet_ntop(AF_INET, [0] * 4)`).
pub const INADDR_ANY: &str = "0.0.0.0";
/// python `network.inaddr6_any` (`inet_ntop(AF_INET6, [0] * 16)`).
pub const INADDR6_ANY: &str = "::";

/// python's `MIN_CREATETIME_YEAR` / `MAX_CREATETIME_YEAR` (exclusive bounds).
pub const MIN_CREATETIME_YEAR: i64 = 1950;
pub const MAX_CREATETIME_YEAR: i64 = 2200;

/// Address family for [`inet_ntop`] (python passes `socket.AF_INET` / `socket.AF_INET6`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// glibc `inet_ntop4`: dotted decimal.
pub fn inet_ntop4(b: &[u8; 4]) -> String {
    let mut s = String::with_capacity(15);
    push_v4(&mut s, b);
    s
}

fn push_v4(s: &mut String, b: &[u8]) {
    let _ = write!(s, "{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
}

/// glibc `inet_ntop6` (what python's `socket.inet_ntop(AF_INET6, ...)` calls on Linux): the
/// longest run of at least two zero 16-bit groups is compressed to `::` (the first one on
/// ties), groups are lowercase hex without leading zeros, and `::a.b.c.d` / `::ffff:a.b.c.d`
/// are printed for IPv4-compatible / IPv4-mapped addresses.
pub fn inet_ntop6(b: &[u8; 16]) -> String {
    let mut words = [0u16; 8];
    for (i, w) in words.iter_mut().enumerate() {
        *w = u16::from_be_bytes([b[2 * i], b[2 * i + 1]]);
    }
    // longest run of zero words (first wins on ties), at least 2 long
    let (mut best_base, mut best_len) = (-1i32, 0i32);
    let (mut cur_base, mut cur_len) = (-1i32, 0i32);
    for (i, &w) in words.iter().enumerate() {
        if w == 0 {
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
    let mut s = String::with_capacity(46);
    for i in 0..8i32 {
        if best_base != -1 && i >= best_base && i < best_base + best_len {
            if i == best_base {
                s.push(':');
            }
            continue;
        }
        if i != 0 {
            s.push(':');
        }
        if i == 6 && best_base == 0 && (best_len == 6 || (best_len == 5 && words[5] == 0xffff)) {
            push_v4(&mut s, &b[12..16]);
            break;
        }
        let _ = write!(s, "{:x}", words[i as usize]);
    }
    if best_base != -1 && best_base + best_len == 8 {
        s.push(':');
    }
    s
}

/// python `network.inet_ntop(address_family, packed_ip)` (= `socket.inet_ntop`): `Err` for a
/// packed address of the wrong length (python's `ValueError`).
pub fn inet_ntop(family: Family, packed: &[u8]) -> Result<String> {
    match family {
        Family::V4 => match <&[u8; 4]>::try_from(packed) {
            Ok(b) => Ok(inet_ntop4(b)),
            Err(_) => Err(Error::msg("ValueError: invalid length of packed IP address string")),
        },
        Family::V6 => match <&[u8; 16]>::try_from(packed) {
            Ok(b) => Ok(inet_ntop6(b)),
            Err(_) => Err(Error::msg("ValueError: invalid length of packed IP address string")),
        },
    }
}

/// Tables loaded with python's `win10_x64_class_types` (which bind
/// `_LOCAL_ADDRESS_WIN10_UDP`); keyed by table address.
static WIN10_X64_CLASSES: Mutex<Vec<usize>> = Mutex::new(Vec::new());

/// Record the python `class_types` a netscan table was created with: `win10_x64` = python's
/// `network.win10_x64_class_types` (binds `_LOCAL_ADDRESS_WIN10_UDP`), else
/// `network.class_types`.
pub fn bind_class_types(t: TableRef, win10_x64: bool) {
    let key = t as *const _ as *const u8 as usize;
    let mut g = WIN10_X64_CLASSES.lock().unwrap();
    g.retain(|k| *k != key);
    if win10_x64 {
        g.push(key);
    }
}

fn has_win10_udp_class(t: TableRef) -> bool {
    let key = t as *const _ as *const u8 as usize;
    WIN10_X64_CLASSES.lock().unwrap().contains(&key)
}

/// `Ok(None)` for python's caught `InvalidAddressException`.
#[inline]
fn catch<T>(r: Result<T>) -> Result<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.is_invalid_address() => Ok(None),
        Err(e) => Err(e),
    }
}

/// The address bytes of an `_IN_ADDR` (python `bytes(inaddr.addr4)` / `bytes(inaddr.addr6)`).
fn in_addr_string(inaddr: &Obj, family: Family) -> Result<String> {
    let (member, n) = match family {
        Family::V4 => ("addr4", 4),
        Family::V6 => ("addr6", 16),
    };
    let arr = inaddr.m(member)?;
    let mut buf = [0u8; 16];
    arr.layer().read(arr.addr, &mut buf[..n])?;
    inet_ntop(family, &buf[..n])
}

/// python network object classes as methods on [`Obj`]. The object must be a netscan-table
/// `_TCP_LISTENER`, `_TCP_ENDPOINT` or `_UDP_ENDPOINT` (the latter two inherit the listener's
/// methods), except [`NetExt::inaddr`] (`_LOCAL_ADDRESS*`).
pub trait NetExt {
    /// python `get_address_family()`: `InetAF.dereference().AddressFamily` (None when
    /// unreadable).
    fn get_address_family(&self) -> Result<Option<i128>>;
    /// python `get_owner()`: the `_EPROCESS` behind `Owner` (None when the pointer is
    /// unreadable).
    fn get_owner(&self) -> Result<Option<Obj>>;
    /// python `get_owner_pid()`: the owner's `UniqueProcessId` if the owner `is_valid()`.
    fn get_owner_pid(&self) -> Result<Option<i128>>;
    /// python `get_owner_procname()`: the owner's `ImageFileName` as a string (utf-8,
    /// errors="replace", cut at NUL) if the owner `is_valid()`.
    fn get_owner_procname(&self) -> Result<Option<String>>;
    /// python `get_create_time()`: `Value::DateTime`, an absent value (`NotApplicable` for 0,
    /// `Unparsable`), or `None` when the year is not in (1950, 2200).
    fn net_create_time(&self) -> Result<Option<Value>>;
    /// python `get_in_addr()`: the `_IN_ADDR` of `LocalAddr` (None when unreadable / NULL).
    fn get_in_addr(&self) -> Result<Option<Obj>>;
    /// python `dual_stack_sockets()`: `(ver, local address, remote address)` tuples.
    fn dual_stack_sockets(&self) -> Result<Vec<(&'static str, String, &'static str)>>;
    /// python `is_valid()` of the object's class (`_TCP_ENDPOINT` checks the state and owner
    /// too). Unknown types are valid.
    fn net_is_valid(&self) -> Result<bool>;
    /// python `_TCP_ENDPOINT.get_local_address()`.
    fn get_local_address(&self) -> Result<Option<String>>;
    /// python `_TCP_ENDPOINT.get_remote_address()`.
    fn get_remote_address(&self) -> Result<Option<String>>;
    /// python `_LOCAL_ADDRESS.inaddr` / `_LOCAL_ADDRESS_WIN10_UDP.inaddr` property.
    fn inaddr(&self) -> Result<Obj>;
}

impl NetExt for Obj {
    fn get_address_family(&self) -> Result<Option<i128>> {
        catch(self.m("InetAF").and_then(|p| p.deref()).and_then(|a| a.m("AddressFamily")).and_then(|f| f.int()))
    }

    fn get_owner(&self) -> Result<Option<Obj>> {
        catch(self.m("Owner").and_then(|p| p.deref()))
    }

    fn get_owner_pid(&self) -> Result<Option<i128>> {
        let Some(owner) = self.get_owner()? else { return Ok(None) };
        if owner.is_valid() && owner.has_valid_member("UniqueProcessId") {
            return Ok(Some(owner.m("UniqueProcessId")?.int()?));
        }
        Ok(None)
    }

    fn get_owner_procname(&self) -> Result<Option<String>> {
        let Some(owner) = self.get_owner()? else { return Ok(None) };
        if owner.is_valid() && owner.has_valid_member("ImageFileName") {
            return Ok(Some(owner.image_file_name_str()?));
        }
        Ok(None)
    }

    fn net_create_time(&self) -> Result<Option<Value>> {
        let v = wintime_to_datetime(self.path("CreateTime.QuadPart")?.int()?);
        Ok(match v {
            Value::DateTime(d) => {
                let y = year(&d);
                if MIN_CREATETIME_YEAR < y && y < MAX_CREATETIME_YEAR { Some(v) } else { None }
            }
            absent => Some(absent),
        })
    }

    fn get_in_addr(&self) -> Result<Option<Obj>> {
        let r = (|| -> Result<Option<Obj>> {
            let local_addr = self.m("LocalAddr")?.deref()?;
            // `_ = local_addr.pData.dereference().addr4[0]` (a pointer target is read and
            // dereferenced by python's Pointer.__getattr__)
            let target = local_addr.m("pData")?.deref()?;
            target.m("addr4")?.at(0)?.int()?;
            // `if local_addr.pData.dereference():` -- structs are always truthy
            if target.is_pointer() && target.int()? == 0 {
                return Ok(None);
            }
            Ok(Some(local_addr.inaddr()?))
        })();
        match r {
            Ok(v) => Ok(v),
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn dual_stack_sockets(&self) -> Result<Vec<(&'static str, String, &'static str)>> {
        let mut out = Vec::with_capacity(2);
        match self.get_in_addr()? {
            Some(inaddr) => match self.get_address_family()? {
                Some(AF_INET) => out.push(("v4", in_addr_string(&inaddr, Family::V4)?, INADDR_ANY)),
                Some(AF_INET6) => out.push(("v6", in_addr_string(&inaddr, Family::V6)?, INADDR6_ANY)),
                _ => {}
            },
            None => {
                out.push(("v4", INADDR_ANY.to_string(), INADDR_ANY));
                if self.get_address_family()? == Some(AF_INET6) {
                    out.push(("v6", INADDR6_ANY.to_string(), INADDR6_ANY));
                }
            }
        }
        Ok(out)
    }

    fn net_is_valid(&self) -> Result<bool> {
        match self.struct_name() {
            Some("_TCP_ENDPOINT") => tcp_endpoint_is_valid(self),
            Some("_TCP_LISTENER") | Some("_UDP_ENDPOINT") => Ok(matches!(self.get_address_family()?, Some(AF_INET) | Some(AF_INET6))),
            _ => Ok(true),
        }
    }

    fn get_local_address(&self) -> Result<Option<String>> {
        let r = (|| -> Result<String> {
            let inaddr = self.m("AddrInfo")?.deref()?.m("Local")?.m("pData")?.deref()?.deref()?;
            self.ipv4_or_ipv6(&inaddr)
        })();
        catch(r)
    }

    fn get_remote_address(&self) -> Result<Option<String>> {
        let r = (|| -> Result<String> {
            let inaddr = self.m("AddrInfo")?.deref()?.m("Remote")?.deref()?;
            self.ipv4_or_ipv6(&inaddr)
        })();
        catch(r)
    }

    fn inaddr(&self) -> Result<Obj> {
        match self.struct_name() {
            Some("_LOCAL_ADDRESS") => self.m("pData")?.deref()?.deref(),
            Some("_LOCAL_ADDRESS_WIN10_UDP") if has_win10_udp_class(self.table()) => self.m("pData")?.deref(),
            _ => Err(Error::Symbol(format!("AttributeError: StructType has no attribute: {}.inaddr", self.type_name()))),
        }
    }
}

/// python `_TCP_ENDPOINT._ipv4_or_ipv6(inaddr)` (anything but AF_INET is formatted as IPv6).
trait Ipv4OrIpv6 {
    fn ipv4_or_ipv6(&self, inaddr: &Obj) -> Result<String>;
}

impl Ipv4OrIpv6 for Obj {
    fn ipv4_or_ipv6(&self, inaddr: &Obj) -> Result<String> {
        if self.get_address_family()? == Some(AF_INET) { in_addr_string(inaddr, Family::V4) } else { in_addr_string(inaddr, Family::V6) }
    }
}

/// python `_TCP_ENDPOINT.is_valid()`.
fn tcp_endpoint_is_valid(o: &Obj) -> Result<bool> {
    let state = o.m("State")?;
    let v = match state.int() {
        Ok(v) => v,
        Err(e) if e.is_invalid_address() => return Ok(false),
        Err(e) => return Err(e),
    };
    // `state not in state.choices.values()`
    let valid_choice = match state.ty {
        Ty::Enum(i) => state.table().enum_lookup(i, v).is_some(),
        _ => true,
    };
    if !valid_choice {
        return Ok(false);
    }
    let r = (|| -> Result<bool> {
        if !matches!(o.get_address_family()?, Some(AF_INET) | Some(AF_INET6)) {
            return Ok(false);
        }
        if o.get_local_address()?.is_none() {
            let bad_owner = match o.get_owner()? {
                None => true,
                Some(owner) => {
                    let pid = owner.m("UniqueProcessId")?.int()?;
                    pid == 0 || pid > 65535
                }
            };
            if bad_owner {
                return Ok(false);
            }
        }
        Ok(true)
    })();
    match r {
        Ok(v) => Ok(v),
        Err(e) if e.is_invalid_address() => Ok(false),
        Err(e) => Err(e),
    }
}

/// python `is_valid()` for the network classes as a plain bool (errors python would raise are
/// treated as invalid); used by [`WinExt::is_valid`]'s dispatch.
pub fn is_valid(o: &Obj) -> bool {
    o.net_is_valid().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(hex: &str) -> String {
        let mut b = [0u8; 16];
        for i in 0..16 {
            b[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        inet_ntop6(&b)
    }

    // expected strings from python 3 `socket.inet_ntop(socket.AF_INET6, bytes.fromhex(...))`
    // on glibc
    #[test]
    fn ntop6_matches_glibc() {
        let cases = [
            ("00000000000000000000000000000000", "::"),
            ("00000000000000000000000000000001", "::1"),
            ("fe80000000000000c50d519f96a4e108", "fe80::c50d:519f:96a4:e108"),
            ("00000000000000000000ffff7f000001", "::ffff:127.0.0.1"),
            ("0000000000000000000000000a000001", "::10.0.0.1"),
            ("00000000000000000000fffe7f000001", "::fffe:7f00:1"),
            ("00000000000000000001ffff7f000001", "::1:ffff:7f00:1"),
            ("00000000000000000000ffff00000000", "::ffff:0.0.0.0"),
            ("00000000000000000000000000010000", "::0.1.0.0"),
            ("00010000000000010000000000010001", "1::1:0:0:1:1"),
            ("00000000000000000000000000000100", "::100"),
            ("00010000000000000000000000000000", "1::"),
            ("00010000000100000000000000000001", "1:0:1::1"),
            ("00010000000000010000000000000001", "1:0:0:1::1"),
            ("00010000000000000001000000000001", "1::1:0:0:1"),
            ("20010db8000000000001000000000001", "2001:db8::1:0:0:1"),
            ("20010db8000100010001000100010001", "2001:db8:1:1:1:1:1:1"),
            ("20010db8000000010001000100010001", "2001:db8:0:1:1:1:1:1"),
            ("ffffffffffffffffffffffffffffffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            ("00000001000000000000000000000000", "0:1::"),
            ("0000000000000000000000000000ffff", "::ffff"),
            ("000000000000000000000000ffff0000", "::255.255.0.0"),
            ("00000000000000000000000001020304", "::1.2.3.4"),
            ("00000000000000000000ffff01020304", "::ffff:1.2.3.4"),
            ("00010000000000000000ffff01020304", "1::ffff:102:304"),
            ("0000000000000000000100000a000001", "::1:0:a00:1"),
            ("abcd00000000abcd0000000000000000", "abcd:0:0:abcd::"),
            ("abcd0000abcd00000000abcd00000000", "abcd:0:abcd::abcd:0:0"),
        ];
        for (hex, want) in cases {
            assert_eq!(v6(hex), want, "{hex}");
        }
    }

    #[test]
    fn ntop4_and_errors() {
        assert_eq!(inet_ntop4(&[10, 0, 2, 15]), "10.0.2.15");
        assert_eq!(inet_ntop4(&[0, 0, 0, 0]), INADDR_ANY);
        assert_eq!(inet_ntop(Family::V6, &[0; 16]).unwrap(), INADDR6_ANY);
        assert!(inet_ntop(Family::V4, &[0; 3]).is_err());
        assert!(inet_ntop(Family::V6, &[0; 4]).is_err());
    }
}
