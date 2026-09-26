//! windows.netstat.NetStat (python `plugins/windows/netstat.py`): network objects found by
//! walking tcpip.sys's tracking structures (the TCP endpoint `PartitionTable`, then the TCP and
//! UDP port pools' bitmaps and assignment lists), plus python's reusable classmethods
//! ([`get_tcpip_module`], [`list_sockets`], [`parse_partitions`], [`parse_hashtable`],
//! [`find_port_pools`], [`parse_bitmap`], [`enumerate_structures_by_port`]).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::layers::LayerExt;
use crate::objects::{LayerRef, Obj, Space};
use crate::plugins::windows::modules::list_modules;
use crate::plugins::windows::netscan::{INCLUDE_CORRUPT_DESC, columns, create_netscan_symbol_table, emit_rows, timeline_event};
use crate::plugins::{Config, Plugin, Requirement, TimelineEvent};
use crate::renderers::{RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::windows::WinExt;
use crate::util::FxHashSet;

pub struct NetStat;

/// python `NetStat._decode_pointer(value)`.
#[inline]
fn decode_pointer(v: u64) -> u64 {
    v & 0xFFFF_FFFF_FFFF_FFFC
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

/// python `NetStat.parse_bitmap(context, layer_name, bitmap_offset, bitmap_size_in_byte)`:
/// the indices of the set bits (unreadable bytes are skipped; more than 81920 bytes = broken).
pub fn parse_bitmap(layer: LayerRef, bitmap_offset: u64, bitmap_size_in_byte: u64) -> Vec<u32> {
    let mut ret = Vec::new();
    if bitmap_size_in_byte > 8192 * 10 {
        return ret;
    }
    // unreadable bytes contribute no bits, exactly like python skipping them
    let data = layer.read_vec_padded(bitmap_offset, bitmap_size_in_byte as usize);
    for (idx, &b) in data.iter().enumerate() {
        let mut b = b;
        while b != 0 {
            let bit = b.trailing_zeros();
            ret.push(idx as u32 * 8 + bit);
            b &= b - 1;
        }
    }
    ret
}

/// python `NetStat.enumerate_structures_by_port(context, layer_name, net_symbol_table, port,
/// port_pool_addr, proto)`: the `_TCP_LISTENER`s (`udp` = false) or `_UDP_ENDPOINT`s assigned
/// to `port`, pushed to `out`. `Err` = python raised (after the objects already pushed).
pub fn enumerate_structures_by_port(sp: &'static Space, net: TableRef, port: u32, port_pool_addr: u64, udp: bool, out: &mut Vec<Obj>) -> Result<()> {
    let obj_name = if udp { "_UDP_ENDPOINT" } else { "_TCP_LISTENER" };
    let obj_ty = net.get_type(obj_name)?;
    let ptr_offset = net.offset_of(obj_name, "Next")?;
    let list_index = (port >> 8) as u64;
    let truncated_port = (port & 0xff) as u64;
    let assignment = catch((|| -> Result<Obj> {
        let port_pool = Obj::named(sp, "_INET_PORT_POOL", port_pool_addr)?;
        let inpa = port_pool.m("PortAssignments")?.at(list_index)?;
        // reading the array element (a pointer) happens on creation in python
        inpa.int()?;
        inpa.m("InPaBigPoolBase")?.m("Assignments")?.at(truncated_port)
    })())?;
    // `if not assignment` -- a struct is always truthy
    let Some(assignment) = assignment else { return Ok(()) };
    let Some(entry) = catch(assignment.m("Entry").and_then(|e| e.u64()))? else { return Ok(()) };
    let netw_inside = decode_pointer(entry);
    if netw_inside == 0 {
        return Ok(());
    }
    let mut curr = Obj::new(sp, obj_ty, netw_inside.wrapping_sub(ptr_offset));
    out.push(curr);
    let Some(next) = catch(curr.m("Next").and_then(|n| n.u64()))? else { return Ok(()) };
    let mut next_obj_address = decode_pointer(next);
    // python follows `Next` until it is NULL; a cycle would make python loop forever, we stop
    let mut seen = FxHashSet::default();
    seen.insert(curr.addr);
    while next_obj_address != 0 {
        curr = Obj::new(sp, obj_ty, next_obj_address.wrapping_sub(ptr_offset));
        if !seen.insert(curr.addr) {
            break;
        }
        out.push(curr);
        let Some(next) = catch(curr.m("Next").and_then(|n| n.u64()))? else { return Ok(()) };
        next_obj_address = decode_pointer(next);
    }
    Ok(())
}

/// python `NetStat.get_tcpip_module(context, kernel_module_name)`: the tcpip.sys loader entry.
pub fn get_tcpip_module(k: &WinKernel) -> Result<Option<Obj>> {
    for m in list_modules(k) {
        let m = m?;
        if m.m("BaseDllName")?.get_string()? == "tcpip.sys" {
            return Ok(Some(m));
        }
    }
    Ok(None)
}

/// python `NetStat.parse_hashtable(context, layer_name, ht_offset, ht_length, alignment,
/// net_symbol_table)`: the pointers of a hash table's buckets that do not point to themselves.
pub fn parse_hashtable(sp: &'static Space, net: TableRef, ht_offset: u64, ht_length: u64, alignment: u64, out: &mut Vec<u64>) -> Result<()> {
    if ht_length > 4096 {
        return Ok(());
    }
    let ptr_ty = net.get_type("pointer")?;
    for index in 0..ht_length {
        let current = Obj::new(sp, ptr_ty, ht_offset.wrapping_add(index.wrapping_mul(alignment)));
        let Some(v) = catch(current.u64())? else { continue };
        if current.addr == v {
            continue;
        }
        out.push(v);
    }
    Ok(())
}

/// python `NetStat.parse_partitions(context, layer_name, net_symbol_table, tcpip_symbol_table,
/// tcpip_module_offset)`: the `_TCP_ENDPOINT`s of tcpip.sys's `PartitionTable`, pushed to `out`.
pub fn parse_partitions(sp: &'static Space, net: TableRef, tcpip: TableRef, tcpip_module_offset: u64, out: &mut Vec<Obj>) -> Result<()> {
    let alignment = if net.is_64bit() { 0x10 } else { 8 };
    let obj_ty = net.get_type("_TCP_ENDPOINT")?;
    let part_table_symbol = tcpip.get_symbol("PartitionTable")?.address;
    let part_count_symbol = tcpip.get_symbol("PartitionCount")?.address;
    let ptr_ty = net.get_type("pointer")?;
    let Some(part_table_addr) = catch(Obj::new(sp, ptr_ty, tcpip_module_offset.wrapping_add(part_table_symbol)).u64())? else { return Ok(()) };
    let part_table = Obj::named(sp, "_PARTITION_TABLE", part_table_addr)?;
    let Some(part_count) = catch(sp.layer.read_u8(tcpip_module_offset.wrapping_add(part_count_symbol)))? else { return Ok(()) };
    let partitions = part_table.m("Partitions")?.with_count(part_count as u64);
    let entry_offset = net.offset_of("_TCP_ENDPOINT", "ListEntry")?;
    let mut entries = Vec::new();
    for i in 0..partitions.count() {
        let partition = partitions.at(i)?;
        let Some(num_entries) = catch(partition.m("Endpoints").and_then(|e| e.m("NumEntries")).and_then(|n| n.int()))? else { continue };
        if num_entries > 0 {
            let endpoints = partition.m("Endpoints")?;
            let directory = endpoints.m("Directory")?.u64()?;
            let table_size = endpoints.m("TableSize")?.u64()?;
            entries.clear();
            parse_hashtable(sp, net, directory, table_size, alignment, &mut entries)?;
            for &e in &entries {
                out.push(Obj::new(sp, obj_ty, e.wrapping_sub(entry_offset)));
            }
        }
    }
    Ok(())
}

/// python `NetStat.find_port_pools(context, layer_name, net_symbol_table, tcpip_symbol_table,
/// tcpip_module_offset)`: (UDP port pool address, TCP port pool address).
pub fn find_port_pools(sp: &'static Space, net: TableRef, tcpip: TableRef, tcpip_module_offset: u64) -> Result<(u64, u64)> {
    let ptr_ty = net.get_type("pointer")?;
    let read_ptr = |sym: &str| -> Result<u64> { Obj::new(sp, ptr_ty, tcpip_module_offset.wrapping_add(tcpip.get_symbol(sym)?.address)).u64() };
    if tcpip.has_symbol("UdpPortPool") {
        let upp = read_ptr("UdpPortPool")?;
        let tpp = read_ptr("TcpPortPool")?;
        Ok((upp, tpp))
    } else if tcpip.has_symbol("UdpCompartmentSet") {
        let ucs = tcpip.get_symbol("UdpCompartmentSet")?.address;
        let tcs = tcpip.get_symbol("TcpCompartmentSet")?.address;
        let ucs_offset = Obj::new(sp, ptr_ty, tcpip_module_offset.wrapping_add(ucs)).u64()?;
        let tcs_offset = Obj::new(sp, ptr_ty, tcpip_module_offset.wrapping_add(tcs)).u64()?;
        let pool = |off: u64| -> Result<u64> { Obj::named(sp, "_INET_COMPARTMENT_SET", off)?.m("InetCompartment")?.m("ProtocolCompartment")?.m("PortPool")?.u64() };
        let upp = pool(ucs_offset)?;
        let tpp = pool(tcs_offset)?;
        Ok((upp, tpp))
    } else {
        Err(Error::Symbol(format!("Neither UdpPortPool nor UdpCompartmentSet found in {} table", tcpip.name())))
    }
}

/// python `NetStat.list_sockets(context, layer_name, nt_symbols, net_symbol_table,
/// tcpip_module_offset, tcpip_symbol_table)`: TCP endpoints from the partition table, then TCP
/// listeners and UDP endpoints by port (ascending), pushed to `out`. `Err` = python raised
/// after the objects already pushed.
pub fn list_sockets(layer: LayerRef, net: TableRef, tcpip_module_offset: u64, tcpip: TableRef, out: &mut Vec<Obj>) -> Result<()> {
    let sp = Space::on(layer, net);
    parse_partitions(sp, net, tcpip, tcpip_module_offset, out)?;
    let (upp_addr, tpp_addr) = match find_port_pools(sp, net, tcpip, tcpip_module_offset) {
        Ok(v) => v,
        // python logs "Unable to reconstruct port pools" and then uses the unbound names
        Err(e) if e.is_invalid_address() || matches!(e, Error::Symbol(_)) => {
            return Err(Error::msg("UnboundLocalError: cannot access local variable 'upp_addr' where it is not associated with a value"));
        }
        Err(e) => return Err(e),
    };
    let bitmap = |addr: u64| -> Result<Vec<u32>> {
        let bm = Obj::named(sp, "_INET_PORT_POOL", addr)?.m("PortBitMap")?;
        let buffer = bm.m("Buffer")?.u64()?;
        let size = bm.m("SizeOfBitMap")?.u64()?;
        Ok(parse_bitmap(layer, buffer, size / 8))
    };
    let udpa_ports = bitmap(upp_addr)?;
    let tcpl_ports = bitmap(tpp_addr)?;
    for port in tcpl_ports {
        if port == 0 {
            continue;
        }
        enumerate_structures_by_port(sp, net, port, tpp_addr, false, out)?;
    }
    for port in udpa_ports {
        if port == 0 {
            continue;
        }
        enumerate_structures_by_port(sp, net, port, upp_addr, true, out)?;
    }
    Ok(())
}

/// python `NetStat._generator(show_corrupt_results)`.
fn rows(ctx: &Context, show_corrupt: bool, out: &mut dyn FnMut(Vec<Value>) -> Result<()>) -> Result<()> {
    let k = ctx.windows_kernel()?;
    let net = create_netscan_symbol_table(ctx, k)?;
    let tcpip_module = get_tcpip_module(k)?;
    // python: vollog.error(...) then `tcpip_module.DllBase` on None raises AttributeError
    let Some(tcpip_module) = tcpip_module else {
        return Err(Error::msg("AttributeError: 'NoneType' object has no attribute 'DllBase'"));
    };
    // everything python catches as a VolatilityException (incl. InvalidAddressException)
    let found = (|| -> Result<(u64, TableRef)> {
        let base = tcpip_module.m("DllBase")?.u64()?;
        let size = tcpip_module.m("SizeOfImage")?.u64()?;
        Ok((base, ctx.symbol_table_from_pdb(k.vlayer, "tcpip.pdb", Some(base), Some(size))?))
    })();
    let Ok((base, tcpip)) = found else { return Ok(()) };
    let mut objs = Vec::new();
    let tail = list_sockets(k.vlayer, net, base, tcpip, &mut objs).err();
    emit_rows(&objs, tail, show_corrupt, true, out)
}

impl Plugin for NetStat {
    fn name(&self) -> &'static str {
        "windows.netstat.NetStat"
    }
    fn description(&self) -> &'static str {
        "Traverses network tracking structures present in a particular windows memory image."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::flag("include-corrupt", INCLUDE_CORRUPT_DESC)]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(columns())?;
        rows(ctx, cfg.get_bool("include-corrupt"), &mut |r| out.row(0, r))
    }
    fn timeline(&self, ctx: &Context, _cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        // python's generate_timeline calls _generator() without show_corrupt_results; absent
        // values are formatted with str() ("-")
        let mut ev = Vec::new();
        let r = rows(ctx, false, &mut |r| {
            ev.extend(timeline_event(&r, "-"));
            Ok(())
        });
        Some(r.map(|_| ev))
    }
}
