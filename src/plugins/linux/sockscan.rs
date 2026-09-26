//! linux.sockscan.Sockscan (python `plugins/linux/sockscan.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Scans the memory layer below the kernel for pointers to the socket file operations
//! (`struct file.f_op`, then walks file -> dentry -> inode -> socket -> sock) and to the
//! socket destructors (`struct sock.sk_destruct`), and decodes each sock with
//! [`SockHandlers`] built for `init_task`.
//!
//! python quirks kept on purpose: the "seen" set only records destructor-path addresses (the
//! file-ops path always checks/adds `None`, so only the first file-ops socket is processed,
//! although every file-ops hit is still walked), and the "remove empty results" test checks
//! `isinstance(src, NotAvailableValue)` for both the source and the destination.

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::scan::{MultiStringScanner, scan_each};
use crate::objects::{Obj, Space};
use crate::plugins::linux::sockstat::{SockHandlers, StatVal};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::{LinuxExt, NetExt, container_of};
use crate::util::FxHashSet;

pub struct Sockscan;

/// python `_canonicalize_symbol_addrs(kernel, symbol_names)`: the packed (canonical) addresses
/// of the symbols that exist, deduplicated like python's set.
fn canonicalize_symbol_addrs(k: &LinuxKernel, names: &[&str]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for name in names {
        let Ok(o) = k.object_from_symbol(name) else { continue };
        let addr = k.layer.canonicalize(o.addr);
        let packed = if k.table.is_64bit() { addr.to_le_bytes().to_vec() } else { (addr as u32).to_le_bytes().to_vec() };
        if !out.contains(&packed) {
            out.push(packed);
        }
    }
    out
}

/// python `_walk_file_ops_needles(...)`: from a `file.f_op` hit to the `sock` on the memory
/// layer. `Ok(None)` where python returns None; `Err` where python raises (an invalid
/// `container_of` result -> AttributeError on `None.socket`).
fn walk_file_ops_needle(k: &LinuxKernel, phys_sp: &'static Space, needle_addr: u64, f_op_offset: u64) -> Result<Option<Obj>> {
    let r = (|| -> Result<Option<Obj>> {
        let pfile = Obj::named(phys_sp, "file", needle_addr.wrapping_sub(f_op_offset))?;
        let dentry = pfile.get_dentry()?;
        if dentry.u64()? == 0 {
            return Ok(None);
        }
        let d_inode = dentry.m("d_inode")?;
        let d_inode_v = d_inode.u64()?;
        if d_inode_v == 0 {
            return Ok(None);
        }
        let Some(socket_alloc) = container_of(d_inode_v, "socket_alloc", "vfs_inode", k)? else {
            return Err(Error::msg("AttributeError: 'NoneType' object has no attribute 'socket'"));
        };
        let sk = socket_alloc.m("socket")?.m("sk")?;
        if sk.u64()? == 0 {
            return Ok(None);
        }
        let vsock = sk.deref()?;
        let Some((physical, _)) = k.layer.translate_addr(vsock.addr) else { return Err(Error::invalid(vsock.addr)) };
        Ok(Some(Obj::named(phys_sp, "sock", physical)?))
    })();
    match r {
        Err(e) if e.is_invalid_address() => Ok(None),
        r => r,
    }
}

/// python `_extract_sock_fields(psock, sock_handler)`: the row of a scanned sock, `Ok(None)`
/// where python skips it.
fn extract_sock_fields(psock: &Obj, handler: &SockHandlers) -> Result<Option<Vec<Value>>> {
    let r = (|| -> Result<Option<Vec<Value>>> {
        let sock_type = psock.sock_get_type()?;
        let family = psock.get_family()?;
        let f = handler.process_sock(psock)?;
        let protocol = f.sock.get_protocol()?;
        let [src, src_port, dst, dst_port, state] = &f.stat;
        // remove empty results (python tests `isinstance(src, NotAvailableValue)` twice)
        let src_na = *src == StatVal::None;
        if (src.as_str() == Some("0.0.0.0") || src_na) && (dst.as_str() == Some("0.0.0.0") || src_na) {
            if state.as_str() == Some("UNCONNECTED") {
                return Ok(None);
            } else if src_port.as_str() == Some("0") && dst_port.as_str() == Some("0") {
                return Ok(None);
            }
        }
        Ok(Some(vec![
            Value::Int(psock.addr as i128),
            Value::Str(family),
            Value::SStr(sock_type),
            protocol.map_or(Value::NotAvailable, Value::Str),
            src.to_value(),
            src_port.to_value(),
            dst.to_value(),
            dst_port.to_value(),
            state.to_value(),
            f.filter.to_value(),
        ]))
    })();
    match r {
        Err(e) if e.is_invalid_address() => Ok(None),
        r => r,
    }
}

impl Plugin for Sockscan {
    fn name(&self) -> &'static str {
        "linux.sockscan.Sockscan"
    }
    fn description(&self) -> &'static str {
        "Scans for network connections found in memory layer."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
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
        // the memory layer below the kernel (python `kernel_layer.dependencies[0]`)
        let phys_sp = Space::get(k.phys, k.vlayer, k.table);
        let init_task = k.object_from_symbol("init_task")?;
        let handler = SockHandlers::new(&k.module, &init_task)?;

        let file_ops = canonicalize_symbol_addrs(k, &["socket_file_ops", "sockfs_dentry_operations"]);
        let f_op_offset = k.offset_of("file", "f_op")?;
        let destructors =
            canonicalize_symbol_addrs(k, &["sock_def_destruct", "packet_sock_destruct", "unix_sock_destructor", "netlink_sock_destruct", "inet_sock_destruct"]);
        let sk_destruct_offset = k.offset_of("sock", "sk_destruct")?;

        // python `socket_destructor_needles | file_ops_needles`
        let mut patterns: Vec<Vec<u8>> = destructors.clone();
        for p in &file_ops {
            if !patterns.contains(p) {
                patterns.push(p.clone());
            }
        }
        if patterns.is_empty() {
            return Ok(());
        }
        let is_destructor: Vec<bool> = patterns.iter().map(|p| destructors.contains(p)).collect();
        let is_file_ops: Vec<bool> = patterns.iter().map(|p| file_ops.contains(p)).collect();
        let scanner = MultiStringScanner::new(&patterns);

        let mut seen: FxHashSet<Option<u64>> = FxHashSet::default();
        let mut err: Option<Error> = None;
        scan_each(k.phys, &scanner, None, |(needle_addr, idx): (u64, u32)| {
            let r = (|| -> Result<()> {
                let idx = idx as usize;
                let mut psock = None;
                let mut sock_physical_addr = None;
                if is_destructor[idx] {
                    let a = needle_addr.wrapping_sub(sk_destruct_offset);
                    sock_physical_addr = Some(a);
                    psock = Some(Obj::named(phys_sp, "sock", a)?);
                }
                if is_file_ops[idx] {
                    psock = walk_file_ops_needle(k, phys_sp, needle_addr, f_op_offset)?;
                }
                if let Some(psock) = psock
                    && seen.insert(sock_physical_addr)
                    && let Some(row) = extract_sock_fields(&psock, &handler)?
                {
                    out.row(0, row)?;
                }
                Ok(())
            })();
            match r {
                Ok(()) => true,
                Err(e) => {
                    err = Some(e);
                    false
                }
            }
        });
        err.map_or(Ok(()), Err)
    }
}
