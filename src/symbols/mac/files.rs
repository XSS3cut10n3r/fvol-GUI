//! python `MacUtilities.files_descriptors_for_process` (open file descriptors of a `proc`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use super::MacExt;
use crate::error::{Error, Result};
use crate::objects::Obj;

/// One yielded `(f, path, fd_num)`.
#[derive(Clone, Debug)]
pub struct FdEntry {
    /// The `fileproc *` pointer object (python `f`; member access dereferences).
    pub fileproc: Obj,
    /// The path: the vnode's full path, `<socket>`, `<pipe>`, ...; for a file whose type is
    /// unknown (python `get_fg_type()` returned None) the value left over from the previous
    /// descriptor (a python local-variable quirk).
    pub path: String,
    /// The descriptor number.
    pub fd: u64,
}

/// A python builtin exception (not a volatility exception): the plugin would crash with a
/// traceback. Plugins pass the errors of [`files_descriptors_for_process`] through
/// [`raise_python`] to get python's behaviour.
pub fn py_builtin(kind: &str, msg: &str) -> Error {
    Error::Msg(format!("{kind}: {msg}"))
}

/// python's reaction to an error that escaped the generator: builtin exceptions made by
/// [`py_builtin`] (ValueError from an enumeration lookup, UnboundLocalError) crash the plugin
/// -- panic, which the CLI reports like python's uncaught exception (traceback, exit 1, rows
/// so far kept) -- while volatility exceptions are returned for the usual error report.
pub fn raise_python(e: Error) -> Error {
    if let Error::Msg(m) = &e {
        if m.starts_with("ValueError: ") || m.starts_with("UnboundLocalError: ") || m.starts_with("IndexError: ") {
            panic!("{m}");
        }
    }
    e
}

/// python `fileglob.get_fg_type()` via `f.f_fglob`, with python's ValueError for enumeration
/// values outside the choices turned into a [`py_builtin`] error.
pub fn fileproc_fg_type(f: &Obj) -> Result<Option<String>> {
    let fg = f.m("f_fglob")?.deref()?;
    match fg.get_fg_type() {
        Err(Error::Msg(m)) if m.contains("enumeration") => Err(py_builtin("ValueError", &m)),
        r => r,
    }
}

/// python `MacUtilities.files_descriptors_for_process(context, symbol_table_name, task)` for
/// a `proc` (or `proc *`). Items in python's order; a trailing `Err` means python raised there
/// (see [`raise_python`]).
pub fn files_descriptors_for_process(task: &Obj) -> Vec<Result<FdEntry>> {
    let mut out = Vec::new();
    let read_int = |member: &str| -> Result<i128> {
        match task.m("p_fd").and_then(|fd| fd.m(member)).and_then(|v| v.int()) {
            Ok(v) => Ok(v),
            Err(e) if e.is_invalid_address() => Ok(1024),
            Err(e) => Err(e),
        }
    };
    let mut num_fds = match read_int("fd_lastfile") {
        Ok(v) => v,
        Err(e) => return vec![Err(e)],
    };
    let nfiles = match read_int("fd_nfiles") {
        Ok(v) => v,
        Err(e) => return vec![Err(e)],
    };
    if nfiles > num_fds {
        num_fds = nfiles;
    }
    if num_fds > 4096 {
        num_fds = 1024;
    }
    // table_addr = task.p_fd.fd_ofiles.dereference(): a `fileproc *` object at the table
    // address, constructed (read) by python
    let table = match task.m("p_fd").and_then(|fd| fd.m("fd_ofiles")).and_then(|p| p.deref()).and_then(|t| t.u64().map(|_| t)) {
        Ok(t) => t,
        Err(e) if e.is_invalid_address() => return out,
        Err(e) => return vec![Err(e)],
    };
    let count = num_fds.clamp(0, u32::MAX as i128) as u64;
    let psize = table.size();
    let native_mask = table.sp.native.address_mask();
    // one read for the whole table when possible (python reads each pointer as it iterates;
    // the first unreadable one raises out of the generator)
    let mut buf = vec![0u8; (count * psize) as usize];
    let whole = (psize == 8 || psize == 4) && table.layer().read(table.addr, &mut buf).is_ok();
    let mut path: Option<String> = None;
    for fd in 0..count {
        let f = table.at_addr(table.addr.wrapping_add(fd * psize));
        let value = if whole {
            let o = (fd * psize) as usize;
            let mut b = [0u8; 8];
            b[..psize as usize].copy_from_slice(&buf[o..o + psize as usize]);
            u64::from_le_bytes(b) & native_mask
        } else {
            match f.u64() {
                Ok(v) => v,
                Err(e) => {
                    out.push(Err(e));
                    return out;
                }
            }
        };
        if value == 0 {
            continue;
        }
        let ftype = match fileproc_fg_type(&f) {
            Ok(t) => t,
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => {
                out.push(Err(e));
                return out;
            }
        };
        match ftype.as_deref() {
            Some("VNODE") => {
                let p = f
                    .m("f_fglob")
                    .and_then(|g| g.m("fg_data"))
                    .and_then(|d| d.deref())
                    .and_then(|v| v.cast("vnode"))
                    .and_then(|v| v.full_path());
                match p {
                    Ok(p) => path = Some(p),
                    Err(e) => {
                        out.push(Err(e));
                        return out;
                    }
                }
            }
            Some(t) => path = Some(format!("<{}>", t.to_lowercase())),
            None => {}
        }
        match &path {
            Some(p) => out.push(Ok(FdEntry { fileproc: f, path: p.clone(), fd })),
            None => {
                out.push(Err(py_builtin("UnboundLocalError", "cannot access local variable 'path' where it is not associated with a value")));
                return out;
            }
        }
    }
    out
}
