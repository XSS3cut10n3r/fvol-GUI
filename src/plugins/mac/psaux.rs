//! mac.psaux.Psaux (python `plugins/mac/psaux.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! python quirk, reproduced: the argument cursor advances by `len(str(arg)) + 1`, where
//! `str(arg)` is the python REPR of the bytes object (`b'...'` with escapes), not its length.

use crate::context::Context;
use crate::error::Result;
use crate::objects::{LayerRef, Obj};
use crate::objects::util::array_to_string;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::MacExt;

pub struct Psaux;

/// `len(repr(b))` for a python bytes object (CPython `bytes_repr`): `b''` plus 1 per printable
/// byte, 2 for `\\ \t \n \r` (and for `'` when the repr uses single quotes, i.e. when the data
/// holds both quote kinds), 4 (`\xHH`) for other bytes < 0x20 or >= 0x7f.
pub fn py_bytes_repr_len(b: &[u8]) -> usize {
    let (mut n, mut squotes, mut dquotes) = (3usize, 0usize, 0usize);
    for &c in b {
        n += match c {
            b'\'' => {
                squotes += 1;
                1
            }
            b'"' => {
                dquotes += 1;
                1
            }
            b'\\' | b'\t' | b'\n' | b'\r' => 2,
            c if !(0x20..0x7f).contains(&c) => 4,
            _ => 1,
        };
    }
    // smart quotes: `"` delimits when there are single but no double quotes; otherwise every
    // single quote is escaped
    if squotes > 0 && dquotes > 0 {
        n += squotes;
    }
    n
}

/// python's alignment loop: `while pos < limit: read 1 byte (stop if unreadable or not NUL);
/// pos += 1`, returning the final `pos`. Reads a page at a time (validity is per page; a
/// failing piece is re-done byte by byte), so a huge garbage `p_argslen` over zeroed memory
/// costs page reads instead of one read per byte.
fn skip_nuls(layer: LayerRef, mut pos: i128, limit: i128) -> i128 {
    let mut buf = [0u8; 0x1000];
    while pos < limit {
        let page_left = 0x1000 - (pos as u64 & 0xfff) as i128;
        let n = page_left.min(limit - pos) as usize;
        match layer.read(pos as u64, &mut buf[..n]) {
            Ok(()) => match buf[..n].iter().position(|&c| c != 0) {
                Some(i) => return pos + i as i128,
                None => pos += n as i128,
            },
            Err(_) => {
                let mut check = [0u8; 1];
                while pos < limit {
                    if layer.read(pos as u64, &mut check).is_err() || check[0] != 0 {
                        return pos;
                    }
                    pos += 1;
                }
            }
        }
    }
    pos
}

/// One task's row, `None` where python `continue`s.
fn task_row(task: &Obj) -> Result<Option<Vec<Value>>> {
    let Some(layer) = task.add_process_layer()? else { return Ok(None) };
    let user_stack = task.m("user_stack")?.int()?;
    let argslen = task.m("p_argslen")?.int()?;
    // python ints: may go negative (the layer masks the address like python's does)
    let mut argsstart: i128 = user_stack - argslen;
    if !layer.is_valid(argsstart as u64, 1) || argslen == 0 {
        return Ok(None);
    }
    let p_argc = task.m("p_argc")?.int()?;
    if p_argc == 0 {
        return Ok(None);
    }
    // "Add one because the first two are usually duplicates"
    let mut argc = p_argc + 1;
    if argc > 1024 {
        return Ok(None);
    }
    let task_name = array_to_string(&task.m("p_comm")?, None)?;
    let mut args: Vec<Vec<u8>> = Vec::new();
    let mut buf = [0u8; 256];
    while argc > 0 {
        if layer.read(argsstart as u64, &mut buf).is_err() {
            break;
        }
        let arg = match buf.iter().position(|&c| c == 0) {
            Some(i) => &buf[..i],
            None => &buf[..],
        };
        argsstart += py_bytes_repr_len(arg) as i128 + 1;
        if args.is_empty() {
            // skip the alignment NULs
            argsstart = skip_nuls(layer, argsstart, user_stack);
            args.push(arg.to_vec());
        } else if arg != args[0].as_slice() {
            args.push(arg.to_vec());
        }
        argc -= 1;
    }
    let mut args_str = String::new();
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            args_str.push(' ');
        }
        args_str.push_str(&String::from_utf8_lossy(a));
    }
    let pid = task.m("p_pid")?.int()?;
    Ok(Some(vec![Value::Int(pid), Value::Str(task_name), Value::Int(p_argc), Value::Str(args_str)]))
}

impl Plugin for Psaux {
    fn name(&self) -> &'static str {
        "mac.psaux.Psaux"
    }
    fn description(&self) -> &'static str {
        "Recovers program command line arguments."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Argc", ColType::Int),
            Column::new("Arguments", ColType::Str),
        ])?;
        let pids = cfg.get_ints("pid");
        let filter = super::pslist::pid_filter(&pids);
        let tasks = super::pslist::list_tasks(k, "tasks", &filter);
        // per task in parallel, rows formatted on the workers, emitted in python's order
        crate::plugins::emit_par_blocks(out, tasks, |t, b| {
            if let Some(r) = task_row(t)? {
                b.push(r);
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{py_bytes_repr_len, skip_nuls};
    use crate::error::{Error, Result};
    use crate::layers::{Layer, Mapping};
    use crate::objects::leak_layer;
    use std::sync::Arc;

    /// 3 pages; the middle one is unreadable.
    struct Mem(Vec<u8>);
    impl Layer for Mem {
        fn name(&self) -> &str {
            "m1a_psaux_mem"
        }
        fn max_address(&self) -> u64 {
            (1 << 48) - 1
        }
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let a = addr as usize;
            let end = a + buf.len();
            if end > self.0.len() || (a < 0x2000 && end > 0x1000) {
                return Err(Error::invalid(addr));
            }
            buf.copy_from_slice(&self.0[a..end]);
            Ok(())
        }
        fn is_valid(&self, addr: u64, len: u64) -> bool {
            let mut b = vec![0u8; len as usize];
            self.read(addr, &mut b).is_ok()
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
            f(Mapping { offset: addr, len, mapped: addr });
        }
    }

    #[test]
    fn nul_skipping_matches_byte_loop() {
        let mut m = vec![0u8; 0x3000];
        m[0x800] = 7;
        m[0x2100] = 9;
        let l = leak_layer(Arc::new(Mem(m)));
        // the python loop, byte by byte
        let slow = |mut pos: i128, limit: i128| {
            let mut c = [0u8; 1];
            while pos < limit {
                if l.read(pos as u64, &mut c).is_err() || c[0] != 0 {
                    break;
                }
                pos += 1;
            }
            pos
        };
        for (start, limit) in [(0x10, 0x3000), (0x801, 0x3000), (0x801, 0x900), (0x2000, 0x3000), (0x2101, 0x3000), (0x2101, 0x2101), (0x2200, 0x2100), (0xfff, 0x1800)] {
            assert_eq!(skip_nuls(l, start, limit), slow(start, limit), "{start:#x}..{limit:#x}");
        }
    }

    #[test]
    fn bytes_repr_len_matches_python() {
        // len(str(b)) computed with CPython 3.14
        assert_eq!(py_bytes_repr_len(b""), 3);
        assert_eq!(py_bytes_repr_len(b"/usr/libexec/xpcd"), 20);
        assert_eq!(py_bytes_repr_len(b"a'b"), 6); // b"a'b"
        assert_eq!(py_bytes_repr_len(b"a'b\""), 8); // b'a\'b"'
        assert_eq!(py_bytes_repr_len(b"''\""), 8); // b'\'\'"'
        assert_eq!(py_bytes_repr_len(b"a\"b"), 6); // b'a"b'
        assert_eq!(py_bytes_repr_len(b"\\\t\n\r"), 11);
        assert_eq!(py_bytes_repr_len(b"\x00\x1f\x7f\x80\xff "), 3 + 5 * 4 + 1);
    }
}
