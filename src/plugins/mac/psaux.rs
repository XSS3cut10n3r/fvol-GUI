//! mac.psaux.Psaux (python `plugins/mac/psaux.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! python quirk, reproduced: the argument cursor advances by `len(str(arg)) + 1`, where
//! `str(arg)` is the python REPR of the bytes object (`b'...'` with escapes), not its length.

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
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
            let mut check = [0u8; 1];
            while argsstart < user_stack {
                if layer.read(argsstart as u64, &mut check).is_err() || check[0] != 0 {
                    break;
                }
                argsstart += 1;
            }
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
        let rows = crate::util::par::par_map(tasks.len(), |i| match &tasks[i] {
            Ok(t) => task_row(t),
            Err(_) => Ok(None),
        });
        for (task, row) in tasks.into_iter().zip(rows) {
            task?;
            if let Some(r) = row? {
                out.row(0, r)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::py_bytes_repr_len;

    #[test]
    fn bytes_repr_len_matches_python() {
        // len(str(b)) computed with CPython 3.14
        assert_eq!(py_bytes_repr_len(b""), 3);
        assert_eq!(py_bytes_repr_len(b"/usr/libexec/xpcd"), 20);
        assert_eq!(py_bytes_repr_len(b"a'b"), 6); // b"a'b"
        assert_eq!(py_bytes_repr_len(b"a'b\""), 9); // b'a\'b"'
        assert_eq!(py_bytes_repr_len(b"a\"b"), 6); // b'a"b'
        assert_eq!(py_bytes_repr_len(b"\\\t\n\r"), 11);
        assert_eq!(py_bytes_repr_len(b"\x00\x1f\x7f\x80\xff "), 3 + 5 * 4 + 1);
    }
}
