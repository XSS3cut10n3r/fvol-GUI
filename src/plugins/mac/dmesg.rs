//! mac.dmesg.Dmesg (python `plugins/mac/dmesg.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::mac::MacKernel;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::objects::util::pointer_to_string;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};

pub struct Dmesg;

/// python `str.splitlines()` (no keepends): splits on \n, \r, \r\n, \v, \f, \x1c, \x1d, \x1e,
/// \x85,  ,  ; no trailing empty line.
pub fn py_splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        let brk = matches!(c, '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}');
        if brk {
            out.push(&s[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' {
                if let Some(&(_, '\n')) = it.peek() {
                    it.next();
                    end += 1;
                }
            }
            start = end;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// Byte offset of python code-point index `idx` (python slice semantics: negative counts from
/// the end, clamped to `0..=len`).
fn char_boundary(s: &str, idx: i128) -> usize {
    let n = s.chars().count() as i128;
    let i = if idx < 0 { (n + idx).max(0) } else { idx.min(n) };
    s.char_indices().nth(i as usize).map(|(b, _)| b).unwrap_or(s.len())
}

/// python `Dmesg.get_kernel_log_buffer(context, kernel_module_name)`: the kernel log lines.
pub fn get_kernel_log_buffer(k: &MacKernel) -> Result<Vec<String>> {
    if !k.has_symbol("msgbufp") {
        return Err(Error::Symbol(format!(
            "{}!msgbufp: The provided symbol table does not include the \"msgbufp\" symbol. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt.",
            k.table.name()
        )));
    }
    let msgbufp = k.object_from_symbol("msgbufp")?;
    let msg_size = msgbufp.m("msg_size")?.int()?;
    let msg_bufx = msgbufp.m("msg_bufx")?.int()?;
    let msg_bufc = msgbufp.m("msg_bufc")?;
    msg_bufc.u64()?; // python constructs (reads) the pointer here
    if msg_size < 1 {
        // python: ValueError("Count must be greater than 0") from address_to_string
        panic!("ValueError: Count must be greater than 0");
    }
    let data = pointer_to_string(&msg_bufc, msg_size as u64)?;
    let msg_bufx = if msg_bufx <= msg_size { msg_bufx } else { 0 };
    let split = char_boundary(&data, msg_bufx);
    let mut dmesg = String::with_capacity(data.len());
    dmesg.push_str(&data[split..]);
    dmesg.push_str(&data[..split]);
    Ok(py_splitlines(&dmesg).into_iter().map(|l| l.to_string()).collect())
}

impl Plugin for Dmesg {
    fn name(&self) -> &'static str {
        "mac.dmesg.Dmesg"
    }
    fn description(&self) -> &'static str {
        "Prints the kernel log buffer."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![Column::new("line", ColType::Str)])?;
        for line in get_kernel_log_buffer(k)? {
            out.row(0, vec![Value::Str(line)])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitlines() {
        assert_eq!(py_splitlines("a\nb\r\nc\rd\x0be\u{2028}f\n"), vec!["a", "b", "c", "d", "e", "f"]);
        assert_eq!(py_splitlines("\n\nx"), vec!["", "", "x"]);
        assert!(py_splitlines("").is_empty());
    }

    #[test]
    fn slicing() {
        assert_eq!(char_boundary("aé b", 2), 3);
        assert_eq!(char_boundary("abc", -1), 2);
        assert_eq!(char_boundary("abc", 10), 3);
        assert_eq!(char_boundary("abc", -10), 0);
    }
}
