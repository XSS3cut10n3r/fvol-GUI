//! mac.bash.Bash (python `plugins/mac/bash.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! For `bash`/`sh`/`dash` processes: scan the heap (python `get_process_memory_sections(...,
//! rw_no_file=True)`) for `#`, then for pointers to those `#`s, and validate a bash
//! `hist_entry` (linux `bash32`/`bash64` ISF) around each hit.

use crate::context::Context;
use crate::error::Result;
use crate::layers::scan::{BytesScanner, MultiStringScanner, scan};
use crate::objects::util::array_to_string;
use crate::objects::{Obj, Space};
use crate::plugins::{Config, Plugin, ReqKind, Requirement, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::mac::MacExt;
use crate::symbols::mac::vm::{MacVmExt, scan_sections};
use std::cmp::Ordering;

pub struct Bash;

// TODO(dedupe): owned by L1 (symbols/linux/bash) -- python `symbols/linux/extensions/bash.py`
// `hist_entry` class extension, minimal private port.
mod hist_entry {
    use super::PyInt;
    use crate::error::Result;
    use crate::objects::Obj;
    use crate::objects::util::array_to_string;
    use crate::renderers::Value;

    fn timestamp(h: &Obj) -> Result<String> {
        array_to_string(&h.m("timestamp")?.deref()?, None)
    }

    /// python `hist_entry.get_command()`.
    pub fn get_command(h: &Obj) -> Result<String> {
        array_to_string(&h.m("line")?.deref()?, None)
    }

    /// python `hist_entry.is_valid()` (`Err` = a non-InvalidAddress exception python raises).
    pub fn is_valid(h: &Obj) -> Result<bool> {
        let (cmd, ts) = match get_command(h).and_then(|c| timestamp(h).map(|t| (c, t))) {
            Ok(v) => v,
            Err(e) if e.is_invalid_address() => return Ok(false),
            Err(e) => return Err(e),
        };
        if cmd.is_empty() || ts.is_empty() {
            return Ok(false);
        }
        let mut chars = ts.chars();
        if ts.chars().count() < 10 || chars.next() != Some('#') {
            return Ok(false);
        }
        Ok(PyInt::parse(chars.as_str()).is_some())
    }

    /// python `hist_entry.get_time_as_integer()` (only called on valid entries).
    pub fn get_time_as_integer(h: &Obj) -> Result<PyInt> {
        let ts = timestamp(h)?;
        let mut chars = ts.chars();
        chars.next();
        // python raises ValueError here; unreachable for entries that passed is_valid()
        Ok(PyInt::parse(chars.as_str()).unwrap_or_else(|| panic!("ValueError: invalid literal for int() with base 10: {:?}", chars.as_str())))
    }

    /// python `hist_entry.get_time_object()`: `conversion.unixtime_to_datetime(...)`.
    pub fn get_time_object(h: &Obj) -> Result<Value> {
        Ok(crate::util::time::unixtime_to_datetime(get_time_as_integer(h)?.saturating_i128()))
    }
}

/// An arbitrary-precision python int as parsed by `int(str)` (base 10), ordered like python.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PyInt {
    neg: bool,
    /// ASCII decimal digits without leading zeros (empty = 0)
    digits: Vec<u8>,
}

/// Zero code points of the Unicode decimal digit runs (`unicodedata.decimal`, Unicode 16.0 as
/// in python 3.14): python `int()` accepts any of them as digits.
const DECIMAL_ZEROS: [u32; 76] = [
    0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66, 0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0,
    0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0, 0xff10, 0x104a0,
    0x10d30, 0x10d40, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0, 0x11650, 0x116c0, 0x116d0, 0x116da, 0x11730, 0x118e0, 0x11950,
    0x11bf0, 0x11c50, 0x11d50, 0x11da0, 0x11f50, 0x16130, 0x16a60, 0x16ac0, 0x16b50, 0x16d70, 0x1ccf0, 0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6,
    0x1e140, 0x1e2f0, 0x1e4f0, 0x1e5f1, 0x1e950, 0x1fbf0,
];

/// Non-ASCII characters python's `str.isspace()` accepts.
const UNICODE_SPACES: [u32; 19] =
    [0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000];

impl PyInt {
    /// python `int(s)` for a str (CPython `_PyUnicode_TransformDecimalAndSpaceToASCII` then
    /// `PyLong_FromString(base=10)`); `None` = ValueError.
    pub fn parse(s: &str) -> Option<PyInt> {
        let mut ascii: Vec<u8> = Vec::with_capacity(s.len());
        for c in s.chars() {
            let u = c as u32;
            if u < 127 {
                ascii.push(u as u8);
            } else if UNICODE_SPACES.contains(&u) {
                ascii.push(b' ');
            } else {
                let i = DECIMAL_ZEROS.partition_point(|&z| z <= u);
                match i.checked_sub(1).map(|i| DECIMAL_ZEROS[i]) {
                    Some(z) if u - z < 10 => ascii.push(b'0' + (u - z) as u8),
                    _ => return None,
                }
            }
        }
        let is_ws = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
        let start = ascii.iter().position(|c| !is_ws(c))?;
        let end = ascii.iter().rposition(|c| !is_ws(c))? + 1;
        let mut t = &ascii[start..end];
        let neg = match t.first() {
            Some(b'-') => {
                t = &t[1..];
                true
            }
            Some(b'+') => {
                t = &t[1..];
                false
            }
            _ => false,
        };
        if t.is_empty() || !t[0].is_ascii_digit() || !t[t.len() - 1].is_ascii_digit() {
            return None;
        }
        let mut digits = Vec::with_capacity(t.len());
        let mut prev_us = false;
        for &c in t {
            if c == b'_' {
                if prev_us {
                    return None;
                }
                prev_us = true;
                continue;
            }
            if !c.is_ascii_digit() {
                return None;
            }
            prev_us = false;
            if !(digits.is_empty() && c == b'0') {
                digits.push(c);
            }
        }
        Some(PyInt { neg: neg && !digits.is_empty(), digits })
    }

    /// The value, saturated to the i128 range.
    pub fn saturating_i128(&self) -> i128 {
        let mut v: i128 = 0;
        for &d in &self.digits {
            v = v.saturating_mul(10).saturating_add((d - b'0') as i128);
        }
        if self.neg { -v } else { v }
    }
}

impl Ord for PyInt {
    fn cmp(&self, other: &Self) -> Ordering {
        let mag = || self.digits.len().cmp(&other.digits.len()).then_with(|| self.digits.cmp(&other.digits));
        match (self.neg, other.neg) {
            (false, false) => mag(),
            (true, true) => mag().reverse(),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
        }
    }
}

impl PartialOrd for PyInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// python `Bash._generator` rows: (pid, task name, CommandTime, Command). The rows of one task
/// are computed together; tasks run in parallel and are emitted in python order through `emit`
/// (`Ok(false)` stops). A returned `Err` is where python raised.
fn generate(ctx: &Context, cfg: &Config, emit: &mut dyn FnMut(Vec<Value>) -> Result<bool>) -> Result<()> {
    let k = ctx.mac_kernel()?;
    let is_32bit = !k.table.is_64bit();
    let bash_table = ctx.load_isf(if is_32bit { "linux/bash32" } else { "linux/bash64" })?;
    let ts_offset = bash_table.offset_of("hist_entry", "timestamp")?;
    let pids = cfg.get_ints("pid");
    let filter = super::pslist::pid_filter(&pids);
    let tasks = super::pslist::list_tasks(k, "tasks", &filter);
    // python passes the kernel MODULE name as the table name (see symbols::mac::vm)
    const CONFIG_KERNEL: &str = "kernel";
    let task_rows = |task: &Obj| -> Result<Vec<Vec<Value>>> {
        let task_name = array_to_string(&task.m("p_comm")?, None)?;
        if !matches!(task_name.as_str(), "bash" | "sh" | "dash") {
            return Ok(Vec::new());
        }
        let Some(layer) = task.add_process_layer()? else { return Ok(Vec::new()) };
        let sections = scan_sections(&task.get_process_memory_sections(CONFIG_KERNEL, true)?);
        let bang_addrs: Vec<Vec<u8>> = scan(layer, &BytesScanner::new(b"#"), Some(&sections))
            .into_iter()
            .map(|a| {
                if is_32bit {
                    let a = u32::try_from(a).unwrap_or_else(|_| panic!("struct.error: 'I' format requires 0 <= number <= 4294967295"));
                    a.to_le_bytes().to_vec()
                } else {
                    a.to_le_bytes().to_vec()
                }
            })
            .collect();
        // python computes the sections again for the second scan (same result)
        let sp = Space::on(layer, bash_table);
        let mut history: Vec<(PyInt, Obj)> = Vec::new();
        for (address, _) in scan(layer, &MultiStringScanner::new(&bang_addrs), Some(&sections)) {
            let hist = Obj::named(sp, "hist_entry", address.wrapping_sub(ts_offset))?;
            if hist_entry::is_valid(&hist)? {
                history.push((hist_entry::get_time_as_integer(&hist)?, hist));
            }
        }
        // sorted(history_entries, key=get_time_as_integer): stable
        history.sort_by(|a, b| a.0.cmp(&b.0));
        let mut rows = Vec::with_capacity(history.len());
        for (_, hist) in history {
            rows.push(vec![
                Value::Int(task.m("p_pid")?.int()?),
                Value::Str(task_name.clone()),
                hist_entry::get_time_object(&hist)?,
                Value::Str(hist_entry::get_command(&hist)?),
            ]);
        }
        Ok(rows)
    };
    let per_task = crate::util::par::par_map(tasks.len(), |i| match &tasks[i] {
        Ok(t) => task_rows(t),
        Err(_) => Ok(Vec::new()),
    });
    for (task, rows) in tasks.into_iter().zip(per_task) {
        task?;
        for r in rows? {
            if !emit(r)? {
                return Ok(());
            }
        }
    }
    Ok(())
}

impl Plugin for Bash {
    fn name(&self) -> &'static str {
        "mac.bash.Bash"
    }
    fn description(&self) -> &'static str {
        "Recovers bash command history from memory."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("CommandTime", ColType::DateTime),
            Column::new("Command", ColType::Str),
        ])?;
        generate(ctx, cfg, &mut |r| out.row(0, r).map(|_| true))
    }
    fn timeline(&self, ctx: &Context, cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        let mut ev = Vec::new();
        let r = generate(ctx, cfg, &mut |mut r| {
            let command = match r.pop() {
                Some(Value::Str(s)) => s,
                _ => String::new(),
            };
            let time = r.pop().unwrap_or(Value::NotAvailable);
            let name = match r.pop() {
                Some(Value::Str(s)) => s,
                _ => String::new(),
            };
            let pid = match r.pop() {
                Some(Value::Int(p)) => p,
                _ => 0,
            };
            ev.push(TimelineEvent { description: format!("{pid} ({name}): \"{command}\""), kind: TimeKind::Created, time });
            Ok(true)
        });
        Some(r.map(|_| ev))
    }
}

#[cfg(test)]
mod tests {
    use super::PyInt;

    fn p(s: &str) -> Option<i128> {
        PyInt::parse(s).map(|v| v.saturating_i128())
    }

    #[test]
    fn py_int_like_python() {
        assert_eq!(p("1234567890"), Some(1234567890));
        assert_eq!(p(" 12 "), Some(12));
        assert_eq!(p("13\u{85}"), Some(13));
        assert_eq!(p("13\x0b"), Some(13));
        assert_eq!(p("13\x1c"), None);
        assert_eq!(p("\u{661}\u{662}"), Some(12));
        assert_eq!(p("\u{661}_\u{662}"), Some(12));
        assert_eq!(p("+_1"), None);
        assert_eq!(p("1__2"), None);
        assert_eq!(p("1_"), None);
        assert_eq!(p("0x10"), None);
        assert_eq!(p("00012"), Some(12));
        assert_eq!(p("-0"), Some(0));
        assert_eq!(p(" - 1"), None);
        assert_eq!(p("1\x00"), None);
        assert_eq!(p(""), None);
        assert_eq!(p("-"), None);
    }

    #[test]
    fn py_int_order() {
        let mut v: Vec<PyInt> = ["5", "-3", "0", "-0", "100000000000000000000000000000000000000000000", "-100000000000000000000000000000000000000000000", "-4", "99"]
            .iter()
            .map(|s| PyInt::parse(s).unwrap())
            .collect();
        v.sort();
        let got: Vec<String> = v.iter().map(|x| format!("{}{}", if x.neg { "-" } else { "" }, String::from_utf8_lossy(&x.digits))).collect();
        assert_eq!(got, ["-100000000000000000000000000000000000000000000", "-4", "-3", "", "", "5", "99", "100000000000000000000000000000000000000000000"]);
    }
}
