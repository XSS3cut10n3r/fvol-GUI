//! windows.strings.Strings (python `plugins/windows/strings.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! python's reverse map (`generate_mapping`) is a dict of *sets* of `(name, offset)` tuples.
//! Kernel entries are keyed by physical page and carry the virtual start of the mapped run;
//! process entries are (python quirk, reproduced) keyed by the VIRTUAL start page of each run
//! and carry its physical start. A result with several entries is printed in python set order,
//! which depends on `str` hashes and is therefore random per python process; this port uses
//! the order python produces with `PYTHONHASHSEED=0` (see `util::pyset`).
//!
//! Only the pages named in the strings file are materialized (python builds the full map).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::Layer;
use crate::objects::LayerRef;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::store::IsfLocation;
use crate::symbols::windows::WinExt;
use crate::util::FxHashMap;
use crate::util::pyset::{PySet, py_hash_int, py_hash_str_seed0, py_hash_tuple};

pub struct Strings;

#[inline]
fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// python `Strings._parse_line(line)`: `re.search(rb"^(?:\W*)([0-9]+)(?:\W*)(\w[\w\W]+)\n?",
/// line)` with the engine's backtracking order. Returns (offset digits, string).
pub fn parse_line(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = line.len();
    // \W* is greedy and a digit is a word char: the digits start at the first word char
    let a = line.iter().position(|&b| is_word(b))?;
    let maxd = line[a..].iter().take_while(|b| b.is_ascii_digit()).count();
    for d in (1..=maxd).rev() {
        let p = a + d;
        let w = line[p..].iter().take_while(|&&b| !is_word(b)).count();
        let pos = p + w;
        // \w then [\w\W]+ (greedy to the end of the line, the trailing \n? matches empty)
        if pos + 2 <= len {
            return Some((&line[a..a + d], &line[pos..]));
        }
    }
    None
}

/// python `int(digits)` (None if it does not fit 128 bits).
fn parse_int(d: &[u8]) -> Option<u128> {
    d.iter().try_fold(0u128, |acc, &b| acc.checked_mul(10)?.checked_add((b - b'0') as u128))
}

/// Interned tuple names (`"kernel"`, `"Process <pid>"`) with their python hashes.
struct Names {
    names: Vec<(String, u64)>,
    index: FxHashMap<String, u32>,
}

impl Names {
    fn id(&mut self, s: String) -> u32 {
        if let Some(&i) = self.index.get(&s) {
            return i;
        }
        let i = self.names.len() as u32;
        let h = py_hash_str_seed0(&s);
        self.index.insert(s.clone(), i);
        self.names.push((s, h));
        i
    }
}

/// The part of python's `generate_mapping` reverse map that the queried pages need.
struct RevMap {
    /// sorted, unique queried page numbers
    keys: Vec<u64>,
    sets: Vec<PySet<(u32, u64)>>,
    names: Names,
}

impl RevMap {
    fn add(&mut self, slot: usize, name: u32, off: u64) {
        let h = py_hash_tuple(&[self.names.names[name as usize].1, py_hash_int(off as i128)]);
        self.sets[slot].add(h, (name, off));
    }
    /// Slots of the queried keys in `[lo, hi)`.
    fn range(&self, lo: u64, hi: u64) -> std::ops::Range<usize> {
        let a = self.keys.partition_point(|&k| k < lo);
        let b = self.keys.partition_point(|&k| k < hi);
        a..b.max(a)
    }
}

/// Coalesced runs of `layer.mapping(0, len, ignore_errors=True)` (any target layer).
fn runs(layer: &dyn Layer, len: u64) -> Vec<(u64, u64, u64)> {
    let mut v = Vec::new();
    layer.mapping_targets(0, len, &mut |m, _| {
        v.push((m.offset, m.len, m.mapped));
        true
    });
    v
}

fn generate_mapping(ctx: &Context, pids: &[i128], keys: Vec<u64>) -> Result<RevMap> {
    let k = ctx.windows_kernel()?;
    let n = keys.len();
    let mut rm = RevMap { keys, sets: (0..n).map(|_| PySet::new()).collect(), names: Names { names: Vec::new(), index: FxHashMap::default() } };
    let kernel = rm.names.id("kernel".to_string());
    // kernel: every page of every run, keyed by its physical page
    for (offset, len, mapped) in runs(k.vlayer, k.vlayer.max_address()) {
        let first = mapped >> 12;
        let count = len.div_ceil(0x1000);
        for slot in rm.range(first, first.saturating_add(count)) {
            rm.add(slot, kernel, offset);
        }
    }
    let Some(&max_key) = rm.keys.last() else { return Ok(rm) };
    // processes: one entry per run, keyed by the run's virtual start page; only runs starting
    // below the highest queried page can matter
    let filter = super::pslist::pid_filter(pids);
    let procs = super::pslist::list_processes(k, &|_| Ok(false));
    let mut todo: Vec<Option<(u64, LayerRef)>> = Vec::with_capacity(procs.len());
    for p in &procs {
        let proc = match p {
            Ok(p) => p,
            Err(_) => break,
        };
        if filter(proc)? {
            todo.push(None);
            continue;
        }
        match proc.m("UniqueProcessId").and_then(|p| p.u64()).and_then(|pid| Ok((pid, proc.add_process_layer()?))) {
            Ok(v) => todo.push(Some(v)),
            Err(e) if e.is_invalid_address() => todo.push(None),
            Err(e) => return Err(e),
        }
    }
    let bound = (max_key.saturating_add(1)).saturating_mul(0x1000);
    let keys = &rm.keys;
    let found: Vec<Vec<(usize, u64)>> = crate::util::par::par_map(todo.len(), |i| {
        let Some((_, layer)) = todo[i] else { return Vec::new() };
        let len = bound.min(layer.max_address());
        runs(layer, len)
            .into_iter()
            .filter_map(|(offset, _, mapped)| keys.binary_search(&(offset >> 12)).ok().map(|slot| (slot, mapped)))
            .collect()
    });
    for (t, f) in todo.iter().zip(found) {
        let Some((pid, _)) = t else { continue };
        if f.is_empty() {
            continue;
        }
        let name = rm.names.id(format!("Process {pid}"));
        for (slot, mapped) in f {
            rm.add(slot, name, mapped);
        }
    }
    // an error while listing processes surfaces after the processes before it (python raises
    // mid-generator)
    for p in procs {
        p?;
    }
    Ok(rm)
}

impl Plugin for Strings {
    fn name(&self) -> &'static str {
        "windows.strings.Strings"
    }
    fn description(&self) -> &'static str {
        "Reads output from the strings command and indicates which process(es) each string belongs to."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Process ID to include (all other processes are excluded)", ReqKind::ListInt).optional(),
            Requirement::new("strings_file", "Strings file", ReqKind::Uri),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("String", ColType::Str),
            Column::new("Physical Address", ColType::Hex),
            Column::new("Result", ColType::Str),
        ])?;
        let url = cfg.get_str("strings_file").ok_or_else(|| Error::msg("strings_file is required"))?;
        let data = IsfLocation::Url(url.to_string()).read().map_err(|e| crate::util::paths::resource_error(url, e))?;
        // python: readline() loop, unparsable lines are logged (stderr) and skipped
        let mut lines: Vec<(u128, &[u8])> = Vec::new();
        let mut rest: &[u8] = &data;
        while !rest.is_empty() {
            let end = rest.iter().position(|&b| b == b'\n').map(|i| i + 1).unwrap_or(rest.len());
            let (line, r) = rest.split_at(end);
            rest = r;
            if let Some((d, s)) = parse_line(line) {
                if let Some(off) = parse_int(d) {
                    lines.push((off, s));
                }
            }
        }
        let mut keys: Vec<u64> = lines.iter().filter_map(|(o, _)| u64::try_from(o >> 12).ok()).collect();
        keys.sort_unstable();
        keys.dedup();
        let pids = cfg.get_ints("pid");
        let rm = generate_mapping(ctx, &pids, keys)?;
        // pages can be mapped hundreds of thousands of times: render each page's list once
        let mut rendered: Vec<Option<String>> = vec![None; rm.keys.len()];
        for (off, s) in lines {
            let slot = u64::try_from(off >> 12).ok().and_then(|k| rm.keys.binary_search(&k).ok()).filter(|&i| !rm.sets[i].is_empty());
            let result = match slot {
                Some(i) => rendered[i]
                    .get_or_insert_with(|| {
                        use std::fmt::Write;
                        let mut r = String::new();
                        for (j, &(n, o)) in rm.sets[i].iter().enumerate() {
                            if j > 0 {
                                r.push_str(", ");
                            }
                            let _ = write!(r, "{}:{:#x}", rm.names.names[n as usize].0, o);
                        }
                        r
                    })
                    .clone(),
                None => "FREE MEMORY".to_string(),
            };
            let string: String = s.iter().map(|&b| b as char).collect();
            out.row(0, vec![Value::Str(string), Value::Int(off as i128), Value::Str(result)])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse() {
        assert_eq!(parse_line(b"  123 hello\n"), Some((&b"123"[..], &b"hello\n"[..])));
        assert_eq!(parse_line(b"123\n"), Some((&b"12"[..], &b"3\n"[..])));
        assert_eq!(parse_line(b"123"), Some((&b"1"[..], &b"23"[..])));
        assert_eq!(parse_line(b"12"), None);
        assert_eq!(parse_line(b"1"), None);
        assert_eq!(parse_line(b"abc 12"), None);
        assert_eq!(parse_line(b"5 a"), None);
        assert_eq!(parse_line(b"5 a\n"), Some((&b"5"[..], &b"a\n"[..])));
        assert_eq!(parse_line(b"  77 !! x_y z"), Some((&b"77"[..], &b"x_y z"[..])));
        assert_eq!(parse_line(b"\n"), None);
    }
}
