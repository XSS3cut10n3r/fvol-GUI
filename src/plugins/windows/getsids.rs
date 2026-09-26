//! windows.getsids.GetSIDs (python `plugins/windows/getsids.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::Result;
use crate::layers::registry::is_invalid_or_registry;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::windows::registry::hivelist::list_hives;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::prelude::*;
use crate::symbols::windows::registry::{RegData, RegExt, is_key_error, is_value_error};
use crate::util::FxHashMap;

pub struct GetSIDs;

/// python `repr(bytes)` (what `str()` of a `bytes` subclass such as `MultiTypeData` gives).
pub fn py_bytes_repr(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') { b'"' } else { b'\'' };
    let mut s = String::with_capacity(b.len() + 3);
    s.push('b');
    s.push(quote as char);
    for &c in b {
        match c {
            b'\\' => s.push_str("\\\\"),
            b'\t' => s.push_str("\\t"),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            _ if c == quote => {
                s.push('\\');
                s.push(c as char);
            }
            0x20..=0x7e => s.push(c as char),
            _ => s.push_str(&format!("\\x{c:02x}")),
        }
    }
    s.push(quote as char);
    s
}

/// python `GetSIDs.lookup_user_sids()`: {SID: user name} from the software hive's ProfileList
/// (`ProfileImagePath` basename, computed through python's `str(MultiTypeData)` quirk).
fn lookup_user_sids(ctx: &Context, k: &WinKernel) -> Result<FxHashMap<String, String>> {
    const KEY: &str = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    const VAL: &str = "ProfileImagePath";
    let mut sids = FxHashMap::default();
    for hive in list_hives(ctx, k, Some("config\\software"), None) {
        let hive = hive?;
        let r = (|| -> Result<()> {
            let key = hive.get_key_node(KEY)?;
            for subkey in key.get_subkeys() {
                let subkey = subkey?;
                let sid = match subkey.get_name() {
                    Ok(s) => s,
                    Err(e) if is_invalid_or_registry(&e) => continue,
                    Err(e) => return Err(e),
                };
                for node in subkey.get_values() {
                    let name = match node.get_name() {
                        Ok(n) if n.is_empty() => "(Default)".to_string(),
                        Ok(n) => n,
                        Err(e) if is_invalid_or_registry(&e) => continue,
                        Err(e) => return Err(e),
                    };
                    // python wraps the data in MultiTypeData (reading node.Type for bytes)
                    let data = match node.decode_data() {
                        Ok(RegData::Int(v)) => Ok(v.to_string().into_bytes()),
                        Ok(RegData::Bytes(b)) => node.get_value_type().map(|_| b),
                        Err(e) => Err(e),
                    };
                    let data = match data {
                        Ok(b) => b,
                        Err(e) if is_value_error(&e) || is_invalid_or_registry(&e) => continue,
                        Err(e) => return Err(e),
                    };
                    if name == VAL {
                        let s = py_bytes_repr(&data).replace("\\x00", "");
                        let mut path = s.as_str();
                        if let Some((i, _)) = path.char_indices().last() {
                            path = &path[..i];
                        }
                        sids.insert(sid.clone(), super::modules::ntpath_basename(path).to_string());
                    }
                }
            }
            Ok(())
        })();
        match r {
            Ok(()) => {}
            Err(e) if is_key_error(&e) || is_invalid_or_registry(&e) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(sids)
}

/// Rows of one process (a trailing Err = python raised there).
fn proc_rows(task: &Obj, user_sids: &FxHashMap<String, String>) -> Vec<Result<Vec<Value>>> {
    let r = (|| -> Result<Vec<Result<Vec<Value>>>> {
        let token = match task.m("Token").and_then(|t| t.fast_ref_dereference()) {
            Ok(t) => Some(t.cast("_TOKEN")?),
            Err(e) if e.is_invalid_address() => None,
            Err(e) => return Err(e),
        };
        let task_name = array_to_string(&task.m("ImageFileName")?, None)?;
        let Some(token) = token else {
            return Ok(vec![Ok(vec![
                Value::Int(task.m("UniqueProcessId")?.int()?),
                Value::Str(task_name),
                Value::SStr("Token unreadable"),
                Value::SStr(""),
            ])]);
        };
        let d = super::sids::data();
        let mut rows = Vec::new();
        let sids = token.get_sids()?;
        if sids.is_empty() {
            return Ok(rows);
        }
        let pid = task.m("UniqueProcessId")?.int()?;
        for sid in sids {
            let name = if let Some(n) = d.well_known.get(&sid) {
                Value::Str(n.clone())
            } else if let Some(n) = d.service_sids.get(&sid) {
                Value::Str(n.clone())
            } else if let Some(n) = user_sids.get(&sid) {
                Value::Str(n.clone())
            } else {
                match super::sids::find_sid_re(&sid) {
                    Some(n) => Value::Str(n.to_string()),
                    None => Value::NotAvailable,
                }
            };
            rows.push(Ok(vec![Value::Int(pid), Value::Str(task_name.clone()), Value::Str(sid), name]));
        }
        Ok(rows)
    })();
    match r {
        Ok(rows) => rows,
        Err(e) => vec![Err(e)],
    }
}

impl Plugin for GetSIDs {
    fn name(&self) -> &'static str {
        "windows.getsids.GetSIDs"
    }
    fn description(&self) -> &'static str {
        "Print the SIDs owning each process"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("SID", ColType::Str),
            Column::new("Name", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let pids = cfg.get_ints("pid");
        let filter = super::pslist::pid_filter(&pids);
        let procs = super::pslist::list_processes(k, &filter);
        // python: the generator starts with lookup_user_sids(), before the first process
        let user_sids = lookup_user_sids(ctx, k)?;
        let per_proc = crate::util::par::par_map(procs.len(), |i| match &procs[i] {
            Ok(p) => proc_rows(p, &user_sids),
            Err(_) => Vec::new(),
        });
        for (p, rows) in procs.into_iter().zip(per_proc) {
            p?;
            for r in rows {
                out.row(0, r?)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bytes_repr() {
        assert_eq!(py_bytes_repr(b"C\x00:\x00\\\x00"), "b'C\\x00:\\x00\\\\\\x00'");
        assert_eq!(py_bytes_repr(b"a'b"), "b\"a'b\"");
        assert_eq!(py_bytes_repr(b"a'\"b"), "b'a\\'\"b'");
        assert_eq!(py_bytes_repr(b"\t\n\r\x7f\xe9"), "b'\\t\\n\\r\\x7f\\xe9'");
    }
}
