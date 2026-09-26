//! windows.registry.printkey.PrintKey (python `plugins/windows/registry/printkey.py`), plus
//! python's reusable `PrintKey.key_iterator` ([`key_iterator`]).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::Layer;
use crate::layers::registry::{RegistryHive, is_invalid_or_registry, registry_format};
use crate::objects::Obj;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, Encoding, RowSink, Value};
use crate::symbols::windows::registry::{RegData, RegExt, RegValueType, is_key_error, is_value_error};

pub struct PrintKey;

/// One item of python `PrintKey.key_iterator`: `(depth, is_key, last_write_time, key_path,
/// volatile, node)`.
pub struct KeyIterItem<'a> {
    pub depth: usize,
    pub is_key: bool,
    /// The LastWriteTime of the key being listed (python `last_write_time`).
    pub last_write_time: &'a Value,
    pub key_path: &'a str,
    pub volatile: bool,
    pub node: Obj,
}

/// python `PrintKey.key_iterator(hive, node_path, recurse)` as a visitor: `f` gets every item
/// in python's order and returns `Ok(false)` to stop. An `Err` is where python raised (from the
/// walk or from `f`).
pub fn key_iterator(hive: &'static RegistryHive, node_path: &[Obj], recurse: bool, f: &mut dyn FnMut(KeyIterItem) -> Result<bool>) -> Result<bool> {
    let node_path: Vec<Obj> = if node_path.is_empty() { vec![hive.get_node(hive.root_cell_offset())] } else { node_path.to_vec() };
    let mut names = vec![hive.get_name().to_string()];
    for k in &node_path[1..] {
        names.push(match k.get_name() {
            Ok(n) => n,
            Err(e) if is_invalid_or_registry(&e) => "-".to_string(),
            Err(e) => return Err(e),
        });
    }
    let key_path = names.join("\\");
    let mut node_path = node_path;
    walk(hive, &mut node_path, &key_path, recurse, f)
}

fn walk(hive: &'static RegistryHive, node_path: &mut Vec<Obj>, key_path: &str, recurse: bool, f: &mut dyn FnMut(KeyIterItem) -> Result<bool>) -> Result<bool> {
    let node = *node_path.last().unwrap();
    if node.ty == hive.types.cell_data {
        return Err(registry_format(hive.name(), "Encountered _CELL_DATA instead of _CM_KEY_NODE"));
    }
    if node_path.len() > 990 {
        return Err(Error::msg("RecursionError: maximum recursion depth exceeded"));
    }
    let lwt = node.last_write_time()?;
    let depth = node_path.len();
    for sub in node.get_subkeys() {
        let key_node = sub?;
        let item = KeyIterItem { depth, is_key: true, last_write_time: &lwt, key_path, volatile: key_node.get_volatile()?, node: key_node };
        if !f(item)? {
            return Ok(false);
        }
        if recurse && !node_path.iter().any(|x| x.addr == key_node.addr) {
            let name = match key_node.get_name() {
                Ok(n) => n,
                Err(e) if is_invalid_or_registry(&e) => continue,
                Err(e) => return Err(e),
            };
            let sub_path = format!("{key_path}\\{name}");
            node_path.push(key_node);
            let go = walk(hive, node_path, &sub_path, recurse, f);
            node_path.pop();
            if !go? {
                return Ok(false);
            }
        }
    }
    let volatile = node.get_volatile()?;
    for value_node in node.get_values() {
        if !f(KeyIterItem { depth, is_key: false, last_write_time: &lwt, key_path, volatile, node: value_node })? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// python `_printkey_iterator` row for one `key_iterator` item.
fn printkey_row(hive: &RegistryHive, it: &KeyIterItem) -> Result<Vec<Value>> {
    let hive_off = Value::Int(hive.hive_offset() as i128);
    if it.is_key {
        let name = match it.node.get_name() {
            Ok(n) => Value::Str(n),
            Err(e) if is_invalid_or_registry(&e) => Value::Unreadable,
            Err(e) => return Err(e),
        };
        let lwt = it.node.last_write_time()?;
        return Ok(vec![lwt, hive_off, Value::SStr("Key"), Value::Str(it.key_path.to_string()), name, Value::NotApplicable, Value::Bool(it.volatile)]);
    }
    let name = match it.node.get_name() {
        Ok(n) if n.is_empty() => Value::SStr("(Default)"),
        Ok(n) => Value::Str(n),
        Err(e) if is_invalid_or_registry(&e) => Value::Unreadable,
        Err(e) => return Err(e),
    };
    let (vtype, data) = match it.node.get_value_type() {
        Ok(t) => (Value::SStr(t.name()), value_data(&it.node, t)?),
        Err(e) if is_invalid_or_registry(&e) => (Value::Unreadable, Value::Unreadable),
        Err(e) => return Err(e),
    };
    Ok(vec![it.last_write_time.clone(), hive_off, vtype, Value::Str(it.key_path.to_string()), name, data, Value::Bool(it.volatile)])
}

/// python printkey's `format_hints.MultiTypeData` wrapping of `decode_data()`.
pub fn value_data(node: &Obj, t: RegValueType) -> Result<Value> {
    match node.decode_data() {
        Ok(RegData::Int(i)) => Ok(Value::MultiTypeData { data: i.to_string().into_bytes(), encoding: Encoding::Utf8, split_nulls: false, show_hex: false, converted_int: true }),
        Ok(RegData::Bytes(b)) => Ok(match t {
            RegValueType::Binary => Value::MultiTypeData { data: b, encoding: Encoding::Utf16Le, split_nulls: false, show_hex: true, converted_int: false },
            RegValueType::MultiSz => Value::MultiTypeData { data: b, encoding: Encoding::Utf16Le, split_nulls: true, show_hex: false, converted_int: false },
            _ => Value::MultiTypeData { data: b, encoding: Encoding::Utf16Le, split_nulls: false, show_hex: false, converted_int: false },
        }),
        Err(e) if is_value_error(&e) || is_invalid_or_registry(&e) => Ok(Value::Unreadable),
        Err(e) => Err(e),
    }
}

/// Rows of one hive (python `_registry_walker` body): `(depth, row)`, then `Err` if python
/// raised an exception it does not catch.
fn hive_rows(hive: &'static RegistryHive, key: Option<&str>, recurse: bool) -> (Vec<(usize, Vec<Value>)>, Option<Error>) {
    let mut rows = Vec::new();
    let r = (|| -> Result<()> {
        let node_path = match key {
            Some(k) => hive.get_key(k)?,
            None => vec![hive.get_node(hive.root_cell_offset())],
        };
        let base = node_path.len();
        key_iterator(hive, &node_path, recurse, &mut |it| {
            let row = printkey_row(hive, &it)?;
            rows.push((it.depth - base, row));
            Ok(true)
        })?;
        Ok(())
    })();
    match r {
        Ok(()) => (rows, None),
        Err(e) if e.is_invalid_address() || is_key_error(&e) || crate::layers::registry::is_registry_exception(&e) => {
            rows.push((
                0,
                vec![
                    Value::Unreadable,
                    Value::Int(hive.hive_offset() as i128),
                    Value::SStr("Key"),
                    Value::Str(format!("{}\\{}", hive.get_name(), key.unwrap_or(""))),
                    Value::Unreadable,
                    Value::Unreadable,
                    Value::Unreadable,
                ],
            ));
            (rows, None)
        }
        Err(e) => (rows, Some(e)),
    }
}

impl Plugin for PrintKey {
    fn name(&self) -> &'static str {
        "windows.registry.printkey.PrintKey"
    }
    fn description(&self) -> &'static str {
        "Lists the registry keys under a hive or specific key value."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("offset", "Hive Offset", ReqKind::Int).optional(),
            Requirement::new("key", "Key to start from", ReqKind::Str).optional(),
            Requirement::flag("recurse", "Recurses through keys"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Last Write Time", ColType::DateTime),
            Column::new("Hive Offset", ColType::Hex),
            Column::new("Type", ColType::Str),
            Column::new("Key", ColType::Str),
            Column::new("Name", ColType::Str),
            Column::new("Data", ColType::MultiTypeData),
            Column::new("Volatile", ColType::Bool),
        ])?;
        let k = ctx.windows_kernel()?;
        let offset = cfg.get_int("offset").map(|o| o as u64);
        let offsets = offset.map(|o| vec![o]);
        let key = cfg.get_str("key");
        let recurse = cfg.get_bool("recurse");
        let hives = super::hivelist::list_hives(ctx, k, None, offsets.as_deref());
        // hives are independent: walk them in parallel, emit in python's order
        let per_hive = crate::util::par::par_map(hives.len(), |i| match &hives[i] {
            Ok(h) => Some(hive_rows(h, key, recurse)),
            Err(_) => None,
        });
        for (h, rows) in hives.into_iter().zip(per_hive) {
            h?;
            let (rows, err) = rows.unwrap_or_default();
            for (d, r) in rows {
                out.row(d, r)?;
            }
            if let Some(e) = err {
                return Err(e);
            }
        }
        Ok(())
    }
}
