//! windows.registry.userassist.UserAssist (python `plugins/windows/registry/userassist.py`):
//! decodes UserAssist keys from the NTUSER.DAT hives.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::layers::registry::{RegistryHive, is_invalid_or_registry};
use crate::objects::Obj;
use crate::plugins::{Config, Plugin, ReqKind, Requirement, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::registry::{RegData, RegExt, is_key_error};
use crate::util::json::Json;
use std::collections::HashMap;
use std::sync::OnceLock;

pub struct UserAssist;

const USERASSIST_PATH: &str = "software\\microsoft\\windows\\currentversion\\explorer\\userassist";
const WIN7_SIZE: usize = 72;
const XP_SIZE: usize = 16;

/// The GUID -> known-folder map (python `userassist.json`).
fn folder_guids() -> &'static HashMap<String, String> {
    static M: OnceLock<HashMap<String, String>> = OnceLock::new();
    M.get_or_init(|| {
        let mut m = HashMap::new();
        if let Ok(j) = Json::parse(include_bytes!("userassist.json")) {
            if let Some(obj) = j.as_object() {
                for (k, v) in obj {
                    if let Some(s) = v.as_str() {
                        m.insert(k.to_string(), s.to_string());
                    }
                }
            }
        }
        m
    })
}

/// python `codecs.encode(s, "rot_13")`.
fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            _ => c,
        })
        .collect()
}

/// python `str(datetime.timedelta(seconds=(focus_time + 500) / 1000.0))`.
fn timedelta_str(focus_time: u32) -> String {
    let total_us: u64 = (focus_time as u64 + 500) * 1000;
    let days = total_us / 86_400_000_000;
    let mut rem = total_us % 86_400_000_000;
    let hours = rem / 3_600_000_000;
    rem %= 3_600_000_000;
    let mins = rem / 60_000_000;
    rem %= 60_000_000;
    let secs = rem / 1_000_000;
    let us = rem % 1_000_000;
    let mut s = String::new();
    if days > 0 {
        s.push_str(&format!("{days} day{}, ", if days == 1 { "" } else { "s" }));
    }
    s.push_str(&format!("{hours}:{mins:02}:{secs:02}"));
    if us > 0 {
        s.push_str(&format!(".{us:06}"));
    }
    s
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn i64le(b: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// python `parse_userassist_data(reg_val)` -> (id, count, focus, time, lastupdated) values.
/// `win7`: Some(true)=Win7+, Some(false)=XP, None=unknown OS (only raw data set).
struct UAFields {
    id: Value,
    count: Value,
    focus: Value,
    time: Value,
    lastupdated: Value,
    rawdata: Value,
}

fn hexbytes(data: Vec<u8>) -> Value {
    Value::Bytes(data)
}

fn parse_userassist(node: &Obj, win7: Option<bool>) -> Result<UAFields> {
    // defaults: python renderers.UnparsableValue()
    let mut f = UAFields {
        id: Value::Unparsable,
        count: Value::Unparsable,
        focus: Value::Unparsable,
        time: Value::Unparsable,
        lastupdated: Value::Unparsable,
        rawdata: Value::Unparsable,
    };
    let data = match node.decode_data() {
        Ok(RegData::Bytes(b)) => b,
        Ok(RegData::Int(_)) => return Ok(f),
        Err(e) => return Err(e),
    };
    f.rawdata = hexbytes(data.clone());
    let win7 = match win7 {
        Some(w) => w,
        None => return Ok(f), // OS unknown: only raw data
    };
    let size = if win7 { WIN7_SIZE } else { XP_SIZE };
    if data.len() < size {
        return Ok(f);
    }
    if win7 {
        f.id = Value::NotApplicable;
        f.count = Value::Int(u32le(&data, 4) as i128);
        let focus_time = u32le(&data, 12);
        f.time = Value::Str(timedelta_str(focus_time));
        f.focus = Value::Int(u32le(&data, 8) as i128);
        f.lastupdated = crate::util::time::wintime_to_datetime(i64le(&data, 60) as i128);
    } else {
        f.id = Value::Int(u32le(&data, 0) as i128);
        let c = u32le(&data, 4);
        f.count = Value::Int(if c < 5 { c } else { c - 5 } as i128);
        f.focus = Value::NotApplicable;
        f.time = Value::NotApplicable;
        f.lastupdated = crate::util::time::wintime_to_datetime(i64le(&data, 8) as i128);
    }
    Ok(f)
}

/// The 12-column row (matches python's yield tuple order).
type Row = (usize, Vec<Value>);

fn list_userassist(hive: &'static RegistryHive, win7: Option<bool>, rows: &mut Vec<Row>) -> Result<()> {
    let hive_off = Value::Int(hive.hive_offset() as i128);
    let hive_name = Value::Str(crate::symbols::windows::registry::cmhive_get_name(&hive.cmhive()).unwrap_or_default());
    // python list_userassist catches KeyError / RegistryException from get_key internally
    // (logs a warning to stderr) and yields nothing -> no fallback row for "key not found".
    let node_path = match hive.get_key(USERASSIST_PATH) {
        Ok(p) => p,
        Err(e) if is_key_error(&e) || crate::layers::registry::is_registry_exception(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    let userassist_node = *node_path.last().unwrap();
    for guidkey in userassist_node.get_subkeys() {
        let guidkey = guidkey?;
        for countkey in guidkey.get_subkeys() {
            let countkey = countkey?;
            let countkey_path = countkey.get_key_path()?;
            let lwt = countkey.last_write_time()?;
            // the parent Count key row (depth 0)
            rows.push((
                0,
                vec![
                    hive_off.clone(),
                    hive_name.clone(),
                    Value::Str(countkey_path.clone()),
                    lwt.clone(),
                    Value::SStr("Key"),
                    Value::NotApplicable,
                    Value::NotApplicable,
                    Value::NotApplicable,
                    Value::NotApplicable,
                    Value::NotApplicable,
                    Value::NotApplicable,
                    Value::NotApplicable,
                ],
            ));
            // subkeys (depth 1, "Subkey")
            for subkey in countkey.get_subkeys() {
                let subkey_name = match subkey {
                    Ok(s) => match s.get_name() {
                        Ok(n) => Value::Str(n),
                        Err(e) if is_invalid_or_registry(&e) => Value::Unreadable,
                        Err(e) => return Err(e),
                    },
                    Err(e) if is_invalid_or_registry(&e) => Value::Unreadable,
                    Err(e) => return Err(e),
                };
                rows.push((
                    1,
                    vec![
                        hive_off.clone(),
                        hive_name.clone(),
                        Value::Str(countkey_path.clone()),
                        lwt.clone(),
                        Value::SStr("Subkey"),
                        subkey_name,
                        Value::NotApplicable,
                        Value::NotApplicable,
                        Value::NotApplicable,
                        Value::NotApplicable,
                        Value::NotApplicable,
                        Value::NotApplicable,
                    ],
                ));
            }
            // values (depth 1, "Value")
            for value in countkey.get_values() {
                let mut value_name = match value.get_name() {
                    Ok(n) if n.is_empty() => "(Default)".to_string(),
                    Ok(n) => n,
                    Err(e) if is_invalid_or_registry(&e) => {
                        push_value_row(rows, &hive_off, &hive_name, &countkey_path, &lwt, Value::Unreadable, unparsable_fields());
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                value_name = rot13(&value_name);
                if win7 == Some(true) {
                    if let Some((guid, _)) = value_name.split_once('\\').map(|(a, b)| (a.to_string(), b)) {
                        if let Some(folder) = folder_guids().get(&guid) {
                            value_name = value_name.replacen(&guid, folder, 1);
                        }
                    } else if let Some(folder) = folder_guids().get(&value_name) {
                        value_name = folder.clone();
                    }
                }
                let f = parse_userassist(&value, win7)?;
                push_value_row(rows, &hive_off, &hive_name, &countkey_path, &lwt, Value::Str(value_name), f);
            }
        }
    }
    Ok(())
}

fn unparsable_fields() -> UAFields {
    UAFields { id: Value::Unparsable, count: Value::Unparsable, focus: Value::Unparsable, time: Value::Unparsable, lastupdated: Value::Unparsable, rawdata: Value::Unparsable }
}

fn push_value_row(rows: &mut Vec<Row>, hive_off: &Value, hive_name: &Value, path: &str, lwt: &Value, name: Value, f: UAFields) {
    rows.push((1, vec![hive_off.clone(), hive_name.clone(), Value::Str(path.to_string()), lwt.clone(), Value::SStr("Value"), name, f.id, f.count, f.focus, f.time, f.lastupdated, f.rawdata]));
}

/// python `_win7_or_later`: `_KUSER_SHARED_DATA` has member `CookiePad`. None when the type is
/// unavailable (python `SymbolError` -> `_win7` stays None).
fn win7_or_later(k: &crate::context::WinKernel) -> Option<bool> {
    if k.table.user_type("_KUSER_SHARED_DATA").is_none() {
        return None;
    }
    Some(crate::objects::Field::new(k.table, "_KUSER_SHARED_DATA", "CookiePad").is_ok())
}

/// Rows across all ntuser hives (python `_generator`). Each hive that raises the caught set
/// yields the all-Unreadable fallback row (depth 0).
fn generate(ctx: &Context, cfg: &Config) -> Result<Vec<Row>> {
    let k = ctx.windows_kernel()?;
    let win7 = win7_or_later(k);
    let offset = cfg.get_int("offset").map(|o| o as u64);
    let offsets = offset.map(|o| vec![o]);
    let mut rows = Vec::new();
    for hive in super::hivelist::list_hives(ctx, k, Some("ntuser.dat"), offsets.as_deref()) {
        let hive = hive?;
        let mut hive_rows = Vec::new();
        match list_userassist(hive, win7, &mut hive_rows) {
            Ok(()) => {
                rows.extend(hive_rows);
            }
            // python catches PagedInvalidAddressException, InvalidAddressException, KeyError;
            // then yields a fallback all-Unreadable row.
            Err(e) if e.is_invalid_address() || is_key_error(&e) => {
                rows.extend(hive_rows);
                let name = crate::symbols::windows::registry::cmhive_get_name(&hive.cmhive());
                rows.push((
                    0,
                    vec![
                        Value::Int(hive.hive_offset() as i128),
                        name.map(Value::Str).unwrap_or(Value::Unreadable),
                        Value::Unreadable,
                        Value::Unreadable,
                        Value::Unreadable,
                        Value::Unreadable,
                        Value::Unreadable,
                        Value::Unreadable,
                        Value::Unreadable,
                        Value::Unreadable,
                        Value::Unreadable,
                        Value::Unreadable,
                    ],
                ));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(rows)
}

impl Plugin for UserAssist {
    fn name(&self) -> &'static str {
        "windows.registry.userassist.UserAssist"
    }
    fn description(&self) -> &'static str {
        "Print userassist registry keys and information."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("offset", "Hive Offset", ReqKind::Int).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Hive Offset", ColType::Hex),
            Column::new("Hive Name", ColType::Str),
            Column::new("Path", ColType::Str),
            Column::new("Last Write Time", ColType::DateTime),
            Column::new("Type", ColType::Str),
            Column::new("Name", ColType::Str),
            Column::new("ID", ColType::Int),
            Column::new("Count", ColType::Int),
            Column::new("Focus Count", ColType::Int),
            Column::new("Time Focused", ColType::Str),
            Column::new("Last Updated", ColType::DateTime),
            Column::new("Raw Data", ColType::HexBytes),
        ])?;
        for (depth, row) in generate(ctx, cfg)? {
            out.row(depth, row)?;
        }
        Ok(())
    }
    fn timeline(&self, ctx: &Context, cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        let r = (|| -> Result<Vec<TimelineEvent>> {
            let mut ev = Vec::new();
            for (_d, row) in generate(ctx, cfg)? {
                // python: name is str AND lastupdated not NotApplicableValue
                let name = match &row[5] {
                    Value::Str(s) => s.clone(),
                    _ => continue,
                };
                if matches!(row[10], Value::NotApplicable) {
                    continue;
                }
                let path = match &row[2] {
                    Value::Str(s) => s.clone(),
                    _ => String::new(),
                };
                let count = match &row[7] {
                    Value::Int(i) => i.to_string(),
                    _ => "-".to_string(),
                };
                let description = format!("UserAssist: {name} {path} ({count})");
                ev.push(TimelineEvent { description, kind: TimeKind::Modified, time: row[10].clone() });
            }
            Ok(ev)
        })();
        Some(r)
    }
}
