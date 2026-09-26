//! windows.registry.amcache.Amcache (python `plugins/windows/registry/amcache.py`): extracts
//! executed-application information from the `Amcache.hve` hive (Win8 `Root\File`/`Root\Programs`
//! and Win10 `Root\InventoryApplication*` / `Root\InventoryDriverBinary`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;

use crate::objects::Obj;
use crate::plugins::{Config, Plugin, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::registry::{RegData, RegExt};
use std::collections::HashMap;

pub struct Amcache;

const DRIVER: &str = "Driver";
const PROGRAM: &str = "Program";
const FILE: &str = "File";

/// python `_AmcacheEntry` (all fields default to NotApplicableValue).
#[derive(Clone)]
struct Entry {
    entry_type: &'static str,
    path: Value,
    company: Value,
    last_modify_time: Value,
    last_modify_time_2: Value,
    install_time: Value,
    compile_time: Value,
    sha1_hash: Value,
    service: Value,
    product_name: Value,
    product_version: Value,
}

impl Entry {
    fn new(entry_type: &'static str) -> Entry {
        Entry {
            entry_type,
            path: Value::NotApplicable,
            company: Value::NotApplicable,
            last_modify_time: Value::NotApplicable,
            last_modify_time_2: Value::NotApplicable,
            install_time: Value::NotApplicable,
            compile_time: Value::NotApplicable,
            sha1_hash: Value::NotApplicable,
            service: Value::NotApplicable,
            product_name: Value::NotApplicable,
            product_version: Value::NotApplicable,
        }
    }
    fn astuple(&self) -> Vec<Value> {
        vec![
            Value::SStr(self.entry_type),
            self.path.clone(),
            self.company.clone(),
            self.last_modify_time.clone(),
            self.last_modify_time_2.clone(),
            self.install_time.clone(),
            self.compile_time.clone(),
            self.sha1_hash.clone(),
            self.service.clone(),
            self.product_name.clone(),
            self.product_version.clone(),
        ]
    }
}

type Values = HashMap<String, Obj>;

/// python `_get_string_value`.
fn get_string(values: &Values, name: &str) -> Value {
    let Some(v) = values.get(name) else { return Value::NotAvailable };
    match v.decode_data() {
        Ok(RegData::Bytes(b)) => {
            let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            let s: String = char::decode_utf16(units).map(|r| r.unwrap_or('\u{FFFD}')).collect();
            Value::Str(s.trim_end_matches('\u{0000}').to_string())
        }
        Ok(RegData::Int(_)) => Value::Unparsable,
        Err(_) => Value::Unparsable,
    }
}

/// python `_get_datetime_filetime_value`.
fn get_filetime(values: &Values, name: &str) -> Value {
    let Some(v) = values.get(name) else { return Value::NotAvailable };
    match v.decode_data() {
        Ok(RegData::Int(i)) => crate::util::time::wintime_to_datetime(i as i128),
        Ok(RegData::Bytes(_)) => Value::Unparsable,
        Err(_) => Value::Unparsable,
    }
}

/// python `_get_datetime_utc_epoch_value`.
fn get_utc_epoch(values: &Values, name: &str) -> Value {
    let Some(v) = values.get(name) else { return Value::NotAvailable };
    match v.decode_data() {
        Ok(RegData::Int(i)) => match crate::util::time::unix_float_to_dt(i as f64) {
            Some(dt) => Value::DateTime(dt),
            None => Value::Unparsable,
        },
        Ok(RegData::Bytes(_)) => Value::Unparsable,
        Err(_) => Value::Unparsable,
    }
}

/// python `_get_datetime_str_value` (always Unparsable when the value exists, since
/// `decode_data` returns int/bytes, never str — a faithful port of the python logic).
fn get_datetime_str(values: &Values, name: &str) -> Value {
    let Some(v) = values.get(name) else { return Value::NotAvailable };
    match v.decode_data() {
        Ok(_) | Err(_) => Value::Unparsable,
    }
}

/// python `sha1.lstrip("0000")` (strips leading '0' chars).
fn lstrip_zeros(v: &Value) -> Value {
    match v {
        Value::Str(s) => Value::Str(s.trim_start_matches('0').to_string()),
        other => other.clone(),
    }
}

/// Build the `{name: value}` dict for a key, keeping only the wanted value names.
fn wanted_values(key: &Obj, wanted: &[&str]) -> Result<Values> {
    let mut m = HashMap::new();
    for v in key.get_values() {
        let name = v.get_name()?;
        if wanted.contains(&name.as_str()) {
            m.insert(name, v);
        }
    }
    Ok(m)
}

// enum value-name tables (python enums)
const WIN8_FILE: &[&str] = &["100", "101", "0", "1", "6", "7", "9", "11", "12", "15", "17", "d", "f"];
const WIN8_PROGRAM: &[&str] = &["0", "1", "2", "a", "11", "12", "f", "10"];
const WIN10_INVAPP: &[&str] = &["InstallDate", "Name", "Publisher", "RootDirPath", "Version"];
const WIN10_INVAPPFILE: &[&str] = &["FileId", "LinkDate", "LowerCaseLongPath", "ProductName", "ProductVersion", "ProgramId", "Publisher"];
const WIN10_DRIVER: &[&str] = &["DriverId", "DriverName", "DriverCompany", "Product", "Service", "DriverTimeStamp"];

fn as_string_key(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        _ => String::new(),
    }
}

/// python `parse_file_key` (Win8 Root\File).
fn parse_file_key(file_key: &Obj) -> Result<Vec<(Value, Entry)>> {
    let mut out = Vec::new();
    for vol in file_key.get_subkeys() {
        let vol = vol?;
        for fk in vol.get_subkeys() {
            let fk = fk?;
            let values = wanted_values(&fk, WIN8_FILE)?;
            let program_id = get_string(&values, "100");
            let mut e = Entry::new(FILE);
            e.path = get_string(&values, "15");
            e.company = get_string(&values, "1");
            e.last_modify_time = get_filetime(&values, "11");
            e.last_modify_time_2 = get_filetime(&values, "17");
            e.install_time = get_filetime(&values, "12");
            e.compile_time = get_utc_epoch(&values, "f");
            e.sha1_hash = lstrip_zeros(&get_string(&values, "101"));
            e.product_name = get_string(&values, "0");
            out.push((program_id, e));
        }
    }
    Ok(out)
}

/// python `parse_programs_key` (Win8 Root\Programs).
fn parse_programs_key(programs_key: &Obj) -> Result<Vec<(String, Entry)>> {
    let mut out = Vec::new();
    for pk in programs_key.get_subkeys() {
        let pk = pk?;
        let values = wanted_values(&pk, WIN8_PROGRAM)?;
        let program_id = pk.get_name()?.trim().trim_matches('\u{0000}').to_string();
        let mut e = Entry::new(PROGRAM);
        e.company = get_string(&values, "2");
        e.last_modify_time = pk.last_write_time()?;
        e.install_time = get_utc_epoch(&values, "a");
        e.product_name = get_string(&values, "0");
        e.product_version = get_string(&values, "1");
        out.push((program_id, e));
    }
    Ok(out)
}

/// python `parse_inventory_app_key` (Win10 Root\InventoryApplication).
fn parse_inventory_app_key(inv: &Obj) -> Result<Vec<(String, Entry)>> {
    let mut out = Vec::new();
    for pk in inv.get_subkeys() {
        let pk = pk?;
        let program_id = pk.get_name()?;
        let values = wanted_values(&pk, WIN10_INVAPP)?;
        let name = get_string(&values, "Name");
        let mut e = Entry::new(PROGRAM);
        e.path = get_string(&values, "RootDirPath");
        e.last_modify_time = pk.last_write_time()?;
        e.install_time = get_datetime_str(&values, "InstallDate");
        e.product_name = match &name {
            Value::Str(_) => name.clone(),
            _ => Value::SStr("UNKNOWN"),
        };
        e.company = get_string(&values, "Publisher");
        e.product_version = get_string(&values, "Version");
        out.push((program_id.trim().trim_matches('\u{0000}').to_string(), e));
    }
    Ok(out)
}

/// python `parse_inventory_app_file_key` (Win10 Root\InventoryApplicationFile).
fn parse_inventory_app_file_key(inv: &Obj) -> Result<Vec<(Value, Entry)>> {
    let mut out = Vec::new();
    for fk in inv.get_subkeys() {
        let fk = fk?;
        let values = wanted_values(&fk, WIN10_INVAPPFILE)?;
        let mut e = Entry::new(FILE);
        e.last_modify_time = fk.last_write_time()?;
        e.path = get_string(&values, "LowerCaseLongPath");
        e.compile_time = get_datetime_str(&values, "LinkDate");
        e.sha1_hash = lstrip_zeros(&get_string(&values, "FileId"));
        e.company = get_string(&values, "Publisher");
        e.product_name = get_string(&values, "ProductName");
        e.product_version = get_string(&values, "ProductVersion");
        let program_id = get_string(&values, "ProgramId");
        out.push((program_id, e));
    }
    Ok(out)
}

/// python `parse_driver_binary_key` (Win10 Root\InventoryDriverBinary).
fn parse_driver_binary_key(dbk: &Obj) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    for bk in dbk.get_subkeys() {
        let bk = bk?;
        let values = wanted_values(&bk, WIN10_DRIVER)?;
        let name = bk.get_name()?;
        let (driver_name, mut sha1_hash) = if name.contains('/') {
            (Value::Str(name.clone()), get_string(&values, "DriverId"))
        } else {
            (get_string(&values, "DriverName"), Value::Str(name.clone()))
        };
        if let Value::Str(s) = &sha1_hash {
            sha1_hash = Value::Str(if let Some(rest) = s.strip_prefix("0000") { rest.to_string() } else { s.clone() });
        }
        let mut e = Entry::new(DRIVER);
        e.path = driver_name;
        e.company = get_string(&values, "DriverCompany");
        e.last_modify_time = bk.last_write_time()?;
        e.compile_time = get_utc_epoch(&values, "DriverTimeStamp");
        e.sha1_hash = lstrip_zeros(&sha1_hash);
        e.service = get_string(&values, "Service");
        e.product_name = get_string(&values, "Product");
        out.push(e);
    }
    Ok(out)
}

/// python catch of `(KeyError, registry.RegistryException)` around a get_key+parse: returns
/// `default` for those, propagates everything else (e.g. InvalidAddressException).
fn caught<T>(r: Result<T>, default: T) -> Result<T> {
    match r {
        Ok(v) => Ok(v),
        Err(e) if crate::symbols::windows::registry::is_key_error(&e) || crate::layers::registry::is_registry_exception(&e) => Ok(default),
        Err(e) => Err(e),
    }
}

/// python `_generator`.
fn generate(ctx: &Context, cfg: &Config) -> Result<Vec<(usize, Entry)>> {
    let k = ctx.windows_kernel()?;
    let _ = cfg;
    let mut rows: Vec<(usize, Entry)> = Vec::new();
    let amcache = match super::hivelist::list_hives(ctx, k, Some("amcache"), None).into_iter().next() {
        Some(Ok(h)) => h,
        Some(Err(e)) => return Err(e),
        None => return Ok(rows),
    };

    // driver binary
    let drivers = caught((|| parse_driver_binary_key(&amcache.get_key_node("Root\\InventoryDriverBinary")?))(), Vec::new())?;
    for e in drivers {
        rows.push((0, e));
    }

    // Win8 programs + files
    let programs = caught((|| parse_programs_key(&amcache.get_key_node("Root\\Programs")?))(), Vec::new())?;
    let files = caught((|| parse_file_key(&amcache.get_key_node("Root\\File")?))(), Vec::new())?;
    emit_grouped(files, programs, &mut rows);

    // Win10 inventory app + files
    let programs = caught((|| parse_inventory_app_key(&amcache.get_key_node("Root\\InventoryApplication")?))(), Vec::new())?;
    let files = caught((|| parse_inventory_app_file_key(&amcache.get_key_node("Root\\InventoryApplicationFile")?))(), Vec::new())?;
    emit_grouped(files, programs, &mut rows);

    Ok(rows)
}

/// python's `itertools.groupby(sorted(files, key=program_id))` emission with program correlation
/// (`programs` is a dict; leftover programs are emitted afterwards in insertion order).
fn emit_grouped(mut files: Vec<(Value, Entry)>, programs: Vec<(String, Entry)>, rows: &mut Vec<(usize, Entry)>) {
    // python dict semantics: a later duplicate id overwrites the earlier value but keeps its
    // insertion position.
    let mut order: Vec<String> = Vec::new();
    let mut map: HashMap<String, Entry> = HashMap::new();
    for (id, e) in programs {
        if !map.contains_key(&id) {
            order.push(id.clone());
        }
        map.insert(id, e);
    }
    // stable sort by program-id string (absent -> "")
    files.sort_by(|a, b| as_string_key(&a.0).cmp(&as_string_key(&b.0)));
    let mut i = 0;
    while i < files.len() {
        let key = as_string_key(&files[i].0);
        let mut j = i;
        while j < files.len() && as_string_key(&files[j].0) == key {
            j += 1;
        }
        let mut files_indent = 0;
        if let Some(prog) = map.remove(key.trim().trim_matches('\u{0000}')) {
            rows.push((0, prog));
            files_indent = 1;
        }
        for (_, e) in files[i..j].iter() {
            rows.push((files_indent, e.clone()));
        }
        i = j;
    }
    // leftover programs, in insertion order
    for id in order {
        if let Some(e) = map.remove(&id) {
            rows.push((0, e));
        }
    }
}

impl Plugin for Amcache {
    fn name(&self) -> &'static str {
        "windows.registry.amcache.Amcache"
    }
    fn description(&self) -> &'static str {
        "Extract information on executed applications from the AmCache."
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(columns())?;
        // leftover-program insertion order must match python (dict order). Handle here.
        let rows = generate_ordered(ctx, cfg)?;
        for (depth, e) in rows {
            out.row(depth, e.astuple())?;
        }
        Ok(())
    }
    fn timeline(&self, ctx: &Context, cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        let r = (|| -> Result<Vec<TimelineEvent>> {
            let mut ev = Vec::new();
            for (_d, e) in generate_ordered(ctx, cfg)? {
                let path = match &e.path {
                    Value::Str(s) => s.clone(),
                    _ => continue,
                };
                if let Value::DateTime(_) = e.last_modify_time {
                    ev.push(TimelineEvent { description: format!("Amcache: {} {} registry key modified", e.entry_type, path), kind: TimeKind::Modified, time: e.last_modify_time.clone() });
                }
                if let Value::DateTime(_) = e.last_modify_time_2 {
                    ev.push(TimelineEvent { description: format!("Amcache: {} {} STANDARD_INFORMATION create time", e.entry_type, path), kind: TimeKind::Created, time: e.last_modify_time_2.clone() });
                }
                if let Value::DateTime(_) = e.install_time {
                    ev.push(TimelineEvent { description: format!("Amcache: {} {} installed", e.entry_type, path), kind: TimeKind::Created, time: e.install_time.clone() });
                }
                if let Value::DateTime(_) = e.compile_time {
                    ev.push(TimelineEvent { description: format!("Amcache: {} {} compiled (PE metadata)", e.entry_type, path), kind: TimeKind::Modified, time: e.compile_time.clone() });
                }
            }
            Ok(ev)
        })();
        Some(r)
    }
}

fn columns() -> Vec<Column> {
    vec![
        Column::new("EntryType", ColType::Str),
        Column::new("Path", ColType::Str),
        Column::new("Company", ColType::Str),
        Column::new("LastModifyTime", ColType::DateTime),
        Column::new("LastModifyTime2", ColType::DateTime),
        Column::new("InstallTime", ColType::DateTime),
        Column::new("CompileTime", ColType::DateTime),
        Column::new("SHA1", ColType::Str),
        Column::new("Service", ColType::Str),
        Column::new("ProductName", ColType::Str),
        Column::new("ProductVersion", ColType::Str),
    ]
}

/// Deprecated alias `windows.amcache.Amcache`.
pub struct AmcacheDeprecated;
impl Plugin for AmcacheDeprecated {
    fn name(&self) -> &'static str {
        "windows.amcache.Amcache"
    }
    fn description(&self) -> &'static str {
        "Extract information on executed applications from the AmCache (deprecated)."
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        Amcache.run(ctx, cfg, out)
    }
    fn timeline(&self, ctx: &Context, cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        Amcache.timeline(ctx, cfg)
    }
}

// re-export generate with python's leftover-program dict ordering preserved.
fn generate_ordered(ctx: &Context, cfg: &Config) -> Result<Vec<(usize, Entry)>> {
    generate(ctx, cfg)
}
