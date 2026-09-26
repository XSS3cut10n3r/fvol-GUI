//! windows.svcscan.SvcScan (python `plugins/windows/svcscan.py`) plus the python
//! `symbols/windows/extensions/services.py` classes (`SERVICE_RECORD`, `SERVICE_HEADER`) and the
//! machinery `windows.svclist.SvcList` / `windows.malware.svcdiff.SvcDiff` reuse:
//! [`get_prereq_info`] (services symbol table + registry binary map), [`service_scan`],
//! [`enumerate_vista_or_later_header`] and [`ServiceRow`] (python `get_record_tuple`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::layers::scan::{BytesScanner, scan};
use crate::objects::util::array_to_string;
use crate::objects::{LayerRef, Obj, Space};
use crate::plugins::windows::registry::hivelist::list_hives;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::table::{StrEnc, StrErrors};
use crate::symbols::windows::registry::{RegData, RegExt, is_key_error, is_registry_exception};
use crate::symbols::windows::versions;
use crate::symbols::windows::prelude::*;
use crate::util::FxHashMap;

pub struct SvcScan;

/// A `ServiceBinaryInfo` field read from the registry (python `str` or an absent value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegStr {
    Str(String),
    /// `renderers.UnreadableValue()`
    Unreadable,
    /// `renderers.UnparsableValue()`
    Unparsable,
}

impl RegStr {
    fn value(&self) -> Value {
        match self {
            RegStr::Str(s) => Value::Str(s.clone()),
            RegStr::Unreadable => Value::Unreadable,
            RegStr::Unparsable => Value::Unparsable,
        }
    }
}

/// python `ServiceBinaryInfo(dll, binary)`.
#[derive(Clone, Debug)]
pub struct ServiceBinaryInfo {
    pub dll: RegStr,
    pub binary: RegStr,
}

/// python `service_binary_dll_map`: service key name -> binary info.
pub type BinaryMap = FxHashMap<String, ServiceBinaryInfo>;

/// python `SvcScan._win_version_file_map` (newest -> oldest).
const WIN_VERSION_FILE_MAP: [(versions::OsDistinguisher, bool, &str); 18] = [
    (versions::IS_WIN10_25398_OR_LATER, true, "services-win10-25398-x64"),
    (versions::IS_WIN10_19041_OR_LATER, true, "services-win10-19041-x64"),
    (versions::IS_WIN10_19041_OR_LATER, false, "services-win10-19041-x86"),
    (versions::IS_WIN10_18362_OR_LATER, true, "services-win10-18362-x64"),
    (versions::IS_WIN10_18362_OR_LATER, false, "services-win10-18362-x86"),
    (versions::IS_WIN10_17763_OR_LATER, false, "services-win10-17763-x86"),
    (versions::IS_WIN10_16299_OR_LATER, true, "services-win10-16299-x64"),
    (versions::IS_WIN10_16299_OR_LATER, false, "services-win10-16299-x86"),
    (versions::IS_WIN10_15063, true, "services-win10-15063-x64"),
    (versions::IS_WIN10_15063, false, "services-win10-15063-x86"),
    (versions::IS_WIN10_UP_TO_15063, true, "services-win8-x64"),
    (versions::IS_WIN10_UP_TO_15063, false, "services-win8-x86"),
    (versions::IS_WINDOWS_8_OR_LATER, true, "services-win8-x64"),
    (versions::IS_WINDOWS_8_OR_LATER, true, "services-win8-x86"),
    (versions::IS_VISTA_OR_LATER, true, "services-vista-x64"),
    (versions::IS_VISTA_OR_LATER, false, "services-vista-x86"),
    (versions::IS_WINDOWS_XP, false, "services-xp-x86"),
    (versions::IS_XP_OR_2003, true, "services-xp-2003-x64"),
];

/// python `SvcScan._create_service_table(context, symbol_table, config_path)`.
pub fn create_service_table(ctx: &Context, k: &WinKernel) -> Result<TableRef> {
    let is_64 = k.table.is_64bit();
    let file = WIN_VERSION_FILE_MAP
        .iter()
        .find(|(check, for_64, _)| *for_64 == is_64 && check.check(k.table))
        .map(|(_, _, f)| *f)
        .ok_or_else(|| Error::msg("NotImplementedError: This version of Windows is not supported!"))?;
    ctx.load_isf_with(&format!("windows/services/{file}"), Some(k.table), &[])
}

fn is_lookup_error(e: &Error) -> bool {
    is_key_error(e) || e.is_invalid_address() || is_registry_exception(e)
}

/// python `SvcScan._get_service_key`: `ControlSet\Services` of the first `machine\system` hive
/// that has one.
pub fn get_service_key(ctx: &Context, k: &WinKernel) -> Result<Option<Obj>> {
    for hive in list_hives(ctx, k, Some("machine\\system"), None) {
        let hive = hive?;
        match hive.get_key_node("CurrentControlSet\\Services") {
            Ok(n) => return Ok(Some(n)),
            Err(e) if is_lookup_error(&e) => {}
            Err(e) => return Err(e),
        }
        match hive.get_key_node("ControlSet001\\Services") {
            Ok(n) => return Ok(Some(n)),
            Err(e) if is_lookup_error(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// `value.decode_data().decode("utf-16").rstrip("\x00")` (UnicodeDecodeError -> Unparsable).
fn decode_reg_string(v: &Obj) -> Result<RegStr> {
    match v.decode_data()? {
        RegData::Bytes(b) => match crate::objects::strings::decode(&b, StrEnc::Utf16, StrErrors::Strict) {
            Ok(s) => Ok(RegStr::Str(s.trim_end_matches('\0').to_string())),
            Err(_) => Ok(RegStr::Unparsable),
        },
        // python: AttributeError ('int' object has no attribute 'decode')
        RegData::Int(_) => Err(Error::msg("AttributeError: 'int' object has no attribute 'decode'")),
    }
}

/// python `SvcScan._get_service_dll`.
fn get_service_dll(service_key: &Obj) -> Result<RegStr> {
    let mut param = None;
    for sub in service_key.get_subkeys() {
        let sub = sub?;
        if sub.get_name()? == "Parameters" {
            param = Some(sub);
            break;
        }
    }
    let Some(param) = param else { return Ok(RegStr::Unreadable) };
    for val in param.get_values() {
        if val.get_name()? == "ServiceDll" {
            return decode_reg_string(&val);
        }
    }
    Ok(RegStr::Unreadable)
}

/// python `SvcScan._get_service_binary`.
fn get_service_binary(service_key: &Obj) -> Result<RegStr> {
    for val in service_key.get_values() {
        if val.get_name()? == "ImagePath" {
            return decode_reg_string(&val);
        }
    }
    Ok(RegStr::Unreadable)
}

/// python `SvcScan._get_service_binary_map(services_key)`.
pub fn get_service_binary_map(services_key: &Obj) -> Result<BinaryMap> {
    let mut map = BinaryMap::default();
    for sk in services_key.get_subkeys() {
        let sk = sk?;
        let name = sk.get_name()?;
        let dll = get_service_dll(&sk)?;
        let binary = get_service_binary(&sk)?;
        map.insert(name, ServiceBinaryInfo { dll, binary });
    }
    Ok(map)
}

/// What python's `get_prereq_info` returns (the name filter is always `["services.exe"]`).
pub struct Prereq {
    pub table: TableRef,
    pub binary_map: BinaryMap,
}

/// python `SvcScan.get_prereq_info(context, config_path, kernel_module_name)`.
pub fn get_prereq_info(ctx: &Context, k: &WinKernel) -> Result<Prereq> {
    let table = create_service_table(ctx, k)?;
    let binary_map = match get_service_key(ctx, k)? {
        Some(key) => get_service_binary_map(&key)?,
        None => BinaryMap::default(),
    };
    Ok(Prereq { table, binary_map })
}

/// python `pslist.PsList.create_name_filter(["services.exe"])`.
pub fn services_filter(p: &Obj) -> Result<bool> {
    Ok(array_to_string(&p.m("ImageFileName")?, None)? != "services.exe")
}

/// The fields of a python `get_record_tuple` that decide tuple equality (python compares the
/// absent values by identity: a record holding a freshly created absent value never equals
/// anything, see [`ServiceRow::key`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowKey {
    offset: u64,
    order: i128,
    pid: i128,
    start: &'static str,
    state: &'static str,
    ty: String,
    name: String,
    display: String,
    binary: String,
    reg_binary: RegStr,
    reg_dll: RegStr,
}

/// One python `get_record_tuple` row.
#[derive(Clone, Debug)]
pub struct ServiceRow {
    pub values: Vec<Value>,
    /// `service[6]` (the name) when it is a string (None = a fresh `UnreadableValue`).
    pub name: Option<String>,
    /// None when the tuple contains a freshly created absent value (never `==` another tuple).
    pub key: Option<RowKey>,
}

/// `_SERVICE_RECORD` accessors on one process layer.
struct Rec {
    sp: &'static Space,
}

const SERVICE_TYPE_FLAGS: [(&str, u64); 7] = [
    ("SERVICE_KERNEL_DRIVER", 1),
    ("SERVICE_FILE_SYSTEM_DRIVER", 2),
    ("SERVICE_ADAPTOR", 4),
    ("SERVICE_RECOGNIZER_DRIVER", 8),
    ("SERVICE_WIN32_OWN_PROCESS", 16),
    ("SERVICE_WIN32_SHARE_PROCESS", 32),
    ("SERVICE_INTERACTIVE_PROCESS", 256),
];

impl Rec {
    fn record(&self, addr: u64) -> Result<Obj> {
        Obj::named(self.sp, "_SERVICE_RECORD", addr)
    }

    /// python `SERVICE_RECORD.is_valid()`.
    fn is_valid(&self, r: &Obj) -> bool {
        let order_ok = matches!(r.m("Order").and_then(|o| o.int()), Ok(o) if (0..=0xFFFF).contains(&o));
        order_ok && r.m("State").and_then(|s| s.description()).is_ok() && r.m("Start").and_then(|s| s.description()).is_ok()
    }

    /// python `SERVICE_RECORD.get_type()`.
    fn get_type(&self, r: &Obj) -> Result<String> {
        let t = r.m("Type")?.u64()?;
        let names: Vec<&str> = SERVICE_TYPE_FLAGS.iter().filter(|(_, v)| t & v != 0).map(|(n, _)| *n).collect();
        Ok(names.join("|"))
    }

    fn string_at(&self, r: &Obj, member: &str) -> Result<Option<String>> {
        let r = (|| -> Result<String> { r.m(member)?.deref()?.cast_string(512, StrEnc::Utf16, StrErrors::Replace).string() })();
        match r {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// python `get_record_tuple(service_record, binary_info)` for the record at `r` whose
    /// `vol.offset` is `offset` (a `PrevEntry` pointer's own address for all but the first
    /// record of a traversal, exactly like python).
    fn row(&self, r: &Obj, offset: u64, map: &BinaryMap) -> Result<ServiceRow> {
        // service_binary_dll_map.get(service_record.get_name(), default)
        let lookup_name = self.string_at(r, "ServiceName")?;
        let info = lookup_name.as_ref().and_then(|n| map.get(n));
        let order = r.m("Order")?.int()?;
        let state = r.m("State")?.description()?;
        let running = state == "SERVICE_RUNNING";
        // get_pid()
        let pid: Option<Value> = if !running || !self.get_type(r)?.contains("PROCESS") {
            None
        } else {
            match r.m("ServiceProcess").and_then(|p| p.m("ProcessId")).and_then(|p| p.int()) {
                Ok(v) => Some(Value::Int(v)),
                Err(e) if e.is_invalid_address() => Some(Value::Unreadable),
                Err(e) => return Err(e),
            }
        };
        let start = r.m("Start")?.description()?;
        let state = r.m("State")?.description()?;
        let ty = self.get_type(r)?;
        let name = self.string_at(r, "ServiceName")?;
        let display = self.string_at(r, "DisplayName")?;
        // get_binary()
        let binary: Option<Option<String>> = if r.m("State")?.description()? != "SERVICE_RUNNING" {
            None
        } else {
            let res = if self.get_type(r)?.contains("PROCESS") {
                (|| -> Result<String> {
                    r.m("ServiceProcess")?.m("BinaryPath")?.deref()?.cast_string(512, StrEnc::Utf16, StrErrors::Replace).string()
                })()
            } else {
                (|| -> Result<String> { r.m("DriverName")?.deref()?.cast_string(512, StrEnc::Utf16, StrErrors::Replace).string() })()
            };
            match res {
                Ok(s) => Some(Some(s)),
                Err(e) if e.is_invalid_address() => Some(None),
                Err(e) => return Err(e),
            }
        };
        let key = match (&pid, &name, &display, &binary, info) {
            (Some(Value::Int(p)), Some(n), Some(d), Some(Some(b)), Some(i)) => Some(RowKey {
                offset,
                order,
                pid: *p,
                start,
                state,
                ty: ty.clone(),
                name: n.clone(),
                display: d.clone(),
                binary: b.clone(),
                reg_binary: i.binary.clone(),
                reg_dll: i.dll.clone(),
            }),
            _ => None,
        };
        let opt = |s: &Option<String>| match s {
            Some(s) => Value::Str(s.clone()),
            None => Value::Unreadable,
        };
        let values = vec![
            Value::Int(offset as i128),
            Value::Int(order),
            pid.unwrap_or(Value::NotApplicable),
            Value::SStr(start),
            Value::SStr(state),
            Value::Str(ty),
            opt(&name),
            opt(&display),
            match &binary {
                None => Value::NotApplicable,
                Some(b) => opt(b),
            },
            info.map(|i| i.binary.value()).unwrap_or(Value::Unreadable),
            info.map(|i| i.dll.value()).unwrap_or(Value::Unreadable),
        ];
        Ok(ServiceRow { values, name, key })
    }
}

/// Safety cap on one `PrevEntry` walk (python would loop forever on a cyclic list).
const MAX_TRAVERSE: usize = 1 << 20;

/// python `SvcScan.enumerate_vista_or_later_header(...)` for the `_SERVICE_HEADER` candidate at
/// `offset`: the rows of `ServiceRecord.traverse()`. A trailing `Err` = python raised there.
/// `f` returns false to stop the walk (python's consumer `break`).
pub fn enumerate_vista_or_later_header(
    table: TableRef,
    map: &BinaryMap,
    proc_layer: LayerRef,
    offset: u64,
    f: &mut dyn FnMut(ServiceRow) -> bool,
) -> Result<()> {
    if offset % 8 != 0 {
        return Ok(());
    }
    let rec = Rec { sp: Space::on(proc_layer, table) };
    let header = Obj::named(rec.sp, "_SERVICE_HEADER", offset)?;
    // SERVICE_HEADER.is_valid(): ServiceRecord.is_valid()
    let first = match header.m("ServiceRecord").and_then(|p| p.u64()) {
        Ok(v) => rec.record(v)?,
        Err(e) if e.is_invalid_address() => return Ok(()),
        Err(e) => return Err(e),
    };
    if !rec.is_valid(&first) {
        return Ok(());
    }
    // SERVICE_RECORD.traverse(): PrevEntry flavour (every shipped services ISF has it)
    if first.has_member("PrevEntry") {
        if !f(rec.row(&first, first.addr, map)?) {
            return Ok(());
        }
        // `rec = self.PrevEntry`: python yields the pointer objects, so a row's offset is the
        // address of the PrevEntry field that pointed at the record
        let mut ptr = first.m("PrevEntry")?;
        for _ in 0..MAX_TRAVERSE {
            let v = match ptr.u64() {
                Ok(v) => v,
                Err(e) if e.is_invalid_address() => return Ok(()),
                Err(e) => return Err(e),
            };
            if v == 0 {
                return Ok(());
            }
            let r = ptr.deref()?;
            if !rec.is_valid(&r) {
                return Ok(());
            }
            if !f(rec.row(&r, ptr.addr, map)?) {
                return Ok(());
            }
            ptr = r.m("PrevEntry")?;
        }
    } else {
        // ServiceList.Blink flavour (python yields the dereferenced records themselves)
        let mut r = first;
        for _ in 0..MAX_TRAVERSE {
            if !rec.is_valid(&r) {
                return Ok(());
            }
            if !f(rec.row(&r, r.addr, map)?) {
                return Ok(());
            }
            r = match r.m("ServiceList").and_then(|l| l.m("Blink")).and_then(|b| b.u64()) {
                Ok(0) => return Ok(()),
                Ok(v) => rec.record(v)?,
                Err(e) if e.is_invalid_address() => return Ok(()),
                Err(e) => return Err(e),
            };
        }
    }
    Ok(())
}

/// python `SvcScan.service_scan(...)`: rows in python order; `f` gets every row python yields.
pub fn service_scan(k: &WinKernel, pre: &Prereq, f: &mut dyn FnMut(ServiceRow) -> Result<()>) -> Result<()> {
    let table = pre.table;
    let map = &pre.binary_map;
    let is_vista_or_later = versions::IS_VISTA_OR_LATER.check(k.table);
    let tag: &[u8] = if is_vista_or_later { b"serH" } else { b"sErv" };
    let tag_off = Obj::named(Space::on(k.vlayer, table), "_SERVICE_RECORD", 0)?.member_offset("Tag")?;
    // python's `seen` list, indexed by offset (only comparable tuples can ever match)
    let mut seen: FxHashMap<u64, Vec<RowKey>> = FxHashMap::default();
    for task in crate::plugins::windows::pslist::list_processes(k, &services_filter) {
        let task = task?;
        let proc_layer = match task.m("UniqueProcessId").and_then(|_| task.add_process_layer()) {
            Ok(l) => l,
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => return Err(e),
        };
        let mut sections = Vec::new();
        for vad in task.get_vad_root()?.traverse() {
            let vad = vad?;
            let base = vad.get_start()?;
            let size = vad.get_size()?;
            if size != 0 {
                sections.push((base, vad.get_size()?));
            }
        }
        let hits = scan(proc_layer, &BytesScanner::new(tag), Some(&sections));
        for offset in hits {
            if !is_vista_or_later {
                let rec = Rec { sp: Space::on(proc_layer, table) };
                let r = rec.record(offset.wrapping_sub(tag_off))?;
                if !rec.is_valid(&r) {
                    continue;
                }
                f(rec.row(&r, r.addr, map)?)?;
                continue;
            }
            let mut err = None;
            enumerate_vista_or_later_header(table, map, proc_layer, offset, &mut |row| {
                if let Some(key) = &row.key {
                    let v = seen.entry(key.offset).or_default();
                    if v.contains(key) {
                        return false;
                    }
                    v.push(key.clone());
                }
                if let Err(e) = f(row) {
                    err = Some(e);
                    return false;
                }
                true
            })?;
            if let Some(e) = err {
                return Err(e);
            }
        }
    }
    Ok(())
}

/// The TreeGrid columns of SvcScan and its subclasses.
pub fn columns() -> Vec<Column> {
    vec![
        Column::new("Offset", ColType::Hex),
        Column::new("Order", ColType::Int),
        Column::new("PID", ColType::Int),
        Column::new("Start", ColType::Str),
        Column::new("State", ColType::Str),
        Column::new("Type", ColType::Str),
        Column::new("Name", ColType::Str),
        Column::new("Display", ColType::Str),
        Column::new("Binary", ColType::Str),
        Column::new("Binary (Registry)", ColType::Str),
        Column::new("Dll", ColType::Str),
    ]
}

impl Plugin for SvcScan {
    fn name(&self) -> &'static str {
        "windows.svcscan.SvcScan"
    }
    fn description(&self) -> &'static str {
        "Scans for windows services."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(columns())?;
        let k = ctx.windows_kernel()?;
        let pre = get_prereq_info(ctx, k)?;
        service_scan(k, &pre, &mut |row| out.row(0, row.values))
    }
}
