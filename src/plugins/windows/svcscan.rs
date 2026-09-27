//! windows.svcscan.SvcScan (python `plugins/windows/svcscan.py`) plus the python
//! `symbols/windows/extensions/services.py` classes (`SERVICE_RECORD`, `SERVICE_HEADER`) and the
//! machinery `windows.svclist.SvcList` / `windows.malware.svcdiff.SvcDiff` reuse:
//! [`get_prereq_info`] / [`with_prereq`] (services symbol table + registry binary map),
//! [`service_scan`] / [`service_list`] (the memory walks planned first, see [`ServicePlan`], then
//! the rows) and [`ServiceRow`] (python `get_record_tuple`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::layers::scan::{BytesScanner, scan};
use crate::objects::util::array_to_string;
use crate::objects::{Field, LayerRef, Obj, Space};
use crate::plugins::windows::registry::hivelist::list_hives;
use crate::plugins::{Config, Plugin};
use crate::renderers::text::RowEncoder;
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

/// python `SvcScan._get_service_binary_map(services_key)`. The service keys are independent:
/// they are listed first and read in parallel; python's first error (a subkey that fails to
/// list, or one whose values raise) is returned.
pub fn get_service_binary_map(services_key: &Obj) -> Result<BinaryMap> {
    let mut keys: Vec<Result<Obj>> = Vec::new();
    for sk in services_key.get_subkeys() {
        let failed = sk.is_err();
        keys.push(sk);
        if failed {
            break;
        }
    }
    let entry = |sk: &Obj| -> Result<(String, ServiceBinaryInfo)> {
        let name = sk.get_name()?;
        let dll = get_service_dll(sk)?;
        let binary = get_service_binary(sk)?;
        Ok((name, ServiceBinaryInfo { dll, binary }))
    };
    let infos = crate::util::par::par_map(keys.len(), |i| keys[i].as_ref().ok().map(entry));
    let mut map = BinaryMap::default();
    map.reserve(keys.len());
    for (sk, info) in keys.into_iter().zip(infos) {
        sk?;
        if let Some(info) = info {
            let (name, info) = info?;
            map.insert(name, info);
        }
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
    let binary_map = get_binary_map(ctx, k)?;
    Ok(Prereq { table, binary_map })
}

/// The registry part of `get_prereq_info`: `_get_service_binary_map(_get_service_key(...))`.
fn get_binary_map(ctx: &Context, k: &WinKernel) -> Result<BinaryMap> {
    match get_service_key(ctx, k)? {
        Some(key) => get_service_binary_map(&key),
        None => Ok(BinaryMap::default()),
    }
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
    /// The row's values (empty when the row was formatted on the worker: see `enc`).
    pub values: Vec<Value>,
    /// `service[6]` (the name) when it is a string (None = a fresh `UnreadableValue`).
    pub name: Option<String>,
    /// None when the tuple contains a freshly created absent value (never `==` another tuple).
    pub key: Option<RowKey>,
    /// Address of the `_SERVICE_RECORD` (with `key.offset`, what determines the row).
    pub rec: u64,
    /// The row formatted with the sink's row encoder (the values are then dropped).
    pub enc: Option<Vec<u8>>,
}

impl ServiceRow {
    /// Hand the row to `out` (formatted bytes when it was encoded on a worker).
    pub fn emit(&self, out: &mut dyn RowSink) -> Result<()> {
        match &self.enc {
            Some(b) => out.rows_encoded(b, 1),
            None => out.row(0, self.values.clone()),
        }
    }
}

/// A row as the replay hands it out: rows are shared (python yields a record's row again
/// when a walk passes it again).
pub type RowRef = std::rc::Rc<ServiceRow>;

/// Resolved `_SERVICE_RECORD` members (None: not in this table, looked up by name).
#[derive(Clone, Copy)]
struct RecFields {
    order: Option<Field>,
    state: Option<Field>,
    start: Option<Field>,
    ty: Option<Field>,
    name: Option<Field>,
    display: Option<Field>,
    driver: Option<Field>,
    process: Option<Field>,
}

impl RecFields {
    fn new(table: TableRef) -> RecFields {
        let f = |m: &str| Field::new(table, "_SERVICE_RECORD", m).ok();
        RecFields {
            order: f("Order"),
            state: f("State"),
            start: f("Start"),
            ty: f("Type"),
            name: f("ServiceName"),
            display: f("DisplayName"),
            driver: f("DriverName"),
            process: f("ServiceProcess"),
        }
    }
}

/// `r.<member>` through a resolved field when there is one.
#[inline]
fn member(r: &Obj, f: &Option<Field>, name: &str) -> Result<Obj> {
    match f {
        Some(f) => Ok(r.f(f)),
        None => r.m(name),
    }
}

/// `_SERVICE_RECORD` accessors on one process layer.
#[derive(Clone, Copy)]
struct Rec {
    sp: &'static Space,
    f: RecFields,
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
    fn new(proc_layer: LayerRef, table: TableRef, f: RecFields) -> Rec {
        Rec { sp: Space::on(proc_layer, table), f }
    }

    fn record(&self, addr: u64) -> Result<Obj> {
        Obj::named(self.sp, "_SERVICE_RECORD", addr)
    }

    /// python `SERVICE_RECORD.is_valid()`.
    fn is_valid(&self, r: &Obj) -> bool {
        let order_ok = matches!(member(r, &self.f.order, "Order").and_then(|o| o.int()), Ok(o) if (0..=0xFFFF).contains(&o));
        order_ok
            && member(r, &self.f.state, "State").and_then(|s| s.description()).is_ok()
            && member(r, &self.f.start, "Start").and_then(|s| s.description()).is_ok()
    }

    /// python `SERVICE_RECORD.get_type()`.
    fn get_type(&self, r: &Obj) -> Result<String> {
        let t = member(r, &self.f.ty, "Type")?.u64()?;
        let mut s = String::new();
        for (n, v) in SERVICE_TYPE_FLAGS {
            if t & v != 0 {
                if !s.is_empty() {
                    s.push('|');
                }
                s.push_str(n);
            }
        }
        Ok(s)
    }

    /// `ptr.dereference().cast("string", encoding="utf-16", errors="replace", max_length=512)`
    /// (None = InvalidAddressException).
    fn string_of(ptr: Result<Obj>) -> Result<Option<String>> {
        match ptr.and_then(|p| p.deref()).and_then(|s| s.cast_string(512, StrEnc::Utf16, StrErrors::Replace).string()) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// python `get_record_tuple(service_record, binary_info)` for the record at `r` whose
    /// `vol.offset` is `offset` (a `PrevEntry` pointer's own address for all but the first
    /// record of a traversal, exactly like python). Every python expression is evaluated once,
    /// in python's order (repeats read the same memory, so they return the same value).
    fn row(&self, r: &Obj, offset: u64, map: &BinaryMap) -> Result<ServiceRow> {
        // service_binary_dll_map.get(service_record.get_name(), default)
        let name = Self::string_of(member(r, &self.f.name, "ServiceName"))?;
        let info = name.as_ref().and_then(|n| map.get(n));
        let order = member(r, &self.f.order, "Order")?.int()?;
        let state = member(r, &self.f.state, "State")?.description()?;
        let running = state == "SERVICE_RUNNING";
        let mut ty: Option<String> = None;
        // get_pid()
        let pid: Option<Value> = if !running {
            None
        } else {
            let t = self.get_type(r)?;
            let is_process = t.contains("PROCESS");
            ty = Some(t);
            if !is_process {
                None
            } else {
                match member(r, &self.f.process, "ServiceProcess").and_then(|p| p.m("ProcessId")).and_then(|p| p.int()) {
                    Ok(v) => Some(Value::Int(v)),
                    Err(e) if e.is_invalid_address() => Some(Value::Unreadable),
                    Err(e) => return Err(e),
                }
            }
        };
        let start = member(r, &self.f.start, "Start")?.description()?;
        let ty = match ty {
            Some(t) => t,
            None => self.get_type(r)?,
        };
        let display = Self::string_of(member(r, &self.f.display, "DisplayName"))?;
        // get_binary()
        let binary: Option<Option<String>> = if !running {
            None
        } else if ty.contains("PROCESS") {
            Some(Self::string_of(member(r, &self.f.process, "ServiceProcess").and_then(|p| p.m("BinaryPath")))?)
        } else {
            Some(Self::string_of(member(r, &self.f.driver, "DriverName"))?)
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
            match binary {
                None => Value::NotApplicable,
                Some(b) => opt(&b),
            },
            info.map(|i| i.binary.value()).unwrap_or(Value::Unreadable),
            info.map(|i| i.dll.value()).unwrap_or(Value::Unreadable),
        ];
        Ok(ServiceRow { values, name, key, rec: r.addr, enc: None })
    }
}

/// Safety cap on one `PrevEntry` walk (python would loop forever on a cyclic list).
const MAX_TRAVERSE: usize = 1 << 20;

/// One record python's `traverse()` yields: the record and its `vol.offset`.
#[derive(Clone, Copy)]
struct Cand {
    rec: Obj,
    offset: u64,
}

#[derive(Clone, Copy)]
enum Walk {
    /// PrevEntry flavour: the first record, yielded as is
    First(Obj),
    /// PrevEntry flavour: follow this record's `PrevEntry` next
    AfterPrev(Obj),
    /// PrevEntry flavour: the pointer to read next
    Prev(Obj),
    /// ServiceList flavour: the record to validate and yield next
    Blink(Obj),
    /// ServiceList flavour: follow this record's `ServiceList.Blink` next
    AfterBlink(Obj),
    Done,
}

/// python `SERVICE_RECORD.traverse()` from a header's (validated) first record, one record at
/// a time (the pointer walk only; the rows are computed separately, see [`walk_rows`]).
struct Traverse {
    rec: Rec,
    state: Walk,
    /// loop iterations started (the [`MAX_TRAVERSE`] cap)
    n: usize,
}

impl Traverse {
    fn new(rec: Rec, first: Obj) -> Traverse {
        let state = if first.has_member("PrevEntry") { Walk::First(first) } else { Walk::Blink(first) };
        Traverse { rec, state, n: 0 }
    }

    /// The next record (None: the walk ended; `Some(Err)`: python raised there).
    fn next(&mut self) -> Option<Result<Cand>> {
        loop {
            match self.state {
                Walk::Done => return None,
                Walk::First(r) => {
                    self.state = Walk::AfterPrev(r);
                    return Some(Ok(Cand { rec: r, offset: r.addr }));
                }
                Walk::AfterPrev(r) => match r.m("PrevEntry") {
                    Ok(p) => self.state = Walk::Prev(p),
                    Err(e) => {
                        self.state = Walk::Done;
                        return Some(Err(e));
                    }
                },
                Walk::Prev(ptr) => {
                    self.state = Walk::Done;
                    if self.n >= MAX_TRAVERSE {
                        return None;
                    }
                    self.n += 1;
                    let v = match ptr.u64() {
                        Ok(v) => v,
                        Err(e) if e.is_invalid_address() => return None,
                        Err(e) => return Some(Err(e)),
                    };
                    if v == 0 {
                        return None;
                    }
                    let r = match ptr.deref() {
                        Ok(r) => r,
                        Err(e) => return Some(Err(e)),
                    };
                    if !self.rec.is_valid(&r) {
                        return None;
                    }
                    // `rec = self.PrevEntry`: python yields the pointer objects, so a row's
                    // offset is the address of the PrevEntry field that pointed at the record
                    self.state = Walk::AfterPrev(r);
                    return Some(Ok(Cand { rec: r, offset: ptr.addr }));
                }
                Walk::Blink(r) => {
                    self.state = Walk::Done;
                    if self.n >= MAX_TRAVERSE || !self.rec.is_valid(&r) {
                        return None;
                    }
                    self.n += 1;
                    // ServiceList.Blink flavour: python yields the dereferenced records
                    self.state = Walk::AfterBlink(r);
                    return Some(Ok(Cand { rec: r, offset: r.addr }));
                }
                Walk::AfterBlink(r) => {
                    self.state = Walk::Done;
                    match r.m("ServiceList").and_then(|l| l.m("Blink")).and_then(|b| b.u64()) {
                        Ok(0) => return None,
                        Ok(v) => match self.rec.record(v) {
                            Ok(n) => self.state = Walk::Blink(n),
                            Err(e) => return Some(Err(e)),
                        },
                        Err(e) if e.is_invalid_address() => return None,
                        Err(e) => return Some(Err(e)),
                    }
                }
            }
        }
    }
}

/// Where the rows of a walk go (python's loop body over the records).
trait RowConsumer {
    /// python's loop body for one row; false = `break`.
    fn row(&mut self, row: RowRef) -> Result<bool>;
}

/// Fewer candidates than this are computed on the calling thread.
const PAR_MIN: usize = 24;

/// The row of `c` (formatted with `enc` when given: the values are then dropped).
fn row_of(rec: &Rec, map: &BinaryMap, enc: Option<&RowEncoder>, c: &Cand) -> Result<ServiceRow> {
    let mut row = rec.row(&c.rec, c.offset, map)?;
    if let Some(e) = enc {
        let mut b = Vec::new();
        e.row(&mut b, &row.values);
        row.values = Vec::new();
        row.enc = Some(b);
    }
    Ok(row)
}


/// python `SvcScan.enumerate_vista_or_later_header(...)`'s checks of the `_SERVICE_HEADER`
/// candidate at `offset`: its first record when python walks from it.
fn header_first(rec: &Rec, offset: u64) -> Result<Option<Obj>> {
    if offset % 8 != 0 {
        return Ok(None);
    }
    let header = Obj::named(rec.sp, "_SERVICE_HEADER", offset)?;
    // SERVICE_HEADER.is_valid(): ServiceRecord.is_valid()
    let first = match header.m("ServiceRecord").and_then(|p| p.u64()) {
        Ok(v) => rec.record(v)?,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(rec.is_valid(&first).then_some(first))
}

/// How a planned walk ended.
enum WalkEnd {
    /// the records ran out
    Finished,
    /// python raised after the planned records
    Raised(Error),
    /// the walk goes on from here (a record already planned by an earlier walk, or the plan's
    /// size cap), if python gets that far
    Resume(Traverse),
}

enum Planned {
    /// the records of one header's walk (indices into the plan's unique records)
    Walk { ids: Vec<u32>, end: WalkEnd },
    /// python raised checking this header
    Raise(Error),
}

/// Most records walked ahead of their rows over the headers of one process (bounds the
/// memory); the walks beyond it go on record by record.
const PLAN_CAP: usize = 1 << 18;

/// The pointer walks of python's loop over `enumerate_vista_or_later_header(offset)` for the
/// header candidates of one process, made before any row is computed (see [`plan_headers`]).
struct HeaderPlan {
    rec: Rec,
    walks: Vec<Planned>,
    /// the distinct records walked (their rows are computed in one parallel pass)
    cands: Vec<Cand>,
    /// (offset, record address) -> index into `cands`
    ids: FxHashMap<(u64, u64), u32>,
    /// per `cands` entry: its row's index in the [`RowStore`] (set by [`compute_rows`])
    gids: Vec<u32>,
}

/// Walk the pointers of every header candidate in `offsets` (cheap, serial), each walk
/// stopping at a record an earlier walk already visited when `stop_at_visited` (svcscan: the
/// records after it are the ones that walk visited, and python's `seen` break comes at the
/// first of them whose row is comparable).
fn plan_headers(rec: Rec, offsets: &[u64], stop_at_visited: bool) -> HeaderPlan {
    let mut walks: Vec<Planned> = Vec::new();
    let mut cands: Vec<Cand> = Vec::new();
    let mut ids: FxHashMap<(u64, u64), u32> = FxHashMap::default();
    let mut total = 0usize;
    for &offset in offsets {
        let first = match header_first(&rec, offset) {
            Ok(Some(f)) => f,
            Ok(None) => continue,
            Err(e) => {
                walks.push(Planned::Raise(e));
                break;
            }
        };
        let mut t = Traverse::new(rec, first);
        let mut walk = Vec::new();
        let end = loop {
            if total >= PLAN_CAP {
                break WalkEnd::Resume(t);
            }
            match t.next() {
                None => break WalkEnd::Finished,
                Some(Err(e)) => break WalkEnd::Raised(e),
                Some(Ok(cand)) => {
                    total += 1;
                    match ids.get(&(cand.offset, cand.rec.addr)) {
                        Some(&id) => {
                            walk.push(id);
                            if stop_at_visited {
                                break WalkEnd::Resume(t);
                            }
                        }
                        None => {
                            let id = cands.len() as u32;
                            ids.insert((cand.offset, cand.rec.addr), id);
                            cands.push(cand);
                            walk.push(id);
                        }
                    }
                }
            }
        };
        walks.push(Planned::Walk { ids: walk, end });
    }
    HeaderPlan { rec, walks, cands, ids, gids: Vec::new() }
}

/// The rows of the planned records of one or more [`ServicePlan`]s (a record planned twice,
/// e.g. by svcdiff's scan and list walks of the same process, has one row).
pub struct RowStore {
    rows: Vec<Option<Result<RowRef>>>,
}

impl RowStore {
    /// The row at `i` (an error is python raising at the first use).
    fn take(&mut self, i: u32) -> Result<RowRef> {
        let i = i as usize;
        match &self.rows[i] {
            Some(Ok(r)) => Ok(r.clone()),
            _ => self.rows[i].take().expect("a failed row raises once"),
        }
    }
}

/// Compute the rows of every record planned in `plans` in one parallel pass (formatted with
/// `enc` when given) and point the plans at them.
pub fn compute_rows(plans: &mut [&mut ServicePlan], map: &BinaryMap, enc: Option<&RowEncoder>) -> RowStore {
    let mut uniq: FxHashMap<(usize, u64, u64), u32> = FxHashMap::default();
    let mut work: Vec<(Rec, Cand)> = Vec::new();
    for plan in plans.iter_mut() {
        for p in plan.procs.iter_mut() {
            let (rec, cands, gids) = match p {
                ProcPlan::Headers(hp) => (hp.rec, &hp.cands, &mut hp.gids),
                ProcPlan::Records { rec, cands, gids, .. } => (*rec, &*cands, gids),
            };
            let space = rec.sp as *const Space as usize;
            *gids = cands
                .iter()
                .map(|c| {
                    *uniq.entry((space, c.offset, c.rec.addr)).or_insert_with(|| {
                        work.push((rec, *c));
                        (work.len() - 1) as u32
                    })
                })
                .collect();
        }
    }
    drop(uniq);
    let one = |(rec, c): &(Rec, Cand)| row_of(rec, map, enc, c);
    let rows: Vec<Result<ServiceRow>> = if work.len() < PAR_MIN { work.iter().map(one).collect() } else { crate::util::par::par_map(work.len(), |i| one(&work[i])) };
    RowStore { rows: rows.into_iter().map(|r| Some(r.map(RowRef::new))).collect() }
}

/// The rows of a [`HeaderPlan`] to `c` in python's order: the walks are replayed with the rows
/// of `store`; a walk that goes on past its planned records continues record by record with
/// the rows computed (a record's row only depends on the record and its offset).
fn replay_headers(hp: HeaderPlan, store: &mut RowStore, map: &BinaryMap, enc: Option<&RowEncoder>, c: &mut dyn RowConsumer) -> Result<()> {
    let HeaderPlan { rec, walks, ids, gids, .. } = hp;
    'walks: for p in walks {
        match p {
            Planned::Raise(e) => return Err(e),
            Planned::Walk { ids: walk, end } => {
                for id in walk {
                    if !c.row(store.take(gids[id as usize])?)? {
                        continue 'walks;
                    }
                }
                match end {
                    WalkEnd::Finished => {}
                    WalkEnd::Raised(e) => return Err(e),
                    WalkEnd::Resume(mut t) => loop {
                        let cand = match t.next() {
                            None => break,
                            Some(Err(e)) => return Err(e),
                            Some(Ok(cand)) => cand,
                        };
                        let row = match ids.get(&(cand.offset, cand.rec.addr)) {
                            Some(&id) => store.take(gids[id as usize])?,
                            None => RowRef::new(row_of(&rec, map, enc, &cand)?),
                        };
                        if !c.row(row)? {
                            break;
                        }
                    },
                }
            }
        }
    }
    Ok(())
}

/// Every row to a callback (svclist).
struct All<'a>(&'a mut dyn FnMut(RowRef) -> Result<()>);

impl RowConsumer for All<'_> {
    fn row(&mut self, row: RowRef) -> Result<bool> {
        (self.0)(row)?;
        Ok(true)
    }
}

/// svcscan's `seen` list: `break` at the first row equal to an earlier one.
struct Dedup<'a> {
    /// python's `seen` list, indexed by offset (only comparable tuples can ever match)
    seen: FxHashMap<u64, Vec<RowKey>>,
    f: &'a mut dyn FnMut(RowRef) -> Result<()>,
}

impl RowConsumer for Dedup<'_> {
    fn row(&mut self, row: RowRef) -> Result<bool> {
        if let Some(key) = &row.key {
            let v = self.seen.entry(key.offset).or_default();
            if v.contains(key) {
                return Ok(false);
            }
            v.push(key.clone());
        }
        (self.f)(row)?;
        Ok(true)
    }
}

/// What one process contributes to a service walk.
enum ProcPlan {
    /// Vista and later: `_SERVICE_HEADER` walks
    Headers(HeaderPlan),
    /// XP / 2003: every valid `_SERVICE_RECORD` at a tag hit, then where python raised
    Records { rec: Rec, cands: Vec<Cand>, gids: Vec<u32>, tail: Option<Error> },
}

/// svcscan's / svclist's memory walks (everything but the rows, which need the registry's
/// binary map): the processes' plans, then where python raised (after their rows).
pub struct ServicePlan {
    procs: Vec<ProcPlan>,
    raise: Option<Error>,
}

/// The walks of python `SvcScan.service_scan(...)` over the `services.exe` processes.
pub fn plan_service_scan(k: &WinKernel, table: TableRef) -> ServicePlan {
    let mut procs = Vec::new();
    let raise = (|| -> Result<()> {
        let fields = RecFields::new(table);
        let is_vista_or_later = versions::IS_VISTA_OR_LATER.check(k.table);
        let tag: &[u8] = if is_vista_or_later { b"serH" } else { b"sErv" };
        let tag_off = Obj::named(Space::on(k.vlayer, table), "_SERVICE_RECORD", 0)?.member_offset("Tag")?;
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
            let rec = Rec::new(proc_layer, table, fields);
            if is_vista_or_later {
                procs.push(ProcPlan::Headers(plan_headers(rec, &hits, true)));
                continue;
            }
            // every valid record is a row
            let mut cands = Vec::new();
            let mut tail = None;
            for offset in hits {
                match rec.record(offset.wrapping_sub(tag_off)) {
                    Ok(r) if rec.is_valid(&r) => cands.push(Cand { rec: r, offset: r.addr }),
                    Ok(_) => {}
                    Err(e) => {
                        tail = Some(e);
                        break;
                    }
                }
            }
            procs.push(ProcPlan::Records { rec, cands, gids: Vec::new(), tail });
        }
        Ok(())
    })()
    .err();
    ServicePlan { procs, raise }
}

/// The walks of python `SvcList.service_list(...)` (the `Sc27` headers inside the
/// services.exe image).
pub fn plan_service_list(k: &WinKernel, table: TableRef) -> ServicePlan {
    let mut procs = Vec::new();
    if !k.table.is_64bit() || !versions::IS_WIN10_15063_OR_LATER.check(k.table) {
        // python: vollog.warning("This plugin only supports Windows 10 version 15063+ ...")
        return ServicePlan { procs, raise: None };
    }
    let raise = (|| -> Result<()> {
        let fields = RecFields::new(table);
        for proc in crate::plugins::windows::pslist::list_processes(k, &services_filter) {
            let proc = proc?;
            let proc_layer = match proc.add_process_layer() {
                Ok(l) => l,
                Err(e) if e.is_invalid_address() => {
                    // the warning's f-string reads the pid
                    proc.m("UniqueProcessId")?.int()?;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let Some(range) = get_exe_range(&proc)? else { continue };
            let offsets = scan(proc_layer, &BytesScanner::new(b"Sc27"), Some(&[range]));
            procs.push(ProcPlan::Headers(plan_headers(Rec::new(proc_layer, table, fields), &offsets, false)));
        }
        Ok(())
    })()
    .err();
    ServicePlan { procs, raise }
}

/// python `SvcList._get_exe_range(proc)`: `[(start, size)]` of the VAD mapping
/// `...\services.exe`, or None.
fn get_exe_range(proc: &Obj) -> Result<Option<(u64, u64)>> {
    for vad in proc.get_vad_root()?.traverse() {
        let vad = vad?;
        if let Value::Str(f) = vad.get_file_name() {
            if f.to_lowercase().ends_with("\\services.exe") {
                return Ok(Some((vad.get_start()?, vad.get_size()?)));
            }
        }
    }
    Ok(None)
}

/// The rows python yields for a [`ServicePlan`], in order, to `f`, from `store` (see
/// [`compute_rows`]; rows past the planned records are computed with `map` / `enc`); `dedup` =
/// svcscan's `seen` break (the header walks of svclist have none).
pub fn replay_services(plan: ServicePlan, store: &mut RowStore, map: &BinaryMap, enc: Option<&RowEncoder>, dedup: bool, f: &mut dyn FnMut(RowRef) -> Result<()>) -> Result<()> {
    let mut seen = Dedup { seen: FxHashMap::default(), f };
    for p in plan.procs {
        match p {
            ProcPlan::Headers(hp) => {
                if dedup {
                    replay_headers(hp, store, map, enc, &mut seen)?;
                } else {
                    replay_headers(hp, store, map, enc, &mut All(&mut *seen.f))?;
                }
            }
            ProcPlan::Records { gids, tail, .. } => {
                for g in gids {
                    (seen.f)(store.take(g)?)?;
                }
                if let Some(e) = tail {
                    return Err(e);
                }
            }
        }
    }
    match plan.raise {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// [`compute_rows`] + [`replay_services`] for one plan.
fn run_plan(mut plan: ServicePlan, map: &BinaryMap, enc: Option<&RowEncoder>, dedup: bool, f: &mut dyn FnMut(RowRef) -> Result<()>) -> Result<()> {
    let mut store = compute_rows(&mut [&mut plan], map, enc);
    replay_services(plan, &mut store, map, enc, dedup, f)
}

/// python `SvcScan.service_scan(...)`: rows in python order; `f` gets every row python yields
/// (formatted with `enc` when given).
pub fn service_scan(k: &WinKernel, pre: &Prereq, enc: Option<&RowEncoder>, f: &mut dyn FnMut(RowRef) -> Result<()>) -> Result<()> {
    run_plan(plan_service_scan(k, pre.table), &pre.binary_map, enc, true, f)
}

/// python `SvcList.service_list(...)`: every row python yields, in order (formatted with `enc`
/// when given).
pub fn service_list(k: &WinKernel, pre: &Prereq, enc: Option<&RowEncoder>, f: &mut dyn FnMut(RowRef) -> Result<()>) -> Result<()> {
    run_plan(plan_service_list(k, pre.table), &pre.binary_map, enc, false, f)
}

/// The SvcScan / SvcList plugin body: prerequisites, the memory walks (meanwhile), the rows
/// (formatted on the workers), emitted in order.
pub fn run_service_plugin(ctx: &Context, k: &WinKernel, list: bool, out: &mut dyn RowSink) -> Result<()> {
    let (pre, plan) = with_prereq(ctx, k, |table| if list { plan_service_list(k, table) } else { plan_service_scan(k, table) })?;
    let enc = out.encoder();
    run_plan(plan, &pre.binary_map, enc.as_ref(), !list, &mut |row| row.emit(out))
}

/// python's `get_prereq_info(...)` followed by `plan(table)`, with the registry part of the
/// prerequisites (the ServiceDll / ImagePath map, which only the rows need) read on another
/// thread meanwhile. python's error order: the prerequisites raise first.
pub fn with_prereq<P>(ctx: &Context, k: &WinKernel, plan: impl FnOnce(TableRef) -> P) -> Result<(Prereq, P)> {
    let table = create_service_table(ctx, k)?;
    std::thread::scope(|s| {
        let h = s.spawn(|| get_binary_map(ctx, k));
        let p = plan(table);
        let map = match h.join() {
            Ok(m) => m?,
            Err(panic) => std::panic::resume_unwind(panic),
        };
        Ok((Prereq { table, binary_map: map }, p))
    })
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
        run_service_plugin(ctx, k, false, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::GlobalOptions;

    /// python's `enumerate_vista_or_later_header` + `service_scan` loop, one record at a time
    /// (the reference for the windowed / parallel walk).
    fn reference_scan(k: &WinKernel, pre: &Prereq, list: bool) -> Vec<Vec<Value>> {
        let fields = RecFields::new(pre.table);
        let mut rows = Vec::new();
        let mut seen: Vec<RowKey> = Vec::new();
        let tag: &[u8] = if list { b"Sc27" } else { b"serH" };
        for task in crate::plugins::windows::pslist::list_processes(k, &services_filter) {
            let task = task.unwrap();
            let Ok(layer) = task.add_process_layer() else { continue };
            let mut sections = Vec::new();
            for vad in task.get_vad_root().unwrap().traverse() {
                let vad = vad.unwrap();
                let file = vad.get_file_name();
                if list && !matches!(&file, Value::Str(f) if f.to_lowercase().ends_with("\\services.exe")) {
                    continue;
                }
                if vad.get_size().unwrap() != 0 {
                    sections.push((vad.get_start().unwrap(), vad.get_size().unwrap()));
                }
                if list {
                    break;
                }
            }
            let rec = Rec::new(layer, pre.table, fields);
            for offset in scan(layer, &BytesScanner::new(tag), Some(&sections)) {
                if offset % 8 != 0 {
                    continue;
                }
                let header = Obj::named(rec.sp, "_SERVICE_HEADER", offset).unwrap();
                let Ok(v) = header.m("ServiceRecord").and_then(|p| p.u64()) else { continue };
                let first = rec.record(v).unwrap();
                if !rec.is_valid(&first) {
                    continue;
                }
                let mut take = |row: ServiceRow| -> bool {
                    if !list {
                        if let Some(key) = &row.key {
                            if seen.contains(key) {
                                return false;
                            }
                            seen.push(key.clone());
                        }
                    }
                    rows.push(row.values);
                    true
                };
                if !take(rec.row(&first, first.addr, &pre.binary_map).unwrap()) {
                    continue;
                }
                let mut ptr = first.m("PrevEntry").unwrap();
                loop {
                    let Ok(v) = ptr.u64() else { break };
                    if v == 0 {
                        break;
                    }
                    let r = ptr.deref().unwrap();
                    if !rec.is_valid(&r) || !take(rec.row(&r, ptr.addr, &pre.binary_map).unwrap()) {
                        break;
                    }
                    ptr = r.m("PrevEntry").unwrap();
                }
            }
        }
        rows
    }

    /// The windowed, parallel walks give python's rows (svcscan's `seen` break included) on the
    /// Windows 10 / 11 test images.
    #[test]
    #[ignore]
    fn service_walks_match_sequential_reference() {
        for img in ["/home/user/cbc2/task2/memory-dirty.raw", "/home/user/rs-vol/testdata/images/windows/rsvol-win10-x64-17763-imagery.raw"] {
            if !std::path::Path::new(img).exists() {
                continue;
            }
            let ctx = Context::new(GlobalOptions { file: Some(img.into()), ..Default::default() }).unwrap();
            let k = ctx.windows_kernel().unwrap();
            let pre = get_prereq_info(&ctx, k).unwrap();
            let mut got = Vec::new();
            service_scan(k, &pre, None, &mut |r| {
                got.push(r.values.clone());
                Ok(())
            })
            .unwrap();
            let want = reference_scan(k, &pre, false);
            assert!(want.len() > 500, "{img}: {} rows", want.len());
            assert_eq!(format!("{got:?}"), format!("{want:?}"), "{img} svcscan");
            let mut got = Vec::new();
            service_list(k, &pre, None, &mut |r| {
                got.push(r.values.clone());
                Ok(())
            })
            .unwrap();
            let want = reference_scan(k, &pre, true);
            assert!(want.len() > 500, "{img}: {} rows", want.len());
            assert_eq!(format!("{got:?}"), format!("{want:?}"), "{img} svclist");
            println!("{img}: svclist {} rows identical", got.len());
        }
    }
}
