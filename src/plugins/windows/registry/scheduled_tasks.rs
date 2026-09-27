//! windows.registry.scheduled_tasks.ScheduledTasks (python `plugins/windows/registry/
//! scheduled_tasks.py`): decodes scheduled tasks from the SOFTWARE hive's
//! `Schedule\TaskCache` (Actions / Triggers / DynamicInfo RegBin blobs). Also registered as the
//! deprecated alias `windows.scheduled_tasks.ScheduledTasks`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//! Reference: https://cyber.wtf/2022/06/01/windows-registry-analysis-todays-episode-tasks/

use crate::context::Context;
use crate::error::Result;
use crate::layers::registry::{RegistryHive, is_registry_exception};
use crate::objects::Obj;
use crate::plugins::{Config, Plugin, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::registry::{RegData, RegExt, RegValueType, is_key_error};
use crate::util::time::wintime_to_datetime;
use std::collections::HashMap;

pub struct ScheduledTasks;

// ---- byte reader (python `_ScheduledTasksReader`, an io.BytesIO) ------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }
    fn tell(&self) -> usize {
        self.pos
    }
    /// python BytesIO.read(n): returns up to `n` bytes, advancing by what was returned.
    fn read(&mut self, n: usize) -> &'a [u8] {
        let start = self.pos.min(self.data.len());
        let end = (self.pos + n).min(self.data.len());
        self.pos += n; // pos may pass the end (BytesIO semantics)
        if start <= end { &self.data[start..end] } else { &[] }
    }
    /// python BytesIO.read() to end (used when a length is None).
    fn read_rest(&mut self) -> &'a [u8] {
        let start = self.pos.min(self.data.len());
        self.pos = self.data.len();
        &self.data[start..]
    }
    /// python seek(delta, SEEK_CUR).
    fn seek_cur(&mut self, delta: i64) {
        self.pos = (self.pos as i64 + delta).max(0) as usize;
    }
    /// python seek(pos) (absolute).
    fn seek_set(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn read_uint(&mut self, size: usize, aligned: bool) -> Option<u64> {
        let b = self.read(size);
        if b.len() != size {
            return None;
        }
        let mut v = 0u64;
        for (i, &byte) in b.iter().enumerate() {
            v |= (byte as u64) << (8 * i);
        }
        if aligned {
            self.seek_cur(8 - size as i64);
        }
        Some(v)
    }
    fn read_aligned_u1(&mut self) -> Option<u8> {
        self.read_uint(1, true).map(|v| v as u8)
    }
    fn read_u2(&mut self) -> Option<u16> {
        self.read_uint(2, false).map(|v| v as u16)
    }
    fn read_u4(&mut self) -> Option<u32> {
        self.read_uint(4, false).map(|v| v as u32)
    }
    fn read_aligned_u4(&mut self) -> Option<u32> {
        self.read_uint(4, true).map(|v| v as u32)
    }
    fn read_u8(&mut self) -> Option<u64> {
        self.read_uint(8, false)
    }
    /// python `read_bool` (aligned variant does an *absolute* seek(7), a faithfully-ported bug,
    /// but it is never called with aligned=True).
    fn read_bool(&mut self, aligned: bool) -> Option<bool> {
        let b = self.read(1);
        if b.len() != 1 {
            return None;
        }
        if aligned {
            self.seek_set(7);
        }
        Some(b[0] != 0)
    }
    /// python `decode_filetime`.
    fn decode_filetime(&mut self) -> Option<Value> {
        let filetime = self.read_u8()?;
        if filetime == 0 || filetime == 0xFFFF_FFFF_FFFF_FFFF {
            return None;
        }
        match wintime_to_datetime(filetime as i128) {
            v @ Value::DateTime(_) => Some(v),
            _ => None,
        }
    }
    /// python `read_task_scheduler_time`.
    fn read_task_scheduler_time(&mut self) -> Option<Value> {
        let _ = self.read_aligned_u1(); // is_localized
        self.decode_filetime()
    }
    /// python `read_buffer`.
    fn read_buffer(&mut self, aligned: bool) -> Option<Vec<u8>> {
        let count = if aligned { self.read_aligned_u4() } else { self.read_u4() }? as usize;
        let data = self.read(count).to_vec();
        if aligned {
            self.seek_cur(((8 - (count % 8)) % 8) as i64);
        }
        Some(data)
    }
    /// python `read_bstring` (utf-16le, errors="replace", rstrip NUL, empty -> None).
    fn read_bstring(&mut self, aligned: bool) -> Option<String> {
        let size = if aligned { self.read_aligned_u4() } else { self.read_u4() }? as usize;
        let raw = self.read(size);
        let val = decode_utf16le_replace(raw);
        let val = val.trim_end_matches('\u{0000}').to_string();
        let out = if val.is_empty() { None } else { Some(val) };
        if aligned {
            self.seek_cur(((8 - (size % 8)) % 8) as i64);
        }
        out
    }
    /// python `read_aligned_bstring_expand_sz` (utf-16le strict; error -> None).
    fn read_aligned_bstring_expand_sz(&mut self) -> Option<String> {
        let sz = self.read_aligned_u4()? as usize;
        let byte_count = sz * 2 + 2;
        if sz == 0 {
            return None;
        }
        let raw = self.read(byte_count);
        let content = decode_utf16le_strict(raw);
        self.seek_cur(((8 - (byte_count % 8)) % 8) as i64);
        content.map(|c| c.trim_end_matches('\u{0000}').to_string())
    }
    /// python `read_tstimeperiod` (7 u2s); consumes 14 bytes.
    fn read_tstimeperiod(&mut self) -> Option<[u16; 7]> {
        let v = [self.read_u2(), self.read_u2(), self.read_u2(), self.read_u2(), self.read_u2(), self.read_u2(), self.read_u2()];
        if v.iter().any(|x| x.is_none()) {
            return None;
        }
        Some([v[0].unwrap(), v[1].unwrap(), v[2].unwrap(), v[3].unwrap(), v[4].unwrap(), v[5].unwrap(), v[6].unwrap()])
    }
}

fn decode_utf16le_replace(b: &[u8]) -> String {
    let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    char::decode_utf16(units).map(|r| r.unwrap_or('\u{FFFD}')).collect()
}
fn decode_utf16le_strict(b: &[u8]) -> Option<String> {
    if b.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    char::decode_utf16(units).collect::<std::result::Result<String, _>>().ok()
}

/// python `conversion.windows_bytes_to_guid` (minimal-digit lowercase hex, not zero-padded).
fn windows_bytes_to_guid(buf: &[u8]) -> Option<String> {
    if buf.len() != 16 {
        return None;
    }
    let a = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let b = u16::from_le_bytes([buf[4], buf[5]]);
    let c = u16::from_le_bytes([buf[6], buf[7]]);
    let d = u16::from_be_bytes([buf[8], buf[9]]);
    let e = u64::from_be_bytes([0, 0, buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]);
    Some(format!("{{{a:x}-{b:x}-{c:x}-{d:x}-{e:x}}}"))
}

/// python `decode_sid`.
fn decode_sid(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }
    let revision = data[0];
    let subid_count = data[1] as usize;
    let id_authority = u64::from_be_bytes([0, 0, data[2], data[3], data[4], data[5], data[6], data[7]]);
    if data.len() < 8 + subid_count * 4 {
        return None;
    }
    let mut parts = vec![revision.to_string(), id_authority.to_string()];
    for i in 0..subid_count {
        let o = 8 + i * 4;
        parts.push(u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]).to_string());
    }
    Some(format!("S-{}", parts.join("-")))
}

// ---- enums --------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActionType {
    Exe,
    ComHandler,
    // Email actions are decoded (bytes consumed) but python's `_decode_email_action` never
    // returns one (missing `return`), so this variant is never constructed.
    #[allow(dead_code)]
    Email,
    MessageBox,
}
impl ActionType {
    fn name(self) -> &'static str {
        match self {
            ActionType::Exe => "Exe",
            ActionType::ComHandler => "ComHandler",
            ActionType::Email => "Email",
            ActionType::MessageBox => "MessageBox",
        }
    }
}

#[derive(Clone, Copy)]
enum TriggerType {
    WindowsNotificationFacility,
    Session,
    Registration,
    Logon,
    Event,
    Time,
    Idle,
    Boot,
}
impl TriggerType {
    fn from_magic(m: u32) -> Option<TriggerType> {
        Some(match m {
            0x6666 => TriggerType::WindowsNotificationFacility,
            0x7777 => TriggerType::Session,
            0x8888 => TriggerType::Registration,
            0xAAAA => TriggerType::Logon,
            0xCCCC => TriggerType::Event,
            0xDDDD => TriggerType::Time,
            0xEEEE => TriggerType::Idle,
            0xFFFF => TriggerType::Boot,
            _ => return None,
        })
    }
    fn name(self) -> &'static str {
        match self {
            TriggerType::WindowsNotificationFacility => "WindowsNotificationFacility",
            TriggerType::Session => "Session",
            TriggerType::Registration => "Registration",
            TriggerType::Logon => "Logon",
            TriggerType::Event => "Event",
            TriggerType::Time => "Time",
            TriggerType::Idle => "Idle",
            TriggerType::Boot => "Boot",
        }
    }
}

fn sid_type_name(v: u32) -> &'static str {
    match v {
        1 => "SidType.User",
        2 => "SidType.Group",
        3 => "SidType.Domain",
        4 => "SidType.Alias",
        5 => "SidType.WellKnownGroup",
        6 => "SidType.DeletedAccount",
        7 => "SidType.Invalid",
        8 => "SidType.Unknown",
        9 => "SidType.Computer",
        10 => "SidType.Label",
        11 => "SidType.LogonSession",
        _ => "SidType.Unknown",
    }
}

fn session_state_name(v: u32) -> &'static str {
    match v {
        1 => "ConsoleConnect",
        2 => "ConsoleDisconnect",
        3 => "RemoteConnect",
        4 => "RemoteDisconnect",
        5 => "SessionLock",
        6 => "SessionUnlock",
        _ => "Unknown",
    }
}





// ---- decoded structures -------------------------------------------------------------------

struct TaskAction {
    action_type: ActionType,
    action: String,
    action_args: Option<String>,
    working_directory: Option<String>,
}

struct TaskTrigger {
    enabled: Option<bool>,
    trigger_type: TriggerType,
    description: Option<String>,
}

struct JobBucket {
    principal_id: Option<String>,
    display_name: Option<String>,
}

struct UserInfo {
    sid_type: u32,
    sid: Option<String>,
    username: Option<String>,
}

/// python `UserInfo._decode`.
fn decode_user_info(r: &mut Reader) -> Option<UserInfo> {
    // read_aligned_u1() != 0 : None compares != 0 as True in python
    let skip_user = r.read_aligned_u1().map(|v| v != 0).unwrap_or(true);
    let skip_sid = if !skip_user { Some(r.read_aligned_u1().map(|v| v != 0).unwrap_or(true)) } else { None };
    let mut sid_type = 0u32;
    let mut sid = None;
    if !skip_user && skip_sid == Some(false) {
        sid_type = r.read_aligned_u4().unwrap_or(8); // ValueError -> SidType.Unknown(8)
        let sid_raw = r.read_buffer(true)?;
        sid = decode_sid(&sid_raw);
    }
    let username = if !skip_user { r.read_bstring(true) } else { None };
    Some(UserInfo { sid_type, sid, username })
}

/// python `OptionalSettings._decode` — only consumes bytes (its fields are not rendered).
fn decode_optional_settings(r: &mut Reader) -> Option<()> {
    const LEN_WITH_PRIVILEGES: u32 = 0x38;
    const LEN_WITH_TIME_PERIODS: u32 = 0x58;
    let length = r.read_aligned_u4();
    if length == Some(0) {
        return None;
    }
    let base = [r.read_u4(), r.read_u4(), r.read_u4(), r.read_u4(), r.read_u4(), r.read_u4(), r.read_u4()];
    let net_id = r.read(16);
    if base.iter().any(|x| x.is_none()) || net_id.len() != 16 {
        return None;
    }
    r.seek_cur(4); // padding
    let length = length.unwrap_or(u32::MAX);
    if length == LEN_WITH_PRIVILEGES || length == LEN_WITH_TIME_PERIODS {
        let _privileges_raw = r.read_u8()?;
    }
    if length == LEN_WITH_TIME_PERIODS {
        r.read_tstimeperiod();
        r.read_tstimeperiod();
        r.read_bool(false);
        r.seek_cur(3);
    }
    Some(())
}

/// python `JobBucket._decode`.
fn decode_job_bucket(r: &mut Reader, version: u8) -> Option<JobBucket> {
    let _flags_raw = r.read_aligned_u4()?;
    let _crc32 = r.read_aligned_u4()?;
    let mut principal_id = None;
    let mut display_name = None;
    if version >= 0x16 {
        principal_id = r.read_bstring(true);
    }
    if version >= 0x17 {
        display_name = r.read_bstring(true);
    }
    decode_user_info(r);
    decode_optional_settings(r);
    Some(JobBucket { principal_id, display_name })
}

/// python `_JobSchedule.decode` (only `start_boundary` / `is_enabled` are used; the mode always
/// decodes to Unknown since TimeMode's values are strings, so the description is always None).
struct JobSchedule {
    is_enabled: Option<bool>,
}
fn decode_job_schedule(r: &mut Reader) -> Option<JobSchedule> {
    let _start = r.read_task_scheduler_time();
    let _end = r.read_task_scheduler_time();
    let _ = r.read_task_scheduler_time();
    let _rep_interval = r.read_u4();
    let _rep_duration = r.read_u4();
    let _exec_limit = r.read_u4();
    let _mode_index = r.read_u4();
    let _data1 = r.read_u2();
    let _data2 = r.read_u2();
    let _data3 = r.read_u2();
    r.seek_cur(2); // pad
    let _stop = r.read_bool(false);
    let is_enabled = r.read_bool(false);
    r.seek_cur(6); // pad(2)+unknown(4)
    let _max_delay = r.read_u4();
    r.seek_cur(4); // pad
    Some(JobSchedule { is_enabled })
}

// ---- trigger decoders ---------------------------------------------------------------------

fn decode_generic_trigger(r: &mut Reader, version: u8, trigger_type: TriggerType) -> Option<TaskTrigger> {
    let _start = r.read_task_scheduler_time();
    let _end = r.read_task_scheduler_time();
    let _ = r.read_u4(); // delay
    let _ = r.read_u4(); // timeout
    let _rep_interval = r.read_u4();
    let _ = r.read_u4();
    let _ = r.read_u4();
    let _ = r.read_bool(false); // stop at duration end
    r.seek_cur(3);
    let trigger_enabled = r.read_aligned_u1().unwrap_or(0) != 0;
    r.seek_cur(8); // unknown
    if version >= 0x16 {
        let cur = r.tell();
        let _ = r.read_bstring(false); // trigger id
        r.seek_cur(((8 - (r.tell() - cur) % 8) % 8) as i64);
    }
    Some(TaskTrigger { enabled: Some(trigger_enabled), trigger_type, description: Some(format!("{} trigger", trigger_type.name())) })
}

fn decode_logon_trigger(r: &mut Reader, version: u8) -> Option<TaskTrigger> {
    let mut base = decode_generic_trigger(r, version, TriggerType::Logon)?;
    if let Some(user) = decode_user_info(r) {
        if let Some(username) = &user.username {
            base.description = Some(format!("{}: {} ({})", username, user.sid.clone().unwrap_or_else(|| "None".to_string()), sid_type_name(user.sid_type)));
        }
    }
    Some(base)
}

fn decode_session_trigger(r: &mut Reader, version: u8) -> Option<TaskTrigger> {
    let mut base = decode_generic_trigger(r, version, TriggerType::Session)?;
    let session_type_raw = r.read_u4();
    r.seek_cur(4);
    let st = session_state_name(session_type_raw.unwrap_or(u32::MAX));
    let user_info = decode_user_info(r);
    base.description = match user_info.as_ref().and_then(|u| u.username.as_ref()) {
        Some(username) => Some(format!("{st} for user {username}")),
        None => Some(st.to_string()),
    };
    Some(base)
}

fn decode_time_trigger(r: &mut Reader, version: u8) -> Option<TaskTrigger> {
    let job = decode_job_schedule(r)?;
    if version >= 0x16 {
        let cur = r.tell();
        let _ = r.read_bstring(false);
        r.seek_cur(((8 - (r.tell() - cur) % 8) % 8) as i64);
    }
    // TimeMode always decodes to Unknown -> get_description() is always None.
    Some(TaskTrigger { enabled: job.is_enabled, trigger_type: TriggerType::Time, description: None })
}

fn decode_event_trigger(r: &mut Reader, version: u8) -> Option<TaskTrigger> {
    let mut base = decode_generic_trigger(r, version, TriggerType::Event)?;
    let subscription = r.read_aligned_bstring_expand_sz();
    r.seek_cur(8);
    let _ = r.read_aligned_bstring_expand_sz();
    let len_value_queries = match r.read_aligned_u4() {
        Some(n) => n,
        None => return Some(base),
    };
    let mut valid: Vec<(String, String)> = Vec::new();
    for _ in 0..len_value_queries {
        let k = r.read_aligned_bstring_expand_sz();
        let v = r.read_aligned_bstring_expand_sz();
        if let (Some(k), Some(v)) = (k, v) {
            valid.push((k, v));
        }
    }
    if base.description.is_none() {
        base.description = Some("Event Trigger".to_string());
    }
    let subs = subscription.as_deref().map(py_repr_none_or).unwrap_or_else(|| "None".to_string());
    let d = base.description.take().unwrap();
    base.description = Some(format!("{d}: Subscription: {subs}, Queries: {}", py_list_repr(&valid)));
    Some(base)
}

/// python f-string of an Optional[str]: the string itself (unquoted) or "None".
fn py_repr_none_or(s: &str) -> String {
    s.to_string()
}

/// python `str([(k, v), ...])` for a list of string tuples.
fn py_list_repr(v: &[(String, String)]) -> String {
    let mut s = String::from("[");
    for (i, (k, val)) in v.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&format!("({}, {})", py_str_repr(k), py_str_repr(val)));
    }
    s.push(']');
    s
}

/// python `repr(str)` (single-quoted, with the common escapes).
fn py_str_repr(s: &str) -> String {
    let use_double = s.contains('\'') && !s.contains('"');
    let q = if use_double { '"' } else { '\'' };
    let mut out = String::new();
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

fn decode_wnf_trigger(r: &mut Reader, version: u8) -> Option<TaskTrigger> {
    let mut base = decode_generic_trigger(r, version, TriggerType::WindowsNotificationFacility)?;
    let state = r.read(8);
    let state_name: String = state.iter().map(|b| format!("{b:02x}")).collect();
    let datalen = r.read_aligned_u4();
    match datalen {
        Some(n) => {
            let _ = r.read(n as usize);
        }
        None => {
            let _ = r.read_rest();
        }
    }
    base.description = Some(format!("WNF state {state_name}"));
    Some(base)
}

// ---- action / trigger / dynamic-info sets -------------------------------------------------

fn decode_messagebox_action(r: &mut Reader) -> Option<TaskAction> {
    let caption = r.read_bstring(false);
    let content = r.read_bstring(false);
    Some(TaskAction {
        action_type: ActionType::MessageBox,
        action: format!("\"{}\": {}", caption.as_deref().unwrap_or("<Unknown>"), content.as_deref().unwrap_or("<Unknown>")),
        action_args: None,
        working_directory: None,
    })
}

fn decode_exe_action(r: &mut Reader, version: u16) -> Option<TaskAction> {
    let command = r.read_bstring(false);
    let args = r.read_bstring(false);
    let (command, args) = match (command, args) {
        (Some(c), Some(a)) => (c, a),
        _ => return None,
    };
    let workdir = r.read_bstring(false);
    if version == 3 {
        let _flags = r.read_u2();
    }
    Some(TaskAction { action_type: ActionType::Exe, action: command, action_args: Some(args), working_directory: workdir })
}

fn decode_email_action(r: &mut Reader) -> Option<TaskAction> {
    // python builds the action but never returns it (missing `return`), so this always yields None.
    for _ in 0..8 {
        let _ = r.read_bstring(false);
    }
    if let Some(n) = r.read_u4() {
        for _ in 0..n {
            let _ = r.read_bstring(false);
        }
    }
    if let Some(n) = r.read_u4() {
        for _ in 0..n {
            let _ = r.read_bstring(false);
            let _ = r.read_bstring(false);
        }
    }
    None
}

fn decode_comhandler_action(r: &mut Reader) -> Option<TaskAction> {
    let guid_raw = r.read(16).to_vec();
    // python: `if not guid_raw and len(guid_raw) == 16: return None` -> never true; keep going.
    let clsid = windows_bytes_to_guid(&guid_raw).unwrap_or_default();
    let args = r.read_bstring(false);
    Some(TaskAction { action_type: ActionType::ComHandler, action: clsid, action_args: args, working_directory: None })
}

struct ActionSet {
    actions: Vec<Option<TaskAction>>,
    context: Option<String>,
}
fn decode_action_set(data: &[u8]) -> Option<ActionSet> {
    let mut r = Reader::new(data);
    let mut actions = Vec::new();
    let version = r.read_u2()?;
    let context = if version == 2 || version == 3 { r.read_bstring(false) } else { None };
    loop {
        let magic = match r.read_u2() {
            Some(m) => m,
            None => break,
        };
        let _ = r.read_bstring(false); // action identifier
        let action = match magic {
            0x8888 => decode_email_action(&mut r),
            0x6666 => decode_exe_action(&mut r, version),
            0x7777 => decode_comhandler_action(&mut r),
            0x9999 => decode_messagebox_action(&mut r),
            _ => break,
        };
        // python appends the action even when it is None.
        actions.push(action);
    }
    Some(ActionSet { actions, context })
}

struct TriggerSet {
    job_bucket: JobBucket,
    triggers: Vec<Option<TaskTrigger>>,
}
fn decode_trigger_set(data: &[u8]) -> Option<TriggerSet> {
    let mut r = Reader::new(data);
    let version = r.read_aligned_u1();
    let _ = r.read_task_scheduler_time();
    let _ = r.read_task_scheduler_time();
    let version = version?;
    let job_bucket = decode_job_bucket(&mut r, version)?;
    let mut triggers: Vec<Option<TaskTrigger>> = Vec::new();
    loop {
        let magic = match r.read_aligned_u4() {
            Some(m) => m,
            None => break,
        };
        let trigger_type = match TriggerType::from_magic(magic) {
            Some(t) => t,
            None => break, // "Invalid trigger magic {hex}"
        };
        let trigger = match trigger_type {
            TriggerType::Logon => decode_logon_trigger(&mut r, version),
            TriggerType::Session => decode_session_trigger(&mut r, version),
            TriggerType::WindowsNotificationFacility => decode_wnf_trigger(&mut r, version),
            TriggerType::Boot => decode_generic_trigger(&mut r, version, TriggerType::Boot),
            TriggerType::Registration => decode_generic_trigger(&mut r, version, TriggerType::Logon),
            TriggerType::Event => decode_event_trigger(&mut r, version),
            TriggerType::Idle => decode_generic_trigger(&mut r, version, TriggerType::Logon),
            TriggerType::Time => decode_time_trigger(&mut r, version),
        };
        triggers.push(trigger);
    }
    Some(TriggerSet { job_bucket, triggers })
}

struct DynamicInfo {
    creation_time: Option<Value>,
    last_run_time: Option<Value>,
    last_successful_run_time: Option<Value>,
}
fn decode_dynamic_info(data: &[u8]) -> Option<DynamicInfo> {
    let mut r = Reader::new(data);
    let magic = r.read_u4();
    if magic != Some(3) {
        return None;
    }
    let creation_time = r.decode_filetime(); // 1st
    let last_run_time = r.decode_filetime(); // 2nd
    r.seek_cur(4); // deprecated TaskState
    let _last_error = r.read_u4();
    let last_success = r.decode_filetime(); // 3rd
    // python: cls(last_run_time, creation_time, last_success, err) with fields
    // (creation_time, last_run_time, last_successful_run_time, ...): creation<-2nd, run<-1st.
    Some(DynamicInfo { creation_time: last_run_time, last_run_time: creation_time, last_successful_run_time: last_success })
}

// ---- guid map + task-key parsing ----------------------------------------------------------

/// python `_build_guid_name_map`.
fn build_guid_name_map(key: &Obj, map: &mut HashMap<String, String>) {
    let mut id_value = None;
    for value in key.get_values() {
        match value.get_name() {
            Ok(n) if n == "Id" => {
                id_value = Some(value);
                break;
            }
            Ok(_) => {}
            Err(_) => continue,
        }
    }
    if let Some(v) = id_value {
        if matches!(v.get_value_type(), Ok(RegValueType::Sz)) {
            if let Ok(RegData::Bytes(b)) = v.decode_data() {
                if let Ok(name) = key.get_name() {
                    let id = decode_utf16le_replace(&b);
                    let id = id.trim_end_matches('\u{0000}').to_string();
                    map.insert(id, name);
                }
            }
        }
    }
    for subkey in key.get_subkeys() {
        if let Ok(sk) = subkey {
            build_guid_name_map(&sk, map);
        }
    }
}

/// A row (depth is always 0).
type Row = Vec<Value>;

fn absent_na() -> Value {
    Value::NotAvailable
}
fn opt_str(o: Option<String>) -> Value {
    match o {
        Some(s) => Value::Str(s),
        None => Value::NotAvailable,
    }
}
fn opt_time(o: &Option<Value>) -> Value {
    match o {
        Some(v) => v.clone(),
        None => Value::NotAvailable,
    }
}

/// python `_parse_task_key`.
fn parse_task_key(key: &Obj, guid_map: &HashMap<String, String>, rows: &mut Vec<Row>) -> Result<()> {
    let mut actions_v = None;
    let mut triggers_v = None;
    let mut dyninfo_v = None;
    for value in key.get_values() {
        let name = match value.get_name() {
            Ok(n) => n,
            Err(_) => continue,
        };
        match name.as_str() {
            "Actions" => actions_v = Some(value),
            "Triggers" => triggers_v = Some(value),
            "DynamicInfo" => dyninfo_v = Some(value),
            _ => {}
        }
    }
    let key_name = key.get_name().ok();
    let task_name = match &key_name {
        Some(k) => guid_map.get(k).cloned().map(Value::Str).unwrap_or(Value::NotAvailable),
        None => Value::NotAvailable,
    };

    let action_set = match &actions_v {
        Some(v) => parse_bytes_value(v, decode_action_set)?,
        None => None,
    };
    let trigger_set = match &triggers_v {
        Some(v) => parse_bytes_value(v, decode_trigger_set)?,
        None => None,
    };
    let (principal_id, display_name) = match &trigger_set {
        Some(ts) => (opt_str(ts.job_bucket.principal_id.clone()), opt_str(ts.job_bucket.display_name.clone())),
        None => (Value::NotAvailable, Value::NotAvailable),
    };
    let dynamic_info = match &dyninfo_v {
        Some(v) => parse_bytes_value(v, decode_dynamic_info)?,
        None => None,
    };
    let (creation_time, last_run_time, last_success) = match &dynamic_info {
        Some(di) => (opt_time(&di.creation_time), opt_time(&di.last_run_time), opt_time(&di.last_successful_run_time)),
        None => (Value::NotAvailable, Value::NotAvailable, Value::NotAvailable),
    };

    // all_triggers = triggers or [None] if trigger_set else [None]
    let all_triggers: Vec<Option<&TaskTrigger>> = match &trigger_set {
        Some(ts) if !ts.triggers.is_empty() => ts.triggers.iter().map(|t| t.as_ref()).collect(),
        _ => vec![None],
    };
    let all_actions: Vec<Option<&TaskAction>> = match &action_set {
        Some(a) if !a.actions.is_empty() => a.actions.iter().map(|o| o.as_ref()).collect(),
        _ => vec![None],
    };

    let context_val = match &action_set {
        Some(a) if a.context.is_some() => Value::Str(a.context.clone().unwrap()),
        _ => Value::NotAvailable,
    };
    let guid_val = opt_str(key_name.clone());

    for action in &all_actions {
        for trigger in &all_triggers {
            let (args, working_directory) = match action {
                Some(a) => {
                    let args = if matches!(a.action_type, ActionType::Exe | ActionType::ComHandler) {
                        match &a.action_args {
                            Some(s) => Value::Str(s.clone()),
                            None => Value::NotAvailable,
                        }
                    } else {
                        Value::NotApplicable
                    };
                    let wd = if a.action_type == ActionType::Exe {
                        match &a.working_directory {
                            Some(s) => Value::Str(s.clone()),
                            None => Value::NotAvailable,
                        }
                    } else {
                        Value::NotApplicable
                    };
                    (args, wd)
                }
                None => (Value::NotAvailable, Value::NotAvailable),
            };
            let enabled = match trigger {
                Some(t) if t.enabled.is_some() => Value::Bool(t.enabled.unwrap()),
                _ => Value::NotAvailable,
            };
            let trigger_type = match trigger {
                Some(t) => Value::SStr(t.trigger_type.name()),
                None => Value::NotAvailable,
            };
            let trigger_desc = match trigger {
                Some(t) => match &t.description {
                    Some(d) if !d.is_empty() => Value::Str(d.clone()),
                    _ => Value::NotAvailable,
                },
                None => Value::NotAvailable,
            };
            let action_type = match action {
                Some(a) => Value::SStr(a.action_type.name()),
                None => Value::NotAvailable,
            };
            let action_val = match action {
                Some(a) => Value::Str(a.action.clone()),
                None => Value::NotAvailable,
            };
            rows.push(vec![
                task_name.clone(),
                principal_id.clone(),
                display_name.clone(),
                enabled,
                creation_time.clone(),
                last_run_time.clone(),
                last_success.clone(),
                trigger_type,
                trigger_desc,
                action_type,
                action_val,
                args,
                context_val.clone(),
                working_directory,
                guid_val.clone(),
            ]);
        }
    }
    let _ = absent_na;
    Ok(())
}

/// python `parse_*_value`: decode_data(); if not bytes -> None; else decode(data).
fn parse_bytes_value<T>(value: &Obj, decode: fn(&[u8]) -> Option<T>) -> Result<Option<T>> {
    match value.decode_data() {
        Ok(RegData::Bytes(b)) => Ok(decode(&b)),
        Ok(RegData::Int(_)) => Ok(None),
        Err(e) if e.is_invalid_address() => Ok(None),
        Err(e) => Err(e),
    }
}

fn generate(ctx: &Context, cfg: &Config) -> Result<Vec<Row>> {
    let k = ctx.windows_kernel()?;
    let _ = cfg;
    let mut rows = Vec::new();
    let software = match super::hivelist::list_hives(ctx, k, Some("SOFTWARE"), None).into_iter().next() {
        Some(Ok(h)) => h,
        Some(Err(e)) => return Err(e),
        None => return Ok(rows), // "Failed to get SOFTWARE hive"
    };
    let (task_key, task_tree) = get_task_keys(software)?;
    let task_key = match task_key {
        Some(k) => k,
        None => return Ok(rows), // "Failed to get 'Tasks' key"
    };
    let mut guid_map = HashMap::new();
    if let Some(tree) = task_tree {
        build_guid_name_map(&tree, &mut guid_map);
    }
    // the task keys are independent: parsed in parallel, rows in python's order (python
    // raises at the first failing key, or where listing the keys failed)
    let mut keys: Vec<Obj> = Vec::new();
    let mut list_err = None;
    for key in task_key.get_subkeys() {
        match key {
            Ok(k) => keys.push(k),
            Err(e) => {
                list_err = Some(e);
                break;
            }
        }
    }
    let parsed = crate::util::par::par_map(keys.len(), |i| {
        let mut r = Vec::new();
        parse_task_key(&keys[i], &guid_map, &mut r).map(|_| r)
    });
    for p in parsed {
        rows.extend(p?);
    }
    match list_err {
        Some(e) => Err(e),
        None => Ok(rows),
    }
}

/// python `_get_task_keys` (KeyError / RegistryException -> None).
fn get_task_keys(hive: &'static RegistryHive) -> Result<(Option<Obj>, Option<Obj>)> {
    let tasks = caught_key(hive.get_key_node("Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"))?;
    let tree = caught_key(hive.get_key_node("Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"))?;
    Ok((tasks, tree))
}

fn caught_key(r: Result<Obj>) -> Result<Option<Obj>> {
    match r {
        Ok(o) => Ok(Some(o)),
        Err(e) if is_key_error(&e) || is_registry_exception(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

fn columns() -> Vec<Column> {
    vec![
        Column::new("Task Name", ColType::Str),
        Column::new("Principal ID", ColType::Str),
        Column::new("Display Name", ColType::Str),
        Column::new("Enabled", ColType::Bool),
        Column::new("Creation Time", ColType::DateTime),
        Column::new("Last Run Time", ColType::DateTime),
        Column::new("Last Successful Run Time", ColType::DateTime),
        Column::new("Trigger Type", ColType::Str),
        Column::new("Trigger Description", ColType::Str),
        Column::new("Action Type", ColType::Str),
        Column::new("Action", ColType::Str),
        Column::new("Action Arguments", ColType::Str),
        Column::new("Action Context", ColType::Str),
        Column::new("Working Directory", ColType::Str),
        Column::new("Key Name", ColType::Str),
    ]
}

fn run_scheduled(ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
    out.begin(columns())?;
    for row in generate(ctx, cfg)? {
        out.row(0, row)?;
    }
    Ok(())
}

fn timeline_events(ctx: &Context, cfg: &Config) -> Result<Vec<TimelineEvent>> {
    let mut ev = Vec::new();
    for row in generate(ctx, cfg)? {
        // columns: [.. creation(4) last_run(5) last_success(6) .. trigger_desc(8) .. action(10) .. guid(14)]
        let action_desc = value_str(&row[10]);
        let trigger_desc = value_str(&row[8]);
        if let Value::DateTime(_) = row[5] {
            ev.push(TimelineEvent { description: format!("ScheduledTasks: task action {action_desc} with trigger {trigger_desc} ran"), kind: TimeKind::Accessed, time: row[5].clone() });
        }
        if let Value::DateTime(_) = row[6] {
            ev.push(TimelineEvent { description: format!("ScheduledTasks: task action {action_desc} with trigger {trigger_desc} ran successfully"), kind: TimeKind::Accessed, time: row[6].clone() });
        }
        if let Value::DateTime(_) = row[4] {
            // python: `task.trigger_description or '<UNKNOWN>'` (absent values are truthy)
            let td = match value_str(&row[8]) {
                s if s.is_empty() => "<UNKNOWN>".to_string(),
                s => s,
            };
            ev.push(TimelineEvent { description: format!("ScheduledTasks: Creation Time for task {} with trigger {}", value_str(&row[14]), td), kind: TimeKind::Created, time: row[4].clone() });
        }
    }
    Ok(ev)
}

/// python `str(value)` (f-string interpolation) of a row value; absent values use their
/// `__str__`: "N/A" for NotApplicable / NotAvailable, "-" for Unreadable / Unparsable.
fn value_str(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::SStr(s) => s.to_string(),
        Value::NotApplicable | Value::NotAvailable => "N/A".to_string(),
        _ => "-".to_string(),
    }
}

impl Plugin for ScheduledTasks {
    fn name(&self) -> &'static str {
        "windows.registry.scheduled_tasks.ScheduledTasks"
    }
    fn description(&self) -> &'static str {
        "Decodes scheduled task information from the Windows registry, including information about triggers, actions, run times, and creation times."
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        run_scheduled(ctx, cfg, out)
    }
    fn timeline(&self, ctx: &Context, cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        Some(timeline_events(ctx, cfg))
    }
}

/// Deprecated alias `windows.scheduled_tasks.ScheduledTasks`.
pub struct ScheduledTasksDeprecated;
impl Plugin for ScheduledTasksDeprecated {
    fn name(&self) -> &'static str {
        "windows.scheduled_tasks.ScheduledTasks"
    }
    fn description(&self) -> &'static str {
        "Decodes scheduled task information from the Windows registry, including information about triggers, actions, run times, and creation times (deprecated)."
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        run_scheduled(ctx, cfg, out)
    }
    fn timeline(&self, ctx: &Context, cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        Some(timeline_events(ctx, cfg))
    }
}
