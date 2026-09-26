//! linux.kmsg.Kmsg (python `plugins/linux/kmsg.py`): the kernel log buffer.
//!
//! python picks the first `ABCKmsg` subclass whose `symtab_checks` matches the kernel, in
//! `class_subclasses` order: `Kmsg_pre_3_5`, `Kmsg_3_5_to_3_11`, `Kmsg_3_11_to_5_10`,
//! `Kmsg_5_10_to_`. All four readers are ported ([`Variant`]).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::automagic::linux::LinuxKernel;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::LayerExt;
use crate::objects::Obj;
use crate::objects::strings::decode_utf8;
use crate::objects::util::{array_to_string, pointer_to_string};
use crate::plugins::mac::dmesg::py_splitlines;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::{StrErrors, TableRef};

pub struct Kmsg;

/// python `ABCKmsg.LEVELS`.
pub const LEVELS: [&str; 8] = ["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"];

/// python `ABCKmsg.FACILITIES`.
pub const FACILITIES: [&str; 12] = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp"];

/// The python `ABCKmsg` implementation matching a kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// `Kmsg_pre_3_5`: `log_buf` is a plain text buffer.
    Pre35,
    /// `Kmsg_3_5_to_3_11`: an array of `log` records.
    Log35,
    /// `Kmsg_3_11_to_5_10`: an array of `printk_log` records.
    PrintkLog311,
    /// `Kmsg_5_10_to_`: the lockless `printk_ringbuffer`.
    Ringbuffer510,
}

impl Variant {
    /// python `class_subclasses(ABCKmsg)` order.
    pub const ALL: [Variant; 4] = [Variant::Pre35, Variant::Log35, Variant::PrintkLog311, Variant::Ringbuffer510];

    /// python `<subclass>.symtab_checks(vmlinux)`.
    pub fn symtab_checks(self, k: &LinuxKernel) -> bool {
        let t = k.table;
        let has_member = |ty: &str, m: &str| t.user_type(ty).is_some_and(|u| t.member(u, m).is_some());
        match self {
            Variant::Pre35 => {
                k.has_symbol("log_end")
                    && k.has_symbol("log_buf_len")
                    && !k.has_symbol("log_first_idx")
                    && !(k.has_type("log") && has_member("log", "ts_nsec"))
            }
            Variant::Log35 => k.has_type("log") && has_member("log", "ts_nsec") && k.has_symbol("log_first_idx"),
            Variant::PrintkLog311 => {
                !k.has_type("printk_ringbuffer")
                    && k.has_type("printk_log")
                    && has_member("printk_log", "ts_nsec")
                    && k.has_symbol("log_first_idx")
            }
            Variant::Ringbuffer510 => k.has_symbol("prb") && k.has_type("printk_ringbuffer"),
        }
    }

    /// python `ABCKmsg.run_all` selection (None: "Unsupported kernel ring buffer
    /// implementation", no records).
    pub fn select(k: &LinuxKernel) -> Option<Variant> {
        Variant::ALL.into_iter().find(|v| v.symtab_checks(k))
    }
}

/// python `get_level_text(level)`.
fn level_text(level: i128) -> Value {
    if (0..LEVELS.len() as i128).contains(&level) { Value::SStr(LEVELS[level as usize]) } else { Value::Str(level.to_string()) }
}

/// python `get_facility_text(facility)`.
fn facility_text(facility: i128) -> Value {
    if (0..FACILITIES.len() as i128).contains(&facility) { Value::SStr(FACILITIES[facility as usize]) } else { Value::Str(facility.to_string()) }
}

/// python `nsec_to_sec_str(nsec)` (the kernel's `print_time` rounding).
pub fn nsec_to_sec_str(nsec: i128) -> String {
    let (s, r) = (nsec.div_euclid(1_000_000_000), nsec.rem_euclid(1_000_000_000));
    format!("{s}.{:06}", r / 1000)
}

/// python `get_caller_text(caller_id)`.
fn caller_text(caller_id: i128) -> String {
    let name = if caller_id & 0x8000_0000 != 0 { "CPU" } else { "Task" };
    format!("{name}({})", caller_id & !0x8000_0000i128)
}

/// One kernel log record prefix: (facility, level, timestamp, caller).
struct Prefix {
    facility: Value,
    level: Value,
    timestamp: String,
    caller: Option<String>,
}

impl Prefix {
    /// python `get_prefix(obj)` + `get_level_text` / `get_facility_text` (obj: `log`,
    /// `printk_log` or `printk_info`).
    fn read(obj: &Obj) -> Result<Prefix> {
        let facility = obj.m("facility")?.int()?;
        let level = obj.m("level")?.int()?;
        let timestamp = nsec_to_sec_str(obj.m("ts_nsec")?.int()?);
        let caller = if obj.has_member("caller_id") { Some(caller_text(obj.m("caller_id")?.int()?)) } else { None };
        Ok(Prefix { facility: facility_text(facility), level: level_text(level), timestamp, caller })
    }
}

/// Row sink wrapper (python `Kmsg._generator`).
struct Emitter<'a> {
    out: &'a mut dyn RowSink,
}

impl Emitter<'_> {
    fn emit(&mut self, p: &Prefix, line: &str) -> Result<()> {
        self.out.row(
            0,
            vec![
                p.facility.clone(),
                p.level.clone(),
                Value::Str(p.timestamp.clone()),
                match &p.caller {
                    Some(c) if !c.is_empty() => Value::Str(c.clone()),
                    _ => Value::NotAvailable,
                },
                Value::Str(line.to_string()),
            ],
        )
    }
}

/// Reader state shared by the implementations (python `ABCKmsg.__init__`).
struct Reader<'a> {
    k: &'a LinuxKernel,
    /// python `long_unsigned_int_size` (`get_type("pointer").size`).
    long_size: u64,
}

impl Reader<'_> {
    /// python `ABCKmsg.get_string(addr, length)`: None when the range is not valid.
    fn get_string(&self, addr: u128, length: u128) -> Result<Option<String>> {
        let layer = self.k.vlayer;
        let (Ok(addr), Ok(len)) = (u64::try_from(addr), u64::try_from(length)) else { return Ok(None) };
        if !layer.is_valid(addr, len) {
            // python: vollog.warning("Failed to read log record at address 0x%x", addr)
            return Ok(None);
        }
        let txt = layer.read_vec(addr, len as usize)?;
        decode_utf8(&txt, StrErrors::Replace).map(Some)
    }

    // ---------------------------------------------------------------- Kmsg_pre_3_5

    fn run_pre_3_5(&self, em: &mut Emitter) -> Result<()> {
        let k = self.k;
        let log_buf_ptr = k.object_from_symbol("log_buf")?;
        log_buf_ptr.u64()?;
        let log_buf_len = k.object_from_symbol("log_buf_len")?.int()?;
        if log_buf_len < 1 {
            return Err(Error::msg("ValueError: pointer_to_string requires a positive count"));
        }
        let mut log_buf = pointer_to_string(&log_buf_ptr, log_buf_len.min(u64::MAX as i128) as u64)?;
        let log_end = k.object_from_symbol("log_end")?.int()?;
        if log_end > log_buf_len {
            let start = char_boundary(&log_buf, log_end - log_buf_len);
            log_buf = format!("{}{}", &log_buf[start..], &log_buf[..start]);
        }
        for line in py_splitlines(&log_buf) {
            // If there was a wrap-around in the ring buffer, it will find remnants at the top.
            // As those remnants do not conform to the expected line format, they are discarded
            let Some((level_facility, timestamp, text)) = match_pre_3_5_line(line) else { continue };
            // The lower 3 bit are the log level, the rest are the log facility
            let (level, facility) = split_level_facility(&level_facility);
            let p = Prefix {
                facility: match facility.parse::<i128>() {
                    Ok(f) => facility_text(f),
                    Err(_) => Value::Str(facility),
                },
                level: level_text(level),
                timestamp: timestamp.to_string(),
                caller: None,
            };
            em.emit(&p, text)?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------- Kmsg_3_5_to_3_11 / Kmsg_3_11_to_5_10

    fn run_log_records(&self, em: &mut Emitter, log_struct_name: &str) -> Result<()> {
        let k = self.k;
        // This can happen on kernels where log_buf is declared twice
        let log_buf_ptr = match k.object_from_symbol("log_buf").and_then(|p| p.u64()) {
            Ok(v) => v as i128,
            Err(e) if e.is_invalid_address() => return Ok(()),
            Err(e) => return Err(e),
        };
        let log_buf_len = k.object_from_symbol("log_buf_len")?.int()?;
        let log_first_idx = k.object_from_symbol("log_first_idx")?.int()?;
        let log_next_idx = k.object_from_symbol("log_next_idx")?.int()?;
        let log_struct_size = k.size_of(log_struct_name)? as i128;

        let mut cur_idx = log_first_idx;
        let mut end_idx = if log_first_idx < log_next_idx { log_next_idx } else { log_buf_len };
        while cur_idx < end_idx {
            let msg_offset = log_buf_ptr + cur_idx;
            let msg = k.object_abs(log_struct_name, msg_offset as u64)?;
            let r = (|| -> Result<()> {
                if msg.m("len")?.int()? == 0 {
                    // A length == 0 for the next message indicates a wrap-around to the
                    // beginning of the buffer.
                    cur_idx = 0;
                    end_idx = log_next_idx;
                    return Ok(());
                }
                let p = Prefix::read(&msg)?;
                // get_log_lines(msg)
                if msg.m("text_len")?.int()? > 0 {
                    let text_len = msg.m("text_len")?.int()?;
                    let text = self.get_string((msg.addr as i128 + log_struct_size) as u128, text_len as u128)?;
                    if let Some(text) = text.filter(|t| !t.is_empty()) {
                        for line in py_splitlines(&text) {
                            em.emit(&p, line)?;
                        }
                    }
                }
                // get_dict_lines(msg)
                let dict_len = msg.m("dict_len")?.int()?;
                if dict_len != 0 {
                    let dict_offset = msg.addr as i128 + log_struct_size + msg.m("text_len")?.int()?;
                    let dict_data = match (u64::try_from(dict_offset), usize::try_from(dict_len)) {
                        (Ok(off), Ok(len)) => k.vlayer.read_vec(off, len),
                        _ => Err(Error::invalid(dict_offset as u64)),
                    };
                    match dict_data {
                        Ok(data) => {
                            for chunk in data.split(|&b| b == 0) {
                                em.emit(&p, &format!(" {}", decode_utf8(chunk, StrErrors::Replace)?))?;
                            }
                        }
                        // python: vollog.debug("Unable to read kmsg dict from 0x%x", dict_offset)
                        Err(e) if e.is_invalid_address() => {}
                        Err(e) => return Err(e),
                    }
                }
                cur_idx += msg.m("len")?.int()?;
                Ok(())
            })();
            match r {
                Ok(()) => {}
                // python: vollog.warning("Kmsg buffer msg length could not be read")
                Err(e) if e.is_invalid_address() => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------- Kmsg_5_10_to_

    fn run_ringbuffer(&self, em: &mut Emitter) -> Result<()> {
        let k = self.k;
        // static struct printk_ringbuffer *prb = &printk_rb_static;
        let ringbuffers = k.object_from_symbol("prb")?.deref()?;
        let desc_ring = ringbuffers.m("desc_ring")?;
        let text_data_ring = ringbuffers.m("text_data_ring")?;
        let count_bits = desc_ring.m("count_bits")?.int()?;
        let descs = desc_ring.m("descs")?.u64()?;
        let infos = desc_ring.m("infos")?.u64()?;
        let desc_ty = k.get_type("prb_desc")?;
        let info_ty = k.get_type("printk_info")?;
        let (desc_size, info_size) = (k.table.size_of(desc_ty), k.table.size_of(info_ty));
        let desc0 = Obj::new(desc_ring.sp, desc_ty, descs);
        let info0 = Obj::new(desc_ring.sp, info_ty, infos);
        // python `arr[cur_id % desc_count]`: the element address (masked by the layer); for
        // count_bits >= 48 the modulo does not change the masked address.
        let elem = |base: &Obj, size: u64, id: i128| -> Obj {
            let idx = if count_bits < 48 { id.rem_euclid(1i128 << count_bits) as u64 } else { id as u64 };
            base.at_addr(base.addr.wrapping_add(size.wrapping_mul(idx)))
        };

        // See kernel/printk/printk_ringbuffer.h
        let desc_state_var_bits_sz = (self.long_size * 8) as i128;
        let desc_flags_shift = desc_state_var_bits_sz - 2;
        let desc_flags_mask = 3i128 << desc_flags_shift;
        let desc_id_mask = !desc_flags_mask;

        // text_data_ring members, read on first use (python re-reads them per record)
        let mut ring: Option<(i128, u64)> = None;

        let mut cur_id = desc_ring.m("tail_id")?.m("counter")?.int()?;
        let mut end_id: Option<i128> = None;
        while Some(cur_id) != end_id {
            end_id = Some(desc_ring.m("head_id")?.m("counter")?.int()?);
            let desc = elem(&desc0, desc_size, cur_id);
            let info = elem(&info0, info_size, cur_id);
            let state = (desc.m("state_var")?.m("counter")?.int()? >> desc_flags_shift) & 3;
            // desc_committed / desc_finalized
            if state == 1 || state == 2 {
                let p = Prefix::read(&info)?;
                // get_log_lines(text_data_ring, desc, info)
                let (size_bits, data) = match ring {
                    Some(r) => r,
                    None => {
                        let r = (text_data_ring.m("size_bits")?.int()?, text_data_ring.m("data")?.u64()?);
                        ring = Some(r);
                        r
                    }
                };
                if let Some(text) = self.text_from_data_ring(size_bits, data, &desc, &info)? {
                    for line in py_splitlines(&text) {
                        em.emit(&p, line)?;
                    }
                }
                // get_dict_lines(info)
                let dev_info = info.m("dev_info")?;
                let subsystem = array_to_string(&dev_info.m("subsystem")?, None)?;
                if !subsystem.is_empty() {
                    em.emit(&p, &format!(" SUBSYSTEM={subsystem}"))?;
                }
                let device = array_to_string(&dev_info.m("device")?, None)?;
                if !device.is_empty() {
                    em.emit(&p, &format!(" DEVICE={device}"))?;
                }
            }
            cur_id += 1;
            cur_id &= desc_id_mask;
        }
        Ok(())
    }

    /// python `get_text_from_data_ring(text_data_ring, desc, info)`; None when the record has
    /// no (non-empty) text.
    fn text_from_data_ring(&self, size_bits: i128, data: u64, desc: &Obj, info: &Obj) -> Result<Option<String>> {
        let lpos = desc.m("text_blk_lpos")?;
        let modulo = |v: i128| if size_bits < 100 { v.rem_euclid(1i128 << size_bits) } else { v };
        let mut begin = modulo(lpos.m("begin")?.int()?);
        let end = modulo(lpos.m("next")?.int()?);
        // This record doesn't contain text
        if begin & 1 != 0 {
            return Ok(None);
        }
        // This means a wrap-around to the beginning of the buffer
        if begin > end {
            begin = 0;
        }
        // Each element in the ringbuffer is "ID + data". See prb_data_ring struct
        let text_start = begin + self.long_size as i128;
        let offset = data as i128 + text_start;
        // Safety first ;)
        let text_len = info.m("text_len")?.int()?.min(end - begin);
        Ok(self.get_string(offset as u128, text_len as u128)?.filter(|t| !t.is_empty()))
    }
}

/// Byte offset of python code-point index `idx` (a non-negative slice start, clamped).
fn char_boundary(s: &str, idx: i128) -> usize {
    if idx <= 0 {
        return 0;
    }
    s.char_indices().nth(idx.min(usize::MAX as i128) as usize).map_or(s.len(), |(b, _)| b)
}

/// First code points of the Unicode `Nd` digit runs (python 3.14 / Unicode 16.0): python's
/// `\d` (str patterns) and `int()` digits. Every run is ten consecutive code points.
const ND_ZEROS: [u32; 76] = [
    0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66, 0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090,
    0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0,
    0xff10, 0x104a0, 0x10d30, 0x10d40, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0, 0x11650, 0x116c0, 0x116d0, 0x116da,
    0x11730, 0x118e0, 0x11950, 0x11bf0, 0x11c50, 0x11d50, 0x11da0, 0x11f50, 0x16130, 0x16a60, 0x16ac0, 0x16b50, 0x16d70, 0x1ccf0, 0x1d7ce,
    0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0, 0x1e4f0, 0x1e5f1, 0x1e950, 0x1fbf0,
];

/// python `\d` for str patterns: the decimal value of a Unicode `Nd` character.
fn decimal_value(c: char) -> Option<u8> {
    let c = c as u32;
    if (0x30..=0x39).contains(&c) {
        return Some((c - 0x30) as u8);
    }
    if c < 0x660 {
        return None;
    }
    let i = ND_ZEROS.partition_point(|&z| z <= c);
    let z = ND_ZEROS[i.checked_sub(1)?];
    (c - z < 10).then_some((c - z) as u8)
}

/// python `\s` for str patterns (`str.isspace()`).
fn is_py_space(c: char) -> bool {
    matches!(c, '\t'..='\r' | '\x1c'..='\x20' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}

/// python `re.match(r"<(\d+)>\[\s*(\d+\.\d+)\]\s(.*?)$", line)` on a line without line
/// breaks: (group 1 as ASCII decimal digits, group 2, group 3).
fn match_pre_3_5_line(line: &str) -> Option<(String, &str, &str)> {
    let mut it = line.char_indices().peekable();
    let digits = |it: &mut std::iter::Peekable<std::str::CharIndices>, acc: Option<&mut String>| -> usize {
        let mut n = 0;
        let mut acc = acc;
        while let Some(&(_, c)) = it.peek() {
            match decimal_value(c) {
                Some(d) => {
                    if let Some(a) = acc.as_deref_mut() {
                        a.push((b'0' + d) as char);
                    }
                    n += 1;
                    it.next();
                }
                None => break,
            }
        }
        n
    };
    if it.next()?.1 != '<' {
        return None;
    }
    let mut level_facility = String::new();
    if digits(&mut it, Some(&mut level_facility)) == 0 {
        return None;
    }
    if it.next()?.1 != '>' || it.next()?.1 != '[' {
        return None;
    }
    while it.peek().is_some_and(|&(_, c)| is_py_space(c)) {
        it.next();
    }
    let ts_start = it.peek()?.0;
    if digits(&mut it, None) == 0 || it.next()?.1 != '.' || digits(&mut it, None) == 0 {
        return None;
    }
    let (ts_end, c) = it.next()?;
    if c != ']' {
        return None;
    }
    let (_, c) = it.next()?;
    if !is_py_space(c) {
        return None;
    }
    let rest = it.peek().map_or(line.len(), |&(i, _)| i);
    Some((level_facility, &line[ts_start..ts_end], &line[rest..]))
}

/// python `int(s) & 7` and `str(int(s) >> 3)` for a string of ASCII decimal digits of any
/// length (python ints are unbounded).
fn split_level_facility(digits: &str) -> (i128, String) {
    // level: the value mod 8 only depends on the last three decimal digits
    let tail = &digits[digits.len().saturating_sub(3)..];
    let level = tail.parse::<i128>().unwrap_or(0) & 7;
    // facility: long division by 8
    let mut q = String::with_capacity(digits.len());
    let mut rem = 0u32;
    for b in digits.bytes() {
        let cur = rem * 10 + (b - b'0') as u32;
        let d = cur / 8;
        rem = cur % 8;
        if !(q.is_empty() && d == 0) {
            q.push((b'0' + d as u8) as char);
        }
    }
    if q.is_empty() {
        q.push('0');
    }
    (level, q)
}

/// python `symbol_space.verify_table_versions("dwarf2json", lambda version, _: (not version) or
/// version > (0, 4, 1))` for the kernel table: `Ok(false)` = an invalid table was found.
fn verify_table_versions(t: TableRef) -> Result<bool> {
    let md = t.metadata();
    let Some(producer) = md.get("producer") else { return Ok(true) };
    if producer.get("name").and_then(|n| n.as_str()) != Some("dwarf2json") {
        return Ok(true);
    }
    let version = producer.get("version").and_then(|v| v.as_str()).unwrap_or("");
    if version.is_empty() || !version.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Ok(true);
    }
    let mut parts = Vec::new();
    for x in version.split('.') {
        match x.parse::<u128>() {
            Ok(v) => parts.push(v),
            // python int("") (e.g. "0..1")
            Err(_) => return Err(Error::msg(format!("ValueError: invalid literal for int() with base 10: '{x}'"))),
        }
    }
    Ok(parts.as_slice() > [0u128, 4, 1].as_slice())
}

impl Plugin for Kmsg {
    fn name(&self) -> &'static str {
        "linux.kmsg.Kmsg"
    }
    fn description(&self) -> &'static str {
        "Kernel log buffer reader"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.linux_kernel()?;
        if !verify_table_versions(k.table)? {
            // python: vollog.info("Invalid symbol table, ...") and run() returns None, which the
            // CLI renderer then fails on
            return Err(Error::msg("AttributeError: 'NoneType' object has no attribute 'columns'"));
        }
        out.begin(vec![
            Column::new("facility", ColType::Str),
            Column::new("level", ColType::Str),
            Column::new("timestamp", ColType::Str),
            Column::new("caller", ColType::Str),
            Column::new("line", ColType::Str),
        ])?;
        let Some(variant) = Variant::select(k) else {
            // python: vollog.error("Unsupported kernel ring buffer implementation. ...")
            return Ok(());
        };
        let reader = Reader { k, long_size: k.size_of("pointer")? };
        let mut em = Emitter { out };
        match variant {
            Variant::Pre35 => reader.run_pre_3_5(&mut em),
            Variant::Log35 => reader.run_log_records(&mut em, "log"),
            Variant::PrintkLog311 => reader.run_log_records(&mut em, "printk_log"),
            Variant::Ringbuffer510 => reader.run_ringbuffer(&mut em),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(nsec_to_sec_str(17110365556), "17.110365");
        assert_eq!(nsec_to_sec_str(0), "0.000000");
    }

    #[test]
    fn callers() {
        assert_eq!(caller_text(0x80000001), "CPU(1)");
        assert_eq!(caller_text(1234), "Task(1234)");
    }

    #[test]
    fn pre_3_5_lines() {
        let (lf, ts, rest) = match_pre_3_5_line("<6>[ 9565.250411] line1!").unwrap();
        assert_eq!((lf.as_str(), ts, rest), ("6", "9565.250411", "line1!"));
        assert!(match_pre_3_5_line("6>[ 1.2] x").is_none());
        assert!(match_pre_3_5_line("<6>[1.2]x").is_none());
        let (lf, ts, rest) = match_pre_3_5_line("<\u{661}\u{662}>[\u{a0}1.2]\u{3000}").unwrap();
        assert_eq!((lf.as_str(), ts, rest), ("12", "1.2", ""));
        assert_eq!(split_level_facility("14"), (6, "1".to_string()));
        assert_eq!(split_level_facility("007"), (7, "0".to_string()));
        assert_eq!(split_level_facility("123456789012345678901234567890123456789012"), (4, "15432098626543209862654320986265432098626".to_string()));
    }
}
