//! windows.mftscan.MFTScan / ADS / ResidentData (python `plugins/windows/mftscan.py`): MFT
//! `FILE` records found by a yara scan of the physical layer, their STANDARD_INFORMATION /
//! FILE_NAME attributes, alternate data streams and resident data, plus the reusable
//! [`enumerate_mft_records`] (python `MFTScan.enumerate_mft_records`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Python scans `primary.config["memory_layer"]` with yara-python and the rule
//! `rule r1 {strings: $a = /FILE0|FILE\*|BAAD/ condition: $a}` through `YaraScanner`: every
//! chunk (16 MiB + 4 KiB overlap) is matched whole and every string instance is reported --
//! including those in the overlap, which the next chunk reports again (python prints those
//! records twice). The three literals cannot overlap each other or themselves, so yara's
//! instances are exactly all their occurrences, in ascending offset order. Here the search is
//! the core Teddy multi-literal kernel, and the records are parsed on the scan's worker threads
//! (the `finish` phase of each chunk) into ready-made rows; the calling thread only renders.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::Layer;
use crate::layers::scan::{MultiStringScanner, Scanner, scan_each};
use crate::plugins::{Config, Plugin, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::mft::{MftEntry, mft_flags_name, permission_flags_name};
use crate::util::time::wintime_to_datetime;
use std::marker::PhantomData;

pub struct MFTScan;
pub struct ADS;
pub struct ResidentData;

/// The yara rule's literals (`/FILE0|FILE\*|BAAD/`).
pub const MFT_SIGNATURES: [&[u8]; 3] = [b"FILE0", b"FILE*", b"BAAD"];

/// yara-python + volatility `YaraScanner` for `/FILE0|FILE\*|BAAD/` over one chunk, with the
/// per-hit work `parse` done on the scan's worker threads. Hits are NOT limited to the first
/// `chunk_size` bytes of a chunk (YaraScanner reports the overlap too).
struct MftYaraScanner<'a, T, F> {
    ms: MultiStringScanner,
    layer: &'a dyn Layer,
    parse: F,
    _t: PhantomData<fn() -> T>,
}

/// libyara `YR_MAX_STRING_MATCHES`: yara-python keeps the first million instances of a string
/// per `match()` call (one chunk here) and warns about the rest.
const YR_MAX_STRING_MATCHES: usize = 1_000_000;

impl<'a, T: Send, F: Fn(MftEntry<'a>) -> T + Sync> Scanner for MftYaraScanner<'a, T, F> {
    type Hit = T;
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<T>) {
        let mut n = 0;
        self.ms.search(data, |p, _| {
            hits.push((self.parse)(MftEntry::new(self.layer, data_offset + p as u64)));
            n += 1;
            n < YR_MAX_STRING_MATCHES
        });
    }
    fn prescan(&self, data: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
        let start = out.len();
        self.ms.search(data, |p, i| {
            out.push((p as u64, i));
            out.len() - start < YR_MAX_STRING_MATCHES
        });
        true
    }
    fn finish(&self, matches: &[(u64, u32)], data_offset: u64, hits: &mut Vec<T>) {
        let matches = &matches[..matches.len().min(YR_MAX_STRING_MATCHES)];
        hits.reserve(matches.len());
        for &(p, _) in matches {
            hits.push((self.parse)(MftEntry::new(self.layer, data_offset + p)));
        }
    }
    fn stream_window(&self) -> Option<usize> {
        Some(5)
    }
    fn prescan_piece(&self, data: &[u8], base: u64, from: usize, limit: usize, out: &mut Vec<(u64, u32)>) -> usize {
        let mut next = limit;
        if from < limit {
            self.ms.search(&data[from..], |p, i| {
                let at = from + p;
                if at >= limit {
                    return false;
                }
                out.push((base + at as u64, i));
                next = next.max(at + MFT_SIGNATURES[i as usize].len());
                true
            });
        }
        next
    }
}

/// python `MFTScan.enumerate_mft_records(context, config_path, primary_layer_name)`: an
/// `MFT_ENTRY` at every yara hit of `/FILE0|FILE\*|BAAD/` in `layer` (the kernel's physical
/// layer), in python's order (records in chunk overlaps come twice, like python).
/// `parse` runs on the scan's worker threads, in parallel; `consume` gets its results on the
/// calling thread in python order and returns `false` to stop.
pub fn enumerate_mft_records<'a, T: Send>(layer: &'a dyn Layer, parse: impl Fn(MftEntry<'a>) -> T + Sync, consume: impl FnMut(T) -> bool) {
    let scanner = MftYaraScanner { ms: MultiStringScanner::new(&MFT_SIGNATURES), layer, parse, _t: PhantomData };
    scan_each(layer, &scanner, None, consume);
}

/// The rows python's generator yields for one record, and the exception it raised after them
/// (a python crash: nothing follows).
pub struct RecordRows {
    pub rows: Vec<(usize, Vec<Value>)>,
    pub err: Option<Error>,
}

impl RecordRows {
    fn new(rows: Vec<(usize, Vec<Value>)>, r: Result<()>) -> RecordRows {
        RecordRows { rows, err: r.err() }
    }
}

/// python `enum.lookup()` falling back to `hex(value)`.
#[inline]
fn enum_or_hex(name: Option<&'static str>, v: u8) -> Value {
    match name {
        Some(n) => Value::SStr(n),
        None => Value::Str(format!("{v:#x}")),
    }
}

/// `str(mft_record.get_signature())`.
#[inline]
fn signature_value(e: &MftEntry) -> Result<Value> {
    Ok(match e.signature_static()? {
        Some(s) => Value::SStr(s),
        None => Value::Str(e.get_signature()?),
    })
}

#[inline]
fn times(t: [u64; 4]) -> [Value; 4] {
    t.map(|x| wintime_to_datetime(x as i128))
}

/// Swallow invalid-address errors (python `except InvalidAddressException`).
#[inline]
fn caught(r: Result<()>) -> Result<()> {
    match r {
        Err(e) if !e.is_invalid_address() => Err(e),
        _ => Ok(()),
    }
}

/// python `MFTScan.parse_standard_information_records(record)` (level 0 rows).
pub fn parse_standard_information_records(e: &MftEntry, out: &mut Vec<(usize, Vec<Value>)>) -> Result<()> {
    let flag = e.flags()?;
    let mft_type = enum_or_hex(mft_flags_name(flag), flag);
    caught((|| {
        for si in e.standard_information_entries()? {
            let sig = signature_value(e)?;
            let rn = e.record_number()?;
            let lc = e.link_count()?;
            let [c, m, u, a] = times(si.times()?);
            out.push((
                0,
                vec![
                    Value::Int(si.offset as i128),
                    sig,
                    Value::Int(rn as i128),
                    Value::Int(lc as i128),
                    mft_type.clone(),
                    Value::NotApplicable,
                    Value::SStr("STANDARD_INFORMATION"),
                    c,
                    m,
                    u,
                    a,
                    Value::NotApplicable,
                ],
            ));
        }
        Ok(())
    })())
}

/// python `MFTScan.parse_filename_records(record)` (level 1 rows).
pub fn parse_filename_records(e: &MftEntry, out: &mut Vec<(usize, Vec<Value>)>) -> Result<()> {
    let flag = e.flags()?;
    let mft_type = enum_or_hex(mft_flags_name(flag), flag);
    caught((|| {
        for f in e.filename_entries()? {
            let p = f.flags()?;
            let permissions = enum_or_hex(permission_flags_name(p), p);
            let sig = signature_value(e)?;
            let rn = e.record_number()?;
            let lc = e.link_count()?;
            let [c, m, u, a] = times(f.times()?);
            let name = f.get_full_name()?;
            out.push((
                1,
                vec![
                    Value::Int(f.offset as i128),
                    sig,
                    Value::Int(rn as i128),
                    Value::Int(lc as i128),
                    mft_type.clone(),
                    permissions,
                    Value::SStr("FILE_NAME"),
                    c,
                    m,
                    u,
                    a,
                    Value::Str(name),
                ],
            ));
        }
        Ok(())
    })())
}

/// MFTScan's rows for one record (python `parse_mft_records` for one `mft_record`).
pub fn mftscan_rows(e: MftEntry) -> RecordRows {
    let mut rows = Vec::new();
    let r = parse_standard_information_records(&e, &mut rows).and_then(|_| parse_filename_records(&e, &mut rows));
    RecordRows::new(rows, r)
}

/// python `MFTScan.generate_timeline()` for one record: the events, and the exception python
/// raised after them.
fn timeline_events(e: MftEntry) -> (Vec<TimelineEvent>, Option<Error>) {
    let mut ev = Vec::new();
    let fname = match e.longest_filename() {
        Ok(f) => f,
        Err(err) => return (ev, Some(err)),
    };
    let mut push = |desc: String, row: &[Value]| {
        for (kind, i) in [(TimeKind::Created, 7), (TimeKind::Modified, 8), (TimeKind::Changed, 9), (TimeKind::Accessed, 10)] {
            ev.push(TimelineEvent { description: desc.clone(), kind, time: row[i].clone() });
        }
    };
    let mut rows = Vec::new();
    let r = parse_standard_information_records(&e, &mut rows);
    let fname = fname.as_deref().unwrap_or("None");
    for (_, row) in &rows {
        push(format!("MFT STANDARD_INFORMATION entry for {fname}"), row);
    }
    if let Err(err) = r {
        return (ev, Some(err));
    }
    rows.clear();
    let r = parse_filename_records(&e, &mut rows);
    for (_, row) in &rows {
        let name = match &row[11] {
            Value::Str(s) => s.as_str(),
            _ => "",
        };
        push(format!("MFT FILE_NAME entry for {name}"), row);
    }
    (ev, r.err())
}

/// `renderers.LayerData.from_object(content)` for resident content python read successfully:
/// the renderer's padded re-read returns the same bytes, and its hole map (translation layers
/// only) finds no hole in a fully readable range.
#[inline]
fn content_value(content: Option<(u64, Vec<u8>)>) -> Value {
    match content {
        Some((_, data)) if !data.is_empty() => Value::LayerBytes { data, errors: Vec::new() },
        _ => Value::NotAvailable,
    }
}

/// python `ADS.parse_ads_data_records(record)` rows.
pub fn ads_rows(e: MftEntry) -> RecordRows {
    let mut rows = Vec::new();
    let r = (|| -> Result<()> {
        for attr in e.alternate_data_streams() {
            let attr = attr?;
            let filename = match e.longest_filename()? {
                Some(s) if !s.is_empty() => Value::Str(s),
                _ => Value::NotAvailable,
            };
            let content = content_value(attr.get_resident_filecontent()?);
            let ads_name = match attr.get_resident_filename()? {
                Some(s) if !s.is_empty() => Value::Str(s),
                _ => Value::NotAvailable,
            };
            let sig = signature_value(&e)?;
            let rn = e.record_number()?;
            rows.push((
                0,
                vec![
                    Value::Int(attr.attr_data_offset() as i128),
                    sig,
                    Value::Int(rn as i128),
                    Value::SStr(attr.attr_type_name()),
                    filename,
                    ads_name,
                    content,
                ],
            ));
        }
        Ok(())
    })();
    RecordRows::new(rows, r)
}

/// python `ResidentData.parse_resident_data(record)` row (if any).
pub fn resident_data_rows(e: MftEntry) -> RecordRows {
    let mut rows = Vec::new();
    let r = (|| -> Result<()> {
        let attr = match e.resident_data_attributes().next() {
            None => return Ok(()),
            Some(a) => a?,
        };
        let content = content_value(attr.get_resident_filecontent()?);
        // str(filename): NotAvailableValue() stringifies as "N/A"
        let filename = match e.longest_filename()? {
            Some(s) if !s.is_empty() => Value::Str(s),
            _ => Value::SStr("N/A"),
        };
        let sig = signature_value(&e)?;
        let rn = e.record_number()?;
        rows.push((
            0,
            vec![Value::Int(attr.attr_data_offset() as i128), sig, Value::Int(rn as i128), Value::SStr(attr.attr_type_name()), filename, content],
        ));
        Ok(())
    })();
    RecordRows::new(rows, r)
}

/// Scan the kernel's physical layer and render `rows(record)` of every record in order.
fn run_rows<'a>(layer: &'a dyn Layer, rows: fn(MftEntry<'a>) -> RecordRows, out: &mut dyn RowSink) -> Result<()> {
    let mut res = Ok(());
    enumerate_mft_records(layer, rows, |rr| {
        for (depth, values) in rr.rows {
            if let Err(e) = out.row(depth, values) {
                res = Err(e);
                return false;
            }
        }
        if let Some(e) = rr.err {
            res = Err(e);
            return false;
        }
        true
    });
    res
}

impl Plugin for MFTScan {
    fn name(&self) -> &'static str {
        "windows.mftscan.MFTScan"
    }
    fn description(&self) -> &'static str {
        "Scans for MFT FILE objects present in a particular windows memory image."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let layer = ctx.windows_kernel()?.phys;
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("Record Type", ColType::Str),
            Column::new("Record Number", ColType::Int),
            Column::new("Link Count", ColType::Int),
            Column::new("MFT Type", ColType::Str),
            Column::new("Permissions", ColType::Str),
            Column::new("Attribute Type", ColType::Str),
            Column::new("Created", ColType::DateTime),
            Column::new("Modified", ColType::DateTime),
            Column::new("Updated", ColType::DateTime),
            Column::new("Accessed", ColType::DateTime),
            Column::new("Filename", ColType::Str),
        ])?;
        run_rows(layer, mftscan_rows, out)
    }
    /// python `generate_timeline()`. If python raises midway (an unreadable FILE_NAME name or
    /// record flags) the events generated before stay in python's timeline, so they are
    /// returned without the error.
    fn timeline(&self, ctx: &Context, _cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        let layer = match ctx.windows_kernel() {
            Ok(k) => k.phys,
            Err(e) => return Some(Err(e)),
        };
        let mut all = Vec::new();
        enumerate_mft_records(layer, timeline_events, |(ev, err)| {
            all.extend(ev);
            err.is_none()
        });
        Some(Ok(all))
    }
}

impl Plugin for ADS {
    fn name(&self) -> &'static str {
        "windows.mftscan.ADS"
    }
    fn description(&self) -> &'static str {
        "Scans for Alternate Data Stream"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let layer = ctx.windows_kernel()?.phys;
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("Record Type", ColType::Str),
            Column::new("Record Number", ColType::Int),
            Column::new("MFT Type", ColType::Str),
            Column::new("Filename", ColType::Str),
            Column::new("ADS Filename", ColType::Str),
            Column::new("Hexdump", ColType::LayerData),
        ])?;
        run_rows(layer, ads_rows, out)
    }
}

impl Plugin for ResidentData {
    fn name(&self) -> &'static str {
        "windows.mftscan.ResidentData"
    }
    fn description(&self) -> &'static str {
        "Scans for MFT Records with Resident Data"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let layer = ctx.windows_kernel()?.phys;
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("Record Type", ColType::Str),
            Column::new("Record Number", ColType::Int),
            Column::new("MFT Type", ColType::Str),
            Column::new("Filename", ColType::Str),
            Column::new("Hexdump", ColType::LayerData),
        ])?;
        run_rows(layer, resident_data_rows, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// yara's instances of `/FILE0|FILE\*|BAAD/` over a buffer: every occurrence, ascending
    /// (reference: yara-python 4.5.4 `rules.match(data=...)` on the same buffers).
    #[test]
    fn yara_semantics() {
        let ms = MultiStringScanner::new(&MFT_SIGNATURES);
        let hits = |d: &[u8]| {
            let mut v = Vec::new();
            ms.search(d, |p, _| {
                v.push(p);
                true
            });
            v
        };
        assert_eq!(hits(b"BAADBAADFILE0FILE*FILE1FILEBAAD"), vec![0, 4, 8, 13, 27]);
        assert_eq!(hits(b"FILFILE0xBAABAAD"), vec![3, 12]);
    }
}
