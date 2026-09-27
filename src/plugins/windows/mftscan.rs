//! windows.mftscan.MFTScan / ADS / ResidentData (python `plugins/windows/mftscan.py`): MFT
//! `FILE` records found by a yara scan of the physical layer, their STANDARD_INFORMATION /
//! FILE_NAME attributes, alternate data streams and resident data, plus the reusable
//! [`enumerate_mft_records`] / [`enumerate_mft_batches`] (python
//! `MFTScan.enumerate_mft_records`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Python scans `primary.config["memory_layer"]` with yara-python and the rule
//! `rule r1 {strings: $a = /FILE0|FILE\*|BAAD/ condition: $a}` through `YaraScanner`: every
//! chunk (16 MiB + 4 KiB overlap) is matched whole and every string instance is reported --
//! including those in the overlap, which the next chunk reports again (python prints those
//! records twice). The three literals cannot overlap each other or themselves, so yara's
//! instances are exactly all their occurrences, in ascending offset order (at most a million per
//! chunk, yara-python's cap). Here the search is the core Teddy multi-literal kernel.
//!
//! Speed: the records of a chunk are parsed on the scan's worker threads into one batch of
//! compact POD rows (strings / bytes in per-batch arenas); the rendering thread turns each row
//! into `Value`s right before handing it to the renderer, so row memory stays cache-hot and is
//! allocated and freed on one thread. The main image (5 GiB, 480k hits, 1.39M rows, 280 MB of
//! text) renders in about the time of the renderer alone.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::Layer;
use crate::layers::scan::{MultiStringScanner, Scanner, scan_each};
use crate::objects::LayerRef;
use crate::plugins::{Config, Plugin, TimeKind, TimelineBatch, TimelineEvent, TimelineGroups, TimelineTime};
use crate::renderers::text::{JsonTrees, RowEncoder};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::mft::{MftEntry, mft_flags_name, permission_flags_name, signature_str};
use crate::util::time::wintime_to_datetime;
use std::marker::PhantomData;

pub struct MFTScan;
pub struct ADS;
pub struct ResidentData;

/// The yara rule's literals (`/FILE0|FILE\*|BAAD/`).
pub const MFT_SIGNATURES: [&[u8]; 3] = [b"FILE0", b"FILE*", b"BAAD"];

/// libyara `YR_MAX_STRING_MATCHES`: yara-python keeps the first million instances of a string
/// per `match()` call (one chunk here) and warns about the rest.
const YR_MAX_STRING_MATCHES: usize = 1_000_000;

/// yara-python + volatility `YaraScanner` for `/FILE0|FILE\*|BAAD/` over one chunk: every
/// occurrence, NOT limited to the first `chunk_size` bytes of the chunk (YaraScanner reports the
/// overlap too). The records of a chunk are parsed on the scan's worker threads into one batch.
struct MftYaraScanner<'a, B, N, A> {
    ms: MultiStringScanner,
    layer: &'a dyn Layer,
    new: N,
    add: A,
    _b: PhantomData<fn() -> B>,
}

impl<'a, B, N, A> MftYaraScanner<'a, B, N, A>
where
    B: Send,
    N: Fn() -> B + Sync,
    A: Fn(&mut B, MftEntry<'a>) -> bool + Sync,
{
    fn batch(&self, offsets: impl Iterator<Item = u64>) -> B {
        let mut b = (self.new)();
        for off in offsets.take(YR_MAX_STRING_MATCHES) {
            if !(self.add)(&mut b, MftEntry::new(self.layer, off)) {
                break;
            }
        }
        b
    }
}

impl<'a, B, N, A> Scanner for MftYaraScanner<'a, B, N, A>
where
    B: Send,
    N: Fn() -> B + Sync,
    A: Fn(&mut B, MftEntry<'a>) -> bool + Sync,
{
    type Hit = B;
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<B>) {
        let mut offs = Vec::new();
        self.prescan(data, &mut offs);
        hits.push(self.batch(offs.iter().map(|m| data_offset + m.0)));
    }
    fn prescan(&self, data: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
        let start = out.len();
        self.ms.search(data, |p, i| {
            out.push((p as u64, i));
            out.len() - start < YR_MAX_STRING_MATCHES
        });
        true
    }
    fn finish(&self, matches: &[(u64, u32)], data_offset: u64, hits: &mut Vec<B>) {
        hits.push(self.batch(matches.iter().map(|m| data_offset + m.0)));
    }
    fn stream_window(&self) -> Option<usize> {
        Some(5)
    }
    // prescan = the greedy literal search over the whole chunk (overlap included), capped
    fn cache_query(&self) -> Option<crate::layers::scancache::CacheQuery<'_>> {
        Some(crate::layers::scancache::CacheQuery::Greedy { patterns: self.ms.patterns(), limit: u64::MAX, cap: YR_MAX_STRING_MATCHES })
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

/// python `MFTScan.enumerate_mft_records(context, config_path, primary_layer_name)`, batched:
/// an `MFT_ENTRY` at every yara hit of `/FILE0|FILE\*|BAAD/` in `layer` (the kernel's physical
/// layer), in python's order (records in chunk overlaps come twice, like python). The records
/// of each scan chunk are handed to `add` in order on a worker thread (chunks in parallel), into
/// a batch made by `new`; `add` returns `false` to end the batch (python raised: nothing after
/// that record matters). `consume` gets the batches on the calling thread in python order and
/// returns `false` to stop the scan.
pub fn enumerate_mft_batches<'a, B: Send>(
    layer: &'a dyn Layer,
    new: impl Fn() -> B + Sync,
    add: impl Fn(&mut B, MftEntry<'a>) -> bool + Sync,
    consume: impl FnMut(B) -> bool,
) {
    let scanner = MftYaraScanner { ms: MultiStringScanner::new(&MFT_SIGNATURES), layer, new, add, _b: PhantomData };
    scan_each(layer, &scanner, None, consume);
}

/// python `MFTScan.enumerate_mft_records(...)` one record at a time: `parse` runs on the scan's
/// worker threads, `consume` gets the results on the calling thread in python order (`false`
/// stops).
pub fn enumerate_mft_records<'a, T: Send>(layer: &'a dyn Layer, parse: impl Fn(MftEntry<'a>) -> T + Sync, mut consume: impl FnMut(T) -> bool) {
    enumerate_mft_batches(
        layer,
        Vec::new,
        |b: &mut Vec<T>, e| {
            b.push(parse(e));
            true
        },
        |b| b.into_iter().all(&mut consume),
    );
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
fn signature_value(raw: [u8; 4]) -> Value {
    match signature_str(raw) {
        Ok(s) => Value::SStr(s),
        Err(s) => Value::Str(s),
    }
}

/// Swallow invalid-address errors (python `except InvalidAddressException`).
#[inline]
fn caught(r: Result<()>) -> Result<()> {
    match r {
        Err(e) if !e.is_invalid_address() => Err(e),
        _ => Ok(()),
    }
}

/// A `(start, len)` range of a batch arena.
type Span = (usize, usize);

#[inline]
fn span_of(start: usize, end: usize) -> Span {
    (start, end - start)
}

#[inline]
fn text(arena: &str, s: Span) -> &str {
    &arena[s.0..s.0 + s.1]
}

// ------------------------------------------------------------------------------------------
// MFTScan

/// One MFTScan row (a STANDARD_INFORMATION or FILE_NAME attribute of a record).
#[derive(Clone, Copy)]
pub struct MftScanRow {
    /// `Offset`: the attribute data (`STANDARD_INFORMATION_ENTRY` / `FILE_NAME_ENTRY`)
    pub offset: u64,
    /// Created, Modified, Updated, Accessed (FILETIME)
    pub times: [u64; 4],
    pub record_number: u32,
    /// FILE_NAME rows: the name in the batch's `names`
    pub name: Span,
    pub link_count: u16,
    /// raw `MFT_ENTRY.Signature`
    pub signature: [u8; 4],
    /// `MFT_ENTRY.Flags`
    pub flags: u8,
    /// FILE_NAME rows: `FILE_NAME_ENTRY.Flags`
    pub permissions: u8,
    /// FILE_NAME row (tree level 1) or STANDARD_INFORMATION row (level 0)
    pub file_name: bool,
}

/// The MFTScan rows of the records of one scan chunk, and the exception python raised after them.
#[derive(Default)]
pub struct MftScanBatch {
    pub rows: Vec<MftScanRow>,
    pub names: String,
    pub err: Option<Error>,
}

impl MftScanBatch {
    fn clear(&mut self) {
        self.rows.clear();
        self.names.clear();
    }
}

/// python `MFTScan.parse_standard_information_records(record)`.
pub fn parse_standard_information_records(b: &mut MftScanBatch, e: &MftEntry) -> Result<()> {
    let flags = e.flags()?;
    caught((|| {
        for si in e.standard_information_entries()? {
            let signature = e.signature_raw()?;
            let record_number = e.record_number()?;
            let link_count = e.link_count()?;
            let times = si.times()?;
            b.rows.push(MftScanRow { offset: si.offset, times, record_number, name: (0, 0), link_count, signature, flags, permissions: 0, file_name: false });
        }
        Ok(())
    })())
}

/// python `MFTScan.parse_filename_records(record)`.
pub fn parse_filename_records(b: &mut MftScanBatch, e: &MftEntry) -> Result<()> {
    let flags = e.flags()?;
    caught((|| {
        for f in e.filename_entries()? {
            let permissions = f.flags()?;
            let signature = e.signature_raw()?;
            let record_number = e.record_number()?;
            let link_count = e.link_count()?;
            let times = f.times()?;
            let start = b.names.len();
            f.get_full_name_into(&mut b.names)?;
            let name = span_of(start, b.names.len());
            b.rows.push(MftScanRow { offset: f.offset, times, record_number, name, link_count, signature, flags, permissions, file_name: true });
        }
        Ok(())
    })())
}

/// python `MFTScan.parse_mft_records` for one record, into `b` (false = python raised).
pub fn add_mftscan_record(b: &mut MftScanBatch, e: MftEntry) -> bool {
    let r = parse_standard_information_records(b, &e).and_then(|_| parse_filename_records(b, &e));
    match r {
        Ok(()) => true,
        Err(err) => {
            b.err = Some(err);
            false
        }
    }
}

/// MFTScan's `Value`s of one row (python `_generator`).
pub fn mftscan_values(b: &MftScanBatch, r: &MftScanRow) -> [Value; 12] {
    let [c, m, u, a] = r.times.map(|t| wintime_to_datetime(t as i128));
    let (permissions, attr_type, name) = if r.file_name {
        (
            enum_or_hex(permission_flags_name(r.permissions), r.permissions),
            Value::SStr("FILE_NAME"),
            Value::Str(text(&b.names, r.name).to_owned()),
        )
    } else {
        (Value::NotApplicable, Value::SStr("STANDARD_INFORMATION"), Value::NotApplicable)
    };
    [
        Value::Int(r.offset as i128),
        signature_value(r.signature),
        Value::Int(r.record_number as i128),
        Value::Int(r.link_count as i128),
        enum_or_hex(mft_flags_name(r.flags), r.flags),
        permissions,
        attr_type,
        c,
        m,
        u,
        a,
        name,
    ]
}

fn emit_mftscan(b: MftScanBatch, out: &mut dyn RowSink) -> Result<()> {
    for r in &b.rows {
        out.row_ref(r.file_name as usize, &mftscan_values(&b, r))?;
    }
    b.err.map_or(Ok(()), Err)
}

/// MFTScan's rows with the renderer's encoder (quick / csv / pretty): each scan batch is also
/// formatted on its scan worker; the output thread appends the blocks (rows are at tree depths
/// 0 and 1, valid without clamping except possibly a batch's first row, which the renderer
/// checks: such a batch is emitted row by row).
fn run_encoded(layer: &dyn Layer, enc: &RowEncoder, out: &mut dyn RowSink) -> Result<()> {
    #[derive(Default)]
    struct Batch {
        b: MftScanBatch,
        block: Vec<u8>,
    }
    let mut res = Ok(());
    enumerate_mft_batches(
        layer,
        Batch::default,
        |x: &mut Batch, e| {
            let n0 = x.b.rows.len();
            let more = add_mftscan_record(&mut x.b, e);
            for r in &x.b.rows[n0..] {
                enc.row_at(&mut x.block, r.file_name as usize, &mftscan_values(&x.b, r));
            }
            more
        },
        |x| {
            res = (|| {
                let rows = &x.b.rows;
                if let (Some(first), Some(last)) = (rows.first(), rows.last())
                    && !out.rows_encoded_at(&x.block, rows.len(), first.file_name as usize, last.file_name as usize)?
                {
                    for r in rows {
                        out.row_ref(r.file_name as usize, &mftscan_values(&x.b, r))?;
                    }
                }
                x.b.err.map_or(Ok(()), Err)
            })();
            res.is_ok()
        },
    );
    res
}

/// MFTScan's rows with a json / jsonl encoder: each scan batch is also encoded on its scan
/// worker as complete trees (a STANDARD_INFORMATION row with its FILE_NAME children,
/// `RowEncoder::tree_row`). A batch goes to the renderer as one block when it starts with a
/// top-level row and so does the batch after it (then no later row belongs to its last tree);
/// otherwise its rows go one by one. Each batch is therefore held until the next one arrives.
fn run_trees(layer: &dyn Layer, enc: &RowEncoder, out: &mut dyn RowSink) -> Result<()> {
    #[derive(Default)]
    struct Batch {
        b: MftScanBatch,
        block: Vec<u8>,
        t: JsonTrees,
        /// encoded as trees (its first row is at depth 0)
        trees: bool,
    }
    fn emit(mut x: Batch, next_top: bool, enc: &RowEncoder, out: &mut dyn RowSink) -> Result<()> {
        if x.trees && next_top {
            let (n, last) = enc.trees_end(&mut x.t, &mut x.block);
            if out.rows_encoded_trees(&mut x.block, n, last)? {
                return x.b.err.map_or(Ok(()), Err);
            }
        }
        for r in &x.b.rows {
            out.row_ref(r.file_name as usize, &mftscan_values(&x.b, r))?;
        }
        x.b.err.map_or(Ok(()), Err)
    }
    let mut held: Option<Batch> = None;
    let mut res = Ok(());
    enumerate_mft_batches(
        layer,
        Batch::default,
        |x: &mut Batch, e| {
            let n0 = x.b.rows.len();
            let more = add_mftscan_record(&mut x.b, e);
            if n0 == 0 {
                x.trees = x.b.rows.first().is_some_and(|r| !r.file_name);
            }
            if x.trees {
                for r in &x.b.rows[n0..] {
                    enc.tree_row(&mut x.t, &mut x.block, r.file_name as usize, &mftscan_values(&x.b, r));
                }
            }
            more
        },
        |x| {
            res = (|| {
                if x.b.rows.is_empty() && x.b.err.is_none() {
                    return Ok(());
                }
                // python raised after this batch's rows: nothing follows them
                let next_top = x.b.rows.first().is_none_or(|r| !r.file_name);
                if let Some(h) = held.take() {
                    emit(h, next_top, enc, out)?;
                }
                if x.b.err.is_some() {
                    return emit(x, true, enc, out);
                }
                held = Some(x);
                Ok(())
            })();
            res.is_ok()
        },
    );
    if res.is_ok()
        && let Some(h) = held.take()
    {
        res = emit(h, true, enc, out);
    }
    res
}

/// python `MFTScan.generate_timeline()` for one record: its events are appended to `g` (four
/// per STANDARD_INFORMATION / FILE_NAME row, yielded Created, Modified, Changed, Accessed; one
/// group each); `Err` = python raised after them.
fn timeline_record(g: &mut TimelineGroups, desc: &mut String, tmp: &mut MftScanBatch, e: &MftEntry) -> Result<()> {
    use std::fmt::Write;
    let fname = e.longest_filename()?;
    let wt = |t: u64| match wintime_to_datetime(t as i128) {
        Value::DateTime(dt) => TimelineTime::DateTime(dt),
        Value::Unparsable => TimelineTime::Unparsable,
        _ => TimelineTime::NotApplicable,
    };
    tmp.clear();
    let r = parse_standard_information_records(tmp, e);
    let fname = fname.as_deref().unwrap_or("None");
    for row in &tmp.rows {
        desc.clear();
        let _ = write!(desc, "MFT STANDARD_INFORMATION entry for {fname}");
        g.push(desc, row.times.map(wt));
    }
    r?;
    tmp.clear();
    let r = parse_filename_records(tmp, e);
    for row in &tmp.rows {
        desc.clear();
        let _ = write!(desc, "MFT FILE_NAME entry for {}", text(&tmp.names, row.name));
        g.push(desc, row.times.map(wt));
    }
    r
}

/// The event types of a `timeline_record` group, in yield order (`times` = [c, m, u, a]).
const MFT_ORDER: [TimeKind; 4] = [TimeKind::Created, TimeKind::Modified, TimeKind::Changed, TimeKind::Accessed];

// ------------------------------------------------------------------------------------------
// ADS / ResidentData

/// One ADS / ResidentData row.
#[derive(Clone, Copy)]
pub struct DataRow {
    /// `Offset`: the attribute's `Attr_Data`
    pub offset: u64,
    pub record_number: u32,
    /// raw `MFT_ENTRY.Signature`
    pub signature: [u8; 4],
    /// `Attr_Header.AttrType`
    pub attr_type: &'static str,
    /// `longest_filename()` in the batch's `text` (None / empty = python's absent value)
    pub filename: Span,
    /// ADS: `get_resident_filename()` in `text`
    pub stream_name: Span,
    /// `get_resident_filecontent()` in `bytes` (empty = python's absent value)
    pub content: Span,
}

/// The ADS / ResidentData rows of one scan chunk, and the exception python raised after them.
#[derive(Default)]
pub struct DataBatch {
    pub rows: Vec<DataRow>,
    pub text: String,
    pub bytes: Vec<u8>,
    pub err: Option<Error>,
}

impl DataBatch {
    fn push_text(&mut self, s: Option<String>) -> Span {
        let start = self.text.len();
        if let Some(s) = s {
            self.text.push_str(&s);
        }
        span_of(start, self.text.len())
    }
    fn push_bytes(&mut self, c: Option<(u64, Vec<u8>)>) -> Span {
        let start = self.bytes.len();
        if let Some((_, d)) = c {
            self.bytes.extend_from_slice(&d);
        }
        span_of(start, self.bytes.len())
    }
    fn fail(&mut self, r: Result<()>) -> bool {
        match r {
            Ok(()) => true,
            Err(e) => {
                self.err = Some(e);
                false
            }
        }
    }
}

/// python `ADS.parse_ads_data_records(record)` into `b` (false = python raised).
pub fn add_ads_record(b: &mut DataBatch, e: MftEntry) -> bool {
    let r = (|| -> Result<()> {
        for attr in e.alternate_data_streams() {
            let attr = attr?;
            let filename = e.longest_filename()?;
            let content = attr.get_resident_filecontent()?;
            let stream_name = attr.get_resident_filename()?;
            let signature = e.signature_raw()?;
            let record_number = e.record_number()?;
            let filename = b.push_text(filename);
            let stream_name = b.push_text(stream_name);
            let content = b.push_bytes(content);
            b.rows.push(DataRow { offset: attr.attr_data_offset(), record_number, signature, attr_type: attr.attr_type_name(), filename, stream_name, content });
        }
        Ok(())
    })();
    b.fail(r)
}

/// python `ResidentData.parse_resident_data(record)` into `b` (false = python raised).
pub fn add_resident_data_record(b: &mut DataBatch, e: MftEntry) -> bool {
    let r = (|| -> Result<()> {
        let attr = match e.resident_data_attributes().next() {
            None => return Ok(()),
            Some(a) => a?,
        };
        let content = attr.get_resident_filecontent()?;
        let filename = e.longest_filename()?;
        let signature = e.signature_raw()?;
        let record_number = e.record_number()?;
        let filename = b.push_text(filename);
        let content = b.push_bytes(content);
        b.rows.push(DataRow { offset: attr.attr_data_offset(), record_number, signature, attr_type: attr.attr_type_name(), filename, stream_name: (0, 0), content });
        Ok(())
    })();
    b.fail(r)
}

/// `renderers.LayerData.from_object(content)` for resident content python read successfully:
/// the renderer's padded re-read returns the same bytes, and its hole map (translation layers
/// only) finds no hole in a fully readable range.
#[inline]
fn content_value(b: &DataBatch, s: Span) -> Value {
    if s.1 == 0 {
        return Value::NotAvailable;
    }
    Value::LayerBytes { data: b.bytes[s.0..s.0 + s.1].to_vec(), errors: Vec::new() }
}

/// `x or NotAvailableValue()` for a string.
#[inline]
fn str_or_na(b: &DataBatch, s: Span) -> Value {
    if s.1 == 0 { Value::NotAvailable } else { Value::Str(text(&b.text, s).to_owned()) }
}

fn emit_ads(b: DataBatch, out: &mut dyn RowSink) -> Result<()> {
    for r in &b.rows {
        out.row(
            0,
            vec![
                Value::Int(r.offset as i128),
                signature_value(r.signature),
                Value::Int(r.record_number as i128),
                Value::SStr(r.attr_type),
                str_or_na(&b, r.filename),
                str_or_na(&b, r.stream_name),
                content_value(&b, r.content),
            ],
        )?;
    }
    b.err.map_or(Ok(()), Err)
}

fn emit_resident_data(b: DataBatch, out: &mut dyn RowSink) -> Result<()> {
    for r in &b.rows {
        // str(filename): NotAvailableValue() stringifies as "N/A"
        let filename = if r.filename.1 == 0 { Value::SStr("N/A") } else { Value::Str(text(&b.text, r.filename).to_owned()) };
        out.row(
            0,
            vec![
                Value::Int(r.offset as i128),
                signature_value(r.signature),
                Value::Int(r.record_number as i128),
                Value::SStr(r.attr_type),
                filename,
                content_value(&b, r.content),
            ],
        )?;
    }
    b.err.map_or(Ok(()), Err)
}

/// python `context.layers[config["primary"]].config["memory_layer"]`: the physical layer below
/// the Windows translation layer. The plugins need no kernel symbols, a Windows DTB is enough.
/// Without one python reports its own `primary` requirement (also on Linux images: python's
/// stackers do not satisfy it there).
pub fn primary_memory_layer(ctx: &Context) -> Result<LayerRef> {
    match ctx.windows_kernel() {
        Ok(k) => Ok(k.phys),
        // the translation layer was built, only the kernel symbols are missing
        Err(Error::Unsatisfied(s)) if !s.contains("layer_name") => ctx.physical(),
        Err(_) => Err(crate::plugins::unsatisfied_described(&[("primary", crate::plugins::UnsatKind::Layer, "Memory layer for the kernel")])),
    }
}

/// Config flag set by the timeliner: python chooses the automagic stackers by the category of
/// the plugin run from the CLI (`choose_os_stackers`). A standalone `windows.*` plugin only
/// gets the Windows stacker, but the timeliner's category excludes none, so inside the
/// timeliner MFTScan's `primary` is also satisfied by a Linux or Mac layer.
pub const ANY_OS_STACKER: &str = "rsvol-any-os-stacker";

/// [`primary_memory_layer`] when every OS stacker may build the `primary` layer: the physical
/// layer below the Windows, else the Linux, else the Mac translation layer.
pub fn any_os_memory_layer(ctx: &Context) -> Result<LayerRef> {
    primary_memory_layer(ctx).or_else(|e| {
        if let Ok(k) = ctx.linux_kernel() {
            return Ok(k.phys);
        }
        if let Ok(k) = ctx.mac_kernel() {
            return Ok(k.phys);
        }
        Err(e)
    })
}

/// Scan the physical layer, build batches with `add`, render them with `emit`.
fn run_batches<'a, B: Default + Send>(
    layer: &'a dyn Layer,
    add: fn(&mut B, MftEntry<'a>) -> bool,
    emit: fn(B, &mut dyn RowSink) -> Result<()>,
    out: &mut dyn RowSink,
) -> Result<()> {
    let mut res = Ok(());
    enumerate_mft_batches(layer, B::default, add, |b| {
        res = emit(b, out);
        res.is_ok()
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
        let layer = primary_memory_layer(ctx)?;
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
        match out.encoder() {
            Some(enc) if enc.supports_depth() => run_encoded(layer, &enc, out),
            Some(enc) if enc.supports_trees() => run_trees(layer, &enc, out),
            _ => run_batches(layer, add_mftscan_record, emit_mftscan, out),
        }
    }
    /// python `generate_timeline()`. If python raises midway (an unreadable FILE_NAME name or
    /// record flags) the events generated before stay in python's timeline, so they are
    /// returned without the error.
    fn timeline(&self, ctx: &Context, cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        Some(timeline_batches(ctx, cfg).map(|b| b.into_iter().flat_map(TimelineBatch::into_events).collect()))
    }
    /// `timeline()` as the scan workers' batches (millions of events: no concatenation).
    fn timeline_batches(&self, ctx: &Context, cfg: &Config) -> Option<(Vec<TimelineBatch>, Option<Error>)> {
        Some(match timeline_batches(ctx, cfg) {
            Ok(b) => (b, None),
            Err(e) => (Vec::new(), Some(e)),
        })
    }
}

/// The events of `MFTScan.generate_timeline()`, compact, one batch per scan batch, in order.
fn timeline_batches(ctx: &Context, cfg: &Config) -> Result<Vec<TimelineBatch>> {
    let layer = if cfg.get_bool(ANY_OS_STACKER) { any_os_memory_layer(ctx) } else { primary_memory_layer(ctx) }?;
    struct Batch {
        g: TimelineGroups,
        desc: String,
        tmp: MftScanBatch,
        failed: bool,
    }
    let mut all = Vec::new();
    enumerate_mft_batches(
        layer,
        || Batch { g: TimelineGroups::new(MFT_ORDER), desc: String::new(), tmp: MftScanBatch::default(), failed: false },
        |b: &mut Batch, e| {
            b.failed = timeline_record(&mut b.g, &mut b.desc, &mut b.tmp, &e).is_err();
            !b.failed
        },
        |b| {
            if !b.g.groups.is_empty() {
                all.push(TimelineBatch::Groups(b.g));
            }
            !b.failed
        },
    );
    Ok(all)
}

impl Plugin for ADS {
    fn name(&self) -> &'static str {
        "windows.mftscan.ADS"
    }
    fn description(&self) -> &'static str {
        "Scans for Alternate Data Stream"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let layer = primary_memory_layer(ctx)?;
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("Record Type", ColType::Str),
            Column::new("Record Number", ColType::Int),
            Column::new("MFT Type", ColType::Str),
            Column::new("Filename", ColType::Str),
            Column::new("ADS Filename", ColType::Str),
            Column::new("Hexdump", ColType::LayerData),
        ])?;
        run_batches(layer, add_ads_record, emit_ads, out)
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
        let layer = primary_memory_layer(ctx)?;
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("Record Type", ColType::Str),
            Column::new("Record Number", ColType::Int),
            Column::new("MFT Type", ColType::Str),
            Column::new("Filename", ColType::Str),
            Column::new("Hexdump", ColType::LayerData),
        ])?;
        run_batches(layer, add_resident_data_record, emit_resident_data, out)
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

    /// `timeline()` through a model of python's `timeliner.Timeliner` with only MFTScan
    /// selected (`--plugin-filter windows.mftscan.MFTScan`): one row per distinct description in
    /// first-seen order, every row showing the times dict of the LAST event (python's loop
    /// variable leaks). Needs the image and `MFT_TIMELINER_REF` (python's output), so ignored.
    #[test]
    #[ignore]
    fn timeliner_model() {
        use crate::context::GlobalOptions;
        let (Ok(img), Ok(reference)) = (std::env::var("MFT_TIMELINER_IMG"), std::env::var("MFT_TIMELINER_REF")) else { return };
        let ctx = Context::new(GlobalOptions { file: Some(img), ..Default::default() }).unwrap();
        let ev = MFTScan.timeline(&ctx, &Config::default()).unwrap().unwrap();
        let mut order: Vec<&str> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for e in &ev {
            if seen.insert(e.description.as_str()) {
                order.push(&e.description);
            }
        }
        let last = ev.last().unwrap().description.as_str();
        let get = |k: TimeKind| ev.iter().rev().filter(|e| e.description == last).find(|e| e.kind == k).map(|e| e.time.clone()).unwrap_or(Value::NotApplicable);
        let cell = |v: &Value| {
            let mut o = Vec::new();
            crate::renderers::text::render_cell(&mut o, ColType::DateTime, v, false);
            String::from_utf8(o).unwrap()
        };
        let times = [TimeKind::Created, TimeKind::Modified, TimeKind::Accessed, TimeKind::Changed].map(|k| cell(&get(k))).join("\t");
        let mut want = String::from("Volatility 3 Framework 2.28.2\n\nPlugin\tDescription\tCreated Date\tModified Date\tAccessed Date\tChanged Date\n");
        for d in order {
            want.push_str(&format!("\nMFTScan\t{d}\t{times}"));
        }
        want.push('\n');
        let got = std::fs::read_to_string(reference).unwrap();
        assert!(got == want, "timeliner model differs");
    }

    /// A data layer that is not file-backed (the scan reads it chunk by chunk through the layer).
    struct Mem(Vec<u8>);
    impl Layer for Mem {
        fn name(&self) -> &str {
            "memory_layer"
        }
        fn max_address(&self) -> u64 {
            self.0.len() as u64 - 1
        }
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let a = addr as usize;
            match self.0.get(a..a + buf.len()) {
                Some(s) => {
                    buf.copy_from_slice(s);
                    Ok(())
                }
                None => Err(Error::invalid(addr)),
            }
        }
        fn is_valid(&self, addr: u64, len: u64) -> bool {
            addr + len <= self.0.len() as u64
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(crate::layers::Mapping) -> bool) {
            let end = (addr + len).min(self.0.len() as u64);
            if addr < end {
                f(crate::layers::Mapping { offset: addr, len: end - addr, mapped: addr });
            }
        }
    }

    /// python's chunking + YaraScanner: 16 MiB + 4 KiB chunks, every hit of a chunk reported
    /// (overlap hits twice), a hit straddling a chunk end only by the next chunk, the layer's
    /// last byte never scanned.
    #[test]
    fn chunk_overlap_semantics() {
        const C: usize = 0x100_0000;
        let size = 2 * C + 0x3000;
        let mut d = vec![0u8; size];
        let put = |d: &mut Vec<u8>, at: usize, s: &[u8]| d[at..at + s.len()].copy_from_slice(s);
        let sigs: [(usize, &[u8]); 7] = [
            (0x10, b"FILE0"),
            (C - 2, b"BAAD"),          // across the chunk boundary, inside chunk 0's overlap
            (C + 0x100, b"FILE*"),     // in chunk 0's overlap: reported by chunks 0 and 1
            (C + 0x1000 - 2, b"BAAD"), // straddles the end of chunk 0's data: only chunk 1
            (2 * C + 0x20, b"FILE0"),  // chunk 1's overlap + chunk 2
            (size - 0x20, b"FILE0"),   // only the last (short) chunk
            (size - 4, b"BAAD"),       // needs the layer's last byte: never scanned
        ];
        for (at, s) in sigs {
            put(&mut d, at, s);
        }
        let layer = Mem(d);
        let mut got = Vec::new();
        enumerate_mft_records(&layer, |e| e.offset, |o| {
            got.push(o as usize);
            true
        });
        let want = vec![0x10, C - 2, C + 0x100, C + 0x100, C + 0x1000 - 2, 2 * C + 0x20, 2 * C + 0x20, size - 0x20];
        assert_eq!(got, want);
    }

    /// No Intel layer at all: python reports its own `primary` requirement (captured from
    /// `vol.py -q -f <1 MiB of zeros> windows.mftscan.MFTScan`).
    #[test]
    fn unsatisfied_primary() {
        struct Stub;
        impl Plugin for Stub {
            fn name(&self) -> &'static str {
                "windows.mftscan.MFTScan"
            }
            fn description(&self) -> &'static str {
                ""
            }
            fn run(&self, _ctx: &Context, _cfg: &Config, _out: &mut dyn RowSink) -> Result<()> {
                Err(crate::plugins::unsatisfied_described(&[("primary", crate::plugins::UnsatKind::Layer, "Memory layer for the kernel")]))
            }
        }
        static S: Stub = Stub;
        let plugins: Vec<&'static dyn Plugin> = vec![&S];
        let argv: Vec<String> = ["vol.py", "-q", "windows.mftscan.MFTScan"].iter().map(|s| s.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let s = crate::cli::Settings { no_system_defaults: true, ..Default::default() };
        assert_eq!(crate::cli::run(&argv, &plugins, &mut out, &mut err, &s), 1);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Volatility 3 Framework 2.28.2\n\nUnsatisfied requirement plugins.MFTScan.primary: Memory layer for the kernel\n\n\
             A translation layer requirement was not fulfilled.  Please verify that:\n\
             \tA file was provided to create this layer (by -f, --single-location or by config)\n\
             \tThe file exists and is readable\n\
             \tThe file is a valid memory image and was acquired cleanly\n"
        );
        assert_eq!(String::from_utf8(err).unwrap(), "Unable to validate the plugin requirements: ['plugins.MFTScan.primary']\n");
    }

    #[test]
    fn signatures() {
        assert_eq!(signature_str(*b"FILE"), Ok("FILE"));
        assert_eq!(signature_str(*b"BAAD"), Ok("BAAD"));
        assert_eq!(signature_str(*b"AB\0C"), Err("AB".to_string()));
    }
}
