//! quick / pretty / csv / json / jsonl / none / mermaid renderers, a port of volatility3
//! `cli/text_renderer.py` (derived from Volatility 3, Volatility Software License 1.0).
//!
//! quick / csv / jsonl stream: rows are formatted straight into one large byte buffer that is
//! written to the output whenever it passes `FLUSH_AT`. pretty / json / mermaid buffer the whole
//! grid like python does. Cells are formatted by COLUMN type (python looks the type renderer up
//! by `column.type`), with python's formatting rules for every value kind.

use super::pyfmt::*;
use super::{ColType, Column, Encoding, RowSink, Value};
use crate::cli::filter::CliFilter;
use crate::error::{Error, Result};
use std::io::Write;

/// Renderer names in the order volatility3 lists them (`class_subclasses(CLIRenderer)`).
pub const RENDERER_NAMES: [&str; 7] = ["quick", "none", "csv", "pretty", "json", "jsonl", "mermaid"];

/// Structured renderers get the banner on stderr instead of stdout.
pub fn is_structured(name: &str) -> bool {
    matches!(name, "csv" | "json" | "jsonl" | "mermaid")
}

/// CLI options that affect rendering.
#[derive(Clone, Debug, Default)]
pub struct RenderOptions {
    /// `--filters` values
    pub filters: Vec<String>,
    /// `--hide-columns` (None when not given)
    pub hide_columns: Option<Vec<String>>,
    /// Hand every row to the output right away (the CLI sets this when stdout is a terminal,
    /// so rows show up as a slow plugin finds them, like python's per-row flush). Otherwise
    /// output is written in large blocks.
    pub flush_rows: bool,
}

/// A failure raised by the renderer itself (python: RenderException, or an uncaught exception
/// such as IndexError / re.error inside the filter).
#[derive(Clone, Debug, PartialEq)]
pub enum RenderFailure {
    NoVisibleColumns,
    Crash(String),
}

/// A renderer driven by the CLI: the plugin feeds it through [`RowSink`], then the CLI calls
/// `finish` (success) or `abort` (the plugin failed).
pub trait TextRenderer: RowSink {
    /// Write the trailing output and flush.
    fn finish(&mut self) -> Result<()>;
    /// The plugin failed. `unsatisfied`: the failure is one python detects before rendering
    /// starts (requirements), so any output not yet written is dropped. Otherwise whatever python
    /// would have written up to the failure is flushed.
    fn abort(&mut self, unsatisfied: bool) -> Result<()>;
    /// Renderer-side failure, if the last error came from the renderer.
    fn failure(&self) -> Option<&RenderFailure>;
}

/// Create a renderer by (lower-case) name.
pub fn create<'a>(name: &str, out: &'a mut dyn Write, opts: RenderOptions) -> Option<Box<dyn TextRenderer + 'a>> {
    let base = Base::new(out, opts);
    Some(match name {
        "quick" => Box::new(Quick { b: base, scratch: Vec::new(), spans: Vec::new() }),
        "csv" => Box::new(Csv { b: base, scratch: Vec::new(), spans: Vec::new() }),
        "pretty" => Box::new(Pretty {
            b: base,
            widths: Vec::new(),
            tree_width: 0,
            arena: Vec::new(),
            cells: Vec::new(),
            depths: Vec::new(),
            scratch: Vec::new(),
            spans: Vec::new(),
        }),
        "json" => Box::new(Json::new(base, false)),
        "jsonl" => Box::new(Json::new(base, true)),
        "none" => Box::new(NoneRenderer { b: base }),
        "mermaid" => Box::new(Mermaid { b: base, rows: Vec::new() }),
        _ => return None,
    })
}

// ------------------------------------------------------------------------------------------
// shared plumbing

const FLUSH_AT: usize = 1 << 18;

struct Base<'a> {
    buf: Vec<u8>,
    w: &'a mut dyn Write,
    /// bytes already handed to `w`
    flushed: bool,
    opts: RenderOptions,
    columns: Vec<Column>,
    hidden: Vec<bool>,
    filter: Option<CliFilter>,
    /// TreeGrid population: `len(prev_nodes)`
    depth_len: usize,
    rows: usize,
    failure: Option<RenderFailure>,
    begun: bool,
}

impl<'a> Base<'a> {
    fn new(w: &'a mut dyn Write, opts: RenderOptions) -> Base<'a> {
        Base {
            buf: Vec::with_capacity(FLUSH_AT + 8192),
            w,
            flushed: false,
            opts,
            columns: Vec::new(),
            hidden: Vec::new(),
            filter: None,
            depth_len: 0,
            rows: 0,
            failure: None,
            begun: false,
        }
    }

    /// TreeGrid.populate: a row can be at most one level deeper than the previous one.
    #[inline]
    fn depth(&mut self, level: usize) -> usize {
        let d = level.min(self.depth_len);
        self.depth_len = d + 1;
        d
    }

    #[inline]
    fn maybe_flush(&mut self) -> Result<()> {
        if self.buf.len() >= FLUSH_AT || (self.opts.flush_rows && !self.buf.is_empty()) {
            self.flush_buf()?;
        }
        Ok(())
    }

    fn flush_buf(&mut self) -> Result<()> {
        if !self.buf.is_empty() {
            self.flushed = true;
            self.w.write_all(&self.buf)?;
            self.buf.clear();
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.flush_buf()?;
        self.w.flush()?;
        Ok(())
    }

    /// Store the columns and set up the filter (`CLIFilter(grid, args.filters)`).
    fn set_columns(&mut self, columns: Vec<Column>) {
        self.begun = true;
        if !self.opts.filters.is_empty() {
            let f = CliFilter::new(&columns, &self.opts.filters);
            if f.is_active() {
                self.filter = Some(f);
            }
        }
        self.hidden = vec![false; columns.len()];
        self.columns = columns;
    }

    /// `CLIRenderer.ignored_columns`
    fn compute_hidden(&mut self) -> Result<()> {
        let n = self.columns.len();
        let list = match &self.opts.hide_columns {
            None => return Ok(()),
            Some(l) => l,
        };
        let mut count = 0;
        if !list.is_empty() {
            let prefixes: Vec<String> = list.iter().map(|p| p.to_lowercase()).collect();
            for (i, c) in self.columns.iter().enumerate() {
                let lname = c.name.to_lowercase();
                if prefixes.iter().any(|p| lname.starts_with(p.as_str())) {
                    self.hidden[i] = true;
                    count += 1;
                }
            }
        }
        if count == n {
            self.failure = Some(RenderFailure::NoVisibleColumns);
            return Err(Error::msg("No visible columns to render"));
        }
        Ok(())
    }

    fn crash(&mut self, msg: String) -> Error {
        self.failure = Some(RenderFailure::Crash(msg.clone()));
        Error::Msg(msg)
    }

    /// Run the filter over already-rendered strings.
    fn filtered<S: AsRef<str>>(&mut self, line: &[S]) -> Result<bool> {
        match &self.filter {
            None => Ok(false),
            Some(f) => match f.filter(line) {
                Ok(v) => Ok(v),
                Err(e) => Err(self.crash(e.0)),
            },
        }
    }
}

fn check_len(columns: &[Column], values: &[Value]) -> Result<()> {
    if values.len() != columns.len() {
        return Err(Error::msg(
            "Values must be a list of objects made up of simple types and number the same as the columns",
        ));
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------
// cell formatting

/// `optional()` wrapper text for absent values.
#[inline]
fn absent_text(v: &Value) -> Option<&'static [u8]> {
    match v {
        Value::NotApplicable => Some(b"N/A"),
        Value::Unreadable | Value::Unparsable | Value::NotAvailable => Some(b"-"),
        _ => None,
    }
}

/// Values whose cell text (in any column) is plain printable ASCII without tabs, newlines or
/// csv specials: numbers, hex / binary, booleans, datetimes, absent markers.
#[inline(always)]
fn plain_cell(v: &Value) -> bool {
    matches!(
        v,
        Value::Int(_)
            | Value::Float(_)
            | Value::Bool(_)
            | Value::DateTime(_)
            | Value::Unreadable
            | Value::Unparsable
            | Value::NotApplicable
            | Value::NotAvailable
    )
}

/// `hex_bytes_as_text(value)`
pub fn hex_bytes_as_text(out: &mut Vec<u8>, data: &[u8], errors: &[u32]) {
    const WIDTH: usize = 16;
    out.push(b'\n');
    let mut printables = [0u8; WIDTH];
    let mut np = 0;
    let mut err_iter = errors.iter().peekable();
    for (count, &byte) in data.iter().enumerate() {
        let is_err = match err_iter.peek() {
            Some(&&e) if e as usize == count => {
                err_iter.next();
                true
            }
            _ => false,
        };
        if is_err {
            out.extend_from_slice(b"__ ");
            printables[np] = b'.';
        } else {
            push_hex_byte(out, byte);
            out.push(b' ');
            printables[np] = if (0x20..=0x7e).contains(&byte) { byte } else { b'.' };
        }
        np += 1;
        if count % WIDTH == WIDTH - 1 {
            out.extend_from_slice(&printables[..np]);
            if count < data.len() - 1 {
                out.push(b'\n');
            }
            np = 0;
        }
    }
    if np > 0 {
        let padding = WIDTH - np;
        for _ in 0..padding {
            out.extend_from_slice(b"   ");
        }
        out.extend_from_slice(&printables[..np]);
        for _ in 0..padding {
            out.push(b' ');
        }
    }
}

fn decode(data: &[u8], enc: Encoding) -> String {
    match enc {
        Encoding::Utf16Le => decode_utf16le_replace(data),
        Encoding::Utf8 => String::from_utf8_lossy(data).into_owned(),
        Encoding::Latin1 => data.iter().map(|&b| b as char).collect(),
    }
}

/// `multitypedata_as_text(value)`
fn multitypedata_as_text(out: &mut Vec<u8>, data: &[u8], enc: Encoding, split_nulls: bool, show_hex: bool) {
    if show_hex {
        return hex_bytes_as_text(out, data, &[]);
    }
    let s = decode(data, enc);
    let slen = char_len(&s) as f64;
    let half = data.len() as f64 / 2.0;
    if split_nulls && (half - 1.0) <= slen && slen <= half {
        for c in s.chars() {
            if c == '\0' {
                out.push(b'\n');
            } else {
                let mut b = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
        }
        return;
    }
    let first = s.split('\0').next().unwrap_or("");
    let flen = char_len(first) as f64;
    if slen - 1.0 <= flen && flen <= slen {
        out.extend_from_slice(first.as_bytes());
        return;
    }
    hex_bytes_as_text(out, data, &[])
}

fn push_hex_joined(out: &mut Vec<u8>, data: &[u8]) {
    for (i, &b) in data.iter().enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        push_hex_byte(out, b);
    }
}

fn display_disassembly(out: &mut Vec<u8>, data: &[u8], offset: u64, arch: Option<&'static str>) {
    if let Some(a) = arch {
        out.extend_from_slice(crate::disasm::format_capstone(data, offset, a).as_bytes());
    }
}

/// python `f"{x}"` (the "default" type renderer) for a non-absent value.
fn push_default(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Int(i) => push_i128(out, *i),
        Value::Str(s) => out.extend_from_slice(s.as_bytes()),
        Value::SStr(s) => out.extend_from_slice(s.as_bytes()),
        Value::Bytes(b) => push_bytes_repr(out, b),
        Value::Float(f) => push_float(out, *f),
        Value::Bool(b) => out.extend_from_slice(if *b { b"True" } else { b"False" }),
        Value::DateTime(dt) => push_datetime_iso(out, dt, b' '),
        Value::MultiTypeData { data, .. } => push_bytes_repr(out, data),
        Value::Disassembly { data, .. } => push_bytes_repr(out, data),
        Value::LayerData(s) => out.extend_from_slice(s.as_bytes()),
        Value::LayerBytes { data, .. } => push_bytes_repr(out, data),
        Value::Unreadable | Value::Unparsable | Value::NotAvailable => out.push(b'-'),
        Value::NotApplicable => out.extend_from_slice(b"N/A"),
    }
}

fn value_bytes(v: &Value) -> Option<&[u8]> {
    match v {
        Value::Bytes(b) => Some(b),
        Value::MultiTypeData { data, .. } => Some(data),
        Value::Disassembly { data, .. } => Some(data),
        Value::LayerBytes { data, .. } => Some(data),
        _ => None,
    }
}

/// Text of a cell for the quick / pretty / csv renderers (`CLIRenderer._type_renderers`).
/// `mermaid` switches to `MermaidRenderer._type_renderers` (Disassembly and LayerData columns use
/// the default renderer there).
pub fn render_cell(out: &mut Vec<u8>, ty: ColType, v: &Value, mermaid: bool) {
    // the common cells first (same results as the general rules below)
    match (ty, v) {
        (ColType::Hex, Value::Int(i)) if *i >= 0 && *i <= u64::MAX as i128 => return push_0x_hex_u64(out, *i as u64),
        (ColType::Int, Value::Int(i)) => return push_i128(out, *i),
        (_, Value::SStr(s)) => return out.extend_from_slice(s.as_bytes()),
        (_, Value::Str(s)) => return out.extend_from_slice(s.as_bytes()),
        (ColType::DateTime, Value::DateTime(dt)) => return push_datetime_cli(out, dt),
        _ => {}
    }
    if let Some(t) = absent_text(v) {
        out.extend_from_slice(t);
        return;
    }
    match (ty, v) {
        (ColType::Hex, Value::Int(i)) => {
            out.extend_from_slice(b"0x");
            push_hex(out, *i);
        }
        (ColType::Hex, Value::Bool(b)) => out.extend_from_slice(if *b { b"0x1" } else { b"0x0" }),
        (ColType::Bin, Value::Int(i)) => {
            out.extend_from_slice(b"0b");
            push_bin(out, *i);
        }
        (ColType::Bin, Value::Bool(b)) => out.extend_from_slice(if *b { b"0b1" } else { b"0b0" }),
        (ColType::HexBytes, _) if value_bytes(v).is_some() => {
            let errs: &[u32] = if let Value::LayerBytes { errors, .. } = v { errors } else { &[] };
            hex_bytes_as_text(out, value_bytes(v).unwrap(), errs)
        }
        (ColType::MultiTypeData, Value::MultiTypeData { data, encoding, split_nulls, show_hex, .. }) => {
            multitypedata_as_text(out, data, *encoding, *split_nulls, *show_hex)
        }
        (ColType::MultiTypeData, Value::Bytes(data)) => multitypedata_as_text(out, data, Encoding::Utf16Le, false, false),
        (ColType::Disassembly, Value::Disassembly { data, offset, arch }) if !mermaid => {
            display_disassembly(out, data, *offset, *arch)
        }
        (ColType::Bytes, _) if value_bytes(v).is_some() => push_hex_joined(out, value_bytes(v).unwrap()),
        (ColType::LayerData, Value::LayerBytes { data, errors }) if !mermaid => hex_bytes_as_text(out, data, errors),
        (ColType::DateTime, Value::DateTime(dt)) => push_datetime_cli(out, dt),
        _ => push_default(out, v),
    }
}

/// Write a cell the way python's JsonRenderer + `json.dumps` do (no intermediate values).
fn write_json_cell(out: &mut Vec<u8>, ty: ColType, v: &Value, scratch: &mut Vec<u8>) {
    let absent = v.is_absent();
    match ty {
        ColType::HexBytes | ColType::LayerData if absent => return out.extend_from_slice(b"\"N/A\""),
        ColType::HexBytes | ColType::LayerData | ColType::Bytes if value_bytes(v).is_some() => {
            if ty == ColType::LayerData && !matches!(v, Value::LayerBytes { .. }) {
                return write_json_default(out, v, scratch);
            }
            out.push(b'"');
            push_hex_joined(out, value_bytes(v).unwrap());
            out.push(b'"');
            return;
        }
        ColType::Disassembly | ColType::MultiTypeData => {
            // quoted_optional(...)
            if absent {
                return out.extend_from_slice(b"\"\"");
            }
            scratch.clear();
            render_cell(scratch, ty, v, false);
            if scratch.as_slice() == b"-" || scratch.as_slice() == b"N/A" {
                return out.extend_from_slice(b"\"\"");
            }
            let converted_int = matches!(v, Value::MultiTypeData { converted_int: true, .. });
            if !(converted_int || matches!(v, Value::Int(_) | Value::Bool(_))) {
                scratch.insert(0, b'"');
                scratch.push(b'"');
            }
            return push_json_str(out, &String::from_utf8_lossy(scratch));
        }
        ColType::Bytes => {
            if let Some(t) = absent_text(v) {
                out.push(b'"');
                out.extend_from_slice(t);
                out.push(b'"');
                return;
            }
        }
        ColType::DateTime => {
            if absent {
                return out.extend_from_slice(b"null");
            }
            if let Value::DateTime(dt) = v {
                out.push(b'"');
                push_datetime_iso(out, dt, b'T');
                out.push(b'"');
                return;
            }
        }
        _ => {}
    }
    write_json_default(out, v, scratch)
}

/// JsonRenderer's "default" renderer: the python value itself through `json.dumps`.
fn write_json_default(out: &mut Vec<u8>, v: &Value, scratch: &mut Vec<u8>) {
    match v {
        Value::Int(i) => push_i128(out, *i),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Float(f) => {
            if f.is_nan() {
                out.extend_from_slice(b"NaN")
            } else if f.is_infinite() {
                out.extend_from_slice(if *f > 0.0 { b"Infinity" } else { b"-Infinity" })
            } else {
                push_float(out, *f)
            }
        }
        Value::Str(s) => push_json_str(out, s),
        Value::SStr(s) => push_json_str(out, s),
        _ if v.is_absent() => out.extend_from_slice(b"null"),
        _ => {
            scratch.clear();
            push_default(scratch, v);
            push_json_str(out, &String::from_utf8_lossy(scratch));
        }
    }
}

/// python `f"{data}"` of the JsonRenderer value (what `--filters` sees with json / jsonl).
fn json_py_str(ty: ColType, v: &Value) -> String {
    let mut j = Vec::new();
    let mut scratch = Vec::new();
    write_json_cell(&mut j, ty, v, &mut scratch);
    match j.as_slice() {
        b"null" => return "None".into(),
        b"true" => return "True".into(),
        b"false" => return "False".into(),
        _ => {}
    }
    if j.first() == Some(&b'"') {
        // strings: decode the JSON literal back
        return match crate::cli::json::parse(&String::from_utf8_lossy(&j)) {
            Ok(crate::cli::json::Json::Str(s)) => s,
            _ => String::new(),
        };
    }
    match v {
        Value::Float(f) => {
            let mut o = Vec::new();
            push_float(&mut o, *f);
            String::from_utf8_lossy(&o).into_owned()
        }
        _ => String::from_utf8_lossy(&j).into_owned(),
    }
}

/// Render the visible (or all) cells of a row into `buf`, recording `(start, end)` offsets.
fn render_line(buf: &mut Vec<u8>, spans: &mut Vec<(usize, usize)>, cols: &[Column], hidden: &[bool], values: &[Value], all: bool) {
    buf.clear();
    spans.clear();
    for (i, v) in values.iter().enumerate() {
        if all || !hidden[i] {
            let st = buf.len();
            render_cell(buf, cols[i].ty, v, false);
            spans.push((st, buf.len()));
        }
    }
}

fn span_strs<'b>(buf: &'b [u8], spans: &[(usize, usize)]) -> Vec<&'b str> {
    spans.iter().map(|&(a, b)| std::str::from_utf8(&buf[a..b]).unwrap_or("")).collect()
}

// ------------------------------------------------------------------------------------------
// row encoder (formatting off the renderer's thread)

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EncKind {
    Quick,
    Csv,
    Jsonl,
    Json,
    Pretty,
    /// `-r none`: nothing to format
    Null,
}

/// Formats depth-0 rows exactly like one of the text renderers would, without touching the
/// renderer, so hot plugins can format on worker threads (see [`RowSink::encoder`]). The bytes
/// are private to the renderer that made the encoder: hand them back to it with
/// [`RowSink::rows_encoded`].
#[derive(Clone, Debug)]
pub struct RowEncoder {
    kind: EncKind,
    ncols: usize,
    /// visible columns in column order: (column index, type)
    cols: Vec<(usize, ColType)>,
    /// json / jsonl: sorted (escaped key, column index or usize::MAX for `__children`)
    keys: Vec<(Vec<u8>, usize)>,
    /// every column's type
    types: Vec<ColType>,
    /// per column: how an integer cell is written (`cell_u64`)
    int_cells: Vec<IntCell>,
}

/// How [`RowEncoder::cell_u64`] writes an integer cell of a column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IntCell {
    /// not shown
    Hidden,
    /// `0x` + hex (a Hex column in quick / csv)
    Hex,
    /// decimal (an Int column in quick / csv; json writes the number)
    Dec,
    /// pretty's cell record around `0x` + hex / decimal
    PrettyHex,
    PrettyDec,
    /// anything else: through `push_cell`
    Other,
}

impl RowEncoder {
    fn new(kind: EncKind, columns: &[Column], hidden: &[bool], keys: Vec<(Vec<u8>, usize)>) -> RowEncoder {
        let int_cells = columns
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let shown = match kind {
                    EncKind::Jsonl | EncKind::Json => keys.iter().any(|k| k.1 == i),
                    EncKind::Null => false,
                    _ => !hidden[i],
                };
                match (kind, c.ty) {
                    _ if !shown => IntCell::Hidden,
                    (EncKind::Quick | EncKind::Csv, ColType::Hex) => IntCell::Hex,
                    (EncKind::Quick | EncKind::Csv, ColType::Int) => IntCell::Dec,
                    (EncKind::Pretty, ColType::Hex) => IntCell::PrettyHex,
                    (EncKind::Pretty, ColType::Int) => IntCell::PrettyDec,
                    (EncKind::Jsonl | EncKind::Json, ty) if !matches!(ty, ColType::Disassembly | ColType::MultiTypeData) => IntCell::Dec,
                    _ => IntCell::Other,
                }
            })
            .collect();
        RowEncoder {
            kind,
            ncols: columns.len(),
            cols: columns.iter().enumerate().filter(|(i, _)| !hidden[*i]).map(|(i, c)| (i, c.ty)).collect(),
            keys,
            types: columns.iter().map(|c| c.ty).collect(),
            int_cells,
        }
    }

    /// How [`RowEncoder::cell_u64`] writes column `col`, when it is plain text: `Some(true)` =
    /// `0x` + hex ([`crate::renderers::pyfmt::write_0x_hex_u64`]), `Some(false)` = decimal
    /// ([`crate::renderers::pyfmt::write_u64`]); None = anything else (use `cell_u64`).
    pub fn u64_cell_text(&self, col: usize) -> Option<bool> {
        match self.int_cells[col] {
            IntCell::Hex => Some(true),
            IntCell::Dec => Some(false),
            _ => None,
        }
    }

    /// [`RowEncoder::cell`] of `Value::Int(v)`, without building the value (hot template loops).
    #[inline]
    pub fn cell_u64(&self, out: &mut Vec<u8>, col: usize, v: u64) {
        match self.int_cells[col] {
            IntCell::Hidden => {}
            IntCell::Hex => push_0x_hex_u64(out, v),
            IntCell::Dec => push_u64(out, v),
            IntCell::PrettyHex | IntCell::PrettyDec => {
                let hdr = out.len();
                out.extend_from_slice(&[0u8; 8]);
                let st = out.len();
                if self.int_cells[col] == IntCell::PrettyHex {
                    push_0x_hex_u64(out, v);
                } else {
                    push_u64(out, v);
                }
                let len = (out.len() - st) as u32;
                out[hdr..hdr + 4].copy_from_slice(&len.to_le_bytes());
                out[hdr + 4..hdr + 8].copy_from_slice(&len.to_le_bytes());
            }
            IntCell::Other => self.push_cell(out, col, self.types[col], &Value::Int(v as i128)),
        }
    }

    /// Whether the rows are thrown away (`-r none`): callers may skip building values.
    pub fn is_null(&self) -> bool {
        self.kind == EncKind::Null
    }

    /// Append one depth-0 row. `values.len()` must be the number of columns.
    #[inline]
    pub fn row(&self, out: &mut Vec<u8>, values: &[Value]) {
        self.encode(out, 0, values)
    }

    /// Whether [`RowEncoder::row_at`] is available: quick / csv / pretty / none (json and jsonl
    /// nest child rows inside their parents).
    pub fn supports_depth(&self) -> bool {
        !matches!(self.kind, EncKind::Jsonl | EncKind::Json)
    }

    /// Append one row at tree depth `depth` (see [`RowSink::rows_encoded_at`]: the depths of a
    /// block must be valid without clamping, each at most one more than the previous row's).
    /// Only when [`RowEncoder::supports_depth`].
    #[inline]
    pub fn row_at(&self, out: &mut Vec<u8>, depth: usize, values: &[Value]) {
        assert!(depth == 0 || self.supports_depth(), "RowEncoder::row_at: json rows can't be encoded below the top level");
        self.encode(out, depth, values)
    }

    #[inline]
    fn encode(&self, out: &mut Vec<u8>, depth: usize, values: &[Value]) {
        self.encode_marked(out, depth, values, usize::MAX);
    }

    /// One visible cell of column `i` in this renderer's row format.
    #[inline]
    fn push_cell(&self, out: &mut Vec<u8>, i: usize, ty: ColType, v: &Value) {
        match self.kind {
            EncKind::Quick => render_cell(out, ty, v, false),
            EncKind::Csv => {
                let st = out.len();
                render_cell(out, ty, v, false);
                if !plain_cell(v) {
                    csv_fix_field(out, st);
                }
            }
            EncKind::Jsonl | EncKind::Json => write_json_cell(out, self.types[i], v, &mut Vec::new()),
            EncKind::Pretty => {
                // u32 length, u32 width (| SLOW), bytes
                let hdr = out.len();
                out.extend_from_slice(&[0u8; 8]);
                let st = out.len();
                render_cell(out, ty, v, false);
                let len = (out.len() - st) as u32;
                let w = if plain_cell(v) { len } else { pretty_width(&out[st..]) };
                out[hdr..hdr + 4].copy_from_slice(&len.to_le_bytes());
                out[hdr + 4..hdr + 8].copy_from_slice(&w.to_le_bytes());
            }
            EncKind::Null => {}
        }
    }

    /// `encode`, returning where column `mark`'s cell went in `out` (an empty span at the end
    /// when that column is not shown).
    fn encode_marked(&self, out: &mut Vec<u8>, depth: usize, values: &[Value], mark: usize) -> (usize, usize) {
        assert_eq!(values.len(), self.ncols, "RowEncoder::row: wrong number of values");
        let mut span = None;
        match self.kind {
            EncKind::Quick => {
                out.push(b'\n');
                push_tree_prefix(out, depth);
                for (k, &(i, ty)) in self.cols.iter().enumerate() {
                    if k > 0 {
                        out.push(b'\t');
                    }
                    let st = out.len();
                    self.push_cell(out, i, ty, &values[i]);
                    if i == mark {
                        span = Some((st, out.len()));
                    }
                }
            }
            EncKind::Csv => {
                push_u64(out, depth as u64);
                for &(i, ty) in &self.cols {
                    out.push(b',');
                    let st = out.len();
                    self.push_cell(out, i, ty, &values[i]);
                    if i == mark {
                        span = Some((st, out.len()));
                    }
                }
                out.push(b'\n');
            }
            EncKind::Jsonl => {
                push_json_node(out, &self.keys, &self.types, values, 1, true, true, &mut Vec::new(), mark, &mut span);
                out.push(b'\n');
            }
            EncKind::Json => {
                out.push(b',');
                push_newline_indent(out, 1);
                push_json_node(out, &self.keys, &self.types, values, 1, false, true, &mut Vec::new(), mark, &mut span);
            }
            EncKind::Pretty => {
                // u32 depth, then the cells
                out.extend_from_slice(&(depth as u32).to_le_bytes());
                for &(i, ty) in &self.cols {
                    let st = out.len();
                    self.push_cell(out, i, ty, &values[i]);
                    if i == mark {
                        span = Some((st, out.len()));
                    }
                }
            }
            EncKind::Null => {}
        }
        span.unwrap_or((out.len(), out.len()))
    }

    /// A template for depth-0 rows that differ only in column `col`: `prefix` + the
    /// [`RowEncoder::cell`] of that column + `suffix` is exactly [`RowEncoder::row`] (appends
    /// to both buffers; `values[col]` is a placeholder).
    pub fn row_template(&self, values: &[Value], col: usize, prefix: &mut Vec<u8>, suffix: &mut Vec<u8>) {
        let mut buf = Vec::new();
        let (a, b) = self.encode_marked(&mut buf, 0, values, col);
        prefix.extend_from_slice(&buf[..a]);
        suffix.extend_from_slice(&buf[b..]);
    }

    /// The cell of column `col` as it appears inside this encoder's rows (the gap of a
    /// [`RowEncoder::row_template`]; nothing for a hidden column).
    #[inline]
    pub fn cell(&self, out: &mut Vec<u8>, col: usize, v: &Value) {
        let shown = match self.kind {
            EncKind::Jsonl | EncKind::Json => self.keys.iter().any(|k| k.1 == col),
            _ => self.cols.iter().any(|c| c.0 == col),
        };
        if shown {
            self.push_cell(out, col, self.types[col], v);
        }
    }
}

impl<'a> Base<'a> {
    /// The row encoder of a renderer (None before `begin`, after a failure, or with an active
    /// filter: filtered rows need the renderer's per-row decision).
    fn encoder(&self, kind: EncKind, keys: Vec<(Vec<u8>, usize)>) -> Option<RowEncoder> {
        if !self.begun || self.filter.is_some() || self.failure.is_some() {
            return None;
        }
        Some(RowEncoder::new(kind, &self.columns, &self.hidden, keys))
    }

    /// Streaming renderers: append pre-formatted rows (the last one at `last_depth`). Big
    /// blocks go straight to the output after whatever is buffered (no copy).
    fn append_encoded(&mut self, block: &[u8], nrows: usize, last_depth: usize) -> Result<()> {
        self.encoded_rows(nrows, last_depth);
        if block.len() >= FLUSH_AT {
            self.flush_buf()?;
            self.flushed = true;
            self.w.write_all(block)?;
            return Ok(());
        }
        self.buf.extend_from_slice(block);
        self.maybe_flush()
    }

    /// Bookkeeping for `nrows` encoded rows, the last one at `last_depth`.
    #[inline]
    fn encoded_rows(&mut self, nrows: usize, last_depth: usize) {
        if nrows > 0 {
            self.depth_len = last_depth + 1;
            self.rows += nrows;
        }
    }

    /// Whether a block whose first row is at `first_depth` needs no clamping.
    #[inline]
    fn depth_fits(&self, nrows: usize, first_depth: usize) -> bool {
        nrows == 0 || first_depth <= self.depth_len
    }
}

// ------------------------------------------------------------------------------------------
// quick

struct Quick<'a> {
    b: Base<'a>,
    scratch: Vec<u8>,
    spans: Vec<(usize, usize)>,
}

impl RowSink for Quick<'_> {
    fn begin(&mut self, columns: Vec<Column>) -> Result<()> {
        self.b.set_columns(columns);
        self.b.compute_hidden()?;
        let b = &mut self.b;
        b.buf.push(b'\n');
        let mut first = true;
        for (i, c) in b.columns.iter().enumerate() {
            if b.hidden[i] {
                continue;
            }
            if !first {
                b.buf.push(b'\t');
            }
            first = false;
            b.buf.extend_from_slice(c.name.as_bytes());
        }
        b.buf.push(b'\n');
        Ok(())
    }

    fn row(&mut self, depth: usize, values: Vec<Value>) -> Result<()> {
        self.row_ref(depth, &values)
    }

    fn row_ref(&mut self, depth: usize, values: &[Value]) -> Result<()> {
        check_len(&self.b.columns, values)?;
        let d = self.b.depth(depth);
        if self.b.filter.is_some() {
            render_line(&mut self.scratch, &mut self.spans, &self.b.columns, &self.b.hidden, values, false);
            let line = span_strs(&self.scratch, &self.spans);
            if self.b.filtered(&line)? {
                return Ok(());
            }
            let b = &mut self.b;
            b.buf.push(b'\n');
            push_tree_prefix(&mut b.buf, d);
            for (k, s) in line.iter().enumerate() {
                if k > 0 {
                    b.buf.push(b'\t');
                }
                b.buf.extend_from_slice(s.as_bytes());
            }
        } else {
            let b = &mut self.b;
            b.buf.push(b'\n');
            push_tree_prefix(&mut b.buf, d);
            let mut first = true;
            for (i, v) in values.iter().enumerate() {
                if b.hidden[i] {
                    continue;
                }
                if !first {
                    b.buf.push(b'\t');
                }
                first = false;
                render_cell(&mut b.buf, b.columns[i].ty, v, false);
            }
        }
        self.b.rows += 1;
        self.b.maybe_flush()
    }

    fn encoder(&self) -> Option<RowEncoder> {
        self.b.encoder(EncKind::Quick, Vec::new())
    }

    fn rows_encoded(&mut self, block: &[u8], nrows: usize) -> Result<()> {
        self.b.append_encoded(block, nrows, 0)
    }

    fn rows_encoded_at(&mut self, block: &[u8], nrows: usize, first_depth: usize, last_depth: usize) -> Result<bool> {
        if !self.b.depth_fits(nrows, first_depth) {
            return Ok(false);
        }
        self.b.append_encoded(block, nrows, last_depth)?;
        Ok(true)
    }
}

#[inline]
fn push_tree_prefix(out: &mut Vec<u8>, d: usize) {
    if d > 0 {
        for _ in 0..d {
            out.push(b'*');
        }
        out.push(b' ');
    }
}

impl TextRenderer for Quick<'_> {
    fn finish(&mut self) -> Result<()> {
        if self.b.begun {
            self.b.buf.push(b'\n');
        }
        self.b.flush()
    }
    fn abort(&mut self, unsatisfied: bool) -> Result<()> {
        abort_streaming(&mut self.b, unsatisfied)
    }
    fn failure(&self) -> Option<&RenderFailure> {
        self.b.failure.as_ref()
    }
}

fn abort_streaming(b: &mut Base<'_>, unsatisfied: bool) -> Result<()> {
    if unsatisfied && !b.flushed {
        b.buf.clear();
    }
    b.flush()
}

// ------------------------------------------------------------------------------------------
// csv (csv.DictWriter, excel dialect, lineterminator "\n", escapechar "\\")

struct Csv<'a> {
    b: Base<'a>,
    scratch: Vec<u8>,
    spans: Vec<(usize, usize)>,
}

#[inline]
fn csv_special(c: u8) -> bool {
    matches!(c, b',' | b'"' | b'\n' | b'\r' | b'\\')
}

/// Escape the field that occupies `out[start..]` in place (QUOTE_MINIMAL, doublequote,
/// escapechar '\\'). Nothing to do for the common plain field.
#[inline]
fn csv_fix_field(out: &mut Vec<u8>, start: usize) {
    if !out[start..].iter().any(|&c| csv_special(c)) {
        return;
    }
    let field: Vec<u8> = out.split_off(start);
    push_csv_field(out, &field);
}

/// Append one csv field.
fn push_csv_field(out: &mut Vec<u8>, field: &[u8]) {
    let needs_quote = field.iter().any(|&c| matches!(c, b',' | b'"' | b'\n' | b'\r'));
    if needs_quote {
        out.push(b'"');
    }
    for &c in field {
        match c {
            b'"' => out.extend_from_slice(b"\"\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            c => out.push(c),
        }
    }
    if needs_quote {
        out.push(b'"');
    }
}

impl RowSink for Csv<'_> {
    fn begin(&mut self, columns: Vec<Column>) -> Result<()> {
        self.b.set_columns(columns);
        self.b.compute_hidden()?;
        let b = &mut self.b;
        b.buf.extend_from_slice(b"TreeDepth");
        for (i, c) in b.columns.iter().enumerate() {
            if !b.hidden[i] {
                b.buf.push(b',');
                push_csv_field(&mut b.buf, c.name.as_bytes());
            }
        }
        b.buf.push(b'\n');
        Ok(())
    }

    fn row(&mut self, depth: usize, values: Vec<Value>) -> Result<()> {
        self.row_ref(depth, &values)
    }

    fn row_ref(&mut self, depth: usize, values: &[Value]) -> Result<()> {
        check_len(&self.b.columns, values)?;
        let d = self.b.depth(depth);
        if self.b.filter.is_some() {
            render_line(&mut self.scratch, &mut self.spans, &self.b.columns, &self.b.hidden, values, false);
            let line = span_strs(&self.scratch, &self.spans);
            if self.b.filtered(&line)? {
                return Ok(());
            }
            let b = &mut self.b;
            push_u64(&mut b.buf, d as u64);
            for s in &line {
                b.buf.push(b',');
                push_csv_field(&mut b.buf, s.as_bytes());
            }
        } else {
            let b = &mut self.b;
            push_u64(&mut b.buf, d as u64);
            for (i, v) in values.iter().enumerate() {
                if b.hidden[i] {
                    continue;
                }
                b.buf.push(b',');
                let st = b.buf.len();
                render_cell(&mut b.buf, b.columns[i].ty, v, false);
                if !plain_cell(v) {
                    csv_fix_field(&mut b.buf, st);
                }
            }
        }
        self.b.buf.push(b'\n');
        self.b.rows += 1;
        self.b.maybe_flush()
    }

    fn encoder(&self) -> Option<RowEncoder> {
        self.b.encoder(EncKind::Csv, Vec::new())
    }

    fn rows_encoded(&mut self, block: &[u8], nrows: usize) -> Result<()> {
        self.b.append_encoded(block, nrows, 0)
    }

    fn rows_encoded_at(&mut self, block: &[u8], nrows: usize, first_depth: usize, last_depth: usize) -> Result<bool> {
        if !self.b.depth_fits(nrows, first_depth) {
            return Ok(false);
        }
        self.b.append_encoded(block, nrows, last_depth)?;
        Ok(true)
    }
}

impl TextRenderer for Csv<'_> {
    fn finish(&mut self) -> Result<()> {
        if self.b.begun {
            self.b.buf.push(b'\n');
        }
        self.b.flush()
    }
    fn abort(&mut self, unsatisfied: bool) -> Result<()> {
        abort_streaming(&mut self.b, unsatisfied)
    }
    fn failure(&self) -> Option<&RenderFailure> {
        self.b.failure.as_ref()
    }
}

// ------------------------------------------------------------------------------------------
// pretty

/// Pretty cell width flag: the cell has tabs or newlines (tab expansion / per-line output).
const SLOW: u32 = 1 << 31;

struct Pretty<'a> {
    b: Base<'a>,
    /// max display width per column
    widths: Vec<usize>,
    tree_width: usize,
    /// all rendered visible cells, back to back
    arena: Vec<u8>,
    /// (length in `arena`, display width | SLOW) of every stored visible cell, row after row
    cells: Vec<(u32, u32)>,
    /// path_depth of every stored row
    depths: Vec<u32>,
    scratch: Vec<u8>,
    spans: Vec<(usize, usize)>,
}

/// Display width of a cell: the longest line after `tab_stop` expansion, in characters.
fn cell_width(s: &[u8]) -> usize {
    let (mut w, mut col) = (0usize, 0usize);
    for &c in s {
        match c {
            b'\n' => {
                w = w.max(col);
                col = 0;
            }
            b'\t' => col += 8 - col % 8,
            c if c & 0xc0 == 0x80 => {}
            _ => col += 1,
        }
    }
    w.max(col)
}

/// `cell_width` with the `SLOW` flag for cells holding tabs / newlines.
#[inline]
fn pretty_width(s: &[u8]) -> u32 {
    if s.iter().all(|&c| c < 0x80 && c != b'\t' && c != b'\n') {
        return s.len() as u32;
    }
    let w = cell_width(s) as u32;
    if s.iter().any(|&c| c == b'\t' || c == b'\n') { w | SLOW } else { w }
}

#[inline]
fn push_spaces(out: &mut Vec<u8>, mut n: usize) {
    const SP: [u8; 64] = [b' '; 64];
    while n > 64 {
        out.extend_from_slice(&SP);
        n -= 64;
    }
    out.extend_from_slice(&SP[..n]);
}

/// Write `line` with tabs expanded (`tab_stop`), right-aligned in `width` characters.
fn push_cell_line(out: &mut Vec<u8>, line: &[u8], width: usize) {
    let w = cell_width(line);
    push_spaces(out, width.saturating_sub(w));
    let mut col = 0usize;
    for &c in line {
        if c == b'\t' {
            let pad = 8 - col % 8;
            push_spaces(out, pad);
            col += pad;
        } else {
            out.push(c);
            if c & 0xc0 != 0x80 {
                col += 1;
            }
        }
    }
}

/// The `index`-th '\n'-separated line of `s` (empty past the end).
fn nth_line(s: &[u8], index: usize) -> &[u8] {
    s.split(|&c| c == b'\n').nth(index).unwrap_or(b"")
}

impl Pretty<'_> {
    fn visible(&self) -> Vec<usize> {
        (0..self.b.columns.len()).filter(|&i| !self.b.hidden[i]).collect()
    }
}

impl RowSink for Pretty<'_> {
    fn begin(&mut self, columns: Vec<Column>) -> Result<()> {
        eprintln!("Formatting...");
        self.b.set_columns(columns);
        self.widths = self.b.columns.iter().map(|c| char_len(&c.name)).collect();
        self.b.compute_hidden()?;
        Ok(())
    }

    fn row(&mut self, depth: usize, values: Vec<Value>) -> Result<()> {
        self.row_ref(depth, &values)
    }

    fn row_ref(&mut self, depth: usize, values: &[Value]) -> Result<()> {
        check_len(&self.b.columns, values)?;
        let d = self.b.depth(depth) + 1; // path_depth
        self.tree_width = self.tree_width.max(d);
        if self.b.filter.is_some() {
            // the filter sees every column (hidden ones too)
            render_line(&mut self.scratch, &mut self.spans, &self.b.columns, &self.b.hidden, values, true);
            for (i, &(a, b)) in self.spans.iter().enumerate() {
                self.widths[i] = self.widths[i].max(cell_width(&self.scratch[a..b]));
            }
            let line = span_strs(&self.scratch, &self.spans);
            if self.b.filtered(&line)? {
                return Ok(());
            }
            for (i, &(a, b)) in self.spans.iter().enumerate() {
                if !self.b.hidden[i] {
                    let cell = &self.scratch[a..b];
                    self.arena.extend_from_slice(cell);
                    self.cells.push(((b - a) as u32, pretty_width(cell)));
                }
            }
        } else {
            for (i, v) in values.iter().enumerate() {
                if self.b.hidden[i] {
                    continue; // hidden widths are never used
                }
                let st = self.arena.len();
                render_cell(&mut self.arena, self.b.columns[i].ty, v, false);
                let w = if plain_cell(v) { (self.arena.len() - st) as u32 } else { pretty_width(&self.arena[st..]) };
                self.widths[i] = self.widths[i].max((w & !SLOW) as usize);
                self.cells.push(((self.arena.len() - st) as u32, w));
            }
        }
        self.depths.push(d as u32);
        self.b.rows += 1;
        Ok(())
    }

    fn encoder(&self) -> Option<RowEncoder> {
        self.b.encoder(EncKind::Pretty, Vec::new())
    }

    fn rows_encoded(&mut self, block: &[u8], nrows: usize) -> Result<()> {
        self.rows_encoded_at(block, nrows, 0, 0).map(|_| ())
    }

    fn rows_encoded_at(&mut self, block: &[u8], nrows: usize, first_depth: usize, last_depth: usize) -> Result<bool> {
        if !self.b.depth_fits(nrows, first_depth) {
            return Ok(false);
        }
        let visible = self.visible();
        let mut p = 0usize;
        let u32_at = |p: usize| u32::from_le_bytes(block[p..p + 4].try_into().unwrap());
        for _ in 0..nrows {
            let d = u32_at(p) + 1; // path_depth
            p += 4;
            self.tree_width = self.tree_width.max(d as usize);
            self.depths.push(d);
            for &i in &visible {
                let (len, w) = (u32_at(p), u32_at(p + 4));
                p += 8;
                self.arena.extend_from_slice(&block[p..p + len as usize]);
                p += len as usize;
                self.widths[i] = self.widths[i].max((w & !SLOW) as usize);
                self.cells.push((len, w));
            }
        }
        self.b.encoded_rows(nrows, last_depth);
        Ok(true)
    }
}

impl TextRenderer for Pretty<'_> {
    fn finish(&mut self) -> Result<()> {
        if !self.b.begun {
            return self.b.flush();
        }
        let visible = self.visible();
        let nvis = visible.len();
        // header
        let buf = &mut self.b.buf;
        push_spaces(buf, self.tree_width);
        for &i in &visible {
            buf.extend_from_slice(b" | ");
            let name = self.b.columns[i].name.as_bytes();
            push_cell_line(buf, name, self.widths[i]);
        }
        buf.push(b'\n');
        let widths: Vec<usize> = visible.iter().map(|&i| self.widths[i]).collect();
        let mut pos = 0usize;
        for (r, &depth) in self.depths.iter().enumerate() {
            let cells = &self.cells[r * nvis..(r + 1) * nvis];
            let buf = &mut self.b.buf;
            if cells.iter().all(|c| c.1 & SLOW == 0) {
                // one line, no tabs: pad + copy
                for _ in 0..depth {
                    buf.push(b'*');
                }
                push_spaces(buf, self.tree_width - depth as usize);
                for (k, &(len, w)) in cells.iter().enumerate() {
                    buf.extend_from_slice(b" | ");
                    push_spaces(buf, widths[k].saturating_sub(w as usize));
                    buf.extend_from_slice(&self.arena[pos..pos + len as usize]);
                    pos += len as usize;
                }
                buf.push(b'\n');
            } else {
                let mut spans = Vec::with_capacity(nvis);
                for &(len, _) in cells {
                    spans.push((pos, pos + len as usize));
                    pos += len as usize;
                }
                let lines = spans.iter().map(|&(a, b)| self.arena[a..b].iter().filter(|&&c| c == b'\n').count() + 1).max().unwrap_or(0);
                for index in 0..lines {
                    let mark = if index == 0 { b'*' } else { b' ' };
                    for _ in 0..depth {
                        buf.push(mark);
                    }
                    push_spaces(buf, self.tree_width - depth as usize);
                    for (k, &(a, b)) in spans.iter().enumerate() {
                        buf.extend_from_slice(b" | ");
                        let cell = &self.arena[a..b];
                        let line = if lines == 1 { cell } else { nth_line(cell, index) };
                        push_cell_line(buf, line, widths[k]);
                    }
                    buf.push(b'\n');
                }
            }
            if self.b.buf.len() >= FLUSH_AT {
                self.b.flush_buf()?;
            }
        }
        self.b.flush()
    }
    fn abort(&mut self, _unsatisfied: bool) -> Result<()> {
        self.b.buf.clear();
        self.b.flush()
    }
    fn failure(&self) -> Option<&RenderFailure> {
        self.b.failure.as_ref()
    }
}

// ------------------------------------------------------------------------------------------
// json / jsonl

/// A serialized node: `data[..split]` is everything up to and including `"__children": `,
/// `data[split..]` everything after the children array.
struct JNode {
    data: Vec<u8>,
    split: usize,
    /// indentation level of the node's opening brace (json only)
    level: usize,
    children: Vec<JNode>,
}

struct Slot {
    node: Option<JNode>,
    /// index in `top` when this node is a top-level entry
    top: Option<usize>,
}

struct Json<'a> {
    b: Base<'a>,
    lines: bool,
    /// dict keys in sorted order: (JSON-escaped key, column index or usize::MAX for __children)
    keys: Vec<(Vec<u8>, usize)>,
    /// every column's type
    types: Vec<ColType>,
    stack: Vec<Slot>,
    /// top-level nodes in creation order (`None` while still open)
    top: std::collections::VecDeque<Option<JNode>>,
    top_base: usize,
    scratch: Vec<u8>,
    /// json: the finished top-level nodes in order, each as `,\n  {...}`
    done: Vec<u8>,
    /// node buffers to reuse
    spare: Vec<Vec<u8>>,
    /// the last top-level row, written straight into the output (`b.buf` / `done`) as a leaf:
    /// (start of its bytes, start of the object, position of its `[]`). A child row turns it
    /// back into an open node; anything else leaves it as it is.
    spec: Option<(usize, usize, usize)>,
    /// whether the previous top-level row stayed a leaf (then the next one is written
    /// speculatively; plugins whose rows have children skip the round trip)
    leafy: bool,
}

/// A row's JSON object (`json.dumps(..., sort_keys=True)` layout, `indent=2` unless `lines`)
/// at indentation `level`. The `__children` value is written as `[]` when `leaf`, otherwise
/// left out; returns its position.
#[allow(clippy::too_many_arguments)]
fn push_json_node(
    out: &mut Vec<u8>,
    keys: &[(Vec<u8>, usize)],
    types: &[ColType],
    values: &[Value],
    level: usize,
    lines: bool,
    leaf: bool,
    scratch: &mut Vec<u8>,
    mark: usize,
    span: &mut Option<(usize, usize)>,
) -> usize {
    let mut split = 0;
    out.push(b'{');
    for (k, (key, col)) in keys.iter().enumerate() {
        if k > 0 {
            out.push(b',');
        }
        if lines {
            if k > 0 {
                out.push(b' ');
            }
        } else {
            push_newline_indent(out, level + 1);
        }
        out.extend_from_slice(key);
        out.extend_from_slice(b": ");
        if *col == usize::MAX {
            split = out.len();
            if leaf {
                out.extend_from_slice(b"[]");
            }
        } else {
            let st = out.len();
            write_json_cell(out, types[*col], &values[*col], scratch);
            if *col == mark {
                *span = Some((st, out.len()));
            }
        }
    }
    if !lines {
        push_newline_indent(out, level);
    }
    out.push(b'}');
    split
}

fn write_json_node(out: &mut Vec<u8>, node: &JNode, lines: bool) {
    out.extend_from_slice(&node.data[..node.split]);
    if node.children.is_empty() {
        out.extend_from_slice(b"[]");
    } else {
        out.push(b'[');
        for (k, c) in node.children.iter().enumerate() {
            if k > 0 {
                out.push(b',');
            }
            if lines {
                if k > 0 {
                    out.push(b' ');
                }
            } else {
                push_newline_indent(out, node.level + 2);
            }
            write_json_node(out, c, lines);
        }
        if !lines {
            push_newline_indent(out, node.level + 1);
        }
        out.push(b']');
    }
    out.extend_from_slice(&node.data[node.split..]);
}

impl<'a> Json<'a> {
    fn new(b: Base<'a>, lines: bool) -> Json<'a> {
        Json {
            b,
            lines,
            keys: Vec::new(),
            types: Vec::new(),
            stack: Vec::new(),
            top: Default::default(),
            top_base: 0,
            scratch: Vec::new(),
            done: Vec::new(),
            spare: Vec::new(),
            spec: None,
            leafy: true,
        }
    }

    fn close_to(&mut self, depth: usize) {
        while self.stack.len() > depth {
            let slot = self.stack.pop().unwrap();
            if let Some(node) = slot.node {
                match slot.top {
                    Some(t) => self.top[t - self.top_base] = Some(node),
                    None => {
                        if let Some(parent) = self.stack.last_mut().and_then(|p| p.node.as_mut()) {
                            parent.children.push(node);
                        }
                    }
                }
            }
        }
    }

    /// A top-level row (nothing open, no filter) as a finished leaf, straight into the output.
    fn write_spec(&mut self, values: &[Value]) -> Result<()> {
        if self.lines {
            // flush first: the speculative bytes must stay in the buffer
            self.b.maybe_flush()?;
            let out = &mut self.b.buf;
            let start = out.len();
            let split = push_json_node(out, &self.keys, &self.types, values, 1, true, true, &mut self.scratch, usize::MAX, &mut None);
            out.push(b'\n');
            self.spec = Some((start, start, split));
        } else {
            let out = &mut self.done;
            let start = out.len();
            out.push(b',');
            push_newline_indent(out, 1);
            let node = out.len();
            let split = push_json_node(out, &self.keys, &self.types, values, 1, false, true, &mut self.scratch, usize::MAX, &mut None);
            self.spec = Some((start, node, split));
        }
        self.b.rows += 1;
        Ok(())
    }

    /// The speculative row gets a child: take it back out of the output as an open node.
    fn unspec(&mut self) {
        let Some((start, node, split)) = self.spec.take() else { return };
        let out = if self.lines { &mut self.b.buf } else { &mut self.done };
        // jsonl: without the line's "\n"
        let end = if self.lines { out.len() - 1 } else { out.len() };
        let mut data = self.spare.pop().unwrap_or_default();
        data.clear();
        data.extend_from_slice(&out[node..split]);
        data.extend_from_slice(&out[split + 2..end]);
        out.truncate(start);
        self.top.push_back(None);
        let top = Some(self.top_base + self.top.len() - 1);
        self.stack.push(Slot { node: Some(JNode { data, split: split - node, level: 1, children: Vec::new() }), top });
    }

    fn build_node(&mut self, values: &[Value], level: usize) -> JNode {
        let mut data = self.spare.pop().unwrap_or_else(|| Vec::with_capacity(64 + 24 * self.keys.len()));
        let split = push_json_node(&mut data, &self.keys, &self.types, values, level, self.lines, false, &mut self.scratch, usize::MAX, &mut None);
        JNode { data, split, level, children: Vec::new() }
    }

    /// Serialize every finished top-level node at the front of the queue: jsonl writes it out,
    /// json keeps it (python dumps the whole list at the end).
    fn emit_ready(&mut self) -> Result<()> {
        while let Some(Some(_)) = self.top.front() {
            let node = self.top.pop_front().unwrap().unwrap();
            self.top_base += 1;
            if self.lines {
                write_json_node(&mut self.b.buf, &node, true);
                self.b.buf.push(b'\n');
            } else {
                self.done.push(b',');
                push_newline_indent(&mut self.done, 1);
                write_json_node(&mut self.done, &node, false);
            }
            // reuse the buffer of a finished leaf node (the common case) for the next row
            if node.children.is_empty() && self.spare.len() < 64 {
                let mut d = node.data;
                d.clear();
                self.spare.push(d);
            }
        }
        if self.lines { self.b.maybe_flush() } else { Ok(()) }
    }
}

#[inline]
fn push_newline_indent(out: &mut Vec<u8>, level: usize) {
    const IND: [u8; 65] = {
        let mut a = [b' '; 65];
        a[0] = b'\n';
        a
    };
    if level <= 32 {
        out.extend_from_slice(&IND[..1 + 2 * level]);
        return;
    }
    out.push(b'\n');
    for _ in 0..level {
        out.extend_from_slice(b"  ");
    }
}

impl RowSink for Json<'_> {
    fn begin(&mut self, columns: Vec<Column>) -> Result<()> {
        self.b.buf.push(b'\n');
        self.b.set_columns(columns);
        self.b.compute_hidden()?;
        let mut keys: Vec<(String, usize)> = vec![("__children".to_string(), usize::MAX)];
        for (i, c) in self.b.columns.iter().enumerate() {
            if !self.b.hidden[i] {
                keys.push((c.name.clone(), i));
            }
        }
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        self.keys = keys
            .into_iter()
            .map(|(k, i)| {
                let mut e = Vec::new();
                push_json_str(&mut e, &k);
                (e, i)
            })
            .collect();
        self.types = self.b.columns.iter().map(|c| c.ty).collect();
        Ok(())
    }

    fn row(&mut self, depth: usize, values: Vec<Value>) -> Result<()> {
        self.row_ref(depth, &values)
    }

    fn row_ref(&mut self, depth: usize, values: &[Value]) -> Result<()> {
        check_len(&self.b.columns, values)?;
        let d = self.b.depth(depth);
        if d == 0 && self.b.filter.is_none() {
            // the previous top-level row is complete
            if self.spec.take().is_some() {
                self.leafy = true;
            } else if let Some(n) = self.stack.first().and_then(|s| s.node.as_ref()) {
                self.leafy = n.children.is_empty() && self.stack.len() == 1;
            }
            self.close_to(0);
            self.emit_ready()?;
            if self.leafy && self.top.is_empty() {
                return self.write_spec(values);
            }
        } else {
            self.unspec();
        }
        self.close_to(d);
        let keep = if self.b.filter.is_some() {
            let line: Vec<String> = (0..values.len())
                .filter(|&i| !self.b.hidden[i])
                .map(|i| json_py_str(self.b.columns[i].ty, &values[i]))
                .collect();
            !self.b.filtered(&line)?
        } else {
            true
        };
        let slot = if keep {
            let parent = if d > 0 { self.stack.get(d - 1).and_then(|p| p.node.as_ref()) } else { None };
            let (top, level) = match parent {
                Some(p) => (None, p.level + 2),
                None => {
                    self.top.push_back(None);
                    (Some(self.top_base + self.top.len() - 1), 1)
                }
            };
            let node = self.build_node(values, level);
            self.b.rows += 1;
            Slot { node: Some(node), top }
        } else {
            Slot { node: None, top: None }
        };
        self.stack.push(slot);
        self.emit_ready()
    }

    fn encoder(&self) -> Option<RowEncoder> {
        self.b.encoder(if self.lines { EncKind::Jsonl } else { EncKind::Json }, self.keys.clone())
    }

    fn rows_encoded(&mut self, block: &[u8], nrows: usize) -> Result<()> {
        // everything emitted so far comes first
        self.spec = None;
        self.close_to(0);
        self.emit_ready()?;
        if self.lines {
            return self.b.append_encoded(block, nrows, 0);
        }
        self.done.extend_from_slice(block);
        self.b.encoded_rows(nrows, 0);
        Ok(())
    }

    // rows_encoded_at: json nests child rows in their parents, which a block can't (its rows
    // would be closed before the next row arrives): the default (not taken) applies
}

impl TextRenderer for Json<'_> {
    fn finish(&mut self) -> Result<()> {
        if !self.b.begun {
            return self.b.flush();
        }
        self.spec = None;
        self.close_to(0);
        self.emit_ready()?;
        if !self.lines {
            if self.done.is_empty() {
                self.b.buf.extend_from_slice(b"[]\n");
            } else {
                // `done` holds ",\n  {...}" per node: drop the first comma
                self.b.buf.push(b'[');
                self.b.flush_buf()?;
                self.b.w.write_all(&self.done[1..])?;
                self.b.flushed = true;
                self.done = Vec::new();
                self.b.buf.extend_from_slice(b"\n]\n");
            }
        }
        self.b.flush()
    }
    fn abort(&mut self, unsatisfied: bool) -> Result<()> {
        // python writes "\n" when rendering starts and the rest at the end
        if unsatisfied && !self.b.flushed {
            self.b.buf.clear();
        } else if !self.b.flushed {
            let keep = if self.b.begun { 1 } else { 0 };
            self.b.buf.truncate(keep.min(self.b.buf.len()));
        } else {
            self.b.buf.clear();
        }
        self.b.flush()
    }
    fn failure(&self) -> Option<&RenderFailure> {
        self.b.failure.as_ref()
    }
}

// ------------------------------------------------------------------------------------------
// none

struct NoneRenderer<'a> {
    b: Base<'a>,
}

impl RowSink for NoneRenderer<'_> {
    fn begin(&mut self, columns: Vec<Column>) -> Result<()> {
        self.b.columns = columns;
        self.b.begun = true;
        Ok(())
    }
    fn row(&mut self, _depth: usize, values: Vec<Value>) -> Result<()> {
        check_len(&self.b.columns, &values)
    }
    fn row_ref(&mut self, _depth: usize, values: &[Value]) -> Result<()> {
        check_len(&self.b.columns, values)
    }
    fn encoder(&self) -> Option<RowEncoder> {
        self.b.begun.then(|| RowEncoder::new(EncKind::Null, &self.b.columns, &vec![false; self.b.columns.len()], Vec::new()))
    }
    fn rows_encoded(&mut self, _block: &[u8], _nrows: usize) -> Result<()> {
        Ok(())
    }
    fn rows_encoded_at(&mut self, _block: &[u8], _nrows: usize, _first_depth: usize, _last_depth: usize) -> Result<bool> {
        Ok(true)
    }
}

impl TextRenderer for NoneRenderer<'_> {
    fn finish(&mut self) -> Result<()> {
        self.b.flush()
    }
    fn abort(&mut self, _unsatisfied: bool) -> Result<()> {
        self.b.flush()
    }
    fn failure(&self) -> Option<&RenderFailure> {
        None
    }
}

// ------------------------------------------------------------------------------------------
// mermaid

struct Mermaid<'a> {
    b: Base<'a>,
    rows: Vec<(usize, Vec<u8>)>,
}

impl RowSink for Mermaid<'_> {
    fn begin(&mut self, columns: Vec<Column>) -> Result<()> {
        eprintln!("Formatting...");
        self.b.columns = columns;
        self.b.begun = true;
        Ok(())
    }
    fn row(&mut self, depth: usize, values: Vec<Value>) -> Result<()> {
        self.row_ref(depth, &values)
    }
    fn row_ref(&mut self, depth: usize, values: &[Value]) -> Result<()> {
        check_len(&self.b.columns, values)?;
        let d = self.b.depth(depth) + 1;
        let mut label = Vec::new();
        let mut cell = Vec::new();
        for (i, v) in values.iter().enumerate() {
            if i > 0 {
                label.extend_from_slice(b"<br>");
            }
            label.extend_from_slice(self.b.columns[i].name.as_bytes());
            label.push(b':');
            cell.clear();
            render_cell(&mut cell, self.b.columns[i].ty, v, true);
            for &c in &cell {
                match c {
                    b'"' => label.extend_from_slice(b"&quot;"),
                    b'\n' => label.extend_from_slice(b"<br>"),
                    _ => label.push(c),
                }
            }
        }
        self.rows.push((d, label));
        Ok(())
    }
}

impl TextRenderer for Mermaid<'_> {
    fn finish(&mut self) -> Result<()> {
        if !self.b.begun {
            return self.b.flush();
        }
        let rows = std::mem::take(&mut self.rows);
        let out = &mut self.b.buf;
        out.extend_from_slice(b"graph TD");
        let mut parents: Vec<usize> = Vec::new();
        let mut prev_depth = 0usize;
        for (k, (depth, label)) in rows.iter().enumerate() {
            let id = k + 1;
            if k > 0 {
                if *depth > prev_depth {
                    for _ in 0..(depth - prev_depth) {
                        parents.push(id - 1);
                    }
                } else if *depth < prev_depth {
                    for _ in 0..(prev_depth - depth) {
                        parents.pop();
                    }
                }
            }
            out.extend_from_slice(b"\n\t");
            if let Some(&p) = parents.last() {
                out.push(b'n');
                push_u64(out, p as u64);
                out.extend_from_slice(b" --> ");
            }
            out.push(b'n');
            push_u64(out, id as u64);
            out.extend_from_slice(b"[\"");
            out.extend_from_slice(label);
            out.extend_from_slice(b"\"]");
            prev_depth = *depth;
        }
        out.push(b'\n');
        self.b.flush()
    }
    fn abort(&mut self, _unsatisfied: bool) -> Result<()> {
        self.b.buf.clear();
        self.b.flush()
    }
    fn failure(&self) -> Option<&RenderFailure> {
        None
    }
}

#[cfg(test)]
#[path = "text_tests.rs"]
pub(crate) mod tests_support;
