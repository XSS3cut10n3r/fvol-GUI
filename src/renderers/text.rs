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
        "quick" => Box::new(Quick { b: base }),
        "csv" => Box::new(Csv { b: base, scratch: Vec::new() }),
        "pretty" => Box::new(Pretty { b: base, widths: Vec::new(), tree_width: 0, rows: Vec::new() }),
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
        if self.buf.len() >= FLUSH_AT {
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

/// A JSON-level value (what python's JsonRenderer puts into the node dict).
enum JVal {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(Vec<u8>),
}

fn json_value(ty: ColType, v: &Value) -> JVal {
    let absent = v.is_absent();
    let mut s = Vec::new();
    match ty {
        ColType::HexBytes => {
            if absent {
                return JVal::Str(b"N/A".to_vec());
            }
            if let Some(b) = value_bytes(v) {
                push_hex_joined(&mut s, b);
                return JVal::Str(s);
            }
        }
        ColType::LayerData => {
            if absent {
                return JVal::Str(b"N/A".to_vec());
            }
            if let Value::LayerBytes { data, .. } = v {
                push_hex_joined(&mut s, data);
                return JVal::Str(s);
            }
        }
        ColType::Disassembly | ColType::MultiTypeData => {
            // quoted_optional(...)
            if absent {
                return JVal::Str(Vec::new());
            }
            let mut r = Vec::new();
            let converted_int = match v {
                Value::MultiTypeData { converted_int, .. } => *converted_int,
                _ => false,
            };
            render_cell(&mut r, ty, v, false);
            if r == b"-" || r == b"N/A" {
                return JVal::Str(Vec::new());
            }
            if converted_int || matches!(v, Value::Int(_) | Value::Bool(_)) {
                return JVal::Str(r);
            }
            s.push(b'"');
            s.extend_from_slice(&r);
            s.push(b'"');
            return JVal::Str(s);
        }
        ColType::Bytes => {
            if let Some(t) = absent_text(v) {
                return JVal::Str(t.to_vec());
            }
            if let Some(b) = value_bytes(v) {
                push_hex_joined(&mut s, b);
                return JVal::Str(s);
            }
        }
        ColType::DateTime => {
            if absent {
                return JVal::Null;
            }
            if let Value::DateTime(dt) = v {
                push_datetime_iso(&mut s, dt, b'T');
                return JVal::Str(s);
            }
        }
        _ => {}
    }
    match v {
        Value::Int(i) => JVal::Int(*i),
        Value::Bool(b) => JVal::Bool(*b),
        Value::Float(f) => JVal::Float(*f),
        Value::Str(x) => JVal::Str(x.as_bytes().to_vec()),
        Value::SStr(x) => JVal::Str(x.as_bytes().to_vec()),
        _ if absent => JVal::Null,
        _ => {
            push_default(&mut s, v);
            JVal::Str(s)
        }
    }
}

impl JVal {
    fn write_json(&self, out: &mut Vec<u8>) {
        match self {
            JVal::Null => out.extend_from_slice(b"null"),
            JVal::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
            JVal::Int(i) => push_i128(out, *i),
            JVal::Float(f) => {
                if f.is_nan() {
                    out.extend_from_slice(b"NaN")
                } else if f.is_infinite() {
                    out.extend_from_slice(if *f > 0.0 { b"Infinity" } else { b"-Infinity" })
                } else {
                    push_float(out, *f)
                }
            }
            JVal::Str(s) => push_json_str(out, &String::from_utf8_lossy(s)),
        }
    }
    /// python `f"{data}"` (for the filter)
    fn py_str(&self) -> String {
        match self {
            JVal::Null => "None".into(),
            JVal::Bool(b) => (if *b { "True" } else { "False" }).into(),
            JVal::Int(i) => i.to_string(),
            JVal::Float(f) => {
                let mut v = Vec::new();
                push_float(&mut v, *f);
                String::from_utf8_lossy(&v).into_owned()
            }
            JVal::Str(s) => String::from_utf8_lossy(s).into_owned(),
        }
    }
}

// ------------------------------------------------------------------------------------------
// quick

struct Quick<'a> {
    b: Base<'a>,
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
        check_len(&self.b.columns, &values)?;
        let d = self.b.depth(depth);
        if self.b.filter.is_some() {
            let mut line: Vec<String> = Vec::with_capacity(values.len());
            for (i, v) in values.iter().enumerate() {
                if !self.b.hidden[i] {
                    let mut s = Vec::new();
                    render_cell(&mut s, self.b.columns[i].ty, v, false);
                    line.push(String::from_utf8_lossy(&s).into_owned());
                }
            }
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
}

/// Append one csv field with QUOTE_MINIMAL / doublequote / escapechar '\\' semantics.
fn push_csv_field(out: &mut Vec<u8>, field: &[u8]) {
    let needs_quote = field.iter().any(|&c| matches!(c, b',' | b'"' | b'\n' | b'\r'));
    if needs_quote {
        out.push(b'"');
    }
    let mut start = 0;
    for (i, &c) in field.iter().enumerate() {
        match c {
            b'"' => {
                out.extend_from_slice(&field[start..i]);
                out.extend_from_slice(b"\"\"");
                start = i + 1;
            }
            b'\\' => {
                out.extend_from_slice(&field[start..i]);
                out.extend_from_slice(b"\\\\");
                start = i + 1;
            }
            _ => {}
        }
    }
    out.extend_from_slice(&field[start..]);
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
        check_len(&self.b.columns, &values)?;
        let d = self.b.depth(depth);
        if self.b.filter.is_some() {
            let mut line: Vec<String> = Vec::with_capacity(values.len());
            for (i, v) in values.iter().enumerate() {
                if !self.b.hidden[i] {
                    let mut s = Vec::new();
                    render_cell(&mut s, self.b.columns[i].ty, v, false);
                    line.push(String::from_utf8_lossy(&s).into_owned());
                }
            }
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
                self.scratch.clear();
                render_cell(&mut self.scratch, b.columns[i].ty, v, false);
                push_csv_field(&mut b.buf, &self.scratch);
            }
        }
        self.b.buf.push(b'\n');
        self.b.rows += 1;
        self.b.maybe_flush()
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

struct Pretty<'a> {
    b: Base<'a>,
    /// max width per column (python keys this by column NAME)
    widths: Vec<usize>,
    tree_width: usize,
    /// (path_depth, visible cells split into lines)
    rows: Vec<(usize, Vec<Vec<String>>)>,
}

/// `PrettyTextRenderer.tab_stop`
fn tab_stop(line: &str) -> std::borrow::Cow<'_, str> {
    if !line.contains('\t') {
        return std::borrow::Cow::Borrowed(line);
    }
    let mut out = String::with_capacity(line.len() + 8);
    let mut n = 0usize; // chars written
    for c in line.chars() {
        if c == '\t' {
            let pad = 8 - (n % 8);
            for _ in 0..pad {
                out.push(' ');
            }
            n += pad;
        } else {
            out.push(c);
            n += 1;
        }
    }
    std::borrow::Cow::Owned(out)
}

/// python `format(s, "<N")` / `format(s, ">N")`
fn push_padded(out: &mut Vec<u8>, s: &str, width: usize, right: bool) {
    let len = char_len(s);
    let pad = width.saturating_sub(len);
    if right {
        for _ in 0..pad {
            out.push(b' ');
        }
        out.extend_from_slice(s.as_bytes());
    } else {
        out.extend_from_slice(s.as_bytes());
        for _ in 0..pad {
            out.push(b' ');
        }
    }
}

impl Pretty<'_> {
    /// index of the first column with the same name (python keys widths by name)
    fn width_slot(&self, i: usize) -> usize {
        let name = &self.b.columns[i].name;
        self.b.columns.iter().position(|c| c.name == *name).unwrap_or(i)
    }

    fn write_line<S: AsRef<str>>(&mut self, tree: &str, cells: &[S]) {
        let buf = &mut self.b.buf;
        push_padded(buf, tree, self.tree_width, false);
        let mut k = 0;
        for i in 0..self.b.columns.len() {
            if self.b.hidden[i] {
                continue;
            }
            let slot = self.b.columns.iter().position(|c| c.name == self.b.columns[i].name).unwrap_or(i);
            buf.extend_from_slice(b" | ");
            push_padded(buf, cells[k].as_ref(), self.widths[slot], true);
            k += 1;
        }
        buf.push(b'\n');
    }
}

impl RowSink for Pretty<'_> {
    fn begin(&mut self, columns: Vec<Column>) -> Result<()> {
        eprint!("Formatting...\n");
        self.b.set_columns(columns);
        self.widths = self.b.columns.iter().map(|c| char_len(&c.name)).collect();
        self.b.compute_hidden()?;
        Ok(())
    }

    fn row(&mut self, depth: usize, values: Vec<Value>) -> Result<()> {
        check_len(&self.b.columns, &values)?;
        let d = self.b.depth(depth) + 1; // path_depth
        self.tree_width = self.tree_width.max(d);
        let mut rendered: Vec<String> = Vec::with_capacity(values.len());
        let mut s = Vec::new();
        for (i, v) in values.iter().enumerate() {
            s.clear();
            render_cell(&mut s, self.b.columns[i].ty, v, false);
            let text = String::from_utf8_lossy(&s).into_owned();
            let w = text.split('\n').map(|l| char_len(&tab_stop(l))).max().unwrap_or(0);
            let slot = self.width_slot(i);
            if w > self.widths[slot] {
                self.widths[slot] = w;
            }
            rendered.push(text);
        }
        if self.b.filtered(&rendered)? {
            return Ok(());
        }
        let mut line = Vec::with_capacity(rendered.len());
        for (i, text) in rendered.into_iter().enumerate() {
            if !self.b.hidden[i] {
                line.push(text.split('\n').map(|x| x.to_string()).collect::<Vec<String>>());
            }
        }
        self.rows.push((d, line));
        self.b.rows += 1;
        Ok(())
    }
}

impl TextRenderer for Pretty<'_> {
    fn finish(&mut self) -> Result<()> {
        if !self.b.begun {
            return self.b.flush();
        }
        let titles: Vec<String> =
            (0..self.b.columns.len()).filter(|&i| !self.b.hidden[i]).map(|i| self.b.columns[i].name.clone()).collect();
        self.write_line("", &titles);
        let rows = std::mem::take(&mut self.rows);
        let mut cells: Vec<String> = Vec::new();
        for (depth, line) in rows {
            let nums_line = line.iter().map(|c| c.len()).max().unwrap_or(0);
            for index in 0..nums_line {
                cells.clear();
                for col in &line {
                    cells.push(col.get(index).map(|s| tab_stop(s).into_owned()).unwrap_or_default());
                }
                let tree: String = std::iter::repeat_n(if index == 0 { '*' } else { ' ' }, depth).collect();
                self.write_line(&tree, &cells);
                if self.b.buf.len() >= FLUSH_AT {
                    self.b.flush_buf()?;
                }
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

struct JNode {
    /// serialized JSON scalars, one per visible (deduplicated, key-sorted) column
    values: Vec<Vec<u8>>,
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
    /// sorted (key, column index) pairs; `usize::MAX` marks "__children"
    keys: Vec<(String, usize)>,
    stack: Vec<Slot>,
    /// top-level nodes in creation order (`None` while still open)
    top: std::collections::VecDeque<Option<JNode>>,
    top_base: usize,
    /// visible column indices that end up in the dict (last one wins for duplicate names)
    visible: Vec<usize>,
}

impl<'a> Json<'a> {
    fn new(b: Base<'a>, lines: bool) -> Json<'a> {
        Json { b, lines, keys: Vec::new(), stack: Vec::new(), top: Default::default(), top_base: 0, visible: Vec::new() }
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

    fn write_node(&self, out: &mut Vec<u8>, node: &JNode, indent: Option<usize>) {
        match indent {
            None => {
                out.push(b'{');
                for (k, (key, col)) in self.keys.iter().enumerate() {
                    if k > 0 {
                        out.extend_from_slice(b", ");
                    }
                    push_json_str(out, key);
                    out.extend_from_slice(b": ");
                    self.write_value(out, node, *col, None);
                }
                out.push(b'}');
            }
            Some(level) => {
                out.push(b'{');
                for (k, (key, col)) in self.keys.iter().enumerate() {
                    if k > 0 {
                        out.push(b',');
                    }
                    push_newline_indent(out, level + 1);
                    push_json_str(out, key);
                    out.extend_from_slice(b": ");
                    self.write_value(out, node, *col, Some(level + 1));
                }
                push_newline_indent(out, level);
                out.push(b'}');
            }
        }
    }

    fn write_value(&self, out: &mut Vec<u8>, node: &JNode, col: usize, indent: Option<usize>) {
        if col == usize::MAX {
            if node.children.is_empty() {
                out.extend_from_slice(b"[]");
                return;
            }
            out.push(b'[');
            for (k, c) in node.children.iter().enumerate() {
                match indent {
                    None => {
                        if k > 0 {
                            out.extend_from_slice(b", ");
                        }
                        self.write_node(out, c, None);
                    }
                    Some(level) => {
                        if k > 0 {
                            out.push(b',');
                        }
                        push_newline_indent(out, level + 1);
                        self.write_node(out, c, Some(level + 1));
                    }
                }
            }
            if let Some(level) = indent {
                push_newline_indent(out, level);
            }
            out.push(b']');
        } else {
            out.extend_from_slice(&node.values[col]);
        }
    }

    /// jsonl: write every finished top-level node at the front of the queue
    fn emit_ready(&mut self) -> Result<()> {
        while let Some(Some(_)) = self.top.front() {
            let node = self.top.pop_front().unwrap().unwrap();
            self.top_base += 1;
            let mut out = std::mem::take(&mut self.b.buf);
            self.write_node(&mut out, &node, None);
            out.push(b'\n');
            self.b.buf = out;
        }
        self.b.maybe_flush()
    }
}

#[inline]
fn push_newline_indent(out: &mut Vec<u8>, level: usize) {
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
        // dict keys: "__children" plus each visible column name (later duplicates win)
        let mut keys: Vec<(String, usize)> = vec![("__children".to_string(), usize::MAX)];
        for (i, c) in self.b.columns.iter().enumerate() {
            if self.b.hidden[i] {
                continue;
            }
            match keys.iter_mut().find(|(k, _)| *k == c.name) {
                Some(slot) => slot.1 = i,
                None => keys.push((c.name.clone(), i)),
            }
        }
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        // node.values holds only the columns referenced by the keys, in key order
        self.visible = keys.iter().filter(|(_, c)| *c != usize::MAX).map(|(_, c)| *c).collect();
        let mut n = 0;
        for k in keys.iter_mut() {
            if k.1 != usize::MAX {
                k.1 = n;
                n += 1;
            }
        }
        self.keys = keys;
        Ok(())
    }

    fn row(&mut self, depth: usize, values: Vec<Value>) -> Result<()> {
        check_len(&self.b.columns, &values)?;
        let d = self.b.depth(depth);
        self.close_to(d);
        let keep = if self.b.filter.is_some() {
            let line: Vec<String> = (0..values.len())
                .filter(|&i| !self.b.hidden[i])
                .map(|i| json_value(self.b.columns[i].ty, &values[i]).py_str())
                .collect();
            !self.b.filtered(&line)?
        } else {
            true
        };
        let slot = if keep {
            let mut vals = Vec::with_capacity(self.visible.len());
            for &i in &self.visible {
                let mut s = Vec::new();
                json_value(self.b.columns[i].ty, &values[i]).write_json(&mut s);
                vals.push(s);
            }
            let node = JNode { values: vals, children: Vec::new() };
            let parent_kept = d > 0 && self.stack.get(d - 1).is_some_and(|p| p.node.is_some());
            let top = if parent_kept {
                None
            } else {
                self.top.push_back(None);
                Some(self.top_base + self.top.len() - 1)
            };
            self.b.rows += 1;
            Slot { node: Some(node), top }
        } else {
            Slot { node: None, top: None }
        };
        self.stack.push(slot);
        if self.lines { self.emit_ready() } else { Ok(()) }
    }
}

impl TextRenderer for Json<'_> {
    fn finish(&mut self) -> Result<()> {
        if !self.b.begun {
            return self.b.flush();
        }
        self.close_to(0);
        if self.lines {
            self.emit_ready()?;
        } else {
            let top: Vec<JNode> = std::mem::take(&mut self.top).into_iter().flatten().collect();
            let mut out = std::mem::take(&mut self.b.buf);
            if top.is_empty() {
                out.extend_from_slice(b"[]");
            } else {
                out.push(b'[');
                for (k, n) in top.iter().enumerate() {
                    if k > 0 {
                        out.push(b',');
                    }
                    push_newline_indent(&mut out, 1);
                    self.write_node(&mut out, n, Some(1));
                    if out.len() >= FLUSH_AT {
                        self.b.w.write_all(&out)?;
                        self.b.flushed = true;
                        out.clear();
                    }
                }
                out.extend_from_slice(b"\n]");
            }
            out.push(b'\n');
            self.b.buf = out;
        }
        self.b.flush()
    }
    fn abort(&mut self, unsatisfied: bool) -> Result<()> {
        // python writes "\n" when rendering starts and the rest at the end
        if unsatisfied && !self.b.flushed {
            self.b.buf.clear();
        } else if !self.lines || !self.b.flushed {
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
        eprint!("Formatting...\n");
        self.b.columns = columns;
        self.b.begun = true;
        Ok(())
    }
    fn row(&mut self, depth: usize, values: Vec<Value>) -> Result<()> {
        check_len(&self.b.columns, &values)?;
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
