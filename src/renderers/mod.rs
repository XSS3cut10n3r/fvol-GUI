//! Tree-grid output model shared by every plugin, plus the text renderers
//! (quick / pretty / csv / json / jsonl / none) that must reproduce volatility3's
//! `cli/text_renderer.py` output byte for byte.
//!
//! CONTRACT (stable, used by all plugins):
//!   * A plugin first calls `sink.begin(columns)` exactly once, then `sink.row(depth, values)`
//!     for every row in output order. `depth` is 0 for top-level rows, 1 for children, ...
//!     (volatility3's TreeGrid `path_depth - 1`).
//!   * `values.len() == columns.len()`.
//!   * Formatting is chosen by the COLUMN type (exactly like volatility3, which looks up the
//!     renderer by `column.type`), with the Value providing the data. E.g. a `ColType::Hex`
//!     column renders `Value::Int(16)` as `0x10`, a `ColType::Int` column renders it as `16`.
//!   * Absent values render as "-" (`Unreadable`, `Unparsable`, `NotAvailable`) or "N/A"
//!     (`NotApplicable` only -- volatility3's `optional()` wrapper) in the quick / pretty / csv
//!     renderers regardless of column type, and as `null` in json/jsonl for most column types.
//!   * Depth jumps are clamped like volatility3's TreeGrid does (a row can be at most one level
//!     deeper than the previous row).

pub mod pyfmt; // python-compatible number / string / datetime formatting helpers
pub mod text; // quick / pretty / csv / json / jsonl / none / mermaid renderers (CLI agent)

use crate::error::Result;

/// Column type, mirroring the python type given in the TreeGrid column definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColType {
    /// python `int`
    Int,
    /// python `str`
    Str,
    /// python `bytes`  (rendered "de ad be ef")
    Bytes,
    /// python `float`
    Float,
    /// python `bool`  (rendered "True"/"False")
    Bool,
    /// python `datetime.datetime`
    DateTime,
    /// `format_hints.Hex`
    Hex,
    /// `format_hints.Bin`
    Bin,
    /// `format_hints.HexBytes`
    HexBytes,
    /// `format_hints.MultiTypeData`
    MultiTypeData,
    /// `renderers.Disassembly`
    Disassembly,
    /// `renderers.LayerData` (rare; hexdump of layer memory)
    LayerData,
}

/// A column declaration.
#[derive(Clone, Debug)]
pub struct Column {
    pub name: String,
    pub ty: ColType,
}

impl Column {
    pub fn new(name: impl Into<String>, ty: ColType) -> Column {
        Column { name: name.into(), ty }
    }
}

/// Shorthand: `cols![("PID", Int), ("ImageFileName", Str)]`
#[macro_export]
macro_rules! cols {
    ($(($name:expr, $ty:ident)),* $(,)?) => {
        vec![$($crate::renderers::Column::new($name, $crate::renderers::ColType::$ty)),*]
    };
}

/// A UTC timestamp with microsecond precision (python `datetime.datetime` with tz=UTC).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DateTime {
    /// Seconds since 1970-01-01T00:00:00Z (may be negative).
    pub secs: i64,
    /// 0..1_000_000
    pub micros: u32,
    /// false for a naive datetime (python renders `%Z` as empty string then).
    pub utc: bool,
}

/// A single cell value.
#[derive(Clone, Debug)]
pub enum Value {
    /// Any integer (python ints are unbounded; i128 covers every u64 and i64).
    Int(i128),
    Str(String),
    /// Static string, avoids an allocation for constants like "Disabled".
    SStr(&'static str),
    Bytes(Vec<u8>),
    Float(f64),
    Bool(bool),
    DateTime(DateTime),
    /// `format_hints.MultiTypeData(data, encoding, split_nulls, show_hex)`; `converted_int` as in python.
    MultiTypeData { data: Vec<u8>, encoding: Encoding, split_nulls: bool, show_hex: bool, converted_int: bool },
    /// `renderers.Disassembly(data, offset, architecture)`; arch is one of intel/intel64/arm/arm64 or None.
    Disassembly { data: Vec<u8>, offset: u64, arch: Option<&'static str> },
    /// Pre-rendered `renderers.LayerData` hexdump text (plugins resolve the memory themselves).
    /// Prefer [`Value::LayerBytes`], which also renders correctly in json/jsonl/mermaid.
    LayerData(String),
    /// `renderers.LayerData` resolved by the plugin: `data` is what python's
    /// `LayerDataRenderer.render_bytes` returns (the padded read), `errors` the indices into
    /// `data` it reports as unreadable (rendered `__` by the text renderers; usually empty).
    LayerBytes { data: Vec<u8>, errors: Vec<u32> },
    Unreadable,
    Unparsable,
    NotApplicable,
    NotAvailable,
    /// python `None` where a plugin hands one over as data (e.g. a `generate_timeline`
    /// timestamp). python's TreeGrid rejects it in every column (`TypeError: Values item with
    /// index .. is the wrong type ..`), so it never reaches a renderer; renderers print it like
    /// python's default `f"{x}"`.
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    Utf16Le,
    Latin1,
}

impl Value {
    #[inline]
    pub fn int<T: Into<i128>>(v: T) -> Value {
        Value::Int(v.into())
    }
    #[inline]
    pub fn str<S: Into<String>>(s: S) -> Value {
        Value::Str(s.into())
    }
    #[inline]
    pub fn is_absent(&self) -> bool {
        matches!(self, Value::Unreadable | Value::Unparsable | Value::NotApplicable | Value::NotAvailable)
    }
}

/// Receives the output of a plugin. Implemented by the renderers (and by in-memory
/// collectors used when one plugin consumes another's output, e.g. timeliner).
pub trait RowSink {
    /// Declare the columns. Called exactly once, before any row.
    fn begin(&mut self, columns: Vec<Column>) -> Result<()>;
    /// Emit one row at tree depth `depth` (0 = top level).
    fn row(&mut self, depth: usize, values: Vec<Value>) -> Result<()>;

    /// [`RowSink::row`] from borrowed values (e.g. a stack array): no per-row `Vec` for hot
    /// plugins. The text renderers format straight from the slice; the default copies.
    fn row_ref(&mut self, depth: usize, values: &[Value]) -> Result<()> {
        self.row(depth, values.to_vec())
    }

    /// A formatter producing exactly this sink's output for depth-0 rows that can run on other
    /// threads (the text renderers without `--filters`). Plugins with huge outputs format rows
    /// in parallel with it and hand the bytes to [`RowSink::rows_encoded`]. Only for plugins
    /// whose rows are ALL at depth 0.
    fn encoder(&self) -> Option<text::RowEncoder> {
        None
    }

    /// Append `nrows` depth-0 rows formatted by this sink's [`RowSink::encoder`] (in order,
    /// after every row emitted so far). Only valid when `encoder()` returned `Some`.
    fn rows_encoded(&mut self, _block: &[u8], _nrows: usize) -> Result<()> {
        Err(crate::error::Error::msg("rows_encoded: this sink has no row encoder"))
    }

    /// [`RowSink::rows_encoded`] handing over the buffer: a renderer that keeps blocks until
    /// the end (pretty) stores it without a copy. Returns the buffer when it was not kept.
    fn rows_encoded_owned(&mut self, block: Vec<u8>, nrows: usize) -> Result<Option<Vec<u8>>> {
        self.rows_encoded(&block, nrows)?;
        Ok(Some(block))
    }

    /// [`RowSink::rows_encoded`] for rows encoded with `RowEncoder::row_at` (tree depths, the
    /// first row at `first_depth`, the last at `last_depth`; within the block each row at most
    /// one level below the previous one). Returns `false` and appends nothing when the block
    /// can't be taken as is (its first row would be clamped to a shallower depth, or json
    /// nesting): the caller then emits those rows one by one.
    fn rows_encoded_at(&mut self, _block: &[u8], _nrows: usize, _first_depth: usize, _last_depth: usize) -> Result<bool> {
        Ok(false)
    }

    /// Append a block of complete trees encoded with `RowEncoder::tree_row` /
    /// `RowEncoder::trees_end` (json / jsonl: [`text::JsonTrees`] gives `nrows` and
    /// `last_depth`), after every row emitted so far. The caller guarantees that the next row
    /// (if any) is at depth 0, i.e. that no later row belongs to the block's trees. The sink may
    /// take the buffer (leaving it empty) or copy it. `false` = not taken, nothing appended:
    /// emit the rows one by one.
    fn rows_encoded_trees(&mut self, _block: &mut Vec<u8>, _nrows: usize, _last_depth: usize) -> Result<bool> {
        Ok(false)
    }
}

/// In-memory sink, handy for tests and for plugins that post-process another plugin's rows.
#[derive(Default)]
pub struct CollectSink {
    pub columns: Vec<Column>,
    pub rows: Vec<(usize, Vec<Value>)>,
}

impl RowSink for CollectSink {
    fn begin(&mut self, columns: Vec<Column>) -> Result<()> {
        self.columns = columns;
        Ok(())
    }
    fn row(&mut self, depth: usize, values: Vec<Value>) -> Result<()> {
        self.rows.push((depth, values));
        Ok(())
    }
}
