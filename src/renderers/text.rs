//! quick / pretty / csv / json / jsonl / none renderers (volatility3 cli/text_renderer.py). CLI agent.
// TEMPORARY - replaced by CLI agent (minimal python-compatible quick renderer for testing)

use super::{ColType, Column, RowSink, Value};
use crate::error::Result;
use std::io::Write;

/// python `QuickTextRenderer`: tab separated, rows written immediately.
pub struct QuickRenderer<W: Write> {
    out: W,
    cols: Vec<Column>,
}

impl<W: Write> QuickRenderer<W> {
    pub fn new(out: W) -> Self {
        QuickRenderer { out, cols: Vec::new() }
    }
    /// Write the trailing newline (python writes it after the grid).
    pub fn finish(&mut self) -> Result<()> {
        self.out.write_all(b"\n")?;
        self.out.flush()?;
        Ok(())
    }
}

/// Render one cell like python's CLI type renderers.
pub fn render_cell(ty: ColType, v: &Value) -> String {
    match v {
        Value::NotApplicable | Value::NotAvailable => return "N/A".into(),
        Value::Unreadable | Value::Unparsable => return "-".into(),
        _ => {}
    }
    match (ty, v) {
        (ColType::Hex, Value::Int(i)) => {
            if *i < 0 {
                format!("0x-{:x}", -i)
            } else {
                format!("0x{i:x}")
            }
        }
        (ColType::Bin, Value::Int(i)) => format!("0b{i:b}"),
        (ColType::DateTime, Value::DateTime(d)) => crate::util::time::fmt_quick(d),
        (_, Value::Int(i)) => i.to_string(),
        (_, Value::Str(s)) => s.clone(),
        (_, Value::SStr(s)) => s.to_string(),
        (_, Value::Bool(b)) => if *b { "True" } else { "False" }.into(),
        (_, Value::Bytes(b)) => b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" "),
        (_, Value::Float(f)) => format!("{f}"),
        (_, Value::DateTime(d)) => crate::util::time::fmt_quick(d),
        (_, other) => format!("{other:?}"),
    }
}

impl<W: Write> RowSink for QuickRenderer<W> {
    fn begin(&mut self, columns: Vec<Column>) -> Result<()> {
        let names: Vec<&str> = columns.iter().map(|c| c.name.as_str()).collect();
        write!(self.out, "\n{}\n", names.join("\t"))?;
        self.cols = columns;
        Ok(())
    }
    fn row(&mut self, depth: usize, values: Vec<Value>) -> Result<()> {
        let cells: Vec<String> = self.cols.iter().zip(values.iter()).map(|(c, v)| render_cell(c.ty, v)).collect();
        self.out.write_all(b"\n")?;
        if depth > 0 {
            write!(self.out, "{} ", "*".repeat(depth))?;
        }
        self.out.write_all(cells.join("\t").as_bytes())?;
        Ok(())
    }
}
