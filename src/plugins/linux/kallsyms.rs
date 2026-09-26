//! linux.kallsyms.Kallsyms (python `plugins/linux/kallsyms.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::{ColType, Column, RowBlock, RowSink, Value};
use std::sync::Mutex;
use crate::symbols::linux::kallsyms::{KasSymbol, Kallsyms as Kas};

pub struct Kallsyms;

/// python's TreeGrid `TypeError` for a `None` in a `str` column.
fn none_in_str_column(index: usize, column: &str) -> Error {
    Error::msg(format!("TypeError: Values item with index {index} is the wrong type for column {column} (got <class 'NoneType'> but expected <class 'str'>)"))
}

/// python `Kallsyms._generator` row for one symbol.
fn row(s: KasSymbol) -> Result<[Value; 8]> {
    // python `_get_symbol_size`: falsy or negative sizes are N/A
    let size = match s.size {
        Some(z) if z > 0 => Value::Int(z),
        _ => Value::NotAvailable,
    };
    let exported = s.exported.map_or(Value::NotAvailable, Value::Bool);
    let type_description = s.type_description();
    let subsystem = s.subsystem.ok_or_else(|| none_in_str_column(4, "SubSystem"))?;
    let module_name = s.module_name.ok_or_else(|| none_in_str_column(5, "ModuleName"))?;
    Ok([
        Value::Int(s.address as i128),
        match s.type_ {
            Some(t) if !t.is_empty() => Value::Str(t),
            _ => Value::NotAvailable,
        },
        size,
        exported,
        Value::SStr(subsystem),
        Value::Str(module_name),
        Value::Str(s.name),
        type_description.map_or(Value::NotAvailable, Value::SStr),
    ])
}

/// Appends `s`'s row to `b`; false (the error in `err`) where python raises.
fn push_symbol(b: &mut RowBlock, err: &mut Option<Error>, s: Result<KasSymbol>) -> bool {
    match s.and_then(row) {
        Ok(r) => {
            b.push_ref(&r);
            true
        }
        Err(e) => {
            *err = Some(e);
            false
        }
    }
}

/// python `for symbol in symbols: yield row(symbol)` over a collected part (a trailing `Err` =
/// python raised there), the rows built and formatted on all cores.
fn emit_symbols(out: &mut dyn RowSink, symbols: Vec<Result<KasSymbol>>) -> Result<()> {
    const CHUNK: usize = 2048;
    let n = symbols.len();
    let mut chunks: Vec<Mutex<Vec<Result<KasSymbol>>>> = Vec::with_capacity(n.div_ceil(CHUNK));
    let mut it = symbols.into_iter().peekable();
    while it.peek().is_some() {
        chunks.push(Mutex::new(it.by_ref().take(CHUNK).collect()));
    }
    super::stream_chunks(out, n, CHUNK, |r, b| {
        let mut err = None;
        for s in std::mem::take(&mut *chunks[r.start / CHUNK].lock().unwrap()) {
            if !push_symbol(b, &mut err, s) {
                break;
            }
        }
        err
    })
}

impl Plugin for Kallsyms {
    fn name(&self) -> &'static str {
        "linux.kallsyms.Kallsyms"
    }
    fn description(&self) -> &'static str {
        "Kallsyms symbols enumeration plugin."
    }
    fn epilog(&self) -> Option<&'static str> {
        Some(
            "If no arguments are provided, all symbols are included: core, modules, ftrace, and BPF.\n    Alternatively, you can use any combination of --core, --modules, --ftrace, and --bpf\n    to customize the output.",
        )
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::flag("core", "Include core symbols"),
            Requirement::flag("modules", "Include module symbols"),
            Requirement::flag("ftrace", "Include ftrace symbols"),
            Requirement::flag("bpf", "Include BPF symbols"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Addr", ColType::Hex),
            Column::new("Type", ColType::Str),
            Column::new("Size", ColType::Int),
            Column::new("Exported", ColType::Bool),
            Column::new("SubSystem", ColType::Str),
            Column::new("ModuleName", ColType::Str),
            Column::new("SymbolName", ColType::Str),
            Column::new("Description", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        let kas = Kas::get(k)?;
        let mut flags = [cfg.get_bool("core"), cfg.get_bool("modules"), cfg.get_bool("ftrace"), cfg.get_bool("bpf")];
        if !flags.iter().any(|&f| f) {
            flags = [true; 4];
        }
        let enc = out.encoder();
        let enc = enc.as_ref();
        for (part, _) in flags.iter().enumerate().filter(|(_, f)| **f) {
            let symbols = match part {
                0 => {
                    // streamed: rows are built and formatted on the cores that expanded the
                    // symbols, and written here in kallsyms order
                    let mut res = Ok(());
                    kas.for_each_core_block(
                        &|| (RowBlock::new(enc), None),
                        &|(b, err): &mut (RowBlock, Option<Error>), s| push_symbol(b, err, s),
                        &mut |(b, err)| {
                            res = b.emit(out).and(err.map_or(Ok(()), Err));
                            res.is_ok()
                        },
                    );
                    res?;
                    continue;
                }
                1 => kas.get_modules_symbols(None),
                2 => kas.get_ftrace_symbols(),
                _ => kas.get_bpf_symbols(),
            };
            emit_symbols(out, symbols)?;
        }
        Ok(())
    }
}
