//! windows.memmap.Memmap (python `plugins/windows/memmap.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::layers::{Layer, Mapping};
use crate::objects::LayerRef;
use crate::plugins::{Config, Plugin, ReqKind, Requirement};
use crate::renderers::text::RowEncoder;
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;
use std::io::Write;

pub struct Memmap;

/// python `proc_layer.mapping(0x0, proc_layer.maximum_address, ignore_errors=True)` runs
/// (including runs backed by swap layers).
fn runs(layer: LayerRef) -> Vec<Mapping> {
    let mut v = Vec::new();
    layer.mapping_targets(0, layer.max_address(), &mut |m, _| {
        v.push(m);
        true
    });
    v
}

/// A process's rows: its runs (formatted by the output thread), or already formatted.
enum Rows {
    Runs(Vec<Mapping>),
    Encoded((Vec<u8>, usize)),
}

/// The process's rows (without --dump) formatted by `enc`: (bytes, row count).
fn encode_runs(layer: LayerRef, enc: &RowEncoder) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let (mut n, mut file_offset) = (0usize, 0u64);
    let null = enc.is_null();
    layer.mapping_targets(0, layer.max_address(), &mut |m, _| {
        if !null {
            let row = [
                Value::Int(m.offset as i128),
                Value::Int(m.mapped as i128),
                Value::Int(m.len as i128),
                Value::Int(file_offset as i128),
                Value::SStr("Disabled"),
            ];
            enc.row(&mut out, &row);
        }
        n += 1;
        file_offset = file_offset.wrapping_add(m.len);
        true
    });
    (out, n)
}

/// Append the padded contents of `[offset, offset+len)` to `f`, in bounded chunks.
fn dump_run(layer: &dyn Layer, f: &mut std::fs::File, buf: &mut Vec<u8>, offset: u64, len: u64) -> std::io::Result<()> {
    const CHUNK: u64 = 16 << 20;
    let mut done = 0u64;
    while done < len {
        let n = CHUNK.min(len - done);
        buf.resize(n as usize, 0);
        layer.read_padded(offset + done, buf);
        f.write_all(buf)?;
        done += n;
    }
    Ok(())
}

impl Plugin for Memmap {
    fn name(&self) -> &'static str {
        "windows.memmap.Memmap"
    }
    fn description(&self) -> &'static str {
        "Prints the memory map"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Process ID to include (all other processes are excluded)", ReqKind::Int).optional(),
            Requirement::flag("dump", "Extract listed memory segments"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Virtual", ColType::Hex),
            Column::new("Physical", ColType::Hex),
            Column::new("Size", ColType::Hex),
            Column::new("Offset in File", ColType::Hex),
            Column::new("File output", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let pids: Vec<i128> = cfg.get_int("pid").into_iter().collect();
        let filter = super::pslist::pid_filter(&pids);
        let dump = cfg.get_bool("dump");
        let procs = super::pslist::list_processes(k, &filter);
        // (pid, layer) per process; None = python's `continue` on InvalidAddressException
        let mut errs: Vec<Option<crate::error::Error>> = Vec::with_capacity(procs.len());
        let layers: Vec<Option<(i128, LayerRef)>> = procs
            .iter()
            .map(|p| {
                let (v, e) = match p {
                    Ok(proc) => match proc.m("UniqueProcessId").and_then(|p| p.int()).and_then(|pid| Ok((pid, proc.add_process_layer()?))) {
                        Ok(v) => (Some(v), None),
                        Err(e) if e.is_invalid_address() => (None, None),
                        Err(e) => (None, Some(e)),
                    },
                    Err(_) => (None, None),
                };
                errs.push(e);
                v
            })
            .collect();
        // walking a whole address space is independent per process: stream them in parallel
        // (bounded look-ahead), emit in python order. Without --dump the workers also format
        // the rows (the renderer's encoder), so the output thread only copies bytes.
        let enc = if dump { None } else { out.encoder() };
        let mut result: Result<()> = Ok(());
        let mut buf = Vec::new();
        let mut procs = procs.into_iter();
        crate::util::par::par_map_stream(
            layers.len(),
            4,
            |i| match (&layers[i], &enc) {
                (Some((_, l)), Some(enc)) => Rows::Encoded(encode_runs(*l, enc)),
                (Some((_, l)), None) => Rows::Runs(runs(*l)),
                (None, _) => Rows::Runs(Vec::new()),
            },
            |i, rows| {
                let r = (|| -> Result<()> {
                    procs.next().unwrap()?;
                    if let Some(e) = errs[i].take() {
                        return Err(e);
                    }
                    let Some((pid, layer)) = layers[i] else { return Ok(()) };
                    let maps = match rows {
                        Rows::Encoded((block, n)) => return out.rows_encoded(&block, n),
                        Rows::Runs(maps) => maps,
                    };
                    let mut file = None;
                    let name = format!("pid.{pid}.dmp");
                    if dump {
                        file = Some(ctx.create_output_file(&name)?.0);
                    }
                    let mut file_offset: u64 = 0;
                    for m in maps {
                        let file_output = match file.as_mut() {
                            Some(f) => {
                                dump_run(layer, f, &mut buf, m.offset, m.len)?;
                                Value::Str(name.clone())
                            }
                            None => Value::SStr("Disabled"),
                        };
                        out.row_ref(
                            0,
                            &[
                                Value::Int(m.offset as i128),
                                Value::Int(m.mapped as i128),
                                Value::Int(m.len as i128),
                                Value::Int(file_offset as i128),
                                file_output,
                            ],
                        )?;
                        file_offset = file_offset.wrapping_add(m.len);
                    }
                    if let Some(mut f) = file {
                        f.flush()?;
                    }
                    Ok(())
                })();
                match r {
                    Ok(()) => true,
                    Err(e) => {
                        result = Err(e);
                        false
                    }
                }
            },
        );
        result
    }
}
