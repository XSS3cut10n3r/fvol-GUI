//! layerwriter.LayerWriter (python `plugins/layerwriter.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! python copies the layer block by block with `layer.read(i, n, pad=True)`. The output is
//! built here as a sparse file of the same length: file-backed runs are copied with
//! `copy_file_range(2)` (a reflink on btrfs/xfs, an in-kernel copy elsewhere) from the image,
//! holes stay unwritten (they read as zeros), everything else is read through the layer and
//! written with `pwrite` -- all in parallel pieces.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::{Layer, metadata};
use crate::objects::LayerRef;
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::Arc;

pub struct LayerWriter;

/// python `LayerWriter.default_block_size`.
pub const DEFAULT_BLOCK_SIZE: i128 = 0x500000;

unsafe extern "C" {
    fn copy_file_range(fd_in: i32, off_in: *mut i64, fd_out: i32, off_out: *mut i64, len: usize, flags: u32) -> isize;
}

/// One python context layer.
pub struct NamedLayer {
    pub name: String,
    /// python class name
    pub class: &'static str,
    pub layer: LayerRef,
    /// `"mapped" in layer.metadata`
    pub mapped: bool,
}

/// python `context.layers` of a generic plugin run, in insertion order: the container stack
/// bottom-up (`base_layer`, ..., `memory_layer`), then the OS `primary` layer.
pub fn context_layers(ctx: &Context, description: &str) -> Result<Vec<NamedLayer>> {
    let p = super::primary::primary(ctx, description)?;
    let listing = ctx.physical_listing()?.to_vec();
    // pair the listing (python get_depends: pre-order) with the dependency tree; the layers
    // live for the whole run
    let mut flat: Vec<LayerRef> = Vec::new();
    fn walk(l: LayerRef, out: &mut Vec<LayerRef>) {
        out.push(l);
        for d in l.dependencies() {
            let d: &'static Arc<dyn Layer> = Box::leak(Box::new(d));
            walk(d.as_ref(), out);
        }
    }
    walk(p.phys, &mut flat);
    let mut v: Vec<(usize, NamedLayer)> = listing
        .iter()
        .zip(flat)
        .map(|(e, l)| (e.depth, NamedLayer { name: e.name.clone(), class: e.class, layer: l, mapped: metadata(l).mapped.is_some() }))
        .collect();
    if p.intel.is_none() {
        // no OS layer: the stacker names the top container layer after the requirement
        if let Some(top) = v.iter_mut().find(|x| x.0 == 0) {
            top.1.name = "primary".into();
        }
    }
    v.sort_by(|a, b| b.0.cmp(&a.0));
    let mut out: Vec<NamedLayer> = v.into_iter().map(|(_, l)| l).collect();
    if p.intel.is_some() {
        out.push(NamedLayer { name: "primary".into(), class: p.layer.class_name(), layer: p.layer, mapped: true });
    }
    Ok(out)
}

/// Number of bytes python writes: `sum(min(chunk, max + 1 - i) for i in range(0, max, chunk))`.
pub fn python_length(max: u64, chunk: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    let n = max.div_ceil(chunk);
    let last = (n - 1) * chunk;
    last + chunk.min(max + 1 - last)
}

/// Copy `[src_off, src_off+len)` of `src` to `dst` at `dst_off` (copy_file_range, falling back to
/// read + pwrite).
fn copy_range(src: &File, src_off: u64, dst: &File, dst_off: u64, len: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    let (mut so, mut dof, mut left) = (src_off as i64, dst_off as i64, len);
    while left > 0 {
        let n = unsafe { copy_file_range(src.as_raw_fd(), &mut so, dst.as_raw_fd(), &mut dof, left.min(1 << 30) as usize, 0) };
        if n <= 0 {
            break;
        }
        left -= n as u64;
    }
    // fallback (unsupported / short copy): plain copies
    let mut buf = vec![0u8; (left.min(8 << 20)) as usize];
    while left > 0 {
        let k = left.min(buf.len() as u64) as usize;
        src.read_exact_at(&mut buf[..k], so as u64)?;
        dst.write_all_at(&buf[..k], dof as u64)?;
        so += k as i64;
        dof += k as i64;
        left -= k as u64;
    }
    Ok(())
}

/// python `LayerWriter.write_layer`: write `len` bytes of `layer` (python's padded reads) into
/// `out` as a sparse file.
pub fn write_layer(layer: &dyn Layer, out: &File, len: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    out.set_len(len)?;
    if len == 0 {
        return Ok(());
    }
    // runs of data: (layer offset, length, backing-file offset if file-backed)
    let mut runs: Vec<(u64, u64, Option<u64>)> = Vec::new();
    let file = crate::layers::base_file(layer);
    if layer.as_file().is_some() {
        runs.push((0, len, Some(0)));
    } else {
        let direct = layer.lower().is_some_and(|l| l.as_file().is_some());
        layer.mapping(0, len, &mut |m| {
            let n = m.len.min(len - m.offset);
            // only raw runs are file bytes: a compressed block maps to its compressed data and a
            // fill run to its value, and `translate` answers None for both
            let fo = if direct { layer.translate(m.offset).filter(|&(_, rem)| rem >= n).map(|(fo, _)| fo) } else { None };
            runs.push((m.offset, n, fo));
            true
        });
    }
    // split into pieces for the workers
    const PIECE: u64 = 256 << 20;
    let mut pieces = Vec::new();
    for (o, l, f) in runs {
        let mut d = 0;
        while d < l {
            let n = PIECE.min(l - d);
            pieces.push((o + d, n, f.map(|x| x + d)));
            d += n;
        }
    }
    let err: std::sync::Mutex<Option<std::io::Error>> = std::sync::Mutex::new(None);
    crate::util::par::par_for(pieces.len(), |i| {
        let (o, n, f) = pieces[i];
        let r = match (f, file) {
            // block-aligned on both sides: copy_file_range can share the extents (reflink)
            (Some(fo), Some(src)) if (fo | o) & 0xfff == 0 => copy_range(src.file(), fo, out, o, n),
            // unaligned file-backed data: write straight from the image mapping
            (Some(fo), Some(src)) => match src.slice(fo, n as usize) {
                Some(data) => out.write_all_at(data, o),
                None => copy_range(src.file(), fo, out, o, n),
            },
            _ => {
                // read through the layer; all-zero blocks stay holes
                let mut buf = vec![0u8; (8u64 << 20).min(n) as usize];
                let mut d = 0;
                let mut r = Ok(());
                while d < n && r.is_ok() {
                    let k = (buf.len() as u64).min(n - d) as usize;
                    layer.read_padded(o + d, &mut buf[..k]);
                    if buf[..k].iter().any(|&b| b != 0) {
                        r = out.write_all_at(&buf[..k], o + d);
                    }
                    d += k as u64;
                }
                r
            }
        };
        if let Err(e) = r {
            *err.lock().unwrap() = Some(e);
        }
    });
    match err.into_inner().unwrap() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

impl Plugin for LayerWriter {
    fn name(&self) -> &'static str {
        "layerwriter.LayerWriter"
    }
    fn description(&self) -> &'static str {
        "Runs the automagics and writes out the primary layer produced by the stacker."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("block_size", "Size of blocks to copy over", ReqKind::Int)
                .optional()
                .default(ConfigValue::Int(DEFAULT_BLOCK_SIZE)),
            Requirement::flag("list", "List available layers"),
            Requirement::new("layers", "Names of layers to write (defaults to the highest non-mapped layer)", ReqKind::ListStr).optional(),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let layers = context_layers(ctx, "Memory layer for the kernel")?;
        if cfg.get_bool("list") {
            out.begin(vec![Column::new("Layer name", ColType::Str), Column::new("Layer type", ColType::Str)])?;
            for l in &layers {
                out.row(0, vec![Value::Str(l.name.clone()), Value::SStr(l.class)])?;
            }
            return Ok(());
        }
        out.begin(vec![Column::new("Status", ColType::Str)])?;
        let mut names = cfg.get_strs("layers");
        if names.is_empty() {
            // the most recently added layer that isn't mapped
            names = layers.iter().filter(|l| !l.mapped).last().map(|l| vec![l.name.clone()]).unwrap_or_default();
        }
        let block = cfg.get_int("block_size").unwrap_or(DEFAULT_BLOCK_SIZE);
        for name in names {
            let Some(l) = layers.iter().find(|l| l.name == name) else {
                out.row(0, vec![Value::Str(format!("Layer Name {name} does not exist"))])?;
                continue;
            };
            if block == 0 {
                panic!("ValueError: range() arg 3 must not be zero");
            }
            let max = l.layer.max_address();
            let len = if block < 0 { 0 } else { python_length(max, block.min(u64::MAX as i128) as u64) };
            let preferred = format!("{name}.raw");
            let (file, final_name) = match ctx.create_output_file(&preferred) {
                Ok(x) => x,
                Err(e) => {
                    out.row(0, vec![Value::Str(format!("Layer cannot be written to {preferred}: {e}"))])?;
                    out.row(0, vec![Value::Str(format!("Layer has been written to {preferred}"))])?;
                    continue;
                }
            };
            if let Err(e) = write_layer(l.layer, &file, len) {
                out.row(0, vec![Value::Str(format!("Layer cannot be written to {preferred}: {}", Error::Io(e)))])?;
            }
            out.row(0, vec![Value::Str(format!("Layer has been written to {final_name}"))])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_lengths() {
        // sum(min(c, max+1-i) for i in range(0, max, c))
        let py = |max: u64, c: u64| -> u64 { (0..max).step_by(c as usize).map(|i| c.min(max + 1 - i)).sum() };
        for &(m, c) in &[(0u64, 5u64), (1, 5), (4, 5), (5, 5), (6, 5), (10, 5), (11, 5), (0x13fffffff, 0x500000), (0x140000000, 0x500000)] {
            assert_eq!(python_length(m, c), py(m, c), "max={m} c={c}");
        }
    }
}
