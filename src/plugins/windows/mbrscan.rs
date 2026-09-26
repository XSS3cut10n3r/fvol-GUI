//! windows.mbrscan.MBRScan (python `plugins/windows/mbrscan.py`): potential Master Boot Records
//! found by scanning the physical layer for the `55 aa` boot signature.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! The scan is python's `MultiStringScanner([b"\x55\xaa"])` (core scanner, python chunking and
//! order); each hit's MBR is read, hashed and turned into rows on the scan's worker threads, the
//! calling thread only renders. Python only catches `PagedInvalidAddressException`, which the
//! physical layer never raises: any unreadable field ends the plugin with an error, like python.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::scan::{MultiStringScanner, Scanner, scan_each};
use crate::layers::{Layer, Mapping};
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::mbr::PartitionTable;

pub struct MBRScan;

/// MBR size, boot code size (python `mbr_length`, `bootcode_length`).
const MBR_LENGTH: u64 = 0x200;
const BOOTCODE_LENGTH: usize = 0x1B8;
/// python `mbr_signature`.
const MBR_SIGNATURE: &[u8] = b"\x55\xaa";

/// The core `MultiStringScanner` with the per-hit work `parse` done in the `finish` phase (on
/// the scan's worker threads).
struct ParseScanner<T, F> {
    ms: MultiStringScanner,
    parse: F,
    _t: std::marker::PhantomData<fn() -> T>,
}

impl<T: Send, F: Fn(u64) -> T + Sync> Scanner for ParseScanner<T, F> {
    type Hit = T;
    fn chunk_size(&self) -> u64 {
        self.ms.chunk_size()
    }
    fn overlap(&self) -> u64 {
        self.ms.overlap()
    }
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<T>) {
        let mut v = Vec::new();
        self.ms.scan(data, data_offset, &mut v);
        hits.extend(v.into_iter().map(|(a, _)| (self.parse)(a)));
    }
    fn prescan(&self, data: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
        self.ms.prescan(data, out)
    }
    fn finish(&self, matches: &[(u64, u32)], data_offset: u64, hits: &mut Vec<T>) {
        hits.extend(matches.iter().map(|&(p, _)| (self.parse)(data_offset + p)));
    }
    fn stream_window(&self) -> Option<usize> {
        self.ms.stream_window()
    }
    fn prescan_piece(&self, data: &[u8], base: u64, from: usize, limit: usize, out: &mut Vec<(u64, u32)>) -> usize {
        self.ms.prescan_piece(data, base, from, limit, out)
    }
}

/// Rows of one hit and the exception python raised after them.
struct HitRows {
    rows: Vec<(usize, Vec<Value>)>,
    err: Option<Error>,
}

fn md5_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let d = crate::crypto::md5::digest(data);
    let mut s = String::with_capacity(32);
    for b in d {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

/// python `LayerDataRenderer.render_bytes` hole map of `[start, start+len)` (no surrounding
/// bytes): empty for data layers (the file); for translation layers python's walk over
/// `layer.mapping(start, end_offset)` (sic: the end offset is passed as the length), whose
/// off-by-one lets the byte right after a run pass. `Err` = python's `StopIteration` crash
/// when nothing is mapped.
pub fn layer_data_errors(layer: &dyn Layer, start: u64, len: u64) -> Result<Vec<u32>> {
    if layer.as_file().is_some() || len == 0 {
        return Ok(Vec::new());
    }
    let end = start + len;
    let mut runs: Vec<Mapping> = Vec::new();
    layer.mapping(start, end, &mut |m| {
        runs.push(m);
        m.offset <= end
    });
    let mut it = runs.into_iter();
    let Some(mut cur) = it.next() else { return Err(Error::msg("StopIteration")) };
    let mut errors = Vec::new();
    for i in start..end {
        if i < cur.offset {
            errors.push((i - start) as u32);
        }
        if i > cur.offset + cur.len {
            if let Some(n) = it.next() {
                cur = n;
            }
        }
        if i > cur.offset + cur.len {
            errors.push((i - start) as u32);
        }
    }
    errors.dedup();
    Ok(errors)
}

/// The rows python yields for the `55 aa` hit at `offset`.
fn mbr_rows(layer: &dyn Layer, offset: u64, full: bool, arch: &'static str) -> HitRows {
    let mut rows: Vec<(usize, Vec<Value>)> = Vec::new();
    let r = (|| -> Result<()> {
        // python: a negative MBR start fails the (padded) read of the file layer
        let start = offset.checked_sub(MBR_LENGTH - MBR_SIGNATURE.len() as u64).ok_or(Error::invalid(offset))?;
        let mut full_mbr = [0u8; MBR_LENGTH as usize];
        if layer.as_file().is_some() && !layer.is_valid(start, MBR_LENGTH) {
            return Err(Error::invalid(start));
        }
        layer.read_padded(start, &mut full_mbr);
        let bootcode = &full_mbr[..BOOTCODE_LENGTH];
        if bootcode.iter().all(|&b| b == 0) {
            return Ok(());
        }
        let table = PartitionTable::new(layer, start);
        let sig = table.get_disk_signature()?;
        let md5_boot = md5_hex(bootcode);
        let md5_full = md5_hex(&full_mbr);
        let head = |sig: String| vec![Value::Int(offset as i128), Value::Str(sig), Value::Str(md5_boot.clone()), Value::Str(md5_full.clone())];
        let disasm = Value::Disassembly { data: bootcode.to_vec(), offset: 0, arch: Some(arch) };
        let mut top = head(sig);
        if !full {
            top.extend([Value::NotApplicable, Value::NotApplicable, Value::NotApplicable, Value::NotApplicable, disasm]);
        } else {
            top.extend(std::iter::repeat_n(Value::NotApplicable, 13));
            top.push(disasm);
            let errors = layer_data_errors(layer, start, BOOTCODE_LENGTH as u64)?;
            top.push(Value::LayerBytes { data: bootcode.to_vec(), errors });
        }
        rows.push((0, top));
        for i in 0..4u64 {
            let e = table.entry(i);
            let mut row = head(table.get_disk_signature()?);
            if !full {
                row.extend([
                    Value::Int(i as i128 + 1),
                    Value::Bool(e.is_bootable()?),
                    Value::SStr(e.get_partition_type()?),
                    Value::Int(e.get_size_in_sectors()? as i128),
                    Value::NotApplicable,
                ]);
            } else {
                row.extend([
                    Value::Int(i as i128 + 1),
                    Value::Bool(e.is_bootable()?),
                    Value::Int(e.get_bootable_flag()? as i128),
                    Value::SStr(e.get_partition_type()?),
                    Value::Int(e.partition_type()? as i128),
                    Value::Int(e.get_starting_lba()? as i128),
                    Value::Int(e.get_starting_cylinder()? as i128),
                    Value::Int(e.get_starting_chs()? as i128),
                    Value::Int(e.get_starting_sector()? as i128),
                    Value::Int(e.get_ending_cylinder()? as i128),
                    Value::Int(e.get_ending_chs()? as i128),
                    Value::Int(e.get_ending_sector()? as i128),
                    Value::Int(e.get_size_in_sectors()? as i128),
                    Value::NotApplicable,
                    Value::NotApplicable,
                ]);
            }
            rows.push((1, row));
        }
        Ok(())
    })();
    HitRows { rows, err: r.err() }
}

impl Plugin for MBRScan {
    fn name(&self) -> &'static str {
        "windows.mbrscan.MBRScan"
    }
    fn description(&self) -> &'static str {
        "Scans for and parses potential Master Boot Records (MBRs)"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::flag(
            "full",
            "It analyzes and provides all the information in the partition entry and bootcode hexdump. (It returns a lot of information, so we recommend you render it in CSV.)",
        )]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.windows_kernel()?;
        let layer = k.phys;
        let full = cfg.get_bool("full");
        let arch = if k.table.is_64bit() { "intel64" } else { "intel" };
        let mut cols = vec![
            Column::new("Potential MBR at Physical Offset", ColType::Hex),
            Column::new("Disk Signature", ColType::Str),
            Column::new("Bootcode MD5", ColType::Str),
            Column::new("Full MBR MD5", ColType::Str),
            Column::new("PartitionIndex", ColType::Int),
            Column::new("Bootable", ColType::Bool),
        ];
        if !full {
            cols.extend([
                Column::new("PartitionType", ColType::Str),
                Column::new("SectorInSize", ColType::Hex),
                Column::new("Disasm", ColType::Disassembly),
            ]);
        } else {
            cols.extend([
                Column::new("BootFlag", ColType::Hex),
                Column::new("PartitionType", ColType::Str),
                Column::new("PartitionTypeRaw", ColType::Hex),
                Column::new("StartingLBA", ColType::Hex),
                Column::new("StartingCylinder", ColType::Int),
                Column::new("StartingCHS", ColType::Int),
                Column::new("StartingSector", ColType::Int),
                Column::new("EndingCylinder", ColType::Int),
                Column::new("EndingCHS", ColType::Int),
                Column::new("EndingSector", ColType::Int),
                Column::new("SectorInSize", ColType::Hex),
                Column::new("Disasm", ColType::Disassembly),
                Column::new("Bootcode", ColType::LayerData),
            ]);
        }
        out.begin(cols)?;
        let scanner = ParseScanner { ms: MultiStringScanner::new(&[MBR_SIGNATURE]), parse: |off| mbr_rows(layer, off, full, arch), _t: std::marker::PhantomData };
        let mut res = Ok(());
        scan_each(layer, &scanner, None, |h: HitRows| {
            for (depth, values) in h.rows {
                if let Err(e) = out.row(depth, values) {
                    res = Err(e);
                    return false;
                }
            }
            if let Some(e) = h.err {
                res = Err(e);
                return false;
            }
            true
        });
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A translation layer mapping `[10, 15)` and `[20, 25)`.
    struct Holes;
    impl Layer for Holes {
        fn name(&self) -> &str {
            "holes"
        }
        fn max_address(&self) -> u64 {
            100
        }
        fn read(&self, addr: u64, _buf: &mut [u8]) -> Result<()> {
            Err(Error::invalid(addr))
        }
        fn is_valid(&self, _addr: u64, _len: u64) -> bool {
            false
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
            for (o, l) in [(10u64, 5u64), (20, 5)] {
                let s = o.max(addr);
                let e = (o + l).min(addr + len);
                if s < e && !f(Mapping { offset: s, len: e - s, mapped: s }) {
                    return;
                }
            }
        }
    }

    /// python `LayerDataRenderer.render_bytes` hole map, worked by hand for [8, 28): bytes
    /// before a run are holes, the byte right after a run passes (off-by-one), the walk moves
    /// to the next run one byte late, and bytes past the last run are holes.
    #[test]
    fn layer_data_hole_map() {
        assert_eq!(layer_data_errors(&Holes, 8, 20).unwrap(), vec![0, 1, 9, 10, 11, 18, 19]);
        assert!(layer_data_errors(&Holes, 40, 4).is_err());
    }

    #[test]
    fn md5() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }
}
