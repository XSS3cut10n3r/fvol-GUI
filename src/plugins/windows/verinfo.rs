//! windows.verinfo.VerInfo (python `plugins/windows/verinfo.py`): PE version resources of
//! kernel modules and process DLLs, plus the reusable [`get_version_information`] helper.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::scan::{FnScanner, scan};
use crate::objects::{LayerRef, Obj, Space};
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::windows::pefile::{PeError, PeFile};
use crate::symbols::windows::{WinExt, pe};

pub struct VerInfo;

/// How python's `VerInfo.get_version_information` failed, by python exception type (callers
/// catch different sets: verinfo catches all but [`VersionError::Fatal`], consoles only
/// `InvalidAddressException`, `TypeError` and `AttributeError`).
#[derive(Debug)]
pub enum VersionError {
    /// `InvalidAddressException` while reconstructing the image.
    Invalid(Error),
    /// `ValueError` from `reconstruct()` (bad signatures, oversized image / sections).
    Value(String),
    /// `TypeError`: no layer (python passes `None` when no session layer maps a module).
    Type,
    /// `AttributeError`: no `VS_FIXEDFILEINFO` (or pefile's own AttributeError).
    Attribute,
    /// `PEFormatError`, `OverflowError`, `ZeroDivisionError`: nobody catches these.
    Fatal(Error),
}

impl VersionError {
    /// The exceptions windows.verinfo turns into UnreadableValue.
    pub fn caught_by_verinfo(&self) -> bool {
        !matches!(self, VersionError::Fatal(_))
    }
}

/// python `VerInfo.get_version_information(context, pe_table_name, layer_name, base_address)`:
/// `(major, minor, product, build)` from `VS_FIXEDFILEINFO[0].ProductVersion{MS,LS}` of the
/// PE at `base` (reconstructed like `IMAGE_DOS_HEADER.reconstruct()` and parsed like
/// `pefile.PE(fast_load=True)` + the resource directory). Reads only the pages it needs.
pub fn get_version_information(pe_table: TableRef, layer: Option<LayerRef>, base: u64) -> std::result::Result<(u16, u16, u16, u16), VersionError> {
    let Some(layer) = layer else { return Err(VersionError::Type) };
    let dos = Obj::named(Space::on(layer, pe_table), "_IMAGE_DOS_HEADER", base).map_err(VersionError::Fatal)?;
    let (view, err) = pe::reconstruct_view(&dos);
    match err {
        None => {}
        Some(pe::ReconError::Invalid(e)) => return Err(VersionError::Invalid(e)),
        Some(pe::ReconError::Value(m)) => return Err(VersionError::Value(m)),
        Some(e) => return Err(VersionError::Fatal(Error::msg(e.to_string()))),
    }
    let pe = match PeFile::parse(&view) {
        Ok(p) => p,
        Err(PeError::Attribute(_)) => return Err(VersionError::Attribute),
        Err(e) => return Err(VersionError::Fatal(Error::msg(e.to_string()))),
    };
    let fixed = pe.parse_version_info();
    let v = fixed.first().ok_or(VersionError::Attribute)?;
    Ok(((v.product_version_ms >> 16) as u16, v.product_version_ms as u16, (v.product_version_ls >> 16) as u16, v.product_version_ls as u16))
}

/// python `VerInfo.find_version_info(context, layer_name, filename)` (one file name; see
/// [`find_version_info`]).
pub fn find_version_info_one(layer: LayerRef, filename: &str) -> Result<Option<(u16, u16, u16, u16)>> {
    find_version_info(layer, &[filename.to_string()]).pop().unwrap_or(Ok(None))
}

/// python `VerInfo.find_version_info(context, layer_name, filename)` for several file names
/// in one scan of `layer`: for each name the result of python's per-name scan (the first
/// `"OriginalFilename\0" + name` (UTF-16BE) hit, then the `VS_FIXEDFILEINFO` before it).
/// `Err` where python would raise (unreadable preamble).
pub fn find_version_info(layer: LayerRef, names: &[String]) -> Vec<Result<Option<(u16, u16, u16, u16)>>> {
    let utf16be = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect() };
    let prefix = utf16be("OriginalFilename\0");
    let needles: Vec<Vec<u8>> = names.iter().map(|n| utf16be(&format!("OriginalFilename\0{n}"))).collect();
    let scanner = FnScanner::new(|data: &[u8], off: u64, hits: &mut Vec<(usize, u64)>| {
        let chunk = crate::layers::scan::DEFAULT_CHUNK_SIZE as usize;
        let mut pos = 0;
        while let Some(p) = crate::layers::scan::find(&data[pos..], &prefix) {
            let at = pos + p;
            if at >= chunk {
                break;
            }
            for (i, n) in needles.iter().enumerate() {
                if data[at..].starts_with(n) {
                    hits.push((i, off + at as u64));
                }
            }
            pos = at + 1;
        }
    });
    let mut first: Vec<Option<u64>> = vec![None; names.len()];
    for (i, at) in scan(layer, &scanner, None) {
        if first[i].is_none() {
            first[i] = Some(at);
        }
    }
    first
        .into_iter()
        .map(|hit| {
            let Some(offset) = hit else { return Ok(None) };
            let data = crate::layers::LayerExt::read_vec(layer, offset.wrapping_sub(0x500), 0x500)?;
            parse_fixed_file_info(&data).map(Some)
        })
        .collect()
}

/// The (FV1, FV2, FV3, FV4) python's `find_version_info` unpacks (`"<IHHHHHHHH"`) after the
/// `VS_FIXEDFILEINFO` signature in the 0x500 bytes before a hit. Python quirk: without a
/// signature `data.find(sig) + 4 == 3` is still ">= 0", so the words at offset 3 are used;
/// too little data is python's `struct.error`.
pub fn parse_fixed_file_info(data: &[u8]) -> Result<(u16, u16, u16, u16)> {
    let at = crate::layers::scan::find(data, b"\xbd\x04\xef\xfe").map(|p| p as i64).unwrap_or(-1) + 4;
    let at = at as usize;
    if at + 20 > data.len() {
        return Err(Error::msg("struct.error: unpack requires a buffer of 20 bytes"));
    }
    let h = |i: usize| u16::from_le_bytes([data[at + 4 + i * 2], data[at + 5 + i * 2]]);
    // struct_version, FV2, FV1, FV4, FV3, ... -> (FV1, FV2, FV3, FV4)
    Ok((h(1), h(0), h(3), h(2)))
}

#[cfg(test)]
mod tests {
    use super::parse_fixed_file_info;

    #[test]
    fn fixed_file_info() {
        // after the signature python unpacks "<IHHHHHHHH": struct_version, FV2, FV1, FV4, FV3, ...
        let mut data = vec![0u8; 0x500];
        let at = 0x100;
        data[at..at + 4].copy_from_slice(b"\xbd\x04\xef\xfe");
        let fields: [u16; 10] = [0, 1, 3, 6, 19935, 9600, 3, 6, 19935, 9600];
        for (i, v) in fields.iter().enumerate() {
            data[at + 4 + 2 * i..at + 6 + 2 * i].copy_from_slice(&v.to_le_bytes());
        }
        // dwStrucVersion = 0x00010000, FileVersionMS = (6 << 16) | 3, LS = (9600 << 16) | 19935
        assert_eq!(parse_fixed_file_info(&data).unwrap(), (6, 3, 9600, 19935));
        // python quirk: no signature -> data.find() + 4 == 3, unpack from offset 3
        let mut data = vec![0u8; 0x500];
        data[3 + 8..3 + 10].copy_from_slice(&7u16.to_le_bytes());
        assert_eq!(parse_fixed_file_info(&data).unwrap(), (0, 0, 0, 7));
        // signature too close to the end: struct.error
        let mut data = vec![0u8; 0x500];
        data[0x4f0..0x4f4].copy_from_slice(b"\xbd\x04\xef\xfe");
        assert!(parse_fixed_file_info(&data).is_err());
    }
}

fn version_values(v: std::result::Result<(u16, u16, u16, u16), ()>) -> [Value; 4] {
    match v {
        Ok((a, b, c, d)) => [Value::Int(a as i128), Value::Int(b as i128), Value::Int(c as i128), Value::Int(d as i128)],
        Err(()) => [Value::Unreadable, Value::Unreadable, Value::Unreadable, Value::Unreadable],
    }
}

impl Plugin for VerInfo {
    fn name(&self) -> &'static str {
        "windows.verinfo.VerInfo"
    }
    fn description(&self) -> &'static str {
        "Lists version information from PE files."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::flag("extensive", "Search physical layer for version information")]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Base", ColType::Hex),
            Column::new("Name", ColType::Str),
            Column::new("Major", ColType::Int),
            Column::new("Minor", ColType::Int),
            Column::new("Product", ColType::Int),
            Column::new("Build", ColType::Int),
        ])?;
        let k = ctx.windows_kernel()?;
        let extensive = cfg.get_bool("extensive");
        let pe_table = ctx.load_isf("windows/pe")?;

        // ---- kernel modules. python passes the session layers as a *generator*: every
        // find_session_layer() call resumes it, so each layer is handed out at most once and
        // once it is exhausted every later module gets None (TypeError -> unreadable).
        let session_layers = super::modules::get_session_layers(k, &[])?;
        let mut cursor = 0usize;
        struct ModRow {
            base: u64,
            name: Value,
            layer: Option<LayerRef>,
        }
        let mut mods = Vec::new();
        // where python raised while walking the modules (rows before it are still printed)
        let mut mod_err: Option<Error> = None;
        for m in super::modules::list_modules(k) {
            let r = (|| -> Result<ModRow> {
                let m = m?;
                let name = match m.m("BaseDllName")?.get_string() {
                    Ok(n) => Value::Str(n),
                    Err(e) if e.is_invalid_address() => Value::Unreadable,
                    Err(e) => return Err(e),
                };
                let base = m.m("DllBase")?.u64()?;
                let mut layer = None;
                while cursor < session_layers.len() {
                    let l = session_layers[cursor];
                    cursor += 1;
                    if l.is_valid(base, 1) {
                        layer = Some(l);
                        break;
                    }
                }
                Ok(ModRow { base, name, layer })
            })();
            match r {
                Ok(row) => mods.push(row),
                Err(e) => {
                    mod_err = Some(e);
                    break;
                }
            }
        }
        let versions = crate::util::par::par_map(mods.len(), |i| get_version_information(pe_table, mods[i].layer, mods[i].base));
        let mut vals: Vec<std::result::Result<(u16, u16, u16, u16), ()>> = Vec::with_capacity(mods.len());
        let mut want: Vec<(usize, String)> = Vec::new();
        for (i, v) in versions.into_iter().enumerate() {
            match v {
                Ok(t) => vals.push(Ok(t)),
                Err(e) if e.caught_by_verinfo() => {
                    vals.push(Err(()));
                    if let (true, Value::Str(n)) = (extensive, &mods[i].name) {
                        want.push((i, n.clone()));
                    }
                }
                Err(e) => {
                    let e = match e {
                        VersionError::Fatal(e) => e,
                        e => Error::msg(format!("{e:?}")),
                    };
                    // python dies at this module: emit the rows before it first
                    for (j, r) in vals.iter().enumerate() {
                        let mut row = vec![Value::NotApplicable, Value::NotApplicable, Value::Int(mods[j].base as i128), mods[j].name.clone()];
                        row.extend(version_values(*r));
                        out.row(0, row)?;
                    }
                    return Err(e);
                }
            }
        }
        if !want.is_empty() {
            let names: Vec<String> = want.iter().map(|(_, n)| n.clone()).collect();
            let found = find_version_info(k.phys, &names);
            // python scans module by module: a failing read stops it at that module
            let mut stop: Option<(usize, Error)> = None;
            for ((i, _), f) in want.iter().zip(found) {
                match f {
                    Ok(Some(t)) => vals[*i] = Ok(t),
                    Ok(None) => {}
                    Err(e) => {
                        stop = Some((*i, e));
                        break;
                    }
                }
            }
            if let Some((i, e)) = stop {
                for j in 0..i {
                    let mut row = vec![Value::NotApplicable, Value::NotApplicable, Value::Int(mods[j].base as i128), mods[j].name.clone()];
                    row.extend(version_values(vals[j]));
                    out.row(0, row)?;
                }
                return Err(e);
            }
        }
        for (m, v) in mods.iter().zip(vals) {
            let mut row = vec![Value::NotApplicable, Value::NotApplicable, Value::Int(m.base as i128), m.name.clone()];
            row.extend(version_values(v));
            out.row(0, row)?;
        }
        if let Some(e) = mod_err {
            return Err(e);
        }

        // ---- processes and their DLLs, in parallel, emitted in order
        let procs = super::pslist::list_processes(k, &|_| Ok(false));
        let proc_rows = |proc: &Obj| -> Vec<Result<Vec<Value>>> {
            let mut rows = Vec::new();
            let r = (|| -> Result<()> {
                let pid = match proc.m("UniqueProcessId").and_then(|p| p.int()) {
                    Ok(p) => p,
                    Err(e) if e.is_invalid_address() => return Ok(()),
                    Err(e) => return Err(e),
                };
                let pl = match proc.add_process_layer() {
                    Ok(l) => l,
                    Err(e) if e.is_invalid_address() => return Ok(()),
                    Err(e) => return Err(e),
                };
                let mut pname: Option<String> = None;
                for entry in proc.load_order_modules() {
                    let entry = entry?;
                    let name = match entry.m("BaseDllName")?.get_string() {
                        Ok(n) => Value::Str(n),
                        Err(e) if e.is_invalid_address() => Value::Unreadable,
                        Err(e) => return Err(e),
                    };
                    let base = entry.m("DllBase")?;
                    let (dll_base, ver) = match base.u64() {
                        Ok(b) => {
                            let v = match get_version_information(pe_table, Some(pl), b) {
                                Ok(t) => Ok(t),
                                // (InvalidAddressException, ValueError, AttributeError)
                                Err(VersionError::Invalid(_) | VersionError::Value(_) | VersionError::Attribute) => Err(()),
                                Err(VersionError::Fatal(e)) => return Err(e),
                                Err(e) => return Err(Error::msg(format!("{e:?}"))),
                            };
                            (Value::Int(b as i128), v)
                        }
                        Err(e) if e.is_invalid_address() => (Value::Unreadable, Err(())),
                        Err(e) => return Err(e),
                    };
                    if pname.is_none() {
                        pname = Some(proc.image_file_name_str()?);
                    }
                    let mut row = vec![Value::Int(pid), Value::Str(pname.clone().unwrap()), dll_base, name];
                    row.extend(version_values(ver));
                    rows.push(Ok(row));
                }
                Ok(())
            })();
            if let Err(e) = r {
                rows.push(Err(e));
            }
            rows
        };
        crate::plugins::emit_par_rows(out, procs, |p| proc_rows(p))
    }
}
