//! windows.truecrypt.Passphrase (python `plugins/windows/truecrypt.py`): cached passphrases in
//! the .data section of truecrypt.sys.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::LayerExt;
use crate::objects::util::array_to_string;
use crate::objects::{LayerRef, Obj, Space};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::windows::{WinExt, pe};

pub struct Passphrase;

/// python `Passphrase.scan_module(module_base, layer_name)`: (offset, passphrase) pairs; a
/// trailing `Err` is where python raised.
pub fn scan_module(pe_table: TableRef, layer: LayerRef, module_base: u64, min_length: i128) -> Vec<Result<(u64, String)>> {
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let dos = Obj::named(Space::on(layer, pe_table), "_IMAGE_DOS_HEADER", module_base)?;
        let nt = pe::get_nt_header(&dos)?;
        let mut data_section = None;
        for sec in pe::get_sections(&nt)? {
            if array_to_string(&sec.m("Name")?, None)? == ".data" {
                data_section = Some(sec);
                break;
            }
        }
        // next() on an exhausted generator inside a generator: RuntimeError (PEP 479)
        let sec = data_section.ok_or_else(|| Error::msg("RuntimeError: generator raised StopIteration"))?;
        let base = sec.m("VirtualAddress")?.u64()?.wrapping_add(module_base);
        let size = sec.path("Misc.VirtualSize")?.u64()?;
        if size % 4 != 0 {
            return Err(Error::msg("ValueError: PE data section not DWORD-aligned!"));
        }
        let count = size / 4;
        // the int32 array is read element by element; read it page-wise and stop at the first
        // unreadable element like python
        let mut page: Option<(u64, Vec<u8>)> = None;
        for i in 0..count {
            let at = base.wrapping_add(i * 4);
            let length = {
                let pg = at & !0xFFF;
                let within = (at & 0xFFF) as usize;
                if within + 4 <= 0x1000 {
                    if page.as_ref().map(|p| p.0) != Some(pg) {
                        page = layer.read_vec(pg, 0x1000).ok().map(|d| (pg, d));
                    }
                    match &page {
                        Some((_, d)) => i32::from_le_bytes(d[within..within + 4].try_into().unwrap()),
                        None => layer.read_i32(at)?,
                    }
                } else {
                    layer.read_i32(at)?
                }
            };
            if !(min_length <= length as i128 && length <= 64) {
                continue;
            }
            let offset = at.wrapping_add(4);
            let pass = layer.read_vec(offset, length as usize)?;
            if !pass.iter().all(|&c| (0x20..0x7F).contains(&c)) {
                continue;
            }
            let buf = layer.read_vec(offset.wrapping_add(length as u64 + 1), 3)?;
            if buf.iter().any(|&b| b != 0) {
                continue;
            }
            out.push(Ok((offset, String::from_utf8_lossy(&pass).into_owned())));
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

impl Plugin for Passphrase {
    fn name(&self) -> &'static str {
        "windows.truecrypt.Passphrase"
    }
    fn description(&self) -> &'static str {
        "TrueCrypt Cached Passphrase Finder"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("min-length", "Minimum length of passphrases to identify", ReqKind::Int).optional().default(ConfigValue::Int(5))]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![Column::new("Offset", ColType::Hex), Column::new("Length", ColType::Int), Column::new("Password", ColType::Str)])?;
        let k = ctx.windows_kernel()?;
        let mut base = None;
        for m in super::modules::list_modules(k) {
            let m = m?;
            if m.m("BaseDllName")?.get_string()?.to_lowercase() == "truecrypt.sys" {
                base = Some(m.m("DllBase")?.u64()?);
                break;
            }
        }
        let Some(base) = base else {
            return Ok(());
        };
        let pe_table = ctx.load_isf("windows/pe")?;
        let min_length = cfg.get_int("min-length").unwrap_or(5);
        for r in scan_module(pe_table, k.vlayer, base, min_length) {
            let (offset, password) = r?;
            out.row(0, vec![Value::Int(offset as i128), Value::Int(password.chars().count() as i128), Value::Str(password)])?;
        }
        Ok(())
    }
}
