//! windows.registry.certificates.Certificates (python `plugins/windows/registry/
//! certificates.py`): lists certificates from the registry's SystemCertificates stores.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::registry::is_invalid_or_registry;
use crate::plugins::windows::registry::printkey::key_iterator;
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::registry::{RegData, RegExt, RegValueType, is_key_error};
use std::io::Write;

pub struct Certificates;

const TOP_KEYS: [&str; 2] = ["Microsoft\\SystemCertificates", "Software\\Microsoft\\SystemCertificates"];

/// python `Certificates.parse_data(data)`: (name, certificate_data).
fn parse_data(mut data: &[u8]) -> Result<(Value, Option<Vec<u8>>)> {
    let mut name = Value::NotAvailable;
    let mut cert = None;
    while data.len() > 12 {
        let ctype = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let clen = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let end = (12 + clen).min(data.len());
        let cvalue = &data[12..end];
        if ctype == 0x1_0000_000B {
            name = Value::Str(decode_utf16_bom(cvalue)?.trim_matches('\0').to_string());
        } else if ctype == 0x1_0000_0020 {
            cert = Some(cvalue.to_vec());
        }
        data = &data[end..];
    }
    Ok((name, cert))
}

/// python `str(bytes, "utf-16")`: BOM-aware (defaults to little-endian without a BOM).
fn decode_utf16_bom(data: &[u8]) -> Result<String> {
    let (le, body) = match data {
        [0xFF, 0xFE, rest @ ..] => (true, rest),
        [0xFE, 0xFF, rest @ ..] => (false, rest),
        _ => (true, data),
    };
    if body.len() % 2 != 0 {
        return Err(Error::msg("UnicodeDecodeError: truncated data"));
    }
    let units: Vec<u16> = body.chunks_exact(2).map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) }).collect();
    char::decode_utf16(units).collect::<std::result::Result<String, _>>().map_err(|_| Error::msg("UnicodeDecodeError"))
}

/// ascii casefold index (registry paths are ascii; matches python's `casefold().index`).
fn ci_index(haystack: &str, needle: &str) -> Option<usize> {
    haystack.to_lowercase().find(&needle.to_lowercase())
}

/// One certificate row and, with `--dump`, its file (name, certificate data).
struct CertRow {
    values: Vec<Value>,
    dump: Option<(String, Vec<u8>)>,
}

/// python `_generator`'s rows for one hive, and the error python raised after them.
fn hive_rows(hive: &'static crate::layers::registry::RegistryHive, dump: bool) -> (Vec<CertRow>, Option<Error>) {
    let mut rows = Vec::new();
    for top_key in TOP_KEYS {
        let node_path = match hive.get_key(top_key) {
            Ok(p) => p,
            Err(e) if is_key_error(&e) || is_invalid_or_registry(&e) => continue,
            Err(e) => return (rows, Some(e)),
        };
        let r = key_iterator(hive, &node_path, true, &mut |it| {
            if it.is_key {
                return Ok(true);
            }
            let is_binary = matches!(it.node.get_value_type(), Ok(RegValueType::Binary));
            if !is_binary {
                return Ok(true);
            }
            let data = match it.node.decode_data()? {
                RegData::Bytes(b) => b,
                RegData::Int(_) => Vec::new(),
            };
            let (name, cert_data) = parse_data(&data)?;
            let kp = it.key_path;
            let uko = match ci_index(kp, top_key) {
                Some(i) => i + top_key.len() + 1,
                None => return Ok(true),
            };
            let reg_section = match kp[uko..].find('\\') {
                Some(rel) => &kp[uko..uko + rel],
                None => &kp[uko..],
            };
            let key_hash = kp.rsplit('\\').next().unwrap_or("");
            let dump = match (dump, cert_data) {
                (true, Some(cd)) => Some((format!("{}-{}-{}.crt", hive.hive_offset(), reg_section, key_hash), cd)),
                _ => None,
            };
            rows.push(CertRow { values: vec![Value::SStr(top_key), Value::Str(reg_section.to_string()), Value::Str(key_hash.to_string()), name], dump });
            Ok(true)
        });
        match r {
            Ok(_) => {}
            Err(e) if is_key_error(&e) || is_invalid_or_registry(&e) => continue,
            Err(e) => return (rows, Some(e)),
        }
    }
    (rows, None)
}

impl Plugin for Certificates {
    fn name(&self) -> &'static str {
        "windows.registry.certificates.Certificates"
    }
    fn description(&self) -> &'static str {
        "Lists the certificates in the registry's Certificate Store."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::flag("dump", "Extract listed certificates")]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Certificate path", ColType::Str),
            Column::new("Certificate section", ColType::Str),
            Column::new("Certificate ID", ColType::Str),
            Column::new("Certificate name", ColType::Str),
        ])?;
        let k = ctx.windows_kernel()?;
        let dump = cfg.get_bool("dump");
        // the hives in parallel; rows (and --dump files) in python's order
        for item in super::hivelist::list_hives_map(ctx, k, None, None, |hive| hive_rows(hive, dump)) {
            let (rows, err) = item?;
            for r in rows {
                if let Some((dump_name, data)) = r.dump {
                    if let Ok((mut f, _)) = ctx.create_output_file(&dump_name) {
                        let _ = f.write_all(&data);
                        let _ = f.flush();
                    }
                }
                out.row(0, r.values)?;
            }
            if let Some(e) = err {
                return Err(e);
            }
        }
        Ok(())
    }
}
