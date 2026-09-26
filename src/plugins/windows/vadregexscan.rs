//! windows.vadregexscan.VadRegExScan (python `plugins/windows/vadregexscan.py`): a python `re`
//! regex scan over every process' VADs.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::scan::{DEFAULT_CHUNK_SIZE, FnScanner, scan};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::prelude::*;
use crate::yara::regex::{Flags, Regex};

pub struct VadRegExScan;

/// python `VadRegExScan.MAXSIZE_DEFAULT` (the bytes read at each hit; the `maxsize` option is
/// not used by python).
const MAXSIZE_DEFAULT: usize = 128;

/// python `scanners.RegExScanner(pattern)` (`re.DOTALL`): hits of `finditer` starting before
/// `chunk_size` in each chunk.
pub fn regex_scanner(re: &Regex) -> FnScanner<u64, impl Fn(&[u8], u64, &mut Vec<u64>) + Sync + '_> {
    FnScanner::new(move |data: &[u8], off: u64, out: &mut Vec<u64>| {
        for (s, _) in re.find_iter(data) {
            if s as u64 >= DEFAULT_CHUNK_SIZE {
                break;
            }
            out.push(off + s as u64);
        }
    })
}

impl Plugin for VadRegExScan {
    fn name(&self) -> &'static str {
        "windows.vadregexscan.VadRegExScan"
    }
    fn description(&self) -> &'static str {
        "Scans all virtual memory areas for tasks using RegEx."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pid", "Filter on specific process IDs", ReqKind::ListInt).optional(),
            Requirement::new("pattern", "RegEx pattern", ReqKind::Str),
            Requirement::new("maxsize", "Maximum size in bytes for displayed context", ReqKind::Int)
                .optional()
                .default(ConfigValue::Int(MAXSIZE_DEFAULT as i128)),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("PID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("Offset", ColType::Hex),
            Column::new("Text", ColType::Str),
            Column::new("Hex", ColType::Bytes),
        ])?;
        let k = ctx.windows_kernel()?;
        let pids = cfg.get_ints("pid");
        let pattern = cfg.get_str("pattern").unwrap_or("").as_bytes().to_vec();
        // compiled lazily at the first scanned process, like python's RegExScanner
        let mut compiled: Option<(Regex, Regex)> = None;
        for proc in crate::plugins::windows::pslist::list_processes(k, &crate::plugins::windows::pslist::pid_filter(&pids)) {
            let proc = proc?;
            let layer = proc.add_process_layer()?;
            let mut sections = Vec::new();
            for vad in proc.get_vad_root()?.traverse() {
                let vad = vad?;
                let base = vad.get_start()?;
                if vad.get_size()? != 0 {
                    sections.push((base, vad.get_size()?));
                }
            }
            if compiled.is_none() {
                let scan_re = Regex::new(&pattern, Flags::S).map_err(|e| Error::msg(format!("re.error: {}", e.msg)))?;
                let match_re = Regex::new(&pattern, 0).map_err(|e| Error::msg(format!("re.error: {}", e.msg)))?;
                compiled = Some((scan_re, match_re));
            }
            let (scan_re, match_re) = compiled.as_ref().unwrap();
            let hits = scan(layer, &regex_scanner(scan_re), Some(&sections));
            let mut data = [0u8; MAXSIZE_DEFAULT];
            for offset in hits {
                layer.read_padded(offset, &mut data);
                let bytes = match match_re.match_at(&data, 0) {
                    Some((s, e)) => data[s..e].to_vec(),
                    None => data.to_vec(),
                };
                let text = crate::objects::strings::decode_utf8(&bytes, crate::symbols::StrErrors::Replace)?;
                out.row(
                    0,
                    vec![
                        Value::Int(proc.m("UniqueProcessId")?.int()?),
                        Value::Str(proc.image_file_name_str()?),
                        Value::Int(offset as i128),
                        Value::Str(text),
                        Value::Bytes(bytes),
                    ],
                )?;
            }
        }
        Ok(())
    }
}
