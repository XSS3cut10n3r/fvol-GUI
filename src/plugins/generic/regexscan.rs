//! regexscan.RegExScan (python `plugins/regexscan.py`) and python's `scanners.RegExScanner`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::layers::LayerExt;
use crate::layers::scan::{DEFAULT_CHUNK_SIZE, Scanner, scan};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::yara::regex::{Flags, Regex};

pub struct RegExScan;

/// python `RegExScan.MAXSIZE_DEFAULT`.
pub const MAXSIZE_DEFAULT: i128 = 128;

/// python `layers.scanners.RegExScanner(pattern, flags=re.DOTALL)`: the start of every
/// `re.finditer` match that begins in the chunk's first `chunk_size` bytes (hit = layer
/// address). Two-phase (the search depends only on the chunk bytes), so pages mapped at several
/// virtual addresses are searched once.
pub struct RegExScanner {
    pub regex: Regex,
}

impl RegExScanner {
    /// `RegExScanner(pattern)` (python compiles with `re.DOTALL`). Err = python's `re.error`.
    pub fn new(pattern: &[u8]) -> std::result::Result<RegExScanner, crate::yara::regex::Error> {
        Ok(RegExScanner { regex: Regex::new(pattern, Flags::S)? })
    }
}

impl Scanner for RegExScanner {
    type Hit = u64;
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<u64>) {
        for (s, _) in self.regex.find_iter(data) {
            if s as u64 >= DEFAULT_CHUNK_SIZE {
                break;
            }
            hits.push(data_offset + s as u64);
        }
    }
    fn prescan(&self, data: &[u8], out: &mut Vec<(u64, u32)>) -> bool {
        for (s, _) in self.regex.find_iter(data) {
            if s as u64 >= DEFAULT_CHUNK_SIZE {
                break;
            }
            out.push((s as u64, 0));
        }
        true
    }
    fn finish(&self, matches: &[(u64, u32)], data_offset: u64, hits: &mut Vec<u64>) {
        hits.extend(matches.iter().map(|&(o, _)| data_offset + o));
    }
}

/// python `str(b, encoding="UTF-8", errors="replace")`.
fn utf8_replace(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

impl Plugin for RegExScan {
    fn name(&self) -> &'static str {
        "regexscan.RegExScan"
    }
    fn description(&self) -> &'static str {
        "Scans kernel memory using RegEx patterns."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new("pattern", "RegEx pattern", ReqKind::Str),
            Requirement::new("maxsize", "Maximum size in bytes for displayed context", ReqKind::Int)
                .optional()
                .default(ConfigValue::Int(MAXSIZE_DEFAULT)),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let p = super::primary::primary_intel(ctx, "Memory layer for the kernel")?;
        let pattern = cfg.get_str("pattern").unwrap_or("").as_bytes().to_vec();
        let maxsize = cfg.get_int("maxsize").unwrap_or(MAXSIZE_DEFAULT);
        out.begin(vec![Column::new("Offset", ColType::Hex), Column::new("Text", ColType::Str), Column::new("Hex", ColType::Bytes)])?;
        // python compiles the plain pattern first (re.error -> ValueError, an uncaught python
        // exception after the header was rendered)
        let compiled = match Regex::new(&pattern, 0) {
            Ok(r) => r,
            Err(e) => panic!("ValueError: Invalid regex pattern: {}", e.py_str(&pattern)),
        };
        let scanner = RegExScanner::new(&pattern).unwrap_or_else(|e| panic!("re.PatternError: {}", e.py_str(&pattern)));
        // python `layer.read(offset, maxsize, pad=True)`: a negative size raises in python
        let maxsize = usize::try_from(maxsize).unwrap_or_else(|_| panic!("ValueError: negative maxsize"));
        for offset in scan(p.layer, &scanner, None) {
            let data = p.layer.read_vec_padded(offset, maxsize);
            let m = match compiled.search(&data, 0) {
                Some((s, e)) => data[s..e].to_vec(),
                None => data,
            };
            out.row(0, vec![Value::Int(offset as i128), Value::Str(utf8_replace(&m)), Value::Bytes(m)])?;
        }
        Ok(())
    }
}
