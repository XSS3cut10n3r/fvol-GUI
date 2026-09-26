//! yarascan.YaraScan (python `plugins/yarascan.py`) and python's `YaraScanner` layer scanner.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::layers::scan::{Scanner, scan};
use crate::layers::{Layer, LayerExt};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::yara::rules::Rules;
use crate::yara::rules::volatility::{Hit, process_yara_options, scanner_hits};

pub struct YaraScan;

/// python `YaraScan.get_yarascan_option_requirements()` (shared with windows.vadyarascan /
/// linux.vmayarascan).
pub fn yarascan_option_requirements() -> Vec<Requirement> {
    vec![
        Requirement::flag("insensitive", "Makes the search case insensitive"),
        Requirement::flag("wide", "Match wide (unicode) strings"),
        Requirement::new("yara_string", "Yara rules (as a string)", ReqKind::Str).optional(),
        Requirement::new("yara_file", "Yara rules (as a file)", ReqKind::Uri).optional(),
        Requirement::new("yara_compiled_file", "Yara compiled rules (as a file)", ReqKind::Uri).optional(),
        Requirement::new("max_size", "Set the maximum size (default is 1GB)", ReqKind::Int)
            .optional()
            .default(ConfigValue::Int(0x40000000)),
    ]
}

/// python `YaraScan.process_yara_options(dict(self.config))` for a plugin config: `Ok(None)` when
/// no rules were given (python logs an error and returns None). A rule file is read like
/// python's `ResourceAccessor().open(...)` (file:// URIs and plain paths); a compile error or
/// an unreadable file is python's uncaught exception (we panic with its text).
pub fn rules_from_config(cfg: &Config) -> Option<Rules> {
    let file_src = if cfg.get_str("yara_string").is_none() {
        cfg.get_str("yara_file").map(|u| {
            let path = crate::util::paths::file_uri_to_path(u).unwrap_or_else(|| std::path::PathBuf::from(u));
            std::fs::read(&path).unwrap_or_else(|e| panic!("FileNotFoundError: {e}: '{u}'"))
        })
    } else {
        None
    };
    if cfg.get_str("yara_string").is_none() && file_src.is_none() {
        if let Some(u) = cfg.get_str("yara_compiled_file") {
            // yara.load(file=...) of a compiled rules file: not supported by the yara engine
            panic!("yara.Error: could not load compiled rules from {u} (unsupported)");
        }
    }
    match process_yara_options(cfg.get_str("yara_string"), file_src.as_deref(), cfg.get_bool("insensitive"), cfg.get_bool("wide")) {
        Ok(r) => r,
        Err(e) => panic!("yara.SyntaxError: {e}"),
    }
}

/// python `YaraScanner(rules)` as a layer scanner: every instance of every matching string of
/// every matching rule in the chunk's data, INCLUDING the overlap (python applies no
/// `chunk_size` filter here, so matches in a chunk's overlap are reported twice).
pub struct YaraScanner<'a> {
    pub rules: &'a Rules,
}

impl Scanner for YaraScanner<'_> {
    type Hit = Hit;
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<Hit>) {
        hits.extend(scanner_hits(self.rules, data, data_offset));
    }
}

/// python `renderers.LayerData(context, layer_name, offset, length)` as the CLI's
/// `LayerDataRenderer.render_bytes` sees it (no surrounding context bytes): the padded read and
/// the "error" byte indices, computed with python's exact (quirky) walk over
/// `layer.mapping(start, end, ignore_errors=True)` for translation layers.
pub fn layer_data_value(layer: &dyn Layer, offset: u64, length: u64) -> Value {
    let start = offset;
    let end = offset.wrapping_add(length);
    let mut errors = Vec::new();
    if layer.lower().is_some() && end > start {
        // python walks `layer.mapping(start, end_offset)` (the END passed as the length) but
        // only pulls the next run while `i > offset + sublength` for some i < end: the runs
        // inside [start, end) give the same answer (a run cut at `end` is never left early).
        let mut runs: Vec<(u64, u64)> = Vec::new();
        layer.mapping(start, length, &mut |m| {
            runs.push((m.offset, m.len));
            true
        });
        let mut it = runs.into_iter();
        // no run inside [start, end): python's first run starts beyond `end` (every byte is an
        // error byte)
        let mut cur = it.next().unwrap_or((end, 0));
        for i in start..end {
            let (o, l) = cur;
            if i < o {
                errors.push((i - start) as u32);
            }
            if i > o.wrapping_add(l) {
                if let Some(n) = it.next() {
                    cur = n;
                }
            }
            let (o, l) = cur;
            if i > o.wrapping_add(l) {
                errors.push((i - start) as u32);
            }
        }
    }
    let data = layer.read_vec_padded(start, length as usize);
    Value::LayerBytes { data, errors }
}

impl Plugin for YaraScan {
    fn name(&self) -> &'static str {
        "yarascan.YaraScan"
    }
    fn description(&self) -> &'static str {
        "Scans kernel memory using yara rules (string or file)."
    }
    fn requirements(&self) -> Vec<Requirement> {
        yarascan_option_requirements()
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let p = super::primary::primary_intel(ctx, "Memory layer for the kernel")?;
        out.begin(vec![
            Column::new("Offset", ColType::Hex),
            Column::new("Rule", ColType::Str),
            Column::new("Component", ColType::Str),
            Column::new("Value", ColType::LayerData),
        ])?;
        // python: `YaraScanner(rules=None)` raises ValueError("No rules provided to YaraScanner")
        let rules = rules_from_config(cfg).unwrap_or_else(|| panic!("ValueError: No rules provided to YaraScanner"));
        for (offset, rule, name, value) in scan(p.layer, &YaraScanner { rules: &rules }, None) {
            let v = layer_data_value(p.layer, offset, value.len() as u64);
            out.row(0, vec![Value::Int(offset as i128), Value::Str(rule), Value::Str(name), v])?;
        }
        Ok(())
    }
}
