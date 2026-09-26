//! configwriter.ConfigWriter (python `plugins/configwriter.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use super::pyconfig::{Items, primary_tree};
use crate::cli::json::Json;
use crate::context::Context;
use crate::error::Result;
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use std::io::Write;

pub struct ConfigWriter;

/// python's LayerStacker stacker order (`automagic.LayerStacker.stackers`).
pub const STACKERS: [&str; 11] = [
    "AVMLStacker",
    "Elf64Stacker",
    "XenCoreDumpStacker",
    "LimeStacker",
    "QemuStacker",
    "WindowsCrashDumpStacker",
    "VmwareStacker",
    "LinuxIntelVMCOREINFOStacker",
    "LinuxIntelStacker",
    "MacIntelStacker",
    "WindowsIntelStacker",
];

impl Plugin for ConfigWriter {
    fn name(&self) -> &'static str {
        "configwriter.ConfigWriter"
    }
    fn description(&self) -> &'static str {
        "Runs the automagics and both prints and outputs configuration in the output directory."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::flag("extra", "Outputs whole configuration tree")]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let p = super::primary::primary(ctx, "Memory layer for the kernel")?;
        let extra = cfg.get_bool("extra");
        let mut items = Items::new();
        let filename = if extra {
            let loc = ctx.opts.single_location.clone().unwrap_or_default();
            let stackers: Vec<Json> = match &ctx.opts.stackers {
                Some(l) if !l.is_empty() => l.iter().map(|x| Json::Str(x.clone())).collect(),
                _ => STACKERS.iter().map(|x| Json::Str(x.to_string())).collect(),
            };
            items.push(("automagic.LayerStacker.single_location".into(), Json::Str(loc)));
            items.push(("automagic.LayerStacker.stackers".into(), Json::Arr(stackers)));
            items.push(("plugins.ConfigWriter.extra".into(), Json::Bool(true)));
            items.push(("plugins.ConfigWriter.primary".into(), Json::Str("primary".into())));
            items.extend(primary_tree(ctx, &p, "plugins.ConfigWriter.primary", true, true)?);
            "config.extra"
        } else {
            items.push(("extra".into(), Json::Bool(false)));
            items.extend(primary_tree(ctx, &p, "primary", false, true)?);
            "config.json"
        };
        out.begin(vec![Column::new("Key", ColType::Str), Column::new("Value", ColType::Str)])?;
        // json.dumps(config, sort_keys=True, indent=2) (python logs a warning on failure)
        if let Ok((mut f, _)) = ctx.create_output_file(filename) {
            let _ = f.write_all(Json::Obj(items.clone()).dump(Some(2)).as_bytes());
        }
        for (k, v) in items {
            out.row(0, vec![Value::Str(k), Value::Str(v.dump(None))])?;
        }
        Ok(())
    }
}
