//! python configuration trees of stacked layers and kernel modules: what
//! `requirement.build_configuration()` (and, for `--extra`, `context.config`) contains after the
//! automagics ran. Used by configwriter and `timeliner --record-config`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Items are `(dotted key, value)` in python's `HierarchicalDict` iteration order (a level's
//! leaves in insertion order, then its sub-dicts); the key orders below were taken from python
//! runs on raw (Windows, macOS), ELF core and LiME images.

use super::primary::{Primary, PrimaryOs};
use crate::cli::json::Json;
use crate::context::Context;
use crate::error::Result;

pub type Items = Vec<(String, Json)>;

/// Full python class path of a layer class name.
pub fn layer_class_path(class: &str) -> String {
    let module = match class {
        "FileLayer" | "BufferDataLayer" => "physical",
        "Elf64Layer" => "elf",
        "LimeLayer" => "lime",
        "AVMLLayer" => "avml",
        "QemuSuspendLayer" => "qemu",
        "VmwareLayer" => "vmware",
        "WindowsCrashDump32Layer" | "WindowsCrashDump64Layer" => "crash",
        "XenCoreDumpLayer" => "xen",
        "SegmentedLayer" | "NonLinearlySegmentedLayer" => "segmented",
        "RegistryHive" => "registry",
        c if c.contains("Intel") => "intel",
        _ => "physical",
    };
    format!("volatility3.framework.layers.{module}.{class}")
}

fn s(v: impl Into<String>) -> Json {
    Json::Str(v.into())
}

/// The physical (container) layer stack below an Intel layer, at `prefix` (e.g.
/// `"primary.memory_layer"`). `extra` = `context.config` form (layer names as values, the ELF
/// layer's own symbol table).
pub fn container_tree(ctx: &Context, prefix: &str, extra: bool) -> Result<Items> {
    let listing = ctx.physical_listing()?.to_vec();
    let location = ctx.opts.single_location.clone().unwrap_or_default();
    let mut out = Items::new();
    fn rec(listing: &[crate::layers::containers::StackEntry], i: usize, prefix: &str, extra: bool, location: &str, out: &mut Items) {
        let e = &listing[i];
        if e.class == "FileLayer" {
            out.push((format!("{prefix}.location"), s(location)));
            out.push((format!("{prefix}.class"), s(layer_class_path(e.class))));
            return;
        }
        out.push((format!("{prefix}.class"), s(layer_class_path(e.class))));
        // children: the following entries one level deeper, up to the next sibling
        let mut kids = Vec::new();
        let mut j = i + 1;
        while j < listing.len() && listing[j].depth > e.depth {
            if listing[j].depth == e.depth + 1 {
                kids.push(j);
            }
            j += 1;
        }
        if extra {
            for &k in &kids {
                out.push((format!("{prefix}.{}", listing[k].name), s(listing[k].name.clone())));
            }
            if e.class == "Elf64Layer" {
                let url = crate::symbols::symbol_path().find("linux", "elf").first().map(|l| l.url()).unwrap_or_default();
                out.push((format!("{prefix}.isf_url"), s(url)));
                out.push((format!("{prefix}.symbol_mask"), Json::Int(0)));
            }
        }
        for &k in &kids {
            rec(listing, k, &format!("{prefix}.{}", listing[k].name), extra, location, out);
        }
    }
    if !listing.is_empty() {
        rec(&listing, 0, prefix, extra, &location, &mut out);
    }
    Ok(out)
}

/// (page_map_offset, kernel_virtual_offset, kernel_banner) of the primary Intel layer as
/// python's OS stackers record them.
fn intel_params(ctx: &Context, p: &Primary) -> Result<(u64, Option<u64>, Option<String>)> {
    let latin1 = |b: &[u8]| b.iter().map(|&c| c as char).collect::<String>();
    Ok(match p.os {
        PrimaryOs::Linux => {
            let k = ctx.linux_kernel()?;
            (k.dtb, Some(k.aslr_shift), Some(latin1(&k.banner)))
        }
        PrimaryOs::Mac => {
            let k = ctx.mac_kernel()?;
            (k.dtb, Some(k.kaslr_shift), Some(latin1(&k.banner)))
        }
        PrimaryOs::Windows => (ctx.windows_kernel()?.dtb, None, None),
        PrimaryOs::None => (0, None, None),
    })
}

/// A `TranslationLayerRequirement`'s tree at `prefix` (python `build_configuration()` order, or
/// `context.config` order with `extra`), with the WinSwapLayers keys when `swap`.
pub fn primary_tree(ctx: &Context, p: &Primary, prefix: &str, extra: bool, swap: bool) -> Result<Items> {
    let mut out = Items::new();
    let Some(intel) = p.intel else {
        // no OS layer: the top container layer is the primary layer itself
        return container_tree(ctx, prefix, extra);
    };
    let (dtb, kvo, banner) = intel_params(ctx, p)?;
    let class = s(layer_class_path(crate::layers::Layer::class_name(intel)));
    let nswap = ctx.opts.swap_locations.len() as i128;
    if !extra && swap {
        out.push((format!("{prefix}.swap_layers"), Json::Bool(true)));
    }
    out.push((format!("{prefix}.page_map_offset"), Json::Int(dtb as i128)));
    if let Some(k) = kvo {
        out.push((format!("{prefix}.kernel_virtual_offset"), Json::Int(k as i128)));
    }
    if let Some(b) = banner {
        out.push((format!("{prefix}.kernel_banner"), s(b)));
    }
    out.push((format!("{prefix}.class"), class));
    if extra {
        out.push((format!("{prefix}.memory_layer"), s("memory_layer")));
        if swap {
            out.push((format!("{prefix}.swap_layers"), Json::Bool(true)));
        }
    }
    out.extend(container_tree(ctx, &format!("{prefix}.memory_layer"), extra)?);
    if swap {
        out.push((format!("{prefix}.swap_layers.number_of_elements"), Json::Int(nswap)));
    }
    Ok(out)
}

/// A plugin's `ModuleRequirement("kernel")` tree at `prefix` (`"<Class>.kernel"`) for the OS
/// named by the plugin (`windows.*`, `linux.*`, `mac.*`).
pub fn kernel_tree(ctx: &Context, plugin: &str, prefix: &str) -> Result<Items> {
    let mut out = Items::new();
    out.push((format!("{prefix}.class"), s("volatility3.framework.contexts.Module")));
    let l = format!("{prefix}.layer_name");
    let (layer, dtb, kvo, banner, offset, table, sym_class, swap) = if plugin.starts_with("linux.") {
        let k = ctx.linux_kernel()?;
        (k.layer, k.dtb, k.aslr_shift, Some(k.banner.clone()), k.aslr_shift, k.table, "linux.LinuxKernelIntermedSymbols", false)
    } else if plugin.starts_with("mac.") {
        let k = ctx.mac_kernel()?;
        (k.layer, k.dtb, k.kaslr_shift, Some(k.banner.clone()), k.kaslr_shift, k.table, "mac.MacKernelIntermedSymbols", false)
    } else {
        let k = ctx.windows_kernel()?;
        (k.layer, k.dtb, k.base, None, k.base, k.table, "windows.WindowsKernelIntermedSymbols", true)
    };
    out.push((format!("{l}.class"), s(layer_class_path(crate::layers::Layer::class_name(layer)))));
    let banner_ident = banner.clone();
    if let Some(b) = banner {
        out.push((format!("{l}.kernel_banner"), s(b.iter().map(|&c| c as char).collect::<String>())));
    }
    out.push((format!("{l}.kernel_virtual_offset"), Json::Int(kvo as i128)));
    out.extend(container_tree(ctx, &format!("{l}.memory_layer"), false)?);
    out.push((format!("{l}.page_map_offset"), Json::Int(dtb as i128)));
    if swap {
        out.push((format!("{l}.swap_layers"), Json::Bool(true)));
        out.push((format!("{l}.swap_layers.number_of_elements"), Json::Int(ctx.opts.swap_locations.len() as i128)));
    }
    out.push((format!("{prefix}.offset"), Json::Int(offset as i128)));
    out.push((format!("{prefix}.symbol_table_name.class"), s(format!("volatility3.framework.symbols.{sym_class}"))));
    // Linux/Mac kernels are found by banner through python's identifier cache: among several
    // ISFs with the same banner python takes the one its SQLite cache lists last
    let mut url = table.isf_url().to_string();
    if let Some(b) = &banner_ident {
        if let Some(loc) = super::isfinfo::python_identifier_location(ctx, b) {
            url = loc;
        }
    }
    out.push((format!("{prefix}.symbol_table_name.isf_url"), s(url)));
    out.push((format!("{prefix}.symbol_table_name.symbol_mask"), Json::Int(table.symbol_mask() as i128)));
    Ok(out)
}

/// A configuration value as python's `json.dump` writes it.
pub fn config_value_json(v: &crate::plugins::ConfigValue) -> Json {
    use crate::plugins::ConfigValue;
    match v {
        ConfigValue::Bool(b) => Json::Bool(*b),
        ConfigValue::Int(i) => Json::Int(*i),
        ConfigValue::Str(x) => s(x.clone()),
        ConfigValue::Bytes(b) => s(String::from_utf8_lossy(b).into_owned()),
        ConfigValue::List(l) => Json::Arr(l.iter().map(config_value_json).collect()),
    }
}

/// python `plugin.build_configuration()` after the automagics ran, keys under `prefix` (`""`
/// for `--save-config`, `"<Class>."` for `timeliner --record-config`). Walks the plugin's python
/// requirement list (`pyreqs`): the kernel module and translation layers as their configuration
/// trees, version dependencies as `false`, lists as their value or `[]`, every other option when
/// it has a value (given or defaulted). Fails like python's construction when the kernel or the
/// layer cannot be found.
pub fn build_configuration(ctx: &Context, plugin: &str, cfg: &crate::plugins::Config, prefix: &str) -> Result<Items> {
    let mut out = Items::new();
    for r in crate::plugins::pyreqs::py_reqs(plugin).unwrap_or(&[]) {
        let (kind, name) = r.split_once(':').unwrap_or(("?", r));
        let key = format!("{prefix}{name}");
        match kind {
            "K" => out.extend(kernel_tree(ctx, plugin, &key)?),
            "P" => {
                let prim = super::primary::primary(ctx, "Memory layer for the kernel")?;
                // the WinSwapLayers automagic (swap_layers) is excluded for linux / mac plugins
                let swap = !(plugin.starts_with("linux.") || plugin.starts_with("mac."));
                out.extend(primary_tree(ctx, &prim, &key, false, swap)?);
            }
            "v" => out.push((key, Json::Bool(false))),
            "l" => out.push((key, cfg.get(name).map(config_value_json).unwrap_or(Json::Arr(Vec::new())))),
            _ => {
                if let Some(v) = cfg.get(name) {
                    out.push((key, config_value_json(v)));
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::{Config, ConfigValue};

    #[test]
    fn py_reqs_sorted_and_cover_every_plugin() {
        let t = &crate::plugins::pyreqs::PY_REQS;
        assert!(t.windows(2).all(|w| w[0].0 < w[1].0), "PY_REQS must stay sorted for the binary search");
        for p in crate::plugins::all() {
            assert!(crate::plugins::pyreqs::py_reqs(p.name()).is_some(), "{} has no python requirement list", p.name());
        }
    }

    /// python's `--save-config` for `isfinfo.IsfInfo --filter linux`: version dependencies are
    /// `false`, booleans always recorded, an unset URI left out (rsvol used to write only the
    /// options it knows, so `-c` could not find the image again).
    #[test]
    fn build_configuration_records_like_python() {
        let ctx = Context::new(Default::default()).unwrap();
        let mut cfg = Config::default();
        cfg.set("filter", ConfigValue::List(vec![ConfigValue::Str("linux".into())]));
        cfg.set("validate", ConfigValue::Bool(false));
        cfg.set("live", ConfigValue::Bool(false));
        let items = build_configuration(&ctx, "isfinfo.IsfInfo", &cfg, "").unwrap();
        assert_eq!(
            Json::Obj(items).dump(Some(2)),
            "{\n  \"SQLiteCache\": false,\n  \"filter\": [\n    \"linux\"\n  ],\n  \"live\": false,\n  \"validate\": false\n}"
        );
        // an unset list is recorded as []
        let items = build_configuration(&ctx, "isfinfo.IsfInfo", &Config::default(), "x.").unwrap();
        assert!(items.contains(&("x.filter".to_string(), Json::Arr(Vec::new()))));
    }
}
