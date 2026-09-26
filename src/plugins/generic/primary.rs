//! The `primary` layer of the generic plugins: python's
//! `TranslationLayerRequirement(name="primary", ...)` as satisfied by the LayerStacker automagic.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! python stacks the container layers (LiME, ELF core, crash dump, ...) on the input file and
//! then tries the OS stackers in `stack_order` (`LinuxIntelVMCOREINFOStacker`,
//! `LinuxIntelStacker`, `MacIntelStacker`, `WindowsIntelStacker`); the first that succeeds puts
//! an Intel translation layer (named after the requirement, `"primary"`) on top. When none
//! succeeds the top container layer is the primary layer. rsvol's `Context` already runs each
//! OS discovery lazily and caches it per image, so this just asks them in python's order.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::IntelLayer;
use crate::objects::LayerRef;

/// Which OS stacker produced the primary layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrimaryOs {
    Linux,
    Mac,
    Windows,
    /// no OS stacker succeeded: the primary layer is the physical (container) layer
    None,
}

/// The stacked `primary` layer.
#[derive(Clone, Copy)]
pub struct Primary {
    /// The top layer (the OS Intel layer, else the physical layer).
    pub layer: LayerRef,
    /// The Intel layer when an OS stacker succeeded.
    pub intel: Option<&'static IntelLayer>,
    /// python `memory_layer` (the layer below the Intel layer / the top container layer).
    pub phys: LayerRef,
    pub os: PrimaryOs,
    /// python class of the stacker that built the Intel layer (`"WindowsIntelStacker"`, ...).
    pub stacker: Option<&'static str>,
}

/// python's unsatisfied `primary` requirement (the CLI prints
/// `Unsatisfied requirement plugins.<Class>.primary: <description>`).
pub fn unsatisfied(description: &str) -> Error {
    crate::plugins::unsatisfied_described(&[("primary", crate::plugins::UnsatKind::Layer, description)])
}

/// Only the physical layer (python plugins that immediately step down to `memory_layer`, e.g.
/// banners / vmscan): no OS discovery is run. `description` is the requirement's description.
pub fn physical(ctx: &Context, description: &str) -> Result<LayerRef> {
    ctx.physical().map_err(|_| unsatisfied(description))
}

/// `TranslationLayerRequirement(name="primary", architectures=["Intel32", "Intel64"])`: only an
/// Intel layer satisfies it (configwriter, regexscan, yarascan).
pub fn primary_intel(ctx: &Context, description: &str) -> Result<Primary> {
    let p = primary(ctx, description)?;
    if p.intel.is_none() {
        return Err(unsatisfied(description));
    }
    Ok(p)
}

/// Per-image cache of "this OS stacker found nothing" (the core caches only successful
/// discoveries), keyed like the core's caches by the ISF search path fingerprint of that OS
/// and `--stackers`, so e.g. a Windows image does not pay for the Linux/Mac banner scans on
/// every run.
fn absent_kind(ctx: &Context, os: &str) -> String {
    let mut k = format!("absent-{os}-{}", ctx.symbol_path().os_fingerprint(os));
    if let Some(s) = &ctx.opts.stackers {
        k.push('-');
        k.push_str(&crate::util::paths::hex(s.join("\0").as_bytes()));
    }
    k
}

fn known_absent(ctx: &Context, os: &str) -> bool {
    ctx.image_path().ok().is_some_and(|img| crate::automagic::cache::load(&img, &absent_kind(ctx, os)).is_some())
}

fn mark_absent(ctx: &Context, os: &str, e: &Error) {
    if matches!(e, Error::Unsatisfied(_)) {
        if let Ok(img) = ctx.image_path() {
            crate::automagic::cache::store(&img, &absent_kind(ctx, os), &[("absent", "1".to_string())]);
        }
    }
}

/// The stacked primary layer (runs the OS discoveries in python's stacker order).
pub fn primary(ctx: &Context, description: &str) -> Result<Primary> {
    let phys = physical(ctx, description)?;
    if !known_absent(ctx, "linux") {
        match ctx.linux_kernel() {
            Ok(k) => return Ok(Primary { layer: k.vlayer, intel: Some(k.layer), phys, os: PrimaryOs::Linux, stacker: Some(k.stacker) }),
            Err(e) => mark_absent(ctx, "linux", &e),
        }
    }
    if !known_absent(ctx, "mac") {
        match ctx.mac_kernel() {
            Ok(k) => return Ok(Primary { layer: k.vlayer, intel: Some(k.layer), phys, os: PrimaryOs::Mac, stacker: Some("MacIntelStacker") }),
            Err(e) => mark_absent(ctx, "mac", &e),
        }
    }
    if let Ok(k) = ctx.windows_kernel() {
        return Ok(Primary { layer: k.vlayer, intel: Some(k.layer), phys, os: PrimaryOs::Windows, stacker: Some("WindowsIntelStacker") });
    }
    Ok(Primary { layer: phys, intel: None, phys, os: PrimaryOs::None, stacker: None })
}

/// The primary layer of a plugin of python category `category` (`"windows"`, `"linux"`,
/// `"mac"`, else generic): python's `choose_os_stackers(plugin)` leaves only that OS's stackers
/// (all of them for a generic plugin).
pub fn primary_for_category(ctx: &Context, category: &str, description: &str) -> Result<Primary> {
    let phys = physical(ctx, description)?;
    let found = match category {
        "windows" => ctx.windows_kernel().ok().map(|k| (k.vlayer, k.layer, PrimaryOs::Windows, "WindowsIntelStacker")),
        "linux" => ctx.linux_kernel().ok().map(|k| (k.vlayer, k.layer, PrimaryOs::Linux, k.stacker)),
        "mac" => ctx.mac_kernel().ok().map(|k| (k.vlayer, k.layer, PrimaryOs::Mac, "MacIntelStacker")),
        _ => return primary(ctx, description),
    };
    Ok(match found {
        Some((layer, intel, os, stacker)) => Primary { layer, intel: Some(intel), phys, os, stacker: Some(stacker) },
        None => Primary { layer: phys, intel: None, phys, os: PrimaryOs::None, stacker: None },
    })
}
