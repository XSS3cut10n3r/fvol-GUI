//! Physical container formats stacked on the input file, and the container part of
//! volatility3's LayerStacker automagic.
//! Derived from Volatility 3's framework/automagic/stacker.py and framework/layers/*.py
//! (Volatility Software License 1.0).
//!
//! Entry point: [`stack`] (or [`stack_with`] for options / the windows.info style listing).
//!
//! Detection order == python's: stackers are sorted by `stack_order` (stable), the ties being
//! in import order (measured with vol.py -vvvvvv on 2.28.2):
//!   AVMLStacker(10) Elf64Stacker(10) XenCoreDumpStacker(10) LimeStacker(10) QemuStacker(10)
//!   WindowsCrashDumpStacker(11) VmwareStacker(20)   | then (core) LinuxIntelVMCOREINFO(34),
//!   LinuxIntel(35), MacIntel(35), WindowsIntel(40).
//! Like python, after a layer stacks the remaining stackers are retried from the start on top
//! of it, a stacker is used at most once, and any failure (exception in python) just means
//! "not this format". Every stacker here has an empty `exclusion_list`, so the per-OS filter
//! of `choose_os_stackers` never removes them.
//!
//! All container layers are [`SegmentedLayer`]s: a flat sorted run table over the lower layer
//! (the mmapped file), so reads are a table lookup (binary search, or a bucket index for large
//! tables) plus one memcpy, and `slice()` is zero-copy. Layer names (`Layer::name`) are the
//! python class names.
//!
//! Notes for users of the layers:
//!   * `mapping()` returns the valid runs; for raw runs `mapped` is the file offset. For
//!     non-linear runs (QEMU fill pages, compressed AVML frames) `mapped` is the offset of the
//!     encoded data and must not be used for linear arithmetic: read those through
//!     `read`/`slice` (a scanner should try `slice()` first, then `read_padded`).
//!   * `is_valid(addr, len)` checks that every byte is present (python checks only the
//!     first byte of each chunk in the file; identical for len 1 and for untruncated files).

pub mod avml;
pub mod crash;
pub mod elf;
mod json;
pub mod lime;
pub mod qemu;
pub mod segmented;
pub mod vmware;

#[cfg(test)]
mod tests;

pub use segmented::SegmentedLayer;

use crate::error::{Error, Result};
use crate::layers::file::FileLayer;
use crate::layers::Layer;
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The layer a container is stacked on, with a direct path to the mmapped bytes when it is
/// the input file.
#[derive(Clone)]
pub(crate) struct Base {
    pub layer: Arc<dyn Layer>,
    pub file: Option<Arc<FileLayer>>,
}

impl Base {
    pub fn from_file(file: &Arc<FileLayer>) -> Base {
        let layer: Arc<dyn Layer> = file.clone();
        Base { layer, file: Some(file.clone()) }
    }

    /// python `maximum_address + 1` (the file size for the file layer).
    pub fn len(&self) -> u64 {
        match &self.file {
            Some(f) => f.len(),
            None => self.layer.max_address().saturating_add(1),
        }
    }

    /// Strict read (python `read` without pad): the whole range must be present.
    pub fn bytes(&self, off: u64, len: usize) -> Result<Cow<'_, [u8]>> {
        if let Some(f) = &self.file {
            return match f.slice(off, len) {
                Some(s) => Ok(Cow::Borrowed(s)),
                None => Err(Error::invalid(off)),
            };
        }
        let mut v = vec![0u8; len];
        self.layer.read(off, &mut v)?;
        Ok(Cow::Owned(v))
    }

    #[inline]
    pub fn array<const N: usize>(&self, off: u64) -> Result<[u8; N]> {
        let b = self.bytes(off, N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(&b);
        Ok(a)
    }
    pub fn u8(&self, off: u64) -> Result<u8> {
        Ok(self.array::<1>(off)?[0])
    }
    pub fn u16le(&self, off: u64) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array(off)?))
    }
    pub fn u32le(&self, off: u64) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array(off)?))
    }
    pub fn u64le(&self, off: u64) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array(off)?))
    }
    pub fn u32be(&self, off: u64) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array(off)?))
    }
    pub fn u64be(&self, off: u64) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array(off)?))
    }
}

/// python `objects.String` with utf-8/strict: decode all `max_length` bytes strictly, then cut
/// at the first NUL.
pub(crate) fn py_string(bytes: &[u8]) -> Result<String> {
    let s = std::str::from_utf8(bytes).map_err(|_| Error::Layer("string is not valid utf-8".into()))?;
    Ok(match s.find('\0') {
        Some(i) => s[..i].to_string(),
        None => s.to_string(),
    })
}

/// The container stackers, in python's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stacker {
    Avml,
    Elf64,
    Xen,
    Lime,
    Qemu,
    WindowsCrashDump,
    Vmware,
}

impl Stacker {
    pub const ALL: [Stacker; 7] = [
        Stacker::Avml,
        Stacker::Elf64,
        Stacker::Xen,
        Stacker::Lime,
        Stacker::Qemu,
        Stacker::WindowsCrashDump,
        Stacker::Vmware,
    ];

    /// python class name (as used by `--stackers` / `automagic.LayerStacker.stackers`).
    pub fn class_name(self) -> &'static str {
        match self {
            Stacker::Avml => "AVMLStacker",
            Stacker::Elf64 => "Elf64Stacker",
            Stacker::Xen => "XenCoreDumpStacker",
            Stacker::Lime => "LimeStacker",
            Stacker::Qemu => "QemuStacker",
            Stacker::WindowsCrashDump => "WindowsCrashDumpStacker",
            Stacker::Vmware => "VmwareStacker",
        }
    }

    /// python `stack_order`.
    pub fn stack_order(self) -> u32 {
        match self {
            Stacker::WindowsCrashDump => 11,
            Stacker::Vmware => 20,
            _ => 10,
        }
    }
}

/// Options for [`stack_with`].
#[derive(Default, Clone, Copy)]
pub struct StackOptions<'a> {
    /// Path of the input file (needed by the VMware stacker to find the .vmss/.vmsn next to
    /// a .vmem). When None it is recovered from /proc/self/maps.
    pub location: Option<&'a Path>,
    /// python `automagic.LayerStacker.stackers`: only stackers whose class name is listed run.
    pub stackers: Option<&'a [String]>,
}

/// One line of the windows.info style layer listing (`get_depends`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackEntry {
    /// Depth below the physical layer (the physical layer is 0; the kernel's translation
    /// layer, which the caller puts on top, shifts every depth by one).
    pub depth: usize,
    /// python layer name after construction magic ("memory_layer", "base_layer", ...).
    pub name: String,
    /// python class name ("LimeLayer", "FileLayer", ...).
    pub class: &'static str,
}

/// Result of [`stack_with`].
pub struct Stacked {
    /// Top physical layer (the file itself for raw images).
    pub layer: Arc<dyn Layer>,
    /// Stackers that succeeded, bottom-up.
    pub stackers: Vec<Stacker>,
    /// Dependency listing of the physical layer in python `get_depends` order.
    pub layers: Vec<StackEntry>,
}

/// Detect the container format(s) of `file` and return the physical memory layer (the file
/// itself for raw images), exactly as python's LayerStacker does before the OS stackers.
pub fn stack(file: Arc<FileLayer>) -> Result<Arc<dyn Layer>> {
    Ok(stack_with(file, &StackOptions::default())?.layer)
}

struct Node {
    class: &'static str,
    /// (requirement name, node index)
    deps: Vec<(&'static str, usize)>,
}

pub fn stack_with(file: Arc<FileLayer>, opts: &StackOptions) -> Result<Stacked> {
    let location: Option<PathBuf> = match opts.location {
        Some(p) => Some(p.to_path_buf()),
        None => file_location(&file),
    };
    let mut remaining: Vec<Stacker> = Stacker::ALL
        .iter()
        .copied()
        .filter(|s| match opts.stackers {
            Some(list) if !list.is_empty() => list.iter().any(|n| n == s.class_name()),
            _ => true,
        })
        .collect();
    let mut top = Base::from_file(&file);
    let mut nodes = vec![Node { class: "FileLayer", deps: vec![] }];
    let mut top_node = 0usize;
    let mut used = Vec::new();
    'outer: loop {
        for k in 0..remaining.len() {
            let st = remaining[k];
            let got: Result<SegmentedLayer> = match st {
                Stacker::Avml => avml::stack(&top),
                Stacker::Elf64 => elf::stack_elf64(&top),
                Stacker::Xen => elf::stack_xen(&top),
                Stacker::Lime => lime::stack(&top),
                Stacker::Qemu => qemu::stack(&top),
                Stacker::WindowsCrashDump => crash::stack(&top),
                // python: only on the FileLayer itself, and it needs the file location
                Stacker::Vmware => match (&location, top_node) {
                    (Some(loc), 0) => vmware::stack(&top, loc),
                    _ => Err(Error::Layer("vmware: not a file layer / unknown location".into())),
                },
            };
            if let Ok(layer) = got {
                let class = layer.class_name();
                let has_meta = st == Stacker::Vmware;
                let layer: Arc<dyn Layer> = Arc::new(layer);
                let mut deps = vec![("base_layer", top_node)];
                if has_meta {
                    nodes.push(Node { class: "FileLayer", deps: vec![] });
                    deps.push(("meta_layer", nodes.len() - 1));
                }
                nodes.push(Node { class, deps });
                top_node = nodes.len() - 1;
                top = Base { layer, file: None };
                used.push(st);
                remaining.remove(k);
                continue 'outer;
            }
        }
        break;
    }
    let layers = describe(&nodes, top_node);
    Ok(Stacked { layer: top.layer, stackers: used, layers })
}

/// python layer names after ConstructionMagic (post-order construction, requirement name with
/// a numeric suffix on collision), listed in `get_depends` pre-order.
fn describe(nodes: &[Node], top: usize) -> Vec<StackEntry> {
    fn construct(nodes: &[Node], n: usize, req: &'static str, taken: &mut Vec<String>, names: &mut Vec<Option<String>>) {
        for &(r, d) in &nodes[n].deps {
            construct(nodes, d, r, taken, names);
        }
        let mut name = req.to_string();
        let mut counter = 2;
        while taken.contains(&name) {
            name = format!("{req}{counter}");
            counter += 1;
        }
        taken.push(name.clone());
        names[n] = Some(name);
    }
    fn list(nodes: &[Node], n: usize, depth: usize, names: &[Option<String>], out: &mut Vec<StackEntry>) {
        out.push(StackEntry { depth, name: names[n].clone().unwrap_or_default(), class: nodes[n].class });
        for &(_, d) in &nodes[n].deps {
            list(nodes, d, depth + 1, names, out);
        }
    }
    let mut names = vec![None; nodes.len()];
    let mut taken = Vec::new();
    construct(nodes, top, "memory_layer", &mut taken, &mut names);
    let mut out = Vec::new();
    list(nodes, top, 0, &names, &mut out);
    out
}

/// Recover the path of the mmapped input file from /proc/self/maps (the FileLayer does not
/// keep it). Only used for the VMware .vmem/.vmss pairing.
fn file_location(file: &FileLayer) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    if file.is_empty() {
        return None;
    }
    let want = file.data().as_ptr() as usize;
    let maps = std::fs::read("/proc/self/maps").ok()?;
    for line in maps.split(|&b| b == b'\n') {
        let Some(dash) = line.iter().position(|&b| b == b'-') else { continue };
        let Ok(hex) = std::str::from_utf8(&line[..dash]) else { continue };
        if usize::from_str_radix(hex, 16).ok() != Some(want) {
            continue;
        }
        // fields: range perms offset dev inode path
        let mut i = 0usize;
        for _ in 0..5 {
            while i < line.len() && line[i] != b' ' {
                i += 1;
            }
            while i < line.len() && line[i] == b' ' {
                i += 1;
            }
        }
        let mut path = &line[i..];
        if let Some(p) = path.strip_suffix(b" (deleted)") {
            path = p;
        }
        if path.first() != Some(&b'/') {
            return None;
        }
        // the kernel escapes newlines as "\012"
        let mut buf = Vec::with_capacity(path.len());
        let mut k = 0;
        while k < path.len() {
            if path[k..].starts_with(b"\\012") {
                buf.push(b'\n');
                k += 4;
            } else {
                buf.push(path[k]);
                k += 1;
            }
        }
        return Some(PathBuf::from(std::ffi::OsStr::from_bytes(&buf)));
    }
    None
}
