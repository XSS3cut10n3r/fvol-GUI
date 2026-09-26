//! Mac automagic (python `automagic/mac.py`: MacIntelStacker, MacSymbolFinder, plus the
//! KernelModule step) producing the [`MacKernel`] handle behind `Context::mac_kernel()`.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Flow (python order and semantics):
//!   1. banners = identifier index `dictionary("mac")` (python `get_identifier_dictionary`);
//!   2. scan the physical layer for any banner (python `MultiStringScanner`: leftmost-longest,
//!      non-overlapping, python chunking) -- streamed, first valid hit wins;
//!   3. per hit: load the ISF (unmasked temporary table), `find_aslr` (version_major/minor
//!      check at the banner-derived shift, 4K aligned), `BootPML4` -> temporary Intel32e
//!      layer, read `IdlePML4` (u32) -> DTB (page aligned, non-zero);
//!   4. python's MacSymbolFinder then loads the same ISF with `symbol_mask` = layer address
//!      mask (48 bits) and KernelModule sets the module offset to `kernel_virtual_offset`
//!      (= the KASLR shift).
//! Any exception python would raise inside the stacker (unreadable version fields, a banner
//! whose version does not parse, a missing symbol) aborts the whole Mac stacker, like
//! python's LayerStacker swallowing the exception.
//!
//! Results are cached per image (`automagic::cache`, kind "mac"), keyed additionally on the
//! symbol search path, so warm runs do no scanning and no identifier-index work.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::layers::scan::{DEFAULT_CHUNK_SIZE, FnScanner, MultiStringScanner, Scanner, find};
use crate::layers::{IntelLayer, Layer, LayerExt, PagingMode, PteFlavor};
use crate::objects::{LayerRef, Module};
use crate::symbols::mac::{py_int_bytes, v2p};
use crate::symbols::{self, IsfLocation, TableRef};
use crate::util::trace::span;
use std::sync::Arc;

/// The macOS kernel (python `context.modules[config["kernel"]]` for mac plugins plus its
/// layers). Derefs to the kernel [`Module`] (offset = python `kernel_virtual_offset`).
///
/// ```ignore
/// let k = ctx.mac_kernel()?;
/// let tasks = k.object_from_symbol("tasks")?;          // module-relative symbol
/// let allproc = k.symbol_addr("allproc")?;             // absolute address
/// let valid = k.layer.is_valid(addr, 8);
/// ```
pub struct MacKernel {
    /// The kernel module (virtual layer, kernel symbol table, base = kaslr shift).
    pub module: Module,
    /// The kernel virtual layer (python `layer_name`, an `Intel32e` layer, os "mac").
    pub layer: &'static IntelLayer,
    /// Same layer as `&dyn Layer`.
    pub vlayer: LayerRef,
    /// The physical layer (python `memory_layer`).
    pub phys: LayerRef,
    /// The kernel symbol table (python `symbol_table_name1`, symbol_mask = 2^48 - 1).
    pub table: TableRef,
    /// python `kernel_virtual_offset` (KASLR shift).
    pub kaslr_shift: u64,
    /// python `page_map_offset`.
    pub dtb: u64,
    /// The matched kernel banner (`version` constant data, including the trailing NUL).
    pub banner: Vec<u8>,
    /// Where the kernel ISF was loaded from (python `isf_url`).
    pub isf: IsfLocation,
}

impl std::ops::Deref for MacKernel {
    type Target = Module;
    fn deref(&self) -> &Module {
        &self.module
    }
}

/// Everything the Mac automagic determines for an image (cacheable).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacAutomagic {
    /// The banner that matched (identifier of `isf`).
    pub banner: Vec<u8>,
    /// The kernel ISF.
    pub isf: IsfLocation,
    /// python `kernel_virtual_offset`.
    pub kaslr_shift: u64,
    /// python `page_map_offset` (from `IdlePML4`).
    pub dtb: u64,
}

/// Run the Mac automagic for `ctx` (called once by `Context::mac_kernel`).
pub fn init(ctx: &Context) -> Result<MacKernel> {
    let _t = span("mac kernel init (total)");
    let (phys_arc, phys) = ctx.physical_arc().map_err(|e| unsatisfied(ctx, &e, LAYER))?;
    if !crate::automagic::stacker_enabled(ctx.opts.stackers.as_deref(), "MacIntelStacker") {
        return Err(unsatisfied(ctx, &Error::msg("MacIntelStacker disabled by --stackers"), LAYER));
    }
    let image = ctx.image_path().map_err(|e| unsatisfied(ctx, &e, LAYER))?;
    let fp = symbol_path_fingerprint();
    let am = match cache_load(&image, &fp) {
        Some(a) => a,
        None => {
            // python: the MacIntelStacker built no layer
            let mut index = None;
            let r = run_indexed(phys_arc, &mut index);
            symbols::store::keep_decoded_for(None);
            let a = r.map_err(|e| unsatisfied(ctx, &e, LAYER))?;
            let deps = index.map(|i| i.choice_deps("mac", &a.banner)).unwrap_or_default();
            cache_store(&image, &fp, &a, deps);
            a
        }
    };
    crate::util::trace::note(|| format!("mac kernel ISF: {}", am.isf.url()));
    let banner_str: String = am.banner.iter().map(|&b| b as char).collect();
    let layer = IntelLayer::new("layer_name", phys_arc.clone(), am.dtb, PagingMode::Intel32e, PteFlavor::Generic)
        .with_os("mac")
        .with_kernel_virtual_offset(Some(am.kaslr_shift))
        .with_kernel_banner(Some(banner_str));
    let layer: &'static IntelLayer = Box::leak(Box::new(layer));
    let vlayer: LayerRef = layer;
    let table = {
        let _t = span("mac kernel isf load");
        // python MacSymbolFinder: symbol_mask = layer.address_mask (a layer without a kernel
        // symbol table: only the symbol requirement is unsatisfied)
        symbols::load_location(&am.isf, "symbol_table_name", None, vlayer.address_mask()).map_err(|e| unsatisfied(ctx, &e, SYMS))?
    };
    let module = Module::new(vlayer, table, am.kaslr_shift);
    Ok(MacKernel { module, layer, vlayer, phys: *phys, table, kaslr_shift: am.kaslr_shift, dtb: am.dtb, banner: am.banner, isf: am.isf })
}

/// python: no translation layer -> both kernel requirements are unsatisfied.
const LAYER: &[&str] = &["kernel.layer_name", "kernel.symbol_table_name"];
/// python: a layer but no kernel symbol table.
const SYMS: &[&str] = &["kernel.symbol_table_name"];

/// Log the failure detail (python logs these at -v levels) and return python's
/// UnsatisfiedException for `paths` (the convention of `Context::init_windows`).
fn unsatisfied(ctx: &Context, detail: &Error, paths: &[&str]) -> Error {
    if ctx.opts.verbosity > 0 {
        eprintln!("automagic: {detail}");
    }
    crate::plugins::unsatisfied(paths)
}

// ---------------------------------------------------------------------------------------------
// MacIntelStacker
// ---------------------------------------------------------------------------------------------

/// python `MacIntelStacker.stack` on the physical layer (+ the MacSymbolFinder lookup, which
/// resolves the same banner to the same ISF). `Err` = no layer (the detail python logs).
pub fn run(phys: &Arc<dyn Layer>) -> Result<MacAutomagic> {
    run_indexed(phys, &mut None)
}

/// [`run`]; `index` receives the identifier index the banner -> ISF choice was made from.
fn run_indexed(phys: &Arc<dyn Layer>, index: &mut Option<&'static symbols::store::IdentifierIndex>) -> Result<MacAutomagic> {
    // python: never stack on top of an intel layer
    if phys.as_intel().is_some() {
        return Err(Error::msg("Mac automagic: the memory layer is already a translation layer"));
    }
    let banners = {
        let _t = span("mac: identifier index");
        // with the image's banner (a quick scan, meanwhile) the index builds the matching kernel
        // ISF from the JSON it decompresses anyway; no guessing among many mac kernels
        symbols::store::keep_decoded_for_with(Some("mac"), false);
        let hint = std::sync::Mutex::new(None);
        let idx = symbols::store::identifier_index_with(symbols::symbol_path(), &|| {
            let phys = phys.clone();
            let h = std::thread::Builder::new().name("rsvol-hint".into()).spawn(move || {
                symbols::store::set_banner_hint(crate::automagic::banner_hint(phys.as_ref(), b"Darwin Kernel Version ", b":"));
            });
            *hint.lock().unwrap_or_else(|e| e.into_inner()) = h.ok();
        });
        *index = Some(idx);
        let d = idx.dictionary("mac");
        // a single mac kernel ISF: load it while the banner is searched (the stacker loads it
        // next and waits for this load)
        let mut isfs: Vec<&IsfLocation> = d.iter().map(|(_, l)| l).collect();
        isfs.dedup();
        if isfs.len() == 1 {
            symbols::store::load_in_background(isfs[0].clone());
        }
        if let Some(h) = hint.into_inner().unwrap_or_else(|e| e.into_inner()) {
            let _ = h.join();
        }
        d
    };
    if banners.is_empty() {
        return Err(Error::msg("No Mac banners found - if this is a mac plugin, please check your symbol files location"));
    }
    let scanner = BannerScanner::new(banners.iter().map(|(b, _)| b.as_slice()).collect());
    let abort = |e: Error| Error::msg(format!("Exception during stacking (MacIntelStacker): {e}"));
    // Phase 1: stop the scan at the first hit (the scanning threads are joined) and validate it
    // alone -- validating while all threads fault in and scan 16 MiB windows is many times
    // slower (memory bus + mmap lock contention), and the first hit is almost always the kernel.
    // The scan runs in growing batches (see `scan_each_progressive`): banners sit early in
    // physical memory, so most of a fixed look-ahead wave would be wasted bandwidth.
    let first = {
        let _t = span("mac: banner scan (first hit)");
        let mut first = None;
        scan_each_progressive(phys.as_ref(), &scanner, |h| h.0, |h| {
            first = Some(h);
            false
        });
        first
    };
    let Some((off, idx)) = first else {
        return Err(Error::msg("No suitable mac banner could be matched"));
    };
    {
        let _t = span("mac: banner validation");
        let (banner, loc) = &banners[idx as usize];
        if let Some(a) = try_banner(phys, banner, loc, off).map_err(abort)? {
            return Ok(a);
        }
    }
    // Phase 2 (first hit rejected): python's loop over the remaining hits, validated inline.
    let mut result: Option<Result<MacAutomagic>> = None;
    {
        let _t = span("mac: banner scan + validation (remaining hits)");
        let mut skip = 1usize;
        scan_each_progressive(phys.as_ref(), &scanner, |h| h.0, |(off, idx)| {
            if skip > 0 {
                skip -= 1;
                return true;
            }
            let (banner, loc) = &banners[idx as usize];
            match try_banner(phys, banner, loc, off) {
                Ok(Some(a)) => {
                    result = Some(Ok(a));
                    false
                }
                Ok(None) => true,
                Err(e) => {
                    // python: the exception aborts the whole stacker
                    result = Some(Err(e));
                    false
                }
            }
        });
    }
    match result {
        Some(Ok(a)) => Ok(a),
        Some(Err(e)) => Err(abort(e)),
        None => Err(Error::msg("No suitable mac banner could be matched")),
    }
}

/// One iteration of python's banner loop: `Ok(None)` = `continue`.
fn try_banner(phys: &Arc<dyn Layer>, banner: &[u8], loc: &IsfLocation, banner_offset: u64) -> Result<Option<MacAutomagic>> {
    let table = {
        let _t = span("mac: temporary isf load");
        symbols::load_location(loc, "MacintelStacker", None, 0)?
    };
    let kaslr_shift = find_aslr(phys.as_ref(), table, banner, banner_offset)?;
    if kaslr_shift == 0 {
        return Ok(None);
    }
    let bootpml4 = v2p(table.get_symbol("BootPML4")?.address as i128 + kaslr_shift as i128);
    let tmp = IntelLayer::new("MacDTBTempLayer1", phys.clone(), bootpml4 as u64, PagingMode::Intel32e, PteFlavor::Generic).with_os("Mac");
    let idlepml4_ptr = table.get_symbol("IdlePML4")?.address as i128 + kaslr_shift as i128;
    let mut b = [0u8; 4];
    if tmp.read(idlepml4_ptr as u64, &mut b).is_err() {
        return Ok(None);
    }
    let dtb = u32::from_le_bytes(b) as u64;
    // python: non page-aligned -> continue; `if new_layer and dtb` -> a zero DTB also continues
    if dtb % 4096 != 0 || dtb == 0 {
        return Ok(None);
    }
    Ok(Some(MacAutomagic { banner: banner.to_vec(), isf: loc.clone(), kaslr_shift, dtb }))
}

/// python `layer.read(addr, 4)` + `struct.unpack("<I")` with python int addresses.
fn read_u32_at(phys: &dyn Layer, addr: i128) -> Result<u32> {
    if addr < 0 || addr > u64::MAX as i128 {
        return Err(Error::invalid(addr as u64));
    }
    phys.read_u32(addr as u64)
}

/// python `MacIntelStacker.find_aslr(context, symbol_table, layer_name, compare_banner,
/// compare_banner_offset)`; `table` must be unmasked (python's temporary table).
pub fn find_aslr(phys: &dyn Layer, table: TableRef, compare_banner: &[u8], compare_banner_offset: u64) -> Result<u64> {
    let version = table.get_symbol("version")?.address as i128;
    let vmaj = v2p(table.get_symbol("version_major")?.address as i128);
    let vmin = v2p(table.get_symbol("version_minor")?.address as i128);
    let check = |offset: u64, banner: &[u8]| -> Result<Option<u64>> {
        // banner_major, banner_minor = (int(x) for x in banner[22:].split(b".")[0:2])
        let rest = banner.get(22..).unwrap_or(&[]);
        let mut parts = rest.split(|&c| c == b'.');
        let bad = || Error::msg("ValueError: invalid banner version");
        let major_want = parts.next().and_then(py_int_bytes).ok_or_else(bad)?;
        let minor_want = parts.next().ok_or_else(bad).and_then(|p| py_int_bytes(p).ok_or_else(bad))?;
        let tmp = offset as i128 - v2p(version);
        let major = read_u32_at(phys, vmaj + tmp)?;
        if major as i128 != major_want {
            return Ok(None);
        }
        let minor = read_u32_at(phys, vmin + tmp)?;
        if minor as i128 != minor_want {
            return Ok(None);
        }
        if tmp & 0xFFF != 0 {
            return Ok(None);
        }
        Ok(Some((tmp & 0xFFFF_FFFF) as u64))
    };
    if compare_banner_offset != 0 && !compare_banner.is_empty() {
        return Ok(check(compare_banner_offset, compare_banner)?.unwrap_or(0));
    }
    // python `_scan_generator`: every Darwin banner in the layer (regex), first valid wins
    let mut result: Result<u64> = Ok(0);
    let scanner = FnScanner::new(|data: &[u8], off: u64, hits: &mut Vec<u64>| darwin_scan(data, off, DEFAULT_CHUNK_SIZE, hits));
    scan_each_progressive(phys, &scanner, |h| *h, |offset| {
        let banner = match phys.read_vec(offset, 128) {
            Ok(b) => b,
            Err(e) => {
                result = Err(e);
                return false;
            }
        };
        let banner = match banner.iter().position(|&c| c == 0) {
            Some(i) => &banner[..i],
            None => &banner[..],
        };
        match check(offset, banner) {
            Ok(Some(s)) => {
                result = Ok(s);
                false
            }
            Ok(None) => true,
            Err(e) => {
                result = Err(e);
                false
            }
        }
    });
    result
}

// ---------------------------------------------------------------------------------------------
// Scanners
// ---------------------------------------------------------------------------------------------

pub use crate::layers::scan::scan_each_progressive;

/// python `MultiStringScanner(banners)` semantics (leftmost-longest, non-overlapping, only
/// hits starting before `chunk_size`), accelerated for banner sets: every banner shares a long
/// common prefix ("Darwin Kernel Version 1"), so candidates are found with SIMD `memmem` on
/// the prefix and verified against the (few hundred) patterns, longest first. Falls back to
/// the generic trie scanner when the patterns share no prefix. Hit = (offset, pattern index).
pub struct BannerScanner {
    prefix: Vec<u8>,
    /// (pattern, index) sorted by length, longest first
    by_len: Vec<(Vec<u8>, u32)>,
    fallback: Option<MultiStringScanner>,
}

impl BannerScanner {
    pub fn new(patterns: Vec<&[u8]>) -> BannerScanner {
        let nonempty: Vec<&[u8]> = patterns.iter().copied().filter(|p| !p.is_empty()).collect();
        let mut prefix: &[u8] = nonempty.first().copied().unwrap_or(&[]);
        for p in &nonempty {
            let n = prefix.iter().zip(p.iter()).take_while(|(a, b)| a == b).count();
            prefix = &prefix[..n];
        }
        let mut by_len: Vec<(Vec<u8>, u32)> =
            patterns.iter().enumerate().filter(|(_, p)| !p.is_empty()).map(|(i, p)| (p.to_vec(), i as u32)).collect();
        // longest first; equal patterns keep the first index (python's trie collapses them)
        by_len.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.1.cmp(&b.1)));
        let fallback = if prefix.is_empty() { Some(MultiStringScanner::new(&patterns)) } else { None };
        BannerScanner { prefix: prefix.to_vec(), by_len, fallback }
    }

    /// All matches in `data` as (offset in data, pattern index); `f` returns false to stop.
    pub fn search(&self, data: &[u8], mut f: impl FnMut(usize, u32) -> bool) {
        if let Some(m) = &self.fallback {
            return m.search(data, f);
        }
        let mut pos = 0usize;
        while pos < data.len() {
            let Some(i) = find(&data[pos..], &self.prefix) else { return };
            let at = pos + i;
            let rest = &data[at..];
            match self.by_len.iter().find(|(p, _)| rest.starts_with(p)) {
                Some((p, idx)) => {
                    if !f(at, *idx) {
                        return;
                    }
                    pos = at + p.len();
                }
                None => pos = at + 1,
            }
        }
    }
}

impl Scanner for BannerScanner {
    type Hit = (u64, u32);
    fn scan(&self, data: &[u8], data_offset: u64, hits: &mut Vec<(u64, u32)>) {
        let cs = self.chunk_size();
        self.search(data, |off, idx| {
            if (off as u64) < cs {
                hits.push((data_offset + off as u64, idx));
                true
            } else {
                false
            }
        });
    }
}

const DARWIN: &[u8] = b"Darwin Kernel Version ";

enum Darwin {
    /// match of this length
    Match(usize),
    NoMatch,
    /// no NUL after the version: neither this nor any later candidate can match
    NoNul,
}

/// `\d{1,3}` followed by `term` at `s[i..]`: the index after `term`.
#[inline]
fn digits_then(s: &[u8], mut i: usize, term: u8) -> Option<usize> {
    let start = i;
    while i < s.len() && i - start < 3 && s[i].is_ascii_digit() {
        i += 1;
    }
    if i == start || i >= s.len() || s[i] != term {
        return None;
    }
    Some(i + 1)
}

/// python `re.match(rb"Darwin Kernel Version \d{1,3}\.\d{1,3}\.\d{1,3}: [^\x00]+\x00", s)`
/// (DOTALL) for `s` starting with "Darwin Kernel Version ".
fn darwin_match(s: &[u8]) -> Darwin {
    let i = DARWIN.len();
    let Some(i) = digits_then(s, i, b'.') else { return Darwin::NoMatch };
    let Some(i) = digits_then(s, i, b'.') else { return Darwin::NoMatch };
    let Some(i) = digits_then(s, i, b':') else { return Darwin::NoMatch };
    if i >= s.len() || s[i] != b' ' {
        return Darwin::NoMatch;
    }
    let i = i + 1;
    // [^\x00]+\x00
    if i >= s.len() {
        return Darwin::NoNul;
    }
    if s[i] == 0 {
        return Darwin::NoMatch;
    }
    match s[i..].iter().position(|&c| c == 0) {
        Some(j) => Darwin::Match(i + j + 1),
        None => Darwin::NoNul,
    }
}

/// python `RegExScanner(darwin_signature)` on one chunk (non-overlapping `finditer`).
fn darwin_scan(data: &[u8], data_offset: u64, chunk_size: u64, hits: &mut Vec<u64>) {
    let mut pos = 0usize;
    while pos < data.len() {
        let Some(i) = find(&data[pos..], DARWIN) else { return };
        let at = pos + i;
        if at as u64 >= chunk_size {
            return;
        }
        match darwin_match(&data[at..]) {
            Darwin::Match(len) => {
                hits.push(data_offset + at as u64);
                pos = at + len;
            }
            Darwin::NoMatch => pos = at + 1,
            Darwin::NoNul => return,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------------------------

/// Identity of the symbol search path (a different `-s` may resolve banners differently): the
/// full key material, stored in the cache entry and compared.
fn symbol_path_fingerprint() -> String {
    let sp = symbols::symbol_path();
    format!("{}-{}", crate::util::paths::hex(format!("{:?}", sp.download_dir).as_bytes()), sp.os_fingerprint("mac"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// `IsfLocation` <-> one cache line value (tab separated).
fn loc_encode(loc: &IsfLocation) -> Option<String> {
    let ok = |s: &str| !s.contains(['\t', '\n', '\r']);
    match loc {
        IsfLocation::File(p) => {
            let s = p.to_str()?;
            ok(s).then(|| format!("file\t{s}"))
        }
        IsfLocation::Zip { zip, member } => {
            let z = zip.to_str()?;
            (ok(z) && ok(member)).then(|| format!("zip\t{z}\t{member}"))
        }
        IsfLocation::Embedded { rel, top, .. } => ok(rel).then(|| format!("emb\t{}\t{rel}", *top as u8)),
        IsfLocation::Url(u) => ok(u).then(|| format!("url\t{u}")),
    }
}

fn loc_decode(s: &str) -> Option<IsfLocation> {
    let mut it = s.split('\t');
    match it.next()? {
        "file" => {
            let p = std::path::PathBuf::from(it.next()?);
            p.is_file().then_some(IsfLocation::File(p))
        }
        "zip" => {
            let zip = std::path::PathBuf::from(it.next()?);
            let member = it.next()?.to_string();
            zip.is_file().then_some(IsfLocation::Zip { zip, member })
        }
        "url" => {
            let u = it.next()?.to_string();
            symbols::store::url_local_path(&u).is_ok_and(|p| p.is_file()).then_some(IsfLocation::Url(u))
        }
        "emb" => {
            let top = it.next()? == "1";
            let rel = it.next()?;
            symbols::embedded::FILES
                .iter()
                .find(|(r, t, _)| *r == rel && *t == top)
                .map(|&(rel, top, data)| IsfLocation::Embedded { rel, top, data })
        }
        _ => None,
    }
}

fn cache_load(image: &std::path::Path, fp: &str) -> Option<MacAutomagic> {
    use crate::automagic::cache::{get, load};
    let kv = load(image, "mac")?;
    // the banner -> ISF choice (python's identifier cache, the banner's candidate ISFs)
    if get(&kv, "sympath")? != fp || !symbols::store::choice_deps_hold(&kv) {
        return None;
    }
    let num = |k: &str| get(&kv, k).and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok());
    Some(MacAutomagic { banner: unhex(get(&kv, "banner")?)?, isf: loc_decode(get(&kv, "isf")?)?, kaslr_shift: num("kaslr")?, dtb: num("dtb")? })
}

fn cache_store(image: &std::path::Path, fp: &str, a: &MacAutomagic, deps: Vec<(&'static str, String)>) {
    let Some(isf) = loc_encode(&a.isf) else { return };
    let mut kv = vec![
        ("sympath", fp.to_string()),
        ("banner", hex(&a.banner)),
        ("isf", isf),
        ("kaslr", format!("{:#x}", a.kaslr_shift)),
        ("dtb", format!("{:#x}", a.dtb)),
    ];
    kv.extend(deps);
    crate::automagic::cache::store(image, "mac", &kv);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full-image scan throughput of the banner scanners (heavy: run through limit.sh with
    /// `RSVOL_MAC_IMAGE=<image> cargo test --profile fast mac_scan_bench -- --ignored --nocapture`).
    #[test]
    #[ignore]
    fn mac_scan_bench() {
        let Some(img) = std::env::var_os("RSVOL_MAC_IMAGE") else { return };
        let phys: Arc<dyn Layer> = crate::automagic::stack_physical(std::path::Path::new(&img), None, false, None).unwrap().0;
        let sp = symbols::SymbolPath::new(&["/home/user/rs-vol/testdata/symbols".to_string()]);
        let banners = symbols::store::identifier_index(&sp).dictionary("mac");
        let pats: Vec<&[u8]> = banners.iter().map(|(b, _)| b.as_slice()).collect();
        let gb = phys.max_address() as f64 / 1e9;
        for round in 0..2 {
            let t = std::time::Instant::now();
            let hits = crate::layers::scan::scan(phys.as_ref(), &BannerScanner::new(pats.clone()), None);
            let s = t.elapsed().as_secs_f64();
            eprintln!("[{round}] BannerScanner (memmem prefix): {} hits, {:.3}s, {:.2} GB/s", hits.len(), s, gb / s);
            let t = std::time::Instant::now();
            let hits2 = crate::layers::scan::scan(phys.as_ref(), &MultiStringScanner::new(&pats), None);
            let s = t.elapsed().as_secs_f64();
            eprintln!("[{round}] MultiStringScanner (trie):     {} hits, {:.3}s, {:.2} GB/s", hits2.len(), s, gb / s);
            assert_eq!(hits, hits2);
            let t = std::time::Instant::now();
            let mut hits4 = Vec::new();
            scan_each_progressive(phys.as_ref(), &BannerScanner::new(pats.clone()), |h| h.0, |h| {
                hits4.push(h);
                true
            });
            let s = t.elapsed().as_secs_f64();
            eprintln!("[{round}] BannerScanner progressive:     {} hits, {:.3}s, {:.2} GB/s", hits4.len(), s, gb / s);
            assert_eq!(hits, hits4);
            let t = std::time::Instant::now();
            let mut first = None;
            scan_each_progressive(phys.as_ref(), &BannerScanner::new(pats.clone()), |h| h.0, |h| {
                first = Some(h);
                false
            });
            eprintln!("[{round}] progressive first hit {:x?}: {:.3}ms", first, t.elapsed().as_secs_f64() * 1e3);
            let t = std::time::Instant::now();
            let mut first = None;
            crate::layers::scan::scan_each(phys.as_ref(), &BannerScanner::new(pats.clone()), None, |h| {
                first = Some(h);
                false
            });
            eprintln!("[{round}] scan_each first hit {:x?}: {:.3}ms", first, t.elapsed().as_secs_f64() * 1e3);
            let t = std::time::Instant::now();
            let sc = FnScanner::new(|data: &[u8], off: u64, hits: &mut Vec<u64>| darwin_scan(data, off, DEFAULT_CHUNK_SIZE, hits));
            let hits3 = crate::layers::scan::scan(phys.as_ref(), &sc, None);
            let s = t.elapsed().as_secs_f64();
            eprintln!("[{round}] Darwin regex scanner:          {} hits, {:.3}s, {:.2} GB/s", hits3.len(), s, gb / s);
        }
    }

    /// Per-chunk cost breakdown (page faults vs memmem), single thread.
    #[test]
    #[ignore]
    fn mac_chunk_bench() {
        let Some(img) = std::env::var_os("RSVOL_MAC_IMAGE") else { return };
        let fl = crate::layers::FileLayer::open(std::path::Path::new(&img)).unwrap();
        let file = std::fs::File::open(&img).unwrap();
        let prefix = b"Darwin Kernel Version 1";
        let cs = 16usize << 20;
        let time = |name: &str, f: &mut dyn FnMut() -> usize| {
            let t = std::time::Instant::now();
            let n = f();
            eprintln!("{name}: {:.3}ms ({n})", t.elapsed().as_secs_f64() * 1e3);
        };
        let count = |d: &[u8]| {
            let mut n = 0;
            let mut p = 0;
            while let Some(i) = find(&d[p..], prefix) {
                n += 1;
                p += i + 1;
            }
            n
        };
        // global mapping, first touch (faults) then again (hot)
        let base = 0x10_0000_0000usize.min(fl.len() as usize - 5 * cs) & !0xfff;
        let base = base.min(1 << 30);
        time("global mmap 16MiB first touch + memmem", &mut || count(&fl.data()[base..base + cs]));
        time("global mmap 16MiB hot memmem", &mut || count(&fl.data()[base..base + cs]));
        time("MapWindow(populate=false) 16MiB map+memmem+unmap", &mut || {
            let w = crate::util::mmap::MapWindow::new(&file, (base + cs) as u64, cs, false).unwrap();
            count(w.as_slice())
        });
        time("MapWindow(populate=true) 16MiB map+memmem+unmap", &mut || {
            let w = crate::util::mmap::MapWindow::new(&file, (base + 2 * cs) as u64, cs, true).unwrap();
            count(w.as_slice())
        });
        time("MapWindow(populate=true) map only", &mut || {
            let w = crate::util::mmap::MapWindow::new(&file, (base + 3 * cs) as u64, cs, true).unwrap();
            w.as_slice().len()
        });
        let mut buf = vec![0u8; cs];
        time("pread 16MiB + memmem", &mut || {
            use std::os::unix::fs::FileExt;
            file.read_exact_at(&mut buf, (base + 4 * cs) as u64).unwrap();
            count(&buf)
        });
        time("hot buffer memchr(D) count", &mut || buf.iter().filter(|&&b| b == b'D').count());
    }

    /// A flat data layer (no lower layer).
    struct Buf(Vec<u8>);
    impl Layer for Buf {
        fn name(&self) -> &str {
            "buf"
        }
        fn max_address(&self) -> u64 {
            self.0.len() as u64 - 1
        }
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let a = addr as usize;
            match self.0.get(a..a + buf.len()) {
                Some(s) => {
                    buf.copy_from_slice(s);
                    Ok(())
                }
                None => Err(Error::invalid(addr)),
            }
        }
        fn is_valid(&self, addr: u64, len: u64) -> bool {
            addr + len <= self.0.len() as u64
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(crate::layers::Mapping) -> bool) {
            f(crate::layers::Mapping { offset: addr, len, mapped: addr });
        }
    }

    /// A segmented layer over `lower`: runs (offset, len, mapped).
    struct Seg {
        lower: Arc<dyn Layer>,
        runs: Vec<(u64, u64, u64)>,
        max: u64,
    }
    impl Layer for Seg {
        fn name(&self) -> &str {
            "seg"
        }
        fn max_address(&self) -> u64 {
            self.max
        }
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            for &(o, l, m) in &self.runs {
                if addr >= o && addr + buf.len() as u64 <= o + l {
                    return self.lower.read(m + (addr - o), buf);
                }
            }
            Err(Error::invalid(addr))
        }
        fn is_valid(&self, addr: u64, len: u64) -> bool {
            self.runs.iter().any(|&(o, l, _)| addr >= o && addr + len <= o + l)
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(crate::layers::Mapping) -> bool) {
            let end = addr + len;
            for &(o, l, m) in &self.runs {
                let (s, e) = (o.max(addr), (o + l).min(end));
                if s < e && !f(crate::layers::Mapping { offset: s, len: e - s, mapped: m + (s - o) }) {
                    return;
                }
            }
        }
        fn lower(&self) -> Option<&Arc<dyn Layer>> {
            Some(&self.lower)
        }
    }

    #[test]
    fn progressive_scan_matches_scan_each() {
        // needle occurrences everywhere, incl. across chunk boundaries and in overlaps
        let mut data = vec![b'.'; 40_000];
        let needle = b"NEEDLE";
        let mut p = 3usize;
        while p + needle.len() < data.len() {
            data[p..p + needle.len()].copy_from_slice(needle);
            p += 97 + (p % 13);
        }
        for &(chunk, overlap) in &[(256u64, 16u64), (1000, 100), (4096, 4096), (333, 7)] {
            let sc = FnScanner::new(move |d: &[u8], off: u64, hits: &mut Vec<u64>| {
                let mut pos = 0;
                while let Some(i) = find(&d[pos..], needle) {
                    let at = pos + i;
                    if at as u64 >= chunk {
                        break;
                    }
                    hits.push(off + at as u64);
                    pos = at + 1;
                }
            })
            .with_chunking(chunk, overlap);
            let flat: Arc<dyn Layer> = Arc::new(Buf(data.clone()));
            let seg = Seg { lower: flat.clone(), runs: vec![(0, 5000, 100), (5000, 3000, 9000), (9000, 20_000, 12_000)], max: 28_999 };
            for layer in [flat.as_ref(), &seg as &dyn Layer] {
                let want = crate::layers::scan::scan(layer, &sc, None);
                let mut got = Vec::new();
                scan_each_progressive(layer, &sc, |h| *h, |h| {
                    got.push(h);
                    true
                });
                assert_eq!(got, want, "chunk {chunk} overlap {overlap} layer {}", layer.name());
                assert!(!want.is_empty());
                // early stop after k hits
                let mut first = Vec::new();
                scan_each_progressive(layer, &sc, |h| *h, |h| {
                    first.push(h);
                    first.len() < 5
                });
                assert_eq!(first, want[..5]);
            }
        }
    }

    fn darwin_all(data: &[u8]) -> Vec<u64> {
        let mut v = Vec::new();
        darwin_scan(data, 0, u64::MAX, &mut v);
        v
    }

    #[test]
    fn darwin_regex_semantics() {
        let ok = b"xxDarwin Kernel Version 13.2.0: Thu Apr 17; root:xnu\x00yy";
        assert_eq!(darwin_all(ok), vec![2]);
        // 4 digits: no match
        assert!(darwin_all(b"Darwin Kernel Version 1234.2.0: a\x00").is_empty());
        // empty tail: no match
        assert!(darwin_all(b"Darwin Kernel Version 13.2.0: \x00").is_empty());
        // no NUL at all
        assert!(darwin_all(b"Darwin Kernel Version 13.2.0: abc").is_empty());
        // missing space after colon
        assert!(darwin_all(b"Darwin Kernel Version 13.2.0:abc\x00").is_empty());
        // non-overlapping: the second banner inside the first match's tail is consumed
        let two = b"Darwin Kernel Version 1.2.3: a Darwin Kernel Version 4.5.6: b\x00Darwin Kernel Version 7.8.9: c\x00";
        assert_eq!(darwin_all(two), vec![0, 62]);
        // a failing candidate does not hide the next one
        let d = b"Darwin Kernel Version x Darwin Kernel Version 1.2.3: q\x00";
        assert_eq!(darwin_all(d), vec![24]);
        // chunk filter
        let mut v = Vec::new();
        darwin_scan(ok, 100, 2, &mut v);
        assert!(v.is_empty());
    }

    #[test]
    fn banner_scanner_matches_trie_scanner() {
        let pats: Vec<&[u8]> = vec![
            b"Darwin Kernel Version 13.2.0: A\x00",
            b"Darwin Kernel Version 13.2.0: AB\x00",
            b"Darwin Kernel Version 13.2.0: A",
            b"Darwin Kernel Version 12.0.0: Z\x00",
        ];
        let data: &[u8] = b"..Darwin Kernel Version 13.2.0: AB\x00..Darwin Kernel Version 13.2.0: A\x00Darwin Kernel Version 13.2.0: AC Darwin Kernel Version 12.0.0: Z\x00Darwin Kernel Version 12.0.0: Q\x00";
        let b = BannerScanner::new(pats.clone());
        assert!(b.fallback.is_none());
        let m = MultiStringScanner::new(&pats);
        let mut x = Vec::new();
        b.search(data, |o, i| {
            x.push((o, i));
            true
        });
        let mut y = Vec::new();
        m.search(data, |o, i| {
            y.push((o, i));
            true
        });
        assert_eq!(x, y);
        assert_eq!(x.len(), 4);
    }

    #[test]
    fn location_roundtrip() {
        let p = std::env::current_exe().unwrap();
        let l = IsfLocation::File(p.clone());
        assert_eq!(loc_decode(&loc_encode(&l).unwrap()), Some(l));
        if let Some(&(rel, top, data)) = symbols::embedded::FILES.first() {
            let e = IsfLocation::Embedded { rel, top, data };
            assert_eq!(loc_decode(&loc_encode(&e).unwrap()), Some(e));
        }
        assert_eq!(unhex(&hex(b"Darwin\x00\xff")), Some(b"Darwin\x00\xff".to_vec()));
    }
}
