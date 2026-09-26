//! The analysis context: global options, the memory layers stacked on the input file,
//! loaded symbol tables, lazily-run automagic results (kernel discovery), and the output
//! file handler.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! OWNED BY THE CORE AGENT. The CLI relies only on:
//!   * `GlobalOptions` (fields below; add more as needed)
//!   * `Context::new(opts) -> Result<Context>`  (must be cheap: nothing is scanned until a
//!      plugin asks for it)
//!   * `Context::create_output_file(&self, preferred_name) -> Result<(File, String)>`
//!
//! Plugins use:
//!   * [`Context::windows_kernel`] -> [`WinKernel`] (virtual kernel layer, physical layer,
//!     kernel symbol table, base; derefs to a [`Module`] so `k.object(...)`,
//!     `k.get_symbol(...)` work like python's `context.modules[kernel]`);
//!   * [`Context::physical`] -> python's `memory_layer`;
//!   * [`Context::load_isf`] -> e.g. `ctx.load_isf("windows/pe")`.

use crate::error::{Error, Result};
use crate::layers::{IntelLayer, Layer, PagingMode, PteFlavor};
use crate::objects::{LayerRef, Module, leak_layer};
use crate::symbols::{self, SymbolPath, TableRef};
use std::fs::File;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

/// Global (non plugin-specific) CLI options.
#[derive(Clone, Debug, Default)]
pub struct GlobalOptions {
    /// `-f/--file` (already converted from a path; not a URI)
    pub file: Option<String>,
    /// `--single-location` URI (file:// ...)
    pub single_location: Option<String>,
    /// `--single-swap-locations`
    pub swap_locations: Vec<String>,
    /// `-s/--symbol-dirs` (already split on ';')
    pub symbol_dirs: Vec<String>,
    /// `--cache-path`
    pub cache_path: Option<String>,
    /// `--offline`
    pub offline: bool,
    /// `-u/--remote-isf-url`
    pub remote_isf_url: Option<String>,
    /// `-o/--output-dir` (default ".")
    pub output_dir: String,
    /// `-q/--quiet`
    pub quiet: bool,
    /// `-v` count
    pub verbosity: u8,
    /// `--stackers`
    pub stackers: Option<Vec<String>>,
    /// `--clear-cache`
    pub clear_cache: bool,
}

/// The Windows kernel (python `context.modules[config["kernel"]]` plus its layers).
/// Derefs to the kernel [`Module`].
pub struct WinKernel {
    /// The kernel module: virtual kernel layer, kernel symbol table, base (python module).
    pub module: Module,
    /// The kernel virtual layer (python `layer_name`, a `WindowsIntel*` layer).
    pub layer: &'static IntelLayer,
    /// Same layer as a `&dyn Layer`.
    pub vlayer: LayerRef,
    /// The physical layer (python `memory_layer`).
    pub phys: LayerRef,
    /// The kernel symbol table.
    pub table: TableRef,
    /// Kernel base (python `kernel_virtual_offset`, 48-bit masked).
    pub base: u64,
    /// python `page_map_offset`.
    pub dtb: u64,
    /// PDB identity of the kernel.
    pub pdb_name: String,
    pub guid: String,
    pub age: u32,
}

impl std::ops::Deref for WinKernel {
    type Target = Module;
    fn deref(&self) -> &Module {
        &self.module
    }
}

type Lazy<T> = OnceLock<std::result::Result<T, String>>;

pub struct Context {
    pub opts: GlobalOptions,
    /// the local file of the image's data (downloaded / decompressed on first use)
    image: Lazy<PathBuf>,
    physical: Lazy<(Arc<dyn Layer>, LayerRef)>,
    physical_listing: OnceLock<Vec<crate::automagic::StackEntry>>,
    /// python's native symbol tables appended while stacking (see [`Context::stacking_native_tables`])
    native_tables: OnceLock<Vec<&'static str>>,
    win: Lazy<WinKernel>,
    linux: Lazy<crate::automagic::linux::LinuxKernel>,
    mac: Lazy<crate::automagic::mac::MacKernel>,
    output_lock: Mutex<()>,
}

/// Text stored for a failed lazy init: the bare path list for `Unsatisfied` (so the CLI can
/// parse it back), the display text otherwise.
fn err_text(e: Error) -> String {
    match e {
        Error::Unsatisfied(s) => s,
        e => e.to_string(),
    }
}

fn keep_err<T>(r: &std::result::Result<T, String>) -> Result<&T> {
    r.as_ref().map_err(|e| Error::Unsatisfied(e.clone()))
}

impl Context {
    /// Cheap: records options and sets the symbol search path. Nothing is opened or scanned.
    pub fn new(opts: GlobalOptions) -> Result<Context> {
        if opts.clear_cache {
            // python --clear-cache deletes every *.cache in its cache directory (downloads too)
            // and its identifier cache; the same for ours (python's is only treated as empty)
            crate::util::paths::clear_cache_dir(&crate::util::paths::rsvol_cache_dir());
        }
        symbols::set_symbol_path(SymbolPath::new(&opts.symbol_dirs));
        symbols::set_remote_isf_url(opts.remote_isf_url.clone(), opts.offline);
        // the identifier index is python's identifier cache as python updates it (after
        // --clear-cache, which deletes it, the one python builds from scratch)
        symbols::store::set_python_identifier_cache(
            (!opts.clear_cache).then(|| symbols::pycache::db_path(opts.cache_path.as_deref())),
        );
        // downloaded PDBs are kept in python's cache directory, as python keeps them (after
        // --clear-cache python has deleted them, so they are downloaded again)
        symbols::windows::pdb::set_python_cache(crate::util::paths::vol3_cache_dir(opts.cache_path.as_deref()), !opts.clear_cache);
        Ok(Context {
            opts,
            image: OnceLock::new(),
            physical: OnceLock::new(),
            physical_listing: OnceLock::new(),
            native_tables: OnceLock::new(),
            win: OnceLock::new(),
            linux: OnceLock::new(),
            mac: OnceLock::new(),
            output_lock: Mutex::new(()),
        })
    }

    /// The symbol search path.
    pub fn symbol_path(&self) -> &'static SymbolPath {
        symbols::symbol_path()
    }

    /// Path of the file holding the input image's data (`-f` or `--single-location`), opened
    /// like python's `ResourceAccessor`: a `http://`, `https://` or `ftp://` location is
    /// downloaded once into the rsvol cache (`data_<sha512>.cache`, reused until
    /// `--clear-cache`), and a location ending in `.gz`, `.bz2` or `.xz` is decompressed once
    /// into the rsvol cache (see [`crate::util::resource`]).
    pub fn image_path(&self) -> Result<PathBuf> {
        let Some(url) = self.image_url() else {
            return Err(Error::Unsatisfied("Unable to run LayerStacker, single_location parameter not provided".into()));
        };
        let r = self.image.get_or_init(|| {
            let _t = crate::util::trace::span("image open (download / decompression)");
            crate::util::resource::open(&url, self.opts.file.as_deref().map(std::path::Path::new), self.opts.offline).map_err(|e| {
                // python logs the stacking exception at warning level
                eprintln!("WARNING  volatility3.framework.plugins: Automagic exception occurred: {e}");
                e.to_string()
            })
        });
        r.clone().map_err(Error::Msg)
    }

    /// python's location of the image: `--single-location` (what `-f` became), or the `file:`
    /// URL of `-f`.
    pub fn image_url(&self) -> Option<String> {
        match (&self.opts.single_location, &self.opts.file) {
            (Some(loc), _) => Some(loc.clone()),
            (None, Some(f)) => Some(crate::util::paths::path_to_file_uri(&std::path::absolute(f).unwrap_or_else(|_| PathBuf::from(f)))),
            (None, None) => None,
        }
    }

    /// The local file of another location a layer reads (swap files), opened like the image.
    fn open_location(&self, loc: &str) -> Option<PathBuf> {
        let local = loc.strip_prefix("file://").map(|p| PathBuf::from(crate::util::paths::unquote(p)));
        let url = match &local {
            Some(_) => loc.to_string(),
            None if crate::util::download::is_remote(loc) => loc.to_string(),
            None => crate::util::paths::path_to_file_uri(&std::path::absolute(loc).unwrap_or_else(|_| PathBuf::from(loc))),
        };
        let local = local.or_else(|| (!crate::util::download::is_remote(loc)).then(|| PathBuf::from(loc)));
        crate::util::resource::open(&url, local.as_deref(), self.opts.offline).ok()
    }

    /// python `memory_layer`: the input file with container layers stacked on it.
    pub fn physical(&self) -> Result<LayerRef> {
        Ok(self.physical_arc()?.1)
    }

    /// `memory_layer` as the owning `Arc` (to build translation layers on) and as `&dyn Layer`.
    pub fn physical_arc(&self) -> Result<&(Arc<dyn Layer>, LayerRef)> {
        keep_err(self.physical.get_or_init(|| {
            let path = self.image_path().map_err(err_text)?;
            let url = self.image_url();
            let st =
                crate::automagic::stack_physical(&path, url.as_deref(), self.opts.offline, self.opts.stackers.as_deref()).map_err(err_text)?;
            let _ = self.physical_listing.set(st.layers);
            let _ = self.native_tables.set(st.native_tables);
            let l = st.layer;
            let r = leak_layer(l.clone());
            Ok((l, r))
        }))
    }

    /// python `get_depends(memory_layer)`: (depth, python layer name, python class name) of the
    /// physical layer stack (depth 0 = `memory_layer`). A kernel translation layer sits on top
    /// at depth 0, so callers listing it add 1 to these depths (see windows.info).
    pub fn physical_listing(&self) -> Result<&[crate::automagic::StackEntry]> {
        self.physical_arc()?;
        Ok(self.physical_listing.get().map(|v| v.as_slice()).unwrap_or(&[]))
    }

    /// Names of the native symbol tables (python `NativeTable`, no `producer` metadata) that
    /// python's container layers put into the symbol space while stacking, before any kernel
    /// table (only VMware's `vmware`). python's `symbol_space.verify_table_versions` raises
    /// `AttributeError` on the first of them.
    pub fn stacking_native_tables(&self) -> Result<&[&'static str]> {
        self.physical_arc()?;
        Ok(self.native_tables.get().map(|v| v.as_slice()).unwrap_or(&[]))
    }

    /// The part of python's `symbol_space.verify_table_versions(producer, validator)` that runs
    /// before the kernel table is reached: the stacking-time native tables come first in the
    /// symbol space and `table.producer` raises on them (python bug; e.g. linux.kmsg on a
    /// VMware .vmem). `Ok(())` when there are none.
    pub fn verify_stacking_tables(&self) -> Result<()> {
        if self.stacking_native_tables()?.is_empty() {
            Ok(())
        } else {
            Err(Error::msg("AttributeError: 'NativeTable' object has no attribute 'producer'"))
        }
    }

    /// The Windows kernel (runs the Windows automagic on first use; cached per image).
    pub fn windows_kernel(&self) -> Result<&WinKernel> {
        keep_err(self.win.get_or_init(|| self.init_windows().map_err(err_text)))
    }

    /// The Linux kernel (runs the Linux automagic on first use; see `automagic::linux`).
    pub fn linux_kernel(&self) -> Result<&crate::automagic::linux::LinuxKernel> {
        keep_err(self.linux.get_or_init(|| crate::automagic::linux::init(self).map_err(err_text)))
    }

    /// The macOS kernel (runs the Mac automagic on first use; see `automagic::mac`).
    pub fn mac_kernel(&self) -> Result<&crate::automagic::mac::MacKernel> {
        keep_err(self.mac.get_or_init(|| crate::automagic::mac::init(self).map_err(err_text)))
    }

    /// Log an automagic failure detail (python logs these at -v levels) and return the python
    /// UnsatisfiedException for `paths`.
    fn unsatisfied(&self, detail: &Error, paths: &[&str]) -> Error {
        if self.opts.verbosity > 0 {
            eprintln!("automagic: {detail}");
        }
        crate::plugins::unsatisfied(paths)
    }

    fn init_windows(&self) -> Result<WinKernel> {
        let _t = crate::util::trace::span("windows kernel init (total)");
        // python: no translation layer -> both the layer and the symbol requirement are
        // unsatisfied; a layer without kernel symbols -> only the symbol requirement
        const LAYER: &[&str] = &["kernel.layer_name", "kernel.symbol_table_name"];
        const SYMS: &[&str] = &["kernel.symbol_table_name"];
        let (phys_arc, phys) = self.physical_arc().map_err(|e| self.unsatisfied(&e, LAYER))?;
        if !crate::automagic::stacker_enabled(self.opts.stackers.as_deref(), "WindowsIntelStacker") {
            return Err(self.unsatisfied(&Error::msg("WindowsIntelStacker disabled by --stackers"), LAYER));
        }
        let image = self.image_path()?;
        let cache_kind = format!("win{}", crate::automagic::stackers_key(self.opts.stackers.as_deref()));
        let cached = crate::automagic::cache::load(&image, &cache_kind).and_then(|kv| {
            use crate::automagic::cache::get;
            let num = |k: &str| get(&kv, k).and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok());
            Some(crate::automagic::windows::WinAutomagic {
                dtb: num("dtb")?,
                mode: match get(&kv, "mode")? {
                    "Intel32" => PagingMode::Intel32,
                    "Pae" => PagingMode::Pae,
                    "Intel32e" => PagingMode::Intel32e,
                    _ => return None,
                },
                kvo: num("kvo")?,
                pdb_name: get(&kv, "pdb")?.to_string(),
                guid: get(&kv, "guid")?.to_string(),
                age: get(&kv, "age")?.parse().ok()?,
            })
        });
        // A kernel symbol table loading speculatively on another thread: when the kernel search
        // has to scan the whole image (no valid KDBG), the module-list candidate is known long
        // before the scan ends, and its ISF (found by name only: no index, no download) loads
        // meanwhile. Used only if it is the final answer.
        type SpecTable = (symbols::IsfLocation, symbols::SymbolTable);
        let spec: Mutex<Option<((String, String, u32), std::thread::JoinHandle<Option<SpecTable>>)>> = Mutex::new(None);
        let am = match cached {
            Some(a) => a,
            None => {
                use crate::automagic::windows::{KernelFound, WinAutomagic, find_dtb, find_kernel_with};
                let d = {
                    let _t = crate::util::trace::span("windows dtb scan");
                    find_dtb(phys_arc).map_err(|e| self.unsatisfied(&e, LAYER))?.ok_or_else(|| self.unsatisfied(&Error::msg("no Windows DTB found"), LAYER))?
                };
                let vl = IntelLayer::new("layer_name", phys_arc.clone(), d.dtb, d.mode, PteFlavor::Windows);
                let k = {
                    let _t = crate::util::trace::span("windows pdbscan");
                    let path = self.symbol_path();
                    let on_candidate = |k: &KernelFound| {
                        let mut g = spec.lock().unwrap_or_else(|e| e.into_inner());
                        if g.is_some() {
                            return;
                        }
                        let key = (k.pdb.pdb_name.clone(), k.pdb.guid.clone(), k.pdb.age);
                        let (pdb, guid, age) = key.clone();
                        let job = move || {
                            let _t = crate::util::trace::span("kernel isf load (speculative)");
                            let loc = symbols::store::find_windows_isf_local(path, &pdb, &guid, age)?;
                            let t = symbols::store::load(&loc, "symbol_table_name", &symbols::BuildOptions::default()).ok()?;
                            Some((loc, t))
                        };
                        if let Ok(h) = std::thread::Builder::new().name("rsvol-spec".into()).spawn(job) {
                            *g = Some((key, h));
                        }
                    };
                    find_kernel_with(&vl, *phys, &on_candidate)
                        .map_err(|e| self.unsatisfied(&e, SYMS))?
                        .ok_or_else(|| self.unsatisfied(&Error::msg("No suitable kernels found during pdbscan"), SYMS))?
                };
                let a = WinAutomagic { dtb: d.dtb, mode: d.mode, kvo: k.kvo, pdb_name: k.pdb.pdb_name, guid: k.pdb.guid, age: k.pdb.age };
                crate::automagic::cache::store(
                    &image,
                    &cache_kind,
                    &[
                        ("dtb", format!("{:#x}", a.dtb)),
                        ("mode", format!("{:?}", a.mode)),
                        ("kvo", format!("{:#x}", a.kvo)),
                        ("pdb", a.pdb_name.clone()),
                        ("guid", a.guid.clone()),
                        ("age", a.age.to_string()),
                    ],
                );
                a
            }
        };
        let swap: Vec<Arc<dyn Layer>> = self
            .opts
            .swap_locations
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                let p = self.open_location(s)?;
                crate::layers::FileLayer::open(&p).ok().map(|f| Arc::new(f.with_name(&format!("swap_layers{i}"))) as Arc<dyn Layer>)
            })
            .collect();
        let layer = IntelLayer::new("layer_name", phys_arc.clone(), am.dtb, am.mode, PteFlavor::Windows)
            .with_os("Windows")
            .with_kernel_virtual_offset(Some(am.kvo))
            .with_swap(swap);
        let layer: &'static IntelLayer = Box::leak(Box::new(layer));
        let vlayer: LayerRef = layer;
        let loc = {
            let _t = crate::util::trace::span("kernel isf lookup");
            symbols::store::find_windows_isf(self.symbol_path(), &am.pdb_name, &am.guid, am.age, self.opts.offline).map_err(|e| self.unsatisfied(&e, SYMS))?
        };
        let speculative = match spec.into_inner().unwrap_or_else(|e| e.into_inner()) {
            Some((key, h)) if key == (am.pdb_name.clone(), am.guid.clone(), am.age) => {
                let _t = crate::util::trace::span("kernel isf load (joining the speculative load)");
                h.join().ok().flatten().filter(|(sloc, _)| *sloc == loc)
            }
            // a wrong guess: that thread finishes (or dies with the process) on its own
            _ => None,
        };
        let table = match speculative {
            Some((_, t)) => symbols::adopt_location(&loc, "symbol_table_name", None, 0, t),
            None => {
                let _t = crate::util::trace::span("kernel isf load");
                symbols::load_location(&loc, "symbol_table_name", None, 0).map_err(|e| self.unsatisfied(&e, SYMS))?
            }
        };
        let module = Module::new(vlayer, table, am.kvo);
        Ok(WinKernel {
            module,
            layer,
            vlayer,
            phys: *phys,
            table,
            base: am.kvo,
            dtb: am.dtb,
            pdb_name: am.pdb_name,
            guid: am.guid,
            age: am.age,
        })
    }

    /// python `IntermediateSymbolTable.create(context, path, sub_path, filename)` by
    /// `"sub/filename"`, e.g. `ctx.load_isf("windows/pe")`. Memoized.
    pub fn load_isf(&self, name: &str) -> Result<TableRef> {
        let (sub, file) = name.rsplit_once('/').unwrap_or(("", name));
        symbols::load_isf(sub, file, None, &[])
    }

    /// `load_isf` with python `native_types=` (another table's natives) and `table_mapping=`.
    pub fn load_isf_with(&self, name: &str, natives: Option<TableRef>, mapping: &[(&str, &str)]) -> Result<TableRef> {
        let (sub, file) = name.rsplit_once('/').unwrap_or(("", name));
        symbols::load_isf(sub, file, natives, mapping)
    }

    /// Load the ISF of a Windows PDB (e.g. a user module's PDB), downloading/converting it if
    /// needed (python `PDBUtility.load_windows_symbol_table`).
    pub fn load_windows_pdb(&self, pdb_name: &str, guid: &str, age: u32) -> Result<TableRef> {
        let loc = symbols::store::find_windows_isf(self.symbol_path(), pdb_name, guid, age, self.opts.offline)?;
        let prefix = pdb_name.trim_end_matches(".pdb").replace('.', "_");
        symbols::load_location(&loc, &prefix, None, 0)
    }

    /// python `PDBUtility.symbol_table_from_pdb(context, path, layer, pdb_name, offset, size)`:
    /// find the RSDS record of `pdb_name` (e.g. "tcpip.pdb") inside `[offset, offset+size)` of
    /// `layer` and load (or download/convert) its ISF.
    pub fn symbol_table_from_pdb(&self, layer: LayerRef, pdb_name: &str, offset: Option<u64>, size: Option<u64>) -> Result<TableRef> {
        Ok(self.modtable_from_pdb(layer, pdb_name, offset, size)?.1)
    }

    /// python `PDBUtility.module_from_pdb(...)`: like [`Context::symbol_table_from_pdb`] but
    /// returns a [`Module`] based at the MZ header found before the RSDS record.
    pub fn module_from_pdb(&self, layer: LayerRef, pdb_name: &str, offset: Option<u64>, size: Option<u64>) -> Result<Module> {
        let (mz, t) = self.modtable_from_pdb(layer, pdb_name, offset, size)?;
        let mz = mz.ok_or_else(|| Error::Symbol(format!("No MZ header found for {pdb_name}")))?;
        Ok(Module::new(layer, t, mz))
    }

    fn modtable_from_pdb(&self, layer: LayerRef, pdb_name: &str, offset: Option<u64>, size: Option<u64>) -> Result<(Option<u64>, TableRef)> {
        let start = offset.unwrap_or(layer.min_address());
        let size = size.unwrap_or_else(|| layer.max_address().wrapping_sub(start));
        let mut first = None;
        crate::automagic::windows::pdbname_scan(layer, &[pdb_name.as_bytes()], Some(start), Some(start.wrapping_add(size)), |s| {
            first = Some(s);
            false
        });
        let s = first.ok_or_else(|| Error::Symbol(format!("Did not find GUID of {pdb_name} in module @ {start:#x}!")))?;
        let t = self.load_windows_pdb(&s.pdb_name, &s.guid, s.age)?;
        Ok((s.mz_offset, t))
    }

    /// Create a file in the output directory (volatility3 CLIFileHandler semantics: if the
    /// preferred name already exists a counter is appended, see `cli::files::create`).
    /// Returns the open file and the FINAL file name, which is what python's
    /// `file_handle.preferred_filename` holds after `close()` (plugins that read it before
    /// closing, like `pedump.dump_pe`, print the preferred name instead).
    pub fn create_output_file(&self, preferred_name: &str) -> Result<(File, String)> {
        let _g = self.output_lock.lock().unwrap_or_else(|e| e.into_inner());
        let dir = OUTPUT_DIR_OVERRIDE.with(|d| d.borrow().clone());
        crate::cli::files::create(dir.as_deref().unwrap_or(&self.opts.output_dir), preferred_name)
    }
}

thread_local! {
    static OUTPUT_DIR_OVERRIDE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Run `f` with [`Context::create_output_file`] writing into `dir` (instead of
/// `opts.output_dir`) for calls made on this thread. `vol serve` uses it to give every plugin
/// run its own output directory while all runs share one `Context`.
pub fn with_output_dir<R>(dir: &str, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<String>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let prev = self.0.take();
            OUTPUT_DIR_OVERRIDE.with(|d| *d.borrow_mut() = prev);
        }
    }
    let _restore = Restore(OUTPUT_DIR_OVERRIDE.with(|d| d.borrow_mut().replace(dir.to_string())));
    f()
}

#[cfg(test)]
mod bench {
    use super::*;
    use crate::layers::LayerExt;
    use crate::layers::scan::{BytesScanner, scan};

    /// A physical layer that corrupts ~`rate`% of pages (deterministically) to simulate smear.
    struct Smear {
        inner: Arc<dyn Layer>,
        rate: u64,
        seed: u64,
    }
    impl Smear {
        fn corrupt(&self, page: u64) -> Option<u64> {
            let h = crate::util::fxhash::hash_u64(page ^ self.seed);
            if h % 100 < self.rate { Some(h) } else { None }
        }
    }
    impl Layer for Smear {
        fn name(&self) -> &str {
            "smear"
        }
        fn max_address(&self) -> u64 {
            self.inner.max_address()
        }
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read(addr, buf)?;
            for (i, b) in buf.iter_mut().enumerate() {
                let a = addr + i as u64;
                if let Some(h) = self.corrupt(a >> 12) {
                    *b ^= (crate::util::fxhash::hash_u64(h ^ a) & 0xff) as u8;
                }
            }
            Ok(())
        }
        fn is_valid(&self, addr: u64, len: u64) -> bool {
            self.inner.is_valid(addr, len)
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(crate::layers::Mapping) -> bool) {
            self.inner.mapping(addr, len, f)
        }
        fn lower(&self) -> Option<&Arc<dyn Layer>> {
            Some(&self.inner)
        }
    }

    /// `cargo test --release smear_robustness -- --ignored --nocapture`: walk processes, VADs,
    /// modules, strings, tokens over a physical layer with corrupted pages -- errors are fine,
    /// panics are not.
    #[test]
    #[ignore]
    fn smear_robustness() {
        use crate::symbols::windows::prelude::*;
        let img = std::env::var("RSVOL_BENCH_IMG").unwrap_or_else(|_| "/home/user/cbc2/task2/memory-dirty.raw".into());
        let ctx = Context::new(GlobalOptions { file: Some(img), ..Default::default() }).unwrap();
        let k = ctx.windows_kernel().unwrap();
        let (phys, _) = ctx.physical_arc().unwrap();
        for rate in [1u64, 5, 20, 50] {
            let smear: Arc<dyn Layer> = Arc::new(Smear { inner: phys.clone(), rate, seed: 0x5eed });
            let vl = IntelLayer::new("layer_name", smear, k.dtb, k.layer.mode(), PteFlavor::Windows).with_kernel_virtual_offset(Some(k.base));
            let vl: &'static IntelLayer = Box::leak(Box::new(vl));
            let kk = WinKernel { module: Module::new(vl, k.table, k.base), layer: vl, vlayer: vl, phys: k.phys, table: k.table, base: k.base, dtb: k.dtb, pdb_name: String::new(), guid: String::new(), age: 0 };
            let (mut procs, mut vads, mut mods, mut errs) = (0, 0, 0, 0);
            for p in crate::plugins::windows::pslist::list_processes(&kk, &|_| Ok(false)) {
                let Ok(p) = p else {
                    errs += 1;
                    continue;
                };
                procs += 1;
                let _ = p.is_valid();
                let _ = p.image_file_name();
                let _ = p.get_create_time();
                let _ = p.get_session_id();
                let _ = p.get_handle_count();
                let _ = p.environment_variables();
                if let Ok(t) = p.m("Token").and_then(|t| t.fast_ref_dereference()).and_then(|t| t.cast("_TOKEN")) {
                    let _ = t.get_sids();
                    let _ = t.privileges();
                }
                if let Ok(root) = p.get_vad_root() {
                    for v in root.traverse() {
                        match v {
                            Ok(v) => {
                                vads += 1;
                                let _ = (v.get_start(), v.get_end(), v.get_file_name(), v.get_commit_charge(), v.get_parent());
                            }
                            Err(_) => errs += 1,
                        }
                    }
                }
                for m in p.load_order_modules() {
                    match m {
                        Ok(m) => {
                            mods += 1;
                            let _ = m.m("FullDllName").and_then(|n| n.get_string());
                        }
                        Err(_) => errs += 1,
                    }
                }
            }
            for m in crate::plugins::windows::modules::list_modules(&kk) {
                if let Ok(m) = m {
                    let _ = m.m("BaseDllName").and_then(|n| n.get_string());
                }
            }
            println!("smear {rate}%: {procs} procs, {vads} vads, {mods} modules, {errs} errors, no panic");
        }
    }

    /// Render `rows` with the quick renderer (plus the version banner) and diff them against a
    /// python reference file.
    fn assert_rendered_like(name: &str, cols: Vec<crate::renderers::Column>, rows: Vec<Vec<crate::renderers::Value>>, refp: &str) {
        let mut out: Vec<u8> = b"Volatility 3 Framework 2.28.2\n".to_vec();
        {
            let mut r = crate::renderers::text::create("quick", &mut out, Default::default()).unwrap();
            r.begin(cols).unwrap();
            for row in rows {
                r.row(0, row).unwrap();
            }
            r.finish().unwrap();
        }
        let reference = std::fs::read(refp).unwrap();
        if out != reference {
            let a = String::from_utf8_lossy(&out);
            let b = String::from_utf8_lossy(&reference);
            for (i, (x, y)) in a.lines().zip(b.lines()).enumerate() {
                assert_eq!(x, y, "{name}: line {i} differs");
            }
            panic!("{name}: length differs: ours {} lines, ref {} lines", a.lines().count(), b.lines().count());
        }
        println!("{name} via core API: byte-identical ({} bytes)", out.len());
    }

    /// API proof for the named-object helpers (`ObjectsExt`) on top of the pool scanner:
    /// windows.symlinkscan, windows.mutantscan and windows.driverscan rebuilt from the core API
    /// are byte-identical to python's output on the main image.
    #[test]
    #[ignore]
    fn object_scans_via_core_api() {
        use crate::plugins::windows::poolscanner::{builtin_constraints, generate_pool_scan_each};
        use crate::renderers::{ColType, Column, Value};
        use crate::symbols::windows::objects::is_name_info_value_error;
        use crate::symbols::windows::prelude::*;
        let ctx = Context::new(GlobalOptions { file: Some("/home/user/cbc2/task2/memory-dirty.raw".into()), ..Default::default() }).unwrap();
        let k = ctx.windows_kernel().unwrap();
        let refdir = "/home/user/rs-vol/bench/ref/py";
        let skip = |e: &Error| is_name_info_value_error(e) || e.is_invalid_address();

        // symlinkscan
        let mut rows = Vec::new();
        generate_pool_scan_each(&ctx, k, k.table, &builtin_constraints(k.table.name(), &[b"Sym\xe2", b"Symb"]), |h| {
            let link = h.object;
            let from = match link.get_link_name() {
                Ok(n) => n,
                Err(e) if skip(&e) => return Ok(true),
                Err(e) => return Err(e),
            };
            let to = match link.m("LinkTarget").and_then(|t| t.get_string()) {
                Ok(n) => n,
                Err(e) if e.is_invalid_address() => return Ok(true),
                Err(e) => return Err(e),
            };
            rows.push(vec![Value::Int(link.addr as i128), link.get_create_time()?, Value::Str(from), Value::Str(to)]);
            Ok(true)
        })
        .unwrap();
        let cols = vec![Column::new("Offset", ColType::Hex), Column::new("CreateTime", ColType::DateTime), Column::new("From Name", ColType::Str), Column::new("To Name", ColType::Str)];
        assert_rendered_like("symlinkscan", cols, rows, &format!("{refdir}/windows.symlinkscan.SymlinkScan.txt"));

        // mutantscan
        let mut rows = Vec::new();
        generate_pool_scan_each(&ctx, k, k.table, &builtin_constraints(k.table.name(), &[b"Mut\xe1", b"Muta"]), |h| {
            let name = match h.object.mutant_name() {
                Ok(n) => Value::Str(n),
                Err(e) if skip(&e) => Value::NotApplicable,
                Err(e) => return Err(e),
            };
            rows.push(vec![Value::Int(h.object.addr as i128), name]);
            Ok(true)
        })
        .unwrap();
        let cols = vec![Column::new("Offset", ColType::Hex), Column::new("Name", ColType::Str)];
        assert_rendered_like("mutantscan", cols, rows, &format!("{refdir}/windows.mutantscan.MutantScan.txt"));

        // driverscan
        let start_off = k.offset_of("_DRIVER_OBJECT", "DriverStart").unwrap();
        let kstart = crate::plugins::windows::modules::get_kernel_space_start(k).unwrap();
        let mut rows = Vec::new();
        generate_pool_scan_each(&ctx, k, k.table, &builtin_constraints(k.table.name(), &[b"Dri\xf6", b"Driv"]), |h| {
            let d = h.object;
            if !d.layer().is_valid(d.addr + start_off, 8) {
                return Ok(true);
            }
            let ds = d.m("DriverStart")?.u64()?;
            if !(ds == 0 || ds > kstart) {
                return Ok(true);
            }
            let driver_name = match d.get_driver_name() {
                Ok(n) => Some(n),
                Err(e) if skip(&e) => None,
                Err(e) => return Err(e),
            };
            let opt = |r: Result<String>| match r {
                Ok(s) => Ok(Some(s)),
                Err(e) if e.is_invalid_address() => Ok(None),
                Err(e) => Err(e),
            };
            let service_key = opt(d.m("DriverExtension").and_then(|x| x.deref()).and_then(|x| x.m("ServiceKeyName")).and_then(|x| x.get_string()))?;
            let name = opt(d.m("DriverName").and_then(|x| x.get_string()))?;
            let truthy = |s: &Option<String>| s.as_ref().is_some_and(|s| !s.is_empty());
            if !truthy(&driver_name) && !truthy(&service_key) && !truthy(&name) {
                return Ok(true);
            }
            let v = |s: Option<String>| if truthy(&s) { Value::Str(s.unwrap()) } else { Value::NotAvailable };
            rows.push(vec![
                Value::Int(d.addr as i128),
                Value::Int(ds as i128),
                Value::Int(d.m("DriverSize")?.int()?),
                v(service_key),
                v(driver_name),
                v(name),
            ]);
            Ok(true)
        })
        .unwrap();
        let cols = vec![
            Column::new("Offset", ColType::Hex),
            Column::new("Start", ColType::Hex),
            Column::new("Size", ColType::Hex),
            Column::new("Service Key", ColType::Str),
            Column::new("Driver Name", ColType::Str),
            Column::new("Name", ColType::Str),
        ];
        assert_rendered_like("driverscan", cols, rows, &format!("{refdir}/windows.driverscan.DriverScan.txt"));

        // FILE_OBJECT.file_name_with_device for every File handle python's windows.handles
        // printed (Offset = object body on the kernel layer, Name = file_name_with_device)
        let handles = std::fs::read_to_string(format!("{refdir}/windows.handles.Handles.txt")).unwrap();
        let mut n = 0;
        for line in handles.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 7 || f[4] != "File" {
                continue;
            }
            let off = u64::from_str_radix(f[2].trim_start_matches("0x"), 16).unwrap();
            let fo = k.object_abs("_FILE_OBJECT", off).unwrap();
            let ours = match fo.file_name_with_device().unwrap() {
                Value::Str(s) => s,
                Value::Unreadable => "-".to_string(),
                v => panic!("{v:?}"),
            };
            assert_eq!(ours, f[6..].join("\t"), "file_name_with_device at {off:#x}");
            assert!(fo.access_string().unwrap().len() == 6);
            n += 1;
        }
        println!("file_name_with_device: {n} handle names identical");
    }

    /// The TLB fast path of multi-page `is_valid` answers exactly like python's `_mapping`
    /// walk: random ranges (1 byte .. 64 pages) around mapped/unmapped boundaries of the
    /// windows kernel, windows process layers and a linux ELF-core kernel (segmented phys).
    #[test]
    #[ignore]
    fn is_valid_fast_path_is_exact() {
        let check = |name: &str, l: &IntelLayer, seed: u64| {
            let runs = l.mappings(0, l.max_address());
            let mut x = seed | 1;
            let mut next = || {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x
            };
            let (mut n, mut valid) = (0u64, 0u64);
            for _ in 0..200_000 {
                let m = &runs[next() as usize % runs.len()];
                // start near either edge of a mapped run, or inside it
                let base = match next() % 3 {
                    0 => m.offset.wrapping_sub(next() % 0x3000),
                    1 => (m.offset + m.len).wrapping_sub(next() % 0x3000),
                    _ => m.offset + next() % m.len.max(1),
                };
                let len = match next() % 4 {
                    0 => 1 + next() % 16,
                    1 => 1 + next() % 0x1000,
                    2 => 1 + next() % 0x10000,
                    _ => 1 + next() % (64 * 0x1000),
                };
                let (fast, exact) = (l.is_valid(base, len), l.is_valid_exact(base, len));
                assert_eq!(fast, exact, "{name}: is_valid({base:#x}, {len:#x})");
                n += 1;
                valid += fast as u64;
            }
            println!("{name}: {n} ranges, {valid} valid, identical");
        };
        let ctx = Context::new(GlobalOptions { file: Some("/home/user/cbc2/task2/memory-dirty.raw".into()), ..Default::default() }).unwrap();
        let k = ctx.windows_kernel().unwrap();
        check("windows kernel", k.layer, 1);
        let procs: Vec<_> = crate::plugins::windows::pslist::list_processes(k, &|_| Ok(false)).into_iter().filter_map(|p| p.ok()).collect();
        for p in procs.iter().take(4) {
            let dtb = p.m("Pcb").and_then(|pcb| pcb.m("DirectoryTableBase")).and_then(|d| d.u64()).unwrap();
            let pl = k.layer.process_layer(dtb, "proc");
            check("windows process", &pl, dtb);
        }
        let ctx = Context::new(GlobalOptions {
            file: Some("/home/user/rs-vol/testdata/images/linux/rsvol-noble-6.8.0-139.elf".into()),
            symbol_dirs: vec!["/home/user/rs-vol/testdata/symbols".into()],
            ..Default::default()
        })
        .unwrap();
        let lk = ctx.linux_kernel().unwrap();
        check("linux ELF kernel", lk.layer, 7);
    }

    /// The Linux walkers and class helpers on a corrupted (segmented ELF-core) physical layer:
    /// task lists with threads, task fields, creds, create times, VMAs (maple tree on 6.8)
    /// and mapped file paths must never panic.
    #[test]
    #[ignore]
    fn smear_robustness_linux() {
        use crate::automagic::linux::LinuxKernel;
        use crate::symbols::linux::LinuxExt;
        for img in ["rsvol-noble-6.8.0-139.elf", "rsvol-jammy-5.15.0-191.lime"] {
            let ctx = Context::new(GlobalOptions {
                file: Some(format!("/home/user/rs-vol/testdata/images/linux/{img}")),
                symbol_dirs: vec!["/home/user/rs-vol/testdata/symbols".into()],
                ..Default::default()
            })
            .unwrap();
            let k = ctx.linux_kernel().unwrap();
            let (phys, _) = ctx.physical_arc().unwrap();
            for (rate, seed) in [0u64, 1, 2, 5, 10, 20, 50].into_iter().flat_map(|r| (1..=4u64).map(move |s| (r, s * 0x9e37_79b9))) {
                let smear: Arc<dyn Layer> = Arc::new(Smear { inner: phys.clone(), rate, seed });
                let vl = IntelLayer::new("layer_name", smear, k.dtb, k.layer.mode(), k.layer.flavor())
                    .with_os("linux")
                    .with_kernel_virtual_offset(Some(k.aslr_shift));
                let vl: &'static IntelLayer = Box::leak(Box::new(vl));
                let kk = LinuxKernel {
                    module: Module::new(vl, k.table, k.aslr_shift),
                    layer: vl,
                    vlayer: vl,
                    phys: k.phys,
                    table: k.table,
                    kaslr_shift: k.kaslr_shift,
                    aslr_shift: k.aslr_shift,
                    dtb: k.dtb,
                    banner: k.banner.clone(),
                    stacker: k.stacker,
                };
                let (mut tasks, mut vmas, mut files, mut errs) = (0, 0, 0, 0);
                let r = crate::plugins::linux::pslist::list_tasks(&kk, &|_| Ok(false), true, &mut |t| {
                    tasks += 1;
                    if crate::plugins::linux::pslist::get_task_fields(&t, true).is_err() {
                        errs += 1;
                    }
                    let _ = (t.is_valid(), t.state(), t.get_threads().len(), t.get_boottime(true));
                    let _ = t.add_process_layer();
                    if let Ok(mm) = t.m("mm").and_then(|m| m.deref()) {
                        for v in mm.get_vma_iter().into_iter().take(256) {
                            let Ok(v) = v else {
                                errs += 1;
                                continue;
                            };
                            vmas += 1;
                            let _ = (v.vma_is_valid(), v.get_protection(), v.get_flags(), v.get_page_offset());
                            if let Ok(f) = v.m("vm_file").and_then(|f| f.deref()) {
                                files += 1;
                                let _ = (f.get_dentry(), f.get_vfsmnt(), f.get_inode());
                            }
                        }
                    }
                    Ok(true)
                });
                if r.is_err() {
                    errs += 1;
                }
                println!("{img} smear {rate}% seed {seed:#x}: {tasks} tasks, {vmas} vmas, {files} files, {errs} errors, no panic");
            }
        }
    }

    /// The Mac walkers and class helpers on a corrupted physical layer: every list method,
    /// process layers, map entries, fileglob types and vnode paths must never panic.
    #[test]
    #[ignore]
    fn smear_robustness_mac() {
        use crate::automagic::mac::MacKernel;
        use crate::symbols::mac::{MAX_ELEMENTS, MacExt};
        let img = "/home/user/rs-vol/testdata/images/mac/rsvol-mac-mavericks-10.9.2-13C64.dmp".to_string();
        let ctx = Context::new(GlobalOptions {
            file: Some(img),
            symbol_dirs: vec!["/home/user/rs-vol/testdata/symbols".into()],
            ..Default::default()
        })
        .unwrap();
        let k = ctx.mac_kernel().unwrap();
        let (phys, _) = ctx.physical_arc().unwrap();
        for (rate, seed) in [0u64, 1, 2, 5, 10, 20, 50].into_iter().flat_map(|r| (1..=6u64).map(move |s| (r, s * 0x9e37_79b9))) {
            let smear: Arc<dyn Layer> = Arc::new(Smear { inner: phys.clone(), rate, seed });
            let vl = IntelLayer::new("layer_name", smear, k.dtb, k.layer.mode(), PteFlavor::Generic)
                .with_os("mac")
                .with_kernel_virtual_offset(Some(k.kaslr_shift));
            let vl: &'static IntelLayer = Box::leak(Box::new(vl));
            let kk = MacKernel {
                module: Module::new(vl, k.table, k.kaslr_shift),
                layer: vl,
                vlayer: vl,
                phys: k.phys,
                table: k.table,
                kaslr_shift: k.kaslr_shift,
                dtb: k.dtb,
                banner: k.banner.clone(),
                isf: k.isf.clone(),
            };
            let (mut procs, mut entries, mut files, mut errs) = (0, 0, 0, 0);
            for method in crate::plugins::mac::pslist::PSLIST_METHODS {
                for p in crate::plugins::mac::pslist::list_tasks(&kk, method, &|_| Ok(false)) {
                    let Ok(p) = p else {
                        errs += 1;
                        continue;
                    };
                    procs += 1;
                    let _ = p.m("p_comm").and_then(|c| crate::objects::util::array_to_string(&c, None));
                    let Ok(task) = p.get_task() else { continue };
                    let _ = task.m("map");
                    let _ = p.add_process_layer();
                    for e in p.get_map_iter().into_iter().take(64) {
                        match e {
                            Ok(e) => {
                                entries += 1;
                                let _ = (e.get_perms(), e.get_range_alias(), e.get_special_path(), e.get_offset());
                                if let Ok(o) = e.get_object() {
                                    let _ = o.get_map_object();
                                }
                            }
                            Err(_) => errs += 1,
                        }
                    }
                    // proc.p_fd.fd_ofiles[0..=fd_lastfile]: fileglob types and vnode paths
                    let Ok(fd) = p.m("p_fd").and_then(|f| f.deref()) else { continue };
                    let n = fd.m("fd_lastfile").and_then(|n| n.int()).unwrap_or(0).clamp(0, 64) as u64;
                    let Ok(first) = fd.m("fd_ofiles").and_then(|f| f.deref()) else { continue };
                    let arr = first.cast_array(n + 1, first.ty);
                    for fp in arr.elements() {
                        let Ok(f) = fp.deref() else { continue };
                        let Ok(fg) = f.m("f_fglob").and_then(|g| g.deref()) else { continue };
                        files += 1;
                        let _ = fg.get_fg_type();
                        if let Ok(v) = fg.m("fg_data").and_then(|d| d.deref()).and_then(|d| d.cast("vnode")) {
                            let _ = v.full_path();
                        }
                    }
                }
            }
            let _ = kk.object_from_symbol("allproc").map(|a| a.walk_list_head("le_next", MAX_ELEMENTS));
            println!("mac smear {rate}% seed {seed:#x}: {procs} procs, {entries} map entries, {files} files, {errs} errors, no panic");
        }
    }

    /// API proof against python: windows.dlllist.DllList's default output rebuilt from the
    /// core extension API (get_peb / load_order_modules / UNICODE_STRING / get_load_count on
    /// process layers), rendered by the real quick renderer and diffed with the reference.
    #[test]
    #[ignore]
    fn dlllist_via_core_api() {
        use crate::renderers::{ColType, Column, Value};
        use crate::symbols::windows::WinExt;
        use crate::util::time::wintime_to_datetime;
        let img = std::env::var("RSVOL_BENCH_IMG").unwrap_or_else(|_| "/home/user/cbc2/task2/memory-dirty.raw".into());
        let refp = std::env::var("RSVOL_BENCH_REF").unwrap_or_else(|_| "/home/user/rs-vol/bench/ref/py/windows.dlllist.DllList.txt".into());
        let ctx = Context::new(GlobalOptions { file: Some(img), ..Default::default() }).unwrap();
        let k = ctx.windows_kernel().unwrap();
        let mut out: Vec<u8> = b"Volatility 3 Framework 2.28.2\n".to_vec();
        {
            let mut r = crate::renderers::text::create("quick", &mut out, Default::default()).unwrap();
            r.begin(vec![
                Column::new("PID", ColType::Int),
                Column::new("Process", ColType::Str),
                Column::new("Base", ColType::Hex),
                Column::new("Size", ColType::Hex),
                Column::new("Name", ColType::Str),
                Column::new("Path", ColType::Str),
                Column::new("LoadCount", ColType::Int),
                Column::new("LoadTime", ColType::DateTime),
                Column::new("File output", ColType::Str),
            ])
            .unwrap();
            let kuser = crate::plugins::windows::info::get_kuser_structure(k).unwrap();
            let (maj, min) = (kuser.m("NtMajorVersion").unwrap().int().unwrap(), kuser.m("NtMinorVersion").unwrap().int().unwrap());
            let load_time_field = maj > 6 || (maj == 6 && min >= 1);
            for p in crate::plugins::windows::pslist::list_processes(k, &|_| Ok(false)) {
                let proc = p.unwrap();
                proc.add_process_layer().unwrap();
                for e in proc.load_order_modules() {
                    let e = e.unwrap();
                    let (mut base_name, mut full_name) = (Value::Unreadable, Value::Unreadable);
                    if let Ok(b) = e.m("BaseDllName").and_then(|n| n.get_string()) {
                        base_name = Value::Str(b);
                        if let Ok(f) = e.m("FullDllName").and_then(|n| n.get_string()) {
                            full_name = Value::Str(f);
                        }
                    }
                    let load_time = if load_time_field {
                        e.path("LoadTime.QuadPart").and_then(|q| q.int()).map(wintime_to_datetime).unwrap_or(Value::Unreadable)
                    } else {
                        Value::NotApplicable
                    };
                    let hexv = |r: crate::error::Result<i128>| r.map(Value::Int).unwrap_or(Value::NotAvailable);
                    r.row(
                        0,
                        vec![
                            Value::Int(proc.m("UniqueProcessId").unwrap().int().unwrap()),
                            Value::Str(proc.image_file_name_str().unwrap()),
                            hexv(e.m("DllBase").and_then(|x| x.int())),
                            hexv(e.m("SizeOfImage").and_then(|x| x.int())),
                            base_name,
                            full_name,
                            e.get_load_count().map(Value::Int).unwrap_or(Value::NotAvailable),
                            load_time,
                            Value::SStr("Disabled"),
                        ],
                    )
                    .unwrap();
                }
            }
            r.finish().unwrap();
        }
        let reference = std::fs::read(&refp).unwrap();
        if out != reference {
            let a = String::from_utf8_lossy(&out);
            let b = String::from_utf8_lossy(&reference);
            for (i, (x, y)) in a.lines().zip(b.lines()).enumerate() {
                if x != y {
                    panic!("line {i} differs:\n ours: {x}\n  ref: {y}");
                }
            }
            panic!("length differs: ours {} lines, ref {} lines", a.lines().count(), b.lines().count());
        }
        println!("dlllist via core API: byte-identical ({} bytes)", out.len());
    }

    /// `cargo test --release module_pdb_lookup -- --ignored --nocapture` (needs the test image
    /// and tcpip.pdb's ISF in a symbol dir): python `PDBUtility.module_from_pdb` for tcpip.sys.
    #[test]
    #[ignore]
    fn module_pdb_lookup() {
        use crate::symbols::windows::WinExt;
        let img = std::env::var("RSVOL_BENCH_IMG").unwrap_or_else(|_| "/home/user/cbc2/task2/memory-dirty.raw".into());
        let ctx = Context::new(GlobalOptions { file: Some(img), ..Default::default() }).unwrap();
        let k = ctx.windows_kernel().unwrap();
        let m = crate::plugins::windows::modules::list_modules(k)
            .into_iter()
            .filter_map(|m| m.ok())
            .find(|m| m.m("BaseDllName").and_then(|n| n.get_string()).map(|n| n.eq_ignore_ascii_case("tcpip.sys")).unwrap_or(false))
            .unwrap();
        let base = m.m("DllBase").unwrap().u64().unwrap();
        let size = m.m("SizeOfImage").unwrap().u64().unwrap();
        let t = std::time::Instant::now();
        let md = ctx.module_from_pdb(k.vlayer, "tcpip.pdb", Some(base), Some(size)).unwrap();
        println!("tcpip.pdb module at {:#x} (DllBase {base:#x}), table {} from {} in {:.2} ms", md.offset, md.table().name(), md.table().isf_url(), t.elapsed().as_secs_f64() * 1e3);
        assert_eq!(md.offset, base);
        assert!(md.table().symbol_count() > 0);
    }

    /// `RSVOL_BENCH_IMG=... cargo test --release translation_bench -- --ignored --nocapture`
    /// (run through bench/scripts/limit.sh): page-walk / mapping / virtual-scan throughput.
    #[test]
    #[ignore]
    fn translation_bench() {
        let img = std::env::var("RSVOL_BENCH_IMG").unwrap_or_else(|_| "/home/user/cbc2/task2/memory-dirty.raw".into());
        let ctx = Context::new(GlobalOptions { file: Some(img), ..Default::default() }).unwrap();
        let k = ctx.windows_kernel().unwrap();
        let t = std::time::Instant::now();
        let runs = k.vlayer.mappings(0, (1 << 48) - 1);
        let bytes: u64 = runs.iter().map(|m| m.len).sum();
        let d = t.elapsed();
        println!("kernel layer mapping(0, 2^48): {} runs, {} MiB mapped, {:.2} ms", runs.len(), bytes >> 20, d.as_secs_f64() * 1e3);
        let t = std::time::Instant::now();
        let mut pages = 0u64;
        let mut buf = vec![0u8; 0x1000];
        for m in &runs {
            let mut a = m.offset;
            while a < m.offset + m.len {
                let n = 0x1000.min(m.offset + m.len - a) as usize;
                k.vlayer.read_padded(a, &mut buf[..n]);
                pages += 1;
                a += n as u64;
            }
        }
        let d = t.elapsed();
        println!("read_padded of every mapped kernel page: {pages} pages, {:.2} ms ({:.0} ns/page)", d.as_secs_f64() * 1e3, d.as_nanos() as f64 / pages as f64);
        let t = std::time::Instant::now();
        let hits = scan(k.vlayer, &BytesScanner::new(b"RSDS"), None);
        let d = t.elapsed();
        println!("virtual scan of the kernel layer for RSDS: {} hits, {:.2} ms", hits.len(), d.as_secs_f64() * 1e3);
        let procs: Vec<_> = crate::plugins::windows::pslist::list_processes(k, &|_| Ok(false)).into_iter().filter_map(|p| p.ok()).collect();
        let t = std::time::Instant::now();
        let mut ubytes = 0u64;
        for p in &procs {
            use crate::symbols::windows::WinExt;
            if let Ok(l) = p.add_process_layer() {
                ubytes += l.mappings(0, 0x7FFF_FFFF_FFFF).iter().map(|m| m.len).sum::<u64>();
            }
        }
        let d = t.elapsed();
        println!("user-space mapping of {} processes: {} MiB, {:.2} ms", procs.len(), ubytes >> 20, d.as_secs_f64() * 1e3);
    }
}
