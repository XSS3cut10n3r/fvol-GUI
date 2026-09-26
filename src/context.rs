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
use std::path::{Path, PathBuf};
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
    physical: Lazy<(Arc<dyn Layer>, LayerRef)>,
    physical_listing: OnceLock<Vec<crate::automagic::StackEntry>>,
    win: Lazy<WinKernel>,
    linux: Lazy<crate::automagic::linux::LinuxKernel>,
    mac: Lazy<crate::automagic::mac::MacKernel>,
    output_lock: Mutex<()>,
}

fn keep_err<T>(r: &std::result::Result<T, String>) -> Result<&T> {
    r.as_ref().map_err(|e| Error::Unsatisfied(e.clone()))
}

impl Context {
    /// Cheap: records options and sets the symbol search path. Nothing is opened or scanned.
    pub fn new(opts: GlobalOptions) -> Result<Context> {
        if opts.clear_cache {
            // python --clear-cache wipes its identifier cache and cached data; ours are the
            // identifier index, the automagic results and the binary symbol tables
            let dir = crate::util::paths::rsvol_cache_dir();
            let _ = std::fs::remove_file(dir.join("identifiers.cache"));
            let _ = std::fs::remove_dir_all(dir.join("automagic"));
            let _ = std::fs::remove_dir_all(dir.join("isf"));
        }
        symbols::set_symbol_path(SymbolPath::new(&opts.symbol_dirs));
        Ok(Context {
            opts,
            physical: OnceLock::new(),
            physical_listing: OnceLock::new(),
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

    /// Path of the input image (`-f` or a `file://` `--single-location`).
    pub fn image_path(&self) -> Result<PathBuf> {
        if let Some(f) = &self.opts.file {
            return Ok(PathBuf::from(f));
        }
        if let Some(loc) = &self.opts.single_location {
            if let Some(p) = loc.strip_prefix("file://") {
                return Ok(PathBuf::from(percent_decode(p)));
            }
            return Ok(PathBuf::from(loc));
        }
        Err(Error::Unsatisfied("Unable to run LayerStacker, single_location parameter not provided".into()))
    }

    /// python `memory_layer`: the input file with container layers stacked on it.
    pub fn physical(&self) -> Result<LayerRef> {
        Ok(self.physical_arc()?.1)
    }

    /// `memory_layer` as the owning `Arc` (to build translation layers on) and as `&dyn Layer`.
    pub fn physical_arc(&self) -> Result<&(Arc<dyn Layer>, LayerRef)> {
        keep_err(self.physical.get_or_init(|| {
            let path = self.image_path().map_err(|e| e.to_string())?;
            let (l, listing) = crate::automagic::stack_physical(&path, self.opts.stackers.as_deref()).map_err(|e| e.to_string())?;
            let _ = self.physical_listing.set(listing);
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

    /// The Windows kernel (runs the Windows automagic on first use; cached per image).
    pub fn windows_kernel(&self) -> Result<&WinKernel> {
        keep_err(self.win.get_or_init(|| self.init_windows().map_err(|e| e.to_string())))
    }

    /// The Linux kernel (runs the Linux automagic on first use; see `automagic::linux`).
    pub fn linux_kernel(&self) -> Result<&crate::automagic::linux::LinuxKernel> {
        keep_err(self.linux.get_or_init(|| crate::automagic::linux::init(self).map_err(|e| e.to_string())))
    }

    /// The macOS kernel (runs the Mac automagic on first use; see `automagic::mac`).
    pub fn mac_kernel(&self) -> Result<&crate::automagic::mac::MacKernel> {
        keep_err(self.mac.get_or_init(|| crate::automagic::mac::init(self).map_err(|e| e.to_string())))
    }

    fn init_windows(&self) -> Result<WinKernel> {
        let _t = crate::util::trace::span("windows kernel init (total)");
        let (phys_arc, phys) = self.physical_arc()?;
        if !crate::automagic::stacker_enabled(self.opts.stackers.as_deref(), "WindowsIntelStacker") {
            return Err(Error::Unsatisfied("WindowsIntelStacker disabled by --stackers".into()));
        }
        let image = self.image_path()?;
        let cached = crate::automagic::cache::load(&image, "win").and_then(|kv| {
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
        let am = match cached {
            Some(a) => a,
            None => {
                let a = crate::automagic::windows::run(phys_arc)?;
                crate::automagic::cache::store(
                    &image,
                    "win",
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
                let p = s.strip_prefix("file://").map(percent_decode).unwrap_or_else(|| s.clone());
                crate::layers::FileLayer::open(Path::new(&p)).ok().map(|f| Arc::new(f.with_name(&format!("swap_layers{i}"))) as Arc<dyn Layer>)
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
            symbols::store::find_windows_isf(self.symbol_path(), &am.pdb_name, &am.guid, am.age, self.opts.offline)?
        };
        let table = {
            let _t = crate::util::trace::span("kernel isf load");
            symbols::load_location(&loc, "symbol_table_name", None, 0)?
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
        let _g = self.output_lock.lock().unwrap();
        crate::cli::files::create(&self.opts.output_dir, preferred_name)
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() + 0 && i + 2 <= b.len() - 1 {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod bench {
    use super::*;
    use crate::layers::LayerExt;
    use crate::layers::scan::{BytesScanner, scan};

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
