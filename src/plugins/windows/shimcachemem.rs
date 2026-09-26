//! windows.shimcachemem.ShimcacheMem (python `plugins/windows/shimcachemem.py`): shimcache
//! entries from the ahcache.sys (8.1+) / ntoskrnl (8.0, 2003-7) AVL tables, or the XP
//! shared-section cache.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::{Context, WinKernel};
use crate::error::{Error, Result};
use crate::layers::LayerExt;
use crate::layers::intel::Target;
use crate::objects::util::address_to_string;
use crate::objects::{LayerRef, Obj, Space};
use crate::plugins::windows::{pslist, vadinfo};
use crate::plugins::{Config, Plugin, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::TableRef;
use crate::symbols::windows::cache::eresource_is_valid;
use crate::symbols::windows::prelude::*;
use crate::symbols::windows::shimcache::ShimcacheExt;
use crate::symbols::windows::versions::{self, OsDistinguisher};
use crate::util::FxHashSet;
use crate::util::par;
use std::sync::{Condvar, Mutex};

pub struct ShimcacheMem;

/// python `_win_version_file_map` (checked newest -> oldest; `shimcache-xp-2003-*` does not
/// exist in volatility3 either).
static WIN_VERSION_FILE_MAP: [(&OsDistinguisher, bool, &str); 14] = [
    (&versions::IS_WIN10, true, "shimcache-win10-x64"),
    (&versions::IS_WIN10, false, "shimcache-win10-x86"),
    (&versions::IS_WINDOWS_8_OR_LATER, true, "shimcache-win8-x64"),
    (&versions::IS_WINDOWS_8_OR_LATER, false, "shimcache-win8-x86"),
    (&versions::IS_WINDOWS_7, true, "shimcache-win7-x64"),
    (&versions::IS_WINDOWS_7, false, "shimcache-win7-x86"),
    (&versions::IS_VISTA_OR_LATER, true, "shimcache-vista-x64"),
    (&versions::IS_VISTA_OR_LATER, false, "shimcache-vista-x86"),
    (&versions::IS_2003, false, "shimcache-2003-x86"),
    (&versions::IS_2003, true, "shimcache-2003-x64"),
    (&versions::IS_WINDOWS_XP_SP3, false, "shimcache-xp-sp3-x86"),
    (&versions::IS_WINDOWS_XP_SP2, false, "shimcache-xp-sp2-x86"),
    (&versions::IS_XP_OR_2003, true, "shimcache-xp-2003-x64"),
    (&versions::IS_XP_OR_2003, false, "shimcache-xp-2003-x86"),
];

/// python `NT_KRNL_MODS`.
const NT_KRNL_MODS: [&str; 4] = ["ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe", "ntkrpamp.exe"];

/// python `ShimcacheMem.create_shimcache_table(context, symbol_table_name, config_path)`.
pub fn create_shimcache_table(ctx: &Context, k: &WinKernel) -> Result<TableRef> {
    let is_64bit = k.table.is_64bit();
    let file = WIN_VERSION_FILE_MAP
        .iter()
        .find(|(check, for_64bit, _)| *for_64bit == is_64bit && check.check(k.table))
        .map(|(_, _, f)| *f)
        .ok_or_else(|| Error::msg("NotImplementedError: This version of Windows is not supported!"))?;
    ctx.load_isf_with(&format!("windows/shimcache/{file}"), Some(k.table), &[("nt_symbols", k.table.name())])
}

/// python `Modules.list_modules(context, kernel)` as the lazy generator python iterates (the
/// section lookup stops at the first matching module; `modules::list_modules` walks the whole
/// list up front).
fn lazy_list_modules(k: &WinKernel) -> Result<crate::symbols::windows::ListIter> {
    if k.base == 0 {
        return Err(Error::msg("Intel layer does not have an associated kernel virtual offset, failing"));
    }
    let tname = if k.table.user_type("_KLDR_DATA_TABLE_ENTRY").is_some() { "_KLDR_DATA_TABLE_ENTRY" } else { "_LDR_DATA_TABLE_ENTRY" };
    let head = k.get_symbol("PsLoadedModuleList")?.address;
    let list_entry = k.object("_LIST_ENTRY", head)?;
    let reloff = k.offset_of(tname, "InLoadOrderLinks")?;
    let module = k.object_abs(tname, list_entry.addr.wrapping_sub(reloff))?;
    Ok(module.m("InLoadOrderLinks")?.to_list(tname, "InLoadOrderLinks", true, true, None))
}

/// python `IMAGE_DOS_HEADER.get_nt_header()` + `IMAGE_NT_HEADERS.get_sections()` +
/// `array_to_string(sec.Name)` search of the `windows/pe` objects at `base`, done with direct
/// reads at the (fixed, PE-format) offsets of the `windows/pe` ISF types -- identical reads,
/// checks, masking and error messages as `symbols::windows::pe`, without loading the pe
/// table (whose lookup walks the whole `windows/` symbol tree: ~0.4 ms, more than all the
/// rest of this lookup). Returns `(VirtualAddress, Misc.VirtualSize)` of the first section
/// whose lower-cased name is `want`.
fn find_pe_section(layer: LayerRef, base: u64, want: &str) -> Result<Option<(u64, u64)>> {
    // _IMAGE_DOS_HEADER.e_magic @0 (u16), e_lfanew @60 (i32); _IMAGE_NT_HEADERS(64).Signature
    // @0 (u32), FileHeader @4 {Machine @0 u16, NumberOfSections @2 u16, SizeOfOptionalHeader
    // @16 u16}, OptionalHeader @24; _IMAGE_SECTION_HEADER (40 bytes): Name @0 (8 x u8),
    // Misc.VirtualSize @8 (u32), VirtualAddress @12 (u32).
    let mask = layer.address_mask();
    let at = |a: u64, off: u64| a.wrapping_add(off) & mask;
    let dos = base & mask;
    let e_magic = layer.read_u16(at(dos, 0))?;
    if e_magic != 0x5A4D {
        return Err(Error::msg(format!("e_magic {e_magic:04X} is not a valid DOS signature.")));
    }
    let e_lfanew = layer.read_i32(at(dos, 60))? as i64;
    let nt = (dos as i64).wrapping_add(e_lfanew) as u64 & mask;
    let signature = layer.read_u32(at(nt, 0))?;
    if signature != 0x4550 {
        return Err(Error::msg(format!("NT header signature {signature:04X} is not a valid")));
    }
    layer.read_u16(at(nt, 4))?; // FileHeader.Machine (_IMAGE_NT_HEADERS64 cast: same offsets)
    let size_of_optional_header = layer.read_u16(at(nt, 4 + 16))? as u64;
    let start = size_of_optional_header.wrapping_add(at(nt, 24));
    let number_of_sections = layer.read_u16(at(nt, 4 + 2))? as u64;
    for i in 0..number_of_sections {
        let sec = start.wrapping_add(i * 40) & mask;
        if address_to_string(layer, at(sec, 0), 8, "replace", "utf-8")?.to_lowercase() == want {
            let virtual_address = layer.read_u32(at(sec, 12))? as u64;
            let virtual_size = layer.read_u32(at(sec, 8))? as u64;
            return Ok(Some((virtual_address, virtual_size)));
        }
    }
    Ok(None)
}

/// python `ShimcacheMem.get_module_section_range(...)` for each of `sections` of the first
/// module whose `BaseDllName` is in `module_list` (python looks the module up again for every
/// section; the walk is deterministic, so it is done once here).
pub fn get_module_section_ranges(k: &WinKernel, module_list: &[&str], sections: &[&str]) -> Result<Vec<Option<(u64, u64)>>> {
    // A decoded utf-16 name has at most ceil(Length / 2) characters (errors="replace"), so
    // shorter names cannot match: python reads them (and only logs read errors), we skip them.
    let min_len = module_list.iter().map(|n| 2 * n.encode_utf16().count() as u64).min().unwrap_or(0);
    let mut krnl_mod = None;
    for m in lazy_list_modules(k)? {
        let m = m?;
        let name = m.m("BaseDllName")?;
        let r = (|| -> Result<bool> {
            if name.m("Length")?.u64()? < min_len {
                return Ok(false);
            }
            Ok(module_list.contains(&name.get_string()?.as_str()))
        })();
        match r {
            Ok(true) => {
                krnl_mod = Some(m);
                break;
            }
            Ok(false) => {}
            Err(e) if e.is_invalid_address() => {} // python logs a warning
            Err(e) => return Err(e),
        }
    }
    let Some(m) = krnl_mod else { return Ok(vec![None; sections.len()]) };
    let mut out = Vec::with_capacity(sections.len());
    for section_name in sections {
        let base = m.m("DllBase")?.u64()?;
        out.push(find_pe_section(k.vlayer, base, &section_name.to_lowercase())?.map(|(va, size)| (base.wrapping_add(va), size)));
    }
    Ok(out)
}

/// At most this many threads for the (big-range) `.data` scan: page-fault-bound probes, more
/// threads only add spawn cost.
const MAX_THREADS: usize = 8;

/// Threads (caller included) of the row [`pipeline`]: rows cost ~2.5x the list walk step that
/// produces them, so 3 workers keep up with the walk; more only add spawn cost and exposure to
/// scheduling delays on a busy machine.
const PIPELINE_THREADS: usize = 4;

/// Visit `range(start, start + size, step)` in python order with `f` (true hits are `Some`),
/// stopping after `want` hits or at the first error (python raised there). Ranges with more
/// than `SERIAL_MAX` candidates (ntoskrnl's `.data`) are split into blocks evaluated in
/// parallel; results are consumed strictly in order, so hits and errors past the stopping
/// point are ignored.
fn scan_ordered<T, F>(start: u64, size: u64, step: u64, want: usize, f: F) -> Result<Vec<T>>
where
    T: Send,
    F: Fn(u64) -> Result<Option<T>> + Sync,
{
    // ahcache.sys' .data (~800 pointers, ~0.2 ms) is not worth the threads
    const SERIAL_MAX: u64 = 4096;
    let n = size.div_ceil(step);
    let mut hits = Vec::new();
    if n <= SERIAL_MAX {
        for i in 0..n {
            if let Some(h) = f(start.wrapping_add(i * step))? {
                hits.push(h);
                if hits.len() == want {
                    break;
                }
            }
        }
        return Ok(hits);
    }
    // one block per thread for small ranges, 64K-candidate blocks for big ones (so an early
    // hit ends the scan soon)
    let block = n.div_ceil(par::threads().min(MAX_THREADS) as u64).clamp(1024, 1 << 16);
    let blocks = n.div_ceil(block) as usize;
    let mut err = None;
    par::par_map_stream(
        blocks,
        0,
        |b| {
            // hits of this block in order, ending at the first error
            let mut v: Vec<Result<T>> = Vec::new();
            let lo = b as u64 * block;
            for i in lo..(lo + block).min(n) {
                match f(start.wrapping_add(i * step)) {
                    Ok(Some(h)) => v.push(Ok(h)),
                    Ok(None) => {}
                    Err(e) => {
                        v.push(Err(e));
                        break;
                    }
                }
            }
            v
        },
        |_, v| {
            for r in v {
                match r {
                    Ok(h) => {
                        hits.push(h);
                        if hits.len() == want {
                            return false;
                        }
                    }
                    Err(e) => {
                        err = Some(e);
                        return false;
                    }
                }
            }
            true
        },
    );
    match err {
        Some(e) => Err(e),
        None => Ok(hits),
    }
}

/// `f` over the entries a (python generator) `produce` yields, computed while production is
/// still running: `produce` runs on the calling thread (a pointer-chasing list walk) and up
/// to `PIPELINE_THREADS - 1` workers pick the entries up as they appear; the caller helps once
/// production ends. Returns the results in production order and `produce`'s result (python's
/// generator raising after the entries it yielded).
fn pipeline<T, R, P, F>(produce: P, f: F) -> (Vec<R>, Result<()>)
where
    T: Copy + Send,
    R: Send,
    P: FnOnce(&mut dyn FnMut(T)) -> Result<()>,
    F: Fn(&T) -> R + Sync,
{
    struct Queue<T> {
        items: Vec<T>,
        next: usize,
        sleeping: usize,
        done: bool,
    }
    /// Ends production when dropped -- also when `produce` panics, so no worker waits forever.
    struct Finish<'a, T>(&'a Mutex<Queue<T>>, &'a Condvar);
    impl<T> Drop for Finish<'_, T> {
        fn drop(&mut self) {
            self.0.lock().unwrap_or_else(|p| p.into_inner()).done = true;
            self.1.notify_all();
        }
    }
    // wake sleeping workers once this many entries are waiting (not per entry: a futex wake
    // costs about as much as producing an entry)
    const WAKE_BATCH: usize = 8;
    let q = Mutex::new(Queue { items: Vec::new(), next: 0, sleeping: 0, done: false });
    let cv = Condvar::new();
    let lock = || q.lock().unwrap_or_else(|p| p.into_inner());
    let claim = || -> Option<(usize, T)> {
        let mut g = lock();
        loop {
            if g.next < g.items.len() {
                let i = g.next;
                g.next += 1;
                return Some((i, g.items[i]));
            }
            if g.done {
                return None;
            }
            g.sleeping += 1;
            g = cv.wait(g).unwrap_or_else(|p| p.into_inner());
            g.sleeping -= 1;
        }
    };
    let work = || {
        let mut out = Vec::new();
        while let Some((i, e)) = claim() {
            out.push((i, f(&e)));
        }
        out
    };
    let workers = par::threads().min(PIPELINE_THREADS).saturating_sub(1);
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..workers).map(|_| s.spawn(work)).collect();
        let finish = Finish(&q, &cv);
        let r = produce(&mut |e| {
            let mut g = lock();
            g.items.push(e);
            let wake = g.sleeping > 0 && g.items.len() - g.next >= WAKE_BATCH;
            drop(g);
            if wake {
                cv.notify_all();
            }
        });
        drop(finish);
        let mut parts = vec![work()];
        for h in handles {
            parts.push(h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)));
        }
        let n = lock().items.len();
        let mut slots: Vec<Option<R>> = (0..n).map(|_| None).collect();
        for (i, v) in parts.into_iter().flatten() {
            slots[i] = Some(v);
        }
        (slots.into_iter().map(|v| v.expect("every entry is claimed once")).collect(), r)
    })
}

/// python `versions.is_windows_8_1_or_later(...) or versions.is_win10(...)`.
fn is_8_1_or_later(k: &WinKernel) -> bool {
    versions::IS_WINDOWS_8_1_OR_LATER.check(k.table) || versions::IS_WIN10.check(k.table)
}

/// python `ShimcacheMem.find_shimcache_win_8_or_later(...)`, yielding the list entries
/// WITHOUT python's `is_valid()` filter (the caller applies it: the walk itself only reads the
/// links, so filtering later gives the same result).
pub fn find_shimcache_win_8_or_later(k: &WinKernel, shim: TableRef, yield_: &mut dyn FnMut(Obj)) -> Result<()> {
    let is_8_1_or_later = is_8_1_or_later(k);
    let module_names: &[&str] = if is_8_1_or_later { &["ahcache.sys"] } else { &NT_KRNL_MODS };
    let ranges = {
        let _t = crate::util::trace::span("shimcache module sections");
        get_module_section_ranges(k, module_names, &[".data", "PAGE"])?
    };
    let (Some((data_start, data_size)), Some((page_start, page_size))) = (ranges[0], ranges[1]) else { return Ok(()) };
    let is_64bit = k.table.is_64bit();
    let sp = Space::on(k.vlayer, shim);
    let handle_ty = shim.get_type("SHIM_CACHE_HANDLE")?;
    let ptr_ty = Obj::new(sp, handle_ty, 0).cast_pointer_to(handle_ty)?.ty;
    let page_end = page_start.wrapping_add(page_size);
    let t = crate::util::trace::span("shimcache handle scan");
    let heads = scan_ordered(data_start, data_size, if is_64bit { 8 } else { 4 }, 2, |off| {
        let handle = Obj::new(sp, ptr_ty, off).deref()?;
        if handle.shim_handle_is_valid(page_start, page_end)? { handle.head() } else { Ok(None) }
    })?;
    drop(t);
    if heads.len() != 2 {
        return Ok(());
    }
    // Windows 8 x64: the first cache; 8 x86, 8.1 and 10: the second one.
    let valid_head = if !is_64bit && !is_8_1_or_later {
        heads[1]
    } else if !is_8_1_or_later {
        heads[0]
    } else {
        heads[1]
    };
    let entry_type = format!("{}!SHIM_CACHE_ENTRY", shim.name());
    for e in valid_head.m("ListEntry")?.to_list(&entry_type, "ListEntry", true, true, None) {
        yield_(e?);
    }
    Ok(())
}

/// python `ShimcacheMem.try_get_shim_head_at_offset(...)` with the per-call constants hoisted.
struct HeadProbe {
    sp: &'static Space,
    avl_ty: crate::symbols::Ty,
    entry_ty: crate::symbols::Ty,
    avl_size: u64,
    ersrc_size: u64,
    ersrc_alignment: u64,
    page_start: u64,
    page_end: u64,
}

impl HeadProbe {
    fn probe(&self, k: &WinKernel, offset: u64) -> Result<Option<Obj>> {
        let rtl_avl_table = Obj::new(self.sp, self.avl_ty, offset);
        if !rtl_avl_table.avl_table_is_valid(self.page_start, self.page_end)? {
            return Ok(None);
        }
        // python `%` on ints: the alignment is a power of two, so the u64 wrap is exact
        let eresource_rel_off = self.ersrc_size + (offset.wrapping_sub(self.ersrc_size) & (self.ersrc_alignment - 1));
        let eresource = k.object_abs("_ERESOURCE", offset.wrapping_sub(eresource_rel_off))?;
        if !eresource_is_valid(&eresource)? {
            return Ok(None);
        }
        let shim_head_offset = offset.wrapping_add(self.avl_size);
        if !k.vlayer.is_valid(shim_head_offset, 1) {
            return Ok(None);
        }
        let shim_head = Obj::new(self.sp, self.entry_ty, shim_head_offset);
        Ok(if shim_head.shim_entry_is_valid()? { Some(shim_head) } else { None })
    }
}

/// python `ShimcacheMem.find_shimcache_win_2k3_to_7(...)`, yielding the list entries.
pub fn find_shimcache_win_2k3_to_7(k: &WinKernel, shim: TableRef, yield_: &mut dyn FnMut(Obj)) -> Result<()> {
    let ranges = get_module_section_ranges(k, &NT_KRNL_MODS, &[".data", "PAGE"])?;
    let (Some((data_start, data_size)), Some((page_start, page_size))) = (ranges[0], ranges[1]) else { return Ok(()) };
    let is_64bit = k.table.is_64bit();
    let avl_ty = shim.get_type("_RTL_AVL_TABLE")?;
    let probe = HeadProbe {
        sp: Space::on(k.vlayer, shim),
        avl_ty,
        entry_ty: shim.get_type("SHIM_CACHE_ENTRY")?,
        avl_size: shim.size_of(avl_ty),
        ersrc_size: k.size_of("_ERESOURCE")?,
        ersrc_alignment: if is_64bit { 0x20 } else { 0x10 },
        page_start,
        page_end: page_start.wrapping_add(page_size),
    };
    let heads = scan_ordered(data_start, data_size, if is_64bit { 8 } else { 4 }, 1, |off| probe.probe(k, off))?;
    let Some(shim_head) = heads.first() else { return Ok(()) };
    let entry_type = format!("{}!SHIM_CACHE_ENTRY", shim.name());
    for e in shim_head.m("ListEntry")?.to_list(&entry_type, "ListEntry", true, true, None) {
        yield_(e?);
    }
    Ok(())
}

/// One process of python `find_shimcache_win_xp`: the candidate entries `(physical address key,
/// entry)` in python order, a trailing `Err` where python raised.
fn xp_process_candidates(shim: TableRef, process: &Obj) -> Vec<Result<((u64, u16), Obj)>> {
    const SHIM_NUM_ENTRIES_OFFSET: u64 = 0x8;
    const SHIM_MAX_ENTRIES: u64 = 0x60;
    const SHIM_LRU_OFFSET: u64 = 0x10;
    const SHIM_HEADER_SIZE: u64 = 0x190;
    const SHIM_CACHE_ENTRY_SIZE: u64 = 0x228;
    let mut out = Vec::new();
    let r = (|| -> Result<()> {
        let _pid = process.m("UniqueProcessId")?.int()?;
        // the python filter compares get_tag() (a str) with b"Vad ": never true, nothing skipped
        for vad in vadinfo::list_vads(process, &|_| Ok(false)) {
            let vad = vad?;
            let proc_layer = match process.add_process_layer() {
                Ok(l) => l,
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            };
            let magic = (|| -> Result<bool> {
                let mut b = [0u8; 4];
                proc_layer.read(vad.get_start()?, &mut b)?;
                Ok(b == *b"\xef\xbe\xad\xde")
            })();
            match magic {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) if e.is_invalid_address() => continue,
                Err(e) => return Err(e),
            }
            let start = vad.get_start()?;
            let sp = Space::on(proc_layer, shim);
            let num_entries = Obj::named(sp, "unsigned int", start.wrapping_add(SHIM_NUM_ENTRIES_OFFSET))?.u64()?;
            if num_entries > SHIM_MAX_ENTRIES {
                continue;
            }
            let entry_ty = shim.get_type("SHIM_CACHE_ENTRY")?;
            let mut cache_idx_ptr = start.wrapping_add(SHIM_LRU_OFFSET);
            for _ in 0..num_entries {
                let cache_idx_val = Obj::named(sp, "unsigned long", cache_idx_ptr)?.u64()?;
                cache_idx_ptr = cache_idx_ptr.wrapping_add(4);
                if cache_idx_val > SHIM_MAX_ENTRIES - 1 {
                    continue;
                }
                let off = start.wrapping_add(SHIM_HEADER_SIZE).wrapping_add(SHIM_CACHE_ENTRY_SIZE * cache_idx_val);
                if !proc_layer.is_valid(off, 1) {
                    continue;
                }
                // python `proc_layer.translate(offset)`: (physical offset, layer name)
                let Some((phys, target)) = proc_layer.as_intel().and_then(|l| l.translate_addr(off)) else {
                    return Err(Error::invalid(off));
                };
                let key = (phys, if let Target::Swap(n) = target { 1 + n as u16 } else { 0 });
                let shim_entry = Obj::new(sp, entry_ty, off);
                if !shim_entry.shim_entry_is_valid()? {
                    continue;
                }
                out.push(Ok((key, shim_entry)));
            }
        }
        Ok(())
    })();
    if let Err(e) = r {
        out.push(Err(e));
    }
    out
}

/// python `ShimcacheMem.find_shimcache_win_xp(...)`: processes are examined in parallel, the
/// physical-address deduplication runs in python order.
pub fn find_shimcache_win_xp(k: &WinKernel, shim: TableRef, yield_: &mut dyn FnMut(Obj)) -> Result<()> {
    let procs = pslist::list_processes(k, &|_| Ok(false));
    let per_proc = par::par_map(procs.len(), |i| match &procs[i] {
        Ok(p) => xp_process_candidates(shim, p),
        Err(_) => Vec::new(),
    });
    let mut seen = FxHashSet::default();
    for (p, cands) in procs.into_iter().zip(per_proc) {
        p?;
        for c in cands {
            let (key, e) = c?;
            if seen.insert(key) {
                yield_(e);
            }
        }
    }
    Ok(())
}

/// python `ShimcacheMem._generator()` values after `Order`: (last_modified, last_update,
/// exec_flag, file_size, file_path).
fn entry_values(e: &Obj) -> Result<[Value; 5]> {
    let last_modified = e.last_modified()?;
    let last_update = e.last_update()?;
    let exec_flag = e.exec_flag()?;
    let file_size = e.file_size()?;
    let file_path = e.file_path()?;
    Ok([last_modified, last_update, exec_flag, file_size, file_path])
}

/// python `_generator()`: calls `emit([last_modified, last_update, exec_flag, file_size,
/// file_path])` per row (the caller numbers them). The rows are computed in parallel with the
/// list walk (see [`pipeline`]) and emitted in python order, stopping at the first error python
/// would have raised.
fn generate(ctx: &Context, emit: &mut dyn FnMut([Value; 5]) -> Result<()>) -> Result<()> {
    enum Algo {
        Win8OrLater,
        Win2k3To7,
        WinXp,
        Unsupported,
    }
    let k = ctx.windows_kernel()?;
    let t = k.table;
    let algo = if versions::IS_WINDOWS_8_OR_LATER.check(t) {
        Algo::Win8OrLater
    } else if versions::IS_2003.check(t) || versions::IS_VISTA_OR_LATER.check(t) || versions::IS_WINDOWS_7.check(t) {
        Algo::Win2k3To7
    } else if versions::IS_WINDOWS_XP_SP2.check(t) || versions::IS_WINDOWS_XP_SP3.check(t) {
        Algo::WinXp
    } else {
        Algo::Unsupported
    };
    let shim = {
        let _t = crate::util::trace::span("shimcache table load");
        create_shimcache_table(ctx, k)?
    };
    // python filters the win8+ list walk with SHIM_CACHE_ENTRY.is_valid()
    let check_valid = matches!(algo, Algo::Win8OrLater);
    // one row per entry; None = skipped (is_valid() filter, or InvalidAddressException)
    let row = |e: &Obj| -> Result<Option<[Value; 5]>> {
        if check_valid && !e.shim_entry_is_valid()? {
            return Ok(None);
        }
        match entry_values(e) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.is_invalid_address() => Ok(None),
            Err(e) => Err(e),
        }
    };
    let t = crate::util::trace::span("shimcache entries + rows");
    let (rows, walk) = match algo {
        Algo::Win8OrLater => pipeline(|y| find_shimcache_win_8_or_later(k, shim, y), row),
        Algo::Win2k3To7 => pipeline(|y| find_shimcache_win_2k3_to_7(k, shim, y), row),
        Algo::WinXp => pipeline(|y| find_shimcache_win_xp(k, shim, y), row),
        // python: vollog.warn("Cannot parse shimcache entries for this version of Windows")
        _ => return Ok(()),
    };
    drop(t);
    for r in rows {
        if let Some(v) = r? {
            emit(v)?;
        }
    }
    walk
}

impl Plugin for ShimcacheMem {
    fn name(&self) -> &'static str {
        "windows.shimcachemem.ShimcacheMem"
    }
    fn description(&self) -> &'static str {
        "Reads Shimcache entries from the ahcache.sys AVL tree"
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Order", ColType::Int),
            Column::new("Last Modified", ColType::DateTime),
            Column::new("Last Update", ColType::DateTime),
            Column::new("Exec Flag", ColType::Bool),
            Column::new("File Size", ColType::Hex),
            Column::new("File Path", ColType::Str),
        ])?;
        let mut order = 0i128;
        generate(ctx, &mut |[lm, lu, ef, fs, fp]| {
            let row = vec![Value::Int(order), lm, lu, ef, fs, fp];
            order += 1;
            out.row(0, row)
        })
    }
    fn timeline(&self, ctx: &Context, _cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        let mut ev = Vec::new();
        let r = generate(ctx, &mut |[last_modified, last_update, _, _, file_path]| {
            // python f-string of the file path: a str, or an absent value's str()
            let path = match &file_path {
                Value::Str(s) => s.as_str(),
                Value::NotApplicable => "N/A",
                _ => "-",
            };
            if let Value::DateTime(_) = last_update {
                ev.push(TimelineEvent { description: format!("Shimcache: File {path} executed"), kind: TimeKind::Accessed, time: last_update });
            }
            if let Value::DateTime(_) = last_modified {
                ev.push(TimelineEvent { description: format!("Shimcache: File {path} modified"), kind: TimeKind::Modified, time: last_modified });
            }
            Ok(())
        });
        Some(r.map(|_| ev))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::{Layer, Mapping};

    /// A flat in-memory layer.
    struct Mem(Vec<u8>);

    impl Layer for Mem {
        fn name(&self) -> &str {
            "mem"
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
            addr.saturating_add(len) <= self.0.len() as u64
        }
        fn mapping(&self, addr: u64, len: u64, f: &mut dyn FnMut(Mapping) -> bool) {
            f(Mapping { offset: addr, len, mapped: addr });
        }
    }

    fn put(m: &mut [u8], at: usize, b: &[u8]) {
        m[at..at + b.len()].copy_from_slice(b);
    }

    fn pe_layer(magic: &[u8]) -> LayerRef {
        let mut m = vec![0u8; 0x2000];
        put(&mut m, 0x1000, magic);
        put(&mut m, 0x1000 + 60, &0x80i32.to_le_bytes());
        put(&mut m, 0x1080, b"PE\0\0");
        put(&mut m, 0x1084, &0x8664u16.to_le_bytes()); // Machine
        put(&mut m, 0x1086, &3u16.to_le_bytes()); // NumberOfSections
        put(&mut m, 0x1094, &0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
        let sections = 0x1080 + 24 + 0xF0;
        for (i, (name, va, vs)) in
            [(&b".text\0\0\0"[..], 0x1000u32, 0x500u32), (b".data\0\0\0", 0x3000, 0x194c), (b"PAGE\0\0\0\0", 0x5000, 0x2000)].into_iter().enumerate()
        {
            let s = sections + i * 40;
            put(&mut m, s, name);
            put(&mut m, s + 8, &vs.to_le_bytes());
            put(&mut m, s + 12, &va.to_le_bytes());
        }
        Box::leak(Box::new(Mem(m)))
    }

    #[test]
    fn pe_sections() {
        let l = pe_layer(b"MZ");
        assert_eq!(find_pe_section(l, 0x1000, ".data").unwrap(), Some((0x3000, 0x194c)));
        assert_eq!(find_pe_section(l, 0x1000, "page").unwrap(), Some((0x5000, 0x2000)));
        assert_eq!(find_pe_section(l, 0x1000, ".bss").unwrap(), None);
        let bad = pe_layer(b"ZM");
        assert_eq!(find_pe_section(bad, 0x1000, ".data").unwrap_err().to_string(), "e_magic 4D5A is not a valid DOS signature.");
    }

    #[test]
    fn scan_order_and_errors() {
        // hits at multiples of 1000 candidates; an error at candidate 2500
        for size in [800u64 * 8, 100_000 * 8] {
            let f = |off: u64| -> Result<Option<u64>> {
                let i = off / 8;
                if i == 2500 {
                    return Err(Error::invalid(off));
                }
                Ok(if i % 1000 == 999 || i == 700 { Some(i) } else { None })
            };
            let hits = scan_ordered(0, size, 8, 2, f).unwrap();
            if size == 800 * 8 {
                assert_eq!(hits, vec![700]);
            } else {
                assert_eq!(hits, vec![700, 999]);
                // a fourth hit needs candidates past the error: python raised there
                assert_eq!(scan_ordered(0, size, 8, 3, f).unwrap(), vec![700, 999, 1999]);
                assert!(scan_ordered(0, size, 8, 4, f).unwrap_err().is_invalid_address());
            }
        }
    }

    #[test]
    fn pipeline_order_and_error() {
        let (rows, r) = pipeline(
            |y| {
                for i in 0..1000u64 {
                    y(i);
                }
                Err(Error::invalid(7))
            },
            |i: &u64| i * 2,
        );
        assert_eq!(rows, (0..1000u64).map(|i| i * 2).collect::<Vec<_>>());
        assert!(r.unwrap_err().is_invalid_address());
        let (rows, r) = pipeline(|_| Ok(()), |i: &u64| *i);
        assert!(rows.is_empty() && r.is_ok());
    }
}
