# rsvol core API — python volatility3 → rust cheat-sheet

For plugin porters. Everything here mirrors volatility3 2.28.2 semantics; when in doubt read the
python source in `/home/user/rs-vol/volatility3/` and the doc comments of the rust items named
below. Output must be byte-identical, so port *behaviour* (which exceptions are caught where,
evaluation order when it decides which rows are skipped), not just the happy path.

## The mental model

| python | rust |
|---|---|
| `context.layers[name]` | `LayerRef` = `&'static dyn Layer` (layers live for the whole run) |
| `context.symbol_space[table]` | `TableRef` = `&'static SymbolTable` |
| object (`vol.layer_name`, `vol.native_layer_name`, template, `vol.offset`) | `Obj { sp: &'static Space, ty: Ty, addr: u64 }` — 32-byte `Copy` value, no lifetimes |
| `context.modules[self.config["kernel"]]` | `ctx.windows_kernel()?` → `&WinKernel` (derefs to `Module`); `ctx.linux_kernel()?`, `ctx.mac_kernel()?` |
| `InvalidAddressException` | `Err(e)` with `e.is_invalid_address()` |
| `SymbolError` / `AttributeError` for a missing member | `Err(Error::Symbol(..))` |
| a generator that may raise midway | `Vec<Result<Obj>>` / iterator of `Result<Obj>`; a trailing `Err` = python raised there |

Creating an `Obj` never reads memory. Reads happen in the value accessors (`int()`, `u64()`,
`string()`, `deref()`...), exactly where python reads (python primitives read on attribute
access; structs never read).

```rust
use crate::context::Context;
use crate::objects::{Obj, Module, Space, Field, LayerRef};
use crate::objects::util::{array_to_string, pointer_to_string};
use crate::symbols::windows::WinExt;          // EPROCESS/LIST_ENTRY/UNICODE_STRING/... methods
use crate::renderers::{Value, ColType, Column};
```

## Kernel, modules, symbols

| python | rust |
|---|---|
| `kernel = self.context.modules[self.config["kernel"]]` | `let k = ctx.windows_kernel()?;` |
| `kernel.layer_name` / `context.layers[kernel.layer_name]` | `k.vlayer` (`&dyn Layer`), `k.layer` (`&IntelLayer`) |
| `kernel.symbol_table_name` / `context.symbol_space[...]` | `k.table` |
| `kernel.offset` | `k.base` (== `k.offset`) |
| `layer.config["memory_layer"]` (physical) | `k.phys` / `ctx.physical()?` |
| `layer.config["page_map_offset"]` | `k.dtb` |
| `kernel.get_symbol("PsActiveProcessHead").address` | `k.get_symbol("PsActiveProcessHead")?.address` (relative) |
| `kernel.offset + kernel.get_symbol(x).address` | `k.symbol_addr(x)?` |
| `kernel.has_symbol(x)` / `has_type(x)` | `k.has_symbol(x)` / `k.has_type(x)` |
| `kernel.object(object_type="_LIST_ENTRY", offset=rel)` | `k.object("_LIST_ENTRY", rel)?` |
| `kernel.object(..., offset=addr, absolute=True)` | `k.object_abs("_EPROCESS", addr)?` |
| `kernel.object_from_symbol("KeNumberProcessors")` | `k.object_from_symbol("KeNumberProcessors")?` |
| `kernel.get_type("_EPROCESS").relative_child_offset("ActiveProcessLinks")` | `k.offset_of("_EPROCESS", "ActiveProcessLinks")?` |
| `kernel.get_type("_EPROCESS").size` | `k.size_of("_EPROCESS")?` |
| `symbols.symbol_table_is_64bit(context, table)` | `k.table.is_64bit()` |
| `symbol_table.get_symbol("x").type` | `k.table.get_symbol("x")?.ty` (`Option<Ty>`) |
| `get_symbols_by_absolute_location(addr)` | `k.symbols_at(addr, 0)` |
| `context.object(table + "!_PEB", layer_name=proc_layer, offset=peb)` | `Obj::named(Space::on(proc_layer, k.table), "_PEB", peb)?` |
| `context.object(..., layer_name=L, native_layer_name=N)` | `Obj::named(Space::get(L, N, table), "type", addr)?` |
| `intermed.IntermediateSymbolTable.create(ctx, path, "windows", "pe", class_types=...)` | `ctx.load_isf("windows/pe")?` (memoized) |
| `...create(..., native_types=kernel_natives, table_mapping={"nt_symbols": kernel.symbol_table_name})` | `ctx.load_isf_with("windows/callbacks-x64", Some(k.table), &[("nt_symbols", k.table.name())])?` |
| `PDBUtility.load_windows_symbol_table(ctx, guid, age, pdb_name, ...)` | `ctx.load_windows_pdb(pdb_name, guid, age)?` |
| `PDBUtility.symbol_table_from_pdb(ctx, path, layer, "tcpip.pdb", base, size)` | `ctx.symbol_table_from_pdb(layer, "tcpip.pdb", Some(base), Some(size))?` |
| `PDBUtility.module_from_pdb(...)` | `ctx.module_from_pdb(layer, "ntdll.pdb", Some(base), Some(size))?` → `Module` |
| `PDBUtility.pdbname_scan(ctx, layer, page_size, names, start, end)` | `crate::automagic::windows::pdbname_scan(layer, &[b"x.pdb"], start, end, \|sig\| { ..; true })` |
| `versions.is_win10(context, table)` | `crate::symbols::windows::versions::IS_WIN10.check(k.table)` |
| `symbol_cache.get_identifier_dictionary(os)` / `find_location(id, os)` | `symbols::store::identifier_index(symbols::symbol_path()).dictionary("linux")` / `.find(id, "linux")` (includes `-u` remote lists, which win ties like python) |
| `ResourceAccessor().open(url)` (file:// or cached download) | `IsfLocation::Url(url).read()?` (decompressed by extension) / `symbols::store::url_local_path(url)?` |
| `urllib.parse.unquote(s)` / `file://` URL → path | `crate::util::paths::{unquote, file_uri_to_path}` |

## Objects

| python | rust |
|---|---|
| `proc.UniqueProcessId` (int) | `proc.m("UniqueProcessId")?.int()?` (`i128`, exact python int) / `.u64()?` / `.i64()?` |
| `proc.Pcb.DirectoryTableBase` | `proc.u64_at("Pcb.DirectoryTableBase")?` (= `proc.path(..)?.u64()?`, `proc.m("Pcb")?.m("DirectoryTableBase")?.u64()?`); `int_at` for the exact python int |
| `ptr.Member` (auto-deref) | `ptr.m("Member")?` (dereferences pointers like python) |
| `ptr.dereference()` | `ptr.deref()?` ; `ptr.deref_on(layer)?` for `dereference(layer_name)` |
| `if ptr:` / `bool(x)` | `x.bool()?` (value != 0) |
| `ptr.is_readable()` | `ptr.is_readable()` |
| `ptr.get_raw_value()` | `ptr.raw_u64()?` (unmasked) |
| `obj.vol.offset` / `.vol.size` / `.vol.type_name` | `obj.addr` / `obj.size()` / `obj.type_name()` (no table prefix; `full_type_name()` has it) |
| `obj.vol.layer_name` / `.native_layer_name` | `obj.layer()` / `obj.native()` |
| `obj.has_member("x")` / `has_valid_member("x")` | `obj.has_member("x")` / `obj.has_valid_member("x")` |
| `obj.cast("_UNICODE_STRING")` | `obj.cast("_UNICODE_STRING")?` (`"table!type"` works too) |
| `obj.cast("string", max_length=n, errors="replace", encoding="utf-16")` + `str()` | `obj.read_string(n, "utf-16", "replace")?` or `obj.cast_string(n, StrEnc::Utf16, StrErrors::Replace).string()?` |
| `obj.cast("bytes", length=n)` / `bytes(obj)` | `obj.cast_bytes(n).bytes()?` |
| `obj.cast("array", count=n, subtype=table.get_type("unsigned long"))` | `obj.cast_array_of(n, "unsigned long")?` / `obj.cast_array(n, ty)` |
| `obj.cast("pointer", subtype=t)` | `obj.cast_pointer_to(t)?` |
| `array[i]`, `len(array)`, `for x in array` | `arr.at(i)?`, `arr.count()`, `arr.elements()` ; all int elements at once: `arr.ints()?` |
| `array.count = n` | `arr.with_count(n)` |
| `enum.description` / `.lookup()` | `e.description()?` (Err outside the choices, like python's ValueError) |
| `enum.is_valid_choice` / `EnumName.CONSTANT` | `e.is_valid_choice()` / `e.enum_value("CONSTANT")?` |
| bitfields | `obj.m("Flag")?.int()?` (already `(v & ((1<<end)-1)) >> start`) |
| `container_of(ptr, "task_struct", "tasks")` / `obj.vol.offset - relative_child_offset` | `list_head.container_of("task_struct", "tasks")?` / `obj.container_at(addr, "task_struct", "tasks")?` |
| `objects.utility.array_to_string(arr)` | `array_to_string(&arr, None)?` |
| `utility.pointer_to_string(ptr, count)` | `pointer_to_string(&ptr, count)?` |
| `utility.rol / bswap_64` | `crate::objects::util::{rol, bswap_32, bswap_64}` |
| `conversion.wintime_to_datetime(x)` | `crate::util::time::wintime_to_datetime(x)` → `Value` (DateTime / NotApplicable / Unparsable) |
| `conversion.unixtime_to_datetime(x)` | `crate::util::time::unixtime_to_datetime(x)` |
| `str(datetime)` / `time.asctime(time.gmtime(t))` | `crate::util::time::py_str(&dt)` / `crate::util::time::asctime(t)` |

Hot loops: resolve members once, then no hashing per access:

```rust
let pid = Field::new(k.table, "_EPROCESS", "UniqueProcessId")?;
let dtb = Field::path(k.table, "_EPROCESS", "Pcb.DirectoryTableBase")?;
for p in &procs { let v = p.f(&pid).int()?; let d = p.f(&dtb).u64()?; }
```

## Windows class extensions (`use crate::symbols::windows::prelude::*`)

The prelude brings in `WinExt` (EPROCESS / ETHREAD / KTHREAD / LIST_ENTRY / UNICODE_STRING /
KSYSTEM_TIME / EX_FAST_REF / LDR_DATA_TABLE_ENTRY / FILE_OBJECT...), `VadExt` (MMVAD tree),
`TokenExt` (TOKEN), `KtimerExt` (KTIMER), `CacheExt` (CONTROL_AREA / SHARED_CACHE_MAP / VACB),
`PoolExt` (POOL_HEADER / OBJECT_HEADER / executive objects / big-page tracker, in
`symbols::windows::pool`) and `ObjectsExt` (DEVICE_OBJECT / DRIVER_OBJECT / symbolic links /
mutants / FILE_OBJECT names, in `symbols::windows::objects`). See "Pool scanning" below.

| python | rust |
|---|---|
| `proc.get_vad_root().traverse()` | `proc.get_vad_root()?.traverse()` → `Vec<Result<Obj>>` (nodes cast to `_MMVAD_SHORT`/`_MMVAD`) |
| `vad.get_start()/get_end()/get_size()/get_parent()` | same names → `Result<u64>` / `Result<i128>` |
| `vad.get_tag()` / `get_file_name()` | `vad.get_tag()` (`Option<String>`) / `vad.get_file_name()` (`Value`) |
| `vad.get_commit_charge()` / `get_private_memory()` | same (member objects: `.int()?`) |
| `vad.get_protection(protect_values, winnt_protections)` | `vad.get_protection(&vals, &vadinfo::WINNT_PROTECTIONS)?` with `vals = vadinfo::protect_values(k)?` |
| `VadInfo.list_vads(proc, filter)` / `vad_dump(...)` | `crate::plugins::windows::vadinfo::{list_vads, vad_dump}` |
| `token.get_sids()` / `privileges()` | `token.get_sids()?` / `token.privileges()?` |
| `ktimer.get_dpc()` / `get_due_time()` / `valid_type()` / `get_signaled()` | same names |
| `control_area.get_available_pages()` / `shared_cache_map.get_available_pages()` | `obj.get_available_pages()` → `Vec<Result<(u64, u64, u64)>>` |
| `vacb.get_file_offset()` / `control_area.get_subsection()` / `get_pte(off)` | same names |
| python f-string `f"{x:#010x}"`, `f"{s:<20}"` | `crate::util::pyformat::{fmt_int(x, "#010x"), fmt_str(s, "<20")}` |

### Core Windows helpers (`WinExt`)

| python | rust |
|---|---|
| `pslist.PsList.list_processes(ctx, kernel, filter_func)` | `crate::plugins::windows::pslist::list_processes(k, &filter)` → `Vec<Result<Obj>>` (filter returns true = skip) |
| `PsList.create_pid_filter(pids)` | `pslist::pid_filter(&pids)` |
| `modules.Modules.list_modules(ctx, kernel)` | `crate::plugins::windows::modules::list_modules(k)` |
| `Modules.get_session_layers / find_session_layer` | `modules::get_session_layers(k, &pids)?` / `modules::find_session_layer(&layers, base)` |
| `PEDump.dump_ldr_entry / dump_pe` | `modules::dump_ldr_entry(ctx, pe, &ldr, layer, prefix)?` / `modules::dump_pe(...)` |
| `proc.add_process_layer()` | `proc.add_process_layer()?` → `LayerRef` (memoized per DTB) |
| `proc.get_peb()` / `get_peb32()` | `proc.get_peb()?` / `proc.get_peb32()?` (`Option`) |
| `proc.load_order_modules()` / `init_order_...` / `mem_order_...` | `proc.load_order_modules()` → `Vec<Result<Obj>>` |
| `proc.get_handle_count()` / `get_session_id()` | `proc.get_handle_count()` / `proc.get_session_id()?` → `Value` |
| `proc.get_create_time()` / `get_exit_time()` (also ETHREAD, symbolic links) | `obj.get_create_time()?` / `obj.get_exit_time()?` → `Value` |
| `proc.get_is_wow64()` / `get_wow_64_process()` / `get_vad_root()` | same names |
| `proc.environment_variables()` | `proc.environment_variables()` → `Vec<(String, String)>` |
| `proc.is_valid()` (EPROCESS / ETHREAD / FILE_OBJECT ...) | `obj.is_valid()` (dispatches on type name like python classes) |
| `proc.ImageFileName.cast("string", max_length=count, errors="replace")` | `proc.image_file_name_str()?` ; `array_to_string(ImageFileName)` = `proc.image_file_name()?` |
| `list_entry.to_list(symbol_type, member, forward, sentinel, layer)` | `le.to_list("_EPROCESS", "ActiveProcessLinks", true, true, None)` → lazy iterator of `Result<Obj>` |
| `for x in obj.SomeListEntry` (`LIST_ENTRY.__iter__`) | `obj.m("SomeListEntry")?.list_of(<parent type>, "SomeListEntry")` |
| `unicode_string.get_string()` / `.String` | `us.get_string()?` |
| `ksystem_time.get_time()` | `t.get_time()?` |
| `ex_fast_ref.dereference()` | `r.fast_ref_dereference()?` (a `pointer` object, cast it) |
| `ethread.owning_process()` / `get_cross_thread_flags()` | same names |
| `kthread.get_state()` / `get_wait_reason()` | same names → `Value` |
| `ldr_entry.get_load_count()` | `ldr.get_load_count()` |
| `dos_header.get_nt_header()` / `reconstruct()` / `nt.get_sections()` | `crate::symbols::windows::pe::{get_nt_header, reconstruct, get_sections, write_pieces}` |
| `kdbg.get_build_lab()` / `get_csdversion()` | `crate::symbols::windows::kdbg::{get_build_lab, get_csdversion}` |
| `info.Info.get_kdbg_structure / get_kuser_structure / get_version_structure / get_ntheader_structure` | `crate::plugins::windows::info::{...}` same names |
| `mft.MFTEntry` / `MFTFileName` / `MFTAttribute` (`windows/mft` ISF) | `crate::symbols::windows::mft::{MftEntry, MftFileName, MftAttribute}` (`attributes()`, `standard_information_entries()`, `filename_entries()`, `longest_filename()`, `resident_data_attributes()`, `alternate_data_streams()`, `get_full_name()`, `get_resident_filename()`, `get_resident_filecontent()`) |
| `MFTScan.enumerate_mft_records(ctx, path, primary)` | `crate::plugins::windows::mftscan::{enumerate_mft_records, enumerate_mft_batches}(layer, ...)` (yara `/FILE0\|FILE\*\|BAAD/` semantics, parse on the scan workers); layer = `mftscan::primary_memory_layer(ctx)?` |
| `mbr.PARTITION_TABLE` / `PARTITION_ENTRY` (`windows/mbr` ISF) | `crate::symbols::windows::mbr::{PartitionTable, PartitionEntry}` |

### PE files: pefile, pe_symbols, verinfo

| python | rust |
|---|---|
| `pe_data = BytesIO(); for off, d in dos.reconstruct(): seek/write` (to parse it) | `let (view, err) = pe::reconstruct_view(&dos);` — lazy page view, reads only what is parsed; `err: Option<ReconError>` (`is_invalid_or_value()` = what `except (InvalidAddressException, ValueError)` catches; the view keeps the pieces written before it) |
| `pefile.PE(data=pe_data.getvalue(), fast_load=True)` | `crate::symbols::windows::pefile::PeFile::parse(&view)?` (`PeError::Format` = PEFormatError, `PeError::Attribute` = AttributeError); works on `&[u8]`/`Vec<u8>` too |
| `pe.parse_data_directories([EXPORT])` + `pe.DIRECTORY_ENTRY_EXPORT.symbols` | `pe.parse_exports()` → `Option<ExportDir>` (`.symbols: Vec<Export{ordinal, address, name, forwarder}>`) |
| `pe.parse_data_directories([IMPORT])` + `pe.DIRECTORY_ENTRY_IMPORT` | `pe.parse_imports()` → `Option<Vec<ImportDesc{dll, time_date_stamp, imports: Vec<Import{name, ordinal, address}>}>>` |
| `pe.parse_data_directories([RESOURCE])` + `pe.VS_FIXEDFILEINFO` | `pe.parse_version_info()` → `Vec<FixedFileInfo>` (empty = AttributeError) |
| `pe.OPTIONAL_HEADER.ImageBase` / `pe.sections` / `get_data(rva, n)` / `get_string_at_rva` | `pe.optional_header.image_base` / `pe.sections` / same names |
| `VerInfo.get_version_information(ctx, pe_table, layer, base)` | `crate::plugins::windows::verinfo::get_version_information(pe_table, Some(layer), base)` |
| `PESymbols.addresses_for_process_symbols(ctx, path, kernel, {"ntdll.dll": {"names": [...]}})` | `pe_symbols::addresses_for_process_symbols(ctx, k, &vec![("ntdll.dll".into(), WantedSymbols::names(&[..]))])?` → `Vec<(module, Vec<(name, addr)>)>` |
| `PESymbols.get_kernel_modules / get_process_modules(ctx, kernel, filter)` | `pe_symbols::get_kernel_modules(k, Some(&filter))?` / `get_process_modules(k, Some(&filter))?` → `CollectedModules` |
| `PESymbols.find_symbols(ctx, path, wanted, collected)` | `pe_symbols::find_symbols(ctx, &wanted, &collected)?` → `(found, missing)` |
| `PESymbols.path_and_symbol_for_address(ctx, path, collected, ranges, addr)` | `pe_symbols::path_and_symbol_for_address(ctx, &collected, &ranges, addr)?` |
| `PESymbols.get_vads_for_process_cache / get_proc_vads_with_file_paths / filepath_for_address / range_info_for_address / filename_for_path` | same names in `crate::plugins::windows::pe_symbols` |
| `PEDump.dump_pe_at_base / dump_kernel_pe_at_base` | `crate::plugins::windows::pedump::{dump_pe_at_base, dump_kernel_pe_at_base}` |

### Registry (`crate::symbols::windows::registry::RegExt`, `crate::layers::registry`, package W3)

Hives are layers (`&'static RegistryHive`, memoized per hive offset); key nodes / values are
`Obj`s on them. Error classes: `registry::{is_key_error, is_value_error, is_registry_exception,
is_invalid_or_registry}` (python `KeyError` / `ValueError` / `RegistryException`).

| python | rust |
|---|---|
| `HiveList.list_hives(ctx, path, kernel, filter_string, hive_offsets)` | `crate::plugins::windows::registry::hivelist::list_hives(ctx, k, filter, offsets)` → `Vec<Result<&'static RegistryHive>>` (trailing `Err` = python raised); the `_CMHIVE`s: `hivelist::list_hive_objects(ctx, k, filter)` |
| `registry.RegistryHive(ctx, config, name="hive0x...")` / `_find_registry_process()` | `hivelist::hive_at(k, hive_offset)?` / `hivelist::registry_process(k)?` |
| `hive.get_key(path, return_list=True)` / `get_node(cell)` / `get_cell(cell)` / `root_cell_offset` / `get_name()` | `hive.get_key(path)?` (nodes root..key) / `get_key_node(path)?` / `get_node(cell)` / `get_cell(cell)` / `root_cell_offset()` / `get_name()` |
| `HiveScan.scan_hives(ctx, kernel)` | `crate::plugins::windows::registry::hivescan::scan_hives(ctx, k)` |
| `CM_KEY_NODE.get_subkeys() / get_values() / get_name() / get_key_path() / get_volatile()`, `node.LastWriteTime` | `RegExt` same names (lazy iterators; `last_write_time()` → `Value`) |
| `CM_KEY_VALUE.get_type() / decode_data()` | `v.get_value_type()?` → `RegValueType` / `v.decode_data()?` → `RegData` |
| `CM_KEY_BODY.get_full_key_name()` (a handle's `Key` body) | `body.get_full_key_name()?` (`RegExt`; `None` where python returns None) |
| `PrintKey.key_iterator(hive, node_path, recurse)` / `MultiTypeData(decode_data())` | `printkey::key_iterator(hive, &path, recurse, &mut f)` (visitor) / `printkey::value_data(&node, ty)?` |
| `Hashdump.get_hive_key / get_bootkey / get_hbootkey / get_user_keys / sid_to_key` | same names in `crate::plugins::windows::registry::hashdump` (+ `read_value_data`, and `find_hives` = python `run()`'s SYSTEM/SAM/SECURITY pick) |
| `Lsadump.get_lsa_key / get_secret_by_name / decrypt_secret / decrypt_aes` | same names in `crate::plugins::windows::registry::lsadump` |

### GUI, network, consoles (package W4)

| python | rust |
|---|---|
| `WindowStations.create_gui_table(ctx, symbol_table, config_path)` | `crate::symbols::windows::gui::create_gui_table(ctx, k.table)?` (python's version → `windows/gui/gui-*` map, `gui::WIN_VERSION_FILE_MAP`) |
| `WindowStations.get_session_map(ctx, kernel, gui_table)` | `crate::plugins::windows::windowstations::get_session_map(k, gui_table)?` → `Vec<(session id, &'static Space)>` (python dict order) |
| `WindowStations.scan_gui_object(ctx, path, kernel, tag, object_type)` / `scan_window_stations(ctx, path, kernel)` | `windowstations::scan_gui_object(ctx, k, tag, object_type, \|obj\| ..)` / `windowstations::scan_window_stations(ctx, k, \|winsta, name, session\| ..)` (streaming, `Ok(false)` stops) |
| `tagWINDOWSTATION` / `tagDESKTOP` / `tagWND` / `_LARGE_UNICODE_STRING` methods | `gui::GuiExt`, named after the class: `winsta_{get_session_id, is_valid, traverse, get_info(k.table), desktops(k.table)}`, `desktop_{get_window_station, get_session_id, is_valid, get_threads}`, `wnd_{get_name, get_desktop, get_session_id, is_valid, get_process, get_window_procedure}`, `large_unicode_get_string` |
| a desktop's window tree / `Windows.list_windows` | `gui::desktop_windows(top: WndRef, max, &mut f)` / `crate::plugins::windows::windows::list_windows(ctx, k, f)` |
| `Desktops.list_desktops` / `DeskScan.scan_desktops` | `desktops::list_desktops(ctx, k, f)` / `deskscan::scan_desktops(ctx, k, f)` (rows: `desktops::{desktop_columns, desktop_values}`) |
| `NetScan.determine_tcpip_version(ctx, kernel)` (netscan ISF version detection) | `crate::plugins::windows::netscan::determine_tcpip_version(k)?` → (ISF file name, python's `win10_x64_class_types`?) |
| `NetScan.create_netscan_symbol_table / create_netscan_constraints / scan` | `netscan::{create_netscan_symbol_table(ctx, k)?, create_netscan_constraints(t)?, scan_each(ctx, k, t, \|obj\| ..)}` |
| netscan / netstat `_generator` rows, columns, `generate_timeline` | `netscan::{object_rows(&obj, show_corrupt, netstat)?, emit_rows(..), columns(), timeline_event(&row, absent)}` |
| `_TCP_ENDPOINT` / `_TCP_LISTENER` / `_UDP_ENDPOINT` / `_LOCAL_ADDRESS` methods (`get_owner(_pid/_procname)`, `get_create_time`, `get_local_address`, `get_remote_address`, `dual_stack_sockets`, `is_valid`) | `crate::symbols::windows::network::NetExt` (same names; `net_create_time`, `net_is_valid`); call `network::bind_class_types(t, win10_x64)` after loading a netscan ISF; glibc `inet_ntop` = `network::inet_ntop(Family, bytes)` |
| `NetStat.get_tcpip_module / list_sockets / parse_partitions / find_port_pools / enumerate_structures_by_port / parse_hashtable / parse_bitmap` (tcpip.sys walking) | same names in `crate::plugins::windows::netstat` (tcpip table: `ctx.symbol_table_from_pdb(k.vlayer, "tcpip.pdb", Some(base), Some(size))?`) |
| consoles classes (`_ROW`, `_SCREEN_INFORMATION`, `_CONSOLE_INFORMATION`, `_COMMAND_HISTORY`, `_COMMAND`, `_EXE_ALIAS_LIST`, `_ALIAS`) | `crate::symbols::windows::consoles::ConsoleExt` (+ `Screen`); properties shadowing members are methods: `command_count()`, `process_handle()`, `screen_buffer()`, `Screen::screen_x/screen_y` |
| `Consoles.find_conhost_proc / find_conhostexe / determine_conhost_version / create_conhost_symbol_table / get_console_settings_from_registry` | `crate::plugins::windows::consoles::{find_conhost_procs, find_conhostexe, determine_conhost_version, create_conhost_symbol_table, get_console_settings_from_registry}` |
| `CmdScan.get_filtered_vads(proc, size_filter)` | `crate::plugins::windows::cmdscan::get_filtered_vads(&proc, size_filter)?` |

## Linux (`use crate::symbols::linux::prelude::*` - LinuxExt, FsExt, CapsExt, NetExt, ...)

`let k = ctx.linux_kernel()?;` → `&LinuxKernel`, derefs to the kernel `Module` (offset =
`aslr_shift`). Fields: `layer` (`&IntelLayer` named "layer_name": `Intel32e` from the VMCOREINFO
stacker, `LinuxIntel32e` from the banner stacker), `vlayer`, `phys`, `table`
(`symbol_table_name1`, symbol_mask = layer address mask), `kaslr_shift`, `aslr_shift`, `dtb`,
`banner`, `stacker`. Cached per image + symbol roots + `--stackers`.

| python | rust |
|---|---|
| `PsList.list_tasks(ctx, kernel, filter, include_threads)` | `crate::plugins::linux::pslist::list_tasks(k, &filter, threads, &mut \|task\| { ...; Ok(true) })?` (callback; `Ok(false)` stops) |
| `PsList.create_pid_filter(pids)` / `get_task_fields(task, decorate)` | `pslist::pid_filter(&pids)` / `pslist::get_task_fields(&task, decorate)?` |
| `list_head.to_list(type, member, forward, sentinel, layer)` | `lh.to_list("task_struct", "tasks", true, true, None)` → lazy `ListIter` of `Result<Obj>` |
| `for x in obj.list_head_member` / `hlist_head.to_list(type, member)` | `lh.list_of(type, member)` / `hh.hlist_to_list(type, member)` |
| `task.is_valid()` (task_struct / vm_area_struct / ... ) | `obj.is_valid()` (unported types return true) |
| `task.add_process_layer()` / `get_address_space_layer()` | same names → `Option<LayerRef>` |
| `task.is_kernel_thread / is_thread_group_leader / is_user_thread` | same names → `Result<bool>` |
| `task.get_threads()` / `state` / `get_parent_pid()` | same names |
| `task.get_create_time()` / `get_boottime(root_ns)` / `get_time_namespace*()` | same names (python's exact float arithmetic, `symbols::linux::timespec`) |
| `mm.get_vma_iter()` (mmap list < 6.1, maple tree >= 6.1) / `get_slot_iter()` | same names → `Vec<Result<..>>` |
| `vma.get_protection()` / `get_flags()` / `get_page_offset()` / `is_valid()` | `get_protection()` / `get_flags()` / `get_page_offset()` / `vma_is_valid()` |
| `path.dentry / .mnt`, `file.get_inode()` | `get_dentry()` / `get_vfsmnt()` / `get_inode()` |
| `task.cred.uid` (int or kuid_t) | `cred.cred_value("uid")?` |
| `LinuxUtilities.container_of(addr, type, member, vmlinux)` | `crate::symbols::linux::container_of(addr, type, member, &vmlinux)?` → `Option<Obj>` |
| `vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(ctx, obj)` | `crate::symbols::linux::vmlinux_of(&obj)?` |
| `elfs.Elfs.elf_dump(...)` | `crate::symbols::linux::elf::{elf_table, elf_dump, elf_dump_ex}` (`elf_dump_ex` → (preferred, final) names) |
| `elf` extension (`get_program_headers`, `get_section_headers`, `get_link_maps`, `get_symbols`, `elf_phdr.get_vaddr/dynamic_sections`, `elf_sym.get_name`, `elf_linkmap.get_name`) | `symbols::linux::elf::{Elf::new(layer, table, off)?, Phdr, ElfSym, LinkMap, elf_sym_get_name}` same method names |
| bash `hist_entry` (`is_valid`, `get_command`, `get_time_object`, `get_time_as_integer`) + `bash32/bash64` ISFs (linux and mac) | `symbols::linux::bash::{bash_table(ctx, is_64bit), HistEntry::parse(&hist)?}` (`.command`, `.time_object()`, `.time` (i128), `.time_int` = exact python int, the `sorted()` key); python `int(str)`: `bash::{PyInt::parse, py_int}` |
| `yarascan.YaraScan.get_yarascan_option_requirements()` / `process_yara_options(config)` | `plugins::linux::vmayarascan::{yarascan_option_requirements, yara_rules_from_config}` (+ `crate::yara::rules::volatility`) |
| `renderers.LayerData(context, offset, layer, length)` | `plugins::linux::vmayarascan::layer_data(layer, offset, len)` → `Value::LayerBytes` |
| `scanners.RegExScanner(pattern)` | `plugins::linux::vmaregexscan::regex_scanner(&Regex)` |
| linux malfind `_get_dirty_pages` / `_is_suspicious` | `plugins::linux::malware::malfind::{get_dirty_pages, is_suspicious}` (`IntelLayer::page_dirty_cursor`) |
| `LinuxUtilities.virtual_to_physical_address(a)` | `crate::symbols::linux::virtual_to_physical_address(a)` |
| `pslist.list_tasks` into a Vec (for `par_map` per-task work) | `pslist::collect_tasks(k, &filter, threads)` → `(Vec<Obj>, Option<Error>)` (trailing python raise) |
| `task.get_process_memory_sections(heap_only)` | same name → `Result<Vec<(start, size)>>` |
| `task.is_being_ptraced / is_ptracing / get_ptrace_tracer_tid() / get_ptrace_tracee_tids() / get_ptrace_tracee_flags()` | same names (`PT_FLAGS` python Flag semantics) |
| `vma.get_name(context, task)` | `vma.vma_get_name(&task)?` → `Option<String>` (`symbols::linux::utilities::vma_get_name`) |
| `vma.get_malicious_pages(proclayer)` / `is_suspicious(proclayer)` | same names (`Option<LayerRef>`); `IntelLayer::is_dirty(addr)` / `page_size_at(addr)` = python `is_dirty` / `_translate` size |
| `LinuxUtilities.path_for_file(ctx, task, filp, files_only)` | `crate::symbols::linux::utilities::path_for_file(&task, &filp, files_only)?` (d_path, memoized) |
| `LinuxUtilities.do_get_path / get_path_mnt / _get_new_sock_pipe_path` | `utilities::{do_get_path, get_path_mnt, get_new_sock_pipe_path}` |
| `LinuxUtilities.files_descriptors_for_process(ctx, table, task, files_only)` | `utilities::files_descriptors_for_process(&task, files_only)` → `Vec<Result<(fd, filp, path)>>` |
| `LinuxUtilities.walk_internal_list(...)` / `convert_fourcc_code(c)` | `utilities::{walk_internal_list, convert_fourcc_code}` |
| `fs_struct.get_root_dentry() / get_root_mnt()`, `files_struct.get_fds() / get_max_fds()` | `FsExt` same names |
| `qstr.name_as_str()`, `dentry.path() / is_root() / is_subdir() / d_ancestor() / get_subdirs()` | `FsExt`: `name_as_str`, `dentry_path`, `is_root`, `is_subdir`, `d_ancestor`, `get_subdirs` |
| `inode.is_dir/is_reg/.. / get_inode_type() / get_*_time() / get_file_mode() / get_pages() / get_contents()` | `FsExt` same names (times → `Value`); `dentry.get_inode()` via `LinuxExt::get_inode` (dispatch) |
| `super_block.major / minor / uuid / get_type() / get_flags_access() / get_flags_opts()` | `FsExt`: `major()`, `minor()`, `uuid()`, `sb_get_type()`, `get_flags_access()`, `get_flags_opts()` |
| `mount.*` / `vfsmount.*` (get_mnt_sb/root/flags/parent/mountpoint, has_parent, get_vfsmnt_*/get_dentry_*, is_shared/slave/unbindable, get_devname, get_dominating_id, next_peer, is_equal) | `FsExt` same names (dispatch on the struct name) |
| `mnt_namespace.get_inode() / get_mount_points()` | `FsExt::get_mnt_ns_inode()` / `get_mount_points()` |
| `address_space.i_pages`, `page.is_valid() / to_paddr() / get_content() / get_flags_list()` | `FsExt`: `i_pages()`, `page_is_valid()`, `to_paddr()`, `page_get_content()`, `get_flags_list()` |
| `IDStorage.choose_id_storage(ctx, "kernel").get_entries(root)` / `PageCache(...).get_cached_pages()` | `symbols::linux::idstorage::{IdStorage::choose(vmlinux)?.get_entries(&root), PageCache::new(vmlinux, mapping)?.get_cached_pages()}` |
| `idr.get_entries()` / `rb_root.get_nodes()` / `scatterlist.for_each_sg() / get_content()` | `idstorage::{idr_get_entries, rb_get_nodes, sg_for_each, sg_get_content}` |
| `kernel_cap_t/kernel_cap_struct.get_capabilities() / get_kernel_cap_full() / enumerate_capabilities() / has_capability()` | `CapsExt` same names; `caps::CAPABILITIES` |
| network extensions (`net_device`, `in_device`, `inet6_dev`, `*_ifaddr`, `socket`/`sock`/`*_sock`) | `NetExt` (`symbols::linux::network`): python names; `net_get_inode`, `sock_get_state`, `sock_get_type`, `unix_get_name` where names clash; `inet_ntop4/6`, `convert_ipv4/6`, constants |
| `module.*` (get_module_base/core/init, get_*_size, get_name, get_sections, get_symbols, get_symbol(_by_address), get_module_address_boundaries, section_symtab/strtab/typetab, get_symbol_type), `module.is_valid()` | `ModuleExt` (`symbols::linux::module`) same names; `is_valid` via `LinuxExt::is_valid` / `module::module_is_valid(_checked)` |
| `kernel_symbol` / `module_sect_attr` / `bin_attribute` / `bpf_prog(_aux)` / `latch_tree_root.find` / `kobject.reference_count` | `ModuleExt`: `get_name()` (dispatch), `get_value()`, `get_namespace()`, `address()`, `get_type()`, `get_tag()`, `get_address_region()`, `find(key, &mut comp)`, `reference_count()` |
| `linux_utilities_modules.Modules.*` (list_modules, run_modules_scanners, module_lookup_by_address, get_hidden_modules, get_kset_modules, get_load_parameters, get_modules_memory_boundaries, mask_mods_list, lookup_module_address) | `symbols::linux::modules` same names (`vm` = `k` / `&Module`; `ALL_GATHERERS`, `ModuleInfo`) |
| `kallsyms.Kallsyms(ctx, layer, module)` + `lookup_address / lookup_name / get_*_symbols` | `symbols::linux::kallsyms::Kallsyms::get(vm)?` (built once, cached, thread-safe) + same names → `KasSymbol` |
| `ModuleExtract.extract_module(ctx, kernel, module)` | `symbols::linux::module_extract::extract_module(vm, &module)?` → `Option<Vec<u8>>` |
| `linux_constants.KSYM_NAME_LEN / MODULE_* / NM_TYPES_DESC` | `symbols::linux::constants` |
| `tainting.Tainting.get_taints_parsed / get_taints_as_plain_string(ctx, kernel, taints, is_module)`, `linux_constants.TAINT_FLAGS` | `symbols::linux::tainting::{Tainting::new(k)?.get_taints_parsed(taints, is_module)?, TAINT_FLAGS}` (build `Tainting` once per run) |
| `Modules.get_kset_modules` keeping the `module_kobject.mod` pointer objects | `modules::get_kset_modules_ptrs(k)?` → `(name, pointer Obj, value)` |
| many `Modules.module_lookup_by_address` calls (e.g. a table of handlers) | `modules::module_lookup_by_addresses(k, &mods, &addrs)` (one symbol-table pass for all kernel addresses; stops at the first `Err`) |
| `get_symbols_by_absolute_location(addr)` for many addresses | `k.table.symbols_at_exact_many(&rel_offsets)` (one linear pass; `symbols_at(off, 0)` itself answers the first 8 exact lookups linearly, then builds the address index) |
| `for sn in vmlinux.symbols: vmlinux.get_symbol(sn).address` (whole-table scans) | `k.table.symbol_names_addrs()` → `(raw name bytes, masked address)` |
| `ModuleDisplayPlugin.generate_results(...)` / `columns_results` (lsmod, check_modules, hidden_modules) | `plugins::linux::lsmod::{generate_results(ctx, k, iter of (vol.offset, module), dump, out), columns()}` |
| `Hidden_modules.find_hidden_modules / get_lsmod_module_addresses`, `Check_modules.compare_kset_and_lsmod` | `plugins::linux::malware::{hidden_modules, check_modules}` same names |
| `Check_idt.get_idt_type`, `IOMem.parse_resource`, `Boottime.get_time_namespaces_bootime` | `plugins::linux::{malware::check_idt::get_idt_type, iomem::parse_resource, boottime::get_time_namespaces_boottime}` |

## Mac (`use crate::symbols::mac::MacExt`)

`let k = ctx.mac_kernel()?;` → `&MacKernel`, derefs to the kernel `Module` (offset = python
`kernel_virtual_offset`, the KASLR shift). Fields: `layer` (`&IntelLayer`, python
`layer_name`), `vlayer`, `phys`, `table` (symbol_mask 2^48-1), `kaslr_shift`, `dtb`, `banner`,
`isf`. Automagic results are cached per image + symbol path (warm runs do no scanning).

| python | rust |
|---|---|
| `kernel.object_from_symbol("allproc")` | `k.object_from_symbol("allproc")?` |
| `PsList.list_tasks(ctx, kernel, filter, method)` | `crate::plugins::mac::pslist::list_tasks(k, "tasks", &filter)` (+ `list_tasks_{allproc,tasks,sessions,process_group,pid_hash_table}`) |
| `PsList.create_pid_filter(pids)` | `pslist::pid_filter(&pids)` |
| `queue_entry.walk_list(head, member, type_name)` | `q.walk_list(&head, "p_list", "proc", MAX_ELEMENTS)` → `Vec<Result<Obj>>` |
| `MacUtilities.walk_tailq / walk_list_head / walk_slist(q, next)` | `q.walk_tailq(next, MAX_ELEMENTS)` / `walk_list_head` / `walk_slist` |
| `proc.get_task()` / `add_process_layer()` / `get_map_iter()` | same names (`add_process_layer()?` → `Option<LayerRef>`) |
| `fileglob.get_fg_type()` / `vm_map_object.get_map_object()` | same names |
| `vm_map_entry.get_perms() / get_range_alias() / get_special_path() / get_object() / get_offset()` | same names (`get_perms` also for `sysctl_oid`) |
| `sysctl_oid.get_ctltype()` / `vnode.full_path()` | same names |
| `datetime.datetime.fromtimestamp(t)` (naive local time) | `crate::util::time::fromtimestamp_local(t)` → `Result<DateTime, String>` (`Err` = python exception text) |
| `mac.MacUtilities.virtual_to_physical_address(a)` | `crate::symbols::mac::virtual_to_physical_address(a)` |
| `lsmod.Lsmod.list_modules(ctx, kernel)` | `crate::plugins::mac::lsmod::list_modules(k)` → `Vec<Result<Obj>>` (first a `kmod_info`, then `kmod_info *` pointers) |
| `MacUtilities.generate_kernel_handler_info(ctx, layer, kernel, mods)` | `symbols::mac::generate_kernel_handler_info(k, list_modules(k))?` → `Vec<Handler>` |
| `MacUtilities.lookup_module_address(ctx, handlers, addr, kernel_name)` | `symbols::mac::lookup_module_address(k.table, &handlers, addr, Some(k.offset))` (`None` = no module name passed) |
| `kauth_scope.get_listeners()` | `scope.get_listeners()` (`MacExt`) |
| `MacUtilities.files_descriptors_for_process(ctx, table, task)` | `symbols::mac::files::files_descriptors_for_process(&task)` → `Vec<Result<FdEntry>>`; map a trailing error with `files::raise_python` (python ValueError / UnboundLocalError crash the plugin) |
| `socket.get_family() / get_state() / get_converted_connection_info()` ..., `inpcb.*`, `ifnet.sockaddr_dl()`, `str(sockaddr_dl)`, `sockaddr.get_address()` | `symbols::mac::net::{socket_get_family, socket_get_state, socket_get_converted_connection_info, inpcb_get_tcp_state, ifnet_sockaddr_dl, sockaddr_dl_str, sockaddr_get_address}` |
| `conversion.convert_ipv4 / convert_ipv6 / convert_port / convert_network_four_tuple` | `symbols::mac::net::{convert_ipv4, convert_ipv6, ipv6_to_string, convert_port, convert_network_four_tuple}` (python 3.14 `ipaddress` formatting; host AF_INET6 = 10) |
| `Mount.list_mounts` / `List_Files.list_files` / `Kevents.list_kernel_events` / `Netstat.list_sockets` / `Kauth_scopes.list_kauth_scopes` / `Dmesg.get_kernel_log_buffer` | same names in `crate::plugins::mac::{mount, list_files, kevents, netstat, kauth_scopes, dmesg}` |

A trailing `Err` in a walker's `Vec` marks where python would have raised. Python exceptions
that are not volatility exceptions (e.g. `ValueError` from `datetime`) crash python's plugin
with a traceback; the rsvol equivalent is a plugin panic, which the CLI renders the same way.

## Layers

| python | rust |
|---|---|
| `layer.read(off, n)` | `layer.read_vec(off, n)?` / `layer.read(off, &mut buf)?` / `read_u64(off)?` ... (`LayerExt`) |
| `layer.read(off, n, pad=True)` | `layer.read_vec_padded(off, n)` / `layer.read_padded(off, &mut buf)` |
| `layer.is_valid(off, n)` | `layer.is_valid(off, n)` |
| `layer.mapping(off, n, ignore_errors=True)` | `layer.mapping(off, n, &mut \|m\| {..; true})` / `layer.mappings(off, n)` (python runs, coalesced) |
| `layer.translate(off)` | `k.layer.translate_addr(off)` → `Option<(phys, Target)>` ; generic `layer.translate(off)` |
| `layer.maximum_address` / `address_mask` | `layer.max_address()` / `layer.address_mask()` |
| `layer.metadata.get("pae")` / `architecture` / `os` | `crate::layers::metadata(layer).pae` / `.architecture` / `.os` |
| `layer.canonicalize(addr)` | `k.layer.canonicalize(addr)` |
| `layer.config["kernel_virtual_offset"]` | `layer.as_intel().and_then(\|i\| i.kernel_virtual_offset())` |
| `isinstance(layer, intel.Intel)` | `layer.as_intel().is_some()` |
| `isinstance(layer, linear.LinearlyMappedLayer)` (false for AVML / QEMU) | `layer.is_linear()` (scans read non-linear layers through the layer, per segment) |

## Scanning (python `layer.scan(context, scanner, sections=...)`)

Chunking, overlap handling and hit order are python-identical; chunks are scanned on all cores.

```rust
use crate::layers::scan::{scan, scan_each, BytesScanner, MultiStringScanner, FnScanner};
let hits: Vec<u64> = scan(k.phys, &BytesScanner::new(b"KDBG"), None);          // all hits
let tags = MultiStringScanner::new(&[b"Proc".as_ref(), b"Pro\xe3"]);
scan_each(k.phys, &tags, None, |(addr, pattern_idx)| { /* ... */ true });         // stream, early stop
let s = FnScanner::new(|data: &[u8], off: u64, out: &mut Vec<u64>| { /* regex etc. */ });
let hits = scan(k.vlayer, &s, Some(&[(start, len)]));                           // sections
```

Scanner hits must respect python's rule "only report matches starting before `chunk_size`";
the built-in scanners do. Per-hit validation can run inside the scanner (it runs in parallel).
Scanners must use python's `chunk_size`/`overlap` values for that scanner class: the overlap
changes python's last chunk of a section (hits there can be reported twice, like python).

| python | rust |
|---|---|
| `layer.scan(ctx, scanners.BytesScanner(needle), sections)` | `scan(layer, &BytesScanner::new(needle), Some(&secs))` → `Vec<u64>` |
| `layer.scan(ctx, scanners.MultiStringScanner(patterns))` | `scan_each(layer, &MultiStringScanner::new(&pats), None, \|(addr, idx)\| ..)` (AVX2 prefilter; `RSVOL_NO_SIMD=1` forces scalar) |
| `layer.scan(ctx, scanners.RegExScanner(pattern))` | `FnScanner::new(\|data, off, out\| ..)` with the regex engine (apply the `chunk_size` rule yourself) |
| `PdbSignatureScanner(names)` / `PDBUtility.pdbname_scan(...)` | `automagic::windows::{RsdsScanner, pdbname_scan}` (streaming) or `PdbSignatureScanner` (GUID/age in the hit); the matcher on raw bytes: `symbols::windows::pdb::{rsds_search, rsds_scan, find_mz_before, guid_string}` |
| a scan that usually stops at an early hit (banners) | `scan_each_progressive(layer, &scanner, \|h\| h.0, \|h\| ..)` (growing batches; same hits/order as `scan_each`) |

A custom scanner gets the fast paths by implementing the optional `Scanner` methods:
`prescan`/`finish` (byte matching that depends only on the chunk's bytes: identical physical
pages mapped at several virtual addresses are searched once) and `stream_window`/`prescan_piece`
(big chunks read in 64 KiB cache-resident pieces). `BytesScanner`, `MultiStringScanner`,
`RsdsScanner` and the pool header scanner implement them; a plain `scan` still works (mapped
chunks, slower).

**Scan cache** (`crate::layers::scancache`): a two-phase scanner that also implements
`cache_query()` has its raw `prescan` matches cached per image (`~/.cache/rsvol/scan/`); repeat
scans of the same layer / sections / chunking replay them through `finish` in python order
without reading the layer, so put every python-side check in `finish` (it runs on every run).
Describe the prescan exactly: `CacheQuery::Greedy { patterns, limit, cap }` (python
`MultiStringScanner`; delegate to the inner `MultiStringScanner::cache_query()`),
`CacheQuery::Every { needle, limit }` (python `BytesScanner`), or `CacheQuery::Opaque { key }`
(the prescan output as is; `key` = name + version + every parameter). Literal queries are
answered from per-literal atoms, and a full-layer miss also records well-known literals (pool
tags, MFT / MBR signatures, vmscan page starts) in the same sweep, so the next scanner of that
family is warm too. Never implement it for scanners of user-supplied patterns (yara/regex).
`RSVOL_NO_SCAN_CACHE=1` disables the cache, `--clear-cache` wipes it.

### Pool scanning (`crate::plugins::windows::poolscanner`, `crate::symbols::windows::pool`)

| python | rust |
|---|---|
| `PoolScanner.builtin_constraints(table, [b"Fil\xe5", b"File"])` | `builtin_constraints(k.table.name(), &[b"Fil\xe5", b"File"])` → `Vec<PoolConstraint>` |
| `PoolConstraint(tag, type_name, object_type=, size=, page_type=, ...)` | `PoolConstraint::new(b"Tag", "nt!_TYPE").object_type("File").size(Some(min), None).page_type(pool_type::PAGED \| pool_type::NONPAGED)` |
| `for c, obj, hdr in PoolScanner.generate_pool_scan(ctx, kernel, constraints)` | `generate_pool_scan_each(ctx, k, k.table, &cons, \|h: PoolHit\| { h.constraint; h.object; h.header; Ok(true) })?` (streaming, python order) or `generate_pool_scan(ctx, k, &cons)?` → `Vec<PoolHit>` |
| `generate_pool_scan_extended(ctx, kernel, object_table, constraints)` | `generate_pool_scan_extended(ctx, k, table, &cons)?` |
| `PoolScanner.pool_scan(ctx, layer, table, constraints, alignment)` | `pool_scan(ctx, k, layer, table, &cons, align)?` → `Vec<(constraint idx, _POOL_HEADER)>`; `pool_scan_with(.., post, f)` runs `post` on the scan threads |
| `handles.Handles.get_type_map(...)` / `find_cookie(...)` | `poolscanner::get_type_map(k)?` (memoized) / `find_cookie(k)?` |
| `pool_header.is_free_pool() / is_paged_pool() / is_nonpaged_pool()` | same names (`PoolExt`, in the prelude) |
| `obj.get_object_header()` / `ExecutiveObject.get_name()` | `obj.get_object_header(None)?` / `obj.executive_name(None)?` → `Option<String>` |
| `object_header.get_object_type(type_map, cookie)` / `NameInfo` / `get_name()` | `hdr.get_object_type(&type_map, cookie)?` / `hdr.name_info()?` / `hdr.header_name()?` |
| `big_page.get_key() / get_pool_type() / get_number_of_bytes() / is_free() / is_valid()` | same names (`big_page_is_valid()`, or `is_valid()` via `WinExt`) |
| `device.get_device_name()` / `get_attached_devices()` | `dev.get_device_name()?` / `dev.get_attached_devices()` → `Vec<Result<Obj>>` (`ObjectsExt`) |
| `driver.get_driver_name()` / `link.get_link_name()` / `mutant.get_name()` | `get_driver_name()?` / `get_link_name()?` / `mutant_name()?` (`Err` with `objects::is_name_info_value_error` = python's `ValueError`) |
| `file_obj.file_name_with_device()` / `access_string()` | `fo.file_name_with_device()?` → `Value::Str` or `Value::Unreadable` / `fo.access_string()?` |
| `modules.Modules.get_kernel_space_start(ctx, kernel)` | `crate::plugins::windows::modules::get_kernel_space_start(k)?` |
| `psscan.PsScan.scan_processes(ctx, kernel, filter_func)` | `crate::plugins::windows::psscan::scan_processes(ctx, k, &filter)` / `scan_processes_each(ctx, k, &filter, \|p\| ..)` |
| `PsScan.virtual_process_from_physical / physical_offset_from_virtual / create_offset_filter / get_osversion` | same names in `psscan` |

Worked example (python `filescan`), byte-identical to python:

```rust
use crate::plugins::windows::poolscanner::{builtin_constraints, generate_pool_scan_each};
let cons = builtin_constraints(k.table.name(), &[b"Fil\xe5", b"File"]);
generate_pool_scan_each(ctx, k, k.table, &cons, |h| {
    match h.object.m("FileName").and_then(|n| n.get_string()) {
        Ok(name) => out.row(0, vec![Value::Int(h.object.addr as i128), Value::Str(name)])?,
        Err(e) if e.is_invalid_address() => {}          // python: continue
        Err(e) => return Err(e),
    }
    Ok(true)
})?;
```

The ignored test `context::bench::object_scans_via_core_api` rebuilds symlinkscan, mutantscan
and driverscan this way and diffs them against python's output.

### Kernel objects, threads, callbacks (`crate::plugins::windows::*`, package W1)

Streaming `*_each(ctx, k, |obj| { ..; Ok(true) })` variants return python's mid-iteration
error after the objects before it; collected variants return `Vec<Result<..>>` with a trailing
`Err`.

| python | rust |
|---|---|
| `ssdt.SSDT.build_module_collection(ctx, kernel)` | `ssdt::build_module_collection(k)?` → `ModuleCollection` |
| `collection.get_module_symbols_by_absolute_location(addr)` | `coll.module_symbols(addr)` → `Vec<(module name, Vec<symbol>)>` (symbols without `table!`); `coll.contains(addr)` = non-empty |
| `context.modules.free_module_name(prefix)` / `os.path.splitext(p)[0]` | `ssdt::free_module_name(&existing, prefix)?` / `ssdt::splitext_root(p)` |
| `DriverScan.scan_drivers(ctx, kernel)` / `get_names_for_driver(d)` | `driverscan::scan_drivers_each(ctx, k, f)` / `scan_drivers` / `get_names_for_driver(&d)?` |
| `driver.get_devices()` / `device.get_attached_devices()` | `d.get_devices()` / `dev.get_attached_devices()` (`ObjectsExt`; python semantics: a NULL pointer yields the object at 0, the walk ends on an unreadable pointer) |
| `driverirp.MAJOR_FUNCTIONS` | `driverirp::MAJOR_FUNCTIONS`, `driverirp::IRP_MJ_SHUTDOWN` |
| `Handles.handles(ctx, kernel, handle_table)` (`_make_handle_array`, `_get_item`) | `handles::HandleWalker::new(k)?.handles(&proc.m("ObjectTable")?)` → `Vec<Result<HandleItem { header, handle_value, granted_access }>>` |
| `Handles._generator`'s per-handle naming (File / Process / Thread / Key / NameInfo) | `handles::handle_object_info(&item, &type_map, cookie)?` → `Option<(type, name Value)>` |
| `FileScan.scan_files` / `MutantScan.scan_mutants` / `SymlinkScan.scan_symlinks` / `ModScan.scan_modules` | `filescan::scan_files_each` / `mutantscan::scan_mutants_each` / `symlinkscan::scan_symlinks_each` / `modscan::scan_modules` |
| `Modules._generator` (dump / base / name handling) | `modules::generate(ctx, cfg, out, &mut \|\| entries)` + `modules::columns()` |
| `BigPools.list_big_pools(ctx, kernel, tags, show_free)` | `bigpools::list_big_pools_each(ctx, k, tags, show_free, f)` |
| `ThrdScan.scan_threads` / `gather_thread_info(ethread, vads_cache)` | `thrdscan::scan_threads(_each)` / `thrdscan::gather_thread_info(&t, Some(&mut cache))?` → `Option<ThreadInfo>`; many threads: `thrdscan::thread_rows(threads, out)` (parallel VAD walks) |
| `Threads.list_threads(ctx, kernel, proc)` / `list_process_threads` | `threads::list_threads(k, &proc)` / `threads::list_process_threads(k)` |
| `orphan_kernel_threads.Threads.list_orphan_kernel_threads` | `orphan_kernel_threads::list_orphan_kernel_threads(ctx, k)` |
| `KPCRs.list_kpcrs(ctx, kernel)` / `Timers.list_timers(ctx, kernel)` | `kpcrs::list_kpcrs(k)` → `Vec<Result<(kpcr, prcb)>>` / `timers::list_timers_each(k, f)` |
| `Callbacks.create_callback_symbol_table / scan / list_notify_routines / list_registry_callbacks / list_bugcheck(_reason)_callbacks` | same names in `callbacks` → `Vec<Result<CallbackEntry { kind, address, detail }>>` |
| `UnloadedModules.create_unloadedmodules_table / list_unloadedmodules` | same names in `unloadedmodules` |
| `DebugRegisters._get_debug_info(ethread)` | `debugregisters::get_debug_info(&t)?` |

### Services, malware helpers (`crate::plugins::windows::*`, package W5)

| python | rust |
|---|---|
| `SvcScan.get_prereq_info(...)` (services ISF + registry `ImagePath` / `ServiceDll` map) | `svcscan::get_prereq_info(ctx, k)?` → `Prereq { table, binary_map }` |
| `SvcScan.service_scan(...)` / `SvcList.service_list(...)` (rows of `get_record_tuple`) | `svcscan::service_scan(k, &pre, &mut \|row\| ..)` / `svclist::service_list(k, &pre, f)` → `ServiceRow { values, name, key }` |
| `SvcScan.enumerate_vista_or_later_header(...)` / `SERVICE_RECORD.traverse()` | `svcscan::enumerate_vista_or_later_header(table, &map, layer, offset, f)` (row offsets are the `PrevEntry` pointers' own addresses, like python) |
| `pslist.PsList.create_name_filter(["services.exe"])` / `create_active_process_filter()` | `svcscan::services_filter` / `malware::processghosting::active_process_filter` |
| `Malfind.is_vad_empty(layer, vad)` / `list_injection_sites(...)` | `malware::malfind::is_vad_empty(layer, start, size)?` / `malware::malfind::list_injection_sites(&proc, &pv)` |
| `YaraScan.get_yarascan_option_requirements()` / `process_yara_options(config)` | `vadyarascan::yarascan_option_requirements()` / `vadyarascan::rules_from_config(cfg)?` |
| `scanners.RegExScanner(pattern)` (DOTALL, `chunk_size` rule) | `vadregexscan::regex_scanner(&re)` → `FnScanner` |
| `DirectSystemCalls` / `IndirectSystemCalls` machinery (`syscall_finder_type`, `_is_syscall_block`, `_generator`) | `malware::direct_system_calls::{SyscallFinder, DIRECT, run_finder}`, `malware::indirect_system_calls::INDIRECT` |
| a python dict keyed by int (insertion order) | `malware::hollowprocesses::OrderedMap<V>` |

## Plugins & output

* A plugin is a unit struct implementing `crate::plugins::Plugin` (see `src/plugins/windows/pslist.rs`),
  registered in its group `mod.rs`. `requirements()` lists only CLI-visible options in python order.
* `out.begin(vec![Column::new("PID", ColType::Int), ...])` then `out.row(depth, values)`.
  Column TYPE decides formatting (`ColType::Hex` renders `Value::Int(16)` as `0x10`).
* python `renderers.UnreadableValue()` = `Value::Unreadable` ("-"), `NotApplicableValue()` =
  `Value::NotApplicable` ("N/A"), `UnparsableValue()` = `Value::Unparsable` ("-").
* Files: `let (file, name) = ctx.create_output_file(&sanitize_filename(..))?;` (python's
  `-N` de-duplication and mode 0o600 minus umask, like `tempfile.mkstemp`; a plugin creating a
  file itself uses `cli::files::open_new(path)`) — `name` is the
  final name python prints after `close()`; `pedump.dump_pe` prints the requested name instead.
* A plugin's own unsatisfied requirement (e.g. `TranslationLayerRequirement(name="primary",
  description=...)`): `Err(crate::plugins::unsatisfied_described(&[("primary", UnsatKind::Layer,
  "Memory layer for the kernel")]))` prints python's message (kinds: Layer, Symbols, Other).
* Errors: return `Err(e)`; python's "skip this row on InvalidAddressException" is
  `match row() { Err(e) if e.is_invalid_address() => continue, ... }`.
  An `Error::Msg` / `Error::Symbol` whose text starts with a python builtin exception name
  (`"AttributeError: ..."`, `"ValueError: ..."`, `"TypeError: ..."`, `"KeyError"`, ... see
  `cli::python_builtin_exception`) is reported like python's uncaught exception (traceback on
  stderr, no `"\n\n"` on stdout); other errors get python's `process_exceptions` block.

* Timeliner (`TimeLinerInterface.generate_timeline`): implement `timeline()`; if the python
  generator can raise AFTER its first yield, implement `timeline_events()` instead and return
  the events yielded so far plus the error (python keeps them). `plugins::default_config(p)`
  is the config the timeliner constructs a plugin with. The 22 python timeliner plugins are
  listed in `plugins::generic::timeliner::TIMELINER_PLUGINS`.

## Generic plugin helpers (`crate::plugins::generic`)

| python | rust |
|---|---|
| `TranslationLayerRequirement(name="primary")` layer | `primary::primary(ctx, desc)?` (`.layer`, `.intel`, `.phys`, `.os`); `primary_intel` when python requires Intel32/64; `primary::physical(ctx, desc)?` for plugins stepping down to `memory_layer` |
| `scanners.RegExScanner(pattern)` | `regexscan::RegExScanner::new(pattern)?` (two-phase `Scanner`, hit = address) |
| `yarascan.YaraScanner(rules)` / `process_yara_options(config)` | `yarascan::YaraScanner { rules: &r }` / `yarascan::rules_from_config(cfg)` |
| `renderers.LayerData(ctx, layer, offset, length)` | `yarascan::layer_data_value(layer, offset, length)` (`Value::LayerBytes` like the CLI renderer) |
| `yarascan.get_yarascan_option_requirements()` | `yarascan::yarascan_option_requirements()` |
| `Banners.locate_banners(ctx, layer)` | `banners::locate_banners(layer)?` |
| `LayerWriter.write_layer(...)` | `layerwriter::write_layer(layer, &file, len)` (sparse, reflink / copy_file_range) |
| a requirement's `build_configuration()` tree | `pyconfig::{primary_tree, kernel_tree, container_tree}` |

## Python-compatibility utilities (`crate::util`)

| python | rust |
|---|---|
| `json.loads(s)` (dicts: a repeated key keeps its first position, last value) | `util::json::Json::parse(bytes)?` (DOM) / `util::json::Parser` (pull parser, the ISF loader); pull-parsed objects: `util::json::dict_dedupe(&mut entries, \|e\| key)` |
| iterating a python `set` of ints (CPython slot order) | `util::pyset::PyIntSet`; sets of str / tuples (as with `PYTHONHASHSEED=0`): `util::pyset::{PySet, py_hash_int, py_hash_str_seed0, py_hash_tuple}` |
| `sqlite3` full table scan (rowid order), e.g. volatility3's `identifier.cache` | `util::sqlite::Database::open(path)?` → `table(name)?`, `for_each_row(&t, f)` / `rows(&t)` |
| `format(v, spec)` / f-string format specs | `util::pyformat::{fmt_int, fmt_str}` |
| `datetime` conversions / `str(datetime)` | `util::time::{wintime_to_datetime, unixtime_to_datetime, py_str, asctime, fromtimestamp_local}` |

## Performance notes

* `Obj` is `Copy`; pass by value. Member lookup is a precomputed hash probe (~20 ns); `Field`
  avoids even that. Page walks go through a per-thread TLB and a shared page-table-validity cache;
  `layer.slice()` gives zero-copy access to mmapped bytes within one page.
* Symbol tables are flat mmapped blobs (warm load ~0.02 ms); kernel discovery is cached per image
  (`~/.cache/rsvol/automagic`). `RSVOL_TRACE=1` prints timing spans; `RSVOL_CACHE=dir` relocates
  the caches (use an empty dir to measure cold runs).
* Use `crate::util::par::{par_map, par_for, par_map_stream}` for per-process / per-item work
  that reads lots of memory; results stay in order. Pattern (see `plugins/windows/vadinfo.rs`):
  compute each process's rows as `Vec<Result<Vec<Value>>>` in parallel, then emit them in python
  order, stopping at the first `Err` exactly where python would have raised. Keep work that has
  side effects python would not reach after an error (e.g. `--dump` files) sequential.
