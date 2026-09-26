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
`TokenExt` (TOKEN), `KtimerExt` (KTIMER), `CacheExt` (CONTROL_AREA / SHARED_CACHE_MAP / VACB).
Pool / object-header helpers live in `crate::symbols::windows::pool`.

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

## Linux (`use crate::symbols::linux::LinuxExt`)

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
| `elfs.Elfs.elf_dump(...)` | `crate::symbols::linux::elf::{elf_table, elf_dump}` |
| `LinuxUtilities.virtual_to_physical_address(a)` | `crate::symbols::linux::virtual_to_physical_address(a)` |

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

## Plugins & output

* A plugin is a unit struct implementing `crate::plugins::Plugin` (see `src/plugins/windows/pslist.rs`),
  registered in its group `mod.rs`. `requirements()` lists only CLI-visible options in python order.
* `out.begin(vec![Column::new("PID", ColType::Int), ...])` then `out.row(depth, values)`.
  Column TYPE decides formatting (`ColType::Hex` renders `Value::Int(16)` as `0x10`).
* python `renderers.UnreadableValue()` = `Value::Unreadable` ("-"), `NotApplicableValue()` =
  `Value::NotApplicable` ("N/A"), `UnparsableValue()` = `Value::Unparsable` ("-").
* Files: `let (file, name) = ctx.create_output_file(&sanitize_filename(..))?;` — `name` is the
  final name python prints after `close()`; `pedump.dump_pe` prints the requested name instead.
* Errors: return `Err(e)`; python's "skip this row on InvalidAddressException" is
  `match row() { Err(e) if e.is_invalid_address() => continue, ... }`.

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
