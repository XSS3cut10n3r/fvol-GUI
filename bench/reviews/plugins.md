# Performance review: per-plugin work (object model + plugins)

Reviewer scope: everything a plugin does after startup. That covers the object model (`Obj`, member
lookups by name, `Field`, reads through the translation and segment layers, list walking) and the
plugins themselves. Scan engine throughput and startup/automagic belong to the other reviews. They
appear here only where a plugin's own design puts them on its critical path, as in timeliner.

Date 2026-09-26. rsvol `6825849` (main). Prototype: branch `perf-review` in
`testdata/scratch/review-plugins/rsvol` (commit `41783e6`), with the patch in
`testdata/scratch/review-plugins/0001-perf-objects-plugins-prototype-from-the-plugin-perfo.patch`.

## Verdict

**No, the per-plugin work is not at the hardware limit.** It splits into three groups:

* **Object-walking plugins** are 2.5 to 7x above a first-principles floor. This group includes
  handles, vadinfo, vadwalk, iat, verinfo, ldrmodules, threads, dlllist, the svc* plugins, the
  pe_symbols users, most `linux.*` and `mac.*` plugins, kallsyms and pagecache.Files. The costs
  break down as follows:
  * rsvol spends 11,000 to 15,000 instructions per kernel object. For example, handles runs 453M
    instructions for 40,889 handles (530M before the prototype), and vadinfo about 15k per VAD. A
    hand-written reader would need about 1,000.
  * Minor page faults are 25 to 50% of their CPU time. On the main image, handles takes 10.5k
    faults, of which 6.5k are anonymous heap growth. ldrmodules takes 11k faults, costing 30 ms of
    system time out of 70 ms CPU.
  * Many plugins still format every row serially on the main thread after the parallel phase. For
    handles that serial phase was 5.3 ms of 19 ms.
  * The per-process fan-out is coarse (one process = one task) and spawns fresh threads on every
    parallel call: 20 to 100 per run.
  * None of this is hardware-bound. Prototyping the three cheapest fixes (below) gave:
    * handles −52 to −54% wall;
    * iat, vadinfo and svc* −30 to −45%;
    * 30+ plugins −10 to −31% instructions;
    * byte-identical output on all 31 images.
* **Output-write-bound plugins are at their floor.** dumpfiles is 741 ms for 528 MiB. memmap
  (all processes, 2.2 GB) and timeliner, mftscan and mbrscan (to a file) are also here. They are
  limited by this box's btrfs + dm-crypt buffered-write path, about 0.7 to 1.7 GB/s. To
  `/dev/null` these plugins still have a 3 to 4x gap: timeliner's serial merge, mftscan's 26%
  parallel efficiency, and memmap formatting.
* **Timeliner is dominated by work python also does and that rsvol does not cache.** The critical
  path of its concurrent sub-plugins is the *failing* Linux kernel discovery: a full-image banner
  scan of the Windows image, 277 ms warm and 646 ms steady, against 455 ms (warm) and 822 ms
  (steady) of `plugin.run`. On the mac image the failing Linux and Windows discoveries cost 484 ms
  to 2.3 s for a 444-byte output.

Scan-bound plugins in steady mode are the scan review's topic: the pool scanners, psscan, sockscan,
vmcoreinfo, banners, vmscan and mbrscan. Their post-scan work in warm mode is small: pool scanners
6 to 10 ms, linux psscan 10 ms, sockscan 9 ms, vmcoreinfo 1.3 ms.

## How this was measured

* Machine: i7-12700KF (8P+4E, 20 threads), 62 GB RAM, btrfs on dm-crypt, Linux 7.1.8.
* Images: `memory-dirty.raw` (Windows 11 22000, 5 GiB), the 1809 image, noble 6.8 and jammy 5.15
  ELF with `-s testdata/symbols`, and mac 10.9.2.
* Builds and harness:
  * Release builds with the repo's flags. Profiling builds add frame pointers and line tables;
    A/B pairs always use identical flags.
  * `perf` 7.2 from the Arch package, run unprivileged; user-space only because
    `perf_event_paranoid=2` and the sample rate is capped at 1 kHz, so every profile aggregates
    15 to 30 runs.
  * `RSVOL_TRACE` spans are included.
  * Harness `tim.py` / `ab.py` measures min and median wall over 5 to 11 interleaved runs, with
    `wait4` user and system times.
  * `abinst.sh` counts `instructions:u`, min of 5 runs.
* Cache state: warm symbol, automagic and identifier caches. `RSVOL_NO_SCAN_CACHE=1` ("steady")
  unless noted as warm.
* **Noise caveat:** load average was 6 to 18 throughout: other agents' builds, python oracles and
  a game. Absolute wall times move by ±30 to 100% between runs. Relative A/B numbers from
  interleaved runs and the instruction counts were stable, so those are what the conclusions rest
  on.
* The quiet-VM numbers in `bench/vm/results2.tsv` (rsvol `95528b2`, Zen 2) are stale for this
  purpose. Later work made many plugins 3 to 5x faster: dlllist is 26.8 ms there and 5.7 ms here.
  suspended_threads and debugregisters, called out as the smallest margins against vol-rs, now run
  in 10.7 and 6.4 ms here, against vol-rs warm 103 and 95 ms on the VM.
* Scripts are in `testdata/scratch/review-plugins/`: `tim.py`, `ab.py`,
  `abinst.sh`, `prof.sh`, `profsweep.sh`, `timeline.sh` and `micro/*.c`. Raw results are in
  `res/`.

### Floor model

A plugin's floor is the sum of the terms below. Each term was measured on this box.

| term | cost | how measured |
|---|---|---|
| process + cached kernel/ISF | **1.2 ms** | frameworkinfo 0.7, windows.info 1.0, pslist 1.2 ms |
| cache-missing object reads | ~90 ns each, across 20 threads | |
| minor fault on the image mmap | **2.4 to 3.1 µs**, once per 64 KiB block | `micro/faults.c`: 10k random pages 23.7 ms on 1 thread, 4.55 ms on 20 threads (fault-around maps 16 pages) |
| minor fault on anonymous memory | ~1 to 2 µs per page | |
| formatting output | ~1 GB/s per core, parallel | |
| writing output: pipe or `/dev/null` | ≥5 GB/s | |
| writing output: page-cache file here | 0.7 to 1.7 GB/s | dumpfiles 528 MiB in 741 ms; memmap 2.2 GB in 1.3 to 1.9 s |

`MADV_HUGEPAGE` on the image mapping does not reduce faults: btrfs gives no PMD-mappable folios
here. `pread` of 64 KiB blocks is 3.5x worse than faulting (8.9 µs per page).

## Top plugins: current, floor, gap, bound-by

The columns are:

* **now**: `main` (release), min wall. Steady unless marked warm. Quiet-period survey where
  available, otherwise the min across runs.
* **proto**: the prototype, measured in the same interleaved runs as `now`.
* **floor**: from the model above.
* **gap**: now / floor.

**Windows, `memory-dirty.raw` (Windows 11 22000, 5 GiB)**

| plugin | now ms | proto ms | floor ms | gap | bound by |
|---|---:|---:|---:|---:|---|
| timeliner.Timeliner (warm, stdout `/dev/null`) | 455 | same | ~100 | 4.5x | Critical path is the Linux banner scan of the Windows image, 277 ms (646 steady). Serial merge 100 to 113 ms; sort 11 ms; parallel render 53 to 60 ms. To a file: 666 to 2000 ms, write-bound (414 MB). |
| windows.dumpfiles.DumpFiles | 767 | same | ~740 | 1.0x | Buffered writes of 528 MiB (741 ms `create + write`). Everything else is ~25 ms. |
| windows.memmap.Memmap (all processes) | 290 (`/dev/null`); 1300 to 1900 (file) | same | ~100; ~1300 | 2.9x; 1.0x | 42.5M rows, 2.2 GB of output. Formatting on the workers; file writes. |
| windows.mftscan.MFTScan (warm) | 184 to 216 | same | ~50 (+ write) | ~4x | Replay of 480k matches through the MFT parser: 667 ms user + 297 ms system over 184 ms, so 26% parallel efficiency. Datetime formatting 12%. 280 MB of output. |
| windows.handles.Handles | 21.7 to 22.0 | **10.6** | ~3.3 | 6.6x → 3.2x | Per-object instructions (13k to 11k per handle). Serial emit 5.3 ms. Space::get mutex contention (23% of cycles). Largest process on the critical path (System, explorer: 5.3 ms). 10.5k faults. |
| windows.svcdiff.SvcDiff | 12.8 to 15.8 | **7.9** | ~2.5 | 5x → 3x | Single-threaded services.exe walk. UTF-16 decode of 512-byte buffers (24%). glibc memmem in the VAD scan (30%). |
| windows.verinfo.VerInfo | 9.6 to 15.0 | **8.5** | ~3 | 3 to 5x | 9.3k faults (PE pages). Resource parsing and malloc. Member lookups (9%). |
| windows.etwpatch.EtwPatch | 13.1 | ~12 | ~3 | 4.4x | pe_symbols: an RSDS scan of every instance of each module (`find_rsds` 34%). 83 threads spawned. |
| windows.statistics.Statistics | 12.5 | same | ~2 | 6x | One thread translating every page of the kernel address space. |
| windows.iat.IAT | 6.0 to 11.0 | **3.6** | ~2.5 | 2.4 to 4x | Serial emit of 1.5 MB. Import parsing and malloc. |
| windows.svcscan.SvcScan | 9.6 to 10.7 | **6.1** | ~2 | 5x → 3x | As svcdiff. |
| windows.suspended_threads.SuspendedThreads | 10.7 | ~9.5 | ~3 | 3.6x | 165 pdbname (RSDS) scans over module instances (find_rsds 36%). 100 threads spawned. list_process_threads 1.5 ms. |
| windows.vadinfo.VadInfo | 8.1 to 10.2 | **5.7** | ~2.5 | 3.5x → 2.3x | Member-by-name lookups (22% + 8% `m()` + 7% memcmp). Serial emit 3 ms. |
| windows.ldrmodules.LdrModules | 8.7 to 10.1 | −6 to −21% | ~3 | 3x | 11k faults (system time 30 of 70 ms CPU). Member lookups (11%). |
| windows.vadwalk.VadWalk | 8.4 to 8.6 | **6.0** | ~2.3 | 3.7x | Member lookups (30%). Serial emit. |
| windows.unhooked_system_calls | 8.1 to 9.4 | same | ~3 | 3x | find_rsds 39%. 67 threads spawned. |
| windows.debugregisters.DebugRegisters | 6.4 to 8.8 | same | ~2.5 | 3x | Trap frames of all threads. 82 threads spawned. VAD walk of all processes. |
| windows.cmdscan.CmdScan | 7.2 to 7.7 | same | ~2 | 3.6x | glibc memmem 63% (about 3 GB/s against 7 GB/s for AVX2 and 15 to 19 GB/s for the existing Teddy search). |
| windows.dlllist.DllList | 5.7 | −7 to −12% | ~2 | 2.9x | 5.5k faults. Member lookups. |
| windows.consoles.Consoles | 5.1 | same | ~2 | 2.5x | `decode_row` + `trim_end_matches(py_isspace)` 44%. |

**Linux: noble 6.8 ELF (jammy 5.15 similar)**

| plugin | now ms | proto ms | floor ms | gap | bound by |
|---|---:|---:|---:|---:|---|
| linux.kallsyms.Kallsyms | 41 to 53 | same | ~7 | 6 to 7x | Rows are built and rendered one at a time on the main thread (21 MB; the render alone is ~10 ms). malloc/free 25%. Token expansion (`expand_with`) 26% runs in parallel. |
| linux.pagecache.Files | 28 to 44 | −6 to −10% | ~6 | 5x | get_inodes walk 23 ms, serial replay 7.8 ms, serial render 8.7 ms (5 MB). |
| linux.kthreads.Kthreads | 12 to 16 | same | ~2 | 6x | Builds the symbol address index on every run (8.4 ms). `scan_self_referential` 28%. |
| linux.mountinfo / lsof / proc.Maps / pscallstack / elfs / library_list / malfind | 4 to 9 | −2 to −10% (instructions −15 to −31%) | ~2 | 2 to 4x | `SegmentedLayer::read` per scalar read (fixed by the prototype TLB). Member lookups. Linear `symbols_at_exact_many` in lsof and check_syscall (36%). |
| linux.psscan / sockscan (warm) | 10.2 / 8.8 | same | ~3 | 3x | Post-scan validation. Steady (126 to 137 ms) is scan-bound. |

**mac 10.9.2**

| plugin | now ms | proto ms | floor ms | gap | bound by |
|---|---:|---:|---:|---:|---|
| timeliner.Timeliner (warm) | 484 (2348 with the image partly evicted) | same | ~25 | ~20x | Failing Linux discovery runs two full-image scans (326 + 274 ms); failing Windows discovery. The output is 444 bytes. |
| mac.malfind.Malfind | 57 | same | ~6 | 9x | 9.6 MB emitted serially (`out.row` loop). Page faults (≥10%). Disassembly formatting. |
| mac.list_files.List_Files | 44 | same | ~6 | 7x | Serial walk 18 ms, names 6 ms, path build 11 ms, render 3.8 ms. |

**Windows, 1809 image (2 GiB), prototype**

| plugin | before ms | after ms | change |
|---|---:|---:|---:|
| handles | 15.0 | 7.6 | −49% |
| svcdiff | 12.7 | 7.9 | −38% |
| svcscan | 9.6 | 6.4 | −33% |
| vadinfo | 7.1 | 5.1 | −28% |
| iat | 3.2 | 2.5 | −21% |
| verinfo | 8.1 | 7.2 | −11% |

## Where the time goes (cross-cutting)

1. **Member and type lookups by name at runtime.**
   * Share of CPU in object-walking plugins: `SymbolTable::member` + `Obj::m` + memcmp + `lookup`
     take 20 to 45% (vadwalk 30% + 6% + 7.5%; vadinfo 22% + 8% + 7%; threads 17% + 7%;
     debugregisters 16% + 5.5%).
   * `Field` exists but only a few hot paths use it. `VadExt`, `WinExt`, `name_info` and
     `get_object_type` all use `m("literal")`, `cast("literal")` and
     `Obj::named(sp, "unsigned char", ..)` per object.
   * `name_info` also calls `get_symbol("ObpInfoMaskToOffset")` per handle.
2. **Lock contention in the object model.**
   * `Space::get` takes a global `Mutex<FxHashMap>`. `PoolExt::name_info` called it three times
     per handle, so handles spent **23% of cycles** in `Space::get` + `lock_contended` on 20
     threads.
   * `IntelLayer::address_mask()` fell back to the trait default: an f64 `log2` per call, 3 to 5%
     of handles.
3. **Serial row emission.**
   * Most per-process plugins run `par_map` and then build, render and free every `Vec<Value>` on
     the main thread: handles 5.3 ms serial, vadinfo 3.0 ms, kallsyms ~10 ms, pagecache.Files
     8.7 ms.
   * All rows of all processes stay alive until then. That is 15 to 25 MB of fresh heap spread over
     20 per-thread arenas. For handles, **6.5k of 10.5k faults** were `sysmalloc` or `_int_malloc`
     heap growth.
   * The `RowEncoder` / `rows_encoded` path that already exists is used by only timeliner, memmap
     and mftscan.
4. **Page faults.**
   * Baseline system time is 25 to 50% of CPU: ldrmodules 30 of 70 ms, handles 16 to 34 ms,
     verinfo 23 to 26 ms, dlllist 13 to 18 ms.
   * Image faults are a floor term, 2.5 µs per 64 KiB block touched. Heap faults are avoidable: see
     item 3, buffer pools, and the glibc `hugetlb` or `top_pad` tunables.
   * With `GLIBC_TUNABLES=glibc.malloc.hugetlb=1`, system time dropped for vadinfo (19 to 5 ms),
     iat (9.4 to 5.2 ms) and handles (37 to 24 ms). This result is noisy.
5. **Parallel structure.**
   * One process = one task, so the biggest handle table sets the critical path: 5.3 ms for System
     and explorer against 70 ms total over 127 processes.
   * `par_map` and `par_map_stream` spawn scoped threads on every call. A plugin spawns 20 to 100
     threads per run: suspended_threads 100, etwpatch 83, debugregisters 82. A 20-thread
     spawn+join costs 150 to 430 µs on this box.
   * Every section also starts with cold thread-local TLBs and caches.
   * statistics runs on one thread.
   * mftscan's warm replay keeps only 5.2 of 20 cores busy.
6. **Repeated work across runs, and within runs across instances.**
   * The symbol address index is rebuilt on every run (kthreads 8.4 ms), or up to 8 linear scans
     of 0.5 ms each are done instead (lsof, check_syscall).
   * pe_symbols scans every instance of a module for RSDS even when instances share physical pages
     (`find_rsds` 34 to 39% of etwpatch, unhooked_system_calls and suspended_threads).
   * timeliner re-runs the failing kernel discoveries of the other two OSes on every run: full-image
     scans with no negative cache.
7. **Reads on segmented images (ELF, LiME, crash dumps).** Every scalar read went through `dyn`
   `SegmentedLayer::read`, a run lookup and a copy: 7 to 12% of mountinfo, pagecache.Files and
   lsof. The TLB held only the physical page.
8. **String decoding.** `cast("string", max_length=512, encoding="utf-16")` decoded all 256 units
   and then cut at the NUL (svcscan: 23% of CPU in `decode_utf16`).

## Prototype (validated)

Clone branch `perf-review`, commit `41783e6`: 20 files, +304/−145.

* **Object model.**
  * Per-thread, direct-mapped caches for `SymbolTable::member()` (512 slots) and `get_type()`
    (128 slots). They are keyed by (table id, type, name pointer, length), and a hit re-compares
    the name bytes, so a reused pointer can never return another member.
  * A thread-local 16-entry front cache for `Space::get`.
  * `name_info` uses `self.sp` and `native_space()` instead of `Space::get`.
  * A cached `address_mask` in `IntelLayer`.
  * Thread-local TLB entries also store the **host address** of the page. `read`, `read_padded`
    and `slice` on ELF, LiME and crash-dump images then copy straight from the mapping, as on raw
    images.
* **Rows.** `plugins::emit_par_rows(out, procs, f)`: workers run `f` and format the rows with the
  sink's `RowEncoder`, then drop the `Vec<Value>`s locally. The main thread only appends bytes.
  Without an encoder (`--filters`) it falls back to `out.row`. Applied to 11 plugins: handles,
  vadinfo (not with `--dump`), vadwalk, iat, privileges, envars, getsids, verinfo, and malware
  ldrmodules, hollowprocesses, processghosting and suspicious_threads.
* **Strings.**
  * `decode_cstring` cuts UTF-16 input at the first NUL unit *before* decoding when the error
    handler is not strict. Nothing after the first NUL unit can change the text before it: an
    error adjacent to the NUL covers the same bytes whether the data ends there or not. Strict
    decoding still sees every byte.
  * ASCII fast path in `decode_utf16`.
* **Validation.**
  * `check_all.sh` on the main image: 97/97 OK.
  * `check_images.sh` on all 30 other manifest images: 1873 OK. The 4 DIFFs are all `isfinfo`
    against stale stored references (run with `NO_LIVE_ISFINFO=1`), and the prototype's output is
    identical to `main`'s.
  * 91 renderer and filter A/B cases: `csv`, `json`, `jsonl`, `pretty`, `none` and `--filters`
    on the 13 changed plugins. All identical.
  * The python argument cases handles_pid, vadinfo_pid, vadinfo_dump, envars_pid and
    envars_silent all pass.
  * `cargo test`: 535 passed.

**Wall-time results, main image** (interleaved A/B, min of 9 to 11; baseline and prototype built
with identical flags):

| plugin | before (quiet) | after (quiet) | Δ quiet | Δ loaded (load 14) |
|---|---:|---:|---:|---:|
| handles | 22.0 | 10.6 | **−52%** | −54% |
| vadinfo | 8.1 | 5.7 | −29% | −41% |
| vadwalk | 8.4 | 6.0 | −29% | −29% |
| iat | 6.0 | 3.6 | **−40%** | −32% |
| svcscan | 9.6 | 6.1 | −37% | −35% |
| svcdiff | 12.8 | 7.9 | **−39%** | −41% |
| svclist | 6.0 | 4.6 | −24% | −22% |
| verinfo | 9.6 | 8.5 | −12% | −27% |
| envars | 2.3 | 1.9 | −16% | −11% |
| privileges | 4.0 | 3.2 | −22% | −13% |
| dlllist | 4.7 | 4.2 | −12% | −7% |
| suspended_threads | 14.0 | 13.2 | −6% | −12% |
| ldrmodules | 10.1 | 9.5 | −6% | −21% |

Handles' `plugin.run` went from 19 ms (12.5 parallel + 5.3 emit) to 9.3 ms. Its task-clock went
from 187 to 80 ms.

**Instructions, one thread, min of 5 runs:**

| image | plugin | change |
|---|---|---:|
| Windows | svclist | −55% |
| Windows | svcdiff | −53% |
| Windows | svcscan | −49% |
| Windows | threads | −27% |
| Windows | debugregisters | −27% |
| Windows | envars | −31% |
| Windows | vadinfo | −24% |
| Windows | dlllist | −24% |
| Windows | ldrmodules | −22% |
| Windows | vadwalk | −21% |
| Windows | malfind | −19% |
| Windows | unhooked_system_calls | −17% |
| Windows | suspended_threads | −17% |
| Windows | etwpatch | −16% |
| Windows | handles | −15% |
| Windows | verinfo | −12% |
| Linux | pscallstack | −31% |
| Linux | elfs | −28% |
| Linux | proc.Maps | −28% |
| Linux | malfind | −26% |
| Linux | mountinfo | −23% |
| Linux | library_list | −19% |
| Linux | sockstat | −17% |
| Linux | pagecache.Files | −17% |
| Linux | lsof | −17% |
| Linux | pslist | −18% |
| mac | all measured | −1 to −7% |
| any | kallsyms, check_syscall, statistics, cmdscan | ~0% (bound elsewhere) |

After the prototype, handles is still at 11k instructions per handle. The shares are:

* handle-table walk: 29% (every entry field read separately);
* the generic scalar read: `Obj::int` 12.6% + `IntelLayer::read_impl` 8.4% + memmove 6.9%;
* `get_full_key_name`: 18% for 3.4k Key handles (about 24k instructions each);
* `name_info`: 17%;
* `format!`: 7%;
* TLB refills: 7.6%.

That remainder is the next tier of work.

## Ranked opportunities

| # | opportunity | gain | effort | risk | validated |
|---|---|---|---|---|---|
| 1 | **Rows formatted on the workers everywhere** (`emit_par_rows` and streaming equivalents). Remaining serial emitters: kallsyms, pagecache.Files, mac malfind and list_files, dlllist, threads, non-malware ldrmodules, linux psaux, pidhashtable, capabilities and psscan, pebmasquerade. | handles −52%, iat −40%, vadinfo and vadwalk −29%, privileges −22% (measured). Estimated: kallsyms −10 to −20 ms, pagecache.Files −8 ms, mac malfind −20 to −40 ms. | low: helper exists, ~10 lines per plugin | low: the encoder is already the timeliner, memmap and mftscan path; 91 renderer and filter cases identical | yes (11 plugins) |
| 2 | **Object-model inline caches + zero-copy TLB** (member/type caches, `Space::get` front cache, `name_info` fix, cached mask, host pointer in TLB) | −10 to −31% instructions on 30+ plugins. −5 to −15% wall alone on mid-size plugins; −40% or more where it removed contention (handles). | low | low: hits are verified by bytes; ids never reused | yes |
| 3 | **Decode C strings only up to the first NUL** (non-strict) + ASCII fast path | svcscan −37%, svcdiff −39%, svclist −24%, envars −16%. Every UTF-16 `max_length` cast. | trivial | low | yes |
| 4 | **Negative automagic cache.** Remember "no Linux/mac/Windows kernel in this image" per image and symbol-path identity. Timeliner reruns failing discoveries of the other OSes on every run. | Windows timeliner warm 455 → ~290 ms (critical path becomes mftscan, 108 ms), steady 822 → ~730 ms. mac timeliner 484 to 2348 → ~25 ms. Linux timeliner 356 → ≤240 ms. It drops the 339 to 833 ms mac discovery, and mftscan (234 ms) becomes the critical path. pagecache.Files takes 57 to 65 ms inside timeliner when it is not competing with that scan. | medium (automagic owner) | medium: the key must cover everything discovery reads (image, `-s` dirs, identifier index, python cache state) | measured, not built |
| 5 | **Persistent worker pool** in `util::par`. Spawn once and wake per section, which keeps thread-local TLBs and caches warm. Make `par_map_stream` panic-safe at the same time. | −0.3 to −2 ms per plugin with 3 to 5 parallel sections (20 to 100 spawns now). −5 to −15% on 5 to 15 ms plugins. | medium | low-medium | spawn cost measured |
| 6 | **Persist the symbol address index** in the ISF blob or a sidecar cache | kthreads −8.4 of 12 to 16 ms. Removes the linear `symbols_at` scans (lsof, check_syscall 36%). | medium: blob version bump | low | measured |
| 7 | **handles next tier.** Split tables over 512-entry leaves across workers; decode entries from one 4 KiB slice; hoist `ObpInfoMaskToOffset`, `_OBJECT_HEADER_NAME_INFO`, cookie and type lookups out of the per-handle path; replace `format!` with pushes; `get_full_key_name` without per-level Strings. | 10.6 → ~5 ms (2x instructions, critical path 5.3 → ~2 ms) | medium | low-medium | profiled |
| 8 | **pe_symbols RSDS scans.** A per-physical-page "no RSDS here" memo across module instances, plus the existing AVX2 Teddy search instead of `find_rsds` SSE2 / glibc memmem. | −20 to −35% CPU in etwpatch, unhooked_system_calls, suspended_threads and skeleton_key; −1 to −3 ms wall | medium | low-medium: straddling matches need care | profiled |
| 9 | **statistics in parallel.** Precompute fault runs per top-level page-table entry on all cores, then run python's sequential stepping over them. | 12.5 → ~2 to 3 ms | medium | medium: python's stepping quirks | profiled |
| 10 | **mftscan finish.** Find the serial section (26% parallel efficiency); memoize formatted datetimes (12%). | 184 → ~90 ms warm; also timeliner | medium | low | profiled |
| 11 | **Allocator hygiene.** Pooled per-worker buffers; `mallopt(M_TOP_PAD)` at startup, or re-exec with `glibc.malloc.hugetlb=1` / THP-aligned arenas. | −5 to −15 ms CPU in fault-heavy plugins; small wall gain | low | low | tunable tested (noisy) |
| 12 | **AVX2 / Teddy single-pattern find** in `scan::BytesScanner` and `scan::find` (replace glibc memmem) | cmdscan −30 to −50% CPU; svc* scan part | low | low | microbench only (2.4x) |
| 13 | **Write path** (dumpfiles, file outputs). At the FS floor. Only reflink or `copy_file_range` of page runs on the same filesystem could beat it. | uncertain: 135k 4 KiB runs make clone ioctls likely slower | high | medium | no (not recommended) |

## Plan

1. **Land the prototype** (items 1 to 3). It is ready and gate-clean; drop the trace spans if
   unwanted. Then extend `emit_par_rows` / encoder emission to the remaining serial emitters:
   kallsyms needs a worker-side encode inside `for_each_core_symbol`; pagecache.Files already has
   `par_rows`; mac malfind and list_files, dlllist and threads follow the same per-process
   pattern. Gate: `check_all.sh`, `check_images.sh`, and the renderer/filter A/B from this review.
2. **Infrastructure** (items 5, 6, 11). Build the pool as a drop-in for `par_map` and
   `par_map_stream` that keeps results in order. `catch_unwind` in workers fixes the side finding
   below. Persist the address index. Add allocator settings in `main`.
3. **Cross-component** (item 4) with the automagic owner: a negative discovery cache. It is the
   single largest absolute win (0.17 to 2 s per timeliner run).
4. **Targeted rewrites** (items 7 to 10, 12), guided by the profiles in this review. Re-measure
   each on a quiet machine, or with the instruction-count harness when the box is busy.

## Side findings

* **`par_map_stream` deadlocks if a worker panics.** Slot `i` is never filled and the consumer
  waits on `ready` forever. Reproduction: run
  `RSVOL_TRACE=1 vol ... windows.suspended_threads.SuspendedThreads 2>&1 >/dev/null | head -40`.
  Once `head` exits, a worker's `eprintln!` panics on EPIPE and the process hangs with every thread
  in `futex_wait`. Any panic in a worker would do the same, turning a crash into a hang. Fix: catch
  the unwind in the worker and fill the slot with an error.
* `perf_event_paranoid=2` and a 1 kHz sample cap make profiling short runs slow. Aggregate 15 to 30
  runs per profile (`prof.sh`), or count instructions (`abinst.sh`).
* rsvol's own exit is cheap (`exit_group` to reaped in 0.15 to 0.4 ms). The 13 to 17 ms `munmap`
  cost of 160k fault-around PTEs seen in `micro/faults.c` does not occur here, because rsvol's
  touched set is clustered.
