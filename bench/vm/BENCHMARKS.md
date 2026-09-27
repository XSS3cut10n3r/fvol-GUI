# fastvol vs vol-rs vs python volatility3 — quiet-VM benchmark (pass 3)

2026-09-26 (pass 3: 23:19-23:23 VM time) · dedicated KVM guest: AMD EPYC 7302P (Zen 2) host, 32 vCPU, 30 GiB RAM, Ubuntu 25.04, kernel 6.14.0-37-generic; nothing else running (see [machine.txt](machine.txt), [method.md](method.md#run-3)). Earlier reports: [pass 2](BENCHMARKS-run2.md) (rsvol `95528b2`), [run 1](BENCHMARKS-run1.md).

- **fastvol** `b400e76` (binary `fvol`; the project was called rsvol until this commit), built on the dev box with rustc 1.100.0-nightly (1303417c4 2026-09-21), LLD 23.1.1 and `RUSTFLAGS="-C target-cpu=znver2 -C target-feature=+crt-static"` plus the linker flags of [docs/building.md](../../docs/building.md#build-for-other-machines), fat LTO, then copied to the VM; sha256 `fafe9aa0e981170e…`. Pass 2 was built on the VM with `target-cpu=native`: the same Zen 2 instruction set.
- **vol-rs** 1.0.0: the competitor's own release binary (`4c1076f` + uncommitted working tree of 2026-09-25, sha256 ac1e4ed6…, generic x86-64). Its times and output hashes are pass 2's (same VM, same binary); it was not run again.
- **python** volatility3 2.28.2 on CPython 3.14.7 (PGO+LTO+BOLT build) with capstone, yara-python, pycryptodome: the reference whose output fastvol reproduces. Its times and output hashes are run 1's, or pass 2's where pass 2 ran python again (marked †); it was not run again for the plugin rounds.
- Windows image: `memory-dirty.raw`, 5 GiB raw Windows 11 21H2 x64 (build 22000, `windows.info`: 15.22000); Linux image: `rsvol-noble-6.8.0-139.elf`, 3 GiB, Ubuntu 24.04 kernel 6.8 (`-s` holding only its `.json.xz` ISF). Both page-cached.
- Plugins: fastvol implements all 197 plugins of volatility3 2.28.2. The same lists as pass 2: Windows 77 plugins (generic + Windows, `statistics` and `timeliner` last); Linux 59 = every `linux.*` plugin that runs without arguments (57 of 60; not `vmayarascan`, `vmaregexscan`, `module_extract`) + `banners` + `timeliner`.

Every number is the wall-clock time of a whole process (`TOOL -q -o DIR -f IMG PLUGIN`, stdout to a file), best of 5 interleaved runs for each fastvol column (pass 3) and each vol-rs column (pass 2), best of 2 runs for python on Windows (1 for statistics, timeliner and on Linux). The columns:

| column | cache state before every timed run |
|---|---|
| **fastvol cold** | fastvol's whole cache directory (`FASTVOL_CACHE`) deleted: binary symbol tables, identifier index, automagic results, scan results — the first-ever run of fastvol on this image |
| **fastvol steady** | symbol-table / identifier / automagic caches warm, the per-image scan cache disabled (`FASTVOL_NO_SCAN_CACHE=1`): the honest cost of a plugin's own work, every scan really done |
| **fastvol warm** | every cache warm, incl. the scan cache: what a user sees on the 2nd+ run of a plugin |
| **vol-rs cold** | `$XDG_CACHE_HOME/vol-rs` deleted (its parsed symbol files, per-image automagic results and banner index), except the PDB it downloaded from the Microsoft symbol server (so no timed run touches the network) |
| **vol-rs warm** | vol-rs's cache as its previous run left it (vol-rs has no scan-result cache) |
| **python** | run 1's warm runs (identifier cache warm), pass 2's for the plugins marked † |

fastvol steady and fastvol warm are compared with vol-rs warm, fastvol cold with vol-rs cold (like for like); "fastest on" for a fastvol column counts the plugins where it beats python and **both** vol-rs columns. The fastest number of each row is bold in the per-plugin tables.

## Headline

| Windows (77 plugins) | python | vol-rs cold | vol-rs warm | fastvol cold | fastvol steady | fastvol warm |
|---|---:|---:|---:|---:|---:|---:|
| total wall (sum of per-plugin best) | 4078.23 s | 183.76 s | 148.61 s | 4.07 s | 2.94 s | 1.40 s |
| total CPU (user+sys) | 4076.88 s | 976.28 s | 939.22 s | 53.51 s | 46.33 s | 7.58 s |
| median plugin wall | 4.49 s | 624 ms | 164 ms | 22.8 ms | 6.6 ms | 5.2 ms |
| geometric mean plugin wall | 5.36 s | 800 ms | 283 ms | 29.3 ms | 10.9 ms | 5.7 ms |
| fastest on¹ | 0/77 | 0/77 | 0/77 | **75/77** | **76/77** | **77/77** |
| faster than the like-for-like vol-rs column on |  |  |  | 75/77 vs vol-rs cold | 76/77 vs vol-rs warm | 77/77 vs vol-rs warm |
| speedup vs like-for-like vol-rs: total / geo-mean |  |  |  | 45.1x / 27.3x | 50.5x / 25.9x | 106x / 49.6x |
| speedup vs python: total / geo-mean |  |  |  | 1,002x / 183x | 1,386x / 491x | 2,905x / 941x |

| Linux (59 plugins) | python | vol-rs cold | vol-rs warm | fastvol cold | fastvol steady | fastvol warm |
|---|---:|---:|---:|---:|---:|---:|
| total wall (sum of per-plugin best) | 2804.03 s | 217.20 s | 105.23 s | 8.32 s | 3.30 s | 2.79 s |
| total CPU (user+sys) | 2802.62 s | 682.84 s | 144.10 s | 72.23 s | 41.22 s | 24.45 s |
| median plugin wall | 18.28 s | 2.23 s | 311 ms | 92.3 ms | 6.0 ms | 5.3 ms |
| geometric mean plugin wall | 20.00 s | 2.34 s | 288 ms | 104 ms | 7.5 ms | 5.8 ms |
| fastest on¹ | 0/59 | 0/59 | 0/59 | **59/59** | **59/59** | **59/59** |
| faster than the like-for-like vol-rs column on |  |  |  | 59/59 vs vol-rs cold | 59/59 vs vol-rs warm | 59/59 vs vol-rs warm |
| speedup vs like-for-like vol-rs: total / geo-mean |  |  |  | 26.1x / 22.5x | 31.9x / 38.2x | 37.7x / 50.0x |
| speedup vs python: total / geo-mean |  |  |  | 337x / 192x | 849x / 2,650x | 1,006x / 3,468x |

¹ for a fastvol column: the plugins where it beats python and both vol-rs columns; for vol-rs and python: the plugins where that column beats all three fastvol columns and the remaining tool.

Where a fastvol column is not the fastest number of its row:

- `vmscan.Vmscan` (fastvol cold and steady): vol-rs ships no VMCS ISFs, so it prints the empty table in
  4.1 ms without reading the image; python and fastvol scan the whole 5 GiB image for VMCS page starts
  (fastvol steady 39.0 ms, 311 ms in pass 2). fastvol warm replays its cached hits in 1.6 ms and is now
  the fastest. Same output in all three tools.
- `isfinfo.IsfInfo` (fastvol cold only): 30.3 ms vs vol-rs warm 3.7 ms. Not a fastvol change: during
  the Windows round python's identifier cache had no row for a kernel ISF that had appeared in python's
  symbols directory since pass 2, so every cold run indexed that ISF itself (see Changes since pass 2).
  Measured by hand after python had updated its cache, a cold isfinfo takes 4 ms, with fvol `b400e76`
  and with pass 2's rsvol `95528b2` alike. vol-rs prints 3 lines here, python and fastvol 14.
- Linux: none. fastvol cold is the fastest on all 59 plugins, ahead of vol-rs *warm* too (closest:
  `linux.ip.Link`, 94.5 ms vs 125 ms).

## Changes since pass 2 (rsvol `95528b2` → fvol `b400e76`)

What changed (`git log --first-parent 95528b2..b400e76`): warm paths for vmscan and vmcoreinfo (compiled-in VMCS layouts, the vmcoreinfo scan answered by the scan cache), a faster xz decoder, lazy symbol tables for first runs (see [pass 2's rerun](BENCHMARKS-run2.md#first-runs-with-lazy-symbol-tables-rsvol-cold-rerun)), then the hardware-floor optimization pass: per-run startup cost (hot-text ordering, RELR, exit-teardown helper), one persistent thread pool, scanning and memory access (a random-access image mapping, pipelined scans, a zero-copy scan cache), the object model and per-plugin row work, the libraries (inflate, xz images, YARA, SHA-NI), output and file writes, and cold start (parallel PDB download, identifier index built during the kernel search); see `bench/handoff/*.md`, and `bench/reviews/FOLLOWUPS.md` for what is left.

Same VM, images, plugin lists and procedure (the build differs, see above). A per-plugin time counts as a regression when it is more than 1.10x **and** more than 1 ms above pass 2's: between run 1 and pass 2, vol-rs's warm times (same binary) stayed within 0.94-1.05x for 80% of the plugins (10th-90th percentile, see Checks); the 1 ms floor keeps the smallest plugins' timer-level jitter out.

| Windows, pass 2 → pass 3 (77 plugins) | fastvol cold | fastvol steady | fastvol warm |
|---|---:|---:|---:|
| total wall | 8.82 s → 4.07 s (2.17x) | 4.43 s → 2.94 s (1.51x) | 2.18 s → 1.40 s (1.55x) |
| median plugin wall | 68.6 ms → 22.8 ms (3.01x) | 10.2 ms → 6.6 ms (1.55x) | 8.6 ms → 5.2 ms (1.65x) |
| geometric mean plugin wall | 77.4 ms → 29.3 ms (2.64x) | 17.6 ms → 10.9 ms (1.61x) | 9.6 ms → 5.7 ms (1.69x) |
| plugins faster / not faster than in pass 2 | 76 / 1 | 77 / 0 | 76 / 1 |

- biggest wins, fastvol cold: `vmscan.Vmscan` 286 ms → 41.0 ms (6.97x), `windows.handles.Handles` 118 ms → 26.5 ms (4.45x), `windows.virtmap.VirtMap` 62.8 ms → 16.9 ms (3.72x), `windows.dlllist.DllList` 85.5 ms → 23.1 ms (3.70x)
- biggest wins, fastvol steady: `vmscan.Vmscan` 311 ms → 39.0 ms (7.97x), `windows.handles.Handles` 61.5 ms → 13.5 ms (4.56x), `windows.verinfo.VerInfo` 48.6 ms → 15.9 ms (3.06x), `windows.dlllist.DllList` 26.8 ms → 9.0 ms (2.98x)
- biggest wins, fastvol warm: `vmscan.Vmscan` 15.0 ms → 1.6 ms (9.38x), `windows.handles.Handles` 66.6 ms → 13.2 ms (5.05x), `windows.verinfo.VerInfo` 49.5 ms → 15.6 ms (3.17x), `windows.dlllist.DllList` 26.8 ms → 9.1 ms (2.95x)
- **regression beyond noise**, fastvol cold `isfinfo.IsfInfo`: 3.1 ms → 30.3 ms (9.8x slower): environment, not fastvol: a new ntkrnlmp ISF (`8E3373D6…-1.json.xz`, written 19:02) appeared in the VM's python install symbols dir between the passes, and python's `identifier.cache` had no row for it during the Windows round, so every cold run indexed that ISF itself (~62 ms CPU, ~30 ms wall; the warm columns reuse fastvol's own index: 2.6 ms). After python's pass-3 startup runs updated its identifier cache, isfinfo cold took 4 ms for both fvol `b400e76` and rsvol `95528b2` (by hand on the VM)

| Linux, pass 2 → pass 3 (59 plugins) | fastvol cold | fastvol steady | fastvol warm |
|---|---:|---:|---:|
| total wall | 35.38 s → 8.32 s (4.25x) | 4.80 s → 3.30 s (1.45x) | 4.42 s → 2.79 s (1.58x) |
| median plugin wall | 541 ms → 92.3 ms (5.86x) | 10.1 ms → 6.0 ms (1.68x) | 9.8 ms → 5.3 ms (1.85x) |
| geometric mean plugin wall | 553 ms → 104 ms (5.32x) | 11.8 ms → 7.5 ms (1.57x) | 10.0 ms → 5.8 ms (1.73x) |
| plugins faster / not faster than in pass 2 | 59 / 0 | 58 / 1 | 59 / 0 |

- biggest wins, fastvol cold: `linux.hidden_modules.Hidden_modules` 557 ms → 86.6 ms (6.43x), `linux.psaux.PsAux` 548 ms → 85.8 ms (6.38x), `linux.modxview.Modxview` 540 ms → 84.7 ms (6.38x), `linux.malware.check_modules.Check_modules` 534 ms → 85.5 ms (6.25x)
- biggest wins, fastvol steady: `linux.kthreads.Kthreads` 34.0 ms → 9.9 ms (3.43x), `linux.elfs.Elfs` 18.3 ms → 7.2 ms (2.54x), `linux.pagecache.Files` 79.6 ms → 32.7 ms (2.43x), `linux.library_list.LibraryList` 19.2 ms → 8.0 ms (2.40x)
- biggest wins, fastvol warm: `linux.vmcoreinfo.VMCoreInfo` 121 ms → 2.0 ms (60.4x), `linux.kthreads.Kthreads` 33.0 ms → 9.7 ms (3.40x), `linux.kallsyms.Kallsyms` 99.9 ms → 36.6 ms (2.73x), `linux.psscan.PsScan` 35.1 ms → 14.7 ms (2.39x)
- no regression beyond noise
- slower within noise: 1 of 177 plugin-columns, the largest fastvol steady `linux.check_syscall.Check_syscall` 9.1 ms → 9.8 ms

## Windows summary

- **fastvol cold** vs vol-rs cold: median 31.0x, geo-mean 27.3x, min 0.10x, max 2,725x; vs python: median 206x, geo-mean 183x, min 12.4x, max 64,136x
- **fastvol steady** vs vol-rs warm: median 33.9x, geo-mean 25.9x, min 0.11x, max 5,517x; vs python: median 411x, geo-mean 491x, min 48.2x, max 132,816x
- **fastvol warm** vs vol-rs warm: median 36.8x, geo-mean 49.6x, min 1.48x, max 5,348x; vs python: median 796x, geo-mean 941x, min 150x, max 128,761x
- fastvol cold is not the fastest on 2: `isfinfo.IsfInfo` (30.3 ms vs vol-rs warm 3.7 ms), `vmscan.Vmscan` (41.0 ms vs vol-rs warm 4.1 ms)
- fastvol steady is not the fastest on 1: `vmscan.Vmscan` (39.0 ms vs vol-rs warm 4.1 ms)
- fastvol warm is the fastest on every plugin
- fastvol stdout byte-identical to python's recorded output (after the banner line) in every run of all three columns: **72/77** (the others: `frameworkinfo.FrameworkInfo` sorted =, `isfinfo.IsfInfo` = py rerun, `windows.info.Info` = py rerun, `windows.windows.Windows` sorted =, `timeliner.Timeliner` = ref machine, see Checks); vol-rs (both columns, pass 2): 59/77
- the three fastvol columns printed the same stdout in all their runs on 77/77 plugins (the caches never change output)

| Windows without statistics / timeliner (75 plugins) | python | vol-rs cold | vol-rs warm | fastvol cold | fastvol steady | fastvol warm |
|---|---:|---:|---:|---:|---:|---:|
| total wall (sum of per-plugin best) | 922.77 s | 92.77 s | 59.90 s | 2.94 s | 1.88 s | 664 ms |
| total CPU (user+sys) | 922.18 s | 716.26 s | 684.39 s | 38.72 s | 33.37 s | 3.13 s |
| median plugin wall | 4.28 s | 616 ms | 139 ms | 22.0 ms | 6.2 ms | 5.2 ms |
| geometric mean plugin wall | 4.61 s | 722 ms | 248 ms | 27.9 ms | 10.3 ms | 5.3 ms |
| fastest on¹ | 0/75 | 0/75 | 0/75 | **73/75** | **74/75** | **75/75** |
| faster than the like-for-like vol-rs column on |  |  |  | 73/75 vs vol-rs cold | 74/75 vs vol-rs warm | 75/75 vs vol-rs warm |
| speedup vs like-for-like vol-rs: total / geo-mean |  |  |  | 31.5x / 25.9x | 31.9x / 24.2x | 90.2x / 47.0x |
| speedup vs python: total / geo-mean |  |  |  | 314x / 165x | 492x / 449x | 1,390x / 872x |

## Linux summary

- **fastvol cold** vs vol-rs cold: median 24.0x, geo-mean 22.5x, min 3.63x, max 37.0x; vs python: median 197x, geo-mean 192x, min 46.2x, max 6,765x
- **fastvol steady** vs vol-rs warm: median 43.8x, geo-mean 38.2x, min 3.59x, max 119x; vs python: median 3,292x, geo-mean 2,650x, min 81.2x, max 67,094x
- **fastvol warm** vs vol-rs warm: median 47.4x, geo-mean 50.0x, min 14.1x, max 603x; vs python: median 3,570x, geo-mean 3,468x, min 306x, max 68,506x
- fastvol cold is the fastest on every plugin
- fastvol steady is the fastest on every plugin
- fastvol warm is the fastest on every plugin
- fastvol stdout byte-identical to python's recorded output (after the banner line) in every run of all three columns: **58/59** (the others: `timeliner.Timeliner` = ref machine, see Checks); vol-rs (both columns, pass 2): 45/59
- the three fastvol columns printed the same stdout in all their runs on 59/59 plugins (the caches never change output)

## Startup: cold vs warm cache (`windows.pslist.PsList`, 5 GiB image)

cold = the tool's own cache deleted before every run (fastvol: its whole cache directory; vol-rs: `$XDG_CACHE_HOME/vol-rs` except downloaded PDBs; python: `identifier.cache` + `data_*.cache`); the image stays page-cached and the kernel symbol file provisioned. warm = the cache written by the previous run. Best of 5 (python: 3), median in parentheses. All three tools were run again in pass 3.

| tool | cold | warm |
|---|---:|---:|
| fvol `b400e76` | 19.1 ms (20.0 ms) | 2.5 ms (2.8 ms) |
| vol-rs | 546 ms (564 ms) | 78.5 ms (85.1 ms) |
| python | 1.98 s (2.03 s) | 1.01 s (1.16 s) |
| pass 2: rsvol `95528b2` | 64.7 ms (66.8 ms) | 3.3 ms (3.6 ms) |
| pass 2: vol-rs | 563 ms (567 ms) | 80.6 ms (85.5 ms) |
| pass 2: python | 1.87 s (1.97 s) | 1.20 s (1.20 s) |

fvol's first run takes 19.1 ms (pass 2: 64.7 ms; 49.5 ms with the lazy symbol tables right after
pass 2, see [pass 2's rerun](BENCHMARKS-run2.md#first-runs-with-lazy-symbol-tables-rsvol-cold-rerun)):
it no longer builds the binary symbol table of the 0.6 MB `.json.xz` kernel ISF before the plugin but
resolves what the plugin uses and leaves the full table to a detached helper after the output; the
rest came with the optimization pass's cold-start and startup work (not broken down here). A warm run
takes 2.5 ms (median 2.8 ms; pass 2: 3.3 ms): hot-text ordering, RELR relocations, the exit-teardown
helper and warm-path trims ([docs/building.md](../../docs/building.md#startup)). vol-rs and python
were run again for this table: vol-rs 3% below pass 2; python's best cold run is 1.98 s (pass 2:
1.87 s) and its best warm run 1.01 s (pass 2: 1.20 s; run 1: 998 ms).

## Windows per-plugin

| plugin | python | vol-rs cold | vol-rs warm | fastvol cold | fastvol steady | fastvol warm | steady vs vol-rs warm | steady vs pass 2 | fastvol out = py | vol-rs out = py | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|:---:|:---:|---|
| banners.Banners | 29.23 s | 624 ms | 626 ms | 182 ms | 182 ms | **1.6 ms** | 3.45x | 1.01x | yes | yes | warm: fastvol replays the cached hits of its whole-image banner scan |
| frameworkinfo.FrameworkInfo | 383 ms† | 5.0 ms | 3.8 ms | **1.1 ms** | **1.1 ms** | 1.2 ms | 3.45x | 1.36x | sorted = | **no** | python lists components in the readdir order of its install dir (ext4 here, btrfs on the reference machine): sorted outputs identical, and fastvol's output is byte-identical to python's on the reference machine |
| isfinfo.IsfInfo | 374 ms† | 3.8 ms | 3.7 ms | 30.3 ms | 2.7 ms | **2.5 ms** | 1.37x | 1.07x | = py rerun | **no** | python's recorded output predates a new kernel ISF in python's symbols dir; fastvol's output = python's, run side by side after pass 3 (see Checks). Cold: see Changes since pass 2 |
| vmscan.Vmscan | 1.88 s | 4.1 ms | 4.1 ms | 41.0 ms | 39.0 ms | **1.6 ms** | **0.11x** | 7.97x | yes | yes | vol-rs ships no VMCS ISFs and returns the empty table without reading the image; python and fastvol scan the whole 5 GiB image (fastvol warm: from its scan cache) |
| windows.amcache.Amcache | 1.04 s | 561 ms | 84.7 ms | 18.2 ms | **2.1 ms** | 2.3 ms | 40.3x | 1.52x | yes | yes |  |
| windows.bigpools.BigPools | 4.49 s | 616 ms | 139 ms | 19.6 ms | 5.7 ms | **5.2 ms** | 24.4x | 1.77x | yes | yes |  |
| windows.cachedump.Cachedump | 2.09 s | 565 ms | 96.8 ms | 20.7 ms | 4.6 ms | **4.3 ms** | 21.0x | 1.41x | yes | yes |  |
| windows.callbacks.Callbacks | 19.44 s | 2.96 s | 2.45 s | 65.2 ms | 48.3 ms | **6.7 ms** | 50.6x | 1.62x | yes | yes |  |
| windows.cmdline.CmdLine | 1.23 s | 559 ms | 91.1 ms | 19.7 ms | 5.3 ms | **4.8 ms** | 17.2x | 1.83x | yes | yes |  |
| windows.cmdscan.CmdScan | 5.83 s | 833 ms | 360 ms | 25.8 ms | 12.5 ms | **6.6 ms** | 28.8x | 1.58x | yes | **no** |  |
| windows.consoles.Consoles | 7.57 s | 832 ms | 359 ms | 23.2 ms | **9.6 ms** | 9.7 ms | 37.4x | 1.72x | yes | **no** |  |
| windows.crashinfo.Crashinfo | 432 ms | 555 ms | 83.8 ms | **1.1 ms** | **1.1 ms** | **1.1 ms** | 76.2x | 1.91x | yes | yes | not a crash dump: every tool exits 1 |
| windows.debugregisters.DebugRegisters | 19.12 s | 561 ms | 94.8 ms | 24.9 ms | **11.5 ms** | **11.5 ms** | 8.24x | 2.08x | yes | yes |  |
| windows.deskscan.DeskScan | 13.77 s | 2.62 s | 2.17 s | 66.1 ms | 53.1 ms | **6.6 ms** | 40.9x | 1.47x | yes | yes |  |
| windows.desktops.Desktops | 17.25 s | 2.71 s | 2.22 s | 69.2 ms | 55.0 ms | **10.1 ms** | 40.3x | 1.50x | yes | yes |  |
| windows.devicetree.DeviceTree | 13.84 s | 2.66 s | 2.18 s | 66.2 ms | 52.2 ms | **5.2 ms** | 41.9x | 1.47x | yes | yes |  |
| windows.dlllist.DllList | 8.46 s | 703 ms | 227 ms | 23.1 ms | **9.0 ms** | 9.1 ms | 25.2x | 2.98x | yes | **no** |  |
| windows.driverirp.DriverIrp | 14.82 s | 2.67 s | 2.17 s | 70.1 ms | 53.9 ms | **10.1 ms** | 40.3x | 1.48x | yes | yes |  |
| windows.drivermodule.DriverModule | 13.73 s | 2.59 s | 2.15 s | 64.3 ms | 48.9 ms | **5.1 ms** | 43.9x | 1.61x | yes | yes |  |
| windows.driverscan.DriverScan | 14.10 s | 2.63 s | 2.19 s | 64.1 ms | 49.5 ms | **5.2 ms** | 44.3x | 1.57x | yes | yes |  |
| windows.dumpfiles.DumpFiles | 144.37 s | 8.09 s | 7.52 s | 157 ms | 146 ms | **144 ms** | 51.6x | 1.66x | yes | **no** | writes 1.48 GB of files per run (vol-rs: 4.5 GB, different set) |
| windows.envars.Envars | 1.90 s | 572 ms | 102 ms | 20.7 ms | **6.0 ms** | 6.1 ms | 17.0x | 1.93x | yes | yes |  |
| windows.etwpatch.EtwPatch | 17.51 s | 699 ms | 224 ms | 48.2 ms | 25.2 ms | **22.0 ms** | 8.89x | 1.86x | yes | yes |  |
| windows.filescan.FileScan | 24.59 s | 2.78 s | 2.31 s | 71.2 ms | 56.7 ms | **14.0 ms** | 40.7x | 1.59x | yes | **no** |  |
| windows.getservicesids.GetServiceSIDs | 2.56 s | 598 ms | 128 ms | 19.7 ms | 3.7 ms | **3.3 ms** | 34.5x | 1.38x | yes | yes |  |
| windows.getsids.GetSIDs | 2.80 s | 598 ms | 120 ms | 22.0 ms | **6.9 ms** | 7.9 ms | 17.4x | 1.48x | yes | **no** |  |
| windows.handles.Handles | 37.62 s | 1.13 s | 667 ms | 26.5 ms | 13.5 ms | **13.2 ms** | 49.4x | 4.56x | yes | yes |  |
| windows.hashdump.Hashdump | 1.89 s | 563 ms | 92.7 ms | 20.7 ms | 4.6 ms | **4.4 ms** | 20.2x | 1.37x | yes | **no** | exit py/vol-rs/fastvol = 0/1/0 |
| windows.iat.IAT | 4.62 s | 643 ms | 170 ms | 22.8 ms | 10.6 ms | **10.3 ms** | 16.1x | 2.35x | yes | yes |  |
| windows.info.Info | 840 ms | 569 ms | 81.7 ms | 18.7 ms | 1.9 ms | **1.6 ms** | 43.0x | 1.42x | = py rerun | **no** | its Symbols row names the kernel ISF, which now resolves to python's install dir; fastvol's output = python's, run side by side after pass 3 (see Checks) |
| windows.joblinks.JobLinks | 1.14 s | 562 ms | 94.2 ms | 20.1 ms | 5.6 ms | **5.2 ms** | 16.8x | 1.50x | yes | yes |  |
| windows.kpcrs.KPCRs | 925 ms | 562 ms | 82.1 ms | 18.1 ms | 1.7 ms | **1.5 ms** | 48.3x | 1.41x | yes | yes |  |
| windows.lsadump.Lsadump | 2.12 s | 568 ms | 90.9 ms | 21.4 ms | **4.6 ms** | 5.1 ms | 19.8x | 1.30x | yes | **no** |  |
| windows.malware.drivermodule.DriverModule | 14.12 s | 2.63 s | 2.15 s | 64.5 ms | 50.9 ms | **5.0 ms** | 42.3x | 1.53x | yes | yes |  |
| windows.mbrscan.MBRScan | 16.53 s | 1.37 s | 900 ms | 215 ms | 201 ms | **71.5 ms** | 4.48x | 1.06x | yes | **no** |  |
| windows.modscan.ModScan | 13.08 s | 2.62 s | 2.15 s | 63.4 ms | 47.6 ms | **2.9 ms** | 45.1x | 1.58x | yes | yes |  |
| windows.modules.Modules | 1.01 s | 562 ms | 85.5 ms | 18.2 ms | **2.5 ms** | 2.6 ms | 34.2x | 1.56x | yes | yes |  |
| windows.mutantscan.MutantScan | 13.51 s | 2.63 s | 2.20 s | 64.4 ms | 50.5 ms | **4.8 ms** | 43.5x | 1.50x | yes | yes |  |
| windows.netscan.NetScan | 20.68 s | 2.63 s | 2.17 s | 66.3 ms | 53.9 ms | **3.3 ms** | 40.2x | 1.41x | yes | yes |  |
| windows.netstat.NetStat | 1.16 s | 1.05 s | 572 ms | 28.5 ms | 3.6 ms | **3.2 ms** | 159x | 1.81x | yes | yes |  |
| windows.orphan_kernel_threads.Threads | 16.71 s | 2.68 s | 2.20 s | 66.6 ms | 51.6 ms | **7.6 ms** | 42.6x | 1.54x | yes | yes |  |
| windows.pe_symbols.PESymbols | 359 ms | 3.1 ms | 3.0 ms | **1.0 ms** | **1.0 ms** | **1.0 ms** | 3.00x | 1.30x | yes | yes | exit py/vol-rs/fastvol = 2/1/2; needs arguments: usage error in every tool |
| windows.poolscanner.PoolScanner | 37.29 s | 3.28 s | 2.87 s | 73.5 ms | 60.2 ms | **16.7 ms** | 47.7x | 1.59x | yes | **no** |  |
| windows.privileges.Privs | 1.33 s | 566 ms | 99.8 ms | 20.3 ms | 5.6 ms | **5.4 ms** | 17.8x | 1.80x | yes | yes |  |
| windows.pslist.PsList | 1.17 s | 558 ms | 88.2 ms | 18.4 ms | **2.6 ms** | 2.7 ms | 33.9x | 1.62x | yes | yes |  |
| windows.psscan.PsScan | 14.86 s | 2.67 s | 2.23 s | 63.7 ms | 49.4 ms | **5.8 ms** | 45.1x | 1.57x | yes | yes |  |
| windows.pstree.PsTree | 1.44 s | 560 ms | 96.6 ms | 21.1 ms | **5.4 ms** | 5.7 ms | 17.9x | 1.85x | yes | yes |  |
| windows.registry.amcache.Amcache | 1.04 s | 570 ms | 86.2 ms | 18.4 ms | 2.2 ms | **1.9 ms** | 39.2x | 1.45x | yes | yes |  |
| windows.registry.cachedump.Cachedump | 1.95 s | 563 ms | 97.0 ms | 20.7 ms | 5.0 ms | **4.7 ms** | 19.4x | 1.24x | yes | yes |  |
| windows.registry.certificates.Certificates | 4.28 s | 637 ms | 173 ms | 19.4 ms | **4.7 ms** | **4.7 ms** | 36.8x | 1.96x | yes | yes |  |
| windows.registry.getcellroutine.GetCellRoutine | 1.36 s | 695 ms | 227 ms | 19.8 ms | 5.0 ms | **4.8 ms** | 45.4x | 1.26x | yes | yes |  |
| windows.registry.hashdump.Hashdump | 2.07 s | 572 ms | 94.3 ms | 20.0 ms | 4.9 ms | **4.4 ms** | 19.2x | 1.24x | yes | **no** | exit py/vol-rs/fastvol = 0/1/0 |
| windows.registry.hivelist.HiveList | 982 ms | 557 ms | 83.3 ms | 18.3 ms | **2.1 ms** | 2.2 ms | 39.7x | 1.52x | yes | yes |  |
| windows.registry.hivescan.HiveScan | 3.28 s | 582 ms | 116 ms | 18.1 ms | 2.9 ms | **2.6 ms** | 39.9x | 1.28x | yes | yes |  |
| windows.registry.lsadump.Lsadump | 2.21 s | 574 ms | 93.7 ms | 20.9 ms | **4.7 ms** | 4.8 ms | 19.9x | 1.32x | yes | **no** |  |
| windows.registry.printkey.PrintKey | 2.38 s | 592 ms | 120 ms | 21.1 ms | **6.6 ms** | 7.0 ms | 18.2x | 1.29x | yes | yes |  |
| windows.registry.scheduled_tasks.ScheduledTasks | 6.14 s | 638 ms | 164 ms | 19.9 ms | 6.1 ms | **5.8 ms** | 26.9x | 1.08x | yes | yes |  |
| windows.registry.userassist.UserAssist | 1.85 s | 590 ms | 111 ms | 18.9 ms | 3.7 ms | **3.5 ms** | 29.9x | 1.32x | yes | yes |  |
| windows.scheduled_tasks.ScheduledTasks | 6.24 s | 645 ms | 164 ms | 19.3 ms | **6.2 ms** | **6.2 ms** | 26.5x | 1.08x | yes | yes |  |
| windows.sessions.Sessions | 1.26 s | 564 ms | 92.5 ms | 19.6 ms | **5.3 ms** | **5.3 ms** | 17.5x | 1.85x | yes | yes |  |
| windows.shimcachemem.ShimcacheMem | 1.63 s | 562 ms | 93.2 ms | 20.8 ms | 3.6 ms | **3.5 ms** | 25.9x | 1.47x | yes | yes |  |
| windows.ssdt.SSDT | 1.17 s | 570 ms | 97.4 ms | 19.9 ms | **5.3 ms** | 5.4 ms | 18.4x | 1.19x | yes | yes |  |
| windows.suspended_threads.SuspendedThreads | 19.44 s | 574 ms | 103 ms | 37.6 ms | 18.9 ms | **17.0 ms** | 5.46x | 2.04x | yes | yes |  |
| windows.symlinkscan.SymlinkScan | 13.13 s | 2.63 s | 2.18 s | 64.9 ms | 48.7 ms | **4.1 ms** | 44.8x | 1.56x | yes | yes |  |
| windows.thrdscan.ThrdScan | 34.60 s | 2.83 s | 2.35 s | 68.9 ms | 55.7 ms | **10.2 ms** | 42.1x | 1.66x | yes | yes |  |
| windows.threads.Threads | 18.67 s | 739 ms | 263 ms | 23.0 ms | **9.7 ms** | 10.1 ms | 27.1x | 2.15x | yes | yes |  |
| windows.timers.Timers | 1.63 s | 564 ms | 100 ms | 19.7 ms | 5.0 ms | **4.7 ms** | 20.1x | 1.62x | yes | yes |  |
| windows.truecrypt.Passphrase | 792 ms | 549 ms | 85.1 ms | 17.8 ms | 2.0 ms | **1.6 ms** | 42.5x | 1.60x | yes | yes |  |
| windows.unloadedmodules.UnloadedModules | 776 ms | 549 ms | 82.5 ms | 18.2 ms | **1.8 ms** | 1.9 ms | 45.8x | 1.33x | yes | yes |  |
| windows.vadinfo.VadInfo | 105.40 s | 919 ms | 456 ms | 27.3 ms | 14.3 ms | **13.5 ms** | 31.9x | 2.20x | yes | yes |  |
| windows.vadwalk.VadWalk | 19.89 s | 791 ms | 316 ms | 24.1 ms | 10.6 ms | **10.5 ms** | 29.8x | 1.93x | yes | yes |  |
| windows.verinfo.VerInfo | 49.59 s | 752 ms | 282 ms | 29.9 ms | 15.9 ms | **15.6 ms** | 17.7x | 3.06x | yes | yes |  |
| windows.virtmap.VirtMap | 720 ms | 552 ms | 82.5 ms | 16.9 ms | **1.7 ms** | 1.8 ms | 48.5x | 1.47x | yes | yes |  |
| windows.windows.Windows | 17.95 s† | 2.75 s | 2.28 s | 67.9 ms | 52.9 ms | **10.8 ms** | 43.2x | 1.60x | sorted = | **no** | python's row order is nondeterministic (set iteration: its 3 runs in pass 2 printed 3 orders); sorted outputs identical |
| windows.windowstations.WindowStations | 17.14 s | 2.67 s | 2.32 s | 63.6 ms | 50.8 ms | **8.5 ms** | 45.7x | 1.59x | yes | **no** |  |
| windows.statistics.Statistics | 1686.76 s | 71.68 s | 70.06 s | 26.3 ms | **12.7 ms** | 13.1 ms | 5,517x | 2.02x | yes | yes | python's page walk is quadratic (re-walks every valid run per step); fastvol walks each page once |
| timeliner.Timeliner | 1468.70 s | 19.31 s | 18.65 s | 1.10 s | 1.05 s | **727 ms** | 17.7x | 1.24x | = ref machine | **no** | python's output depends on plugin discovery (readdir) order, see Checks; fastvol's output is byte-identical to python's on the reference machine |

## Linux per-plugin

| plugin | python | vol-rs cold | vol-rs warm | fastvol cold | fastvol steady | fastvol warm | steady vs vol-rs warm | steady vs pass 2 | fastvol out = py | vol-rs out = py | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|:---:|:---:|---|
| banners.Banners | 21.56 s | 398 ms | 395 ms | 109 ms | 110 ms | **1.8 ms** | 3.59x | 1.04x | yes | yes |  |
| linux.bash.Bash | 10.21 s | 2.21 s | 209 ms | 93.1 ms | 7.9 ms | **7.5 ms** | 26.5x | 1.29x | yes | yes |  |
| linux.boottime.Boottime | 8.00 s | 2.09 s | 132 ms | 90.7 ms | **2.3 ms** | 2.7 ms | 57.4x | 1.52x | yes | yes |  |
| linux.capabilities.Capabilities | 8.21 s | 2.07 s | 130 ms | 89.4 ms | **3.7 ms** | **3.7 ms** | 35.2x | 1.97x | yes | yes |  |
| linux.check_afinfo.Check_afinfo | 20.19 s | 2.26 s | 322 ms | 88.9 ms | 4.2 ms | **4.1 ms** | 76.7x | 1.29x | yes | yes |  |
| linux.check_creds.Check_creds | 9.73 s | 2.09 s | 129 ms | 91.7 ms | 2.6 ms | **2.2 ms** | 49.7x | 1.42x | yes | yes |  |
| linux.check_idt.Check_idt | 28.25 s | 2.31 s | 313 ms | 92.4 ms | 7.5 ms | **7.3 ms** | 41.7x | 1.72x | yes | yes |  |
| linux.check_modules.Check_modules | 9.35 s | 2.08 s | 126 ms | 94.7 ms | 2.6 ms | **2.5 ms** | 48.5x | 1.35x | yes | yes |  |
| linux.check_syscall.Check_syscall | 22.01 s | 2.43 s | 494 ms | 99.0 ms | 9.8 ms | **9.5 ms** | 50.4x | 0.93x | yes | yes |  |
| linux.ebpf.EBPF | 8.71 s | 2.04 s | 137 ms | 89.0 ms | 2.0 ms | **1.9 ms** | 68.3x | 1.40x | yes | yes |  |
| linux.elfs.Elfs | 13.57 s | 2.28 s | 278 ms | 93.8 ms | **7.2 ms** | 7.3 ms | 38.7x | 2.54x | yes | yes |  |
| linux.envars.Envars | 8.11 s | 2.08 s | 135 ms | 89.6 ms | 5.4 ms | **5.2 ms** | 25.0x | 1.39x | yes | yes |  |
| linux.graphics.fbdev.Fbdev | 6.12 s† | 2.11 s | 123 ms | 86.1 ms | 1.5 ms | **1.4 ms** | 82.2x | 1.53x | yes | yes |  |
| linux.hidden_modules.Hidden_modules | 17.42 s | 2.51 s | 589 ms | 86.6 ms | 5.0 ms | **4.6 ms** | 118x | 1.68x | yes | yes |  |
| linux.iomem.IOMem | 9.14 s | 2.07 s | 123 ms | 92.7 ms | 2.0 ms | **1.6 ms** | 61.6x | 1.25x | yes | yes |  |
| linux.ip.Addr | 10.62 s† | 2.06 s | 125 ms | 90.9 ms | 2.1 ms | **1.9 ms** | 59.5x | 1.48x | yes | **no** |  |
| linux.ip.Link | 9.21 s† | 2.06 s | 125 ms | 94.5 ms | **1.8 ms** | 2.0 ms | 69.6x | 1.39x | yes | **no** |  |
| linux.kallsyms.Kallsyms | 105.37 s | 3.17 s | 1.17 s | 114 ms | 44.1 ms | **36.6 ms** | 26.5x | 2.32x | yes | **no** | python raises TypeError after 204,803 rows; fastvol reproduces output and exit code |
| linux.keyboard_notifiers.Keyboard_notifiers | 19.50 s | 2.25 s | 318 ms | 89.0 ms | 5.6 ms | **5.4 ms** | 56.9x | 1.80x | yes | **no** |  |
| linux.kmsg.Kmsg | 8.34 s | 2.08 s | 135 ms | 87.0 ms | **2.7 ms** | **2.7 ms** | 50.0x | 1.59x | yes | yes |  |
| linux.kthreads.Kthreads | 27.17 s | 2.26 s | 328 ms | 94.3 ms | 9.9 ms | **9.7 ms** | 33.2x | 3.43x | yes | yes |  |
| linux.library_list.LibraryList | 43.77 s | 2.21 s | 271 ms | 92.9 ms | 8.0 ms | **7.8 ms** | 33.8x | 2.40x | yes | yes |  |
| linux.lsmod.Lsmod | 15.90 s | 2.11 s | 129 ms | 89.7 ms | 2.8 ms | **2.4 ms** | 46.2x | 1.39x | yes | yes |  |
| linux.lsof.Lsof | 24.84 s† | 2.14 s | 179 ms | 92.3 ms | **7.6 ms** | 7.8 ms | 23.5x | 1.72x | yes | yes |  |
| linux.malfind.Malfind | 31.59 s | 2.38 s | 431 ms | 93.5 ms | 9.4 ms | **9.2 ms** | 45.9x | 1.59x | yes | **no** |  |
| linux.malware.check_afinfo.Check_afinfo | 17.31 s | 2.26 s | 313 ms | 91.1 ms | 4.2 ms | **4.0 ms** | 74.5x | 1.19x | yes | yes |  |
| linux.malware.check_creds.Check_creds | 9.17 s | 2.03 s | 131 ms | 94.3 ms | 2.7 ms | **2.5 ms** | 48.5x | 1.26x | yes | yes |  |
| linux.malware.check_idt.Check_idt | 30.09 s | 2.31 s | 313 ms | 89.1 ms | 7.6 ms | **7.5 ms** | 41.2x | 1.67x | yes | yes |  |
| linux.malware.check_modules.Check_modules | 7.89 s | 2.19 s | 126 ms | 85.5 ms | 2.7 ms | **2.4 ms** | 46.8x | 1.41x | yes | yes |  |
| linux.malware.check_syscall.Check_syscall | 29.14 s | 2.53 s | 512 ms | 100 ms | 9.5 ms | **9.4 ms** | 53.9x | 1.02x | yes | yes |  |
| linux.malware.hidden_modules.Hidden_modules | 18.28 s | 2.50 s | 585 ms | 93.9 ms | 4.9 ms | **4.7 ms** | 119x | 1.76x | yes | yes |  |
| linux.malware.keyboard_notifiers.Keyboard_notifiers | 19.19 s | 2.27 s | 315 ms | 90.3 ms | 5.7 ms | **5.2 ms** | 55.2x | 1.79x | yes | **no** |  |
| linux.malware.malfind.Malfind | 34.63 s | 2.50 s | 416 ms | 92.3 ms | **9.5 ms** | 9.7 ms | 43.8x | 1.55x | yes | **no** |  |
| linux.malware.modxview.Modxview | 19.57 s | 2.50 s | 568 ms | 91.4 ms | 6.0 ms | **5.6 ms** | 94.6x | 1.68x | yes | yes |  |
| linux.malware.netfilter.Netfilter | 37.23 s | 2.23 s | 310 ms | 96.3 ms | 8.0 ms | **7.2 ms** | 38.8x | 1.78x | yes | **no** |  |
| linux.malware.process_spoofing.ProcessSpoofing | 10.48 s | 2.08 s | 136 ms | 90.4 ms | 5.6 ms | **5.0 ms** | 24.2x | 1.41x | yes | yes |  |
| linux.malware.tty_check.Tty_Check | 27.70 s | 2.27 s | 311 ms | 94.1 ms | **7.5 ms** | 7.8 ms | 41.5x | 1.84x | yes | yes |  |
| linux.modxview.Modxview | 17.78 s | 2.48 s | 580 ms | 84.7 ms | 5.4 ms | **5.3 ms** | 107x | 1.87x | yes | yes |  |
| linux.mountinfo.MountInfo | 11.89 s† | 2.06 s | 151 ms | 95.9 ms | **6.0 ms** | **6.0 ms** | 25.2x | 2.03x | yes | yes |  |
| linux.netfilter.Netfilter | 39.74 s | 2.28 s | 322 ms | 89.9 ms | **7.6 ms** | 7.8 ms | 42.4x | 1.76x | yes | **no** |  |
| linux.pagecache.Files | 58.40 s† | 2.95 s | 1.01 s | 118 ms | **32.7 ms** | 37.8 ms | 31.0x | 2.43x | yes | yes |  |
| linux.pagecache.InodePages | 7.62 s† | 2.13 s | 124 ms | 87.5 ms | 1.8 ms | **1.4 ms** | 69.2x | 1.28x | yes | yes | needs --inode or --find: every tool prints the empty table and the error, exit 0 |
| linux.pidhashtable.PIDHashTable | 10.53 s | 2.06 s | 136 ms | 86.4 ms | 5.1 ms | **4.6 ms** | 26.7x | 1.75x | yes | yes |  |
| linux.proc.Maps | 41.70 s | 2.40 s | 449 ms | 94.6 ms | 9.6 ms | **9.5 ms** | 46.8x | 1.80x | yes | yes |  |
| linux.psaux.PsAux | 8.90 s | 2.08 s | 132 ms | 85.8 ms | **5.1 ms** | **5.1 ms** | 25.9x | 1.47x | yes | yes |  |
| linux.pslist.PsList | 10.59 s | 2.08 s | 132 ms | 89.7 ms | 3.3 ms | **2.7 ms** | 39.8x | 1.33x | yes | yes |  |
| linux.psscan.PsScan | 58.63 s | 2.39 s | 486 ms | 213 ms | 122 ms | **14.7 ms** | 3.99x | 1.19x | yes | yes |  |
| linux.pstree.PsTree | 8.89 s | 2.10 s | 131 ms | 89.6 ms | **3.0 ms** | 3.6 ms | 43.5x | 1.60x | yes | yes |  |
| linux.ptrace.Ptrace | 8.54 s | 2.10 s | 138 ms | 89.4 ms | **3.0 ms** | 3.1 ms | 46.1x | 2.17x | yes | **no** |  |
| linux.sockscan.Sockscan | 27.16 s† | 2.22 s | 425 ms | 204 ms | 116 ms | **7.0 ms** | 3.67x | 1.01x | yes | yes |  |
| linux.sockstat.Sockstat | 19.34 s† | 2.09 s | 183 ms | 92.9 ms | **7.7 ms** | 7.8 ms | 23.7x | 1.71x | yes | yes |  |
| linux.tracing.ftrace.CheckFtrace | 25.89 s | 2.26 s | 315 ms | 93.9 ms | 7.6 ms | **7.3 ms** | 41.4x | 1.72x | yes | yes |  |
| linux.tracing.perf_events.PerfEvents | 8.22 s | 2.18 s | 130 ms | 90.0 ms | 2.9 ms | **2.7 ms** | 44.8x | 1.48x | yes | **no** |  |
| linux.tracing.tracepoints.CheckTracepoints | 25.14 s | 2.27 s | 332 ms | 91.6 ms | 7.1 ms | **7.0 ms** | 46.7x | 1.87x | yes | **no** |  |
| linux.tty_check.tty_check | 24.36 s | 2.23 s | 314 ms | 94.2 ms | **7.7 ms** | 7.8 ms | 40.7x | 1.74x | yes | yes |  |
| linux.vmcoreinfo.VMCoreInfo | 9.23 s | 3.05 s | 1.21 s | 200 ms | 114 ms | **2.0 ms** | 10.6x | 1.07x | yes | yes | warm: the VMCOREINFO magic scan is answered by the scan cache (new since pass 2); steady scans the image |
| linux.pagecache.RecoverFs | 710.99 s† | 86.71 s | 85.86 s | 2.34 s | **2.28 s** | 2.33 s | 37.6x | 1.50x | yes | **no** | writes a .tar.gz of the recovered file system per run (fastvol 905 MB, python 842 MB, vol-rs 626 MB; see Checks); python: 1 run, no warm-up |
| linux.pscallstack.PsCallStack | 650.81 s | 2.51 s | 535 ms | 96.2 ms | 9.7 ms | **9.5 ms** | 55.1x | 1.79x | yes | yes |  |
| timeliner.Timeliner | 262.11 s | 3.13 s | 1.24 s | 359 ms | 203 ms | **88.4 ms** | 6.12x | 1.03x | = ref machine | **no** | python's output depends on plugin discovery (readdir) order, see Checks; fastvol's output is byte-identical to python's on the reference machine |

† python's time and output hash from pass 2, which ran python again for these plugins; all other python numbers are run 1's. "steady vs pass 2" = rsvol `95528b2` steady / fvol `b400e76` steady.

## Checks

- **Run-to-run stability (Windows).** vol-rs warm in pass 2 vs run 1 (same binary, same procedure): ratio median 1.008, 10th-90th percentile 0.972–1.046 over 77 plugins. Within pass 3, the median-of-5 is 1.04x (fastvol cold), 1.05x (fastvol steady), 1.06x (fastvol warm) the best run (median over plugins).
- **Run-to-run stability (Linux).** vol-rs warm in pass 2 vs run 1 (same binary, same procedure): ratio median 1.000, 10th-90th percentile 0.940–1.045 over 49 plugins. Within pass 3, the median-of-5 is 1.10x (fastvol cold), 1.06x (fastvol steady), 1.07x (fastvol warm) the best run (median over plugins).
- **Output equality details** (every fastvol run of every column is checked, not only the best one).
  130 of the 136 plugin rows printed python's recorded output (run 1's stdout hash, or pass 2's where
  pass 2 ran python again) in all 15 fastvol runs. The other six:
  - `frameworkinfo.FrameworkInfo`, `windows.windows.Windows` and both `timeliner.Timeliner` rows:
    python's own output varies here (the readdir order of its install directory, set iteration order;
    details in pass 2's [Checks](BENCHMARKS-run2.md#checks)). All 15 fastvol runs of each printed the
    same bytes as rsvol `95528b2` in pass 2 (`962733ee…`, `7d57cce8…`, `3984c9cd…`, `543ed014…`):
    python's output on the reference machine (frameworkinfo, both timeliners) and python's output on
    the VM after sorting (frameworkinfo, windows.windows).
  - `isfinfo.IsfInfo` and `windows.info.Info`: between the passes a new Windows kernel ISF
    (`ntkrnlmp.pdb/8E3373D6…-1.json.xz`, written 19:02) appeared in the symbols directory of the VM's
    python volatility3 install. Both plugins print python's symbol file locations (windows.info's
    Symbols row now names `volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/…json.xz` instead of
    the cache path), so python's recorded outputs no longer match python on the VM. After pass 3 both
    plugins were run side by side with python on the VM: fvol's output was byte-identical to python's.
  - `linux.pagecache.RecoverFs`: stdout identical in every run. The archive is now 905 MB (pass 2:
    837 MB, python 842 MB): the output pass switched fastvol's gzip writer to a single-probe level-1
    deflate (`bd45d38`). The archive bytes differ from python's in any case (tar mtimes, compressor);
    its members were not compared in this run (pass 2 did; the dump-parity gate
    `bench/scripts/check_dumps.sh` compares RecoverFs archives with python's member by member).
- **Verification outside the benchmark.** The benchmarked build passes the parity gates on 31 test
  images, every output byte-identical to python's: 599 unit tests, 98/98 on the main image,
  1114/1114 on 13 Windows images, 763/763 on 17 Linux/mac images.
- **Cache states.** The three fastvol columns printed the same stdout in all of their 15 runs on
  every plugin (77/77, 59/59), so no cache changed any output. The cache directory sizes were not
  recorded in pass 3.
- **Where fastvol cold loses.** A first-ever run now costs little more than a steady one: per plugin,
  cold minus steady is a median 14.7 ms on Windows (0-48 ms; pass 2: 58.4 ms) and 85.7 ms on Linux
  (pass 2: 529 ms). On Linux a first run no longer builds the 64 MB kernel ISF's binary table before
  the plugin: it indexes the JSON while decoding it, resolves only the types and symbols the plugin
  touches, and a detached idle-priority helper (`fastvol-isfb-helper`) writes the full table after
  the output ([docs/caching.md](../../docs/caching.md)). So fastvol cold now beats vol-rs *warm* on
  all 59 Linux plugins and on 75 of 77 Windows plugins (not: `vmscan`, `isfinfo`, see above). The
  timed run ends when fvol exits; the helper's work comes after it and is not in any column.
- **Load.** `/proc/loadavg` every 10 s during pass 3 (23:19-23:22, 19 samples): load1 min 0.07, median 7.62, p90 12.22, max 12.43. Only the benchmark ran; the load comes from the multi-threaded fastvol runs executing back to back (fastvol uses all 32 vCPUs), and the 1-minute average carries over between runs.

