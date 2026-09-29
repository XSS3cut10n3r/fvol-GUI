# fastvol vs vol-rs vs python volatility3: benchmark

Measured 2026-09-27 20:11–21:18 CDT on this machine (a desktop, not a dedicated server):

| | |
|---|---|
| CPU | 12th Gen Intel(R) Core(TM) i7-12700KF: 12 cores / 20 threads (8 performance + 4 efficiency cores), up to 5.0 GHz, governor `powersave` |
| Memory | 62 GiB |
| Storage | btrfs on LUKS (dm-crypt) on a Micron 2200S NVMe 1024GB |
| OS | Omarchy, Linux 7.1.8-arch1-3 |
| Load | load average 3.1 at the start, 2.2 at the end (our own runs included) |
| fastvol | commit 8870abe, binary sha256 `0cca274f0ff0cf95…`, rustc 1.100.0-nightly (1303417c4 2026-09-21), `target-cpu=native` (the repo's default build) |
| vol-rs | vol-rs 1.0.0 (Volatility 3 framework 2.28.0), binary sha256 `ac1e4ed6b64a6f07…` (the build benchmarked on the VM) |
| python | Python 3.14.7 / volatility3 v2.28.2-10-g3fcb731e with capstone, yara-python, pycryptodome |
| Images | Windows 11 x64 raw, 5.0 GiB; Ubuntu 24.04 Linux 6.8 ELF core, 3.0 GiB |

## How it was measured

- Every run is one process (`TOOL -q -o DIR -f IMAGE PLUGIN`, output to a file), timed from start to exit; runs are sequential, never two at once.
- **Figures are medians** of each tool's runs: fastvol 5 runs, vol-rs 3, python 1 per plugin (2 per triage session). A median does not favour the tool with more runs the way a best-of does.
- Each tool has its own caches (python's and vol-rs's symbol files were provisioned once; nothing downloads during the runs). The cache states:
  - **python**: warm (ISFs and identifier cache present). A first-ever python run would also download and convert the PDB; that is not measured.
  - **vol-rs cold / warm**: its cache deleted before every run (except downloaded PDBs) / as the previous run left it.
  - **fastvol cold**: its whole cache deleted before every run (symbol tables, identifier index, automagic results, scan results).
  - **fastvol steady**: symbol caches warm, **scan-result cache off**: every scan is really done. This is the like-for-like comparison with python's warm runs.
  - **fastvol warm**: every cache warm, including the per-image scan cache: scan results are replayed, not recomputed. What a user sees when re-running a plugin, but not the same work as python.
- The images are in the page cache unless a table says *evicted* (dropped with `posix_fadvise(DONTNEED)`, so they are read from the NVMe drive).

- **python, run in parallel for part of the all-plugins rounds** (to finish in minutes instead of hours): 15 windows plugins, 59 linux plugins ran 6 python processes at a time, each pinned to its own physical performance core, after that round's fastvol and vol-rs runs (never alongside them). Six control plugins timed both alone and in the pool took **2.1% less time** (median) in the pool: running in parallel did not slow python down, the speedups are not inflated.

- vol-rs: 3 runs per state for the first 62 plugins, 1 run after the schedule was shortened (like python).

## Triage session (the realistic case)

A first look at an image: the common plugins run one after another, as an analyst would. **first** = the tool's cache empty at the start (it fills as the session goes), **second** = the same session again. Python's caches are always warm.

**Windows** (12 plugins: info, pslist, pstree, psscan, cmdline, dlllist, netscan, modules, getsids, handles, filescan, hivelist)

| image | session | python | vol-rs | fastvol | fastvol vs python | fastvol vs vol-rs |
|---|---|--:|--:|--:|--:|--:|
| in page cache | first | 59.51 s | 3.71 s | **126 ms** | 473x | 29.5x |
| in page cache | second | 59.62 s | 3.44 s | **35.1 ms** | 1,701x | 98.2x |
| evicted (read from disk) | first | 69.94 s | 6.47 s | **1.67 s** | 41.9x | 3.88x |
| evicted (read from disk) | second | 78.67 s | 6.26 s | **635 ms** | 124x | 9.86x |

**Linux** (10 plugins: pslist, pstree, psaux, bash, lsmod, sockstat, lsof, malfind, elfs, check_syscall)

| image | session | python | vol-rs | fastvol | fastvol vs python | fastvol vs vol-rs |
|---|---|--:|--:|--:|--:|--:|
| in page cache | first | 80.76 s | 2.76 s | **227 ms** | 356x | 12.1x |
| in page cache | second | 82.67 s | 1.32 s | **33.2 ms** | 2,489x | 39.8x |
| evicted (read from disk) | first | 84.90 s | 3.59 s | **399 ms** | 213x | 9.01x |
| evicted (read from disk) | second | 84.96 s | 2.06 s | **207 ms** | 411x | 9.98x |

## Every plugin once: Windows 11, 77 plugins

Sums answer "how long to run every plugin once"; they are dominated by the few slowest plugins. The per-plugin speedups below them show the spread.

| | python | vol-rs cold | vol-rs warm | fastvol cold | fastvol steady | fastvol warm |
|---|--:|--:|--:|--:|--:|--:|
| total (sum of per-plugin medians) | 2,288 s | 90.26 s | 72.61 s | 3.94 s | 2.35 s | 1.19 s |
| median plugin | 2.79 s | 327 ms | 91.1 ms | 24.3 ms | 2.8 ms | 2.3 ms |
| total CPU (user + sys) | 2,283 s | 282 s | 267 s | 27.05 s | 23.23 s | 3.42 s |

| per-plugin speedup | geometric mean | median | 10th pct | 90th pct | slowest | fastest | plugins slower | sum ratio |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| fastvol cold vs python | **108x** | 131x | 25.5x | 408x | 21.0x (info) | 39,837x (statistics) | 0 | 581x |
| fastvol steady vs python | **556x** | 533x | 231x | 1,584x | 48.2x (vmscan) | 240,412x (statistics) | 0 | 972x |
| fastvol warm vs python | **1,170x** | 1,150x | 361x | 3,468x | 134x (dumpfiles) | 241,386x (statistics) | 0 | 1,924x |
| fastvol cold vs vol-rs cold | **14.0x** | 12.9x | 9.75x | 21.3x | 0.10x (vmscan) | 1,544x (statistics) | 1 | 22.9x |
| fastvol steady vs vol-rs warm | **26.9x** | 28.2x | 10.5x | 54.1x | 0.09x (vmscan) | 9,257x (statistics) | 1 | 30.9x |
| fastvol warm vs vol-rs warm | **56.7x** | 44.9x | 17.6x | 361x | 1.75x (isfinfo) | 9,294x (statistics) | 0 | 61.1x |

Output identical to python in every timed run: fastvol cold 76/77, steady 76/77, warm 76/77; vol-rs cold 59/77, warm 59/77.
fastvol's differences: `windows.windows.Windows` (python iterates a set: its row order changes run to run).

## Every plugin once: Linux 6.8, 59 plugins

Sums answer "how long to run every plugin once"; they are dominated by the few slowest plugins. The per-plugin speedups below them show the spread. On Linux python spends most of each run decompressing and parsing the kernel's symbol file (3.3 MB xz, 61.5 MB of JSON) (its median plugin takes 10.6 s); fastvol keeps a binary symbol table in its cache, which the steady and warm states use. **fastvol cold** rebuilds everything each run and is the comparison with no fastvol cache at all.

| | python | vol-rs cold | vol-rs warm | fastvol cold | fastvol steady | fastvol warm |
|---|--:|--:|--:|--:|--:|--:|
| total (sum of per-plugin medians) | 1,600 s | 117 s | 66.21 s | 5.47 s | 2.62 s | 2.21 s |
| median plugin | 10.61 s | 1.05 s | 162 ms | 58.3 ms | 2.7 ms | 2.2 ms |
| total CPU (user + sys) | 1,595 s | 309 s | 79.77 s | 44.67 s | 27.48 s | 18.76 s |

| per-plugin speedup | geometric mean | median | 10th pct | 90th pct | slowest | fastest | plugins slower | sum ratio |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| fastvol cold vs python | **184x** | 176x | 90.7x | 369x | 31.0x (vmcoreinfo) | 5,540x (pscallstack) | 0 | 292x |
| fastvol steady vs python | **3,094x** | 3,722x | 1,711x | 5,903x | 48.2x (vmcoreinfo) | 67,714x (pscallstack) | 0 | 611x |
| fastvol warm vs python | **4,417x** | 4,228x | 2,862x | 6,374x | 213x (pagecache) | 68,295x (pscallstack) | 0 | 724x |
| fastvol cold vs vol-rs cold | **16.5x** | 17.4x | 15.7x | 19.7x | 2.37x (banners) | 34.8x (pagecache) | 0 | 21.4x |
| fastvol steady vs vol-rs warm | **37.6x** | 42.5x | 21.8x | 63.7x | 2.13x (sockscan) | 147x (hidden_modules) | 0 | 25.3x |
| fastvol warm vs vol-rs warm | **53.6x** | 48.4x | 34.4x | 86.2x | 13.2x (timeliner) | 785x (vmcoreinfo) | 0 | 30.0x |

Output identical to python in every timed run: fastvol cold 59/59, steady 59/59, warm 59/59; vol-rs cold 45/59, warm 45/59.

## Startup: `windows.pslist.PsList`

| | python | vol-rs cold | vol-rs warm | fastvol cold | fastvol warm |
|---|--:|--:|--:|--:|--:|
| median of 10 (python 3) | 537 ms | 270 ms | 49.8 ms | 21.7 ms | 1.3 ms |

## Per plugin (medians)

**windows**

| plugin | python | vol-rs cold | vol-rs warm | fastvol cold | fastvol steady | fastvol warm | steady vs python |
|---|--:|--:|--:|--:|--:|--:|--:|
| `banners.Banners` | 13.34 s | 355 ms | 361 ms | 155 ms | 153 ms | 0.76 ms | 87.3x |
| `frameworkinfo.FrameworkInfo` | 229 ms | 3.0 ms | 2.6 ms | 0.68 ms | 0.72 ms | 0.62 ms | 319x |
| `isfinfo.IsfInfo` | 230 ms | 2.4 ms | 2.3 ms | 1.3 ms | 1.3 ms | 1.3 ms | 172x |
| `vmscan.Vmscan` | 1.33 s | 2.8 ms | 2.4 ms | 28.2 ms | 27.6 ms | 0.73 ms | 48.2x |
| `windows.amcache.Amcache` | 583 ms | 280 ms | 49.8 ms | 22.1 ms | 0.84 ms | 1.0 ms | 695x |
| `windows.bigpools.BigPools` | 2.79 s | 311 ms | 78.2 ms | 23.4 ms | 2.4 ms | 2.3 ms | 1,169x |
| `windows.cachedump.Cachedump` | 1.28 s | 299 ms | 57.4 ms | 23.4 ms | 1.9 ms | 1.9 ms | 658x |
| `windows.callbacks.Callbacks` | 10.35 s | 1.32 s | 1.11 s | 56.4 ms | 32.3 ms | 3.4 ms | 320x |
| `windows.cmdline.CmdLine` | 656 ms | 295 ms | 54.6 ms | 23.3 ms | 1.9 ms | 2.1 ms | 352x |
| `windows.cmdscan.CmdScan` | 3.47 s | 409 ms | 183 ms | 26.6 ms | 6.1 ms | 2.6 ms | 570x |
| `windows.consoles.Consoles` | 4.82 s | 418 ms | 182 ms | 25.0 ms | 4.2 ms | 4.1 ms | 1,143x |
| `windows.crashinfo.Crashinfo` | 286 ms | 285 ms | 49.2 ms | 0.65 ms | 0.65 ms | 0.53 ms | 443x |
| `windows.debugregisters.DebugRegisters` | 10.58 s | 288 ms | 55.5 ms | 25.9 ms | 5.3 ms | 4.6 ms | 2,004x |
| `windows.deskscan.DeskScan` | 7.54 s | 1.16 s | 912 ms | 55.3 ms | 34.0 ms | 4.1 ms | 221x |
| `windows.desktops.Desktops` | 9.70 s | 1.20 s | 964 ms | 58.3 ms | 35.0 ms | 5.3 ms | 277x |
| `windows.devicetree.DeviceTree` | 7.81 s | 1.17 s | 930 ms | 53.6 ms | 33.3 ms | 2.6 ms | 235x |
| `windows.dlllist.DllList` | 4.43 s | 350 ms | 121 ms | 25.5 ms | 4.0 ms | 3.9 ms | 1,111x |
| `windows.driverirp.DriverIrp` | 8.31 s | 1.15 s | 939 ms | 57.4 ms | 35.9 ms | 5.2 ms | 231x |
| `windows.drivermodule.DriverModule` | 7.97 s | 1.16 s | 939 ms | 55.0 ms | 33.3 ms | 2.6 ms | 239x |
| `windows.driverscan.DriverScan` | 7.87 s | 1.16 s | 950 ms | 55.9 ms | 33.4 ms | 2.3 ms | 236x |
| `windows.dumpfiles.DumpFiles` | 86.28 s | 5.52 s | 4.58 s | 646 ms | 625 ms | 643 ms | 138x |
| `windows.envars.Envars` | 1.06 s | 289 ms | 58.6 ms | 23.7 ms | 2.7 ms | 2.8 ms | 389x |
| `windows.etwpatch.EtwPatch` | 10.19 s | 375 ms | 128 ms | 38.4 ms | 9.3 ms | 8.7 ms | 1,093x |
| `windows.filescan.FileScan` | 14.34 s | 1.24 s | 1.01 s | 59.5 ms | 37.7 ms | 7.8 ms | 381x |
| `windows.getservicesids.GetServiceSIDs` | 1.44 s | 312 ms | 75.3 ms | 23.7 ms | 1.7 ms | 1.6 ms | 846x |
| `windows.getsids.GetSIDs` | 1.78 s | 313 ms | 71.9 ms | 25.1 ms | 3.0 ms | 3.1 ms | 593x |
| `windows.handles.Handles` | 22.73 s | 594 ms | 361 ms | 27.5 ms | 7.0 ms | 6.7 ms | 3,232x |
| `windows.hashdump.Hashdump` | 1.21 s | 290 ms | 56.7 ms | 24.3 ms | 2.0 ms | 1.9 ms | 590x |
| `windows.iat.IAT` | 3.02 s | 327 ms | 91.1 ms | 24.9 ms | 4.2 ms | 4.3 ms | 716x |
| `windows.info.Info` | 466 ms | 278 ms | 48.3 ms | 22.2 ms | 0.99 ms | 1.00 ms | 471x |
| `windows.joblinks.JobLinks` | 707 ms | 288 ms | 55.0 ms | 22.9 ms | 2.1 ms | 2.0 ms | 341x |
| `windows.kpcrs.KPCRs` | 553 ms | 280 ms | 48.2 ms | 22.4 ms | 0.77 ms | 0.67 ms | 717x |
| `windows.lsadump.Lsadump` | 1.28 s | 290 ms | 55.1 ms | 23.6 ms | 2.0 ms | 2.3 ms | 637x |
| `windows.malware.drivermodule.DriverModule` | 7.89 s | 1.15 s | 944 ms | 55.4 ms | 33.8 ms | 2.6 ms | 233x |
| `windows.mbrscan.MBRScan` | 9.40 s | 716 ms | 484 ms | 192 ms | 167 ms | 22.3 ms | 56.2x |
| `windows.modscan.ModScan` | 7.32 s | 1.14 s | 911 ms | 55.1 ms | 32.9 ms | 1.2 ms | 223x |
| `windows.modules.Modules` | 549 ms | 279 ms | 50.7 ms | 22.6 ms | 1.2 ms | 1.2 ms | 472x |
| `windows.mutantscan.MutantScan` | 7.68 s | 1.14 s | 927 ms | 56.3 ms | 33.4 ms | 2.3 ms | 230x |
| `windows.netscan.NetScan` | 10.49 s | 1.16 s | 920 ms | 55.0 ms | 33.0 ms | 1.9 ms | 318x |
| `windows.netstat.NetStat` | 677 ms | 534 ms | 287 ms | 27.9 ms | 1.8 ms | 1.9 ms | 386x |
| `windows.orphan_kernel_threads.Threads` | 9.39 s | 1.16 s | 954 ms | 56.7 ms | 35.1 ms | 3.5 ms | 268x |
| `windows.pe_symbols.PESymbols` | 234 ms | 2.5 ms | 1.8 ms | 0.64 ms | 0.57 ms | 0.58 ms | 412x |
| `windows.poolscanner.PoolScanner` | 21.50 s | 1.52 s | 1.25 s | 61.0 ms | 37.9 ms | 9.4 ms | 568x |
| `windows.privileges.Privs` | 697 ms | 288 ms | 55.2 ms | 23.4 ms | 2.4 ms | 2.1 ms | 293x |
| `windows.pslist.PsList` | 638 ms | 282 ms | 52.5 ms | 23.0 ms | 1.1 ms | 1.3 ms | 596x |
| `windows.psscan.PsScan` | 8.46 s | 1.19 s | 949 ms | 55.6 ms | 33.7 ms | 2.9 ms | 251x |
| `windows.pstree.PsTree` | 767 ms | 309 ms | 56.4 ms | 23.5 ms | 2.1 ms | 2.4 ms | 374x |
| `windows.registry.amcache.Amcache` | 572 ms | 306 ms | 53.0 ms | 23.2 ms | 0.98 ms | 0.87 ms | 584x |
| `windows.registry.cachedump.Cachedump` | 1.26 s | 289 ms | 55.8 ms | 23.9 ms | 1.9 ms | 1.8 ms | 673x |
| `windows.registry.certificates.Certificates` | 2.67 s | 329 ms | 99.4 ms | 22.9 ms | 2.1 ms | 1.9 ms | 1,259x |
| `windows.registry.getcellroutine.GetCellRoutine` | 894 ms | 400 ms | 157 ms | 23.3 ms | 2.2 ms | 1.8 ms | 408x |
| `windows.registry.hashdump.Hashdump` | 1.19 s | 282 ms | 56.1 ms | 23.2 ms | 2.0 ms | 1.9 ms | 592x |
| `windows.registry.hivelist.HiveList` | 570 ms | 276 ms | 47.9 ms | 22.4 ms | 1.0 ms | 1.1 ms | 567x |
| `windows.registry.hivescan.HiveScan` | 1.98 s | 301 ms | 64.6 ms | 23.4 ms | 1.3 ms | 1.3 ms | 1,542x |
| `windows.registry.lsadump.Lsadump` | 1.25 s | 288 ms | 55.5 ms | 24.0 ms | 2.2 ms | 2.2 ms | 572x |
| `windows.registry.printkey.PrintKey` | 1.52 s | 299 ms | 69.0 ms | 24.4 ms | 2.7 ms | 2.7 ms | 558x |
| `windows.registry.scheduled_tasks.ScheduledTasks` | 3.65 s | 338 ms | 95.2 ms | 24.2 ms | 2.4 ms | 2.6 ms | 1,521x |
| `windows.registry.userassist.UserAssist` | 1.08 s | 293 ms | 63.6 ms | 23.5 ms | 1.7 ms | 1.3 ms | 643x |
| `windows.scheduled_tasks.ScheduledTasks` | 3.57 s | 328 ms | 96.4 ms | 23.1 ms | 2.3 ms | 2.4 ms | 1,584x |
| `windows.sessions.Sessions` | 676 ms | 285 ms | 55.6 ms | 23.4 ms | 2.1 ms | 2.1 ms | 329x |
| `windows.shimcachemem.ShimcacheMem` | 918 ms | 288 ms | 55.9 ms | 23.5 ms | 1.5 ms | 1.7 ms | 609x |
| `windows.ssdt.SSDT` | 659 ms | 282 ms | 55.4 ms | 23.8 ms | 2.8 ms | 2.3 ms | 239x |
| `windows.suspended_threads.SuspendedThreads` | 10.95 s | 284 ms | 58.1 ms | 31.7 ms | 5.9 ms | 5.9 ms | 1,867x |
| `windows.symlinkscan.SymlinkScan` | 7.71 s | 1.17 s | 864 ms | 52.9 ms | 30.5 ms | 2.2 ms | 253x |
| `windows.thrdscan.ThrdScan` | 19.06 s | 1.17 s | 960 ms | 55.4 ms | 33.1 ms | 4.6 ms | 576x |
| `windows.threads.Threads` | 10.31 s | 355 ms | 145 ms | 24.8 ms | 4.0 ms | 3.9 ms | 2,597x |
| `windows.timers.Timers` | 969 ms | 270 ms | 53.0 ms | 23.2 ms | 2.4 ms | 2.2 ms | 397x |
| `windows.truecrypt.Passphrase` | 495 ms | 270 ms | 49.0 ms | 21.8 ms | 1.0 ms | 0.87 ms | 490x |
| `windows.unloadedmodules.UnloadedModules` | 466 ms | 262 ms | 49.0 ms | 21.7 ms | 0.87 ms | 0.80 ms | 533x |
| `windows.vadinfo.VadInfo` | 53.32 s | 465 ms | 237 ms | 26.0 ms | 5.2 ms | 5.0 ms | 10,179x |
| `windows.vadwalk.VadWalk` | 10.43 s | 421 ms | 164 ms | 24.1 ms | 3.8 ms | 3.7 ms | 2,747x |
| `windows.verinfo.VerInfo` | 30.14 s | 375 ms | 144 ms | 28.9 ms | 8.3 ms | 8.2 ms | 3,630x |
| `windows.virtmap.VirtMap` | 469 ms | 273 ms | 47.6 ms | 22.0 ms | 0.81 ms | 0.76 ms | 577x |
| `windows.windows.Windows` | 10.22 s | 1.16 s | 918 ms | 55.7 ms | 33.5 ms | 5.8 ms | 305x |
| `windows.windowstations.WindowStations` | 9.74 s | 1.17 s | 919 ms | 55.1 ms | 32.1 ms | 4.0 ms | 304x |
| `windows.statistics.Statistics` | 948 s | 36.76 s | 36.52 s | 23.8 ms | 3.9 ms | 3.9 ms | 240,412x |
| `timeliner.Timeliner` | 819 s | 8.37 s | 7.97 s | 653 ms | 598 ms | 316 ms | 1,370x |

**linux**

| plugin | python | vol-rs cold | vol-rs warm | fastvol cold | fastvol steady | fastvol warm | steady vs python |
|---|--:|--:|--:|--:|--:|--:|--:|
| `banners.Banners` | 12.54 s | 229 ms | 230 ms | 96.5 ms | 96.5 ms | 0.86 ms | 130x |
| `linux.bash.Bash` | 8.77 s | 1.01 s | 106 ms | 57.0 ms | 5.1 ms | 4.1 ms | 1,711x |
| `linux.boottime.Boottime` | 7.00 s | 971 ms | 66.8 ms | 58.6 ms | 1.4 ms | 1.2 ms | 5,087x |
| `linux.capabilities.Capabilities` | 7.12 s | 973 ms | 68.2 ms | 55.6 ms | 2.0 ms | 1.8 ms | 3,517x |
| `linux.check_afinfo.Check_afinfo` | 12.48 s | 1.05 s | 163 ms | 58.3 ms | 2.8 ms | 2.3 ms | 4,394x |
| `linux.check_creds.Check_creds` | 6.98 s | 970 ms | 67.2 ms | 56.9 ms | 1.2 ms | 1.2 ms | 5,903x |
| `linux.check_idt.Check_idt` | 18.27 s | 1.06 s | 161 ms | 58.5 ms | 3.8 ms | 3.3 ms | 4,840x |
| `linux.check_modules.Check_modules` | 7.07 s | 969 ms | 66.1 ms | 58.1 ms | 1.2 ms | 0.93 ms | 5,781x |
| `linux.check_syscall.Check_syscall` | 16.14 s | 1.15 s | 255 ms | 77.8 ms | 7.0 ms | 5.2 ms | 2,319x |
| `linux.ebpf.EBPF` | 6.21 s | 967 ms | 64.9 ms | 57.6 ms | 1.2 ms | 1.0 ms | 5,039x |
| `linux.elfs.Elfs` | 10.16 s | 1.05 s | 144 ms | 60.3 ms | 3.3 ms | 3.0 ms | 3,083x |
| `linux.envars.Envars` | 6.53 s | 975 ms | 70.2 ms | 55.4 ms | 2.1 ms | 1.9 ms | 3,142x |
| `linux.graphics.fbdev.Fbdev` | 5.08 s | 972 ms | 65.8 ms | 56.0 ms | 0.68 ms | 0.86 ms | 7,521x |
| `linux.hidden_modules.Hidden_modules` | 11.52 s | 1.21 s | 294 ms | 56.2 ms | 2.5 ms | 1.8 ms | 4,621x |
| `linux.iomem.IOMem` | 5.43 s | 964 ms | 64.8 ms | 60.0 ms | 1.1 ms | 0.88 ms | 5,078x |
| `linux.ip.Addr` | 6.76 s | 974 ms | 65.7 ms | 58.2 ms | 1.1 ms | 1.1 ms | 5,996x |
| `linux.ip.Link` | 6.66 s | 965 ms | 64.8 ms | 57.4 ms | 1.1 ms | 0.94 ms | 6,070x |
| `linux.kallsyms.Kallsyms` | 49.28 s | 1.48 s | 582 ms | 66.4 ms | 13.9 ms | 15.9 ms | 3,556x |
| `linux.keyboard_notifiers.Keyboard_notifiers` | 11.08 s | 1.06 s | 163 ms | 57.3 ms | 2.6 ms | 2.2 ms | 4,212x |
| `linux.kmsg.Kmsg` | 5.54 s | 976 ms | 70.3 ms | 58.8 ms | 1.6 ms | 1.4 ms | 3,538x |
| `linux.kthreads.Kthreads` | 16.04 s | 1.07 s | 166 ms | 59.7 ms | 5.1 ms | 5.0 ms | 3,169x |
| `linux.library_list.LibraryList` | 47.51 s | 1.04 s | 138 ms | 60.8 ms | 4.0 ms | 3.6 ms | 11,749x |
| `linux.lsmod.Lsmod` | 10.00 s | 979 ms | 66.7 ms | 56.1 ms | 1.5 ms | 1.5 ms | 6,694x |
| `linux.lsof.Lsof` | 11.45 s | 993 ms | 91.4 ms | 58.3 ms | 4.2 ms | 4.2 ms | 2,747x |
| `linux.malfind.Malfind` | 18.70 s | 1.11 s | 216 ms | 58.8 ms | 4.9 ms | 4.5 ms | 3,783x |
| `linux.malware.check_afinfo.Check_afinfo` | 9.72 s | 1.06 s | 165 ms | 55.6 ms | 2.7 ms | 2.3 ms | 3,550x |
| `linux.malware.check_creds.Check_creds` | 5.35 s | 970 ms | 66.9 ms | 59.0 ms | 1.4 ms | 1.3 ms | 3,828x |
| `linux.malware.check_idt.Check_idt` | 15.33 s | 1.06 s | 163 ms | 58.5 ms | 3.7 ms | 3.6 ms | 4,147x |
| `linux.malware.check_modules.Check_modules` | 5.54 s | 973 ms | 66.6 ms | 57.6 ms | 1.1 ms | 1.2 ms | 4,898x |
| `linux.malware.check_syscall.Check_syscall` | 12.37 s | 1.15 s | 259 ms | 73.1 ms | 5.8 ms | 5.3 ms | 2,118x |
| `linux.malware.hidden_modules.Hidden_modules` | 10.02 s | 1.20 s | 303 ms | 56.9 ms | 2.1 ms | 1.9 ms | 4,861x |
| `linux.malware.keyboard_notifiers.Keyboard_notifiers` | 10.20 s | 1.07 s | 163 ms | 57.1 ms | 2.6 ms | 2.3 ms | 3,996x |
| `linux.malware.malfind.Malfind` | 18.07 s | 1.12 s | 216 ms | 55.8 ms | 5.1 ms | 4.7 ms | 3,562x |
| `linux.malware.modxview.Modxview` | 10.61 s | 1.19 s | 288 ms | 58.6 ms | 2.6 ms | 2.2 ms | 4,140x |
| `linux.malware.netfilter.Netfilter` | 21.11 s | 1.06 s | 167 ms | 56.9 ms | 4.2 ms | 3.8 ms | 5,080x |
| `linux.malware.process_spoofing.ProcessSpoofing` | 4.68 s | 967 ms | 69.2 ms | 59.2 ms | 2.1 ms | 2.0 ms | 2,195x |
| `linux.malware.tty_check.Tty_Check` | 16.42 s | 1.07 s | 162 ms | 59.0 ms | 4.5 ms | 4.5 ms | 3,639x |
| `linux.modxview.Modxview` | 11.38 s | 1.19 s | 289 ms | 60.6 ms | 2.4 ms | 2.2 ms | 4,834x |
| `linux.mountinfo.MountInfo` | 6.66 s | 973 ms | 76.3 ms | 56.6 ms | 2.5 ms | 2.2 ms | 2,624x |
| `linux.netfilter.Netfilter` | 21.49 s | 1.06 s | 162 ms | 58.2 ms | 3.9 ms | 3.8 ms | 5,575x |
| `linux.pagecache.Files` | 35.36 s | 1.43 s | 524 ms | 74.6 ms | 12.8 ms | 12.1 ms | 2,759x |
| `linux.pagecache.InodePages` | 4.13 s | 962 ms | 67.1 ms | 58.4 ms | 0.84 ms | 0.78 ms | 4,913x |
| `linux.pidhashtable.PIDHashTable` | 6.20 s | 978 ms | 67.8 ms | 58.4 ms | 1.8 ms | 1.6 ms | 3,475x |
| `linux.proc.Maps` | 19.98 s | 1.14 s | 235 ms | 58.0 ms | 5.4 ms | 4.9 ms | 3,722x |
| `linux.psaux.PsAux` | 6.06 s | 972 ms | 74.3 ms | 56.4 ms | 2.0 ms | 1.9 ms | 3,069x |
| `linux.pslist.PsList` | 5.61 s | 967 ms | 67.7 ms | 57.0 ms | 1.7 ms | 1.4 ms | 3,351x |
| `linux.psscan.PsScan` | 35.30 s | 1.09 s | 258 ms | 155 ms | 106 ms | 7.3 ms | 333x |
| `linux.pstree.PsTree` | 5.65 s | 968 ms | 66.8 ms | 57.4 ms | 1.8 ms | 1.4 ms | 3,116x |
| `linux.ptrace.Ptrace` | 5.78 s | 973 ms | 70.2 ms | 56.0 ms | 1.7 ms | 1.5 ms | 3,387x |
| `linux.sockscan.Sockscan` | 15.98 s | 1.07 s | 219 ms | 155 ms | 103 ms | 3.8 ms | 155x |
| `linux.sockstat.Sockstat` | 12.67 s | 996 ms | 89.5 ms | 57.5 ms | 4.1 ms | 4.4 ms | 3,085x |
| `linux.tracing.ftrace.CheckFtrace` | 16.20 s | 1.06 s | 165 ms | 58.2 ms | 3.9 ms | 4.0 ms | 4,120x |
| `linux.tracing.perf_events.PerfEvents` | 5.15 s | 965 ms | 67.2 ms | 59.1 ms | 1.6 ms | 1.4 ms | 3,143x |
| `linux.tracing.tracepoints.CheckTracepoints` | 16.50 s | 1.06 s | 166 ms | 55.5 ms | 3.3 ms | 3.1 ms | 4,978x |
| `linux.tty_check.tty_check` | 16.33 s | 1.07 s | 162 ms | 60.2 ms | 4.0 ms | 4.0 ms | 4,033x |
| `linux.vmcoreinfo.VMCoreInfo` | 5.01 s | 1.60 s | 754 ms | 161 ms | 104 ms | 0.96 ms | 48.2x |
| `linux.pagecache.RecoverFs` | 423 s | 56.10 s | 56.10 s | 1.61 s | 1.92 s | 1.99 s | 220x |
| `linux.pscallstack.PsCallStack` | 333 s | 1.18 s | 282 ms | 60.1 ms | 4.9 ms | 4.9 ms | 67,714x |
| `timeliner.Timeliner` | 129 s | 1.48 s | 644 ms | 165 ms | 115 ms | 48.7 ms | 1,116x |

Raw data: [raw/raw.jsonl](raw/raw.jsonl) (every run), [raw/machine.json](raw/machine.json), [results.tsv](results.tsv). Harness: `bench/scripts/bench_local.py`; this report: `bench/scripts/bench_local_report.py`.
