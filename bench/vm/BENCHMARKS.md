# rsvol vs vol-rs vs python volatility3 — quiet-VM benchmark

2026-09-26 · dedicated KVM guest: AMD EPYC 7302P (Zen 2) host, 32 vCPU, 30 GiB RAM, Ubuntu 25.04, kernel 6.14.0-37-generic; nothing else running (see [machine.txt](machine.txt), [method.md](method.md)).

- **rsvol** `344e88c` (main), built on the VM: `cargo build --release` (rustc 1.98.1, repo config: `target-cpu=native`, `+crt-static`, fat LTO)
- **vol-rs** 1.0.0: the competitor's own release binary (`4c1076f` + uncommitted working tree of 2026-09-25, sha256 ac1e4ed6…, generic x86-64); a `target-cpu=native` rebuild is checked below
- **python** volatility3 2.28.2 on CPython 3.14.7 (PGO+LTO+BOLT build) with capstone, yara-python, pycryptodome — the reference whose output rsvol reproduces
- Windows image: `memory-dirty.raw`, 5 GiB raw Windows 10 x64 19041; Linux image: `rsvol-noble-6.8.0-139.elf`, 3 GiB, Ubuntu 24.04 kernel 6.8. Both page-cached.

Numbers are wall-clock time of the whole process (`TOOL -q -o DIR -f IMG PLUGIN`, stdout to a file), best of 5 interleaved runs for rsvol and vol-rs, best of 2 for python (1 for statistics, timeliner and the Linux round), each after an untimed warm-up run.

## Windows summary

| all plugins (77 plugins) | python | vol-rs | rsvol |
|---|---:|---:|---:|
| total wall (sum of per-plugin best) | 4078.23 s | 149.69 s | 6.26 s |
| total CPU time (user+sys) | 4076.89 s | 945.58 s | 58.43 s |
| median plugin wall | 4.49 s | 164 ms | 10.4 ms |

- total wall: rsvol is **23.9x faster than vol-rs** and **652x faster than python**
- per-plugin speedup vs vol-rs: median **21.5x**, geometric mean 15.8x, min 0.02x, max 2,547x
- per-plugin speedup vs python: median **283x**, geometric mean 300x, min 6.12x, max 60,675x
- rsvol is the fastest of the three on **76/77** plugins; not on: `vmscan.Vmscan` (rsvol 307 ms vs vol-rs 4.7 ms: vol-rs ships no VMCS ISFs and returns the empty table without reading the image; python and rsvol scan the whole 5 GiB image)
- stdout byte-identical to python's on the VM (after the banner line): rsvol **74/77** (not: `frameworkinfo.FrameworkInfo`, `windows.windows.Windows`, `timeliner.Timeliner`), vol-rs 59/77 — the notes column and Checks explain each of rsvol's

| without statistics / timeliner (75 plugins) | python | vol-rs | rsvol |
|---|---:|---:|---:|
| total wall (sum of per-plugin best) | 922.77 s | 60.22 s | 3.09 s |
| total CPU time (user+sys) | 922.19 s | 689.71 s | 44.12 s |
| median plugin wall | 4.28 s | 142 ms | 10.1 ms |

- total wall: rsvol is **19.5x faster than vol-rs** and **298x faster than python**
- per-plugin speedup vs vol-rs: median **21.5x**, geometric mean 14.9x, min 0.02x, max 95.1x
- per-plugin speedup vs python: median **280x**, geometric mean 278x, min 6.12x, max 3,073x
- rsvol is the fastest of the three on **74/75** plugins; not on: `vmscan.Vmscan` (rsvol 307 ms vs vol-rs 4.7 ms: vol-rs ships no VMCS ISFs and returns the empty table without reading the image; python and rsvol scan the whole 5 GiB image)
- stdout byte-identical to python's on the VM (after the banner line): rsvol **73/75** (not: `frameworkinfo.FrameworkInfo`, `windows.windows.Windows`), vol-rs 58/75 — the notes column and Checks explain each of rsvol's

## Linux summary

| linux plugins (48 plugins) | python | vol-rs | rsvol |
|---|---:|---:|---:|
| total wall (sum of per-plugin best) | 1655.71 s | 15.79 s | 892 ms |
| total CPU time (user+sys) | 1654.85 s | 47.92 s | 11.41 s |
| median plugin wall | 18.03 s | 314 ms | 9.5 ms |

- total wall: rsvol is **17.7x faster than vol-rs** and **1,857x faster than python**
- per-plugin speedup vs vol-rs: median **27.7x**, geometric mean 26.9x, min 3.42x, max 70.6x
- per-plugin speedup vs python: median **2,090x**, geometric mean 1,866x, min 77.4x, max 37,619x
- rsvol is the fastest of the three on **48/48** plugins
- stdout byte-identical to python's on the VM (after the banner line): rsvol **48/48**, vol-rs 38/48
- excluded from these totals: `timeliner.Timeliner` (python 262.11 s, vol-rs 1.23 s, rsvol 140 ms) — not comparable: rsvol does not implement linux.pagecache.Files / linux.lsof.Lsof, which feed python's linux timeline (72k of python's 76k rows)

## Startup: cold vs warm cache (`windows.pslist.PsList`, 5 GiB image)

cold = the tool's own cache directory deleted before every run (the image stays page-cached, the kernel symbol file stays provisioned); warm = the cache written by the previous run. Best of 5 (python: 3), median in parentheses.

| tool | cold | warm |
|---|---:|---:|
| rsvol `344e88c` | 73.1 ms (74.2 ms) | 3.0 ms (3.8 ms) |
| rsvol `123c8d4` | 74.2 ms (74.6 ms) | 3.8 ms (4.9 ms) |
| vol-rs (pass 2) | 573 ms (582 ms) | 86.8 ms (88.0 ms) |
| vol-rs (pass 1) | 565 ms (568 ms) | 83.0 ms (85.4 ms) |
| python (pass 1) | 1.78 s (1.83 s) | 998 ms (1.12 s) |

The cold rsvol run includes decompressing and indexing the 0.6 MB `.json.xz` kernel ISF into its binary ISF cache; vol-rs's cold run reads its 4 MB plain-JSON symbol file; python's cold run rebuilds its identifier cache.

## Windows per-plugin

| plugin | python | vol-rs | rsvol | rsvol vs vol-rs | rsvol vs python | rsvol out = py | vol-rs out = py | note |
|---|---:|---:|---:|---:|---:|:---:|:---:|---|
| banners.Banners | 29.23 s | 622 ms | 182 ms | 3.41x | 160x | yes | yes |  |
| frameworkinfo.FrameworkInfo | 375 ms | 4.2 ms | 1.7 ms | 2.47x | 221x | **no** | **no** | python lists components in the readdir order of its install dir (ext4 here, btrfs where rsvol's references were made); rsvol also leaves out the 10 linux plugins it does not implement |
| isfinfo.IsfInfo | 385 ms | 3.4 ms | 2.4 ms | 1.42x | 160x | yes | **no** |  |
| vmscan.Vmscan | 1.88 s | 4.7 ms | 307 ms | **0.02x** | 6.12x | yes | yes | vol-rs ships no VMCS ISFs and returns the empty table without reading the image; python and rsvol scan the whole 5 GiB image |
| windows.amcache.Amcache | 1.04 s | 84.6 ms | 3.1 ms | 27.3x | 335x | yes | yes |  |
| windows.bigpools.BigPools | 4.49 s | 142 ms | 10.4 ms | 13.7x | 432x | yes | yes |  |
| windows.cachedump.Cachedump | 2.09 s | 92.9 ms | 6.1 ms | 15.2x | 343x | yes | yes |  |
| windows.callbacks.Callbacks | 19.44 s | 2.51 s | 77.6 ms | 32.3x | 250x | yes | yes |  |
| windows.cmdline.CmdLine | 1.23 s | 89.5 ms | 9.3 ms | 9.62x | 132x | yes | yes |  |
| windows.cmdscan.CmdScan | 5.83 s | 356 ms | 21.6 ms | 16.5x | 270x | yes | **no** |  |
| windows.consoles.Consoles | 7.57 s | 356 ms | 18.0 ms | 19.8x | 421x | yes | **no** |  |
| windows.crashinfo.Crashinfo | 432 ms | 78.8 ms | 2.1 ms | 37.5x | 206x | yes | yes | not a crash dump: every tool exits 1 |
| windows.debugregisters.DebugRegisters | 19.12 s | 95.7 ms | 24.1 ms | 3.97x | 793x | yes | yes |  |
| windows.deskscan.DeskScan | 13.77 s | 2.23 s | 76.9 ms | 29.0x | 179x | yes | yes |  |
| windows.desktops.Desktops | 17.25 s | 2.24 s | 81.2 ms | 27.6x | 212x | yes | yes |  |
| windows.devicetree.DeviceTree | 13.84 s | 2.17 s | 77.3 ms | 28.1x | 179x | yes | yes |  |
| windows.dlllist.DllList | 8.46 s | 230 ms | 27.5 ms | 8.37x | 308x | yes | **no** |  |
| windows.driverirp.DriverIrp | 14.82 s | 2.24 s | 79.3 ms | 28.3x | 187x | yes | yes |  |
| windows.drivermodule.DriverModule | 13.73 s | 2.19 s | 77.3 ms | 28.3x | 178x | yes | yes |  |
| windows.driverscan.DriverScan | 14.10 s | 2.16 s | 76.8 ms | 28.2x | 184x | yes | yes |  |
| windows.dumpfiles.DumpFiles | 144.37 s | 7.60 s | 244 ms | 31.1x | 591x | yes | **no** | writes 1.48 GB of files per run (vol-rs: 4.5 GB, different set) |
| windows.envars.Envars | 1.90 s | 100 ms | 11.9 ms | 8.44x | 159x | yes | yes |  |
| windows.etwpatch.EtwPatch | 17.51 s | 220 ms | 44.4 ms | 4.96x | 394x | yes | yes |  |
| windows.filescan.FileScan | 24.59 s | 2.37 s | 88.9 ms | 26.7x | 277x | yes | **no** |  |
| windows.getservicesids.GetServiceSIDs | 2.56 s | 129 ms | 5.0 ms | 25.8x | 511x | yes | yes |  |
| windows.getsids.GetSIDs | 2.80 s | 122 ms | 10.0 ms | 12.1x | 280x | yes | **no** |  |
| windows.handles.Handles | 37.62 s | 656 ms | 60.6 ms | 10.8x | 621x | yes | yes |  |
| windows.hashdump.Hashdump | 1.89 s | 89.4 ms | 6.0 ms | 14.9x | 315x | yes | **no** | exit py/vol-rs/rsvol = 0/1/0 |
| windows.iat.IAT | 4.62 s | 168 ms | 28.8 ms | 5.84x | 160x | yes | yes |  |
| windows.info.Info | 841 ms | 81.3 ms | 2.7 ms | 30.1x | 311x | yes | **no** |  |
| windows.joblinks.JobLinks | 1.14 s | 89.6 ms | 8.3 ms | 10.8x | 137x | yes | yes |  |
| windows.kpcrs.KPCRs | 925 ms | 81.1 ms | 2.4 ms | 33.8x | 385x | yes | yes |  |
| windows.lsadump.Lsadump | 2.12 s | 94.1 ms | 6.0 ms | 15.7x | 354x | yes | **no** |  |
| windows.malware.drivermodule.DriverModule | 14.12 s | 2.15 s | 77.8 ms | 27.7x | 181x | yes | yes |  |
| windows.mbrscan.MBRScan | 16.53 s | 893 ms | 210 ms | 4.25x | 78.6x | yes | **no** |  |
| windows.modscan.ModScan | 13.08 s | 2.18 s | 74.8 ms | 29.2x | 175x | yes | yes |  |
| windows.modules.Modules | 1.01 s | 84.1 ms | 3.7 ms | 22.7x | 273x | yes | yes |  |
| windows.mutantscan.MutantScan | 13.51 s | 2.16 s | 75.5 ms | 28.7x | 179x | yes | yes |  |
| windows.netscan.NetScan | 20.68 s | 2.26 s | 76.5 ms | 29.5x | 270x | yes | yes |  |
| windows.netstat.NetStat | 1.16 s | 561 ms | 5.9 ms | 95.1x | 197x | yes | yes |  |
| windows.orphan_kernel_threads.Threads | 16.71 s | 2.19 s | 78.7 ms | 27.9x | 212x | yes | yes |  |
| windows.pe_symbols.PESymbols | 359 ms | 3.3 ms | 1.4 ms | 2.36x | 256x | yes | yes | exit py/vol-rs/rsvol = 2/1/2; needs arguments: usage error in every tool |
| windows.poolscanner.PoolScanner | 37.30 s | 2.83 s | 95.1 ms | 29.8x | 392x | yes | **no** |  |
| windows.privileges.Privs | 1.33 s | 98.1 ms | 10.1 ms | 9.71x | 132x | yes | yes |  |
| windows.pslist.PsList | 1.17 s | 81.7 ms | 3.8 ms | 21.5x | 309x | yes | yes |  |
| windows.psscan.PsScan | 14.86 s | 2.21 s | 78.1 ms | 28.4x | 190x | yes | yes |  |
| windows.pstree.PsTree | 1.44 s | 94.8 ms | 9.9 ms | 9.58x | 146x | yes | yes |  |
| windows.registry.amcache.Amcache | 1.03 s | 83.9 ms | 3.2 ms | 26.2x | 323x | yes | yes |  |
| windows.registry.cachedump.Cachedump | 1.95 s | 94.8 ms | 6.1 ms | 15.5x | 319x | yes | yes |  |
| windows.registry.certificates.Certificates | 4.28 s | 170 ms | 9.4 ms | 18.1x | 456x | yes | yes |  |
| windows.registry.getcellroutine.GetCellRoutine | 1.36 s | 230 ms | 6.6 ms | 34.8x | 205x | yes | yes |  |
| windows.registry.hashdump.Hashdump | 2.07 s | 90.7 ms | 6.0 ms | 15.1x | 346x | yes | **no** | exit py/vol-rs/rsvol = 0/1/0 |
| windows.registry.hivelist.HiveList | 982 ms | 78.7 ms | 3.1 ms | 25.4x | 317x | yes | yes |  |
| windows.registry.hivescan.HiveScan | 3.29 s | 110 ms | 3.7 ms | 29.9x | 888x | yes | yes |  |
| windows.registry.lsadump.Lsadump | 2.21 s | 93.6 ms | 6.2 ms | 15.1x | 357x | yes | **no** |  |
| windows.registry.printkey.PrintKey | 2.38 s | 117 ms | 8.4 ms | 13.9x | 283x | yes | yes |  |
| windows.registry.scheduled_tasks.ScheduledTasks | 6.14 s | 166 ms | 7.2 ms | 23.0x | 853x | yes | yes |  |
| windows.registry.userassist.UserAssist | 1.85 s | 106 ms | 4.7 ms | 22.5x | 394x | yes | yes |  |
| windows.scheduled_tasks.ScheduledTasks | 6.24 s | 164 ms | 7.1 ms | 23.1x | 879x | yes | yes |  |
| windows.sessions.Sessions | 1.26 s | 94.4 ms | 9.8 ms | 9.63x | 129x | yes | yes |  |
| windows.shimcachemem.ShimcacheMem | 1.63 s | 92.3 ms | 5.2 ms | 17.8x | 314x | yes | yes |  |
| windows.ssdt.SSDT | 1.17 s | 94.9 ms | 6.2 ms | 15.3x | 189x | yes | yes |  |
| windows.suspended_threads.SuspendedThreads | 19.44 s | 104 ms | 36.9 ms | 2.83x | 527x | yes | yes |  |
| windows.symlinkscan.SymlinkScan | 13.13 s | 2.16 s | 75.8 ms | 28.5x | 173x | yes | yes |  |
| windows.thrdscan.ThrdScan | 34.60 s | 2.40 s | 89.5 ms | 26.8x | 387x | yes | yes |  |
| windows.threads.Threads | 18.67 s | 259 ms | 23.3 ms | 11.1x | 801x | yes | yes |  |
| windows.timers.Timers | 1.63 s | 97.9 ms | 7.9 ms | 12.4x | 206x | yes | yes |  |
| windows.truecrypt.Passphrase | 792 ms | 80.5 ms | 2.7 ms | 29.8x | 293x | yes | yes |  |
| windows.unloadedmodules.UnloadedModules | 776 ms | 82.5 ms | 2.6 ms | 31.7x | 298x | yes | yes |  |
| windows.vadinfo.VadInfo | 105.40 s | 449 ms | 34.3 ms | 13.1x | 3,073x | yes | yes |  |
| windows.vadwalk.VadWalk | 19.89 s | 313 ms | 24.4 ms | 12.8x | 815x | yes | yes |  |
| windows.verinfo.VerInfo | 49.59 s | 284 ms | 49.9 ms | 5.69x | 994x | yes | yes |  |
| windows.virtmap.VirtMap | 720 ms | 81.1 ms | 2.4 ms | 33.8x | 300x | yes | yes |  |
| windows.windows.Windows | 17.95 s | 2.30 s | 84.6 ms | 27.2x | 212x | order only | **no** | python's row order is nondeterministic (set iteration); sorted outputs identical |
| windows.windowstations.WindowStations | 17.14 s | 2.30 s | 82.2 ms | 27.9x | 208x | yes | **no** |  |
| windows.statistics.Statistics | 1686.76 s | 70.80 s | 27.8 ms | 2,547x | 60,675x | yes | yes | python's page walk is quadratic (re-walks every valid run per step); rsvol walks each page once |
| timeliner.Timeliner | 1468.70 s | 18.67 s | 3.14 s | 5.95x | 468x | = ref machine | **no** | python's output depends on plugin discovery (readdir) order, see Checks; rsvol's output is byte-identical to python's on the reference machine |

## Linux per-plugin

| plugin | python | vol-rs | rsvol | rsvol vs vol-rs | rsvol vs python | rsvol out = py | vol-rs out = py | note |
|---|---:|---:|---:|---:|---:|:---:|:---:|---|
| banners.Banners | 21.56 s | 397 ms | 114 ms | 3.47x | 188x | yes | yes |  |
| linux.bash.Bash | 10.21 s | 218 ms | 9.9 ms | 22.0x | 1,032x | yes | yes |  |
| linux.boottime.Boottime | 8.00 s | 125 ms | 3.7 ms | 33.8x | 2,161x | yes | yes |  |
| linux.capabilities.Capabilities | 8.21 s | 130 ms | 6.6 ms | 19.6x | 1,243x | yes | yes |  |
| linux.check_afinfo.Check_afinfo | 20.19 s | 351 ms | 5.1 ms | 68.8x | 3,959x | yes | yes |  |
| linux.check_creds.Check_creds | 9.73 s | 134 ms | 3.4 ms | 39.3x | 2,861x | yes | yes |  |
| linux.check_idt.Check_idt | 28.25 s | 332 ms | 12.1 ms | 27.4x | 2,335x | yes | yes |  |
| linux.check_modules.Check_modules | 9.35 s | 125 ms | 3.5 ms | 35.8x | 2,670x | yes | yes |  |
| linux.check_syscall.Check_syscall | 22.01 s | 503 ms | 8.3 ms | 60.6x | 2,652x | yes | yes |  |
| linux.ebpf.EBPF | 8.71 s | 123 ms | 2.5 ms | 49.1x | 3,482x | yes | yes |  |
| linux.elfs.Elfs | 13.57 s | 282 ms | 17.0 ms | 16.6x | 798x | yes | yes |  |
| linux.envars.Envars | 8.11 s | 145 ms | 7.1 ms | 20.4x | 1,142x | yes | yes |  |
| linux.hidden_modules.Hidden_modules | 17.42 s | 594 ms | 8.7 ms | 68.2x | 2,002x | yes | yes |  |
| linux.iomem.IOMem | 9.14 s | 130 ms | 2.2 ms | 59.0x | 4,156x | yes | yes |  |
| linux.kallsyms.Kallsyms | 105.37 s | 1.22 s | 105 ms | 11.6x | 1,005x | yes | **no** | python raises TypeError after 204,803 rows; rsvol reproduces output and exit code |
| linux.keyboard_notifiers.Keyboard_notifiers | 19.50 s | 339 ms | 10.0 ms | 33.9x | 1,950x | yes | **no** |  |
| linux.kmsg.Kmsg | 8.34 s | 135 ms | 4.0 ms | 33.8x | 2,084x | yes | yes |  |
| linux.kthreads.Kthreads | 27.17 s | 316 ms | 31.3 ms | 10.1x | 868x | yes | yes |  |
| linux.library_list.LibraryList | 43.77 s | 277 ms | 18.7 ms | 14.8x | 2,341x | yes | yes |  |
| linux.lsmod.Lsmod | 15.89 s | 132 ms | 3.9 ms | 33.7x | 4,076x | yes | yes |  |
| linux.malfind.Malfind | 31.59 s | 416 ms | 14.9 ms | 27.9x | 2,120x | yes | **no** |  |
| linux.malware.check_afinfo.Check_afinfo | 17.31 s | 339 ms | 6.0 ms | 56.4x | 2,885x | yes | yes |  |
| linux.malware.check_creds.Check_creds | 9.17 s | 126 ms | 3.1 ms | 40.6x | 2,957x | yes | yes |  |
| linux.malware.check_idt.Check_idt | 30.09 s | 311 ms | 12.0 ms | 25.9x | 2,508x | yes | yes |  |
| linux.malware.check_modules.Check_modules | 7.89 s | 125 ms | 3.6 ms | 34.8x | 2,193x | yes | yes |  |
| linux.malware.check_syscall.Check_syscall | 29.14 s | 494 ms | 9.3 ms | 53.2x | 3,133x | yes | yes |  |
| linux.malware.hidden_modules.Hidden_modules | 18.29 s | 607 ms | 8.6 ms | 70.6x | 2,126x | yes | yes |  |
| linux.malware.keyboard_notifiers.Keyboard_notifiers | 19.19 s | 337 ms | 9.8 ms | 34.3x | 1,958x | yes | **no** |  |
| linux.malware.malfind.Malfind | 34.63 s | 416 ms | 14.3 ms | 29.1x | 2,421x | yes | **no** |  |
| linux.malware.modxview.Modxview | 19.57 s | 576 ms | 10.0 ms | 57.6x | 1,957x | yes | yes |  |
| linux.malware.netfilter.Netfilter | 37.23 s | 316 ms | 11.7 ms | 27.0x | 3,182x | yes | **no** |  |
| linux.malware.process_spoofing.ProcessSpoofing | 10.48 s | 131 ms | 7.6 ms | 17.2x | 1,380x | yes | yes |  |
| linux.malware.tty_check.Tty_Check | 27.70 s | 318 ms | 13.4 ms | 23.7x | 2,067x | yes | yes |  |
| linux.modxview.Modxview | 17.77 s | 569 ms | 9.7 ms | 58.6x | 1,832x | yes | yes |  |
| linux.netfilter.Netfilter | 39.74 s | 309 ms | 12.0 ms | 25.7x | 3,312x | yes | **no** |  |
| linux.pidhashtable.PIDHashTable | 10.54 s | 140 ms | 9.4 ms | 14.9x | 1,121x | yes | yes |  |
| linux.proc.Maps | 41.70 s | 449 ms | 17.6 ms | 25.5x | 2,369x | yes | yes |  |
| linux.psaux.PsAux | 8.90 s | 138 ms | 7.9 ms | 17.5x | 1,126x | yes | yes |  |
| linux.pslist.PsList | 10.59 s | 132 ms | 4.5 ms | 29.4x | 2,353x | yes | yes |  |
| linux.psscan.PsScan | 58.63 s | 478 ms | 140 ms | 3.42x | 420x | yes | yes |  |
| linux.pstree.PsTree | 8.89 s | 126 ms | 4.7 ms | 26.8x | 1,892x | yes | yes |  |
| linux.ptrace.Ptrace | 8.54 s | 131 ms | 6.5 ms | 20.2x | 1,314x | yes | **no** |  |
| linux.tracing.ftrace.CheckFtrace | 25.89 s | 312 ms | 12.9 ms | 24.2x | 2,007x | yes | yes |  |
| linux.tracing.perf_events.PerfEvents | 8.22 s | 130 ms | 4.2 ms | 30.9x | 1,956x | yes | **no** |  |
| linux.tracing.tracepoints.CheckTracepoints | 25.14 s | 315 ms | 12.0 ms | 26.3x | 2,095x | yes | **no** |  |
| linux.tty_check.tty_check | 24.36 s | 319 ms | 12.5 ms | 25.5x | 1,948x | yes | yes |  |
| linux.vmcoreinfo.VMCoreInfo | 9.23 s | 1.19 s | 119 ms | 9.99x | 77.4x | yes | yes |  |
| linux.pscallstack.PsCallStack | 650.81 s | 533 ms | 17.3 ms | 30.8x | 37,619x | yes | yes |  |
| timeliner.Timeliner | 262.11 s | 1.23 s | 140 ms | 8.81x | 1,874x | **no** | **no** | not comparable: rsvol does not implement linux.pagecache.Files / linux.lsof.Lsof, which feed python's linux timeline (72k of python's 76k rows) |

## Checks

- **Run-to-run stability.** vol-rs (same binary) was timed in both Windows passes, ~1.5 h apart: pass-2/pass-1 ratio median 0.995, 10th-90th percentile 0.957–1.020. Within a pass, rsvol's median-of-5 is 1.03x its best (median over plugins), vol-rs's 1.03x.
- **rsvol `123c8d4` (pass 1)** total 6.29 s vs 6.26 s for `344e88c`; per-plugin numbers of both are in results.tsv.
- **vol-rs rebuilt with `target-cpu=native`** (pass 3, interleaved with rsvol again): total 144.77 s vs 149.69 s for the release binary, per-plugin ratio median 0.982 (10th-90th percentile 0.950–1.006); rsvol is faster than the native vol-rs on 76/77 plugins (not: `vmscan.Vmscan`).
- **Output equality details.**
  - `windows.windows.Windows`: python iterates a set, so its row order changes run to run; rsvol's and python's
    outputs on the VM are identical after sorting.
  - `timeliner.Timeliner` (Windows): python's `Timeliner._generator` re-appends *every* entry accumulated so far
    after each plugin it runs (with the stale `times` of the last row), so its row count and content depend on the
    order in which plugins are discovered, i.e. the readdir order of the `volatility3/plugins` tree. On the VM (ext4)
    python printed 3,460,648 lines; on the machine where rsvol's references were made (btrfs) it printed 2,842,936.
    rsvol's output on the VM is byte-identical (sha256 `3984c9cd…`) to that reference output. The same readdir-order
    effect explains `frameworkinfo` (sorted, python's lists are identical on both machines).
  - `windows.dumpfiles.DumpFiles`: besides the listing, the 1,630 dumped files (1.48 GB) were compared: same names,
    same contents (sha256 of every file), same 0600 mode as python's.
  - Before settling on CPython 3.14.7, Ubuntu's CPython 3.13.3 was tried for the sanity check: python's own output then
    differs from its 3.14 output (`dlllist` prints year 144 as `144`, 3.14 as `0144`), so the reference interpreter
    matters; 3.14.7 is what rsvol's golden outputs were made with.

