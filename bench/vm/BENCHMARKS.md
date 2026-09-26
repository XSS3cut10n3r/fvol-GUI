# rsvol vs vol-rs vs python volatility3 — quiet-VM benchmark (final)

2026-09-26 · dedicated KVM guest: AMD EPYC 7302P (Zen 2) host, 32 vCPU, 30 GiB RAM, Ubuntu 25.04, kernel 6.14.0-37-generic; nothing else running (see [machine.txt](machine.txt), [method.md](method.md)).

- **rsvol** `95528b2` (main HEAD), built on the VM: `cargo build --release` (rustc 1.98.1, repo config: `target-cpu=native`, `+crt-static`, fat LTO); binary sha256 `23a71a59…`
- **vol-rs** 1.0.0: the competitor's own release binary (`4c1076f` + uncommitted working tree of 2026-09-25, sha256 ac1e4ed6…, generic x86-64; a `target-cpu=native` rebuild of it was 2% faster per plugin (median) in run 1)
- **python** volatility3 2.28.2 on CPython 3.14.7 (PGO+LTO+BOLT build) with capstone, yara-python, pycryptodome: the reference whose output rsvol reproduces. Its times and output hashes are reused from run 1 (same image, same python, same VM); † marks plugins python was run for again in run 2.
- Windows image: `memory-dirty.raw`, 5 GiB raw Windows 11 21H2 x64 (build 22000, `windows.info`: 15.22000); Linux image: `rsvol-noble-6.8.0-139.elf`, 3 GiB, Ubuntu 24.04 kernel 6.8 (`-s` holding only its `.json.xz` ISF). Both page-cached.
- Plugins: rsvol implements all 197 plugins of volatility3 2.28.2. Windows round: the same 77 plugins as run 1 (generic + Windows, `statistics` and `timeliner` last); Linux round: 59 = every `linux.*` plugin that runs without arguments (57 of 60; not `vmayarascan`, `vmaregexscan`, `module_extract`) + `banners` + `timeliner`, which now includes the lsof / pagecache rows exactly like python's timeline.

Every number is the wall-clock time of a whole process (`TOOL -q -o DIR -f IMG PLUGIN`, stdout to a file), best of 5 interleaved runs for each rsvol and vol-rs column, best of 2 runs for python on Windows (1 for statistics, timeliner and on Linux). The columns:

| column | cache state before every timed run |
|---|---|
| **rsvol cold** | rsvol's whole cache directory (`RSVOL_CACHE`) deleted: binary symbol tables, identifier index, automagic results, scan results — the first-ever run of rsvol on this image |
| **rsvol steady** | symbol-table / identifier / automagic caches warm, the per-image scan cache disabled (`RSVOL_NO_SCAN_CACHE=1`): the honest cost of a plugin's own work, every scan really done |
| **rsvol warm** | every cache warm, incl. the scan cache: what a user sees on the 2nd+ run of a plugin |
| **vol-rs cold** | `$XDG_CACHE_HOME/vol-rs` deleted (its parsed symbol files, per-image automagic results and banner index), except the PDB it downloaded from the Microsoft symbol server (so no timed run touches the network) |
| **vol-rs warm** | vol-rs's cache as its previous run left it (vol-rs has no scan-result cache) |
| **python** | run 1's warm runs (identifier cache warm) |

rsvol steady and rsvol warm are compared with vol-rs warm, rsvol cold with vol-rs cold (like for like); "fastest on" for an rsvol column counts the plugins where it beats python and **both** vol-rs columns. The fastest number of each row is bold in the per-plugin tables.

## Headline

| Windows (77 plugins) | python | vol-rs cold | vol-rs warm | rsvol cold | rsvol steady | rsvol warm |
|---|---:|---:|---:|---:|---:|---:|
| total wall (sum of per-plugin best) | 4078.23 s | 183.76 s | 148.61 s | 8.82 s | 4.43 s | 2.18 s |
| total CPU (user+sys) | 4076.88 s | 976.28 s | 939.22 s | 85.14 s | 57.93 s | 9.05 s |
| median plugin wall | 4.49 s | 624 ms | 164 ms | 68.6 ms | 10.2 ms | 8.6 ms |
| geometric mean plugin wall | 5.36 s | 800 ms | 283 ms | 77.4 ms | 17.6 ms | 9.6 ms |
| fastest on¹ | 0/77 | 1/77 | 1/77 | **75/77** | **76/77** | **76/77** |
| faster than the like-for-like vol-rs column on |  |  |  | 76/77 vs vol-rs cold | 76/77 vs vol-rs warm | 76/77 vs vol-rs warm |
| speedup vs like-for-like vol-rs: total / geo-mean |  |  |  | 20.8x / 10.3x | 33.5x / 16.0x | 68.1x / 29.4x |
| speedup vs python: total / geo-mean |  |  |  | 463x / 69.2x | 920x / 304x | 1,869x / 557x |

| Linux (59 plugins) | python | vol-rs cold | vol-rs warm | rsvol cold | rsvol steady | rsvol warm |
|---|---:|---:|---:|---:|---:|---:|
| total wall (sum of per-plugin best) | 2804.03 s | 217.20 s | 105.23 s | 35.38 s | 4.80 s | 4.42 s |
| total CPU (user+sys) | 2802.62 s | 682.84 s | 144.10 s | 164.29 s | 65.81 s | 52.78 s |
| median plugin wall | 18.28 s | 2.23 s | 311 ms | 541 ms | 10.1 ms | 9.8 ms |
| geometric mean plugin wall | 20.00 s | 2.34 s | 288 ms | 553 ms | 11.8 ms | 10.0 ms |
| fastest on¹ | 0/59 | 0/59 | 0/59 | **10/59** | **59/59** | **59/59** |
| faster than the like-for-like vol-rs column on |  |  |  | 59/59 vs vol-rs cold | 59/59 vs vol-rs warm | 59/59 vs vol-rs warm |
| speedup vs like-for-like vol-rs: total / geo-mean |  |  |  | 6.14x / 4.23x | 21.9x / 24.4x | 23.8x / 29.0x |
| speedup vs python: total / geo-mean |  |  |  | 79.3x / 36.1x | 584x / 1,690x | 635x / 2,009x |

¹ for an rsvol column: the plugins where it beats python and both vol-rs columns; for vol-rs and python: the plugins where that column beats all three rsvol columns and the remaining tool.

Where an rsvol column is not the fastest number of its row:

- `vmscan.Vmscan` (all three rsvol columns): vol-rs ships no VMCS ISFs, so it prints the empty table in
  4 ms without reading the image; python and rsvol scan the whole 5 GiB image for VMCS page starts
  (rsvol steady 311 ms, rsvol warm 15 ms replaying its cached hits). Same output in all three tools.
- `windows.suspended_threads.SuspendedThreads` (rsvol cold only): 107 ms vs vol-rs warm 103 ms; the
  cold run is ~65 ms of first-run symbol-table building plus the plugin's 38 ms (rsvol steady).
- Linux, rsvol cold only (49 of 59 plugins): a first-ever rsvol run spends ~0.53 s indexing and
  converting the 3.3 MB `.json.xz` kernel ISF (64 MB of JSON), so it loses to vol-rs *warm* (0.12-0.53 s)
  on the plugins that are cheap once the symbols are loaded; it beats vol-rs cold (2.0-3.2 s; banners 0.4 s, RecoverFs 87 s) on all 59,
  and rsvol steady / warm are the fastest on all 59 (see Checks).
  **Since then** a first run loads big ISFs lazily and writes their binary tables in a detached
  helper after the output: rsvol cold now beats vol-rs warm on all 59 Linux plugins (total
  34.19 s -> 10.83 s, median 517 -> 110 ms; see [First runs with lazy symbol tables](#first-runs-with-lazy-symbol-tables-rsvol-cold-rerun)).

## Windows summary

- **rsvol cold** vs vol-rs cold: median 9.01x, geo-mean 10.3x, min 0.01x, max 849x; vs python: median 92.9x, geo-mean 69.2x, min 6.57x, max 19,985x
- **rsvol steady** vs vol-rs warm: median 21.8x, geo-mean 16.0x, min 0.01x, max 2,737x; vs python: median 279x, geo-mean 304x, min 6.04x, max 65,889x
- **rsvol warm** vs vol-rs warm: median 25.1x, geo-mean 29.4x, min 0.27x, max 2,747x; vs python: median 443x, geo-mean 557x, min 125x, max 66,148x
- rsvol cold is not the fastest on 2: `vmscan.Vmscan` (286 ms vs vol-rs warm 4.1 ms), `windows.suspended_threads.SuspendedThreads` (107 ms vs vol-rs warm 103 ms)
- rsvol steady is not the fastest on 1: `vmscan.Vmscan` (311 ms vs vol-rs warm 4.1 ms)
- rsvol warm is not the fastest on 1: `vmscan.Vmscan` (15.0 ms vs vol-rs warm 4.1 ms)
- rsvol stdout byte-identical to python's (after the banner line) in every run of all three columns: **74/77** (the others: `frameworkinfo.FrameworkInfo` sorted =, `windows.windows.Windows` sorted =, `timeliner.Timeliner` = ref machine, see Checks); vol-rs (both columns): 59/77
- the three rsvol columns printed the same stdout in all their runs on 77/77 plugins (the caches never change output)

| Windows without statistics / timeliner (75 plugins) | python | vol-rs cold | vol-rs warm | rsvol cold | rsvol steady | rsvol warm |
|---|---:|---:|---:|---:|---:|---:|
| total wall (sum of per-plugin best) | 922.77 s | 92.77 s | 59.90 s | 7.14 s | 3.10 s | 1.24 s |
| total CPU (user+sys) | 922.18 s | 716.26 s | 684.39 s | 62.41 s | 44.26 s | 4.58 s |
| median plugin wall | 4.28 s | 616 ms | 139 ms | 68.5 ms | 10.1 ms | 8.6 ms |
| geometric mean plugin wall | 4.61 s | 722 ms | 248 ms | 74.3 ms | 16.6 ms | 8.9 ms |
| fastest on¹ | 0/75 | 1/75 | 1/75 | **73/75** | **74/75** | **74/75** |
| faster than the like-for-like vol-rs column on |  |  |  | 74/75 vs vol-rs cold | 74/75 vs vol-rs warm | 74/75 vs vol-rs warm |
| speedup vs like-for-like vol-rs: total / geo-mean |  |  |  | 13.0x / 9.73x | 19.3x / 15.0x | 48.2x / 27.8x |
| speedup vs python: total / geo-mean |  |  |  | 129x / 62.0x | 298x / 278x | 743x / 516x |

## Linux summary

- **rsvol cold** vs vol-rs cold: median 4.09x, geo-mean 4.23x, min 3.42x, max 22.3x; vs python: median 33.5x, geo-mean 36.1x, min 11.5x, max 1,185x
- **rsvol steady** vs vol-rs warm: median 26.0x, geo-mean 24.4x, min 3.35x, max 70.1x; vs python: median 1,977x, geo-mean 1,690x, min 75.9x, max 37,403x
- **rsvol warm** vs vol-rs warm: median 29.5x, geo-mean 29.0x, min 9.72x, max 158x; vs python: median 2,179x, geo-mean 2,009x, min 76.4x, max 34,990x
- rsvol cold is not the fastest on 49 (behind vol-rs warm by 14.7 ms to 432 ms, median 362 ms; every plugin is in the per-plugin table)
- rsvol steady is the fastest on every plugin
- rsvol warm is the fastest on every plugin
- rsvol stdout byte-identical to python's (after the banner line) in every run of all three columns: **58/59** (the others: `timeliner.Timeliner` = ref machine, see Checks); vol-rs (both columns): 45/59
- the three rsvol columns printed the same stdout in all their runs on 59/59 plugins (the caches never change output)

## Startup: cold vs warm cache (`windows.pslist.PsList`, 5 GiB image)

cold = the tool's own cache deleted before every run (rsvol: its whole cache directory; vol-rs: `$XDG_CACHE_HOME/vol-rs` except downloaded PDBs; python: `identifier.cache` + `data_*.cache`); the image stays page-cached and the kernel symbol file provisioned. warm = the cache written by the previous run. Best of 5 (python: 3), median in parentheses.

| tool | cold | warm |
|---|---:|---:|
| rsvol `95528b2` | 64.7 ms (66.8 ms) | 3.3 ms (3.6 ms) |
| vol-rs | 563 ms (567 ms) | 80.6 ms (85.5 ms) |
| python | 1.87 s (1.97 s) | 1.20 s (1.20 s) |
| run 1: rsvol `344e88c` | 73.1 ms (74.2 ms) | 3.0 ms (3.8 ms) |
| run 1: vol-rs | 565 ms (568 ms) | 83.0 ms (85.4 ms) |
| run 1: python | 1.78 s (1.83 s) | 998 ms (1.12 s) |

rsvol's cold start is building its binary symbol table from the 0.6 MB `.json.xz` kernel ISF (read +
xz decode 34 ms, parse + build 16 ms; the cache file is written by a background thread joined before
exit; `RSVOL_TRACE=1`); vol-rs's cold start parses its 4 MB plain-JSON symbol file; python's rebuilds
its identifier cache. Python's warm best is 1.20 s here vs 1.00 s in run 1 (run 1's three warm runs
spread from 1.00 to 1.21 s, run 2's from 1.203 to 1.206 s).

## First runs with lazy symbol tables (rsvol cold, rerun)

2026-09-26, same VM, images and vol-rs binary as above. **before** = rsvol main `342a0c6`, **after** =
the lazy-symbol-table branch (`718b5e9`), both built on the VM with rustc 1.98.1. Every run is
`vol -q -o <fresh dir> -f IMG [-s ~/rsvol-bench/isf] PLUGIN` with rsvol's whole cache directory deleted
before the run (a first-ever run; python's identifier cache present, as for the cold column above),
best of 5, the two builds interleaved; rsvol's detached blob helper is waited for between runs
(untimed). vol-rs warm / cold are the numbers of the per-plugin tables above (same binary and VM).

What changed: a first run no longer builds the 64 MB kernel ISF's binary table before the plugin
runs. It indexes the JSON (~33 ms on this VM for the noble ISF, vs ~150 ms for the full build),
resolves only the types and symbols the plugin touches, and hands the full table to a detached
helper process after the output; the kernel ISF is decompressed while the image is scanned, and
the VMCOREINFO note search stops at the deciding note (see docs/architecture.md, Symbols).

| Linux (59 plugins) | rsvol cold before | rsvol cold after | rsvol warm | vol-rs warm | vol-rs cold |
|---|---:|---:|---:|---:|---:|
| total wall (sum of per-plugin best) | 34.19 s | 10.83 s | 4.24 s | 105.23 s | 217.20 s |
| median plugin wall | 517 ms | 110 ms | | 311 ms | 2.23 s |
| geometric mean plugin wall | 533 ms | 127 ms | | 288 ms | 2.34 s |
| rsvol cold faster than vol-rs warm on | 11/59 | **59/59** | | | |

The closest row is `linux.pagecache.InodePages`: 106.9 ms cold vs vol-rs warm 124.5 ms. All 59
plugins printed the same output before and after (sha256 of stdout minus the banner, every run).

Where the blob of a lazily loaded table is written, measured (cold run, best of 7):

| | noble `linux.pslist` | `windows.pslist` |
|---|---:|---:|
| detached helper after the output (the default) | 130.8 ms | 46.5 ms |
| no blob at all (`RSVOL_DEFERRED_ISFB=off`) | 132.9 ms | 45.3 ms |
| a thread of the run, joined before exit (`=thread`) | 278.7 ms | 68.9 ms |
| full table before the plugin (`RSVOL_LAZY_ISF=0`) | 369.2 ms | 61.3 ms |

Cache states (coldbench.py modes, best of 5): cold = empty cache; newimg = symbol tables warm,
automagic and scan caches empty (a new image); symcold = automagic warm, symbol tables empty;
warm = everything cached.

| case | before: cold | newimg | symcold | warm | after: cold | newimg | symcold | warm | vol-rs cold | vol-rs warm |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `windows.pslist` | 62.4 ms | 6.1 ms | 58.4 ms | 3.6 ms | 49.5 ms | 6.3 ms | 46.5 ms | 3.7 ms | 551 ms | 83.8 ms |
| `windows.info` | 61.6 ms | 5.3 ms | 59.8 ms | 2.7 ms | 49.0 ms | 5.1 ms | 44.2 ms | 2.4 ms | 556 ms | 80.7 ms |
| `windows.netscan` | 135 ms | 87.1 ms | 58.5 ms | 5.8 ms | 128 ms | 85.4 ms | 49.8 ms | 6.0 ms | 2.60 s | 2.21 s |
| `windows.handles` | 107 ms | 61.8 ms | 109 ms | 60.6 ms | 102 ms | 59.4 ms | 105 ms | 55.6 ms | 1.09 s | 620 ms |
| `linux.pslist` | 512 ms | 45.5 ms | 236 ms | 4.8 ms | 126 ms | 20.6 ms | 108 ms | 4.7 ms | 2.04 s | 132 ms |
| `linux.psscan` | 615 ms | 183 ms | 235 ms | 31.3 ms | 268 ms | 146 ms | 132 ms | 20.0 ms | 2.30 s | 473 ms |
| `linux.kallsyms` | 572 ms | 128 ms | 290 ms | 88.8 ms | 206 ms | 98.8 ms | 182 ms | 84.5 ms | 2.90 s | 968 ms |
| `linux.lsof` | 508 ms | 50.5 ms | 235 ms | 12.3 ms | 132 ms | 27.8 ms | 113 ms | 13.8 ms | 2.16 s | 183 ms |

(This table is the `5846095` build; the per-plugin run above is `718b5e9`, which also reads the
kernel ISF's identifier from its lazy table and drops a 64 MB memset: `linux.pslist` cold 126 ->
107 ms.)

Per plugin (Linux):

|---|---:|---:|---:|---:|---:|
| banners.Banners | 125.0 ms | 125.2 ms | 2.3 ms | 394.6 ms | 397.6 ms |
| linux.bash.Bash | 515.6 ms | 115.7 ms | 10.3 ms | 209.4 ms | 2.21 s |
| linux.boottime.Boottime | 517.0 ms | 109.0 ms | 3.7 ms | 132.0 ms | 2.09 s |
| linux.capabilities.Capabilities | 511.0 ms | 109.7 ms | 6.5 ms | 130.3 ms | 2.07 s |
| linux.check_afinfo.Check_afinfo | 529.0 ms | 105.4 ms | 5.5 ms | 322.1 ms | 2.26 s |
| linux.check_creds.Check_creds | 507.6 ms | 104.0 ms | 3.6 ms | 129.3 ms | 2.09 s |
| linux.check_idt.Check_idt | 534.4 ms | 107.7 ms | 12.3 ms | 313.0 ms | 2.31 s |
| linux.check_modules.Check_modules | 535.7 ms | 106.2 ms | 3.7 ms | 126.1 ms | 2.08 s |
| linux.check_syscall.Check_syscall | 513.7 ms | 122.8 ms | 10.5 ms | 494.3 ms | 2.43 s |
| linux.ebpf.EBPF | 502.0 ms | 107.0 ms | 2.9 ms | 136.6 ms | 2.04 s |
| linux.elfs.Elfs | 529.0 ms | 119.0 ms | 16.7 ms | 278.5 ms | 2.28 s |
| linux.envars.Envars | 509.4 ms | 107.1 ms | 7.1 ms | 135.1 ms | 2.08 s |
| linux.graphics.fbdev.Fbdev | 508.8 ms | 103.6 ms | 2.4 ms | 123.3 ms | 2.11 s |
| linux.hidden_modules.Hidden_modules | 517.5 ms | 107.5 ms | 7.9 ms | 588.7 ms | 2.51 s |
| linux.iomem.IOMem | 512.3 ms | 103.1 ms | 2.7 ms | 123.3 ms | 2.07 s |
| linux.ip.Addr | 525.8 ms | 106.7 ms | 2.8 ms | 124.9 ms | 2.06 s |
| linux.ip.Link | 510.7 ms | 102.8 ms | 2.7 ms | 125.2 ms | 2.06 s |
| linux.kallsyms.Kallsyms | 586.6 ms | 199.3 ms | 94.9 ms | 1.17 s | 3.17 s |
| linux.keyboard_notifiers.Keyboard_notifiers | 516.2 ms | 106.1 ms | 9.1 ms | 318.4 ms | 2.25 s |
| linux.kmsg.Kmsg | 509.2 ms | 109.0 ms | 4.3 ms | 135.1 ms | 2.08 s |
| linux.kthreads.Kthreads | 511.4 ms | 135.0 ms | 33.4 ms | 328.5 ms | 2.26 s |
| linux.library_list.LibraryList | 525.5 ms | 123.5 ms | 17.6 ms | 270.7 ms | 2.21 s |
| linux.lsmod.Lsmod | 511.3 ms | 107.0 ms | 3.9 ms | 129.3 ms | 2.11 s |
| linux.lsof.Lsof | 517.0 ms | 114.9 ms | 12.6 ms | 178.8 ms | 2.14 s |
| linux.malfind.Malfind | 516.2 ms | 116.1 ms | 14.4 ms | 431.2 ms | 2.38 s |
| linux.malware.check_afinfo.Check_afinfo | 516.7 ms | 106.2 ms | 5.4 ms | 313.1 ms | 2.26 s |
| linux.malware.check_creds.Check_creds | 515.7 ms | 108.1 ms | 3.8 ms | 130.9 ms | 2.03 s |
| linux.malware.check_idt.Check_idt | 526.3 ms | 111.0 ms | 11.7 ms | 312.9 ms | 2.31 s |
| linux.malware.check_modules.Check_modules | 531.4 ms | 104.9 ms | 4.0 ms | 126.4 ms | 2.19 s |
| linux.malware.check_syscall.Check_syscall | 522.7 ms | 127.5 ms | 10.8 ms | 512.3 ms | 2.53 s |
| linux.malware.hidden_modules.Hidden_modules | 515.0 ms | 110.6 ms | 8.2 ms | 584.6 ms | 2.50 s |
| linux.malware.keyboard_notifiers.Keyboard_notifiers | 525.8 ms | 110.2 ms | 9.7 ms | 314.6 ms | 2.27 s |
| linux.malware.malfind.Malfind | 518.5 ms | 113.2 ms | 14.1 ms | 416.4 ms | 2.50 s |
| linux.malware.modxview.Modxview | 517.1 ms | 109.7 ms | 9.0 ms | 567.7 ms | 2.50 s |
| linux.malware.netfilter.Netfilter | 517.0 ms | 110.3 ms | 12.2 ms | 310.5 ms | 2.23 s |
| linux.malware.process_spoofing.ProcessSpoofing | 526.0 ms | 106.0 ms | 7.4 ms | 135.8 ms | 2.08 s |
| linux.malware.tty_check.Tty_Check | 521.2 ms | 113.3 ms | 12.2 ms | 311.1 ms | 2.27 s |
| linux.modxview.Modxview | 524.7 ms | 108.0 ms | 9.2 ms | 579.9 ms | 2.48 s |
| linux.mountinfo.MountInfo | 513.5 ms | 112.8 ms | 13.2 ms | 151.1 ms | 2.06 s |
| linux.netfilter.Netfilter | 529.6 ms | 111.0 ms | 12.2 ms | 322.5 ms | 2.28 s |
| linux.pagecache.Files | 559.8 ms | 182.2 ms | 81.0 ms | 1.01 s | 2.95 s |
| linux.pagecache.InodePages | 516.4 ms | 106.9 ms | 2.3 ms | 124.5 ms | 2.13 s |
| linux.pidhashtable.PIDHashTable | 534.4 ms | 115.6 ms | 8.3 ms | 136.4 ms | 2.06 s |
| linux.proc.Maps | 523.2 ms | 117.5 ms | 16.6 ms | 449.4 ms | 2.40 s |
| linux.psaux.PsAux | 524.6 ms | 107.1 ms | 7.1 ms | 132.0 ms | 2.08 s |
| linux.pslist.PsList | 515.2 ms | 106.7 ms | 4.7 ms | 131.5 ms | 2.08 s |
| linux.psscan.PsScan | 632.2 ms | 251.1 ms | 20.4 ms | 486.2 ms | 2.39 s |
| linux.pstree.PsTree | 515.7 ms | 108.1 ms | 4.8 ms | 130.6 ms | 2.10 s |
| linux.ptrace.Ptrace | 510.5 ms | 109.1 ms | 5.9 ms | 138.2 ms | 2.10 s |
| linux.sockscan.Sockscan | 615.8 ms | 221.1 ms | 10.1 ms | 425.0 ms | 2.22 s |
| linux.sockstat.Sockstat | 514.4 ms | 111.2 ms | 12.1 ms | 182.6 ms | 2.09 s |
| linux.tracing.ftrace.CheckFtrace | 512.2 ms | 110.1 ms | 11.7 ms | 314.6 ms | 2.26 s |
| linux.tracing.perf_events.PerfEvents | 506.2 ms | 106.4 ms | 4.4 ms | 130.0 ms | 2.18 s |
| linux.tracing.tracepoints.CheckTracepoints | 522.3 ms | 115.4 ms | 12.2 ms | 331.7 ms | 2.27 s |
| linux.tty_check.tty_check | 538.5 ms | 112.2 ms | 12.5 ms | 313.7 ms | 2.23 s |
| linux.vmcoreinfo.VMCoreInfo | 617.8 ms | 229.3 ms | 2.7 ms | 1.21 s | 3.05 s |
| linux.pagecache.RecoverFs | 3.94 s | 3.57 s | 3.44 s | 85.86 s | 86.71 s |
| linux.pscallstack.PsCallStack | 524.2 ms | 116.6 ms | 17.9 ms | 534.6 ms | 2.51 s |
| timeliner.Timeliner | 653.3 ms | 394.9 ms | 123.2 ms | 1.24 s | 3.13 s |

## Windows per-plugin

| plugin | python | vol-rs cold | vol-rs warm | rsvol cold | rsvol steady | rsvol warm | steady vs vol-rs warm | rsvol out = py | vol-rs out = py | note |
|---|---:|---:|---:|---:|---:|---:|---:|:---:|:---:|---|
| banners.Banners | 29.23 s | 624 ms | 626 ms | 184 ms | 183 ms | **2.3 ms** | 3.42x | yes | yes | warm: rsvol replays the cached hits of its whole-image banner scan |
| frameworkinfo.FrameworkInfo | 383 ms† | 5.0 ms | 3.8 ms | 1.6 ms | **1.5 ms** | 1.7 ms | 2.53x | sorted = | **no** | python lists components in the readdir order of its install dir (ext4 here, btrfs on the reference machine): sorted outputs identical, and rsvol's output is byte-identical to python's on the reference machine |
| isfinfo.IsfInfo | 374 ms† | 3.8 ms | 3.7 ms | 3.1 ms | 2.9 ms | **2.8 ms** | 1.28x | yes | **no** |  |
| vmscan.Vmscan | 1.88 s | **4.1 ms** | **4.1 ms** | 286 ms | 311 ms | 15.0 ms | **0.01x** | yes | yes | vol-rs ships no VMCS ISFs and returns the empty table without reading the image; python and rsvol scan the whole 5 GiB image (rsvol warm: from its scan cache) |
| windows.amcache.Amcache | 1.04 s | 561 ms | 84.7 ms | 66.2 ms | 3.2 ms | **2.7 ms** | 26.5x | yes | yes |  |
| windows.bigpools.BigPools | 4.49 s | 616 ms | 139 ms | 66.5 ms | 10.1 ms | **9.2 ms** | 13.8x | yes | yes |  |
| windows.cachedump.Cachedump | 2.09 s | 565 ms | 96.8 ms | 63.8 ms | 6.5 ms | **5.9 ms** | 14.9x | yes | yes |  |
| windows.callbacks.Callbacks | 19.44 s | 2.96 s | 2.45 s | 131 ms | 78.4 ms | **8.6 ms** | 31.2x | yes | yes |  |
| windows.cmdline.CmdLine | 1.23 s | 559 ms | 91.1 ms | 67.2 ms | 9.7 ms | **9.1 ms** | 9.39x | yes | yes |  |
| windows.cmdscan.CmdScan | 5.83 s | 833 ms | 360 ms | 77.7 ms | 19.7 ms | **16.5 ms** | 18.3x | yes | **no** |  |
| windows.consoles.Consoles | 7.57 s | 832 ms | 359 ms | 75.6 ms | **16.5 ms** | 17.1 ms | 21.8x | yes | **no** |  |
| windows.crashinfo.Crashinfo | 432 ms | 555 ms | 83.8 ms | 2.2 ms | **2.1 ms** | 2.2 ms | 39.9x | yes | yes | not a crash dump: every tool exits 1 |
| windows.debugregisters.DebugRegisters | 19.12 s | 561 ms | 94.8 ms | 81.2 ms | **23.9 ms** | 24.0 ms | 3.97x | yes | yes |  |
| windows.deskscan.DeskScan | 13.77 s | 2.62 s | 2.17 s | 135 ms | 78.1 ms | **11.6 ms** | 27.8x | yes | yes |  |
| windows.desktops.Desktops | 17.25 s | 2.71 s | 2.22 s | 145 ms | 82.5 ms | **20.4 ms** | 26.9x | yes | yes |  |
| windows.devicetree.DeviceTree | 13.84 s | 2.66 s | 2.18 s | 133 ms | 76.8 ms | **9.8 ms** | 28.4x | yes | yes |  |
| windows.dlllist.DllList | 8.46 s | 703 ms | 227 ms | 85.5 ms | **26.8 ms** | **26.8 ms** | 8.46x | yes | **no** |  |
| windows.driverirp.DriverIrp | 14.82 s | 2.67 s | 2.17 s | 136 ms | 79.6 ms | **14.6 ms** | 27.3x | yes | yes |  |
| windows.drivermodule.DriverModule | 13.73 s | 2.59 s | 2.15 s | 132 ms | 78.8 ms | **8.8 ms** | 27.3x | yes | yes |  |
| windows.driverscan.DriverScan | 14.10 s | 2.63 s | 2.19 s | 133 ms | 77.6 ms | **9.3 ms** | 28.3x | yes | yes |  |
| windows.dumpfiles.DumpFiles | 144.37 s | 8.09 s | 7.52 s | 296 ms | 242 ms | **240 ms** | 31.0x | yes | **no** | writes 1.48 GB of files per run (vol-rs: 4.5 GB, different set) |
| windows.envars.Envars | 1.90 s | 572 ms | 102 ms | 68.6 ms | **11.6 ms** | 12.2 ms | 8.78x | yes | yes |  |
| windows.etwpatch.EtwPatch | 17.51 s | 699 ms | 224 ms | 118 ms | 46.8 ms | **45.3 ms** | 4.79x | yes | yes |  |
| windows.filescan.FileScan | 24.59 s | 2.78 s | 2.31 s | 145 ms | 90.3 ms | **28.3 ms** | 25.5x | yes | **no** |  |
| windows.getservicesids.GetServiceSIDs | 2.56 s | 598 ms | 128 ms | 66.4 ms | **5.1 ms** | **5.1 ms** | 25.1x | yes | yes |  |
| windows.getsids.GetSIDs | 2.80 s | 598 ms | 120 ms | 68.0 ms | 10.2 ms | **10.0 ms** | 11.8x | yes | **no** |  |
| windows.handles.Handles | 37.62 s | 1.13 s | 667 ms | 118 ms | **61.5 ms** | 66.6 ms | 10.8x | yes | yes |  |
| windows.hashdump.Hashdump | 1.89 s | 563 ms | 92.7 ms | 65.0 ms | 6.3 ms | **5.6 ms** | 14.7x | yes | **no** | exit py/vol-rs/rsvol = 0/1/0 |
| windows.iat.IAT | 4.62 s | 643 ms | 170 ms | 82.7 ms | 24.9 ms | **24.2 ms** | 6.84x | yes | yes |  |
| windows.info.Info | 840 ms | 569 ms | 81.7 ms | 63.0 ms | 2.7 ms | **2.2 ms** | 30.3x | yes | **no** |  |
| windows.joblinks.JobLinks | 1.14 s | 562 ms | 94.2 ms | 66.1 ms | 8.4 ms | **8.1 ms** | 11.2x | yes | yes |  |
| windows.kpcrs.KPCRs | 925 ms | 562 ms | 82.1 ms | 63.5 ms | 2.4 ms | **1.9 ms** | 34.2x | yes | yes |  |
| windows.lsadump.Lsadump | 2.12 s | 568 ms | 90.9 ms | 66.8 ms | 6.0 ms | **5.7 ms** | 15.1x | yes | **no** |  |
| windows.malware.drivermodule.DriverModule | 14.12 s | 2.63 s | 2.15 s | 134 ms | 78.0 ms | **9.0 ms** | 27.6x | yes | yes |  |
| windows.mbrscan.MBRScan | 16.53 s | 1.37 s | 900 ms | 280 ms | 213 ms | **103 ms** | 4.22x | yes | **no** |  |
| windows.modscan.ModScan | 13.08 s | 2.62 s | 2.15 s | 132 ms | 75.0 ms | **4.0 ms** | 28.6x | yes | yes |  |
| windows.modules.Modules | 1.01 s | 562 ms | 85.5 ms | 65.1 ms | 3.9 ms | **3.3 ms** | 21.9x | yes | yes |  |
| windows.mutantscan.MutantScan | 13.51 s | 2.63 s | 2.20 s | 138 ms | 75.5 ms | **8.0 ms** | 29.1x | yes | yes |  |
| windows.netscan.NetScan | 20.68 s | 2.63 s | 2.17 s | 133 ms | 75.8 ms | **6.1 ms** | 28.6x | yes | yes |  |
| windows.netstat.NetStat | 1.16 s | 1.05 s | 572 ms | 67.7 ms | 6.5 ms | **6.4 ms** | 88.0x | yes | yes |  |
| windows.orphan_kernel_threads.Threads | 16.71 s | 2.68 s | 2.20 s | 138 ms | 79.4 ms | **13.4 ms** | 27.7x | yes | yes |  |
| windows.pe_symbols.PESymbols | 359 ms | 3.1 ms | 3.0 ms | **1.3 ms** | **1.3 ms** | 1.6 ms | 2.31x | yes | yes | exit py/vol-rs/rsvol = 2/1/2; needs arguments: usage error in every tool |
| windows.poolscanner.PoolScanner | 37.29 s | 3.28 s | 2.87 s | 155 ms | 95.8 ms | **40.0 ms** | 29.9x | yes | **no** |  |
| windows.privileges.Privs | 1.33 s | 566 ms | 99.8 ms | 68.4 ms | 10.1 ms | **9.7 ms** | 9.88x | yes | yes |  |
| windows.pslist.PsList | 1.17 s | 558 ms | 88.2 ms | 65.2 ms | 4.2 ms | **3.5 ms** | 21.0x | yes | yes |  |
| windows.psscan.PsScan | 14.86 s | 2.67 s | 2.23 s | 137 ms | 77.7 ms | **11.4 ms** | 28.7x | yes | yes |  |
| windows.pstree.PsTree | 1.44 s | 560 ms | 96.6 ms | 69.0 ms | 10.0 ms | **9.5 ms** | 9.66x | yes | yes |  |
| windows.registry.amcache.Amcache | 1.04 s | 570 ms | 86.2 ms | 64.5 ms | 3.2 ms | **2.7 ms** | 26.9x | yes | yes |  |
| windows.registry.cachedump.Cachedump | 1.95 s | 563 ms | 97.0 ms | 64.4 ms | 6.2 ms | **5.6 ms** | 15.6x | yes | yes |  |
| windows.registry.certificates.Certificates | 4.28 s | 637 ms | 173 ms | 66.9 ms | 9.2 ms | **8.6 ms** | 18.8x | yes | yes |  |
| windows.registry.getcellroutine.GetCellRoutine | 1.36 s | 695 ms | 227 ms | 66.3 ms | 6.3 ms | **6.2 ms** | 36.0x | yes | yes |  |
| windows.registry.hashdump.Hashdump | 2.07 s | 572 ms | 94.3 ms | 65.0 ms | **6.1 ms** | 6.2 ms | 15.5x | yes | **no** | exit py/vol-rs/rsvol = 0/1/0 |
| windows.registry.hivelist.HiveList | 982 ms | 557 ms | 83.3 ms | 63.2 ms | **3.2 ms** | 3.5 ms | 26.0x | yes | yes |  |
| windows.registry.hivescan.HiveScan | 3.28 s | 582 ms | 116 ms | 64.5 ms | 3.7 ms | **3.2 ms** | 31.3x | yes | yes |  |
| windows.registry.lsadump.Lsadump | 2.21 s | 574 ms | 93.7 ms | 65.2 ms | 6.2 ms | **5.7 ms** | 15.1x | yes | **no** |  |
| windows.registry.printkey.PrintKey | 2.38 s | 592 ms | 120 ms | 66.1 ms | 8.5 ms | **8.0 ms** | 14.1x | yes | yes |  |
| windows.registry.scheduled_tasks.ScheduledTasks | 6.14 s | 638 ms | 164 ms | 66.1 ms | 6.6 ms | **6.2 ms** | 24.9x | yes | yes |  |
| windows.registry.userassist.UserAssist | 1.85 s | 590 ms | 111 ms | 66.1 ms | 4.9 ms | **4.0 ms** | 22.6x | yes | yes |  |
| windows.scheduled_tasks.ScheduledTasks | 6.24 s | 645 ms | 164 ms | 66.3 ms | 6.7 ms | **6.2 ms** | 24.5x | yes | yes |  |
| windows.sessions.Sessions | 1.26 s | 564 ms | 92.5 ms | 68.5 ms | 9.8 ms | **9.6 ms** | 9.44x | yes | yes |  |
| windows.shimcachemem.ShimcacheMem | 1.63 s | 562 ms | 93.2 ms | 64.3 ms | 5.3 ms | **5.2 ms** | 17.6x | yes | yes |  |
| windows.ssdt.SSDT | 1.17 s | 570 ms | 97.4 ms | 62.4 ms | 6.3 ms | **6.2 ms** | 15.5x | yes | yes |  |
| windows.suspended_threads.SuspendedThreads | 19.44 s | 574 ms | 103 ms | 107 ms | **38.5 ms** | 42.5 ms | 2.68x | yes | yes |  |
| windows.symlinkscan.SymlinkScan | 13.13 s | 2.63 s | 2.18 s | 133 ms | 76.2 ms | **6.5 ms** | 28.6x | yes | yes |  |
| windows.thrdscan.ThrdScan | 34.60 s | 2.83 s | 2.35 s | 145 ms | 92.3 ms | **25.4 ms** | 25.4x | yes | yes |  |
| windows.threads.Threads | 18.67 s | 739 ms | 263 ms | 77.6 ms | 20.9 ms | **20.7 ms** | 12.6x | yes | yes |  |
| windows.timers.Timers | 1.63 s | 564 ms | 100 ms | 65.1 ms | 8.1 ms | **7.7 ms** | 12.4x | yes | yes |  |
| windows.truecrypt.Passphrase | 792 ms | 549 ms | 85.1 ms | 64.1 ms | 3.2 ms | **2.6 ms** | 26.6x | yes | yes |  |
| windows.unloadedmodules.UnloadedModules | 776 ms | 549 ms | 82.5 ms | 64.2 ms | **2.4 ms** | 2.7 ms | 34.4x | yes | yes |  |
| windows.vadinfo.VadInfo | 105.40 s | 919 ms | 456 ms | 88.7 ms | **31.4 ms** | 33.4 ms | 14.5x | yes | yes |  |
| windows.vadwalk.VadWalk | 19.89 s | 791 ms | 316 ms | 78.6 ms | **20.5 ms** | 20.9 ms | 15.4x | yes | yes |  |
| windows.verinfo.VerInfo | 49.59 s | 752 ms | 282 ms | 107 ms | **48.6 ms** | 49.5 ms | 5.81x | yes | yes |  |
| windows.virtmap.VirtMap | 720 ms | 552 ms | 82.5 ms | 62.8 ms | 2.5 ms | **2.0 ms** | 33.0x | yes | yes |  |
| windows.windows.Windows | 17.95 s† | 2.75 s | 2.28 s | 146 ms | 84.4 ms | **21.6 ms** | 27.1x | sorted = | **no** | python's row order is nondeterministic (set iteration: 3 python runs, 3 orders); sorted outputs identical |
| windows.windowstations.WindowStations | 17.14 s | 2.67 s | 2.32 s | 141 ms | 81.0 ms | **17.3 ms** | 28.7x | yes | **no** |  |
| windows.statistics.Statistics | 1686.76 s | 71.68 s | 70.06 s | 84.4 ms | 25.6 ms | **25.5 ms** | 2,737x | yes | yes | python's page walk is quadratic (re-walks every valid run per step); rsvol walks each page once |
| timeliner.Timeliner | 1468.70 s | 19.31 s | 18.65 s | 1.60 s | 1.31 s | **914 ms** | 14.2x | = ref machine | **no** | python's output depends on plugin discovery (readdir) order, see Checks; rsvol's output is byte-identical to python's on the reference machine |

## Linux per-plugin

| plugin | python | vol-rs cold | vol-rs warm | rsvol cold | rsvol steady | rsvol warm | steady vs vol-rs warm | rsvol out = py | vol-rs out = py | note |
|---|---:|---:|---:|---:|---:|---:|---:|:---:|:---:|---|
| banners.Banners | 21.56 s | 398 ms | 395 ms | 116 ms | 114 ms | **2.5 ms** | 3.46x | yes | yes |  |
| linux.bash.Bash | 10.21 s | 2.21 s | 209 ms | 530 ms | 10.2 ms | **9.9 ms** | 20.5x | yes | yes |  |
| linux.boottime.Boottime | 8.00 s | 2.09 s | 132 ms | 528 ms | 3.5 ms | **3.2 ms** | 37.7x | yes | yes |  |
| linux.capabilities.Capabilities | 8.21 s | 2.07 s | 130 ms | 537 ms | 7.3 ms | **6.5 ms** | 17.8x | yes | yes |  |
| linux.check_afinfo.Check_afinfo | 20.19 s | 2.26 s | 322 ms | 535 ms | 5.4 ms | **5.0 ms** | 59.6x | yes | yes |  |
| linux.check_creds.Check_creds | 9.73 s | 2.09 s | 129 ms | 537 ms | 3.7 ms | **3.1 ms** | 34.9x | yes | yes |  |
| linux.check_idt.Check_idt | 28.25 s | 2.31 s | 313 ms | 536 ms | 12.9 ms | **12.3 ms** | 24.3x | yes | yes |  |
| linux.check_modules.Check_modules | 9.35 s | 2.08 s | 126 ms | 541 ms | 3.5 ms | **3.2 ms** | 36.0x | yes | yes |  |
| linux.check_syscall.Check_syscall | 22.01 s | 2.43 s | 494 ms | 529 ms | **9.1 ms** | 9.9 ms | 54.3x | yes | yes |  |
| linux.ebpf.EBPF | 8.71 s | 2.04 s | 137 ms | 533 ms | 2.8 ms | **2.4 ms** | 48.8x | yes | yes |  |
| linux.elfs.Elfs | 13.57 s | 2.28 s | 278 ms | 543 ms | 18.3 ms | **17.3 ms** | 15.2x | yes | yes |  |
| linux.envars.Envars | 8.11 s | 2.08 s | 135 ms | 546 ms | **7.5 ms** | 7.8 ms | 18.0x | yes | yes |  |
| linux.graphics.fbdev.Fbdev | 6.12 s† | 2.11 s | 123 ms | 531 ms | 2.3 ms | **1.8 ms** | 53.6x | yes | yes |  |
| linux.hidden_modules.Hidden_modules | 17.42 s | 2.51 s | 589 ms | 557 ms | 8.4 ms | **7.9 ms** | 70.1x | yes | yes |  |
| linux.iomem.IOMem | 9.14 s | 2.07 s | 123 ms | 537 ms | **2.5 ms** | 2.9 ms | 49.3x | yes | yes |  |
| linux.ip.Addr | 10.62 s† | 2.06 s | 125 ms | 553 ms | **3.1 ms** | 3.3 ms | 40.3x | yes | **no** |  |
| linux.ip.Link | 9.21 s† | 2.06 s | 125 ms | 558 ms | 2.5 ms | **2.4 ms** | 50.1x | yes | **no** |  |
| linux.kallsyms.Kallsyms | 105.37 s | 3.17 s | 1.17 s | 610 ms | 102 ms | **99.9 ms** | 11.4x | yes | **no** | python raises TypeError after 204,803 rows; rsvol reproduces output and exit code |
| linux.keyboard_notifiers.Keyboard_notifiers | 19.50 s | 2.25 s | 318 ms | 556 ms | 10.1 ms | **9.4 ms** | 31.5x | yes | **no** |  |
| linux.kmsg.Kmsg | 8.34 s | 2.08 s | 135 ms | 534 ms | 4.3 ms | **3.6 ms** | 31.4x | yes | yes |  |
| linux.kthreads.Kthreads | 27.17 s | 2.26 s | 328 ms | 546 ms | 34.0 ms | **33.0 ms** | 9.66x | yes | yes |  |
| linux.library_list.LibraryList | 43.77 s | 2.21 s | 271 ms | 539 ms | 19.2 ms | **18.5 ms** | 14.1x | yes | yes |  |
| linux.lsmod.Lsmod | 15.90 s | 2.11 s | 129 ms | 548 ms | 3.9 ms | **3.5 ms** | 33.2x | yes | yes |  |
| linux.lsof.Lsof | 24.84 s† | 2.14 s | 179 ms | 541 ms | 13.1 ms | **13.0 ms** | 13.6x | yes | yes |  |
| linux.malfind.Malfind | 31.59 s | 2.38 s | 431 ms | 539 ms | 14.9 ms | **14.5 ms** | 28.9x | yes | **no** |  |
| linux.malware.check_afinfo.Check_afinfo | 17.31 s | 2.26 s | 313 ms | 546 ms | **5.0 ms** | 5.1 ms | 62.6x | yes | yes |  |
| linux.malware.check_creds.Check_creds | 9.17 s | 2.03 s | 131 ms | 533 ms | **3.4 ms** | 3.6 ms | 38.5x | yes | yes |  |
| linux.malware.check_idt.Check_idt | 30.09 s | 2.31 s | 313 ms | 536 ms | **12.7 ms** | **12.7 ms** | 24.6x | yes | yes |  |
| linux.malware.check_modules.Check_modules | 7.89 s | 2.19 s | 126 ms | 534 ms | **3.8 ms** | 4.1 ms | 33.3x | yes | yes |  |
| linux.malware.check_syscall.Check_syscall | 29.14 s | 2.53 s | 512 ms | 548 ms | **9.7 ms** | 9.8 ms | 52.8x | yes | yes |  |
| linux.malware.hidden_modules.Hidden_modules | 18.28 s | 2.50 s | 585 ms | 546 ms | 8.6 ms | **8.5 ms** | 68.0x | yes | yes |  |
| linux.malware.keyboard_notifiers.Keyboard_notifiers | 19.19 s | 2.27 s | 315 ms | 559 ms | 10.2 ms | **9.8 ms** | 30.8x | yes | **no** |  |
| linux.malware.malfind.Malfind | 34.63 s | 2.50 s | 416 ms | 544 ms | 14.7 ms | **14.1 ms** | 28.3x | yes | **no** |  |
| linux.malware.modxview.Modxview | 19.57 s | 2.50 s | 568 ms | 534 ms | 10.1 ms | **9.4 ms** | 56.2x | yes | yes |  |
| linux.malware.netfilter.Netfilter | 37.23 s | 2.23 s | 310 ms | 532 ms | 14.2 ms | **13.0 ms** | 21.9x | yes | **no** |  |
| linux.malware.process_spoofing.ProcessSpoofing | 10.48 s | 2.08 s | 136 ms | 529 ms | **7.9 ms** | 8.2 ms | 17.2x | yes | yes |  |
| linux.malware.tty_check.Tty_Check | 27.70 s | 2.27 s | 311 ms | 537 ms | 13.8 ms | **12.7 ms** | 22.5x | yes | yes |  |
| linux.modxview.Modxview | 17.78 s | 2.48 s | 580 ms | 540 ms | **10.1 ms** | **10.1 ms** | 57.4x | yes | yes |  |
| linux.mountinfo.MountInfo | 11.89 s† | 2.06 s | 151 ms | 544 ms | 12.2 ms | **11.9 ms** | 12.4x | yes | yes |  |
| linux.netfilter.Netfilter | 39.74 s | 2.28 s | 322 ms | 545 ms | 13.4 ms | **13.3 ms** | 24.1x | yes | **no** |  |
| linux.pagecache.Files | 58.40 s† | 2.95 s | 1.01 s | 580 ms | **79.6 ms** | 80.0 ms | 12.7x | yes | yes |  |
| linux.pagecache.InodePages | 7.62 s† | 2.13 s | 124 ms | 532 ms | **2.3 ms** | 2.4 ms | 54.1x | yes | yes | needs --inode or --find: every tool prints the empty table and the error, exit 0 |
| linux.pidhashtable.PIDHashTable | 10.53 s | 2.06 s | 136 ms | 532 ms | 8.9 ms | **8.4 ms** | 15.3x | yes | yes |  |
| linux.proc.Maps | 41.70 s | 2.40 s | 449 ms | 552 ms | 17.3 ms | **16.3 ms** | 26.0x | yes | yes |  |
| linux.psaux.PsAux | 8.90 s | 2.08 s | 132 ms | 548 ms | **7.5 ms** | **7.5 ms** | 17.6x | yes | yes |  |
| linux.pslist.PsList | 10.59 s | 2.08 s | 132 ms | 552 ms | 4.4 ms | **4.0 ms** | 29.9x | yes | yes |  |
| linux.psscan.PsScan | 58.63 s | 2.39 s | 486 ms | 643 ms | 145 ms | **35.1 ms** | 3.35x | yes | yes |  |
| linux.pstree.PsTree | 8.89 s | 2.10 s | 131 ms | 536 ms | 4.8 ms | **4.2 ms** | 27.2x | yes | yes |  |
| linux.ptrace.Ptrace | 8.54 s | 2.10 s | 138 ms | 532 ms | 6.5 ms | **6.2 ms** | 21.3x | yes | **no** |  |
| linux.sockscan.Sockscan | 27.16 s† | 2.22 s | 425 ms | 630 ms | 117 ms | **10.0 ms** | 3.63x | yes | yes |  |
| linux.sockstat.Sockstat | 19.34 s† | 2.09 s | 183 ms | 556 ms | **13.2 ms** | 13.5 ms | 13.8x | yes | yes |  |
| linux.tracing.ftrace.CheckFtrace | 25.89 s | 2.26 s | 315 ms | 538 ms | 13.1 ms | **12.3 ms** | 24.0x | yes | yes |  |
| linux.tracing.perf_events.PerfEvents | 8.22 s | 2.18 s | 130 ms | 553 ms | 4.3 ms | **3.8 ms** | 30.2x | yes | **no** |  |
| linux.tracing.tracepoints.CheckTracepoints | 25.14 s | 2.27 s | 332 ms | 532 ms | 13.3 ms | **11.9 ms** | 24.9x | yes | **no** |  |
| linux.tty_check.tty_check | 24.36 s | 2.23 s | 314 ms | 538 ms | **13.4 ms** | 13.9 ms | 23.4x | yes | yes |  |
| linux.vmcoreinfo.VMCoreInfo | 9.23 s | 3.05 s | 1.21 s | 638 ms | 122 ms | **121 ms** | 9.93x | yes | yes | the VMCOREINFO note search is not a cached scan: warm = steady |
| linux.pagecache.RecoverFs | 710.99 s† | 86.71 s | 85.86 s | 3.88 s | **3.43 s** | 3.48 s | 25.0x | yes | **no** | writes a .tar.gz of the recovered file system per run (rsvol 837 MB, python 842 MB: the same 21,862 members with the same contents, see Checks; vol-rs 626 MB); python: 1 run, no warm-up |
| linux.pscallstack.PsCallStack | 650.81 s | 2.51 s | 535 ms | 549 ms | **17.4 ms** | 18.6 ms | 30.7x | yes | yes |  |
| timeliner.Timeliner | 262.11 s | 3.13 s | 1.24 s | 682 ms | 210 ms | **128 ms** | 5.94x | = ref machine | **no** | python's output depends on plugin discovery (readdir) order, see Checks; rsvol's output is byte-identical to python's on the reference machine |

† python run again in run 2 (see the column notes above); all other python numbers are run 1's.

## Checks

- **Run-to-run stability (Windows).** vol-rs warm (same binary, same procedure as run 1's vol-rs column) vs run 1: ratio median 1.008, 10th-90th percentile 0.972–1.046 over 77 plugins. Within run 2, the median-of-5 is 1.02x (vol-rs cold), 1.02x (vol-rs warm), 1.02x (rsvol cold), 1.03x (rsvol steady), 1.04x (rsvol warm) the best run (median over plugins).
- **Run-to-run stability (Linux).** vol-rs warm (same binary, same procedure as run 1's vol-rs column) vs run 1: ratio median 1.000, 10th-90th percentile 0.940–1.045 over 49 plugins. Within run 2, the median-of-5 is 1.04x (vol-rs cold), 1.05x (vol-rs warm), 1.03x (rsvol cold), 1.05x (rsvol steady), 1.06x (rsvol warm) the best run (median over plugins).
- **rsvol `344e88c` (run 1) vs `95528b2` steady (Windows, the 77 plugins of run 1; run 1 had no scan cache, so its column matches "steady").** Total 6.26 s vs 4.43 s, per-plugin ratio steady/run 1 median 1.004 (10th-90th percentile 0.917–1.050); timeliner 3.14 s vs 1.31 s.
- **rsvol `344e88c` (run 1) vs `95528b2` steady (Linux, the 49 plugins of run 1; run 1 had no scan cache, so its column matches "steady").** Total 1.03 s vs 1.12 s, per-plugin ratio steady/run 1 median 1.030 (10th-90th percentile 0.966–1.117); timeliner 140 ms vs 210 ms (the Linux timeline now also runs lsof and the pagecache plugins).
- **Output equality details** (every rsvol run of every column is checked, not only the best one).
  - `frameworkinfo.FrameworkInfo`: python lists components in the readdir order of its install directory,
    so its output on the VM (ext4) and on the reference machine (btrfs) differ in order only. rsvol's output
    is byte-identical to python's on the reference machine and to python's on the VM after sorting (458
    lines). Since run 1, rsvol implements every plugin, so the lists now also have the same entries.
  - `windows.windows.Windows`: python iterates a set, so its row order changes from run to run (its 3 runs
    in run 2 printed 3 different orders); rsvol's output equals python's after sorting (562 lines).
  - `timeliner.Timeliner` (Windows): python's `Timeliner._generator` re-appends *every* entry accumulated
    so far after each plugin it runs, so its row count and content depend on plugin discovery (readdir)
    order: 3,460,648 lines on the VM (run 1), 2,842,936 on the reference machine. All 15 rsvol runs
    printed exactly the reference machine's output (sha256 of the body `3984c9cd…`, 2,842,935 lines
    after the banner).
  - `timeliner.Timeliner` (Linux): now comparable. rsvol implements every Linux plugin, including
    `linux.lsof` and `linux.pagecache.Files`, which feed most of python's Linux timeline. The same
    readdir effect: python printed 75,744 lines on the VM (run 1) and 50,697 on the reference machine;
    all 15 rsvol runs printed exactly the reference machine's output (`543ed014…`).
  - `isfinfo.IsfInfo`: python was run again next to rsvol because both read python's identifier cache;
    it printed the same as in run 1, and rsvol's output is identical.
  - The 10 newly benchmarked Linux plugins: python's output on the VM is identical to the reference
    machine's for all of them, and rsvol's to python's.
  - `linux.pagecache.RecoverFs`: besides stdout, the archive was compared member by member
    (`tarfile`: name, type, mode, link target, size, uid/gid and the sha256 of the contents). rsvol's
    and python's archives have the same 21,862 members with the same contents. Only the archive
    bytes differ: every tar entry is stamped with the time of the run (python does the same), and the
    two gzip compressors differ.
- **Cache states.** The three rsvol columns printed the same stdout in all of their 15 runs on every
  plugin, so no cache changed any output. After both rounds, rsvol-warm's cache directory held
  33 MB of binary symbol tables (the Windows kernel + tcpip and the Linux kernel), 1.4 MB of scan
  results for both images, 28 KB identifier index and 12 KB of automagic results.
- **Where rsvol cold loses.** A first-ever rsvol run on the Linux image spends ~0.53 s before the
  plugin starts: to find the kernel it indexes the banner of the 3.3 MB `.json.xz` ISF (xz-decoding
  64 MB of JSON) while it builds the binary symbol table from it (`RSVOL_TRACE=1`: identifier index
  530 ms, overlapped symbol-table build 265 ms). vol-rs's cold run pays the same kind of cost (~2 s).
  So rsvol cold beats vol-rs cold on every Linux plugin, but vol-rs *warm* (~0.13 s on the smallest
  plugins) beats rsvol's first-ever run on most of them. From the second run on, rsvol (steady and
  warm) is the fastest on every Linux plugin. On Windows the equivalent cost is ~53 ms, below vol-rs
  warm's ~80 ms floor.
- **Load.** `/proc/loadavg` every 10 s during run 2 (06:03-07:29, 513 samples): load1 min 0.55,
  median 1.78, p90 8.52, max 16.3. Only the benchmark ran; load above 1 comes from the multi-threaded
  rust runs executing back to back (rsvol uses all 32 vCPUs).

