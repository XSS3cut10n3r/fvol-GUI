# Plugin work packages (orchestrator planning notes)

Round A = foundations (start right after core merges). Round B = dependents.

## Round A
- **A1 pool**: poolscanner framework (plugins/windows/poolscanner.py + symbols/windows/extensions/pool.py, bigpools
  ISFs), handles' object-type map + cookie helpers (handles.py get_type_map / find_cookie / OBJECT_HEADER
  decoding) → plugins: poolscanner.PoolScanner, bigpools, psscan, filescan, driverscan, modscan, mutantscan,
  symlinkscan, thrdscan, handles.Handles.
- **A2 pe+vad**: MMVAD extensions (vad tree, protection, tags, file names), PE helpers (pedump, pe_symbols (1085 lines,
  used by many), verinfo), ssdt → plugins: vadinfo, vadwalk, virtmap, memmap, pedump, pe_symbols, verinfo, iat,
  dlllist, ssdt, cmdline, privileges, joblinks, sessions, pstree.
- **A3 registry**: registry hive layer (layers/registry.py) + registry extensions (CM_KEY_NODE, values, big data),
  hivelist (hivescan once A1 merged) → printkey, userassist, certificates, hashdump, lsadump, cachedump
  (+ deprecated aliases), amcache, scheduled_tasks, getcellroutine (needs ssdt from A2: private minimal copy ok),
  envars, getsids, getservicesids.
- **G generic**: banners, frameworkinfo, isfinfo, layerwriter, configwriter, regexscan, yarascan, vmscan, timeliner
  (timeliner last: needs other plugins' timeline()).
- **L1 linux base** (when test images exist): symbols/linux/extensions (3273 lines) + linux process plugins.

## Round B
- **B1 kernel**: callbacks, timers, kpcrs, unloadedmodules, crashinfo, truecrypt, etwpatch, debugregisters,
  driverirp, devicetree, mbrscan, mftscan (MFTScan/ADS/ResidentData), dumpfiles, statistics, strings,
  threads, orphan_kernel_threads, suspended_threads.
- **B2 net**: netscan, netstat.
- **B3 gui/console**: consoles, cmdscan, windowstations, desktops, deskscan, windows.windows (win32k PDB symbols).
- **B4 malware+services**: svcscan, svclist, svcdiff, malware/* (malfind, hollowprocesses, ldrmodules, pebmasquerade,
  processghosting, psxview, suspicious_threads, drivermodule, skeleton_key_check, direct/indirect/unhooked syscalls),
  shimcachemem, vadregexscan, vadyarascan.
- **L2 linux kernel**, **L3 linux fs/net**, **M1 mac**.

## Perf follow-ups (later)
- crypto: DONE. Beats OpenSSL on SHA1 (1.12x), RC4 (1.35x), DES (2.6-2.9x), AES (1.9-2.0x bulk, 5-7x small),
  all small-message hashes (2.4-5.3x); MD5/SHA256 bulk tie (1.00-1.02x) at the measured hardware dependency floor.

## Wave 2 (launched after core merge 0630ba6)
Running: W1 scanners+kernel objects, W2a process, W2b PE/files, W3 registry, W4 net+gui, G generic,
L1 linux ext+process, M1 mac. Pending: W5 malware+services (after disasm + yara land), L2 linux kernel,
L3 linux fs/net (after L1's extensions land).
- snappy/xpress: DONE (snappy 2.4x system libsnappy / 1.22x -march=native build, xpress-huffman 1.65x wimlib, lz77 4.1x).
- regex/yara: DONE. 1.28-20x best of PCRE2-JIT/RE2 on every refbench case, compile faster than PCRE2-JIT, 5.7-16x libyara.
- codecs: DONE. xz beats liblzma 5.8.3 1.10-2.6x (x86-64 asm symbol loop); inflate/zlib/gzip 2.2-4.5x zlib; bzip2 1.6-4.6x libbz2; lznt1 2.7-3.9x; snappy 2.4x; xpress 1.65-4.1x.
- core: level-by-level page-table range walker (memmap all-procs 42M rows = 19 s, strings, statistics use per-page translate).
- statistics requires kernel symbols; python only needs the memory layer.

## Queue (launch as agent slots free up; 20-concurrent cap)
1. perf pass snappy/xpress + container layers   2. W5 malware+services (needs disasm merged)
3. L2 linux kernel, L3 linux fs/net (need L1 extensions merged)

## Dedupe list (cleanup pass later)
- src/plugins/windows/thread_pe_symbols.rs (W1 private) -> W2b pe_symbols (symbol names currently empty!)
- handles.rs private registry key naming -> W3 RegExt helpers
- hivescan private list_big_pools -> W1 bigpools::list_big_pools_each
- core RSDS scanner duplicates symbols::windows::pdb::rsds_scan
- W4 private: consoles.rs version-info reader + netscan.rs verinfo copy -> W2b verinfo
- README-API.md: add W4 helpers (symbols/windows/{gui,network,consoles}.rs, windowstations scan helpers)
- vmscan: 94 ms vs vol-rs 3 ms (vol-rs has no VMCS layouts installed and skips the scan). Needs a per-image
  scan-index cache or a cheaper page-stride scan to win. Consider a general per-image scan-result cache
  (all scanners' signatures recorded in one pass, keyed path+size+mtime) in the perf phase.

## MILESTONE (2026-09-26): full parity
All plugins ported. Byte-identical to python volatility3 2.28.2 on every reference: Windows main image 98/98,
Windows 1809 98/98, Linux 62/62 on each of 4 images (6.8 + 5.15, ELF + LiME), macOS 10.9 27/27.
(isfinfo references refreshed: they depend on the live symbol-dir contents; ours == a fresh python run.)
448 unit tests. Remaining: perf passes (scan cache, cold start, output pipeline/range walker), final
benchmarks (ubuntu-vm), docs.
