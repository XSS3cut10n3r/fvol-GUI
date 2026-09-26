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
- crypto still < OpenSSL on bulk: SHA1/SHA256 0.9x, MD5 0.77x, DES 0.38x (small 0.64x), AES128-CBC 0.72x,
  small AES 0.75-0.96x (per-call Vec alloc / key schedule). Wins: all small-message hash/HMAC/RC4 (1.2-3.4x),
  AES256-ECB bulk 1.03x.
