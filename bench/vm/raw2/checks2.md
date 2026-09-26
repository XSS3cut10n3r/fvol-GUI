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
