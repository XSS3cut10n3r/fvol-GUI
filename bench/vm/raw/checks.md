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
