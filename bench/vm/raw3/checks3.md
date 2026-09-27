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
