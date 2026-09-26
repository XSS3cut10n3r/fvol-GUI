# Method — 3-way benchmark on a quiet VM

Goal: a reproducible, like-for-like timing of **python volatility3** (the reference), **vol-rs**
(the competing Rust port) and **rsvol** on a machine where nothing else runs.

There were two runs on the same VM (same boot, same images, same python and vol-rs):

- **run 1** (00:12-04:07 VM time, rsvol `123c8d4` / `344e88c`): python, vol-rs and rsvol, one
  column per tool. Files: `results.tsv`, `raw/`, `BENCHMARKS-run1.md`. Described in the sections
  below up to "Run 2".
- **run 2** (the final numbers in `BENCHMARKS.md`, rsvol `95528b2` = main HEAD after the scan-result
  cache and the cold-start work): rsvol in three cache states and vol-rs cold/warm, python reused
  from run 1. Files: `results2.tsv`, `raw2/`. Described in "Run 2 (final)".

## Machine

A dedicated KVM guest (`ubuntu-vm`): 32 vCPU of an AMD EPYC 7302P host (Zen 2: AVX2, SHA-NI, AES,
PCLMUL; no AVX-512/VAES; the guest reports "AMD EPYC Processor", family 23 model 1), 30 GiB RAM,
Ubuntu 25.04, kernel 6.14, glibc 2.41. It was rebooted right before the setup, only the idle
desktop session and sshd were running, and a sampler logged `/proc/loadavg` every 10 s during
the whole run (`raw/load.log`; the per-plugin `load1_at_start` in results.tsv). The load
average rises only while the multi-threaded Rust tools run and falls back to 1.0 during the
single-threaded python runs, i.e. the load is our own. Full details in machine.txt.

All three tools read the same files: the image and ISFs sit on the VM's local disk and are in the
page cache (the image was `cat` to /dev/null first, and every plugin gets an untimed warm-up run of
each tool). Each tool's cache and symbol directories were redirected into the benchmark directory
with `XDG_CACHE_HOME` / `XDG_DATA_HOME` (all three honour them), so the user's own
`~/.cache/volatility3` was not touched and every tool started from the same provisioned files:

- python + rsvol: `$XDG_CACHE_HOME/volatility3/symbols/windows/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B3-1.json.xz`
  and `tcpip.pdb/20223492C3DD1819D9E4F2A0EE975F74-1.json` (copied from the reference machine, so
  python never downloads or converts a PDB during a timed run);
- vol-rs: `$XDG_DATA_HOME/vol-rs/symbols/windows/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B3-1.json`;
- Linux round: `-s ~/rsvol-bench/isf` (holding only `linux/rsvol-noble-6.8.0-139-generic.json.xz`) for all three.

## Tools

| tool | version | build |
|---|---|---|
| rsvol | `344e88c` (main, 2026-09-26) | built on the VM: `cargo build --release` with the repo's `.cargo/config.toml` (`target-cpu=native` → LLVM `znver1` + avx2/bmi2/sha/aes/pclmul, `+crt-static`), fat LTO, codegen-units=1, rustc 1.98.1 |
| rsvol (first pass) | `123c8d4` | same, dynamically linked (before the static-pie change) |
| vol-rs | 1.0.0 (`4c1076f` + the author's uncommitted working tree of 2026-09-25 19:35) | the competitor's own release binary (fat LTO, codegen-units=1, generic x86-64), sha256 `ac1e4ed6…`, copied as-is (glibc 2.38 symbols, runs on 2.41) |
| vol-rs (native check) | same source | rebuilt on the VM with `RUSTFLAGS=-C target-cpu=native`, same profile |
| python | volatility3 2.28.2 (`3fcb731e`) on CPython 3.14.7 | python-build-standalone (PGO + LTO + BOLT) via uv, venv with capstone 5.0.9, yara-python 4.5.4, pycryptodome 3.23.0, pefile 2024.8.26 — the same versions as the reference setup that produced rsvol's golden outputs |

CPython 3.14.7 rather than Ubuntu's 3.13.3: with 3.13 python's own output differs (e.g.
`dlllist` prints the year 144 as `144` instead of `0144`), so it would not be the reference
rsvol is held to.

## Procedure (`bench_vm.py`, adapted from `bench/scripts/bench3.py`)

For every plugin in `bench/three_way/plugins.txt` (77 Windows plugins, statistics and timeliner
last), run back to back on the 5 GiB `memory-dirty.raw`:

1. one **untimed warm-up** run of each tool (python's skipped for `windows.statistics` and
   `timeliner`, 25-28 min each; every cache they use is warm by then);
2. **5 interleaved timed rounds** `rsvol, vol-rs, python`; python takes part in the first 2
   rounds only (1 for statistics/timeliner).

Each run is `TOOL -q -o <fresh dir> -f IMG PLUGIN`, spawned with `subprocess.Popen` and reaped with
`os.wait4`: **wall** = `perf_counter` from spawn to reap, **CPU** = that child's `ru_utime +
ru_stime`, plus its max RSS. stdout goes to a file (so the renderer really writes the output);
the output directory is measured and deleted after every run (dumpfiles writes 1.48 GB per run,
vol-rs's dumpfiles 4.5 GB).
The reported number is the **best wall time**; the median of the 5 rust runs is in the raw files.

Output check: the sha256 of each run's stdout without its first line (the version banner) is
recorded, so every plugin's output of rsvol and vol-rs is compared byte for byte with python's on
the VM, not only in the sanity check.

Sanity check before timing (by hand): `pslist, psscan, dlllist, hivelist, netscan` — rsvol's
stdout equals python's (after the banner) for all five; vol-rs differs on `dlllist`.

Pass 2: main moved to `344e88c` during pass 1 (static-pie, lean startup, regex/YARA and codec
passes). Pass 1 was finished as it was (rsvol `123c8d4`, so the long python run was not
restarted), then `344e88c` was built on the VM and the Windows list was re-run with the same
procedure for **rsvol and vol-rs only** (interleaved, warm-up + best of 5), reusing python's
pass-1 times and output hashes (python's side does not depend on the rsvol build). The tables
use pass 2 for rsvol and vol-rs; vol-rs's pass-1 numbers (same binary) serve as a
run-to-run stability check.

Pass 3: vol-rs rebuilt on the VM with `RUSTFLAGS=-C target-cpu=native` (same release profile),
timed with the same procedure against rsvol `344e88c` again — to check that the comparison does not
hinge on rsvol being built for the host CPU while the vol-rs release binary is generic x86-64.

Startup (`startup_vm.py`): `windows.pslist.PsList`, **cold** = the tool's own cache directory
deleted before each run (rsvol `$XDG_CACHE_HOME/rsvol`, vol-rs `$XDG_CACHE_HOME/vol-rs`, python
`identifier.cache` + `data_*.cache`; the kernel symbol files stay, the image stays page-cached),
**warm** = the cache left by the previous run; best of 5 (python 3).

Linux round: the 47 `linux.*` plugins of `bench/linux_noarg.txt` that rsvol implements (48, minus
`linux.vmayarascan`, which only fails with "No rules provided" in every tool) plus `banners` and
`timeliner`, on the 3 GiB `rsvol-noble-6.8.0-139.elf` (Ubuntu 24.04, kernel 6.8), rsvol
`344e88c`, rust tools warm-up + best of 5, python warm-up + 1 timed run (`pscallstack` and
`timeliner`: 1 run, no warm-up).

Everything ran sequentially: one tool process at a time on the VM.

Untimed checks afterwards: the full stdout of python and rsvol for `windows.windows` (sorted
comparison), both timeliners (per-plugin row counts, and rsvol's Windows output against the
reference machine's python output), and `windows.dumpfiles` (sha256 of all 1,630 dumped files of
python vs rsvol).

## Run 2 (final)

Why: since run 1 rsvol gained on-disk caches that change what a "warm" run means: besides the
binary symbol tables, identifier index and automagic results it now keeps a per-image **scan
cache** (the raw pattern hits of every full scan, replayed through the plugin's own validation on
later runs; `src/layers/scancache.rs`). One rsvol number per plugin would either hide the first-run
cost or credit rsvol with work it did not redo, so run 2 reports three rsvol columns.

Build: `git -C rs-vol archive main` of `95528b2` (main HEAD) copied to the VM and built there with
`~/.cargo/bin/cargo build --release` (rustup stable = rustc 1.98.1, the toolchain of run 1; repo
config `target-cpu=native` + `+crt-static`, fat LTO, codegen-units=1): static-pie, sha256
`23a71a59…` (full hash in machine.txt). Sanity check before timing: pslist, psscan, dlllist,
hivelist, netscan on Windows and the 10 newly implemented Linux plugins + pslist/bash: stdout equal
to python's.

Columns (`scripts/bench2_vm.py`; each tool reads the same page-cached files; `XDG_CACHE_HOME` /
`XDG_DATA_HOME` redirected into the benchmark directory as in run 1; each rsvol column has its own
cache directory via `RSVOL_CACHE`, see `src/util/paths.rs`):

| column | before every timed run |
|---|---|
| rs_cold | `RSVOL_CACHE=cache2/rs-cold` deleted (`rm -rf`): no symbol tables, identifier index, automagic results, ISF summaries or scan results |
| rs_steady | `RSVOL_CACHE=cache2/rs-steady`, `RSVOL_NO_SCAN_CACHE=1`: symbol/automagic caches warm, scan cache off |
| rs_warm | `RSVOL_CACHE=cache2/rs-warm`: everything warm, incl. the scan cache of this plugin |
| vr_cold | `$XDG_CACHE_HOME/vol-rs` emptied except `pdb/` (the tcpip.pdb vol-rs downloaded from the Microsoft symbol server in run 1, kept like the provisioned ISFs of the other tools so that no timed run depends on the network); deleted: `images.tsv` (per-image automagic results), `banners.tsv`, `symbols/*.bin` (its parsed Linux ISF) |
| vr_warm | vol-rs's cache as the previous run left it (run 1's vol-rs column) |
| py | run 1's python runs, times and stdout hashes (`--py-ref raw/win_pass1.jsonl`, `raw/linux.jsonl`) |

rsvol writes its cache files in background threads that are joined before the process exits, so
every timed run includes its cache writes. The kernel symbol files stay provisioned for all tools
in every column (python/rsvol: the `.json.xz` / `.json` ISFs in `$XDG_CACHE_HOME/volatility3/symbols`
and `-s isf/`; vol-rs: its `.json` in `$XDG_DATA_HOME/vol-rs/symbols`).

Per plugin: one untimed warm-up run of rs_steady, rs_warm and vr_warm (none for the cold columns:
their cache is deleted before every run), then **5 interleaved rounds** `rs_cold, rs_steady,
rs_warm, vr_cold, vr_warm`; the reported number is the best wall time of the 5 (the median is in
results2.tsv). Wall, CPU and max RSS are measured per process exactly as in run 1.

Python ran again only where run 1 has nothing to reuse or where its output depends on state that
changed since run 1 (warm-up + 2 timed runs on Windows, warm-up + 1 on Linux):
`isfinfo.IsfInfo` (its output lists python's identifier cache, which python's own runs update;
rsvol reads the same file, so the two ran next to each other; python printed the same as in run 1), `frameworkinfo.FrameworkInfo` and
`windows.windows.Windows` (to keep their full outputs for the sorted comparisons) and the 10
Linux plugins run 1 did not have (`graphics.fbdev`, `ip.Addr`, `ip.Link`, `lsof`, `mountinfo`,
`pagecache.Files/InodePages/RecoverFs`, `sockscan`, `sockstat`; `pagecache.RecoverFs`: 1 run, no
warm-up).

Output check: every timed run's stdout hash (without the banner line) is compared with python's;
"rsvol out = py" requires all 15 rsvol runs (3 columns x 5) to match, and the three rsvol columns
must print the same bytes (the caches must never change output). The Linux round now covers every
Linux plugin rsvol implements that runs without arguments: rsvol now has all 60 `linux.*`
plugins of python volatility3 2.28.2; the round runs the 47 of run 1, the 10 above, `banners` and
`timeliner` (whose timeline now includes the lsof/pagecache rows, as python's does). Left out
because they need arguments (without them every tool only prints a usage error): `linux.vmayarascan`
(yara rules; also left out in run 1), `linux.vmaregexscan` (`--pattern`), `linux.module_extract`
(`--base`). `linux.pagecache.InodePages` is kept as in `bench/linux_noarg.txt`: without `--inode` /
`--find` every tool prints the empty table plus python's error message and exits 0.

Startup (`scripts/startup2_vm.py`): as in run 1, `windows.pslist.PsList` best of 5 (python 3),
cold = the tool's own cache deleted before every run (rsvol: its whole `RSVOL_CACHE`), warm = the
cache left by the previous run.

Order on the VM (`scripts/run2.sh`): Windows round, Linux round, startup; `/proc/loadavg` sampled
every 10 s (`raw2/load.log`). Untimed checks afterwards (`raw2/checks2.md`).

## Files

- `results2.tsv`, `BENCHMARKS.md` — run 2 (final): one row per (os, plugin), every column's best /
  median wall, CPU, max RSS, exit code, the output flags, like-for-like speedups, rsvol's run-1 time
  and vol-rs's run-1 time, the per-plugin note. `python3 scripts/report2.py raw2 raw .` regenerates
  both.
- `raw2/win.jsonl`, `raw2/linux.jsonl` — every single run of run 2 (warm-ups flagged), with wall,
  user, sys, max RSS, rc, stdout hash, line count, output bytes, bytes written to `-o`, load.
- `raw2/win.tsv`, `raw2/linux.tsv`, `raw2/startup.tsv` — the summaries written on the VM;
  `raw2/*.log`, `raw2/timeline.txt`, `raw2/load.log`; `raw2/notes2.tsv`, `raw2/meta2.env`,
  `raw2/checks2.md`, `raw2/notfastest.md`, `raw2/startup_note.md` — hand-written inputs of the report.
- `BENCHMARKS-run1.md` — run 1's report as it was.
- `results.tsv` — one row per (os, plugin): best and median wall, CPU, max RSS and exit code of
  each tool, the output-equality flags, speedups, rsvol `123c8d4`'s pass-1 time, vol-rs's pass-1
  time and the native vol-rs time (pass 3), the per-plugin note.
- `raw/*.jsonl` — every single run (warm-ups flagged), with wall, user, sys, max RSS, rc, stdout
  hash, line count, stdout bytes and output-file bytes.
- `raw/win_pass{1,2,3…}.tsv`, `raw/linux.tsv` — the per-pass summaries written by `bench_vm.py`.
- `raw/startup.tsv` — cold/warm startup runs (pass 1: rsvol `123c8d4`; pass 2: rsvol `344e88c`).
- `raw/load.log` — `/proc/loadavg` every 10 s during the whole session.
- `raw/notes.tsv`, `raw/meta.env`, `raw/checks.md` — hand-written inputs of the report.
- `machine.txt` — lscpu, memory, kernel, tool versions, binary hashes, load summary, timeline.
- `scripts/` — run 1: `bench_vm.py`, `startup_vm.py`, `report.py` (regenerates run 1's report and
  results.tsv: `cd bench/vm && python3 scripts/report.py raw /tmp/run1`; it writes BENCHMARKS.md, so
  do not point it at `.`); run 2: `run2.sh`, `bench2_vm.py`, `startup2_vm.py`, `report2.py`, `tar_manifest.py` (the
  RecoverFs archive comparison).
