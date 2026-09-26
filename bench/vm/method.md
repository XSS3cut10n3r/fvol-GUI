# Method — 3-way benchmark on a quiet VM

Goal: a reproducible, like-for-like timing of **python volatility3** (the reference), **vol-rs**
(the competing Rust port) and **rsvol** on a machine where nothing else runs.

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

## Files

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
- `scripts/` — `bench_vm.py` and `startup_vm.py` as run on the VM; `report.py` regenerates
  BENCHMARKS.md and results.tsv: `cd bench/vm && python3 scripts/report.py raw .`
