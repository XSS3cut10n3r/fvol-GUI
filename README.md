# rsvol

rsvol is a Rust rewrite of the [Volatility 3](https://github.com/volatilityfoundation/volatility3)
memory forensics framework, version 2.28.2. It has the same plugins, the same options and the same
output: for a given image, plugin and set of arguments, stdout is byte-for-byte identical to
python volatility3, and files written by dumping plugins have the same names and contents. The
few exceptions are listed under [Known differences](#known-differences-from-python-volatility3).

It is written for incident responders and forensic analysts who already use volatility3 and want
the same results in milliseconds instead of minutes.

This README describes rsvol 0.1.0, which tracks volatility3 2.28.2.

## Highlights

- All 197 plugins of a full volatility3 2.28.2 install, including the YARA, capstone and
  pycryptodome based ones, with python's argument parser, `--help` text and error messages.
- Windows, Linux and macOS memory images in raw, LiME, ELF core, Windows crash dump, VMware,
  QEMU, AVML and Xen formats, plus Windows swap files through `--single-swap-locations`.
  Images compressed with gzip, bzip2 or xz are read like python reads them, but decompressed
  once, in parallel where the format allows, instead of on every read.
- Median plugin run of about 10 ms on a 5 GiB Windows image, versus 4.5 s for python.
- One static binary with no dependencies: Rust `std` only, no crates. Codecs, crypto, the
  disassembler, the regex and YARA engines, the PDB parser and the JSON parser are written from
  scratch.
- A built-in web UI, `vol serve`, for browsing results, processes and memory in a browser.
- Caches that make repeat runs cheap and are keyed so that they cannot change output.

## Performance

These numbers come from [bench/vm/BENCHMARKS.md](bench/vm/BENCHMARKS.md), which holds the full
per-plugin tables (run 1 is kept in [BENCHMARKS-run1.md](bench/vm/BENCHMARKS-run1.md)). They were
measured on a dedicated KVM guest with 32 vCPUs of an AMD EPYC 7302P host and 30 GiB of RAM, running
Ubuntu 25.04, with nothing else running. rsvol commit `95528b2` was compared with python
volatility3 2.28.2 on CPython 3.14.7 and with vol-rs 1.0.0, another Rust port. Each figure is the
wall-clock time of the whole process with the image in the page cache, best of 5 interleaved runs.
The method is in [bench/vm/method.md](bench/vm/method.md).

rsvol has on-disk caches (see [Caching](#caching)), so it is reported three ways: **cold** (every
rsvol cache wiped before each run: a first-ever run), **steady** (symbol caches warm, per-image scan
cache disabled: the honest per-run cost of the scanning work) and **warm** (all caches warm: what a
second run of a plugin costs). vol-rs is reported cold (its caches wiped) and warm.

| Measurement (sum of per-plugin best)            | python    | vol-rs cold | vol-rs warm | rsvol cold | rsvol steady | rsvol warm |
| ----------------------------------------------- | --------: | ----------: | ----------: | ---------: | -----------: | ---------: |
| Windows 11 x64 build 22000, 5 GiB, 77 plugins   | 4078 s    | 183.8 s     | 148.6 s     | 8.82 s     | 4.43 s       | 2.18 s     |
| Windows, median plugin                          | 4.49 s    | 624 ms      | 164 ms      | 68.6 ms    | 10.2 ms      | 8.6 ms     |
| Linux 6.8, 3 GiB ELF core, 59 plugins           | 2804 s    | 217.2 s     | 105.2 s     | 35.4 s     | 4.80 s       | 4.42 s     |
| Linux 6.8, median plugin                        | 18.3 s    | 2.23 s      | 311 ms      | 541 ms     | 10.1 ms      | 9.8 ms     |

Like for like (rsvol cold vs vol-rs cold, rsvol warm vs vol-rs warm): Windows 20.8x / 68.1x faster in
total, Linux 6.1x / 23.8x. rsvol steady and warm are the fastest of the three tools on every plugin
except `vmscan.Vmscan`, where vol-rs ships no VMCS symbol files and returns an empty table without
reading the image, while python and rsvol scan all 5 GiB. (Since that run, rsvol's vmscan sweeps the
page starts through the image mapping and caches the bytes its checks read: on the same VM it now
takes 44 ms steady and 1.8 ms warm, vol-rs 3.4 ms.) A first-ever Linux run pays ~0.5 s once to
index and build the kernel's 64 MB symbol table, which is then cached.

`windows.pslist.PsList` startup: rsvol 64.7 ms cold / 3.3 ms warm, vol-rs 563 ms / 80.6 ms,
python 1.87 s / 1.20 s.

On that run rsvol's stdout was byte-identical to python's on every plugin (after sorting for the
two plugins whose python output order itself varies between runs); vol-rs matched on 59/77 Windows
and 45/59 Linux plugins.

## Quick start

Build the binary, then point it at an image:

```bash
cargo build --release
./target/release/vol -f <IMAGE> windows.pslist.PsList
```

```text
Volatility 3 Framework 2.28.2

PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

4	0	System	0xe485b4eaa040	134	-	N/A	False	2026-09-14 02:53:44.000000 UTC	N/A	Disabled
100	4	Registry	0xe485b4f1a080	4	-	N/A	False	2026-09-14 02:53:39.000000 UTC	N/A	Disabled
344	4	smss.exe	0xe485b555d040	2	-	N/A	False	2026-09-14 02:53:44.000000 UTC	N/A	Disabled
```

The binary is self-contained, so you can copy `target/release/vol` anywhere on your `PATH`; the
examples call it `vol`. The command line is the one you know from volatility3. The most common
options:

```bash
# list every plugin, then the options of one plugin
vol -h
vol windows.pslist.PsList -h

# Linux and macOS need symbol files that match the kernel: pass their directories with -s
vol -s <SYMBOL_DIR> -f <IMAGE> linux.pslist.PsList

# write dumped files to an existing directory with -o
vol -f <IMAGE> -o <OUTPUT_DIR> windows.dlllist.DllList --pid 828 --dump

# choose a renderer with -r: quick (default), pretty, csv, json, jsonl, mermaid, none
vol -f <IMAGE> -r json windows.pslist.PsList
```

Windows kernel symbols are downloaded from the Microsoft symbol server on first use, like python
does. See [docs/usage.md](docs/usage.md) for symbol setup on every OS, dumping, renderers and
filters.

## Building

You need a Rust toolchain of version 1.95 or newer, the `rust-version` in `Cargo.toml`: the
project uses edition 2024 and `std::hint::cold_path`, which was stabilized in 1.95. Stable 1.95.0
builds it and passes the tests and parity gates. The published benchmarks were built with rustc
1.98.1. Linux on x86-64 is the tested platform.

```bash
cargo build --release          # target/release/vol, for benchmarks and daily use
cargo build --profile fast     # target/fast/vol, optimized without LTO, quick to rebuild
cargo test --profile fast      # unit and differential tests
```

The release profile uses fat LTO and a single codegen unit. The repository's
[.cargo/config.toml](.cargo/config.toml) adds two compiler flags to every build:

- `-C target-cpu=native` compiles for the CPU of the build machine. The binary may use
  instructions such as AVX2 or BMI2 without checking for them, so it can crash with an illegal
  instruction on an older or different CPU.
- `-C target-feature=+crt-static` links a static-pie binary, which skips the dynamic loader and
  runs on any x86-64 Linux with no shared library requirements.

The same file limits a build to 6 parallel jobs; pass `-j <N>` to cargo to use more.

To build a binary for other machines, override the flags with `RUSTFLAGS`, which replaces the
`rustflags` of the config file:

```bash
# generic x86-64, still static
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release

# CPUs with AVX2, such as Intel Haswell and AMD Zen or newer
RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+crt-static" cargo build --release
```

The SIMD code paths, which cover scanning, JSON parsing, crypto, the snappy, Xpress and bzip2
decoders and the Linux kernel searches, detect CPU features at run time, so a generic build still
uses AVX2, SSSE3, BMI2, AES-NI and SHA-NI where they exist. Two small helpers, the match length of
the zlib-exact compressor and the hex digits of the disassembler, use AVX2 or BMI2 only when the
build enables them, because a run-time check there would cost more than it saves. Output is
identical either way.

## No dependencies

`Cargo.toml` has an empty `[dependencies]` table and must stay that way. rsvol uses the Rust
standard library and calls a few libc functions such as `mmap` directly, since `std` already links
libc. Everything python volatility3 gets from third-party packages is implemented in the tree:
xz/lzma, zlib, bzip2, snappy, LZNT1 and Xpress codecs, MD5, SHA-1, SHA-256, RC4, DES and AES,
a capstone-compatible x86 disassembler, a regex engine with python `re` semantics, a YARA rule
engine, a PDB to ISF converter, and readers for JSON, zip and SQLite files.

The only external program rsvol runs is `curl`, and only where python volatility3 goes to the
network: downloading PDB files from the Microsoft symbol server, images given to `-f` or
`--single-location` as `http://`, `https://` or `ftp://` URLs together with the `.vmss` or `.vmsn`
file next to a remote `.vmem`, and remote ISF lists and files named with `-u/--remote-isf-url`.
`--offline` disables all of them.

## Web UI

`vol serve` starts a local web application for one image:

```bash
vol serve -f <IMAGE>
```

```text
rsvol web UI · Volatility 3 Framework 2.28.2
  image   /cases/memory-dirty.raw (5.0 GiB)
  output  /cases/vol-serve-output
  open    http://127.0.0.1:8765/#token=1c5fa1176bd21e349985b1160bfc6ac6
Anyone with this URL can read the image. Press Ctrl+C to stop.
```

Open the printed URL. The UI offers a searchable plugin palette with option forms, result tables
that stay fast with millions of rows, an interactive process tree with per-process views, a hex
viewer and disassembler over any layer, side-by-side comparison of two runs, and exports. The
image stays open between runs, so only the first plugin pays for kernel discovery.

The server listens on 127.0.0.1 by default and every API call must carry the random 128-bit
access token from the URL. Host headers are checked against DNS rebinding and cross-site requests
are refused. Treat the URL as a password. The full tutorial and reference, including the security
model, are in [docs/web-ui.md](docs/web-ui.md).

## Caching

rsvol keeps its own cache in `~/.cache/rsvol`, or in `$XDG_CACHE_HOME/rsvol` when that variable is
set. It reads and writes python's symbol directory `~/.cache/volatility3/symbols` too, so symbol
files downloaded by either tool are shared.

| What                               | Where                                           | Why                                                        |
| ---------------------------------- | ----------------------------------------------- | ---------------------------------------------------------- |
| Binary symbol tables               | `~/.cache/rsvol/isf/*.isfb`                     | A warm symbol table load is one `mmap`, with no JSON parse |
| Symbol file identifier index       | `~/.cache/rsvol/identifiers.cache`              | Finds the ISF for a kernel banner or PDB without rereading |
| python's identifier cache (read)   | `~/.cache/volatility3/identifier.cache`         | Seeds the identifier index, and picks python's ISF        |
| Kernel discovery results           | `~/.cache/rsvol/automagic/`                     | Warm runs skip the DTB, KDBG and banner scans              |
| Windows ISF choices                | `~/.cache/rsvol/isfchoice/`                     | Warm runs skip the identifier index for Windows PDBs       |
| Raw scan hits                      | `~/.cache/rsvol/scan/`, capped at 256 MiB       | Scanning plugins replay hits instead of rereading memory   |
| `isfinfo --live` results           | `~/.cache/rsvol/isfinfo.cache`                  | Warm `isfinfo` runs parse no files                         |
| Downloads                          | `~/.cache/rsvol/data_<SHA512>.cache`            | Remote images and `-u` files are downloaded once           |
| Decompressed images                | `~/.cache/rsvol/decompressed/`                  | A `.gz`, `.bz2` or `.xz` image is decompressed once        |
| Downloaded Windows PDBs            | `~/.cache/volatility3/data_<SHA512>.cache`      | Kept where python keeps them, and shared with python       |
| Converted Windows PDBs             | `~/.cache/volatility3/symbols/windows/`         | Shared with python volatility3                             |

A binary symbol table is written after the run that first loads its ISF. For a big ISF, such as
a Linux kernel's, that run resolves only the types and symbols it uses, and a helper process
started after its output is complete writes the table in the background, at idle priority,
while the run exits: `ps` shows it as `rsvol-isfb-helper`. Concurrent runs build a table once.

A downloaded PDB is converted to `windows/<PDB>/<GUID>-<AGE>.json.xz` in the first symbol
directory where the file can be created, as python does: normally
`~/.cache/volatility3/symbols`, but a writable `-s` directory or python volatility3 installation
comes first. The PDB itself stays in python's cache directory under the name python gives it,
`data_` and the SHA-512 of its symbol server URL, or in the `--cache-path` directory. python finds
it there, and rsvol uses a PDB that python or rsvol downloaded before instead of downloading it
again.

Downloads are named like python's, `data_` and the SHA-512 of the URL, and like python's they are
never checked for changes on the server.

A decompressed image is stored with its key: the image location and the canonical path, size and
modification time of the compressed file. When the compressed file changes, the next run
decompresses it again and deletes the old copy, and copies of compressed files that no longer
exist are deleted whenever an image is decompressed. A copy is as big as the uncompressed image.

When python volatility3 has run on this machine, rsvol reads its identifier cache (never writes
it; `--cache-path` selects it as for python) instead of reading every symbol file on the search
path. It takes python's entries exactly as python's own cache update would keep them and reads
only the files python would read again, so a first run with a large symbol pack costs
milliseconds instead of hundreds. When several ISFs carry the same Linux or macOS banner or the
same Windows PDB GUID and age, for example `x.json` next to `x.json.xz`, or a kernel ISF both in
volatility3's `symbols` directory and in `~/.cache/volatility3/symbols`, python loads the one
its cache lists last, and so does rsvol. Without python's cache, or with `--clear-cache`, which
makes python start a new one, rsvol takes the one python's new cache would list last. The
answer for a Windows PDB is kept in `~/.cache/rsvol/isfchoice/` until python's cache or a
directory on the search path changes. Set `RSVOL_NO_PY_IDENT_SEED=1` to build the index from
the symbol files alone, in search path order.

To empty the caches, run any plugin with `--clear-cache` or delete the directory. Like python's
`--clear-cache`, which deletes every `*.cache` file in its cache directory, downloads included,
rsvol's deletes every `*.cache` file in `~/.cache/rsvol`: downloads, the identifier index and the
`isfinfo` cache. It also removes the symbol tables, the kernel discovery results, the Windows
ISF choices, the scan results and the decompressed images. It deletes nothing outside
`~/.cache/rsvol`, so converted PDBs and python's own cache stay. Where python's `--clear-cache`
would have deleted a file in its own cache, rsvol ignores that file for the run: it does not read
python's identifier cache but chooses ISFs as python's new one would, and it downloads a needed
PDB again.

```bash
vol --clear-cache -f <IMAGE> windows.info.Info
rm -rf ~/.cache/rsvol
```

A cache can make a run faster but cannot change its output:

- Every cache file stores its complete key and the key is compared on load, so a hash collision
  or a stale file is a miss, never a wrong answer.
- Keys identify their inputs. Image-based caches use the canonical path, size and modification
  time of the image; the scan cache adds the inode and the identity of the rsvol executable, so a
  rebuilt binary never trusts scans recorded by an older one. Symbol tables are keyed by the
  source file's URL, size and modification time and the table format version.
- The scan cache stores raw byte matches (and, for `vmscan.Vmscan`, the few hundred image bytes of
  each matched page that its checks read), never a plugin's results. On a replay every plugin
  still runs all of its python-equivalent validation on those matches, in python's order.
- Writes are atomic, so a crash or a concurrent run leaves either the old file or the new one.
- The parity gates run the reference comparisons twice, once with an empty cache and once warm.

The one assumption: an image file whose size and modification time did not change still has the
same contents. If you modify an image in place and restore its timestamp, clear the cache.

### Environment variables

| Variable                 | Effect                                                                              |
| ------------------------ | ----------------------------------------------------------------------------------- |
| `RSVOL_CACHE=<DIR>`      | Use `<DIR>` as the rsvol cache directory. An empty directory gives a cold run.      |
| `XDG_CACHE_HOME=<DIR>`   | Base directory of both the rsvol and the python volatility3 caches.                 |
| `RSVOL_NO_SCAN_CACHE=1`  | Disable the scan cache.                                                             |
| `RSVOL_THREADS=<N>`      | Number of worker threads. The default is every logical CPU.                         |
| `RSVOL_NO_SIMD=1`        | Use the scalar search kernels for scanning instead of AVX2.                         |
| `RSVOL_TRACE=1`          | Print timing spans to stderr.                                                       |
| `RSVOL_VOL3_ROOT=<DIR>`  | Use the symbol directories of the python volatility3 checkout at `<DIR>`.           |
| `RSVOL_NO_PY_IDENT_SEED=1` | Build the identifier index without python's identifier cache, in search path order. |
| `RSVOL_LAZY_ISF=0`       | Build every symbol table in full before the plugin runs.                            |
| `RSVOL_DEFERRED_ISFB=<M>` | How the binary table of a lazily loaded ISF is written: `helper` (default), `thread` (by the run itself, before it exits) or `off`. |

## Verification

Parity is tested by diffing rsvol's stdout, exit status and dumped files against python volatility3
2.28.2, running on CPython 3.14.7 with capstone, yara-python and pycryptodome installed. Every plugin
that runs without arguments is compared on every image listed in [bench/images.tsv](bench/images.tsv);
at the last full gate **all 1,975 plugin/image pairs on 31 images were byte-identical** (0 diffs):

| OS | Images (format) |
| -- | --------------- |
| Windows x64 | Windows 11 22000 (raw, 5 GiB, 98 plugins); Windows 11 24H2 26100 (full crash dump); Windows 10 19041 (bitmap crash dump); Windows 10 17763 (raw); Server 2012 R2 9600 (raw); Windows 7 SP1 (raw, synthesized full crash dump) |
| Windows x86 | Windows 7 SP1 PAE (raw, synthesized bitmap crash dump); Server 2008 SP1 PAE (raw); Vista SP2 (32-bit crash dump); Server 2003 (raw); XP SP3 (32-bit crash dump); XP SP2 (raw) |
| Linux x64 | kernels 3.2 (Debian 7), 4.15 (Ubuntu 18.04: ELF core, VMware .vmem/.vmss, AVML), 5.15 (ELF, LiME), 6.8 (ELF, LiME), 6.17 (ELF, QEMU savevm), 7.0 (ELF) |
| Linux x86 | 4.15 PAE (ELF core, LiME), 6.1 i686 (raw, LiME) |
| macOS | 10.9.2 Mavericks, 10.12.6 Sierra (raw) |

Where python itself fails (for example `linux.kallsyms.Kallsyms` raising `TypeError`, x86-only
restrictions of the GUI plugins, or python bugs such as its 8-byte `Elf32_Sym` fields), rsvol
prints the same partial output and exits with the same status. On top of the no-argument gates:

- an option x renderer sweep ([bench/scripts/sweep.py](bench/scripts/sweep.py)): every plugin's
  options (`--pid`, `--dump`, offsets, filters, invalid values), all renderers, `--save-config`/`-c`
  round trips, on 15 of the images, ~4,000 cases;
- fuzzing with corrupted images ([bench/scripts/fuzz_images.py](bench/scripts/fuzz_images.py)):
  17,000+ plugin runs on 211 mutants, no panics; hangs/OOMs that python would also suffer are
  bounded;
- differential harnesses for the libraries: YARA engine vs yara-python, regex vs python `re`,
  disassembler vs capstone, PE parser vs pefile, PDB converter vs python's pdbconv, codecs and
  crypto vs the reference C libraries;
- unit tests (535) including python-generated fixtures for argparse, `--help` and the renderers.

See [docs/development.md](docs/development.md) for how to run the gates
(`bench/scripts/check_all.sh`, `check_win_images.sh`, `check_nix.sh`).

## Known differences from python volatility3

- **Nondeterministic python output.** Some plugins print the contents of a python `set`, whose
  order changes from one python run to the next.
  - `windows.windows.Windows` orders sibling windows by the heap addresses of python objects.
    rsvol prints the same rows in list order. The parity check compares sorted output for this
    plugin, see [bench/nondeterministic.txt](bench/nondeterministic.txt).
  - `linux.mountinfo.MountInfo --mount-format`, `windows.malware.svcdiff.SvcDiff` and
    `windows.strings.Strings` depend on python's randomized string hashing. rsvol reproduces the
    order of a python run with `PYTHONHASHSEED=0`; set that variable when you compare.
  - Sets of integers, as in `psxview` and `pstree`, iterate in a fixed order in CPython. rsvol
    reproduces that order exactly, so these plugins match without any setting.
  - When several ISFs on the search path carry the same kernel banner or PDB identifier, python
    loads the one its identifier cache lists last. A cache python builds from scratch (its
    first run, or `--clear-cache`) lists new files in the order of a python `set` of their
    URLs, which depends on the randomized string hashing. rsvol follows an existing python
    cache exactly, and for a new one reproduces a python run with `PYTHONHASHSEED=0`.
- **Loading a configuration with `-c`.** rsvol takes the plugin options, the image location and
  the swap files from the file and finds the kernel in the image again, where python builds the
  layers and the symbol table the file describes. A file written by `--save-config`, by python
  or by rsvol, for the same image and symbol files gives the same output either way, but a file
  edited by hand to name another DTB, kernel offset or ISF is not followed.
- **`timeliner.Timeliner --record-config`** records each plugin that ran with the configuration
  `--save-config` would write for it. python's timeliner builds its plugins in one shared
  configuration, where plugins with the same class name, such as `windows.pslist.PsList` and
  `linux.pslist.PsList`, share one subtree and a layer stacked for one plugin is reused by the
  next, so its `config.json` can hold a few more keys, for example the other plugin's options.
- **Plugin discovery order.** python runs the `timeliner.Timeliner` plugins and lists
  `frameworkinfo.FrameworkInfo` components in the directory order of its installation, which
  depends on the file system. rsvol uses the order of the reference installation, so python on
  another file system can print a different timeline. `frameworkinfo` describes rsvol: the plugin
  list is the plugins rsvol registers.
- **Program name.** Usage lines print the name of the executable, normally `usage: vol`, where
  python prints `usage: vol.py` when started as `python vol.py`.
- **Progress and logging.** rsvol prints no progress output on stderr. `-v` prints only the
  reason kernel discovery failed, and `-l <FILE>` writes only the "Logging started" line.
- **Options that need python.** `-p/--plugin-dirs` cannot load python plugins; rsvol warns and
  ignores it. `--parallelism` is accepted and has no effect, since rsvol always uses every core
  unless `RSVOL_THREADS` says otherwise.
- **YARA.** Rules that `import` a module such as `pe` fail with "modules are not supported", and
  `--yara-compiled-file` is not supported. Plain rules, strings and conditions work.
- **Compressed images that do not decompress.** A `.gz`, `.bz2` or `.xz` image that is corrupt,
  truncated or not compressed despite its name stops rsvol before the plugin runs, with the
  decoder's error on stderr and python's "Unsatisfied requirement" message. python opens such a
  file lazily and fails while reading it, so plugins that accept the bare file, such as
  `layerwriter.LayerWriter`, print the decoder's error or a traceback instead. Valid compressed
  images give python's output.
- **Corrupt circular lists.** Where python would loop forever on a smeared structure, such as a
  cyclic subsection list in `windows.dumpfiles.DumpFiles`, rsvol stops with an error.
- **`isfinfo.IsfInfo`** leaves the `hash` column empty for rows it adds to python's identifier
  cache, and skips files that make python crash. With `--live` and no python volatility3
  installation to point at, see `RSVOL_VOL3_ROOT`, it lists the symbol files shipped with
  volatility3 under `embedded:///` URLs instead of python's installation paths.
- **Python version.** The reference is CPython 3.14. Under CPython 3.13, python volatility3
  itself prints some values differently, for example the year 144 as `144` instead of `0144`.

## Documentation

| Document                                         | Type        | Content                                          |
| ------------------------------------------------ | ----------- | ------------------------------------------------ |
| [docs/usage.md](docs/usage.md)                   | How-to      | Symbols per OS, dumping, renderers, filters      |
| [docs/web-ui.md](docs/web-ui.md)                 | Tutorial and reference | `vol serve`, its options and security model |
| [docs/architecture.md](docs/architecture.md)     | Explanation | How rsvol is built and why it is fast            |
| [docs/development.md](docs/development.md)       | How-to      | Porting plugins, parity gates, benchmarks        |
| [DESIGN.md](DESIGN.md)                           | Rules       | The contributor contract                         |
| [src/objects/README-API.md](src/objects/README-API.md) | Reference | python to Rust API cheat-sheet             |

## Contributing

Read [DESIGN.md](DESIGN.md) first: zero crates, byte-identical output, no panics on malformed
memory. [docs/development.md](docs/development.md) explains how to port a plugin and how to prove
it matches python.

## License

rsvol is a port of Volatility 3 and is distributed under the Volatility Software License 1.0,
the license of volatility3. The full text is in [LICENSE.txt](LICENSE.txt). Every source file
ported from volatility3 carries a header saying so. The license requires that you publish the
source of changes and additions you make available to others, and it counts ports and
translations as additions.

The web UI embeds a subset of the JetBrains Mono font, which is licensed under the SIL Open Font
License 1.1; see [src/web/assets/OFL.txt](src/web/assets/OFL.txt).
