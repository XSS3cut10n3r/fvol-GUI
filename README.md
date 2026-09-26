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
- Median plugin run of about 10 ms on a 5 GiB Windows image, versus 4.5 s for python.
- One static binary with no dependencies: Rust `std` only, no crates. Codecs, crypto, the
  disassembler, the regex and YARA engines, the PDB parser and the JSON parser are written from
  scratch.
- A built-in web UI, `vol serve`, for browsing results, processes and memory in a browser.
- Caches that make repeat runs cheap and are keyed so that they cannot change output.

## Performance

These numbers come from [bench/vm/BENCHMARKS.md](bench/vm/BENCHMARKS.md), which holds the full
per-plugin tables, and are copied here so they can be updated from that file. They were measured
on a dedicated KVM guest with 32 vCPUs of an AMD EPYC 7302P host and 30 GiB of RAM, running
Ubuntu 25.04, with nothing else running. rsvol commit `344e88c` was compared with python
volatility3 2.28.2 on CPython 3.14.7 and with vol-rs 1.0.0, another Rust port. Each figure is the
wall-clock time of the whole process with the image in the page cache. The method is in
[bench/vm/method.md](bench/vm/method.md).

| Measurement                                     | python    | vol-rs   | rsvol    |
| ----------------------------------------------- | --------: | -------: | -------: |
| Windows x64 build 22000, 5 GiB, 77 plugins, sum | 4078.23 s | 149.69 s | 6.26 s   |
| Windows, median plugin                          | 4.49 s    | 164 ms   | 10.4 ms  |
| Linux 6.8, 3 GiB ELF core, 48 plugins, sum      | 1655.71 s | 15.79 s  | 892 ms   |
| Linux 6.8, median plugin                        | 18.03 s   | 314 ms   | 9.5 ms   |
| `windows.pslist.PsList`, warm cache             | 998 ms    | 86.8 ms  | 3.0 ms   |
| `windows.pslist.PsList`, empty cache            | 1.78 s    | 573 ms   | 73.1 ms  |

rsvol was the fastest of the three on 76 of 77 Windows plugins and on all 48 Linux plugins. The
exception is `vmscan.Vmscan`: vol-rs ships no VMCS symbol files and returns an empty table
without reading the image, while python and rsvol scan all 5 GiB.

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

The main SIMD code paths, which cover scanning, JSON parsing and crypto, detect CPU features at
run time, so a generic build still uses AVX2, AES-NI and SHA-NI where they exist. A few codec and
search routines are compiled in only when the target enables the feature, so a generic build is
slightly slower there. Output is identical either way.

## No dependencies

`Cargo.toml` has an empty `[dependencies]` table and must stay that way. rsvol uses the Rust
standard library and calls a few libc functions such as `mmap` directly, since `std` already links
libc. Everything python volatility3 gets from third-party packages is implemented in the tree:
xz/lzma, zlib, bzip2, snappy, LZNT1 and Xpress codecs, MD5, SHA-1, SHA-256, RC4, DES and AES,
a capstone-compatible x86 disassembler, a regex engine with python `re` semantics, a YARA rule
engine, a PDB to ISF converter, and readers for JSON, zip and SQLite files.

The only external program rsvol runs is `curl`, and only where python volatility3 goes to the
network: downloading PDB files from the Microsoft symbol server, and fetching remote ISF lists and
files named with `-u/--remote-isf-url`. `--offline` disables both.

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
| Kernel discovery results           | `~/.cache/rsvol/automagic/`                     | Warm runs skip the DTB, KDBG and banner scans              |
| Raw scan hits                      | `~/.cache/rsvol/scan/`, capped at 256 MiB       | Scanning plugins replay hits instead of rereading memory   |
| `isfinfo --live` results           | `~/.cache/rsvol/isfinfo.cache`                  | Warm `isfinfo` runs parse no files                         |
| Remote ISF downloads               | `~/.cache/rsvol/remote/`                        | Files fetched for `-u` are downloaded once                 |
| Converted Windows PDBs             | `~/.cache/volatility3/symbols/windows/`         | Shared with python volatility3                             |

To empty the caches, run any plugin with `--clear-cache` or delete the directory. `--clear-cache`
removes the symbol tables, the identifier index, the kernel discovery results and the scan
results. It keeps downloaded files and the `isfinfo` cache, and never deletes anything in
python's cache directory.

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
- The scan cache stores only raw byte matches. On a replay every plugin still runs all of its
  python-equivalent validation on those matches, in python's order.
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

## Verification

Parity is tested by diffing rsvol's stdout and dumped files against python volatility3 2.28.2,
running on CPython 3.14.7 with capstone, yara-python and pycryptodome installed. The reference
outputs cover seven images:

| Image                                         | Format          | Plugins compared |
| --------------------------------------------- | --------------- | ---------------: |
| Windows 11 x64, build 22000, 5 GiB            | raw             | 98               |
| Windows 10 x64, build 17763, 2 GiB            | raw             | 98               |
| Ubuntu 24.04, kernel 6.8, 3 GiB               | ELF core, LiME  | 62 each          |
| Ubuntu 22.04, kernel 5.15, 3 GiB              | ELF core, LiME  | 62 each          |
| macOS 10.9.2                                  | raw             | 27               |

Every plugin that runs without arguments is compared on every image, plus a set of argument and
renderer cases. At the full-parity milestone recorded in [bench/PACKAGES.md](bench/PACKAGES.md),
all of them were byte-identical. Where python itself fails, as `linux.kallsyms.Kallsyms` does
with a `TypeError` on these kernels, rsvol prints the same partial output and exits with the same
status. The unit tests include fixtures generated with python for the argument parser, the
`--help` output and the renderers. Separate differential harnesses compare the YARA engine with
yara-python, the disassembler with capstone, the PE parser with pefile, and the codecs and crypto
with the reference C libraries. See [docs/development.md](docs/development.md) for how to run the
gates.

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
- **Downloaded PDB symbols** are stored as plain `<GUID>-<age>.json`, where python writes
  `<GUID>-<age>.json.xz`. Both tools read both. The file URL shown by `windows.info.Info` names
  whichever file exists.
- **Remote images.** The image must be a local file, given as a path or a `file://` URL. python can
  also open `http://` and `https://` locations.
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
