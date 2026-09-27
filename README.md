<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img alt="fastvol" src="docs/assets/logo.svg" width="480">
  </picture>
</p>

<p align="center">
  <b>Volatility 3 memory forensics, rewritten in Rust.</b><br>
  Same plugins, same output, a fraction of the time.
</p>

<p align="center">
  <a href="https://github.com/volatilityfoundation/volatility3"><img alt="volatility3: 2.28.2" src="docs/assets/badges/volatility3.svg"></a>
  <a href="#highlights"><img alt="plugins: 197" src="docs/assets/badges/plugins.svg"></a>
  <a href="#verification"><img alt="parity: 1975/1975" src="docs/assets/badges/parity.svg"></a>
  <a href="#highlights"><img alt="dependencies: 0" src="docs/assets/badges/dependencies.svg"></a>
  <a href="#supported-images"><img alt="images: windows, linux, macos" src="docs/assets/badges/images.svg"></a>
  <a href="#license"><img alt="license: VSL 1.0" src="docs/assets/badges/license.svg"></a>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="docs/usage.md">Usage</a> ·
  <a href="docs/web-ui.md">Web UI</a> ·
  <a href="#performance">Performance</a> ·
  <a href="#documentation">Docs</a>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/benchmark-dark.svg">
    <img alt="Bar chart on a log scale of the total time to run each benchmark plugin once. Windows 11, 77 plugins: python volatility3 4,078 s; vol-rs 183.8 s on a first run and 148.6 s on a repeat run; fastvol 4.07 s and 1.40 s. Linux 6.8, 59 plugins: python volatility3 2,804 s; vol-rs 217.2 s and 105.2 s; fastvol 8.32 s and 2.79 s." src="docs/assets/benchmark.svg" width="840">
  </picture>
</p>

## Highlights

- **All 197 plugins** of volatility3 2.28.2, with the same options, `--help`, errors and exit codes.
- **Byte-identical output** to python volatility3 on 31 images, Windows XP to 11, Linux 3.2 to 7.0, macOS.
- **1,006-2,905x faster than python**, 38-106x faster than vol-rs (total time of repeat runs, Linux to Windows).
- **Zero dependencies**: one static binary, Rust standard library only.
- **Every common format**: raw, LiME, ELF core, crash dump, VMware, QEMU, AVML, Xen, gzip/bzip2/xz.
- **Built-in web UI**: `fvol serve`.

## Install

Requires Rust 1.95+. Tested on Linux x86-64.

```bash
cargo build --release    # -> target/release/fvol
```

> [!NOTE]
> The build targets the build machine's CPU; for a portable binary see
> [docs/building.md](docs/building.md#build-for-other-machines).

## Quick start

```bash
fvol -f memory.raw windows.pslist.PsList                 # run a plugin
fvol -h                                                  # list plugins
fvol -s ./symbols -f linux.lime linux.pslist.PsList      # Linux/macOS: symbol dir
fvol -f memory.raw -o out/ windows.dlllist.DllList --dump # dump files
fvol -f memory.raw -r json windows.pslist.PsList         # quick, pretty, csv, json, jsonl
eval "$(fvol completion bash)"                           # TAB-complete plugins and options
```

Windows symbols are downloaded automatically. See [docs/usage.md](docs/usage.md).

## Web UI

```bash
fvol serve -f memory.raw   # prints a local URL with an access token
```

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/screenshots/web-ui-overview-dark.png">
    <img alt="The web UI's overview of a Windows 11 image: evidence details, a process tree with lifelines, suggested first plugins and triage hints." src="docs/assets/screenshots/web-ui-overview-light.png" width="840">
  </picture>
</p>

Plugin palette, million-row tables, process tree, hex viewer, run comparison, exports. Localhost
only, token-protected. [docs/web-ui.md](docs/web-ui.md)

## Supported images

| OS      | Arch     | Tested versions                                                             |
| ------- | -------- | --------------------------------------------------------------------------- |
| Windows | x64, x86 | XP, 2003, Vista, 2008, 7, 2012 R2, 10 (17763, 19041), 11 (22000, 26100)     |
| Linux   | x64, x86 | kernels 3.2, 4.15, 5.15, 6.1, 6.8, 6.17, 7.0                                |
| macOS   | x64      | 10.9, 10.12                                                                 |

Formats: raw, LiME, ELF core, Windows crash dump, VMware, QEMU savevm, AVML, Xen; gzip/bzip2/xz
compressed; `http(s)://` URLs; Windows page files.

## Verification

Every plugin's stdout, exit code and dumped files are diffed against python volatility3 2.28.2:

| Check                                     | Result                     |
| ----------------------------------------- | -------------------------- |
| No-argument runs, 31 images               | 1,975 / 1,975 identical    |
| Options x renderers sweep, 15 images      | ~4,000 cases, all match ³  |
| Dumped files, 31 images                   | 315 / 315 identical        |
| Fuzzing with corrupted images             | 17,000+ runs, 0 panics     |
| Unit tests                                | 600 passing                |

³ Except the documented gaps in [differences.md](docs/differences.md). How to run the gates: [docs/development.md](docs/development.md).

## Performance

Dedicated 32-vCPU KVM guest, image in page cache, sum of per-plugin best of 5
([full results](bench/vm/BENCHMARKS.md)). Cold = all caches empty; warm = repeat run.

|                              | python | vol-rs cold | vol-rs warm | fastvol cold | fastvol warm |
| ---------------------------- | -----: | ----------: | ----------: | -----------: | -----------: |
| Windows 11, 77 plugins       | 4078 s |     183.8 s |     148.6 s |       4.07 s |       1.40 s |
| Windows, median plugin       | 4.49 s |      624 ms |      164 ms |      22.8 ms |       5.2 ms |
| Linux 6.8, 59 plugins        | 2804 s |     217.2 s |     105.2 s |       8.32 s |       2.79 s |
| Linux, median plugin         | 18.3 s |      2.23 s |      311 ms |      92.3 ms |       5.3 ms |
| `windows.pslist` startup     | 1.98 s |      546 ms |     78.5 ms |      19.1 ms |       2.5 ms |
| Output identical to python   |    ref |     104/136 |     104/136 |    136/136 ¹ |    136/136 ¹ |

¹ 132 byte for byte (2 against a python rerun, as python's symbol paths changed); 4 compared sorted or against the reference machine, as python's own order varies ([details](docs/differences.md)).

Why it's fast: memory-mapped images and symbol tables, all-core scanning, lazy loading,
content-keyed caches that can't change output, and from-scratch libraries that beat the C
originals. [docs/architecture.md](docs/architecture.md#performance-techniques)

## Documentation

| Doc                                            | Content                                     |
| ---------------------------------------------- | ------------------------------------------- |
| [usage.md](docs/usage.md)                      | Symbols, dumping, renderers, filters, YARA  |
| [web-ui.md](docs/web-ui.md)                    | `fvol serve` and its security model         |
| [building.md](docs/building.md)                | Build profiles, portable binaries           |
| [caching.md](docs/caching.md)                  | Cache files, `--clear-cache`, env variables |
| [differences.md](docs/differences.md)          | Known differences from python volatility3   |
| [architecture.md](docs/architecture.md)        | Internals and performance techniques        |
| [development.md](docs/development.md)          | Porting plugins, parity gates, benchmarks   |

## License

Volatility Software License 1.0, as a port of Volatility 3 ([LICENSE.txt](LICENSE.txt)). The web UI
embeds JetBrains Mono (SIL OFL 1.1).

fastvol is built on the work of the Volatility Foundation and the volatility3 contributors. It is
an independent project, not affiliated with or endorsed by the Volatility Foundation.
