# Review: output paths (renderers, stdout, file-writing plugins) — are we at the hardware limit?

Reviewer: output-path performance review. Date: 2026-09-26. Code: `6825849`.
Machine: i7-12700KF (8 P-cores with HT + 4 E-cores = 20 threads), 62 GiB RAM, Linux 7.1.8. Output
directories are on btrfs (`compress=zstd:3`) on dm-crypt (LUKS) on a Micron 2200S NVMe. **The kernel
dirty-page limits are `vm.dirty_bytes = 256 MiB` and `vm.dirty_background_bytes = 64 MiB`.** That setting
decides most of the results below. Any output beyond about 200 MB runs at writeback speed, not at
page-cache speed.

Scope:

- The renderers (`src/renderers/`: quick, csv, json, jsonl and pretty, `pyfmt`, `RowEncoder`, parallel
  pre-formatted rows).
- How stdout is written (`RawStdout`, `FLUSH_AT`), to a pipe, a file and `/dev/null`.
- Every file-writing plugin:
  - `dumpfiles`
  - `memmap --dump`
  - `vadinfo --dump`
  - `pslist`, `dlllist` and `modules --dump`
  - `layerwriter`
  - `pagecache.RecoverFs` (tar + gzip)
  - `fbdev` (PNG)
  - `timeliner`, `mftscan` and all-process `memmap` (large stdout)

Nothing in the repository was changed except this file. The prototypes and harnesses are in
`testdata/scratch/review-output/`, which is gitignored:

- `rsvol/` is the clone. `prototypes.patch` holds every prototype change. The prototypes that change
  semantics are switched on by environment variables: `RSVOL_DEFLATE_FAST=1`, `RSVOL_GZ_LEVEL=n` and
  `RSVOL_JSON_TREES=1`.
- `vol_p8` is the final prototype binary (all prototypes, plus the vadinfo parity fix of §4.7).
- `floors/` holds the floor harnesses:
  - `floors.c` covers memcpy, `/dev/null`, pipes, buffered and fsync writes, parallel writers, file
    creation, `copy_file_range`/reflink and sparse files.
  - `onefile.c` tests strategies for writing one big file.
  - `replay.c` rebuilds an exact dump set, which gives the filesystem floor for that set.
  - `reflink.c` compares per-page `FICLONERANGE` with `pwrite`.
  - `gzpar.c` measures parallel libdeflate and zlib-ng.
  - `pipeblk.c` tests pipe block sizes.
  - `psample.c` + `psym.py` form a minimal perf_event sampling profiler, because `perf` is not
    installed.
- `timeit.py` and `ab.py` are the timing harnesses: best/median, and interleaved A/B.

## 1. Verdict

**Mostly yes, on this machine.** Almost every large-output path is bound by the filesystem: btrfs
page-cache insertion, or kernel writeback under the 256 MiB dirty limit. rsvol runs within 1.0-1.25x
of what a trivial C program needs to write the same bytes. **Five paths are not at the limit:**

- RecoverFs;
- PE dumps;
- JSON for tree-shaped plugins;
- fbdev;
- pipes to fast consumers.

The first four were prototyped and measured, and their output is byte-identical. Two
**parity bugs** in `vadinfo --dump` turned up along the way (§4.7).

| Path | Now (best) | Measured floor | At the limit? |
|---|---|---|---|
| `memmap` all processes → file (2.22 GB, 42.5 M rows) | 1.12-1.14 s | 0.92-0.96 s to write the same bytes with `write()` | **Yes** (1.2x; the gap is startup plus the first block) |
| `memmap` all → `/dev/null` | 234-264 ms (`-r none` 64 ms) | ~120-150 ms: 2.2 GB of stores at DRAM bandwidth | Near (only `/dev/null` sees this gap) |
| `memmap` all → pipe (`\| cat`) | 0.81-1.03 s | 0.53-0.65 s with DRAM-cold blocks, 0.28-0.30 s with L2-hot 256 KiB blocks | **No** (1.3-3x; fast pipe consumers only) |
| `timeliner` → `/dev/null` / file (2.84 M rows, 414 MB) | 383-446 / 519-521 ms | render share 62 ms; file adds ~0.15-0.2 s of `write` | Yes (≤1.15x) |
| `mftscan` quick/csv → `/dev/null` / file (1.39 M rows, 280 MB) | 98-129 / 185-197 ms | ~90 / ~150 ms | Yes (≤1.3x) |
| **`mftscan -r jsonl` / `-r json`** (538 / 678 MB) | 379-428 / 583-722 ms | ~130 / ~200 ms (quick + byte volume) | **No: the tree rows are JSON-encoded serially (3x)** |
| `dumpfiles` (1,630 files, 537 MiB data, 1.4 GB apparent size) | 812-912 ms (create + write 756-842 ms) | 835-853 ms to replay the same files, sparse, 1 or 8 threads | **Yes** (1.0x) |
| `vadinfo --dump` (14,022 files, 2.14 GB data, 16.7 GB apparent size) | 6.0-9.6 s | 5.4-7.9 s to replay | **Yes** (~1.0-1.2x; writeback-bound) |
| **`dlllist` / `pslist` / `modules --dump`** | dlllist 3.35-6.1 s (load 11-20), pslist 44-54 ms, modules 70-91 ms | dlllist 2.4-2.6 s to replay **sparse**; 72% of the bytes it writes are zero pages | **No: zero pages are written out** (and the image is copied twice) |
| `memmap --pid 2076 --dump` (1.89 GB apparent, 624 MiB data) | 1.7 s | ~1.0-1.3 s (0.5-0.65 GB/s writeback) | Near (1.3x) |
| `layerwriter` (5 GiB raw image, 31 k extents) | 256-454 ms | 0.44-1.16 s for a C `copy_file_range` over the same extents | **Yes** (reflink cost is per extent) |
| **`pagecache.RecoverFs`** (3.8 GB tar → 837 MB .tar.gz) | 2.59-4.05 s | ~1.3-1.4 s: prep 0.2 s + writing ~0.9 GB of incompressible .gz at 0.48-0.77 GB/s | **No (2x): compression is CPU-bound** |
| **`fbdev --dump`** (1280x800 PNG) | 16.0 ms | ~5 ms | **No (3x): per-pixel u128 conversion** |

### Top 3 opportunities (all prototyped and measured, output byte-identical)

1. **RecoverFs: a fast single-probe deflate at level 1 plus a background file-writer thread.**
   - 2.59 → 1.76 s best and 3.21 → 2.09 s median, **-32 to -35%**, in an interleaved A/B.
   - Compression CPU halves: 20.7 → 10.1 s of user time.
   - The .tar.gz is 905 MB instead of 837 MB (+8%). python's own is 842 MB.
   - The fast mode runs at 198-200 MB/s per thread against 110 for the current level 4 and 243 for
     libdeflate L1, at libdeflate L1's ratio.
   - The writer thread alone is worth -9 to -13%.
   - The tar content and stdout are unchanged: all 21,862 members match the baseline archive in
     name, type, size, link target, mode and content MD5. `gzip -t` passes.
2. **PE dumps (`pslist`, `modules`, `dlllist --dump`): write the image straight from the chunks
   python's single padded read copies, zero-copy, and leave all-zero pages as holes.**
   - dlllist writes **1.4 GB instead of 5.0 GB** on the main image. Across all 14 Windows images it
     writes 62-82% less.
   - pslist --dump: 51 → 28 ms (**-45%**). modules --dump: 91 → 54 ms (**-40%**). dlllist --dump:
     5.25 → 4.55 s best and 6.46 → 4.74 s median (-13% / -27%), with CPU down from 4.54 s to 1.79 s
     (-61%).
   - The box is writeback-bound, so the saving on dlllist grows where writeback is not the limit.
   - Byte-identical on 42/42 plugin × image runs (14 Windows images, about 45,000 files) and against
     python on winxp pid 2392.
   - A first per-page version was *not* identical: see §4.7.
3. **JSON and JSONL for tree-shaped plugins: encode complete subtrees on the worker threads**
   (`RowEncoder::tree_row`, `RowSink::rows_encoded_trees`, wired into mftscan).
   - `mftscan -r jsonl`: 379 → 145 ms (**2.6x**). `-r json`: 583 → 343 ms (**1.7x**).
   - Byte-identical on 3 images, with and without `--hide-columns`.

Smaller, also validated: the `fbdev` PNG conversion fast path, 16.0 → 7.6 ms (**2.1x**), identical PNG.

**Parity bugs found on the way (§4.7), in the shipped code, both on winxp-sp2 with `--dump`:**

- **`vadinfo --dump` writes 2 files that differ from python.** The files are
  `pid.2392.vad.0x7c9c0000-0x7d1d3fff.dmp` (3.1 MB of 8.5 MB) and `pid.944.vad.0x20000000-...`. The
  cause: the dump enumerates runs with `mapping_targets` (`walk_ranges`), but python reads each VAD
  with `read(offset, 10 MiB, pad=True)`, and the two walks disagree on a large page that runs past the
  end of physical memory.
  - Prototype fix: `IntelLayer::padded_read_chunks` per 10 MiB chunk.
  - With it, all 285 of pid 2392's files, and 4,577 of the 4,578 files of the whole run, are identical
    to python. On the main image the output is unchanged.
- **One smeared VAD (start > end, pid 4080) prints `Error outputting file` where python prints the file
  name and creates an empty file.** `get_size` wraps as `u64`, so the `maxsize` check fires; python's
  size is negative. This is a 1-line stdout difference. Not fixed in the prototype.

## 2. Method

- **Floors.** C harnesses (`floors/*.c`, `gcc -O2 -march=native`) measure what the hardware and kernel
  allow for each kind of output: bandwidth, per-call and per-file costs.
  - The most useful floor is `replay.c`. It recreates an actual dump set: same names, same sizes, same
    data segments (via `SEEK_DATA`/`SEEK_HOLE`), holes kept, `pwrite` from an mmap of the source, with 1
    or 8 threads. It shows what any program would need to produce exactly those files on this
    filesystem.
- **Profiles.** `perf` is not installed, so `psample.c` opens per-CPU `cpu-clock` perf events on the
  child with `inherit=1`. It samples user IPs at 1 kHz (`perf_event_max_sample_rate` is 1000 here) and
  reads the exec mappings from `/proc/pid/maps`. `psym.py` symbolizes the samples with `nm` and
  `readelf` against an unstripped release build (`CARGO_PROFILE_RELEASE_DEBUG=line-tables-only`).
- **Syscalls.** `strace -f -c`, and `-w` for wall time per syscall.
- **Spans.** `RSVOL_TRACE=1` gives the plugin's own spans.
- **Timing.** `timeit.py` reports best and median, with user and system time. `ab.py` interleaves the
  baseline (`/home/user/rs-vol/target/release/vol`, HEAD) and the prototype, with a fresh output
  directory for every run.
- **Parity.**
  - Stdout and dumped files are compared with `cmp` and `diff -r` against the baseline.
  - The project gates check the baseline against python. §4.7 lists the `--dump` cases they miss.
  - The PE change was additionally checked against a python run (`vol.py windows.dlllist --pid 2392
    --dump` on winxp-sp2: 103/103 files identical).
- **Noise caveat.** The box was shared with 4 other review agents (fat-LTO builds, full-image scans,
  dumps) and a running game. The load average was 5-30. All comparisons are interleaved A/B runs, and
  floors are the best observed values. Absolute times of IO-bound runs vary ±30-100% between minutes,
  so the ratios are the reliable part.

## 3. Measured floors on this machine

| Resource | Measured |
|---|---|
| memcpy (256 MiB buffers) | 1 thread 11.1-17.1 GB/s; 16 threads 18.0-19.3 GB/s; L2-resident 256 KiB 52-67 GB/s |
| `write(2)` to `/dev/null` | 104-113 ns per call up to 64 KiB, ~200 ns per 256 KiB-1 MiB call (no copy) |
| Pipe, writer → `read()` reader | 256 KiB writes: 3.5-5.8 GB/s. 64 KiB: 3.9. 1 MiB: 3.45. 4 MiB: 2.0. `F_SETPIPE_SZ` 1 MiB: 5.0 (no gain). With `cat` as the reader: L2-hot 256 KiB 7.4-7.9 GB/s, DRAM-cold 15 MiB blocks 3.4-4.2 GB/s (slicing them into 64/256 KiB writes does not help) |
| btrfs buffered `write()`, 1 stream, into page cache | 128 MiB burst: 1.9-2.7 GB/s (fsync +50-84 ms). **2 GiB of real memmap text: 2.3-2.4 GB/s** at load 7, 1.2-1.7 at load 20 |
| Same, incompressible (sustained, writeback-bound) | synthetic 1 GiB: 0.55-1.02 GB/s. **The real 798 MiB .tar.gz: 0.48-0.77 GB/s** |
| One file, other strategies | `pwrite` from 2/4/8 threads into one file: 0.93-1.19 GB/s, **no gain** (btrfs inode lock). `O_DIRECT` 4 MiB: 0.46-0.99. `fallocate` first: 0.63. Writing through an `mmap` of the output: 1.31-1.35 against 2.40 for `write` |
| Many files, parallel writers | 1.5 GiB over 1/2/4/8/16 files and threads: 1.49 / 1.93 / 1.72 / 1.07 / 1.70 GB/s (noisy; ≤1.3x from parallelism) |
| File creation (`open` with `O_CREAT\|O_EXCL`, empty file, one directory) | **10.6-37 µs per file; 1,630 files = 17-60 ms**. 1-16 threads make no difference (the directory lock). Two extra `stat`s cost +16-24 µs |
| Reflink / `copy_file_range` (5 GiB image, 31,028 compressed extents) | 0.44-1.16 s, bound by extent count. Per-4 KiB-page `FICLONERANGE`: **10-13 µs** against 1.2-4.8 µs for `pwrite`. 64 KiB runs: 0.78 µs/page against 1.84. Sparse `ftruncate` 5 GiB: < 50 ms |
| **Replay floors (exact dump sets, holes kept)** | dumpfiles (537 MiB, 1,630 files, 15 k extents): **0.83-1.18 s**. vadinfo (2,138 MiB, 14,022 files, 108 k extents): **5.4-10 s**. dlllist dense (5,043 MiB): 5.3-8.7 s. dlllist sparse (1,415 MiB): **2.4-2.6 s** (all in ~0.2-0.65 GB/s: writeback of many small compressed extents) |
| deflate, 1 thread (512 MiB of the RecoverFs tar) | ours L1 147-152 MB/s (37.5%), L4 110 (36.6%). libdeflate L1 243-258 (39.3%), L4 174-177 (37.1%). zlib-ng L1 309 (46%). **Ours, fast-L1 prototype: 198-200 (39.3%)** |
| deflate, 20 threads (1 GiB sample) | ours L1 1.60 GB/s, L4 1.26. libdeflate L1 3.39, L4 2.15. Whole 3.8 GB tar with libdeflate: L1 1.0 s, L4 1.33 s |

What these floors mean:

- **Big stdout to a file** is bound by btrfs page-cache insertion: ~1.9 µs per 4 KiB page in the
  kernel, single-threaded per file.
- **Dumps** are bound by writeback of dirty pages once they pass the 256 MiB dirty limit. The only
  lever a process has is to write fewer bytes. Parallel writers barely help here.
- **Pipes** are bound by two copies. Keeping the source in cache doubles the throughput.
- On a machine with the default `dirty_ratio` (20% of RAM, ~12 GB), dumps below that size would finish
  at page-cache speed (~2 GB/s per stream, ~1.3x with parallel files). Their data volume would still
  decide their time.

## 4. Findings by path

### 4.1 Renderers: ns per row

Stdout goes to `/dev/null`, baseline binary, best of 5, on the main 5 GiB Windows image. Δ is the
difference to `-r none`, which runs the plugin and discards the rows.

**timeliner** (2,842,936 rows, all at depth 0, so every renderer gets the parallel `RowEncoder`)

| renderer | bytes | wall | Δ wall | ns/row (wall) | Δ user CPU | ns/row (CPU) |
|---|---|---|---|---|---|---|
| none | – | 434.8 ms | – | – | – | – |
| quick | 414 MB (146 B/row) | 497.5 | +63 | **22** | +316 ms | 111 |
| csv | 420 MB | 496.1 | +61 | 22 | +482 | 170 |
| jsonl | 751 MB | 608.7 | +174 | 61 | +661 | 233 |
| json | 851 MB | 657.2 | +222 | 78 | +1053 | 370 |
| pretty | 1,561 MB | 757.8 | +323 | 114 | +1748 | 615 |

**mftscan** (1,392,590 rows: 469,963 at depth 0 and 922,627 children at depth 1)

| renderer | bytes | wall | Δ wall | ns/row (wall) | note |
|---|---|---|---|---|---|
| none | – | 79.8 ms | – | – | |
| quick | 280 MB | 128.9 | +49 | **35** | `rows_encoded_at` (parallel, tree depths OK) |
| csv | 281 MB | 132.9 | +53 | 38 | same |
| **jsonl** | 538 MB | **428.1** | +348 | **250** | **serial**: `supports_depth()` is false for json, so mftscan falls back to `row_ref` on the output thread, which builds a `JNode` per row |
| **json** | 678 MB | **722.4** | +643 | **461** | serial, plus a 678 MB `done` buffer (+150 ms of system time from page faults) |
| pretty | 578 MB | 373.4 | +294 | 211 | the grid must be complete before any output (python semantics). The line building in `finish` is parallel. +280 ms of system time from faulting in the buffered cells and output |
| jsonl, **prototype** | same bytes | **145-150** | +70-84 | 50-60 | subtree blocks encoded on the scan workers |
| json, **prototype** | same bytes | **324-343** | +245-263 | 176-190 | as above. The rest is the 678 MB `done` copy and its faults (could hand over owned blocks) |

Floor per row: the CPU has to store the bytes (146-201 B at 11-17 GB/s per core ≈ 10-15 ns) and do the
number conversions (the `pyfmt` SWAR hex/decimal/datetime ≈ 3-10 ns each). That puts quick at roughly
**25-45 ns/row of CPU**. rsvol spends 111-244 ns/row of CPU (the profiles show `render_cell`,
`push_datetime_cli`, `date_bytes`, `drop_glue<Value>`, `encode_marked` and `push_cell`, plus building
`Value`s in the plugin). That is 3-5x above a hand-tuned floor in CPU. Because it runs on 20 threads, it
costs only 22-35 ns/row of wall time, or ≤ 60 ms on the largest outputs. **Not worth chasing, except for
the serial json/jsonl path for tree plugins.** The number formatting (`pyfmt`: two-digit tables, SWAR hex
with one 18-byte store, fixed-size tail copies) is already at the level of a SIMD implementation. There
is nothing left to vectorize that would show up in wall time.

### 4.2 Stdout: `/dev/null`, pipe, file

`RawStdout` writes fd 1 directly, with no `LineWriter` and no lock. `Base` buffers 256 KiB
(`FLUSH_AT`), and blocks of at least 256 KiB go straight to `write_all` without a copy. This is the right
design. Measured on all-process memmap (2.22 GB):

| sink | rsvol | floor | comment |
|---|---|---|---|
| `/dev/null` | 234-293 ms | ~120-150 ms | Each process's ~15 MB block is formatted into recycled but DRAM-sized buffers, so 2.2 GB of stores go to DRAM. Only cache-sized blocks written immediately would avoid that, and it would matter only for `/dev/null` and fast pipes |
| file | **1.12-1.14 s** | 0.92-0.96 s (`onefile write`, same bytes, interleaved) | At the btrfs single-stream floor. Parallel `pwrite` into the stdout file, `O_DIRECT`, `fallocate` and mmap output were all measured slower (§3) |
| pipe (`\| cat`) | 0.81-1.03 s | 0.53-0.65 s (cold) / 0.28-0.30 s (L2-hot) | 1.3-3x. Needs just-in-time small blocks (≤ 256 KiB formatted right before the write). Real consumers (grep, python, less) are usually slower than `cat`: **low priority** |

timeliner: `/dev/null` 383-446 ms, pipe 441-460 ms, file 519-521 ms. mftscan: 98-102, 145-149 and
185-197 ms. The extra time for a file equals the byte volume at page-cache speed. Timeliner emits its
rows only after it has collected every plugin's events, so its `write` cannot overlap that work.

### 4.3 Dump plugins: writeback-bound, so the only lever is writing fewer bytes

**dumpfiles** is already built like the floor tools:

- page lists in parallel;
- parallel creation when no `-N` suffix can collide;
- 8 writer threads, largest file first;
- `pwritev` straight from the mmapped image;
- zero pages left as holes (528 MiB written of the 613 MiB python writes, 1.4 GB apparent size).

It runs at **1.0x its replay floor**: 812-912 ms against 835-853 ms.

**vadinfo --dump** writes sequentially in python order: 14,022 files, 108 k `pwritev` calls averaging
20 KB, holes for zero pages. `strace -w` puts 4.3 s of its 6.5 s inside `pwritev`, while their CPU time
is only 1.16 s. The rest is `balance_dirty_pages` sleeping. The replay floor with **8 threads is no
faster than with 1** (6.0-6.9 s against 5.4-7.9 s), so parallelizing vadinfo (which dumpfiles' scheme
would allow, since python catches every dump error) buys nothing on this box. The same goes for
`memmap --pid N --dump` (65% of pages are zero and are already holes; 624 MiB written in 1.7 s).

The small costs per file:

- `cli::files::create` makes 4 syscalls per file: `create_dir_all` (a `statx` plus a failing `mkdir`),
  `Path::exists` (a `statx`), then `open(O_EXCL)`.
- For vadinfo that is 42 k extra syscalls, 0.25 s of wall time under strace, ~2-4% of the run.
- Caching "directory exists" for the run and relying on `O_EXCL`/`EEXIST` alone keeps the naming
  semantics identical, because `EEXIST` already means "take the next `-N`". Not prototyped (tiny).

**PE dumps (pslist, modules, dlllist --dump) are the exception: they write the zeros.**
`pe::reconstruct` reads the whole image with `read_vec_padded(base, SizeOfImage)`. That is correct: it is
python's single padded read. `fix_image_base` then copies the whole image a second time (`raw[..a] + nv +
raw[b..]`), and `write_pieces` writes every byte.

- On the main image, 928,805 of the 1,291,169 pages dlllist writes (**72%**) are all zeros, which
  are pages never paged in.
- Across the 14 Windows images, 62-82% of dlllist's bytes are zeros.

The prototype fixes both. `IntelLayer::padded_read_chunks` exposes the chunks of `walk(addr, len,
ignore_errors = true)`. That is exactly what `read_padded` copies, python's fault skips included,
along with read_impl's single-page fast path. On top of it:

- `pe::reconstruct_parts` describes the raw piece (address, size, ImageBase patch) instead of reading
  it. `reconstruct()` still materializes it, and `reconstruct_view` is unchanged.
- The new `pe::write_reconstructed`:
  - writes each chunk straight from the mapped physical or swap layer through
    `memmap::SparseDump::range` (zero-copy `pwritev`, with all-zero 4 KiB pieces left as holes);
  - extends the file to `SizeOfImage`;
  - then writes the ImageBase patch and the section-header pieces with positional writes, as python's
    seek + write does.
- If the patch does not fit inside the image, or the layer is not an Intel layer, it materializes
  the piece exactly like `reconstruct` and writes it sparse.

Results:

| image × plugin | allocated before → after | time (interleaved A/B, best / median) |
|---|---|---|
| main: pslist --dump (113 files) | 42 → 20 MiB | 51.3 → 28.3 ms (-45%) / 68.9 → 42.0 ms (-39%) |
| main: modules --dump (183) | 77 → 61 MiB | 90.6 → 54.2 ms (-40%) / 94.9 → 58.2 ms (-39%) |
| main: dlllist --dump (5,446) | 5,044 → 1,416 MiB | 5.25 → 4.55 s (-13%) / 6.46 → 4.74 s (-27%) at load 11-15. CPU (user + system) 4.54 → 1.79 s |
| all 14 Windows images × 3 plugins | 62-82% less for dlllist | **42/42 byte-identical** (stdout, names, contents). winxp pid 2392: 103/103 files identical to a python run |

dlllist stays writeback-bound. The replay floor for its sparse set is 2.4-2.6 s (measured at load
~11, when the baseline took 3.35 s). What remains is the single thread writing in python order: 0.28 s
of user and 1.5 s of system CPU, which cannot overlap the throttled writeback. Writer threads, as in
dumpfiles, would close that.

**Reflinking from the image or from earlier dumps** was measured and **rejected**:

- An index of every 4 KiB image page shows that only 4.4% (dumpfiles, 18 MiB) and 3.5% (vadinfo,
  75 MiB) of the dumped non-zero data sits in image-contiguous runs of 16 pages or more.
- vadinfo re-dumps 54.7% of its pages (shared DLL pages across processes). Only 177 MiB of those come in
  runs of 16 pages or more from one earlier file.
- A 4 KiB reflink costs 10-13 µs, more than writing the page. It would also scatter hundreds of
  thousands of shared 4 KiB references into 128 KiB zstd extents, which makes the dumps slow to read.
- Reflinks only pay for long aligned runs. `layerwriter` already uses them.

### 4.4 layerwriter

The whole layer is written with `copy_file_range` in 256 MiB pieces on all cores. btrfs turns that into
reflinks, and holes stay holes. On the raw image: **256-454 ms** for 5 GiB and 31,037 extents. That is
faster than the C harness's best (0.44 s), because cloning costs are per extent. It is at the floor. A
single `FICLONE` would have the same per-extent cost.

### 4.5 RecoverFs: CPU-bound compression, then writeback-bound

Profile of the baseline:

- **20.7 s of user CPU**: 78% in `Compressor::compress_segment` and 14% in `write_seqs` +
  `write_block`.
- The producer (main) thread uses only 0.56 s, mostly `memmove`. The tar producer is not the
  bottleneck.
- 3.8 GB of tar compress at level 4 at ~110 MB/s per thread.

The gzip bytes do not have to match python (the tar timestamps differ anyway, and only the member
contents count), so the level and the algorithm are free.

- **Fast single-probe level 1** (prototype, in `deflate_enc.rs`: `Params::fast`, `Mf::find_fast`,
  `insert_range_fast`):
  - One 4-byte hash bucket probe and greedy parsing.
  - No chains and no 3-byte table.
  - Hash-only inserts inside matches.
  - The existing RLE path, block splitter and Huffman writer are unchanged.
  - Result: **198-200 MB/s per thread, 39.3% ratio**, identical to libdeflate L1's ratio and 82% of its
    speed. The current L1 is 147-152 MB/s at 37.5%, and L4 is 110 MB/s at 36.6%.
  - The codec unit tests pass with the fast mode on, including the round trip through our inflater.
- **Background writer** (prototype, `util/bgwrite.rs` `ThreadWriter`, 1 MiB buffers, 16 queued):
  - The compressed output is written on its own thread, so when writeback throttles the file, the
    pipeline keeps compressing.
  - Before this change `GzipEncoder::collect_one` called `write_all` on the producer thread.

| A/B, noble-6.8 ELF | best | median |
|---|---|---|
| baseline (L4, BufWriter) | 2,592 ms | 3,211 ms |
| L1 (current algorithm) | -9.5% | -18% (earlier run) |
| fast L1, BufWriter | 2,518 against 3,587 (-30%) | -26% |
| L4 + writer thread | -13% | -22% |
| **fast L1 + writer thread** | **1,759 ms (-32%)** | **2,092 ms (-35%)** |

With the fast mode, user CPU drops to 10.1 s, and 28% of it is now the block writer (`write_seqs`,
`write_block`, `huffman_lengths`, and the quicksort in `huffman_lengths`).

Remaining floor: prep 0.2 s plus writing ~0.9 GB of incompressible .gz at 0.48-0.77 GB/s ≈ **1.3-1.4 s**.
Two more steps would get close to it:

- Closing the last 20% to libdeflate L1 (block writer, literal-run bit packing) cuts CPU further.
- Keeping level 4 matches python's size better but costs 2x the CPU. At this machine's write floor,
  fast L1 is the better trade.

### 4.6 fbdev PNG

`fb_raw_to_rgba` handles each pixel with u128 shifts and masks and per-field branches: 14 ns/pixel,
69% of the run's CPU. For a 32 bpp framebuffer whose channels are whole bytes (the common case), the
conversion is a byte shuffle. The prototype runs it through a 4-entry index table, with a unit test
comparing it to the generic path on 5 layouts plus short buffers. **16.0 → 7.6 ms** (best of 15, A/B).
The PNG is identical. What remains is `zlib_exact` (pillow's exact zlib level 6 bytes are required, so
it is sequential by nature) and reading the 4 MB framebuffer.

### 4.7 Parity notes found on the way (important for anyone touching PE or dump code)

- **A page read on its own is not the same as that page inside one long padded read.**
  - This was the first sparse PE prototype. It wrote from mmapped pages one at a time (via
    `SparseDump::range`) and differed on `winxp-sp2 pid 2392 SHELL32.dll`: 992 pages, 3.1 MB.
  - python (checked with `vol.py`) and the baseline agree with each other.
  - The cause: VA `0x7cc00000-0x7d000000` sits behind a 4 MiB PDE whose physical range runs past the
    end of the image.
    - python's `_mapping` validates the rest of the large page as one chunk. It skips with its mask
      arithmetic, which zeroes an alternating set of pages.
    - A per-page read (and `translate()`, and `slice()`) validates only its own 4 KiB, so it returns
      data.
  - The final prototype writes the exact chunks of the single walk (`padded_read_chunks`), so it is
    both zero-copy and identical.
- The same probe shows that `mapping_targets`/`walk_ranges` reports those pages as mapped, for the
  same range, where `walk(ignore_errors)` (the padded read) zeroes them or takes other physical pages.
  Its doc comment says it gives "the same chunks as walk".
  - This is a **real parity bug in `vadinfo --dump`**, which enumerates runs with `mapping_targets`
    while python reads each VAD in `read(offset, 10 MiB, pad=True)` calls.
  - On winxp-sp2 the full `vadinfo --dump` (4,578 files) differs from python in 2 files:
    `pid.2392.vad.0x7c9c0000-0x7d1d3fff.dmp`, where 3.1 MB differ in both directions, and
    `pid.944.vad.0x20000000-0x202c4fff.dmp`.
  - Prototype fix in `vad_dump`: walk python's 10 MiB chunks with `padded_read_chunks`. Both files
    become identical to python. The main image's 14,022 vadinfo dumps are unchanged, and the speed is the same within noise.
  - `memmap` (walked from 0) matches python on the same process; its stdout was checked against a
    python run.
- **`pe::PeView` (verinfo, iat, pe_symbols) materializes pages one at a time**, so it would diverge from
  python for a module whose resource or IAT lies on such a page. It is not visible in any reference
  output today: verinfo prints `-` for this module in both. The fix is to build its pages from
  `padded_read_chunks` over the whole image. The probe is `review_probe_page_vs_long_read` in
  `prototypes.patch`.
- **`vadinfo --dump` on a smeared VAD with start > end** (winxp-sp2 pid 4080, VAD `0x81373148000-0x40ffff`):
  - python computes a negative size, skips the `maxsize` test, creates an empty file and prints its
    name.
  - rsvol's `get_size` wraps as `u64`, so `0 < maxsize < size` holds, and it prints `Error outputting
    file` with no file created. That is a 1-line stdout difference.
  - The fix is to compare the size as a signed number (`i128`). Not prototyped.
- The existing gates did not catch these because the multi-image references run plugins without
  arguments. `vadinfo --dump` on the 30 extra images is only covered by the sweep's option cases. A
  gate that diffs `--dump` output against python on every image would have caught them.

## 5. Ranked opportunities

| # | Opportunity | Gain (measured unless noted) | Effort | Risk | Status |
|---|---|---|---|---|---|
| 1 | RecoverFs: fast single-probe deflate L1 + `ThreadWriter` | -32 to -35% wall (2.59 → 1.76 s best), -51% CPU. The .gz is +8% | S-M (~100 lines + tests) | Low: the output only has to decompress to the same tar. Round-trip tests exist | **Validated** |
| 2 | PE dumps: `IntelLayer::padded_read_chunks` + `pe::write_reconstructed` (exact chunks of python's one padded read, zero-copy, holes for zero pages) | pslist/modules --dump -40 to -45%. dlllist writes 72% fewer bytes and uses 61% less CPU (-13 to -27% wall here, more on hosts that are not writeback-bound). No full-image copies | S-M (~150 lines) | Low with this version (python's single read kept). A per-page variant is **wrong** (§4.7) | **Validated: 42/42 images × plugins, python oracle** |
| 3 | JSON/JSONL subtree blocks for tree plugins (`tree_row`, `trees_end`, `rows_encoded_trees`, one-batch look-ahead in mftscan) | mftscan jsonl 2.6x, json 1.7x. Applies to any tree-shaped plugin with big output | M (~190 lines; the renderer contract gains one method) | Medium: a block must end at a tree boundary, which the look-ahead guarantees and otherwise falls back to row-by-row | **Validated on 3 images** |
| 4 | fbdev byte-shuffle fast path | 16.0 → 7.6 ms (2.1x) | XS | None (unit test against the generic path) | **Validated** |
| 5 | json renderer: keep owned subtree blocks instead of copying into `done` | est. json 343 → ~200-250 ms on mftscan (the 678 MB copy plus faults) | S | Low | Not prototyped |
| 6 | dlllist/vadinfo/memmap --dump: writer threads (dumpfiles' scheme; python catches every dump error, so order only matters for names) | est. dlllist 3.1 → ~2.5 s here. Up to ~1.3x on hosts that are not writeback-bound | M | Low-medium (the `-N` suffix rules; dumpfiles already solves it) | Not prototyped. The replay floor shows ≤1.1x on this box |
| 7 | deflate block writer (the remaining 28% of fast-L1 CPU): libdeflate-style bit packing, no sort in `huffman_lengths` | est. RecoverFs another -10 to -15% CPU | M | Low | Not prototyped |
| 8 | `cli::files::create`: cache the directory, drop `Path::exists` (use `O_EXCL`/`EEXIST` only) | 3 syscalls per file: ~2-4% of vadinfo --dump (0.25 s under strace) | XS | Low (same naming) | Not prototyped |
| 9 | Pipes: format just in time into ≤ 256 KiB blocks so the source is cache-hot | memmap \| cat: up to 1.5-3x | M-L (per-plugin block structure) | Low | Not prototyped. Only for fast consumers |
| 10 | **Parity:** vadinfo --dump reads exactly like python (`padded_read_chunks` per 10 MiB chunk) | fixes 2 differing files on winxp-sp2; speed neutral | XS | Low | **Validated** against python (4,577/4,578; the last one is #11) |
| 11 | **Parity:** a smeared VAD with start > end needs a signed `get_size` in `vad_dump` | fixes 1 stdout line and 1 missing empty file on winxp-sp2 | XS | Low | Not prototyped |
| 12 | **Parity:** PeView pages from `padded_read_chunks` instead of per-page reads | latent (verinfo, iat, pe_symbols) | S | Low | Probe written, not fixed |

## 6. Measured and rejected

| Idea | Result |
|---|---|
| Parallel `pwrite` into the stdout file | 0.93-1.19 GB/s against 1.24 for a single `write`: btrfs serializes buffered writes per inode |
| `O_DIRECT` output | 0.46-0.99 GB/s (loses btrfs compression, synchronous) |
| `fallocate` before writing | 0.63 GB/s |
| mmap the output file | 1.31-1.35 GB/s against 2.40 for `write` (`page_mkwrite` per page) |
| Bigger pipe buffer (`F_SETPIPE_SZ` 1 MiB) | 5.0 against 5.8 GB/s |
| Slicing big cold blocks into 64/256 KiB pipe writes | no gain (3.4-4.2 GB/s either way). Only cache-hot sources help |
| Parallel file creation in one directory | 17-18 ms for 1,630 files at 1-8 threads (the directory lock) |
| Reflink scattered pages from the image (dumpfiles, vadinfo, memmap) | 10-13 µs per 4 KiB reflink against 1.2-4.8 µs per `pwrite`. Only 3.5-4.4% of the data is in runs of 16 pages or more (memmap per process: 18% in runs of 64 KiB or more) |
| Cross-dump dedupe via reflink (vadinfo re-dumps 54.7% of its pages) | only 8% in runs of 16 pages or more. Metadata bloat and slow reads of the dumps |
| Parallel vadinfo writers | replay floor: 8 threads no faster than 1 (writeback-bound) |
| zlib-ng L1-style quick deflate for RecoverFs | 309 MB/s but a 46% ratio: +25% bytes to write at 0.5-0.8 GB/s of writeback. Worse than fast L1 overall |

## 7. Plan

1. **Parity fixes, before any speed work** (#10-#12).
   - Fix the `vad_dump` read semantics as prototyped (`padded_read_chunks` over python's 10 MiB
     chunks).
   - Compare the VAD size as a signed number.
   - Build PeView pages from `padded_read_chunks`.
   - Add python-oracle checks of `--dump` outputs (vadinfo, dlllist, `memmap --pid`) on every Windows
     image to the gates. winxp-sp2 is the image that exposes both bugs.
2. **PE sparse dumps** (#2).
   - Land `padded_read_chunks`, `reconstruct_parts` / `RawPiece` and `write_reconstructed`.
   - Switch `modules::dump_pe` and `pslist::process_dump` to them.
   - Gate: `check_win_images.sh` plus the `--dump` sweep cases. The prototype already passes
     `o/pecheck.sh` on all 14 images.
   - Add tests for a PE whose `SizeOfImage` is not page aligned, one whose section headers extend the
     file, and the winxp large-page case.
3. **RecoverFs** (#1).
   - Make fast L1 the level-1 algorithm of `deflate_enc`. If zlib-format callers depend on L1's ratio,
     use a separate `Params::fast` instead.
   - Set `GZ_LEVEL = 1`.
   - Put the `ThreadWriter` behind all three compressors.
   - Gate: round-trip tests, the RecoverFs member comparison (`o/tarcmp.py`), bz2/xz unchanged.
4. **fbdev** (#4): as prototyped.
5. **JSON trees** (#3 + #5).
   - Land the encoder and renderer API.
   - Use it in mftscan and in any other tree-shaped plugin with large output: look for `row_ref(depth`
     with depth > 0 in hot plugins.
   - Hand blocks over owned in json mode.
   - Gate: the renderer fixtures, and the sweep with `-r json`/`-r jsonl` on all images.
6. Optional: dump writer threads (#6), the deflate block writer (#7), `files::create` syscalls (#8),
   just-in-time pipe blocks (#9).
7. Document in BENCHMARKS/README that dump and large-output timings depend on `vm.dirty_bytes` and the
   filesystem. On this box (256 MiB dirty limit, btrfs zstd + LUKS), any dump beyond ~200 MB runs at
   0.3-0.7 GB/s of writeback, whatever the tool does.

## 8. Reproduce

```sh
cd /home/user/rs-vol/testdata/scratch/review-output
floors/floors {memcpy|null|pipe|write|parwrite|create|cfr|mmapw} fw [IMG]   # floors, fw = btrfs scratch dir
floors/onefile o/memmap_sample.txt fw 2116 {write|pwrite_mt N|direct|mmap|falloc}
floors/replay SRC_DUMP_DIR fw/rp {1|8}                                     # replay floor of a dump set
floors/reflink IMG fw/rl 65536 {1|16} THREADS {0=FICLONERANGE|2=pwrite}
floors/gzpar o/rfs.tar {libdeflate|zng} LEVEL THREADS
floors/psample out.samples -o /dev/null VOL ARGS...; python3 floors/psym.py out.samples VOL 30 --main
./ab.py 5 o/ab -- BASE_CMD... -- PROTO_CMD...                              # interleaved A/B, fresh -o dir
RSVOL_GZ_LEVEL=1 RSVOL_DEFLATE_FAST=1 ./vol_p8 -q -s ../../symbols -o o/ab -f IMG linux.pagecache.RecoverFs
RSVOL_JSON_TREES=1 ./vol_p8 -q -r jsonl -f IMG windows.mftscan.MFTScan
o/pecheck.sh                                                               # PE dumps: baseline vs prototype, all Windows images
```
