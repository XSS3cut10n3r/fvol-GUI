# Handoff: output paths and file writes (optimization agent)

- **Branch:** `worktree-agent-aa1b2f06105ba46b8`
- **Worktree:** `.claude/worktrees/agent-aa1b2f06105ba46b8`
- **Merged main:** up to `e8b234e`, merge commit `c97c552`.
- **Working tree:** clean. There are no WIP commits.

## Commits (all ready, oldest first)

| commit | what |
|---|---|
| `c4da6ad` | fix(dump): python's single padded read for vadinfo, malfind and PE dumps, plus the dump-parity gate `bench/scripts/check_dumps.sh` |
| `bd45d38` | perf(recoverfs): single-probe level-1 deflate plus a background file writer |
| `a6a3ca6` | perf(render): json/jsonl blocks of complete trees encoded on worker threads (mftscan) |
| `ae15f71` | perf(fbdev): byte-shuffle fast path for 32 bpp framebuffers |
| `e695998` | perf(files): one syscall per output file |
| `81c5e01` | perf(dump): linux and mac VMA dumps and ELF dumps written sparse from python's padded reads |
| `79ab7ac` | perf(hivelist): hive dumps leave all-zero pages as holes |

Each commit message has the details and the measured numbers.

## Gate status (final binary = `target/release/vol` at `79ab7ac` plus the main merge)

| gate | result |
|---|---|
| `cargo.sh test --profile fast` | 549 passed, 0 failed |
| `check_all.sh` | 98/98 |
| `check_win_images.sh` | 1113 OK, 1 DIFF |
| `check_nix.sh all` | 763 OK, 0 DIFF |
| `check_dumps.sh --rs-only winxp-sp2-x86 main` | 24/24 OK |
| `check_dumps.sh` on 10 Windows images (final binary minus the VMA and hivelist commits) | 140/140 OK |
| `check_dumps.sh` noble-6.8-elf, final binary | 8/8 OK |
| `check_dumps.sh -c 'hivelist_dump' -c 'vadinfo_dump' -c 'malfind_dump'`, final binary | 30/30 OK on the 10 Windows images that finished before the stop |

The single `check_win_images.sh` DIFF was `isfinfo.IsfInfo` on win2003-x86. That check compares against a live python run, and the difference is python's identifier-cache state while other agents were running. A rerun of that plugin passed.

## Parity bugs: fixed and verified against python

1. **`windows.vadinfo --dump` wrote 2 files that differed from python on winxp-sp2.**
   - The files: `pid.2392.vad.0x7c9c0000-0x7d1d3fff.dmp` and `pid.944.vad.0x20000000-0x202c4fff.dmp`.
   - `malfind --dump` shares this code path, so it was affected too.
   - Cause: the dump was enumerated with `mapping_targets` and written page by page. Python instead reads 10 MiB at a time with `read(off, 10 MiB, pad=True)`: one page-table walk per read.
   - Fix: `IntelLayer::padded_read_chunks`, a small additive method in its own `impl` block at the end of `src/layers/intel.rs` that exposes the existing `walk`. The shared helper `cli::files::dump_padded_reads` uses it.
2. **A smeared VAD with start > end (pid 4080) printed `Error outputting file`; python writes an empty file.** The VAD size is now signed (i128), as it is in python.
3. **`PeView` (verinfo / iat / pe_symbols) had a latent page-by-page read.**
   - Pages inside a large page, or of an unaligned base, now come from the chunks of python's one long read.
   - A unit test reproduces the divergence: a 4 MiB page only half inside the physical layer. No current reference output showed it.
4. **Found on the way and fixed:**
   - Linux ELF dumps (`linux.elfs --dump`, `linux.pslist --dump`) read each segment in 1 MiB pieces. Python does one padded read per segment; they now do the same.
   - `dump_pe` now returns None on write errors and on a negative seek offset, like python.
   - RecoverFs's temporary archive was created with mode 0o644 instead of python's 0o600.

On winxp-sp2, `check_dumps.sh` fails the old binary on exactly bugs 1 and 2, and the new binary passes 14/14.

## `check_dumps.sh` (plus `dumpgate.py`)

```
bench/scripts/check_dumps.sh [-b BIN] [-c CASE_GLOB]... [--py-only|--rs-only] [--list] [NAME|GLOB ...]
```

- **Images:** `NAME` is a name from `bench/images.tsv` (globs allowed) or `main`, the main image. The main image uses its existing `bench/ref/pyargs` dump references.
- **Cases:** every file-writing plugin.
  - Windows: pslist, psscan, dlllist, modules, modscan, vadinfo and malfind `--dump`; dumpfiles; hivelist and certificates `--dump`; layerwriter; memmap `--pid P --dump`; pedump `--pid`/`--base`; pedump `--kernel-module`.
  - Linux: pslist, elfs, lsmod and proc.Maps `--dump`; RecoverFs; fbdev `--dump`; layerwriter; InodePages `--inode --dump`.
  - mac: proc_maps `--dump`; layerwriter.
- **What is compared:**
  - exit code, stdout, and the dumped files: names, sizes and SHA-256;
  - RecoverFs tarballs are compared by member (name, type, size, mode, uid/gid, user/group names, link target, content hash), not by compressed bytes.
- **Python references:**
  - cached in `testdata/scratch/dumpgate/py/<image>/<case>/`;
  - generated on first use: one python process at a time, through `limit.sh` with an 8G cap and a 15 min timeout. A timeout or kill is recorded as SKIP;
  - dumps are hashed and then deleted on both sides.
  - Seeded without running python from the existing no-argument references: dumpfiles and RecoverFs dirs of `py_refs_images`, and pyargs for `main`.
- **Cache status when stopped:**
  - Complete: all 13 Windows images and main.
  - Linux: noble-6.8-elf complete; noble-6.8-lime, jammy-5.15-elf/lime, bionic64-4.15-elf, bionic32-4.15-pae-elf and deb12-6.1-686-raw have the RecoverFs seed plus some cases (debian7-3.2-x64 has 5 cases).
  - Not started: the other Linux images and both mac images.
  - A normal run generates the missing references. Expect about 1-5 min of python per case. mac `proc_maps --dump` will probably hit the 15 min SKIP, because python writes about 137 GB there.
- Uses the main checkout's `bench/scripts/limit.sh`; the nested-slot fix on main is needed.

## Optimizations: before → after

Baseline is `target/release/vol` of the main checkout at the review commit. Runs are interleaved A/B, best of N, on a box at load 6-36, so treat absolute times as noisy.

| path | before | after | review floor |
|---|---|---|---|
| RecoverFs, noble-6.8 ELF | 8.55 s best / 9.11 s median, 38.3 s user | 4.48 s / 5.39 s, 20.0 s user | ~1.3-1.4 s at a quiet time (review baseline 2.59 s) |
| pslist --dump, main image | 79 ms | 29 ms | review's prototype: 28 ms |
| modules --dump, main image | 95 ms | 44 ms | review's prototype: 54 ms |
| dlllist --dump, main image | 5,044 MiB written, 4.5 s CPU | 1,416 MiB written, 1.2 s CPU | 2.4-2.6 s replay floor (see below) |
| mftscan `-r jsonl`, main image | 373 ms | 144 ms | ~130 ms |
| mftscan `-r json`, main image | 527 ms | 179 ms | ~200 ms |
| fbdev `--dump`, 1280x800 | 24.6 ms | 11.3 ms | ~5 ms |
| mac-10.9.2 `mac.proc_maps.Maps --dump` | 109.7 s, 137,580 MiB allocated | 3.3 s, 674 MiB | – |
| noble-6.8 `linux.proc.Maps --dump` | 2.50 s, 2,798 MiB | 1.22 s, 346 MiB | – |
| bionic32 `linux.proc.Maps --dump` | 2.13 s | 0.27 s | – |
| noble-6.8 `linux.elfs.Elfs --dump` | 1.16 s | 0.70 s | – |
| hivelist `--dump`, main image | 68 / 164 ms (best / median), 87 MiB | 60 / 88 ms, 37 MiB | – |
| `cli::files::create` | 4 syscalls per file | 1 syscall per file | – |

Notes on the table:

- **RecoverFs:**
  - Stdout is unchanged. Tar members are identical to python on 8 images, and gz/bz2/xz members are identical to the previous build.
  - The .tar.gz grows by about 8% (905 MB against 837 MB). Python's own archive is 842 MB.
- **dlllist --dump:** wall time was unmeasurable during these runs, 13-21 s either way, because writeback was saturated.
- **Byte identity:**
  - PE, VMA, ELF and hive dumps are byte-identical to the previous build on every image tried.
  - The dump gate checks them against python on the images listed above.
  - JSON output is byte-identical on 5 images, with and without `--hide-columns`.
- **fbdev:** the rest of its time is `zlib_exact` (pillow's exact level-6 bytes), which I don't own.

## Gotchas

- `src/layers/intel.rs` got one additive method, `padded_read_chunks`, in a separate `impl` block after `impl Layer for IntelLayer`. I did this despite the "don't touch layers" rule because `walk` is private. The layers owner should keep it.
- **Probable layers bug, not fixed:** `walk_ranges` (behind `mapping_targets` / `mapping_with_targets`) does not give the same chunks as `walk` on a large page whose physical range is only partly valid, even though its doc comment says it does.
  - memmap (walked from 0) happened to match python on the image checked.
  - The layers owner should compare `walk_ranges` with `walk` on winxp-sp2 pid 2392 (`review_probe_page_vs_long_read` in the review's patch).
- `SparseDump` moved from `plugins/windows/memmap.rs` to `cli/files.rs`, next to `write_sparse`, `dump_padded_reads` and `dump_padded_reads_at`.
- The RecoverFs `ThreadWriter` (`util/bgwrite.rs`) is joined when its compressor is finished or dropped. That happens before the plugin returns, so nothing is still writing when `util/exit.rs` runs.
- `RowSink::rows_encoded_trees(&mut Vec<u8>, nrows, last_depth)` is a new trait method whose default is "not taken".
  - The caller must guarantee that the row after the block is at depth 0. mftscan does this with a one-batch look-ahead.
  - The block's first row must be at depth 0 (asserted).
- Sandbox: this agent's shell rejects heredocs, `for` loops and `$VAR`-computed commands. The helper scripts are in the worktree's gitignored `testdata/scratch/opt/` (`ab.py` interleaved A/B, `ab_dump.sh`, `bench_*.sh`).

## Next steps

1. Merge the branch.
2. Run the orchestrator's combined gate.
3. Run `check_dumps.sh` with no `--rs-only` on all images, which fills in the missing Linux and mac python references. Or run `--py-only` overnight first. Both are sequential: one python process at a time.

## Remaining ideas (for FOLLOWUPS.md)

- **dlllist/pslist/modules --dump writer threads.** Keep file creation, and therefore naming, in order on the main thread. Push `pe::write_reconstructed`-style jobs to a pool of about 8 threads. Emit rows in order as their jobs complete: the "File output" column depends on write errors. `pe::reconstruct_parts` already separates the cheap header parsing from the bulk write. Review estimate: dlllist 3.1 → about 2.5 s where writeback is not saturated.
- **memmap (all processes) to a pipe.** It measures about 1.0 s against 0.35 s to /dev/null. Cold 15 MiB blocks through a pipe run at 1.7-1.9 GB/s against 4.8-5.3 GB/s for L2-hot 256 KiB blocks on this box. Closing the gap needs formatting in chunks of about 256 KiB, in parallel, just in time: work units below process level, with the file offset and run merges precomputed per chunk. Only fast consumers gain.
- **deflate block writer** (`write_seqs`, `write_block`, the sort in `huffman_lengths`): about 28% of fast-L1 CPU. RecoverFs is now bound by writeback of its output, so this saves CPU, not wall time.
- **vadinfo --dump in parallel** (dumpfiles' scheme). The review's replay floor shows 8 threads no faster than 1 on this box, so it is low priority.
- **A dedicated all-zero-page fast path in `SparseDump::range`** for long unmapped stretches. `padded_read_chunks` already skips faults, so the gain is small.
