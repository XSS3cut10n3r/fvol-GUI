# Handoff: libraries optimization agent (hardware-floor pass)

* Branch: `worktree-agent-aed98a4db91d4678a`
* Worktree: `.claude/worktrees/agent-aed98a4db91d4678a`. Scratch, scripts and
  binaries: `testdata/scratch/opt-libs/` inside that worktree (the Write tool refuses the
  shared checkout's `testdata/`).
* Review: `bench/reviews/libraries.md`. Prototype: `testdata/scratch/review-libs/prototype.patch`
  in the main checkout.
* Owned files: `src/yara/*`, `src/crypto/*`, `src/codecs/*` except `deflate_enc.rs` and
  `gzip_enc.rs` (now the output agent's), `src/util/resource.rs`, the yara/regex scan plugins,
  `bench/refbench/*`. Not owned: `src/layers/*`, `src/objects/*`, `src/util/par.rs`, `pool.rs`.

## Commit status

Every commit is complete: no WIP commits. main was merged at `451e64d`.

| commit | what |
|---|---|
| 76c8ccb | perf(yara): sparse-aware VAD/VMA scanning, streamed bounded-memory hits (`src/yara/rules/regions.rs`) |
| 36bc966 | fix(plugins): yarascan / regexscan / vadregexscan / vmaregexscan stream hits (HitRun RLE) |
| 67c7ee7 | perf(crypto): SHA-NI SSE/AVX transition guard + test |
| 53652ef | fix(bench): `codec_xz_micro.rs` builds again |
| 1e3917e | perf(codecs): big xz blocks streamed through a writer thread; CRC checked while in cache |
| c77f117 | perf(codecs): inflate at libdeflate parity |
| e5e8e6b | chore(util): `RSVOL_TRACE` spans for compressed-image decode vs writer drain |
| 451e64d | merge main |

**Ready to merge: yes.** Gates on the merged tree, run once with an empty private
`RSVOL_CACHE` so the ISF xz first-run path was exercised:
* `cargo.sh test --profile fast`: 550 + 2 passed.
* `check_all.sh`: 98/98.
* `check_win_images.sh`: 13 images, 1114 OK, 0 DIFF.
* `check_nix.sh all`: stopped by the orchestrator's hard stop before it finished. It is still
  to be confirmed by the combined gate. vmayarascan / vmaregexscan outputs were byte-identical
  to the base build in A/B runs on 7 Linux images, but those A/Bs used plugin arguments, which
  the no-arg gate lists do not.

## Done, with numbers

All A/B runs are interleaved against the pre-change build (`vol.base`, commit 447969b) on a
heavily loaded box. Micro-benchmarks are pinned to CPU 4 and report best-of-N user-mode
cycles.

1. **vadyarascan hole skipping** (`Matcher::scan_holes`, region engine), `--yara-string
   Microsoft` on the main image:
   * wall 1.25-1.47 s → **0.28-0.31 s**; user CPU 10.0-11.0 s → **1.9-2.1 s**.
   * The review's prototype reached 0.41 s / 2.9 s.
   * review `rules.yar`: 1.71 → 0.48 s. `mixed.yar` (contains an xor string, so it falls back
     to the full scan): 3.8 → 1.9 s.
   * Implemented without touching `layers`: the runs come from `mapping_targets()`, then
     `target.read_padded()`. That is what `IntelLayer::read_padded` does internally.
   * Also ported to linux.vmayarascan: CPU 2-10x lower, 7 Linux images identical (ELF, AVML,
     QEMU, LiME, PAE).
   * Identical VMAs are now deduplicated too, with the same page-mapping signature vadyarascan
     used.
   * Tests:
     * `scan_holes_equals_scan`: random sparse buffers, every engine type; `scan_refs` checked
       against `scan`.
     * **`scan_holes_margin_pins_context_atoms`**: plants context-anchored zero atoms at their
       maximal depth inside a hole. It passes with margin = depth, fails with depth - 1, and
       passes with the real margin, so it fails if the margin shrinks below what the engines
       need. The real maximum depth is about 8, because the atom filters reach 8 bytes; the
       margin formula plus 64 is far above that.
2. **OOM / streaming hits**:
   * vady/vma yarascan emit region by region: 16-byte `HitRef`s, and `stream_ordered` holds
     workers back once unconsumed hits exceed a memory budget. yarascan and the three regex
     scanners use `scan_each` with run-length hits (`HitRun`).
   * `zero.yar --pid 344 5816` (29 M hits): the base build is OOM-killed under `limit.sh -m 2G`;
     the new build takes 24 s at 784 MB and its 4.1 GB output is identical to the uncapped
     baseline.
   * Six pathological cases under a 2 GB cap, 30 s each: base was OOM-killed in 5 of 6; new
     streams 2-8 GB of output at 0.3-1.2 GB RSS, mostly mapped image pages.
   * vmayarascan with a zero rule on pid 1 (34 M lines): 10.1 s / 7.2 GB → 4.7 s / 0.48 GB,
     identical output.
3. **SHA-NI**: both `sha_ni::compress` functions are now `#[inline(never)]` **and** issue
   `vzeroupper` on entry.
   * Finding: `#[inline(never)]` alone is not enough. The test `ni_fast_after_avx_code` measured
     4.6 ms against 24 µs clean (190x) with only inline(never).
   * With both guards the test passes. It fails if the entry `vzeroupper` is removed; verified
     for SHA-1 in the fast test build.
4. **`codec_xz_micro.rs`**: builds and verifies again, with and without `--cfg lzma_stats`.
5. **xz first run** (2 GB single-block `xz -6`, fresh cache, windows.pslist):
   * 22.7-23.7 s → **18.8-19.3 s** wall, against a 17.7 s decode floor.
   * RSS 2.1-2.5 → 0.7 GB.
   * The decompressed image is byte-identical to the raw file.
   * How: `lzma2_decode_to` is a sliding-window decoder (dictionary + 32 MiB) feeding
     `FileSink::at`, a new positional writer thread.
   * Filtered (x86/delta) big blocks keep the mmap path.
   * bzip2 already streamed through `FileSink`; unchanged.
6. **inflate at libdeflate parity**. Old / new / libdeflate 1.25 (distro) / libdeflate built
   from source `-O3 -march=native`, in Mcyc:

   | input | old | new | distro | -O3 native |
   |---|---|---|---|---|
   | 256 MB of the win10 image | 1772 | 1416 | 1363 | 1420 |
   | second 256 MB sample | 1692 | 1276 | 1251 | 1305 |
   | binary.bin | 369 | 297 | 293 | 303 |
   | big.json.l6 | 79 | 71 | 73 | 81 |
   | isf.json | 14.1 | 11.8 | 11.9 | 12.1 |

   * Instructions 3261 → 2558 M (libdeflate 2552 M); branch misses 22.5 → 17.0 M (16.5 M).
   * `.gz` first run on 2 GB: 6.6-7.5 s → 3.75-4.2 s wall in 2 clean rounds. Later rounds hit
     box-wide I/O stalls.
   * New test `codecs_inflate_tables_decode_every_codeword`.
7. **Cold-start LZMA**: the xz block CRC is now computed in 256 KiB steps right after they are
   decoded (`lzma2_decode_into_seen`).
   * ntkrnlmp ISF: 83.8 → 80.9 Mcyc (-3.5%).
   * 50 MB `big.json`: -6.2%.

## Next steps / remaining ideas (for FOLLOWUPS.md)

1. **Parallel writer for `.gz` first runs** (highest value left for compressed images).
   * Decode is now about 2.3 s per 2 GB, while a single `write()` thread into the page cache
     takes about 3.4 s (review), so the writer is probably the bottleneck.
   * Plan: give `FileSink::at` 2-3 writer threads using pwrite, and switch
     `resource.rs::decompress_file_with` to positional mode.
   * bzip2 calls `sink.truncate`: drain the in-flight writes before accepting new ones, then
     `set_len(start + pos)` at finish.
   * Use `FASTVOL_TRACE=1` to see "decompress: decode" against "writer drain".
   * Measure only when the box is quiet: one run took 96 s wall because of global writeback
     stalls.
2. **Multi-symbol inflate tables** (2 literals per lookup when l1 + l2 <= 11), to go beyond
   libdeflate.
   * Literal entries have bits 8..15 free, so they can hold the second literal. Store it with
     a u16 write and advance `op` by `1 + double`, without a branch.
   * Build the double table from the single one in descending index order.
   * About 10K table builds per 256 MB, so check that the build cost stays below the gain.
3. **Parallel single-stream deflate decode** (rapidgzip style), 4.4 → ~1.5 s per 2 GB .gz
   (review estimate). High effort.
4. **Hole skipping for the xor / difference engine** (`Matcher`): the D stream of zeros is
   zeros. Today any xor string disables skipping (mixed.yar: 1.9 s instead of about 0.5 s).
   Also, `.{n}` repeats in regexes hide context from the atom filters, so such rules are not
   zero-inert.
5. **`gzip::member_candidates`** uses `iter().position(0x1F)`. Switch to the SIMD memchr in
   `src/yara/memchr.rs`, or start the scan lazily. It is about 14% of CPU but little wall time,
   since it runs in parallel.
6. **Identifier extraction during the ISF decode**: the symbols owner can hook
   `lzma2_decode_into_seen` or an xz-level wrapper. The review estimates about 6% of cold
   identifier-index CPU.
7. **dist == 1 inflate copy**: `[*s; 32]` goes through the stack (`vmovdqu` to rsp). Minor
   (1.6% of matches).

## Gotchas

* The worktree guard refuses Write/Edit to the shared checkout and some bash compound
  commands (heredocs, loops with variables). Put scripts in files under
  `testdata/scratch/opt-libs/`.
* The heavy `limit.sh` slots were often full. Micro-benchmarks under ~500 MB were run without
  `limit.sh`; every image run went through `limit.sh`, and OOM tests used `-m 2G`.
* The in-tree LZMA2 encoder references the whole block (hash heads), so its streams need
  dict = block size. The sliding-window test therefore builds a stream from independently
  encoded segments.
* `push_run` must never extend a run created by an earlier `scan()` call, because the scan
  framework reorders a work item's hits per chunk. That is what the `base` argument is for;
  a unit test covers it.

## Test / bench commands

* `bench/scripts/cargo.sh test --profile fast` (yara, codecs, crypto tests included).
* A/B scripts in `testdata/scratch/opt-libs/`:
  * `ab.sh N NAME args...`: `vol.base` vs `vol.new`, interleaved, with cmp.
  * `vma_all.sh`, `rx_all.sh`: plugin A/Bs.
  * `patho.sh`: OOM cases under 2 GB.
  * `xzimg.sh ROUNDS IMAGE PLUGIN`: first run on a compressed image with a fresh cache.
  * `xzab.sh BASE ROUNDS RUNS FILES`: xz micro A/B.
  * `infl/ab.sh BASE ROUNDS RUNS FILES`: inflate A/B with libdeflate distro and native builds.
    The inputs `infl/img256*.gz` are 256 MB samples of the win10 image.
