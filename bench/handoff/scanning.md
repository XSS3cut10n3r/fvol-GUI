# Handoff: memory access + scanning (hardware-floor pass)

Branch `worktree-agent-a8fe8f6e9b5d7d736`, worktree `.claude/worktrees/agent-a8fe8f6e9b5d7d736`.
HEAD `bfbfd6c`, main merged at 1667990 (nothing newer on main when I stopped). All commits are ready. There is no WIP.

| Commit | What |
|---|---|
| 7e5001f | perf(layers): random-access (MADV_RANDOM) second image mapping for translation-layer reads |
| 0aa28c8 | perf(scan): pipelined virtual scans, batched chunk budget (A1), early PTE release |
| b96aaef | bench: `bench/scripts/coldcache_bench.sh` (cold/warm, reflink + FADV_DONTNEED) |
| 95d843d, f3a335d | perf(scancache): fixed-width atom files (FORMAT_VERSION 2), replay from mapped atoms |
| bfbfd6c | docs |

## Gates
The final binary is HEAD built `--release`, copied to `testdata/scratch/opt-scan/bin/vol-final`.
- `cargo test --profile fast`: 542 + 2 passed.
- `check_all`: 98/98 with `RSVOL_NO_SCAN_CACHE=1` (so the executor really runs), and 98/98 with a fresh cache.
- `check_win_images`: 1114/1114.
- `check_nix all`: 763/763. One run showed a DIFF on noble-6.8-elf `isfinfo.IsfInfo`. The live python reference was empty (4 lines) on the saturated box. A re-run of that image gave 62/62.

## Numbers
The table uses best-of-N, base = `6825849`-era main (`opt-scan/bin/vol-base`). The box was saturated (load 15-39) the whole time, so read the ratios, not the absolute times. The source files are `testdata/scratch/opt-scan/bench-{r1,r2,final}.txt`.

| Case | Base | After | Review target / floor |
|---|---|---|---|
| cold windows.pslist | 173 ms | 33 ms (quiet run); 374 -> 113 under load 30 | ~70 |
| cold dlllist | 1143 ms | 191 ms | 244 |
| cold handles | 1213 ms | 257 ms | 493 |
| cold crash-dump pslist | 540-640 ms | 47 ms | - |
| cold crash-dump dlllist | 2090-3127 ms | 139-384 ms | - |
| cold ELF / LiME pslist | 116-122 ms | 59-73 ms | - |
| cold elf psaux | 331 ms | 105 ms | - |
| cold VMware pslist | 130 ms | 100 ms | - |
| cold psscan | 1492 ms | 1411 ms | 1.28 s floor |
| warm psscan (steady) | base 68.6 / A1 56.1 / final 53.3 (same window, load 12) | pipeline end ~33-36 ms in a lighter moment | 31-33 floor |

Warm filescan, netscan and thrdscan improve by the same amount as psscan. Unchanged, within noise: warm pslist/dlllist/handles, cold and warm vmscan, banners, and memmap/vadinfo/pslist `--dump`. The dumps are dominated by the box's dirty-page writeback: 3-30 s swings for identical binaries.

`mftscan.ADS` warm, "scan cache: load" span: 7.4 -> 2.9 ms. The replay, 27.9 -> 25.5 ms, is plugin `finish` work.

## Design notes and gotchas
- **Random-access path.**
  - `FileLayer::data_random()` is a lazily created second mapping. `RSVOL_NO_RANDOM_MAP=1` turns it off.
  - `Layer::slice_random`, `read_random` and `read_padded_random` are the physical layers' random path. They are used ONLY by `IntelLayer`: page walks, `read`, `read_padded` and `slice`.
  - Physical layers' own `slice`/`read` stay on the default mapping. Otherwise objects plus `read_array` on the physical layer fault the same pages into both mappings: mftscan took +12k minor faults.
  - `Layer::slice_bulk` keeps the SparseDump dumpers (memmap, vadinfo, dumpfiles) on the default mapping. Through the random mapping, a cold memmap --dump took 33-41 s instead of 6-7 s.
  - Never advise the default mapping `MADV_RANDOM`.
- **Scan pipeline.**
  - `run_pipeline` in `scan.rs` has one set of workers doing, in priority order: plan sealed rounds > walk pieces > run items.
  - The joiner is incremental. Rounds ramp from 8 MiB to 256 MiB, with at most 16k chunks each.
  - The look-ahead is counted in bytes of item data. Counting items made 40% of thread time idle behind slow items.
  - Physical and other scans use the same scheduler (`split_rounds`).
  - `RSVOL_TRACE=1` prints thread time for walk, plan, items and idle, plus the walk-done and plan times.
- `FileLayer::release` (MADV_DONTNEED after big chunks) is roughly neutral on the CLI now that main's exit helper takes the teardown off the exit path. It is kept for `fvol serve` and for runs with the helper off.
- **Cold bench.**
  - `bench/scripts/coldcache_bench.sh -b base=BIN -b new=BIN[,ENV=V] -n 3 -c win-pslist,...`; `-l` lists the cases.
  - Eviction retries until `fincore` shows 0: pages locked by an in-flight readahead survive one DONTNEED.
  - Stdout goes to a file, not /dev/null.
  - Don't wrap `check_*.sh` in `limit.sh` on an old checkout: the nested python limit.sh deadlocked. This is fixed on main.
- **Validation helpers.**
  - `FASTVOL_BENCH_IMG=<img> FASTVOL_BENCH_WIN=1 cargo.sh test --profile fast -- --ignored scan_exact vscan_bench` checks that the pipeline and parallel chunks are identical to the sequential walk on the real image.
  - The unit tests `pipeline_matches_sequential_scan` and `pipeline_propagates_panics` use a synthetic page table.

## Next steps / remaining ideas (not started)
1. Re-measure warm pool scans and dumps on a quiet box. The round-size and ROUND_CHUNKS choice (16k) was picked under load: 8k, 64k and uncapped were within noise.
2. #5, cold read planner for virtual scans: probe with `preadv2(RWF_NOWAIT)`, then merged 128 KiB-aligned reads per round. The measured headroom is ~10%: cold psscan 1.41 s vs a 1.28 s floor.
3. Put the random-mapping PTEs of virtual scans (psscan: ~12k faults) out of teardown with a parallel release at scan end. Probably redundant with main's exit helper; measure first.
4. Group items: the slowest item is 6-10 ms against a 0.75 ms average, so there is a tail. Try smaller GROUP_BYTES or LPT ordering within a round.
5. Scancache: the replay still builds one `(offset, tag)` Vec (7.7 MB for MFT). Scanner::finish could take the mapped arrays. `Session::load` (Page atoms) still copies.
6. `#6`, the persistent pool for scan phases. `util::pool` belongs to another agent, and the consumer must stay on the calling thread.
