# Review: memory access and scanning — are we at the hardware limit?

Reviewer: scanning / memory-access performance review. Date: 2026-09-26. Code: `6825849`.
Machine: i7-12700KF (8 P-cores with HT + 4 E-cores = 20 threads), 1 socket, 1 NUMA node, 25 MiB L3,
62 GiB RAM, Linux 7.1.8. Images live on btrfs (`compress=zstd:3`) on dm-crypt (`xts-aes-vaes-avx2`) on a
Micron 2200S NVMe (PCIe 3.0 x4, rated about 3.3 GB/s).

Scope: file mmap and `MapWindow`, Intel translation and the range walker, containers, the scan executor
(`src/layers/scan.rs`), the scan cache (`scancache.rs`), pool scanners, full physical scans, automagic
scans, translate-heavy plugins, and cold versus warm page cache.

Nothing in the repository was changed except this file. The prototypes are in
`testdata/scratch/review-scan/`:

- `rsvol/` is a clone. `prototypes.patch` holds all of the prototype changes, each switched on by an
  environment variable.
- `bin/vol-{base,a1..a6}` are the measured binaries.
- `hwbench/hwbench.rs` is the std-only floor benchmark.
- `tm.py` is the timing harness.

## 1. Verdict

**Partly.** How close rsvol is to the hardware limit depends on the path.

| Path | Now vs measured floor | At the limit? |
|---|---|---|
| Full physical scans, warm page cache (banners, mbrscan, vmcoreinfo, Linux psscan and sockscan) | **88-94%** of the page-cache read floor. That floor is itself ~90% of peak DRAM read bandwidth. | **Yes** |
| vmscan page-start sweep, warm | 27 ms. This is bound by fault-around (82k faults), and THP for file mappings is unavailable here. | Practically yes |
| Kernel-virtual pool scans, warm (psscan, filescan, netscan...) | 48 ms vs a ~31-33 ms floor: **65-68%**. **73-78%** with prototype A1. | No |
| Scan-cache replays, warm (2^nd^ run) | 1.4-10 ms. This is dominated by the fixed process cost and per-hit object reads. It is not bound by memory access. | n/a (tiny) |
| Full physical scans, cold page cache | 1.86-2.09 s vs a 1.69-1.87 s cold-IO ceiling: **90-100%** | **Yes** |
| Structure-walking plugins, **cold** page cache (pslist, dlllist, handles, info, and the page-table walk of virtual scans) | **4-9x slower than necessary.** Each mmap major fault reads 4 MiB around the faulting page. | **No: the biggest gap found** |

The three biggest opportunities, all prototyped and measured:

1. **Cold cache: map the image a second time with `MADV_RANDOM` for the translation layers** (a6).
   - Cold `windows.pslist`: 296 -> 70 ms (**4.2x**).
   - Cold `dlllist`: 2.13 -> 0.24 s (**8.7x**).
   - Cold `handles`: 3.57 -> 0.49 s (**7.2x**).
   - Cold `info`: 24-54 -> 7.5-17 ms.
   - Cold `psscan`: 9-22% faster.
   - Neutral on warm runs, on cold vmscan, and on cold `memmap`/`vadinfo --dump`. Output is byte-identical.
2. **Warm virtual scans: stop charging every mapping run to one shared atomic** (A1).
   - All pool scans get 10-15% faster: psscan 48.5-49.1 -> 42.2-44.8 ms, filescan 53-54 -> 45.6-47.6 ms.
   - User CPU drops by 35-40%.
   - About 15 lines, no risk. Output is byte-identical on 11 plugins, and the unit tests pass.
3. **Warm virtual scans: remove the serial prologue** (not prototyped).
   - Chunk building plus the plan take 10-11 ms of the 43 ms. 3.3-3.8 ms of that is a serial join, and 4-4.7 ms
     is a round plan that is only 7-way parallel.
   - Estimate: psscan 43 -> 35-37 ms. Medium effort.

## 2. Method

Tools:

- **Timing:** `tm.py`. It forks, execs, and calls `wait4`, so the wall time includes the exit teardown. It
  reports best and median wall time plus the rusage of the best run.
- **Counters:** `perf` 6.x, taken from the Arch package into scratch (`perf_event_paranoid=2`, so user-space
  counters only). Also `strace -ttt` around `exit_group` to measure exit teardown.
- **Phase breakdown:** `RSVOL_TRACE=1`, plus extra counters in the clone.

Warm-case setup:

- Warm cases use a private `RSVOL_CACHE`.
- "steady" means `RSVOL_NO_SCAN_CACHE=1`, so the scan really runs.
- "warm" means the scan cache is populated.

**Cold cache without root.** The image is copied with `cp --reflink=always`. The copy shares the compressed
on-disk extents but has its own page cache. Before every cold run, `posix_fadvise(POSIX_FADV_DONTNEED)`
evicts the copy (`hwbench evict`), so each cold run is repeatable and independent. It does not disturb the
shared image other agents were timing. Runs go through `bench/scripts/limit.sh`. **This harness is worth
keeping in `bench/`: until now the repo had no way to measure cold-cache behaviour.**

Noise:

- The machine was shared: a game used ~190% CPU, and other agents ran `rustc` builds. Load average was
  8-27.
- All A/B comparisons are interleaved, and the headline table (section 4) was taken in a quieter window
  (load average ~9).
- Treat single numbers as ±10%.

**Page-cache churn is real on this box.** When the review started, only 289 MB of the 5 GiB
`memory-dirty.raw` was resident. During the session it fell to 1.9-4.7 GB several times, under other
agents' load. Cold and partly cold runs are a normal case, not an academic one.

## 3. Hardware floors (measured)

| Floor | Method | Result |
|---|---|---|
| DRAM read bandwidth | `hwbench membw`: AVX2 OR-reduce over a 2 GiB anonymous THP buffer, best of 5 | 1 thread 30.3 GB/s; 4 threads 38.9 GB/s; 8-16 threads **40-41.7 GB/s peak**; 20 threads 34 GB/s (HT and E-cores contend). Under load: ~34-35 GB/s peak. |
| memcpy | `hwbench memcpy` (loaded) | 20 threads 18.6 GB/s of copied bytes |
| Page-cache read (warm), sequential | `hwbench pread`, 64 KiB blocks, work-stealing, 5 GiB image | 1 thread 6-12.6 GB/s; 8 threads 34.6; 16-20 threads **38.2-38.4 GB/s**. **pread + AVX2 scan, 20 threads: 37.4 GB/s = 143.7 ms per 5.37 GB.** This is the full-scan floor, ~90% of the DRAM peak. |
| Page-cache read vs block size | 20 threads | 4-128 KiB flat; 1 MiB 17 GB/s and 4 MiB 13.5 GB/s, because the buffer falls out of L2. rsvol's 64 KiB pieces are right. |
| Page-cache random reads (warm) | `hwbench randread` | 8 KiB: 20 threads **24.5 GB/s** (579 MB in 24.7 ms); 1 thread 1.78 µs/op. 4 KiB: 3.25 µs/op/thread at 20 threads. |
| mmap fault cost (warm) | `hwbench mmap`, touch 1 byte per page | Fault-around maps 64 KiB: **16,386 faults/GiB for every advice mode, including `MADV_RANDOM`**, so `MADV_RANDOM` does not change warm behaviour. 1 thread 1.6 µs/fault (~100 ns/page); 20 threads ~3.9 µs/fault. Teardown: munmap or exit costs 46-127 ns/page (60-65 ms per 5 GiB). |
| mmap vs pread for a full scan | 5 GiB, 20 threads | Global mapping 23.8 GB/s; per-worker 16 MiB windows 31.8 GB/s (munmap TLB shootdowns: 1.8-4.2 s of thread time); **pread 37-38.7 GB/s**. |
| `MAP_POPULATE` / `MADV_POPULATE_READ` | global, 3 GiB | 414 ms and 250 ms vs 152 ms for plain faulting: **slower**. |
| Huge pages for file mappings | `MADV_HUGEPAGE`, then `smaps_rollup` | `FilePmdMapped: 0`. btrfs large data folios need `CONFIG_BTRFS_EXPERIMENTAL`, which is not set. **Unavailable here.** |
| NUMA | `numactl -H` | 1 node: nothing to do |
| Thread spawn + join | `std::thread::scope` | 20 threads 146 µs; 8 threads 64 µs |
| **Cold** read, disk | reflink + evict, 5 GiB image | 28,279 of 31,028 extents are zstd-compressed at 128 KiB: 2.48 GB on disk for 5.37 GB (2.2:1). btrfs bdi `read_ahead_kb = 4096`. |
| Cold sequential | `hwbench pread` / `chunked` | 1 thread (1 MiB) 1.6-1.96 GB/s. 20 threads 2.6 GB/s. rsvol's own pattern (16 MiB items read as 64 KiB preads): **1.69-1.92 s = 2.8-3.2 GB/s**. Best: split, one fd per thread, `FADV_SEQUENTIAL` = 2.95 GB/s (noise-level difference). |
| Cold ceiling, attribution | `inblock`, zstd bench | The device delivers only 1.2-1.4 GB/s physical, 40% of its rating. Userspace zstd decompression runs at 1.0-1.3 GB/s per core. The ceiling is the kernel's btrfs-compressed read path (decompression workers, `thread_pool` 8 by default, plus dm-crypt), not the NVMe. rsvol cannot change it. The `thread_pool=` mount option is a sysadmin knob. |

## 4. Current numbers per path

Base binary (`6825849`), 5 GiB Windows 10 image, fully resident. Quiet window (load average ~9). Best of 5.
Full-scan floor = 143.7 ms, measured in the same window.

| Plugin | steady (scan runs) | warm (scan cache) | Floor | % of floor | Bound by |
|---|---:|---:|---:|---:|---|
| `banners.Banners` | 153.8 ms | 1.4 ms | 143.7 | **93%** | DRAM (kernel copy) |
| `windows.mbrscan` | 157.4 | 21.5 | 143.7 | **91%** | DRAM; warm: per-hit md5 and disassembly |
| `windows.mftscan.ADS` | 183.9 | 23.6 | 143.7 | 78% | per-hit parsing (480k matches) |
| `windows.mftscan.MFTScan` | 243.4 | 99.6 | 143.7 | 59% | 1.39M output rows; exit teardown 24-27 ms |
| `vmscan.Vmscan` | 27.0 | 1.35 | ~16-20 (fault-around sweep) | ~65% | page faults (82k) |
| `windows.psscan` | 48.1 | 2.9 | ~31-33 | 65-68% | see section 5.2 |
| `windows.filescan` | 51.0 | 8.3 | ~31-33 | 62% | same |
| `windows.thrdscan` | 51.9 | 6.1 | | | same |
| `windows.poolscanner` | 53.4 | 10.5 | | | same |
| `windows.netscan` | 47.1 | 2.1 | | | same |
| Linux 6.8, 3.24 GB, floor 94.8 ms: `banners` / `vmcoreinfo` / `sockscan` / `psscan` | 105.5 / 100.9 / 103.1 / 107.4 | 1.4 / 1.4 / 3.7 / 7.7 | 94.8 | **90 / 94 / 92 / 88%** | DRAM |

Automagic scans are already cheap:

- Windows DTB scan: 0.5 ms.
- PDB low-stub scan: 0.8-1.6 ms.
- Linux banner and VMCOREINFO notes in one early-stopping scan: 13 ms.
- All of these are cached per image, and warm runs do no scan.

Cold page cache (evicted reflink copy, one run per cell, repeated 2-3 times):

| Plugin | cold, base | Notes |
|---|---:|---|
| `banners.Banners` | 1.86-2.09 s | Cold IO ceiling for the same pattern is 1.69-1.87 s: **90-100%** |
| `windows.mbrscan` / `vmscan` | 1.78 s / 1.81-2.09 s | at the ceiling |
| `windows.psscan` | 1.83-1.98 s | 624 major faults x 4 MiB read-around = 2.8 GB read. The page-table walk alone takes 1,131 ms. |
| `windows.pslist` | 296-346 ms | 57-69 major faults x 4 MiB = 224 MB read to touch ~140 pages |
| `windows.dlllist` / `handles` | 1.49-2.13 s / 1.62-3.57 s | 2.4 GB read-around |
| `windows.info` | 24-54 ms | |
| `memmap --pid 2872 --dump` / `vadinfo --dump` | 4.0-4.3 s / 2.5-3.2 s | Warm: 1.7-2.9 s. Both are mostly write-throttled: `vm.dirty_bytes` is 256 MiB, and rsvol already writes sparse files. |

## 5. Gap attribution

### 5.1 Full physical scans (warm): at the limit

- `banners` executes in 161 ms of worker time. That is 3.13 s of busy time over 20 threads, **97%
  utilization**. The slowest 16 MiB item takes 32 ms, against an average of 9.8 ms. The tail is under 3%.
- Of the ~10 ms between floor and wall, ~1.2 ms is process start, ~5 ms is output and exit, and ~3-4% is the
  scan itself.
- User code is efficient: the P-core user IPC is 2.57, and there are only 113k user LLC misses. The Teddy
  kernel works on L1/L2-resident pread buffers.
- The DRAM traffic is the kernel's `copy_to_user` (sys time is 1.7 s of 2.4 s of CPU). That is the
  unavoidable read of 5.37 GB.
- Neither mmap (23.8-31.8 GB/s measured) nor any other syscall-free path beats pread here.
- The 16 MiB + 4 KiB python chunk overlap costs 0.02%. The re-read of the `stream_window` per 64 KiB piece is
  negligible.

### 5.2 Kernel-virtual pool scans (warm): 65-68% of floor

Workload: 330,714 python chunks over 1.8 GB of mapped kernel VA. That is 71,367 distinct file ranges
totalling 579 MB, and 20,084 of the ranges are adjacent in the file.

Base binary, quiet run, ~48 ms in total:

| Phase | Base | After A1 | Floor |
|---|---:|---:|---:|
| Process start and kernel init | ~1.2 ms | same | ~1 |
| `build chunks`: parallel page-table walk | 13-15 ms in total | 2.6-4.0 | ~2.5 |
| `build chunks`: serial join (concatenate 3,072 pieces, 8 MB) | incl. above | **3.3-3.8** | ~0 |
| `plan`: file offsets, 7 rounds sorted by file offset (7-way parallel) | 4.0-5.0 | 4.0-4.7 | ~1 |
| `execute`: 637 items, ~75% utilization, slowest item 5.5 ms | 28-31 | 28.6-31.2 | ~25 |
| Output and exit teardown (~12k faults x 16 PTEs) | ~4-5 | ~4-5 | ~1-2 |

**Root cause of base's slow walk** (perf annotate):

- 17-20% of all psscan user cycles sat on one `lock xadd`: `budget.fetch_add(1)` in `mapping_runs`, run once
  per mapping run from every walker thread on a single shared cache line.
- 96-98% of the samples in that closure land on the instruction after the xadd.
- Batching the budget (A1) cuts user CPU from ~220 ms to ~145 ms, and the walk to 2.6-4 ms.

**Execute** (thread time, 20 threads):

- `pread` is ~50%. It is page-cache work and copying per 4 KiB page, not syscalls: merging 71k preads into
  36-52k preads gained nothing.
- Teddy prescan is ~19%. It runs at ~6-10 GB/s per thread on 8 KiB ranges, while HT siblings share cores.
- `finish` is ~3%: 5,975 matches at ~2-3 µs each.
- The floor for reading these 579 MB as scattered 8 KiB reads is 24.7 ms (measured). Execute is at ~85% of
  it.

### 5.3 Warm scan-cache replays

- **filescan** replays 14,528 matches in 7-8 ms and scales poorly: 18 ms on 1 thread, 7.2 ms on 20. The
  costs are:
  - 3.6k page faults (virtual-layer object reads);
  - the in-order consumer;
  - 2 thread spawns (~0.3 ms).
- **Cache loads** take 0.02-0.3 ms, except the MFT literal atoms (480k matches): varint decoding takes
  6.3-7.1 ms, **27%** of `mftscan.ADS` warm.
- **mbrscan** warm (21.5 ms) is per-hit work: 2x md5, partition table reads, and disassembly for 5.8k hits.
- **mftscan** warm (99.6 ms) is bound by its 1.39M output rows.

### 5.4 Exit teardown

The parent waits for `exit_mmap`, which tears down everything the global image mapping populated:

- psscan: 4-5 ms.
- mftscan: 24-27 ms (45 ms under load).
- vmscan: 0.6 ms, because it already calls `MADV_DONTNEED` per chunk in parallel.

The startup review (`startup.md`) independently proposes moving teardown off the exit path. That would
cover these cases as well.

### 5.5 Cold page cache

- **Full scans** are at the ceiling of the kernel's compressed read path. The ceiling is described in
  section 3.
- **Random structure access is the problem.**
  - btrfs sets the bdi readahead to 4 MiB, and an mmap major fault reads `ra_pages` around the faulting
    page. Every cold page-table or structure access therefore costs a 4 MiB read.
  - For psscan: the walk issues 624 major faults, which pull 2.5 GB in 1,131 ms. That is 57% of the cold
    run, spent before a byte is scanned.
  - psscan's real data footprint is 17,462 compressed 128 KiB extents, 2.18 GB. On ext4/xfs with the
    default 128 KiB readahead, this read amplification would be 32x smaller.

## 6. Ranked opportunities

| # | Change | Measured / expected gain | Effort | Risk | Validated |
|---|---|---|---|---|---|
| 1 | **Second image mapping with `MADV_RANDOM`, used by the translation layers.** In `IntelLayer` it becomes the `phys_raw` pointer for page-table and data reads. Bulk readers of the physical layer (vmscan sweep, small-scan slices, layerwriter, container decoders) keep the default mapping. | **Cold:** pslist 296->70 ms (4.2x); dlllist 2,132->244 ms (8.7x); handles 3,570->493 ms (7.2x); info 24-54->7.5-17 ms; psscan -9% (-12 to -22% with global advice). **Warm:** neutral (identical fault counts, times within noise). Cold vmscan and dumps: neutral. | S (~40 lines; a6 is 35) | Performance only. **Do not apply the advice globally:** it makes cold vmscan 1.9->8.7 s and cold `memmap --dump` 12.8->54.9 s. The prototype covers raw images only; segmented containers (ELF, LiME, crash) need their small `slice()` reads routed to the random mapping too. | **Yes** (a3 global, a6 targeted; outputs identical) |
| 2 | **Batch the chunk-budget atomic in `scan::mapping_runs`** (A1). Count runs locally and `fetch_add(4096)` per batch. The code is shown below this table. | Warm pool scans: psscan -10-13%; filescan -12-15%; netscan -10-20%; user CPU -35-40%; walk 13-15 -> 2.6-4 ms | XS | None. On a corrupted layer the cap may overshoot by at most `threads x 4096` runs, still bounded. `layers::scan` tests pass. | **Yes** (11 pool plugins byte-identical) |
| 3 | **Take the serial prologue out of virtual scans.** Join the 3,072 walk pieces with prefix sums and a parallel copy (or never materialise the full chunk `Vec`). Stream rounds into the executor as their pieces complete, so walk and plan overlap `execute`. Plan more rounds in parallel. | Estimate: psscan 43 -> 35-37 ms (-15%), and the same for every pool scan. Floor ~31-33 ms. | M-H | Ordering bugs. Mitigated by the existing chunk-list-vs-sequential-walk tests and the md5 gates. | No (phases measured: join 3.3-3.8 ms serial, plan 4-4.7 ms) |
| 4 | **`MADV_DONTNEED` a big chunk's range right after its `finish`**, in parallel, as vmscan already does. | mftscan exit teardown 24-27 -> 9-13 ms; wall 232-236 -> 220-222 ms (-5%); banners and mbrscan neutral | XS | None: pages simply re-fault | **Yes** (a5) |
| 5 | **Cold-mode read planner for virtual scans.** Probe residency with a one-byte `preadv2(RWF_NOWAIT)`. If the range is not resident, read the round's distinct extents in file order as merged preads (128 KiB-aligned, 128 KiB gap fill) before scanning from them. | The hwbench floor for psscan's exact footprint is 1.28 s (merged, 1.94 GB/s), vs 1.43-1.81 s with #1. That is another ~15-25% on cold virtual scans. | M | Warm regression if the probe misfires. `RWF_NOWAIT` is exact and costs one syscall per item. | Floor only. A naive per-item `POSIX_FADV_WILLNEED` prototype was **2x slower**, so plain fadvise is not the answer. |
| 6 | **Use the persistent worker pool** (`util::pool`) for the scan phases (walk, plan, execute, replay) instead of spawning fresh scoped threads. | 146 µs per phase; psscan has ~5 phases, ~0.7 ms (1.5%). Warm replays: 0.15-0.3 ms of 3-10 ms (3-5%). | S-M | The pool runs one job at a time; nested parallelism falls back to spawning. | No |
| 7 | **Store scan-cache atoms as fixed-width arrays** (u32 relative offset, u16 tag, per-chunk index) that are mapped and used in place, with no varint decode. | MFT atoms: load 6.3-7.1 -> <1 ms, so `mftscan.ADS` warm -25% and `MFTScan` -6%. Other atoms: no change (0.02-0.3 ms today). | S-M | Format version bump; files grow ~2x (the cache cap is 256 MiB) | No |

Prototype A1 (the whole change):

```rust
// scan::mapping_runs — was: `!emitted || budget.fetch_add(1, Relaxed) < cap` per run
const BATCH: usize = 4096;
let mut local = 0usize;
let mut spent = budget.load(Ordering::Relaxed);
layer.mapping_targets(addr, len, &mut |m, t| {
    /* ... emit as before ... */
    if !emitted { return true; }
    local += 1;
    if local == BATCH { spent = budget.fetch_add(BATCH, Ordering::Relaxed) + BATCH; local = 0; }
    spent + local <= cap
});
if local > 0 { budget.fetch_add(local, Ordering::Relaxed); }
```

### Measured and rejected

| Idea | Result |
|---|---|
| Merge adjacent or near preads in `scan_group` (gap 0 / 4 KiB / 16 KiB) | 71k -> 52k / 44k / 36k preads, **no gain**. The cost is per page, not per syscall. |
| Read the scattered pages of virtual scans through the global mmap instead of pread | Equal execute time (37 vs 39 ms), plus more PTEs to tear down |
| pread page tables in the range walker instead of faulting them in | No gain after A1: the walk is 2.6 ms and faults drop only 12k -> 10.5k |
| LSD radix sort of the round keys in `plan_round` | No gain: plan 5.4-5.6 ms vs 4.0-4.7 ms. The sort is not the plan's bottleneck; the 7-way round parallelism and the serial concatenation are. |
| `POSIX_FADV_WILLNEED` per work item or per 16 MiB chunk when cold | Cold psscan 3.6-3.8 s vs 1.8 s (**worse**). Cold banners unchanged. |
| `FADV_SEQUENTIAL` or one fd per worker for cold full scans | Within noise (1.69-2.9 s spread on identical runs). rsvol's pattern is already at the cold ceiling. |
| `MAP_POPULATE` / `MADV_POPULATE_READ` | Slower than fault-around (see section 3) |
| `MapWindow` per worker instead of pread for streaming full scans | pread is 20-60% faster: munmap TLB shootdowns in a 20-thread process. The executor already uses pread; `MapWindow` remains only for whole-chunk (non-streaming) scanners such as yara and regex, where a 16 MiB pread buffer would fall out of L2 (4 MiB-block pread: 13.5 GB/s). |
| THP / large folios for the image mapping | Not available: btrfs without `CONFIG_BTRFS_EXPERIMENTAL`, `FilePmdMapped` stays 0. Where available (ext4/xfs large folios), it would cut vmscan's 82k faults ~32x and shrink the teardown. It is an environment property, not a code change. |
| `O_DIRECT` | Leaves the page cache cold for the next plugin, and btrfs falls back to buffered IO for compressed extents. Not pursued. |
| NUMA placement | Single node |

## 7. Recommended plan

1. **Land A1 (#2) now.** It is trivial, risk-free, and gives 10-15% on every kernel-virtual pool scan.
2. **Land #4.** Three lines, the same pattern vmscan already uses. If the startup review's
   teardown-off-the-exit-path change lands, #4 becomes redundant.
3. **Implement #1 properly:**
   - `FileLayer` owns a lazily created second `Mmap` advised `MADV_RANDOM`.
   - `IntelLayer::phys_raw` and the segmented containers' small reads use it.
   - Every bulk sequential reader stays on the default mapping.
   - Add a cold-cache gate to `bench/`: `cp --reflink` the images, `POSIX_FADV_DONTNEED` before each run
     (hwbench's `evict`), compare cold pslist, dlllist, handles, psscan, vmscan and `memmap --dump`, and
     check that the warm fault counts do not change.
4. **Then #3**, the streaming prologue of virtual scans, which gets pool scans to ~85-90% of their floor. #5
   (cold read planner) and #7 (scan-cache format) are next, if cold first runs of scanners or warm MFT runs
   matter to users.
5. **Stop optimizing full physical scans.** They are at 88-94% of a floor that is itself 90% of the DRAM peak,
   and at the cold-IO ceiling. Beyond this, a full scan only gets faster by not scanning, which the scan
   cache already does on warm runs.

## 8. Reproduction

```bash
S=$PWD/testdata/scratch/review-scan
cd $S/hwbench && rustc --edition 2024 -O -C target-cpu=native hwbench.rs
./hwbench membw 16 2048 5                         # DRAM floor
./hwbench pread <IMG> 20 64 3 scan                # page-cache full-scan floor
./hwbench randread <IMG> 20 8 74112               # scattered 8 KiB floor
./hwbench mmap <IMG> 20 global none touch 1       # fault / teardown cost
cp --reflink=always <IMG> $S/img/x.raw; ./hwbench evict $S/img/x.raw   # cold without root
./hwbench chunked $S/img/x.raw 20                 # cold IO ceiling, rsvol's pattern
./hwbench blocks $S/img/x.raw $S/prof/footprint.txt 20 4096 gap=128    # cold floor of psscan's footprint
python3 $S/tm.py -n 5 -e RSVOL_CACHE=$S/cache -e RSVOL_NO_SCAN_CACHE=1 -- $S/bin/vol-base -q -f <IMG> windows.psscan
# prototype switches (bin/vol-a6 has all): A1 always on; RSVOL_MADV=intel|random; RSVOL_BIG_DONTNEED=1;
# RSVOL_SCAN_GAP=<bytes>; RSVOL_SCAN_MMAP=1; RSVOL_WALK_PREAD=1; RSVOL_PLAN_RADIX=1; RSVOL_SCAN_PREFETCH=1;
# RSVOL_TRACE=1 (+RSVOL_FOOTPRINT_STATS=1, RSVOL_FOOTPRINT=<file>) for phase and IO statistics.
```
