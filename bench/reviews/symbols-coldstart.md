# Review: first-run (cold-start) costs: symbol discovery, xz, lazy index, automagic, PDB conversion

Reviewer: symbols / cold-start performance review. Date: 2026-09-26. Code: `6825849`.
Machine: i7-12700KF (8 P-cores with HT = CPUs 0-15, 4 E-cores = CPUs 16-19), 62 GB, Linux 7.1.8.
The machine was **busy** during the whole review: a game plus other agents' builds, load average 7-21.
Absolute times are therefore best-of-N and noisy by +-5 ms. Relative results and trace spans are reliable.

Prototypes live in the clone `testdata/scratch/review-symbols/rsvol`, branch `review-coldstart`. It has four
commits on top of `6825849`:

| commit | content |
|---|---|
| `506f27f` | harness tests (`src/symbols/review_tests.rs`) and trace notes |
| `6374ec8` | P1: Windows speculation |
| `ea24d68` | P2: PDB `.json.xz` written after the output |
| `ac9934e` | P5: split scan chunks |

Harness tests in `review_tests.rs`: `rv_decode`, `rv_decode_loop`, `rv_decode_prefault`, `rv_faults`,
`rv_scan_bw`, `rv_membw`, `rv_xz_isf`, `rv_rechunk`. The helper scripts `tr.sh`, `rep.sh` and `ab.py` are in
`testdata/scratch/review-symbols/`. Nothing in the repo was changed except this file (but see §9: two of my
runs wrote ISFs into `volatility3/symbols`; both were removed).

## 1. Verdict

**The serial parts are at the hardware limit. The critical paths are not.** Each cold scenario is gated by one
of two physical floors:

- **A serial LZMA decode of a single-block `.json.xz`.** The Windows kernel ISF (6.7 MB) takes 16.4 ms on a
  free P-core. That is about 11 cycles per range-coder decision, against an estimated floor of 8-8.5 (see also
  `libraries.md`). No format trick makes it parallel: python-written ISFs have one block and no
  state resets, so the adaptive probabilities chain every bit.
- **A forced physical scan at DRAM or page-cache bandwidth.** The two cases are the full 2.15 GB KDBG scan on
  1809 and the 2.17 GB walk to jammy's VMCOREINFO note. Both are measured at the DRAM read bandwidth under
  load (31 GB/s, identical to a pure in-memory read on the same box at that moment). The quiet floor is
  37-38 GB/s (`scanning.md`).

What sits on top of those floors is 15-35% of the cold time. Almost all of it is work that runs *after* the
floor-bound step instead of beside it:

- the lazy JSON index after the decode;
- a speculative Windows load of the wrong file;
- the xz *compression* of a freshly converted PDB;
- the ramp barriers of the note scan.

The dominant first-run cost for a new Windows build is outside the CPU: the PDB download
(about 1.1 s of a 1.17 s run). A 4-way range download measured 42% faster.

| scenario (regime A: python's DB covers the symbol dir) | now (best of 5) | floor | gap | limit type |
|---|---:|---:|---:|---|
| win-main `windows.pslist` cold | 26.5 ms | ~20.5 ms (~16.5 with a theoretical decoder) | 6 ms (23%) | LZMA serial |
| win-1809 `windows.pslist` cold | 81.2 ms (P1: 76.5) | ~58 ms quiet (2.15 GB @ 37 GB/s + 2) | 23 ms, of which 5-9 ms is a wrong speculation | DRAM BW |
| noble `linux.pslist` cold (`.json.xz`, 3 blocks) | 73.2 ms | ~46 ms | 27 ms (37%) | largest block's LZMA |
| jammy `linux.pslist` cold / newimg | 106 / 90 ms | ~62 ms (2.17 GB + in-flight @ 37 GB/s) | 28-44 ms | DRAM BW |
| mac `mac.pslist` cold | 32.4-34.3 ms | ~23 ms | 10 ms (30%) | LZMA serial |
| PDB-cold (ISF converted from a cached PDB, no network) | 67-79 ms | ~30 ms | ~45 ms | CPU; xz compression on the path |
| PDB-cold **with network** (memlabs Win7 x64, 8.8 MB PDB) | 1170 ms | download-bound | ~500 ms with range download | network |
| regime B: python's DB lacks the 179 ISFs of `testdata/symbols` | 505 ms (noble), 790-940 (coldbench) | ~300-350 ms | ~1.5x | all-core LZMA throughput |

## 2. Method

**Traces.**

- `RSVOL_TRACE=1` spans, plus notes I added in the clone: per-xz-block decode times and each VMCOREINFO note
  offset with its stop decision.
- `perf stat` (user cycles, instructions, branch misses, task-clock) via
  `testdata/scratch/review-plugins/perf`.
- Kernel profiling is not allowed here (`perf_event_paranoid=2`).
- Critical paths are reconstructed from the span durations. The spans nest; the speculative threads run in
  parallel.

**Cache states** are coldbench's:

| state | what is deleted |
|---|---|
| cold | everything, incl. `isfchoice` (coldbench itself keeps `isfchoice`, see §9) |
| newimg | automagic and scan caches |
| symcold | `isf`, `identifiers.cache`, `isfchoice` |
| warm | nothing |

Runs used a private `RSVOL_CACHE` and a private python `--cache-path`.

**Two regimes of python's identifier DB**, which rsvol replays:

- **Regime A.** The DB already has rows for every ISF on the path. `pycache-full` was built by one private
  python run over `-s testdata/symbols`, which took 52 s. This matches the task's reference numbers.
- **Regime B.** The DB lacks them: a copy of today's `~/.cache/volatility3/identifier.cache` has 122 rows, none
  for `testdata/symbols`. Plain `coldbench.py` now runs in regime B, because `testdata/symbols` grew to 301
  ISFs and python's DB was rebuilt. That is why today's coldbench shows noble / jammy / mac cold at
  940 / 818 / 790 ms.

**A/B runs.** `ab.py` interleaves binaries per round with separate caches. Correctness was checked with stdout
md5 across base and prototypes (windows info/pslist/modules on three images, pslist on the PDB-cold runs): all
identical.

## 3. Hardware reference numbers (this box, measured)

| quantity | value | source |
|---|---|---|
| LZMA decode, Windows ISF (0.63 → 6.69 MB, one block) | 16.4 ms prefaulted P-core (quiet); 100 M cycles at 14 c/decision under load; 7.16 M decisions, 462 k symbols, 1.0 M branch misses | `rv_decode_prefault`, `perf stat rv_decode_loop` + `--cfg lzma_stats` |
| LZMA decode, mac 10.9 ISF (11.6 MB) | 14.6-15.0 ms; 13.1 c/decision | same |
| LZMA decode, noble 6.17 / resolute 7.0 ISFs (74 / 77.5 MB, **one block**) | 95-100 / 112-118 ms; 12.1 c/decision | same |
| LZMA decode, noble 6.8 ISF (3 blocks 24/24/13 MB) | 1 thread 96 ms; blocks in parallel 41.6 ms in the harness; 45-70 ms per block in-process under load | `rv_decode`, block trace |
| P-core vs E-core, same decode | 18.7 vs 24.9-27.1 ms (1.4x) | `taskset` |
| fresh output buffer page faults | 7 MB: 1.1 ms; 64 MB: 7 ms (THP), 15 ms (4 K pages); decoding into a pre-populated buffer: **no measurable gain** (<1 ms) | `rv_faults`, `rv_decode_prefault` |
| DRAM read, 20 threads (under load) | 28-33 GB/s; quiet peak 40-42 GB/s | `rv_membw`, `scanning.md` |
| full physical scan, 2.15 GB 1809 image | 69 ms = 31 GB/s. The fused KDBG+module scanner, `FastBytesScanner` and the pure DRAM read are all equal | `rv_scan_bw` |
| lazy index, Windows ISF / mac / noble 6.8 | 3.3-4.5 / 4.2-8.2 / 15-22 ms (shallow 1.4 / 1.8 / 5.3; members 2.0 / 1.9 / 11.1) | trace |
| full blob build, same ISFs | 7.1 / 9.4 / 55 ms | `rv_decode` |
| PDB → JSON conversion, 12.4 MB `ntkrnlmp.pdb` | 7-17 ms | trace |
| xz *compression* of the converted 6.7 MB ISF (preset 6, 512 KiB blocks, 12 threads) | 31-56 ms. Preset 0-1: 22-31 ms (not dominated by match finding) | trace, `rv_xz_isf` |
| decode of an rsvol-written (multi-block) ISF | Windows 3.6 ms (vs 16.4 single-block); noble 6.17 re-chunked 13-15 ms (vs 100) | `rv_rechunk` |

## 4. Per-scenario critical paths

### 4.1 win-main `windows.pslist`, cold (26.5 ms best; the task quotes ~25)

```
0 ── DTB scan 0.5 ── low-stub pdbscan 1.1 ── identifier index 1.0 (python rows; 0 with a cached isfchoice)
   ── read + xz decode 19.3-23 (pure decode 16.4; +1 fault, +0.4 CRC, rest cold-start effects)
   ── lazy index 3.3-4.5 (shallow 1.4, members 2.0, names 0.3, skeleton 0.3)
   ── plugin + output + exit ~2
```

- Nothing overlaps: the decode cannot start before the GUID is known (2.5 ms in).
- **Floor ≈ 1.6 + 16.4 + ~0.5 (index tail if streamed) + 2 = ~20.5 ms.** With a decoder at the estimated LZMA
  floor, ~16.5 ms.
- **Gap ≈ 6 ms:**
  - lazy index not overlapped: ~2.5-3 ms is overlappable;
  - index serial: 1 ms;
  - in-process decode overhead: ~2-3 ms. The prefault prototype shows faults are not it (<1 ms). Frequency
    ramp and cold caches remain.
- Without python's DB (a first-time user), the index replays python's DB build. It decodes the other shipped
  Windows ISFs, whose slowest file is 27 ms decode + 7 ms parse, and cold becomes 45-69 ms. Floor: the
  slowest ISF on the path.

### 4.2 win-1809 `windows.pslist`, cold (81.2 ms; P1 76.5) / newimg (70-74)

```
0 ── DTB 0.5 ── low stub (none) ── fused KDBG + module-list scan of 2.15 GB: 68-76 ms (18 KDBG hits, none valid)
      └─ at ~2 ms, module-list candidate → speculative ISF load on another thread
   ── [base] kernel ISF lookup 1.9 → join speculative 5.5 → the RIGHT ISF lazily 3.7
   ── plugin ~2
```

- **Bug.** The speculation picks the ISF by name. Its first root is `volatility3/symbols/.../8B11…json.xz`.
  Python's identifier DB, and therefore rsvol's final answer, picks `~/.cache/volatility3/symbols/.../8B11…json`.
- The main thread then joins a 50 ms decode of the wrong file, discards it, loads the right one, and the helper
  builds two blobs.
- **Floor:** 2.15 GB / 37 GB/s = 58 ms quiet (69 ms at the 31 GB/s I measured under load) + DTB + plugin.
- The scan runs at the measured DRAM rate. Python semantics require every KDBG hit, so the full scan cannot be
  skipped.
- **Gap:** the wrong speculation, 5-9 ms (fixed by P1). The rest is noise, bandwidth under load, or the scan
  engine (`scanning.md`).

### 4.3 noble `linux.pslist`, cold (73.2 ms) / symcold (61-65) / newimg (14.4)

```
0 ── identifier index 3.5 (301 python rows)
   ∥ hint + VMCOREINFO scan: batch 4 chunks 5-7 ms (banner at 57 MB) ─ batch 8 chunks 6.5 ms (note at 160 MB) = 13-14 ms
   └─ at the hint (~6 ms): speculative load of the .json.xz: 3 blocks decoded in parallel,
      each 24 MB block 36 ms on a free P-core (45-60 ms in-process under load)
      ── lazy index 15-22 ms (shallow 5.3, skeleton/enums 3.3, members 11-12.5, names 1.3)
   ── plugin ~2
```

- **Floor ≈ 6 + 36 + ~4 (lazy tail if streamed) + 2 = ~48 ms.**
- **Gap ~25 ms:**
  - lazy index after the decode: ~8-10 ms overlappable (block 1 carries `user_types`, `enums` and the first
    39% of the bytes);
  - in-process decode slowdown: 3 decoders plus the scan and other load, versus a free core;
  - the first scan batch uses only 4 threads.
- The task's "31 ms" figure is the plain `.json` of the same kernel being python's choice (mmap, no decode).
  Which of the two sibling files python picks depends on its DB row order.

### 4.4 jammy `linux.pslist`, cold (104-106) / newimg (90-93)

```
0 ── index 3 ∥ scan: ramp 4-8-16 chunks (hint at 0x10a00200) then stream, 20 chunks in flight, to the first
     valid note at file offset 2.17 GB (phys 0x1002ca00c; stale "VMCOREINFO" strings at 283 MB-1.7 GB)
     └─ the ISF is the plain .json: mapped, lazily indexed in 28 ms beside the scan
   ── plugin ~2
```

- **Floor:** 2.08 GB of chunks before the note / 37 GB/s = 56 ms, + ~2-3 ms of in-flight overshoot + 2
  = ~62 ms quiet.
- Achieved: ~25-27 GB/s effective, versus 31 GB/s DRAM under load.
- Measured alternatives to the ramp:

  | variant | jammy newimg | noble newimg |
  |---|---|---|
  | one barrier batch, then stream | -2 to -4 ms | +12 ms |
  | stream from chunk 0 | -2 to -4 ms | +9 ms |

  **Keep the ramp.**
- The ELF core has no VMCOREINFO PT_NOTE (checked with `readelf -n`), so there is no shortcut to the note's
  position.
- Python semantics need every byte before the first valid note: this is bandwidth-bound.

### 4.5 mac `mac.pslist`, cold (32.4-34.3 ms) / symcold (23-25) / newimg (10.2-10.9)

```
0 ── identifier index 2.5 ── first-hit banner scan 5-12 (batches of 3 and 5 chunks, one thread per chunk)
   ── temporary ISF load: decode 11.3 MB single block 25-31 (pure 14.6-15.0) ── lazy 4.2-8.2 ── validation
   ── plugin ~2
```

- The banner scan waits for the index: its needles are the dictionary's banners. The hint thread only runs
  when the index has ISFs to read.
- **Floor:** max(index, prefix scan) ~4 + 15 + ~1 + 2 = ~23 ms.
- **Gap ~10 ms:**
  - index → scan serialisation, ~2.5 ms;
  - one thread per chunk in the first batches, ~3-5 ms;
  - lazy index not overlapped, ~3-4 ms (`user_types` = the first 47% of the file).

### 4.6 PDB-cold: the kernel ISF must be converted (PDB in python's cache, fresh python DB)

```
0 ── DTB + low stub 1.5 ── identifier index 21-33 (fresh python DB: decodes the shipped ISFs)
   ── PDB → JSON 7-17 ── xz COMPRESSION 31-56 ── write + rename ── lazy index 2.5-3 ── plugin
```

- 67-79 ms. The `.json.xz` exists only so that python and later runs find the table. Nothing in this run
  reads it: the JSON is kept in memory.
- **With a network download** (memlabs Win7 x64, 8.8 MB PDB, one real run): 1170 ms wall.
  - curl: DNS 78 ms, redirect + TLS, TTFB 508 ms, transfer ~750 ms at 11.7 MB/s on one connection.
  - rsvol's own share is ~45 ms: index 7, conversion 9, compression 28, load 3.

### 4.7 Regime B: python's DB does not cover the symbol dir

- noble cold with `-s testdata/symbols` and python's current DB: 505 ms wall, 6.9 s CPU (task-clock), so
  **13.6 of 20 hardware threads busy** on average (while the box also ran a game).
- 179 ISFs must be fully decoded and parsed. Python parity needs the whole document: a later duplicate
  `linux_banner` / `metadata` key wins in python's dict. An early exit at the banner (80-86% into Linux ISFs)
  is therefore not allowed.
- Largest-first scheduling already hides the longest single-block file (resolute, 115 ms).
- **Floor ≈ total decode work / effective cores ≈ 300-350 ms.** Throughput-bound, ~1.5x off, mostly
  environment.
- Only a faster LZMA decoder or not decoding helps. Python takes 52 s for the same update.

## 5. What cannot be beaten (and why), answering the specific questions

- **Decode only the needed ranges of a `.json.xz`?** No.
  - LZMA2 in python/xz-written ISFs is one block of 0x80 chunks: no dictionary or state resets, so no random
    access.
  - Prefix decoding does not help either. The types a plugin needs are late in the file: `_EPROCESS` sits at
    ~75% of the Windows ISF (`user_types` is 51-100%); `linux_banner` sits at 86% of Linux ISFs.
  - Python's dict semantics (a later duplicate key wins; invalid JSON means no table) require the whole
    document before any answer is final.
- **Start plugin work before the decode ends?** Only with buffered output and a rollback. The overlap is at most
  the last ~25% of the decode, against a plugin that takes 2 ms for pslist. Not worth it.
- **Parallel LZMA for single-block files?** Impossible: adaptive probabilities chain every decision. The asm loop
  already carries a ~6-cycle chain, loads both children of a node and uses a table update. The remaining gap to
  the estimated floor (mispredicts on symbol type) is 15-25% at very high effort (`libraries.md` agrees).
- **Page faults of the fresh output buffer, P-core pinning, `MAP_POPULATE` or a pre-populating helper thread:**
  measured, all under 1 ms. The scheduler already keeps the main-thread decode on P-cores: whole-process pinning
  to P-cores made no difference; E-cores only are 1.4x slower.
- **Better KDBG ordering within python semantics:** no.
  - With no valid KDBG, python needs every KDBG hit, so the scan is full.
  - The module-list candidate is already found at ~2 ms and speculated on.
- **Better VMCOREINFO ordering:** measured, the ramp is right (§4.4).
- **Parallel identifier extraction:** already all-core and largest-first. Regime B is throughput-bound.
  - One real gap: a *straggler* file's serial identifier parse (5-9 ms after its decode) is on the critical
    path of small indexes, e.g. the fresh-python-DB Windows case.
  - Fix: parse behind the decoder (streaming), or use the parallel SIMD parser when cores are idle.

## 6. Prototypes (measured)

**P1: the Windows speculative ISF is python's choice; a mismatched speculation is never joined** (`6374ec8`).

- The speculation thread calls a new `store::find_windows_isf_no_download`: `find_location_cached` (python's DB
  choice, memoised for the final lookup), else by name. It sends its location through a channel before loading.
- `init_windows` joins only if that location equals the final one.

| | cold 1809 pslist | cold 1809 info | newimg |
|---|---:|---:|---:|
| base (release, best of 5) | 81.2 ms | 81.9 ms | 69.7-71.7 ms |
| P1 | 76.5 ms | 72.9 ms | 71.6-73.7 ms (equal: the wrong blob is cached after one run) |

- Trace: join 5.5 ms + second load 3.7 ms become 0.02 ms, and one helper blob build instead of two.
- The index build also moves off the critical path, into the speculation thread during the scan.
- Output identical on 1809, main and Win7 images. **Validated. Gain 5-9 ms (6-11%). Effort: small. Risk: low**
  (the final decision code is unchanged).

**P2: the converted PDB's `.json.xz` is written after the output** (`ea24d68`, `RSVOL_PDB_XZ_BG`).

| mode | PDB-cold wall (6 rounds, fast profile) |
|---|---:|
| synchronous (today) | 67-79 ms, median ~74 |
| background thread (joined before exit) | 75-79 ms: no gain, the exit waits for it |
| **detached helper** (re-converts the cached PDB, compresses, renames, then builds the blob) | **40-45 ms, median ~44** |

- The file appears ~65-90 ms after exit. Stdout is identical. The written ISF equals python's except the
  producer datetime/version, as today.
- **Validated. Gain ~30 ms (-40%) of the no-network first run of a new Windows build. Effort: medium. Risk:
  low-medium:**
  - the file appears later than in python;
  - the first run's in-memory JSON and the file differ in the producer datetime (not printed by any plugin
    checked);
  - fallback when the helper cannot start.

**P3: VMCOREINFO scan ramp variants** (env switch, reverted). Jammy -2 to -4 ms, noble newimg +9 to +12 ms.
**Rejected: keep the ramp.**

**P4: fault / placement experiments.** Pre-populated output buffers, P-core pinning. **Rejected: <1 ms.**

**P5: sub-chunk parallelism for the progressive Linux hint + notes scan** (`ac9934e`, `RSVOL_SPLIT=K`).

- 16 MiB chunks are split into K ranges read on the pool. The scanner reports every occurrence, so no state
  crosses a range boundary.

| | kernel init | wall median |
|---|---|---|
| noble newimg | 10.2 → 8.2-8.6 ms min | 13.4 → 12.0-12.9 ms |
| noble cold | -2 to -4 ms | |
| jammy | +4 to +8 ms: nested oversubscription in the streamed phase | |

- **Partially validated. Gain ~2 ms (10-15% of noble newimg)**, only if restricted to batches with fewer chunks
  than threads. Effort: small. Risk: low.
- The same idea for the mac `BannerScanner` needs boundary handling for its non-overlapping matches. The
  estimated gain is 3-5 ms of the 10-11 ms mac newimg; not prototyped.

**P6: PDB range download (manual test).**

| download | time |
|---|---:|
| one `curl` | 1262 ms |
| redirect lookup + 4 parallel `curl -r` ranges of the blob URL (bytes identical) | 729 ms |

**Validated once. -530 ms, network-dependent.**

## 7. Ranked opportunities

| # | opportunity | gain | effort | risk | validated |
|---|---|---|---|---|---|
| 1 | **Parallel range download of PDBs**: resolve msdl's redirect, fetch 4-8 `Range` parts, fall back to one request if the server lacks ranges; also prefetch the PDB when the module-list candidate validates during the KDBG scan | ~0.5 s of a ~1.2 s true first run on a new Windows build (the largest absolute first-run cost) | medium | low-medium (network edge cases; python makes one request) | once (P6) |
| 2 | **Write the converted `.json.xz` in the detached helper** (P2) | ~30 ms of 74 (-40%) whenever a PDB is converted | medium | low-medium | yes |
| 3 | **Windows speculation uses python's choice, never joins a mismatch** (P1) | 5-9 ms on KDBG-scan images (1809: -6 to -11%) | small | low | yes |
| 4 | **Overlap the lazy index with the decode.** Publish decode progress per LZMA2 chunk (≤2 MiB). Run the shallow pass behind it: it is already newline-chunked, so it streams naturally. Parse a big section's members as soon as it closes | Windows ~2.5-3 ms (10%), mac ~3-4 ms (10-12%), noble/jammy-xz ~8-10 ms (11-13%), single-block 70+ MB Linux ISFs ~8-10 ms | medium-high | medium (lazy acceptance must stay byte-exact; the index already has the range machinery) | estimated from stage times |
| 5 | **Background pre-build of other ISFs** (the helper, at idle priority, after a run, with a disk budget), so a later first run on a new image whose ISF was never loaded costs newimg time. Options, per ISF: the blob (Windows ~3 MB, mac 4.3 MB, Linux 27-32 MB) or a re-chunked 512 KiB-block xz copy (1.2-1.4x the original size, parallel decode 5-7x faster) | e.g. noble 6.17 first load 120 → ~15 ms (blob) / ~35 ms (re-chunk); mac 32 → 10 ms; Windows 26 → 4 ms | medium | low (disk and background CPU are the cost: ~150 ms CPU per Linux ISF) | decode side measured (`rv_rechunk`); policy not built |
| 6 | **Mac: banner prefix scan in parallel with the index; split first-batch chunks** | 4-7 ms of 32 cold / 10.5 newimg | small-medium | low | estimated |
| 7 | **Straggler-aware identifier extraction**: parse behind the decoder or with the SIMD parser when cores are idle; also checksum and extract in cache-hot chunks (`libraries.md`, item 2) | 5-9 ms on small fresh-python-DB indexes (Windows fresh user: 45-69 ms); ~8% of regime-B CPU | medium | low | estimated |
| 8 | **Split chunks in the under-filled first batches of the progressive Linux scan** (P5, restricted) | ~2 ms on noble newimg (10-15%) | small | low | partly |
| 9 | Build the identifier index at the start of `init_windows` (beside the DTB scan and pdbscan). It must keep decoded Windows JSON, or the fresh-DB case decodes the kernel ISF twice | 1-2 ms | small | low | no |
| 10 | Faster PDB → JSON conversion or compression tuning (preset 0-1 only saves ~30%) | ≤10 ms, moot after #2 | medium | low | measured, low value |

Rejected, with measurements in §5-6: partial or range LZMA decoding, speculative plugin execution, output-buffer
prefaulting, P-core pinning, removing the VMCOREINFO ramp, and further LZMA asm work (a 15-25% ceiling at very
high effort; `libraries.md`).

## 8. Plan

1. **Merge P1** (small, validated). Add a unit test with two locations for one GUID, where python's DB prefers
   the second, and assert that one table is loaded and one helper runs.
2. **Productise P2.**
   - Pass the helper the raw JSON path, or the PDB path plus the producer datetime, so the file matches the
     in-memory table.
   - Fall back to a background thread if the helper cannot start.
   - Keep python's "first writable dir" choice: it is already decided by `open_output` before the helper runs.
3. **Range download (#1).**
   - `curl -r` in N processes, or one `curl --parallel --config` with N ranged requests. Check for `206` and
     `Content-Range`; else keep the single-request file.
   - Prefetch in the speculation thread when `find_windows_isf_no_download` returns `None` and the candidate
     validated. Python would download the same file unless a later KDBG hit changes the answer.
4. **Streaming lazy index (#4)**, Windows single-block first, then per-block for multi-block xz. Keep the
   existing whole-document validation as the acceptance test. The lazy-vs-full unit test over every ISF on the
   machine covers correctness.
5. **Budgeted background pre-build (#5)**: same-OS ISFs in `-s` dirs, most recently modified first, e.g. a
   512 MB blob budget. Measure with a new coldbench mode, "newimg + ISF never loaded".
6. Mac first-hit scan (#6) and the restricted P5 split (#8) together, since both are scan-batch shaping.

## 9. Notes, caveats, incidents

**coldbench caveats.**

- "cold" does not delete `isfchoice/`, so the Windows cold runs skip the identifier index (~1 ms).
- Results depend on python's `identifier.cache` content. With today's DB (122 rows) and the grown
  `testdata/symbols` (301 ISFs), noble / jammy / mac cold measure regime B: 790-940 ms.
- Suggestion: give coldbench a `--cache-path` for a pinned python DB, and add an `isfnew` mode (automagic and
  scan caches empty, plus the kernel ISF's blob deleted).

**Duplicate ISFs.**

- The 1809 GUID exists as `volatility3/symbols/.../8B11….json.xz` and `~/.cache/.../8B11….json`.
- The noble 6.8 and jammy kernels exist as both `.json` and `.json.xz` in `testdata/symbols`.
- Which file python's DB picks changes rsvol's first-run cost by up to 40 ms (mmap vs a parallel decode) and
  exposed the P1 bug.

**Incident.** Two of my Windows runs without a writable `-s` dir wrote converted ISFs into the first writable
root, `/home/user/rs-vol/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/`. That is python's own behaviour.

- The files: `8E3373D6…-1.json.xz` at 17:03, and `3844DBB9…-2.json.xz` at 17:23 (the latter after a real PDB
  download into my private `--cache-path`).
- Both were deleted within minutes. The directory now holds only the original `8B11….json.xz` (Sep 25).
- Concurrent runs by other agents in that window may have seen the extra ISF.
- Later runs used `-s <scratch dir>` first.

**Reproduce.**

- `testdata/scratch/review-symbols/{tr.sh,rep.sh,ab.py}`.
- `RSVOL_TRACE=1` spans.
- Harness: `RV_FILES=… target/fast/build/rsvol/*/out/vol-* rv_decode --ignored --nocapture`, and the other
  `rv_*` tests listed at the top.
- Python DB for regime A: `pycache-full/` (301 rows).
