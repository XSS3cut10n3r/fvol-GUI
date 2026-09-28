# Performance review: the from-scratch libraries vs the hardware limit

Scope: codecs (xz/LZMA, inflate/gzip/zlib, bzip2, snappy/xpress/lznt1), crypto, the x86
disassembler, regex + YARA, PDB→ISF and the JSON/ISF index. Question: are they at the hardware
limit of this machine, and if not, is closing the gap worth it for rsvol's real plugin runtimes?

**Short answer.** Beating the reference C library is not the same as being at the limit, but
for most of these libraries the remaining gap does not matter. Crypto, the regex/YARA search
kernels and whole-image scans are at the limit: crypto at the latency or throughput floor, the
search kernels at single-core DRAM bandwidth, and multi-core scans at the memory bound.
LZMA is already faster than liblzma and 7-Zip's asm decoder, and runs at about 60-75% of a
realistic floor. Inflate, JSON stage 1 and the disassembler are well below their floors, and
inflate is *slower than libdeflate*. Of these, only inflate matters, and only for `.gz` images.
The largest real-world waste found is not in any kernel. `vadyarascan` spends about 75% of
its CPU zero-filling unmapped VAD pages and then YARA-scanning the zeros. A validated prototype
makes it **2.7x faster in wall time and 4.7x cheaper in CPU, with byte-identical output**.

## Machine, method, caveats

* i7-12700KF: 8 Golden Cove P-cores (CPUs 0-15, HT) and 4 Gracemont E-cores (16-19). L2 is
  1.25 MB per P-core and L3 is 25 MB. AVX2, VAES, VPCLMULQDQ, SHA-NI, BMI2; no AVX-512. Golden
  Cove latencies used below: L1 load 5 cycles, imul r32 3, aesenc/aesdec 3 (2 per cycle,
  256-bit VAES), pclmulqdq 3 (1 per cycle), mispredict about 15-17 cycles.
* Measured bandwidth on the mmapped 5 GB image (warm page cache): one P-core streams
  **20-21 GB/s** with a plain AVX2 load loop. L2-resident data streams at 180 GB/s and L1 at
  190-220 GB/s. Eight P-cores together reach about **52 GB/s**, the DRAM limit.
* `perf` is not installed. I wrote two replacements:
  * `testdata/scratch/review-libs/tools/pstat` counts user-mode counters on the P-core PMU
    through `perf_event_open`: cycles, instructions, branch misses, TMA level-1 slots and
    UOPS_DISPATCHED per port.
  * `tools/pprof` plus `tools/symb.py` form a cpu-clock sampling profiler. It stops the child at
    exec with ASLR off and symbolizes against an unstripped LTO build (`target-prof`).
* **The box was heavily loaded throughout** (load average 12-22 from other reviewers and a
  game). Wherever possible the numbers are best-of-N **user-mode cycles** pinned to P-core 4.
  Wall times are indicative only, and every A/B comparison was interleaved.
* All code changes were made in a clone, `testdata/scratch/review-libs/rsvol`. The diff is
  `testdata/scratch/review-libs/prototype.patch`. Nothing in the main checkout was modified
  apart from this file.

## Summary

| Library | Achieved (1 P-core) | Floor (derivation below) | % of floor | Real-world weight | Verdict |
|---|---|---|---|---|---|
| LZMA / xz decode | 10.5-13.6 cycles per range-coder decision | 6 cycles/decision (dependency chain); about 8-9 including the mispredicts the format makes inevitable | 45-57% of chain, 60-77% of realistic | **High on first runs**: 65% of a cold `windows.pslist` and 62% of a cold identifier index; dominates `.xz` images | Already state of the art (1.07-1.3x liblzma, 1.1-1.35x 7-Zip asm). Small, hard headroom; take the cheap overlap wins only |
| Inflate (gzip/zlib) | 6.5 cycles/B, 21.9 cycles per symbol on a real 2 GB image | about 6.5 cycles per table lookup, about 3 cycles/B for that image | about 45-50% | Medium, `.gz` images only (one-time 4.4-6 s per 2 GB) | **Behind libdeflate by 10-36% on 3 of 4 inputs** (24% on the real image). Worth fixing, plus parallel single-stream decode |
| bzip2 | 15-36 cycles/B (4.3-4.7x libbz2) | MLP-bound inverse BWT, about 8-10 cycles/B | about 40-60% | Low (`.bz2` images are rare; already block-parallel) | Leave |
| snappy / xpress / lznt1 | AVML full scan of 2.7 GB: 0.08 s wall | memcpy-bound | n/a | None measurable | Leave |
| MD5 / SHA-1 / SHA-256 | 289 / 105 / 131 cycles per 64 B block | 288 / about 80 / 128 | 100% / about 76% / 98% | None (µs per plugin) | **At the floor.** One latent 150x cliff, trivial fix (below) |
| AES-128 (VAES) | CBC-decrypt 0.157 cycles/B; CBC-encrypt 2.24 cycles/B | 0.156 (throughput); 1.94-2.0 (serial latency) | 100% / 88% | None | At the floor |
| x86 disassembler | 115-140 cycles per instruction rendered (34-41 M/s); 65-75 cycles length-only | about 20-40 decode+format, about 5-10 length-only (table-driven) | 15-30% | **None**: under 3% of `mbrscan`, and `malfind` takes 10 ms in total | Far from floor, not worth closing |
| Regex / YARA search | literal, DFA and Teddy at 25-27 GB/s (quiet machine); `hexre` 3.6 GB/s | single-core DRAM stream 20-21 GB/s (measured, loaded); about 52 GB/s for all cores | 100% (DRAM-bound) except candidate-heavy rule sets | High for `vad`/`vma` YARA scans, but the waste is around the engine, not in it | Kernels at the limit. **Fix what they are fed** (prototype) |
| PDB → ISF | ntkrnlmp 4.2-9 ms | about 1-2 ms (output-bandwidth bound) | about 20-40% | None: 9 ms of a 1.44 s download-bound first run | Leave (optionally defer the 33 ms xz encode) |
| JSON stage 1 (jsonidx) | 2.4 GB/s (64 MB ISF) and 3.8 GB/s (6.7 MB), single thread | simdjson on the same files 4.9 / 5.6 GB/s; about 5-8 GB/s in cache | about 50-70% of simdjson | Low: 4.3 ms of a 28 ms cold Windows run; about 5% of the cold identifier index | 2x headroom, a few ms of real impact. Low priority |

## Per library

### LZMA / xz (`src/codecs/lzma.rs`, `xz.rs`)

**Achieved.** I built `bench/refbench/codec_xz_micro.rs` in the clone. It had rotted: it now
needs the `sink` and `util::mmap` modules, and I added them. Build with `--cfg lzma_stats` to
count decisions (normalize calls).

| input | decisions | rsvol Mcycles | cycles/decision | liblzma Mcycles | branch misses |
|---|---:|---:|---:|---:|---:|
| isf.json.xz (6.7 MB, Windows ISF) | 7.16 M | 90.4 (75.5 on a quiet box, per commit log) | 12.6 (10.5) | 97.1 | 0.99 M |
| big.json.l6.xz (49.6 MB) | 31.6 M | 400.7 | 12.7 | 452.4 | 3.99 M |
| binary.bin.xz (48 MB) | 143.5 M | 2060 | 14.4 | 2272 | 25.3 M |
| Debian 3.2 ISF (15.8 MB, one block) | 9.78 M | 124.3 | 12.7 | 136.6 | 1.23 M |
| **2 GB Windows image, `xz -6 -T1` (one block)** | 5.95 G | 81 050 | 13.6 | (CLI 18.6 s) | 943 M |

Whole-process cycles, `7z e -so` (7-Zip 26.02, x64 ASM LzmaDec) vs `xz -dc` vs the rsvol harness:
isf 108.7 / 92.3 / 80.5 M; big.json 494 / 403 / 361 M; binary 2138 / 2122 / 1927 M. **rsvol is
the fastest LZMA decoder available on this machine.**

**Floor.** Every decision runs `bound = (range >> 11) * p`, then compares `code` with `bound`
and selects the new range and code. The loop-carried chain is shr (1) + imul (3) + sub/cmp (1)
+ cmov (1) = **6 cycles**. Speculatively computing both next bounds does not shorten it: the
`range - bound` path costs sub + shr + imul + select, which is also 6. The probability loads and
updates can all be taken off the chain, and the asm loop already does that with both-children
loads and the `(p, bit)` update table. A realistic floor adds the mispredicts the format forces
on data-dependent symbol types: literal vs match, rep kinds, length choice. At about 1.7
mispredicts per symbol × about 15 cycles:

* 2 GB image: 35.7 G (chain) + about 14 G = about 50 G, against 81 G achieved (**61%**).
* isf.json: 43 M + 15 M = 58 M, against 75.5 M quiet (**77%**).
* The commit log's synthetic bit-tree step is 7.5 cycles per bit, against the chain's 6.

**Real-world impact.** LZMA is the dominant first-run cost.

* **Cold `windows.pslist`: 28-37 ms, of which `isf read+decompress` is 18.7 ms.** Python and
  the volatility3 symbol packs write single-block `.json.xz`, which must be decoded serially.
* **Cold identifier index** with `-s testdata/symbols` (177 `.xz` ISFs) and no python cache to
  seed from: 62% `decode_asm`, 5.3% `crc64_update`, 6.1% `extract_identifier`, about 10%
  jsonidx. The banner sits at 80-86% of each Linux ISF, and python parity needs the whole
  document parsed, so an early exit is not allowed.
* **Single-block `.xz` memory image (2 GB): 18.8-48.6 s wall.** The in-memory decode alone is
  17.7 s, and liblzma's CLI takes 18.6 s. The rest is the decoder blocked in
  `folio_wait_bit_common` and `balance_dirty_pages` (sampled wchan) while it writes its output
  through a shared file mapping (`xz::decompress_to_file` → `MmapMut`) on btrfs+LUKS. It grows
  with other writers on the box.

**Opportunities.**

1. *Stream single-block xz images through a sliding window and the existing `FileSink` writer
   thread* (as `lzma::decompress_alone_to` and the gzip path do), instead of the
   `MmapMut` output.
   * Gain: removes 1-31 s of writeback stalls per 2 GB. The wall time becomes the 17.7 s decode.
   * Effort: low; the code is mostly there. Risk: low. **Not validated.**
2. *Checksum and extract in cache-hot chunks.* CRC-64 runs at 36 GB/s in cache
   (0.13 cycles/B, the PCLMUL throughput floor) but at 13 GB/s after a whole block has left the
   cache. The identifier extraction also re-reads the decoded JSON from DRAM. Doing both every
   64-256 KB while the decoder pauses cuts about 8% of cold identifier-index CPU.
   * Effort: low. Risk: low. Not validated.
3. *Overlap the lazy JSON index with the decode* for single-block ISFs. The shallow index runs
   behind the decoder's output.
   * Gain: up to 4.3 ms of the 28 ms cold Windows run.
   * Effort: medium; this belongs to the symbols reviewer.
4. *Decoder chain work.* Getting from 7.5 to 6 cycles per tree bit, and reducing the
   mispredicts on length choice and rep kind, is worth at most 15-25%.
   * Effort: very high (hand-scheduled asm is already there). Not recommended.

**Verdict.** At the practical limit for serial LZMA. Take items 1 and 2 because they are cheap.

### Inflate / gzip / zlib (`src/codecs/inflate.rs`, `gzip.rs`)

**Achieved vs references.** Single thread, best-of-N user cycles, CRC verified by every side.
Harnesses: `review-libs/inflate/{libmicro.rs,cref.c}`.

| input | rsvol Mcyc | libdeflate Mcyc | zlib-ng Mcyc | zlib Mcyc | rsvol vs libdeflate |
|---|---:|---:|---:|---:|---:|
| isf.json.gz | 18.1 | **15.8** | 21.3 | 58.7 | 0.87x |
| big.json.l1.gz | 108.9 | **99.2** | 132.9 | 307.5 | 0.91x |
| big.json.l6.gz | **97.1** | 108.7 | 128.4 | 298.1 | 1.12x |
| binary.bin.gz | 421.9 | **308.9** | 476.0 | 873.2 | **0.73x** |
| **2 GB real image, `gzip -6`** | 13 908 | **11 225** | 15 881 | – | **0.81x** |

On the image rsvol also executes 24.1 G instructions against libdeflate's 18.3 G, and takes
190 M branch misses against 139 M.

The "2.2-4.5x zlib" claim in `bench/PACKAGES.md` is true, but stock zlib is a weak reference.
**libdeflate is faster** everywhere except `big.json.l6`.

**Floor.** The instrumented copy counts, for the 2 GB image, 497.5 M literals and 136.8 M
matches (1.63 GB of match bytes): 771 M table lookups in all. A lookup's chain is an L1 load (5)
plus shift and mask (1-2), about 6.5 cycles, so about 5.0 G cycles. The unavoidable
literal/match mispredicts add about 1.5-2 G, for **about 6.5-7 G cycles, roughly 3 cycles/B**.
rsvol runs at about 50% of that and libdeflate at about 60%. Multi-symbol tables (ISA-L style:
2-3 literals per lookup when the codes are short) lower the floor further on literal-heavy
memory data.

**Real-world impact.** The first run on a `.gz` image decodes the whole stream serially. A 2 GB
image takes **4.4-6.0 s**:

* `inflate::decode_block` accounts for 60% of the samples.
* `gzip::member_candidates`, the scan for extra members, for 14%.
* `build_table` for 6%.
* The page-cache write adds 1.9 s of sys time on a writer thread.

The same inflate core also serves the zip ISF packs and PNG.

**Opportunities.**

1. *libdeflate parity for the fast loop.* Mirror libdeflate's `decompress_template.h`
   structure, and first measure where the +32% instructions go.
   * Gain: -20% cycles (4.4 → about 3.6 s for 2 GB).
   * Effort: medium. Risk: low (existing differential tests).
2. *Parallel decode of one deflate stream*, as in rapidgzip or pugz:
   * find block boundaries in each chunk of the input;
   * decode with an unknown 32 KB window into 16-bit symbols with window markers;
   * resolve the markers once the previous chunk's window is known.
   Correctness is guarded by the gzip trailer (CRC-32 plus ISIZE), with a serial fallback.
   * Gain: decode throughput 4-8x. The page-cache write becomes the floor (1.6 s through mmap
     and 3.4 s through `write()` for 2 GB single-threaded; parallel `pwrite` helps). About
     4.4-6 → **1.5 s** in total. Effort: high (about 1-1.5 k lines). **Not validated.**
3. *Skip `member_candidates`* when the first member's ISIZE and the file length already rule out
   a second member, or start it lazily. Gain: 14% of the CPU. Effort: low.

**Verdict.** Not at the limit, and behind the best library. Worth fixing only if compressed
`.gz` images are a supported use case you care about, since it is a one-time cost per image.

### bzip2 (`src/codecs/bzip2.rs`)

**Achieved.** Single thread, 15.2 cycles/B on JSON and 36 cycles/B on binary data. libbz2
needs 66 and 169, so rsvol is 4.3-4.7x faster. The file is decoded block-parallel.

**Floor.** Per byte, the inverse BWT walks a 3.6 MB `tt` array that does not fit in L2. With
16 walk lanes and about 60-cycle L3 latency the walk is MLP-bound at about 4 cycles/B, and
Huffman plus MTF costs about 5-10 cycles per symbol. That gives about 8-10 cycles/B on JSON.

**Real-world impact.** Only `.bz2` images, which are rare. **Verdict: leave.** Multi-thread
scaling could not be judged on the loaded box.

### snappy / xpress / lznt1

A full `banners` scan of the 2.7 GB AVML image decodes all of it in **0.08 s wall** (0.53 s
CPU), faster than the same scan over the ELF version (page-fault bound). The documented
speedups over libsnappy and wimlib are 2.4x and 1.65-4.1x. **Not on any hot path. Leave.**

### Crypto (`src/crypto`)

Standalone harness, `review-libs/crypto/cm.rs`, 1 MiB, pinned, best of 30:

| primitive | cycles / 64 B block | floor | how the floor is derived |
|---|---:|---:|---|
| MD5 | 289 | 288 | 64 dependent steps × 4.5 cycles (the add-rotate chain) |
| SHA-1 (NI) | 105 | about 80 | 20 dependent `sha1rnds4` plus the `sha1nexte` chain |
| SHA-256 (NI) | 131 | 128 | serial `sha256rnds2` chain |
| AES-128-CBC decrypt (VAES) | 10.0 (0.157 cycles/B) | 10.0 | 10 rounds per block, 2 × 256-bit `vaesdec` per cycle → 2.5 cycles per block |
| AES-128-CBC encrypt | 143 (2.24 cycles/B) | about 124-128 | serial: 10 × `aesenc` latency 3, plus xor |

**At the floor.** Real-world weight is zero: hashdump, lsadump and cachedump run in 3-7 ms in
total and hash a few hundred bytes. `mbrscan`'s MD5 is 1.8% of its samples.

**Finding: a latent 150x cliff.** SHA-NI has only legacy-SSE encodings. When
`sha_ni::compress` is inlined into a function whose AVX code left the upper YMM halves dirty,
LLVM places `vzeroupper` only at calls and returns, not before the inlined code. On Alder Lake
every legacy-SSE instruction then pays the SSE/AVX transition. I measured **312 cycles/B
instead of 2.05** in a harness where `digest` was inlined into `main`.

In the production LTO build, SHA-256-NI is inlined into `lsadump::decrypt_aes` and SHA-1-NI into
`GetServiceSIDs::run`. Both functions contain YMM code. The upper halves are clean at the SHA
point today: lsadump's cycles are identical with and without the fix, 2.86 M. That makes this
an accident of the code layout, not a guarantee.

**Fix.** Put `#[inline(never)]` on both `sha_ni::compress` functions. It is validated in the
clone and costs nothing measurable. Alternatively, issue `_mm256_zeroupper()` on entry.

### x86 disassembler (`src/disasm`)

**Achieved.** On the real-code corpus (50 MB for each mode):

| workload | rsvol | capstone 5.0 | speedup |
|---|---:|---:|---:|
| `line` (the malfind/mbrscan renderer) | 34-41 M insn/s | 6.5-8.1 M | 5.2x |
| `len` | 62-74 M insn/s | 7.9-8.6 M | 7.9-8.6x |
| `detail` | 49-59 M insn/s | – | – |

At about 4.7 GHz, `line` is 115-140 cycles per instruction and `len` 65-75.

**Floor.** A table-driven length decoder (prefix/opcode/ModRM tables) needs about 5-10 cycles
per instruction. Decode plus text formatting needs about 20-40. rsvol is about 3-10x from
those floors.

**Real-world impact: none.** `mbrscan` renders 293 k disassembly lines, yet the disassembler
(`write_lines` + `decode`) is 2.5% of its samples. The 0x55AA scan in `layers/scan.rs` is 87%.
`malfind` takes 10 ms in total, and `skeleton_key` and `direct_system_calls` are
milliseconds. **Verdict: far from the floor and not worth closing.**

### Regex / YARA (`src/yara`)

**Achieved.** Single thread over a 1 GB mmapped window. From the refbench of a quiet machine
(`yara-perf/final2.md`), confirmed today under load:

* the literal, pair, Teddy and DFA cases run at 25-27 GB/s;
* `alt20` runs at 15 GB/s;
* the YARA `single` and `text20` cases run at 16-25 GB/s;
* `hexre` runs at **3.6 GB/s**, with 167 k string matches in 1 GB.

**Floor.** Single-core DRAM streaming measures 20-21 GB/s under load. The literal engine
matches it (21.1 GB/s today) and beats it when the box is quiet, thanks to its next-page
prefetch. So the prefilters are **at the single-core DRAM limit**. The remaining gap is on
candidate-heavy rule sets like `hexre`, where verification dominates.

Multi-threaded scans are bound by aggregate DRAM (about 52 GB/s) and page faults: 3-4 cores
running rsvol's engine saturate memory. `yarascan` over the kernel layer costs about 0.1-0.24 s
wall; 40% of its samples are in the engine and 29% in the scan framework.

**Real-world impact: the engine is not the problem, its input is.** `windows.vadyarascan` on
the main image reads 10 367 distinct VADs totalling **15.4 GB**, mostly unmapped. For every VAD
it:

* `memset`s the whole buffer, because `read_impl(pad)` fills it before copying: 32% of CPU;
* copies the mapped pages: 17%;
* YARA-scans all 15.4 GB, zeros included: 49%.

The run takes 1.14-1.2 s wall and **12.8-13.9 s CPU**.

**Prototype, validated.** Patch: `testdata/scratch/review-libs/prototype.patch`, about 330
lines including the test and the SHA-NI fix.

* `Layer::read_padded_into_zeroed`, with an `IntelLayer` override, is `read_impl(pad)` without
  the initial fill. It reports the byte ranges it wrote.
* vadyarascan keeps a per-worker buffer that stays all-zero outside a "dirty" run list. After
  each read it clears only the stale bytes that the new runs did not overwrite, then hands the
  holes (the complement of the runs) to the matcher.
* `Matcher::scan_holes` skips hole interiors in the candidate search. This is allowed only when
  the matcher is *zero-inert*:
  * no engine reports a candidate on a 384 KB all-zero buffer, a test run once per matcher;
  * no string is checked at every offset;
  * there is no xor/difference engine.

  The margin kept at each hole edge is the engines' maximum lookaround (pair context, anchor,
  pattern width, window offset) + 64. The Aho-Corasick state is rebuilt from that margin. Rule
  conditions still see the full, materialised buffer, so `uint16(0)`, `filesize`, `#a` and
  `@a` are unaffected.

Why the output cannot change: a candidate whose engine-examined bytes are all zero cannot exist
(checked once per matcher), and every window that touches mapped data lies within the margin
of a live range. If the matcher is not zero-inert, the prototype falls back to the full scan.

Results, interleaved and 3 rounds, one string `Microsoft`:

| | baseline | prototype |
|---|---:|---:|
| wall | 1.14 / 1.12 / 1.15 s | **0.41 / 0.40 / 0.44 s (2.7x)** |
| user CPU | 13.3-13.9 s | **2.87-2.97 s (4.7x)** |

Output was compared with the baseline by `cmp`:

* `Microsoft`: 26 560 rows, identical.
* `vady/rules.yar`, 6 rules including a hex pattern straddling hole edges, a nocase regex, a
  wide nocase string with a count, a condition-only `uint16(0)`/`filesize` rule and a jumped
  hex pattern: 225 258 rows, identical. It ran in 0.45 s against 2.0 s.
* `vady/mixed.yar`: a 40-string Teddy set, a 700-string hash set, hex jumps and alternations,
  xor, base64 and regexes: 2 715 106 rows, identical. It ran in 2.3 s against 3.2 s. The xor
  string disables the hole skip, so only the fill savings remain.
* `vady/zero.yar`, which matches all-zero data and so is not inert (fallback path), restricted
  to 2 PIDs: 57 993 018 rows, identical.
* `cargo test yara`: all 65 tests pass. That includes a new differential test,
  `scan_holes_equals_scan` (in the patch). It builds 6 rule sets covering the literal, pair,
  Teddy, hash, regex, wide, xor, condition-only and non-inert cases, plus 36 random sparse
  buffers of 0.2-1.1 MB with holes of 0-300 KB and patterns planted across hole edges. It
  compares `scan` with `scan_holes`.

  A mutant with a 1-byte margin also passes. The test does not pin the margin down: for an
  inert matcher every engine window holds a non-zero byte, so a real candidate lies within
  (window offset + anchor + context) of a hole edge, and that is the bound the prototype uses.
  A targeted test for context-anchored hex atoms is still to write.

Where the time goes after the change: `memmove` (copying mapped pages out of the page cache)
52%, the YARA engine 23%, `memset` 16%. The remaining cost is the copy bandwidth of the mapped
bytes.

**Remaining work for production:**

* Hole support for the difference (xor) engine: the D stream of zeros is zeros, so the same skip
  applies once `dbuf` is built per live range.
* The same matcher hint in `linux.vmayarascan`. It already copies only mapped runs into fresh
  zero pages, but scans the holes.
* A targeted test for context-anchored hex/regex atoms, where the margin matters. The random
  differential test is already in the patch.

Effort: low to medium. Risk: low, given the inertness check, the fallback and the differential
test.

Related robustness issue, not performance: a rule that matches zeros, such as
`{ 00 × 16 }` with `#z > 1000`, over all VADs makes vadyarascan grow without bound. The
baseline and the prototype behave the same way. My unrestricted run was SIGKILLed after 24 s
and about 180 s of CPU. My mistake here: I ran it without `limit.sh` and briefly caused memory
pressure on the shared box; the page cache dropped from 41 GB to 9 GB. Python streams rows per
VAD, but rsvol collects every VAD's hits before emitting. The fix is to emit per wave or
bound memory.

### PDB → ISF (`src/symbols/windows/pdb`)

The commit log's first run of a download: 1.44 s in total, made of download about 1.3 s,
**conversion 9 ms (ntkrnlmp 4.2 ms)**, xz encode 33 ms and table build 15 ms. The floor is set
by writing about 6.7 MB of JSON, roughly 1-2 ms. **Leave.** The only cheap item is moving the
33 ms xz encode of the python-compatible cache file off the critical path, the way the `.isfb`
helper already is: 2% of a run that only happens once per kernel.

### JSON / ISF index (`src/util/jsonidx.rs`)

Stage 1 (structural index), single thread:

| file | rsvol | simdjson 4.x (haswell kernel) stage 1 | simdjson DOM |
|---|---:|---:|---:|
| noble 6.8 ISF (64.5 MB) | 2.43 GB/s | 4.89 GB/s | 1.97 GB/s |
| Windows ISF (6.7 MB) | 3.80 GB/s | 5.62 GB/s | 1.98 GB/s |

rsvol's indexed ISF walk (stage 1 + walk) runs at 1.24-1.61 GB/s, and its parallel stage 1 at
3.6-5.1 GB/s on 4 threads.

**Floor.** Per 64-byte block the work is:

* 4 `vpshufb` classifications and 1 `pclmulqdq` for the quote mask;
* about 20 scalar mask operations;
* flattening at about 1 cycle per structural (0.13 structurals per byte, so about 8.4 per
  block).

That is about 12-20 cycles per block, **about 5-8 GB/s in cache** (simdjson reaches about
1 B/cycle on this file). rsvol is at about 50-70% of simdjson.

**Real-world impact.** The lazy index takes 4.3 ms of a 28 ms cold Windows run, and jsonidx
is about 5% of the cold identifier index. **Verdict: 2x headroom, a few ms of real impact.
Low priority.**

## Top 3 opportunities, weighted by real-world impact

1. **Sparse-aware VAD/VMA YARA scanning.** Validated prototype, byte-identical output.
   `windows.vadyarascan` goes from 1.14 → 0.42 s wall and 13.6 → 2.9 s CPU on the main image.
   It pays off on every run, because user rules are never cached. The same matcher hint
   carries over to `linux.vmayarascan`. Effort: low to medium; risk: low.
2. **Compressed-image first runs:**
   * Stream single-block `.xz` images through the writer thread instead of a shared file
     mapping. This removes 1-31 s of writeback stalls per 2 GB, leaving the 17.7 s decode.
     Low effort.
   * Bring inflate to libdeflate parity (-20% cycles).
   * Add a rapidgzip-style parallel decode of a single deflate stream: **4.4-6 s → about
     1.5 s per 2 GB `.gz` image**, write-bandwidth bound. High effort, CRC-guarded.
3. **Cold-start LZMA share:**
   * Checksum CRC-64 and extract identifiers in cache-hot chunks during the decode. This cuts
     about 8% of cold identifier-index CPU, where CRC-64 is currently DRAM-bound at 13 GB/s
     instead of 36 GB/s.
   * Pipeline the lazy JSON index behind a single-block ISF decode (up to 4 of the 28 ms cold
     Windows run).

   The decoder itself is already faster than liblzma and 7-Zip, so these overlaps are the
   only cheap levers left.

Zero-cost fix to take regardless: `#[inline(never)]` on the two SHA-NI `compress` functions,
which removes the latent 150x SSE/AVX-transition cliff.

## Reproducing

All paths below are under `testdata/scratch/review-libs/`:

* `tools/pstat -t|-p -- cmd`: user-mode counters, TMA level 1 and port pressure.
* `tools/pprof OUT 250000 -- cmd` followed by `tools/symb.py OUT target-prof/release/vol`: the
  sampling profile. `perf_event_max_sample_rate` is 1000 on this box, so a sample is about
  1 ms.
* `xz/`: `codec_xz_micro` (fixed harness), `codec_xz_stats` (`--cfg lzma_stats`) and `crcb`.
* `inflate/`: `libmicro` (rsvol gzip/bzip2), `libcnt` (symbol counts), and `cref`/`cref_ng`
  (libdeflate, zlib, zlib-ng).
* `crypto/cm.rs` (with `cm2`, which has the fix); `bw/bw` (DRAM/L2/L1 bandwidth);
  `json/s1` (simdjson stage 1 and DOM).
* `img/win.raw.{gz,xz}`: `gzip -6` and one-block `xz -6 -T1` of
  `rsvol-win10-x64-17763-imagery.raw`.
* `vady/*.yar` and the outputs: the vadyarascan equivalence corpus.
