# Further optimizations (not yet implemented)

Collected from the hardware-floor reviews (`bench/reviews/*.md`) and the optimization agents' final
reports. Each item: estimated gain, effort/risk, source. Items are removed from here when implemented.

## Startup / fixed per-run cost
Status after the optimization pass: warm windows.pslist 1005 -> 710 us locally (floor ~424 us, 1.7x),
3.7 -> 2.4 ms median on the VM (VM floor: /bin/true alone takes 621 us).

- **Non-PIE static link**: -100..190 us on the VM (48 CoW faults + 131k instructions of self-relocation,
  mostly ~3,700 panic-location constants). Costs ASLR for a tool that parses untrusted images; the
  compiler flag that drops panic locations is nightly-only. *Deferred on security grounds.*
- **Skip glibc's environment scan** (75k instructions with ~218 env vars; ~0 with a normal environment):
  needs a custom process entry point. Low value, some risk.
- **pread instead of mmap for image reads** (~190 us per the floor experiment): removes image-page faults;
  a 3-5 day redesign of the read paths. Overlaps the scanning agent's dual-mapping work.
- **Warm-path memory touched every run**: a 128 KB table cache and a 268 KB output buffer; size them to
  the run (lazy growth).
- **stat() calls on the warm path**: ~28 for the ISF-choice cache checks, ~16 for the volatility3 install
  search; batch or cache the directory fingerprints.
- **`vol -h`**: ~6.1M instructions of help formatting (not on the warm path).
- **Huge pages for the text on the VM**: the benchmark VM's kernel lacks CONFIG_READ_ONLY_THP_FOR_FS, so
  that step is a no-op there (works locally).

## Runtime (thread pool, timeliner, statistics)
Done: panic propagation, one persistent pool (20-task round ~10 us vs 180-1100 us spawning), negative
kernel-discovery cache (mac timeliner 0.56-1.07 s -> 2.4-3.3 ms, Windows ~500 -> ~300 ms), statistics
11.2 -> 4.5 ms.
- **windows.statistics** still ~2 ms above floor: ~35 back-to-back parallel rounds + ~1 ms upper-level work.
  Prefetch the next round, or add a translate that stops at a given page-table level (intel.rs).
- **Pool wall-time win on 5-15 ms plugins** is unmeasured (box saturated): re-measure on the quiet VM.
- **Timeliner** starts one thread per plugin per run (deliberately off the pool: long blocking threads);
  a dedicated small thread set could shave the spawn cost.

## Scanning and memory access
Done: dual image mapping (sequential for bulk/dumps, MADV_RANDOM for page walks), round-based
parallel scans, mapped scan caches. Source: `bench/handoff/scanning.md`.
- **Cold read planner for virtual scans**: probe with `preadv2(RWF_NOWAIT)`, merge into 128 KiB-aligned
  reads per round. ~10% cold headroom (psscan 1.41 s vs 1.28 s floor).
- **Scan tail**: slowest group item 6-10 ms vs 0.75 ms average; smaller GROUP_BYTES or LPT ordering.
- **Scancache replay** still builds one `(offset, tag)` Vec (7.7 MB for MFT); let `Scanner::finish` take
  the mapped arrays. `Session::load` (Page atoms) still copies.
- **Random-mapping PTE teardown** (psscan ~12k faults): release in parallel at scan end. Measure against
  the exit helper first; may be redundant.
- **Scan phases on the persistent pool** (`util::pool`); the consumer must stay on the calling thread.
- Re-measure ROUND_CHUNKS (16k) on a quiet box; 8k/64k/uncapped were within noise under load.
- `walk_ranges` mishandles partly-valid large pages (found by the output agent; dump writers avoid it).

## Object model and plugin walks
Done: per-thread lookup caches, rows formatted on workers. Source: `bench/handoff/objects.md`.
- **Symbol address index** (`symbols_at`): 7 ms build on a 300k-symbol kernel, 40-60% of tty_check,
  check_idt, netfilter, ftrace, tracepoints, keyboard_notifiers, mac check_syscall/sysctl/trap_table/timers.
  Persist it with the ISF cache, or batch lookups per plugin.
- **Call-site member caches** (`m!(obj, "Name")` with a static per-site slot): name resolution is ~45% of
  vadinfo's instructions (61 lookups per VAD).
- **`enum_lookup`** validates UTF-8 of every constant per call; cache a value -> name table per enum.
- **handles**: split the biggest tables' level-0 leaves across workers; pre-resolved File/Key fields;
  `get_full_key_name` without a per-call FxHashSet/Vec<String>.
- **Page faults** now dominate many walkers (handles 5.3k, dlllist/ldrmodules 5-11k): allocator top-pad /
  hugetlb, RowBlock capacity hints. mac list_files and pagecache.Files are fault bound on the image map.
- Compare the dropped Windows statistics rewrite (`perf-rows-win` branch) against main's version.

## Output and dumps
Done: zero-page holes in dumps, fast RecoverFs deflate, parallel JSON subtrees, `check_dumps.sh`.
Source: `bench/handoff/output.md`.
- **dlllist/pslist/modules --dump writer threads**: create files in order on the main thread, write on
  ~8 workers, emit rows in order. Estimate dlllist 3.1 -> ~2.5 s where writeback isn't saturated.
- **memmap to a pipe**: 1.0 s vs 0.35 s to /dev/null; needs ~256 KiB chunks formatted in parallel just in
  time. Only fast consumers gain.
- **deflate block writer** (`write_seqs`, `write_block`, `huffman_lengths` sort): ~28% of fast-L1 CPU;
  CPU only, RecoverFs is writeback bound.
- vadinfo --dump in parallel (low priority: replay floor shows 8 threads no faster than 1);
  all-zero-page fast path in `SparseDump::range` (small).
- Run `check_dumps.sh` without `--rs-only` to fill in the Linux/mac python references (sequential).

## Libraries and codecs
Done: VAD/VMA yara hole skipping, streamed hits, SHA-NI AVX guard, streamed xz images, inflate at
libdeflate parity. Source: `bench/handoff/libraries.md`.
- **Parallel writer for `.gz` first runs** (highest value for compressed images): decode ~2.3 s per 2 GB
  vs ~3.4 s for one write() thread. 2-3 pwrite threads in `FileSink::at`, positional mode in
  `resource.rs::decompress_file_with`; bzip2's `truncate` must drain in-flight writes.
- **Multi-symbol inflate tables** (2 literals per lookup when l1 + l2 <= 11) to pass libdeflate.
- **Parallel single-stream deflate** (rapidgzip style): 4.4 -> ~1.5 s per 2 GB .gz. High effort.
- **Hole skipping for xor/difference matchers**: any xor string disables it (mixed.yar 1.9 s vs ~0.5 s);
  `.{n}` repeats hide context from atom filters.
- `gzip::member_candidates`: SIMD memchr instead of `iter().position` (~14% CPU, little wall).
- Identifier extraction during the ISF xz decode (~6% of cold identifier-index CPU).
- dist == 1 inflate copy goes through the stack (1.6% of matches).

## Symbols and cold start
Source: `bench/handoff/coldstart.md`.
- **Multi-block `.xz` ISFs** (noble 6.8: 3 blocks): index later blocks while decoding, from a newline
  with depth guessed from indentation and validated later. Saves the ~10-17 ms tail.
- Skeleton blob and root checks after the decode (~0.3-0.6 ms) could overlap it.
- PDB-cold: the converted ISF is now written before exit; if that costs too much, use a faster xz
  preset for the in-run write.
- Unmeasured: mac first-hit fine chunking (drop if no gain on a quiet box), `RSVOL_PREBUILD` sibling
  blobs, regime B (python DB lacking rows; only the two biggest target-OS ISFs decode while indexed).

## arm64
The arm64 build (2026-09-27) runs the portable fallbacks of every x86 SIMD path.
- **NEON versions of the hot SIMD kernels**: the scan searchers (memchr / teddy / pair filters),
  JSON structure and identifier scans, xpress / snappy / bzip2 decoders, SHA-256 (ARMv8 SHA2
  extension) and AES (ARMv8 AES). Measure on a native arm64 box against the x86 numbers first.
- The exit-teardown helper (util/exit.rs) and the pool's `set_tid_address` exit are x86-64 only;
  arm64 uses the portable paths (normal thread exit, in-process teardown).
