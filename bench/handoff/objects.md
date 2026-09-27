# Handoff: object model + per-plugin row work (perf-plugins-objects)

- **Branch:** `perf-plugins-objects`, worktree `/home/user/rs-vol/.claude/worktrees/agent-a0f0516ac31241c6c`
  (a worktree of `/home/user/rs-vol`, so the branch is visible in the main repo). Head `c03de43` +
  this note. Everything is committed; there are **no WIP commits**.
- **Merged into it:** `main` up to `4b73e33` (startup + runtime work: pool, statistics, limit.sh
  fix), `perf-rows-nix` (Linux/mac sub-agent, head `23c7402`) and `perf-rows-win` (Windows
  sub-agent, head `bfc9059`). Merge conflict resolved once: `src/plugins/windows/statistics.rs`
  takes **main's** version (the runtime agent's parallel failure-list walk). The Windows
  sub-agent's own statistics rewrite (on `perf-rows-win`) was dropped by that resolution.
- **Ready to merge:** yes, as far as tested (see Gates). The last full gate run was stopped at the
  orchestrator's request before `check_nix.sh all` finished on the merged head.

## Gates on the merged head (c03de43)

- `bench/scripts/cargo.sh test --profile fast`: 562 + 2 passed, 0 failed.
- `check_all.sh -b <release>`: 98/98 OK.
- `check_win_images.sh`: 1113 OK, 1 DIFF = `isfinfo.IsfInfo` on win2003-x86 (compared against a
  live python run that lists the shared symbol dirs; both sub-agents saw the same flake while
  other agents were changing those dirs; unrelated to plugin code).
- `check_nix.sh all`: not finished (stopped). On `ea6836b` (my object-model work, before the
  sub-agent merges) all four gates passed: 538 unit, 98/98, 1114/1114, 763/763. The nix
  sub-agent ran all four gates green on its branch (763/763 nix) after merging my `e1181f6`.
  **Next agent: run `check_nix.sh -b $PWD/target/release/fvol all` once on this head.**
- Renderer A/B (quick, csv, json, jsonl, pretty, none, `--filters`) against the pre-work main
  binary: identical for all 12 plugins converted here (handles, vadinfo, vadwalk, iat, privileges,
  envars, getsids, verinfo, malware ldrmodules/hollowprocesses/processghosting/suspicious_threads)
  and kthreads; the sub-agents did the same for theirs (see below for one jsonl caveat).

## What is done (numbers: main image unless noted; "base" = main at the start, 447969b)

Instructions are single-thread (`RSVOL_THREADS=1`), min of 3-5; wall is min of 7 interleaved
runs at load average 17-28 (so absolute walls are inflated; relative numbers held up).

### Object model (src/objects, src/symbols/table.rs) -- benefits every plugin
- Per-thread member cache (one 64-byte line per entry, inline copy of names <= 19 bytes, keyed by
  (process-unique table id, user type, name address, length), byte-verified), negative member
  cache (has_member probes), per-thread `get_type` cache, `Space::get` thread-local front cache.
- Zero-copy page cache in the object model built only on `Layer::slice`: (layer, vpn) -> host
  address of the page in the image mapping; scalars load little-endian straight from it (raw,
  ELF, LiME, crash-dump images and the Intel layers over them). `objects::page_bytes`,
  `read_into`, `prefetch` are public helpers. `Field::int_from` decodes a field from bytes.
- C strings decoded only up to the first NUL unit for non-strict handlers (property-tested
  against decode-then-cut), ASCII fast path in UTF-16, ASCII shortcut in address_to_string.
- `name_info` uses the header's own space (no global `Space::get` mutex per handle).
- Instruction sweep base -> `ea6836b` (object model + 11 plugin conversions + handles only),
  RSVOL_THREADS=1: Windows svclist -58%, svcdiff -56%, svcscan -51%, handles -51%,
  processghosting -42%, threads -41%, debugregisters -40%, suspicious_threads -40%,
  hollowprocesses -37%, vadinfo -36%, vadwalk -36%, ldrmodules -35%, dlllist -32%, malfind -31%,
  pslist -20%, 50+ plugins improved, none regressed beyond noise. Linux (noble ELF): mountinfo
  -49%, pscallstack -42%, proc.Maps -41%, elfs -41%, malfind -38%, pagecache.Files -33%, lsof -28%,
  library_list -27%, pslist -34%. mac: lsof -71%, netstat -67%, psaux -21%, proc_maps -18%.

### Rows on the workers (src/renderers/mod.rs `RowBlock`, src/plugins/mod.rs helpers)
- `RowBlock` (format on the worker with the sink's RowEncoder, values kept when there is none),
  `par_blocks`, `stream_blocks` (windows of 8 x threads, bounded memory, catches worker panics and
  resumes them with their payload after the rows before them; consume gets `Option<X>`, `None` =
  the item panicked), `emit_par_blocks` / `emit_par_rows` (python's `for item: yield from rows`
  with python's error points), `stream_chunks` (streaming, par_map_stream, panic-safe; moved here
  from plugins::linux, re-exported there). Unit test `plugins::tests::emit_par_blocks_like_serial`.
- Converted here: the prototype's 11 (handles, vadinfo w/o --dump, vadwalk, iat, privileges,
  envars, getsids, verinfo, malware ldrmodules/hollowprocesses/processghosting/suspicious_threads).
- handles rewrite: zero-copy leaf decoding, header prefetch per leaf, per-run `Namer` (type map as
  leaked &'static names, NameInfoOffset / ObpInfoMaskToOffset resolved once), naming + formatting
  in units of 256 handles across all processes (critical path no longer the biggest table).
  handles 515.6M -> 249M instructions (-52%, ~6k per handle); wall 20.6 -> 6.8 ms under load
  (review: 22.0 quiet base, prototype 10.6, floor ~3.3).
- kthreads: symbols resolved in one pass (`module_lookup_by_addresses`) instead of 8 linear
  lookups + the 7 ms address-index build: 112.7M -> 62.2M instructions.

### Final wall (base -> merged head, load 17-28, min of 7 interleaved) vs review floor
| plugin | base ms | now ms | floor ms | now/floor |
|---|---:|---:|---:|---:|
| handles | 20.6 | 6.8 | ~3.3 | 2.1x |
| vadinfo | 9.1 | 5.3 | ~2.5 | 2.1x |
| vadwalk | 5.9 | 3.8 | ~2.3 | 1.7x |
| svcdiff | 12.7 | 4.5 | ~2.5 | 1.8x |
| svcscan | 10.3 | 3.6 | ~2 | 1.8x |
| iat | 7.1 | 4.3 | ~2.5 | 1.7x |
| threads | 5.6 | 4.7 | ~2.5 | 1.9x |
| dlllist | 12.4 (noisy) | 13.7 min / 16.3 med vs 24.6 med | ~2 | noisy, rerun quiet |

Sub-agent results (their reports, same caveats): kallsyms 49.3 -> 16.8 ms (main-thread CPU 42.7 ->
4.9 ms, floor ~7), pagecache.Files 46.3 -> 20.0 ms (floor ~6), mountinfo 6.5 -> 2.0 ms, proc.Maps
8.5 -> 6.0, pscallstack 9.4 -> 6.4, mac list_files 44.7 -> 29.5 ms (floor ~6, page-fault bound),
mac malfind 24.9 -> 15.7 ms; Windows svc* main-thread CPU halved again, suspended_threads 7.8 ->
5.5 ms, etwpatch 9.1 -> 7.6 ms (pe_symbols RSDS page memo), bigpools 2.9 -> 1.6, timers 2.3 -> 1.6,
malfind 3.1 -> 2.1 ms.

## Converted plugins
- Here: see above. Linux/mac (perf-rows-nix): kallsyms (worker-side block walk), pagecache.Files,
  mountinfo, mac list_files, proc.Maps, elfs, malware.malfind, lsof, pscallstack, library_list,
  psaux, pidhashtable, capabilities, psscan, envars, process_spoofing, sockstat; mac malfind,
  proc_maps, lsof, kevents, psaux. Windows (perf-rows-win): svcscan/svcdiff/svclist (planned
  walks, parallel rows), bigpools, timers, malfind (not --dump), threads/thrdscan/orphan threads,
  dlllist (not --dump), cmdline, pebmasquerade, certificates, scheduled_tasks, devicetree (after
  its scan), suspended_threads/debugregisters (one parallel VAD pass), pe_symbols users.
- Left serial on purpose: linux/mac bash (tiny), mac netstat (raise_python must stay on the output
  thread), RecoverFs (tarball-write bound), pstree/consoles (tree output, little to gain).

## Gotchas
- Byte identity depends on python's error points: every converted plugin must emit the rows before
  an error, then the error; `emit_par_blocks` / `stream_blocks` / `stream_chunks` do this. A
  `consume` passed to `par_map_stream` must never panic (it would deadlock the stream); raise on
  the output thread only through `stream_blocks` (windowed par_map, consume may panic).
- The member cache is keyed by name *address*; names are verified byte-for-byte, so heap names are
  safe. Table ids are process-unique u32 (0 = uncached after 4G tables). Tried and rejected:
  2-way and 8-way associativity (+4-13% instructions, +4% cycles; misses are cheap at IPC ~2.8).
- Page cache: entries never go stale because layers are `'static` and immutable and slices live as
  long as their layer. Only use `page_bytes` on `LayerRef`s (leaked layers).
- Known jsonl difference (nix agent): kallsyms in jsonl when the plugin *ends in an error* flushes
  a block-size-dependent amount before the error; python prints only "\n" there, so neither the
  old nor the new build matched python in that case. Belongs to the renderer.
- Measuring: the box is shared; use `testdata/scratch/opt/abinst.sh` (instructions), `abcyc.py`
  (pinned interleaved cycles), `ab.py` (interleaved wall), `maincpu.sh` + `measure.py` (main-thread
  CPU during plugin.run, instrumentation applied in a throw-away clone only). Several instruction
  runs were polluted by concurrent symbol-cache rebuilds (kallsyms 807M vs 1259M on the same
  binary): take min of >= 5 and re-check outliers.

## Test commands
- `bench/scripts/cargo.sh test --profile fast` (new tests: objects::tests::page_cache_matches_reads,
  lookup_caches_are_exact, strings::tests::cstring_cut_matches_full_decode,
  plugins::tests::emit_par_blocks_like_serial, plugins::linux::tests::stream_chunks_*).
- `bench/scripts/check_all.sh -b $PWD/target/release/fvol`, `check_win_images.sh -b ...`,
  `check_nix.sh -b ... all`.
- Per-plugin renderer A/B: `testdata/scratch/opt/rcmp.sh BIN_A BIN_B IMG plugin [args]`
  (FILTER="-PID,9999" adds a --filters run); subset of plugins on all manifest images:
  `testdata/scratch/opt/subset.sh BIN windows|linux|mac "plugins..."`.

## Next steps / remaining ideas (for FOLLOWUPS.md)
1. Run `check_nix.sh all` once on this head (only gate not re-run after the sub-agent merges).
2. Re-apply the Windows sub-agent's statistics rewrite only if it beats main's version (it was
   dropped in the conflict; compare `perf-rows-win:src/plugins/windows/statistics.rs`).
3. Symbol address index (table.rs `symbols_at`): 7 ms per build on a 300k-symbol kernel; tried a
   parallel sample sort (not better on a saturated box) and 11-bit radix (+9% instructions).
   Better: persist the index with the ISF cache (symbols agent) or batch lookups per plugin like
   kthreads (tty_check, check_idt, netfilter, ftrace, tracepoints, keyboard_notifiers, mac
   check_syscall/check_sysctl/check_trap_table/timers/trustedbsd spend 40-60% there).
4. Call-site member caches (a `m!(obj, "Name")` macro with a static per-site slot) for the VAD /
   thread / process helpers: name resolution is still ~45% of vadinfo's instructions (61 lookups
   per VAD), though cheap in cycles.
5. `SymbolTable::enum_lookup` validates UTF-8 of every constant per call (Windows agent): cache a
   value -> name table per enum.
6. handles: split the level-0 leaves of the biggest tables across workers (walk phase ~3.5 ms of
   ~7 under load); File/Key naming with pre-resolved fields; `get_full_key_name` without the
   per-call FxHashSet and Vec<String>.
7. Page faults are now the largest term for many object walkers (handles 5.3k faults ~16 ms CPU,
   dlllist/ldrmodules 5-11k): allocator top-pad / hugetlb tunables (review item 11), RowBlock
   capacity hints to avoid realloc faults (mac malfind).
8. mac list_files (~17 ms walk) and pagecache.Files dentry listing are page-fault bound on the
   image mapping; speculative prefetch threads made it worse.
9. `Error` clone helper in error.rs (four local copies exist), move `task_items` next to the
   helpers if mac keeps using it.
