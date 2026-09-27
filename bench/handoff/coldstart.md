# Handoff: cold-start / first-run paths (symbols, PDB, automagic speculation)

- Branch: `worktree-agent-a107e7061c55aebc1`
- Worktree: `/home/user/rs-vol/.claude/worktrees/agent-a107e7061c55aebc1`
- Base: main `447969b`; main merged up to `4b73e33` (startup + runtime agents' work, incl. the
  runtime agent's negative-result cache hooks in `context.rs`: conflict resolved, both kept).
- Review: `bench/reviews/symbols-coldstart.md`. Prototypes: branch `review-coldstart` of
  `testdata/scratch/review-symbols/rsvol`.

## State of the commits

All commits are complete (no WIP). `bench/scripts/cargo.sh test --profile fast`: 564 + 2 pass.

| commit | what |
|---|---|
| `c0b3350` | `util::download::download_ranged_to`: parallel HTTP Range download, single-request fallback |
| `ace363f` | Windows speculation takes python's choice; PDB downloaded/converted ahead; deferred `.json.xz` (see `2544125`) |
| `248e348` | `symbols::stream` + `LazyCore::build_streaming`: lazy index follows the xz decoder |
| `e9ab87b` | `coldbench.py`: cold also wipes `isfchoice/`, `isfnew` mode, `--py-cache`, own-helper wait, docs |
| `12653c0` | helper pre-builds up to 3 sibling ISF blobs (512 MiB budget, idle) + docs |
| `528321e` | name table CAS in the member pass again; identifier index streams its 2 biggest ISFs |
| `e2fcf07`, `487663c` | mac first banner hit in 2 MiB chunks (python's bytes per batch) |
| `5e704f6`, `8608fce` | `EarlyIndex` (identifier index beside the kernel search); symbol names indexed while decoding |
| `2544125` | parity fix: the converted `.json.xz` is written by a background thread joined before exit |

### Gates

- Full gates with an empty private `RSVOL_CACHE` on the binary of `8608fce` + main (before the
  runtime merge): check_all 98/98, check_win_images 1114/1114, check_nix all 763/763.
- Full gates on `a91f369` (after the runtime merge): check_all 98/98; check_win_images had ONE
  DIFF, `[win2003-x86] isfinfo.IsfInfo`: our output listed
  `testdata/symbols-extra/windows/ntkrnlmp.pdb/4E4A894DD1A64BC3ADFEA71F18E29364-2.json.xz`,
  python's live run did not. Cause: the converted PDB's `.json.xz` was written by the detached
  helper after exit, and the next command (python's isfinfo) started before it appeared.
  Fixed in `2544125` (background thread joined before exit). **Not re-gated** (stopped on
  request): rerun `check_win_images.sh` (at least `win2003-x86`) and `check_nix.sh all` with an
  empty private cache. NOTE: `testdata/symbols-extra/windows/ntkrnlmp.pdb/4E4A...-2.json.xz` was
  created by these gate runs (python writes the same file there too); delete it if the gates
  should start from the original state.

Ready to merge: after that re-gate.

## Numbers

Benchmark VM (quiet, 32 vCPU EPYC Zen 1, LZMA ~2x slower than the i7), main `1667990` vs this
branch (before `2544125`), best of 10 wall ms (median), `RSVOL_VOL3_ROOT=/nonexistent`:

| scenario | main | this branch | change |
|---|---:|---:|---:|
| win-main pslist, ISF cold (identifier caches warm) | 42.7 (43.5) | 39.9 (41.0) | -7% |
| win-main pslist, all cold, no python DB | 46.5 (47.9) | 41.0 (41.6) | -12% |
| noble linux.pslist, ISF cold | 99.4 (102.8) | 92.0 (95.3) | -7% |
| mac pslist, ISF cold | 51.6 (54.6) | 48.7 (50.1) | -6% |
| PDB-cold (ISF converted from a cached PDB) | 65.5 (68.5) | 28.5 (30.2) | -56% (*) |
| 1809 pslist cold, fresh DB, 2 copies of the GUID | 94.9 (96.2) | 95.0 (95.7) | = |
| true first run, PDB downloaded (12.4 MB) | 5667 (6017) | 3340 (4436) | -41% / -26% |

Local i7-12700KF (load 22-29, other agents' gates running), regime A python DB
(`testdata/scratch/review-symbols/pycache-full`), `scen.sh` interleaved, best of 5 (median):

| scenario | main | this branch | review floor |
|---|---:|---:|---:|
| win-main pslist cold | 30.7 (36.5) | 24.7 (25.9) | ~20.5 |
| win-1809 pslist cold | 76.7 (77.6) | 72.1 (72.8) | ~58 (DRAM bound) |
| PDB-cold | 68.0 (75.6) | 21.9 (23.1) (*) | ~30 |
| noble pslist cold | 61.7 (66.2) | 60.5 (64.6) | ~48 |
| mac pslist cold | 35.5 (36.9) | 35.6 (37.2) | ~23 |
| jammy pslist cold | 105.8 (109.6) | 103.4 (119.8) | ~62 (scan bound; unchanged path) |
| network first run | 1.1-1.9 s | 0.6-0.9 s | download bound |

(*) measured with the `.json.xz` written after exit by the helper. `2544125` writes it before
exit (overlapping the lazy index, plugin and output): expect part of the 25-50 ms compression
back on PDB-cold wall time; re-measure (`scen.sh 5 pdbcold`). The prototype measured "thread
joined before exit" as no gain for pslist; the conversion-ahead and early index gains remain.

Trace-level: Windows kernel ISF lazy index after the decode ends 3.3-5 ms -> 0.9-1.3 ms; mac
4-8 -> ~2 ms; 1809 regime A: the speculative load is python's copy and the join takes 0.01 ms.

## Gotchas

- The sandbox of this agent refuses heredocs/complex shell and writes outside the worktree:
  scratch lives in `testdata/scratch/opt/` of the worktree (scripts `ab.py`, `scen.sh`
  (scenarios main/1809/noble/jammy/mac/pdbcold, `TRACED=1 SHOWTRACE=1`), `tr1.sh` (one traced
  run), `netrun.sh`/`netplan.sh` (network), `vmcold.py`/`vmtrace.sh` (VM), `gates.sh`).
- PDB-cold needs `XDG_CACHE_HOME` pointing at an empty dir, or rsvol finds the ISF in
  `~/.cache/volatility3/symbols` (scen.sh does it).
- On the VM, rsvol finds `~/rsvol-bench/volatility3` as a python install (it holds a converted
  8E33 ISF): use `RSVOL_VOL3_ROOT=/nonexistent`. The VM is clean again (coldstart dir removed).
- New switches: `RSVOL_RANGED_DOWNLOAD=0`, `RSVOL_PDB_RANGES=wave,partKiB,max`,
  `RSVOL_PDB_ISF_WRITE=sync`, `RSVOL_STREAM_ISF=0`, `RSVOL_PREBUILD=N`, `RSVOL_MAC_FIRST_HIT=0`.
- `pdb::convert_ahead(.., download=true)` threads are joined at exit (`finish_ahead`), so an
  unused speculative download finishes instead of leaving partial files.
- Streamed index correctness tests: `cargo.sh test --profile fast streamed` and the ignored
  `on_all_isfs` tests (`limit.sh -m 10G cargo.sh test --profile fast on_all_isfs -- --ignored
  --test-threads 1`: 188 xz ISFs streamed == whole, lazy == full on all).

## Next steps / not done (for FOLLOWUPS.md)

1. Re-gate after `2544125` (above) and re-measure PDB-cold; if the synchronous-before-exit write
   costs too much, write the file in the run but start the compression earlier (it already
   starts right after the conversion) or use a faster xz preset for the in-run write.
2. Multi-block `.xz` ISFs (noble 6.8: 3 blocks): blocks after the first decode in parallel but
   are indexed only once the first block is complete (noble tail after decode ~10-17 ms). Needs a
   per-block structure pass started at a newline with the depth guessed from indentation and
   validated when the previous block is known, plus section-agnostic member checks.
3. Skeleton blob and root checks still run after the decode (~0.3-0.6 ms): could run during it.
4. Mac first-hit fine chunking: no gain on the VM (page-fault bound), local gain not measured
   (box saturated). Measure on a quiet box; drop it if it does not help.
5. Pre-built sibling blobs (`RSVOL_PREBUILD`): benefit (coldbench `isfnew` on a new image) not
   benchmarked.
6. Regime B (python DB lacking rows): throughput-bound; only the two biggest target-OS ISFs are
   decoded while indexed.
