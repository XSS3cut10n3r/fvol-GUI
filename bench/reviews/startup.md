# Review: fixed per-run cost of a warm run

Reviewer: startup/fixed-cost performance review. Date: 2026-09-26. Code: `6825849` (no `src/` change up to
`73f6190`). Machine: i7-12700KF (runs pinned to the P-cores, CPUs 0-15), Linux 7.1.8, btrfs, glibc static-pie
built by rust-lld. Prototypes live in `testdata/scratch/review-startup/` (nothing in the repo was changed
except this file).

## 1. Verdict

rsvol is **not at the hardware limit**. On the four trivial plugins, a warm run costs **2.4x to 3.4x** the
measured floor for the same work. The floor is a minimal static binary that maps the same image and symbol
blob, touches exactly the same data pages and prints the same bytes. Against a floor that reads those pages
with `pread` instead of `mmap`, the ratio is **3.5x to 4.3x**.

| case (warm, min wall, µs) | floor, mmap design | floor, pread design | rsvol now | gap to mmap floor | rsvol, validated prototypes |
|---|---:|---:|---:|---:|---:|
| `windows.pslist.PsList` | 444 | 251 | 1080 | 636 (2.43x) | 711 (-34%) |
| `windows.info.Info` | 224 | 215 | 762 | 538 (3.40x) | 426 (-44%) |
| `linux.pslist.PsList` | 504 | 384 | 1454 | 950 (2.88x) | 1041 (-28%) |
| `mac.pslist.PsList` | 381 | 239 | 1014 | 633 (2.66x) | 683 (-33%) |

About **60% of the CPU time is spent in the kernel**, not in rsvol's code. For windows.pslist the split is
~430 µs kernel and ~300 µs user CPU. Most of the kernel time comes from:

- page faults on the 22 MB executable: 161 of 350 faults;
- tearing down about 4,000 mapped PTEs at exit, which the parent waits for: 185-276 µs;
- 48 copy-on-write faults from static-pie relocation.

Four changes fix most of this without touching plugin code, and all four were prototyped and measured:

- hot-text ordering;
- huge pages for the executable;
- non-PIE linking;
- moving the address-space teardown off the exit path.

Together they cut the warm run by **28-44% (min) and 31-43% (median)**. What remains is mostly user-space
instructions, plus the data-page faults that a `pread` design would remove.

## 2. Method

- **Warm cases.** Private cache `RSVOL_CACHE=testdata/scratch/review-startup/cache`, warmed first; python's
  `~/.cache/volatility3/identifier.cache` present as usual. Outputs were checked byte-identical to the
  baseline for every variant and knob.
  - `winps` = `-q -f /home/user/cbc2/task2/memory-dirty.raw windows.pslist.PsList`
  - `wininfo` = the same image with `windows.info.Info`
  - `linps` = `-q -s testdata/symbols -f testdata/images/linux/rsvol-noble-6.8.0-139.elf linux.pslist.PsList`
  - `macps` = `-q -s testdata/symbols -f testdata/images/mac/rsvol-mac-mavericks-10.9.2-13C64.dmp mac.pslist.PsList`
- **Timing (`tools/runab.c`).** fork, then exec after a pipe handshake, then `wait4`. Per run it records
  wall time, child task-clock (user+kernel CPU), user instructions and page faults (`perf_event_open`,
  enable-on-exec). With `RSVOL_PROTO_EXITTS`, the child writes a timestamp just before `exit_group`; the gap
  to the parent's `wait4` return is reported as "exit latency".
- **Order and statistics.** All variants of a case run in a **random order each round**, and each variant
  runs from its own copy of the binary, so page-cache and CPU-cache warmth is not shared between variants.
  Each figure is the median of three sessions × 250 runs. `tools/runbench.c` (posix_spawn, one binary
  back-to-back) gives the warm-CPU-cache "sequential" numbers.
- **Machine load.** The machine was heavily loaded during the review: other agents' `rustc` builds, and a
  game using about 190% CPU. Load average was 10-20. **Min and p10 are the robust statistics;** medians
  carry ±5-10% noise. Instruction and fault counts are deterministic.
- **Environment size.** The session environment has 217 variables. glibc's `__tunables_init` scans all of
  them: 75k instructions here, against ~7k with a 3-variable environment. `vol.base` needs 2.38M
  instructions under `env -i` against 2.48M here.
- **Tools, all in `testdata/scratch/review-startup/tools/`:**
  - `pftrace.c`: every user page fault with address and IP, plus smaps at exit (ptrace exit-stop).
  - `sstep.c`: ptrace single-step. Gives exact instructions per function, the syscall positions and the
    CPUID count.
  - `uprof.c`: unbiased cycle sampling with one sample per run at a random period.
    `perf_event_max_sample_rate` is 1000 here, and `perf` is not installed.
  - `mb.c`: kernel primitive costs.
  - `floor/`: generated floor programs.
  - `collapse.c`: `MADV_COLLAPSE` of an ELF's read-only segments.

## 3. Current numbers (baseline `vol.base` = release build of `6825849`)

| case | wall min / p10 / med (µs), random-interleaved | sequential min / med | CPU min | user instr | faults | syscalls | output |
|---|---|---|---:|---:|---:|---:|---:|
| winps | 1080 / 1163 / 1246 | 939-963 / 1131 | 818 | 2,477,320 | 350 | 103 | 12,155 B |
| wininfo | 762 / 851 / 914 | 564-602 / 690-704 | 583 | 1,035,283 | 230 | 125 | 623 B |
| linps | 1454 / 1617 / 1812 | 1284-1318 / 1468 | 1175 | 5,909,892 | 411 | 123 | 11,670 B |
| macps | 1014 / 1137 / 1210 | 839-931 / 1060-1337 | 790 | 2,403,754 | 299 | 130 | 8,433 B |

These agree with the "~1.3-2 ms locally" figure once the harness is accounted for. The python-subprocess
harness of `bench3.py` adds its own fork/exec cost.

## 4. The floor, and how it was derived (winps; other cases in §6)

| floor step (random-interleaved, min / med µs) | wall | exit latency | user instr | faults |
|---|---:|---:|---:|---:|
| F0: static non-PIE `_start: exit_group(0)` (`tools/nop.c`) | 81 / 105 | – | 4 | 1 |
| F1: std-only Rust static-pie (same rustflags) that writes the same 12,155 bytes | 156 / 206 | 18 | 122,458 | 30 |
| F2: F1 + open/mmap the image and isfb, replaying the **same 133 data-page faults** as the real run (from `pftrace`) | **444** / 522 | 101 | 124,287 | 163 |
| F2p: F1 + `pread` the **145 distinct image pages** the real run touches (SIGSEGV touch log, knob `RSVOL_PROTO_TOUCHLOG`) + the same 15 isfb faults | **251** / 337 | 27 | 126,806 | 45 |
| rsvol baseline | 1080 / 1246 | 185-276 | 2,477,320 | 350 |

Notes on the floor:

- F1 costs 122k instructions: 75k are glibc tunables parsing (environment-dependent) and 20k are the
  static-pie self-relocation. Nothing rsvol does can go below F1 without replacing glibc's startup.
- The step from F1 to F2 is the data-access cost of the mmap design: ~290 µs for 133 faults. Inside the
  process, the 133 faults cost 193 µs (1.45 µs each, fault-around maps 16 PTEs per fault). The rest is PTE
  teardown at exit (~80 µs; exit latency 101 µs against 18 µs).
- `pread` of 145 pages costs 62 µs and leaves nothing to tear down.

Kernel primitive costs on this box (`tools/mb.c`, best of 15, loaded):

| primitive | cost |
|---|---|
| file read fault (fault-around, 16 PTEs) | 2.4-2.7 µs |
| its share of munmap at exit | 1.3-1.5 µs (~85 ns/PTE) |
| MADV_RANDOM | does **not** disable fault-around (same cost) |
| anon fault | 1.03 µs |
| COW fault | 1.3-1.4 µs |
| pread 4 KiB | 0.63-0.77 µs |
| statx | 0.42-0.5 µs (the 47 paths of a warm run: 19.7 µs) |
| open+close | 0.84 µs |
| null syscall | 0.08 µs |

## 5. Gap breakdown (winps: 1080 against F2 444, gap ~636 µs)

**Page faults by mapping** (`pftrace`, baseline, 350 in total):

| mapping | faults | RSS mapped at exit | attributable to |
|---|---:|---:|---|
| image (5 GiB, r--s) | 118 | 7.5 MB | plugin data (in F2) |
| isfb (4.4 MB) | 15 | 0.9 MB | symbol data (in F2) |
| **executable `.text`** (10.6 MB) | **90** | **5.7 MB** | 426 distinct text pages touched, spread over the whole text; the hot code is only ~500 KB |
| **executable rodata / `.rela.dyn`** | **20** | 1.3 MB | |
| **executable `.data.rel.ro` + GOT** | **48 (COW)** | 192 KB dirty | static-pie relocation of 10,476 `R_X86_64_RELATIVE` entries |
| heap / anon | 19 + 23 + 4 | ~250 KB | 22 of the anon faults are `IntelLayer::TableCache`: 16,384 slots × 8 B = 128 KB of zeroed memory, one random slot per page table |
| stack, vdso, data | ~10 | | |

The executable alone accounts for **161 faults and ~7 MB of mapped PTEs**, against ~25 faults for F1.

**Time components** (measured, loaded box):

| component | winps | how measured |
|---|---:|---|
| exit latency (teardown of all PTEs, parent waits) | 185-276 µs min (F1: 18) | `RSVOL_PROTO_EXITTS` |
| executable faults + their teardown | ~300 µs | sum of the order, THP and non-PIE effects (§6): combo+THP −307 µs min |
| user CPU | 1.44M cycles min (~306 µs) vs F2 0.25M | `cycles:u` |
| kernel CPU | ~430 µs (task-clock 735 µs min − user) vs F2 ~205 µs | task-clock |
| syscalls | 103 (58 statx, 7 readlink, 5 openat, 4 mmap) ≈ 40-50 µs; ~25 avoidable | strace −c, `mb` |

**User instructions by phase** (`sstep`, 2,495,264 instructions, 28 CPUID):

| phase (instruction index at the syscall that ends it) | instructions | top items |
|---|---:|---|
| glibc static init, before the first syscall | 207k | `_dl_relocate_static_pie` 126k, `__tunables_init` 75k (217 env vars) |
| glibc syscalls, start of Rust `main` | 23k | |
| CLI: argparse port, plugin registry, `vol.json`, banner | 200k | plugin sort 52k (quicksort + smallsort + `plugins::all`), malloc 30k, memcmp 22k, `str::contains` 19k |
| context: image open, automagic and isfchoice caches, symbol-dir stats, isfb map | 411k | `store::unhex` 136k: the isfchoice cache is hex text, 8.5 KB; linux/mac automagic caches: 167-170k |
| plugin + render (pslist over ~100 EPROCESS) | 1,640k | `SymbolTable::member` 464k, `Obj::int/m/path` 335k in total, translation 196k, rendering 209k |
| flush + exit | 12k | |

In cycles (unbiased sampling), the CLI and registry take 15.8% and libc init 13.2%, well above their share
of instructions. This is cold code: i-cache and iTLB misses on text spread over 10 MB. That is why dense
hot text and huge pages also cut user cycles: combo+THP runs 1.17M against 1.44M `cycles:u` with only 6%
fewer instructions.

## 6. Prototypes (measured)

All of them are in `testdata/scratch/review-startup/`:

- **Build-only variants** use the baseline source (`rsvol-base`, `rsvol`) with the RUSTFLAGS listed below.
- **Runtime knobs** are in `rsvol-proto`; the patch is in `proto.patch` and adds `src/util/proto.rs`. Every
  knob is off by default, and the knobs are env-gated for measurement only.

Results: min wall, random-interleaved, median of 3 sessions; change against baseline.

| # | variant | winps | wininfo | linps | macps | faults (winps) |
|---|---|---:|---:|---:|---:|---:|
| – | baseline | 1080 | 762 | 1454 | 1014 | 350 |
| A | **non-PIE static, no EH-frame registration**: `-C relocation-model=static -C link-arg=-Wl,--defsym=__register_frame_info=0 -C link-arg=-Wl,--defsym=__deregister_frame_info=0` | 1020 (−6%) | 667 (−12%) | 1424 (−2%) | 914 (−10%) | 305 |
| B | **hot-text ordering**: `-C link-arg=-Wl,--symbol-ordering-file=<868 functions executed by the 4 cases>` | 911 (−16%) | 584 (−23%) | 1287 (−12%) | 864 (−15%) | 273 (text 90→13) |
| C | **huge-page text**: `-Wl,-z,max-page-size=0x200000`, then `MADV_COLLAPSE` of the executable's read-only segments once (`tools/collapse`) | 910 (−16%) | 567 (−26%) | 1293 (−11%) | 860 (−15%) | 274 |
| D | **teardown off the exit path** (`RSVOL_PROTO_DEFER=1`): `close_range`, then a raw `clone(CLONE_VM\|CLONE_UNTRACED)` helper that keeps the mm alive until the parent is gone (`PR_SET_PDEATHSIG`), so `exit_group` unmaps nothing | 931 (−14%; exit latency 185→51 µs) | 655 (−14%) | 1304 (−10%) | 894 (−12%) | 352 |
| E | skip the isfchoice `idtree`/`idcands` stamp check (`RSVOL_PROTO_NOSTAMPS`, **cost probe only**: it changes semantics) | −4% (−7% against its own binary; sequential −31 µs) | −9% | −2% | −6% | −161k instructions |
| A+B+2M | combined build, 4K text | 822 (−24%) | 497 (−35%) | 1205 (−17%) | 768 (−24%) | 233 |
| A+B+2M+C | combined, text collapsed | 773 (−28%) | 477 (−37%) | 1162 (−20%) | 729 (−28%) | 217 |
| A+B+2M+D | combined + teardown helper | 742 (−31%) | 474 (−38%) | 1082 (−26%) | 684 (−33%) | 234 |
| **A+B+2M+C+D** | **everything** | **711 (−34%)** | **426 (−44%)** | **1041 (−28%)** | **683 (−33%)** | 218 |

The same combination measured sequentially (warm CPU caches, posix_spawn):

| case | baseline min / med (µs) | combination min / med (µs) |
|---|---|---|
| winps | 939-963 / 1131 | 630-643 / 735-766 (−33%) |
| wininfo | 564-602 / 690-704 | 345-348 / 423-432 (−40%) |
| linps | 1284-1318 | 956-972 (−26%) |

Floors for the other cases (min wall, µs):

| case | F1 | F2 | F2p |
|---|---:|---:|---:|
| wininfo | 156 | 224 | 215 (only 12 distinct image pages) |
| linps | 163 | 504 | 384 (268 distinct image pages + 57 isfb pages touched) |
| macps | 168 | 381 | 239 (91 pages) |

Findings from the prototypes:

- **Non-PIE alone is a trap.** A plain `-C relocation-model=static` build gets `crtbeginT.o`, which calls
  `__register_frame_info`. libgcc (GCC 16) then classifies all FDEs of the 760 KB `.eh_frame` at startup:
  **+940k instructions**, which eats the whole gain (measured: `vol.nopie`, 3.42M instructions).
  - Setting the weak `__register_frame_info` and `__deregister_frame_info` to 0 with `--defsym` skips the
    registration. Unwinding then falls back to `dl_iterate_phdr` / `PT_GNU_EH_FRAME`.
  - `catch_unwind` was verified to still catch a panic in a static non-PIE test program
    (`testdata/scratch/review-startup/ehtest`).
  - The variant removes the 126k-instruction relocation pass and the 48 COW faults
    (`.data.rel.ro`: 190 KB → 17 KB).
- **The first ordering attempt did nothing.** The crate hash in mangled names (`Cs…`) changes with the
  cargo profile environment, and `--no-warn-symbol-ordering` hides the mismatch.
  - The ordering file must be generated from a build with the same profile settings: build, `nm`,
    translate the names, then relink. That is what `order3` and `combo` did.
  - Executed-function extraction also has to include symbols that `nm -S` lists without a size, or 145
    hot functions go missing.
- **THP text has conditions.**
  - It needs `CONFIG_READ_ONLY_THP_FOR_FS=y` (set on this Arch kernel) and `MADV_COLLAPSE` (Linux 6.1+).
  - It needs a clean file: collapsing a freshly copied binary failed with EAGAIN until the file was
    fsync'd.
  - The collapsed page-cache state **is not permanent**. During this review, `vol.thp`'s huge folios were
    lost once under the memory pressure of parallel builds (faults went back from 274 to 350) and had to be
    re-collapsed.
  - The combined build put the hot code at the start of `.text`, which lies in a 1.4 MB head that is not
    2 MB-aligned and so cannot be collapsed. Text faults stayed at 15 there. Starting `.text` on a 2 MB
    boundary would make it ~0.
- **Teardown is the largest single item.** Exit latency measured from inside the process:

  | binary | exit latency min / med (µs) |
  |---|---|
  | baseline | 185-276 / 275-595 |
  | teardown helper | 45-51 / 68-73 |
  | combination without the helper | 109 / 154 |
  | F1 | 18 |

  Back-to-back runs gain less (sequential wininfo: none), because the helper's teardown then competes with
  the next run.

## 7. Ranked opportunities

Gains are for winps unless stated, from the random-interleaved min, and do not add up linearly. "Validated"
means measured on the real binary.

| rank | opportunity | gain | effort | risk | validated |
|---:|---|---|---|---|---|
| 1 | **Hot-text ordering** (`--symbol-ordering-file` from an executed-function trace of the parity corpus; regenerated by a script at release) | −169 µs (−16%); wininfo −23%, linps −12%, macps −15%; text faults 90→13 | 1-2 days (the script, plus a two-pass link step or a profile-stable crate hash) | none for output. A stale list only costs speed. | yes |
| 2 | **Teardown off the critical path** (CLONE_VM helper at exit) | −149 µs (−14%) alone; −62 µs on top of 1+3+4; exit latency −134 µs | 1 day | low-medium: an extra ~0.1-0.3 ms process (raw-syscall child, no TLS). Parent rusage no longer includes teardown CPU. Must stay off for `vol serve`/embedding. Pipes verified (`| wc -c`), no zombies. | yes |
| 3 | **Huge-page text** (2 MB-aligned segments + `MADV_COLLAPSE` of `/proc/self/exe` in the existing detached helper, re-armed when `getrusage` minflt is high) | −170 µs (−16%) alone; −49 µs on top of 1+4 (combo 822→773). Also removes iTLB misses. | 1-2 days | none for output. Kernel/config dependent; state lost under memory pressure; 18 MB of huge pages in the page cache. | yes |
| 4 | **Non-PIE static + no EH-frame registration** | −60 µs (−6%); wininfo −12%, macps −10%; −154k instructions, −45 faults | ½ day | medium. Loses ASLR of the executable image; depends on `crtbeginT.o` + libgcc behaviour (`--defsym` hack). Needs the full test suite, including the panic paths at `cli/mod.rs:895` and the codecs. | yes |
| 5 | **Read image pages with `pread` into a page arena** instead of faulting the 5 GiB mapping, for non-scan access. Keep the mmap for scans. | from floors F2→F2p: −193 µs (−18%) winps, −120 µs linps, −142 µs macps; about −110 µs once 2 is in | 3-5 days (raw-pointer paths in `intel.rs`, `segmented.rs`, `elf.rs`, `qemu.rs`, `slice()`) | medium: read semantics, padding and errors must stay identical; the arena grows with touched pages | floor only |
| 6 | **Cache formats and CLI trims**: binary instead of hex in the automagic/isfchoice caches (−136k to −170k instructions); compile-time sorted plugin table (−52k); TableCache sized for small runs or lazily grown (−22 anon faults); a smaller heap output buffer instead of the 268 KB mmap/munmap; drop duplicate `statx`/`readlink`s and the `getrandom` HashMap seed | ~−40 to −60 µs (4-6%) | 1-2 days | low | partially (instructions and faults counted; NOSTAMPS probe) |
| 7 | **Member-lookup cost in trivial plugins**: `SymbolTable::member` is 464k (winps) / 944k (linps) instructions. Resolve `Field`s once per type in pslist and the `Obj::m` paths, or memoise (type, name). | ~−20 to −40 µs | 1-2 days | low | no (instruction profile only) |
| 8 | glibc startup: tunables scan (75k instructions at 217 env vars) and 28 CPUID. On a KVM guest every CPUID exits to the hypervisor, likely ~30-60 µs of the VM's 3.3 ms. Avoidable only with a custom `_start` or another libc. | 5-15 µs locally, more on the VM | large | high | no |

## 8. Recommended plan

1. **Hot-text ordering (rank 1).**
   - Add `bench/scripts/gen_order.sh`. It runs the release binary under `sstep` or a coverage-free tracer
     over the no-arg reference corpus: the four cases here plus one run per plugin family is enough.
   - Emit the executed-function list, with sizeless symbols included and names taken from the build being
     linked.
   - Pass it through `.cargo/config.toml` rustflags. Expect about −15% on every warm run.
2. **Teardown helper (rank 2).** Only in the CLI `main` path, after the final flush and `finish_deferred`;
   never in tests or `vol serve`. Keep the raw-syscall child: no TLS, no allocation.
3. **Huge-page text (rank 3), behind feature detection.**
   - Link with `-z max-page-size=0x200000`, and align `.text` to 2 MB so the hot head can be collapsed.
   - From the detached helper, `MADV_COLLAPSE` the executable's read-only segments when a marker keyed by
     (dev, inode, mtime, boot id) is missing, or when the run's minflt shows the collapse was lost.
   - Collapse the isfb blobs the same way: 15-57 faults per run.
4. **Small trims (rank 6).** Cheap and safe.
5. **Measure rank 4 on the benchmark VM before adopting it.** The gain is modest, and giving up ASLR on a
   parser of untrusted images is a real trade-off. If adopted, do it together with ordering, which was built
   and verified that way (`combo`).
6. **`pread` arena (rank 5).** Only if the remaining ~1.6x of the mmap floor still matters. It is the
   largest remaining kernel-side item, but it is a data-path redesign.

Expected result of steps 1-4: winps about 1080 → 690-720 µs (min), wininfo 762 → ~420 µs, linps
1454 → ~1040 µs, macps 1014 → ~680 µs on this box. The combined prototype measured 711 / 426 / 1041 / 683 µs.

The benchmark VM (3.3 ms warm pslist) was not measured. Page faults, TLB work and CPUID are relatively more
expensive in a KVM guest, so the kernel-side items (1-3) should give at least the same relative gain there;
~2.2 ms is a reasonable expectation, unverified.

After steps 1-4, winps would sit at ~1.6x the mmap floor. The remainder is:

- ~2.2M user instructions: 1.64M of plugin and rendering work, ~0.6M of fixed CLI and cache overhead;
- 118 image faults, which rank 5 removes;
- ~45 anon faults and ~100 syscalls.

## 9. Correctness risks, summarised

- **Ordering, THP.** Link layout and page-cache state only. No output can change.
- **Teardown helper.**
  - rsvol must not write anything after the helper starts; all fds are closed first.
  - The helper shares the address space but touches only its own static stack and registers.
  - It dies through `PR_SET_PDEATHSIG`, with a `getppid` re-check for the race. It is reparented and
    reaped (`exit_signal` becomes SIGCHLD on reparent).
  - Risk is in portability of the raw clone (x86_64 only as written) and in tools that account child
    CPU time.
- **Non-PIE + `--defsym`.** Unwinding correctness depends on libgcc's `PT_GNU_EH_FRAME` fallback, and the
  executable loses ASLR. The 535 unit tests and the parity gates must pass with the new flags before this
  is adopted.
- **`pread` arena.** Every raw pointer path needs an equivalent read, and the parity gates must run with a
  cold and a warm cache.
- **NOSTAMPS** is not a recommendation. The stamp check keeps python-identical ISF choice when symbol
  directories change. Only its hex decoding (rank 6) is overhead.

## 10. Reproduce

Everything is in `/home/user/rs-vol/testdata/scratch/review-startup/`:

- `tools/final.sh CASE N`: the random-interleaved table.
- `tools/summ.py final.all2.txt`: the summary.
- `tools/runbench`: the sequential runs.
- `bins/`: all variants.
- `floor/*.rs`: generated floors (`tools/genfloor.py`, from `pf/*.txt` and `touch.*.txt`).
- `proto.patch`: the runtime knobs.
- `tools/combo_build.sh`: the combined build (two passes: build, translate `order.*.txt` to the build's
  crate hash, touch, rebuild).
- Raw data: `final.all2.txt`, `seq.txt`, `ss.*.txt` (instruction traces), `prof*.winps.txt`, `pf/`,
  `strace.*`.
