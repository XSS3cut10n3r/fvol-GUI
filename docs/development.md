# Developing rsvol

How-to guides for contributors: porting a plugin, proving it matches python, measuring it, and
working without exhausting the machine. The rules behind these steps are in
[DESIGN.md](../DESIGN.md), which is the contract every change must follow.

Applies to rsvol 0.1.0 and volatility3 2.28.2.

## Read first

| File                                                               | What it gives you                                        |
| ------------------------------------------------------------------ | -------------------------------------------------------- |
| [DESIGN.md](../DESIGN.md)                                          | Hard rules, module ownership, resource safety            |
| [src/objects/README-API.md](../src/objects/README-API.md)          | python to Rust cheat-sheet for layers, objects, symbols, scanning and plugin helpers |
| [bench/PLUGIN_AGENT_TEMPLATE.md](../bench/PLUGIN_AGENT_TEMPLATE.md) | The brief given to plugin porters, with the full checklist |
| `src/plugins/mod.rs`                                               | The `Plugin` trait, `Requirement`, `Config`, the registry |
| `src/renderers/mod.rs`                                             | `Column`, `ColType`, `Value`, `RowSink`                  |
| `src/plugins/windows/pslist.rs`, `kpcrs.rs`                        | Small, complete plugins to copy from                     |

## Set up the test environment

The scripts in `bench/scripts/` use absolute paths. They expect:

| Path                                             | Content                                                     |
| ------------------------------------------------ | ----------------------------------------------------------- |
| `/home/user/rs-vol`                               | The main checkout. Worktrees and clones work too; the scripts still read references and python from here. |
| `/home/user/rs-vol/volatility3/`                  | A checkout of python volatility3 2.28.2, not tracked by git |
| `/home/user/rs-vol/bench/venv/`                   | CPython 3.14 with capstone, yara-python, pycryptodome and pefile |
| `/home/user/rs-vol/bench/ref/`                    | Reference outputs: `py/` and `pyargs/` for the main Windows image, `win1809/`, `linux/<image>/`, `mac/<image>/` |
| `/home/user/rs-vol/testdata/`                     | Test images and ISF files, described in `testdata/README.md` |
| `/home/user/cbc2/task2/memory-dirty.raw`          | The main Windows test image, x64 build 22000, 5 GiB          |

`bench/ref/` and `testdata/` are not in git. The python version matters: references were made
with CPython 3.14.7, and CPython 3.13 prints some values differently.

## Follow the resource-safety rules

The machine is shared by many agents and services, and systemd-oomd kills the entire terminal
session, not only the process that used the memory. These rules are mandatory:

- Build and test only through `bench/scripts/cargo.sh`. It allows at most 5 cargo runs on the
  machine, each capped at 6 GiB, and `.cargo/config.toml` limits each build to 6 jobs.
- Run anything heavy through `bench/scripts/limit.sh [-m <MEM>] <COMMAND>`: python volatility3,
  benchmarks, and tests or tools that touch the multi-GB images. It starts the command in its own
  systemd scope with a hard memory cap, 8G by default, and allows 4 such jobs at a time.
- Run at most one python volatility3 process per agent. The reference generators in
  `bench/scripts/py_refs*.sh` and `py_args_refs.sh` run 2 in parallel by default, bounded by
  `limit.sh`; set `PAR=1` when other agents are working, or a higher `PAR` on an idle machine.
- Never read a memory image into a `Vec`. Map it or read ranges.
- `/tmp` is in RAM. Put anything over about 50 MB in `/home/user/rs-vol/testdata/scratch/`.

## Build and test

```bash
bench/scripts/cargo.sh build --profile fast       # target/fast/vol, for iterating
bench/scripts/cargo.sh build --release            # target/release/vol, for timing
bench/scripts/cargo.sh test --profile fast        # all unit tests
bench/scripts/cargo.sh test --profile fast pslist # tests whose name contains "pslist"
```

Unit tests must stay fast. Tests that need a large image or a reference library are marked
`#[ignore]` and read their inputs from environment variables named in their doc comments, such
as `RSVOL_BENCH_IMG`. Run one with
`bench/scripts/cargo.sh test --profile fast <NAME> -- --ignored`.

## Port a plugin

1. **Read the python plugin** in `/home/user/rs-vol/volatility3/volatility3/framework/plugins/`,
   and the extension classes and helpers it calls. Some plugins also live in
   `volatility3/volatility3/plugins/`.

2. **Create the file** under `src/plugins/<os>/`, mirroring python's layout, for example
   `src/plugins/windows/malware/` or `src/plugins/linux/tracing/`. Start it with the derivation
   header that every ported file carries:

   ```rust
   //! windows.kpcrs.KPCRs (python `plugins/windows/kpcrs.py`): the `_KPCR` of every processor.
   //!
   //! Derived from Volatility 3 (Volatility Software License 1.0).
   ```

3. **Implement `Plugin`.** The name is python's full dotted name, the description is the first
   paragraph of the class docstring, and `requirements()` lists only the command-line options,
   in python's order, with python's names, help texts and defaults:

   ```rust
   pub struct PsList;

   impl Plugin for PsList {
       fn name(&self) -> &'static str {
           "windows.pslist.PsList"
       }
       fn description(&self) -> &'static str {
           "Lists the processes present in a particular windows memory image."
       }
       fn requirements(&self) -> Vec<Requirement> {
           vec![
               Requirement::flag("physical", "Display physical offsets instead of virtual"),
               Requirement::new("pid", "Process ID to include (all other processes are excluded)", ReqKind::ListInt).optional(),
               Requirement::flag("dump", "Extract listed processes"),
           ]
       }
       fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
           let k = ctx.windows_kernel()?;
           out.begin(vec![Column::new("PID", ColType::Int) /* ... */])?;
           // ...
           Ok(())
       }
   }
   ```

   Kernel, layers and symbol tables come from the `Context` when you ask for them; python's
   hidden requirements, such as the kernel module, are not declared. python's complete
   requirement lists, hidden ones included, are data in `src/plugins/pyreqs.tsv`, from which
   `--save-config` and `timeliner --record-config` write python's configuration. Regenerate it
   when python gains a plugin; unit tests check that every registered plugin is in it and that
   the options you declare have python's kinds and defaults:

   ```bash
   bench/scripts/limit.sh -m 4G bench/venv/bin/python bench/scripts/py_plugin_reqs.py > src/plugins/pyreqs.tsv
   ```

4. **Register it** with one line in the group's `register()` in `src/plugins/<os>/mod.rs`, and a
   `pub mod` line. A deprecated python alias, such as `windows.malfind.Malfind` for
   `windows.malware.malfind.Malfind`, is registered too and shares the implementation.

5. **Port the behaviour, including failures.** Where python catches `InvalidAddressException`
   and skips, skip; where it renders `UnreadableValue`, emit `Value::Unreadable`; where python
   would raise, return the error after the rows python printed. Never panic on garbage memory.
   The API cheat-sheet shows the Rust form of each python idiom.

6. **Write files like python.** Get output files from `ctx.create_output_file(name)`, which
   applies python's naming, de-duplication and permissions.

7. **Add `timeline()`** if the python class implements `TimeLinerInterface`.

8. **Make it fast.** Use the scanning primitives and `util::par` helpers, which keep python's
   order, resolve struct members once with `Field` in hot loops, and avoid per-row allocations.
   A two-phase scanner can join the scan cache by implementing `cache_query()`; see the scan
   cache section of the API cheat-sheet for what that description must guarantee.

Put helpers that other plugins will need in `src/symbols/<os>/` or in a helper module next to the
plugin, with doc comments, and add them to `src/objects/README-API.md`.

## Check a plugin against python

Compare one plugin on the main Windows image with its reference:

```bash
bench/scripts/compare.sh -b $PWD/target/fast/vol windows.pslist.PsList
```

```text
OK windows.pslist.PsList 3ms
```

On a difference it prints `DIFF`, the paths of both outputs and the first lines of the diff.
Arguments after the plugin name are passed through:

```bash
bench/scripts/compare.sh -b $PWD/target/fast/vol windows.pslist.PsList --pid 4
```

The stored references were made without arguments, so for options, run python yourself and diff
the outputs:

```bash
bench/scripts/limit.sh -m 8G bench/venv/bin/python volatility3/vol.py \
  -q -f <IMAGE> -o <DIR> windows.pslist.PsList --pid 4 --dump > py.txt
target/fast/vol -q -f <IMAGE> -o <DIR2> windows.pslist.PsList --pid 4 --dump > rs.txt
cmp py.txt rs.txt && diff -r <DIR> <DIR2>
```

To compare on another image, set `IMG` and `REF`, and pass symbol directories in `GLOBAL_ARGS`:

```bash
IMG=/home/user/rs-vol/testdata/images/linux/rsvol-noble-6.8.0-139.elf \
REF=/home/user/rs-vol/bench/ref/linux/rsvol-noble-6.8.0-139-elf/linux.pslist.PsList.txt \
GLOBAL_ARGS="-s /home/user/rs-vol/testdata/symbols" \
bench/scripts/compare.sh -b $PWD/target/fast/vol linux.pslist.PsList
```

Plugins whose python output order is random from run to run are listed in
`bench/nondeterministic.txt`; `compare.sh` accepts them when the sorted outputs match and prints
`OK~`. The `Symbols` line of `windows.info.Info` names the kernel ISF python's identifier cache
lists last, which depends on the cache's history when the same ISF is in several symbol
directories; when only that line differs from the reference, `compare.sh` checks it against a
live python run (`NO_LIVE_SYMBOLS=1` turns that off).

To check `--save-config` for many plugins at once, `bench/scripts/py_save_configs.py` runs
python's command line for each case of a list (one plugin and its options per line) and stops
each plugin right after python wrote the configuration, so only kernel discovery is paid for.
Compare its `<case>.json` files with rsvol's `--save-config` output for the same cases.

## Run the parity gates

Before a merge, run every reference with a private cache, first cold and then warm:

```bash
bench/scripts/gates.sh $PWD/target/release/vol
```

```text
windows cold: == OK=98 DIFF=0 MISSING=0
windows warm: == OK=98 DIFF=0 MISSING=0
nix cold: == TOTAL OK=275 DIFF=0 MISSING=0
nix warm: == TOTAL OK=275 DIFF=0 MISSING=0
```

`gates.sh` runs `check_all.sh`, the 98 no-argument plugins on the main Windows image, and
`check_nix.sh`, the no-argument plugins on the four Linux images and the macOS image. Outputs and
the cache go to `testdata/scratch/gates/` unless you pass another directory as the second
argument. Each script also runs on its own:

```bash
bench/scripts/check_all.sh -b $PWD/target/release/vol
bench/scripts/check_nix.sh -b $PWD/target/release/vol linux
```

The Windows 10 1809 image is not part of `gates.sh`. Check it with a loop over the same plugin
list:

```bash
while read -r p; do
  IMG=/home/user/rs-vol/testdata/images/windows/rsvol-win10-x64-17763-imagery.raw \
  REF=/home/user/rs-vol/bench/ref/win1809/$p.txt \
  OUTDIR=/home/user/rs-vol/testdata/scratch/out1809 \
  bench/scripts/compare.sh -b $PWD/target/release/vol "$p"
done < bench/win_noarg.txt
```

Other checks:

| Area                         | Command                                                     |
| ---------------------------- | ----------------------------------------------------------- |
| Web UI against the CLI       | `bench/web/e2e.sh`                                          |
| CLI fixtures from python     | `bench/venv/bin/python bench/scripts/cli_fixtures.py`, then `cargo.sh test --profile fast cli` |
| Renderer fixtures from python | `bench/venv/bin/python bench/scripts/render_fixtures.py`, then `cargo.sh test --profile fast render` |
| YARA engine vs yara-python   | `bench/scripts/limit.sh -m 4G bench/venv/bin/python bench/scripts/yara_diff.py` |
| Disassembler vs capstone     | `bench/scripts/disasm_diff.py gen` once, then `bench/scripts/disasm_check_all.sh` |
| Options x renderers sweep    | `bench/venv/bin/python bench/scripts/sweep.py gen`, then `sweep.py py` (python, cached), `sweep.py rs -b <BIN>` and `sweep.py report -v` |

To make new references, use `bench/scripts/py_refs.sh` for the Windows image,
`py_refs_linux.sh` and `py_refs_mac.sh` with `IMG` and `NAME` set for the others, and
`py_args_refs.sh` for the argument cases in `bench/args_cases.txt`.

## Fuzz the plugins for robustness

DESIGN.md rule 4 is that no plugin may panic, hang, exhaust memory or run away on a malformed
image; it must degrade the way python does (skip the bad object, render `UnreadableValue`, or, where
python itself raises an uncaught exception, mirror python's exit code and partial output). The fuzz
driver `bench/scripts/fuzz_images.py` (standard-library python, helper modules `fuzz_geom.py`,
`fuzz_targets.py`, `fuzz_mutate.py`, `fuzz_cmds.py`) proves and enforces this.

It builds corrupted copies of the real test images *without copying them*: `cp --reflink=auto`
shares every extent with the base on btrfs, then targeted in-place writes, hole punches and
truncation cost only the changed blocks (about 10 MB per mutant of a 2 GB image). It corrupts the
structures that matter — page-table entries, kernel objects (`_EPROCESS`/`task_struct`/hives/
drivers/files/...) and their linked-list pointers (made cyclic), kernel symbols, container headers
(ELF/LiME/crash/...), plus generic damage (zeroed/garbage pages, huge counts, truncation) — locating
them by parsing the image geometry, walking the page tables and reading the ISF. It then runs every
plugin of the image's OS on each mutant through `limit.sh` (memory cap `-m`, default 4G) with a
per-run timeout of `max(--min-timeout, --mult × the clean run time)`, and classifies each run:

| Class     | Meaning                                                       | Bug? |
| --------- | ------------------------------------------------------------- | ---- |
| `OK`      | exit 0                                                        | no   |
| `ERROR`   | other clean exit (a python-style error/traceback)            | no   |
| `PYRAISE` | a `panic!` whose message names a python exception — rsvol's intended emulation of python's uncaught `raise`; the CLI catches it and exits 1 exactly as python does (stderr text does not affect parity) | no   |
| `PANIC`   | a Rust-internal panic (index/unwrap/overflow/slice/unreachable/stack overflow) | **yes** |
| `HANG`    | killed by the per-run timeout                                 | **yes** |
| `OOM`     | killed by the memory cgroup cap                               | **yes** |
| `SIGNAL`  | died by another signal                                        | **yes** |
| `RUNAWAY` | stdout exceeded the output cap                                | **yes** |

Distinguishing `PYRAISE` from `PANIC` matters: rsvol deliberately emulates python's uncaught
exceptions by panicking with the exception's message, so `panicked at` in stderr is not by itself a
bug. Only a Rust-internal fault (which means the plugin diverged from python instead of skipping the
object) or a hang/OOM/signal/runaway is a bug.

Workflow (all scratch lives on disk under `testdata/scratch/fuzz/`, never `/tmp`, and clean mutants
are deleted immediately — only mutants that produced a bug are kept, with a `.mutlog.json` that
reproduces them):

```bash
# 0. a release binary the driver will use (default: testdata/scratch/fuzz/bin/vol-base)
cp target/release/vol testdata/scratch/fuzz/bin/vol-base

# 1. find structures to corrupt in a clean image (runs a few clean plugins, walks page tables)
bench/scripts/fuzz_images.py targets win1809      # -> testdata/scratch/fuzz/targets/win1809.json

# 2. record clean-image times + output hashes (used for per-run timeouts)
bench/scripts/fuzz_images.py baseline win1809     # -> testdata/scratch/fuzz/baseline/win1809.json

# 3. campaign: N mutants x every plugin case; keeps only mutants that produced a bug
bench/scripts/fuzz_images.py campaign win1809 --mutants 30 --par 2 --mem 4G

# 4. summarise, and reproduce/inspect one kept mutant
bench/scripts/fuzz_images.py report testdata/scratch/fuzz/results/win1809.jsonl
bench/scripts/fuzz_images.py rerun testdata/scratch/fuzz/kept/win1809-s7.img.mutlog.json --keep

# 5. confirm we degrade the SAME way as python on a sample (python via limit.sh, <=2 at a time)
bench/scripts/fuzz_images.py pycompare testdata/scratch/fuzz/results/win1809.jsonl --limit 20

# 6. the small synthetic container fixtures (tests/fixtures/containers)
bench/scripts/fuzz_images.py containers
```

Base image names for `targets`/`baseline`/`campaign`: `win10` (the 5 GiB main Windows image),
`win1809`, `noble-elf`, `noble-lime`, `jammy-elf`, `jammy-lime`, `mac`. Bugs found by a campaign are
reduced to small crafted-input unit tests next to the code they fix, so they never regress. Two the
driver has found so far, both cases where python's own lazy enumeration would run forever on the
corrupted count, so rsvol bounds it and stops instead of hanging/OOMing:

- a corrupted `kallsyms_num_syms` made `linux.kallsyms.Kallsyms` loop up to ~1.8 billion times
  (python does the same unbounded `range(num_syms)`); guarded in `src/symbols/linux/kallsyms.rs`
  (`MAX_PLAUSIBLE_SYMS`), test `tests_robustness::huge_num_syms_does_not_hang`.
- corrupted page tables (a garbage page read as a page table) made the translation walk enumerate a
  practically unbounded mapped space, which every scanning plugin and `windows.memmap` collected into
  memory and OOMed on (python streams it lazily and hangs instead); bounded in `src/layers/scan.rs`
  (`MAX_SCAN_CHUNKS`, the chunk list) and `src/layers/intel.rs` (`MAX_MAPPING_RUNS`, one
  `mapping_with_targets` call), test `scan::tests::scan_chunk_list_is_bounded_on_corrupt_layer`.

Run the driver through `limit.sh` yourself only when you invoke a subcommand that does not already
wrap its own image work — the campaign, baseline and pycompare all wrap every image run internally.

## Measure performance

For quick measurements during development:

| Question                                      | Command                                                   |
| --------------------------------------------- | --------------------------------------------------------- |
| Faster than vol-rs on every plugin?           | `bench/scripts/bench_vs_volrs.sh [-b <BIN>] [-n <RUNS>] [<LIST>]` |
| Cold and warm start                           | `bench/scripts/coldbench.py`                              |
| Fixed cost of a CLI invocation                | `bench/scripts/cli_startup.sh <BIN> [<N>]`                |
| Library throughput vs the C references        | `bench/scripts/refbench.sh`                               |
| Where the time goes in one run                | `RSVOL_TRACE=1 target/release/vol ...`                    |

Use `RSVOL_CACHE=<EMPTY_DIR>` to measure a cold run without touching your own cache. Always
time release builds, through `limit.sh`, and keep the numbers before and after each
optimization.

The published numbers come from a separate quiet machine. [bench/vm/method.md](../bench/vm/method.md)
describes the procedure and `bench/vm/scripts/` holds the scripts. After a new run, regenerate
the report and then copy the summary figures into the README:

```bash
cd bench/vm && python3 scripts/report.py raw .
```

## Commit and merge

- Work on your own branch or worktree and commit often, with conventional commit messages such
  as `feat(windows): port psscan`.
- Change only the files you own, plus one-line registrations.
- Keep `[dependencies]` in `Cargo.toml` empty.
- Before handing over, merge the latest main and make sure the release build, the unit tests and
  the parity gates pass:

  ```bash
  git fetch /home/user/rs-vol main && git merge FETCH_HEAD
  bench/scripts/cargo.sh build --release
  bench/scripts/cargo.sh test --profile fast
  bench/scripts/gates.sh $PWD/target/release/vol
  ```
