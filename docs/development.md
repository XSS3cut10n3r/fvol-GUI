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
   hidden requirements, such as the kernel module, are not declared.

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
`OK~`.

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

To make new references, use `bench/scripts/py_refs.sh` for the Windows image,
`py_refs_linux.sh` and `py_refs_mac.sh` with `IMG` and `NAME` set for the others, and
`py_args_refs.sh` for the argument cases in `bench/args_cases.txt`.

## Measure performance

For quick measurements during development:

| Question                                      | Command                                                   |
| --------------------------------------------- | --------------------------------------------------------- |
| Faster than vol-rs on every plugin?           | `OURS=<BIN> bench/scripts/bench_vs_volrs.sh [-n <RUNS>] [<LIST>]` |
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
