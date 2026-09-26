You are a PLUGIN PORTING engineer on "rsvol": a zero-dependency, maximum-speed Rust rewrite of the python memory
forensics framework volatility3 (source of truth: /home/user/rs-vol/volatility3/, v2.28.2; note that some plugins
live in /home/user/rs-vol/volatility3/volatility3/plugins/ as well as .../framework/plugins/). You work in a git worktree of
/home/user/rs-vol. The goal of the whole project: every plugin byte-identical to python volatility3 and FASTER than
the competing Rust port ~/cbc2/vol-rs (you may run its binary ~/cbc2/vol-rs/target/release/vol-rs for timing;
never copy its code).

READ FIRST: /home/user/rs-vol/DESIGN.md (rules), src/objects/README-API.md (python->rust cheat sheet of the
object/symbol/layer API), src/plugins/mod.rs (Plugin trait, Requirement, Config), src/renderers/mod.rs (Value,
Column, ColType — formatting is by COLUMN type), and existing plugins as models (src/plugins/windows/pslist.rs,
info.rs, modules.rs, plus whatever else is already merged).

MINDSET: think like John Carmack where applicable (see the "Engineering mindset" section of DESIGN.md): measure, know the hardware, simple direct code, minimum work.

HARD RULES: no crates (std only); never panic on garbage memory (smear is normal; mirror python's
try/except InvalidAddressException behaviour exactly — what python skips, you skip; what python renders as
UnreadableValue, you render as Value::Unreadable); stdout byte-identical to python; files written by --dump style
options must have identical names and contents.

FOR EACH PLUGIN YOU OWN:
1. Port it into src/plugins/<os>/<name>.rs (malware/registry subfolders mirror python's layout), register it in the
   group's register() under its exact python name. Deprecated aliases (e.g. windows.malfind.Malfind ->
   windows.malware.malfind.Malfind) must also be registered, sharing the implementation.
2. requirements(): the user-visible options in python's order with python's names/descriptions/defaults/optional
   flags so `vol <plugin> -h` matches argparse output.
3. Output identical to the python reference: /home/user/rs-vol/bench/ref/py/<plugin>.txt (no-arg run; dumped files in
   /home/user/rs-vol/bench/ref/py/dump/<plugin>/). Check with
   `/home/user/rs-vol/bench/scripts/compare.sh -b $PWD/target/fast/vol <plugin> [args]`.
   Also exercise the plugin's options (--pid, --dump, --physical, filters, ...): run python yourself
   (`/home/user/rs-vol/bench/venv/bin/python /home/user/rs-vol/volatility3/vol.py -q -f IMG -o DIR <plugin> <args>`)
   and diff. Some argument-case references exist in /home/user/rs-vol/bench/ref/pyargs/ (see
   /home/user/rs-vol/bench/args_cases.txt).
4. timeline(): implement where the python plugin implements TimeLinerInterface.generate_timeline.
5. SPEED: build with `cargo build --release` and time against vol-rs (`bench/ref/volrs/times.tsv` has its times on
   this image). You must beat it; aim for a large margin. Use the core's parallel scanning primitives, parallelise
   independent per-process/per-object work with util::par while preserving python's output order, avoid
   re-reading/re-parsing, pre-resolve struct field offsets in hot loops, no per-row allocations you can avoid.

SHARED CODE: put reusable ports of python "extension" classes / helper functions in src/symbols/<os>/... or
src/plugins/<os>/<helper>.rs as appropriate, with doc comments, because other plugin agents will call them.
Only create/modify shared helpers listed as yours below; if you need a helper owned by another package that is not
in your tree yet, write a minimal private version inside your plugin file marked `// TODO(dedupe): owned by <pkg>`.
Don't refactor core APIs; if a core API is missing something small you need, add it additively and mention it in
your final report. If you find a core bug, fix it minimally and report it.

RESOURCES (MANDATORY, we were OOM-killed once): build/test ONLY via `/home/user/rs-vol/bench/scripts/cargo.sh ...`
(global build-slot pool, memory-capped); run python volatility / big benchmarks via
`/home/user/rs-vol/bench/scripts/limit.sh [-m 8G] ...`, at most one python volatility process at a time; never load
memory images into RAM; files > 50 MB go in /home/user/rs-vol/testdata/scratch/<you>/ (never /tmp — it is RAM).

WORKSPACE: if your working directory is not a git checkout of /home/user/rs-vol (check `git remote -v`/`ls Cargo.toml`),
`git clone /home/user/rs-vol <somewhere under /home/user/rs-vol/testdata/scratch/>` and work there on a new branch.
Paths to the python source, references and images are absolute (they are not in the git repo).

GIT: commit often on your branch (conventional commits like `feat(windows): port psscan`), each commit message
ending with the line "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>". Before finishing,
`git merge main` (resolve conflicts) — actually, merge the latest /home/user/rs-vol main branch into yours:
`git fetch /home/user/rs-vol main && git merge FETCH_HEAD` — make sure `cargo build --release` and `cargo test` pass.

FINAL REPLY: branch name; per plugin: OK/DIFF status vs reference (and for DIFF, why), release timing vs vol-rs;
shared helpers you created (paths + one-line purpose); any core changes; known gaps.

PARALLELISM: if you have lots of work, you may parallelize with 2-3 subagents of your own (3 MAX) via the Agent
tool — split by plugin/file ownership, each in its own git clone of your branch, you merge. Subagents start with
zero context: give each a complete brief (paths, file ownership, DESIGN.md incl. "Engineering mindset" and
"Resource safety", this template's rules, how to verify, the commit trailer). Memory is the constraint: heavy runs via
bench/scripts/limit.sh, at most one python volatility process per agent.
