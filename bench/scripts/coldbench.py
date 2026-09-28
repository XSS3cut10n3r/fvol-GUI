#!/usr/bin/env python3
"""Cold / warm start benchmark: fastvol (private FASTVOL_CACHE) vs vol-rs (private HOME).

Usage: coldbench.py [-n N] [--bin BIN] [--base BIN] [--no-volrs] [--only NAME[,NAME]] [--scratch DIR]
                    [--py-cache DIR] [--fastvol-args "ARGS"] [--fastvol-env K=V[,K=V]]

--py-cache DIR: python's cache directory the fastvol runs read (`--cache-path DIR`: its
identifier.cache seeds fastvol's identifier index, see below). --fastvol-args / --fastvol-env (old names --rsvol-args / --rsvol-env): extra
global options / environment for the fastvol runs only (e.g. `--fastvol-env
FASTVOL_NO_PY_IDENT_SEED=1`: fastvol's own identifier index).

Cases per (image, plugin), for each fastvol binary (--base: a baseline build, measured
interleaved with --bin so machine load affects both alike):
  cold     empty fastvol cache (first time the image AND the symbol files are seen)
  newimg   symbol caches warm (ISF blobs + identifier index), automagic/scan caches empty
  isfnew   newimg + no ISF blobs: a new image whose kernel ISF was indexed but never loaded
  symcold  automagic caches warm, symbol caches (ISF blobs + identifier index + ISF choices) empty
  warm     everything cached
vol-rs is measured with HOME=<scratch>/volrs-home (its symbol store copied there, caches empty
for cold). Wall time, best of N (default 5). Timing only: outputs go to /dev/null.

The cold and symcold numbers depend on python's identifier cache (python's
`~/.cache/volatility3/identifier.cache`, or the one in --py-cache), which fastvol replays instead
of reading every symbol file:
  regime A: python's cache has a row for every ISF on the search path (python ran with the same
            -s dirs since they last changed): the index costs 1-4 ms; cold = decode + index of
            the one kernel ISF (e.g. noble 6.8 ~65 ms, mac ~30 ms);
  regime B: it lacks rows for the ISFs of -s testdata/symbols (e.g. python never ran with that
            dir, or the dir grew since): fastvol reads every ISF python would read (179 files,
            ~7 s of CPU, 0.5-0.9 s wall) exactly like python's update, so cold is 10-30x slower.
Which regime a machine is in changes over time (python rewrites its cache whenever it runs), so
compare binaries interleaved in one invocation, and pin python's cache with --py-cache: build a
regime-A one once with `bench/venv/bin/python volatility3/vol.py --cache-path DIR -s
testdata/symbols -f testdata/scratch/review-symbols/zero.img linux.pslist` (it fails, after the
update: about 1 minute), or copy one (testdata/scratch/review-symbols/pycache-full). Which of two sibling files
(`x.json` / `x.json.xz`) python's cache lists last also decides whether the cold kernel ISF load
maps a plain file or decodes an xz (noble: ~30 vs ~65 ms).
"""
import os, shutil, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
args = sys.argv[1:]
def opt(name, default=None):
    if name in args:
        return args[args.index(name) + 1]
    return default
N = int(opt("-n", "5"))
BIN = opt("--bin", os.path.join(ROOT, "target/release/fvol"))
BASE = opt("--base")
SCRATCH = opt("--scratch", os.path.join(ROOT, "testdata/scratch/coldstart"))
ONLY = opt("--only")
FASTVOL_ARGS = (opt("--fastvol-args") or opt("--rsvol-args") or "").split()
if opt("--py-cache"):
    FASTVOL_ARGS = ["--cache-path", os.path.abspath(opt("--py-cache"))] + FASTVOL_ARGS
FASTVOL_ENV = dict(kv.split("=", 1) for kv in (opt("--fastvol-env") or opt("--rsvol-env") or "").split(",") if kv)
VOLRS = os.path.expanduser("~/cbc2/vol-rs/target/release/vol-rs")
SYMS = "/home/user/fvol/testdata/symbols"
T = "/home/user/fvol/testdata/images"
CASES = [
    ("win-main pslist", "/home/user/cbc2/task2/memory-dirty.raw", "windows.pslist", []),
    ("win-main info", "/home/user/cbc2/task2/memory-dirty.raw", "windows.info", []),
    ("win-1809 pslist", f"{T}/windows/rsvol-win10-x64-17763-imagery.raw", "windows.pslist", []),
    ("win-1809 info", f"{T}/windows/rsvol-win10-x64-17763-imagery.raw", "windows.info", []),
    ("noble pslist", f"{T}/linux/rsvol-noble-6.8.0-139.elf", "linux.pslist", ["-s", SYMS]),
    ("jammy pslist", f"{T}/linux/rsvol-jammy-5.15.0-191.elf", "linux.pslist", ["-s", SYMS]),
    ("mac pslist", f"{T}/mac/rsvol-mac-mavericks-10.9.2-13C64.dmp", "mac.pslist", ["-s", SYMS]),
]
if ONLY:
    keep = ONLY.split(",")
    CASES = [c for c in CASES if any(k in c[0] for k in keep)]

os.makedirs(SCRATCH, exist_ok=True)
VHOME = os.path.join(SCRATCH, "volrs-home")

def own_helpers(cache):
    """fastvol's detached helpers (`fastvol-isfb-helper`: symbol-table blobs, converted PDB tables)
    started by runs with this FASTVOL_CACHE (other users' helpers are not waited for)"""
    pids = subprocess.run(["pgrep", "-f", "^(fastvol|rsvol)-isfb-helper"], capture_output=True, text=True).stdout.split()
    n = 0
    for pid in pids:
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                n += f"FASTVOL_CACHE={cache}".encode() in f.read().split(b"\0")
        except OSError:
            pass
    return n

def wait_helpers(cache):
    """wait for this bench's helpers so they neither overlap the next timed run nor race its
    cache deletion"""
    for _ in range(6000):
        if cache is None or not own_helpers(cache):
            return
        time.sleep(0.005)

def run(cmd, env):
    t = time.perf_counter()
    r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    d = time.perf_counter() - t
    wait_helpers(env.get("FASTVOL_CACHE"))
    return d, r.returncode

def rm(cache, *names):
    def f():
        for n in names:
            p = os.path.join(cache, n)
            if os.path.isdir(p):
                shutil.rmtree(p)
            elif os.path.exists(p):
                os.remove(p)
    return f

# (isfchoice: the Windows ISF choices, which spare warm runs the identifier index; a cold run
# must not find them)
MODES = [
    ("cold", ("automagic", "scan", "isf", "identifiers.cache", "isfinfo.cache", "remote", "isfchoice")),
    ("newimg", ("automagic", "scan")),
    ("isfnew", ("automagic", "scan", "isf")),
    ("symcold", ("isf", "identifiers.cache", "isfchoice")),
    ("warm", ()),
]

def fastvol_all(binary, cache, img, plugin, extra):
    """best time per mode over N rounds of cold, newimg, symcold, warm (each mode starts from
    the caches the previous run left)"""
    # both names: the --base binary may predate the rename (RSVOL_* only)
    env = dict(os.environ, FASTVOL_CACHE=cache, RSVOL_CACHE=cache, **FASTVOL_ENV)
    env.pop("FASTVOL_TRACE", None)
    env.pop("RSVOL_TRACE", None)
    best = {m: 1e9 for m, _ in MODES}
    rc = 0
    for _ in range(N):
        for mode, names in MODES:
            rm(cache, *names)()
            d, r = run([binary, "-q"] + FASTVOL_ARGS + extra + ["-f", img, plugin], env)
            rc = rc or r
            best[mode] = min(best[mode], d)
    return best, rc

def volrs(img, plugin, extra, cold):
    env = dict(os.environ, HOME=VHOME)
    best, rc = 1e9, 0
    for _ in range(N):
        if cold:
            shutil.rmtree(os.path.join(VHOME, ".cache"), ignore_errors=True)
        d, rc = run([VOLRS, "-q"] + extra + ["-f", img, plugin], env)
        best = min(best, d)
    return best, rc

if "--no-volrs" not in args and not os.path.isdir(os.path.join(VHOME, ".local/share/vol-rs")):
    os.makedirs(os.path.join(VHOME, ".local/share"), exist_ok=True)
    shutil.copytree(os.path.expanduser("~/.local/share/vol-rs"), os.path.join(VHOME, ".local/share/vol-rs"))

ms = lambda x: f"{x * 1e3:7.1f}"
hdr = f"{'case':16} " + " ".join(f"{m:>7}" for m, _ in MODES)
if BASE:
    hdr += " | base: " + " ".join(f"{m:>7}" for m, _ in MODES)
if "--no-volrs" not in args:
    hdr += " | vol-rs: cold    warm"
print(hdr + f"   (ms, best of {N})", flush=True)
for name, img, plugin, extra in CASES:
    cur, rc = fastvol_all(BIN, os.path.join(SCRATCH, "bench-cache"), img, plugin, extra)
    line = f"{name:16} " + " ".join(ms(cur[m]) for m, _ in MODES)
    if BASE:
        base, brc = fastvol_all(BASE, os.path.join(SCRATCH, "bench-cache-base"), img, plugin, extra)
        line += " |       " + " ".join(ms(base[m]) for m, _ in MODES)
    if "--no-volrs" not in args:
        vc, vrc = volrs(img, plugin, extra, True)
        vw, _ = volrs(img, plugin, extra, False)
        line += f" |        {ms(vc)} {ms(vw)}" + (f" (volrs rc={vrc})" if vrc else "")
    if rc:
        line += f"  (fastvol rc={rc})"
    print(line, flush=True)
