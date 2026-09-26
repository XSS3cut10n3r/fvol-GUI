#!/usr/bin/env python3
"""Cold / warm start benchmark: rsvol (private RSVOL_CACHE) vs vol-rs (private HOME).

Usage: coldbench.py [-n N] [--bin BIN] [--base BIN] [--no-volrs] [--only NAME[,NAME]] [--scratch DIR]
                    [--rsvol-args "ARGS"] [--rsvol-env K=V[,K=V]]

--rsvol-args / --rsvol-env: extra global options / environment for the rsvol runs only (e.g.
`--rsvol-args "--cache-path DIR"`: seed the identifier index from python's cache in DIR;
`--rsvol-env RSVOL_NO_PY_IDENT_SEED=1`: rsvol's own identifier index).

Cases per (image, plugin), for each rsvol binary (--base: a baseline build, measured
interleaved with --bin so machine load affects both alike):
  cold     empty rsvol cache (first time the image AND the symbol files are seen)
  newimg   symbol caches warm (ISF blobs + identifier index), automagic/scan caches empty
  symcold  automagic caches warm, symbol caches (ISF blobs + identifier index) empty
  warm     everything cached
vol-rs is measured with HOME=<scratch>/volrs-home (its symbol store copied there, caches empty
for cold). Wall time, best of N (default 5). Timing only: outputs go to /dev/null.
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
BIN = opt("--bin", os.path.join(ROOT, "target/release/vol"))
BASE = opt("--base")
SCRATCH = opt("--scratch", os.path.join(ROOT, "testdata/scratch/coldstart"))
ONLY = opt("--only")
RSVOL_ARGS = (opt("--rsvol-args") or "").split()
RSVOL_ENV = dict(kv.split("=", 1) for kv in (opt("--rsvol-env") or "").split(",") if kv)
VOLRS = os.path.expanduser("~/cbc2/vol-rs/target/release/vol-rs")
SYMS = "/home/user/rs-vol/testdata/symbols"
T = "/home/user/rs-vol/testdata/images"
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

def run(cmd, env):
    t = time.perf_counter()
    r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    return time.perf_counter() - t, r.returncode

def rm(cache, *names):
    def f():
        for n in names:
            p = os.path.join(cache, n)
            if os.path.isdir(p):
                shutil.rmtree(p)
            elif os.path.exists(p):
                os.remove(p)
    return f

MODES = [
    ("cold", ("automagic", "scan", "isf", "identifiers.cache", "isfinfo.cache", "remote")),
    ("newimg", ("automagic", "scan")),
    ("symcold", ("isf", "identifiers.cache")),
    ("warm", ()),
]

def rsvol_all(binary, cache, img, plugin, extra):
    """best time per mode over N rounds of cold, newimg, symcold, warm (each mode starts from
    the caches the previous run left)"""
    env = dict(os.environ, RSVOL_CACHE=cache, **RSVOL_ENV)
    env.pop("RSVOL_TRACE", None)
    best = {m: 1e9 for m, _ in MODES}
    rc = 0
    for _ in range(N):
        for mode, names in MODES:
            rm(cache, *names)()
            d, r = run([binary, "-q"] + RSVOL_ARGS + extra + ["-f", img, plugin], env)
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
    cur, rc = rsvol_all(BIN, os.path.join(SCRATCH, "bench-cache"), img, plugin, extra)
    line = f"{name:16} " + " ".join(ms(cur[m]) for m, _ in MODES)
    if BASE:
        base, brc = rsvol_all(BASE, os.path.join(SCRATCH, "bench-cache-base"), img, plugin, extra)
        line += " |       " + " ".join(ms(base[m]) for m, _ in MODES)
    if "--no-volrs" not in args:
        vc, vrc = volrs(img, plugin, extra, True)
        vw, _ = volrs(img, plugin, extra, False)
        line += f" |        {ms(vc)} {ms(vw)}" + (f" (volrs rc={vrc})" if vrc else "")
    if rc:
        line += f"  (rsvol rc={rc})"
    print(line, flush=True)
