#!/usr/bin/env python3
"""Cold / warm start benchmark: rsvol (private RSVOL_CACHE) vs vol-rs (private HOME).

Usage: coldbench.py [-n N] [--bin BIN] [--no-volrs] [--only NAME[,NAME]] [--scratch DIR]

Cases per (image, plugin):
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
SCRATCH = opt("--scratch", os.path.join(ROOT, "testdata/scratch/coldstart"))
ONLY = opt("--only")
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
CACHE = os.path.join(SCRATCH, "bench-cache")
VHOME = os.path.join(SCRATCH, "volrs-home")

def run(cmd, env):
    t = time.perf_counter()
    r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    return time.perf_counter() - t, r.returncode

def rsvol(img, plugin, extra, prep):
    env = dict(os.environ, RSVOL_CACHE=CACHE)
    env.pop("RSVOL_TRACE", None)
    best, rc = 1e9, 0
    for _ in range(N):
        prep()
        d, rc = run([BIN, "-q"] + extra + ["-f", img, plugin], env)
        best = min(best, d)
    return best, rc

def rm(*names):
    def f():
        for n in names:
            p = os.path.join(CACHE, n)
            if os.path.isdir(p):
                shutil.rmtree(p)
            elif os.path.exists(p):
                os.remove(p)
    return f

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

ms = lambda x: f"{x * 1e3:8.1f}"
print(f"{'case':18} {'cold':>8} {'newimg':>8} {'symcold':>8} {'warm':>8} | {'volrs-cold':>10} {'volrs-warm':>10}   (ms, best of {N})")
for name, img, plugin, extra in CASES:
    cold, rc = rsvol(img, plugin, extra, rm("automagic", "scan", "isf", "identifiers.cache", "isfinfo.cache", "remote"))
    newimg, _ = rsvol(img, plugin, extra, rm("automagic", "scan"))
    symcold, _ = rsvol(img, plugin, extra, rm("isf", "identifiers.cache"))
    warm, _ = rsvol(img, plugin, extra, lambda: None)
    line = f"{name:18} {ms(cold)} {ms(newimg)} {ms(symcold)} {ms(warm)}"
    if "--no-volrs" not in args:
        vc, vrc = volrs(img, plugin, extra, True)
        vw, _ = volrs(img, plugin, extra, False)
        line += f" | {ms(vc):>10} {ms(vw):>10}" + (f" (volrs rc={vrc})" if vrc else "")
    if rc:
        line += f"  (rsvol rc={rc})"
    print(line, flush=True)
