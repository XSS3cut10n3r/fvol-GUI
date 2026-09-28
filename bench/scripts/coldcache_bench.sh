#!/bin/bash
# Cold / warm page-cache benchmark of fastvol plugins, without root.
#
# Cold page cache without root: every image is copied once with `cp --reflink=always` into the
# scratch dir. The copy shares the on-disk extents (no extra disk space) but has its own page
# cache, so `posix_fadvise(POSIX_FADV_DONTNEED)` on the copy before each run evicts exactly that
# image -- repeatable, independent cold runs that do not disturb the shared images other agents
# are timing. (Pages still mapped by a running process are not evicted; nothing maps the copy
# between runs.)
#
# Usage: bench/scripts/coldcache_bench.sh [options]
#   -b LABEL=BIN[,K=V...]  binary to measure (repeatable; runs of all binaries are interleaved so
#                          machine load hits them alike). Default: new=target/release/fvol.
#                          K=V pairs are extra environment for that binary only (A/B env switches).
#   -n N                   runs per (case, binary, mode) (default 3); best and median are reported
#   -m MODES               cold,warm (default both)
#   -c CASES               comma-separated case names or name prefixes (default: all; -l lists them)
#   -s DIR                 scratch dir (default testdata/scratch/coldcache; must be on the images'
#                          btrfs for the reflink copies)
#   -S                     keep the scan cache (default: FASTVOL_NO_SCAN_CACHE=1, scans really run)
#   -l                     list the cases and exit
# Each binary gets a private FASTVOL_CACHE (warmed by one untimed run per case, so cold runs measure
# the image IO, not symbol/automagic first-run work). Dump plugins write into a private output
# dir that is emptied after every run. Heavy: run it through bench/scripts/limit.sh.
#
# CCB_STDERR=1 shows the runs' stderr (debugging a case).
# Columns: best / median wall (ms, includes the exit teardown: fork+exec+wait4 like
# testdata/scratch/review-scan/tm.py), and user/sys CPU and major/minor faults of the best run.
# stdout of the last run of each binary is kept in <scratch>/out-<label>.stdout.
set -euo pipefail
exec python3 - "$@" <<'PYEOF'
import os, sys, shutil, subprocess, time, statistics, getopt

ROOT = "/home/user/fvol"
T = f"{ROOT}/testdata/images"
SYMS = ["-s", f"{ROOT}/testdata/symbols"]
WIN = "/home/user/cbc2/task2/memory-dirty.raw"
# (name, image, extra files copied next to it, plugin args)
CASES = [
    ("win-pslist", WIN, [], ["windows.pslist"]),
    ("win-dlllist", WIN, [], ["windows.dlllist"]),
    ("win-handles", WIN, [], ["windows.handles"]),
    ("win-info", WIN, [], ["windows.info"]),
    ("win-psscan", WIN, [], ["windows.psscan"]),
    ("win-filescan", WIN, [], ["windows.filescan"]),
    ("win-netscan", WIN, [], ["windows.netscan"]),
    ("win-thrdscan", WIN, [], ["windows.thrdscan"]),
    ("win-vmscan", WIN, [], ["vmscan.Vmscan"]),
    ("win-banners", WIN, [], ["banners.Banners"]),
    ("win-mftscan", WIN, [], ["windows.mftscan.MFTScan"]),
    ("win-mftscan-ads", WIN, [], ["windows.mftscan.ADS"]),
    ("win-mbrscan", WIN, [], ["windows.mbrscan"]),
    ("win-memmap-dump", WIN, [], ["windows.memmap", "--pid", "2872", "--dump"]),
    ("win-vadinfo-dump", WIN, [], ["windows.vadinfo", "--pid", "2872", "--dump"]),
    ("win-pslist-dump", WIN, [], ["windows.pslist", "--dump"]),
    ("crash-pslist", f"{T}/windows/vol3-win10-19041-x64-2025_03.dmp", [], ["-s", f"{ROOT}/testdata/symbols", "windows.pslist"]),
    ("crash-dlllist", f"{T}/windows/vol3-win10-19041-x64-2025_03.dmp", [], ["-s", f"{ROOT}/testdata/symbols", "windows.dlllist"]),
    ("elf-pslist", f"{T}/linux/rsvol-noble-6.8.0-139.elf", [], SYMS + ["linux.pslist"]),
    ("elf-psaux", f"{T}/linux/rsvol-noble-6.8.0-139.elf", [], SYMS + ["linux.psaux"]),
    ("elf-psscan", f"{T}/linux/rsvol-noble-6.8.0-139.elf", [], SYMS + ["linux.psscan"]),
    ("lime-pslist", f"{T}/linux/rsvol-noble-6.8.0-139.lime", [], SYMS + ["linux.pslist"]),
    ("lime-psaux", f"{T}/linux/rsvol-noble-6.8.0-139.lime", [], SYMS + ["linux.psaux"]),
    ("vmware-pslist", f"{T}/linux/rsvol-bionic64-4.15.0-212.vmem", [f"{T}/linux/rsvol-bionic64-4.15.0-212.vmss"], SYMS + ["linux.pslist"]),
]

opts, rest = getopt.getopt(sys.argv[1:], "b:n:m:c:s:Sl")
bins, n, modes, only, scratch, keep_scan = [], 3, ["cold", "warm"], None, f"{ROOT}/testdata/scratch/coldcache", False
for o, v in opts:
    if o == "-b":
        label, spec = v.split("=", 1)
        path, *envs = spec.split(",")
        bins.append((label, os.path.abspath(path), dict(e.split("=", 1) for e in envs)))
    elif o == "-n": n = int(v)
    elif o == "-m": modes = v.split(",")
    elif o == "-c": only = v.split(",")
    elif o == "-s": scratch = v
    elif o == "-S": keep_scan = True
    elif o == "-l":
        for c in CASES: print(f"{c[0]:18} {os.path.basename(c[1]):40} {' '.join(c[3])}")
        sys.exit(0)
if not bins:
    bins = [("new", os.path.abspath("target/release/fvol"), {})]
cases = [c for c in CASES if only is None or any(c[0] == k or c[0].startswith(k) for k in only)]
os.makedirs(f"{scratch}/img", exist_ok=True)

def copy_of(src):
    dst = f"{scratch}/img/{os.path.basename(src)}"
    if not (os.path.exists(dst) and os.path.getsize(dst) == os.path.getsize(src)):
        subprocess.run(["cp", "--reflink=always", src, dst], check=True)
    return dst

def resident(path):
    try:
        return int(subprocess.run(["fincore", "-b", "-n", "-o", "RES", path], capture_output=True, text=True).stdout.split()[0])
    except Exception:
        return -1

def evict(path):
    """Drop the image copy from the page cache; returns the bytes still resident (0 = cold)."""
    # pages still locked by a read that completes after the previous run exited (readahead of
    # the rest of a compressed extent) survive one DONTNEED: retry until nothing is resident
    delay = 0.005
    for attempt in range(40):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        finally:
            os.close(fd)
        r = resident(path)
        if r <= 0:
            return 0
        time.sleep(delay)
        delay = min(delay * 1.5, 0.25)
    print(f"warning: {r} bytes of {path} stay resident", file=sys.stderr)
    return r

def run(binary, env, args, outdir):
    os.makedirs(outdir, exist_ok=True)
    argv = [binary, "-q", "-o", outdir] + args
    t = time.perf_counter()
    pid = os.fork()
    if pid == 0:
        # stdout to a real file: some plugins produce nothing when it is /dev/null
        fd = os.open(f"{outdir}.stdout", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        os.dup2(fd, 1)
        if not os.environ.get("CCB_STDERR"):
            os.dup2(os.open("/dev/null", os.O_WRONLY), 2)
        os.execve(binary, argv, env)
    _, st, ru = os.wait4(pid, 0)
    w = time.perf_counter() - t
    shutil.rmtree(outdir, ignore_errors=True)
    return w, ru, st

results = {}
for name, src, extra, pargs in cases:
    img = copy_of(src)
    for e in extra:
        copy_of(e)
    # "-f IMG" goes before the plugin args (global options like -s may be in pargs)
    args = ["-f", img] + pargs
    envs = {}
    for label, binary, benv in bins:
        env = dict(os.environ)
        # both names: a baseline binary may predate the rename (RSVOL_* only)
        env["FASTVOL_CACHE"] = env["RSVOL_CACHE"] = f"{scratch}/cache-{label}"
        if not keep_scan:
            env["FASTVOL_NO_SCAN_CACHE"] = env["RSVOL_NO_SCAN_CACHE"] = "1"
        env.update(benv)
        envs[label] = env
        # untimed warm-up: symbol / automagic caches, page cache
        run(binary, env, args, f"{scratch}/out-{label}")
    for mode in modes:
        for i in range(n):
            for label, binary, _ in (bins if i % 2 == 0 else bins[::-1]):
                left = evict(img) if mode == "cold" else 0
                w, ru, st = run(binary, envs[label], args, f"{scratch}/out-{label}")
                results.setdefault((name, mode, label), []).append((w, ru, st, left))
        for label, _, _ in bins:
            rs = results[(name, mode, label)]
            ws = sorted(r[0] for r in rs)
            b = min(rs, key=lambda r: r[0])
            ru = b[1]
            status = "" if all(r[2] == 0 for r in rs) else f"  EXIT {sorted(set(r[2] for r in rs))}"
            if any(r[3] for r in rs):
                status += f"  NOT-COLD {sum(1 for r in rs if r[3])}/{len(rs)} runs (max {max(r[3] for r in rs) >> 20} MiB resident)"
            print(f"{name:18} {mode:4} {label:8} best {ws[0]*1e3:9.1f} ms  med {statistics.median(ws)*1e3:9.1f} ms  "
                  f"user {ru.ru_utime*1e3:7.1f} sys {ru.ru_stime*1e3:7.1f}  majflt {ru.ru_majflt:6} minflt {ru.ru_minflt:7}{status}", flush=True)
PYEOF
