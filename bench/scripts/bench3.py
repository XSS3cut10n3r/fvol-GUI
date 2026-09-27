#!/usr/bin/env python3
"""Interleaved 3-way benchmark: python volatility3 vs vol-rs vs fastvol, per plugin, run back to back
so all three see the same machine load. Records wall time and CPU time (user+sys of the child).
Usage: bench3.py PLUGIN_LIST OUT.tsv [--py-runs 1] [--rs-runs 3]
Python runs go through limit.sh (memory cap). One process at a time."""
import os, resource, subprocess, sys, time, shutil, tempfile
IMG = os.environ.get("IMG", "/home/user/cbc2/task2/memory-dirty.raw")
LIMIT = "/home/user/rs-vol/bench/scripts/limit.sh"
PY = ["/home/user/rs-vol/bench/venv/bin/python", "/home/user/rs-vol/volatility3/vol.py"]
VOLRS = [os.path.expanduser("~/cbc2/vol-rs/target/release/vol-rs")]
OURS = [os.environ.get("OURS", "/home/user/rs-vol/testdata/scratch/vol-bench3")]
args = sys.argv[1:]
plist, out = args[0], args[1]
py_runs = int(args[args.index("--py-runs") + 1]) if "--py-runs" in args else 1
rs_runs = int(args[args.index("--rs-runs") + 1]) if "--rs-runs" in args else 3

def run(cmd, plugin, n):
    best = None
    for _ in range(n):
        d = tempfile.mkdtemp(dir="/home/user/rs-vol/testdata/scratch")
        r0 = resource.getrusage(resource.RUSAGE_CHILDREN)
        t0 = time.perf_counter()
        rc = subprocess.call(cmd + ["-q", "-o", d, "-f", IMG, plugin], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wall = time.perf_counter() - t0
        r1 = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu = (r1.ru_utime - r0.ru_utime) + (r1.ru_stime - r0.ru_stime)
        shutil.rmtree(d, ignore_errors=True)
        if best is None or wall < best[0]:
            best = (wall, cpu, rc)
    return best

done = set()
if os.path.exists(out):
    done = {l.split("\t")[0] for l in open(out)}
else:
    open(out, "w").write("plugin\tload1\tpy_wall\tpy_cpu\tpy_rc\tvolrs_wall\tvolrs_cpu\tvolrs_rc\trs_wall\trs_cpu\trs_rc\n")
for p in [l.strip() for l in open(plist) if l.strip()]:
    if p in done:
        continue
    load = os.getloadavg()[0]
    rs = run(OURS, p, rs_runs)
    vr = run(VOLRS, p, rs_runs)
    # python via the memory-capped wrapper (limit.sh execs systemd-run; rusage of children still counts it
    # only if the scope runs as our child -- systemd-run --scope does run the command as our descendant)
    py = run([LIMIT, "-m", "8G"] + PY, p, py_runs)
    with open(out, "a") as f:
        f.write(f"{p}\t{load:.1f}\t{py[0]:.3f}\t{py[1]:.3f}\t{py[2]}\t{vr[0]:.4f}\t{vr[1]:.4f}\t{vr[2]}\t{rs[0]:.4f}\t{rs[1]:.4f}\t{rs[2]}\n")
    print(p, f"py={py[0]:.2f}s vr={vr[0]*1000:.0f}ms rs={rs[0]*1000:.0f}ms load={load:.1f}", flush=True)
