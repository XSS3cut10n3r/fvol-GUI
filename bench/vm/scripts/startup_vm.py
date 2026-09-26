#!/usr/bin/env python3
"""Cold vs warm start of `windows.pslist.PsList` for each tool.

cold = the tool's own cache directory removed right before the run (rsvol: $XDG_CACHE_HOME/rsvol,
vol-rs: $XDG_CACHE_HOME/vol-rs, python: identifier.cache + data_*.cache in $XDG_CACHE_HOME/volatility3;
the provisioned kernel symbol files are kept for all tools, the image stays in the page cache).
warm = the cache left by the previous run. Usage: startup_vm.py OUT.tsv [--runs 5] [--py-runs 3]"""
import glob, os, shutil, statistics, subprocess, sys, tempfile, time

B = os.path.expanduser("~/rsvol-bench")
IMG = f"{B}/img/memory-dirty.raw"
C = f"{B}/home/.cache"
os.environ["XDG_CACHE_HOME"] = C
os.environ["XDG_DATA_HOME"] = f"{B}/home/.local/share"
TOOLS = {
    "rsvol": ([os.environ.get("RS_BIN", f"{B}/rsvol/target/release/vol")], lambda: shutil.rmtree(f"{C}/rsvol", ignore_errors=True)),
    "vol-rs": ([f"{B}/bin/vol-rs"], lambda: shutil.rmtree(f"{C}/vol-rs", ignore_errors=True)),
    "python": ([f"{B}/venv314/bin/python", f"{B}/volatility3/vol.py"],
               lambda: [os.remove(f) for f in glob.glob(f"{C}/volatility3/*.cache")]),
}
args = sys.argv[1:]
out = args[0]
runs = int(args[args.index("--runs") + 1]) if "--runs" in args else 5
py_runs = int(args[args.index("--py-runs") + 1]) if "--py-runs" in args else 3
PLUGIN = "windows.pslist.PsList"
only = set(args[args.index("--tools") + 1].split(",")) if "--tools" in args else set(TOOLS)


def run(cmd):
    d = tempfile.mkdtemp(dir=f"{B}/out")
    t0 = time.perf_counter()
    p = subprocess.Popen(cmd + ["-q", "-o", d, "-f", IMG, PLUGIN], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    _, st, ru = os.wait4(p.pid, 0)
    wall = time.perf_counter() - t0
    shutil.rmtree(d, ignore_errors=True)
    return wall, ru.ru_utime + ru.ru_stime, os.waitstatus_to_exitcode(st)


os.makedirs(f"{B}/out", exist_ok=True)
with open(out, "w") as f:
    f.write("tool\tmode\tn\twall_min\twall_med\tcpu_at_min\trc\tall_walls\n")
    for name, (cmd, clear) in TOOLS.items():
        if name not in only:
            continue
        n = py_runs if name == "python" else runs
        for mode in ("cold", "warm"):
            res = []
            if mode == "warm":
                run(cmd)  # make sure the cache exists
            for _ in range(n):
                if mode == "cold":
                    clear()
                res.append(run(cmd))
            b = min(res)
            f.write(f"{name}\t{mode}\t{n}\t{b[0]:.4f}\t{statistics.median(r[0] for r in res):.4f}\t{b[1]:.4f}\t"
                    f"{max(r[2] for r in res)}\t{','.join(f'{r[0]:.4f}' for r in res)}\n")
            f.flush()
            print(name, mode, f"min={b[0]:.4f}s", flush=True)
