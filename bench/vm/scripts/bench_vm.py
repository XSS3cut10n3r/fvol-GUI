#!/usr/bin/env python3
"""Interleaved 3-way benchmark on a quiet machine: python volatility3 vs vol-rs vs rsvol.

Adapted from rs-vol/bench/scripts/bench3.py for the dedicated benchmark VM.

Per plugin:
  1. one untimed warm-up run of each tool (python's warm-up is skipped for the plugins listed in
     --py-nowarm, which take ~15-20 min each; every cache they need is already warm by then);
  2. N interleaved timed rounds: rsvol, vol-rs, python (python only in the first --py-runs rounds).
Every run gets a fresh `-o` directory that is deleted afterwards; stdout goes to a file (so the
renderer really writes its output) whose sha256 (minus the first banner line) is recorded, which
gives a byte-for-byte output comparison of rsvol / vol-rs against python for every plugin.
Wall time = perf_counter around spawn..reap; CPU = ru_utime+ru_stime and max RSS of that one child
from wait4(), so runs are measured individually.

Usage: bench_vm.py PLUGIN_LIST OUT.tsv RAW.jsonl [--runs 5] [--py-runs 2] [--py-nowarm a,b]
"""
import hashlib, json, os, shutil, statistics, subprocess, sys, tempfile, time

B = os.path.expanduser("~/rsvol-bench")
IMG = os.environ.get("IMG", f"{B}/img/memory-dirty.raw")
OUTROOT = f"{B}/out"
TOOLS = {
    "rs": [os.environ.get("RS_BIN", f"{B}/rsvol/target/release/fvol")],
    "volrs": [os.environ.get("VOLRS_BIN", f"{B}/bin/vol-rs")],
    "py": [f"{B}/venv314/bin/python", f"{B}/volatility3/vol.py"],
}
EXTRA = os.environ.get("EXTRA", "").split()  # e.g. "-s /path/to/isf" for the linux round
os.environ["XDG_CACHE_HOME"] = f"{B}/home/.cache"
os.environ["XDG_DATA_HOME"] = f"{B}/home/.local/share"

args = sys.argv[1:]
plist, out_tsv, raw = args[0], args[1], args[2]
opt = lambda k, d: args[args.index(k) + 1] if k in args else d
runs = int(opt("--runs", "5"))
py_runs = int(opt("--py-runs", "2"))
py_nowarm = set(filter(None, opt("--py-nowarm", "").split(",")))
# --py-ref RAW.jsonl: skip python entirely and compare against the python stdout hashes recorded by
# an earlier full run (the python side does not depend on which rsvol build is being timed)
py_ref = {}
if "--py-ref" in args:
    for l in open(opt("--py-ref", "")):
        r = json.loads(l)
        if r["tool"] == "py" and not r.get("warmup"):
            py_ref.setdefault(r["plugin"], []).append(r)
os.makedirs(OUTROOT, exist_ok=True)


def run(tool, plugin):
    d = tempfile.mkdtemp(dir=OUTROOT)
    so_path, se_path = f"{OUTROOT}/stdout.{tool}", f"{OUTROOT}/stderr.{tool}"
    cmd = TOOLS[tool] + ["-q", "-o", d, "-f", IMG] + EXTRA + [plugin]
    with open(so_path, "wb") as so, open(se_path, "wb") as se:
        t0 = time.perf_counter()
        p = subprocess.Popen(cmd, stdout=so, stderr=se, stdin=subprocess.DEVNULL)
        _, status, ru = os.wait4(p.pid, 0)
        wall = time.perf_counter() - t0
    p.returncode = os.waitstatus_to_exitcode(status)
    data = open(so_path, "rb").read()
    body = data.split(b"\n", 1)[1] if b"\n" in data else b""
    written = 0
    for root, _, files in os.walk(d):
        for f in files:
            try:
                written += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    shutil.rmtree(d, ignore_errors=True)
    err = ""
    if p.returncode != 0:
        err = open(se_path, "rb").read()[-400:].decode("utf-8", "replace")
    return {
        "tool": tool, "plugin": plugin, "wall": wall, "cpu": ru.ru_utime + ru.ru_stime,
        "user": ru.ru_utime, "sys": ru.ru_stime, "maxrss_kb": ru.ru_maxrss, "rc": p.returncode,
        "sha": hashlib.sha256(body).hexdigest()[:16], "lines": body.count(b"\n"),
        "out_bytes": len(data), "files_bytes": written, "err": err,
    }


cols = ["plugin", "load1", "py_wall", "py_cpu", "py_rss_mb", "py_rc", "py_n",
        "volrs_wall", "volrs_med", "volrs_cpu", "volrs_rss_mb", "volrs_rc",
        "rs_wall", "rs_med", "rs_cpu", "rs_rss_mb", "rs_rc",
        "rs_eq_py", "volrs_eq_py", "py_lines", "rs_lines", "volrs_lines", "files_mb_py"]
done = set()
if os.path.exists(out_tsv):
    done = {l.split("\t")[0] for l in open(out_tsv)}
else:
    open(out_tsv, "w").write("\t".join(cols) + "\n")

for plugin in [l.strip() for l in open(plist) if l.strip() and not l.startswith("#")]:
    if plugin in done:
        continue
    load = os.getloadavg()[0]
    rec = {t: [] for t in TOOLS}
    rawf = open(raw, "a")
    # untimed warm-up
    for t in ("rs", "volrs", "py"):
        if t == "py" and (plugin in py_nowarm or py_ref):
            continue
        r = run(t, plugin)
        r["warmup"] = True
        rawf.write(json.dumps(r) + "\n"); rawf.flush()
    for i in range(runs):
        for t in ("rs", "volrs", "py"):
            if t == "py" and (i >= py_runs or py_ref):
                continue
            if t == "py" and plugin in py_nowarm and i >= 1:
                continue
            r = run(t, plugin)
            r["round"] = i
            rawf.write(json.dumps(r) + "\n"); rawf.flush()
            rec[t].append(r)
    rawf.close()
    if py_ref:
        rec["py"] = py_ref[plugin]

    def best(t):
        rs = rec[t]
        b = min(rs, key=lambda r: r["wall"])
        return b, statistics.median(r["wall"] for r in rs), rs

    pb, _, pr = best("py")
    vb, vmed, _ = best("volrs")
    rb, rmed, _ = best("rs")
    row = [plugin, f"{load:.2f}",
           f"{pb['wall']:.3f}", f"{pb['cpu']:.3f}", f"{pb['maxrss_kb']/1024:.0f}", str(pb["rc"]), str(len(pr)),
           f"{vb['wall']:.4f}", f"{vmed:.4f}", f"{vb['cpu']:.4f}", f"{vb['maxrss_kb']/1024:.0f}", str(vb["rc"]),
           f"{rb['wall']:.4f}", f"{rmed:.4f}", f"{rb['cpu']:.4f}", f"{rb['maxrss_kb']/1024:.0f}", str(rb["rc"]),
           str(int(rb["sha"] == pb["sha"])), str(int(vb["sha"] == pb["sha"])),
           str(pb["lines"]), str(rb["lines"]), str(vb["lines"]), f"{pb['files_bytes']/1e6:.1f}"]
    with open(out_tsv, "a") as f:
        f.write("\t".join(row) + "\n")
    print(f"{plugin} py={pb['wall']:.2f}s vr={vb['wall']*1000:.1f}ms rs={rb['wall']*1000:.1f}ms "
          f"eq(rs,py)={row[17]} eq(vr,py)={row[18]} load={load:.2f}", flush=True)
