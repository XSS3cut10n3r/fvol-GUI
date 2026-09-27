#!/usr/bin/env python3
"""Pass-2 benchmark on the quiet VM: rsvol in three cache states vs vol-rs cold/warm; python's
times and output hashes are reused from pass 1 (same image, same python, same machine) except for
plugins pass 1 did not run or that are listed in --py-fresh.

Columns (every run: `TOOL -q -o <fresh dir> -f IMG [EXTRA] PLUGIN`, stdout to a file):
  rs_cold    rsvol, FASTVOL_CACHE=<C2>/rs-cold, the whole directory deleted before EVERY run
             (symbol tables, identifier index, automagic results, scan cache: a first-ever run)
  rs_steady  rsvol, FASTVOL_CACHE=<C2>/rs-steady, FASTVOL_NO_SCAN_CACHE=1: symbol/automagic caches warm,
             the per-image scan cache off, so every scan is really done
  rs_warm    rsvol, FASTVOL_CACHE=<C2>/rs-warm: every cache warm (2nd+ run of a plugin)
  vr_cold    vol-rs, $XDG_CACHE_HOME/vol-rs deleted before EVERY run except pdb/ (the PDB files it
             downloaded from the Microsoft symbol server, kept like the provisioned ISFs, so no timed
             run touches the network)
  vr_warm    vol-rs with the cache the previous run left
  py         python volatility3 (only when it runs: plugin not in the pass-1 reference, or --py-fresh)

Per plugin: one untimed warm-up of rs_steady, rs_warm, vr_warm (+ py unless --py-nowarm); the cold
columns get none (their cache is wiped before every run). Then N interleaved rounds
rs_cold, rs_steady, rs_warm, vr_cold, vr_warm (+ py in the first --py-runs rounds).
Wall = perf_counter spawn..reap, CPU/max RSS from wait4 of that child. stdout sha256 (without the
banner line) is recorded for every run.

--vr-ref PASS2.jsonl reuses vol-rs's timed runs from an earlier pass (same machine, same vol-rs build)
instead of running it again: only the three rsvol columns are measured (pass 3).

Usage: bench2_vm.py PLUGIN_LIST OUT.tsv RAW.jsonl [--runs 5] [--py-runs 1] [--py-ref A.jsonl[,B.jsonl]]
       [--vr-ref PASS2.jsonl] [--py-fresh a,b] [--py-nowarm a,b] [--keep a,b] [--keep-dir DIR]
"""
import hashlib, json, os, shutil, statistics, subprocess, sys, tempfile, time

B = os.path.expanduser("~/rsvol-bench")
IMG = os.environ.get("IMG", f"{B}/img/memory-dirty.raw")
OUTROOT = f"{B}/out"
C = f"{B}/home/.cache"
C2 = f"{B}/cache2"
RS = os.environ.get("RS_BIN", f"{B}/rsvol-95528b2/target/release/vol")
VR = os.environ.get("VOLRS_BIN", f"{B}/bin/vol-rs")
PY = [f"{B}/venv314/bin/python", f"{B}/volatility3/vol.py"]
EXTRA = os.environ.get("EXTRA", "").split()  # "-s ~/rsvol-bench/isf" for the linux round
os.environ["XDG_CACHE_HOME"] = C
os.environ["XDG_DATA_HOME"] = f"{B}/home/.local/share"
for k in ("CACHE", "NO_SCAN_CACHE", "THREADS", "TRACE"):
    for pre in ("FASTVOL_", "RSVOL_"):  # RSVOL_* = the pre-rename names, still honoured
        os.environ.pop(pre + k, None)


def both(**kv):
    """fastvol's env vars under both names: the default RS_BIN is a pre-rename build (RSVOL_* only)."""
    return {pre + k: v for k, v in kv.items() for pre in ("FASTVOL_", "RSVOL_")}


def wipe_rs_cold():
    shutil.rmtree(f"{C2}/rs-cold", ignore_errors=True)


def wipe_vr_cold():
    d = f"{C}/vol-rs"
    if os.path.isdir(d):
        for n in os.listdir(d):
            if n == "pdb":
                continue
            p = os.path.join(d, n)
            shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p)


TOOLS = {  # name: (argv, extra env, pre-run hook)
    "rs_cold": ([RS], both(CACHE=f"{C2}/rs-cold"), wipe_rs_cold),
    "rs_steady": ([RS], both(CACHE=f"{C2}/rs-steady", NO_SCAN_CACHE="1"), None),
    "rs_warm": ([RS], both(CACHE=f"{C2}/rs-warm"), None),
    "vr_cold": ([VR], {}, wipe_vr_cold),
    "vr_warm": ([VR], {}, None),
    "py": (PY, {}, None),
}
ORDER = ["rs_cold", "rs_steady", "rs_warm", "vr_cold", "vr_warm"]
WARM = ["rs_steady", "rs_warm", "vr_warm"]

args = sys.argv[1:]
plist, out_tsv, raw = args[0], args[1], args[2]
opt = lambda k, d: args[args.index(k) + 1] if k in args else d
runs = int(opt("--runs", "5"))
py_runs = int(opt("--py-runs", "1"))
py_nowarm = set(filter(None, opt("--py-nowarm", "").split(",")))
py_fresh = set(filter(None, opt("--py-fresh", "").split(",")))
keep = set(filter(None, opt("--keep", "").split(",")))
keep_dir = opt("--keep-dir", f"{B}/p2/keep")
py_ref = {}
if "--py-ref" in args:
    for fn in opt("--py-ref", "").split(","):  # later files override earlier ones per plugin
        got = {}
        for l in open(fn):
            r = json.loads(l)
            if r["tool"] == "py" and not r.get("warmup"):
                got.setdefault(r["plugin"], []).append(r)
        py_ref.update(got)
vr_ref = {}
if "--vr-ref" in args:
    for l in open(opt("--vr-ref", "")):
        r = json.loads(l)
        if r["tool"] in ("vr_cold", "vr_warm") and not r.get("warmup"):
            vr_ref.setdefault(r["plugin"], {}).setdefault(r["tool"], []).append(r)
    ORDER_RUN = [t for t in ORDER if not t.startswith("vr_")]
    WARM_RUN = [t for t in WARM if not t.startswith("vr_")]
else:
    ORDER_RUN, WARM_RUN = ORDER, WARM
os.makedirs(OUTROOT, exist_ok=True)
os.makedirs(C2, exist_ok=True)
os.makedirs(keep_dir, exist_ok=True)


def run(tool, plugin, keep_out=False):
    argv, env_extra, pre = TOOLS[tool]
    if pre:
        pre()
    env = dict(os.environ, **env_extra)
    d = tempfile.mkdtemp(dir=OUTROOT)
    so_path, se_path = f"{OUTROOT}/stdout.{tool}", f"{OUTROOT}/stderr.{tool}"
    cmd = argv + ["-q", "-o", d, "-f", IMG] + EXTRA + [plugin]
    with open(so_path, "wb") as so, open(se_path, "wb") as se:
        t0 = time.perf_counter()
        p = subprocess.Popen(cmd, stdout=so, stderr=se, stdin=subprocess.DEVNULL, env=env)
        _, status, ru = os.wait4(p.pid, 0)
        wall = time.perf_counter() - t0
    rc = os.waitstatus_to_exitcode(status)
    h = hashlib.sha256()
    lines = size = 0
    first = True
    with open(so_path, "rb") as f:  # streamed: timeliner writes hundreds of MB
        for blk in iter(lambda: f.read(1 << 20), b""):
            size += len(blk)
            if first:
                first = False
                nl = blk.find(b"\n")
                blk = blk[nl + 1:] if nl >= 0 else b""
            h.update(blk)
            lines += blk.count(b"\n")
    written = 0
    for root, _, files in os.walk(d):
        for fn in files:
            try:
                written += os.lstat(os.path.join(root, fn)).st_size
            except OSError:
                pass
    shutil.rmtree(d, ignore_errors=True)
    if keep_out:
        shutil.copyfile(so_path, f"{keep_dir}/{plugin}.{tool}.txt")
    err = ""
    if rc != 0:
        err = open(se_path, "rb").read()[-400:].decode("utf-8", "replace")
    return {
        "tool": tool, "plugin": plugin, "wall": wall, "cpu": ru.ru_utime + ru.ru_stime,
        "user": ru.ru_utime, "sys": ru.ru_stime, "maxrss_kb": ru.ru_maxrss, "rc": rc,
        "sha": h.hexdigest()[:16], "lines": lines, "out_bytes": size, "files_bytes": written, "err": err,
        "t": time.time(), "load1": os.getloadavg()[0],
    }


T = ORDER + ["py"]
cols = ["plugin", "load1", "py_src", "py_n"]
for t in T:
    cols += [f"{t}_wall", f"{t}_med", f"{t}_cpu", f"{t}_rss_mb", f"{t}_rc", f"{t}_lines"]
cols += [f"{t}_eq_py" for t in ORDER] + ["rs_consistent", "files_mb_py", "files_mb_rs", "files_mb_vr"]
done = set()
if os.path.exists(out_tsv):
    done = {l.split("\t")[0] for l in open(out_tsv)}
else:
    open(out_tsv, "w").write("\t".join(cols) + "\n")

for plugin in [l.strip() for l in open(plist) if l.strip() and not l.startswith("#")]:
    if plugin in done:
        continue
    if vr_ref and plugin not in vr_ref:
        print(f"{plugin}: not in --vr-ref, skipped", flush=True)
        continue
    load = os.getloadavg()[0]
    py_live = plugin in py_fresh or plugin not in py_ref
    rec = {t: [] for t in T}
    rawf = open(raw, "a")
    for t in WARM_RUN + (["py"] if py_live and plugin not in py_nowarm else []):
        r = run(t, plugin)
        r["warmup"] = True
        rawf.write(json.dumps(r) + "\n"); rawf.flush()
    for i in range(runs):
        for t in ORDER_RUN + (["py"] if py_live and i < py_runs else []):
            r = run(t, plugin, keep_out=(plugin in keep and t in ("rs_warm", "py") and (i == runs - 1 or t == "py")))
            r["round"] = i
            rawf.write(json.dumps(r) + "\n"); rawf.flush()
            rec[t].append(r)
    rawf.close()
    if not py_live:
        rec["py"] = py_ref[plugin]
    if vr_ref:
        rec["vr_cold"], rec["vr_warm"] = vr_ref[plugin]["vr_cold"], vr_ref[plugin]["vr_warm"]
    pb = min(rec["py"], key=lambda r: r["wall"])
    row = [plugin, f"{load:.2f}", "fresh" if py_live else "pass1", str(len(rec["py"]))]
    best = {}
    for t in T:
        rs = rec[t]
        b = min(rs, key=lambda r: r["wall"])
        best[t] = b
        row += [f"{b['wall']:.4f}", f"{statistics.median(r['wall'] for r in rs):.4f}", f"{b['cpu']:.4f}",
                f"{b['maxrss_kb']/1024:.0f}", str(max((r["rc"] for r in rs), key=abs)), str(b["lines"])]
    # eq: every timed run of the tool printed python's (best run's) output
    row += [str(int(all(r["sha"] == pb["sha"] for r in rec[t]))) for t in ORDER]
    rs_shas = {r["sha"] for t in ("rs_cold", "rs_steady", "rs_warm") for r in rec[t]}
    row += [str(int(len(rs_shas) == 1)), f"{pb.get('files_bytes', 0)/1e6:.1f}",
            f"{best['rs_warm']['files_bytes']/1e6:.1f}", f"{best['vr_warm']['files_bytes']/1e6:.1f}"]
    with open(out_tsv, "a") as f:
        f.write("\t".join(row) + "\n")
    ms = lambda t: f"{best[t]['wall']*1000:.1f}"
    print(f"{plugin} py={pb['wall']:.2f}s({row[2]}) rs c/s/w={ms('rs_cold')}/{ms('rs_steady')}/{ms('rs_warm')}ms "
          f"vr c/w={ms('vr_cold')}/{ms('vr_warm')}ms eq(rs)={row[-9:-6]} consistent={row[-4]} load={load:.2f}",
          flush=True)
