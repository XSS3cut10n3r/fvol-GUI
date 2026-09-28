#!/usr/bin/env python3
"""Benchmark fastvol, vol-rs and python volatility3 on this machine (stdlib only).

Usage: bench_local.py OUTDIR [--only win,linux,triage,startup] [--plugins N] [--runs 5] [--vr-runs 3]
                             [--py-runs 1] [--triage-runs 3] [--triage-py-runs 2]

Every run is one process (`TOOL -q -o <fresh dir> -f IMG [-s ISF] PLUGIN`, stdout to a file),
timed from spawn to reap; CPU and max RSS come from wait4. Runs are strictly sequential (nothing
else of ours runs at the same time) and interleaved across tools. Summaries use the MEDIAN of each
tool's runs (not the best), so tools with more runs get no advantage.

Cache states (each tool has private cache/data dirs under OUTDIR, the user's caches are only read
to provision symbol files once):
  py            python volatility3, warm: ISFs provisioned, identifier cache built by an untimed
                run at the start of each round. (A first-ever python run also downloads and
                converts the PDB; that is not measured.)
  vr_cold       vol-rs, its cache wiped before every run except pdb/ (downloaded PDBs), like pass 2
  vr_warm       vol-rs, cache as its previous run left it
  fv_cold       fastvol, its cache dir wiped before every run: symbol tables, identifier index,
                automagic and scan results (it still reads python's identifier cache, as a user
                with volatility3 installed would have)
  fv_steady     fastvol, symbol/automagic caches warm, scan-result cache off: every scan is done
  fv_warm       fastvol, every cache warm, scan results replayed from the per-image scan cache

Rounds:
  win / linux   every plugin of the pass-3 lists (bench/vm/raw3/*.tsv), image in the page cache
  triage        a realistic session: ~12 common plugins in a row, the tool's cache wiped only at
                the start of the first session (persists within it, like a real first look at an
                image), then a second session; each with the image in the page cache and evicted
                from it (posix_fadvise DONTNEED: read from disk)
  startup       windows.pslist.PsList, 10 runs per state
"""
import hashlib, json, os, platform, shutil, statistics, subprocess, sys, tempfile, time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
HOME = os.path.expanduser("~")
FV = os.environ.get("FV_BIN", f"{ROOT}/target/release/fvol")
VR = os.environ.get("VOLRS_BIN", f"{HOME}/cbc2/vol-rs/target/release/vol-rs")
PY = [os.environ.get("PY_BIN", f"{ROOT}/bench/venv/bin/python"), f"{ROOT}/volatility3/vol.py"]
WIN_IMG = os.environ.get("WIN_IMG", f"{HOME}/cbc2/task2/memory-dirty.raw")
LNX_IMG = os.environ.get("LNX_IMG", f"{ROOT}/testdata/images/linux/rsvol-noble-6.8.0-139.elf")
LNX_ISF = f"{ROOT}/testdata/symbols/linux/rsvol-noble-6.8.0-139-generic.json.xz"

WIN_TRIAGE = ["windows.info.Info", "windows.pslist.PsList", "windows.pstree.PsTree", "windows.psscan.PsScan",
              "windows.cmdline.CmdLine", "windows.dlllist.DllList", "windows.netscan.NetScan",
              "windows.modules.Modules", "windows.getsids.GetSIDs", "windows.handles.Handles",
              "windows.filescan.FileScan", "windows.registry.hivelist.HiveList"]
LNX_TRIAGE = ["linux.pslist.PsList", "linux.pstree.PsTree", "linux.psaux.PsAux", "linux.bash.Bash",
              "linux.lsmod.Lsmod", "linux.sockstat.Sockstat", "linux.lsof.Lsof", "linux.malware.malfind.Malfind",
              "linux.elfs.Elfs", "linux.malware.check_syscall.Check_syscall"]

args = sys.argv[1:]
if not args or args[0].startswith("-"):
    sys.exit(__doc__)
OUT = os.path.abspath(args[0])
opt = lambda k, d: args[args.index(k) + 1] if k in args else d
ONLY = set(opt("--only", "win,linux,triage,startup").split(","))
RUNS, VR_RUNS, PY_RUNS = int(opt("--runs", "5")), int(opt("--vr-runs", "3")), int(opt("--py-runs", "1"))
T_RUNS, T_PY_RUNS = int(opt("--triage-runs", "3")), int(opt("--triage-py-runs", "2"))
NPLUG = int(opt("--plugins", "0"))  # 0 = all (a smaller number for a quick trial)
# python runs of the plugin rounds in parallel: N processes, each pinned to its own physical
# performance core, after the round's fastvol / vol-rs runs (never alongside them). Control plugins
# already timed alone are run again in the pool to measure what the parallelism costs python.
PY_PAR = int(opt("--py-par", "1"))
PY_CPUS = [int(c) for c in opt("--py-cpus", "8,10,0,2,4,6").split(",")][:max(PY_PAR, 1)]
RESUME = "--resume" in args

CACHE, DATA, WORK = f"{OUT}/home/cache", f"{OUT}/home/data", f"{OUT}/work"
FVC = {s: f"{OUT}/fv/{s}" for s in ("cold", "steady", "warm")}
ISF_DIR = f"{OUT}/isf"


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return ""


def provision():
    """Private symbol files for python and vol-rs, copied once from the user's caches."""
    for d in (CACHE, DATA, WORK, ISF_DIR + "/linux", *FVC.values()):
        os.makedirs(d, exist_ok=True)
    src = f"{HOME}/.cache/volatility3/symbols/windows"
    for pdb, name in (("ntkrnlmp.pdb", "8E3373D6124E747F0E72EF8E02E676B3-1.json.xz"),
                      ("tcpip.pdb", "20223492C3DD1819D9E4F2A0EE975F74-1.json")):
        dst = f"{CACHE}/volatility3/symbols/windows/{pdb}"
        os.makedirs(dst, exist_ok=True)
        if not os.path.exists(f"{dst}/{name}"):
            shutil.copy2(f"{src}/{pdb}/{name}", dst)
    for sub, dst in ((f"{HOME}/.local/share/vol-rs/symbols", f"{DATA}/vol-rs/symbols"),
                     (f"{HOME}/.cache/vol-rs/pdb", f"{CACHE}/vol-rs/pdb")):
        if os.path.isdir(sub) and not os.path.exists(dst):
            shutil.copytree(sub, dst)
    if not os.path.exists(f"{ISF_DIR}/linux/{os.path.basename(LNX_ISF)}"):
        shutil.copy2(LNX_ISF, f"{ISF_DIR}/linux/")


def machine():
    lscpu = sh("lscpu")
    info = {
        "date": time.strftime("%Y-%m-%d %H:%M %Z"),
        "cpu": sh("lscpu | sed -n 's/^Model name: *//p'"),
        "cpus": os.cpu_count(),
        "cores": sh("lscpu -p=CORE | grep -v '^#' | sort -u | wc -l"),
        "max_mhz": sh("lscpu | sed -n 's/^CPU max MHz: *//p'"),
        "governor": sh("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "mem_gib": round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30, 1),
        "kernel": platform.release(),
        "os": sh(". /etc/os-release && echo $PRETTY_NAME"),
        "storage": sh(f"findmnt -no FSTYPE -T {WIN_IMG}") + " on " + ", ".join(
            l.strip() for l in sh(f"lsblk -sno TYPE,MODEL $(findmnt -no SOURCE -T {WIN_IMG} | sed 's/\\[.*//')").splitlines()),
        "load1_start": os.getloadavg()[0],
        "fastvol": sh(f"cd {ROOT} && git rev-parse --short HEAD") + " " + sh(f"sha256sum {FV}")[:16],
        "fastvol_rustc": sh("rustc --version"),
        "volrs": sh(f"{VR} --version") + " " + sh(f"sha256sum {VR}")[:16],
        "python": sh(f"{PY[0]} --version") + " / volatility3 " + sh(f"cd {ROOT}/volatility3 && git describe --tags 2>/dev/null"),
        "win_image": f"{WIN_IMG} ({os.path.getsize(WIN_IMG) / 2**30:.1f} GiB)",
        "linux_image": f"{LNX_IMG} ({os.path.getsize(LNX_IMG) / 2**30:.1f} GiB)",
    }
    del lscpu
    return info


def base_env():
    env = dict(os.environ, XDG_CACHE_HOME=CACHE, XDG_DATA_HOME=DATA)
    for k in list(env):
        if k.startswith(("FASTVOL_", "RSVOL_")):
            del env[k]
    return env


def wipe(d, keep=()):
    if not os.path.isdir(d):
        return
    for n in os.listdir(d):
        if n in keep:
            continue
        p = os.path.join(d, n)
        shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p)


def tool(state):
    """(argv, extra env, pre-run hook) of a tool state."""
    fv = lambda s, extra={}: ([FV], dict(FASTVOL_CACHE=FVC[s], **extra), None)
    return {
        "py": (PY, {}, None),
        "vr_cold": ([VR], {}, lambda: wipe(f"{CACHE}/vol-rs", keep=("pdb",))),
        "vr_warm": ([VR], {}, None),
        "fv_cold": ([FV], dict(FASTVOL_CACHE=FVC["cold"]), lambda: wipe(FVC["cold"])),
        "fv_steady": fv("steady", {"FASTVOL_NO_SCAN_CACHE": "1"}),
        "fv_warm": fv("warm"),
    }[state]


def run(state, img, extra, plugin, cpu=None):
    argv, env_extra, pre = tool(state)
    if pre:
        pre()
    env = dict(base_env(), **env_extra)
    d = tempfile.mkdtemp(dir=WORK)
    so_p = tempfile.mktemp(dir=WORK, prefix="stdout.")
    pin = (lambda: os.sched_setaffinity(0, {cpu})) if cpu is not None else None
    with open(so_p, "wb") as so:
        t0 = time.perf_counter()
        p = subprocess.Popen(argv + ["-q", "-o", d, "-f", img] + extra + [plugin], stdout=so,
                             stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, env=env, preexec_fn=pin)
        _, status, ru = os.wait4(p.pid, 0)
        wall = time.perf_counter() - t0
    h, lines, first = hashlib.sha256(), 0, True
    with open(so_p, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            if first:
                first = False
                nl = blk.find(b"\n")
                blk = blk[nl + 1:] if nl >= 0 else b""
            h.update(blk)
            lines += blk.count(b"\n")
    shutil.rmtree(d, ignore_errors=True)
    os.remove(so_p)
    return {"state": state, "plugin": plugin, "cpu_pin": cpu, "wall": wall, "cpu": ru.ru_utime + ru.ru_stime,
            "maxrss_mb": ru.ru_maxrss / 1024, "rc": os.waitstatus_to_exitcode(status), "sha": h.hexdigest()[:16],
            "lines": lines, "t": time.time(), "load1": os.getloadavg()[0]}


def page_in(img):
    with open(img, "rb") as f:
        while f.read(64 << 20):
            pass


def evict(img):
    fd = os.open(img, os.O_RDONLY)
    try:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    finally:
        os.close(fd)


def done_plugins(name):
    """Plugins of round `name` with runs of every state in raw.jsonl (for --resume)."""
    seen = {}
    if os.path.exists(f"{OUT}/raw.jsonl"):
        for l in open(f"{OUT}/raw.jsonl"):
            r = json.loads(l)
            if r.get("round") == name and "state" in r and not r.get("warmup"):
                seen.setdefault(r["plugin"], set()).add(r["state"])
    return {p for p, st in seen.items() if st >= {"py", "vr_cold", "vr_warm", "fv_cold", "fv_steady", "fv_warm"}}


def drop_partial(name):
    """Remove the rows of round `name`'s incomplete plugins (an interrupted run) from raw.jsonl."""
    done = done_plugins(name)
    keep = []
    for l in open(f"{OUT}/raw.jsonl"):
        r = json.loads(l)
        if r.get("round") == name and "plugin" in r and r["plugin"] not in done:
            continue
        keep.append(l)
    with open(f"{OUT}/raw.jsonl", "w") as f:
        f.writelines(keep)


def python_pool(name, img, extra, plugins, raw, control_round=None, controls=()):
    """python for `plugins` (and `controls`, logged as `control_round`), PY_PAR at a time, pinned."""
    import queue, threading
    jobs = queue.Queue()
    for p in plugins:
        jobs.put((name, p))
    for p in controls:
        jobs.put((control_round, p))
    lock = threading.Lock()

    def worker(cpu):
        while True:
            try:
                rnd, p = jobs.get_nowait()
            except queue.Empty:
                return
            for i in range(PY_RUNS):
                r = dict(run("py", img, extra, p, cpu=cpu), round=rnd, i=i, py_par=PY_PAR)
                with lock:
                    raw.write(json.dumps(r) + "\n")
                    raw.flush()
                    log(f"{rnd} py {p}: {r['wall']:.2f}s (cpu {cpu})")

    threads = [threading.Thread(target=worker, args=(c,)) for c in PY_CPUS]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def plugin_round(name, img, extra, plugins, raw, controls=()):
    if RESUME:
        drop_partial(name)
        done = done_plugins(name)
        plugins = [p for p in plugins if p not in done]
    log(f"== {name}: {len(plugins)} plugins" + (f" (python {PY_PAR} at a time, pinned)" if PY_PAR > 1 else ""))
    if not plugins:
        return
    page_in(img)
    raw.write(json.dumps({"py_warmup": run("py", img, extra, plugins[0])}) + "\n")  # python caches warm
    states = ["fv_cold", "fv_steady", "fv_warm", "vr_cold", "vr_warm"] + (["py"] if PY_PAR <= 1 else [])
    for k, plugin in enumerate(plugins):
        for s in ("fv_steady", "fv_warm", "vr_warm"):  # untimed warm-ups
            raw.write(json.dumps(dict(run(s, img, extra, plugin), warmup=True, round=name)) + "\n")
        res = []
        for i in range(max(RUNS, VR_RUNS, PY_RUNS)):
            for s in states:
                n = PY_RUNS if s == "py" else VR_RUNS if s.startswith("vr") else RUNS
                if i < n:
                    r = dict(run(s, img, extra, plugin), round=name, i=i)
                    raw.write(json.dumps(r) + "\n")
                    res.append(r)
        raw.flush()
        med = {s: statistics.median(r["wall"] for r in res if r["state"] == s) for s in {r["state"] for r in res}}
        log(f"{name} {k + 1}/{len(plugins)} {plugin}: " + (f"py {med['py']:.2f}s  " if "py" in med else "") +
            f"vr {med['vr_cold'] * 1e3:.0f}/{med['vr_warm'] * 1e3:.0f}ms  "
            f"fv {med['fv_cold'] * 1e3:.0f}/{med['fv_steady'] * 1e3:.1f}/{med['fv_warm'] * 1e3:.1f}ms")
    if PY_PAR > 1:
        page_in(img)
        python_pool(name, img, extra, plugins, raw, f"{name}_control", controls)


def triage_round(name, img, extra, plugins, raw):
    """Sessions: `plugins` in a row. first = the tool's cache empty at the start, second = warm."""
    log(f"== triage {name}: {len(plugins)} plugins per session")
    tools = {"fv": ([FV], lambda: wipe(FVC["cold"]), dict(FASTVOL_CACHE=FVC["cold"])),
             "vr": ([VR], lambda: wipe(f"{CACHE}/vol-rs", keep=("pdb",)), {}),
             "py": (PY, None, {})}
    for disk in ("cached", "evicted"):
        for rep in range(T_RUNS):
            for t, (argv, reset, env_extra) in tools.items():
                if t == "py" and rep >= T_PY_RUNS:
                    continue
                for session in ("first", "second"):
                    if session == "first" and reset:
                        reset()
                    page_in(img) if disk == "cached" else evict(img)
                    env = dict(base_env(), **env_extra)
                    walls, rcs, shas = [], [], []
                    t0 = time.perf_counter()
                    for plugin in plugins:
                        d = tempfile.mkdtemp(dir=WORK)
                        s0 = time.perf_counter()
                        p = subprocess.run(argv + ["-q", "-o", d, "-f", img] + extra + [plugin], stdout=subprocess.PIPE,
                                           stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, env=env)
                        walls.append(time.perf_counter() - s0)
                        rcs.append(p.returncode)
                        shas.append(hashlib.sha256(p.stdout.split(b"\n", 1)[-1]).hexdigest()[:16])
                        shutil.rmtree(d, ignore_errors=True)
                    total = time.perf_counter() - t0
                    r = {"triage": name, "tool": t, "session": session, "disk": disk, "rep": rep, "total": total,
                         "walls": walls, "rcs": rcs, "shas": shas, "t": time.time(), "load1": os.getloadavg()[0]}
                    raw.write(json.dumps(r) + "\n")
                    raw.flush()
                    log(f"triage {name} {disk} rep{rep} {t} {session}: {total:.2f}s")


def startup_round(raw):
    log("== startup: windows.pslist.PsList")
    page_in(WIN_IMG)
    for i in range(10):
        for s in ("fv_cold", "fv_warm", "vr_cold", "vr_warm") + (("py",) if i < 3 else ()):
            raw.write(json.dumps(dict(run(s, WIN_IMG, [], "windows.pslist.PsList"), round="startup", i=i)) + "\n")
        raw.flush()


def plugin_list(os_name):
    rows = [l.split("\t")[0] for l in open(f"{ROOT}/bench/vm/raw3/{os_name}.tsv")][1:]
    return rows[:NPLUG] if NPLUG else rows


def main():
    os.makedirs(OUT, exist_ok=True)
    provision()
    info = machine()
    if RESUME and os.path.exists(f"{OUT}/machine.json"):  # keep the first start's record
        first = json.load(open(f"{OUT}/machine.json"))
        info = dict(first, resumed=info["date"], load1_resume=info["load1_start"])
    with open(f"{OUT}/machine.json", "w") as f:
        json.dump(info, f, indent=1)
    log("machine:", json.dumps(info))
    with open(f"{OUT}/raw.jsonl", "a") as raw:
        if "startup" in ONLY:
            startup_round(raw)
        if "triage" in ONLY:
            cut = (lambda l: l[:NPLUG]) if NPLUG else (lambda l: l)
            triage_round("windows", WIN_IMG, [], cut(WIN_TRIAGE), raw)
            triage_round("linux", LNX_IMG, ["-s", ISF_DIR], cut(LNX_TRIAGE), raw)
        if "win" in ONLY:
            # control plugins, timed alone in the first part of the round (python several seconds each)
            ctl = ["windows.handles.Handles", "windows.filescan.FileScan", "windows.dlllist.DllList",
                   "windows.envars.Envars", "windows.cmdline.CmdLine", "windows.getsids.GetSIDs"]
            plugin_round("windows", WIN_IMG, [], plugin_list("win"), raw, controls=ctl if PY_PAR > 1 else ())
        if "linux" in ONLY:
            plugin_round("linux", LNX_IMG, ["-s", ISF_DIR], plugin_list("linux"), raw)
    info["load1_end"] = os.getloadavg()[0]
    info["finished"] = time.strftime("%Y-%m-%d %H:%M %Z")
    with open(f"{OUT}/machine.json", "w") as f:
        json.dump(info, f, indent=1)
    log("done")


if __name__ == "__main__":
    main()
