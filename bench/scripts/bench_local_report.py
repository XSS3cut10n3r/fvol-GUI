#!/usr/bin/env python3
"""Report of a bench_local.py run: bench/local/BENCHMARKS.md, results.tsv, summary.json (read by
docs/assets/build.py for the README chart) and a copy of the raw data.

Usage: bench_local_report.py RUN_DIR [DEST=bench/local]

Every figure is a median over a tool's runs (python: 1 run per plugin in the all-plugins rounds,
2 per triage session). Speedups are per plugin (python median / fastvol median) and summarized by
their geometric mean, median and spread, which, unlike a sum, is not dominated by the few slowest
plugins.
"""
import json, math, os, shutil, statistics, sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RUN = os.path.abspath(sys.argv[1])
DEST = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else f"{ROOT}/bench/local"

STATES = ["py", "vr_cold", "vr_warm", "fv_cold", "fv_steady", "fv_warm"]
LABEL = {"py": "python", "vr_cold": "vol-rs cold", "vr_warm": "vol-rs warm", "fv_cold": "fastvol cold",
         "fv_steady": "fastvol steady", "fv_warm": "fastvol warm"}
# python's own output order varies between runs / machines for these (docs/differences.md)
UNORDERED = {"frameworkinfo.FrameworkInfo": "python lists components in readdir order",
             "windows.windows.Windows": "python iterates a set: its row order changes run to run",
             "timeliner.Timeliner": "python's timeline depends on plugin discovery (readdir) order"}

rows = [json.loads(l) for l in open(f"{RUN}/raw.jsonl")]
machine = json.load(open(f"{RUN}/machine.json"))


def med(v):
    return statistics.median(v) if v else float("nan")


def gmean(v):
    return math.exp(sum(math.log(x) for x in v) / len(v)) if v else float("nan")


def pct(v, q):
    s = sorted(v)
    return s[min(len(s) - 1, max(0, round(q * (len(s) - 1))))] if s else float("nan")


def t(s):
    """seconds -> '4.07 s' / '22.8 ms' / '0.61 ms'"""
    if s != s:
        return "-"
    if s >= 100:
        return f"{s:,.0f} s"
    if s >= 1:
        return f"{s:.2f} s"
    ms = s * 1e3
    return f"{ms:.0f} ms" if ms >= 100 else f"{ms:.1f} ms" if ms >= 1 else f"{ms:.2f} ms"


def x(r):
    if r != r:
        return "-"
    return f"{r:,.0f}x" if r >= 100 else f"{r:.1f}x" if r >= 10 else f"{r:.2f}x"


# ---- all-plugins rounds: per plugin, per state
plug = {}
for r in rows:
    if "state" in r and not r.get("warmup") and r.get("round") in ("windows", "linux"):
        plug.setdefault((r["round"], r["plugin"]), {}).setdefault(r["state"], []).append(r)
order = {}
for r in rows:
    if "state" in r and r.get("round") in ("windows", "linux"):
        order.setdefault(r["round"], [])
        if r["plugin"] not in order[r["round"]]:
            order[r["round"]].append(r["plugin"])


def summarize(rnd):
    names = [p for p in order.get(rnd, []) if all(s in plug.get((rnd, p), {}) for s in STATES)]
    medians = {p: {s: med([r["wall"] for r in plug[(rnd, p)][s]]) for s in STATES} for p in names}
    out = {"plugins": len(names), "total": {s: sum(medians[p][s] for p in names) for s in STATES},
           "median": {s: med([medians[p][s] for p in names]) for s in STATES},
           "cpu": {s: sum(med([r["cpu"] for r in plug[(rnd, p)][s]]) for p in names) for s in STATES}}
    sp = {}
    for fv, other in (("fv_cold", "py"), ("fv_steady", "py"), ("fv_warm", "py"),
                      ("fv_cold", "vr_cold"), ("fv_steady", "vr_warm"), ("fv_warm", "vr_warm")):
        v = [medians[p][other] / medians[p][fv] for p in names]
        sp[f"{fv}/{other}"] = {"geomean": gmean(v), "median": med(v), "p10": pct(v, 0.1), "p90": pct(v, 0.9),
                               "min": min(v), "max": max(v), "min_plugin": names[v.index(min(v))],
                               "max_plugin": names[v.index(max(v))], "slower": sum(1 for y in v if y < 1),
                               "total": out["total"][other] / out["total"][fv]}
    out["speedup"] = sp
    # output equality with python: every timed run of the state printed python's output
    eq = {}
    for p in names:
        py = {r["sha"] for r in plug[(rnd, p)]["py"]}
        eq[p] = {s: all(r["sha"] in py for r in plug[(rnd, p)][s]) for s in STATES if s != "py"}
    out["equal"] = {s: sum(eq[p][s] for p in names) for s in STATES if s != "py"}
    out["not_equal"] = {s: [p for p in names if not eq[p][s]] for s in ("fv_cold", "fv_steady", "fv_warm")}
    return out, medians, eq


# ---- triage sessions
tri = {}
for r in rows:
    if "triage" in r:
        tri.setdefault((r["triage"], r["disk"], r["session"], r["tool"]), []).append(r)


def triage(os_name, disk, session, tool):
    v = tri.get((os_name, disk, session, tool), [])
    return med([r["total"] for r in v]), len(v), all(all(c == 0 for c in r["rcs"]) for r in v)


# ---- startup
st = {}
for r in rows:
    if r.get("round") == "startup":
        st.setdefault(r["state"], []).append(r["wall"])

# python run in parallel (bench_local.py --py-par): which plugins, and what it cost on the controls
par = {}
for r in rows:
    if r.get("state") == "py" and r.get("py_par", 1) > 1 and r.get("round") in ("windows", "linux"):
        par.setdefault(r["round"], set()).add(r["plugin"])
ctl = {}
for r in rows:
    if r.get("state") == "py" and str(r.get("round", "")).endswith("_control"):
        ctl.setdefault(r["plugin"], []).append(r["wall"])
control = {}
for p_, walls in ctl.items():
    solo = [r["wall"] for r in plug.get(("windows", p_), {}).get("py", []) if r.get("py_par", 1) <= 1]
    if solo:
        control[p_] = {"solo": med(solo), "parallel": med(walls), "ratio": med(walls) / med(solo)}
vr_runs = {}
for (rnd, p_), stt in plug.items():
    vr_runs.setdefault(rnd, set()).add(len(stt.get("vr_cold", [])))

summary = {"machine": machine, "rounds": {}, "triage": {}, "startup": {s: med(v) for s, v in st.items()},
           "py_parallel": {k: sorted(v) for k, v in par.items()},
           "py_parallel_control": {"plugins": control, "ratio_median": med([c["ratio"] for c in control.values()]) if control else None},
           "vr_runs": {k: sorted(v) for k, v in vr_runs.items()}}
tables = {}
for rnd in ("windows", "linux"):
    if order.get(rnd):
        s, medians, eq = summarize(rnd)
        summary["rounds"][rnd] = s
        tables[rnd] = (medians, eq)
for os_name, n in (("windows", 12), ("linux", 10)):
    for disk in ("cached", "evicted"):
        for session in ("first", "second"):
            for tool in ("py", "vr", "fv"):
                m, runs, ok = triage(os_name, disk, session, tool)
                if runs:
                    summary["triage"].setdefault(os_name, {}).setdefault(disk, {}).setdefault(session, {})[tool] = {
                        "total": m, "runs": runs, "all_ok": ok}
    tl = [r for r in rows if r.get("triage") == os_name]
    if tl:
        summary["triage"][os_name]["plugins"] = len(tl[0]["walls"])

# ---- write
os.makedirs(f"{DEST}/raw", exist_ok=True)
for f in ("raw.jsonl", "machine.json"):
    shutil.copy2(f"{RUN}/{f}", f"{DEST}/raw/{f}")
with open(f"{DEST}/summary.json", "w") as f:
    json.dump(summary, f, indent=1, default=float)
with open(f"{DEST}/results.tsv", "w") as f:
    f.write("round\tplugin\t" + "\t".join(f"{s}_median_s" for s in STATES) + "\t" +
            "\t".join(f"{s}_eq_py" for s in STATES if s != "py") + "\n")
    for rnd, (medians, eq) in tables.items():
        for p, m in medians.items():
            f.write(f"{rnd}\t{p}\t" + "\t".join(f"{m[s]:.6f}" for s in STATES) + "\t" +
                    "\t".join(str(int(eq[p][s])) for s in STATES if s != "py") + "\n")

M = machine


def storage(v):
    """'btrfs on crypt, disk  Micron 2200S NVMe 1024GB, part' -> 'btrfs on LUKS (dm-crypt) on a Micron 2200S NVMe 1024GB'"""
    fs, _, stack = v.partition(" on ")
    disk = next((p.split(None, 1)[1] for p in stack.split(", ") if p.startswith("disk") and len(p.split(None, 1)) > 1), "")
    return f"{fs} on {'LUKS (dm-crypt) on ' if 'crypt' in stack else ''}{'a ' + disk if disk else stack}"


def window():
    """The date and the time span of the timed runs (from their timestamps)."""
    import time as _t
    ts = [r["t"] for r in rows if "t" in r]
    if not ts:
        return M["date"]
    a, b = _t.localtime(min(ts)), _t.localtime(max(ts))
    return _t.strftime("%Y-%m-%d %H:%M", a) + _t.strftime("–%H:%M %Z", b)


L = []
L += ["# fastvol vs vol-rs vs python volatility3: benchmark", "",
      f"Measured {window()} on this machine (a desktop, not a dedicated server):", "",
      "| | |", "|---|---|",
      f"| CPU | {M['cpu']}: {M['cores']} cores / {M['cpus']} threads (8 performance + 4 efficiency cores), up to {float(M['max_mhz']) / 1000:.1f} GHz, governor `{M['governor']}` |",
      f"| Memory | {M['mem_gib']:.0f} GiB |",
      f"| Storage | {storage(M['storage'])} |",
      f"| OS | {M['os']}, Linux {M['kernel']} |",
      f"| Load | load average {M['load1_start']:.1f} at the start, {M.get('load1_end', float('nan')):.1f} at the end (our own runs included) |",
      f"| fastvol | commit {M['fastvol'].split()[0]}, binary sha256 `{M['fastvol'].split()[1]}…`, {M['fastvol_rustc']}, `target-cpu=native` (the repo's default build) |",
      f"| vol-rs | {M['volrs'].rsplit(' ', 1)[0]}, binary sha256 `{M['volrs'].rsplit(' ', 1)[1]}…` (the build benchmarked on the VM) |",
      f"| python | {M['python']} with capstone, yara-python, pycryptodome |",
      f"| Images | Windows 11 x64 raw, {M['win_image'].split('(')[-1].rstrip(')')}; Ubuntu 24.04 Linux 6.8 ELF core, {M['linux_image'].split('(')[-1].rstrip(')')} |",
      "",
      "## How it was measured", "",
      "- Every run is one process (`TOOL -q -o DIR -f IMAGE PLUGIN`, output to a file), timed from start to exit; runs are sequential, never two at once.",
      "- **Figures are medians** of each tool's runs: fastvol 5 runs, vol-rs 3, python 1 per plugin (2 per triage session). A median does not favour the tool with more runs the way a best-of does.",
      "- Each tool has its own caches (python's and vol-rs's symbol files were provisioned once; nothing downloads during the runs). The cache states:",
      "  - **python**: warm (ISFs and identifier cache present). A first-ever python run would also download and convert the PDB; that is not measured.",
      "  - **vol-rs cold / warm**: its cache deleted before every run (except downloaded PDBs) / as the previous run left it.",
      "  - **fastvol cold**: its whole cache deleted before every run (symbol tables, identifier index, automagic results, scan results).",
      "  - **fastvol steady**: symbol caches warm, **scan-result cache off**: every scan is really done. This is the like-for-like comparison with python's warm runs.",
      "  - **fastvol warm**: every cache warm, including the per-image scan cache: scan results are replayed, not recomputed. What a user sees when re-running a plugin, but not the same work as python.",
      "- The images are in the page cache unless a table says *evicted* (dropped with `posix_fadvise(DONTNEED)`, so they are read from the NVMe drive).", ""]
pp = summary["py_parallel"]
if pp:
    cr = summary["py_parallel_control"]
    L += ["- **python, run in parallel for part of the all-plugins rounds** (to finish in minutes instead of hours): "
          + ", ".join(f"{len(v)} {k} plugins" for k, v in pp.items())
          + " ran 6 python processes at a time, each pinned to its own physical performance core, after that round's fastvol and vol-rs runs (never alongside them)."
          + ((f" Six control plugins timed both alone and in the pool took **{abs(cr['ratio_median'] - 1) * 100:.1f}% "
              f"{'longer' if cr['ratio_median'] > 1 else 'less time'}** (median) in the pool"
              + (", so those python times, and the speedups over them, are inflated by about that much."
                 if cr['ratio_median'] > 1.005 else ": running in parallel did not slow python down, the speedups are not inflated."))
             if cr["ratio_median"] else ""), ""]
if any(len(v) > 1 for v in summary["vr_runs"].values()):
    n3 = sum(1 for (rnd, p_), stt in plug.items() if len(stt.get("vr_cold", [])) >= 3)
    L += [f"- vol-rs: 3 runs per state for the first {n3} plugins, 1 run after the schedule was shortened (like python).", ""]

tr = summary["triage"]
if tr:
    L += ["## Triage session (the realistic case)", "",
          "A first look at an image: the common plugins run one after another, as an analyst would. **first** = the tool's cache empty at the start (it fills as the session goes), **second** = the same session again. Python's caches are always warm.", ""]
    for os_name, plugs in (("windows", "info, pslist, pstree, psscan, cmdline, dlllist, netscan, modules, getsids, handles, filescan, hivelist"),
                           ("linux", "pslist, pstree, psaux, bash, lsmod, sockstat, lsof, malfind, elfs, check_syscall")):
        if os_name not in tr:
            continue
        L += [f"**{os_name.capitalize()}** ({tr[os_name].get('plugins', '?')} plugins: {plugs})", "",
              "| image | session | python | vol-rs | fastvol | fastvol vs python | fastvol vs vol-rs |", "|---|---|--:|--:|--:|--:|--:|"]
        for disk in ("cached", "evicted"):
            for session in ("first", "second"):
                c = tr[os_name].get(disk, {}).get(session, {})
                if not c:
                    continue
                py, vr, fv = (c.get(k, {}).get("total", float("nan")) for k in ("py", "vr", "fv"))
                L.append(f"| {'in page cache' if disk == 'cached' else 'evicted (read from disk)'} | {session} | {t(py)} | {t(vr)} | **{t(fv)}** | {x(py / fv)} | {x(vr / fv)} |")
        L.append("")

for rnd, n_label in (("windows", "Windows 11"), ("linux", "Linux 6.8")):
    if rnd not in summary["rounds"]:
        continue
    s = summary["rounds"][rnd]
    note = {"linux": " On Linux python spends most of each run decompressing and parsing the kernel's symbol file (3.3 MB xz, 61.5 MB of JSON) (its median plugin takes 10.6 s); fastvol keeps a binary symbol table in its cache, which the steady and warm states use. **fastvol cold** rebuilds everything each run and is the comparison with no fastvol cache at all."}.get(rnd, "")
    L += [f"## Every plugin once: {n_label}, {s['plugins']} plugins", "",
          "Sums answer \"how long to run every plugin once\"; they are dominated by the few slowest plugins. The per-plugin speedups below them show the spread." + note, "",
          "| | " + " | ".join(LABEL[x_] for x_ in STATES) + " |", "|---|" + "--:|" * len(STATES),
          "| total (sum of per-plugin medians) | " + " | ".join(t(s["total"][x_]) for x_ in STATES) + " |",
          "| median plugin | " + " | ".join(t(s["median"][x_]) for x_ in STATES) + " |",
          "| total CPU (user + sys) | " + " | ".join(t(s["cpu"][x_]) for x_ in STATES) + " |", "",
          "| per-plugin speedup | geometric mean | median | 10th pct | 90th pct | slowest | fastest | plugins slower | sum ratio |",
          "|---|--:|--:|--:|--:|--:|--:|--:|--:|"]
    for key, label in (("fv_cold/py", "fastvol cold vs python"), ("fv_steady/py", "fastvol steady vs python"),
                       ("fv_warm/py", "fastvol warm vs python"), ("fv_cold/vr_cold", "fastvol cold vs vol-rs cold"),
                       ("fv_steady/vr_warm", "fastvol steady vs vol-rs warm"), ("fv_warm/vr_warm", "fastvol warm vs vol-rs warm")):
        v = s["speedup"][key]
        L.append(f"| {label} | **{x(v['geomean'])}** | {x(v['median'])} | {x(v['p10'])} | {x(v['p90'])} | {x(v['min'])} ({v['min_plugin'].split('.')[-2]}) | {x(v['max'])} ({v['max_plugin'].split('.')[-2]}) | {v['slower']} | {x(v['total'])} |")
    L += ["", f"Output identical to python in every timed run: fastvol cold {s['equal']['fv_cold']}/{s['plugins']}, steady {s['equal']['fv_steady']}/{s['plugins']}, warm {s['equal']['fv_warm']}/{s['plugins']}; vol-rs cold {s['equal']['vr_cold']}/{s['plugins']}, warm {s['equal']['vr_warm']}/{s['plugins']}."]
    ne = s["not_equal"]["fv_steady"]
    if ne:
        L.append("fastvol's differences: " + "; ".join(f"`{p}` ({UNORDERED.get(p, 'see results.tsv')})" for p in ne) + ".")
    L.append("")

if summary["startup"]:
    S = summary["startup"]
    L += ["## Startup: `windows.pslist.PsList`", "", "| | python | vol-rs cold | vol-rs warm | fastvol cold | fastvol warm |", "|---|--:|--:|--:|--:|--:|",
          f"| median of 10 (python 3) | {t(S.get('py', float('nan')))} | {t(S.get('vr_cold', float('nan')))} | {t(S.get('vr_warm', float('nan')))} | {t(S.get('fv_cold', float('nan')))} | {t(S.get('fv_warm', float('nan')))} |", ""]

L += ["## Per plugin (medians)", ""]
for rnd, (medians, eq) in tables.items():
    L += [f"**{rnd}**", "", "| plugin | " + " | ".join(LABEL[x_] for x_ in STATES) + " | steady vs python |", "|---|" + "--:|" * (len(STATES) + 1)]
    for p, m in medians.items():
        L.append(f"| `{p}` | " + " | ".join(t(m[x_]) for x_ in STATES) + f" | {x(m['py'] / m['fv_steady'])} |")
    L.append("")
L += ["Raw data: [raw/raw.jsonl](raw/raw.jsonl) (every run), [raw/machine.json](raw/machine.json), [results.tsv](results.tsv). Harness: `bench/scripts/bench_local.py`; this report: `bench/scripts/bench_local_report.py`. Earlier runs on a dedicated VM: [../vm/BENCHMARKS.md](../vm/BENCHMARKS.md).", ""]
with open(f"{DEST}/BENCHMARKS.md", "w") as f:
    f.write("\n".join(L))
print(f"wrote {DEST}/BENCHMARKS.md, summary.json, results.tsv")
