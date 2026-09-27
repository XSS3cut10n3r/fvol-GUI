#!/usr/bin/env python3
"""Build bench/vm/BENCHMARKS.md + results3.tsv from the pass-3 result files (adapted from report2.py).
Usage: `cd bench/vm && python3 scripts/report3.py raw3 raw2 raw .`
raw3/ holds win.tsv, linux.tsv, startup.tsv, load.log (bench2_vm.py with --py-ref/--vr-ref, startup2_vm.py;
only the three fastvol columns were run, python and vol-rs are the runs of passes 1 and 2) and the hand-written
meta3.env, notes3.tsv, checks3.md, notfastest.md, startup_note.md; raw2/ is pass 2 (rsvol 95528b2: the
"Changes since pass 2" section, the startup rows, which python times pass 2 ran again); raw/ is run 1
(vol-rs's run-1 times: the run-to-run noise yardstick)."""
import math, os, statistics, sys

D3, D2, D1 = sys.argv[1], sys.argv[2], sys.argv[3]
OUT = sys.argv[4] if len(sys.argv) > 4 else "."


def load(d, name):
    p = os.path.join(d, name)
    if not os.path.exists(p):
        return []
    rows = [l.rstrip("\n").split("\t") for l in open(p) if l.strip()]
    return [dict(zip(rows[0], r)) for r in rows[1:]]


def text(name):
    p = os.path.join(D3, name)
    return open(p).read().rstrip("\n").split("\n") if os.path.exists(p) else []


meta = dict(l.rstrip("\n").split("=", 1) for l in open(os.path.join(D3, "meta3.env")) if "=" in l)
notes = {(r["os"], r["plugin"]): r for r in load(D3, "notes3.tsv")}
pass2 = {"windows": {r["plugin"]: r for r in load(D2, "win.tsv")},
         "linux": {r["plugin"]: r for r in load(D2, "linux.tsv")}}
run1 = {"windows": {r["plugin"]: r for r in load(D1, "win_pass2.tsv")},
        "linux": {r["plugin"]: r for r in load(D1, "linux.tsv")}}

COLS = ["py", "vr_cold", "vr_warm", "rs_cold", "rs_steady", "rs_warm"]
LABEL = {"py": "python", "vr_cold": "vol-rs cold", "vr_warm": "vol-rs warm", "rs_cold": "fastvol cold",
         "rs_steady": "fastvol steady", "rs_warm": "fastvol warm"}
RS = ["rs_cold", "rs_steady", "rs_warm"]
PEER = {"rs_cold": "vr_cold", "rs_steady": "vr_warm", "rs_warm": "vr_warm"}  # like-for-like vol-rs column
NOISE_RATIO, NOISE_ABS = 1.10, 0.001  # a pass-3 time counts as a regression above 1.10x AND +1 ms of pass 2's


def fs(x):
    return f"{x:.2f} s" if x >= 1 else f"{x*1000:.0f} ms" if x >= 0.1 else f"{x*1000:.1f} ms"


def fx(x):
    if x < 1:
        return f"{x:.2f}x"
    return f"{x:,.0f}x" if x >= 100 else f"{x:.1f}x" if x >= 10 else f"{x:.2f}x"


def gmean(xs):
    return math.exp(sum(math.log(x) for x in xs) / len(xs))


def pct(xs, q):
    s = sorted(xs)
    return s[min(len(s) - 1, int(q * len(s)))]


def rows_of(osname, fname):
    out = []
    for a in load(D3, fname):
        n = notes.get((osname, a["plugin"]), {})
        p2 = pass2[osname][a["plugin"]]
        r = dict(os=osname, plugin=a["plugin"], py_src="pass2" if p2["py_src"] == "fresh" else "pass1",
                 py_n=a["py_n"], load=a["load1"], flag=n.get("flag", ""), note=n.get("note", ""),
                 change=n.get("change", ""), consistent=a["rs_consistent"],
                 files_py=a["files_mb_py"], files_rs=a["files_mb_rs"], files_vr=a["files_mb_vr"])
        for t in COLS:
            r[t] = float(a[f"{t}_wall"])
            r[t + "_med"] = float(a[f"{t}_med"])
            r[t + "_cpu"] = float(a[f"{t}_cpu"])
            r[t + "_rss"] = a[f"{t}_rss_mb"]
            r[t + "_rc"] = a[f"{t}_rc"]
            r[t + "_lines"] = a[f"{t}_lines"]
            if t != "py":
                r[t + "_eq"] = a[f"{t}_eq_py"]
        for t in RS:
            r[t + "_p2"] = float(p2[f"{t}_wall"])
        o = run1[osname].get(a["plugin"])
        r["vr_run1"] = float(o["volrs_wall"]) if o else None
        out.append(r)
    return out


win = rows_of("windows", "win.tsv")
lin = rows_of("linux", "linux.tsv")


def rs_eq(r):
    """fastvol's output check: all three fastvol columns share the verdict when rs_consistent=1."""
    if all(r[t + "_eq"] == "1" for t in RS):
        return "yes"
    return {"order": "sorted =", "refmachine": "= ref machine", "sorted": "sorted =",
            "rerun": "= py rerun"}.get(r["flag"], "**no**")


def vr_eq(r):
    c, w = r["vr_cold_eq"], r["vr_warm_eq"]
    return "yes" if c == w == "1" else "**no**"


def best_other(r, t):
    """Fastest measurement of the other tools (python, both vol-rs columns)."""
    return min(r["py"], r["vr_cold"], r["vr_warm"])


def headline(rows, label):
    n = len(rows)
    L = [f"| {label} ({n} plugins) | " + " | ".join(LABEL[t] for t in COLS) + " |",
         "|---|" + "---:|" * len(COLS)]
    L.append("| total wall (sum of per-plugin best) | " + " | ".join(fs(sum(r[t] for r in rows)) for t in COLS) + " |")
    L.append("| total CPU (user+sys) | " + " | ".join(fs(sum(r[t + "_cpu"] for r in rows)) for t in COLS) + " |")
    L.append("| median plugin wall | " + " | ".join(fs(statistics.median(r[t] for r in rows)) for t in COLS) + " |")
    L.append("| geometric mean plugin wall | " + " | ".join(fs(gmean([r[t] for r in rows])) for t in COLS) + " |")
    cells = []
    for t in COLS:
        if t.startswith("rs"):
            k = sum(1 for r in rows if r[t] < best_other(r, t))
            cells.append(f"**{k}/{n}**")
        else:
            others = [c for c in COLS if c != t and not (c.startswith("vr") and t.startswith("vr"))]
            k = sum(1 for r in rows if all(r[t] < r[c] for c in others))
            cells.append(f"{k}/{n}")
    L.append("| fastest on¹ | " + " | ".join(cells) + " |")
    cells = []
    for t in COLS:
        if t in PEER:
            p = PEER[t]
            k = sum(1 for r in rows if r[t] < r[p])
            cells.append(f"{k}/{n} vs {LABEL[p]}")
        else:
            cells.append("")
    L.append("| faster than the like-for-like vol-rs column on | " + " | ".join(cells) + " |")
    cells = []
    for t in COLS:
        if t in PEER:
            p = PEER[t]
            cells.append(f"{fx(sum(r[p] for r in rows) / sum(r[t] for r in rows))} / {fx(gmean([r[p] / r[t] for r in rows]))}")
        else:
            cells.append("")
    L.append("| speedup vs like-for-like vol-rs: total / geo-mean | " + " | ".join(cells) + " |")
    cells = []
    for t in COLS:
        if t.startswith("rs"):
            cells.append(f"{fx(sum(r['py'] for r in rows) / sum(r[t] for r in rows))} / {fx(gmean([r['py'] / r[t] for r in rows]))}")
        else:
            cells.append("")
    L.append("| speedup vs python: total / geo-mean | " + " | ".join(cells) + " |")
    return L


def detail(rows):
    L = []
    for t in RS:
        p = PEER[t]
        sv = [r[p] / r[t] for r in rows]
        sp = [r["py"] / r[t] for r in rows]
        L.append(f"- **{LABEL[t]}** vs {LABEL[p]}: median {fx(statistics.median(sv))}, geo-mean {fx(gmean(sv))}, "
                 f"min {fx(min(sv))}, max {fx(max(sv))}; vs python: median {fx(statistics.median(sp))}, "
                 f"geo-mean {fx(gmean(sp))}, min {fx(min(sp))}, max {fx(max(sp))}")
    for t in RS:
        slow = [r for r in rows if r[t] >= best_other(r, t)]
        who = lambda r: ("vol-rs warm" if best_other(r, t) == r["vr_warm"] else
                         "vol-rs cold" if best_other(r, t) == r["vr_cold"] else "python")
        if not slow:
            L.append(f"- {LABEL[t]} is the fastest on every plugin")
        elif len(slow) <= 12:
            L.append(f"- {LABEL[t]} is not the fastest on {len(slow)}: " + ", ".join(
                f"`{r['plugin']}` ({fs(r[t])} vs {who(r)} {fs(best_other(r, t))})" for r in slow))
        else:
            gap = [r[t] - best_other(r, t) for r in slow]
            L.append(f"- {LABEL[t]} is not the fastest on {len(slow)} (behind {', '.join(sorted(set(who(r) for r in slow)))} "
                     f"by {fs(min(gap))} to {fs(max(gap))}, median {fs(statistics.median(gap))}; every plugin is in "
                     f"the per-plugin table)")
    ne = [r for r in rows if rs_eq(r) != "yes"]
    L.append(f"- fastvol stdout byte-identical to python's recorded output (after the banner line) in every run of all "
             f"three columns: **{len(rows) - len(ne)}/{len(rows)}**" + (
                 " (the others: " + ", ".join(f"`{r['plugin']}` {rs_eq(r)}" for r in ne) + ", see Checks)" if ne else "")
             + f"; vol-rs (both columns, pass 2): {sum(1 for r in rows if vr_eq(r) == 'yes')}/{len(rows)}")
    inc = [r for r in rows if r["consistent"] != "1"]
    L.append(f"- the three fastvol columns printed the same stdout in all their runs on "
             f"{len(rows) - len(inc)}/{len(rows)} plugins" + (" (not: " + ", ".join(r["plugin"] for r in inc) + ")" if inc else
                                                                 " (the caches never change output)"))
    return L


def changes(rows, label):
    """Pass 2 -> pass 3 per fastvol column: totals, medians, geo-means, per-plugin wins and regressions."""
    n = len(rows)
    L = [f"| {label}, pass 2 → pass 3 ({n} plugins) | " + " | ".join(LABEL[t] for t in RS) + " |",
         "|---|" + "---:|" * len(RS)]
    for name, f in (("total wall", sum), ("median plugin wall", statistics.median), ("geometric mean plugin wall", gmean)):
        cells = []
        for t in RS:
            a, b = f([r[t + "_p2"] for r in rows]), f([r[t] for r in rows])
            cells.append(f"{fs(a)} → {fs(b)} ({fx(a / b)})")
        L.append(f"| {name} | " + " | ".join(cells) + " |")
    cells = []
    for t in RS:
        faster = sum(1 for r in rows if r[t] < r[t + "_p2"])
        cells.append(f"{faster} / {n - faster}")
    L.append("| plugins faster / not faster than in pass 2 | " + " | ".join(cells) + " |")
    L.append("")
    for t in RS:
        top = sorted(rows, key=lambda r: r[t + "_p2"] / r[t], reverse=True)[:4]
        L.append(f"- biggest wins, {LABEL[t]}: " + ", ".join(
            f"`{r['plugin']}` {fs(r[t + '_p2'])} → {fs(r[t])} ({fx(r[t + '_p2'] / r[t])})" for r in top))
    reg = [(r, t) for r in rows for t in RS
           if r[t] > r[t + "_p2"] * NOISE_RATIO and r[t] - r[t + "_p2"] > NOISE_ABS]
    if reg:
        for r, t in reg:
            L.append(f"- **regression beyond noise**, {LABEL[t]} `{r['plugin']}`: {fs(r[t + '_p2'])} → {fs(r[t])} "
                     f"({r[t] / r[t + '_p2']:.1f}x slower): {r['change'] or 'not investigated'}")
    else:
        L.append("- no regression beyond noise")
    small = sorted(((r, t) for r in rows for t in RS if r[t] > r[t + "_p2"] and (r, t) not in reg),
                   key=lambda rt: rt[0][rt[1]] / rt[0][rt[1] + "_p2"], reverse=True)
    if small:
        L.append(f"- slower within noise: {len(small)} of {3 * n} plugin-columns, the largest " + ", ".join(
            f"{LABEL[t]} `{r['plugin']}` {fs(r[t + '_p2'])} → {fs(r[t])}" for r, t in small[:3]))
    return L


def table(rows):
    L = ["| plugin | python | vol-rs cold | vol-rs warm | fastvol cold | fastvol steady | fastvol warm | "
         "steady vs vol-rs warm | steady vs pass 2 | fastvol out = py | vol-rs out = py | note |",
         "|---|---:|---:|---:|---:|---:|---:|---:|---:|:---:|:---:|---|"]
    for r in rows:
        cells = []
        best = min(r[t] for t in COLS)
        for t in COLS:
            s = fs(r[t])
            if t == "py" and r["py_src"] == "pass2":
                s += "†"
            cells.append(f"**{s}**" if r[t] == best else s)
        sv = r["vr_warm"] / r["rs_steady"]
        svs = fx(sv) if sv >= 1 else f"**{sv:.2f}x**"
        note = r["note"]
        rcs = [r[t + "_rc"] for t in ("py", "vr_warm", "rs_warm")]
        if any(x != "0" for x in rcs) and "exit" not in note:
            note = f"exit py/vol-rs/fastvol = {'/'.join(rcs)}" + ("; " + note if note else "")
        L.append(f"| {r['plugin']} | " + " | ".join(cells) + f" | {svs} | {fx(r['rs_steady_p2'] / r['rs_steady'])} | "
                 f"{rs_eq(r)} | {vr_eq(r)} | {note} |")
    return L


heavy = {"windows.statistics.Statistics", "timeliner.Timeliner"}
L = ["# fastvol vs vol-rs vs python volatility3 — quiet-VM benchmark (pass 3)", ""]
L.append(f"{meta['DATE']} · dedicated KVM guest: {meta['CPU']}, {meta['NCPU']} vCPU, {meta['MEM']} RAM, {meta['OS']}, "
         f"kernel {meta['KERNEL']}; nothing else running (see [machine.txt](machine.txt), [method.md](method.md#run-3)). "
         f"Earlier reports: [pass 2](BENCHMARKS-run2.md) (rsvol `{meta['RS_P2_COMMIT']}`), [run 1](BENCHMARKS-run1.md).")
L.append("")
L.append(f"- **fastvol** `{meta['RS_COMMIT']}` (binary `fvol`; the project was called rsvol until this commit), built on "
         f"the dev box with {meta['RUSTC']} and `RUSTFLAGS=\"{meta['RUSTFLAGS']}\"` plus the linker flags of "
         f"[docs/building.md](../../docs/building.md#build-for-other-machines), fat LTO, then copied to the VM; "
         f"sha256 {meta['RS_SHA']}. Pass 2 was built on the VM with `target-cpu=native`: the same Zen 2 instruction set.")
L.append(f"- **vol-rs** {meta['VOLRS_VER']}: the competitor's own release binary ({meta['VOLRS_COMMIT']}, generic x86-64). "
         "Its times and output hashes are pass 2's (same VM, same binary); it was not run again.")
L.append(f"- **python** volatility3 {meta['VOL3_VER']} on CPython {meta['PY_VER']} (PGO+LTO+BOLT build) with capstone, yara-python, "
         "pycryptodome: the reference whose output fastvol reproduces. Its times and output hashes are run 1's, or pass 2's "
         "where pass 2 ran python again (marked †); it was not run again for the plugin rounds.")
L.append("- Windows image: `memory-dirty.raw`, 5 GiB raw Windows 11 21H2 x64 (build 22000, `windows.info`: 15.22000); Linux image: `rsvol-noble-6.8.0-139.elf`, "
         "3 GiB, Ubuntu 24.04 kernel 6.8 (`-s` holding only its `.json.xz` ISF). Both page-cached.")
L.append("- Plugins: fastvol implements all 197 plugins of volatility3 2.28.2. The same lists as pass 2: Windows 77 plugins "
         "(generic + Windows, `statistics` and `timeliner` last); Linux 59 = every `linux.*` plugin that runs without "
         "arguments (57 of 60; not `vmayarascan`, `vmaregexscan`, `module_extract`) + `banners` + `timeliner`.")
L.append("")
L.append("Every number is the wall-clock time of a whole process (`TOOL -q -o DIR -f IMG PLUGIN`, stdout to a file), "
         "best of 5 interleaved runs for each fastvol column (pass 3) and each vol-rs column (pass 2), best of 2 runs for "
         "python on Windows (1 for statistics, timeliner and on Linux). The columns:")
L.append("")
L.append("| column | cache state before every timed run |")
L.append("|---|---|")
L.append("| **fastvol cold** | fastvol's whole cache directory (`FASTVOL_CACHE`) deleted: binary symbol tables, identifier "
         "index, automagic results, scan results — the first-ever run of fastvol on this image |")
L.append("| **fastvol steady** | symbol-table / identifier / automagic caches warm, the per-image scan cache disabled "
         "(`FASTVOL_NO_SCAN_CACHE=1`): the honest cost of a plugin's own work, every scan really done |")
L.append("| **fastvol warm** | every cache warm, incl. the scan cache: what a user sees on the 2nd+ run of a plugin |")
L.append("| **vol-rs cold** | `$XDG_CACHE_HOME/vol-rs` deleted (its parsed symbol files, per-image automagic results and "
         "banner index), except the PDB it downloaded from the Microsoft symbol server (so no timed run touches the network) |")
L.append("| **vol-rs warm** | vol-rs's cache as its previous run left it (vol-rs has no scan-result cache) |")
L.append("| **python** | run 1's warm runs (identifier cache warm), pass 2's for the plugins marked † |")
L.append("")
L.append("fastvol steady and fastvol warm are compared with vol-rs warm, fastvol cold with vol-rs cold (like for like); "
         "\"fastest on\" for a fastvol column counts the plugins where it beats python and **both** vol-rs columns. "
         "The fastest number of each row is bold in the per-plugin tables.")
L.append("")
L.append("## Headline")
L.append("")
L += headline(win, "Windows")
L.append("")
L += headline(lin, "Linux")
L.append("")
L.append("¹ for a fastvol column: the plugins where it beats python and both vol-rs columns; for vol-rs and python: "
         "the plugins where that column beats all three fastvol columns and the remaining tool.")
L.append("")
L += text("notfastest.md")
L.append("")
L.append(f"## Changes since pass 2 (rsvol `{meta['RS_P2_COMMIT']}` → fvol `{meta['RS_COMMIT']}`)")
L.append("")
L.append(meta["OPT_PASS"])
L.append("")
L.append(f"Same VM, images, plugin lists and procedure (the build differs, see above). A per-plugin time counts as a regression when it is more than "
         f"{NOISE_RATIO:.2f}x **and** more than {NOISE_ABS * 1000:.0f} ms above pass 2's: between run 1 and pass 2, "
         f"vol-rs's warm times (same binary) stayed within 0.94-1.05x for 80% of the plugins (10th-90th percentile, "
         f"see Checks); the 1 ms floor keeps the smallest plugins' timer-level jitter out.")
L.append("")
L += changes(win, "Windows")
L.append("")
L += changes(lin, "Linux")
L.append("")
L.append("## Windows summary")
L.append("")
L += detail(win)
L.append("")
L += headline([r for r in win if r["plugin"] not in heavy], "Windows without statistics / timeliner")
L.append("")
L.append("## Linux summary")
L.append("")
L += detail(lin)
L.append("")

L.append("## Startup: cold vs warm cache (`windows.pslist.PsList`, 5 GiB image)")
L.append("")
L.append("cold = the tool's own cache deleted before every run (fastvol: its whole cache directory; vol-rs: "
         "`$XDG_CACHE_HOME/vol-rs` except downloaded PDBs; python: `identifier.cache` + `data_*.cache`); the image stays "
         "page-cached and the kernel symbol file provisioned. warm = the cache written by the previous run. "
         "Best of 5 (python: 3), median in parentheses. All three tools were run again in pass 3.")
L.append("")
L.append("| tool | cold | warm |")
L.append("|---|---:|---:|")
for d, tag in ((D3, "pass 3"), (D2, "pass 2")):
    st = {}
    for r in load(d, "startup.tsv"):
        st.setdefault(r["tool"], {})[r["mode"]] = r
    for t in ("rsvol", "vol-rs", "python"):
        if t in st:
            c, w = st[t]["cold"], st[t]["warm"]
            name = {"rsvol": f"fvol `{meta['RS_COMMIT']}`" if d == D3 else f"rsvol `{meta['RS_P2_COMMIT']}`"}.get(t, t)
            label = name if d == D3 else f"pass 2: {name}"
            L.append(f"| {label} | {fs(float(c['wall_min']))} ({fs(float(c['wall_med']))}) | "
                     f"{fs(float(w['wall_min']))} ({fs(float(w['wall_med']))}) |")
L.append("")
L += text("startup_note.md")
L.append("")
L.append("## Windows per-plugin")
L.append("")
L += table(win)
L.append("")
L.append("## Linux per-plugin")
L.append("")
L += table(lin)
L.append("")
L.append("† python's time and output hash from pass 2, which ran python again for these plugins; all other python "
         "numbers are run 1's. \"steady vs pass 2\" = rsvol `" + meta["RS_P2_COMMIT"] + "` steady / fvol `"
         + meta["RS_COMMIT"] + "` steady.")
L.append("")
L.append("## Checks")
L.append("")
for osname, rows in (("Windows", win), ("Linux", lin)):
    rr = [r["vr_warm"] / r["vr_run1"] for r in rows if r["vr_run1"]]
    L.append(f"- **Run-to-run stability ({osname}).** vol-rs warm in pass 2 vs run 1 (same binary, same procedure): "
             f"ratio median {statistics.median(rr):.3f}, 10th-90th percentile {pct(rr, .1):.3f}–{pct(rr, .9):.3f} "
             f"over {len(rr)} plugins. Within pass 3, the median-of-5 is "
             + ", ".join(f"{statistics.median(r[t + '_med'] / r[t] for r in rows):.2f}x ({LABEL[t]})" for t in RS)
             + " the best run (median over plugins).")
L += text("checks3.md")
lv = [float(l.split()[1]) for l in open(os.path.join(D3, "load.log")) if l.strip()]
lt = [l.split()[0] for l in open(os.path.join(D3, "load.log")) if l.strip()]
L.append(f"- **Load.** `/proc/loadavg` every 10 s during pass 3 ({lt[0][:5]}-{lt[-1][:5]}, {len(lv)} samples): load1 min "
         f"{min(lv):.2f}, median {statistics.median(lv):.2f}, p90 {pct(lv, .9):.2f}, max {max(lv):.2f}. Only the "
         "benchmark ran; the load comes from the multi-threaded fastvol runs executing back to back (fastvol uses all "
         "32 vCPUs), and the 1-minute average carries over between runs.")
L.append("")
open(os.path.join(OUT, "BENCHMARKS.md"), "w").write("\n".join(L) + "\n")

cols = ["os", "plugin", "py_src", "py_runs"]
for t in COLS:
    cols += [f"{t}_wall", f"{t}_med", f"{t}_cpu", f"{t}_rss_mb", f"{t}_rc"]
cols += ["rs_eq_py", "rs_consistent", "volrs_cold_eq_py", "volrs_warm_eq_py", "speedup_cold_vs_vr_cold",
         "speedup_steady_vs_vr_warm", "speedup_warm_vs_vr_warm", "speedup_steady_vs_py", "rs_cold_pass2_wall",
         "rs_steady_pass2_wall", "rs_warm_pass2_wall", "volrs_run1_wall", "py_files_mb", "rs_files_mb",
         "volrs_files_mb", "load1_at_start", "note"]
with open(os.path.join(OUT, "results3.tsv"), "w") as f:
    f.write("\t".join(cols) + "\n")
    for r in win + lin:
        v = [r["os"], r["plugin"], r["py_src"], r["py_n"]]
        for t in COLS:
            v += [r[t], r[t + "_med"], r[t + "_cpu"], r[t + "_rss"], r[t + "_rc"]]
        v += [rs_eq(r).replace("**", ""), r["consistent"], r["vr_cold_eq"], r["vr_warm_eq"],
              f"{r['vr_cold']/r['rs_cold']:.3f}", f"{r['vr_warm']/r['rs_steady']:.3f}", f"{r['vr_warm']/r['rs_warm']:.3f}",
              f"{r['py']/r['rs_steady']:.1f}", r["rs_cold_p2"], r["rs_steady_p2"], r["rs_warm_p2"], r["vr_run1"] or "",
              r["files_py"], r["files_rs"], r["files_vr"], r["load"], r["note"]]
        f.write("\t".join(str(x) for x in v) + "\n")
print(open(os.path.join(OUT, "BENCHMARKS.md")).read())
