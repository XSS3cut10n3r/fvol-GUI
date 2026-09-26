#!/usr/bin/env python3
"""Build bench/vm/BENCHMARKS.md + results2.tsv from the run-2 result files.
Usage: `cd bench/vm && python3 scripts/report2.py raw2 raw .`
raw2/ holds win.tsv, linux.tsv, startup.tsv (bench2_vm.py / startup2_vm.py), notes2.tsv, meta2.env,
checks2.md (by hand); raw/ is run 1 (win_pass1.tsv, win_pass2.tsv, linux.tsv, startup.tsv)."""
import math, os, statistics, sys

D2, D1 = sys.argv[1], sys.argv[2]
OUT = sys.argv[3] if len(sys.argv) > 3 else "."


def load(d, name):
    p = os.path.join(d, name)
    if not os.path.exists(p):
        return []
    rows = [l.rstrip("\n").split("\t") for l in open(p) if l.strip()]
    return [dict(zip(rows[0], r)) for r in rows[1:]]


meta = dict(l.rstrip("\n").split("=", 1) for l in open(os.path.join(D2, "meta2.env")) if "=" in l)
notes = {(r["os"], r["plugin"]): r for r in load(D2, "notes2.tsv")}
run1 = {"windows": {r["plugin"]: r for r in load(D1, "win_pass2.tsv")},
        "linux": {r["plugin"]: r for r in load(D1, "linux.tsv")}}

COLS = ["py", "vr_cold", "vr_warm", "rs_cold", "rs_steady", "rs_warm"]
LABEL = {"py": "python", "vr_cold": "vol-rs cold", "vr_warm": "vol-rs warm", "rs_cold": "rsvol cold",
         "rs_steady": "rsvol steady", "rs_warm": "rsvol warm"}
RS = ["rs_cold", "rs_steady", "rs_warm"]
PEER = {"rs_cold": "vr_cold", "rs_steady": "vr_warm", "rs_warm": "vr_warm"}  # like-for-like vol-rs column


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
    for a in load(D2, fname):
        n = notes.get((osname, a["plugin"]), {})
        r = dict(os=osname, plugin=a["plugin"], py_src=a["py_src"], py_n=a["py_n"], load=a["load1"],
                 flag=n.get("flag", ""), note=n.get("note", ""), consistent=a["rs_consistent"],
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
        o = run1[osname].get(a["plugin"])
        r["rs_run1"] = float(o["rs_wall"]) if o else None
        r["vr_run1"] = float(o["volrs_wall"]) if o else None
        out.append(r)
    return out


win = rows_of("windows", "win.tsv")
lin = rows_of("linux", "linux.tsv")


def rs_eq(r):
    """rsvol's output check: all three rsvol columns share the verdict when rs_consistent=1."""
    if all(r[t + "_eq"] == "1" for t in RS):
        return "yes"
    return {"order": "sorted =", "refmachine": "= ref machine", "sorted": "sorted ="}.get(r["flag"], "**no**")


def rs_ok(r):
    return rs_eq(r) != "**no**"


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
    L.append("| fastest on¹ | "
             + " | ".join(cells) + " |")
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
    L.append(f"- rsvol stdout byte-identical to python's (after the banner line) in every run of all three columns: "
             f"**{len(rows) - len(ne)}/{len(rows)}**" + (
                 " (the others: " + ", ".join(f"`{r['plugin']}` {rs_eq(r)}" for r in ne) + ", see Checks)" if ne else "")
             + f"; vol-rs (both columns): {sum(1 for r in rows if vr_eq(r) == 'yes')}/{len(rows)}")
    inc = [r for r in rows if r["consistent"] != "1"]
    L.append(f"- the three rsvol columns printed the same stdout in all their runs on "
             f"{len(rows) - len(inc)}/{len(rows)} plugins" + (" (not: " + ", ".join(r["plugin"] for r in inc) + ")" if inc else
                                                                 " (the caches never change output)"))
    return L


def table(rows):
    L = ["| plugin | python | vol-rs cold | vol-rs warm | rsvol cold | rsvol steady | rsvol warm | steady vs vol-rs warm | "
         "rsvol out = py | vol-rs out = py | note |",
         "|---|---:|---:|---:|---:|---:|---:|---:|:---:|:---:|---|"]
    for r in rows:
        cells = []
        best = min(r[t] for t in COLS)
        for t in COLS:
            s = fs(r[t])
            if t == "py" and r["py_src"] == "fresh":
                s += "†"
            cells.append(f"**{s}**" if r[t] == best else s)
        sv = r["vr_warm"] / r["rs_steady"]
        svs = fx(sv) if sv >= 1 else f"**{sv:.2f}x**"
        note = r["note"]
        rcs = [r[t + "_rc"] for t in ("py", "vr_warm", "rs_warm")]
        if any(x != "0" for x in rcs) and "exit" not in note:
            note = f"exit py/vol-rs/rsvol = {'/'.join(rcs)}" + ("; " + note if note else "")
        L.append(f"| {r['plugin']} | " + " | ".join(cells) + f" | {svs} | {rs_eq(r)} | {vr_eq(r)} | {note} |")
    return L


heavy = {"windows.statistics.Statistics", "timeliner.Timeliner"}
L = ["# rsvol vs vol-rs vs python volatility3 — quiet-VM benchmark (final)", ""]
L.append(f"{meta['DATE']} · dedicated KVM guest: {meta['CPU']}, {meta['NCPU']} vCPU, {meta['MEM']} RAM, {meta['OS']}, "
         f"kernel {meta['KERNEL']}; nothing else running (see [machine.txt](machine.txt), [method.md](method.md)).")
L.append("")
L.append(f"- **rsvol** `{meta['RS_COMMIT']}` (main HEAD), built on the VM: `cargo build --release` ({meta['RUSTC']}, repo "
         f"config: `target-cpu=native`, `+crt-static`, fat LTO); binary sha256 {meta['RS_SHA']}")
L.append(f"- **vol-rs** {meta['VOLRS_VER']}: the competitor's own release binary ({meta['VOLRS_COMMIT']}, generic x86-64; "
         "a `target-cpu=native` rebuild of it was 2% faster per plugin (median) in run 1)")
L.append(f"- **python** volatility3 {meta['VOL3_VER']} on CPython {meta['PY_VER']} (PGO+LTO+BOLT build) with capstone, yara-python, "
         "pycryptodome: the reference whose output rsvol reproduces. Its times and output hashes are reused from run 1 "
         "(same image, same python, same VM); † marks plugins python was run for again in run 2.")
L.append("- Windows image: `memory-dirty.raw`, 5 GiB raw Windows 11 21H2 x64 (build 22000, `windows.info`: 15.22000); Linux image: `rsvol-noble-6.8.0-139.elf`, "
         "3 GiB, Ubuntu 24.04 kernel 6.8 (`-s` holding only its `.json.xz` ISF). Both page-cached.")
L.append("- Plugins: rsvol implements all 197 plugins of volatility3 2.28.2. Windows round: the same 77 plugins as run 1 "
         "(generic + Windows, `statistics` and `timeliner` last); Linux round: 59 = every `linux.*` plugin that runs without "
         "arguments (57 of 60; not `vmayarascan`, `vmaregexscan`, `module_extract`) + `banners` + `timeliner`, which now "
         "includes the lsof / pagecache rows exactly like python's timeline.")
L.append("")
L.append("Every number is the wall-clock time of a whole process (`TOOL -q -o DIR -f IMG PLUGIN`, stdout to a file), "
         "best of 5 interleaved runs for each rsvol and vol-rs column, best of 2 runs for python on Windows (1 for "
         "statistics, timeliner and on Linux). The columns:")
L.append("")
L.append("| column | cache state before every timed run |")
L.append("|---|---|")
L.append("| **rsvol cold** | rsvol's whole cache directory (`RSVOL_CACHE`) deleted: binary symbol tables, identifier "
         "index, automagic results, scan results — the first-ever run of rsvol on this image |")
L.append("| **rsvol steady** | symbol-table / identifier / automagic caches warm, the per-image scan cache disabled "
         "(`RSVOL_NO_SCAN_CACHE=1`): the honest cost of a plugin's own work, every scan really done |")
L.append("| **rsvol warm** | every cache warm, incl. the scan cache: what a user sees on the 2nd+ run of a plugin |")
L.append("| **vol-rs cold** | `$XDG_CACHE_HOME/vol-rs` deleted (its parsed symbol files, per-image automagic results and "
         "banner index), except the PDB it downloaded from the Microsoft symbol server (so no timed run touches the network) |")
L.append("| **vol-rs warm** | vol-rs's cache as its previous run left it (vol-rs has no scan-result cache) |")
L.append("| **python** | run 1's warm runs (identifier cache warm) |")
L.append("")
L.append("rsvol steady and rsvol warm are compared with vol-rs warm, rsvol cold with vol-rs cold (like for like); "
         "\"fastest on\" for an rsvol column counts the plugins where it beats python and **both** vol-rs columns. "
         "The fastest number of each row is bold in the per-plugin tables.")
L.append("")
L.append("## Headline")
L.append("")
L += headline(win, "Windows")
L.append("")
L += headline(lin, "Linux")
L.append("")
L.append("¹ for an rsvol column: the plugins where it beats python and both vol-rs columns; for vol-rs and python: "
         "the plugins where that column beats all three rsvol columns and the remaining tool.")
L.append("")
nf = os.path.join(D2, "notfastest.md")
if os.path.exists(nf):
    L += open(nf).read().rstrip("\n").split("\n")
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
L.append("cold = the tool's own cache deleted before every run (rsvol: its whole cache directory; vol-rs: "
         "`$XDG_CACHE_HOME/vol-rs` except downloaded PDBs; python: `identifier.cache` + `data_*.cache`); the image stays "
         "page-cached and the kernel symbol file provisioned. warm = the cache written by the previous run. "
         "Best of 5 (python: 3), median in parentheses.")
L.append("")
L.append("| tool | cold | warm |")
L.append("|---|---:|---:|")
st2 = {}
for r in load(D2, "startup.tsv"):
    st2.setdefault(r["tool"], {})[r["mode"]] = r
for t in ("rsvol", "vol-rs", "python"):
    if t in st2:
        c, w = st2[t]["cold"], st2[t]["warm"]
        label = f"rsvol `{meta['RS_COMMIT']}`" if t == "rsvol" else t
        L.append(f"| {label} | {fs(float(c['wall_min']))} ({fs(float(c['wall_med']))}) | "
                 f"{fs(float(w['wall_min']))} ({fs(float(w['wall_med']))}) |")
st1 = {}
for r in load(D1, "startup.tsv"):
    st1.setdefault((r["tool"], r["pass"], r["rsvol_commit"]), {})[r["mode"]] = r
for (t, ps, commit), v in sorted(st1.items(), key=lambda kv: (("rsvol", "vol-rs", "python").index(kv[0][0]), -int(kv[0][1]))):
    if t == "rsvol" and commit == meta["RS_RUN1_COMMIT"] or t != "rsvol" and ps == "1":
        label = f"run 1: rsvol `{commit}`" if t == "rsvol" else f"run 1: {t}"
        L.append(f"| {label} | {fs(float(v['cold']['wall_min']))} ({fs(float(v['cold']['wall_med']))}) | "
                 f"{fs(float(v['warm']['wall_min']))} ({fs(float(v['warm']['wall_med']))}) |")
L.append("")
L += open(os.path.join(D2, "startup_note.md")).read().rstrip("\n").split("\n") if os.path.exists(
    os.path.join(D2, "startup_note.md")) else []
L.append("")
L.append("## Windows per-plugin")
L.append("")
L += table(win)
L.append("")
L.append("## Linux per-plugin")
L.append("")
L += table(lin)
L.append("")
L.append("† python run again in run 2 (see the column notes above); all other python numbers are run 1's.")
L.append("")
L.append("## Checks")
L.append("")
for osname, rows in (("Windows", win), ("Linux", lin)):
    rr = [r["vr_warm"] / r["vr_run1"] for r in rows if r["vr_run1"]]
    L.append(f"- **Run-to-run stability ({osname}).** vol-rs warm (same binary, same procedure as run 1's vol-rs column) "
             f"vs run 1: ratio median {statistics.median(rr):.3f}, 10th-90th percentile {pct(rr, .1):.3f}–{pct(rr, .9):.3f} "
             f"over {len(rr)} plugins. Within run 2, the median-of-5 is "
             + ", ".join(f"{statistics.median(r[t + '_med'] / r[t] for r in rows):.2f}x ({LABEL[t]})" for t in COLS[1:])
             + " the best run (median over plugins).")
for osname, rows in (("Windows", win), ("Linux", lin)):
    both = [r for r in rows if r["rs_run1"]]
    t1, t2 = sum(r["rs_run1"] for r in both), sum(r["rs_steady"] for r in both)
    rr = [r["rs_steady"] / r["rs_run1"] for r in both]
    tl = next((r for r in both if r["plugin"] == "timeliner.Timeliner"), None)
    L.append(f"- **rsvol `{meta['RS_RUN1_COMMIT']}` (run 1) vs `{meta['RS_COMMIT']}` steady ({osname}, the {len(both)} plugins "
             f"of run 1; run 1 had no scan cache, so its column matches \"steady\").** Total {fs(t1)} vs {fs(t2)}, "
             f"per-plugin ratio steady/run 1 median {statistics.median(rr):.3f} (10th-90th percentile "
             f"{pct(rr, .1):.3f}–{pct(rr, .9):.3f})" + (f"; timeliner {fs(tl['rs_run1'])} vs {fs(tl['rs_steady'])}" if tl else "")
             + (" (the Linux timeline now also runs lsof and the pagecache plugins)" if osname == "Linux" else "") + ".")
extra = os.path.join(D2, "checks2.md")
if os.path.exists(extra):
    L += open(extra).read().rstrip("\n").split("\n")
L.append("")
open(os.path.join(OUT, "BENCHMARKS.md"), "w").write("\n".join(L) + "\n")

cols = ["os", "plugin", "py_src", "py_runs"]
for t in COLS:
    cols += [f"{t}_wall", f"{t}_med", f"{t}_cpu", f"{t}_rss_mb", f"{t}_rc"]
cols += ["rs_eq_py", "rs_consistent", "volrs_cold_eq_py", "volrs_warm_eq_py", "speedup_cold_vs_vr_cold",
         "speedup_steady_vs_vr_warm", "speedup_warm_vs_vr_warm", "speedup_steady_vs_py", "rs_run1_wall",
         "volrs_run1_wall", "py_files_mb", "rs_files_mb", "volrs_files_mb", "load1_at_start", "note"]
with open(os.path.join(OUT, "results2.tsv"), "w") as f:
    f.write("\t".join(cols) + "\n")
    for r in win + lin:
        v = [r["os"], r["plugin"], r["py_src"], r["py_n"]]
        for t in COLS:
            v += [r[t], r[t + "_med"], r[t + "_cpu"], r[t + "_rss"], r[t + "_rc"]]
        v += [rs_eq(r).replace("**", ""), r["consistent"], r["vr_cold_eq"], r["vr_warm_eq"],
              f"{r['vr_cold']/r['rs_cold']:.3f}", f"{r['vr_warm']/r['rs_steady']:.3f}", f"{r['vr_warm']/r['rs_warm']:.3f}",
              f"{r['py']/r['rs_steady']:.1f}", r["rs_run1"] or "", r["vr_run1"] or "", r["files_py"], r["files_rs"],
              r["files_vr"], r["load"], r["note"]]
        f.write("\t".join(str(x) for x in v) + "\n")
print(open(os.path.join(OUT, "BENCHMARKS.md")).read())
