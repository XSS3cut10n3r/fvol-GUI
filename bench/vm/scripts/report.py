#!/usr/bin/env python3
"""Build bench/vm/BENCHMARKS.md + results.tsv from the VM result files.
Usage: report.py DIR [OUTDIR]   e.g. `cd bench/vm && python3 scripts/report.py raw .`
DIR holds win_pass1.tsv, win_pass2.tsv, win_pass3_volrs_native.tsv, linux.tsv, startup.tsv, notes.tsv,
meta.env, checks.md (all written by bench_vm.py / startup_vm.py on the VM, or by hand)."""
import math, os, statistics, sys

D = sys.argv[1]
OUT = sys.argv[2] if len(sys.argv) > 2 else D


def load(name):
    p = os.path.join(D, name)
    if not os.path.exists(p):
        return []
    rows = [l.rstrip("\n").split("\t") for l in open(p) if l.strip()]
    return [dict(zip(rows[0], r)) for r in rows[1:]]


meta = dict(l.rstrip("\n").split("=", 1) for l in open(os.path.join(D, "meta.env")) if "=" in l)
notes = {(r["os"], r["plugin"]): r for r in load("notes.tsv")}  # os, plugin, flag, note
w1 = {r["plugin"]: r for r in load("win_pass1.tsv")}
w2 = {r["plugin"]: r for r in load("win_pass2.tsv")}
w3 = {r["plugin"]: r for r in load("win_pass3_volrs_native.tsv")}


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


def row(osname, p, pyrow, rrow):
    n = notes.get((osname, p), {})
    return dict(
        os=osname, plugin=p, py=float(pyrow["py_wall"]), py_cpu=float(pyrow["py_cpu"]), py_rc=pyrow["py_rc"],
        py_n=pyrow["py_n"], py_rss=pyrow["py_rss_mb"], files_mb=pyrow["files_mb_py"],
        vr=float(rrow["volrs_wall"]), vr_cpu=float(rrow["volrs_cpu"]), vr_rc=rrow["volrs_rc"], vr_rss=rrow["volrs_rss_mb"],
        rs=float(rrow["rs_wall"]), rs_cpu=float(rrow["rs_cpu"]), rs_rc=rrow["rs_rc"], rs_rss=rrow["rs_rss_mb"],
        rs_med=float(rrow["rs_med"]), vr_med=float(rrow["volrs_med"]),
        rs_eq=rrow["rs_eq_py"], vr_eq=rrow["volrs_eq_py"], load=rrow["load1"],
        flag=n.get("flag", ""), note=n.get("note", ""))


win = []
for p, a in w1.items():
    r = row("windows", p, a, w2.get(p, a))
    r["rs_old"], r["rs_old_eq"], r["vr_1"] = float(a["rs_wall"]), a["rs_eq_py"], float(a["volrs_wall"])
    if p in w3:
        r["vrn"] = float(w3[p]["volrs_wall"])
        r["rs_3"] = float(w3[p]["rs_wall"])
    win.append(r)
lin = [row("linux", r["plugin"], r, r) for r in load("linux.tsv")]

EQ = {"1": "yes", "0": "**no**"}


def eqcell(r, key):
    e = r[key]
    if e == "1":
        return "yes"
    if r["flag"] == "order" and key == "rs_eq":
        return "order only"
    if r["flag"] == "refmachine" and key == "rs_eq":
        return "= ref machine"
    return "**no**"


def table(rows):
    L = ["| plugin | python | vol-rs | rsvol | rsvol vs vol-rs | rsvol vs python | rsvol out = py | vol-rs out = py | note |",
         "|---|---:|---:|---:|---:|---:|:---:|:---:|---|"]
    for r in rows:
        sv = r["vr"] / r["rs"]
        svs = fx(sv) if sv >= 1 else f"**{sv:.2f}x**"
        note = r["note"]
        if (r["py_rc"] != "0" or r["rs_rc"] != "0" or r["vr_rc"] != "0") and "exit" not in note:
            note = (f"exit py/vol-rs/rsvol = {r['py_rc']}/{r['vr_rc']}/{r['rs_rc']}" + ("; " + note if note else ""))
        L.append(f"| {r['plugin']} | {fs(r['py'])} | {fs(r['vr'])} | {fs(r['rs'])} | {svs} | {fx(r['py']/r['rs'])} | "
                 f"{eqcell(r, 'rs_eq')} | {eqcell(r, 'vr_eq')} | {note} |")
    return L


def summary(rows, label):
    tp, tv, tr = (sum(r[k] for r in rows) for k in ("py", "vr", "rs"))
    cp, cv, cr = (sum(r[k] for r in rows) for k in ("py_cpu", "vr_cpu", "rs_cpu"))
    L = [f"| {label} ({len(rows)} plugins) | python | vol-rs | rsvol |", "|---|---:|---:|---:|",
         f"| total wall (sum of per-plugin best) | {fs(tp)} | {fs(tv)} | {fs(tr)} |",
         f"| total CPU time (user+sys) | {fs(cp)} | {fs(cv)} | {fs(cr)} |",
         f"| median plugin wall | {fs(statistics.median(r['py'] for r in rows))} | "
         f"{fs(statistics.median(r['vr'] for r in rows))} | {fs(statistics.median(r['rs'] for r in rows))} |", ""]
    sv = [r["vr"] / r["rs"] for r in rows]
    sp = [r["py"] / r["rs"] for r in rows]
    L.append(f"- total wall: rsvol is **{fx(tv/tr)} faster than vol-rs** and **{fx(tp/tr)} faster than python**")
    L.append(f"- per-plugin speedup vs vol-rs: median **{fx(statistics.median(sv))}**, geometric mean {fx(gmean(sv))}, "
             f"min {fx(min(sv))}, max {fx(max(sv))}")
    L.append(f"- per-plugin speedup vs python: median **{fx(statistics.median(sp))}**, geometric mean {fx(gmean(sp))}, "
             f"min {fx(min(sp))}, max {fx(max(sp))}")
    slow = [r for r in rows if r["rs"] >= r["vr"]]
    s = f"- rsvol is the fastest of the three on **{len(rows)-len(slow)}/{len(rows)}** plugins"
    if slow:
        s += "; not on: " + "; ".join(f"`{r['plugin']}` (rsvol {fs(r['rs'])} vs vol-rs {fs(r['vr'])}: {r['note']})"
                                      for r in slow)
    L.append(s)
    ne = [r for r in rows if r["rs_eq"] != "1"]
    nv = [r for r in rows if r["vr_eq"] != "1"]
    L.append(f"- stdout byte-identical to python's on the VM (after the banner line): rsvol **{len(rows)-len(ne)}/{len(rows)}**"
             + (" (not: " + ", ".join(f"`{r['plugin']}`" for r in ne) + ")" if ne else "")
             + f", vol-rs {len(rows)-len(nv)}/{len(rows)}" + (" — the notes column and Checks explain each of rsvol's" if ne else ""))
    return L


heavy = {"windows.statistics.Statistics", "timeliner.Timeliner"}
L = [f"# rsvol vs vol-rs vs python volatility3 — quiet-VM benchmark", ""]
L.append(f"{meta['DATE']} · dedicated KVM guest: {meta['CPU']}, {meta['NCPU']} vCPU, {meta['MEM']} RAM, "
         f"{meta['OS']}, kernel {meta['KERNEL']}; nothing else running (see [machine.txt](machine.txt), "
         f"[method.md](method.md)).")
L.append("")
L.append(f"- **rsvol** `{meta['RS_COMMIT']}` (main), built on the VM: `cargo build --release` ({meta['RUSTC']}, "
         f"repo config: `target-cpu=native`, `+crt-static`, fat LTO)")
L.append(f"- **vol-rs** {meta['VOLRS_VER']}: the competitor's own release binary ({meta['VOLRS_COMMIT']}, generic x86-64); "
         "a `target-cpu=native` rebuild is checked below")
L.append(f"- **python** volatility3 {meta['VOL3_VER']} on CPython {meta['PY_VER']} (PGO+LTO+BOLT build) with capstone, "
         "yara-python, pycryptodome — the reference whose output rsvol reproduces")
L.append("- Windows image: `memory-dirty.raw`, 5 GiB raw Windows 10 x64 19041; Linux image: "
         "`rsvol-noble-6.8.0-139.elf`, 3 GiB, Ubuntu 24.04 kernel 6.8. Both page-cached.")
L.append("")
L.append("Numbers are wall-clock time of the whole process (`TOOL -q -o DIR -f IMG PLUGIN`, stdout to a file), best "
         "of 5 interleaved runs for rsvol and vol-rs, best of 2 for python (1 for statistics, timeliner and the "
         "Linux round), each after an untimed warm-up run.")
L.append("")
L.append("## Windows summary")
L.append("")
L += summary(win, "all plugins")
L.append("")
L += summary([r for r in win if r["plugin"] not in heavy], "without statistics / timeliner")
L.append("")
lin_cmp = [r for r in lin if r["flag"] != "excluded"]
if lin:
    L.append("## Linux summary")
    L.append("")
    L += summary(lin_cmp, "linux plugins")
    ex = [r for r in lin if r["flag"] == "excluded"]
    for r in ex:
        L.append(f"- excluded from these totals: `{r['plugin']}` (python {fs(r['py'])}, vol-rs {fs(r['vr'])}, "
                 f"rsvol {fs(r['rs'])}) — {r['note']}")
    L.append("")

L.append("## Startup: cold vs warm cache (`windows.pslist.PsList`, 5 GiB image)")
L.append("")
L.append("cold = the tool's own cache directory deleted before every run (the image stays page-cached, the kernel "
         "symbol file stays provisioned); warm = the cache written by the previous run. Best of 5 (python: 3), "
         "median in parentheses.")
L.append("")
L.append("| tool | cold | warm |")
L.append("|---|---:|---:|")
st = {}
for r in load("startup.tsv"):
    st.setdefault((r["tool"], r["pass"], r["rsvol_commit"]), {})[r["mode"]] = r
order = sorted(st, key=lambda k: (("rsvol", "vol-rs", "python").index(k[0]), -int(k[1])))
for (t, ps, commit) in order:
    c, w = st[(t, ps, commit)]["cold"], st[(t, ps, commit)]["warm"]
    label = f"rsvol `{commit}`" if t == "rsvol" else f"{t} (pass {ps})"
    L.append(f"| {label} | {fs(float(c['wall_min']))} ({fs(float(c['wall_med']))}) | "
             f"{fs(float(w['wall_min']))} ({fs(float(w['wall_med']))}) |")
L.append("")
L.append(f"The cold rsvol run includes decompressing and indexing the 0.6 MB `.json.xz` kernel ISF into its binary "
         f"ISF cache; vol-rs's cold run reads its 4 MB plain-JSON symbol file; python's cold run rebuilds its identifier cache.")
L.append("")
L.append("## Windows per-plugin")
L.append("")
L += table(win)
L.append("")
if lin:
    L.append("## Linux per-plugin")
    L.append("")
    L += table(lin)
    L.append("")

L.append("## Checks")
L.append("")
ratio = [r["vr"] / r["vr_1"] for r in win]
L.append(f"- **Run-to-run stability.** vol-rs (same binary) was timed in both Windows passes, ~1.5 h apart: pass-2/pass-1 "
         f"ratio median {statistics.median(ratio):.3f}, 10th-90th percentile {pct(ratio, .1):.3f}–{pct(ratio, .9):.3f}. "
         f"Within a pass, rsvol's median-of-5 is {statistics.median(r['rs_med']/r['rs'] for r in win):.2f}x its best "
         f"(median over plugins), vol-rs's {statistics.median(r['vr_med']/r['vr'] for r in win):.2f}x.")
to, tn = sum(r["rs_old"] for r in win), sum(r["rs"] for r in win)
L.append(f"- **rsvol `{meta['RS_OLD_COMMIT']}` (pass 1)** total {fs(to)} vs {fs(tn)} for `{meta['RS_COMMIT']}`; "
         f"per-plugin numbers of both are in results.tsv.")
nat = [r for r in win if "vrn" in r]
if nat:
    tg, tnat = sum(r["vr"] for r in nat), sum(r["vrn"] for r in nat)
    rr = [r["vrn"] / r["vr"] for r in nat]
    faster = [r for r in nat if r["rs_3"] >= r["vrn"]]
    L.append(f"- **vol-rs rebuilt with `target-cpu=native`** (pass 3, interleaved with rsvol again): total {fs(tnat)} vs "
             f"{fs(tg)} for the release binary, per-plugin ratio median {statistics.median(rr):.3f} "
             f"(10th-90th percentile {pct(rr, .1):.3f}–{pct(rr, .9):.3f}); rsvol is faster than the native vol-rs on "
             f"{len(nat)-len(faster)}/{len(nat)} plugins"
             + (" (not: " + ", ".join(f"`{r['plugin']}`" for r in faster) + ")" if faster else "") + ".")
extra = os.path.join(D, "checks.md")
if os.path.exists(extra):
    L += open(extra).read().rstrip("\n").split("\n")
L.append("")
open(os.path.join(OUT, "BENCHMARKS.md"), "w").write("\n".join(L) + "\n")

cols = ["os", "plugin", "py_wall", "py_cpu", "py_runs", "py_rc", "py_rss_mb", "volrs_wall", "volrs_med", "volrs_cpu",
        "volrs_rc", "volrs_rss_mb", "rs_wall", "rs_med", "rs_cpu", "rs_rc", "rs_rss_mb", "rs_eq_py", "volrs_eq_py",
        "speedup_vs_volrs", "speedup_vs_py", "rs_123c8d4_wall", "rs_123c8d4_eq_py", "volrs_pass1_wall",
        "volrs_native_wall", "py_files_mb", "load1_at_start", "note"]
with open(os.path.join(OUT, "results.tsv"), "w") as f:
    f.write("\t".join(cols) + "\n")
    for r in win + lin:
        f.write("\t".join(str(x) for x in [
            r["os"], r["plugin"], r["py"], r["py_cpu"], r["py_n"], r["py_rc"], r["py_rss"], r["vr"], r["vr_med"],
            r["vr_cpu"], r["vr_rc"], r["vr_rss"], r["rs"], r["rs_med"], r["rs_cpu"], r["rs_rc"], r["rs_rss"],
            r["rs_eq"], r["vr_eq"], f"{r['vr']/r['rs']:.3f}", f"{r['py']/r['rs']:.1f}", r.get("rs_old", ""),
            r.get("rs_old_eq", ""), r.get("vr_1", ""), r.get("vrn", ""), r["files_mb"], r["load"], r["note"]]) + "\n")
print(open(os.path.join(OUT, "BENCHMARKS.md")).read())
