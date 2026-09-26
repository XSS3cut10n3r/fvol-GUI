#!/usr/bin/env python3
"""Differential sweep of plugin options x renderers: python volatility3 2.28.2 against rsvol.

The no-argument output of every plugin is covered by check_all.sh / check_nix.sh. This sweep
covers everything else: each boolean flag, --pid with one and three real PIDs, --offset / --base /
--address / --inode ... with real values read from the reference outputs of other plugins, dump
variants (file names and contents), string / regex / YARA options, invalid values (argparse errors,
bad regexes, missing files), every renderer, and the global options (--filters, --hide-columns,
-o name collisions, --single-location, --save-config / -c round trips).

Run with /home/user/rs-vol/bench/venv/bin/python (yara-python builds the compiled-rules input):

    sweep.py gen    [-i IMG ...]                        write the case lists
    sweep.py py     [-i IMG ...] [-m RE] [-j 2] [--max-est 600] [--force]
                                                        run python for each case not cached yet
    sweep.py rs     [-i IMG ...] [-m RE] [-b BIN] [-j 2] [--failed] [--live]
                                                        run rsvol for each case python has run, compare
    sweep.py report [-i IMG ...] [-v]                   counts per image and every mismatch
    sweep.py show IMG CASE                              diff of one case

IMG is one of win, win1809, noble, jammy, mac (default: all). Python is slow, so each python case
runs once and is cached; `py` never runs more than -j (at most 2) python processes, each through
limit.sh with an 8G cap and a 10 min timeout. Cases whose estimated python time (the plugin's
no-argument time on that image) exceeds --max-est are skipped.

Layout under /home/user/rs-vol/testdata/scratch/sweep/:
    inputs/            YARA rules, strings files and other inputs shared by both sides
    harvest/IMG.json   the real values (PIDs, offsets, bases, ...) the cases were built from
    cases/IMG.jsonl    one case per line: id, argv, mode, est
    py/IMG/ID/         python run: out.txt err.txt meta.json cwd/ files/ (files/ is the -o dir)
    rs/IMG/ID/         rsvol run, same layout
    report/IMG.tsv     id, status, detail

Case modes: `run` (one run), `twice` (the same command twice into one -o directory: file name
de-duplication, and --save-config refusing to overwrite), `config` (--save-config on the first run,
then -c with the plugin arguments left out on the second).

Comparison: stdout byte for byte (after replacing each side's run directory by <RUN>), the exit
code, the dumped files (names and SHA-256), and for failing runs the error text: all of stderr for
argparse errors (exit code 2), the last line otherwise (python's exception line).
"""
import argparse
import concurrent.futures as cf
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time

ROOT = "/home/user/rs-vol"
HERE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCR = ROOT + "/testdata/scratch/sweep"
PY = ROOT + "/bench/venv/bin/python"
VOLPY = ROOT + "/volatility3/vol.py"
LIMIT = ROOT + "/bench/scripts/limit.sh"
SYM = ROOT + "/testdata/symbols"
REF = ROOT + "/bench/ref"
NONDET = HERE + "/bench/nondeterministic.txt"
PLUGINS_JSON = HERE + "/tests/fixtures/cli_plugins.json"

IMAGES = {
    "win": dict(os="windows", path="/home/user/cbc2/task2/memory-dirty.raw", ref=REF + "/py", sym=False),
    "win1809": dict(os="windows", path=ROOT + "/testdata/images/windows/rsvol-win10-x64-17763-imagery.raw",
                    ref=REF + "/win1809", sym=True),
    "noble": dict(os="linux", path=ROOT + "/testdata/images/linux/rsvol-noble-6.8.0-139.elf",
                  ref=REF + "/linux/rsvol-noble-6.8.0-139-elf", sym=True),
    "jammy": dict(os="linux", path=ROOT + "/testdata/images/linux/rsvol-jammy-5.15.0-191.elf",
                  ref=REF + "/linux/rsvol-jammy-5.15.0-191-elf", sym=True),
    "mac": dict(os="mac", path=ROOT + "/testdata/images/mac/rsvol-mac-mavericks-10.9.2-13C64.dmp",
                ref=REF + "/mac/rsvol-mac-mavericks-10.9.2", sym=True),
}
RENDERERS = ["quick", "csv", "json", "jsonl", "pretty", "none", "mermaid"]
SECOND_IMAGES = ("win1809", "jammy")
PY_TIMEOUT = 600
RS_TIMEOUT = 300


# ------------------------------------------------------------------------------------------------
# plugin metadata and reference outputs


def load_plugins():
    d = json.load(open(PLUGINS_JSON))
    return {p["name"]: p["requirements"] for p in d["plugins"]}


def is_alias(name, plugins):
    """python keeps deprecated aliases (windows.malfind.Malfind for windows.malware.malfind.Malfind,
    windows.hashdump for windows.registry.hashdump, linux.check_idt for linux.malware.check_idt):
    options are swept on the canonical name only."""
    parts = name.split(".")
    if len(parts) != 3:
        return False
    for other in plugins:
        o = other.split(".")
        if len(o) == 4 and o[0] == parts[0] and o[2] == parts[1]:
            return True
    return False


def opt(req_name):
    return "--" + req_name.replace("_", "-")


def ref_rows(img, plugin):
    """Rows of a stored quick-renderer reference as dicts (tree markers stripped)."""
    f = f"{IMAGES[img]['ref']}/{plugin}.txt"
    try:
        lines = open(f, encoding="utf-8", errors="replace").read().split("\n")
    except OSError:
        return []
    if len(lines) < 3:
        return []
    hdr = lines[2].split("\t")
    rows = []
    for line in lines[4:]:
        if not line:
            continue
        cells = line.split("\t")
        if len(cells) != len(hdr):
            continue
        if cells[0].startswith("*"):
            cells[0] = cells[0].lstrip("*")[1:]
        rows.append(dict(zip(hdr, cells)))
    return rows


def ref_times(img):
    t = {}
    try:
        for line in open(IMAGES[img]["ref"] + "/times.tsv"):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 3:
                t[f[0]] = float(f[2])
    except OSError:
        pass
    return t


def hx(v):
    return f"{v:#x}"


def as_int(s):
    try:
        return int(s, 0)
    except (TypeError, ValueError):
        return None


def uniq(xs):
    out = []
    for x in xs:
        if x is not None and x not in out:
            out.append(x)
    return out


# ------------------------------------------------------------------------------------------------
# inputs shared by python and rsvol


def write_inputs():
    d = SCR + "/inputs"
    os.makedirs(d, exist_ok=True)
    rules = (
        "rule rsvol_mz { strings: $a = { 4D 5A 90 00 } condition: $a }\n"
        'rule rsvol_text { strings: $b = "kernel32" nocase wide ascii condition: $b }\n'
    )
    open(d + "/rules.yar", "w").write(rules)
    open(d + "/linux.yar", "w").write(
        'rule rsvol_elf { strings: $a = { 7F 45 4C 46 02 01 01 } condition: $a }\n'
        'rule rsvol_marker { strings: $b = "rsvol" condition: $b }\n'
    )
    open(d + "/bad.yar", "w").write("rule broken { strings: $a = { ZZ } condition: $a }\n")
    try:
        import yara  # noqa: PLC0415

        yara.compile(source=rules).save(d + "/rules.yarc")
    except Exception as e:  # noqa: BLE001
        print("warning: no compiled yara rules:", e, file=sys.stderr)
    return d


def rsvol_json(binary, img, argv):
    """Run rsvol with -r json at harvest time (used only to find real argument values)."""
    im = IMAGES[img]
    cmd = [binary, "-q", "-r", "json"] + (["-s", SYM] if im["sym"] else []) + ["-f", im["path"]] + argv
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=300, cwd=SCR)
        return json.loads(r.stdout.decode("utf-8", "replace").split("\n", 1)[1] or "[]")
    except Exception:  # noqa: BLE001
        return []


# ------------------------------------------------------------------------------------------------
# case generation


class Cases:
    def __init__(self, img, plugins, times):
        self.img = img
        self.plugins = plugins
        self.times = times
        self.cases = []
        self.ids = set()

    def est(self, plugin):
        return self.times.get(plugin, 30.0)

    def add(self, plugin, label, args=(), gopts=(), mode="run", est=None, nof=False):
        if plugin is not None and plugin not in self.plugins:
            return
        cid = re.sub(r"[^A-Za-z0-9_.=+~-]", "_", f"{plugin or 'global'}~{label}")[:150]
        if cid in self.ids:
            return
        self.ids.add(cid)
        # isfinfo lists the symbol files on disk and python's identifier cache as it is right now:
        # python is rerun right before rsvol instead of cached
        live = plugin == "isfinfo.IsfInfo"
        argv = list(gopts) + ([plugin] if plugin else []) + [str(a) for a in args]
        self.cases.append(dict(id=cid, plugin=plugin, argv=argv, mode=mode,
                               est=est if est is not None else self.est(plugin), nof=nof, live=live))


def generic_cases(C, os_name, V, alias_ok=False):
    """Flags one at a time, --pid with one and three PIDs, renderers: for every plugin of the OS."""
    for name, reqs in sorted(C.plugins.items()):
        if not name.startswith(os_name + ".") and name.startswith(("windows.", "linux.", "mac.")):
            continue
        if is_alias(name, C.plugins):
            continue
        required = [r for r in reqs if not r["optional"]]
        base = V.get("base_args", {}).get(name)
        if required and base is None:
            continue
        base = base or []
        for r in reqs:
            if r["kind"] == "bool" and r["name"] not in V.get("skip_flags", {}).get(name, ()):
                C.add(name, "flag-" + r["name"], base + [opt(r["name"])])
            if r["name"] in ("pid", "pids") and V.get("pid1") is not None:
                if r["kind"] == "list_int":
                    C.add(name, "pid1", base + [opt(r["name"]), V["pid1"]])
                    C.add(name, "pid3", base + [opt(r["name"])] + V["pids3"])
                    C.add(name, "pid-none", base + [opt(r["name"]), 999999])
                elif r["kind"] == "int":
                    C.add(name, "pid1", base + [opt(r["name"]), V["pid1"]])
        # renderers on the plain run (or its minimal required arguments)
        e = C.est(name)
        # renderers and --save-config do not depend on the image: the primary image of each OS
        # only (win, noble, mac; the second images win1809 / jammy get the options)
        if C.img in SECOND_IMAGES:
            continue
        rs = ["json"]
        if e < 60:
            rs += ["csv", "pretty"]
        if e < 20:
            rs += ["jsonl"]
        for r in rs:
            C.add(name, "r-" + r, base, gopts=["-r", r])
        # --save-config then -c (without the plugin arguments): python's build_configuration()
        if e < 20:
            C.add(name, "savecfg", base, mode="config")


def all_renderers(C, plugin, label, args=()):
    if C.img in SECOND_IMAGES:
        return
    for r in RENDERERS:
        C.add(plugin, f"R{label}-{r}", args, gopts=["-r", r])


def invalid_cases(C, plugin, pidopt="--pid"):
    """argparse-level errors (identical parser code for every plugin: a few plugins suffice)."""
    C.add(plugin, "bad-int", [pidopt, "abc"], est=5)
    C.add(plugin, "bad-hex", [pidopt, "0xZZ"], est=5)
    C.add(plugin, "pid-empty", [pidopt], est=None)
    C.add(plugin, "unknown-opt", ["--no-such-option"], est=5)
    C.add(plugin, "help", ["-h"], est=5)
    C.add(None, "bad-renderer", [plugin], gopts=["-r", "bogus"], est=5)
    C.add(None, "bad-plugin", [plugin + "Bogus"], est=5)
    C.add(None, "no-plugin", [], est=5)
    C.add(None, "main-help", ["-h"], est=5)
    C.add(None, "bad-outdir", [plugin], gopts=["-o", "/nonexistent/rsvol-sweep"], est=5)
    C.add(None, "bad-config", [plugin], gopts=["-c", "/nonexistent/rsvol-sweep.json"], est=5)
    C.add(plugin, "bad-single-location", [], gopts=["--single-location", "file:///nonexistent/rsvol.img"], nof=True, est=5)
    C.add(plugin, "single-location", [], gopts=["--single-location", "file://" + IMAGES[C.img]["path"]], nof=True)
    C.add(plugin, "hide-greedy", [], gopts=["--hide-columns", "PID"], est=5)
    os_name = IMAGES[C.img]["os"]
    stacker = {"windows": "WindowsIntelStacker", "linux": "LinuxIntelStacker", "mac": "MacIntelStacker"}[os_name]
    C.add(plugin, "stackers-os", [], gopts=[f"--stackers={stacker}"])
    C.add(plugin, "stackers-bogus", [], gopts=["--stackers=NoSuchStacker"])
    C.add(plugin, "stackers-empty", [], gopts=["--stackers="])
    C.add(plugin, "offline", [], gopts=["--offline"])
    if os_name == "linux":
        C.add(plugin, "stackers-elf", [], gopts=["--stackers", "Elf64Stacker", stacker, "--", ])


def filter_cases(C, plugin, col_a, pat_a, col_b, pat_b):
    C.add(plugin, "filter-plus", gopts=["--filters", f"+{col_a},{pat_a}"])
    C.add(plugin, "filter-minus", gopts=["--filters", f"-{col_a},{pat_a}"])
    C.add(plugin, "filter-exact", gopts=["--filters", f"+{col_b},{pat_b}!"])
    C.add(plugin, "filter-two", gopts=["--filters", f"+{col_a},{pat_a}", "--filters", f"-{col_b},{pat_b}"])
    C.add(plugin, "filter-nocol", gopts=["--filters", "+NoSuchColumn,abc"])
    C.add(plugin, "filter-badfmt", gopts=["--filters", "justtext"])
    C.add(plugin, "filter-regex", gopts=["--filters", f"+{col_a},^[a-m].*"])
    C.add(plugin, "filter-bad-regex", gopts=["--filters", f"+{col_a},(unclosed"])
    C.add(plugin, "hide-one", gopts=[f"--hide-columns={col_b}"])
    C.add(plugin, "hide-prefix-lower", gopts=[f"--hide-columns={col_a[:3].lower()}"])
    C.add(plugin, "hide-csv", gopts=["-r", "csv", f"--hide-columns={col_b}"])
    C.add(plugin, "hide-json", gopts=["-r", "json", f"--hide-columns={col_a}"])
    C.add(plugin, "hide-all", gopts=["--hide-columns="])  # "" prefixes every column: nothing visible
    C.add(plugin, "hide-all-csv", gopts=["-r", "csv", "--hide-columns="])
    C.add(plugin, "filter-int-regex", gopts=["--filters", f"+{col_b},^1"])
    C.add(plugin, "hide-pretty-filter", gopts=["-r", "pretty", f"--hide-columns={col_b}", "--filters", f"+{col_a},{pat_a}"])


def windows_values(img, binary):
    V = {}
    ps = ref_rows(img, "windows.pslist.PsList")
    n2p = {}
    for r in ps:
        n2p.setdefault(r["ImageFileName"].lower(), int(r["PID"]))
    V["pid_small"] = n2p.get("smss.exe")
    V["pid1"] = n2p.get("explorer.exe") or n2p.get("lsass.exe")
    V["pid_lsass"] = n2p.get("lsass.exe")
    V["pid_svc"] = n2p.get("svchost.exe")
    V["pids3"] = uniq([V["pid_small"], V["pid_lsass"], V["pid1"], 4])[:3]
    phys = rsvol_json(binary, img, ["windows.pslist.PsList", "--physical", "--pid"] + [str(p) for p in uniq([V["pid1"], V["pid_small"]])])
    for row in phys:
        if row.get("PID") == V["pid1"]:
            V["phys1"] = row.get("Offset(P)")
        if row.get("PID") == V["pid_small"]:
            V["phys_small"] = row.get("Offset(P)")
    dl = [r for r in ref_rows(img, "windows.dlllist.DllList") if as_int(r["PID"]) == V["pid1"]]
    if dl:
        V["exe_base"] = as_int(dl[0]["Base"])
        V["exe_name"] = dl[0]["Name"]
    for r in dl:
        if r["Name"].lower() == "kernel32.dll":
            V["k32_base"] = as_int(r["Base"])
        if r["Name"].lower() == "ntdll.dll":
            V["ntdll_base"] = as_int(r["Base"])
    dls = [r for r in ref_rows(img, "windows.dlllist.DllList") if as_int(r["PID"]) == V["pid_small"]]
    if dls:
        V["small_exe_base"] = as_int(dls[0]["Base"])
    mods = ref_rows(img, "windows.modules.Modules")
    for r in mods:
        if r["Name"].lower() == "ntoskrnl.exe":
            V["nt_base"] = as_int(r["Base"])
    sysmods = sorted((as_int(r["Size"]) or 0, r["Name"], as_int(r["Base"])) for r in mods if r["Name"].lower().endswith(".sys"))
    sysmods = [m for m in sysmods if m[0] >= 0x2000]
    if sysmods:
        V["small_mod"] = sysmods[0][1]
        V["small_mod_base"] = sysmods[0][2]
    vads = [r for r in ref_rows(img, "windows.vadinfo.VadInfo") if as_int(r["PID"]) == V["pid1"]]
    for r in vads:
        if "kernel32" in r["File"].lower():
            V["vad_k32"] = as_int(r["Start VPN"])
            break
    svads = [r for r in ref_rows(img, "windows.vadinfo.VadInfo") if as_int(r["PID"]) == V["pid_small"]]
    small = sorted((as_int(r["End VPN"]) - as_int(r["Start VPN"]), as_int(r["Start VPN"])) for r in svads)
    if small:
        V["vad_small"] = small[len(small) // 2][1]
    hives = ref_rows(img, "windows.registry.hivelist.HiveList")
    for r in hives:
        p = r["FileFullPath"]
        if p.upper().endswith("\\SYSTEM") and "hive_system" not in V:
            V["hive_system"] = as_int(r["Offset"])
        if p.lower().endswith("ntuser.dat") and "hive_ntuser" not in V:
            V["hive_ntuser"] = as_int(r["Offset"])
            m = re.search(r"\\Users\\([^\\]+)\\", p, re.I)
            if m:
                V["user"] = m.group(1)
        if p.upper().endswith("\\HARDWARE"):
            V["hive_small"] = as_int(r["Offset"])
    for r in ref_rows(img, "windows.filescan.FileScan"):
        if r["Name"].lower().endswith("\\system32\\ntdll.dll"):
            V["file_phys"] = as_int(r["Offset"])
            break
    for r in ref_rows(img, "windows.dumpfiles.DumpFiles"):
        if r["FileName"].lower() == "ntdll.dll":
            V["file_virt"] = as_int(r["FileObject"])
            break
    tags = {}
    for r in ref_rows(img, "windows.bigpools.BigPools"):
        tags[r["Tag"]] = tags.get(r["Tag"], 0) + 1
    V["tags"] = [t for t, _ in sorted(tags.items(), key=lambda kv: (-kv[1], kv[0]))[:2]]
    sym = rsvol_json(binary, img, ["windows.pe_symbols.PESymbols", "--source", "kernel", "--module", "ntoskrnl.exe", "--symbols", "NtCreateFile"])
    for row in sym:
        if isinstance(row.get("Address"), int):
            V["sym_addr"] = row["Address"]
    V["psscan_phys"] = [row.get("Offset(P)") for row in rsvol_json(binary, img, ["windows.psscan.PsScan", "--physical"])][:6]
    return V


def gen_windows(C, V, inputs):
    img = C.img
    pid1, small, p3 = V["pid1"], V["pid_small"], V["pids3"]
    # strings file: physical offsets of EPROCESS structures, low memory, beyond the image
    sf = f"{inputs}/strings-{img}.txt"
    with open(sf, "w") as f:
        for i, off in enumerate(V.get("psscan_phys", [])):
            if isinstance(off, int):
                f.write(f"{off + 0x10}:rsvol string {i}\n")
        f.write("4096:low page\n0: zero\n  8192 indented, comma\n99999999999:beyond the end\n")
        f.write("not a strings line\n")
    V["base_args"] = {
        "windows.pe_symbols.PESymbols": ["--source", "kernel", "--module", "ntoskrnl.exe", "--symbols", "NtCreateFile"],
        "windows.pedump.PEDump": ["--pid", pid1, "--base", hx(V["exe_base"])] if V.get("exe_base") else None,
        # without --pid python maps the whole kernel layer (> 8 GB on the 5 GB image): one small process
        "windows.strings.Strings": ["--pid", small, "--strings-file", sf],
        "windows.vadregexscan.VadRegExScan": ["--pid", pid1, "--pattern", "kernel32"],
        "regexscan.RegExScan": ["--pattern", "Codebreaker|rsvol"],
        "yarascan.YaraScan": ["--yara-string", V.get("user", "Microsoft")],
        "windows.vadyarascan.VadYaraScan": ["--pid", pid1, "--yara-string", "kernel32"],
        "windows.malware.direct_system_calls.DirectSystemCalls": [],
        "windows.malware.indirect_system_calls.IndirectSystemCalls": [],
    }
    # --dump without --pid writes every DLL / VAD / page of every process (GBs): covered with --pid below
    V["skip_flags"] = {"windows.dlllist.DllList": ("dump",), "windows.vadinfo.VadInfo": ("dump",),
                       "windows.memmap.Memmap": ("dump",)}
    generic_cases(C, "windows", V)
    # --- per plugin
    P = "windows.pslist.PsList"
    C.add(P, "phys-pid", ["--physical", "--pid", pid1])
    C.add(P, "dump-small", ["--pid", small, "--dump"])
    C.add(P, "dump-3", ["--pid"] + p3 + ["--dump"])
    C.add(P, "twice-dump", ["--pid", small, "--dump"], mode="twice")
    C.add(P, "pid-hex", ["--pid", hx(pid1)])
    C.add(P, "pid-dup", ["--pid", pid1, pid1])
    invalid_cases(C, P)
    filter_cases(C, P, "ImageFileName", "svchost", "PID", str(4))
    all_renderers(C, P, "pslist")
    all_renderers(C, "windows.pstree.PsTree", "pstree")
    all_renderers(C, "windows.pstree.PsTree", "pstree-pid", ["--pid", pid1])
    filter_cases(C, "windows.pstree.PsTree", "ImageFileName", "svchost", "PID", str(pid1))
    C.add("windows.pstree.PsTree", "phys-pid", ["--physical", "--pid", pid1])
    C.add("windows.psscan.PsScan", "dump-small", ["--pid", small, "--dump"])
    C.add("windows.psscan.PsScan", "phys-pid", ["--physical", "--pid"] + p3)
    D = "windows.dlllist.DllList"
    C.add(D, "name", ["--pid", pid1, "--name", "ntdll.dll"])
    C.add(D, "name-case", ["--name", "NTDLL.DLL"])
    C.add(D, "name-icase", ["--name", "NTDLL.DLL", "--ignore-case"])
    C.add(D, "icase-only", ["--pid", pid1, "--ignore-case"])
    if V.get("k32_base"):
        C.add(D, "base", ["--pid", pid1, "--base", hx(V["k32_base"])])
        C.add(D, "base-all", ["--base", hx(V["k32_base"])])
        C.add(D, "base-dump", ["--pid", pid1, "--base", hx(V["k32_base"]), "--dump"])
        C.add(D, "base-dec", ["--pid", pid1, "--base", str(V["k32_base"])])
    if V.get("phys1"):
        C.add(D, "offset", ["--offset", hx(V["phys1"])])
        C.add("windows.handles.Handles", "offset", ["--offset", hx(V["phys1"])])
        C.add(D, "offset-pid", ["--offset", hx(V["phys1"]), "--pid", small])
    C.add(D, "offset-bad", ["--offset", "0x1000"])
    C.add(D, "name-bad-regex", ["--pid", pid1, "--name", "(unclosed"])
    C.add(D, "name-regex", ["--pid", pid1, "--name", r"^k.*32\.dll$"])
    C.add(D, "offset-int-bad", ["--offset", "12abc"], est=5)
    C.add(D, "dump-small", ["--pid", small, "--dump"])
    C.add(D, "twice-dump", ["--pid", small, "--dump"], mode="twice")
    C.add(D, "name-dump", ["--pid", pid1, "--name", "ntdll.dll", "--dump"])
    all_renderers(C, "windows.handles.Handles", "handles", ["--pid", small])
    V_ = "windows.vadinfo.VadInfo"
    if V.get("vad_k32"):
        C.add(V_, "address", ["--pid", pid1, "--address", hx(V["vad_k32"])])
        C.add(V_, "address-all", ["--address", hx(V["vad_k32"])])
    C.add(V_, "address-none", ["--pid", pid1, "--address", "0x1"])
    C.add(V_, "dump-small", ["--pid", small, "--dump"])
    C.add(V_, "dump-maxsize", ["--pid", small, "--dump", "--maxsize", "0x10000"])
    if V.get("vad_small"):
        C.add(V_, "dump-address", ["--pid", small, "--dump", "--address", hx(V["vad_small"])])
    C.add(V_, "maxsize-only", ["--pid", small, "--maxsize", "4096"])
    all_renderers(C, V_, "vadinfo", ["--pid", small])
    C.add("windows.memmap.Memmap", "small", ["--pid", small])
    C.add("windows.memmap.Memmap", "dump-small", ["--pid", small, "--dump"])
    for M in ("windows.modules.Modules", "windows.modscan.ModScan"):
        C.add(M, "name", ["--name", "ntoskrnl.exe"])
        C.add(M, "name-nomatch", ["--name", "NTOSKRNL.EXE"])
        if V.get("nt_base"):
            C.add(M, "base", ["--base", hx(V["nt_base"])])
        if V.get("small_mod_base"):
            C.add(M, "dump-base", ["--dump", "--base", hx(V["small_mod_base"])])
            C.add(M, "dump-name", ["--dump", "--name", V["small_mod"]])
    if V.get("small_mod_base"):
        C.add("windows.modules.Modules", "twice-dump", ["--dump", "--base", hx(V["small_mod_base"])], mode="twice")
    E = "windows.pedump.PEDump"
    if V.get("nt_base"):
        C.add(E, "kernel", ["--kernel-module", "--base", hx(V["nt_base"])])
    if V.get("k32_base"):
        C.add(E, "dll-3pids", ["--pid"] + p3 + ["--base", hx(V["k32_base"])])
    C.add(E, "missing-base", ["--pid", pid1], est=5)
    C.add(E, "bad-base", ["--pid", pid1, "--base", "0x10000"])
    K = "windows.registry.printkey.PrintKey"
    C.add(K, "key", ["--key", "ControlSet001\\Services\\Tcpip\\Parameters"])
    C.add(K, "key-recurse", ["--key", "ControlSet001\\Control\\ComputerName", "--recurse"])
    C.add(K, "key-missing", ["--key", "No\\Such\\Key"])
    C.add(K, "key-case", ["--key", "controlset001\\control\\computername"])
    if V.get("hive_system"):
        C.add(K, "offset", ["--offset", hx(V["hive_system"])])
        C.add(K, "offset-key", ["--offset", hx(V["hive_system"]), "--key", "ControlSet001\\Control\\ComputerName", "--recurse"])
    if V.get("hive_small"):
        C.add(K, "offset-recurse", ["--offset", hx(V["hive_small"]), "--recurse"])
    C.add(K, "offset-bad", ["--offset", "0x1234"])
    all_renderers(C, K, "printkey", ["--key", "ControlSet001\\Services\\Tcpip\\Parameters"])
    if V.get("hive_ntuser"):
        C.add("windows.registry.userassist.UserAssist", "offset", ["--offset", hx(V["hive_ntuser"])])
    C.add("windows.registry.userassist.UserAssist", "offset-bad", ["--offset", "0x1234"])
    H = "windows.registry.hivelist.HiveList"
    C.add(H, "filter", ["--filter", "ntuser"])
    C.add(H, "filter-case", ["--filter", "NTUSER"])
    C.add(H, "filter-dump", ["--filter", "HARDWARE", "--dump"])
    C.add(H, "twice-dump", ["--filter", "HARDWARE", "--dump"], mode="twice")
    C.add(H, "filter-none", ["--filter", "nosuchhive"])
    all_renderers(C, H, "hivelist")
    F = "windows.dumpfiles.DumpFiles"
    C.add(F, "pid-small", ["--pid", small])
    if V.get("file_virt"):
        C.add(F, "virtaddr", ["--virtaddr", hx(V["file_virt"])])
    if V.get("file_phys"):
        C.add(F, "physaddr", ["--physaddr", hx(V["file_phys"])])
    C.add(F, "filter", ["--pid", pid1, "--filter", r"ntdll\.dll$"])
    C.add(F, "filter-icase", ["--pid", pid1, "--filter", "NTDLL", "--ignore-case"])
    C.add(F, "filter-bad-regex", ["--pid", pid1, "--filter", "(unclosed"])
    C.add(F, "virtaddr-bad", ["--virtaddr", "0x1000"])
    B = "windows.bigpools.BigPools"
    if V.get("tags"):
        C.add(B, "tag", ["--tags", V["tags"][0]])
        C.add(B, "tags2", ["--tags", ",".join(V["tags"])])
        C.add(B, "tag-free", ["--tags", V["tags"][0], "--show-free"])
    C.add(B, "tag-none", ["--tags", "ZzZz"])
    C.add("windows.envars.Envars", "pid-silent", ["--pid", pid1, "--silent"])
    for Q in ("windows.cmdscan.CmdScan", "windows.consoles.Consoles"):
        C.add(Q, "hist", ["--max-history", "10", "100"])
        C.add(Q, "noreg-hist", ["--no-registry", "--max-history", "25"])
    C.add("windows.consoles.Consoles", "bufs", ["--max-buffers", "2", "8"])
    all_renderers(C, "windows.mbrscan.MBRScan", "mbr")
    all_renderers(C, "windows.mbrscan.MBRScan", "mbrfull", ["--full"])
    all_renderers(C, "windows.malware.malfind.Malfind", "malfind")
    C.add("windows.malware.malfind.Malfind", "dump-pid", ["--pid", pid1, "--dump"])
    all_renderers(C, "windows.info.Info", "info")
    all_renderers(C, "windows.verinfo.VerInfo", "verinfo")
    S = "windows.pe_symbols.PESymbols"
    C.add(S, "k-multi", ["--source", "kernel", "--module", "ntoskrnl.exe", "--symbols", "NtCreateFile", "ZwClose", "NoSuchSymbol"])
    if V.get("sym_addr"):
        C.add(S, "k-addr", ["--source", "kernel", "--module", "ntoskrnl.exe", "--addresses", hx(V["sym_addr"]), hx(V["sym_addr"] + 1)])
        C.add(S, "k-both", ["--source", "kernel", "--module", "ntoskrnl.exe", "--symbols", "NtClose", "--addresses", hx(V["sym_addr"])])
    C.add(S, "p-k32", ["--source", "processes", "--module", "kernel32.dll", "--symbols", "CreateFileW", "LoadLibraryA"])
    C.add(S, "p-nomod", ["--source", "processes", "--module", "nosuch.dll", "--symbols", "X"])
    C.add(S, "k-none", ["--source", "kernel", "--module", "ntoskrnl.exe"])
    C.add(S, "bad-source", ["--source", "bogus", "--module", "ntoskrnl.exe"], est=5)
    C.add(S, "missing-module", ["--source", "kernel"], est=5)
    all_renderers(C, S, "pesym", ["--source", "kernel", "--module", "ntoskrnl.exe", "--symbols", "NtCreateFile", "ZwClose"])
    T = "windows.strings.Strings"
    C.add(T, "pid", ["--pid", pid1, "--strings-file", sf])
    C.add(T, "missing-file", ["--strings-file", "/nonexistent/strings.txt"])
    C.add(T, "missing-uri", ["--strings-file", "file:///nonexistent/strings.txt"])
    C.add(T, "file-uri", ["--pid", small, "--strings-file", "file://" + sf])
    R = "windows.vadregexscan.VadRegExScan"
    C.add(R, "maxsize", ["--pid", pid1, "--pattern", r"[a-z]{4,}\.dll", "--maxsize", "0x1000"])
    C.add(R, "bad-regex", ["--pid", pid1, "--pattern", "(unclosed"])
    C.add(R, "bad-regex2", ["--pid", pid1, "--pattern", "*abc"])
    C.add(R, "nopid", ["--pattern", "rsvol-sweep-no-match"])
    C.add(R, "bytes-escape", ["--pid", small, "--pattern", r"\x4d\x5a\x90"])
    Y = "windows.vadyarascan.VadYaraScan"
    C.add(Y, "file", ["--pid", pid1, "--yara-file", f"{inputs}/rules.yar"])
    C.add(Y, "file-uri", ["--pid", pid1, "--yara-file", f"file://{inputs}/rules.yar"])
    C.add(Y, "compiled", ["--pid", pid1, "--yara-compiled-file", f"file://{inputs}/rules.yarc"])
    C.add(Y, "insensitive", ["--pid", pid1, "--yara-string", "KERNEL32", "--insensitive"])
    C.add(Y, "wide", ["--pid", pid1, "--yara-string", "kernel32", "--wide"])
    C.add(Y, "hex", ["--pid", small, "--yara-string", "{4D 5A 90 00}"])
    C.add(Y, "regex", ["--pid", small, "--yara-string", "/ntdll\\.dll/"])
    C.add(Y, "maxsize", ["--pid", pid1, "--yara-string", "kernel32", "--max-size", "0x1000"])
    C.add(Y, "bad-rule", ["--pid", pid1, "--yara-file", f"{inputs}/bad.yar"])
    C.add(Y, "missing-file", ["--pid", pid1, "--yara-file", "/nonexistent/rules.yar"])
    C.add(Y, "missing-uri", ["--pid", pid1, "--yara-file", "file:///nonexistent/rules.yar"])
    C.add(Y, "no-rules", ["--pid", pid1])
    all_renderers(C, Y, "vadyara", ["--pid", small, "--yara-string", "{4D 5A 90 00}"])
    G = "yarascan.YaraScan"
    C.add(G, "file", ["--yara-file", f"{inputs}/rules.yar"], est=300)
    C.add(G, "insensitive", ["--yara-string", V.get("user", "Microsoft").upper(), "--insensitive"])
    C.add(G, "wide", ["--yara-string", V.get("user", "Microsoft"), "--wide"])
    C.add(G, "no-rules", [], est=5)
    C.add(G, "bad-hex", ["--yara-string", "{ZZ}"], est=5)
    C.add(G, "missing-uri", ["--yara-file", "file:///nonexistent/rules.yar"], est=5)
    C.add(G, "bad-rule", ["--yara-file", f"{inputs}/bad.yar"], est=5)
    all_renderers(C, G, "yarascan", ["--yara-string", V.get("user", "Microsoft")])
    X = "regexscan.RegExScan"
    C.add(X, "maxsize", ["--pattern", "Codebreaker", "--maxsize", "4"])
    C.add(X, "bad-regex", ["--pattern", "(unclosed"], est=5)
    C.add(X, "bad-regex2", ["--pattern", "[a-"], est=5)
    C.add(X, "missing", [], est=5)
    C.add("windows.truecrypt.Passphrase", "minlen", ["--min-length", "1"])
    C.add("vmscan.Vmscan", "log", ["--log-threshold", "1"])
    C.add("layerwriter.LayerWriter", "list", ["--list"])
    C.add("layerwriter.LayerWriter", "bad-layer", ["--layers", "nosuchlayer"])
    C.add("timeliner.Timeliner", "pf-pslist", ["--plugin-filter", "windows.pslist"], est=60)
    C.add("timeliner.Timeliner", "pf-body", ["--plugin-filter", "windows.pslist", "--create-bodyfile"], est=60)
    C.add("timeliner.Timeliner", "pf-record", ["--plugin-filter", "windows.pslist", "--record-config"], est=60)
    C.add("timeliner.Timeliner", "pf-none", ["--plugin-filter", "nosuchplugin"], est=60)
    C.add("timeliner.Timeliner", "pf-json", ["--plugin-filter", "windows.pslist", "windows.dlllist"], gopts=["-r", "json"], est=120)
    C.add("configwriter.ConfigWriter", "plain", [])
    C.add("configwriter.ConfigWriter", "twice", [], mode="twice")
    # config round trips and --write-config
    C.add(P, "config-rt", ["--pid", pid1], mode="config")
    C.add(D, "config-rt", ["--pid", small], mode="config")
    C.add(P, "saveconfig-twice", [], gopts=["--save-config", "saved.json"], mode="twice")
    C.add(P, "write-config", [], gopts=["--write-config"])
    C.add(None, "extend", ["windows.pslist.PsList"], gopts=["-e", f"plugins.PsList.pid=[{pid1}]"])
    C.add(None, "extend-bad", ["windows.pslist.PsList"], gopts=["-e", "nonsense"])


def linux_values(img):
    V = {}
    ps = ref_rows(img, "linux.pslist.PsList")
    n2p = {}
    for r in ps:
        n2p.setdefault(r["COMM"], []).append(int(r["PID"]))
    V["pid1"] = max(n2p.get("bash", [1]))
    V["pid_small"] = min(n2p.get("sleep", [1]))
    V["pid_py"] = min(n2p.get("python3", [1]))
    V["pids3"] = uniq([1, V["pid1"], V["pid_py"]])
    for r in ref_rows(img, "linux.lsmod.Lsmod"):
        if r["Module Name"] == "rsvol_test":
            V["mod_rsvol"] = as_int(r["Offset"])
        if r["Module Name"] == "dummy":
            V["mod_dummy"] = as_int(r["Offset"])
    maps = [r for r in ref_rows(img, "linux.proc.Maps") if as_int(r["PID"]) == V["pid_small"]]
    for r in maps:
        if "libc" in r["File Path"]:
            V["map_libc"] = as_int(r["Start"])
            break
    for r in ref_rows(img, "linux.mountinfo.MountInfo"):
        V["mntns"] = as_int(r["MNT_NS_ID"])
        break
    for r in ref_rows(img, "linux.sockstat.Sockstat"):
        V["netns"] = as_int(r["NetNS"])
        break
    best = None
    for r in ref_rows(img, "linux.pagecache.Files"):
        if r["FileType"] == "REG" and r["FilePath"].startswith("/etc/") and 0 < (as_int(r["CachedPages"]) or 0) <= 4:
            best = r
            break
    if best:
        V["file_path"] = best["FilePath"]
        V["inode_addr"] = as_int(best["InodeAddr"])
    return V


def gen_linux(C, V, inputs):
    pid1, small, p3 = V["pid1"], V["pid_small"], V["pids3"]
    V["base_args"] = {
        "linux.vmaregexscan.VmaRegExScan": ["--pid", pid1, "--pattern", "rsvol"],
        "linux.malware.vmayarascan.VmaYaraScan": ["--pid", pid1, "--yara-string", "rsvol"],
        "linux.vmayarascan.VmaYaraScan": ["--pid", pid1, "--yara-string", "rsvol"],
        "linux.module_extract.ModuleExtract": ["--base", hx(V["mod_rsvol"])] if V.get("mod_rsvol") else None,
        "linux.pagecache.InodePages": ["--find", V["file_path"]] if V.get("file_path") else None,
        "regexscan.RegExScan": ["--pattern", "rsvol-interactive-marker"],
        "yarascan.YaraScan": ["--yara-string", "rsvol-interactive-marker"],
    }
    # --dump without --pid writes every mapping of every process: covered with --pid below
    V["skip_flags"] = {"linux.proc.Maps": ("dump",), "linux.elfs.Elfs": ("dump",)}
    generic_cases(C, "linux", V)
    L = "linux.pslist.PsList"
    C.add(L, "threads-pid", ["--threads", "--pid", pid1])
    C.add(L, "dump-small", ["--pid", small, "--dump"])
    C.add(L, "twice-dump", ["--pid", small, "--dump"], mode="twice")
    C.add(L, "decorate-threads", ["--decorate-comm", "--threads", "--pid"] + p3)
    invalid_cases(C, L)
    filter_cases(C, L, "COMM", "sleep", "PID", "1")
    all_renderers(C, L, "pslist")
    all_renderers(C, "linux.pstree.PsTree", "pstree")
    all_renderers(C, "linux.pstree.PsTree", "pstree-threads", ["--threads", "--pid", pid1])
    all_renderers(C, "linux.malware.malfind.Malfind", "malfind")
    all_renderers(C, "linux.sockstat.Sockstat", "sockstat", ["--pids", V["pid_py"]])
    all_renderers(C, "linux.bash.Bash", "bash")
    all_renderers(C, "linux.malware.modxview.Modxview", "modxview")
    M = "linux.proc.Maps"
    if V.get("map_libc"):
        C.add(M, "address", ["--pid", small, "--address", hx(V["map_libc"])])
        C.add(M, "address-dump", ["--pid", small, "--address", hx(V["map_libc"]), "--dump"])
    C.add(M, "address-none", ["--pid", small, "--address", "0x1"])
    C.add(M, "dump-maxsize", ["--pid", small, "--dump", "--maxsize", "0x10000"])
    C.add(M, "dump-small", ["--pid", small, "--dump"])
    C.add(M, "twice-dump-max", ["--pid", small, "--dump", "--maxsize", "0x4000"], mode="twice")
    all_renderers(C, M, "maps", ["--pid", small])
    C.add("linux.elfs.Elfs", "dump-small", ["--pid", small, "--dump"])
    MF = "linux.malware.malfind.Malfind"
    C.add(MF, "hexdump", ["--hexdump-size", "16"])
    C.add(MF, "dump-max", ["--dump-regions", "--dump-maxsize", "4096"])
    C.add(MF, "dirty-pid", ["--show-all-dirty-pages", "--pid"] + p3)
    MI = "linux.mountinfo.MountInfo"
    if V.get("mntns"):
        C.add(MI, "mntns", ["--mntns", V["mntns"]])
        C.add(MI, "mntns-fmt", ["--mntns", V["mntns"], "--mount-format"])
    C.add(MI, "mntns-none", ["--mntns", "1"])
    SS = "linux.sockstat.Sockstat"
    if V.get("netns"):
        C.add(SS, "netns", ["--netns", V["netns"]])
    C.add(SS, "netns-none", ["--netns", "1"])
    if V.get("mod_dummy"):
        C.add("linux.module_extract.ModuleExtract", "dummy", ["--base", hx(V["mod_dummy"])])
    C.add("linux.module_extract.ModuleExtract", "bad-base", ["--base", "0x1234"])
    C.add("linux.module_extract.ModuleExtract", "missing-base", [], est=5)
    PF = "linux.pagecache.Files"
    C.add(PF, "type-reg", ["--type", "REG"])
    C.add(PF, "type-2", ["--type", "DIR", "LNK"])
    if V.get("file_path"):
        C.add(PF, "find", ["--find", V["file_path"]])
    C.add(PF, "find-none", ["--find", "/no/such/file"])
    IP = "linux.pagecache.InodePages"
    if V.get("inode_addr"):
        C.add(IP, "inode", ["--inode", hx(V["inode_addr"])])
        C.add(IP, "inode-dump", ["--inode", hx(V["inode_addr"]), "--dump"])
    if V.get("file_path"):
        C.add(IP, "find-dump", ["--find", V["file_path"], "--dump"])
    C.add(IP, "neither", [])
    C.add(IP, "find-none", ["--find", "/no/such/file"])
    C.add("linux.pagecache.RecoverFs", "tmpfs-only", ["--tmpfs-only"])
    C.add("linux.pagecache.RecoverFs", "tmpfs-bz2", ["--tmpfs-only", "--compression-format", "bz2"])
    C.add("linux.pagecache.RecoverFs", "tmpfs-xz", ["--tmpfs-only", "--compression-format", "xz"])
    C.add("linux.pagecache.RecoverFs", "bad-format", ["--compression-format", "zip"], est=5)
    CS = "linux.pscallstack.PsCallStack"
    C.add(CS, "pid-unres", ["--pid", pid1, "--unresolved"])
    C.add(CS, "pid-small", ["--pid", small], est=60)
    R = "linux.vmaregexscan.VmaRegExScan"
    C.add(R, "maxsize", ["--pid", pid1, "--pattern", r"[a-z]{6,}", "--maxsize", "0x1000"])
    C.add(R, "bad-regex", ["--pid", pid1, "--pattern", "(unclosed"])
    C.add(R, "nopid", ["--pattern", "rsvol-interactive-marker"], est=120)
    Y = "linux.vmayarascan.VmaYaraScan"
    C.add(Y, "file", ["--pid", pid1, "--yara-file", f"{inputs}/linux.yar"])
    C.add(Y, "compiled", ["--pid", pid1, "--yara-compiled-file", f"file://{inputs}/rules.yarc"])
    C.add(Y, "insensitive", ["--pid", pid1, "--yara-string", "RSVOL", "--insensitive"])
    C.add(Y, "wide", ["--pid", pid1, "--yara-string", "rsvol", "--wide"])
    C.add(Y, "hex", ["--pid", small, "--yara-string", "{7F 45 4C 46}"])
    C.add(Y, "maxsize", ["--pid", small, "--yara-string", "{7F 45 4C 46}", "--max-size", "64"])
    C.add(Y, "bad-rule", ["--pid", pid1, "--yara-file", f"{inputs}/bad.yar"])
    C.add(Y, "missing-uri", ["--pid", pid1, "--yara-file", "file:///nonexistent/rules.yar"])
    all_renderers(C, Y, "vmayara", ["--pid", small, "--yara-string", "{7F 45 4C 46}"])
    G = "yarascan.YaraScan"
    C.add(G, "file", ["--yara-file", f"{inputs}/linux.yar"], est=300)
    C.add(G, "no-rules", [], est=5)
    X = "regexscan.RegExScan"
    C.add(X, "maxsize", ["--pattern", "rsvol", "--maxsize", "4"])
    C.add(X, "bad-regex", ["--pattern", "(unclosed"], est=5)
    C.add("timeliner.Timeliner", "pf-pslist", ["--plugin-filter", "linux.pslist"], est=60)
    C.add("timeliner.Timeliner", "pf-body", ["--plugin-filter", "linux.pslist", "--create-bodyfile"], est=60)
    C.add("timeliner.Timeliner", "pf-record", ["--plugin-filter", "linux.pslist", "--record-config"], est=60)
    C.add("configwriter.ConfigWriter", "plain", [])
    C.add("configwriter.ConfigWriter", "extra", ["--extra"])
    C.add(L, "config-rt", ["--pid", pid1], mode="config")
    C.add(L, "saveconfig-twice", [], gopts=["--save-config", "saved.json"], mode="twice")
    C.add("linux.malware.check_modules.Check_modules", "dump", ["--dump"])
    C.add("linux.lsmod.Lsmod", "twice-dump", ["--dump"], mode="twice")
    C.add("linux.kallsyms.Kallsyms", "core-mod", ["--core", "--modules"])
    C.add("linux.bash.Bash", "pid-str", ["--pid", "1,2"], est=5)


def mac_values(img):
    V = {}
    ps = ref_rows(img, "mac.pslist.PsList")
    n2p = {}
    for r in ps:
        n2p.setdefault(r["NAME"], []).append(int(r["PID"]))
    V["pid1"] = min(n2p.get("Finder", n2p.get("loginwindow", [1])))
    V["pid_small"] = min(n2p.get("kextd", [1]))
    V["pids3"] = uniq([1, V["pid1"], min(n2p.get("launchservicesd", [0]))])
    for r in ref_rows(img, "mac.proc_maps.Maps"):
        if as_int(r.get("PID")) == V["pid_small"]:
            V["map_start"] = as_int(r["Start"])
            break
    return V


def gen_mac(C, V, inputs):
    pid1, small, p3 = V["pid1"], V["pid_small"], V["pids3"]
    V["base_args"] = {
        "regexscan.RegExScan": ["--pattern", "Mavericks"],
        "yarascan.YaraScan": ["--yara-string", "Mavericks"],
    }
    V["skip_flags"] = {"mac.proc_maps.Maps": ("dump",)}
    generic_cases(C, "mac", V)
    L = "mac.pslist.PsList"
    for m in ("tasks", "allproc", "process_group", "sessions", "pid_hash_table"):
        C.add(L, "method-" + m, ["--pslist-method", m])
    C.add(L, "method-bad", ["--pslist-method", "bogus"], est=5)
    C.add(L, "method-pid", ["--pslist-method", "allproc", "--pid"] + p3)
    invalid_cases(C, L)
    filter_cases(C, L, "NAME", "launch", "PID", "1")
    all_renderers(C, L, "pslist")
    all_renderers(C, "mac.pstree.PsTree", "pstree")
    all_renderers(C, "mac.malfind.Malfind", "malfind", ["--pid", pid1])
    M = "mac.proc_maps.Maps"
    if V.get("map_start"):
        C.add(M, "address", ["--pid", small, "--address", hx(V["map_start"])])
        C.add(M, "address-dump", ["--pid", small, "--address", hx(V["map_start"]), "--dump"])
    C.add(M, "dump-maxsize", ["--pid", small, "--dump", "--maxsize", "0x10000"])
    C.add(M, "twice-dump-max", ["--pid", small, "--dump", "--maxsize", "0x4000"], mode="twice")
    C.add(L, "config-rt", ["--pid", pid1], mode="config")
    C.add("timeliner.Timeliner", "pf-pslist", ["--plugin-filter", "mac.pslist"], est=60)
    X = "regexscan.RegExScan"
    C.add(X, "maxsize", ["--pattern", "Darwin", "--maxsize", "4"])
    C.add("yarascan.YaraScan", "hex", ["--yara-string", "{ 44 61 72 77 69 6E 20 4B 65 72 6E 65 6C }"])


def generic_plugins(C, os_name):
    """banners, frameworkinfo, isfinfo, ... (no OS prefix): renderers and flags."""
    C.add("banners.Banners", "r-json", gopts=["-r", "json"])
    C.add("frameworkinfo.FrameworkInfo", "r-csv", gopts=["-r", "csv"])
    C.add("frameworkinfo.FrameworkInfo", "r-json", gopts=["-r", "json"])
    C.add("isfinfo.IsfInfo", "filter", ["--filter", os_name])
    C.add("isfinfo.IsfInfo", "filter-2", ["--filter", os_name, "nosuch"])
    C.add("isfinfo.IsfInfo", "r-json", gopts=["-r", "json"])


# Cases left out because python needs minutes each and other cases cover the same code:
# (image regex, case id regex).
EXPENSIVE = [
    (r"jammy", r"RecoverFs"),
    (r"noble", r"RecoverFs~(r-|flag-)"),
    (r".*", r"^timeliner\.Timeliner~(flag-|r-|savecfg)"),  # full timeliner runs; the pf-* cases filter
    (r".*", r"PsCallStack~(pid3|pid-none|flag-unresolved|r-)"),
    (r"win1809|jammy", r"^yarascan\.YaraScan~file"),
    (r"jammy", r"pagecache\.(Files~(type-reg|type-2|find-none)|InodePages~(neither|flag-dump|find-none|find-dump))"),
]


def cmd_gen(args):
    plugins = load_plugins()
    inputs = write_inputs()
    os.makedirs(SCR + "/cases", exist_ok=True)
    os.makedirs(SCR + "/harvest", exist_ok=True)
    for img in args.img:
        im = IMAGES[img]
        C = Cases(img, plugins, ref_times(img))
        if im["os"] == "windows":
            V = windows_values(img, args.bin)
            gen_windows(C, V, inputs)
        elif im["os"] == "linux":
            V = linux_values(img)
            gen_linux(C, V, inputs)
        else:
            V = mac_values(img)
            gen_mac(C, V, inputs)
        generic_plugins(C, im["os"])
        C.cases = [c for c in C.cases if not any(re.fullmatch(i, img) and re.search(x, c["id"]) for i, x in EXPENSIVE)]
        json.dump(V, open(f"{SCR}/harvest/{img}.json", "w"), indent=1, default=str)
        with open(f"{SCR}/cases/{img}.jsonl", "w") as f:
            for c in C.cases:
                f.write(json.dumps(c) + "\n")
        print(f"{img}: {len(C.cases)} cases, est python {sum(min(c['est'], PY_TIMEOUT) for c in C.cases) / 60:.0f} min")


# ------------------------------------------------------------------------------------------------
# running


def load_cases(img):
    try:
        return [json.loads(line) for line in open(f"{SCR}/cases/{img}.jsonl")]
    except OSError:
        return []


def cache_args(img):
    """A private python identifier cache per image, for both sides: every python run rewrites
    identifier.cache for its own symbol directories (a run without -s drops the testdata ISFs, one
    with -s adds them back as the newest rows), and which of two copies of an ISF python loads
    (`find_location`: the last row) follows that history. Concurrent runs on other images (or by
    other agents) would make python's choice racy."""
    os.makedirs(f"{SCR}/pycache-{img}", exist_ok=True)  # python fails on a missing directory
    return ["--cache-path", f"{SCR}/pycache-{img}"]


def full_argv(img, case, run_dir, extra_first=None):
    im = IMAGES[img]
    base = ["-q"] + cache_args(img) + (["-s", SYM] if im["sym"] else [])
    if not case.get("nof"):
        base += ["-f", im["path"]]
    base += ["-o", run_dir + "/files"]
    return base + (extra_first or []) + case["argv"]


def manifest(run_dir):
    m = {}
    for sub in ("files", "cwd"):
        top = os.path.join(run_dir, sub)
        for dp, _dn, fns in os.walk(top):
            for fn in fns:
                p = os.path.join(dp, fn)
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                m[sub + "/" + os.path.relpath(p, top)] = [os.path.getsize(p), h.hexdigest()]
    return m


def env_for():
    e = dict(os.environ)
    e["COLUMNS"] = "80"
    e["RSVOL_CACHE"] = SCR + "/rscache"
    e.pop("RSVOL_TRACE", None)
    return e


def run_one(cmd_prefix, img, case, run_dir, timeout):
    """Runs a case (all its runs) into run_dir; returns the meta dict."""
    shutil.rmtree(run_dir, ignore_errors=True)
    os.makedirs(run_dir + "/files")
    os.makedirs(run_dir + "/cwd")
    meta = dict(argv=case["argv"], mode=case["mode"], runs=[])
    runs = []
    if case["mode"] == "run":
        runs = [full_argv(img, case, run_dir)]
    elif case["mode"] == "twice":
        runs = [full_argv(img, case, run_dir)] * 2
    elif case["mode"] == "config":
        runs = [full_argv(img, case, run_dir, ["--save-config", "saved.json"])]
        im = IMAGES[img]
        runs.append(["-q"] + cache_args(img) + (["-s", SYM] if im["sym"] else []) + ["-o", run_dir + "/files", "-c", "saved.json", case["argv"][0]])
    for i, argv in enumerate(runs):
        t0 = time.time()
        try:
            r = subprocess.run(cmd_prefix(timeout) + argv, cwd=run_dir + "/cwd", capture_output=True, env=env_for())
            rc, out, err = r.returncode, r.stdout, r.stderr
        except Exception as e:  # noqa: BLE001
            rc, out, err = -999, b"", str(e).encode()
        secs = time.time() - t0
        sfx = "" if i == len(runs) - 1 else str(i + 1)
        open(f"{run_dir}/out{sfx}.txt", "wb").write(out)
        open(f"{run_dir}/err{sfx}.txt", "wb").write(err)
        meta["runs"].append(dict(rc=rc, secs=round(secs, 3)))
        if rc == 124:  # timeout(1)
            meta["timeout"] = True
            break
    meta["rc"] = meta["runs"][-1]["rc"]
    meta["files"] = manifest(run_dir)
    json.dump(meta, open(run_dir + "/meta.json", "w"), indent=1)
    return meta


def py_prefix(timeout):
    return [LIMIT, "-m", "8G", "timeout", str(timeout), "nice", "-n", "10", PY, VOLPY]


def rs_prefix_for(binary):
    link_dir = SCR + "/bin"
    os.makedirs(link_dir, exist_ok=True)
    link = link_dir + "/vol.py"  # argparse messages use the program name: python's is vol.py
    target = os.path.abspath(binary)
    try:
        if os.readlink(link) != target:
            os.unlink(link)
            os.symlink(target, link)
    except OSError:
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(target, link)

    def prefix(timeout):
        return [LIMIT, "-p", "sweeprs", "-s", "3", "-m", "4G", "timeout", str(timeout), link]

    return prefix


def select(args, img):
    cases = load_cases(img)
    if args.match:
        rx = re.compile(args.match)
        cases = [c for c in cases if rx.search(c["id"])]
    return cases


def cmd_py(args):
    jobs = []
    for img in args.img:
        for c in select(args, img):
            d = f"{SCR}/py/{img}/{c['id']}"
            if os.path.exists(d + "/meta.json") and not args.force:
                continue
            if c["est"] > args.max_est:
                continue
            lab = c["id"].split("~", 1)[1]
            phase = 2 if lab.startswith("r-") else 1 if lab.startswith("R") else 0
            second = 1 if img in SECOND_IMAGES else 0  # the second image of an OS: later
            jobs.append(((phase, second, c["est"]), img, c))
    # breadth first: options before renderers, cheapest first
    jobs.sort(key=lambda j: (j[0], j[2]["id"]))
    print(f"{len(jobs)} python cases to run", flush=True)
    lock = threading.Lock()
    done = [0]

    running = [0]

    def work(j):
        _e, img, c = j
        d = f"{SCR}/py/{img}/{c['id']}"
        # `touch SCR/pause` holds new python runs, `touch SCR/throttle` allows one at a time
        # (while the gates run their own python)
        while True:
            with lock:
                if not os.path.exists(SCR + "/pause") and (running[0] == 0 or not os.path.exists(SCR + "/throttle")):
                    running[0] += 1
                    break
            time.sleep(2)
        try:
            m = run_one(py_prefix, img, c, d, PY_TIMEOUT)
        finally:
            with lock:
                running[0] -= 1
        with lock:
            done[0] += 1
            print(f"[{done[0]}/{len(jobs)}] {img} {c['id']} rc={m['rc']} {sum(r['secs'] for r in m['runs']):.1f}s", flush=True)

    with cf.ThreadPoolExecutor(max(1, min(args.jobs, 2))) as ex:
        list(ex.map(work, jobs))


def norm(data, run_dir):
    return data.replace(run_dir.encode(), b"<RUN>")


def last_line(b):
    lines = [x for x in b.decode("utf-8", "replace").split("\n") if x.strip()]
    return lines[-1] if lines else ""


# Known, documented differences (README "Known differences"): (case id regex, reason).
KNOWN = [
    (r"~compiled$", "--yara-compiled-file (libyara's compiled rules format) is not supported"),
]


def sort_strings_revmap(data):
    """windows.strings: each string's mappings come from a python set of (name, offset) tuples
    (hash-randomized order). Compare them as sets."""
    out = []
    for line in data.split(b"\n"):
        f = line.split(b"\t")
        if len(f) > 1:
            f[-1] = b", ".join(sorted(f[-1].split(b", ")))
        out.append(b"\t".join(f))
    return b"\n".join(out)


def sort_last_field_items(data):
    """linux.mountinfo --mount-format joins a python set of mount options: the order follows
    the per-process string hash seed, so python itself is nondeterministic. Compare the
    options as sets."""
    out = []
    for line in data.split(b"\n"):
        f = line.split(b"\t")
        if len(f) > 1:
            f[-1] = b",".join(sorted(f[-1].split(b",")))
        out.append(b"\t".join(f))
    return b"\n".join(out)


# python-nondeterministic output: (predicate on the case, normalization applied to both sides)
SET_ORDER = [
    (lambda c: c["plugin"] == "windows.strings.Strings", sort_strings_revmap),
    (lambda c: c["plugin"] == "linux.mountinfo.MountInfo" and "--mount-format" in c["argv"], sort_last_field_items),
]


def tar_members(path):
    """linux.pagecache.RecoverFs stamps every tar member (and the gzip header) with
    time.time() of the run: compare the members without their times."""
    import tarfile  # noqa: PLC0415

    out = []
    with tarfile.open(path) as t:
        for m in t.getmembers():
            data = t.extractfile(m).read() if m.isfile() else b""
            out.append((m.name, m.type, m.mode, m.size, m.linkname, m.uid, m.gid, hashlib.sha256(data).hexdigest()))
    return out


def compare(img, case, pd, rd):
    pm = json.load(open(pd + "/meta.json"))
    rm = json.load(open(rd + "/meta.json"))
    if pm.get("timeout"):
        return "PY-TIMEOUT", ""
    if any(r["rc"] in (137, -9) for r in pm["runs"]):
        return "PY-KILLED", "python exceeded limit.sh's memory cap"
    if rm.get("timeout"):
        return "RS-TIMEOUT", ""
    for rx, why in KNOWN:
        if re.search(rx, case["id"]):
            return "KNOWN", why
    probs = []
    setnorm = [f for pred, f in SET_ORDER if pred(case)]
    nondet = case["plugin"] in {x.strip() for x in open(NONDET) if x.strip() and not x.startswith("#")}
    order = False
    outs = ["out.txt"] + [f"out{i + 1}.txt" for i in range(len(pm["runs"]) - 1)]
    for o in outs:
        a = norm(open(f"{pd}/{o}", "rb").read(), pd)
        b = norm(open(f"{rd}/{o}", "rb").read(), rd)
        if a != b and setnorm and setnorm[0](a) == setnorm[0](b):
            order = True
        elif a != b:
            if sorted(a.split(b"\n")) == sorted(b.split(b"\n")):
                order = True
            else:
                probs.append(o)
    for i, (x, y) in enumerate(zip(pm["runs"], rm["runs"])):
        if x["rc"] != y["rc"]:
            probs.append(f"rc{i + 1}:{x['rc']}!={y['rc']}")
    if pm["rc"] != 0 and pm["rc"] == rm["rc"]:
        pe = open(pd + "/err.txt", "rb").read()
        re_ = open(rd + "/err.txt", "rb").read()
        if pm["rc"] == 2:
            if norm(pe, pd) != norm(re_, rd):
                probs.append("stderr")
        elif norm(last_line(pe).encode(), pd) != norm(last_line(re_).encode(), rd):
            probs.append("errline")
    pf, rf = pm["files"], rm["files"]
    if set(pf) != set(rf):
        probs.append(f"filenames(py {len(pf)} rs {len(rf)})")
    else:
        bad = [k for k in pf if pf[k] != rf[k]]
        # python-nondeterministic file contents: compare them normalized
        timed = [k for k in bad if re.search(r"recovered_fs\.tar\.(gz|bz2|xz)$", k)]
        if timed and all(tar_members(f"{pd}/{k}") == tar_members(f"{rd}/{k}") for k in timed):
            bad = [k for k in bad if k not in timed]
            order = True
            setnorm = setnorm or [None]
        if bad:
            probs.append(f"filedata({len(bad)}/{len(pf)})")
    if not probs:
        if order:
            return ("OK~" if nondet or setnorm else "ORDER"), ""
        return "OK", ""
    return "DIFF", " ".join(probs)


def cmd_rs(args):
    prefix = rs_prefix_for(args.bin)
    os.makedirs(SCR + "/report", exist_ok=True)
    for img in args.img:
        prev = {}
        rep = f"{SCR}/report/{img}.tsv"
        if os.path.exists(rep):
            for line in open(rep):
                f = line.rstrip("\n").split("\t")
                if len(f) >= 2:
                    prev[f[0]] = f
        cases = [c for c in select(args, img) if os.path.exists(f"{SCR}/py/{img}/{c['id']}/meta.json")]
        # forget comparisons whose python result was deleted (to be rerun)
        prev = {k: v for k, v in prev.items() if os.path.exists(f"{SCR}/py/{img}/{k}/meta.json")}
        if args.failed:
            cases = [c for c in cases if c["id"] in prev and not prev[c["id"]][1].startswith("OK")]
        # live cases rerun python: only with --live (keep within the python process budget)
        cases = [c for c in cases if not c.get("live") or args.live]
        # incremental: skip cases compared after both the python run and the binary changed
        if not args.force:
            bin_t = os.path.getmtime(os.path.realpath(args.bin))

            def stale(c):
                rm = f"{SCR}/rs/{img}/{c['id']}/meta.json"
                if c["id"] not in prev or not os.path.exists(rm):
                    return True
                t = os.path.getmtime(rm)
                return t < bin_t or t < os.path.getmtime(f"{SCR}/py/{img}/{c['id']}/meta.json")

            cases = [c for c in cases if stale(c)]
        lock = threading.Lock()

        live_lock = threading.Lock()

        def work(c):
            pd = f"{SCR}/py/{img}/{c['id']}"
            rd = f"{SCR}/rs/{img}/{c['id']}"
            if c.get("live"):
                with live_lock:  # one python at a time, and rsvol right after it
                    run_one(py_prefix, img, c, pd, PY_TIMEOUT)
                    run_one(prefix, img, c, rd, RS_TIMEOUT)
            else:
                run_one(prefix, img, c, rd, RS_TIMEOUT)
            st, det = compare(img, c, pd, rd)
            with lock:
                prev[c["id"]] = [c["id"], st, det]
                if not st.startswith("OK"):
                    print(f"{img} {st} {c['id']} {det}", flush=True)

        with cf.ThreadPoolExecutor(max(1, args.jobs)) as ex:
            list(ex.map(work, cases))
        with open(rep, "w") as f:
            for k in sorted(prev):
                f.write("\t".join(prev[k]) + "\n")
        summarize(img, prev)


def summarize(img, rows, verbose=False):
    cnt = {}
    for f in rows.values():
        cnt[f[1]] = cnt.get(f[1], 0) + 1
    total = len(load_cases(img))
    print(f"== {img}: cases={total} compared={len(rows)} " + " ".join(f"{k}={v}" for k, v in sorted(cnt.items())))
    if verbose:
        for k in sorted(rows):
            if not rows[k][1].startswith("OK"):
                print("  ", "\t".join(rows[k]))


def cmd_report(args):
    for img in args.img:
        rows = {}
        rep = f"{SCR}/report/{img}.tsv"
        if os.path.exists(rep):
            for line in open(rep):
                f = line.rstrip("\n").split("\t")
                rows[f[0]] = f
        summarize(img, rows, args.verbose)
        pending = [c for c in load_cases(img) if not os.path.exists(f"{SCR}/py/{img}/{c['id']}/meta.json")]
        if pending:
            print(f"   python pending: {len(pending)} (est {sum(min(c['est'], PY_TIMEOUT) for c in pending) / 60:.0f} min)")


def cmd_show(args):
    pd = f"{SCR}/py/{args.image}/{args.case}"
    rd = f"{SCR}/rs/{args.image}/{args.case}"
    pm = json.load(open(pd + "/meta.json"))
    rm = json.load(open(rd + "/meta.json"))
    print("argv:", " ".join(pm["argv"]), "| mode", pm["mode"])
    print("rc py", [r["rc"] for r in pm["runs"]], "rs", [r["rc"] for r in rm["runs"]])
    for o in ["out.txt"] + [f"out{i + 1}.txt" for i in range(len(pm["runs"]) - 1)]:
        a = norm(open(f"{pd}/{o}", "rb").read(), pd).decode("utf-8", "replace").splitlines()
        b = norm(open(f"{rd}/{o}", "rb").read(), rd).decode("utf-8", "replace").splitlines()
        d = list(difflib.unified_diff(a, b, "py/" + o, "rs/" + o, lineterm="", n=1))
        print("\n".join(d[: args.lines]))
    for e in ("err.txt",):
        print(f"-- py {e} (tail):", "\n".join(open(f"{pd}/{e}", errors="replace").read().splitlines()[-4:]))
        print(f"-- rs {e} (tail):", "\n".join(open(f"{rd}/{e}", errors="replace").read().splitlines()[-4:]))
    pf, rf = pm["files"], rm["files"]
    for k in sorted(set(pf) | set(rf)):
        if pf.get(k) != rf.get(k):
            print("file", k, "py", pf.get(k), "rs", rf.get(k))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("gen", "py", "rs", "report"):
        s = sub.add_parser(name)
        s.add_argument("-i", "--img", nargs="+", default=list(IMAGES), choices=list(IMAGES))
        s.add_argument("-m", "--match", default=None)
        s.add_argument("-j", "--jobs", type=int, default=2)
        s.add_argument("-b", "--bin", default=HERE + "/target/release/vol")
        s.add_argument("-v", "--verbose", action="store_true")
        s.add_argument("--max-est", type=float, default=PY_TIMEOUT)
        s.add_argument("--force", action="store_true")
        s.add_argument("--failed", action="store_true")
        s.add_argument("--live", action="store_true", help="rs: also the live cases (reruns python)")
    s = sub.add_parser("show")
    s.add_argument("image")
    s.add_argument("case")
    s.add_argument("-n", "--lines", type=int, default=40)
    args = ap.parse_args()
    {"gen": cmd_gen, "py": cmd_py, "rs": cmd_rs, "report": cmd_report, "show": cmd_show}[args.cmd](args)


if __name__ == "__main__":
    main()
