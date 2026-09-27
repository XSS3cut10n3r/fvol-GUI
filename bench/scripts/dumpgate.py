#!/usr/bin/env python3
"""Dump-parity gate: the files the dumping plugins write (names + contents), plus their stdout
and exit code, compared between python volatility3 2.28.2 and fastvol on every image of
bench/images.tsv (and the main image through its existing bench/ref/pyargs references).

The other gates compare stdout only, and the multi-image references run plugins without
arguments, so a dump whose bytes differ from python's (while the printed file name matches)
went unnoticed there. This gate runs the --dump variants of every file-writing plugin.

Usage (see check_dumps.sh):  dumpgate.py [-b BIN] [--py-only | --rs-only] [-c CASE_GLOB]
                                         [--list] [NAME|GLOB ...]
    NAME        image names of bench/images.tsv (bash-style globs allowed) or "main"; default: all
    -c GLOB     only cases whose id matches (e.g. 'vadinfo*'); repeatable
    --py-only   only generate the missing python references
    --rs-only   only compare against the cached references (cases without one: NOREF)

Python references are cached under testdata/scratch/dumpgate/py/<image>/<case>/ (meta.json,
stdout.txt, stderr.txt, files.json): python runs once per case, never more than one python at a
time, through limit.sh (8G cap) with a 15 minute timeout; a case whose python run times out or
is killed (memory) is recorded as skipped and not retried (delete its dir to retry). The dumps
themselves can be tens of GB: they are hashed (SHA-256; tarballs by member, see below) and
deleted right away, on both sides.

Comparison: exit code, stdout byte for byte, and the dumped files: the same names, and for
each the same size and SHA-256. RecoverFs tarballs (recovered_fs.tar.{gz,bz2,xz}) are compared
by member (name, type, size, mode, uid/gid, user/group names, link target, content SHA-256):
the compressed bytes differ by design (python stamps the current time into the member mtimes
and the gzip header, and fastvol's compression level is its own choice).

Seeds (no python run needed): the main image's cases come from bench/ref/pyargs (stdout +
dump/<case>/), and a case identical to a no-argument reference of py_refs_images.sh
(dumpfiles, RecoverFs) is seeded from <ref_dir>/<plugin>.txt + <ref_dir>/dump/<plugin>/.
"""
import argparse
import concurrent.futures as cf
import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time

ROOT = "/home/user/rs-vol"
SCR = ROOT + "/testdata/scratch/dumpgate"
PY = ROOT + "/bench/venv/bin/python"
VOLPY = ROOT + "/volatility3/vol.py"
LIMIT = ROOT + "/bench/scripts/limit.sh"
MANIFEST = os.environ.get("MANIFEST", ROOT + "/bench/images.tsv")
MAIN_IMG = "/home/user/cbc2/task2/memory-dirty.raw"
PY_TIMEOUT = int(os.environ.get("PY_TIMEOUT", 900))
RS_TIMEOUT = int(os.environ.get("RS_TIMEOUT", 1800))
TAR_NAMES = ("recovered_fs.tar.gz", "recovered_fs.tar.bz2", "recovered_fs.tar.xz")


def images():
    out = []
    for line in open(MANIFEST):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        name, os_, img, symargs, refdir = f[:5]
        out.append(dict(name=name, os=os_, img=img, symargs=[] if symargs == "-" else symargs.split(), refdir=refdir))
    out.append(dict(name="main", os="windows", img=MAIN_IMG, symargs=[], refdir=ROOT + "/bench/ref/py"))
    return out


def ref_rows(refdir, plugin):
    """Rows (lists of cells) of a python reference output (quick renderer), header excluded."""
    p = os.path.join(refdir, plugin + ".txt")
    if not os.path.exists(p):
        return []
    lines = [l.rstrip("\n") for l in open(p, errors="replace")]
    # banner, blank, header, blank, rows...
    rows = [l.split("\t") for l in lines[4:] if l]
    return rows


def pick_windows(refdir):
    """(pid, image base of its exe) of a typical user process, and the kernel base."""
    procs = ref_rows(refdir, "windows.pslist.PsList")
    pid = None
    for want in ("explorer.exe", "lsass.exe", "services.exe", "winlogon.exe"):
        for r in procs:
            if len(r) > 2 and r[2].lower() == want:
                pid = r[0]
                break
        if pid:
            break
    if pid is None and procs:
        pid = procs[-1][0]
    base = None
    for r in ref_rows(refdir, "windows.dlllist.DllList"):
        if r and r[0] == pid and len(r) > 2 and r[2].startswith("0x"):
            base = r[2]
            break
    kbase = None
    mods = ref_rows(refdir, "windows.modules.Modules")
    if mods and len(mods[0]) > 1 and mods[0][1].startswith("0x"):
        kbase = mods[0][1]
    return pid, base, kbase


def pick_inode(refdir):
    """A regular file with cached pages (linux.pagecache.Files): its inode address."""
    best = None
    for r in ref_rows(refdir, "linux.pagecache.Files"):
        if len(r) > 7 and r[5] == "REG" and r[4].startswith("0x") and r[7].isdigit() and 0 < int(r[7]) <= 4096:
            if best is None or int(r[7]) > best[0]:
                best = (int(r[7]), r[4])
    return best[1] if best else None


def cases(im):
    """[(case id, plugin argv)] for an image."""
    rd = im["refdir"]
    if im["name"] == "main":
        # the pyargs dump cases (bench/args_cases.txt), references already on disk
        c = []
        for line in open(ROOT + "/bench/args_cases.txt"):
            name, args = line.rstrip("\n").split("\t", 1)
            d = ROOT + "/bench/ref/pyargs/dump/" + name
            if os.path.isdir(d) and os.listdir(d):
                c.append((name, args.replace('"', "").split()))
        return c
    if im["os"] == "windows":
        c = [
            ("pslist_dump", ["windows.pslist.PsList", "--dump"]),
            ("psscan_dump", ["windows.psscan.PsScan", "--dump"]),
            ("dlllist_dump", ["windows.dlllist.DllList", "--dump"]),
            ("modules_dump", ["windows.modules.Modules", "--dump"]),
            ("modscan_dump", ["windows.modscan.ModScan", "--dump"]),
            ("vadinfo_dump", ["windows.vadinfo.VadInfo", "--dump"]),
            ("malfind_dump", ["windows.malware.malfind.Malfind", "--dump"]),
            ("dumpfiles", ["windows.dumpfiles.DumpFiles"]),
            ("hivelist_dump", ["windows.registry.hivelist.HiveList", "--dump"]),
            ("certificates_dump", ["windows.registry.certificates.Certificates", "--dump"]),
            ("layerwriter", ["layerwriter.LayerWriter"]),
        ]
        pid, base, kbase = pick_windows(rd)
        if pid:
            c.append(("memmap_pid_dump", ["windows.memmap.Memmap", "--pid", pid, "--dump"]))
            if base:
                c.append(("pedump_pid", ["windows.pedump.PEDump", "--pid", pid, "--base", base]))
        if kbase:
            c.append(("pedump_kernel", ["windows.pedump.PEDump", "--kernel-module", "--base", kbase]))
        return c
    if im["os"] == "linux":
        c = [
            ("pslist_dump", ["linux.pslist.PsList", "--dump"]),
            ("elfs_dump", ["linux.elfs.Elfs", "--dump"]),
            ("lsmod_dump", ["linux.lsmod.Lsmod", "--dump"]),
            ("maps_dump", ["linux.proc.Maps", "--dump"]),
            ("recoverfs", ["linux.pagecache.RecoverFs"]),
            ("fbdev_dump", ["linux.graphics.fbdev.Fbdev", "--dump"]),
            ("layerwriter", ["layerwriter.LayerWriter"]),
        ]
        ino = pick_inode(rd)
        if ino:
            c.append(("inodepages_dump", ["linux.pagecache.InodePages", "--inode", ino, "--dump"]))
        return c
    return [
        ("maps_dump", ["mac.proc_maps.Maps", "--dump"]),
        ("layerwriter", ["layerwriter.LayerWriter"]),
    ]


# ------------------------------------------------------------------------------ manifests


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(8 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def tar_manifest(path):
    """Members of a tarball, independent of its compression and of the member mtimes."""
    h = hashlib.sha256()
    n = 0
    with tarfile.open(path, "r:*") as t:
        for m in t:
            data = ""
            if m.isreg():
                f = t.extractfile(m)
                dh = hashlib.sha256()
                while True:
                    b = f.read(8 << 20)
                    if not b:
                        break
                    dh.update(b)
                data = dh.hexdigest()
            rec = [m.name, m.type.decode("latin-1"), m.size, m.mode, m.uid, m.gid, m.uname, m.gname, m.linkname, data]
            h.update((json.dumps(rec) + "\n").encode())
            n += 1
    return "tar:%d:%s" % (n, h.hexdigest())


def file_entry(path, name):
    size = os.path.getsize(path)
    if name in TAR_NAMES:
        try:
            return [None, tar_manifest(path)]
        except Exception as e:  # a broken archive must not match anything
            return [size, "tar-error:%s:%s" % (type(e).__name__, sha256_file(path))]
    return [size, sha256_file(path)]


def manifest(d):
    """{relative path: [size, sha256]} of every file under d (empty dict if d is missing)."""
    paths = []
    if os.path.isdir(d):
        for root, _, files in os.walk(d):
            for f in files:
                p = os.path.join(root, f)
                paths.append((p, os.path.relpath(p, d)))
    # biggest first: hashing is IO + SHA bound, spread over threads
    paths.sort(key=lambda x: -os.path.getsize(x[0]))
    with cf.ThreadPoolExecutor(8) as ex:
        ents = list(ex.map(lambda x: file_entry(x[0], os.path.basename(x[1])), paths))
    return {rel: e for (_, rel), e in zip(paths, ents)}


# ------------------------------------------------------------------------------ runs


def rm(d):
    shutil.rmtree(d, ignore_errors=True)


def run_side(cmd, work, timeout_rc_as_skip):
    """Run cmd with -o work/files; returns meta dict + stdout bytes."""
    rm(work)
    os.makedirs(work + "/files")
    t0 = time.time()
    with open(work + "/stdout.txt", "wb") as so, open(work + "/stderr.txt", "wb") as se:
        rc = subprocess.run(cmd, stdout=so, stderr=se, cwd=work).returncode
    secs = round(time.time() - t0, 1)
    files = manifest(work + "/files")
    rm(work + "/files")
    meta = dict(rc=rc, secs=secs, argv=cmd)
    if timeout_rc_as_skip and rc == 124:
        meta["skip"] = "python timed out (%d s)" % PY_TIMEOUT
    elif timeout_rc_as_skip and rc in (137, -9):
        meta["skip"] = "python killed (memory cap?)"
    with open(work + "/files.json", "w") as f:
        json.dump(files, f, indent=0, sort_keys=True)
    with open(work + "/meta.json", "w") as f:
        json.dump(meta, f)
    return meta


def py_dir(im, cid):
    return "%s/py/%s/%s" % (SCR, im["name"], cid)


def seed(im, cid, argv):
    """Create the python cache entry from existing references, if there are any."""
    d = py_dir(im, cid)
    if im["name"] == "main":
        src_txt = ROOT + "/bench/ref/pyargs/%s.txt" % cid
        src_dump = ROOT + "/bench/ref/pyargs/dump/" + cid
        rc = 0
        for line in open(ROOT + "/bench/ref/pyargs/times.tsv"):
            f = line.split("\t")
            if f[0] == cid:
                rc = int(f[1])
    elif cid in ("dumpfiles", "recoverfs"):
        plugin = argv[0]
        src_txt = "%s/%s.txt" % (im["refdir"], plugin)
        src_dump = "%s/dump/%s" % (im["refdir"], plugin)
        rc = None
        tpath = im["refdir"] + "/times.tsv"
        if os.path.exists(tpath):
            for line in open(tpath):
                f = line.split("\t")
                if f[0] == plugin:
                    rc = int(f[1])
        if rc is None:
            return False
    else:
        return False
    if not os.path.exists(src_txt):
        return False
    os.makedirs(d, exist_ok=True)
    shutil.copyfile(src_txt, d + "/stdout.txt")
    files = manifest(src_dump)
    with open(d + "/files.json", "w") as f:
        json.dump(files, f, indent=0, sort_keys=True)
    with open(d + "/meta.json", "w") as f:
        json.dump(dict(rc=rc, secs=None, argv=argv, seeded_from=src_txt), f)
    return True


def ensure_py(im, cid, argv):
    d = py_dir(im, cid)
    if os.path.exists(d + "/meta.json"):
        return json.load(open(d + "/meta.json"))
    if seed(im, cid, argv):
        return json.load(open(d + "/meta.json"))
    if im["name"] == "main":
        return None
    cache = SCR + "/pycache"
    os.makedirs(cache, exist_ok=True)
    cmd = [LIMIT, "-m", "8G", "timeout", str(PY_TIMEOUT), "nice", "-n", "10", PY, VOLPY, "-q", "--cache-path", cache]
    cmd += im["symargs"] + ["-o", "files", "-f", im["img"]] + argv
    print("  python %s %s ..." % (im["name"], cid), flush=True)
    meta = run_side(cmd, d, True)
    print("  python %s %s: rc=%s %.0fs %s" % (im["name"], cid, meta["rc"], meta["secs"], meta.get("skip", "")), flush=True)
    return meta


def compare(im, cid, argv, binary, show):
    pd = py_dir(im, cid)
    pm = json.load(open(pd + "/meta.json"))
    if pm.get("skip"):
        return "SKIP", pm["skip"]
    rd = "%s/rs/%s/%s" % (SCR, im["name"], cid)
    cmd = [LIMIT, "-m", "8G", "timeout", str(RS_TIMEOUT), binary, "-q"] + im["symargs"] + ["-o", "files", "-f", im["img"]] + argv
    rm_ = run_side(cmd, rd, False)
    probs = []
    if rm_["rc"] != pm["rc"]:
        probs.append("exit code %s, python %s" % (rm_["rc"], pm["rc"]))
    a = open(pd + "/stdout.txt", "rb").read()
    b = open(rd + "/stdout.txt", "rb").read()
    if a != b:
        al, bl = a.splitlines(), b.splitlines()
        nd = sum(1 for x, y in zip(al, bl) if x != y) + abs(len(al) - len(bl))
        first = next((i for i, (x, y) in enumerate(zip(al, bl)) if x != y), min(len(al), len(bl)))
        probs.append("stdout: %d lines differ; first at line %d:\n      py: %r\n      rs: %r" % (nd, first + 1, al[first] if first < len(al) else "<eof>", bl[first] if first < len(bl) else "<eof>"))
    pf = json.load(open(pd + "/files.json"))
    rf = json.load(open(rd + "/files.json"))
    if pf != rf:
        only_p = sorted(set(pf) - set(rf))
        only_r = sorted(set(rf) - set(pf))
        diff = sorted(k for k in set(pf) & set(rf) if pf[k] != rf[k])
        msg = "files: python %d, fastvol %d; %d only python, %d only fastvol, %d differ" % (len(pf), len(rf), len(only_p), len(only_r), len(diff))
        det =["      only python: " + k for k in only_p[:show]]
        det += ["      only fastvol:  " + k for k in only_r[:show]]
        det += ["      differ:      %s (python %s, fastvol %s)" % (k, pf[k][0], rf[k][0]) for k in diff[:show]]
        probs.append(msg + ("\n" + "\n".join(det) if det else ""))
    nfiles = len(rf)
    if probs:
        return "DIFF", "\n    ".join(probs)
    return "OK", "%d files, %.1fs (python %ss)" % (nfiles, rm_["secs"], pm.get("secs"))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-b", "--bin", default=ROOT + "/target/release/fvol")
    ap.add_argument("-c", "--case", action="append", default=[])
    ap.add_argument("--py-only", action="store_true")
    ap.add_argument("--rs-only", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--show", type=int, default=5, help="file names shown per DIFF")
    ap.add_argument("names", nargs="*")
    a = ap.parse_args()
    sel = [im for im in images() if not a.names or any(fnmatch.fnmatchcase(im["name"], n) for n in a.names)]
    tot = {}
    for im in sel:
        if not os.path.exists(im["img"]):
            print("== %s: image missing (%s)" % (im["name"], im["img"]))
            continue
        cs = [(cid, argv) for cid, argv in cases(im) if not a.case or any(fnmatch.fnmatchcase(cid, g) for g in a.case)]
        if a.list:
            for cid, argv in cs:
                have = os.path.exists(py_dir(im, cid) + "/meta.json")
                print("%-28s %-18s %s %s" % (im["name"], cid, "ref" if have else "-  ", " ".join(argv)))
            continue
        cnt = {}
        for cid, argv in cs:
            if not a.rs_only:
                ensure_py(im, cid, argv)
            elif not os.path.exists(py_dir(im, cid) + "/meta.json"):
                seed(im, cid, argv)  # existing references need no python run
            if a.py_only:
                continue
            if not os.path.exists(py_dir(im, cid) + "/meta.json"):
                st, det = "NOREF", ""
            else:
                st, det = compare(im, cid, argv, a.bin, a.show)
            cnt[st] = cnt.get(st, 0) + 1
            if st != "OK" or os.environ.get("VERBOSE"):
                print("[%s] %s %s  %s" % (im["name"], st, cid, det), flush=True)
        if not a.py_only:
            print("== %s: %s" % (im["name"], " ".join("%s=%d" % kv for kv in sorted(cnt.items()))), flush=True)
            for k, v in cnt.items():
                tot[k] = tot.get(k, 0) + v
    if not a.py_only and not a.list:
        print("== TOTAL: %s" % " ".join("%s=%d" % kv for kv in sorted(tot.items())))
        sys.exit(1 if tot.get("DIFF") else 0)


if __name__ == "__main__":
    main()
