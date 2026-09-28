#!/usr/bin/env python3
"""python `re` throughput over an mmapped window of a memory image (the reference for
fastvol's regex engine; see bench/scripts/refbench.sh for the full comparison).

For every case of bench/refbench/regex_cases.tsv: compile time (re.purge() first, best
of N) and `finditer` over the window (best of N), printing one machine-readable line

  BENCH <TAB> python-re <TAB> case <TAB> compile_us <TAB> best_s <TAB> MB/s <TAB> matches <TAB> note

The window is mmapped (never read into memory); python re scans mmap objects directly.
python re is slow on class-heavy patterns, so `--len` may be smaller than the other
engines' window: MB/s is window-size independent, the match count then covers only the
smaller window (the note says so and refbench.sh cross-checks it against a rust run over
the same smaller window).

usage: regex_bench.py [--img IMG] [--off OFF] [--len LEN] [--reps N] [--cases FILE]
                      [--only name,name] [--budget SECONDS]
"""
import argparse
import mmap
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA = os.environ.get("FASTVOL_DATA") or os.path.dirname(subprocess.run(
    ["git", "-C", ROOT, "rev-parse", "--path-format=absolute", "--git-common-dir"],
    capture_output=True, text=True).stdout.strip() or os.path.join(ROOT, ".git"))


def parse_size(s):
    """int with optional K/M/G suffix (binary), e.g. 256M, 0x40000000."""
    mul = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}.get(s[-1:].upper(), 1)
    return int(s[:-1] if mul > 1 else s, 0) * mul


def load_cases(path):
    out = []
    with open(path, "rb") as fh:
        for line in fh:
            line = line.rstrip(b"\r\n")
            if not line or line.startswith(b"#"):
                continue
            name, pat = line.split(b"\t", 1)
            out.append((name.decode(), pat))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--img", default=os.path.join(DATA, "testdata/images/windows/memory-dirty.raw"))
    ap.add_argument("--off", type=parse_size, default=1 << 30)
    ap.add_argument("--len", type=parse_size, default=1 << 30)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--cases", default=os.path.join(ROOT, "bench/refbench/regex_cases.tsv"))
    ap.add_argument("--only", default="")
    ap.add_argument("--budget", type=float, default=0.0,
                    help="stop repeating a case once its total scan time exceeds this (0 = always N reps)")
    args = ap.parse_args()
    only = set(x for x in args.only.split(",") if x)
    fd = os.open(args.img, os.O_RDONLY)
    size = os.fstat(fd).st_size
    ln = min(args.len, size - args.off)
    mm = mmap.mmap(fd, ln, access=mmap.ACCESS_READ, offset=args.off)
    try:
        mm.madvise(mmap.MADV_WILLNEED)
    except Exception:
        pass
    # warm the page cache / page tables once (touch one byte per page)
    s = 0
    for i in range(0, ln, 1 << 20):
        s += mm.find(b"\x01\x02\x03\x04", i, min(ln, i + (1 << 20))) > 0
    for name, pat in load_cases(args.cases):
        if only and name not in only:
            continue
        best_c = 1e9
        for _ in range(20):
            re.purge()
            t0 = time.perf_counter()
            rx = re.compile(pat)
            best_c = min(best_c, time.perf_counter() - t0)
        best = 1e9
        count = -1
        total = 0.0
        for _ in range(args.reps):
            t0 = time.perf_counter()
            n = 0
            for _m in rx.finditer(mm):
                n += 1
            dt = time.perf_counter() - t0
            total += dt
            best = min(best, dt)
            if count >= 0 and n != count:
                print("WARN python-re %s: count changed %d -> %d" % (name, count, n), file=sys.stderr)
            count = n
            if args.budget and total > args.budget:
                break
        note = "window=%dMiB" % (ln >> 20)
        print("BENCH\tpython-re\t%s\t%.1f\t%.4f\t%.1f\t%d\t%s" % (
            name, best_c * 1e6, best, ln / 1e6 / best, count, note), flush=True)
    mm.close()
    os.close(fd)


if __name__ == "__main__":
    main()
