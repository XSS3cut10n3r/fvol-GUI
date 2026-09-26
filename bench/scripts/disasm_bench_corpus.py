#!/usr/bin/env python3
"""Extract executable sections into flat binary corpora for the disassembler benchmarks.

Usage (bench venv python, same sources as disasm_diff.py `gen` real corpora):
  disasm_bench_corpus.py [--out DIR] [--pe DIR ...] [--limit MB] [--keep-zero-pages]

Writes DIR/real32.bin, DIR/real64.bin (concatenated section bytes) and DIR/real32.idx,
DIR/real64.idx (one line per chunk: `vaddr_hex<TAB>length`, in file order).  All-zero 4 KiB
pages are dropped by default (memory-dumped PE sections are 50-70% zero fill, which would make
the benchmark mostly `add byte ptr [rax], al`); each chunk is a run of non-zero pages.  Default DIR is
/home/user/rs-vol/testdata/scratch/disasm/ref/bin, default limit 48 MB per mode.  Sections are streamed to disk one at a
time.  Consumers (bench/refbench/capstone_bench.c, examples/disasm_bench.rs) linearly sweep each
section, skipping one byte after an undecodable instruction.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from disasm_diff import DEFAULT_PE, elf_exec_sections, pe_exec_sections  # noqa: E402


def files_in_order(pe_dirs):
    """Same file order as disasm_diff.gather_real."""
    files = []
    for d in pe_dirs:
        for root, _, names in os.walk(d):
            for nm in sorted(names):
                if nm.endswith(".dmp"):
                    files.append(os.path.join(root, nm))
    for lib in ("/usr/lib", "/usr/lib32"):
        try:
            names = sorted(os.listdir(lib))
        except OSError:
            continue
        rnd = random.Random(1234)
        rnd.shuffle(names)
        for nm in names:
            if ".so" in nm:
                files.append(os.path.join(lib, nm))
    return files


def nonzero_runs(va, body, page=4096):
    """Split a section into runs of pages that are not entirely zero."""
    runs = []
    start = None
    for off in range(0, len(body), page):
        zero = body[off:off + page].count(0) == len(body[off:off + page])
        if not zero and start is None:
            start = off
        elif zero and start is not None:
            runs.append((va + start, body[start:off]))
            start = None
    if start is not None:
        runs.append((va + start, body[start:]))
    return [(a, b) for a, b in runs if len(b) >= 16]


def main(argv):
    out = "/home/user/rs-vol/testdata/scratch/disasm/ref/bin"
    pe_dirs = []
    limit = 48 << 20
    keep_zero = False
    i = 0
    while i < len(argv):
        if argv[i] == "--out":
            out = argv[i + 1]; i += 1
        elif argv[i] == "--pe":
            pe_dirs.append(argv[i + 1]); i += 1
        elif argv[i] == "--limit":
            limit = int(argv[i + 1]) << 20; i += 1
        elif argv[i] == "--keep-zero-pages":
            keep_zero = True
        i += 1
    if not pe_dirs:
        pe_dirs = [d for d in DEFAULT_PE if os.path.isdir(d)]
    os.makedirs(out, exist_ok=True)
    bins = {b: open(os.path.join(out, f"real{b}.bin"), "wb") for b in (32, 64)}
    idxs = {b: open(os.path.join(out, f"real{b}.idx"), "w") for b in (32, 64)}
    budget = {32: 0, 64: 0}
    for p in files_in_order(pe_dirs):
        if budget[32] >= limit and budget[64] >= limit:
            break
        try:
            if os.path.islink(p) or not os.path.isfile(p) or os.path.getsize(p) > (64 << 20):
                continue
            with open(p, "rb") as f:
                data = f.read()
        except OSError:
            continue
        secs = pe_exec_sections(data) if data[:2] == b"MZ" else elf_exec_sections(data)
        for va, body, bits in secs:
            for cva, chunk in ([(va, body)] if keep_zero else nonzero_runs(va, body)):
                if budget[bits] >= limit:
                    break
                chunk = chunk[: limit - budget[bits]]
                budget[bits] += len(chunk)
                bins[bits].write(chunk)
                idxs[bits].write(f"{cva:x}\t{len(chunk)}\n")
        del data
    for b in (32, 64):
        bins[b].close()
        idxs[b].close()
        print(f"real{b}: {budget[b]} bytes -> {out}/real{b}.bin", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
