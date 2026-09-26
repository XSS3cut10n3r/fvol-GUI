#!/usr/bin/env python3
"""Extract executable sections into flat binary corpora for the disassembler benchmarks.

Usage (bench venv python, same sources as disasm_diff.py `gen` real corpora):
  disasm_bench_corpus.py [--out DIR] [--pe DIR ...] [--limit MB]

Writes DIR/real32.bin, DIR/real64.bin (concatenated section bytes) and DIR/real32.idx,
DIR/real64.idx (one line per section: `vaddr_hex<TAB>length`, in file order).  Default DIR is
/tmp/rsvol-disasm/bin, default limit 48 MB per mode.  Sections are streamed to disk one at a
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


def main(argv):
    out = "/tmp/rsvol-disasm/bin"
    pe_dirs = []
    limit = 48 << 20
    i = 0
    while i < len(argv):
        if argv[i] == "--out":
            out = argv[i + 1]; i += 1
        elif argv[i] == "--pe":
            pe_dirs.append(argv[i + 1]); i += 1
        elif argv[i] == "--limit":
            limit = int(argv[i + 1]) << 20; i += 1
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
            if budget[bits] >= limit:
                continue
            body = body[: limit - budget[bits]]
            budget[bits] += len(body)
            bins[bits].write(body)
            idxs[bits].write(f"{va:x}\t{len(body)}\n")
        del data
    for b in (32, 64):
        bins[b].close()
        idxs[b].close()
        print(f"real{b}: {budget[b]} bytes -> {out}/real{b}.bin", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
