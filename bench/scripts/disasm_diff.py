#!/usr/bin/env python3
"""Differential test harness: fastvol's x86 disassembler (src/disasm) vs capstone 5.

Usage (run with the bench venv python, which has capstone):
  disasm_diff.py gen  [--out DIR] [--pe DIR ...] [--quick]   build corpora + capstone reference
  disasm_diff.py cmp  [--out DIR] [--only NAME] [--show N]   build & run examples/disasm_diff.rs
  disasm_diff.py probe MODE HEX...                           print capstone's decoding

Corpus/reference files are written to DIR (default testdata/scratch/disasm/ref) as NAME.ref, one line per
unique instruction:  count<TAB>mode<TAB>addr_hex<TAB>window_hex<TAB>size<TAB>mnemonic<TAB>op_str
`window_hex` holds the bytes available to the decoder at that position (<= 15); size 0 means
capstone rejected the bytes (mnemonic/op_str empty).  Corpora:
  real64 / real32   executable sections of PE files dumped from the memory image
                    (windows.modules/dlllist --dump) and ELF .so files from /usr/lib{,32}
  rand64 / rand32   linear sweeps over random bytes (restart one byte after an invalid insn)
  sweep64 / sweep32 targeted opcode sweeps: every 1/2/3-byte opcode x ModRM x prefix combo,
                    VEX/EVEX/XOP/3DNow/x87 spaces (first instruction of each window only)
The comparison itself is done by examples/disasm_diff.rs (fast, Rust) which prints mismatch
rates per corpus (unique and occurrence-weighted) and writes mismatches to DIR/NAME.mis.
"""
import os
import random
import struct
import subprocess
import sys
from multiprocessing import Pool

import capstone

MODES = {32: capstone.CS_MODE_32, 64: capstone.CS_MODE_64}
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA = os.environ.get("FASTVOL_DATA") or os.path.dirname(subprocess.run(
    ["git", "-C", REPO, "rev-parse", "--path-format=absolute", "--git-common-dir"],
    capture_output=True, text=True).stdout.strip() or os.path.join(REPO, ".git"))
DEFAULT_OUT = os.path.join(DATA, "testdata/scratch/disasm/ref")  # on disk: /tmp is RAM-backed
DEFAULT_PE = [
    os.path.join(DATA, "testdata/scratch/disasm/pe"),
]


def md_for(bits):
    return capstone.Cs(capstone.CS_ARCH_X86, MODES[bits])


# ----------------------------------------------------------------------------- executable sections

def pe_exec_sections(data):
    """Yield (vaddr, bytes, bits) for executable sections of a (memory-dumped) PE file."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x18 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return
    machine, nsec, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    opt = e_lfanew + 0x18
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        bits, image_base = 64, struct.unpack_from("<Q", data, opt + 24)[0]
    elif magic == 0x10B:
        bits, image_base = 32, struct.unpack_from("<I", data, opt + 28)[0]
    else:
        return
    sec = opt + opt_size
    for i in range(nsec):
        off = sec + 40 * i
        if off + 40 > len(data):
            break
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        chars = struct.unpack_from("<I", data, off + 36)[0]
        if not (chars & 0x20000000 or chars & 0x20):
            continue
        size = min(max(vsize, 0), rawsize if rawsize else vsize)
        body = data[rawptr:rawptr + size]
        if len(body) < 16:
            continue
        yield image_base + va, body, bits


def elf_exec_sections(data):
    if data[:4] != b"\x7fELF":
        return
    cls, endian = data[4], data[5]
    if endian != 1:
        return
    if cls == 2:
        machine = struct.unpack_from("<H", data, 18)[0]
        if machine != 62:
            return
        shoff = struct.unpack_from("<Q", data, 0x28)[0]
        shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
        bits = 64
    elif cls == 1:
        machine = struct.unpack_from("<H", data, 18)[0]
        if machine != 3:
            return
        shoff = struct.unpack_from("<I", data, 0x20)[0]
        shentsize, shnum = struct.unpack_from("<HH", data, 0x2E)
        bits = 32
    else:
        return
    for i in range(shnum):
        off = shoff + i * shentsize
        if off + shentsize > len(data):
            break
        if bits == 64:
            _, stype, flags, addr, foff, size = struct.unpack_from("<IIQQQQ", data, off)
        else:
            _, stype, flags, addr, foff, size = struct.unpack_from("<IIIIII", data, off)
        if stype != 1 or not flags & 4:  # SHT_PROGBITS, SHF_EXECINSTR
            continue
        body = data[foff:foff + size]
        if len(body) >= 16:
            yield addr, body, bits


# ----------------------------------------------------------------------------- sweeping

def sweep(args):
    """Linear sweep of one buffer with capstone, restarting 1 byte after invalid instructions.
    Returns {key: [count, line_without_count]}."""
    bits, addr, buf, max_insns = args
    md = md_for(bits)
    out = {}
    n = len(buf)
    off = 0
    produced = 0
    while off < n and produced < max_insns:
        last = off
        for (a, size, mn, ops) in md.disasm_lite(buf[off:], addr + off):
            ib = buf[last:last + size]
            key = (bits, ib)
            e = out.get(key)
            if e is None:
                win = buf[last:last + 15]
                out[key] = [1, f"{bits}\t{a:x}\t{win.hex()}\t{size}\t{mn}\t{ops}"]
            else:
                e[0] += 1
            last += size
            produced += 1
            if produced >= max_insns:
                break
        if produced >= max_insns:
            break
        if last >= n:
            break
        win = buf[last:last + 15]
        key = (bits, b"!" + win)
        e = out.get(key)
        if e is None:
            out[key] = [1, f"{bits}\t{addr + last:x}\t{win.hex()}\t0\t\t"]
        else:
            e[0] += 1
        produced += 1
        off = last + 1
    return out


def single(args):
    """Decode only the first instruction of each window."""
    bits, windows = args
    md = md_for(bits)
    out = []
    addr = 0x401000 if bits == 32 else 0x140001000
    for w in windows:
        r = next(md.disasm_lite(w, addr, 1), None)
        if r is None:
            out.append(f"1\t{bits}\t{addr:x}\t{w.hex()}\t0\t\t")
        else:
            out.append(f"1\t{bits}\t{addr:x}\t{w.hex()}\t{r[1]}\t{r[2]}\t{r[3]}")
    return out


def merge(dicts):
    tot = {}
    for d in dicts:
        for k, (c, line) in d.items():
            e = tot.get(k)
            if e is None:
                tot[k] = [c, line]
            else:
                e[0] += c
    return tot


def write_ref(path, entries):
    with open(path, "w") as f:
        for c, line in entries:
            f.write(f"{c}\t{line}\n")
    print(f"  wrote {path}: {len(entries)} lines", file=sys.stderr)


# ----------------------------------------------------------------------------- corpora

def gather_real(pe_dirs, quick, lib_seed=1234, real_mb=48, only_files=None):
    jobs = {32: [], 64: []}
    budget = {32: 0, 64: 0}
    limit = (4 << 20) if quick else (real_mb << 20)
    files = []
    for d in pe_dirs:
        for root, _, names in os.walk(d):
            for nm in sorted(names):
                if nm.endswith(".dmp"):
                    files.append(os.path.join(root, nm))
    for lib in (() if only_files else ("/usr/lib", "/usr/lib32")):
        try:
            names = sorted(os.listdir(lib))
        except OSError:
            continue
        rnd = random.Random(lib_seed)
        rnd.shuffle(names)
        for nm in names:
            if ".so" in nm:
                files.append(os.path.join(lib, nm))
    if only_files:
        files = list(only_files)
    for p in files:
        try:
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            if os.path.getsize(p) > (64 << 20) and not only_files:
                continue
            with open(p, "rb") as f:
                data = f.read()
        except OSError:
            continue
        secs = list(pe_exec_sections(data)) if data[:2] == b"MZ" else list(elf_exec_sections(data))
        for va, body, bits in secs:
            if budget[bits] >= limit:
                continue
            body = body[: limit - budget[bits]]
            budget[bits] += len(body)
            # split in chunks for parallelism
            for i in range(0, len(body), 1 << 18):
                jobs[bits].append((bits, va + i, body[i:i + (1 << 18)], 1 << 30))
    return jobs


def gen_sweep_windows(bits, rnd, small_tail=False):
    """Targeted opcode-space windows (first instruction only). With small_tail the bytes after
    the opcode are biased towards small values (predicate immediates, short displacements)."""
    W = []

    def tail(n=15):
        if small_tail:
            return bytes(rnd.getrandbits(5) if rnd.getrandbits(1) else rnd.getrandbits(8) for _ in range(n))
        return bytes(rnd.getrandbits(8) for _ in range(n))

    def add(prefix, rest):
        w = (prefix + rest + tail())[:15]
        W.append(w)

    modrms_all = list(range(256))
    modrms_few = [0x00, 0x04, 0x05, 0x08, 0x0C, 0x15, 0x44, 0x4D, 0x84, 0x94, 0xC0, 0xC1, 0xC8,
                  0xD1, 0xD2, 0xDB, 0xE3, 0xE4, 0xED, 0xF0, 0xF6, 0xF8, 0xFF, 0x38, 0x3C, 0x7D]
    pfx1 = [b"", b"\x66", b"\x67", b"\xf2", b"\xf3", b"\xf0", b"\x2e", b"\x3e", b"\x26", b"\x64",
            b"\x65", b"\x36", b"\x66\xf2", b"\xf3\x66", b"\xf0\x66", b"\xf2\xf0", b"\xf3\xf0"]
    if bits == 64:
        pfx1 += [b"\x48", b"\x41", b"\x44", b"\x4c", b"\x4f", b"\x40", b"\x42", b"\x66\x48",
                 b"\xf3\x48", b"\xf2\x48", b"\xf0\x48", b"\x66\x41", b"\x67\x48"]
    # one-byte opcodes x all modrm
    for p in pfx1:
        for op in range(256):
            for m in (modrms_all if p in (b"", b"\x66", b"\x48", b"\xf3", b"\xf2") else modrms_few):
                add(p, bytes([op, m]))
    # two-byte opcodes
    pfx2 = [b"", b"\x66", b"\xf3", b"\xf2", b"\x66\xf3", b"\xf2\x66", b"\xf3\xf2", b"\xf0",
            b"\x67", b"\x2e", b"\xf2\xf3", b"\x66\xf2"]
    if bits == 64:
        pfx2 += [b"\x48", b"\x66\x48", b"\xf3\x48", b"\xf2\x48", b"\x41", b"\x44", b"\x4d",
                 b"\x66\x4c", b"\xf3\x4c", b"\xf2\x4d", b"\x40"]
    for p in pfx2:
        for op in range(256):
            for m in (modrms_all if len(p) <= 1 else modrms_few):
                add(p, bytes([0x0F, op, m]))
    # three-byte opcodes
    for esc in (0x38, 0x3A):
        for p in pfx2:
            for op in range(256):
                for m in modrms_few:
                    add(p, bytes([0x0F, esc, op, m]))
    # 3DNow! suffixes
    for s in range(256):
        for m in (0x00, 0xC1, 0x05, 0x44):
            W.append((bytes([0x0F, 0x0F, m]) + tail(12))[:15])
            # put suffix right after modrm/disp
            if m == 0xC1 or m == 0x00:
                W.append((bytes([0x0F, 0x0F, m, s]) + tail())[:15])
            elif m == 0x05:
                W.append((bytes([0x0F, 0x0F, m]) + tail(4) + bytes([s]) + tail())[:15])
            else:
                W.append((bytes([0x0F, 0x0F, m, 0x24, 0x10, s]) + tail())[:15])
    # VEX
    for mmmmm in (1, 2, 3, 0, 4, 0x1F):
        for pp in range(4):
            for L in range(2):
                for Wb in range(2):
                    for op in range(256):
                        for m in (0x00, 0xC1, 0xCA, 0x44, 0x05, 0xD8, 0x0C, 0xF0):
                            rxb = rnd.choice((7, 7, 7, 0, 5, 2))
                            vvvv = rnd.choice((15, 15, 13, 0, 7))
                            b1 = (rxb << 5) | mmmmm
                            b2 = (Wb << 7) | (vvvv << 3) | (L << 2) | pp
                            add(b"", bytes([0xC4, b1, b2, op, m]))
                            if mmmmm == 1 and Wb == 0:
                                r = rnd.choice((1, 1, 0))
                                add(b"", bytes([0xC5, (r << 7) | (vvvv << 3) | (L << 2) | pp, op, m]))
                                add(b"\x66", bytes([0xC5, (r << 7) | (vvvv << 3) | (L << 2) | pp, op, m]))
    # EVEX
    for mm in (1, 2, 3, 0, 5, 6):
        for pp in range(4):
            for op in range(256):
                for _ in range(12):
                    rxbr = rnd.choice((0xF, 0xF, 0xE, 0x7, 0x0, 0xB))
                    p0 = (rxbr << 4) | mm
                    Wb = rnd.getrandbits(1)
                    vvvv = rnd.choice((15, 15, 3, 0))
                    p1 = (Wb << 7) | (vvvv << 3) | 4 | pp
                    z = rnd.choice((0, 0, 1))
                    ll = rnd.choice((0, 1, 2, 2, 3))
                    b = rnd.choice((0, 0, 0, 1))
                    vp = rnd.choice((1, 1, 1, 0))
                    aaa = rnd.choice((0, 0, 1, 7))
                    p2 = (z << 7) | (ll << 5) | (b << 4) | (vp << 3) | aaa
                    m = rnd.choice(modrms_few)
                    add(b"", bytes([0x62, p0, p1, p2, op, m]))
    # XOP
    for mm in (8, 9, 10, 11):
        for op in range(256):
            for _ in range(6):
                rxb = rnd.choice((7, 7, 0, 5))
                b1 = (rxb << 5) | mm
                b2 = (rnd.getrandbits(1) << 7) | (rnd.choice((15, 15, 0, 5)) << 3) | (rnd.getrandbits(1) << 2) | rnd.choice((0, 0, 1))
                add(b"", bytes([0x8F, b1, b2, op, rnd.choice(modrms_few)]))
    # x87 (all modrm) with a few prefixes
    for p in (b"", b"\x66", b"\x9b", b"\xf2", b"\x48" if bits == 64 else b"\x67"):
        for op in range(0xD8, 0xE0):
            for m in range(256):
                add(p, bytes([op, m]))
    # prefix soup
    soup = [0x66, 0x67, 0xF2, 0xF3, 0xF0, 0x2E, 0x3E, 0x26, 0x36, 0x64, 0x65]
    if bits == 64:
        soup += [0x40, 0x48, 0x41, 0x4C, 0x47]
    for _ in range(60000):
        k = rnd.choice((1, 2, 2, 3, 4, 6, 14, 15))
        p = bytes(rnd.choice(soup) for _ in range(k))
        body = rnd.choice((bytes([rnd.getrandbits(8)]), b"\x0f" + bytes([rnd.getrandbits(8)]),
                           b"\x0f\x38" + bytes([rnd.getrandbits(8)]), b"\x0f\x3a" + bytes([rnd.getrandbits(8)]),
                           b"\xc4", b"\xc5", b"\x62", b"\x90", b"\xa4", b"\xc3", b"\xff"))
        add(p, body)
    return W


def main_gen(argv):
    out = DEFAULT_OUT
    pe_dirs = []
    quick = False
    only = None
    seed = 20240601
    jobs = min(8, os.cpu_count() or 1)
    rand_mb = 16
    lib_seed = 1234
    real_mb = 48
    no_pe = False
    small_tail = False
    only_files = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--out":
            out = argv[i + 1]; i += 1
        elif a == "--pe":
            pe_dirs.append(argv[i + 1]); i += 1
        elif a == "--quick":
            quick = True
        elif a == "--only":
            only = argv[i + 1].split(","); i += 1
        elif a == "--seed":
            seed = int(argv[i + 1]); i += 1
        elif a == "--jobs":
            jobs = int(argv[i + 1]); i += 1
        elif a == "--rand-mb":
            rand_mb = int(argv[i + 1]); i += 1
        elif a == "--lib-seed":
            lib_seed = int(argv[i + 1]); i += 1
        elif a == "--real-mb":
            real_mb = int(argv[i + 1]); i += 1
        elif a == "--no-pe":
            no_pe = True
        elif a == "--small-tail":
            small_tail = True
        elif a == "--files":
            only_files = argv[i + 1].split(","); i += 1
        i += 1
    if not pe_dirs and not no_pe:
        pe_dirs = [d for d in DEFAULT_PE if os.path.isdir(d)]
    os.makedirs(out, exist_ok=True)
    rnd = random.Random(seed)
    with Pool(jobs) as pool:
        if only is None or "real" in only:
            jobs = gather_real(pe_dirs, quick, lib_seed, real_mb, only_files)
            for bits in (64, 32):
                print(f"real{bits}: {len(jobs[bits])} chunks", file=sys.stderr)
                tot = merge(pool.imap_unordered(sweep, jobs[bits], chunksize=1))
                ents = sorted(tot.values(), key=lambda e: -e[0])
                write_ref(os.path.join(out, f"real{bits}.ref"), ents)
        if only is None or "rand" in only:
            size = (1 << 20) if quick else (rand_mb << 20)
            for bits in (64, 32):
                jobs = []
                for i in range(0, size, 1 << 16):
                    buf = bytes(rnd.getrandbits(8) for _ in range(1 << 16)) if False else os.urandom(1 << 16)
                    jobs.append((bits, 0x10000000 + i, buf, 1 << 30))
                tot = merge(pool.imap_unordered(sweep, jobs, chunksize=1))
                ents = sorted(tot.values(), key=lambda e: -e[0])
                write_ref(os.path.join(out, f"rand{bits}.ref"), ents)
        if only is None or "sweep" in only:
            for bits in (64, 32):
                W = gen_sweep_windows(bits, rnd, small_tail)
                W = list(dict.fromkeys(W))
                if quick:
                    W = W[::16]
                chunks = [(bits, W[i:i + 20000]) for i in range(0, len(W), 20000)]
                lines = []
                for part in pool.imap(single, chunks, chunksize=1):
                    lines.extend(part)
                path = os.path.join(out, f"sweep{bits}.ref")
                with open(path, "w") as f:
                    for l in lines:
                        f.write(l + "\n")
                print(f"  wrote {path}: {len(lines)} lines", file=sys.stderr)


def main_cmp(argv):
    out = DEFAULT_OUT
    extra = []
    i = 0
    while i < len(argv):
        if argv[i] == "--out":
            out = argv[i + 1]; i += 1
        else:
            extra.append(argv[i])
        i += 1
    cmd = ["cargo", "run", "-q", "--profile", "fast", "--example", "disasm_diff", "--", "cmp", out] + extra
    sys.exit(subprocess.call(cmd, cwd=REPO))


def main_probe(argv):
    bits = int(argv[0])
    md = md_for(bits)
    for h in argv[1:]:
        b = bytes.fromhex(h)
        r = [(i[1], i[2], i[3]) for i in md.disasm_lite(b, 0x1000)]
        print(h, "=>", " | ".join(f"{s}:{m}\t{o}" for s, m, o in r) if r else "INVALID")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd, rest = sys.argv[1], sys.argv[2:]
    {"gen": main_gen, "cmp": main_cmp, "probe": main_probe}[cmd](rest)
