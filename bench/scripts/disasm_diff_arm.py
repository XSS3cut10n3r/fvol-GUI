#!/usr/bin/env python3
"""Differential test harness: rsvol's ARM / AArch64 disassemblers (src/disasm/arm64, arm) vs
capstone 5.

Usage (bench venv python, which has capstone):
  disasm_diff_arm.py gen   [--out DIR] [--quick] [--only real,rand,sweep]   build corpora + refs
  disasm_diff_arm.py cmp   [--out DIR] [--only NAME,...] [--show N]         run the Rust comparison
  disasm_diff_arm.py objs  [--out DIR]          cross-compile C sources to aarch64/arm objects
  disasm_diff_arm.py exhaustive ARCH [--oracle BIN] [--out DIR] [--range START END]
        all 2^32 words: per-block hashes from the C oracle (bench/refbench/arm_oracle.c) and
        from the Rust example are compared; mismatching blocks are dumped and diffed, the
        mismatching words are written to DIR/ARCH.exh.words (seeds for the spec learner)
  disasm_diff_arm.py probe ARCH HEXWORD...      print capstone's decoding

Corpus/reference files (DIR/NAME.ref), one line per unique instruction word:
  count<TAB>mode<TAB>addr_hex<TAB>word_hex<TAB>size<TAB>mnemonic<TAB>op_str
(mode = arm64 | arm; size 0 = capstone rejected the word).  Corpora per arch:
  real64 / real32   executable sections of the aarch64 / arm ELF files found on this machine
                    (plus clang cross-compiled objects if `objs` was run), linear sweep
  rand64 / rand32   uniformly random words
  sweep64 / sweep32 every value of the top 11 bits (arm64) / bits 27:20 + cond (arm) with
                    randomized low bits
The comparison itself is done by examples/disasm_diff_arm.rs (fast, Rust), which prints
mismatch rates per corpus (unique and occurrence weighted) and writes DIR/NAME.mis.
"""
import os
import random
import struct
import subprocess
import sys
from collections import Counter

import capstone

DEFAULT_OUT = "/home/user/rs-vol/testdata/scratch/disasm/arm"
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ELF_ROOTS = ["/usr/lib/go/src", "/opt/metasploit", "/home/user/.rustup/toolchains", "/usr/share/proxmark3",
             "/usr/lib", "/usr/share"]
MACH = {"arm64": 183, "arm": 40}
BASE_ADDR = 0xFFFFFF8008080000


def md_for(arch):
    if arch == "arm64":
        return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)


# ----------------------------------------------------------------------------------------------
# ELF / ar parsing

def elf_exec_sections(data, machine):
    if data[:4] != b"\x7fELF" or data[5] != 1:
        return
    cls = data[4]
    if struct.unpack_from("<H", data, 18)[0] != machine:
        return
    if cls == 2:
        shoff = struct.unpack_from("<Q", data, 0x28)[0]
        shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    elif cls == 1:
        shoff = struct.unpack_from("<I", data, 0x20)[0]
        shentsize, shnum = struct.unpack_from("<HH", data, 0x2E)
    else:
        return
    for i in range(shnum):
        off = shoff + i * shentsize
        if off + shentsize > len(data):
            break
        if cls == 2:
            _, stype, flags, addr, foff, size = struct.unpack_from("<IIQQQQ", data, off)
        else:
            _, stype, flags, addr, foff, size = struct.unpack_from("<IIIIII", data, off)
        if stype != 1 or not flags & 4:
            continue
        body = data[foff:foff + size]
        if len(body) >= 16:
            yield addr or (BASE_ADDR + foff), body


def ar_members(data):
    if data[:8] != b"!<arch>\n":
        return
    p = 8
    while p + 60 <= len(data):
        hdr = data[p:p + 60]
        try:
            size = int(hdr[48:58].decode().strip())
        except ValueError:
            return
        yield data[p + 60:p + 60 + size]
        p += 60 + size + (size & 1)


def find_code(arch, extra_dirs=()):
    machine = MACH[arch]
    out = []
    for root in list(extra_dirs) + ELF_ROOTS:
        if not os.path.isdir(root):
            continue
        for dp, dn, fn in os.walk(root):
            for f in fn:
                p = os.path.join(dp, f)
                try:
                    if os.path.islink(p) or os.path.getsize(p) < 256 or os.path.getsize(p) > 64 << 20:
                        continue
                    with open(p, "rb") as fh:
                        head = fh.read(20)
                    if head[:4] == b"\x7fELF":
                        if len(head) >= 20 and struct.unpack_from("<H", head, 18)[0] == machine:
                            with open(p, "rb") as fh:
                                out.append((p, fh.read()))
                    elif head[:8] == b"!<arch>\n":
                        with open(p, "rb") as fh:
                            d = fh.read()
                        if any(m[:4] == b"\x7fELF" and len(m) > 20 and struct.unpack_from("<H", m, 18)[0] == machine
                               for m in ar_members(d)):
                            out.append((p, d))
                except OSError:
                    continue
    return out


def code_blobs(arch, extra_dirs=()):
    machine = MACH[arch]
    for path, data in find_code(arch, extra_dirs):
        members = list(ar_members(data)) if data[:8] == b"!<arch>\n" else [data]
        for m in members:
            for addr, body in elf_exec_sections(m, machine):
                yield path, addr, body


# ----------------------------------------------------------------------------------------------
# reference generation

def sweep_linear(md, addr, body, tot):
    """Linear sweep, restarting 4 bytes after an invalid word."""
    n = len(body) & ~3
    off = 0
    while off < n:
        last = off
        for (a, size, mn, ops) in md.disasm_lite(body[off:n], addr + off):
            w = body[last:last + 4]
            key = w
            e = tot.get(key)
            if e is None:
                tot[key] = [1, a, 4, mn, ops]
            else:
                e[0] += 1
            last += 4
        if last >= n:
            break
        w = body[last:last + 4]
        e = tot.get(w)
        if e is None:
            tot[w] = [1, addr + last, 0, "", ""]
        else:
            e[0] += 1
        off = last + 4


def write_ref(path, arch, tot):
    ents = sorted(tot.items(), key=lambda kv: -kv[1][0])
    with open(path, "w") as f:
        for w, (c, a, size, mn, ops) in ents:
            f.write("%d\t%s\t%x\t%s\t%d\t%s\t%s\n" % (c, arch, a, w.hex(), size, mn, ops))
    print("  wrote %s: %d unique words, %d total" % (path, len(ents), sum(e[0] for e in tot.values())),
          file=sys.stderr)


def single_words(md, words, addr_fn):
    tot = {}
    for w in words:
        b = struct.pack("<I", w)
        a = addr_fn(w)
        r = next(md.disasm_lite(b, a, 1), None)
        e = tot.get(b)
        if e is None:
            tot[b] = [1, a, 4, r[2], r[3]] if r else [1, a, 0, "", ""]
        else:
            e[0] += 1
    return tot


def gen(argv):
    out = DEFAULT_OUT
    quick = False
    only = None
    i = 0
    while i < len(argv):
        if argv[i] == "--out":
            out = argv[i + 1]; i += 1
        elif argv[i] == "--quick":
            quick = True
        elif argv[i] == "--only":
            only = argv[i + 1].split(","); i += 1
        i += 1
    os.makedirs(out, exist_ok=True)
    rnd = random.Random(20260925)
    for arch, suffix in (("arm64", "64"), ("arm", "32")):
        md = md_for(arch)
        if only is None or "real" in only:
            tot = {}
            nbytes = 0
            for path, addr, body in code_blobs(arch, [os.path.join(out, "objs", arch)]):
                if quick and nbytes > (2 << 20):
                    break
                nbytes += len(body)
                sweep_linear(md, addr, body, tot)
            print("real%s: %d bytes of code" % (suffix, nbytes), file=sys.stderr)
            write_ref(os.path.join(out, "real%s.ref" % suffix), arch, tot)
        if only is None or "rand" in only:
            n = 200000 if quick else 2000000
            words = [rnd.getrandbits(32) for _ in range(n)]
            tot = single_words(md, words, lambda w: 0x10000 + (w & 0xFFFC) * 16)
            write_ref(os.path.join(out, "rand%s.ref" % suffix), arch, tot)
        if only is None or "sweep" in only:
            words = []
            k = 8 if quick else 48
            if arch == "arm64":
                for top in range(2048):
                    for _ in range(k):
                        words.append((top << 21) | rnd.getrandbits(21))
            else:
                for cond in (0xE, 0xF, rnd.randrange(14)):
                    for mid in range(256):
                        for _ in range(k):
                            words.append((cond << 28) | (mid << 20) | rnd.getrandbits(20))
            tot = single_words(md, words, lambda w: BASE_ADDR + (w & 0x3FFC))
            write_ref(os.path.join(out, "sweep%s.ref" % suffix), arch, tot)


# ----------------------------------------------------------------------------------------------
# cross-compiled objects

def objs(argv):
    out = DEFAULT_OUT
    if "--out" in argv:
        out = argv[argv.index("--out") + 1]
    srcs = []
    src_root = os.path.join(out, "cssrc")
    for dp, dn, fn in os.walk(src_root):
        for f in fn:
            if f.endswith(".c"):
                srcs.append(os.path.join(dp, f))
    srcs.sort()
    configs = {
        "arm64": [["--target=aarch64-linux-gnu", "-O2"], ["--target=aarch64-linux-gnu", "-O0"],
                  ["--target=aarch64-linux-gnu", "-O3", "-march=armv9-a+sve2+sme"],
                  ["--target=aarch64-linux-gnu", "-Os", "-march=armv8.5-a+crypto+lse"]],
        "arm": [["--target=armv7a-linux-gnueabihf", "-marm", "-O2", "-mfpu=neon"],
                ["--target=armv7a-linux-gnueabihf", "-marm", "-O0"],
                ["--target=armv5te-linux-gnueabi", "-marm", "-Os"]],
    }
    for arch, cfgs in configs.items():
        d = os.path.join(out, "objs", arch)
        os.makedirs(d, exist_ok=True)
        n = 0
        for ci, cfg in enumerate(cfgs):
            for s in srcs:
                o = os.path.join(d, "%d_%s.o" % (ci, os.path.basename(s)[:-2]))
                inc = ["-I" + os.path.dirname(s), "-I" + os.path.join(src_root, "capstone-5.0.9", "include"),
                       "-I" + os.path.join(src_root, "capstone-5.0.9")]
                r = subprocess.run(["clang", "-c", "-w", "-DCAPSTONE_HAS_ARM", "-DCAPSTONE_HAS_ARM64",
                                    "-DCAPSTONE_HAS_X86"] + cfg + inc + [s, "-o", o],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                n += r.returncode == 0
        print("%s: %d objects" % (arch, n), file=sys.stderr)


# ----------------------------------------------------------------------------------------------
# comparison / exhaustive

def cmp(argv):
    out = DEFAULT_OUT
    extra = []
    i = 0
    while i < len(argv):
        if argv[i] == "--out":
            out = argv[i + 1]; i += 1
        else:
            extra.append(argv[i])
        i += 1
    cmd = ["cargo", "run", "-q", "--profile", "fast", "--example", "disasm_diff_arm", "--", "corpora", out] + extra
    sys.exit(subprocess.call(cmd, cwd=REPO))


def exhaustive(argv):
    arch = argv[0]
    out = DEFAULT_OUT
    oracle = os.path.join(DEFAULT_OUT, "bin", "arm_oracle")
    start, end = 0, 1 << 32
    bits = 20
    i = 1
    while i < len(argv):
        if argv[i] == "--out":
            out = argv[i + 1]; i += 1
        elif argv[i] == "--oracle":
            oracle = argv[i + 1]; i += 1
        elif argv[i] == "--range":
            start, end = int(argv[i + 1], 16), int(argv[i + 2], 16); i += 2
        i += 1
    rng = ["%x" % start, "%x" % end, str(bits)]
    href = os.path.join(out, "%s.exh.oracle" % arch)
    hgot = os.path.join(out, "%s.exh.rust" % arch)
    if not os.path.exists(href) or "--rehash" in argv:
        with open(href, "w") as f:
            subprocess.check_call([oracle, "blocks", arch] + rng + ["16"], stdout=f)
    exe = os.path.join(REPO, "target", "fast", "examples", "disasm_diff_arm")
    with open(hgot, "w") as f:
        subprocess.check_call([exe, "blocks", arch] + rng + ["16"], stdout=f)
    ref = {l.split()[0]: l.split()[1:] for l in open(href)}
    got = {l.split()[0]: l.split()[1:] for l in open(hgot)}
    bad = [b for b in ref if ref[b][0] != got.get(b, [None])[0]]
    total_valid = sum(int(v[1]) for v in ref.values())
    print("%s: %d blocks, %d valid words in reference, %d mismatching blocks" %
          (arch, len(ref), total_valid, len(bad)), file=sys.stderr)
    words_path = os.path.join(out, "%s.exh.words" % arch)
    nmis = 0
    kinds = Counter()
    examples = {}
    with open(words_path, "w") as wf:
        for b in bad:
            s = int(b) << bits
            dump = subprocess.run([oracle, "dump", arch, "%x" % s, str(1 << bits)], stdout=subprocess.PIPE,
                                  check=True).stdout.decode()
            tmp = os.path.join(out, "%s.exh.block" % arch)
            with open(tmp, "w") as f:
                f.write(dump)
            r = subprocess.run([exe, "mis", arch, tmp], stdout=subprocess.PIPE).stdout.decode()
            for line in r.splitlines():
                parts = line.split("\t")
                if len(parts) < 3:
                    continue
                wf.write(parts[0] + "\n")
                nmis += 1
                k = parts[1].split(" ")[0] + " / " + parts[2].split(" ")[0]
                kinds[k] += 1
                examples.setdefault(k, line)
    print("%s: %d mismatching words (%.6f%% of 2^32) -> %s" % (arch, nmis, 100.0 * nmis / (end - start), words_path),
          file=sys.stderr)
    for k, c in kinds.most_common(50):
        print("%10d %-40s %s" % (c, k, examples[k]), file=sys.stderr)


def probe(argv):
    md = md_for(argv[0])
    for h in argv[1:]:
        w = int(h, 16)
        r = next(md.disasm_lite(struct.pack("<I", w), 0x1000, 1), None)
        print("%08x => %s" % (w, "%s\t%s" % (r[2], r[3]) if r else "INVALID"))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    {"gen": gen, "cmp": cmp, "objs": objs, "exhaustive": exhaustive, "probe": probe}[sys.argv[1]](sys.argv[2:])
