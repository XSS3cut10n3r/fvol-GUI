#!/usr/bin/env python3
"""Differential harness for capstone *detail mode* (regs_access, detail operands, opcode bytes).

Usage (bench venv python, which has capstone; run through bench/scripts/limit.sh -m 4G):
  disasm_detail_diff.py gen   [--dir DIR] [--only real64,real32,...]   write DIR/NAME.det
  disasm_detail_diff.py cmp   [--dir DIR] [--only ...] [--show N]      run examples/disasm_detail_diff.rs
  disasm_detail_diff.py probe 32|64 HEX...                             print capstone's detail view
  disasm_detail_diff.py gen-mut [--dir DIR]                            write DIR/mut{32,64}.det (EVEX z/aaa/b
                                                                       and compare-predicate variants of sweep windows)
  disasm_detail_diff.py gen-evex [--dir DIR]                           write DIR/evex{32,64}.det (all EVEX
                                                                       opcodes x decoration contexts)
  disasm_detail_diff.py learn [--dir DIR] [--only ...]                 relearn the access rules from DIR/*.det and
                                                                       rewrite SPEC in src/disasm/x86/access_spec.rs

DIR defaults to /home/user/fvol/testdata/scratch/disasm/ref (on disk: /tmp is RAM-backed tmpfs).
Full regeneration: `disasm_diff.py gen` (the .ref corpora), then `gen`, `gen-mut`, `learn`, `cmp`.

`gen` streams DIR/NAME.ref (written by disasm_diff.py gen; one unique instruction window per
line) through capstone with detail=True, one instruction at a time (constant memory; a single
process), and writes DIR/NAME.det with one line per decodable window:

  count mode addr_hex window_hex size opcode rex prefix addr_size modrm implR implW accR accW ops
  mnemonic op_str

(tab separated).  opcode / prefix are 4 bytes of hex; implR / implW are capstone's implicit
`regs_read` / `regs_write` and accR / accW the result of `regs_access()`, as comma separated
register names (in capstone's order); ops is `|` separated, each operand one of
  r,NAME,SIZE,ACCESS           i,IMM,SIZE,ACCESS          m,SEG,BASE,INDEX,SCALE,DISP,SIZE,ACCESS,BCAST
(IMM / DISP in signed decimal, missing registers as "-").
"""
import os
import subprocess
import sys

import capstone
from capstone import x86

DEFAULT_DIR = "/home/user/fvol/testdata/scratch/disasm/ref"
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CORPORA = ["real64", "real32"]


def mk(bits):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32)
    md.detail = True
    return md


def rn(insn, r):
    if r == 0:
        return "-"
    n = insn.reg_name(r)
    return n if n is not None else f"?{r}"


def detail_fields(insn):
    """The detail columns (after `size`) for one capstone instruction."""
    names = lambda regs: ",".join(rn(insn, r) for r in regs)
    ar, aw = insn.regs_access()
    ops = []
    for o in insn.operands:
        if o.type == x86.X86_OP_REG:
            ops.append(f"r,{rn(insn, o.reg)},{o.size},{o.access}")
        elif o.type == x86.X86_OP_IMM:
            ops.append(f"i,{o.imm},{o.size},{o.access}")
        elif o.type == x86.X86_OP_MEM:
            m = o.mem
            ops.append(f"m,{rn(insn, m.segment)},{rn(insn, m.base)},{rn(insn, m.index)},{m.scale},"
                       f"{m.disp},{o.size},{o.access},{o.avx_bcast}")
        else:
            ops.append(f"?{o.type}")
    return "\t".join([
        bytes(insn.opcode).hex(),
        str(insn.rex),
        bytes(insn.prefix).hex(),
        str(insn.addr_size),
        str(insn.modrm),
        names(insn.regs_read),
        names(insn.regs_write),
        names(ar),
        names(aw),
        "|".join(ops),
    ])


def gen(dirn, only):
    for name in (only or CORPORA):
        src = os.path.join(dirn, f"{name}.ref")
        dst = os.path.join(dirn, f"{name}.det")
        mds = {32: mk(32), 64: mk(64)}
        n = 0
        with open(src) as fi, open(dst + ".tmp", "w") as fo:
            for line in fi:
                p = line.rstrip("\n").split("\t")
                if len(p) < 7 or p[4] == "0":
                    continue
                bits = int(p[1])
                addr = int(p[2], 16)
                win = bytes.fromhex(p[3])
                insn = next(mds[bits].disasm(win, addr, 1), None)
                if insn is None:
                    continue
                fo.write(f"{p[0]}\t{p[1]}\t{p[2]}\t{p[3]}\t{insn.size}\t{detail_fields(insn)}\t"
                         f"{insn.mnemonic}\t{insn.op_str}\n")
                n += 1
                if n % 200000 == 0:
                    print(f"  {name}: {n}", file=sys.stderr)
        os.replace(dst + ".tmp", dst)
        print(f"  wrote {dst}: {n} lines", file=sys.stderr)


LEGACY = {0x66, 0x67, 0xF2, 0xF3, 0xF0, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65}


def mutations(bits, win, size, mnemonic):
    """Targeted variants of one sweep window (coverage for the rule learner):
    EVEX: z / aaa / b bits of P2;  compare-predicate aliases: every imm8 predicate 0..31."""
    i = 0
    while i < len(win) and (win[i] in LEGACY or (bits == 64 and win[i] & 0xF0 == 0x40)):
        i += 1
    if i + 4 < len(win) and win[i] == 0x62 and (bits == 64 or win[i + 1] & 0xC0 == 0xC0):
        p2 = i + 3
        for z in (0, 1):
            for aaa in (0, 1, 6):
                for b in (0, 1):
                    w = bytearray(win)
                    w[p2] = (w[p2] & 0x68) | (z << 7) | (b << 4) | aaa
                    yield bytes(w)
    if mnemonic.startswith(("vcmp", "cmp", "vpcom", "vpcmp")) and 1 < size <= len(win):
        for pred in range(32):
            w = bytearray(win)
            w[size - 1] = pred
            yield bytes(w)


def gen_mut(dirn):
    """Write DIR/mut32.det and DIR/mut64.det from mutations of the sweep corpora."""
    for bits in (64, 32):
        md = mk(bits)
        seen = set()
        n = 0
        dst = os.path.join(dirn, f"mut{bits}.det")
        with open(os.path.join(dirn, f"sweep{bits}.ref")) as fi, open(dst + ".tmp", "w") as fo:
            for line in fi:
                p = line.rstrip("\n").split("\t")
                if len(p) < 7 or p[4] == "0":
                    continue
                win = bytes.fromhex(p[3])
                addr = int(p[2], 16)
                for w in mutations(bits, win, int(p[4]), p[5]):
                    if w in seen:
                        continue
                    seen.add(w)
                    insn = next(md.disasm(w, addr, 1), None)
                    if insn is None:
                        continue
                    fo.write(f"1\t{bits}\t{addr:x}\t{w.hex()}\t{insn.size}\t{detail_fields(insn)}\t"
                             f"{insn.mnemonic}\t{insn.op_str}\n")
                    n += 1
        os.replace(dst + ".tmp", dst)
        print(f"  wrote {dst}: {n} lines", file=sys.stderr)


def gen_evex(dirn):
    """Write DIR/evex{32,64}.det: every EVEX opcode (maps 1-3, all pp / W / L) in register and
    memory form, crossed with every decoration context (merge / zero masking, broadcast or
    rounding), so the learner sees each mnemonic's access in every EVEX context capstone has."""
    for bits in (64, 32):
        md = mk(bits)
        n = 0
        dst = os.path.join(dirn, f"evex{bits}.det")
        addr = 0x140001000 if bits == 64 else 0x401000
        seen = set()
        with open(dst + ".tmp", "w") as fo:
            for mm in (1, 2, 3):
                for pp in range(4):
                    for W in (0, 1):
                        for op in range(256):
                            for L in (0, 1, 2):
                                for reg in (0, 1, 2, 3, 4, 5, 6, 7):
                                    for form in ("m", "r"):
                                        for z, b, aaa in ((0, 0, 0), (0, 0, 1), (1, 0, 1), (0, 1, 0), (0, 1, 1), (1, 1, 1)):
                                            for vvvv in (2, 0):
                                                p0 = 0xF0 | mm
                                                p1 = (W << 7) | ((~vvvv & 15) << 3) | 4 | pp
                                                p2 = (z << 7) | (L << 5) | (b << 4) | 0x08 | aaa
                                                modrm = bytes([0x40 | (reg << 3), 0x01]) if form == "m" else bytes([0xC0 | (reg << 3) | 1])
                                                w = bytes([0x62, p0, p1, p2, op]) + modrm + b"\x11\x22\x33\x44"
                                                insn = next(md.disasm(w, addr, 1), None)
                                                if insn is None:
                                                    continue
                                                key = (insn.mnemonic, op, pp, W, L, form, z, b, aaa > 0, reg)
                                                if key in seen:
                                                    break
                                                seen.add(key)
                                                win = w[: insn.size]
                                                fo.write(f"1\t{bits}\t{addr:x}\t{win.hex()}\t{insn.size}\t{detail_fields(insn)}\t"
                                                         f"{insn.mnemonic}\t{insn.op_str}\n")
                                                n += 1
                                                break
        os.replace(dst + ".tmp", dst)
        print(f"  wrote {dst}: {n} lines", file=sys.stderr)


LEARN_CORPORA = ["real64", "real32", "sweep64", "sweep32", "rand64", "rand32", "mut64", "mut32", "evex64", "evex32"]


def learn(dirn, only):
    """Run the rule learner and replace the SPEC section of access_spec.rs with its output."""
    names = [n for n in (only or LEARN_CORPORA) if os.path.exists(os.path.join(dirn, f"{n}.det"))]
    out = subprocess.run(["cargo", "run", "-q", "--profile", "fast", "--example", "disasm_detail_diff",
                          "--", "learn", dirn, "--only", ",".join(names)],
                         cwd=REPO, check=True, stdout=subprocess.PIPE, text=True).stdout
    lines = [l.rstrip() for l in out.splitlines() if l.strip()]
    rules = [l for l in lines if not l.startswith("#")]
    path = os.path.join(REPO, "src", "disasm", "x86", "access_spec.rs")
    src = open(path).read()
    marker = 'pub(crate) const SPEC: &str = r#"'
    head = src[: src.index(marker)]
    with open(path, "w") as f:
        f.write(head + marker + "\n" + "\n".join(rules) + '\n"#;\n')
    print(f"  {path}: {len(rules)} rules from {','.join(names)} "
          f"({len(lines) - len(rules)} unresolvable capstone conflicts dropped)", file=sys.stderr)


def probe(bits, hexes):
    md = mk(bits)
    for h in hexes:
        insn = next(md.disasm(bytes.fromhex(h), 0x1000, 1), None)
        if insn is None:
            print(f"{h}\tINVALID")
            continue
        print(f"{h}\t{insn.mnemonic} {insn.op_str}")
        for k, v in zip(["opcode", "rex", "prefix", "addr_size", "modrm", "implR", "implW", "accR",
                         "accW", "ops"], detail_fields(insn).split("\t")):
            print(f"    {k:9} {v}")


def main():
    argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        return
    cmd, rest = argv[0], argv[1:]
    dirn, only, show = DEFAULT_DIR, None, 20
    i = 0
    while i < len(rest):
        if rest[i] == "--dir":
            dirn = rest[i + 1]; i += 1
        elif rest[i] == "--only":
            only = rest[i + 1].split(","); i += 1
        elif rest[i] == "--show":
            show = int(rest[i + 1]); i += 1
        elif cmd == "probe":
            break
        i += 1
    if cmd == "gen":
        gen(dirn, only)
    elif cmd == "learn":
        learn(dirn, only)
    elif cmd == "gen-mut":
        gen_mut(dirn)
    elif cmd == "gen-evex":
        gen_evex(dirn)
    elif cmd == "probe":
        probe(int(rest[0]), rest[1:])
    elif cmd == "cmp":
        args = ["cargo", "run", "-q", "--profile", "fast", "--example", "disasm_detail_diff", "--",
                "cmp", dirn, "--show", str(show)]
        if only:
            args += ["--only", ",".join(only)]
        subprocess.run(args, cwd=REPO, check=False)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
