#!/usr/bin/env python3
"""Differential harness for capstone *detail mode* (regs_access, detail operands, opcode bytes).

Usage (bench venv python, which has capstone; run through bench/scripts/limit.sh -m 4G):
  disasm_detail_diff.py gen   [--dir DIR] [--only real64,real32,...]   write DIR/NAME.det
  disasm_detail_diff.py cmp   [--dir DIR] [--only ...] [--show N]      run examples/disasm_detail_diff.rs
  disasm_detail_diff.py probe 32|64 HEX...                             print capstone's detail view

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

DEFAULT_DIR = "/tmp/rsvol-disasm"
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
