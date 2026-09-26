#!/usr/bin/env python3
"""Generate the VEX / XOP / EVEX instruction spec (src/disasm/x86/spec_{vex,evex}.rs) by probing
capstone 5 with designed encodings and inferring, for every (map, pp, opcode, W, L, ModRM.reg,
mod) class, the mnemonic and which encoding field each printed operand comes from.

usage: gen_vex_spec.py vex  > src/disasm/x86/spec_vex.rs
       gen_vex_spec.py evex > src/disasm/x86/spec_evex.rs

Probe design (64-bit): ModRM.reg = r (0..7, no REX.R), ModRM.rm = 2 (edx/xmm2) or [rdx + 1],
vvvv = 5, is4/imm8 = 0x60 (register 6).  Register numbers 1..7 are therefore attributable to a
field (r=1/3/4/7 are used for inference so they never collide with 2/5/6).
"""
import re
import sys
from collections import defaultdict, OrderedDict

import capstone

MD = {32: capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32),
      64: capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)}
PP = ["np", "66", "f3", "f2"]
KW = {"byte": "b", "word": "w", "dword": "d", "qword": "q", "xmmword": "x", "ymmword": "ymm",
      "zmmword": "zmm", "xword": "xw", "tbyte": "t"}
DEFKW = {"b": "b", "w": "w", "d": "d", "q": "q", "x": "x", "ymm": "ymm", "zmm": "zmm", "mm": "q"}


def dis(bits, b):
    r = next(MD[bits].disasm_lite(b, 0x1000, 1), None)
    if r is None:
        return None
    return r[1], r[2], r[3]


def reg_info(name):
    m = re.fullmatch(r"(x|y|z)mm(\d+)", name)
    if m:
        return {"x": "x", "y": "ymm", "z": "zmm"}[m.group(1)], int(m.group(2))
    m = re.fullmatch(r"k(\d)", name)
    if m:
        return "k", int(m.group(1))
    m = re.fullmatch(r"mm(\d)", name)
    if m:
        return "mm", int(m.group(1))
    g32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
    g64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
    g16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"]
    g8 = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"]
    for cls, tab in (("d", g32), ("q", g64), ("w", g16), ("b", g8)):
        if name in tab:
            return cls, tab.index(name)
    m = re.fullmatch(r"r(\d+)(d|w|b)?", name)
    if m:
        return {"d": "d", "w": "w", "b": "b", None: "q"}[m.group(2)], int(m.group(1))
    return None


def split_ops(op_str):
    return [o.strip() for o in op_str.split(",")] if op_str.strip() else []


MEMRE = re.compile(r"^(?:(\w+) ptr )?(?:ptr )?(?:\w+:)?\[(.*)\](\{1to\d+\})?$")


def parse_operand(tok, fields):
    """Return an abstract operand: ('reg', src, cls) / ('mem', kw) / ('imm',) / ('fixed', name)."""
    deco = ""
    m = re.match(r"^(.*?)((?: \{[^}]*\})*)$", tok)
    base, deco = m.group(1), m.group(2)
    if "[" in base:
        mm = MEMRE.match(base.replace("ptr ptr", "ptr"))
        kw = ""
        if base.startswith("ptr "):
            kw = "p"
        else:
            k = base.split(" ptr")[0] if " ptr" in base else ""
            kw = KW.get(k, "n") if k else "n"
        bc = re.search(r"\{1to(\d+)\}", tok)
        return ("mem", kw, bc.group(1) if bc else None, base)
    if re.fullmatch(r"-?(0x[0-9a-f]+|\d+)", base):
        return ("imm", int(base, 0))
    ri = reg_info(base)
    if ri is None:
        return ("other", base)
    cls, n = ri
    for src, val in fields:
        if n == val:
            return ("reg", src, cls, n)
    return ("fixed", base)


def infer(bits, reg_res, mem_res, fields, r):
    """Combine register- and memory-form results into spec operand tokens.
    Returns list of (selectors_extra, mnemonic, ops) (one or two entries)."""
    out = []

    def toks(res, form):
        size, mn, op = res
        ops = []
        for t in split_ops(op):
            p = parse_operand(t, fields)
            ops.append(p)
        return mn, ops

    def tok_of(p, other=None, only=None):
        kind = p[0]
        if kind == "reg":
            src, cls = p[1], p[2]
            if src == "r":
                return f"r:{cls}"
            if src == "v":
                return f"v:{cls}"
            if src == "4":
                return f"4:{cls}"
            if src == "m":
                if only == "r":
                    return f"R:{cls}"
                if other is not None and other[0] == "mem":
                    kw = other[1]
                    if DEFKW.get(cls) == kw:
                        return f"m:{cls}"
                    return f"m:{cls}/{kw}"
                return f"R:{cls}"
        if kind == "mem":
            return f"M:/{p[1]}" if p[1] != "n" else "M:"
        if kind == "imm":
            return "i:b"
        if kind == "fixed":
            return p[1]
        return None

    R = toks(reg_res, "r") if reg_res else None
    M = toks(mem_res, "m") if mem_res else None
    if R and M and R[0] == M[0] and len(R[1]) == len(M[1]):
        ops = []
        for a, b in zip(R[1], M[1]):
            if a[0] == "reg" and a[1] == "m" and b[0] == "mem":
                t = tok_of(a, b)
            elif a[0] == "mem":
                return None
            else:
                t = tok_of(a)
            if t is None:
                return None
            ops.append(t)
        out.append(([], R[0], ops))
        return out
    if R:
        ops = [tok_of(a, only="r") for a in R[1]]
        if None in ops or any(a[0] == "mem" for a in R[1]):
            return None
        out.append((["r"] if M else ["r"], R[0], ops))
    if M:
        ops = []
        for b in M[1]:
            if b[0] == "reg" and b[1] == "m":
                return None
            t = tok_of(b)
            if t is None:
                return None
            ops.append(t)
        out.append((["m"], M[0], ops))
    return out


def vex_bytes(bits, mmmmm, pp, W, L, vvvv, op, modrm, tail):
    b1 = 0xE0 | mmmmm  # R X B = 0 (inverted bits set)
    b2 = (W << 7) | ((~vvvv & 15) << 3) | (L << 2) | pp
    return bytes([0xC4, b1, b2, op, modrm]) + tail


def xop_bytes(bits, mmmmm, pp, W, L, vvvv, op, modrm, tail):
    b1 = 0xE0 | mmmmm
    b2 = (W << 7) | ((~vvvv & 15) << 3) | (L << 2) | pp
    return bytes([0x8F, b1, b2, op, modrm]) + tail


# two field assignments: (rm, vvvv, is4 register); ModRM.reg stays the same in both.
ASSIGN = [(2, 5, 6), (3, 4, 7)]


def probe_form(enc, bits, mm, pp, W, L, op, r, mem):
    """Probe one ModRM form; returns (novvvv, [res_A, res_B]) or None."""
    for vvvv_mode in ("v", "nov"):
        res = []
        for rm, vv, is4 in ASSIGN:
            vvvv = vv if vvvv_mode == "v" else 0
            tail = bytes([is4 << 4]) + bytes(8)
            if mem:
                b = enc(bits, mm, pp, W, L, vvvv, op, 0x40 | (r << 3) | rm, bytes([1]) + tail)
            else:
                b = enc(bits, mm, pp, W, L, vvvv, op, 0xC0 | (r << 3) | rm, tail)
            res.append(dis(bits, b))
        if res[0] is not None and res[1] is not None:
            return vvvv_mode == "nov", res
        if res[0] is not None or res[1] is not None:
            return None
    return None


def attribute(resA, resB, r, novvvv):
    """Tokenise both probe results and attribute register operands to encoding fields."""
    if resA[1] != resB[1] or resA[0] != resB[0]:
        return None
    ta, tb = split_ops(resA[2]), split_ops(resB[2])
    if len(ta) != len(tb):
        return None
    ops = []
    for a, b in zip(ta, tb):
        pa = parse_operand(a, [])
        pb = parse_operand(b, [])
        if pa[0] == "fixed" and pb[0] == "fixed":
            ra, rb = reg_info(pa[1]), reg_info(pb[1])
            if ra is None or rb is None or ra[0] != rb[0]:
                return None
            cls, na, nb = ra[0], ra[1], rb[1]
            if na == nb:
                src = "r" if na == r else "fixed"
            elif (na, nb) == (ASSIGN[0][0], ASSIGN[1][0]):
                src = "m"
            elif (na, nb) == (ASSIGN[0][1], ASSIGN[1][1]) and not novvvv:
                src = "v"
            elif (na, nb) == (ASSIGN[0][2], ASSIGN[1][2]):
                src = "4"
            else:
                return None
            if src == "fixed":
                ops.append(("fixed", pa[1]))
            else:
                ops.append(("reg", src, cls, na))
        elif pa[0] == "imm" and pb[0] == "imm":
            ops.append(("imm",))
        elif pa[0] == "mem" and pb[0] == "mem":
            ops.append(pa)
        else:
            return None
    return resA[1], ops


def probe_raw(enc, bits, mm, pp, W, L, op, r):
    R = probe_form(enc, bits, mm, pp, W, L, op, r, False)
    M = probe_form(enc, bits, mm, pp, W, L, op, r, True)
    if R is None and M is None:
        return None
    return R, M


def infer_raw(bits, x, r):
    R, M = x
    ra = attribute(R[1][0], R[1][1], r, R[0]) if R else None
    ma = attribute(M[1][0], M[1][1], r, M[0]) if M else None
    if (R and ra is None) or (M and ma is None):
        return ("FAIL", R and R[1][0], M and M[1][0])
    fl_r = ("novvvv",) if R and R[0] else ()
    fl_m = ("novvvv",) if M and M[0] else ()
    out = []
    if ra and ma and ra[0] == ma[0] and len(ra[1]) == len(ma[1]) and fl_r == fl_m:
        ops = []
        ok = True
        for a, b in zip(ra[1], ma[1]):
            if a[0] == "reg" and a[1] == "m" and b[0] == "mem":
                cls, kw = a[2], b[1]
                ops.append(f"m:{cls}" if DEFKW.get(cls) == kw else f"m:{cls}/{kw}")
            elif a == b or (a[0] == "reg" and b[0] == "reg" and a[1:3] == b[1:3]) or (a[0] == b[0] == "imm") \
                    or (a[0] == b[0] == "fixed" and a[1] == b[1]):
                ops.append(tok(a))
            else:
                ok = False
                break
        if ok:
            return [((), ra[0], tuple(ops), fl_r)]
    if ra:
        out.append((("r",), ra[0], tuple(tok(a, reg_only=True) for a in ra[1]), fl_r))
    if ma:
        out.append((("m",), ma[0], tuple(tok(a) for a in ma[1]), fl_m))
    if any(None in e[2] for e in out):
        return ("FAIL", R and R[1][0], M and M[1][0])
    return out


def tok(p, reg_only=False):
    if p[0] == "reg":
        src, cls = p[1], p[2]
        if src == "m":
            return f"R:{cls}"
        return f"{src}:{cls}"
    if p[0] == "mem":
        return f"M:/{p[1]}" if p[1] != "n" else "M:"
    if p[0] == "imm":
        return "i:b"
    if p[0] == "fixed":
        return p[1]
    return None


def probe_all_r(enc, bits, mm, pp, W, L, op):
    out = {}
    for r in range(8):
        x = probe_raw(enc, bits, mm, pp, W, L, op, r)
        out[r] = None if x is None else infer_raw(bits, x, r)
    return out


def gen(kind):
    lines = []
    if kind == "vex":
        maps = [(1, "v1"), (2, "v2"), (3, "v3")]
        enc = vex_bytes
    else:
        maps = [(8, "x8"), (9, "x9"), (10, "xa")]
        enc = xop_bytes
    fails = []
    for mm, mname in maps:
        for pp in range(4):
            for op in range(256):
                # results[(bits, W, L, r)] = list of entries
                table = {}
                for bits in (64, 32):
                    for W in (0, 1):
                        for L in (0, 1):
                            res = probe_all_r(enc, bits, mm, pp, W, L, op)
                            for r in range(8):
                                x = res[r]
                                if isinstance(x, tuple) and x and x[0] == "FAIL":
                                    fails.append((mname, PP[pp], op, bits, W, L, r, x[1], x[2]))
                                    x = None
                                table[(bits, W, L, r)] = x
                emit(lines, mname, PP[pp], op, table)
    return lines, fails


def emit(lines, mname, pp, op, table):
    """Merge equal results across r, L, W, mode and emit spec lines."""
    # key -> set of (bits, W, L, r)
    groups = defaultdict(set)
    for key, ents in table.items():
        if not ents:
            continue
        for e in ents:
            groups[e].add(key)
    for e, keys in groups.items():
        sel, mn, ops, flags = e
        # build selector set: try to factor into mode x W x L x r
        bitsset = sorted({k[0] for k in keys})
        for bits in bitsset:
            ks = {k[1:] for k in keys if k[0] == bits}
            # full coverage check across dimensions
            Ws = sorted({k[0] for k in ks})
            Ls = sorted({k[1] for k in ks})
            rs = sorted({k[2] for k in ks})
            if len(ks) == len(Ws) * len(Ls) * len(rs):
                combos = [(Ws, Ls, rs)]
            else:
                combos = [([w], [l], sorted({k[2] for k in ks if k[0] == w and k[1] == l}))
                          for w in Ws for l in Ls if any(k[0] == w and k[1] == l for k in ks)]
            for Wsel, Lsel, rsel in combos:
                s = []
                if len(bitsset) == 1 or True:
                    s.append(f"mode{bits}")
                if len(Wsel) == 1:
                    s.append(f"w{Wsel[0]}")
                if len(Lsel) == 1:
                    s.append(f"l{Lsel[0]}")
                if len(rsel) < 8:
                    s.append("/" + ",".join(str(x) for x in rsel))
                s += list(sel)
                fl = list(flags)
                if mn in ("vcmpps", "vcmppd", "vcmpss", "vcmpsd"):
                    fl.append("cmp32")
                line = f"{mname} {op:02x} {pp} {' '.join(s)} : {mn} {', '.join(ops)}".rstrip()
                if fl:
                    line += " ; " + " ".join(fl)
                lines.append(line)


def dedupe_modes(lines):
    """Lines identical except for mode32/mode64 -> drop the mode selector."""
    seen = OrderedDict()
    for l in lines:
        k = l.replace(" mode32", "").replace(" mode64", "")
        seen.setdefault(k, set()).add("32" if " mode32" in l else "64")
    out = []
    for k, modes in seen.items():
        if modes == {"32", "64"}:
            out.append(k)
        else:
            m = modes.pop()
            lhs, rhs = k.split(" : ", 1)
            p = lhs.split(" ")
            out.append(" ".join(p[:3] + [f"mode{m}"] + p[3:]) + " : " + rhs)
    return out


def main():
    kind = sys.argv[1]
    lines, fails = gen(kind)
    lines = dedupe_modes(lines)
    name = {"vex": "VEX-encoded instructions (AVX, AVX2, FMA, BMI, F16C, ...)",
            "xop": "XOP-encoded instructions (AMD)"}[kind]
    print(f"//! {name}.")
    print("//! GENERATED by bench/scripts/gen_vex_spec.py (capstone 5 probing); hand edits below the")
    print("//! marker line are preserved by the generator's caller only manually.")
    print()
    print('pub(crate) const SPEC: &str = r#"')
    for l in lines:
        print(l)
    print('"#;')
    for f in fails:
        print("FAIL", f, file=sys.stderr)


if __name__ == "__main__":
    main()
