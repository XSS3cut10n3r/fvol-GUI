#!/usr/bin/env python3
"""Generate the VEX / XOP / EVEX instruction specs (src/disasm/x86/spec_{vex,evex}.rs) by probing
capstone 5 with designed encodings and inferring, for every (mode, map, pp, opcode, W, L,
ModRM.reg, form) class, the mnemonic, which encoding field each printed operand comes from, and
(EVEX) which decorations are accepted: opmask, zeroing, embedded broadcast, rounding / SAE.

usage: gen_vex_spec.py vex  > src/disasm/x86/spec_vex.rs      (VEX + XOP)
       gen_vex_spec.py evex > src/disasm/x86/spec_evex.rs

Two probe "assignments" per class give every encoding field a distinct register number that
changes between them (ModRM.rm 2->3, vvvv 5->4, is4 6->7, VSIB index 1->3) while ModRM.reg stays
fixed, which makes the field attribution of each printed register unambiguous.
"""
import re
import sys
from collections import defaultdict, OrderedDict
from multiprocessing import Pool

import capstone

MD = {32: capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32),
      64: capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)}
PP = ["np", "66", "f3", "f2"]
KW = {"byte": "b", "word": "w", "dword": "d", "qword": "q", "xmmword": "x", "ymmword": "ymm",
      "zmmword": "zmm", "xword": "xw", "tbyte": "t"}
KWSIZE = {"b": 1, "w": 2, "d": 4, "q": 8, "x": 16, "ymm": 32, "zmm": 64, "xw": 10, "t": 10}
DEFKW = {"b": "b", "w": "w", "d": "d", "q": "q", "x": "x", "ymm": "ymm", "zmm": "zmm", "mm": "q"}
# (rm, vvvv, is4, vsib index) per assignment
ASSIGN = [(2, 5, 6, 1), (3, 4, 7, 3)]
SAE = {"{rn-sae}": "er", "{rd-sae}": "er", "{ru-sae}": "er", "{rz-sae}": "er", "{sae}": "sae"}


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


def parse_result(res):
    """capstone (size, mnemonic, op_str) -> (mnemonic, [raw operands], deco dict)."""
    size, mn, op = res
    toks = split_ops(op)
    deco = {"mask": None, "z": False, "sae": None, "sae_pos": None}
    ops = []
    for i, t in enumerate(toks):
        if t in SAE:
            deco["sae"] = t
            deco["sae_pos"] = len(ops)
            continue
        if re.fullmatch(r"\{k\d\}", t):
            deco["mask"] = int(t[2])
            ops.append(("kmask",))
            continue
        m = re.match(r"^(.*?)((?: \{[^}]*\})*)$", t)
        base, dec = m.group(1), m.group(2)
        if dec:
            for d in re.findall(r"\{([^}]*)\}", dec):
                if d == "z":
                    deco["z"] = True
                elif re.fullmatch(r"k\d", d):
                    deco["mask"] = int(d[1])
        if "[" in base:
            kwm = re.match(r"^(\w+) ptr ", base)
            if base.startswith("ptr "):
                kw = "p"
            elif kwm:
                kw = KW.get(kwm.group(1), "?")
            else:
                kw = "n"
            inner = re.search(r"\[(.*)\]", base).group(1)
            bc = re.search(r"\{1to(\d+)\}", base)
            base_nobc = re.sub(r"\{1to\d+\}", "", base)
            disp = None
            dm = re.search(r" ([+-]) (0x[0-9a-f]+|\d+)\]", base_nobc)
            if dm:
                disp = int(dm.group(2), 0) * (1 if dm.group(1) == "+" else -1)
            idx = None
            parts = [p.strip() for p in re.split(r"[+-]", inner)]
            for p in parts:
                pr = p.split("*")[0].strip()
                ri = reg_info(pr)
                if ri and ri[0] in ("x", "ymm", "zmm"):
                    idx = ri
            ops.append(("mem", kw, int(bc.group(1)) if bc else None, disp, idx))
        elif re.fullmatch(r"-?(0x[0-9a-f]+|\d+)", base):
            ops.append(("imm", int(base, 0)))
        else:
            ri = reg_info(base)
            if ri is None:
                ops.append(("other", base))
            else:
                ops.append(("reg", ri[0], ri[1], base))
    return mn, ops, deco, size


def attribute(pa, pb, r, novvvv):
    """Two parsed probe results (assignments A/B) -> list of abstract operands."""
    if pa[0] != pb[0] or len(pa[1]) != len(pb[1]):
        return None
    out = []
    for a, b in zip(pa[1], pb[1]):
        if a[0] != b[0]:
            return None
        if a[0] == "reg":
            cls = a[1]
            if b[1] != cls:
                return None
            na, nb = a[2], b[2]
            if na == nb:
                out.append(("reg", "r", cls) if na == r else ("fixed", a[3]))
            elif (na, nb) == (ASSIGN[0][0], ASSIGN[1][0]):
                out.append(("reg", "m", cls))
            elif (na, nb) == (ASSIGN[0][1], ASSIGN[1][1]) and not novvvv:
                out.append(("reg", "v", cls))
            elif (na, nb) == (ASSIGN[0][2], ASSIGN[1][2]):
                out.append(("reg", "4", cls))
            else:
                return None
        elif a[0] == "mem":
            idx = None
            if a[4] is not None:
                if b[4] is None or a[4][0] != b[4][0] or (a[4][1], b[4][1]) != (ASSIGN[0][3], ASSIGN[1][3]):
                    return None
                idx = a[4][0]
            out.append(("mem", a[1], a[2], a[3], idx))
        elif a[0] == "imm":
            out.append(("imm",))
        elif a[0] == "kmask":
            out.append(("kmask",))
        else:
            return None
    return out


class Enc:
    def __init__(self, kind):
        self.kind = kind

    def bytes(self, bits, mm, pp, W, L, vvvv, op, form, r, asg, aaa=0, z=0, b=0):
        rm, vv, is4, idx = ASSIGN[asg]
        vvvv = vv if vvvv is None else vvvv
        tail = bytes([is4 << 4]) + bytes(8)
        if form == "r":
            mod = bytes([0xC0 | (r << 3) | rm])
        elif form == "m":
            mod = bytes([0x40 | (r << 3) | rm, 1])
        else:  # vsib: [rdx + idx*1 + 1]
            mod = bytes([0x44 | (r << 3), (idx << 3) | 2, 1])
        if self.kind == "evex":
            p0 = 0xF0 | mm
            p1 = (W << 7) | ((~vvvv & 15) << 3) | 4 | pp
            p2 = (z << 7) | (L << 5) | (b << 4) | 0x08 | aaa
            return bytes([0x62, p0, p1, p2, op]) + mod + tail
        b1 = 0xE0 | mm
        b2 = (W << 7) | ((~vvvv & 15) << 3) | ((L & 1) << 2) | pp
        esc = 0xC4 if self.kind == "vex" else 0x8F
        return bytes([esc, b1, b2, op]) + mod + tail


def probe_form(enc, bits, mm, pp, W, L, op, r, form, **ext):
    """-> (novvvv, parsed_A, parsed_B) or None."""
    for vmode in ("v", "nov"):
        res = []
        for asg in (0, 1):
            x = dis(bits, enc.bytes(bits, mm, pp, W, L, None if vmode == "v" else 0, op, form, r, asg, **ext))
            res.append(x)
        if res[0] is not None and res[1] is not None:
            return vmode == "nov", parse_result(res[0]), parse_result(res[1])
        if res[0] is not None or res[1] is not None:
            return None
    return None


def tok(a, form):
    if a[0] == "reg":
        src, cls = a[1], a[2]
        if src == "m":
            return f"R:{cls}"
        return f"{src}:{cls}"
    if a[0] == "mem":
        kw = a[1]
        if a[4] is not None:  # VSIB
            return f"Vs:{a[4]}/{kw}"
        return f"M:/{kw}" if kw != "n" else "M:"
    if a[0] == "imm":
        return "i:b"
    if a[0] == "fixed":
        return a[1]
    if a[0] == "kmask":
        return "kmask"
    if a[0] == "rc":
        return "rc"
    return None


def combine(rops, mops):
    """Merge reg-form and mem-form operand lists into one entry (rm operand m:cls/kw)."""
    if len(rops) != len(mops):
        return None
    out = []
    for a, b in zip(rops, mops):
        if a[0] == "reg" and a[1] == "m" and b[0] == "mem" and b[4] is None:
            cls, kw = a[2], b[1]
            out.append(("rm", cls, kw))
        elif a == b or (a[0] == b[0] == "imm"):
            out.append(a)
        else:
            return None
    return out


def ops_tokens(ops, form):
    t = []
    for a in ops:
        if a[0] == "rm":
            cls, kw = a[1], a[2]
            t.append(f"m:{cls}" if DEFKW.get(cls) == kw else f"m:{cls}/{kw}")
        else:
            x = tok(a, form)
            if x is None:
                return None
            t.append(x)
    return t


def evex_flags(enc, bits, mm, pp, W, L, op, r, form, base_nov, base_ops):
    """Probe decorations for an EVEX class; returns a flag list (or None on inconsistency)."""
    flags = []
    vv = 0 if base_nov else None

    def pr(**ext):
        x = dis(bits, enc.bytes(bits, mm, pp, W, L, vv, op, form, r, 0, **ext))
        return parse_result(x) if x else None

    k1 = pr(aaa=1)
    if k1 is None:
        flags.append("nok")
    elif k1[2]["mask"] == 1:
        flags.append("k")
    kz = pr(aaa=1, z=1) if k1 is not None else pr(aaa=0, z=1)
    if kz is None:
        flags.append("noz")
    elif kz[2]["z"]:
        flags.append("z")
    b1 = pr(b=1)
    if b1 is None:
        flags.append("nobr" if form == "r" else "nobm")
    else:
        if form == "r" and b1[2]["sae"]:
            flags.append(SAE[b1[2]["sae"]])
            flags.append(f"rcpos{b1[2]['sae_pos']}")
        elif form != "r":
            mems = [o for o in b1[1] if o[0] == "mem"]
            if mems and mems[0][2]:
                kw = mems[0][1]
                flags.append({"d": "bd", "q": "bq", "w": "bw", "b": "bqb"}.get(kw, "b?"))
                esz = {"d": 4, "q": 8, "w": 2}.get(kw)
                vl = 16 << min(L, 2)
                if esz and mems[0][2] * esz * 2 == vl:
                    flags.append("bh")
    return flags


def probe_class(args):
    kind, bits, mm, pp, W, L, op = args
    enc = Enc(kind)
    results = {}
    for r in range(8):
        ents = []
        forms = {}
        for form in ("r", "m", "s"):
            if form == "s" and (forms.get("m") or forms.get("r")):
                continue
            p = probe_form(enc, bits, mm, pp, W, L, op, r, form)
            knz = False
            if p is None and kind == "evex" and form != "r":
                p = probe_form(enc, bits, mm, pp, W, L, op, r, form, aaa=1)
                knz = p is not None
            if p is None:
                continue
            nov, pa, pb = p
            ops = attribute(pa, pb, r, nov)
            if ops is None:
                ents.append(("FAIL", form, pa, pb))
                continue
            fl = ["novvvv"] if nov else []
            if kind == "evex":
                if knz:
                    fl += ["k", "knz"]
                    if not pa[2]["z"]:
                        zz = dis(bits, enc.bytes(bits, mm, pp, W, L, 0 if nov else None, op, form, r, 0, aaa=1, z=1))
                        if zz is None:
                            fl.append("noz")
                else:
                    ef = evex_flags(enc, bits, mm, pp, W, L, op, r, form, nov, ops)
                    fl += ef
                # disp8*N check
                mems = [o for o in ops if o[0] == "mem"]
                if mems and mems[0][3] is not None:
                    n = mems[0][3]
                    exp = KWSIZE.get(mems[0][1], 0)
                    if n != exp:
                        fl.append(f"n{n}")
            forms[form] = (pa[0], ops, tuple(fl))
        results[r] = forms if forms else None
        if any(e for e in ents):
            results[r] = ("FAIL", ents)
    return args, results


def class_entries(forms):
    """forms {form: (mn, ops, flags)} -> list of (sel_tuple, mn, tokens, flags)."""
    out = []
    R, M, S = forms.get("r"), forms.get("m"), forms.get("s")

    def fix_rc(t, fl):
        fl = list(fl)
        for f in fl:
            if f.startswith("rcpos"):
                pos = int(f[5:])
                t = list(t)
                t.insert(pos, "rc")
                t = tuple(t)
        return t, tuple(sorted(f for f in fl if not f.startswith("rcpos")))

    rset = lambda F: set(f for f in F[2] if not f.startswith("rcpos")) - {"er", "sae", "nobr"}
    if R and M and R[0] == M[0] and rset(R) == set(M[2]) - {"bd", "bq", "bw", "bqb", "bh", "nobm"}:
        c = combine(R[1], M[1])
        if c is not None:
            t = ops_tokens(c, "rm")
            if t is not None:
                fl = tuple(sorted(set(R[2]) | set(M[2])))
                t, fl = fix_rc(tuple(t), fl)
                out.append(((), R[0], t, fl))
                return out
    for sel, F in (("r", R), ("m", M), ("m", S)):
        if F:
            t = ops_tokens(F[1], sel)
            if t is None:
                return None
            t, fl = fix_rc(tuple(t), F[2])
            out.append(((sel,), F[0], t, fl))
    return out


# vector-length merging: per operand position, the token across L=0,1,2 -> merged token
VLPAT = {("x", "ymm", "zmm"): "X", ("x", "x", "ymm"): "Xh", ("x", "x", "x"): "Xq"}
KWPAT = {("x", "ymm", "zmm"): "X", ("q", "x", "ymm"): "Xh", ("d", "q", "x"): "Xq", ("w", "d", "q"): "Xe"}


def split_tok(t):
    m = re.fullmatch(r"(\w+):([\w]*)(?:/(\w+))?", t)
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)


def merge_vl(e0, e1, e2):
    """Three entries (L=0,1,2) -> merged entry with X-classes, or None."""
    (s0, mn0, t0, f0), (s1, mn1, t1, f1), (s2, mn2, t2, f2) = e0, e1, e2
    if not (s0 == s1 == s2 and mn0 == mn1 == mn2 and len(t0) == len(t1) == len(t2)):
        return None
    if not (f0 == f1 == f2):
        return None
    out = []
    changed = False
    for a, b, c in zip(t0, t1, t2):
        if a == b == c:
            out.append(a)
            continue
        pa, pb, pc = split_tok(a), split_tok(b), split_tok(c)
        if not (pa and pb and pc) or not (pa[0] == pb[0] == pc[0]):
            return None
        src = pa[0]
        cls3 = (pa[1], pb[1], pc[1])
        kw3 = (pa[2], pb[2], pc[2])
        if cls3[0] == cls3[1] == cls3[2]:
            cls = cls3[0]
        else:
            cls = VLPAT.get(cls3)
            if cls is None:
                return None
        # default keywords
        def dk(cl, k):
            return k if k is not None else DEFKW.get(cl)
        kw = None
        if src in ("m", "M", "Vs"):
            k3 = tuple(dk(cl, k) for cl, k in zip(cls3, kw3))
            if k3[0] == k3[1] == k3[2]:
                kw = k3[0]
            else:
                kw = KWPAT.get(k3)
                if kw is None:
                    return None
        if src == "M" or src == "Vs":
            t = f"{src}:{cls}/{kw}" if src == "Vs" else (f"M:/{kw}")
        elif src in ("m",):
            t = f"m:{cls}" if kw == cls or DEFKW.get(cls) == kw else f"m:{cls}/{kw}"
        else:
            t = f"{src}:{cls}"
        out.append(t)
        changed = True
    return (s0, mn0, tuple(out), f0)


def gen(kind):
    if kind == "vex":
        jobs = [("vex", bits, mm, pp, W, L, op) for bits in (64, 32) for mm in (1, 2, 3)
                for pp in range(4) for W in (0, 1) for L in (0, 1) for op in range(256)]
        jobs += [("xop", bits, mm, pp, W, L, op) for bits in (64, 32) for mm in (8, 9, 10)
                 for pp in range(4) for W in (0, 1) for L in (0, 1) for op in range(256)]
    else:
        jobs = [("evex", bits, mm, pp, W, L, op) for bits in (64, 32) for mm in (1, 2, 3)
                for pp in range(4) for W in (0, 1) for L in (0, 1, 2, 3) for op in range(256)]
    table = defaultdict(dict)  # (kind,bits,mm,pp,op) -> {(W,L,r): entries}
    fails = []
    with Pool() as pool:
        for args, results in pool.imap_unordered(probe_class, jobs, chunksize=64):
            k, bits, mm, pp, W, L, op = args
            for r, forms in results.items():
                if forms is None:
                    continue
                if isinstance(forms, tuple) and forms[0] == "FAIL":
                    fails.append((args, r, forms[1][:1]))
                    continue
                ents = class_entries(forms)
                if ents is None:
                    fails.append((args, r, "tokens"))
                    continue
                table[(k, bits, mm, pp, op)][(W, L, r)] = ents
    return table, fails


MAPNAME = {("vex", 1): "v1", ("vex", 2): "v2", ("vex", 3): "v3", ("xop", 8): "x8", ("xop", 9): "x9",
           ("xop", 10): "xa", ("evex", 1): "e1", ("evex", 2): "e2", ("evex", 3): "e3"}


def emit(table):
    lines = []
    for key in sorted(table):
        k, bits, mm, pp, op = key
        cls = table[key]
        # vector-length merge (EVEX: L=0,1,2 ; VEX: nothing to do, L-specific classes are fine)
        merged = {}
        if k == "evex":
            for W in (0, 1):
                for r in range(8):
                    es = [cls.get((W, L, r)) for L in (0, 1, 2)]
                    if all(es) and all(len(e) == len(es[0]) for e in es):
                        mm_ = []
                        for e0, e1, e2 in zip(*es):
                            m = merge_vl(e0, e1, e2)
                            if m is None:
                                break
                            mm_.append(m)
                        else:
                            merged[(W, r)] = mm_
        groups = defaultdict(set)
        for (W, L, r), ents in cls.items():
            if (W, r) in merged and (L in (0, 1, 2) or (L == 3 and ents == cls.get((W, 2, r)))):
                for e in merged[(W, r)]:
                    groups[e].add((W, "012" if L != 3 else "3", r))
                continue
            for e in ents:
                groups[e].add((W, str(L), r))
        for e, keys in groups.items():
            sel, mn, toks, flags = e
            Ws = sorted({x[0] for x in keys})
            Ls = sorted({x[1] for x in keys})
            rs = sorted({x[2] for x in keys})
            if len(keys) == len(Ws) * len(Ls) * len(rs):
                combos = [(Ws, Ls, rs)]
            else:
                combos = []
                for w in Ws:
                    for l in Ls:
                        rr = sorted({x[2] for x in keys if x[0] == w and x[1] == l})
                        if rr:
                            combos.append(([w], [l], rr))
            for Wsel, Lsel, rsel in combos:
                s = [f"mode{bits}"]
                if len(Wsel) == 1:
                    s.append(f"w{Wsel[0]}")
                lset = set("".join(Lsel))
                allL = {"0", "1"} if k != "evex" else {"0", "1", "2", "3"}
                if lset != allL:
                    s.append("|".join(f"l{x}" for x in sorted(lset)))
                if len(rsel) < 8:
                    s.append("/" + ",".join(str(x) for x in rsel))
                s += list(sel)
                fl = list(flags)
                if mn in ("vcmpps", "vcmppd", "vcmpss", "vcmpsd"):
                    fl.append("cmp32")
                if k == "xop" and mm == 10:
                    # XOP map 0xA (bextr / lwpins / lwpval) takes a 32-bit immediate
                    toks = tuple("i:d" if t == "i:b" else t for t in toks)
                if mn in ("vpermil2ps", "vpermil2pd"):
                    # the imm8 is the low nibble of the is4 byte (no extra byte)
                    toks = tuple("i:lo4" if t == "i:b" else t for t in toks)
                line = f"{MAPNAME[(k, mm)]} {op:02x} {PP[pp]} {' '.join(s)} : {mn} {', '.join(toks)}".rstrip()
                if fl:
                    line += " ; " + " ".join(fl)
                lines.append(line)
    return dedupe_modes(lines)


def dedupe_modes(lines):
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
    table, fails = gen(kind)
    lines = emit(table)
    name = {"vex": "VEX / XOP encoded instructions (AVX, AVX2, FMA, BMI, F16C, XOP, ...)",
            "evex": "EVEX encoded instructions (AVX-512)"}[kind]
    print(f"//! {name}.")
    print("//! GENERATED by bench/scripts/gen_vex_spec.py from capstone 5 probing -- do not edit;")
    print("//! manual additions/overrides live in spec_sse.rs.")
    print()
    print('pub(crate) const SPEC: &str = r#"')
    for l in lines:
        print(l)
    print('"#;')
    for f in fails:
        print("FAIL", f, file=sys.stderr)


if __name__ == "__main__":
    main()
