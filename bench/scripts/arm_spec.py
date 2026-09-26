"""Text form of a learned ARM / AArch64 instruction spec (see arm_learn.py) and a python
reference evaluator for it.  The Rust engine (src/disasm/arm64/engine.rs) implements exactly the
same semantics.

Grammar (one record per line, fields separated by TAB, '#' starts a comment line):

  T <name> <n> <e0>|<e1>|...            dense table of n entries
  G <name> <n> <gen> <args> <rules>      big table: generator + override rules
                                         rules: <imask>:<ivalue>=<entry>|...  (first match wins)
  H <mask> <value> <handler>             hand-written handler class
  C <mask> <value> <mnemonic> <template> <constraints>

  entries: text, '!O' (not this class: try the next one) or '!I' (invalid instruction)
  mask/value: hex; classes are listed in priority order (first match wins).

  template: literal text with atoms %...%:
    %r <cls> <sp31> <field> <suffix> <exc>%   register  cls in xwbhsdqvzp, sp31 z|s|-,
                                              number = field mod 32, suffix or '-'
    %n <prefix> <style> <pc> <field> <exc>%   number    prefix or '-', style S64|U64|S32|U32|DEC|SDEC,
                                              pc 0|1 (pc)|2 (pc page)
    %t <table> <index>%                       table     index = bits[/p31 fields]
  field: [s]<lsb>:<width>(,<lsb>:<width>)*[*<scale>][+<base>]   segments LSB first, s = signed
         or L<bit>:<coef>(,<bit>:<coef>)*[+<base>]                  generic linear
  exc: '-' or <key>=O|I(,<key>=O|I)*  (register: key = number, number: key = raw field value)
  constraints: '-' or space separated: tie:<a>=<b>,... | neq:<lsbA>,<lsbB> | neq31:<lsbA>,<lsbB>
               (neq fields are 5 bits wide)

  F cond                                 32-bit ARM condition folding (see src/disasm/arm64/engine.rs)

  generators (functions of the whole instruction word):
    reglist <lsb>           ARM register list "{r0, r4, lr}" of the 16-bit mask at lsb
    sysreg <lsb>            s<op0>_<op1>_c<crn>_c<crm>_<op2> of the 16-bit field at lsb
    bitmask <lsb> <size> <style>   AArch64 logical immediate N:immr:imms (imms at lsb,
                                    immr at lsb+6, N at lsb+12) of element size `size`
"""
import re

from arm_learn import (A0, INVALID, OTHER, extract, fmt_num, model_value, reg_name, render_atom,
                       table_index)


# ----------------------------------------------------------------------------------------------
# generators

def decode_bitmask(n, immr, imms, regsize):
    """ARM ARM DecodeBitMasks (immediate=True): returns value or None if reserved."""
    x = (n << 6) | (~imms & 0x3F)
    if x == 0:
        return None
    length = x.bit_length() - 1
    if length < 1:
        return None
    esize = 1 << length
    if regsize == 32 and n:
        return None
    levels = esize - 1
    s = imms & levels
    r = immr & levels
    if s == levels:
        return None
    welem = (1 << (s + 1)) - 1
    # rotate right by r within esize
    welem = ((welem >> r) | (welem << (esize - r))) & ((1 << esize) - 1)
    v = 0
    for i in range(regsize // esize):
        v |= welem << (i * esize)
    return v


ARM_GPR = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "sb", "sl", "fp", "ip", "sp", "lr", "pc"]


def gen_value(gen, args, w):
    if gen == "reglist":
        m = (w >> int(args[0])) & 0xFFFF
        return "{" + ", ".join(ARM_GPR[i] for i in range(16) if m >> i & 1) + "}"
    if gen == "sysreg":
        e = (w >> int(args[0])) & 0xFFFF
        return "s%d_%d_c%d_c%d_%d" % (e >> 14, (e >> 11) & 7, (e >> 7) & 15, (e >> 3) & 15, e & 7)
    if gen == "bitmask":
        lsb, size, style = int(args[0]), int(args[1]), args[2]
        imms = (w >> lsb) & 63
        immr = (w >> (lsb + 6)) & 63
        n = (w >> (lsb + 12)) & 1
        v = decode_bitmask(n, immr, imms, size)
        if v is None:
            return INVALID
        return "#" + fmt_style(v, style, size)
    raise ValueError(gen)


def fmt_style(v, style, size=64):
    if style == "SX16":   # value truncated to int16, printed as uint32
        v &= 0xFFFF
        if v >> 15:
            v -= 1 << 16
        return fmt_num(v, "U32")
    if style == "SX16OR64":   # 16-bit sign-extended if it fits in 16 bits (as u32), else u64
        if (v & 0xFFFF) == (v & 0xFFFFFFFF):
            return fmt_style(v, "SX16")
        return fmt_num(v, "U64")
    if style == "PLAIN64":    # '#%u' when 0..9 else '#0x%llx' of the 64-bit value
        return fmt_num(v, "U64")
    return fmt_num(v, style)


BITMASK_STYLES = ["U64", "S64", "U32", "S32", "SX16", "SX16OR64"]


# ----------------------------------------------------------------------------------------------
# emission

def seg_field(coef, signed_ok=True):
    """Convert linear coefficients {bit: coef} into a segment field spec text, or a generic one."""
    items = sorted(coef, key=lambda bc: abs(bc[1]))
    if not items:
        return "L"
    s = abs(items[0][1])
    ok = s != 0
    order = []
    for k, (b, c) in enumerate(items):
        if abs(c) != s << k:
            ok = False
            break
        order.append((b, c))
    if ok:
        negs = [c < 0 for b, c in order]
        signed = False
        scale = s
        if all(negs):
            scale = -s
        elif any(negs):
            if negs[-1] and not any(negs[:-1]):
                signed = True
            else:
                ok = False
    if not ok:
        return "L" + ",".join("%d:%d" % (b, c) for b, c in coef)
    # segments: consecutive word bits with consecutive k
    segs = []
    for b, c in order:
        if segs and segs[-1][0] + segs[-1][1] == b:
            segs[-1][1] += 1
        else:
            segs.append([b, 1])
    txt = ("s" if signed else "") + ",".join("%d:%d" % (a, n) for a, n in segs)
    if scale != 1:
        txt += "*%d" % scale
    return txt


def field_text(at):
    f = seg_field(at["coef"])
    if at["base"]:
        f += "%+d" % at["base"]
    return f


def exc_text(at):
    ex = at.get("exc")
    if not ex:
        return "-"
    return ",".join("%s=%s" % (k, v) for k, v in sorted(ex.items(), key=lambda kv: int(kv[0])))


def enc_entry(s):
    if s == OTHER:
        return "!O"
    if s == INVALID:
        return "!I"
    assert "|" not in s and "\t" not in s and "%" not in s and not s.startswith("!"), s
    return s


class Emitter:
    def __init__(self):
        self.tables = {}     # key -> name
        self.lines = []

    def table(self, at, klass):
        tab = at["tab"]
        n = len(tab)
        if n >= 512:
            key = ("G", klass["mask"], klass["value"], tuple(at["bits"]), tuple(at.get("p31", [])), tuple(tab))
        else:
            key = ("T", tuple(tab))
        if key in self.tables:
            return self.tables[key]
        name = "t%d" % len(self.tables)
        self.tables[key] = name
        if n < 512:
            self.lines.append("T\t%s\t%d\t%s" % (name, n, "|".join(enc_entry(s) for s in tab)))
        else:
            self.lines.append(self.big_table(name, at, klass))
        return name

    def big_table(self, name, at, klass):
        tab = at["tab"]
        bits = at["bits"]
        p31 = at.get("p31", [])
        from arm_learn import set_table_index
        words = [set_table_index(klass["value"], bits, p31, x) for x in range(len(tab))]
        best = None
        cands = [("const", ["!O"]), ("const", ["!I"]), ("reglist", ["0"])]
        for lsb in (5, 0):
            cands.append(("sysreg", [str(lsb)]))
        for lsb in (10, 5):
            for size in (64, 32):
                for st in BITMASK_STYLES:
                    cands.append(("bitmask", [str(lsb), str(size), st]))
        for gen, args in cands:
            if gen == "const":
                c = OTHER if args[0] == "!O" else INVALID
                pred = [c] * len(tab)
            else:
                pred = [gen_value(gen, args, w) for w in words]
            miss = sum(1 for a, b in zip(pred, tab) if a != b)
            if best is None or miss < best[0]:
                best = (miss, gen, args, pred)
        miss, gen, args, pred = best
        # override rules: exceptions compressed by merging index cubes with equal results
        exc = {x: tab[x] for x in range(len(tab)) if pred[x] != tab[x]}
        rules = compress(exc, len(tab).bit_length() - 1)
        rtxt = "|".join("%x:%x=%s" % (m, v, enc_entry(r)) for m, v, r in rules) or "-"
        return "G\t%s\t%d\t%s\t%s\t%s" % (name, len(tab), gen, " ".join(args), rtxt)

    def atom(self, at, klass):
        k = at["k"]
        if k == "const":
            return None
        if k == "reg":
            sp = {"zr": "z", "sp": "s"}.get(at.get("sp31"), "-")
            return "%%r %s %s %s %s %s%%" % (at["cls"].lower(), sp, field_text(at), at["suffix"] or "-", exc_text(at))
        if k == "num":
            return "%%n %s %s %d %s %s%%" % (at["prefix"] or "-", at["style"], at["pc"], field_text(at), exc_text(at))
        if k == "table":
            name = self.table(at, klass)
            idx = ",".join(str(b) for b in at["bits"]) or "-"
            if at.get("p31"):
                idx += "/" + ",".join(str(b) if isinstance(b, int) else "%d:%d" % tuple(b) for b in at["p31"])
            return "%%t %s %s%%" % (name, idx or "-")
        raise ValueError(k)

    def klass(self, c):
        if c.get("handler"):
            return "H\t%08x\t%08x\t%s" % (c["mask"], c["value"], c["handler"])
        parts = []
        for i, at in enumerate(c["atoms"]):
            parts.append(c["seps"][i])
            a = self.atom(at, c)
            parts.append(at["s"] if a is None else a)
        parts.append(c["seps"][len(c["atoms"])])
        tmpl = "".join(parts)
        cons = []
        for con in c.get("cons", []):
            if con[0] == "tie":
                cons.append("tie:" + ",".join("%d=%d" % (a, b) for a, b in con[1]))
            else:
                wd = len(con[1])
                cons.append("%s:%d,%d" % (con[0], con[1][0], con[2][0]) + ("" if wd == 5 else ",%d" % wd))
        return "C\t%08x\t%08x\t%s\t%s\t%s" % (c["mask"], c["value"], c["mnem"], tmpl or "-", " ".join(cons) or "-")


def compress(exc, nbits):
    """exc: {index: result}. Returns [(mask, value, result)] covering exactly the exception
    indices (greedy cube merging per result)."""
    by_res = {}
    for x, r in exc.items():
        by_res.setdefault(r, set()).add(x)
    rules = []
    full = (1 << nbits) - 1
    for r, xs in by_res.items():
        cubes = {(full, x) for x in xs}   # (care mask, value)
        changed = True
        while changed:
            changed = False
            new = set()
            used = set()
            lst = sorted(cubes)
            present = set(lst)
            for (m, v) in lst:
                for b in range(nbits):
                    bit = 1 << b
                    if not (m & bit) or (v & bit):
                        continue
                    other = (m, v | bit)
                    if other in present:
                        new.add((m & ~bit, v))
                        used.add((m, v))
                        used.add(other)
            if new:
                cubes = (cubes - used) | new
                changed = True
        # remove cubes covered by others
        cl = sorted(cubes, key=lambda mv: bin(mv[0]).count("1"))
        keep = []
        for m, v in cl:
            if any((v & km) == kv and (m & km) == km for km, kv in keep):
                continue
            keep.append((m, v))
        for m, v in keep:
            rules.append((m, v, r))
    return rules


def emit_text(classes, header=""):
    e = Emitter()
    body = [e.klass(c) for c in classes]
    out = []
    if header:
        out.append(header)
    out.extend(e.lines)
    out.extend(body)
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------------------------------------
# reference evaluator for the text form

def parse_field(txt):
    base = 0
    m = re.match(r"^(.*?)([+-]\d+)?$", txt)
    core = m.group(1)
    if m.group(2):
        base = int(m.group(2))
    if core.startswith("L"):
        coef = []
        for item in core[1:].split(","):
            if item:
                b, c = item.split(":")
                coef.append([int(b), int(c)])
        return {"base": base, "coef": coef}
    signed = core.startswith("s")
    if signed:
        core = core[1:]
    scale = 1
    if "*" in core:
        core, sc = core.split("*")
        scale = int(sc)
    coef = []
    k = 0
    for seg in core.split(","):
        lsb, n = seg.split(":")
        for i in range(int(n)):
            coef.append([int(lsb) + i, scale << k])
            k += 1
    if signed:
        coef[-1][1] = -coef[-1][1]
    return {"base": base, "coef": coef}


def parse_exc(txt):
    if txt == "-":
        return None
    d = {}
    for item in txt.split(","):
        k, v = item.split("=")
        d[k] = v
    return d


class TextSpec:
    def __init__(self, text):
        self.tables = {}
        self.classes = []   # (mask, value, handler or None, mnem, ops, cons)
        self.fold_cond = False
        for line in text.split("\n"):
            if not line or line.startswith("#"):
                continue
            f = line.split("\t")
            if f[0] == "F" and f[1] == "cond":
                self.fold_cond = True
            elif f[0] == "T":
                self.tables[f[1]] = ("dense", [self.entry(x) for x in f[3].split("|")])
            elif f[0] == "G":
                rules = []
                if f[5] != "-":
                    for r in f[5].split("|"):
                        mv, res = r.split("=", 1)
                        m, v = mv.split(":")
                        rules.append((int(m, 16), int(v, 16), self.entry(res)))
                self.tables[f[1]] = ("gen", f[3], f[4].split(" "), rules)
            elif f[0] == "H":
                self.classes.append((int(f[1], 16), int(f[2], 16), f[3], None, None, None))
            elif f[0] == "C":
                ops = self.parse_template(f[4])
                cons = [] if f[5] == "-" else f[5].split(" ")
                self.classes.append((int(f[1], 16), int(f[2], 16), None, f[3], ops, cons))

    @staticmethod
    def entry(x):
        return OTHER if x == "!O" else INVALID if x == "!I" else x

    def parse_template(self, t):
        if t == "-":
            return []
        ops = []
        parts = t.split("%")
        for i, p in enumerate(parts):
            if i % 2 == 0:
                if p:
                    ops.append(("lit", p))
                continue
            f = p.split(" ")
            if f[0] == "r":
                fld = parse_field(f[3])
                at = {"k": "reg", "cls": f[1].upper(), "sp31": {"z": "zr", "s": "sp"}.get(f[2]),
                      "suffix": "" if f[4] == "-" else f[4], "exc": parse_exc(f[5]), **fld}
                ops.append(("atom", at))
            elif f[0] == "n":
                fld = parse_field(f[4])
                at = {"k": "num", "prefix": "" if f[1] == "-" else f[1], "style": f[2], "pc": int(f[3]),
                      "exc": parse_exc(f[5]), **fld}
                ops.append(("atom", at))
            elif f[0] == "t":
                idx = f[2]
                p31 = []
                if "/" in idx:
                    idx, pp = idx.split("/")
                    for x in pp.split(","):
                        if ":" in x:
                            a, wd = x.split(":")
                            p31.append([int(a), int(wd)])
                        else:
                            p31.append(int(x))
                bits = [] if idx in ("-", "") else [int(x) for x in idx.split(",")]
                ops.append(("table", f[1], bits, p31))
            else:
                raise ValueError(p)
        return ops

    def table_lookup(self, name, bits, p31, w):
        t = self.tables[name]
        idx = table_index({"bits": bits, "p31": p31}, w)
        if t[0] == "dense":
            return t[1][idx]
        for m, v, r in t[3]:
            if (idx & m) == v:
                return r
        if t[1] == "const":
            return OTHER if t[2][0] == "!O" else INVALID
        return gen_value(t[1], t[2], w)

    def render_class(self, c, w, addr):
        mask, value, handler, mnem, ops, cons = c
        if handler:
            from arm_learn import HANDLERS
            r = HANDLERS[handler](w, addr)
            return INVALID if r is None else r
        for con in cons:
            kind, arg = con.split(":")
            if kind == "tie":
                for pr in arg.split(","):
                    a, b = pr.split("=")
                    if ((w >> int(a)) ^ (w >> int(b))) & 1:
                        return OTHER
            else:
                xs = [int(x) for x in arg.split(",")]
                a, b = xs[0], xs[1]
                wd = xs[2] if len(xs) > 2 else 5
                ones = (1 << wd) - 1
                va, vb = (w >> a) & ones, (w >> b) & ones
                if va == vb and (kind == "neq" or va != ones):
                    return INVALID
        out = [mnem, "\t"]
        for op in ops:
            if op[0] == "lit":
                out.append(op[1])
            elif op[0] == "atom":
                s = render_atom(op[1], w, addr)
                if s is OTHER or s is INVALID:
                    return s
                out.append(s)
            else:
                s = self.table_lookup(op[1], op[2], op[3], w)
                if s is OTHER or s is INVALID:
                    return s
                out.append(s)
        return "".join(out)

    def build_index(self):
        idx = {}
        for ci, c in enumerate(self.classes):
            m = (c[0] >> 21) & 0x7FF
            v = (c[1] >> 21) & 0x7FF
            free = [i for i in range(11) if not (m >> i) & 1]
            for x in range(1 << len(free)):
                key = v
                for j, b in enumerate(free):
                    if x >> j & 1:
                        key |= 1 << b
                idx.setdefault(key, []).append(ci)
        self._index = idx

    def render(self, w, addr=A0):
        r, matched = self.render_direct(w, addr)
        if not matched and self.fold_cond and (w >> 28) < 14:
            r2, m2 = self.render_direct((w & 0x0FFFFFFF) | 0xE0000000, addr)
            if r2 is not None:
                from arm_learn import cond_insert
                return cond_insert(r2, w >> 28)
            return None
        return r

    def render_direct(self, w, addr=A0):
        if getattr(self, "_index", None) is None:
            self.build_index()
        for ci in self._index.get((w >> 21) & 0x7FF, []):
            c = self.classes[ci]
            if (w & c[0]) != c[1]:
                continue
            r = self.render_class(c, w, addr)
            if r is OTHER:
                continue
            if r is INVALID:
                return None, True
            return r, True
        return None, False
