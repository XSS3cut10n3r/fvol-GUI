"""Probe-driven instruction-class learner for fixed-width (32-bit) ISAs, used to build fastvol's
ARM / AArch64 disassembler specs from the capstone 5 oracle (black box: word -> text).

Model
-----
A *class* is a set of instruction words sharing one printed *shape*: the mnemonic plus the
operand string with every atom (register, immediate, keyword) replaced by its kind.  It is
described by

  * mask / value         -- the bits that select the class,
  * mnemonic / template  -- literal separators interleaved with atoms,
  * one model per atom   -- how the atom text is computed from operand bits:
        const  : fixed text
        reg    : register name   prefix + number(+special name for 31) + suffix,
                 number = (segments value + offset) mod 32
        num    : immediate text  prefix + formatted(value), value = linear function of the
                 operand bits (plus the instruction address for pc-relative operands)
        table  : lookup table indexed by the concatenated operand bits (keywords, oddities)
  * exceptions           -- operand values for which the class is *not* responsible (OTHER:
                            another class prints it) or the word is invalid (INVALID),
  * constraints          -- register fields that must differ (e.g. ldp x0, x0 is invalid).

Classes are discovered from seed words: bits whose single flip keeps the shape are operand
bits (refined over random members so that one special value, e.g. offset 0, does not turn a
field into opcode bits), the others are opcode bits.  Atom dependencies come from which atom
changes when a bit flips; atom models are fitted (linear) or enumerated (tables).
"""
import bisect
import json
import random
import re
import struct

import capstone

A0 = 0x100000              # default probe address
A1 = 0x7FF123456000        # second address (page aligned) for pc-relative detection
A2 = A0 + 4
M64 = (1 << 64) - 1

OTHER = "\x01OTHER"
INVALID = "\x01INVALID"


# ----------------------------------------------------------------------------------------------
# oracle

class Oracle:
    def __init__(self, arch):
        if arch == "arm64":
            self.md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        else:
            self.md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        self.cache = {}
        self.calls = 0

    def __call__(self, w, addr=A0):
        w &= 0xFFFFFFFF
        key = (w, addr)
        c = self.cache
        if key in c:
            return c[key]
        self.calls += 1
        r = next(self.md.disasm_lite(struct.pack("<I", w), addr, 1), None)
        r = (r[2], r[3]) if r is not None else None
        if len(c) > 1500000:
            c.clear()
        c[key] = r
        return r


# ----------------------------------------------------------------------------------------------
# tokenizing / shapes

ATOM_RE = re.compile(r"[A-Za-z0-9_#.\-+]+")

REG_CLASSES = "XWBHSDQVZPR"

# architecture used by tokenize()/shape_of() when not given explicitly (set by the drivers)
CUR_ARCH = ["arm64"]


def tokenize(ops, arch=None):
    """Split an operand string into separators and atoms.  For 32-bit ARM, brace groups
    (register lists, whose length varies with the encoding) are single atoms."""
    arch = arch or CUR_ARCH[0]
    seps = []
    atoms = []
    pos = 0
    if arch == "arm":
        i = 0
        n = len(ops)
        start_sep = 0
        while i < n:
            c = ops[i]
            if c == "{":
                j = ops.find("}", i)
                if j < 0:
                    j = n - 1
                seps.append(ops[start_sep:i])
                atoms.append(ops[i:j + 1])
                i = j + 1
                start_sep = i
                continue
            m = ATOM_RE.match(ops, i)
            if m:
                seps.append(ops[start_sep:i])
                atoms.append(m.group())
                i = m.end()
                start_sep = i
                continue
            i += 1
        seps.append(ops[start_sep:])
        return tuple(seps), tuple(atoms)
    for m in ATOM_RE.finditer(ops):
        seps.append(ops[pos:m.start()])
        atoms.append(m.group())
        pos = m.end()
    seps.append(ops[pos:])
    return tuple(seps), tuple(atoms)


_re_x = re.compile(r"x\d+|xzr|sp")
_re_w = re.compile(r"w\d+|wzr|wsp")
_re_f = re.compile(r"([bhsdq])(\d+)")
_re_v = re.compile(r"v(\d+)((?:\.\d*[bhsdq])?)")
_re_z = re.compile(r"z(\d+)((?:\.[bhsdq])?)")
_re_p = re.compile(r"p(\d+)((?:\.[bhsdq])?)")
_re_za = re.compile(r"za(\d*)([hv]?)((?:\.[bhsdq])?)")
_re_imm = re.compile(r"#-?(?:0x[0-9a-f]+|\d+)")
_re_fp = re.compile(r"#?-?\d+\.\d+")
_re_n = re.compile(r"-?(?:0x[0-9a-f]+|\d+)")
_re_c = re.compile(r"c\d+")
# ARM32 register names
_re_r32 = re.compile(r"r\d+|sb|sl|fp|ip|sp|lr|pc")
_re_vfp = re.compile(r"([sdq])(\d+)")
ARM_GPR = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "sb", "sl", "fp", "ip", "sp", "lr", "pc"]


def aclass(a, arch=None):
    arch = arch or CUR_ARCH[0]
    if arch == "arm":
        if a.startswith("{"):
            return "L"
        if _re_r32.fullmatch(a):
            return "R"
        m = _re_vfp.fullmatch(a)
        if m:
            return m.group(1).upper()
        if re.fullmatch(r"p\d+", a):
            return "P"
    if arch == "arm64":
        if _re_x.fullmatch(a):
            return "X"
        if _re_w.fullmatch(a):
            return "W"
        m = _re_f.fullmatch(a)
        if m:
            return m.group(1).upper()
        m = _re_v.fullmatch(a)
        if m:
            return "V" + m.group(2)
        m = _re_z.fullmatch(a)
        if m:
            return "Z" + m.group(2)
        m = _re_p.fullmatch(a)
        if m:
            return "P" + m.group(2)
        m = _re_za.fullmatch(a)
        if m:
            return "ZA" + ("N" if m.group(1) else "") + m.group(2) + m.group(3)
    if _re_imm.fullmatch(a):
        return "#I"
    if _re_fp.fullmatch(a):
        return "F"
    if _re_n.fullmatch(a):
        return "N"
    if _re_c.fullmatch(a):
        return "C"
    return "K"


def shape_of(t, arch=None):
    """t = (mnemonic, ops) -> hashable shape."""
    arch = arch or CUR_ARCH[0]
    seps, atoms = tokenize(t[1], arch)
    return (t[0], seps, tuple(aclass(a, arch) for a in atoms))


# ----------------------------------------------------------------------------------------------
# atom value parsing / formatting

def parse_num(a):
    """'#-0x10' -> ('#', -16); 'c7' -> ('c', 7); '0xf' -> ('', 15)."""
    m = re.fullmatch(r"([#c]?)(-?)(0x[0-9a-f]+|\d+)", a)
    if not m:
        return None
    v = int(m.group(3), 0)
    if m.group(2):
        v = -v
    return m.group(1), v


def fmt_num(v, style):
    """capstone-style number formatting (HEX_THRESHOLD 9)."""
    if style in ("S64", "S32"):
        bits = 64 if style == "S64" else 32
        v &= (1 << bits) - 1
        if v >> (bits - 1):
            v -= 1 << bits
        if v >= 0:
            return "0x%x" % v if v > 9 else "%d" % v
        return "-0x%x" % -v if v < -9 else "-%d" % -v
    if style in ("U64", "U32"):
        v &= (1 << (64 if style == "U64" else 32)) - 1
        return "0x%x" % v if v > 9 else "%d" % v
    if style == "DEC":
        return "%d" % (v & 0xFFFFFFFF)
    if style == "SDEC":
        v &= 0xFFFFFFFF
        if v >> 31:
            v -= 1 << 32
        return "%d" % v
    raise ValueError(style)


STYLES = ["S64", "U64", "S32", "U32", "DEC", "SDEC"]


def parse_reg(a, cls):
    """-> (number, special) ; special in (None, 'zr', 'sp')."""
    if cls == "X":
        if a == "xzr":
            return 31, "zr"
        if a == "sp":
            return 31, "sp"
        return int(a[1:]), None
    if cls == "W":
        if a == "wzr":
            return 31, "zr"
        if a == "wsp":
            return 31, "sp"
        return int(a[1:]), None
    if cls == "R":
        if a in ARM_GPR:
            return ARM_GPR.index(a), None
        return int(a[1:]), None
    m = re.match(r"[a-z](\d+)", a)
    return int(m.group(1)), None


def reg_name(cls, suffix, special31, n):
    if cls == "R":
        return ARM_GPR[n & 15] + suffix
    if cls in "XW":
        if n == 31 and special31:
            if cls == "X":
                return "xzr" if special31 == "zr" else "sp"
            return "wzr" if special31 == "zr" else "wsp"
        return cls.lower() + str(n) + suffix
    return cls[0].lower() + str(n) + suffix


# ----------------------------------------------------------------------------------------------
# field helpers

def bits_of(mask):
    return [i for i in range(32) if mask >> i & 1]


def extract(w, bitlist):
    """Concatenate bits of w listed LSB-first."""
    v = 0
    for k, b in enumerate(bitlist):
        v |= ((w >> b) & 1) << k
    return v


def deposit(w, bitlist, v):
    for k, b in enumerate(bitlist):
        w = (w & ~(1 << b)) | (((v >> k) & 1) << b)
    return w & 0xFFFFFFFF


def popcount(x):
    return bin(x).count("1")


# ----------------------------------------------------------------------------------------------
# hand-written handlers (families whose printing depends on value comparisons); registered by
# the per-architecture drivers: name -> fn(word, addr) -> text | None (invalid) | OTHER

HANDLERS = {}


# ----------------------------------------------------------------------------------------------
# class model

class Klass:
    """See module doc. Serializable to/from JSON."""

    def __init__(self):
        self.mask = 0
        self.value = 0
        self.mnem = ""
        self.seps = ()
        self.atoms = []        # list of dicts
        self.cons = []         # constraints: [kind, bitsA, bitsB]
        self.prio = 0
        self.seed = 0
        self.handler = None    # special handler name (hand-written logic)

    def to_json(self):
        return {"mask": self.mask, "value": self.value, "mnem": self.mnem, "seps": list(self.seps),
                "atoms": self.atoms, "cons": self.cons, "prio": self.prio, "seed": self.seed,
                "handler": self.handler}

    @staticmethod
    def from_json(d):
        k = Klass()
        k.mask, k.value, k.mnem = d["mask"], d["value"], d["mnem"]
        k.seps = tuple(d["seps"])
        k.atoms = d["atoms"]
        k.cons = d.get("cons", [])
        k.prio = d.get("prio", 0)
        k.seed = d.get("seed", 0)
        k.handler = d.get("handler")
        return k

    def matches(self, w):
        return (w & self.mask) == self.value

    def render(self, w, addr=A0):
        """-> text 'mnem\\tops' | OTHER | INVALID"""
        if self.handler:
            r = HANDLERS[self.handler](w, addr)
            return INVALID if r is None else r
        out = []
        for c in self.cons:
            kind = c[0]
            if kind == "tie":
                for a, b in c[1]:
                    if ((w >> a) ^ (w >> b)) & 1:
                        return OTHER
                continue
            va, vb = extract(w, c[1]), extract(w, c[2])
            ones = (1 << len(c[1])) - 1
            if kind == "neq" and va == vb:
                return INVALID
            if kind == "neq31" and va == vb and va != ones:
                return INVALID
        for i, at in enumerate(self.atoms):
            out.append(self.seps[i])
            s = render_atom(at, w, addr)
            if s is OTHER or s is INVALID:
                return s
            out.append(s)
        out.append(self.seps[len(self.atoms)])
        return self.mnem + "\t" + "".join(out)


def model_value(at, w, addr):
    """Linear model value (python int, not reduced)."""
    v = at["base"]
    for b, c in at["coef"]:
        if (w >> b) & 1:
            v += c
    pc = at.get("pc", 0)
    if pc == 1:
        v += addr
    elif pc == 2:
        v += addr & ~0xFFF
    return v


def table_index(at, w):
    """Table index: operand bits (LSB first) then pseudo bits (register field == 31)."""
    idx = extract(w, at["bits"])
    n = len(at["bits"])
    for k, p in enumerate(at.get("p31", [])):
        start, wd = (p, 5) if isinstance(p, int) else p
        ones = (1 << wd) - 1
        if (w >> start) & ones == ones:
            idx |= 1 << (n + k)
    return idx


def set_table_index(w, at_bits, p31, x):
    """Deposit table index x into w (pseudo bits choose 31 / a non-31 value)."""
    w = deposit(w, at_bits, x)
    n = len(at_bits)
    for k, p in enumerate(p31):
        start, wd = (p, 5) if isinstance(p, int) else p
        ones = (1 << wd) - 1
        want = (x >> (n + k)) & 1
        cur = (w >> start) & ones
        if want and cur != ones:
            w = (w & ~(ones << start)) | (ones << start)
        elif not want and cur == ones:
            w = (w & ~(ones << start)) | (2 << start)
    return w & 0xFFFFFFFF


def render_atom(at, w, addr):
    k = at["k"]
    if k == "const":
        return at["s"]
    if k == "table":
        idx = table_index(at, w)
        s = at["tab"][idx]
        if s == OTHER:
            return OTHER
        if s == INVALID:
            return INVALID
        return s
    if k == "reg":
        n = model_value(at, w, addr) % 32
        ex = at.get("exc")
        if ex:
            e = ex.get(str(n))
            if e is not None:
                return OTHER if e == "O" else INVALID
        return reg_name(at["cls"], at["suffix"], at.get("sp31"), n)
    if k == "num":
        v = model_value(at, w, addr)
        ex = at.get("exc")
        if ex:
            e = ex.get(str(extract(w, sorted(b for b, _ in at["coef"]))))
            if e is not None:
                return OTHER if e == "O" else INVALID
        return at["prefix"] + fmt_num(v, at["style"])
    raise ValueError(k)


# ----------------------------------------------------------------------------------------------
# spec (ordered list of classes) + matcher

class Spec:
    def __init__(self, arch):
        self.arch = arch
        self.classes = []
        self._index = None

    @staticmethod
    def pkey(k):
        """Priority order: effective priority (specificity + bump) first."""
        return (-(popcount(k.mask) + k.prio), k.mask, k.value)

    @staticmethod
    def buckets(k):
        m = (k.mask >> 21) & 0x7FF
        v = (k.value >> 21) & 0x7FF
        free = [i for i in range(11) if not (m >> i) & 1]
        for x in range(1 << len(free)):
            key = v
            for j, b in enumerate(free):
                if x >> j & 1:
                    key |= 1 << b
            yield key

    def add(self, k):
        self.classes.append(k)
        if self._index is not None:
            ci = len(self.classes) - 1
            kk = self.pkey(k)
            for b in self.buckets(k):
                lst = self._index.setdefault(b, [])
                bisect.insort(lst, ci, key=lambda c: self.pkey(self.classes[c]) if c != ci else kk)

    def set_prio(self, k, prio):
        """Change a class priority, keeping the index ordered."""
        if self._index is None:
            k.prio = prio
            return
        ci = self.classes.index(k)
        for b in self.buckets(k):
            lst = self._index.get(b)
            if lst and ci in lst:
                lst.remove(ci)
        k.prio = prio
        kk = self.pkey(k)
        for b in self.buckets(k):
            lst = self._index.setdefault(b, [])
            bisect.insort(lst, ci, key=lambda c: self.pkey(self.classes[c]) if c != ci else kk)

    def order(self):
        self.classes.sort(key=self.pkey)
        self._index = None

    def build_index(self):
        self.order()
        idx = {}
        for ci, k in enumerate(self.classes):
            for key in self.buckets(k):
                idx.setdefault(key, []).append(ci)
        self._index = idx

    def candidates(self, w):
        if self._index is None:
            self.build_index()
        return self._index.get((w >> 21) & 0x7FF, [])

    def render(self, w, addr=A0):
        """-> (text or None, class index or None)"""
        r, ci = self.render_direct(w, addr)
        if ci is None and self.arch == "arm" and (w >> 28) < 14:
            # condition folding: render the AL twin and insert the condition suffix
            r2, ci2 = self.render_direct((w & 0x0FFFFFFF) | 0xE0000000, addr)
            if r2 is not None:
                return cond_insert(r2, w >> 28), ci2
            return None, None
        return r, ci

    def render_direct(self, w, addr=A0):
        for ci in self.candidates(w):
            k = self.classes[ci]
            if (w & k.mask) != k.value or getattr(k, "disabled", False):
                continue
            r = k.render(w, addr)
            if r is OTHER:
                continue
            if r is INVALID:
                return None, ci
            return r, ci
        return None, None

    def save(self, path):
        with open(path, "w") as f:
            json.dump({"arch": self.arch, "classes": [k.to_json() for k in self.classes]}, f)

    @staticmethod
    def load(path):
        with open(path) as f:
            d = json.load(f)
        s = Spec(d["arch"])
        s.classes = [Klass.from_json(x) for x in d["classes"]]
        return s


def oracle_text(t):
    return None if t is None else t[0] + "\t" + t[1]


ARM_CONDS = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le"]


def cond_insert(text, c):
    """Insert ARM condition suffix c into 'mnemonic\tops' before the first '.' of the mnemonic."""
    tab = text.find("\t")
    if tab < 0:
        tab = len(text)
    dot = text.find(".", 0, tab)
    pos = dot if dot >= 0 else tab
    return text[:pos] + ARM_CONDS[c] + text[pos:]


# ----------------------------------------------------------------------------------------------
# learning

class Learner:
    def __init__(self, oracle, arch="arm64", rnd=None, log=None):
        self.O = oracle
        self.arch = arch
        self.rnd = rnd or random.Random(12345)
        self.log = log or (lambda *a: None)
        self.ties = []   # current tie groups (lists of bits, leader first)

    # ------------------------------------------------------------------ helpers
    def shape(self, t):
        return shape_of(t, self.arch)

    def same(self, w, sh):
        t = self.O(w)
        return t is not None and self.shape(t) == sh

    def tie(self, w):
        for g in self.ties:
            b0 = (w >> g[0]) & 1
            for b in g[1:]:
                w = (w & ~(1 << b)) | (b0 << b)
        return w & 0xFFFFFFFF

    def dep(self, w, bitlist, x):
        return self.tie(deposit(w, bitlist, x))

    def flip(self, w, b):
        """flip unit led by bit b (with its tied followers)"""
        w ^= 1 << b
        for g in self.ties:
            if g[0] == b:
                for f in g[1:]:
                    w ^= 1 << f
        return w & 0xFFFFFFFF

    def atom_of(self, w, j):
        return tokenize(self.O(w)[1])[1][j]

    # ------------------------------------------------------------------ bit classification
    def classify_bits(self, seed, sh, force):
        opc = force
        for i in range(32):
            if not (force >> i) & 1 and not self.same(seed ^ (1 << i), sh):
                opc |= 1 << i
        for it in range(4):
            members = self.gen_members(seed, opc, sh, 16, 64, ties=False)
            changed = False
            for i in bits_of(opc & ~force):
                keep = tot = 0
                for m in members[:12]:
                    tot += 1
                    if self.same(m ^ (1 << i), sh):
                        keep += 1
                if tot >= 3 and keep * 2 > tot:
                    opc &= ~(1 << i)
                    changed = True
            if not changed:
                break
        return opc

    def find_ties(self, seed, sh, opc, force):
        """Pairs of opcode bits whose joint flip keeps the shape -> tie groups."""
        cand = bits_of(opc & ~force)
        pairs = []
        for x in range(len(cand)):
            for y in range(x + 1, len(cand)):
                i, j = cand[x], cand[y]
                if ((seed >> i) ^ (seed >> j)) & 1:
                    continue    # tied bits are equal in the seed
                if self.same(seed ^ (1 << i) ^ (1 << j), sh):
                    pairs.append((i, j))
        if not pairs:
            return []
        # keep only pairs that belong to a run of >= 3 consecutive bits with the same distance
        # (register fields); isolated coincidences are ignored
        by_d = {}
        for i, j in pairs:
            by_d.setdefault(j - i, set()).add(i)
        groups = {}
        for d, starts in by_d.items():
            for i in starts:
                run = 1
                k = i - 1
                while k in starts:
                    run += 1
                    k -= 1
                k = i + 1
                while k in starts:
                    run += 1
                    k += 1
                if run >= 3:
                    groups.setdefault(i, set()).add(i + d)
        # union-find into groups
        parent = {}

        def find(a):
            while parent.get(a, a) != a:
                a = parent[a]
            return a
        for i, js in groups.items():
            for j in js:
                ra, rb = find(i), find(j)
                if ra != rb:
                    parent[max(ra, rb)] = min(ra, rb)
        comp = {}
        for b in set(groups) | set(j for js in groups.values() for j in js):
            comp.setdefault(find(b), []).append(b)
        return [sorted(g) for g in comp.values() if len(g) >= 2]

    def gen_members(self, seed, opc, sh, n, tries, ties=True):
        free = ~opc & 0xFFFFFFFF
        members = [seed]
        t = 0
        while len(members) < n and t < tries:
            t += 1
            w = (seed & opc) | (self.rnd.getrandbits(32) & free)
            if ties:
                w = self.tie(w)
            if self.same(w, sh):
                members.append(w)
        return members

    def structured_members(self, members, sh, free):
        """Members with each candidate register field forced to 31 (sp/zr special cases)."""
        out = []
        for start in self.REG_FIELDS:
            fm = self.ONES << start
            if (free & fm) != fm:
                continue
            for m in members[:3]:
                w = self.tie(m | fm)
                if w != m and self.same(w, sh):
                    out.append(w)
                    break
        return out

    REG_FIELDS = (0, 5, 10, 16)
    RW = 5          # register field width
    ONES = 31       # all-ones register number (sp / zr / pc special cases)

    def p31_entry(self, start):
        return start if self.RW == 5 else [start, self.RW]

    def atom_deps(self, sh, members, leaders):
        natoms = len(sh[2])
        deps = [0] * natoms
        O = self.O
        free = 0
        for b in leaders:
            free |= 1 << b
        for m in members[:10] + self.structured_members(members, sh, free):
            _, a0 = tokenize(O(m)[1])
            for i in leaders:
                w = self.flip(m, i)
                t = O(w)
                if t is None or self.shape(t) != sh:
                    continue
                _, a1 = tokenize(t[1])
                for j in range(natoms):
                    if a1[j] != a0[j]:
                        deps[j] |= 1 << i
        return deps

    # ------------------------------------------------------------------ learning
    def learn(self, seed, force=0, depth=0):
        k, bad = self._learn(seed, force)
        if k is None:
            return None
        if not bad or depth >= 5:
            if bad:
                self.log("  unvalidated class", hex(seed), k.mnem, "failures", len(bad))
            return k
        # validation failed: split on candidate selector bits
        for b in self.split_candidates(k, bad):
            k2 = self.learn(seed, force | k.mask | (1 << b), depth + 1)
            if k2 is not None and not getattr(k2, "_bad", None):
                return k2
        k._bad = bad
        self.log("  unvalidated class", hex(seed), k.mnem, "failures", len(bad))
        return k

    def _learn(self, seed, force, depth=0):
        O = self.O
        t0 = O(seed)
        if t0 is None:
            return None, None
        sh = self.shape(t0)
        self.ties = []
        opc = self.classify_bits(seed, sh, force)
        ties = self.find_ties(seed, sh, opc, force)
        tie_bits = 0
        for g in ties:
            for b in g:
                tie_bits |= 1 << b
        opc &= ~tie_bits
        self.ties = ties
        followers = 0
        for g in ties:
            for b in g[1:]:
                followers |= 1 << b
        leaders = [b for b in bits_of(~opc & 0xFFFFFFFF) if not (followers >> b) & 1]
        members = self.gen_members(seed, opc, sh, 24, 96)
        deps = self.atom_deps(sh, members, leaders)
        k = Klass()
        k.mask = opc
        k.value = seed & opc
        k.mnem = t0[0]
        k.seps = sh[1]
        k.seed = seed
        if ties:
            pairs = []
            for g in ties:
                for b in g[1:]:
                    pairs.append([g[0], b])
            k.cons.append(["tie", pairs])
        _, atoms0 = tokenize(t0[1])
        for j, cls in enumerate(sh[2]):
            at = self.model_atom(j, cls, deps[j], sh, members, atoms0[j], depth < 4)
            if at is None:
                if depth < 4 and deps[j]:
                    b = max(bits_of(deps[j]))
                    return self._learn(seed, force | opc | (1 << b), depth + 1)
                self.log("  cannot model atom", j, cls, hex(seed), t0)
                return None, None
            k.atoms.append(at)
        self.find_constraints(k, sh, members)
        bad = self.validate(k, sh)
        if k._foreign:
            self.add_guard(k, sh, members, deps, followers)
        return k, bad

    def add_guard(self, k, sh, members, deps, followers):
        """The class renders words whose printed form differs (e.g. a keyword that disappears
        for some values of otherwise unused bits): add an invisible table atom over the bits no
        atom depends on, mapping the foreign combinations to OTHER / INVALID."""
        used = 0
        for d in deps:
            used |= d
        dc = [b for b in bits_of(~k.mask & ~used & ~followers & 0xFFFFFFFF)]
        if not dc or len(dc) > 10:
            return
        tab = []
        for x in range(1 << len(dc)):
            entry = None
            other = False
            for m0 in members[:4]:
                w = self.dep(m0, dc, x)
                t = self.O(w)
                if t is None:
                    continue
                if self.shape(t) != sh:
                    other = True
                    continue
                entry = ""
                break
            tab.append(entry if entry is not None else (OTHER if other else INVALID))
        if all(e == "" for e in tab):
            return
        k.atoms.append({"k": "table", "bits": dc, "tab": tab})
        k.seps = tuple(k.seps) + ("",)

    def validate(self, k, sh, n=160):
        bad = []
        k._foreign = []
        free = ~k.mask & 0xFFFFFFFF
        tests = []
        for _ in range(n):
            tests.append(self.tie((k.value) | (self.rnd.getrandbits(32) & free)))
        # structured: register fields forced to 31, and to equal values
        for start in self.REG_FIELDS:
            fm = self.ONES << start
            if (free & fm) == fm:
                for _ in range(6):
                    tests.append(self.tie(k.value | (self.rnd.getrandbits(32) & free) | fm))
        for w in tests:
            t = self.O(w)
            if t is None or self.shape(t) != sh:
                r = k.render(w)
                if r is not OTHER and r is not INVALID and r != oracle_text(t):
                    k._foreign.append(w)
                continue
            if k.render(w) != oracle_text(t):
                bad.append(w)
        return bad

    def split_candidates(self, k, bad):
        # bits used by several non-register atoms first (merged encodings), then bits most
        # associated with the failures
        cnt = {}
        for at in k.atoms:
            if at["k"] == "table":
                for b in at["bits"]:
                    cnt[b] = cnt.get(b, 0) + 1
            elif at["k"] == "num":
                for b, _ in at["coef"]:
                    cnt[b] = cnt.get(b, 0) + 1
        shared = sorted([b for b, c in cnt.items() if c >= 2], key=lambda b: -cnt[b])
        seed = k.seed
        free = [b for b in bits_of(~k.mask & 0xFFFFFFFF)]
        score = []
        for b in free:
            diff = sum(1 for w in bad if ((w ^ seed) >> b) & 1)
            score.append((-diff, b))
        score.sort()
        out = []
        for b in shared + [b for _, b in score[:4]]:
            if b not in out:
                out.append(b)
        return out[:5]

    # ------------------------------------------------------------------ atom models
    def model_atom(self, j, cls, dep, sh, members, a0, allow_split=False):
        if dep == 0:
            return {"k": "const", "s": a0}
        dbits = bits_of(dep)
        if cls[0] in REG_CLASSES and not cls.startswith("ZA"):
            at = self.fit_reg(j, cls, dbits, sh, members)
            if at:
                return at
        elif cls in ("#I", "N", "C"):
            at = self.fit_num(j, dbits, sh, members)
            if at:
                return at
            if allow_split and len(dbits) > 6:
                return None     # prefer splitting the class over a big number table
        # keyword-like atom: depends on register fields only through "== 31"?
        p31 = []
        for start in self.REG_FIELDS:
            fbits = set(range(start, start + self.RW))
            if not (dep & (self.ONES << start)) or not fbits <= set(dbits):
                continue
            if self.only_31(j, start, sh, members):
                p31.append(self.p31_entry(start))
                dbits = [b for b in dbits if b not in fbits]
        if len(dbits) + len(p31) <= 16:
            return self.enum_table(j, dbits, sh, members, p31)
        return None

    def only_31(self, j, start, sh, members):
        """True if atom j changes with register field `start` only between 31 and non-31."""
        seen = 0
        for m in members[:4]:
            vals = {}
            for v in ((0, 7, 21, 30, 31) if self.RW == 5 else (0, 3, 9, 14, 15)):
                w = self.tie((m & ~(self.ONES << start)) | (v << start))
                if not self.same(w, sh):
                    continue
                vals[v] = self.atom_of(w, j)
            non31 = set(s for v, s in vals.items() if v != self.ONES)
            if len(non31) > 1:
                return False
            if self.ONES in vals and non31 and vals[self.ONES] not in non31:
                seen += 1
        return seen > 0

    def enum_table(self, j, dbits, sh, members, p31=()):
        p31 = list(p31)
        bases = members[:3]
        extra = members[3:8]
        tab = []
        n = len(dbits) + len(p31)
        for x in range(1 << n):
            entry = None
            other = False
            for m0 in bases + (extra if n <= 10 else []):
                w = self.tie(set_table_index(m0, dbits, p31, x))
                t = self.O(w)
                if t is None:
                    continue
                if self.shape(t) != sh:
                    other = True
                    continue
                entry = tokenize(t[1])[1][j]
                break
            if entry is None:
                entry = OTHER if other else INVALID
            tab.append(entry)
            if n > 10 and len(bases) > 1:
                bases = bases[:1]   # large tables: single base member
        at = {"k": "table", "bits": dbits, "tab": tab}
        if p31:
            at["p31"] = p31
        return at

    def _fit_linear(self, j, dbits, sh, members, parse, modulus):
        for m0 in members[:8]:
            p0 = parse(self.atom_of(m0, j))
            if p0 is None:
                return None
            coef = {}
            ok = True
            for b in dbits:
                w = self.flip(m0, b)
                if not self.same(w, sh):
                    ok = False
                    break
                p = parse(self.atom_of(w, j))
                if p is None:
                    return None
                d = (p - p0) % modulus
                if (m0 >> b) & 1:
                    d = (-d) % modulus
                coef[b] = d
            if not ok:
                continue
            base = p0
            for b in dbits:
                if (m0 >> b) & 1:
                    base -= coef[b]
            base %= modulus
            return base, coef
        return None

    def _check_linear(self, j, dbits, sh, members, parse, modulus, base, coef, extra=48):
        samples = []
        m0 = members[0]
        tests = list(members)
        for _ in range(extra):
            tests.append(self.dep(m0, dbits, self.rnd.getrandbits(len(dbits))))
        for w in tests:
            t = self.O(w)
            if t is None or self.shape(t) != sh:
                continue
            a = tokenize(t[1])[1][j]
            p = parse(a)
            if p is None:
                return None
            v = base
            for b in dbits:
                if (w >> b) & 1:
                    v += coef[b]
            if (v - p) % modulus != 0:
                return None
            samples.append((w, a))
        return samples

    def pc_mode(self, j, sh, members, parse):
        m0 = members[0]
        t0 = self.O(m0, A0)
        t1 = self.O(m0, A1)
        t2 = self.O(m0, A2)
        if t1 is None or t2 is None or self.shape(t1) != sh or self.shape(t2) != sh:
            return 0
        p0 = parse(tokenize(t0[1])[1][j])
        p1 = parse(tokenize(t1[1])[1][j])
        p2 = parse(tokenize(t2[1])[1][j])
        if p0 is None or p1 is None or p2 is None:
            return -1
        if p0 == p1 and p0 == p2:
            return 0
        # 64-bit addresses, or 32-bit wrap-around (ARM)
        for mod in (1 << 64, 1 << 32):
            if (p1 - p0) % mod == (A1 - A0) % mod and (p2 - p0) % mod == 4:
                return 1
            if (p1 - p0) % mod == ((A1 & ~0xFFF) - (A0 & ~0xFFF)) % mod and p2 == p0:
                return 2
        return -1

    def _enum_exceptions(self, dbits, sh, members, key_fn, check_fn):
        """Enumerate a small field over two base members; exceptions must agree."""
        exc = {}
        bases = members[:2]
        for x in range(1 << len(dbits)):
            kinds = []
            for m0 in bases:
                w = self.dep(m0, dbits, x)
                t = self.O(w)
                if t is None:
                    kinds.append("I")
                elif self.shape(t) != sh:
                    kinds.append("O")
                else:
                    if not check_fn(w, t):
                        return None
                    kinds.append(None)
            if all(kk is not None for kk in kinds):
                # confirm on more members: an exception must hold whatever the other fields are
                for m0 in members[2:10]:
                    w = self.dep(m0, dbits, x)
                    t = self.O(w)
                    if t is None:
                        kinds.append("I")
                    elif self.shape(t) != sh:
                        kinds.append("O")
                    else:
                        if not check_fn(w, t):
                            return None
                        kinds.append(None)
                if all(kk is not None for kk in kinds):
                    exc[key_fn(bases[0], x)] = "O" if "O" in kinds else "I"
        return exc

    def fit_reg(self, j, cls, dbits, sh, members):
        def parse(a):
            try:
                return parse_reg(a, cls)[0]
            except Exception:
                return None
        r = self._fit_linear(j, dbits, sh, members, parse, 32)
        if r is None:
            return None
        base, coef = r
        if self._check_linear(j, dbits, sh, members, parse, 32, base, coef) is None:
            return None
        suffix = re.sub(r"^[A-Z]+", "", cls)
        at = {"k": "reg", "cls": cls[0], "suffix": suffix, "base": base,
              "coef": sorted([b, c] for b, c in coef.items()), "sp31": None}
        sp = {}

        def check(w, t):
            a = tokenize(t[1])[1][j]
            num, special = parse_reg(a, cls)
            n = model_value(at, w, A0) % 32
            if num != n:
                return False
            if n == 31 and cls in "XW":
                if sp.setdefault("v", special) != special:
                    return False
            return True
        if len(dbits) <= 8:
            exc = self._enum_exceptions(dbits, sh, members,
                                        lambda m0, x: str(model_value(at, self.dep(m0, dbits, x), A0) % 32),
                                        check)
            if exc is None:
                return None
            if exc:
                at["exc"] = exc
            at["sp31"] = sp.get("v")
        if cls in "XW" and at["sp31"] is None:
            at["sp31"] = "zr"
        return at

    def fit_num(self, j, dbits, sh, members):
        a0 = self.atom_of(members[0], j)
        pn = parse_num(a0)
        if pn is None:
            return None
        prefix = pn[0]

        def parse(a):
            p = parse_num(a)
            if p is None or p[0] != prefix:
                return None
            return p[1]
        pcm = self.pc_mode(j, sh, members, parse)
        if pcm < 0:
            return None
        for modulus in (1 << 64, 1 << 32):
            r = self._fit_linear(j, dbits, sh, members, parse, modulus)
            if r is None:
                continue
            base, coef = r
            samples = self._check_linear(j, dbits, sh, members, parse, modulus, base, coef)
            if samples is None:
                continue
            half = modulus >> 1
            coefs = {b: (c - modulus if c >= half else c) for b, c in coef.items()}
            if pcm == 1:
                base -= A0
            elif pcm == 2:
                base -= A0 & ~0xFFF
            base %= modulus
            if base >= half:
                base -= modulus
            at = {"k": "num", "prefix": prefix, "base": base,
                  "coef": sorted([b, c] for b, c in coefs.items()), "pc": pcm}
            samples = [(w, A0, a) for w, a in samples]
            if pcm:
                # the print style of pc-relative values only shows at high addresses
                for addr in (A1, 0xFFFF800012345000, 0x8000000000000000, 0xFFFFFFFFFFFFF000):
                    for w in members[:6]:
                        t = self.O(w, addr)
                        if t is not None and self.shape(t) == sh:
                            samples.append((w, addr, tokenize(t[1])[1][j]))
            for st in STYLES:
                at["style"] = st
                if all(prefix + fmt_num(model_value(at, w, ad), st) == a for w, ad, a in samples):
                    break
            else:
                continue
            if len(dbits) <= 8:
                def check(w, t):
                    a = tokenize(t[1])[1][j]
                    return prefix + fmt_num(model_value(at, w, A0), at["style"]) == a
                exc = self._enum_exceptions(dbits, sh, members, lambda m0, x: str(x), check)
                if exc is None:
                    return None
                if exc:
                    at["exc"] = exc
            else:
                exc = {}
                n = len(dbits)
                for x in (0, (1 << n) - 1, 1 << (n - 1), 1):
                    kinds = []
                    for m0 in members[:2]:
                        w = self.dep(m0, dbits, x)
                        t = self.O(w)
                        kinds.append("I" if t is None else ("O" if self.shape(t) != sh else None))
                    if all(kk is not None for kk in kinds):
                        exc[str(x)] = "O" if "O" in kinds else "I"
                if exc:
                    at["exc"] = exc
            return at
        return None

    # ------------------------------------------------------------------ constraints
    def find_constraints(self, k, sh, members):
        """Pairs of 5-bit register fields that must differ."""
        # candidate register fields: full 5-bit register fields in the free bits
        free = ~k.mask & 0xFFFFFFFF
        fields = []
        for start in self.REG_FIELDS:
            if (free >> start) & self.ONES == self.ONES:
                fields.append(list(range(start, start + self.RW)))
        if len(fields) < 2:
            return
        for ia in range(len(fields)):
            for ib in range(ia + 1, len(fields)):
                fa, fb = fields[ia], fields[ib]
                res = {}
                for v in ((3, 17, 31) if self.RW == 5 else (3, 9, 15)):
                    r = []
                    for m0 in members[:3]:
                        w = self.tie(deposit(deposit(m0, fa, v), fb, v))
                        if (w & k.mask) != k.value:
                            continue
                        t = self.O(w)
                        r.append("I" if t is None else ("O" if self.shape(t) != sh else "V"))
                    res[v] = "I" if r and all(x == "I" for x in r) else ("V" if "V" in r else "O")
                vmid = 17 if self.RW == 5 else 9
                if res[3] == "I" and res[vmid] == "I":
                    # make sure unequal values are fine (otherwise it is not a pair constraint)
                    ok = 0
                    for m0 in members[:3]:
                        w = self.tie(deposit(deposit(m0, fa, 3), fb, vmid))
                        ok += self.same(w, sh)
                    if ok:
                        k.cons.append(["neq31" if res[self.ONES] == "V" else "neq", fa, fb])
