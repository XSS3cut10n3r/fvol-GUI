#!/usr/bin/env python3
"""Differential test: rsvol's regex engine vs python `re` (bytes patterns).

Generates random patterns over a small alphabet plus random haystacks, computes the
expected `finditer` spans (and group spans for a subset) with python `re`, runs the
Rust driver (an ignored cargo test) on the same cases and compares.

usage: regex_diff.py [-n CASES] [--seed S] [--keep DIR] [--profile fast]
"""
import argparse
import os
import random
import re
import subprocess
import sys
import tempfile
import signal
import warnings

warnings.simplefilter("ignore")


class Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise Timeout()


signal.signal(signal.SIGALRM, _alarm)


def guarded(fn, *a):
    """Run a python-re oracle call with a 0.25 s budget (python itself backtracks
    exponentially on some random patterns); returns None on timeout."""
    signal.setitimer(signal.ITIMER_REAL, 0.25)
    try:
        return fn(*a)
    except Timeout:
        return None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

ALPHA = b"abcAB\n _1-"


class Gen:
    REGULAR = False

    def __init__(self, rng):
        self.r = rng
        self.groups = 0
        self.names = []

    def lit(self):
        c = self.r.choice(b"abcaab")
        return bytes([c])

    def atom(self, depth):
        r = self.r.random()
        if depth > 3 or r < 0.30:
            return self.lit()
        if r < 0.36:
            return b"."
        if r < 0.46:
            return self.cls()
        if r < 0.52:
            return self.r.choice([b"\\d", b"\\w", b"\\s", b"\\W", b"\\D", b"\\S"])
        if r < 0.58:
            return self.r.choice([b"^", b"$", b"\\b", b"\\B", b"\\A", b"\\Z", b"\\z"])
        if r < 0.72:
            self.groups += 1
            inner = self.alt(depth + 1)
            if self.r.random() < 0.15:
                name = b"g%d" % self.groups
                self.names.append(name)
                return b"(?P<" + name + b">" + inner + b")"
            return b"(" + inner + b")"
        if r < 0.80:
            return b"(?:" + self.alt(depth + 1) + b")"
        if self.REGULAR and 0.80 <= r < 0.92:
            return b"(?:" + self.alt(depth + 1) + b")"
        if r < 0.84:
            kind = self.r.choice([b"?=", b"?!", b"?<=", b"?<!"])
            if kind in (b"?<=", b"?<!"):
                # fixed width lookbehind
                inner = b"".join(self.lit() for _ in range(self.r.randint(0, 2)))
                if self.r.random() < 0.3:
                    inner = inner + b"|" + b"".join(self.lit() for _ in range(len(inner)))
                return b"(" + kind + inner + b")"
            return b"(" + kind + self.alt(depth + 1) + b")"
        if r < 0.87:
            return b"(?>" + self.alt(depth + 1) + b")"
        if r < 0.90 and self.groups > 0:
            return b"\\%d" % self.r.randint(1, self.groups)
        if r < 0.92 and self.groups > 0:
            g = self.r.randint(1, self.groups)
            return b"(?(%d)" % g + self.seq(depth + 1) + (b"|" + self.seq(depth + 1) if self.r.random() < 0.5 else b"") + b")"
        if r < 0.95:
            fl = self.r.choice([b"i", b"s", b"m", b"-i", b"i-s", b"x"])
            return b"(?" + fl + b":" + self.alt(depth + 1) + b")"
        return self.lit()

    def cls(self):
        neg = b"^" if self.r.random() < 0.3 else b""
        items = []
        for _ in range(self.r.randint(1, 3)):
            x = self.r.random()
            if x < 0.5:
                items.append(bytes([self.r.choice(b"abcAB_ -")]))
            elif x < 0.75:
                items.append(self.r.choice([b"a-c", b"A-Z", b"0-9", b"a-b"]))
            else:
                items.append(self.r.choice([b"\\d", b"\\w", b"\\s", b"\\n"]))
        return b"[" + neg + b"".join(items) + b"]"

    def quant(self):
        q = self.r.choice([b"*", b"+", b"?", b"{2}", b"{1,3}", b"{0,2}", b"{2,}", b"{,2}", b"{0}", b"{1}"])
        x = self.r.random()
        if x < 0.25:
            q += b"?"
        elif x < 0.32 and not self.REGULAR:
            q += b"+"
        return q

    def piece(self, depth):
        a = self.atom(depth)
        if a in (b"^", b"$", b"\\b", b"\\B", b"\\A", b"\\Z", b"\\z"):
            return a
        if self.r.random() < 0.35:
            a += self.quant()
        return a

    def seq(self, depth):
        return b"".join(self.piece(depth) for _ in range(self.r.randint(0 if depth else 1, 4)))

    def alt(self, depth):
        parts = [self.seq(depth)]
        while self.r.random() < 0.25 and len(parts) < 4:
            parts.append(self.seq(depth))
        return b"|".join(parts)


def gen_pattern(rng):
    g = Gen(rng)
    p = g.alt(0)
    if rng.random() < 0.08:
        p = rng.choice([b"(?i)", b"(?s)", b"(?m)", b"(?x)", b"(?ims)"]) + p
    return p


HAY_LENS = [0, 1, 2, 3, 5, 8, 13, 20, 40]


def gen_hay(rng):
    n = rng.choice(HAY_LENS)
    return bytes(rng.choice(ALPHA) for _ in range(n))


def py_iter(p, flags, hay):
    try:
        rx = re.compile(p, flags)
    except Exception:
        return "ERR"
    return ",".join("%d-%d" % m.span() for m in rx.finditer(hay))


UNI = ["é", "É", "ß", "ſ", "\u212a", "σ", "ς", "Σ", "\u0663", "\u2003", "İ", "ı", "ǅ", "\U0001d400", "ﬀ"]


def gen_str_case(rng):
    """(pattern str, flags, haystack str) for python str-pattern tests."""
    p = gen_pattern(rng).decode("ascii")
    p = "".join(rng.choice(UNI) if ch == "c" and rng.random() < 0.6 else ch for ch in p)
    alpha = "abcAB\n _1-sSkKiI" + "".join(UNI)
    n = rng.choice([0, 1, 3, 8, 20, 40])
    h = "".join(rng.choice(alpha) for _ in range(n))
    f = rng.choice([0, 0, re.I, re.I, re.S, re.M, re.A, re.A | re.I])
    return p, f, h


def py_str_iter(p, flags, hay):
    try:
        rx = re.compile(p, flags)
    except Exception:
        return "ERR"
    out = []
    for m in rx.finditer(hay):
        s, e = m.span()
        bs = len(hay[:s].encode())
        be = len(hay[:e].encode())
        out.append("%d-%d" % (bs, be))
    return ",".join(out)


def py_groups(p, flags, hay):
    try:
        rx = re.compile(p, flags)
    except Exception:
        return "ERR"
    m = rx.search(hay)
    if not m:
        return "NONE"
    out = []
    for g in range(rx.groups + 1):
        s = m.span(g)
        out.append("-" if s == (-1, -1) else "%d-%d" % s)
    return ";".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--keep", default=None)
    ap.add_argument("--profile", default="fast")
    ap.add_argument("--show", type=int, default=25)
    ap.add_argument("--regular", action="store_true", help="only DFA-eligible constructs")
    ap.add_argument("--long", action="store_true", help="add long haystacks (up to 3000 bytes)")
    ap.add_argument("--str", action="store_true", help="python str patterns (Unicode semantics)")
    args = ap.parse_args()
    rng = random.Random(args.seed)
    Gen.REGULAR = args.regular
    if args.long:
        HAY_LENS.extend([200, 1000, 3000])
    flag_choices = [0, 0, 0, 0, re.I, re.S, re.M, re.I | re.S, re.X, re.DOTALL | re.M]
    cases = []
    # a few fixed interesting cases first
    fixed = [
        (b"a*?", 0, b"aa"), (b"(?:|a)*", 0, b"aab"), (b"x*", 0, b"axb"), (b"", 0, b"ab"),
        (b"\\B", 0, b""), (b"\\b", 0, b""), (b"$", 0, b"a\n"), (b"a$", re.M, b"a\na\n"),
        (b"(a?)*b", 0, b"aab"), (b"(?:a|)*", 0, b"aa"), (b"(?:a|b)*?c", 0, b"ababc"),
    ]
    for p, f, h in fixed:
        cases.append((p, f, h, "iter"))
    while args.str and len(cases) < args.n:
        p, f, h = gen_str_case(rng)
        cases.append((p.encode(), f, h.encode(), "str"))
    while len(cases) < args.n:
        p = gen_pattern(rng)
        f = rng.choice(flag_choices)
        for _ in range(3):
            cases.append((p, f, gen_hay(rng), "groups" if rng.random() < 0.2 else "iter"))
    tmp = args.keep or tempfile.mkdtemp(prefix="regex_diff_")
    os.makedirs(tmp, exist_ok=True)
    cpath = os.path.join(tmp, "cases.tsv")
    opath = os.path.join(tmp, "out.tsv")
    expected = []
    kept = []
    timeouts = 0
    for (p, f, h, mode) in cases:
        if mode == "str":
            e = guarded(py_str_iter, p.decode(), f, h.decode())
        else:
            e = guarded(py_iter, p, f, h) if mode == "iter" else guarded(py_groups, p, f, h)
        if e is None:
            timeouts += 1
            continue
        kept.append((p, f, h, mode))
        expected.append(e)
    cases = kept
    with open(cpath, "w") as fh:
        for i, (p, f, h, mode) in enumerate(cases):
            fh.write("%d\t%s\t%d\t%s\t%s\n" % (i, p.hex(), f, h.hex(), mode))
    env = dict(os.environ, RSVOL_REGEX_CASES=cpath, RSVOL_REGEX_OUT=opath)
    cmd = ["cargo", "test", "--profile", args.profile, "--bin", "vol", "yara_regex_difftest_driver", "--", "--ignored", "--nocapture", "--test-threads=1"]
    r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-4000:], r.stderr[-4000:])
        sys.exit(2)
    got = {}
    btdiff = {}
    with open(opath) as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            got[int(parts[0])] = parts[1] if len(parts) > 1 else ""
            if len(parts) > 2:
                btdiff[int(parts[0])] = parts[2]
    bad = 0
    shown = 0
    for i, (p, f, h, mode) in enumerate(cases):
        g = got.get(i)
        if g != expected[i] or i in btdiff:
            bad += 1
            if shown < args.show:
                shown += 1
                print("MISMATCH #%d mode=%s flags=%d pattern=%r hay=%r\n   python=%s\n   rsvol =%s %s" % (
                    i, mode, f, p, h, expected[i], g, btdiff.get(i, "")))
    print("cases=%d mismatches=%d (%.3f%%) python-timeouts-skipped=%d" % (len(cases), bad, 100.0 * bad / max(1, len(cases)), timeouts))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
