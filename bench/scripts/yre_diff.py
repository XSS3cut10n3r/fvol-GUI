#!/usr/bin/env python3
"""Differential test: fastvol's YARA hex / regex string engine vs yara-python 4.5.

Random YARA regexes and hex strings (incl. jumps, wildcards, alternations, chained
strings over 200-byte jumps) with random modifiers are matched against random buffers
and slices of the memory image; every match (offset, matched_length) of `$a` in
`rule r { strings: $a = ... condition: $a }` is compared.

usage: yre_diff.py [-n CASES] [--seed S] [--keep DIR]
"""
import argparse
import os
import random
import subprocess
import sys
import tempfile
import warnings

import yara

warnings.simplefilter("ignore")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
IMAGE = "/home/user/cbc2/task2/memory-dirty.raw"

RE_CHARS = "abcA0- "
HEX_BYTES = ["61", "62", "63", "41", "00", "0A", "20"]


class ReGen:
    def __init__(self, r, lazy):
        self.r = r
        self.lazy = lazy

    def atom(self, d):
        x = self.r.random()
        if d > 2 or x < 0.45:
            c = self.r.choice(RE_CHARS)
            if c in "-":
                return "\\-"
            return c
        if x < 0.52:
            return "."
        if x < 0.62:
            neg = "^" if self.r.random() < 0.3 else ""
            items = "".join(self.r.choice(["a", "b", "c", "A-C", "0-9", "\\w", "\\s", " ", "\\x00"]) for _ in range(self.r.randint(1, 3)))
            return "[" + neg + items + "]"
        if x < 0.70:
            return self.r.choice(["\\w", "\\W", "\\d", "\\D", "\\s", "\\S", "\\x61", "\\n"])
        if x < 0.88:
            return "(" + self.alt(d + 1) + ")"
        return self.r.choice(RE_CHARS.replace("-", ""))

    def quant(self):
        q = self.r.choice(["*", "+", "?", "{2}", "{1,3}", "{0,2}", "{2,}", "{,2}"])
        if self.lazy:
            q += "?"
        return q

    def piece(self, d):
        x = self.r.random()
        if x < 0.05:
            return self.r.choice(["\\b", "\\B"])
        if x < 0.07 and d == 0:
            return self.r.choice(["^", "$"])
        a = self.atom(d)
        if self.r.random() < 0.35:
            a += self.quant()
        return a

    def seq(self, d):
        return "".join(self.piece(d) for _ in range(self.r.randint(1, 4)))

    def alt(self, d):
        parts = [self.seq(d)]
        while self.r.random() < 0.25 and len(parts) < 3:
            parts.append(self.seq(d))
        s = "|".join(parts)
        if self.r.random() < 0.03:
            s += "|"
        return s


def gen_hex(r):
    def tok(d):
        x = r.random()
        if d < 2 and x < 0.12:
            n = r.randint(2, 3)
            alts = [" ".join(tok(d + 1) for _ in range(r.randint(1, 3))) for _ in range(n)]
            return "( " + " | ".join(alts) + " )"
        if x < 0.25:
            return "??"
        if x < 0.32:
            return r.choice(["6?", "?1", "4?", "?0"])
        if x < 0.36:
            return "~" + r.choice(HEX_BYTES)
        return r.choice(HEX_BYTES)

    items = [tok(0)]
    for _ in range(r.randint(0, 5)):
        if r.random() < 0.3:
            a = r.randint(0, 4)
            b = a + r.randint(0, 4)
            j = r.choice(["[%d]" % max(a, 1), "[%d-%d]" % (a, b), "[%d-%d]" % (a, b)])
            if r.random() < 0.15:
                j = r.choice(["[0-300]", "[201]", "[150-250]", "[3-]", "[-]"])
            items.append(j)
            while r.random() < 0.3:
                a = r.randint(0, 3)
                items.append("[%d-%d]" % (a, a + r.randint(0, 3)))
        items.append(tok(0))
    return "{ " + " ".join(items) + " }"


def gen_data(r, img):
    x = r.random()
    if x < 0.6:
        n = r.choice([10, 50, 200, 1000, 3000])
        alpha = b"abcA0- \n\x00"
        return bytes(r.choice(alpha) for _ in range(n))
    if img is not None and x < 0.9:
        size = os.path.getsize(IMAGE)
        off = r.randrange(0, size - 8192)
        img.seek(off)
        return img.read(r.choice([512, 2048, 4096]))
    return bytes(r.randrange(256) for _ in range(r.choice([100, 1000])))


def yara_matches(kind, src, mods, data):
    if kind == "hex":
        s = src
    else:
        flags = ("i" if "nocase" in mods else "") + ("s" if "dotall" in mods else "")
        s = "/" + src + "/" + flags
    extra = " ".join(m for m in mods if m in ("wide", "ascii", "fullword"))
    rule = "rule r { strings: $a = %s %s condition: $a }" % (s, extra)
    try:
        rules = yara.compile(source=rule)
    except Exception:
        return "ERR"
    try:
        ms = rules.match(data=data)
    except Exception:
        return "SCANERR"
    out = []
    for m in ms:
        for st in m.strings:
            for inst in st.instances:
                out.append("%d:%d" % (inst.offset, inst.matched_length))
    return ",".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--keep", default=None)
    ap.add_argument("--profile", default="fast")
    ap.add_argument("--show", type=int, default=20)
    ap.add_argument("--hex-only", action="store_true")
    ap.add_argument("--re-only", action="store_true")
    args = ap.parse_args()
    r = random.Random(args.seed)
    img = open(IMAGE, "rb") if os.path.exists(IMAGE) else None
    cases = []
    while len(cases) < args.n:
        kind = "hex" if (args.hex_only or (not args.re_only and r.random() < 0.45)) else "re"
        if kind == "hex":
            src = gen_hex(r)
            mods = []
        else:
            src = ReGen(r, r.random() < 0.2).alt(0)
            mods = [m for m in ("nocase", "dotall", "wide", "ascii", "fullword") if r.random() < 0.15]
        data = gen_data(r, img)
        cases.append((kind, src, mods, data))
    tmp = args.keep or tempfile.mkdtemp(prefix="yre_diff_")
    os.makedirs(tmp, exist_ok=True)
    cpath = os.path.join(tmp, "cases.tsv")
    opath = os.path.join(tmp, "out.tsv")
    expected = []
    with open(cpath, "w") as fh:
        for i, (kind, src, mods, data) in enumerate(cases):
            fh.write("%d\t%s\t%s\t%s\t%s\n" % (i, kind, src.encode().hex(), ",".join(mods), data.hex()))
            expected.append(yara_matches(kind, src, mods, data))
    env = dict(os.environ, FASTVOL_YRE_CASES=cpath, FASTVOL_YRE_OUT=opath)
    cmd = ["cargo", "test", "--profile", args.profile, "--bin", "fvol", "yara_yre_difftest_driver", "--", "--ignored", "--nocapture", "--test-threads=1"]
    res = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stdout[-3000:], res.stderr[-3000:])
        sys.exit(2)
    got = {}
    with open(opath) as fh:
        for line in fh:
            p = line.rstrip("\n").split("\t")
            got[int(p[0])] = p[1] if len(p) > 1 else ""
    bad = 0
    shown = 0
    scanerr = 0
    for i, (kind, src, mods, data) in enumerate(cases):
        if expected[i] == "SCANERR":
            scanerr += 1
            continue
        if got.get(i) != expected[i]:
            bad += 1
            if shown < args.show:
                shown += 1
                e = expected[i].split(",")
                g = (got.get(i) or "").split(",")
                print("MISMATCH #%d %s %r mods=%s len=%d\n   yara =%s\n   fastvol=%s" % (
                    i, kind, src, mods, len(data), ",".join(e[:12]), ",".join(g[:12])))
                se, sg = set(e), set(g)
                print("   only-yara=%s only-fastvol=%s" % (sorted(se - sg)[:8], sorted(sg - se)[:8]))
    print("cases=%d mismatches=%d (%.2f%%) yara-scan-errors-skipped=%d" % (len(cases), bad, 100.0 * bad / max(1, len(cases)), scanerr))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
