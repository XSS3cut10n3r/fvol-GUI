#!/usr/bin/env python3
"""Differential test of the fastvol YARA rule front-end against yara-python.

Generates random rule sets (random conditions over plain text strings, loops,
of-expressions, rule references, arithmetic edge cases ...) and random data,
runs yara-python (the oracle) and the Rust driver
(`yara_rules_difftest_driver`, a naive reference string matcher + our
evaluator) and compares the serialized results (matching rules, namespace,
tags, meta, strings / instances) and compile errors.

usage: rules_diff.py [N] [SEED]
  env PYTHON-side: needs yara-python (use bench/venv/bin/python)
"""
import os
import random
import subprocess
import sys

import yara

HERE = os.path.dirname(os.path.abspath(__file__))
CRATE = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA = os.environ.get("FASTVOL_DATA") or os.path.dirname(subprocess.run(
    ["git", "-C", CRATE, "rev-parse", "--path-format=absolute", "--git-common-dir"],
    capture_output=True, text=True).stdout.strip() or os.path.join(CRATE, ".git"))
WORK = os.environ.get("FASTVOL_YARA_RULES_WORK", os.path.join(DATA, "testdata/scratch/yara"))

ALPH = b"abAB x\x00"
TEXTS = ["a", "b", "ab", "ba", "A", "aa", "x", "bA", "a b"]


def ser(matches):
    parts = []
    for m in matches:
        meta = []
        for k, v in m.meta.items():
            if isinstance(v, bool):
                v = "T" if v else "F"
            elif isinstance(v, int):
                v = str(v)
            else:
                v = "s" + v.encode("utf-8").hex()
            meta.append("%s=%s" % (k, v))
        strs = []
        for s in m.strings:
            inst = ["%d:%d:%s:%d" % (i.offset, i.matched_length, i.matched_data.hex(), i.xor_key) for i in s.instances]
            strs.append("%s[%s]" % (s.identifier, ",".join(inst)))
        parts.append("%s|%s|%s|%s|%s" % (m.rule, m.namespace, ",".join(m.tags), ";".join(meta), ";".join(strs)))
    return "OK:" + " || ".join(parts)


def oracle(src, data):
    try:
        r = yara.compile(source=src)
    except yara.SyntaxError as e:
        return "ERR:%s" % e
    except Exception as e:  # noqa
        return "EXC:%s" % e
    try:
        return ser(r.match(data=data, timeout=10))
    except Exception as e:  # noqa
        return "SCANERR:%s" % e


class Gen:
    def __init__(self, rng):
        self.r = rng

    def pick(self, xs):
        return self.r.choice(xs)

    # ---------------------------------------------------------------- values
    def int_lit(self):
        c = self.r.random()
        if c < 0.1:
            return self.pick(["0x10", "0xFF", "0x7fffffffffffffff", "0o17", "0o777", "1KB", "2MB", "0KB",
                              "8589934591KB", "0x5452505452501", "9223372036854775807"])
        return str(self.pick([0, 1, 2, 3, 4, 5, 7, 10, 16, 31, 63, 64, 65, 100, 255, 256, 65535,
                              0x7FFFFFFFFFFFFFFF, 9223372036854775806, 4294967295, 12345678901]))

    def int_expr(self, d, ctx):
        r = self.r.random()
        named = [s for s in ctx["strings"] if s != "$"]
        if d <= 0 or r < 0.25:
            c = self.r.random()
            if c < 0.6:
                return self.int_lit()
            if c < 0.75 and ctx["ivars"]:
                return self.pick(ctx["ivars"])
            if c < 0.85:
                return "filesize"
            if named:
                s = self.pick(named)
                ctx["ref"].add(s)
                return self.pick(["#", "@", "!"]) + s[1:]
            return self.int_lit()
        if r < 0.35 and named:
            s = self.pick(named)
            ctx["ref"].add(s)
            k = self.r.random()
            if k < 0.3:
                return "#%s in (%s..%s)" % (s[1:], self.int_expr(d - 1, ctx), self.int_expr(d - 1, ctx))
            return "%s%s[%s]" % (self.pick(["@", "!"]), s[1:], self.int_expr(d - 1, ctx))
        if r < 0.45:
            f = self.pick(["uint8", "uint16", "uint32", "int8", "int16", "int32", "uint16be", "uint32be", "int32be"])
            return "%s(%s)" % (f, self.int_expr(d - 1, ctx))
        if r < 0.55:
            return "%s%s" % (self.pick(["-", "~"]), self.int_atom(d - 1, ctx))
        if r < 0.6 and ctx["for_of"]:
            return self.pick(["#", "@", "!"])
        if r < 0.63:
            return "entrypoint"
        op = self.pick(["+", "-", "*", "\\", "%", "&", "|", "^", "<<", ">>"])
        a, b = self.int_expr(d - 1, ctx), self.int_expr(d - 1, ctx)
        if self.r.random() < 0.7:
            return "(%s %s %s)" % (a, op, b)
        return "%s %s %s" % (a, op, b)

    def small_int(self, ctx):
        named = [s for s in ctx["strings"] if s != "$"]
        c = self.r.random()
        if c < 0.5:
            return str(self.r.randint(0, 5))
        if c < 0.6:
            return "-1"
        if c < 0.75:
            return "filesize" if ctx["depth_loops"] <= 1 else "3"
        if c < 0.85 and ctx["ivars"] and ctx["depth_loops"] <= 1:
            return "(%s + 1)" % self.pick(ctx["ivars"])
        if named:
            s = self.pick(named)
            ctx["ref"].add(s)
            return "#" + s[1:]
        return "2"

    def int_atom(self, d, ctx):
        e = self.int_expr(d, ctx)
        return e if e.startswith("(") or e.isdigit() else "(%s)" % e

    def flt_expr(self, d, ctx):
        r = self.r.random()
        if d <= 0 or r < 0.4:
            return self.pick(["1.5", "0.0", "2.25", "1.0", "3.5", "0.1"])
        if r < 0.6:
            return self.int_expr(d - 1, ctx)
        if r < 0.7:
            return "-" + self.pick(["1.5", "(2.5)"])
        return "(%s %s %s)" % (self.flt_expr(d - 1, ctx), self.pick(["+", "-", "*", "\\"]), self.flt_expr(d - 1, ctx))

    def str_expr(self, d, ctx):
        if ctx["svars"] and self.r.random() < 0.4:
            return self.pick(ctx["svars"])
        return '"%s"' % self.pick(["abc", "ab", "", "ABC", "b", "xyz", "aBc", "\\x80", "\\x00a"])

    def str_set(self, ctx):
        strings = ctx["strings"]
        if not strings or self.r.random() < 0.3:
            for s in strings:
                ctx["ref"].add(s)
            return "them"
        items = []
        for _ in range(self.r.randint(1, 3)):
            if self.r.random() < 0.3:
                pre = self.pick(["$*", "$c*", "$a*", "$"])
                items.append(pre)
                if pre == "$":
                    for s in strings:
                        if s == "$":
                            ctx["ref"].add(s)
                else:
                    for s in strings:
                        if s.startswith(pre[:-1]):
                            ctx["ref"].add(s)
            else:
                s = self.pick(strings)
                ctx["ref"].add(s)
                items.append(s)
        return "(%s)" % ", ".join(items)

    def quant(self, d, ctx):
        r = self.r.random()
        if r < 0.5:
            return self.pick(["all", "any", "none"])
        if r < 0.8:
            return str(self.pick([0, 1, 2, 3]))
        return self.int_atom(d - 1, ctx)

    # ---------------------------------------------------------------- booleans
    def bool_expr(self, d, ctx):
        r = self.r.random()
        named = [s for s in ctx["strings"] if s != "$"]
        if d <= 0 or r < 0.12:
            c = self.r.random()
            if c < 0.4 and named:
                s = self.pick(named)
                ctx["ref"].add(s)
                return s
            if c < 0.55 and ctx["for_of"]:
                return "$"
            if c < 0.7 and ctx["rules"]:
                return self.pick(ctx["rules"])
            return self.pick(["true", "false"])
        if r < 0.2 and named:
            s = self.pick(named)
            ctx["ref"].add(s)
            if self.r.random() < 0.5:
                return "%s at %s" % (s, self.int_expr(d - 1, ctx))
            return "%s in (%s..%s)" % (s, self.int_expr(d - 1, ctx), self.int_expr(d - 1, ctx))
        if r < 0.23 and ctx["for_of"]:
            return self.pick(["$ at %s" % self.int_expr(d - 1, ctx), "$ in (0..%s)" % self.int_expr(d - 1, ctx)])
        if r < 0.33:
            return "%s %s %s" % (self.int_expr(d - 1, ctx), self.pick(["==", "!=", "<", ">", "<=", ">="]),
                                 self.int_expr(d - 1, ctx))
        if r < 0.37:
            return "%s %s %s" % (self.flt_expr(d - 1, ctx), self.pick(["==", "!=", "<", ">", "<=", ">="]),
                                 self.flt_expr(d - 1, ctx))
        if r < 0.42:
            op = self.pick(["==", "!=", "<", ">", "<=", ">=", "contains", "icontains", "startswith",
                            "istartswith", "endswith", "iendswith", "iequals"])
            return "%s %s %s" % (self.str_expr(d - 1, ctx), op, self.str_expr(d - 1, ctx))
        if r < 0.44:
            return "%s matches /%s/%s" % (self.str_expr(d - 1, ctx), self.pick(["a", "b+", "^a", "c$", "[a-b]{2}", "a|B", "\\x00"]),
                                         self.pick(["", "i", "s"]))
        if r < 0.5:
            return "%s %s" % (self.pick(["not", "defined"]), self.bool_atom(d - 1, ctx))
        if r < 0.62:
            return "%s %s %s" % (self.bool_expr(d - 1, ctx), self.pick(["and", "or"]), self.bool_expr(d - 1, ctx))
        if r < 0.66:
            return "(%s)" % self.bool_expr(d - 1, ctx)
        if r < 0.74 and ctx["strings"]:
            q = self.quant(d, ctx)
            s = self.str_set(ctx)
            k = self.r.random()
            if k < 0.2:
                return "%s of %s in (%s..%s)" % (q, s, self.int_expr(d - 1, ctx), self.int_expr(d - 1, ctx))
            if k < 0.35:
                return "%s of %s at %s" % (q, s, self.int_expr(d - 1, ctx))
            return "%s of %s" % (q, s)
        if r < 0.77 and ctx["strings"]:
            return "%s%% of %s" % (self.pick(["1", "50", "34", "100", "66", "(filesize)"]), self.str_set(ctx))
        if r < 0.8 and ctx["rules"]:
            items = [self.pick(ctx["rules"]) for _ in range(self.r.randint(1, 2))]
            if self.r.random() < 0.3:
                items.append(self.pick(ctx["rules"])[:1] + "*")
            q = self.quant(d, ctx)
            if self.r.random() < 0.2:
                return "%s%% of (%s)" % (self.pick(["50", "100", "1"]), ", ".join(items))
            return "%s of (%s)" % (q, ", ".join(items))
        if r < 0.9 and ctx["depth_loops"] < 3:
            return self.for_loop(d, ctx)
        if r < 0.95:
            return self.int_expr(d - 1, ctx)
        return self.str_expr(d - 1, ctx)

    def bool_atom(self, d, ctx):
        e = self.bool_expr(d, ctx)
        return "(%s)" % e

    def for_loop(self, d, ctx):
        q = self.quant(d, ctx)
        ctx["depth_loops"] += 1
        try:
            k = self.r.random()
            if k < 0.3 and ctx["strings"] and not ctx["for_of"]:
                s = self.str_set(ctx)
                ctx["for_of"] = True
                body = self.bool_expr(d - 1, ctx)
                ctx["for_of"] = False
                return "for %s of %s : (%s)" % (q, s, body)
            v = "v%d" % ctx["depth_loops"]
            if k < 0.6:
                # Small bounds only: yara iterates huge ranges for real.
                it = "(%s..%s)" % (self.small_int(ctx), self.small_int(ctx))
                typ = "ivars"
            elif k < 0.8:
                it = "(%s)" % ", ".join(self.int_expr(d - 1, ctx) for _ in range(self.r.randint(1, 3)))
                typ = "ivars"
            else:
                it = "(%s)" % ", ".join(self.str_expr(0, dict(ctx, svars=[])) for _ in range(self.r.randint(1, 3)))
                typ = "svars"
            ctx[typ] = ctx[typ] + [v]
            body = self.bool_expr(d - 1, ctx)
            ctx[typ] = ctx[typ][:-1]
            return "for %s %s in %s : (%s)" % (q, v, it, body)
        finally:
            ctx["depth_loops"] -= 1

    # ---------------------------------------------------------------- rules
    def rule(self, idx, prev_rules):
        name = "r%d" % idx if self.r.random() < 0.8 else "q%d" % idx
        mods = []
        if self.r.random() < 0.1:
            mods.append("private")
        if self.r.random() < 0.05:
            mods.append("global")
        tags = ""
        if self.r.random() < 0.3:
            tags = " : " + " ".join(sorted(set(self.pick(["t1", "t2", "t3"]) for _ in range(2))))
        meta = ""
        if self.r.random() < 0.3:
            items = []
            for _ in range(self.r.randint(1, 3)):
                v = self.pick(['"hello"', "5", "-3", "true", "false", "4294967296", '"\\xc3\\xa9x"', '"a\\x00b"'])
                items.append("%s = %s" % (self.pick(["m1", "m2", "author"]), v))
            meta = "meta: " + " ".join(items) + " "
        strings = []
        decls = []
        ids = ["$a", "$b", "$c1", "$c2", "$", "$_d"]
        for _ in range(self.r.randint(0, 4)):
            sid = self.pick(ids)
            if sid in strings and sid != "$":
                continue
            m = []
            rr = self.r.random()
            if rr < 0.15:
                m.append("nocase")
            elif rr < 0.25:
                m.append("wide")
            if self.r.random() < 0.15:
                m.append("private")
            strings.append(sid)
            decls.append('%s = "%s" %s' % (sid, self.pick(TEXTS), " ".join(m)))
        ctx = {"strings": strings, "ref": set(), "ivars": [], "svars": [], "for_of": False, "rules": prev_rules,
               "depth_loops": 0}
        cond = self.bool_expr(self.r.randint(1, 4), ctx)
        extra = [s for s in strings if s not in ctx["ref"] and not s.startswith("$_")]
        if extra:
            if "$" in extra:
                cond = "(%s) or (any of ($*) and false)" % cond
            for s in extra:
                if s != "$":
                    cond = "(%s) or (%s and false)" % (cond, s)
        sdecl = ("strings: " + " ".join(decls) + " ") if decls else ""
        src = "%s rule %s%s { %s%scondition: %s }" % (" ".join(mods), name, tags, meta, sdecl, cond)
        return name, src

    def source(self):
        rules = []
        names = []
        for i in range(self.r.randint(1, 4)):
            name, src = self.rule(i, names)
            rules.append(src)
            names.append(name)
        return "\n".join(rules)

    def data(self):
        n = self.r.randint(0, 80)
        d = bytes(self.r.choice(ALPH) for _ in range(n))
        c = self.r.random()
        if c < 0.03:
            d = b"MZ" + d
        elif c < 0.08:
            d = self.pe() + d
        elif c < 0.1:
            d = self.elf() + d
        return d

    def pe(self):
        d = bytearray(0x200)
        d[0:2] = b"MZ"
        d[0x3C:0x40] = (0x40).to_bytes(4, "little")
        d[0x40:0x44] = b"PE\0\0"
        d[0x44:0x46] = self.pick([0x14C, 0x8664, 0x1C0]).to_bytes(2, "little")
        nsec = self.r.randint(0, 3)
        d[0x46:0x48] = nsec.to_bytes(2, "little")
        d[0x54:0x56] = (224).to_bytes(2, "little")
        d[0x40 + 40:0x40 + 44] = self.r.choice([0x1000, 0x1010, 0x2345, 0x80]).to_bytes(4, "little")
        for i in range(nsec):
            s = 0x40 + 24 + 224 + i * 40
            d[s + 12:s + 16] = (0x1000 * (i + 1)).to_bytes(4, "little")
            d[s + 20:s + 24] = (0x200 * (i + 1)).to_bytes(4, "little")
        return bytes(d)

    def elf(self):
        d = bytearray(64)
        d[0:4] = b"\x7fELF"
        d[4] = self.pick([1, 2, 3])
        d[16] = self.pick([2, 3])
        d[24] = 0x40
        return bytes(d)

    def mutate(self, src):
        """Random token-level damage to exercise syntax errors and recovery."""
        toks = src.split(" ")
        for _ in range(self.r.randint(1, 3)):
            if not toks:
                break
            i = self.r.randrange(len(toks))
            c = self.r.random()
            if c < 0.4:
                del toks[i]
            elif c < 0.7:
                toks.insert(i, self.pick(["(", ")", "{", "}", "and", "rule", "==", "of", ",", "..", ":", "x",
                                          "$a", "1", "not", "\"s\"", "for", "any", "them", "@", "#", "*"]))
            else:
                toks[i] = self.pick(["(", ")", "}", "or", "rule", "<", "at", "in", "1.5", "$"])
        return " ".join(toks)


def main():
    os.makedirs(WORK, exist_ok=True)
    cases_path = os.path.join(WORK, "rules_cases.tsv")
    out_path = os.path.join(WORK, "rules_out.tsv")
    cases = []
    if len(sys.argv) > 2 and sys.argv[1] == "--cases":
        # Hand-written cases: a python literal list of source strings or
        # (source, data) tuples.
        for c in eval(open(sys.argv[2]).read()):  # trusted local test file
            cases.append(c if isinstance(c, tuple) else (c, b"hello"))
    else:
        n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
        seed = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        rng = random.Random(seed)
        g = Gen(rng)
        for i in range(n):
            src = g.source()
            if rng.random() < 0.15:
                src = g.mutate(src)
            cases.append((src, g.data()))
    n = len(cases)
    with open(cases_path, "w") as f:
        for i, (src, data) in enumerate(cases):
            f.write("%d\t%s\t%s\n" % (i, src.encode().hex(), data.hex()))
    expected = [oracle(src, data) for src, data in cases]
    env = dict(os.environ, FASTVOL_YARA_RULES_CASES=cases_path, FASTVOL_YARA_RULES_OUT=out_path)
    subprocess.run(["cargo", "test", "--profile", "fast", "yara_rules_difftest_driver", "--", "--ignored", "--quiet"],
                   cwd=CRATE, env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    got = {}
    with open(out_path) as f:
        for line in f:
            k, _, v = line.rstrip("\n").partition("\t")
            got[int(k)] = v
    bad = 0
    errs = 0
    for i, (src, data) in enumerate(cases):
        e = expected[i]
        if e.startswith("ERR"):
            errs += 1
        gv = got.get(i)
        same = gv == e
        if not same and e.startswith("ERR:") and gv is not None and gv.startswith("ERR:"):
            # Syntax error texts depend on bison's LALR tables ("expecting ...").
            if "syntax error" in e and "syntax error" in gv:
                same = e.split(", expecting")[0] == gv.split(", expecting")[0]
            # libyara prints an uninitialized union member for floats here.
            if 'invalid value in condition: "' in e and 'p' in e.split('"')[-2]:
                same = gv.startswith(e.split('"')[0])
        if not same:
            bad += 1
            if bad <= 15:
                print("MISMATCH %d\n  src : %s\n  data: %r\n  want: %s\n  got : %s" % (i, src, data, e, gv))
    print("cases=%d compile_errors=%d mismatches=%d" % (n, errs, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
