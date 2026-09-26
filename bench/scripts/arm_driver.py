"""Architecture-independent driver for the probe-driven ARM / AArch64 spec learner (see
arm_learn.py): learn from random / listed words, explore class neighbourhoods, check against the
oracle, emit the Rust text spec.  Per-architecture configuration lives in gen_arm64_spec.py /
gen_arm32_spec.py.

commands (all take SPEC.json first):
  learn   SPEC.json [--rand N] [--words FILE] [--seed S]
  explore SPEC.json [--rounds R]
  check   SPEC.json [--rand N]
  emit    SPEC.json OUT.rs [--verify N]
  stats   SPEC.json
  explain SPEC.json HEXWORD...
"""
import os
import random
import sys
import time
from collections import Counter

import arm_learn
from arm_learn import (HANDLERS, Klass, Learner, Oracle, Spec, oracle_text, popcount)


class ArchConfig:
    name = "arm64"
    handler_classes = []          # (name, mask, value)
    reg_fields = (0, 5, 10, 16)
    rw = 5
    imm_fields = ((10, 12), (10, 6), (16, 6), (5, 16), (12, 4), (10, 3), (22, 2))
    rust_header = ""
    spec_records = []             # extra text-spec records emitted first (e.g. "F\tcond")
    fold_cond = False

    def handled(self, w):
        return any((w & m) == v for _, m, v in self.handler_classes)


def make_learner(cfg, O, seed):
    L = Learner(O, cfg.name, random.Random(seed), log=lambda *a: print(*a, file=sys.stderr))
    L.REG_FIELDS = cfg.reg_fields
    L.RW = cfg.rw
    L.ONES = (1 << cfg.rw) - 1
    return L


def install_handlers(cfg, spec):
    have = {k.handler for k in spec.classes if k.handler}
    for name, mask, value in cfg.handler_classes:
        if name in have:
            continue
        k = Klass()
        k.mask, k.value, k.handler, k.mnem, k.prio = mask, value, name, "<" + name + ">", 1000
        spec.add(k)


def load_or_new(cfg, path):
    arm_learn.CUR_ARCH[0] = cfg.name
    spec = Spec.load(path) if os.path.exists(path) else Spec(cfg.name)
    install_handlers(cfg, spec)
    return spec


def mismatch(spec, O, w):
    exp = oracle_text(O(w))
    got, ci = spec.render(w)
    return exp, got, ci


def add_class(spec, k, keys, stats):
    key = (k.mask, k.value, k.mnem, k.seps, k.handler)
    if key in keys:
        stats["reprio"] += 1
        return keys[key]
    spec.add(k)
    keys[key] = k
    stats["new"] += 1
    return k


def ensure_wins(spec, k, w, exp):
    for _ in range(8):
        got, ci2 = spec.render(w)
        if got == exp or ci2 is None:
            return
        c = spec.classes[ci2]
        if c is k:
            return
        spec.set_prio(k, popcount(c.mask) + c.prio - popcount(k.mask) + 1)


def learn_word(cfg, spec, L, O, w, keys, stats, depth=0):
    exp, got, ci = mismatch(spec, O, w)
    if exp == got:
        return False
    if cfg.handled(w):
        stats["handler_bug"] += 1
        if stats["handler_bug"] < 20:
            L.log("  handler mismatch %08x exp %r got %r" % (w, exp, got))
        return False
    c = w >> 28
    if cfg.fold_cond and c < 14 and depth == 0:
        w2 = (w & 0x0FFFFFFF) | 0xE0000000
        exp2 = oracle_text(O(w2))
        got2, _ = spec.render(w2)
        if exp2 is not None and exp2 != got2:
            learn_word(cfg, spec, L, O, w2, keys, stats, 1)
            exp, got, ci = mismatch(spec, O, w)
            if exp == got:
                return True
        if exp is None:
            # the AL twin is valid but this conditional form is not: invalid class for the
            # twin's region with this condition, if it holds over that region
            _, ci2 = spec.render_direct(w2)
            if ci2 is not None:
                k2 = spec.classes[ci2]
                mask = k2.mask | 0xF0000000
                value = (k2.value & 0x0FFFFFFF) | (c << 28)
                ok = True
                for _ in range(12):
                    t = (value | (L.rnd.getrandbits(32) & ~mask)) & 0xFFFFFFFF
                    if spec.render_direct((t & 0x0FFFFFFF) | 0xE0000000)[0] is None:
                        continue
                    if O(t) is not None:
                        ok = False
                        break
                if ok:
                    k = Klass()
                    k.mask, k.value, k.handler, k.mnem, k.seed = mask, value, "invalid", "<invalid>", w
                    k = add_class(spec, k, keys, stats)
                    ensure_wins(spec, k, w, None)
                    return True
            stats["false_valid"] += 1
            return False
    if exp is None:
        if learn_invalid(cfg, spec, L, O, w, ci, keys, stats):
            return True
        stats["false_valid"] += 1
        stats.setdefault("fv_classes", Counter())[ci] += 1
        return False
    k = L.learn(w)
    if k is None:
        stats["learn_fail"] += 1
        return False
    if k.render(w) != exp:
        stats["bad_model"] += 1
        L.log("  bad model for", hex(w), exp, "->", k.render(w))
        return False
    k = add_class(spec, k, keys, stats)
    ensure_wins(spec, k, w, exp)
    return True


def learn_invalid(cfg, spec, L, O, w, ci, keys, stats):
    """The spec renders w but capstone rejects it: learn the region around w that the same
    class claims and capstone rejects (bits whose single flip keeps both), verify it on random
    members, and add an 'invalid' class for it with a priority above the claiming class."""
    if ci is None:
        return False
    k0 = spec.classes[ci]
    free = 0
    for i in range(32):
        w2 = w ^ (1 << i)
        if O(w2) is None and spec.render(w2)[1] == ci:
            free |= 1 << i
    mask = ~free & 0xFFFFFFFF
    value = w & mask
    for _ in range(24):
        t = (value | (L.rnd.getrandbits(32) & free)) & 0xFFFFFFFF
        if O(t) is not None:
            # region too wide: fall back to the single word
            mask, value = 0xFFFFFFFF, w
            break
    k = Klass()
    k.mask, k.value, k.handler, k.mnem, k.seed = mask, value, "invalid", "<invalid>", w
    k = add_class(spec, k, keys, stats)
    stats["invalid_cls"] += 1
    ensure_wins(spec, k, w, None)
    return spec.render(w)[0] is None


def fmt_stats(stats):
    return dict((k, v) for k, v in stats.items() if k != "fv_classes")


def cmd_learn(cfg, args):
    path = args[0]
    n = 0
    words = []
    seed = 1
    i = 1
    while i < len(args):
        if args[i] == "--rand":
            n = int(args[i + 1]); i += 1
        elif args[i] == "--words":
            with open(args[i + 1]) as f:
                words += [int(x.split()[0], 16) for x in f if x.strip()]
            i += 1
        elif args[i] == "--seed":
            seed = int(args[i + 1]); i += 1
        i += 1
    spec = load_or_new(cfg, path)
    O = Oracle(cfg.name)
    rnd = random.Random(seed)
    L = make_learner(cfg, O, seed + 1)
    keys = {(k.mask, k.value, k.mnem, k.seps, k.handler): k for k in spec.classes}
    stats = Counter()
    t0 = time.time()
    todo = words + [rnd.getrandbits(32) for _ in range(n)]
    for idx, w in enumerate(todo):
        learn_word(cfg, spec, L, O, w, keys, stats)
        if idx % 5000 == 4999:
            print("%d/%d words, %d classes, %s, oracle calls %d, %.0fs" %
                  (idx + 1, len(todo), len(spec.classes), fmt_stats(stats), O.calls, time.time() - t0),
                  file=sys.stderr)
            spec.save(path)
    spec.order()
    spec.save(path)
    print("done: %d classes, %s" % (len(spec.classes), fmt_stats(stats)), file=sys.stderr)


def neighbours(cfg, seed, rnd):
    """Words near a class seed where rare aliases / special cases live."""
    out = [seed ^ (1 << i) for i in range(32)]
    ones = (1 << cfg.rw) - 1
    fields = cfg.reg_fields
    for a in fields:
        out.append(seed | (ones << a))
        out.append(seed & ~(ones << a))
        for b in fields:
            if a < b:
                va = (seed >> a) & ones
                out.append((seed & ~(ones << b)) | (va << b))
                vb = (seed >> b) & ones
                out.append((seed & ~(ones << a)) | (vb << a))
    for lo, n in cfg.imm_fields:
        m = ((1 << n) - 1) << lo
        out.append(seed & ~m)
        out.append(seed | m)
    for _ in range(8):
        out.append(seed ^ (1 << rnd.randrange(32)) ^ (1 << rnd.randrange(32)))
    return [w & 0xFFFFFFFF for w in out]


def cmd_explore(cfg, args):
    path = args[0]
    rounds = 1
    if "--rounds" in args:
        rounds = int(args[args.index("--rounds") + 1])
    spec = load_or_new(cfg, path)
    O = Oracle(cfg.name)
    rnd = random.Random(77)
    L = make_learner(cfg, O, 78)
    keys = {(k.mask, k.value, k.mnem, k.seps, k.handler): k for k in spec.classes}
    t0 = time.time()
    done_seeds = set()
    for r in range(rounds):
        stats = Counter()
        seeds = [k.seed for k in spec.classes if not k.handler and k.seed not in done_seeds]
        for idx, s in enumerate(seeds):
            done_seeds.add(s)
            for w in neighbours(cfg, s, rnd):
                learn_word(cfg, spec, L, O, w, keys, stats)
            if idx % 500 == 499:
                print("round %d: %d/%d seeds, %d classes, %s, %.0fs" %
                      (r, idx + 1, len(seeds), len(spec.classes), fmt_stats(stats), time.time() - t0),
                      file=sys.stderr)
                spec.save(path)
        spec.order()
        spec.save(path)
        print("round %d done: %d classes, %s" % (r, len(spec.classes), fmt_stats(stats)), file=sys.stderr)
        if stats["new"] == 0:
            break


def cmd_emit(cfg, args):
    from arm_spec import TextSpec, emit_text
    path, outp = args[0], args[1]
    nver = 20000
    if "--verify" in args:
        nver = int(args[args.index("--verify") + 1])
    spec = load_or_new(cfg, path)
    spec.order()
    classes = [k.to_json() for k in spec.classes]
    text = emit_text(classes, "\n".join(["# %s spec: %d classes" % (cfg.name, len(classes))] + cfg.spec_records))
    ts = TextSpec(text)
    rnd = random.Random(4242)
    bad = 0
    for i in range(nver):
        if i % 2:
            w = rnd.getrandbits(32)
        else:
            w = spec.classes[i // 2 % len(spec.classes)].seed ^ (rnd.getrandbits(32) & rnd.getrandbits(32) & rnd.getrandbits(32))
        a, _ = spec.render(w)
        b = ts.render(w)
        if a != b:
            bad += 1
            if bad < 10:
                print("text/json mismatch %08x: %r vs %r" % (w, a, b), file=sys.stderr)
    print("text spec: %d bytes, %d lines, verify mismatches %d/%d" % (len(text), text.count("\n"), bad, nver),
          file=sys.stderr)
    assert '"#' not in text
    with open(outp, "w") as f:
        f.write(cfg.rust_header + "\n" + text + "\"#;\n")


def cmd_check(cfg, args):
    path = args[0]
    n = 100000
    if "--rand" in args:
        n = int(args[args.index("--rand") + 1])
    spec = load_or_new(cfg, path)
    O = Oracle(cfg.name)
    rnd = random.Random(99)
    bad = Counter()
    nbad = 0
    ex = {}
    for _ in range(n):
        w = rnd.getrandbits(32)
        exp, got, ci = mismatch(spec, O, w)
        if exp != got:
            nbad += 1
            key = (exp.split("\t")[0] if exp else "INVALID") + " / " + (got.split("\t")[0] if got else "INVALID")
            bad[key] += 1
            ex.setdefault(key, (hex(w), exp, got))
    print("mismatch %d / %d = %.4f%%" % (nbad, n, 100.0 * nbad / n))
    for key, c in bad.most_common(60):
        print(c, key, ex[key])


def cmd_stats(cfg, args):
    spec = load_or_new(cfg, args[0])
    kinds = Counter()
    for k in spec.classes:
        for at in k.atoms:
            kinds[at["k"]] += 1
    print(len(spec.classes), "classes", dict(kinds))
    print(Counter(k.mnem for k in spec.classes).most_common(40))


def cmd_explain(cfg, args):
    spec = load_or_new(cfg, args[0])
    O = Oracle(cfg.name)
    spec.build_index()
    for a in args[1:]:
        w = int(a, 16)
        print("word %08x oracle: %s   spec: %s" % (w, oracle_text(O(w)), spec.render(w)[0]))
        for ci in spec.candidates(w):
            k = spec.classes[ci]
            if (w & k.mask) != k.value:
                continue
            r = k.render(w)
            print("  class %d prio %d pop %d mask %08x value %08x seed %08x mnem %s -> %r" %
                  (ci, k.prio, popcount(k.mask), k.mask, k.value, k.seed, k.mnem, r))
            for at in k.atoms:
                d = dict(at)
                if "tab" in d:
                    d["tab"] = d["tab"] if len(d["tab"]) <= 16 else "[%d entries]" % len(d["tab"])
                print("      ", d)
            if k.cons:
                print("       cons", k.cons)


COMMANDS = {"learn": cmd_learn, "explore": cmd_explore, "check": cmd_check, "emit": cmd_emit,
            "stats": cmd_stats, "explain": cmd_explain}


def main(cfg, argv):
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd not in COMMANDS:
        print(__doc__)
        sys.exit(1)
    COMMANDS[cmd](cfg, argv[2:])
