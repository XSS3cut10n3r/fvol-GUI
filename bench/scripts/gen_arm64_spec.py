#!/usr/bin/env python3
"""Learn / refine the AArch64 instruction-class spec by probing capstone (see arm_learn.py).

usage:
  gen_arm64_spec.py learn SPEC.json [--rand N] [--words FILE] [--seed S]
        sample N random words (and/or words listed in FILE, one hex word per line), learn a
        class for every word the current spec renders differently from capstone
  gen_arm64_spec.py check SPEC.json [--rand N]     report mismatch rate on random words
  gen_arm64_spec.py stats SPEC.json
"""
import os
import random
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from arm_learn import (A0, HANDLERS, INVALID, OTHER, Klass, Learner, Oracle, Spec,  # noqa: E402
                       fmt_num, oracle_text, popcount)


# ----------------------------------------------------------------------------------------------
# hand-written handlers (value-comparison aliases); mirrored in src/disasm/arm64

def _gpr(sf, n):
    if sf:
        return "xzr" if n == 31 else "x%d" % n
    return "wzr" if n == 31 else "w%d" % n


def _imm32(v):
    return "#" + fmt_num(v, "S32")


def h_bitfield(w, addr):
    """SBFM / BFM / UBFM and their aliases (asr lsl lsr sxt* uxt* sbfiz sbfx ubfiz ubfx bfc bfi
    bfxil)."""
    sf = w >> 31
    opc = (w >> 29) & 3
    n = (w >> 22) & 1
    immr = (w >> 16) & 63
    imms = (w >> 10) & 63
    rn = (w >> 5) & 31
    rd = w & 31
    if opc == 3 or sf != n or (not sf and (immr >= 32 or imms >= 32)):
        return None
    width = 64 if sf else 32
    d, s = _gpr(sf, rd), _gpr(sf, rn)
    if opc == 1:
        if rn == 31 and (immr == 0 or imms < immr):
            return "bfc\t%s, %s, %s" % (d, _imm32((width - immr) % width), _imm32(imms + 1))
        if imms < immr:
            return "bfi\t%s, %s, %s, %s" % (d, s, _imm32((width - immr) % width), _imm32(imms + 1))
        return "bfxil\t%s, %s, %s, %s" % (d, s, _imm32(immr), _imm32(imms - immr + 1))
    signed = opc == 0
    if immr == 0:
        m = None
        if imms == 7:
            m = "sxtb" if signed else (None if sf else "uxtb")
        elif imms == 15:
            m = "sxth" if signed else (None if sf else "uxth")
        elif imms == 31:
            m = "sxtw" if signed and sf else None
        if m:
            return "%s\t%s, %s" % (m, d, _gpr(0, rn))
    if not signed and imms != width - 1 and imms + 1 == immr:
        return "lsl\t%s, %s, %s" % (d, s, _imm32(width - 1 - imms))
    if imms == width - 1:
        return "%s\t%s, %s, %s" % ("asr" if signed else "lsr", d, s, _imm32(immr))
    if immr > imms:
        return "%s\t%s, %s, %s, %s" % ("sbfiz" if signed else "ubfiz", d, s, _imm32(width - immr),
                                       _imm32(imms + 1))
    return "%s\t%s, %s, %s, %s" % ("sbfx" if signed else "ubfx", d, s, _imm32(immr), _imm32(imms - immr + 1))


HANDLERS["bitfield"] = h_bitfield
HANDLER_CLASSES = [("bitfield", 0x1F800000, 0x13000000)]


def install_handlers(spec):
    have = {k.handler for k in spec.classes if k.handler}
    for name, mask, value in HANDLER_CLASSES:
        if name in have:
            continue
        k = Klass()
        k.mask, k.value, k.handler, k.mnem, k.prio = mask, value, name, "<" + name + ">", 1000
        spec.add(k)


def handled(w):
    return any((w & m) == v for _, m, v in HANDLER_CLASSES)


def load_or_new(path, arch):
    spec = Spec.load(path) if os.path.exists(path) else Spec(arch)
    install_handlers(spec)
    return spec


def mismatch(spec, O, w):
    t = O(w)
    exp = oracle_text(t)
    got, ci = spec.render(w)
    return exp, got, ci


def learn_word(spec, L, O, w, keys, stats):
    exp, got, ci = mismatch(spec, O, w)
    if exp == got:
        return False
    if handled(w):
        stats["handler_bug"] += 1
        if stats["handler_bug"] < 20:
            L.log("  handler mismatch %08x exp %r got %r" % (w, exp, got))
        return False
    if exp is None:
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
    key = (k.mask, k.value, k.mnem, k.seps)
    if key in keys:
        k = keys[key]
        stats["reprio"] += 1
    else:
        spec.add(k)
        keys[key] = k
        stats["new"] += 1
    # make sure k wins for w
    for _ in range(8):
        spec.order()
        spec._index = None
        got, ci2 = spec.render(w)
        if got == exp:
            break
        if ci2 is None:
            break
        c = spec.classes[ci2]
        if c is k:
            break
        k.prio = popcount(c.mask) + c.prio - popcount(k.mask) + 1
    return True


def cmd_learn(args):
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
    spec = load_or_new(path, "arm64")
    O = Oracle("arm64")
    rnd = random.Random(seed)
    L = Learner(O, "arm64", random.Random(seed + 1), log=lambda *a: print(*a, file=sys.stderr))
    keys = {(k.mask, k.value, k.mnem, k.seps): k for k in spec.classes}
    stats = Counter()
    t0 = time.time()
    todo = words + [rnd.getrandbits(32) for _ in range(n)]
    for idx, w in enumerate(todo):
        learn_word(spec, L, O, w, keys, stats)
        if idx % 20000 == 19999:
            print("%d words, %d classes, %s, oracle calls %d, %.0fs" %
                  (idx + 1, len(spec.classes), dict((k, v) for k, v in stats.items() if k != "fv_classes"),
                   O.calls, time.time() - t0), file=sys.stderr)
            spec.save(path)
    spec.order()
    spec.save(path)
    print("done: %d classes, %s" % (len(spec.classes), dict((k, v) for k, v in stats.items() if k != "fv_classes")),
          file=sys.stderr)
    fv = stats.get("fv_classes")
    if fv:
        for ci, c in fv.most_common(30):
            k = spec.classes[ci] if ci is not None and ci < len(spec.classes) else None
            print("  false-valid via class", ci, c, k and (k.mnem, hex(k.mask), hex(k.value), hex(k.seed)), file=sys.stderr)


def neighbours(seed, rnd):
    """Words near a class seed where rare aliases / special cases live."""
    out = [seed ^ (1 << i) for i in range(32)]
    fields = (0, 5, 10, 16)
    for a in fields:
        out.append(seed | (31 << a))
        out.append(seed & ~(31 << a))
        for b in fields:
            if a < b:
                va = (seed >> a) & 31
                out.append((seed & ~(31 << b)) | (va << b))
                vb = (seed >> b) & 31
                out.append((seed & ~(31 << a)) | (vb << a))
    # low/high immediate-ish fields cleared / set
    for lo, n in ((10, 12), (10, 6), (16, 6), (5, 16), (12, 4), (10, 3), (22, 2)):
        m = ((1 << n) - 1) << lo
        out.append(seed & ~m)
        out.append(seed | m)
    for _ in range(8):
        out.append(seed ^ (1 << rnd.randrange(32)) ^ (1 << rnd.randrange(32)))
    return [w & 0xFFFFFFFF for w in out]


def cmd_explore(args):
    path = args[0]
    rounds = 1
    if "--rounds" in args:
        rounds = int(args[args.index("--rounds") + 1])
    spec = load_or_new(path, "arm64")
    O = Oracle("arm64")
    rnd = random.Random(77)
    L = Learner(O, "arm64", random.Random(78), log=lambda *a: print(*a, file=sys.stderr))
    keys = {(k.mask, k.value, k.mnem, k.seps): k for k in spec.classes}
    t0 = time.time()
    done_seeds = set()
    for r in range(rounds):
        stats = Counter()
        seeds = [k.seed for k in spec.classes if not k.handler and k.seed not in done_seeds]
        for idx, s in enumerate(seeds):
            done_seeds.add(s)
            for w in neighbours(s, rnd):
                learn_word(spec, L, O, w, keys, stats)
            if idx % 500 == 499:
                print("round %d: %d/%d seeds, %d classes, %s, %.0fs" %
                      (r, idx + 1, len(seeds), len(spec.classes),
                       dict((k, v) for k, v in stats.items() if k != "fv_classes"), time.time() - t0),
                      file=sys.stderr)
                spec.save(path)
        spec.order()
        spec.save(path)
        print("round %d done: %d classes, %s" % (r, len(spec.classes),
              dict((k, v) for k, v in stats.items() if k != "fv_classes")), file=sys.stderr)
        if stats["new"] == 0:
            break


RUST_HEADER = """//! AArch64 instruction spec (generated by bench/scripts/gen_arm64_spec.py from probing the
//! capstone 5 oracle; grammar in bench/scripts/arm_spec.py). DO NOT EDIT BY HAND.

pub(crate) const SPEC: &str = r#\""""


def cmd_emit(args):
    """emit SPEC.json OUT.rs [--verify N]"""
    from arm_spec import TextSpec, emit_text
    path, outp = args[0], args[1]
    nver = 20000
    if "--verify" in args:
        nver = int(args[args.index("--verify") + 1])
    spec = load_or_new(path, "arm64")
    spec.order()
    classes = [k.to_json() for k in spec.classes]
    text = emit_text(classes, "# AArch64 spec: %d classes" % len(classes))
    ts = TextSpec(text)
    rnd = random.Random(4242)
    bad = 0
    for i in range(nver):
        w = rnd.getrandbits(32) if i % 2 else spec.classes[i // 2 % len(spec.classes)].seed ^ (rnd.getrandbits(32) & rnd.getrandbits(32) & rnd.getrandbits(32))
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
        f.write(RUST_HEADER + "\n" + text + "\"#;\n")


def cmd_check(args):
    path = args[0]
    n = 100000
    if "--rand" in args:
        n = int(args[args.index("--rand") + 1])
    spec = load_or_new(path, "arm64")
    O = Oracle("arm64")
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


def cmd_stats(args):
    spec = load_or_new(args[0], "arm64")
    kinds = Counter()
    for k in spec.classes:
        for at in k.atoms:
            kinds[at["k"]] += 1
    print(len(spec.classes), "classes", dict(kinds))
    mn = Counter(k.mnem for k in spec.classes)
    print(mn.most_common(40))


def cmd_explain(args):
    spec = load_or_new(args[0], "arm64")
    O = Oracle("arm64")
    spec.build_index()
    for a in args[1:]:
        w = int(a, 16)
        print("word %08x oracle: %s" % (w, oracle_text(O(w))))
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
                    d["tab"] = "[%d entries]" % len(d["tab"])
                print("      ", d)
            if k.cons:
                print("       cons", k.cons)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    {"learn": cmd_learn, "check": cmd_check, "stats": cmd_stats, "explore": cmd_explore, "emit": cmd_emit,
     "explain": cmd_explain}.get(cmd, lambda a: print(__doc__))(sys.argv[2:])
