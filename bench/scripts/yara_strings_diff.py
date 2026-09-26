#!/usr/bin/env python3
"""Differential test of the YARA text-string matcher (src/yara/scan) against yara-python.

Usage: bench/venv/bin/python bench/scripts/yara_strings_diff.py [--cases N] [--seed S]
           [--image PATH --slices K --slice-len BYTES] [--keep DIR]

Generates random text strings (ascii / wide / nocase / fullword / xor / base64 /
base64wide), random haystacks with planted variants (plus optional slices of a memory
image), computes the expected matches with yara-python, then runs the ignored Rust test
`yara_scan_difftest` and reports differences.
"""
import argparse, base64, os, random, subprocess, sys, tempfile

import yara

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LIMIT = os.path.join(ROOT, "bench", "scripts", "limit.sh")


def esc(s):
    out = []
    for b in s:
        if (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122) or b in b" .:/-_,!()":
            out.append(chr(b))
        else:
            out.append("\\x%02x" % b)
    return "".join(out)


def mods_src(m):
    parts = []
    if "a" in m["f"]:
        parts.append("ascii")
    if "w" in m["f"]:
        parts.append("wide")
    if "n" in m["f"]:
        parts.append("nocase")
    if "f" in m["f"]:
        parts.append("fullword")
    if m.get("xor") is not None:
        lo, hi = m["xor"]
        parts.append("xor" if (lo, hi) == (0, 255) else ("xor(%d)" % lo if lo == hi else "xor(%d-%d)" % (lo, hi)))
    alpha = m.get("alpha")
    a = '("%s")' % esc(alpha) if alpha else ""
    if "b" in m["f"]:
        parts.append("base64" + a)
    if "B" in m["f"]:
        parts.append("base64wide" + a)
    return " ".join(parts)


def spec(s, m):
    f = "".join(c for c in m["f"] if c in "awnfbBis")
    if m.get("xor") is not None:
        f += "x%d-%d" % m["xor"]
    if m.get("at") is not None:
        f += "o%d" % m["at"]
    return "%s|%s|%s|%s" % (s.hex(), f, (m.get("alpha") or b"").hex(), m.get("kind", "T"))


def string_src(i, s, m):
    kind = m.get("kind", "T")
    if kind == "H":
        return "  $s%d = %s %s\n" % (i, s.decode(), mods_src(m))
    if kind == "R":
        fl = ("i" if "i" in m["f"] else "") + ("s" if "s" in m["f"] else "")
        return "  $s%d = /%s/%s %s\n" % (i, s.decode(), fl, mods_src(m))
    return '  $s%d = "%s" %s\n' % (i, esc(s), mods_src(m))


HEX_TOK = ["41", "42", "61", "00", "62", "??", "4?", "?1", "[1]", "[0-2]", "[2-4]", "(41|42)", "(61 62|00)", "~41", "[1-]"]
RE_TOK = ["a", "b", "A", "ab", "\\x00", ".", "[ab]", "[^a]", "a+", "b*", "(a|b)", "a{1,3}", "b{2}", ".{0,4}", "\\w", "\\d", "(ab|ba)",
          "a?", "\\s", "x", "b+?", ".*?", "[a-c]{1,2}"]


def rand_hex(rng):
    toks = ["41" if rng.random() < 0.5 else "61"]
    for _ in range(rng.randint(0, 5)):
        toks.append(rng.choice(HEX_TOK))
    toks.append(rng.choice(["42", "62", "00", "41"]))
    return ("{ " + " ".join(toks) + " }").encode()


def rand_re(rng):
    return "".join(rng.choice(RE_TOK) for _ in range(rng.randint(1, 5))).encode()


def rand_re_mods(rng, kind):
    f = ""
    if kind == "R":
        f += rng.choice(["", "", "a", "w", "aw"])
        if rng.random() < 0.3:
            f += "n" if rng.random() < 0.5 else "i"
        if rng.random() < 0.2:
            f += "s"
        if rng.random() < 0.2:
            f += "f"
    return {"f": f, "kind": kind}


def rand_mods(rng):
    kind = rng.random()
    f = ""
    m = {}
    if kind < 0.15:
        f += rng.choice(["b", "B", "bB"])
        if rng.random() < 0.4:
            f += rng.choice(["a", "w", "aw"])
        if rng.random() < 0.2:
            al = list(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
            rng.shuffle(al)
            m["alpha"] = bytes(al)
    else:
        f += rng.choice(["", "a", "w", "aw", "aw", "w"])
        if rng.random() < 0.35:
            f += "n"
        elif rng.random() < 0.35:
            lo = rng.choice([0, 0, 1, 5, 0x20])
            hi = rng.choice([lo, lo + 1, lo + 3, 255, min(255, lo + 10)])
            m["xor"] = (lo, max(lo, hi))
        if rng.random() < 0.3:
            f += "f"
    if rng.random() < 0.02:
        # invalid combination (compile error on both sides)
        f += "n"
        m["xor"] = (0, 255)
    m["f"] = f
    return m


def rand_text(rng):
    n = rng.choice([1, 1, 2, 2, 3, 4, 5, 6, 8, 9, 12, 17, 30])
    pool = rng.choice([b"ab", b"abcAB", b"xyzXYZ01", b"a\x00b", b"Hello World!", bytes(range(256)), b"\x00\x01\xff"])
    return bytes(rng.choice(pool) for _ in range(n))


def variants(s, m, rng):
    out = [s, s.swapcase(), bytes(b if rng.random() < 0.5 else (b ^ 0x20 if chr(b).isalpha() else b) for b in s)]
    w = b"".join(bytes([b, 0]) for b in s)
    out += [w, w.swapcase()]
    k = rng.randrange(256)
    out += [bytes(b ^ k for b in s), bytes(b ^ k for b in w)]
    if m.get("xor"):
        k = rng.randint(*m["xor"])
        out += [bytes(b ^ k for b in s), bytes(b ^ k for b in w)]
    for src in (s, w):
        for pre in (b"", b"A", b"AB"):
            enc = base64.b64encode(pre + src)
            out.append(enc)
            out.append(b"".join(bytes([c, 0]) for c in enc))
    if m.get("alpha"):
        tr = bytes.maketrans(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", m["alpha"])
        for pre in (b"", b"A", b"AB"):
            out.append(base64.b64encode(pre + s).translate(tr))
    return out


def rand_data(rng, strs):
    n = rng.randrange(0, 2500) if rng.random() < 0.97 else rng.randrange(100000, 400000)
    pool = bytes(set(b"".join(s for s, m in strs if m.get("kind", "T") == "T"))) + b"\x00 .aZ9Abx"
    data = bytearray(rng.choice(pool) if rng.random() < 0.7 else rng.randrange(256) for _ in range(n))
    for s, m in strs:
        if m.get("kind", "T") != "T":
            continue
        for v in variants(s, m, rng):
            if rng.random() < 0.5 or len(v) > len(data):
                continue
            p = rng.randrange(0, len(data) - len(v) + 1)
            data[p:p + len(v)] = v
            if rng.random() < 0.3 and p > 0:
                data[p - 1] = rng.choice(b"a0 \x00")
            if m.get("at") is not None and rng.random() < 0.5 and m["at"] + len(v) <= len(data):
                data[m["at"]:m["at"] + len(v)] = v
        if len(data) > 200000:
            for _ in range(50):
                v = rng.choice(variants(s, m, rng))
                p = rng.randrange(0, len(data) - len(v) + 1)
                data[p:p + len(v)] = v
    return bytes(data)


def expected(strs, data):
    src = "rule r {\n strings:\n"
    for i, (s, m) in enumerate(strs):
        src += string_src(i, s, m)
    if any(m.get("at") is not None for _, m in strs):
        conds = []
        for i, (s, m) in enumerate(strs):
            conds.append("$s%d at %d" % (i, m["at"]) if m.get("at") is not None else "$s%d" % i)
        src += " condition:\n  " + " or ".join(conds) + " or true\n}\n"
    else:
        src += " condition:\n  any of them\n}\n"
    try:
        r = yara.compile(source=src)
    except Exception as e:
        return "ERR " + str(e).replace("\t", " "), src
    ms = r.match(data=data)
    parts = {}
    for mt in ms:
        for st in mt.strings:
            k = int(st.identifier[2:])
            parts[k] = " ".join("%d,%d,%d" % (i.offset, i.matched_length, i.xor_key) for i in st.instances)
    return ";".join("%d:%s" % (k, parts[k]) for k in sorted(parts) if parts[k]), src


AW = {"f": "aw"}
IMAGE_RULES = [
    [(b"mimikatz", {"f": "awn"}), (b"This program cannot be run in DOS mode", {"f": ""}),
     (b"cmd.exe /c", {"f": "n"}), (b"http://", {"f": "aw"}), (b"GetProcAddress", {"f": ""}),
     (b"\\Windows\\System32\\", {"f": "wn"}), (b"password", {"f": "nf"}), (b"kernel32.dll", {"f": "n"}),
     (b"svchost.exe", {"f": "wn"}), (b"ntdll.dll", {"f": "awn"}), (b"Mozilla/5.0", {"f": ""})],
    [(b"This program cannot be run", {"f": "", "xor": (1, 255)}), (b"http://", {"f": "aw", "xor": (0, 255)}),
     (b"GetProcAddress", {"f": "", "xor": (0x20, 0x21)}), (b"powershell", {"f": "bB"}),
     (b"cmd.exe", {"f": "aw", "xor": (1, 255)}), (b"MZ", {"f": "f"}), (b"PE", {"f": "w"}),
     (b"\x00\x00\x00\x00\x01", {"f": ""}), (b"e", {"f": "aw"}), (b"ab", {"f": "", "xor": (0, 255)})],
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--image")
    ap.add_argument("--slices", type=int, default=0)
    ap.add_argument("--slice-len", type=int, default=4 << 20)
    ap.add_argument("--keep")
    ap.add_argument("--show", type=int, default=5)
    ap.add_argument("--re-frac", type=float, default=0.25)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    tmp = a.keep or tempfile.mkdtemp(prefix="yarastr")
    os.makedirs(tmp, exist_ok=True)
    cases = []
    for ci in range(a.cases):
        strs = []
        for _ in range(rng.randint(1, 5)):
            r = rng.random()
            if r < a.re_frac / 2:
                strs.append((rand_hex(rng), rand_re_mods(rng, "H")))
            elif r < a.re_frac:
                strs.append((rand_re(rng), rand_re_mods(rng, "R")))
            else:
                strs.append((rand_text(rng), rand_mods(rng)))
            if rng.random() < 0.05:
                strs[-1][1]["at"] = rng.randrange(0, 40)
        data = rand_data(rng, strs)
        exp, src = expected(strs, data)
        cases.append(("c%d" % ci, strs, data.hex(), exp, src))
    for ci in range(a.slices if a.image else 0):
        off = rng.randrange(0, os.path.getsize(a.image) - a.slice_len) & ~0xFFF
        with open(a.image, "rb") as fh:
            fh.seek(off)
            data = fh.read(a.slice_len)
        strs = IMAGE_RULES[ci % len(IMAGE_RULES)]
        exp, src = expected(strs, data)
        cases.append(("img%d@%x" % (ci, off), strs, "@%s:%d:%d" % (a.image, off, a.slice_len), exp, src))
    cpath = os.path.join(tmp, "cases.tsv")
    opath = os.path.join(tmp, "out.tsv")
    with open(cpath, "w") as fh:
        for cid, strs, d, exp, _ in cases:
            fh.write("%s\t%s\t%s\t%s\n" % (cid, ";".join(spec(s, m) for s, m in strs), d, exp))
    env = dict(os.environ, RSVOL_YARA_CASES=cpath, RSVOL_YARA_OUT=opath)
    cmd = ["cargo", "test", "--profile", "fast", "yara_scan_difftest", "--", "--ignored", "--nocapture"]
    subprocess.run([LIMIT, "-m", "4G"] + cmd, cwd=ROOT, env=env, check=True)
    res = dict(l.split("\t", 1) for l in open(opath).read().splitlines())
    bad = [c for c in cases if not res.get(c[0], "").startswith("OK")]
    print("cases: %d  ok: %d  diff: %d" % (len(cases), len(cases) - len(bad), len(bad)))
    for cid, strs, d, exp, src in bad[: a.show]:
        print("=" * 60, cid)
        print(src)
        if not d.startswith("@") and len(d) < 20000:
            print("data:", bytes.fromhex(d))
        print("expected:", exp)
        print("got     :", res.get(cid, "?").split("\t", 1)[-1])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
