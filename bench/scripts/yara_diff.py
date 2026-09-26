#!/usr/bin/env python3
"""Differential test: rsvol's YARA engine (src/yara/rules + src/yara/scan) vs yara-python 4.5.4.

Corpus = hand-written rules exercising every feature (text modifiers nocase / wide / ascii /
fullword / xor / xor(k) / xor(a-b) / base64 / base64wide / custom alphabets / private, hex
strings with ?? / nibbles / ~ / jumps / nested alternatives, regex strings with flags, classes,
quantifiers, anchors, \\b; conditions with counts, offsets, lengths, at / in, of / them, for
loops, filesize, intXX readers, arithmetic / bitwise precedence, string operators, rule
references, private / global rules, tags, meta, namespaces) + INVALID rules that must fail to
compile + hundreds of random rules built from substrings of the scanned data (so they match).
Data = synthetic buffers (text, wide, xor-encoded, base64, fullword boundaries, binary PE-ish
bytes, repetitive / overlapping, zeros for the 1M match cap) + slices of a few MB at random
offsets of the memory image (read with pread, never the whole image).

Oracle: yara-python (`yara.compile(sources=...)`, `rules.match(data=...)`): compile error vs
ok, and for every matching rule: namespace, rule, tags, meta, and for every StringMatch the
identifier and its instances (offset, matched_length, xor_key, matched_data) — count + md5 of
all instances + the first 32 in clear. The rust side is the ignored test
`yara_rules_difftest_driver` (src/yara/benchdrv.rs), which writes the same records; it runs in
its own memory-capped scope (limit.sh), is resumed after a crash / timeout, and the offending
case is reported. Mismatches are summarized by category with minimal repro lines.

usage: yara_diff.py [-n RANDOM] [--seed S] [--slices K] [--keep DIR] [--profile fast|release]
                    [--show N] [--timeout S] [--rust-mem 4G] [--no-limit] [--case ID[,ID]]
                    [--no-memory] [--img IMG]
Run it through limit.sh:  bench/scripts/limit.sh -m 4G bench/venv/bin/python bench/scripts/yara_diff.py
"""
import argparse
import base64
import collections
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
import warnings

warnings.simplefilter("ignore")
import yara  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
LIMIT = "/home/user/rs-vol/bench/scripts/limit.sh"
if not os.access(LIMIT, os.X_OK):
    LIMIT = os.path.join(ROOT, "bench/scripts/limit.sh")
FIRST = 32  # instances listed in clear per string (must match FIRST_INSTANCES in benchdrv.rs)

STD64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
ALT64 = STD64[::-1]  # custom alphabet used by base64("...") strings and the synthetic data

WORDS = [b"Microsoft", b"kernel32", b"ntdll", b"Windows", b"svchost", b"explorer", b"System32",
         b"password", b"http", b"https://", b"abc", b"aa", b"MZ", b"This program", b"cmd.exe",
         b"\\Device\\HarddiskVolume", b".exe", b".dll", b"Registry", b"USER", b"admin",
         b"powershell", b"GetProcAddress", b"LoadLibraryA", b"VirtualAlloc", b"Software\\Microsoft",
         b"secret", b"evil.com", b"a", b"ab"]


# ---------------------------------------------------------------------------------------
# data corpus
# ---------------------------------------------------------------------------------------

def widen(b):
    return bytes(x for c in b for x in (c, 0))


def xor(b, k):
    return bytes(c ^ k for c in b)


def b64(b, alpha=STD64):
    e = base64.b64encode(b)
    return e if alpha == STD64 else e.translate(bytes.maketrans(STD64, alpha))


def synthetic(rng):
    """name -> bytes. Every buffer is built so that the corpus' strings do match."""
    d = collections.OrderedDict()
    d["empty"] = b""
    d["one"] = b"a"
    t = []
    for w in WORDS:
        mixed = bytes(c ^ 0x20 if 97 <= (c | 0x20) <= 122 and rng.random() < .5 else c for c in w)
        t += [w, b" ", w.upper(), b"\n", w.lower(), b"\t", mixed, b"; "]
    t += [b"GET http://evil.com/a?b=c&d=%41 HTTP/1.1\r\nHost: 10.0.0.1\r\n",
          b"https://www.microsoft.com/en-us/ 192.168.1.254:8080 255.255.255.255 1.2.3 999.1.1.1 ",
          b"C:\\Windows\\System32\\svchost.exe -k netsvcs \\Device\\HarddiskVolume3\\Windows\\explorer.exe ",
          b"user@example.com admin@evil.com PASSWORD=hunter2 password: Secret123 ",
          b"abcabcabc aaaa abab ababab xabcx 0123456789 ", b"\"quoted\" back\\slash tab\there"]
    d["text"] = b"".join(t)
    d["wide"] = b"".join(widen(w) + b"\x00\x00" + widen(w.upper()) + b"\x01\x00" + w + b"|" for w in WORDS) + \
        widen(b"C:\\Windows\\System32\\kernel32.dll") + b"\x00\x00" + widen(b"https://evil.com/x?y=1")
    x = []
    for w in WORDS[:20]:
        for k in (0, 1, 0x20, 0x55, 0xff, rng.randrange(256)):
            x += [xor(w, k), bytes([rng.randrange(256)]), xor(widen(w), k), b"\x00\x00"]
    x += [b"bbbb cccc " + xor(b"aaaa", 3)]
    d["xor"] = b"".join(x)
    e = []
    for w in WORDS[:24] + [b"This program cannot be run in DOS mode"]:
        for pad in (b"", b"x", b"xy"):
            for alpha in (STD64, ALT64):
                s = b64(pad + w + b"!!", alpha)
                e += [s, b" ", widen(s), b"  "]
    d["b64"] = b"".join(e)
    f = []
    for w in (b"Microsoft", b"kernel32", b"password", b"abc", b"admin", b"secret"):
        for pre, post in ((b" ", b" "), (b"x", b" "), (b" ", b"x"), (b"_", b"."), (b".", b"_"), (b"1", b"-"),
                          (b"-", b"1"), (b"\x00", b"\x00"), (b"\xff", b"\xfe"), (b"", b"")):
            f += [pre + w + post, widen(pre + w + post), b"#"]
    d["fullword"] = b"".join(f)
    mz = bytearray(512)
    mz[0:2] = b"MZ"
    mz[2:16] = bytes.fromhex("90000300000004000000ffff0000")
    mz[0x3c:0x40] = (0x80).to_bytes(4, "little")
    mz[0x40:0x40 + 39] = b"This program cannot be run in DOS mode."
    mz[0x80:0x86] = b"PE\x00\x00\x64\x86"
    code = bytes.fromhex("4c8bd1b855000000f604250803fe7f017503"
                         "48895c2408488974241057 4883ec20 488d0d11223344 e8aabbccdd 85c0 7405"
                         "488b0512345678 9090 ff1522334455 4885c0 75f0 c3".replace(" ", ""))
    d["bin"] = bytes(mz) + code * 3 + bytes(range(256)) + bytes(range(255, -1, -1))
    d["rep"] = b"a" * 300 + b"ab" * 200 + b"abc" * 100 + b"\x00" * 500 + b"\xff" * 64 + b"aAaA" * 50
    r = bytearray(rng.randrange(256) for _ in range(1 << 16))
    for w in WORDS:
        for _ in range(3):
            p = rng.randrange(len(r) - 64)
            r[p:p + len(w)] = w
    d["rand"] = bytes(r)
    return d


def memory_slices(rng, img, k):
    """k slices (1-3 MB) at random offsets of the non-zero parts of the image + one all-zero
    slice (1.1 MB, for the 1M-matches cap)."""
    size = os.path.getsize(img)
    out = []
    for i in range(k):
        ln = rng.randrange(1 << 20, 3 << 20)
        while True:
            off = rng.randrange(0, size - ln)
            if i % 2 == 0:
                off &= ~0xfff
            if not (3 << 30) <= off < (4 << 30) and not (3 << 30) <= off + ln < (4 << 30):
                break
        out.append(("mem%d" % i, off, ln))
    zero = []
    if size > (3 << 30) + (2 << 20):
        zero.append(("zeros", (3 << 30) + (1 << 20), 1100 * 1024))
    return out, zero


def read_slice(img, off, ln):
    with open(img, "rb") as fh:
        fh.seek(off)
        return fh.read(ln)


# ---------------------------------------------------------------------------------------
# rule corpus
# ---------------------------------------------------------------------------------------

def ystr(b):
    """YARA text string literal for bytes b."""
    out = []
    for c in b:
        if c == 0x22:
            out.append('\\"')
        elif c == 0x5c:
            out.append("\\\\")
        elif c == 0x0a:
            out.append("\\n")
        elif c == 0x09:
            out.append("\\t")
        elif 0x20 <= c < 0x7f:
            out.append(chr(c))
        else:
            out.append("\\x%02x" % c)
    return '"' + "".join(out) + '"'


def rlit(c):
    """YARA regex literal for one byte."""
    if chr(c) in "\\^$.|?*+()[]{}/":
        return "\\" + chr(c)
    if 0x20 <= c < 0x7f:
        return chr(c)
    return "\\x%02x" % c


ALT = ystr(ALT64)

FIXED_VALID = [
    # ---- text strings / modifiers
    'rule t_plain { strings: $a = "Microsoft" condition: $a }',
    'rule t_nocase { strings: $a = "microsoft" nocase condition: $a }',
    'rule t_wide { strings: $a = "Microsoft" wide condition: $a }',
    'rule t_wide_ascii { strings: $a = "Microsoft" wide ascii condition: $a }',
    'rule t_ascii { strings: $a = "Microsoft" ascii condition: $a }',
    'rule t_nocase_wide { strings: $a = "PASSWORD" nocase wide condition: $a }',
    'rule t_nocase_wide_ascii { strings: $a = "password" nocase wide ascii condition: $a }',
    'rule t_fullword { strings: $a = "Microsoft" fullword condition: $a }',
    'rule t_fullword_wide { strings: $a = "Microsoft" fullword wide condition: $a }',
    'rule t_fullword_wide_ascii { strings: $a = "kernel32" fullword wide ascii condition: $a }',
    'rule t_fullword_nocase { strings: $a = "MICROSOFT" fullword nocase condition: $a }',
    'rule t_fullword_nonword { strings: $a = ".exe" fullword $b = "abc" fullword condition: $a or $b }',
    'rule t_xor { strings: $a = "Microsoft" xor condition: $a }',
    'rule t_xor_k { strings: $a = "kernel32" xor(0x55) condition: $a }',
    'rule t_xor_0 { strings: $a = "kernel32" xor(0) condition: $a }',
    'rule t_xor_range { strings: $a = "kernel32" xor(1-0x20) condition: $a }',
    'rule t_xor_range_full { strings: $a = "password" xor(0-255) condition: $a }',
    'rule t_xor_wide { strings: $a = "Microsoft" xor wide condition: $a }',
    'rule t_xor_wide_ascii { strings: $a = "Microsoft" xor wide ascii condition: $a }',
    'rule t_xor_fullword { strings: $a = "Microsoft" xor fullword condition: $a }',
    'rule t_xor_private { strings: $a = "Microsoft" xor private condition: $a }',
    'rule t_xor_rep { strings: $a = "aa" xor condition: $a }',
    'rule t_xor_rep1 { strings: $a = "aaaa" xor(1-5) condition: #a > 0 }',
    'rule t_b64 { strings: $a = "This program cannot" base64 condition: $a }',
    'rule t_b64_short { strings: $a = "abc" base64 condition: $a }',
    'rule t_b64_2 { strings: $a = "ab" base64 condition: $a }',
    'rule t_b64wide { strings: $a = "This program cannot" base64wide condition: $a }',
    'rule t_b64_both { strings: $a = "password" base64 base64wide condition: $a }',
    'rule t_b64_alpha { strings: $a = "password" base64(%s) condition: $a }' % ALT,
    'rule t_b64wide_alpha { strings: $a = "Microsoft" base64wide(%s) condition: $a }' % ALT,
    'rule t_b64_wide { strings: $a = "password" base64 wide condition: $a }',
    'rule t_b64_private { strings: $a = "kernel32" base64 private condition: $a }',
    'rule t_private { strings: $a = "Microsoft" private $b = "Windows" condition: $a and $b }',
    'rule t_private_only { strings: $a = "Microsoft" private condition: $a }',
    r'rule t_esc { strings: $a = "\x4d\x5a\x90\x00" $b = "C:\\Windows" $c = "tab\there" $d = "\"quoted\"" condition: any of them }',
    r'rule t_bytes { strings: $a = "\x00\x00\x00\x00" $b = "\xff\xfe" condition: any of them }',
    'rule t_short { strings: $a = "a" condition: $a }',
    r'rule t_nul { strings: $a = "\x00" condition: #a > 10 }',
    'rule t_overlap { strings: $a = "aa" $b = "abab" $c = "abca" condition: all of them }',
    'rule t_long { strings: $a = "%s" condition: $a }' % ("A" * 200),
    r'rule t_path_nocase { strings: $a = "c:\\windows\\system32" nocase condition: $a }',
    'rule t_nocase_digits { strings: $a = "kernel32.dll" nocase wide ascii condition: $a }',
    'rule t_anon { strings: $ = "Microsoft" $ = "Windows" $ = "kernel32" condition: 2 of them }',
    'rule t_anon_for { strings: $ = "abc" $ = "aa" condition: for all of them : ( # > 1 ) }',
    'rule t_many { strings: %s condition: any of them }' % " ".join('$s%d = "%s"' % (i, w.decode("latin1").replace("\\", "\\\\"))
                                                                   for i, w in enumerate(WORDS)),
    'rule t_same_str { strings: $a = "abc" $b = "abc" $c = "abc" nocase condition: all of them }',
    'rule t_all_mods { strings: $a = "Windows" nocase wide ascii fullword private condition: $a }',
    # ---- hex strings
    'rule h_plain { strings: $a = { 4D 5A 90 00 } condition: $a }',
    'rule h_wild { strings: $a = { 4D 5A ?? 00 } condition: $a }',
    'rule h_nib_lo { strings: $a = { 4? 5A } condition: $a }',
    'rule h_nib_hi { strings: $a = { ?D 5A 90 } condition: $a }',
    'rule h_lead_wild { strings: $a = { ?? 5A 90 00 } condition: $a }',
    'rule h_trail_wild { strings: $a = { 4D 5A ?? ?? } condition: $a }',
    'rule h_jump { strings: $a = { 4D 5A [2] 00 03 } condition: $a }',
    'rule h_jump_range { strings: $a = { 4D 5A [2-6] 04 } condition: $a }',
    'rule h_jump_0 { strings: $a = { 4D 5A [0-2] 90 } condition: $a }',
    'rule h_jump_open { strings: $a = { 4D 5A [1-] 50 45 00 00 } condition: $a }',
    'rule h_jump_any { strings: $a = { 4D 5A [-] 64 86 } condition: $a }',
    'rule h_jump_big { strings: $a = { 4D 5A [100-300] 50 45 } condition: $a }',
    'rule h_jumps { strings: $a = { 48 [1-3] 5C [0-2] 08 [1] 89 } condition: $a }',
    'rule h_alt { strings: $a = { 50 45 00 00 ( 4C 01 | 64 86 ) } condition: $a }',
    'rule h_alt_len { strings: $a = { 48 ( 89 5C | 8B 05 12 | 8D ) } condition: $a }',
    'rule h_alt_nested { strings: $a = { 4D ( 5A | ( 90 | 91 ) 00 ) } condition: $a }',
    'rule h_alt_wild { strings: $a = { FF 15 ( ?? 33 | 22 ?? ) 44 } condition: $a }',
    'rule h_alt_first { strings: $a = { ( 4D 5A | 50 45 ) } condition: $a }',
    'rule h_not { strings: $a = { 4D ~00 90 } condition: $a }',
    'rule h_not_nib { strings: $a = { ~?D 5A } condition: $a }',
    'rule h_not_nib2 { strings: $a = { 4D ~5? } condition: $a }',
    'rule h_private { strings: $a = { 4D 5A } private condition: $a }',
    'rule h_many { strings: $a = { 00 ?? 00 } condition: $a }',
    'rule h_cap { strings: $a = { 00 00 } condition: #a > 5 }',
    'rule h_ff { strings: $a = { FF FF FF FF } condition: $a }',
    'rule h_code { strings: $a = { 4C 8B D1 B8 ?? ?? 00 00 } $b = { E8 ?? ?? ?? ?? 85 C0 } condition: any of them }',
    'rule h_1byte { strings: $a = { 4D } condition: $a }',
    'rule h_asc { strings: $a = { 00 01 02 03 [4-8] 0C 0D } $b = { FF FE FD [-] 00 } condition: $a or $b }',
    # ---- regex strings
    'rule r_alt { strings: $a = /Micro(soft|chip)/ condition: $a }',
    r'rule r_exe { strings: $a = /[a-z]{5,12}\.exe/ condition: $a }',
    r'rule r_exe_i { strings: $a = /[a-z]{5,12}\.exe/ nocase condition: $a }',
    r'rule r_exe_flag { strings: $a = /[a-z]{5,12}\.EXE/i condition: $a }',
    r'rule r_url { strings: $a = /https?:\/\/[a-zA-Z0-9.\/?=_%:-]{3,40}/ condition: $a }',
    r'rule r_ip { strings: $a = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/ condition: $a }',
    r'rule r_dll { strings: $a = /kernel32\.dll/i condition: $a }',
    'rule r_dot { strings: $a = /a.c/ $b = /b.a/s condition: $a or $b }',
    r'rule r_dot_nl { strings: $a = /t.here/ $b = /T\x0a./s condition: any of them }',
    'rule r_anchor { strings: $a = /^MZ/ $b = /\\x00$/ condition: $a or $b }',
    'rule r_lazy { strings: $a = /ab+?/ $b = /ab*/ $c = /(ab)+/ condition: any of them }',
    'rule r_rep { strings: $a = /a{2,3}/ $b = /a{3}/ $c = /a{,2}b/ $d = /a{2,}b/ condition: any of them }',
    r'rule r_class_hex { strings: $a = /[^\x00-\x1f\x7f-\xff]{12}/ condition: #a > 0 }',
    r'rule r_email { strings: $a = /\w+@\w+\.com/ condition: $a }',
    'rule r_wide { strings: $a = /Micro[a-z]+/ wide condition: $a }',
    'rule r_wide_ascii { strings: $a = /Micro[a-z]+/ wide ascii condition: $a }',
    'rule r_nocase_wide { strings: $a = /kernel[0-9]+/ nocase wide condition: $a }',
    'rule r_fullword { strings: $a = /[a-z]+32/ fullword condition: $a }',
    'rule r_private { strings: $a = /[A-Z][a-z]+soft/ private condition: $a }',
    r'rule r_device { strings: $a = /\\Device\\HarddiskVolume[0-9]+/ condition: $a }',
    r'rule r_esc_classes { strings: $a = /\s\S\d\D\w\W/ $b = /[\d\s]{3}/ condition: any of them }',
    'rule r_groups { strings: $a = /(a|b|c)(d|e)?x/ $b = /(ab|abc)+/ condition: any of them }',
    r'rule r_wordb { strings: $a = /\babc\B/ $b = /\Babc\b/ condition: any of them }',
    'rule r_prefix { strings: $a = /.{2,4}Microsoft/ condition: $a }',
    r'rule r_neg_class { strings: $a = /[^a-z ]{4}password/ nocase condition: $a }',
    r'rule r_hexesc { strings: $a = /\x4d\x5a\x90/ condition: $a }',
    'rule r_bin { strings: $a = /\\xff\\xfe[\\x00-\\x10]/ condition: $a }',
    'rule r_star { strings: $a = /GET [^ ]* HTTP/ condition: $a }',
    'rule r_long_alt { strings: $a = /(kernel32|ntdll|svchost|explorer|password|admin)\\.(exe|dll)/ nocase condition: $a }',
    'rule r_quant_group { strings: $a = /(\\x00\\x00){2,4}\\x01/ condition: $a }',
    'rule r_only_dot { strings: $a = /M.Z/s condition: $a }',
    r'rule r_ws { strings: $a = /\s+\r\n/ condition: $a }',
    # ---- conditions
    'rule c_count { strings: $a = "abc" condition: #a == 3 or #a > 5 }',
    'rule c_count2 { strings: $a = "aa" $b = "ab" condition: #a > 1 and #b < 1000 }',
    'rule c_offset { strings: $a = "abc" condition: @a[1] < 100000 }',
    'rule c_offset2 { strings: $a = "abc" condition: @a[2] - @a[1] > 2 }',
    'rule c_offset_last { strings: $a = "Microsoft" condition: @a[#a] >= @a[1] }',
    'rule c_offset_noidx { strings: $a = "Microsoft" condition: @a > 0 }',
    'rule c_length { strings: $a = /ab+/ condition: !a[1] > 2 }',
    'rule c_length2 { strings: $a = /a+/ condition: for any i in (1..#a) : ( !a[i] == 3 ) }',
    'rule c_at { strings: $a = "MZ" condition: $a at 0 }',
    'rule c_at2 { strings: $a = "MZ" $b = { 90 00 } condition: $a at 0 and $b at @a[1] + 2 }',
    'rule c_in { strings: $a = "Windows" condition: $a in (0..1000) }',
    'rule c_in_end { strings: $a = "a" condition: $a in (filesize - 1000..filesize) }',
    'rule c_count_in { strings: $a = "a" condition: #a in (0..1000) >= 2 }',
    'rule c_of { strings: $a = "Microsoft" $b = "Windows" $c = "nosuchthing" condition: 2 of them }',
    'rule c_of_all { strings: $a = "Microsoft" $b = "Windows" condition: all of ($a, $b) }',
    'rule c_of_set { strings: $s1 = "Microsoft" $s2 = "Windows" $t = "kernel32" condition: any of ($s*) and $t }',
    'rule c_of_none { strings: $a = "nosuchthing" $b = "zzqqzz" condition: none of them }',
    'rule c_of_pct { strings: $a = "Microsoft" $b = "Windows" $c = "nosuchthing" $d = "kernel32" condition: 50% of them }',
    'rule c_of_in { strings: $a = "Microsoft" $b = "Windows" condition: any of them in (0..4096) }',
    'rule c_of_at { strings: $a = "MZ" $b = "PE" condition: any of them at 0 }',
    'rule c_of_star { strings: $a = "abc" $b = "aa" condition: all of ($*) }',
    'rule c_for_of { strings: $a = "MZ" $b = "abc" condition: for any of them : ( $ at 0 ) }',
    'rule c_for_of2 { strings: $a = "abc" $b = "aa" condition: for all of them : ( # > 0 ) }',
    'rule c_for_of3 { strings: $a = "abc" $b = "aa" $c = "zzqq" condition: for 2 of ($a, $b, $c) : ( @ < 1000000 ) }',
    'rule c_for_of4 { strings: $a = /ab+/ $b = "aa" condition: for any of ($a, $b) : ( ! > 1 ) }',
    'rule c_for_i { strings: $a = "abc" condition: for any i in (1..#a) : ( @a[i] % 2 == 0 ) }',
    'rule c_for_all_i { strings: $a = "Microsoft" condition: for all i in (1..#a) : ( !a[i] == 9 ) }',
    'rule c_for_x { condition: for any x in (0, 1, 2) : ( uint8(x) == 0x4d ) }',
    'rule c_for_nested { strings: $a = "a" $b = "b" condition: for any i in (1..#a) : ( for any j in (1..#b) : ( @b[j] == @a[i] + 1 ) ) }',
    'rule c_for_range_empty { strings: $a = "zzqqzz" condition: for all i in (1..#a) : ( @a[i] > 0 ) }',
    'rule c_filesize { condition: filesize < 1KB }',
    'rule c_filesize2 { condition: filesize > 1MB }',
    'rule c_filesize0 { condition: filesize == 0 }',
    'rule c_ints { condition: uint16(0) == 0x5A4D }',
    'rule c_ints2 { condition: uint32(uint32(0x3C)) == 0x00004550 }',
    'rule c_ints3 { condition: int8(0) < 0 or uint16be(0) == 0x4d5a or int16be(2) == -28672 }',
    'rule c_ints4 { condition: uint8(filesize - 1) == 0 }',
    'rule c_ints5 { condition: int32(0) != 0 and uint32be(0) & 0xFFFF0000 == 0x4d5a0000 }',
    'rule c_ints_oob { condition: not (uint32(filesize) == 0) }',
    'rule c_arith { strings: $a = "abc" $b = "aa" condition: (#a + #b) * 2 > 3 }',
    'rule c_mod { strings: $a = "abc" condition: #a % 2 == 1 }',
    'rule c_div { strings: $a = "abc" condition: #a \\ 2 >= 1 }',
    'rule c_div0 { strings: $a = "abc" $b = "zzqqzz" condition: #a \\ #b == 1 or $a }',
    'rule c_neg { strings: $a = "abc" condition: -#a < 0 }',
    'rule c_bits { strings: $a = "abc" condition: #a | 1 == 1 or #a & 1 == 1 }',
    'rule c_bits2 { strings: $a = "abc" condition: (#a ^ 5) > 2 and (#a << 2) >= 4 and ~#a != 0 and #a >> 1 < 1000 }',
    'rule c_prec { condition: 1 + 2 * 3 == 7 and 10 - 2 - 3 == 5 and 2 << 1 + 1 == 8 and 7 \\ 2 == 3 }',
    'rule c_prec2 { condition: 1 | 2 ^ 3 & 4 == 3 }',
    'rule c_literals { condition: 0x10 == 16 and 0o20 == 16 and 1KB == 1024 and 1MB == 1048576 }',
    'rule c_bool { condition: true and not false }',
    'rule c_false { condition: false }',
    'rule c_str_ops { condition: "abc" contains "b" and "ABC" icontains "b" and "abc" startswith "ab" and "abc" iendswith "BC" and "abc" iequals "ABC" }',
    'rule c_str_ops2 { condition: "abc" matches /B/i and not ("abc" matches /d/) and "a" != "b" and "abc" == "abc" }',
    'rule c_defined { strings: $a = "abc" condition: defined @a[1] and not defined @a[1000000] }',
    'rule c_undef { strings: $a = "abc" condition: not (@a[1000000] > 0) }',
    'rule c_undef2 { strings: $a = "abc" condition: @a[1000000] > 0 or $a }',
    'rule c_entry { condition: entrypoint == 0 or true }',
    'rule c_idx0 { strings: $a = "abc" condition: @a[0] == 0 or $a }',
    'rule c_in_empty { strings: $a = "abc" condition: $a in (0..0) or $a }',
    'rule c_at_end { strings: $a = "a" condition: $a at filesize - 1 }',
    'rule c_int_bool { condition: filesize }',
    'rule c_not_str { strings: $a = "zzqqzz" condition: not $a }',
    'rule c_count0 { strings: $a = "zzqqzz" condition: #a == 0 }',
    # ---- rule structure
    r'rule m_meta { meta: author = "x\"y" n = 42 neg = -7 big = 9223372036854775807 flag = true off = false hex = "\x41\x42" condition: true }',
    'rule m_meta_dup { meta: a = 1 b = "two" a = "dup" condition: true }',
    r'rule m_meta_bytes { meta: s = "caf\xc3\xa9 \xff end" z = "q\x00z" condition: true }',
    'rule m_tags : tag1 Tag_2 t3 { condition: true }',
    'rule m_tags_str : evil { strings: $a = "Microsoft" condition: $a }',
    'private rule p1 { strings: $a = "Microsoft" condition: $a } rule uses_p1 { condition: p1 }',
    'private rule p2 { condition: true } rule not_p2 { condition: not p2 }',
    'global rule g1 { condition: filesize > 10 } rule after_g1 { condition: true }',
    'global rule g2 { strings: $a = "Microsoft" condition: $a } rule after_g2 { strings: $b = "Windows" condition: $b }',
    'private global rule pg { condition: filesize > 0 } rule after_pg { condition: true }',
    'rule ref_a { strings: $a = "abc" condition: $a } rule ref_b { strings: $b = "aa" condition: $b and ref_a }',
    'rule ref_c { condition: true } rule ref_d { condition: ref_c and not false } rule ref_e { condition: ref_c and ref_d }',
    'rule set_a { condition: filesize > 0 } rule set_b { condition: true } rule set_c { condition: any of (set_a, set_b) }',
    'rule wset_a { condition: false } rule wset_b { condition: true } rule wset_c { condition: 1 of (wset_*) }',
    'global global rule gg { condition: true } rule after_gg { condition: true }',  # yara accepts it
    'rule mix : t { meta: m = 1 strings: $a = "Microsoft" wide ascii $b = { 4D 5A } $c = /kernel3[0-9]/ condition: any of them }',
]

# multi-namespace sources: list of (ns, src)
FIXED_NS = [
    [("ns1", 'rule r { condition: true }'), ("ns2", 'rule r { strings: $a = "Microsoft" condition: $a }')],
    [("ns1", 'global rule g { condition: filesize > 100 } rule r1 { condition: true }'), ("ns2", 'rule r2 { condition: true }')],
    [("a", 'rule x : t1 { meta: v = 1 condition: true }'), ("b", 'private rule x { condition: true } rule y { condition: x }')],
    [("n1", 'rule s { strings: $a = "abc" condition: #a > 1 }'), ("n2", 'rule s { strings: $a = "abc" nocase condition: #a > 1 }'), ("n3", 'rule t { condition: false }')],
]

FIXED_INVALID = [
    'rule i1 { strings: $a = "x" condition: true }',
    'rule i2 { condition: $a }',
    'rule i3 { condition: nosuchrule }',
    'rule i4 { strings: $a = "" condition: $a }',
    'rule i5 { strings: $a = "x" nocase xor condition: $a }',
    'rule i6 { strings: $a = "abc" base64 nocase condition: $a }',
    'rule i7 { strings: $a = "abc" base64 fullword condition: $a }',
    'rule i8 { strings: $a = "abc" base64 xor condition: $a }',
    'rule i9 { strings: $a = "abc" base64("abc") condition: $a }',
    'rule i10 { strings: $a = "abc" xor(256) condition: $a }',
    'rule i11 { strings: $a = "abc" xor(5-2) condition: $a }',
    'rule i12 { strings: $a = "abc" nocase nocase condition: $a }',
    'rule i13 { strings: $a = { 4D 5 } condition: $a }',
    'rule i14 { strings: $a = { 4G } condition: $a }',
    'rule i15 { strings: $a = { [2] 4D } condition: $a }',
    'rule i16 { strings: $a = { 4D [2] } condition: $a }',
    'rule i17 { strings: $a = { 4D [5-2] 5A } condition: $a }',
    'rule i18 { strings: $a = { 4D [0] 5A } condition: $a }',
    'rule i19 { strings: $a = { 4D ( 5A | [2] 90 ) 00 } condition: $a }',
    'rule i20 { strings: $a = { 4D ( 5A | 90 } condition: $a }',
    'rule i21 { strings: $a = { } condition: $a }',
    'rule i22 { strings: $a = { 4D 5A } wide condition: $a }',
    'rule i23 { strings: $a = { 4D 5A } nocase condition: $a }',
    'rule i24 { strings: $a = /abc/ xor condition: $a }',
    'rule i25 { strings: $a = /abc/ base64 condition: $a }',
    'rule i26 { strings: $a = /(abc/ condition: $a }',
    'rule i27 { strings: $a = /a{3,1}/ condition: $a }',
    'rule i28 { strings: $a = /[z-a]/ condition: $a }',
    'rule i29 { strings: $a = // condition: $a }',
    'rule i30 { strings: $a = /abc/x condition: $a }',
    'rule i31 { strings: $a = "x" $a = "y" condition: $a }',
    'rule i32 { condition: true } rule i32 { condition: true }',
    'rule i33 : t t { condition: true }',
    'rule condition { condition: true }',
    'rule i35 { strings: $a = "x" condition: $ }',
    'rule i36 { condition: 1 \\ 0 == 1 }',
    'rule i37 { condition: 1 % 0 == 1 }',
    'rule i38 { strings: $a = "x" condition: any of ($b*) }',
    'rule i39 { condition: any of (zz*) }',
    'rule i40 { strings: $a = "x" condition: #a > "x" }',
    'rule i41 { condition: "a" + 1 == 2 }',
    'rule i42 { condition: }',
    'rule i43 { strings: condition: true }',
    'rule i44 { meta: x = condition: true }',
    'rule i45 { strings: $a = "abc condition: $a }',
    r'rule i46 { strings: $a = "a\qb" condition: $a }',
    r'rule i47 { strings: $a = "\xZZ" condition: $a }',
    'rule i48 { strings: $a = "x" condition: $a at }',
    'rule i49 { strings: $a = "x" condition: for any i in (1..#a) : ( @a[j] > 0 ) }',
    'rule i50 { strings: $a = "x" condition: @a[] > 0 }',
    'rule i51 { condition: foo.bar }',
    'import "nonexistent_module" rule i52 { condition: true }',
    'rule i53 { strings: $a = "x" private private condition: $a }',
    'rule 1abc { condition: true }',
    'rule i56 { strings: $a = "x" condition: $a } }',
    'rule i57 { strings: $a = "x" base64wide("tooshort") condition: $a }',
    'rule i58 { strings: $a = "x" xor(-1) condition: $a }',
    'rule %s { condition: true }' % ("r" * 200),
    'rule i60 { strings: $a = "x" condition: $a and "a" matches /(/ }',
    'rule i61 { strings: $a = { 4D ( 5A | 90 ) [2-] ( 00 | [1-] 01 ) } condition: $a }',
    'rule i62 { strings: $a = "x" condition: $a',
    'rule i63 { strings: $a = "x" fullword fullword condition: $a }',
    'rule i64 { strings: $a = "x" ascii ascii condition: $a }',
    'rule i65 { strings: $a = "x" xor(1) xor(2) condition: $a }',
    'rule i66 { strings: $a = "x" condition: for any of ($a) : ( $a ) and $b }',
    'rule i67 { strings: $a = { 4D ~?? } condition: $a }',
    'rule i68 { strings: $a = { 4D 5A [2-3-4] 00 } condition: $a }',
    'rule i69 { strings: $a = /a/ fullword xor condition: $a }',
    'rule i70 { condition: true and }',
    'rule i71 { strings: $a = "x" condition: #a[1] > 0 }',
    'rule i72 { strings: $a = "abc" base64 base64 condition: $a }',
    'rule i73 { condition: "abc" contains 1 }',
    'rule i74 { strings: $a = /\\/ condition: $a }',
    'rule i75 { strings: $a = "x" condition: all of them of them }',
]


class RuleGen:
    """Random rules built from substrings of the corpus data, so that most of them match."""

    def __init__(self, rng, samples_text, samples_bin):
        self.r = rng
        self.text = samples_text  # list of printable byte strings
        self.bin = samples_bin  # list of binary byte strings (len >= 4)

    def word(self):
        r = self.r.random()
        if r < 0.55:
            return self.r.choice(WORDS)
        s = self.r.choice(self.text)
        a = self.r.randrange(0, max(1, len(s) - 3))
        return s[a:a + self.r.randint(3, 16)]

    # --- strings
    def text_string(self):
        w = self.word()
        mods = []
        R = self.r.random
        if R() < 0.25:
            mods.append("nocase")
        if R() < 0.25:
            mods.append("wide")
            if R() < 0.5:
                mods.append("ascii")
        elif R() < 0.05:
            mods.append("ascii")
        if R() < 0.15:
            mods.append("fullword")
        if R() < 0.14:
            k = self.r.random()
            mods.append("xor" if k < 0.4 else "xor(%d)" % self.r.randrange(256) if k < 0.7 else
                        "xor(%d-%d)" % tuple(sorted((self.r.randrange(256), self.r.randrange(256)))))
        if R() < 0.08:
            mods.append("base64" if R() < 0.7 else "base64(%s)" % ALT)
        if R() < 0.06:
            mods.append("base64wide" if R() < 0.7 else "base64wide(%s)" % ALT)
        if R() < 0.08:
            mods.append("private")
        if any(m.startswith(("xor", "base64")) for m in mods) and R() < 0.9:
            # yara rejects nocase / fullword with xor / base64 and xor with base64: keep a few
            mods = [m for m in mods if m not in ("nocase", "fullword")]
            if any(m.startswith("xor") for m in mods) and any(m.startswith("base64") for m in mods):
                mods = [m for m in mods if not m.startswith("base64")]
        if R() < 0.02 and mods:  # invalid: duplicated modifier
            mods.append(self.r.choice(mods))
        self.r.shuffle(mods)
        return ystr(w) + ("" if not mods else " " + " ".join(mods))

    def hex_string(self):
        s = self.r.choice(self.bin)
        n = self.r.randint(3, min(18, len(s)))
        a = self.r.randrange(0, len(s) - n + 1)
        s = s[a:a + n]
        toks = []
        i = 0
        while i < len(s):
            b = s[i]
            x = self.r.random()
            inner = 0 < i < len(s) - 1
            if x < 0.10:
                toks.append("??")
            elif x < 0.16:
                toks.append(("%X?" % (b >> 4)) if self.r.random() < 0.5 else ("?%X" % (b & 15)))
            elif x < 0.19:
                v = (b + self.r.randint(1, 255)) & 255
                toks.append("~%02X" % v if self.r.random() < 0.7 else ("~%X?" % ((b >> 4) ^ 1)))
            elif x < 0.25:
                alt = "%02X" % self.r.randrange(256)
                if self.r.random() < 0.3:
                    alt += " %02X" % self.r.randrange(256)
                if self.r.random() < 0.2:
                    alt = "( %s | %02X ?? )" % (alt, self.r.randrange(256))
                br = ["%02X" % b, alt]
                self.r.shuffle(br)
                toks.append("( %s )" % " | ".join(br))
            elif x < 0.31 and inner:
                k = self.r.randint(1, min(4, len(s) - 1 - i))
                y = self.r.random()
                if y < 0.4:
                    toks.append("[%d]" % k)
                elif y < 0.8:
                    toks.append("[%d-%d]" % (self.r.randint(max(0, k - 2), k), k + self.r.randint(0, 3)))
                elif y < 0.9:
                    toks.append("[%d-]" % self.r.randint(0, k))
                else:
                    toks.append("[-]")
                i += k
                continue
            else:
                toks.append("%02X" % b)
            i += 1
        if self.r.random() < 0.03:  # invalid ones
            toks.insert(0, self.r.choice(["[2]", "4", "G0", "(", "[3-1]"]))
        return "{ " + " ".join(toks) + " }" + (" private" if self.r.random() < 0.05 else "")

    def regex_string(self):
        s = self.word()
        out = []
        # yara rejects regexps mixing greedy and lazy quantifiers: pick one mode per regex
        mode = self.r.random()
        quants = (["*", "+", "?", "{1,3}", "{2}", "{0,2}", "{1,}", "{,2}"] if mode < 0.85 else
                  ["*?", "+?", "??", "{1,3}?", "{2,}?"] if mode < 0.96 else
                  ["*", "+?", "?", "??"])
        for c in s:
            x = self.r.random()
            ch = chr(c)
            if x < 0.62:
                out.append(rlit(c))
            elif x < 0.72:
                if ch.isdigit():
                    out.append(self.r.choice([r"\d", "[0-9]", r"\w"]))
                elif ch.isalpha():
                    out.append(self.r.choice([r"\w", "[a-z]" if ch.islower() else "[A-Z]", "[a-zA-Z]", "[^0-9]"]))
                elif ch == " ":
                    out.append(self.r.choice([r"\s", " ", "[ \\t]"]))
                else:
                    out.append(r"\W" if not (ch.isalnum() or ch == "_") else rlit(c))
            elif x < 0.77:
                out.append(".")
            else:
                out.append(rlit(c))
            if self.r.random() < 0.12:
                out[-1] = out[-1] + self.r.choice(quants)
        body = "".join(out)
        if self.r.random() < 0.2:
            body = "(%s|%s)" % (body, "".join(rlit(c) for c in self.word()))
        if self.r.random() < 0.1:
            body = r"\b" + body
        if self.r.random() < 0.05:
            body = "^" + body
        if self.r.random() < 0.05:
            body = body + "$"
        flags = ("i" if self.r.random() < 0.15 else "") + ("s" if self.r.random() < 0.1 else "")
        mods = []
        if self.r.random() < 0.1:
            mods.append("nocase")
        if self.r.random() < 0.15:
            mods.append("wide")
            if self.r.random() < 0.5:
                mods.append("ascii")
        if self.r.random() < 0.1:
            mods.append("fullword")
        if self.r.random() < 0.05:
            mods.append("private")
        if self.r.random() < 0.02:
            mods.append(self.r.choice(["xor", "base64"]))  # invalid on regex
        return "/" + body + "/" + flags + ("" if not mods else " " + " ".join(mods))

    # --- conditions
    def cond(self, ids, rules, depth=0):
        R = self.r.random
        ch = self.r.choice
        if not ids:
            ids = []
        if depth > 2 or R() < 0.35:
            return self.leaf(ids, rules)
        x = R()
        if x < 0.4:
            return "(%s and %s)" % (self.cond(ids, rules, depth + 1), self.cond(ids, rules, depth + 1))
        if x < 0.8:
            return "(%s or %s)" % (self.cond(ids, rules, depth + 1), self.cond(ids, rules, depth + 1))
        return "not (%s)" % self.cond(ids, rules, depth + 1)

    def leaf(self, ids, rules):
        R = self.r.random
        ch = self.r.choice
        op = ch(["==", "!=", "<", "<=", ">", ">="])
        n = ch([0, 1, 2, 3, 5, 10])
        if ids and R() < 0.8:
            a = ch(ids)[1:]
            k = R()
            if k < 0.15:
                return "$" + a
            if k < 0.27:
                return "#%s %s %d" % (a, op, n)
            if k < 0.35:
                return "@%s[%d] %s %d" % (a, ch([1, 1, 2, 3]), op, ch([0, 16, 100, 1000, 0x1000, 0x100000]))
            if k < 0.40:
                return "!%s[1] %s %d" % (a, op, ch([1, 3, 5, 9, 16]))
            if k < 0.45:
                return "$%s at %s" % (a, ch(["0", "1", "@%s[1]" % a, "filesize - 9"]))
            if k < 0.52:
                lo = ch([0, 0, 10, 100, 1000])
                return "$%s in (%d..%s)" % (a, lo, ch([str(lo + 100), str(lo + 100000), "filesize"]))
            if k < 0.56:
                return "#%s in (0..%d) %s %d" % (a, ch([100, 10000, 1000000]), op, n)
            if k < 0.70:
                q = ch(["any", "all", "none", "1", "2", "50%"])
                sets = ["them", "($*)", "(%s)" % ", ".join(ids)]
                pre = set(i[:2] for i in ids)
                sets += ["(%s*)" % p for p in pre]
                tail = ch(["", "", "", " in (0..%d)" % ch([100, 100000]), " at 0"])
                return "%s of %s%s" % (q, ch(sets), tail)
            if k < 0.80:
                q = ch(["any", "all", "1", "2"])
                body = ch(["$", "# > 1", "@ > 10", "! >= 3", "$ in (0..100000)", "$ at 0", "# == 1"])
                return "for %s of %s : ( %s )" % (q, ch(["them", "(%s)" % ", ".join(ids)]), body)
            if k < 0.88:
                return "for %s i in (1..#%s) : ( %s )" % (ch(["any", "all"]), a, ch([
                    "@%s[i] %% 2 == 0" % a, "!%s[i] > 3" % a, "@%s[i] + !%s[i] <= filesize" % (a, a), "@%s[i] > 100" % a]))
            if k < 0.94:
                return "(#%s %s #%s) %s %d" % (a, ch(["+", "-", "*", "\\", "%", "|", "&", "^", "<<", ">>"]), ch(ids)[1:], op, n)
            return "%s of (%s)" % (ch(["any", "all"]), ", ".join(ids))
        k = R()
        if rules and k < 0.25:
            return ch(rules)
        if k < 0.45:
            return "filesize %s %s" % (op, ch(["0", "1", "100", "1KB", "64KB", "1MB", "4MB"]))
        if k < 0.70:
            fn = ch(["uint8", "uint16", "uint32", "int8", "int16", "int32", "uint16be", "uint32be", "int32be"])
            v = ch(["0", "0x5A4D", "0x4D", "0x905A4D", "-1", "0x4D5A"])
            return "%s(%s) %s %s" % (fn, ch(["0", "1", "2", "4", "0x3C", "filesize - 4"]), op, v)
        if k < 0.80:
            return ch(["true", "false"])
        return ch(['"abc" contains "b"', '"ABC" icontains "x"', '"abc" matches /b+c$/', '"hello" startswith "he"',
                   '"x" iequals "X"', '"abc" endswith "bc"'])

    def rule(self, idx, prior):
        R = self.r.random
        name = "rnd%d" % idx
        head = ""
        if R() < 0.08:
            head += "private "
        if R() < 0.04:
            head += "global "
        tags = ""
        if R() < 0.2:
            tags = " : " + " ".join(self.r.sample(["evil", "t1", "T_2", "apt", "x"], self.r.randint(1, 3)))
        meta = ""
        if R() < 0.2:
            items = []
            for j in range(self.r.randint(1, 3)):
                v = self.r.choice(['"%s"' % self.r.choice(["abc", "x y", "\\x41\\n"]), str(self.r.randint(-100, 10 ** 6)), "true", "false"])
                items.append("m%d = %s" % (j, v))
            meta = " meta: " + " ".join(items)
        ns = self.r.choice([0, 1, 1, 2, 2, 3, 4])
        strs = []
        for j in range(ns):
            k = self.r.random()
            ident = "$%s%d" % (self.r.choice("abs"), j)
            if k < 0.45:
                strs.append((ident, self.text_string()))
            elif k < 0.75:
                strs.append((ident, self.hex_string()))
            else:
                strs.append((ident, self.regex_string()))
        ids = [i for i, _ in strs]
        cond = self.cond(ids, prior)
        # make sure every string is referenced (except occasionally, which must fail to compile)
        wild = re.findall(r"\$(\w*)\*", cond)  # ($a*) / ($*) sets
        missing = [i for i in ids if not re.search(r"[$#@!]%s\b" % re.escape(i[1:]), cond)
                   and not any(i[1:].startswith(w) for w in wild)]
        if "them" in cond:
            missing = []
        if missing and R() < 0.95:
            cond = "(%s) or (any of (%s) and filesize == 0)" % (cond, ", ".join(missing)) if R() < 0.5 else \
                "(%s) and (any of (%s) or true)" % (cond, ", ".join(missing))
        body = ""
        if strs:
            body = " strings: " + " ".join("%s = %s" % s for s in strs)
        return "%srule %s%s {%s%s condition: %s }" % (head, name, tags, meta, body, cond)


# ---------------------------------------------------------------------------------------
# oracle / records
# ---------------------------------------------------------------------------------------

def clean(s):
    return re.sub(r"[\t\r\n]", " ", s)


def meta_canon(items):
    """yara-python exposes meta as a dict: duplicated keys keep the first position and the last
    value; strings are decoded as UTF-8 with errors ignored."""
    d = {}
    for k, v in items:
        d[k] = v
    out = []
    for k, v in d.items():
        if isinstance(v, bool):
            out.append("%s=b:%d" % (k, v))
        elif isinstance(v, int):
            out.append("%s=i:%d" % (k, v))
        elif isinstance(v, bytes):
            out.append("%s=s:%s" % (k, v.decode("utf-8", "ignore").encode("utf-8").hex()))
        else:
            out.append("%s=s:%s" % (k, str(v).encode("utf-8").hex()))
    return " ".join(out)


def py_case(cid, srcs, datas, timeout):
    """Records for one case (list of str) or None when yara-python timed out."""
    try:
        rules = yara.compile(sources=collections.OrderedDict(srcs))
    except Exception as e:  # yara.SyntaxError, yara.Error
        return ["%d\tCOMPILE\tERR\t%s" % (cid, clean(str(e)))]
    recs = ["%d\tCOMPILE\tOK" % cid]
    for did, buf in datas:
        try:
            ms = rules.match(data=buf, timeout=timeout)
        except yara.TimeoutError:
            return None
        for m in ms:
            recs.append("%d\t%s\tM\t%s\t%s\t%s\t%s" % (cid, did, m.namespace, m.rule, " ".join(m.tags), meta_canon(m.meta.items())))
            for s in m.strings:
                h = hashlib.md5()
                first = []
                for k, i in enumerate(s.instances):
                    line = "%d:%d:%d:%s" % (i.offset, i.matched_length, i.xor_key, i.matched_data.hex())
                    h.update(line.encode())
                    h.update(b"\n")
                    if k < FIRST:
                        first.append(line)
                recs.append("%d\t%s\tS\t%s\t%s\t%s\t%d\t%s\t%s" % (cid, did, m.namespace, m.rule, s.identifier,
                                                                 len(s.instances), h.hexdigest(), " ".join(first)))
    return recs


def rust_canon(rec):
    """Apply the yara-python binding conventions (meta dict / utf-8) to a rust M record."""
    f = rec.split("\t")
    if len(f) >= 7 and f[2] == "M":
        items = []
        for it in f[6].split(" ") if f[6] else []:
            k, _, tv = it.partition("=")
            t, _, v = tv.partition(":")
            items.append((k, int(v) if t == "i" else bool(int(v)) if t == "b" else bytes.fromhex(v)))
        f[6] = meta_canon(items)
        return "\t".join(f)
    return rec


# ---------------------------------------------------------------------------------------
# rust driver
# ---------------------------------------------------------------------------------------

def build_driver(profile):
    r = subprocess.run(["cargo", "test", "--profile", profile, "--bin", "vol", "--no-run", "--message-format=json"],
                       cwd=ROOT, capture_output=True, text=True)
    exe = None
    for line in r.stdout.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        if j.get("reason") == "compiler-artifact" and j.get("executable") and j.get("profile", {}).get("test"):
            exe = j["executable"]
    if r.returncode != 0 or not exe:
        print(r.stderr[-4000:])
        sys.exit(2)
    return exe


def parse_out(path):
    recs = collections.defaultdict(list)
    status = {}
    began = []
    if not os.path.exists(path):
        return recs, status, began
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            f = line.split("\t")
            try:
                cid = int(f[0])
            except ValueError:
                continue
            if len(f) >= 2 and f[1] == "BEGIN":
                began.append(cid)
            elif len(f) >= 2 and f[1] in ("DONE", "PANIC", "TIMEOUT"):
                status[cid] = f[1] + ("" if len(f) < 3 else ": " + f[2])
            else:
                recs[cid].append(line)
    return recs, status, began


def run_rust(exe, cpath, opath, ids, timeout, mem, use_limit):
    if os.path.exists(opath):
        os.remove(opath)
    start = 0
    crashes = {}
    last_stderr = ""
    while True:
        env = dict(os.environ, RSVOL_YARA_CASES=cpath, RSVOL_YARA_OUT=opath, RSVOL_YARA_START=str(start),
                   RSVOL_YARA_TIMEOUT=str(timeout))
        cmd = [exe, "yara::benchdrv::yara_rules_difftest_driver", "--exact", "--ignored", "--test-threads=1", "-q"]
        if use_limit:
            cmd = [LIMIT, "-m", mem] + cmd
        r = subprocess.run(cmd, env=env, capture_output=True, text=True)
        last_stderr = (r.stdout + r.stderr)[-3000:]
        recs, status, began = parse_out(opath)
        if r.returncode == 0:
            break
        began = [c for c in began if c >= start]
        if not began:
            print("rust driver failed before running a case (rc=%d):\n%s" % (r.returncode, last_stderr))
            break
        bad = began[-1]  # the case the driver was in when it died (TIMEOUT records itself)
        if bad not in status:
            crashes[bad] = "CRASH rc=%d%s" % (r.returncode, " (killed: memory cap %s?)" % mem if r.returncode in (137, 143, -9, -15) else "")
            print("rust driver died in case %d (rc=%d), resuming after it" % (bad, r.returncode))
        later = [i for i in ids if i > bad]
        if not later:
            break
        start = later[0]
    recs, status, began = parse_out(opath)
    for c, s in crashes.items():
        status.setdefault(c, s)
    return recs, status


# ---------------------------------------------------------------------------------------
# comparison
# ---------------------------------------------------------------------------------------

def split_recs(recs):
    """-> compile ('OK'|'ERR', msg), {data: [(kind, key, rec_fields)]}"""
    comp = None
    per = collections.OrderedDict()
    for r in recs:
        f = r.split("\t")
        if f[1] == "COMPILE":
            comp = (f[2], f[3] if len(f) > 3 else "")
            continue
        per.setdefault(f[1], []).append(f)
    return comp, per


def inst_list(s):
    return [x.split(":") for x in s.split(" ")] if s else []


def compare_case(cid, py, rs, status, info):
    """-> list of (category, detail) mismatches."""
    out = []
    st = status.get(cid)
    if st is None:
        return [("rust: no result (driver died?)", "")]
    if not st.startswith("DONE"):
        return [("rust: " + st.split(":")[0].split(" ")[0], st)]
    pc, pper = split_recs(py)
    rc, rper = split_recs([rust_canon(x) for x in rs])
    if pc is None or rc is None:
        return [("harness: missing COMPILE record", "py=%s rs=%s" % (pc, rc))]
    if pc[0] != rc[0]:
        if pc[0] == "OK":
            return [("compile: rust rejects valid rule", "rust error: %s" % rc[1])]
        return [("compile: rust accepts invalid rule", "yara error: %s" % pc[1])]
    if pc[0] == "ERR":
        return []
    for did in info["datas"]:
        pm = [f for f in pper.get(did, [])]
        rm = [f for f in rper.get(did, [])]
        prules = [(f[3], f[4]) for f in pm if f[2] == "M"]
        rrules = [(f[3], f[4]) for f in rm if f[2] == "M"]
        for k in prules:
            if k not in rrules:
                out.append(("rule: missing match", "data=%s rule=%s:%s" % (did, k[0], k[1])))
        for k in rrules:
            if k not in prules:
                out.append(("rule: extra match", "data=%s rule=%s:%s" % (did, k[0], k[1])))
        common = [k for k in prules if k in rrules]
        if common != [k for k in rrules if k in prules]:
            out.append(("rule: order", "data=%s py=%s rs=%s" % (did, prules, rrules)))
        pM = {(f[3], f[4]): f for f in pm if f[2] == "M"}
        rM = {(f[3], f[4]): f for f in rm if f[2] == "M"}
        pS = collections.OrderedDict()
        rS = collections.OrderedDict()
        for f in pm:
            if f[2] == "S":
                pS.setdefault((f[3], f[4]), []).append(f)
        for f in rm:
            if f[2] == "S":
                rS.setdefault((f[3], f[4]), []).append(f)
        for k in common:
            if pM[k][5] != rM[k][5]:
                out.append(("rule: tags", "data=%s rule=%s py=[%s] rs=[%s]" % (did, k[1], pM[k][5], rM[k][5])))
            if pM[k][6] != rM[k][6]:
                out.append(("rule: meta", "data=%s rule=%s py=[%s] rs=[%s]" % (did, k[1], pM[k][6], rM[k][6])))
            ps = pS.get(k, [])
            rs_ = rS.get(k, [])

            def keyed(lst):  # anonymous strings are all "$": pair the n-th occurrences
                seen = collections.Counter()
                out = []
                for f in lst:
                    seen[f[5]] += 1
                    out.append(f[5] if seen[f[5]] == 1 else "%s#%d" % (f[5], seen[f[5]]))
                return out
            pids = keyed(ps)
            rids = keyed(rs_)
            for i, f in zip(pids, ps):
                if i not in rids:
                    out.append(("string: missing StringMatch", "data=%s rule=%s string=%s (py %s instances)" % (
                        did, k[1], i, f[6])))
            for i, f in zip(rids, rs_):
                if i not in pids:
                    out.append(("string: extra StringMatch", "data=%s rule=%s string=%s (rs %s instances)" % (
                        did, k[1], i, f[6])))
            if [i for i in pids if i in rids] != [i for i in rids if i in pids]:
                out.append(("string: order", "data=%s rule=%s py=%s rs=%s" % (did, k[1], pids, rids)))
            rd = dict(zip(rids, rs_))
            for key, f in zip(pids, ps):
                g = rd.get(key)
                if g is None or (f[6], f[7]) == (g[6], g[7]):
                    continue
                pc_, rc_ = int(f[6]), int(g[6])
                pi, ri = inst_list(f[8] if len(f) > 8 else ""), inst_list(g[8] if len(g) > 8 else "")
                where = "data=%s rule=%s string=%s" % (did, k[1], f[5])
                first = None
                for j in range(min(len(pi), len(ri))):
                    if pi[j] != ri[j]:
                        first = j
                        break
                if first is not None:
                    a, b = pi[first], ri[first]
                    if a[0] != b[0]:
                        cat = "instances: offsets"
                    elif a[1] != b[1]:
                        cat = "instances: matched_length"
                    elif a[2] != b[2]:
                        cat = "instances: xor_key"
                    else:
                        cat = "instances: matched_data"
                    out.append((cat, "%s #%d py=%s rs=%s (counts py=%d rs=%d)" % (where, first, ":".join(a), ":".join(b), pc_, rc_)))
                elif pc_ != rc_:
                    cat = "instances: missing (rust finds fewer)" if rc_ < pc_ else "instances: extra (rust finds more)"
                    nxt = pi[len(ri)] if len(pi) > len(ri) else ri[len(pi)] if len(ri) > len(pi) else None
                    out.append((cat, "%s counts py=%d rs=%d%s" % (where, pc_, rc_, "" if nxt is None else " first-unmatched=%s" % ":".join(nxt))))
                else:
                    out.append(("instances: differ beyond first %d" % FIRST, "%s count=%d" % (where, pc_)))
    return out


def selftest_output(expected):
    """Harness self-test: feed the oracle's records back as the "rust" output, with a known
    perturbation injected in every 7th case (checks parsing, canonicalization, categories)."""
    got, status = {}, {}
    k = 0
    for cid, recs in expected.items():
        recs = list(recs)
        status[cid] = "DONE"
        has_s = [i for i, r in enumerate(recs) if r.split("\t")[2:3] == ["S"] and r.split("\t")[6] != "0"]
        has_m = [i for i, r in enumerate(recs) if r.split("\t")[2:3] == ["M"]]
        if cid % 7 == 0 and (has_s or has_m or recs[0].endswith("OK")):
            kind = k % 6
            k += 1
            if kind == 0 and has_s:  # one more instance than python
                f = recs[has_s[0]].split("\t")
                f[6] = str(int(f[6]) + 1)
                f[7] = "0" * 32
                recs[has_s[0]] = "\t".join(f)
            elif kind == 1 and has_s:  # wrong length of the first instance
                f = recs[has_s[0]].split("\t")
                inst = f[8].split(" ")
                a = inst[0].split(":")
                a[1] = str(int(a[1]) + 1)
                inst[0] = ":".join(a)
                f[8] = " ".join(inst)
                f[7] = "1" * 32
                recs[has_s[0]] = "\t".join(f)
            elif kind == 2 and has_m:  # rule missing
                key = recs[has_m[0]].split("\t")[1:5]
                recs = [r for r in recs if not (r.split("\t")[1:2] == key[:1] and r.split("\t")[3:5] == key[2:4])]
            elif kind == 3 and has_m:  # tags differ
                f = recs[has_m[0]].split("\t")
                f[5] = (f[5] + " extra").strip()
                recs[has_m[0]] = "\t".join(f)
            elif kind == 4:  # compile disagreement
                recs = ["%d\tCOMPILE\tERR\tselftest" % cid]
            else:
                status[cid] = "PANIC: selftest"
        got[cid] = recs
    return got, status


# ---------------------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=600, help="number of random cases (on top of the fixed ones)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--slices", type=int, default=6, help="memory slices of the image")
    ap.add_argument("--img", default="/home/user/cbc2/task2/memory-dirty.raw")
    ap.add_argument("--no-memory", action="store_true", help="synthetic data only")
    ap.add_argument("--keep", default=None)
    ap.add_argument("--profile", default="fast")
    ap.add_argument("--show", type=int, default=6, help="examples per category")
    ap.add_argument("--timeout", type=float, default=20.0, help="per case, both sides")
    ap.add_argument("--rust-mem", default="4G")
    ap.add_argument("--no-limit", action="store_true", help="run the rust driver without limit.sh")
    ap.add_argument("--case", default="", help="only these case ids; prints all records side by side")
    ap.add_argument("--selftest", action="store_true", help="check the harness itself (no rust run)")
    args = ap.parse_args()
    rng = random.Random(args.seed)
    t_start = time.time()

    syn = synthetic(random.Random(args.seed ^ 0x5eed))
    mems, zeros = ([], []) if args.no_memory or not os.path.exists(args.img) else memory_slices(random.Random(args.seed), args.img, args.slices)
    tmp = args.keep or tempfile.mkdtemp(prefix="yara_diff_")
    os.makedirs(tmp, exist_ok=True)

    # vocabulary for the random rules: printable runs / binary snippets from the data
    texts, bins = [], []
    for name, buf in syn.items():
        texts += re.findall(rb"[\x20-\x7e]{4,40}", buf)
        bins += [buf[i:i + 24] for i in range(0, max(0, len(buf) - 24), 97)]
    for name, off, ln in mems:
        buf = read_slice(args.img, off, ln)
        t = re.findall(rb"[\x20-\x7e]{6,40}", buf)
        texts += rng.sample(t, min(len(t), 400))
        for _ in range(200):
            p = rng.randrange(0, max(1, len(buf) - 32))
            b = buf[p:p + 24]
            if b.count(0) < 12:
                bins.append(b)
        del buf
    texts = [t for t in texts if len(t) >= 3] or [b"abc"]
    bins = [b for b in bins if len(b) >= 4] or [b"MZ\x90\x00"]

    # cases: (srcs, datas, label)
    cases = []
    syn_ids = list(syn.keys())
    mem_ids = [m[0] for m in mems]

    def datas_for(i, heavy=False):
        d = list(syn_ids)
        if mem_ids:
            d.append(mem_ids[i % len(mem_ids)])
        if zeros and (heavy or i % 10 == 0):
            d.append("zeros")
        return d

    for s in FIXED_VALID:
        cases.append(([("default", s)], datas_for(len(cases), heavy=s.startswith(("rule h_cap", "rule h_many", "rule t_nul"))), "fixed"))
    for srcs in FIXED_NS:
        cases.append((srcs, datas_for(len(cases)), "fixed-ns"))
    for s in FIXED_INVALID:
        cases.append(([("default", s)], ["one"], "invalid"))
    gen = RuleGen(rng, texts, bins)
    for i in range(args.n):
        nr = rng.choice([1, 1, 1, 2, 3])
        rules = []
        names = []
        for j in range(nr):
            rules.append(gen.rule(len(cases) * 10 + j, names))
            names.append("rnd%d" % (len(cases) * 10 + j))
        if rng.random() < 0.08 and nr > 1:
            srcs = [("ns%d" % j, r) for j, r in enumerate(rules)]
        else:
            srcs = [("default", "\n".join(rules))]
        cases.append((srcs, datas_for(len(cases)), "random"))

    only = set(int(x) for x in args.case.split(",") if x)
    # data
    data_bufs = collections.OrderedDict(syn)
    specs = []
    for name, buf in syn.items():
        specs.append("D\t%s\t%s" % (name, buf.hex()))
        if args.keep:
            with open(os.path.join(tmp, "data_%s.bin" % name), "wb") as fh:
                fh.write(buf)
    mem_desc = {}
    for name, off, ln in mems + zeros:
        specs.append("F\t%s\t%s\t%d\t%d" % (name, args.img, off, ln))
        mem_desc[name] = "%s@%#x+%d" % (os.path.basename(args.img), off, ln)

    # python oracle (one process, slices loaded one at a time... cached: a few MB each)
    expected = {}
    skipped = 0
    mem_cache = {}
    t0 = time.time()
    for cid, (srcs, datas, label) in enumerate(cases):
        if only and cid not in only:
            continue
        items = []
        for d in datas:
            if d in data_bufs:
                items.append((d, data_bufs[d]))
            else:
                if d not in mem_cache:
                    off, ln = [(o, l) for n, o, l in mems + zeros if n == d][0]
                    mem_cache[d] = read_slice(args.img, off, ln)
                items.append((d, mem_cache[d]))
        recs = py_case(cid, srcs, items, int(args.timeout))
        if recs is None:
            skipped += 1
            if only or skipped <= 3:
                print("python timeout (> %ds), case %d skipped: %s" % (args.timeout, cid, " || ".join(x for _, x in srcs)))
            continue
        expected[cid] = recs
    t_py = time.time() - t0

    cpath = os.path.join(tmp, "cases.tsv")
    opath = os.path.join(tmp, "rust_out.tsv")
    with open(cpath, "w") as fh:
        for s in specs:
            fh.write(s + "\n")
        for cid, (srcs, datas, label) in enumerate(cases):
            if cid not in expected:
                continue
            fh.write("C\t%d\t%s\t%s\n" % (cid, ",".join("%s:%s" % (ns, s.encode().hex()) for ns, s in srcs), ",".join(datas)))
    with open(os.path.join(tmp, "expected.tsv"), "w") as fh:
        for cid in sorted(expected):
            fh.write("\n".join(expected[cid]) + "\n")

    t0 = time.time()
    if args.selftest:
        got, status = selftest_output(expected)
    else:
        exe = build_driver(args.profile)
        got, status = run_rust(exe, cpath, opath, sorted(expected), args.timeout, args.rust_mem, not args.no_limit)
    t_rs = time.time() - t0

    # compare
    cats = collections.OrderedDict()
    n_ok = 0
    n_valid = sum(1 for c in expected.values() if c[0].endswith("\tOK"))
    for cid in sorted(expected):
        srcs, datas, label = cases[cid]
        mm = compare_case(cid, expected[cid], got.get(cid, []), status, {"datas": datas})
        if only:
            print("== case %d (%s)" % (cid, label))
            for ns, s in srcs:
                print("   [%s] %s" % (ns, s))
            print("   python:\n      " + "\n      ".join(expected[cid]))
            print("   rust (%s):\n      %s" % (status.get(cid), "\n      ".join(got.get(cid, []))))
        if not mm:
            n_ok += 1
            continue
        for cat, detail in mm:
            cats.setdefault(cat, []).append((cid, detail))
    print("\n### YARA differential: rsvol vs yara-python %s (libyara %s)" % (yara.__version__, yara.YARA_VERSION))
    print("cases=%d (fixed valid %d, namespaced %d, invalid %d, random %d; valid per yara: %d) data: %d synthetic + %d memory slices%s" % (
        len(expected), len(FIXED_VALID), len(FIXED_NS), len(FIXED_INVALID), args.n, n_valid, len(syn), len(mems),
        " + zeros" if zeros else ""))
    print("agree=%d disagree=%d  python-timeouts-skipped=%d  (python %.1fs, rust %.1fs, total %.1fs, dir %s)" % (
        n_ok, len(expected) - n_ok, skipped, t_py, t_rs, time.time() - t_start, tmp))
    if not cats:
        print("no mismatches")
        return 0
    print("\n| category | cases |\n|---|---:|")
    for cat, lst in sorted(cats.items(), key=lambda kv: -len(set(c for c, _ in kv[1]))):
        print("| %s | %d |" % (cat, len(set(c for c, _ in lst))))
    for cat, lst in sorted(cats.items(), key=lambda kv: -len(set(c for c, _ in kv[1]))):
        print("\n#### %s (%d cases)" % (cat, len(set(c for c, _ in lst))))
        seen = set()
        shown = 0
        # prefer the shortest sources as repros
        for cid, detail in sorted(lst, key=lambda x: sum(len(s) for _, s in cases[x[0]][0])):
            if cid in seen or shown >= args.show:
                continue
            seen.add(cid)
            shown += 1
            srcs = cases[cid][0]
            src = " || ".join(("[%s] " % ns if ns != "default" else "") + s for ns, s in srcs)
            m = re.search(r"data=(\S+)", detail)
            dd = ""
            if m:
                d = m.group(1)
                dd = " data=%s" % (mem_desc.get(d, "synthetic:%s" % d))
            print("- case %d%s: %s\n    repro: %s" % (cid, dd, detail, src))
    return 1


if __name__ == "__main__":
    sys.exit(main())
