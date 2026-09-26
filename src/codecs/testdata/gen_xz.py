#!/usr/bin/env python3
"""Regenerates the xz / lzma test fixtures in this directory (needs xz(1) and python's lzma).

    python3 src/codecs/testdata/gen_xz.py
"""
import lzma
import os
import random
import struct
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def w(name, data):
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(data)


def xz(data, *args):
    return subprocess.run(["xz", "-c", *args], input=data, stdout=subprocess.PIPE, check=True).stdout


# Deterministic ISF-like JSON text (~6 KB).
lines = ['{"metadata": {"format": "6.2.0", "producer": {"name": "rsvol-test"}},', '"user_types": {']
for i in range(60):
    lines.append(f'  "_STRUCT_{i:03d}": {{"size": {8 * (i % 13 + 1)}, "fields": {{"Flink": {{"offset": {i * 8}, '
                 f'"type": {{"kind": "pointer", "subtype": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}}}}}, "kind": "struct"}},')
lines.append('"_END": {}}}')
text = ("\n".join(lines) + "\n").encode()
w("text.json", text)

rnd = random.Random(1234)
noise = bytes(rnd.getrandbits(8) for _ in range(3000))
w("noise.bin", noise)

# x86-like code: CALL/JMP rel32 opcodes with small relative targets among other bytes.
code = bytearray()
for i in range(700):
    op = rnd.choice([0xE8, 0xE9, 0x90, 0x48, 0x8B, 0xC3, 0xE8])
    code.append(op)
    if op in (0xE8, 0xE9):
        code += struct.pack("<i", rnd.randint(-5000, 5000))
w("x86.bin", bytes(code))

# Slowly varying samples (delta filter's use case).
samples = bytearray()
v = [0, 0, 0]
for i in range(1500):
    for c in range(3):
        v[c] = (v[c] + rnd.randint(-3, 3)) & 0xFF
        samples.append(v[c])
w("samples.bin", bytes(samples))

w("empty.xz", xz(b""))
w("text.xz", xz(text, "-6"))
w("text.blocks.xz", xz(text, "-T1", "--block-size=1000"))
w("text.mt.xz", xz(text, "-T2", "--block-size=1000"))  # sizes stored in block headers
w("text.none.xz", xz(text, "--check=none"))
w("text.crc32.xz", xz(text, "--check=crc32"))
w("text.sha256.xz", xz(text, "--check=sha256"))
w("text.props.xz", xz(text, "--lzma2=preset=6,lc=1,lp=3,pb=1"))
w("text.e9.xz", xz(text, "-9e"))
w("noise.xz", xz(noise, "-6"))  # incompressible -> uncompressed LZMA2 chunks
w("x86.bin.xz", xz(bytes(code), "--x86", "--lzma2=preset=6"))
w("samples.bin.xz", xz(bytes(samples), "--delta=dist=3", "--lzma2=preset=6"))
# Two streams with stream padding in between.
w("multi.xz", xz(text, "-6") + b"\0" * 8 + xz(noise, "-1"))

# Legacy .lzma: unknown size + end marker, and the same stream with the size filled in.
alone = xz(text, "--format=lzma", "-6")
w("text.lzma", alone)
w("text.sized.lzma", alone[:5] + struct.pack("<Q", len(text)) + alone[13:])
# a 4 KiB dictionary over 4 copies of the text: the streaming decoder's window slides
w("text4.d4k.lzma", xz(text * 4, "--format=lzma", "--lzma1=preset=6,dict=4KiB"))

# Raw LZMA2 and raw LZMA1 (as used by ZIP method 14).
w("text.lzma2", lzma.compress(text, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "preset": 6}]))
raw1 = lzma.compress(text, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "preset": 6}])
w("text.lzma1", raw1)
print("props byte for text.lzma1:", (2 * 5 + 0) * 9 + 3)
