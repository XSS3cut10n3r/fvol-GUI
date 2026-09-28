#!/usr/bin/env python3
"""Golden PNGs for src/codecs/png.rs, written by Pillow exactly like linux.graphics.fbdev does
(Image.new("RGBA") + putpixel for every pixel + save(BytesIO, "PNG")). Pillow 12.3.0, zlib 1.3.2.

    /home/user/fvol/bench/venv/bin/python tests/fixtures/codecs/gen_png.py
"""
import io
import os

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))


def lcg_bytes(n, seed):  # mirrors png.rs tests::lcg_bytes
    s = seed
    out = bytearray(n)
    for i in range(n):
        s = (s * 1103515245 + 12345) & 0xFFFFFFFF
        out[i] = (s >> 16) & 255
    return bytes(out)


def pattern(w, h):  # mirrors png.rs tests::pattern
    out = bytearray(w * h * 4)
    for y in range(h):
        for x in range(w):
            o = (y * w + x) * 4
            v = 255 if (x // 3 + y // 5) % 7 == 0 else 0
            out[o:o + 4] = bytes(((x * 5 + y) & 255, v, (x * y) & 255, 255 - (y & 15)))
    return bytes(out)


def png(w, h, data):
    im = Image.new("RGBA", (w, h))
    i = 0
    for y in range(h):
        for x in range(w):
            im.putpixel((x, y), tuple(data[i:i + 4]))
            i += 4
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue()


for (w, h, seed) in [(1, 1, 1), (3, 7, 2), (17, 5, 3)]:
    with open(os.path.join(HERE, f"png_lcg_{w}x{h}_s{seed}.png"), "wb") as f:
        f.write(png(w, h, lcg_bytes(w * h * 4, seed)))
for (w, h) in [(16, 16)]:
    with open(os.path.join(HERE, f"png_pattern_{w}x{h}.png"), "wb") as f:
        f.write(png(w, h, pattern(w, h)))

# Larger images are checked by length + CRC-32 only (png.rs tests::golden_len_crc).
import zlib  # noqa: E402

p = png(300, 200, lcg_bytes(300 * 200 * 4, 4))
print("lcg 300x200 s4", len(p), hex(zlib.crc32(p)))
p = png(333, 250, pattern(333, 250))
print("pattern 333x250", len(p), hex(zlib.crc32(p)))
