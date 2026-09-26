#!/usr/bin/env python3
"""Pillow oracle corpus for src/codecs/png.rs (png_rgba_pillow).

    /home/user/rs-vol/bench/venv/bin/python bench/refbench/png_pillow_oracle.py OUTDIR [--quick]
    PNG_CORPUS=OUTDIR cargo test --profile fast png_pillow_corpus -- --ignored --nocapture

For every synthetic RGBA image writes OUTDIR/NAME_WxH.rgba (raw pixels) and OUTDIR/NAME_WxH.png,
the latter produced exactly the way linux.graphics.fbdev does it:
Image.new("RGBA", (w, h)); putpixel((x, y), (r, g, b, a)) for every pixel; save(BytesIO, "PNG").
"""
import io
import os
import random
import sys

from PIL import Image


def pillow_png(w, h, data):
    im = Image.new("RGBA", (w, h))
    put = im.putpixel
    i = 0
    for y in range(h):
        for x in range(w):
            put((x, y), (data[i], data[i + 1], data[i + 2], data[i + 3]))
            i += 4
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue()


def gen(kind, w, h, seed):
    r = random.Random(seed)
    n = w * h * 4
    if kind == "noise":
        return r.randbytes(n)
    if kind == "zero":
        return bytes(n)
    if kind == "black":
        return bytes([0, 0, 0, 255]) * (w * h)
    if kind == "solid":
        return bytes([r.randrange(256) for _ in range(4)]) * (w * h)
    out = bytearray(n)
    if kind == "gradient":
        for y in range(h):
            for x in range(w):
                o = (y * w + x) * 4
                out[o:o + 4] = bytes((x * 255 // max(w - 1, 1), y * 255 // max(h - 1, 1), (x + y) & 255, 255))
        return bytes(out)
    if kind == "alpha":
        for y in range(h):
            for x in range(w):
                o = (y * w + x) * 4
                out[o:o + 4] = bytes(((x * 7) & 255, (y * 3) & 255, 128, (x ^ y) & 255))
        return bytes(out)
    if kind == "rgb565":  # 16bpp framebuffer channels are 5/6/5-bit values, not rescaled
        for i in range(w * h):
            v = r.getrandbits(16) if r.random() < 0.3 else 0x1234
            out[i * 4:i * 4 + 4] = bytes((v >> 11, (v >> 5) & 63, v & 31, 255))
        return bytes(out)
    if kind == "duprows":
        row = r.randbytes(w * 4)
        for y in range(h):
            if r.random() < 0.1:
                row = bytearray(row)
                row[r.randrange(len(row))] = r.randrange(256)
                row = bytes(row)
            out[y * w * 4:(y + 1) * w * 4] = row
        return bytes(out)
    if kind in ("text", "desktop"):
        bg = (0x20, 0x24, 0x28, 255) if kind == "text" else (0x3a, 0x6e, 0xa5, 255)
        fg = (0xd0, 0xd0, 0xd0, 255)
        out[:] = bytes(bg) * (w * h)
        if kind == "desktop":
            # title bars, window bodies with gradients, a noisy "photo"
            for _ in range(max(1, w * h // 150000)):
                x0, y0 = r.randrange(w), r.randrange(h)
                x1, y1 = min(w, x0 + r.randrange(40, 600)), min(h, y0 + r.randrange(30, 400))
                for y in range(y0, y1):
                    for x in range(x0, x1):
                        o = (y * w + x) * 4
                        if y - y0 < 20:
                            out[o:o + 4] = b"\x30\x30\x38\xff"
                        else:
                            out[o:o + 4] = bytes((240 - (y - y0) // 8 % 32, 240, 235, 255))
            px0, py0 = w // 3, h // 3
            for y in range(py0, min(h, py0 + h // 5)):
                for x in range(px0, min(w, px0 + w // 5)):
                    o = (y * w + x) * 4
                    v = (x * 3 + y * 5 + r.randrange(24)) & 255
                    out[o:o + 4] = bytes((v, (v * 7) & 255, 255 - v, 255))
        # 8x16 character cells with random glyph bits
        for cy in range(0, h - 15, 16):
            for cx in range(0, w - 7, 8):
                if r.random() < 0.45:
                    continue
                bits = r.getrandbits(128)
                for gy in range(16):
                    for gx in range(8):
                        if bits >> (gy * 8 + gx) & 1 and 2 < gy < 13:
                            o = ((cy + gy) * w + cx + gx) * 4
                            out[o:o + 4] = bytes(fg)
        return bytes(out)
    if kind == "palette":
        pal = [r.randbytes(3) + b"\xff" for _ in range(16)]
        for i in range(w * h):
            out[i * 4:i * 4 + 4] = pal[(i // 37 + (i % w) // 5) % 16]
        return bytes(out)
    raise ValueError(kind)


def main():
    outdir = sys.argv[1]
    quick = "--quick" in sys.argv
    os.makedirs(outdir, exist_ok=True)
    kinds = ["noise", "gradient", "solid", "zero", "black", "alpha", "rgb565", "duprows", "text", "desktop", "palette"]
    if "--random" in sys.argv:
        # --random N [--seed S]: N images of random kind and size (odd widths, tall/wide shapes)
        n = int(sys.argv[sys.argv.index("--random") + 1])
        seed = int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else 1
        r = random.Random(seed)
        for i in range(n):
            k = r.choice(kinds)
            w = r.choice([r.randrange(1, 40), r.randrange(40, 700), r.randrange(700, 2200)])
            h = r.choice([r.randrange(1, 40), r.randrange(40, 500)])
            if w * h > 1_500_000:
                h = max(1, 1_500_000 // w)
            data = gen(k, w, h, seed * 100000 + i)
            name = f"r{seed}n{i}{k}_{w}x{h}"
            with open(os.path.join(outdir, name + ".rgba"), "wb") as f:
                f.write(data)
            with open(os.path.join(outdir, name + ".png"), "wb") as f:
                f.write(pillow_png(w, h, data))
        print(f"{n} random images in {outdir}")
        return
    cases = []
    for (w, h) in [(1, 1), (3, 7), (17, 5), (2, 9), (64, 1)]:
        cases += [(k, w, h) for k in kinds]
    cases += [(k, 640, 480) for k in kinds]
    if not quick:
        cases += [(k, 1024, 768) for k in ["noise", "gradient", "text", "desktop", "alpha", "duprows", "rgb565"]]
        cases += [(k, 1920, 1080) for k in ["noise", "desktop", "text", "gradient", "black"]]
        cases += [("noise", 17000, 3), ("gradient", 1, 3000), ("text", 2, 1000), ("desktop", 800, 600)]
    for i, (k, w, h) in enumerate(cases):
        data = gen(k, w, h, 1000 + i)
        name = f"{k}_{w}x{h}"
        with open(os.path.join(outdir, name + ".rgba"), "wb") as f:
            f.write(data)
        with open(os.path.join(outdir, name + ".png"), "wb") as f:
            f.write(pillow_png(w, h, data))
    # A zlib stream of exactly 65536 bytes (= one full encoder buffer): a single IDAT.
    r = random.Random(3)
    w, h = 4095, 4
    d = bytearray(r.randrange(256) for _ in range(w * h * 4))
    d[len(d) - 49:] = bytes(49)
    name = f"exact65536_{w}x{h}"
    with open(os.path.join(outdir, name + ".rgba"), "wb") as f:
        f.write(d)
    with open(os.path.join(outdir, name + ".png"), "wb") as f:
        f.write(pillow_png(w, h, bytes(d)))
    print(f"{len(cases) + 1} images in {outdir}")


if __name__ == "__main__":
    main()
