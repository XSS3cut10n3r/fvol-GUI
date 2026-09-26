#!/usr/bin/env python3
"""Helpers for bench/refbench/zlib_exact_run.sh.

    png_pillow_bench.py extract DIR       for every DIR/NAME_WxH.png write DIR/NAME_WxH.filtered
                                          (the decompressed IDAT stream = what Pillow feeds zlib,
                                          one (4*W+1)-byte scanline per deflate call)
    png_pillow_bench.py bench FILE RUNS   time Pillow's Image.save(BytesIO, "PNG") of the RGBA image
                                          in FILE (NAME_WxH.rgba), best of RUNS; prints
                                          "py png NAME BYTES BEST_MS"
"""
import io
import os
import struct
import sys
import time
import zlib

from PIL import Image


def idat(png):
    i, out = 8, []
    while i < len(png):
        (n,) = struct.unpack(">I", png[i:i + 4])
        if png[i + 4:i + 8] == b"IDAT":
            out.append(png[i + 8:i + 8 + n])
        i += 12 + n
    return b"".join(out)


def main():
    if sys.argv[1] == "extract":
        d = sys.argv[2]
        for name in sorted(os.listdir(d)):
            if name.endswith(".png"):
                with open(os.path.join(d, name), "rb") as f:
                    raw = zlib.decompress(idat(f.read()))
                with open(os.path.join(d, name[:-4] + ".filtered"), "wb") as f:
                    f.write(raw)
    elif sys.argv[1] == "bench":
        path, runs = sys.argv[2], int(sys.argv[3])
        stem = os.path.basename(path).rsplit(".", 1)[0]
        w, h = map(int, stem.rsplit("_", 1)[1].split("x"))
        with open(path, "rb") as f:
            im = Image.frombytes("RGBA", (w, h), f.read())
        best, n = 1e30, 0
        for _ in range(runs):
            b = io.BytesIO()
            t = time.perf_counter()
            im.save(b, "PNG")
            best = min(best, time.perf_counter() - t)
            n = len(b.getvalue())
        print(f"py png {stem} {n} {best * 1e3:.3f}")


if __name__ == "__main__":
    main()
