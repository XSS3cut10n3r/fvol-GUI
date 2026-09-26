#!/usr/bin/env python3
"""Snappy test vectors compressed by the reference C++ libsnappy (via ctypes).

    python3 gen_snappy.py <outdir>

Originals come from gen_xpress.gen_data() (mirrored in src/codecs/testdata.rs).
"""
import ctypes
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_xpress import gen_data  # noqa: E402

lib = ctypes.cdll.LoadLibrary("libsnappy.so.1")


def compress(data):
    n = lib.snappy_max_compressed_length(ctypes.c_size_t(len(data)))
    buf = ctypes.create_string_buffer(n)
    ln = ctypes.c_size_t(n)
    r = lib.snappy_compress(data, ctypes.c_size_t(len(data)), buf, ctypes.byref(ln))
    assert r == 0
    return buf.raw[:ln.value]


VECTORS = [("small", 5, 1000), ("block64k", 6, 65536), ("large", 7, 300000)]


def main():
    outdir = sys.argv[1]
    for name, seed, n in VECTORS:
        data = gen_data(seed, n)
        c = compress(data)
        open(f"{outdir}/snappy_{name}.bin", "wb").write(c)
        print(name, n, len(c))


if __name__ == "__main__":
    main()
