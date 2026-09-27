#!/usr/bin/env python3
"""Container layer read throughput: python volatility3 layer classes vs fastvol.

    containers.py make   RAW OUTDIR [MiB]   build large containers from a raw image + address lists
    containers.py pybench OUTDIR [N]        python volatility3 timings (random 4K + sequential)
Rust side (same files, same addresses):
    FASTVOL_LAYER_BENCH=OUTDIR cargo test --release container_bench -- --ignored --nocapture

Each container NAME gets NAME.addrs: little-endian u64 page addresses (random, mapped).
"""
import ctypes
import mmap
import os
import random
import struct
import sys
import time

sys.path.insert(0, "/home/user/rs-vol/volatility3")
sys.dont_write_bytecode = True
PAGE = 0x1000
MB = 1 << 20


def snappy_lib():
    return ctypes.cdll.LoadLibrary("libsnappy.so.1")


def lime(raw, mib):
    half = mib * MB // 2
    out = bytearray()
    for start, src in [(0, 0), (0x40000000, 1 << 30)]:
        out += struct.pack("<IIQQQ", 0x4C694D45, 1, start, start + half - 1, 0) + raw[src:src + half]
    return {".lime": out}, [(0, half), (0x40000000, half)]


def elf(raw, mib):
    half = mib * MB // 2
    hdr = struct.pack("<4sBBBBB7sHHIQQQIHHHHHH", b"\x7fELF", 2, 1, 1, 0, 0, b"\0" * 7, 4, 62, 1, 0, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    ph = b""
    data_off = PAGE
    for i, (paddr, src) in enumerate([(0, 0), (0x40000000, 1 << 30)]):
        ph += struct.pack("<IIQQQQQQ", 1, 7, data_off + i * half, paddr, paddr, half, half, PAGE)
    out = bytearray(hdr + ph)
    out += b"\0" * (PAGE - len(out))
    out += raw[0:half] + raw[1 << 30:(1 << 30) + half]
    return {".elf": out}, [(0, half), (0x40000000, half)]


def crash64_bitmap(raw, mib):
    npages = mib * MB // PAGE
    present = [i % 16 != 15 for i in range(npages)]  # every 16th page missing
    words = []
    for w in range(0, npages, 32):
        v = 0
        for b in range(32):
            if w + b < npages and present[w + b]:
                v |= 1 << b
        words.append(v)
    h = bytearray(2 * PAGE)
    struct.pack_into("<4s4sIIQ", h, 0, b"PAGE", b"DU64", 0xF, 0x4A61, 0x1AE000)
    struct.pack_into("<I", h, 0xF98, 5)
    body = bytearray(0x38) + b"".join(struct.pack("<I", w) for w in words)
    header_size = len(h) + (len(body) + PAGE - 1) // PAGE * PAGE
    struct.pack_into("<4s4sI", body, 0, b"SDMP", b"DUMP", 0)
    struct.pack_into("<QQQ", body, 0x20, header_size, sum(present), npages)
    out = h + body
    out += b"\0" * (header_size - len(out))
    runs = []
    for i in range(npages):
        if present[i]:
            out += raw[i * PAGE:(i + 1) * PAGE]
            if runs and runs[-1][0] + runs[-1][1] == i * PAGE:
                runs[-1] = (runs[-1][0], runs[-1][1] + PAGE)
            else:
                runs.append((i * PAGE, PAGE))
    return {".dmp": out}, runs


def vmware(raw, mib):
    half = mib * MB // 2
    regions = [(0, 0, half // PAGE), (0x100000, half // PAGE, half // PAGE)]

    def tag(name, value, indices=(), size=4):
        name = name.encode()
        return bytes([(len(indices) << 6) | size, len(name)]) + name + b"".join(struct.pack("<I", i) for i in indices) + struct.pack("<I" if size == 4 else "<Q", value)

    tags = tag("regionsCount", len(regions))
    for i, (ppn, pagenum, size) in enumerate(regions):
        tags += tag("regionPPN", ppn, (i,)) + tag("regionPageNum", pagenum, (i,)) + tag("regionSize", size, (i,))
    tags += b"\0\0"
    head = struct.pack("<4sII", b"\xd2\xbe\xd2\xbe", 0, 1) + struct.pack("<64sQQ", b"memory", 12 + 80, 0)
    return {".vmem": raw[0:2 * half], ".vmss": head + tags}, [(0, half), (0x100000000, half)]


def avml(raw, mib):
    lib = snappy_lib()
    half = mib * MB // 2
    out = bytearray()
    runs = []
    for start, src in [(0, 0), (0x40000000, 1 << 30)]:
        data = raw[src:src + half]
        frames = bytearray(b"\xff\x06\x00\x00sNaPpY")
        buf = ctypes.create_string_buffer(lib.snappy_max_compressed_length(ctypes.c_size_t(65536)))
        for i in range(0, len(data), 65536):
            chunk = data[i:i + 65536]
            ln = ctypes.c_size_t(len(buf))
            lib.snappy_compress(chunk, ctypes.c_size_t(len(chunk)), buf, ctypes.byref(ln))
            body = b"\0\0\0\0" + buf.raw[:ln.value]  # CRC not checked by either side
            frames += struct.pack("<I", len(body) << 8) + body
        out += struct.pack("<IIQQQ", 0x4C4D5641, 2, start, start + half - 1, 0) + frames + struct.pack("<Q", len(frames))
        runs.append((start, half))
    return {".avml": out}, runs


def qemu(raw, mib):
    npages = mib * MB // PAGE
    out = bytearray(b"QEVM\0\0\0\3")
    arch = b"pc-i440fx-2.12"
    out += b"\x07" + struct.pack(">I", len(arch)) + arch
    out += b"\x01" + struct.pack(">I", 2) + b"\x03ram" + struct.pack(">II", 0, 4)
    out += struct.pack(">Q", (npages * PAGE) | 4) + b"\x06pc.ram" + struct.pack(">Q", npages * PAGE) + struct.pack(">Q", 0x10)
    out += b"\x7e" + struct.pack(">I", 2) + b"\x02" + struct.pack(">I", 2)
    zero = bytes(PAGE)
    for i in range(npages):
        page = raw[i * PAGE:(i + 1) * PAGE]
        name = b"\x06pc.ram" if i == 0 else b""
        cont = 0 if i == 0 else 0x20
        if page == zero:
            out += struct.pack(">Q", i * PAGE | 0x02 | cont) + name + b"\0"
        else:
            out += struct.pack(">Q", i * PAGE | 0x08 | cont) + name + page
    out += struct.pack(">Q", 0x10) + b"\x7e" + struct.pack(">I", 2)
    out += b"\x00"
    js = b'{"page_size": 4096}'
    out += b"\x06" + struct.pack(">I", len(js)) + js
    return {".qemu": out}, [(0, npages * PAGE)]


FORMATS = {"lime": lime, "elf": elf, "crash64_bitmap": crash64_bitmap, "vmware": vmware, "avml": avml, "qemu": qemu}


def make(rawpath, outdir, mib):
    f = open(rawpath, "rb")
    raw = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    os.makedirs(outdir, exist_ok=True)
    rng = random.Random(7)
    for name, fn in FORMATS.items():
        files, runs = fn(raw, mib)
        for ext, data in files.items():
            with open(os.path.join(outdir, name + ext), "wb") as w:
                w.write(data)
        pages = [s + p * PAGE for s, ln in runs for p in range(ln // PAGE)]
        addrs = [rng.choice(pages) for _ in range(100000)]
        with open(os.path.join(outdir, name + ".addrs"), "wb") as w:
            w.write(b"".join(struct.pack("<Q", a) for a in addrs))
        print(name, "done")


def pybench(outdir, n):
    from volatility3 import framework
    from volatility3.framework import contexts, interfaces
    from volatility3.framework.automagic import stacker
    from volatility3.framework.layers import physical
    import volatility3.framework.layers

    framework.require_interface_version(2, 0, 0)
    framework.import_files(sys.modules["volatility3.framework.layers"])
    for name in FORMATS:
        main = [p for p in os.listdir(outdir) if p.startswith(name + ".") and not p.endswith((".addrs", ".vmss"))][0]
        path = os.path.join(outdir, main)
        t = time.perf_counter()
        ctx = contexts.Context()
        ctx.config["FileLayer.location"] = "file://" + os.path.abspath(path)
        ctx.add_layer(physical.FileLayer(ctx, "FileLayer", "FileLayer"))
        ss = sorted(framework.class_subclasses(interfaces.automagic.StackerLayerInterface), key=lambda x: x.stack_order)
        ss = [s for s in ss if s.__module__.startswith("volatility3.framework.layers")]
        names = stacker.LayerStacker.stack_layer(ctx, "FileLayer", ss)
        top = ctx.layers[names[0]]
        t_open = time.perf_counter() - t
        addrs = struct.unpack(f"<{n}Q", open(os.path.join(outdir, name + ".addrs"), "rb").read(8 * n))
        top.read.cache_clear() if hasattr(top.read, "cache_clear") else None
        t = time.perf_counter()
        for a in addrs:
            top.read(a, PAGE)
        t_rand = time.perf_counter() - t
        # sequential: whole address space in 1 MiB padded reads, capped at 256 MiB of reads
        chunk = MB
        end = top.maximum_address + 1
        total = 0
        t = time.perf_counter()
        a = 0
        runs = [(o, ln) for o, ln, _, _, _ in top.mapping(0, end, ignore_errors=True)]
        for o, ln in runs:
            a = o
            while a < o + ln and total < 256 * MB:
                k = min(chunk, o + ln - a)
                top.read(a, k, pad=True)
                total += k
                a += k
        t_seq = time.perf_counter() - t
        print(f"{name:16s} python open {t_open * 1e3:9.1f} ms   random 4K {n / t_rand:10.0f} reads/s ({n * PAGE / t_rand / 1e6:8.1f} MB/s)"
              f"   sequential {total / t_seq / 1e6:8.1f} MB/s ({type(top).__name__})")


if __name__ == "__main__":
    if sys.argv[1] == "make":
        make(sys.argv[2], sys.argv[3], int(sys.argv[4]) if len(sys.argv) > 4 else 512)
    else:
        pybench(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 20000)
