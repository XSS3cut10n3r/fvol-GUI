#!/usr/bin/env python3
"""Build synthetic container images from real memory and record what python volatility3's
own layer classes read from them (differential test data for src/layers/containers).

    <venv>/bin/python gen_containers.py RAW_IMAGE OUTDIR [--scale N] [--queries N]

For every container NAME it writes NAME.<ext> (+ side files) and NAME.expect:

    STACK <class> <class> ...          python LayerStacker result, top first
    MAX <hex>                          top layer maximum_address
    R <addr> <len> <fnv64|X>           strict read (X = InvalidAddressException)
    P <addr> <len> <fnv64>             padded read

--scale multiplies the amount of memory copied into each container (1 = tiny fixtures
committed in tests/fixtures/containers, bigger ones go to /tmp for the ignored test).
"""
import argparse
import ctypes
import mmap
import os
import random
import struct
import sys

sys.path.insert(0, "/home/user/fvol/volatility3")
sys.dont_write_bytecode = True

from volatility3 import framework  # noqa: E402
from volatility3.framework import contexts, exceptions, interfaces  # noqa: E402
from volatility3.framework.automagic import stacker  # noqa: E402
from volatility3.framework.layers import physical  # noqa: E402

framework.require_interface_version(2, 0, 0)
import volatility3.framework.layers  # noqa: E402

framework.import_files(sys.modules["volatility3.framework.layers"])

PAGE = 0x1000
snappy = ctypes.cdll.LoadLibrary("libsnappy.so.1")


def fnv64(data):
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def snappy_compress(data):
    n = snappy.snappy_max_compressed_length(ctypes.c_size_t(len(data)))
    buf = ctypes.create_string_buffer(n)
    ln = ctypes.c_size_t(n)
    assert snappy.snappy_compress(data, ctypes.c_size_t(len(data)), buf, ctypes.byref(ln)) == 0
    return buf.raw[: ln.value]


def crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def masked_crc(data):
    c = crc32c(data)
    return (((c >> 15) | (c << 17)) + 0xA282EAD8) & 0xFFFFFFFF


class Memory:
    """Real memory pages from the raw image."""

    def __init__(self, path, seed):
        f = open(path, "rb")
        self.m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        self.rng = random.Random(seed)

    def pages(self, n, zero_every=0):
        """n pages of mostly non-zero real memory (some zero pages if zero_every)."""
        out = bytearray()
        for i in range(n):
            if zero_every and i % zero_every == zero_every - 1:
                out += b"\x00" * PAGE
                continue
            while True:
                off = self.rng.randrange(0, len(self.m) // PAGE) * PAGE
                p = self.m[off:off + PAGE]
                if p.count(0) < PAGE * 3 // 4:
                    break
            out += p
        return bytes(out)


# --------------------------------------------------------------------------- formats


def make_lime(mem, s):
    segs = [(0x0, 1 * s), (0x10000, 1 * s), (0x100000, 2 * s), (0x1_0000_0000, 1 * s)]
    out = bytearray()
    for start, npages in segs:
        data = mem.pages(npages)
        out += struct.pack("<IIQQQ", 0x4C694D45, 1, start, start + len(data) - 1, 0)
        out += data
    return {"": bytes(out)}, ".lime"


def elf_header(phnum, shnum=0, phoff=64, shoff=0, shstrndx=0, version=1):
    return struct.pack(
        "<4sBBBBB7sHHIQQQIHHHHHH",
        b"\x7fELF", 2, 1, version, 0, 0, b"\x00" * 7,
        4, 62, 1, 0, phoff, shoff, 0, 64, 56, phnum, 64, shnum, shstrndx,
    )


def phdr(p_type, offset, paddr, filesz, memsz):
    return struct.pack("<IIQQQQQQ", p_type, 7, offset, 0xFFFF800000000000 + paddr, paddr, filesz, memsz, 0x1000)


def make_elf(mem, s, version=1):
    # (paddr, pages, kind): kind 0 = normal PT_LOAD, 1 = filesz != memsz (skipped),
    # 2 = unknown p_type (skipped), 3 = PT_NOTE
    loads = [(0x0, 2 * s, 0), (0x8000, 1 * s, 0), (0x40000, 1 * s, 1), (0x50000, 1 * s, 2), (0xC0000, 2 * s, 0),
             (0x1_0000_0000, 1 * s, 0)]
    n = len(loads) + 1
    data_off = 0x1000
    ph = bytearray(phdr(4, 0x800, 0, 0x100, 0x100))  # PT_NOTE
    blobs = bytearray()
    for paddr, npages, kind in loads:
        d = mem.pages(npages)
        off = data_off + len(blobs)
        if kind == 0:
            ph += phdr(1, off, paddr, len(d), len(d))
        elif kind == 1:
            ph += phdr(1, off, paddr, len(d), len(d) + PAGE)
        else:
            ph += phdr(0x12345678, off, paddr, len(d), len(d))
        blobs += d
    hdr = elf_header(n, version=version)
    out = bytearray(hdr) + ph
    out += b"\x00" * (data_off - len(out))
    out += blobs
    return {"": bytes(out)}, ".elf"


def make_nested(mem, s, pad=False):
    """A LiME image stored inside an ELF PT_LOAD at physical address 0 (python stacks
    Elf64Layer, then LimeLayer on top of it). With pad=True the PT_LOAD is page-rounded and
    the trailing zeros make python's LiME parser fail (only Elf64Layer stacks)."""
    lime, _ = make_lime(mem, s)
    lime = lime[""]
    size = (len(lime) + PAGE - 1) // PAGE * PAGE if pad else len(lime)
    lime = lime + b"\x00" * (size - len(lime))
    out = bytearray(elf_header(1)) + phdr(1, 0x1000, 0, size, size)
    out += b"\x00" * (0x1000 - len(out))
    out += lime
    return {"": bytes(out)}, ".elf"


def crash_header32(runs, dump_type):
    h = bytearray(PAGE)
    struct.pack_into("<4s4sIIIIIIIII", h, 0, b"PAGE", b"DUMP", 0xF, 0x4A61, 0x185000, 0x80000000,
                     0x8055B420, 0x8055D1D8, 0x14C, 1, 0x7E)
    struct.pack_into("<II", h, 0x64, len(runs), sum(c for _, c in runs))
    for i, (b, c) in enumerate(runs):
        struct.pack_into("<II", h, 0x6C + 8 * i, b, c)
    h[0x820:0x820 + 8] = b"rsvol32\x00"
    struct.pack_into("<I", h, 0xF88, dump_type)
    struct.pack_into("<QQ", h, 0xFB8, 12345678, 132000000000000000)
    return h


def crash_header64(runs, dump_type):
    h = bytearray(2 * PAGE)
    struct.pack_into("<4s4sIIQQQQIII", h, 0, b"PAGE", b"DU64", 0xF, 0x4A61, 0x1AE000, 0xFFFFFA8000000000,
                     0xFFFFF80002A4AE90, 0xFFFFF80002A28B90, 0x8664, 2, 0x7E)
    struct.pack_into("<II", h, 0x88, len(runs), sum(c for _, c in runs))
    for i, (b, c) in enumerate(runs):
        struct.pack_into("<QQ", h, 0x98 + 16 * i, b, c)
    struct.pack_into("<I", h, 0xF98, dump_type)
    struct.pack_into("<QQ", h, 0xFA0, 0, 132000000000000000)
    h[0xFB0:0xFB0 + 8] = b"rsvol64\x00"
    struct.pack_into("<Q", h, 0x1030, 12345678)
    return h


def make_crash_full(mem, s, bits):
    runs = [(0x1, 2 * s), (0x10, 1 * s), (0x100, 3 * s)]
    hdr = crash_header32(runs, 1) if bits == 32 else crash_header64(runs, 1)
    data = mem.pages(sum(c for _, c in runs))
    return {"": bytes(hdr) + data}, ".dmp"


def make_crash_bitmap(mem, s, bits):
    # bitmap over 32 * words pages with: a full word, zero words, mixed words
    if bits == 32:
        pattern = [0, 0x0F0F00F1, 0x80000001, 0, 0x00030000]
    else:
        pattern = [0xFFFFFFFF, 0, 0x000000F1, 0x80000001]
    words = [pattern[i % len(pattern)] for i in range(len(pattern) * s)]
    nbits = len(words) * 32 - 5  # not a multiple of 32
    npages = sum(bin(w).count("1") for w in words)
    hdr = crash_header32([], 5) if bits == 32 else crash_header64([], 5)
    summary = bytearray(0x38)
    header_size = len(hdr) + ((0x38 + 4 * len(words) + PAGE - 1) // PAGE) * PAGE
    struct.pack_into("<4s4sI", summary, 0, b"SDMP", b"DUMP", 0)
    struct.pack_into("<QQQ", summary, 0x20, header_size, npages, nbits)
    body = bytes(summary) + b"".join(struct.pack("<I", w) for w in words)
    out = bytearray(hdr) + body
    out += b"\x00" * (header_size - len(out))
    out += mem.pages(npages, zero_every=2)
    return {"": bytes(out)}, ".dmp"


def vmss(regions, version_magic=b"\xd2\xbe\xd2\xbe"):
    def tag(name, value, indices=(), size=4, long=None):
        name = name.encode()
        if long is not None:
            flags = (len(indices) << 6) | 62
            dl = 4 if version_magic[0] & 0xF == 0 else 8
            return (bytes([flags, len(name)]) + name + b"".join(struct.pack("<I", i) for i in indices)
                    + (struct.pack("<I", len(long)) if dl == 4 else struct.pack("<Q", len(long)))
                    + b"\x00" * dl + b"\x00\x00" + long)
        flags = (len(indices) << 6) | size
        fmt = {4: "<I", 8: "<Q"}[size]
        return bytes([flags, len(name)]) + name + b"".join(struct.pack("<I", i) for i in indices) + struct.pack(fmt, value)

    tags = bytearray()
    tags += tag("align_mask", 0xFFFF)
    tags += tag("Memory", 0, (0, 0), long=b"x" * 40)
    tags += tag("regionsCount", len(regions))
    for i, (ppn, pagenum, size) in enumerate(regions):
        tags += tag("regionPageNum", pagenum, (i,))
        tags += tag("regionPPN", ppn, (i,), size=8)
        tags += tag("regionSize", size, (i,))
    tags += b"\x00\x00"
    groups = [b"Checkpoint", b"memory", b"cpu"]
    head = struct.pack("<4sII", version_magic, 0, len(groups))
    first = len(head) + 80 * len(groups)
    out = bytearray(head)
    for g in groups:
        loc = first if g == b"memory" else 0
        out += struct.pack("<64sQQ", g, loc, 0)
    out += tags
    return bytes(out)


def make_vmware(mem, s, ext=".vmss"):
    # vmem is flat: [0, 3s pages) = PPN 0.., then a hole, then region at PPN 0x100000 (4 GiB)
    regions = [(0, 0, 2 * s), (0x20, 2 * s, 1 * s), (0x100000, 3 * s, 1 * s)]
    vmem = mem.pages(4 * s)
    return {"": vmem, ext: vmss(regions)}, ".vmem"


def make_qemu(mem, s):
    out = bytearray(b"QEVM\x00\x00\x00\x03")
    arch = b"pc-i440fx-2.12"
    out += b"\x07" + struct.pack(">I", len(arch)) + arch
    # ram section
    out += b"\x01" + struct.pack(">I", 2) + b"\x03ram" + struct.pack(">II", 0, 4)
    total = 0x1_2000_0000
    out += struct.pack(">Q", total | 0x04)
    for name, size in [(b"pc.ram", total), (b"vga.vram", 0x1000000)]:
        out += bytes([len(name)]) + name + struct.pack(">Q", size)
    out += struct.pack(">Q", 0x10)  # EOS
    out += b"\x7e" + struct.pack(">I", 2)
    out += b"\x02" + struct.pack(">I", 2)
    first = True
    addrs = [0x0, 0x1000, 0x2000, 0x5000, 0x6000, 0x7000, 0x8000, 0x20000, 0xBFFFF000, 0xC0000000, 0xC0001000]
    addrs = addrs + [0x100000 + i * PAGE for i in range(2 * s)]
    for i, a in enumerate(addrs):
        if first:
            out += struct.pack(">Q", a | 0x08) + b"\x06pc.ram" + mem.pages(1)
            first = False
        elif i % 4 == 2:
            out += struct.pack(">Q", a | 0x02 | 0x20) + bytes([0 if i % 8 == 2 else 0xAB])
        else:
            out += struct.pack(">Q", a | 0x08 | 0x20) + mem.pages(1)
    # a page of another RAM block (ignored)
    out += struct.pack(">Q", 0x3000 | 0x08) + b"\x08vga.vram" + mem.pages(1)
    # back to pc.ram
    out += struct.pack(">Q", 0x30000 | 0x08) + b"\x06pc.ram" + mem.pages(1)
    out += struct.pack(">Q", 0x10)
    out += b"\x7e" + struct.pack(">I", 2)
    out += b"\x03" + struct.pack(">I", 2) + struct.pack(">Q", 0x10) + b"\x7e" + struct.pack(">I", 2)
    # a device section whose data starts with a zero byte (python's parser stops there)
    out += b"\x04" + struct.pack(">I", 3) + b"\x05timer" + struct.pack(">II", 0, 2) + struct.pack(">QQ", 0, 1)
    out += b"\x00"
    js = b'{"page_size": 4096, "devices": [{"name": "timer", "vmsd_name": "timer"}]}'
    out += b"\x06" + struct.pack(">I", len(js)) + js
    return {"": bytes(out)}, ".qemu"


def avml_block(start, data, uncompressed_every=3):
    frames = bytearray(b"\xff\x06\x00\x00sNaPpY")
    for i in range(0, len(data), 65536):
        if i:
            frames += b"\xfe\x02\x00\x00\x00\x00"  # padding chunk between frames
        chunk = data[i:i + 65536]
        crc = struct.pack("<I", masked_crc(chunk))
        if (i // 65536) % uncompressed_every == uncompressed_every - 1:
            body = crc + chunk
            frames += struct.pack("<I", 0x01 | (len(body) << 8)) + body
        else:
            body = crc + snappy_compress(chunk)
            frames += struct.pack("<I", 0x00 | (len(body) << 8)) + body
    hdr = struct.pack("<IIQQQ", 0x4C4D5641, 2, start, start + len(data) - 1, 0)
    return hdr + frames + struct.pack("<Q", len(frames))


def make_avml(mem, s):
    out = bytearray()
    out += avml_block(0x0, mem.pages(18 * s, zero_every=2))
    out += avml_block(0x100000, mem.pages(34 * s, zero_every=2))
    return {"": bytes(out)}, ".avml"


def make_xen(mem, s):
    pfns = [5, 0, 7, 0xFFFFFFFF, 2, 3] + [0x100 + i for i in range(1 * s)]
    shstr = b"\x00.shstrtab\x00.xen_pfn\x00.xen_pages\x00"
    npages = len(pfns)
    pages = mem.pages(npages)
    pfn_arr = b"".join(struct.pack("<Q", p) for p in pfns)
    shoff = 64
    body_off = shoff + 4 * 64
    shstr_off = body_off
    pfn_off = shstr_off + len(shstr)
    pages_off = (pfn_off + len(pfn_arr) + PAGE - 1) // PAGE * PAGE

    def shdr(name, typ, off, size):
        return struct.pack("<IIQQQQIIQQ", name, typ, 0, 0, off, size, 0, 0, 8, 0)

    out = bytearray(elf_header(0, 4, phoff=0, shoff=shoff, shstrndx=1))
    out += shdr(0, 0, 0, 0) + shdr(1, 3, shstr_off, len(shstr)) + shdr(11, 1, pfn_off, len(pfn_arr)) + shdr(20, 1, pages_off, len(pages))
    out += shstr + pfn_arr
    out += b"\x00" * (pages_off - len(out))
    out += pages
    return {"": bytes(out)}, ".xen"


FORMATS = {
    "lime": make_lime,
    "elf": make_elf,
    "elf_vbox": lambda m, s: make_elf(m, s, version=0),
    "nested_elf_lime": make_nested,
    "nested_elf_lime_padded": lambda m, s: make_nested(m, s, pad=True),
    "crash32_full": lambda m, s: make_crash_full(m, s, 32),
    "crash64_full": lambda m, s: make_crash_full(m, s, 64),
    "crash32_bitmap": lambda m, s: make_crash_bitmap(m, s, 32),
    "crash64_bitmap": lambda m, s: make_crash_bitmap(m, s, 64),
    "vmware": make_vmware,
    "vmware_vmsn": lambda m, s: make_vmware(m, s, ".vmsn"),
    "qemu": make_qemu,
    "avml": make_avml,
    "xen": make_xen,
}

# --------------------------------------------------------------------------- python side


def py_stack(path):
    ctx = contexts.Context()
    ctx.config["FileLayer.location"] = "file://" + os.path.abspath(path)
    ctx.add_layer(physical.FileLayer(ctx, "FileLayer", "FileLayer"))
    stack_set = sorted(framework.class_subclasses(interfaces.automagic.StackerLayerInterface), key=lambda x: x.stack_order)
    stack_set = [st for st in stack_set if st.__module__.startswith("volatility3.framework.layers")]
    names = stacker.LayerStacker.stack_layer(ctx, "FileLayer", stack_set)
    return ctx, names


def queries(layer, rng, n):
    lo = layer.minimum_address
    hi = layer.maximum_address
    try:
        segs = sorted(layer._segments)
    except AttributeError:
        segs = [(0, 0, hi + 1, hi + 1)]
    points = []
    for start, _, length, _ in segs:
        points += [start, start + length, start + length - 1, start - 1, start + length // 2]
    out = []
    for _ in range(n):
        r = rng.random()
        if r < 0.5 and points:
            a = rng.choice(points) + rng.randrange(-40, 40)
        elif r < 0.8:
            a = rng.randrange(lo, hi + 1)
        else:
            a = rng.randrange(0, (hi + 1) * 2)
        a = max(0, a)
        ln = rng.choice([1, 2, 7, 8, 16, 33, 64, 100, 4096, 4097, 8192, 65536 + 17])
        out.append((a, ln))
    return out


def expect(main, rng, nq):
    """Write MAIN's .expect (python's stacking decision, maximum_address and reads)."""
    ctx, names = py_stack(main)
    top = ctx.layers[names[0]]
    lines = ["STACK " + " ".join(type(ctx.layers[n]).__name__ for n in names), f"MAX {top.maximum_address:x}"]
    for a, ln in queries(top, rng, nq):
        try:
            d = top.read(a, ln)
            lines.append(f"R {a:x} {ln:x} {fnv64(d):016x}")
        except exceptions.InvalidAddressException:
            lines.append(f"R {a:x} {ln:x} X")
        try:
            d = top.read(a, ln, pad=True)
            lines.append(f"P {a:x} {ln:x} {fnv64(d):016x}")
        except exceptions.InvalidAddressException:
            pass
    stem = os.path.splitext(main)[0]
    with open(stem + ".expect", "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"{os.path.basename(main):24s} {os.path.getsize(main):11d} bytes  stack={lines[0][6:]}")


def gen(raw, outdir, scale, nq, seed):
    mem = Memory(raw, seed)
    rng = random.Random(seed)
    os.makedirs(outdir, exist_ok=True)
    for name, fn in FORMATS.items():
        files, ext = fn(mem, scale)
        main = os.path.join(outdir, name + ext)
        for sfx, data in files.items():
            p = main if sfx == "" else main[: -len(ext)] + sfx
            with open(p, "wb") as f:
                f.write(data)
        expect(main, rng, nq)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("raw", nargs="?")
    ap.add_argument("outdir", nargs="?")
    ap.add_argument("--scale", type=int, default=1)
    ap.add_argument("--queries", type=int, default=120)
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--expect-only", nargs="+", metavar="FILE",
                    help="only write .expect files for existing containers")
    a = ap.parse_args()
    if a.expect_only:
        rng = random.Random(a.seed)
        for p in a.expect_only:
            expect(p, rng, a.queries)
    else:
        gen(a.raw, a.outdir, a.scale, a.queries, a.seed)
