#!/usr/bin/env python3
"""Build a VMware-style .vmem + .vmss pair from a QEMU `dump-guest-memory` ELF64 core (test-data generator).

The .vmem gets every PT_LOAD segment concatenated in file order; the .vmss is a minimal VMware
checkpoint whose "memory" group describes, per segment, a region (regionPPN = guest physical page,
regionPageNum = page offset inside the .vmem, regionSize = pages) - exactly the tags volatility3's
VmwareLayer reads. A second group and a few extra tags (incl. one long-form tag with the 62-length
escape) are added so the group table and every tag-encoding branch of the parser are exercised.

usage: mk_vmware_from_elf.py CORE.elf OUT.vmem      (writes OUT.vmss next to OUT.vmem)
"""
import os
import struct
import sys

MAGIC = b"\xd2\xbe\xd2\xbe"  # version 2 (magic[0] & 0xf): long-form tags carry 8-byte sizes


def pt_loads(path):
    with open(path, "rb") as f:
        h = f.read(64)
        if h[:4] != b"\x7fELF" or h[4] != 2:
            sys.exit("not an ELF64 file")
        phoff, = struct.unpack_from("<Q", h, 32)
        phentsize, phnum = struct.unpack_from("<HH", h, 54)
        segs = []
        for i in range(phnum):
            f.seek(phoff + i * phentsize)
            p_type, _fl, off, _va, pa, filesz, _memsz, _al = struct.unpack("<IIQQQQQQ", f.read(56))
            if p_type == 1 and filesz:
                if pa % 4096 or filesz % 4096:
                    sys.exit(f"segment at {pa:#x} not page aligned")
                segs.append((pa, off, filesz))
    return segs


def tag(name, value=None, indices=(), size=4, long_data=None):
    name = name.encode()
    idx = b"".join(struct.pack("<I", i) for i in indices)
    if long_data is not None:
        flags = (len(indices) << 6) | 62
        # size, "compressed size", 2 bytes padding, data
        return bytes([flags, len(name)]) + name + idx + struct.pack("<QQ", len(long_data), len(long_data)) + b"\0\0" + long_data
    flags = (len(indices) << 6) | size
    return bytes([flags, len(name)]) + name + idx + value.to_bytes(size, "little")


def main():
    core, vmem = sys.argv[1], sys.argv[2]
    vmss = vmem[:-5] + ".vmss" if vmem.endswith(".vmem") else sys.exit("output must end in .vmem")
    segs = pt_loads(core)
    regions = []
    page = 0
    with open(core, "rb") as src, open(vmem, "wb") as dst:
        for pa, off, size in segs:
            regions.append((pa // 4096, page, size // 4096))
            page += size // 4096
            done = 0
            while done < size:
                n = os.copy_file_range(src.fileno(), dst.fileno(), size - done, off + done)
                if n <= 0:
                    sys.exit("short copy")
                done += n
    # tags of the "memory" group
    mem = tag("align_mask", 0xFFFF)
    mem += tag("rsvolNote", long_data=b"rsvol synthetic vmss for VmwareLayer tests\0")
    mem += tag("regionsCount", len(regions))
    for i, (ppn, pnum, n) in enumerate(regions):
        mem += tag("regionPPN", ppn, (i,))
        mem += tag("regionPageNum", pnum, (i,))
        mem += tag("regionSize", n, (i,))
    mem += b"\0\0"
    cpu = tag("cpu:numVCPUs", 2) + tag("rsvolWide", 0x1122334455667788, size=8) + b"\0\0"
    groups = [(b"cpu", cpu), (b"memory", mem)]
    hdr = MAGIC + struct.pack("<II", 0, len(groups))
    table_size = len(groups) * struct.calcsize("64sQQ")
    offset = len(hdr) + table_size
    table = b""
    body = b""
    for gname, data in groups:
        table += struct.pack("64sQQ", gname, offset + len(body), len(data))
        body += data
    with open(vmss, "wb") as f:
        f.write(hdr + table + body)
    for r in regions:
        print(f"region PPN {r[0]:#x} -> vmem page {r[1]:#x} ({r[2]:#x} pages)")
    print(f"wrote {vmem} ({page * 4096} bytes) and {vmss}")


if __name__ == "__main__":
    main()
