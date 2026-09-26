#!/usr/bin/env python3
"""Wrap a raw (flat) Windows physical-memory image into a Microsoft crash-dump file (test-data generator).

Produces the "complete memory dump" layouts volatility3's WindowsCrashDump{32,64}Layer reads:
  --type full    DumpType 1: header page(s) + the pages of every _PHYSICAL_MEMORY_RUN, in run order
  --type bitmap  DumpType 5: header page(s) + _SUMMARY_DUMP ("SDMP") + page bitmap + the set pages
Header fields come from a JSON file written by win_physmem_info.py (a volshell script run on the raw
image): kernel DTB, PsLoadedModuleList, PsActiveProcessHead, MmPfnDatabase value, KdDebuggerDataBlock
and MmPhysicalMemoryBlock's runs. Everything not set is left as the "PAGE" fill real dumps have.

usage: mk_crashdump_from_raw.py --bits 32|64 --type full|bitmap --info INFO.json --build N
                                [--pae] [--cpus N] [--systime 'YYYY-mm-dd HH:MM:SS'] RAW OUT
"""
import argparse
import datetime
import json
import os
import struct
import sys

PAGE = 4096


def filetime(s):
    t = datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    return int((t - datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds()) * 10**7


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bits", type=int, choices=(32, 64), required=True)
    ap.add_argument("--type", choices=("full", "bitmap"), required=True)
    ap.add_argument("--info", required=True)
    ap.add_argument("--build", type=int, required=True)
    ap.add_argument("--pae", action="store_true")
    ap.add_argument("--cpus", type=int, default=1)
    ap.add_argument("--systime", default="2020-01-01 00:00:00")
    ap.add_argument("--uptime-secs", type=int, default=3600)
    ap.add_argument("raw")
    ap.add_argument("out")
    a = ap.parse_args()
    info = json.load(open(a.info))
    raw_pages = os.path.getsize(a.raw) // PAGE
    runs = [(b, min(c, raw_pages - b)) for b, c in info["runs"] if b < raw_pages]
    npages = sum(c for _, c in runs)
    hdr_pages = 2 if a.bits == 64 else 1
    hdr = bytearray(b"PAGE" * (hdr_pages * PAGE // 4))
    put = lambda fmt, off, *v: struct.pack_into("<" + fmt, hdr, off, *v)
    dump_type = 1 if a.type == "full" else 5
    if a.bits == 64:
        hdr[0:8] = b"PAGEDU64"
        put("II", 0x8, 0xF, a.build)
        put("QQQQ", 0x10, info["dtb"], info["PfnDataBase"], info["PsLoadedModuleList"], info["PsActiveProcessHead"])
        put("II", 0x30, 0x8664, a.cpus)
        put("I", 0x38, 0xE2)  # MANUALLY_INITIATED_CRASH
        put("QQQQ", 0x40, 0, 0, 0, 0)
        put("Q", 0x80, info["KdDebuggerDataBlock"])
        pmd = 0x88
        if len(runs) > (0x348 - 0x98) // 16:
            sys.exit("too many runs")
        put("IIQ", pmd, len(runs), 0, npages)  # NumberOfRuns, pad, NumberOfPages (ULONG64)
        for i, (b, c) in enumerate(runs):
            put("QQ", pmd + 0x10 + 16 * i, b, c)
        put("I", 0xF98, dump_type)
        put("Q", 0xFA8, filetime(a.systime))
        put("Q", 0x1030, a.uptime_secs * 10**7)
        req_off = 0xFA0
    else:
        hdr[0:8] = b"PAGEDUMP"
        put("II", 0x8, 0xF, a.build)
        put("IIII", 0x10, info["dtb"], info["PfnDataBase"], info["PsLoadedModuleList"], info["PsActiveProcessHead"])
        put("II", 0x20, 0x14C, a.cpus)
        put("I", 0x28, 0xE2)
        put("IIII", 0x2C, 0, 0, 0, 0)
        hdr[0x5C] = 1 if a.pae else 0
        put("I", 0x60, info["KdDebuggerDataBlock"])
        pmd = 0x64
        if len(runs) > (0x320 - 0x6C) // 8:
            sys.exit("too many runs")
        put("II", pmd, len(runs), npages)
        for i, (b, c) in enumerate(runs):
            put("II", pmd + 8 + 8 * i, b, c)
        put("I", 0xF88, dump_type)
        put("Q", 0xFB8, a.uptime_secs * 10**7)
        put("Q", 0xFC0, filetime(a.systime))
        req_off = 0xFA0
    with open(a.raw, "rb") as src, open(a.out, "wb") as dst:
        dst.write(hdr)
        if dump_type == 5:
            max_page = max(b + c for b, c in runs)
            bitmap = bytearray((max_page + 31) // 32 * 4)
            for b, c in runs:
                for p in range(b, b + c):
                    bitmap[p >> 3] |= 1 << (p & 7)
            summ = bytearray(0x38)
            summ[0:8] = b"SDMPDUMP"
            struct.pack_into("<I", summ, 8, 0)
            data_off = (hdr_pages * PAGE + 0x38 + len(bitmap) + PAGE - 1) // PAGE * PAGE
            struct.pack_into("<QQQ", summ, 0x20, data_off, npages, max_page)
            blk = summ + bitmap
            dst.write(blk + b"\0" * (data_off - hdr_pages * PAGE - len(blk)))
        dst.flush()  # copy_file_range below writes through the fd at explicit offsets
        pos = dst.tell()
        for b, c in runs:
            done, size, off = 0, c * PAGE, b * PAGE
            while done < size:
                n = os.copy_file_range(src.fileno(), dst.fileno(), size - done, off + done, pos)
                if n <= 0:
                    sys.exit("short copy")
                done += n
                pos += n
        total = pos
    with open(a.out, "r+b") as f:
        f.seek(req_off)
        f.write(struct.pack("<Q", total))
    print(f"wrote {a.out}: {len(runs)} runs, {npages:#x} pages, DumpType {dump_type}, {total} bytes")


if __name__ == "__main__":
    main()
