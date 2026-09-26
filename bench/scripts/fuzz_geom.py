#!/usr/bin/env python3
"""Image geometry + x86-64 page-table walker for the rsvol robustness fuzzer.

Maps physical addresses to file offsets for raw / ELF-core / LiME images (so corruption can be
placed at a known structure without copying the whole image), locates container header regions,
and walks 4-level page tables to translate the virtual addresses that plugins print back to file
offsets. Used by fuzz_images.py. No dependencies beyond the standard library.
"""

import bisect
import struct

PAGE = 0x1000
MASK48 = (1 << 48) - 1


class Geometry:
    """Physical<->file mapping and header regions for one image file."""

    def __init__(self, path):
        import os
        self.path = path
        self.size = os.path.getsize(path)
        self.runs = []      # (paddr, foff, length) sorted by paddr
        self.headers = []   # (foff, length, what) container metadata regions
        self.kind = 'raw'
        with open(path, 'rb') as f:
            head = f.read(64)
            if head[:4] == b'\x7fELF' and len(head) > 4 and head[4] == 2:
                self.kind = 'elf'
                phoff, = struct.unpack_from('<Q', head, 0x20)
                phentsize, phnum = struct.unpack_from('<HH', head, 0x36)
                self.headers.append((0, 64, 'ehdr'))
                self.headers.append((phoff, phentsize * phnum, 'phdrs'))
                f.seek(phoff)
                ph = f.read(phentsize * phnum)
                for i in range(phnum):
                    p_type, _fl, off, _va, pa, filesz, _mem, _al = struct.unpack_from('<IIQQQQQQ', ph, i * phentsize)
                    if p_type == 1 and filesz:
                        self.runs.append((pa, off, filesz))
                    elif p_type == 4:
                        self.headers.append((off, filesz, 'note'))
            elif head[:4] == b'EMiL':
                self.kind = 'lime'
                off = 0
                while off + 32 <= self.size:
                    f.seek(off)
                    h = f.read(32)
                    magic, _v, start, end = struct.unpack_from('<IIQQ', h)
                    if magic != 0x4C694D45:
                        break
                    self.headers.append((off, 32, 'lime'))
                    n = end - start + 1
                    self.runs.append((start, off + 32, n))
                    off += 32 + n
            else:
                self.runs.append((0, 0, self.size))
        self.runs.sort()
        self._starts = [r[0] for r in self.runs]

    def p2f(self, pa):
        i = bisect.bisect_right(self._starts, pa) - 1
        if i < 0:
            return None
        s, off, n = self.runs[i]
        if 0 <= pa - s < n and off + (pa - s) < self.size:
            return off + (pa - s)
        return None

    def data_ranges(self):
        return [(off, min(n, self.size - off)) for _, off, n in self.runs if off < self.size]


def canon(va):
    va &= MASK48
    return va | 0xffff000000000000 if va & (1 << 47) else va


class Walker:
    """x86-64 4-level walker over an open image fd (present entries only)."""

    def __init__(self, fd, geo, dtb):
        import os
        self._os = os
        self.fd, self.geo, self.dtb = fd, geo, dtb & ~0xfff

    def _rpa(self, pa, n):
        f = self.geo.p2f(pa)
        if f is None:
            return None
        b = self._os.pread(self.fd, n, f)
        return b if len(b) == n else None

    def _ent(self, table, idx):
        b = self._rpa(table + idx * 8, 8)
        return None if b is None else struct.unpack('<Q', b)[0]

    def v2p(self, va, dtb=None):
        table = (dtb if dtb is not None else self.dtb) & ~0xfff
        for level, shift in ((4, 39), (3, 30), (2, 21), (1, 12)):
            e = self._ent(table, (va >> shift) & 0x1ff)
            if e is None or not e & 1:
                return None
            pfn = e & 0x000ffffffffff000
            if level in (3, 2) and e & 0x80:
                size = 1 << shift
                return (pfn & ~(size - 1)) | (va & (size - 1))
            table = pfn
        return table | (va & 0xfff)

    def v2f(self, va, dtb=None):
        pa = self.v2p(va, dtb)
        return None if pa is None else self.geo.p2f(pa)

    def ranges(self, va, n, dtb=None):
        """[(file_offset, length)] covering virtual [va, va+n) (unmapped parts skipped)."""
        out, end = [], va + n
        while va < end:
            chunk = min(end - va, PAGE - (va & 0xfff))
            f = self.v2f(va, dtb)
            if f is not None:
                out.append((f, chunk))
            va += chunk
        return out

    def tables(self, dtb, kernel_half=None, limit=1500, rng=None):
        """Page-table page physical addresses reachable from dtb: [(level, pa)], level 4 = PML4."""
        root = dtb & ~0xfff
        out = [(4, root)]
        frontier = [(4, root)]
        seen = {root}
        while frontier and len(out) < limit:
            level, t = frontier.pop(0)
            if level == 1:
                continue
            raw = self._rpa(t, PAGE)
            if raw is None:
                continue
            ents = struct.unpack('<512Q', raw)
            idxs = range(512)
            if level == 4 and kernel_half is not None:
                idxs = range(256, 512) if kernel_half else range(0, 256)
            kids = []
            for i in idxs:
                e = ents[i]
                if not e & 1 or (level in (3, 2) and e & 0x80):
                    continue
                pa = e & 0x000ffffffffff000
                if self.geo.p2f(pa) is None or pa in seen:
                    continue
                kids.append((level - 1, pa))
            if rng is not None and len(kids) > 48:
                kids = rng.sample(kids, 48)
            for k in kids:
                seen.add(k[1])
                out.append(k)
                frontier.append(k)
        return out[:limit]
