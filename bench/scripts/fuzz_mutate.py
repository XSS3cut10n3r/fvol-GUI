#!/usr/bin/env python3
"""Mutation engine: build a corrupted reflink copy of a base image from a seed + target set.

A mutant is a `cp --reflink=auto` copy (shares extents on btrfs; only changed blocks cost disk)
that is then corrupted in place by a small set of operations chosen from the seed. Each operation
is recorded so `rerun` can reproduce the exact mutant from its log. Standard library only.
"""

import os
import random
import struct
import subprocess

PAGE = 0x1000


def reflink(base, dst):
    if os.path.exists(dst):
        os.unlink(dst)
    subprocess.run(['cp', '--reflink=auto', base, dst], check=True)


def _fill(fd, off, data):
    os.pwrite(fd, data, off)


class Mutator:
    """Applies operations to an open, writable mutant fd and records them."""

    def __init__(self, fd, size, rng):
        self.fd, self.size, self.rng = fd, size, rng
        self.log = []

    def flip(self, off, n=1):
        off = max(0, min(off, max(0, self.size - 1)))
        n = max(1, min(n, self.size - off))
        cur = bytearray(os.pread(self.fd, n, off))
        if not cur:                         # off is past a truncated EOF; nothing to flip
            return
        for i in range(len(cur)):
            cur[i] ^= 1 << self.rng.randrange(8)
        _fill(self.fd, off, bytes(cur))
        self.log.append(('flip', off, len(cur)))

    def zero(self, off, n):
        off = max(0, min(off, self.size))
        n = max(1, min(n, self.size - off))
        _fill(self.fd, off, b'\x00' * n)
        self.log.append(('zero', off, n))

    def garbage(self, off, n):
        off = max(0, min(off, self.size))
        n = max(1, min(n, self.size - off))
        _fill(self.fd, off, self.rng.randbytes(n))
        self.log.append(('garbage', off, n))

    def setbytes(self, off, data):
        off = max(0, min(off, self.size))
        data = data[:self.size - off]
        _fill(self.fd, off, data)
        self.log.append(('setbytes', off, data.hex()))

    def qword(self, off, val):
        if 0 <= off <= self.size - 8:
            _fill(self.fd, off, struct.pack('<Q', val & 0xffffffffffffffff))
            self.log.append(('qword', off, val & 0xffffffffffffffff))

    def punch(self, off, n):
        """Deallocate a range (reads back as zeros); cheap, no disk cost."""
        off = max(0, min(off, self.size))
        n = max(1, min(n, self.size - off))
        try:
            os.posix_fallocate  # noqa
        except AttributeError:
            pass
        # FALLOC_FL_PUNCH_HOLE(2)|KEEP_SIZE(1)
        import ctypes
        libc = ctypes.CDLL('libc.so.6', use_errno=True)
        if libc.fallocate(self.fd, 3, ctypes.c_long(off), ctypes.c_long(n)) != 0:
            _fill(self.fd, off, b'\x00' * n)
        self.log.append(('punch', off, n))

    def apply(self, op):
        name = op[0]
        if name == 'flip':
            self.flip(op[1], op[2])
        elif name == 'zero':
            self.zero(op[1], op[2])
        elif name == 'garbage':
            self.garbage(op[1], op[2])
        elif name == 'setbytes':
            self.setbytes(op[1], bytes.fromhex(op[2]))
        elif name == 'qword':
            self.qword(op[1], op[2])
        elif name == 'punch':
            self.punch(op[1], op[2])
        elif name == 'truncate':
            os.ftruncate(self.fd, op[1])
            self.size = op[1]          # later ops clamp against the new size
            self.log.append(('truncate', op[1]))


def choose_ops(tg, seed, nops):
    """Pick nops corruption operations from the target set for this seed.

    Strategies, weighted: byte flips / zeroing / garbage in a random page-table page, kernel
    object, symbol, container header or arbitrary data page; cyclic list pointers; huge counts;
    truncation. Returns a list of (op-tuple, description) -- ops are resolved to file offsets
    here so the mutant is reproducible from the log alone.
    """
    rng = random.Random(seed)
    ops = []
    tables = tg.get('tables', [])
    objects = tg.get('objects', [])
    symbols = tg.get('symbols', [])
    headers = tg.get('headers', [])
    ranges = tg.get('data_ranges', [])
    size = tg['size']

    def rand_data_off():
        if not ranges:
            return rng.randrange(size)
        off, n = rng.choice(ranges)
        return off + rng.randrange(max(1, n))

    focus = tg.get('_focus', 'mixed')
    strategies = []
    if focus == 'objects':
        # keep the kernel discoverable (no page-table / truncation kills) and hammer the
        # per-object code paths: object bytes, cyclic lists, kernel symbols, scattered pages
        if objects:
            strategies += ['obj', 'obj', 'obj', 'cyclic', 'cyclic', 'cyclic']
        if symbols:
            strategies += ['sym', 'sym']
        strategies += ['page', 'huge']
        if not strategies:
            strategies = ['page']
    elif focus == 'structure':
        # attack the layer/translation/container machinery
        if tables:
            strategies += ['pt', 'pt', 'pt']
        if headers:
            strategies += ['hdr', 'hdr', 'hdr']
        strategies += ['zeropage', 'garbagepage', 'trunc', 'trunc', 'huge']
    else:
        if tables:
            strategies += ['pt', 'pt', 'pt']
        if objects:
            strategies += ['obj', 'obj', 'obj', 'cyclic', 'cyclic']
        if symbols:
            strategies += ['sym', 'sym']
        if headers:
            strategies += ['hdr', 'hdr']
        strategies += ['page', 'page', 'zeropage', 'garbagepage', 'huge', 'trunc']

    for _ in range(nops):
        s = rng.choice(strategies)
        if s == 'pt':
            lvl, pa = rng.choice(tables)
            foff = tg['pt_foff'].get(str(pa)) if 'pt_foff' in tg else None
            if foff is None:
                continue
            # flip bits inside a random entry (present/large/pfn bits) or zero the whole table
            if rng.random() < 0.3:
                ops.append((('zero', foff, PAGE), f'zero PT L{lvl} pa={pa:#x}'))
            else:
                e = rng.randrange(512) * 8
                ops.append((('flip', foff + e, rng.choice([1, 2, 4])), f'flip PTE L{lvl} pa={pa:#x}+{e:#x}'))
        elif s == 'obj':
            o = rng.choice(objects)
            if not o['parts']:
                continue
            voff, foff, n = rng.choice(o['parts'])
            rel = rng.randrange(n)
            kind = rng.choice(['flip', 'flip', 'garbage', 'zero'])
            span = rng.choice([1, 2, 4, 8, 16])
            ops.append(((kind, foff + rel, span), f"{kind} {o['kind']} va={o['va']:#x}+{voff + rel:#x}"))
        elif s == 'cyclic':
            o = rng.choice(objects)
            if not o.get('lists') or not o['parts']:
                continue
            fld, moff = rng.choice(o['lists'])
            # make Flink (and Blink) point back at the list node -> self-referential cyclic list
            node = (o['va'] + moff) & 0xffffffffffffffff
            fo = _va_to_foff(o, o['va'] + moff)
            if fo is not None:
                ops.append((('qword', fo, node), f"cyclic {o['kind']} {fld} va={o['va']:#x}"))
                fo2 = _va_to_foff(o, o['va'] + moff + 8)
                if fo2 is not None:
                    ops.append((('qword', fo2, node), f"cyclic {o['kind']} {fld}.blink"))
            else:
                _voff, foff, n = rng.choice(o['parts'])
                ops.append((('qword', foff, node), f"cyclic-approx {o['kind']}"))
        elif s == 'sym':
            sy = rng.choice(symbols)
            if not sy['parts']:
                continue
            _voff, foff, n = rng.choice(sy['parts'])
            kind = rng.choice(['garbage', 'zero', 'flip', 'huge'])
            if kind == 'huge':
                ops.append((('qword', foff, rng.choice([0x7fffffffffffffff, 0xffffffffffffffff, 1 << 40])),
                            f"huge {sy['name']}"))
            else:
                ops.append(((kind if kind != 'flip' else 'flip', foff, rng.choice([4, 8, 16])),
                            f"{kind} sym {sy['name']}"))
        elif s == 'hdr':
            foff, n, what = rng.choice(headers)
            kind = rng.choice(['flip', 'garbage', 'zero'])
            rel = rng.randrange(max(1, n))
            ops.append(((kind, foff + rel, rng.choice([1, 2, 4, 8])), f"{kind} header {what}+{rel:#x}"))
        elif s == 'page':
            ops.append((('flip', rand_data_off(), rng.choice([1, 4, 16, 64])), 'flip data'))
        elif s == 'zeropage':
            ops.append((('punch', (rand_data_off() // PAGE) * PAGE, PAGE * rng.choice([1, 4, 16])), 'zero pages'))
        elif s == 'garbagepage':
            ops.append((('garbage', (rand_data_off() // PAGE) * PAGE, PAGE), 'garbage page'))
        elif s == 'huge':
            # overwrite a random 4-byte count/length field with a huge value (log form: hex str)
            ops.append((('setbytes', rand_data_off(), 'ffffff7f'), 'huge count'))
        elif s == 'trunc':
            cut = rng.randrange(int(size * 0.05), size)
            ops.append((('truncate', cut), f'truncate at {cut:#x}'))
    return ops


def _va_to_foff(obj, va):
    """File offset of a virtual address inside a harvested object.

    parts are [voff, file_offset, length] triples (voff = offset from obj.va); find the one
    whose virtual span contains va.
    """
    off = va - obj['va']
    for (voff, ff, ln) in obj['parts']:
        if voff <= off < voff + ln:
            return ff + (off - voff)
    return None
