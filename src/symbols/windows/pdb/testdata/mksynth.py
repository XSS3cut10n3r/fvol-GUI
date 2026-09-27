"""Test fixture generator (fastvol): `python3 mksynth.py synth.pdb [variant]`; the golden file
is `pdbconv.py -f synth.pdb -o synth.py.json` from volatility3 2.28.2, and every variant
(zero_elem ptrmix unhandled quad_enum strip_idx omap_high -> err_<variant>.pdb) makes python
raise.

Builds a small synthetic MSF 7.00 PDB exercising rarely used PdbReader paths:
OMAP, pascal (_ST) leaves and S_PUB32_ST, extended numeric leaves, forward referenced array
elements, modifiers, bitfields, <unnamed-tag> renaming, pointer32/pointer64 primitive
pointers, LF_ARGLIST parsed as LF_ENUM, the LF_UNION size quirk, IPI database naming,
name_strip variants, segment 0 / out-of-range segments, latin-1 names."""
import struct, sys

PS = 512
out = sys.argv[1]
V = sys.argv[2] if len(sys.argv) > 2 else ''


def num(v):
    if 0 <= v < 0x8000:
        return struct.pack('<H', v)
    if -128 <= v < 0:
        return struct.pack('<Hb', 0x8000, v)
    if -32768 <= v < 0:
        return struct.pack('<Hh', 0x8001, v)
    if 0 <= v < 0x10000:
        return struct.pack('<HH', 0x8002, v)
    if -2 ** 31 <= v < 0:
        return struct.pack('<Hi', 0x8003, v)
    return struct.pack('<HI', 0x8004, v)


def cstr(s):
    return (s.encode('latin-1') if isinstance(s, str) else s) + b'\0'


def pstr(s):
    b = s.encode('latin-1') if isinstance(s, str) else s
    return bytes([len(b)]) + b


def pad4(b):
    n = (-len(b)) % 4
    return b + bytes([0xF0 + n - i for i in range(n)])


class Types:
    def __init__(self):
        self.recs = []

    def add(self, leaf, payload):
        self.recs.append(struct.pack('<H', leaf) + payload)
        return 0x1000 + len(self.recs) - 1

    def blob(self, min_idx=0x1000):
        body = b''
        for r in self.recs:
            n = (-(len(r) + 2)) % 4
            r = r + bytes([0xF0 + n - i for i in range(n)])
            body += struct.pack('<H', len(r)) + r
        hdr = struct.pack('<IIIIIHHIIIIIIII', 20040203, 56, min_idx, min_idx + len(self.recs), len(body),
                          0xFFFF, 0xFFFF, 4, 0x3FFFF, 0, 0, 0, 0, 0, 0)[:56]
        return hdr + body


def member(ftype, off, name, st=False):
    if st:
        return struct.pack('<HHI', 0x1405, 3, ftype) + num(off) + pstr(name)
    return struct.pack('<HHI', 0x150D, 3, ftype) + num(off) + cstr(name)


def enumerate_(value, name):
    return struct.pack('<HH', 0x1502, 3) + num(value) + cstr(name)


def fieldlist(entries):
    return b''.join(pad4(e) for e in entries)


FWD = 0x80
t = Types()
# --- a dummy first record (python skips the name lookup for element type 0x1000) ---
if V != 'zero_elem':
    dummy = t.add(0x1001, struct.pack('<IH', 0x0074, 2))
# --- forward refs first (like MSVC) ---
fwd_b = t.add(0x1505, struct.pack('<HHIII', 0, FWD, 0, 0, 0) + num(0) + cstr('B'))
fwd_unnamed = t.add(0x1506, struct.pack('<HHI', 0, FWD, 0) + num(0) + cstr('<unnamed-tag>'))
# primitive pointers before any LF_POINTER -> "base": pointer32 / pointer64
fl_early = t.add(0x1203, fieldlist([member(0x0403, 0, 'p32'), member(0x0603, 4, 'p64'), member(0x0074, 12, 'i')]))
early = t.add(0x1505, struct.pack('<HHIII', 3, 0, fl_early, 0, 0) + num(16) + cstr('Early'))
# B definition
fl_b = t.add(0x1203, fieldlist([member(0x0022, 0, 'x'), member(0x0013, 8, 'y'), member(0x0041, 16, 'd')]))
def_b = t.add(0x1505, struct.pack('<HHIII', 3, 0, fl_b, 0, 0) + num(24) + cstr('B'))
# modifier(const B fwd), arrays of them (count via type_references), pointers, bitfield
mod_b = t.add(0x1001, struct.pack('<IH', fwd_b, 1))
arr_b = t.add(0x1503, struct.pack('<II', fwd_b, 0x23) + num(72) + cstr(''))
arr_mod_b = t.add(0x1503, struct.pack('<II', mod_b, 0x23) + num(48) + cstr(''))
arr_arr = t.add(0x1503, struct.pack('<II', arr_b, 0x23) + num(144) + cstr(''))
ptr_b = t.add(0x1002, struct.pack('<II', fwd_b, 0x0A | (4 << 13)))
ptr_ptr = t.add(0x1002, struct.pack('<II', ptr_b, 0x0A))  # size 0, pointer_type 0x0a -> 4
arglist = t.add(0x1201, struct.pack('<II', 1, 0x0074))
proc = t.add(0x1008, struct.pack('<IBBHI', 0x0003, 0, 0, 1, arglist))
ptr_proc = t.add(0x1002, struct.pack('<II', proc, 0x0A | (4 << 13)))
bf = t.add(0x1205, struct.pack('<IBB', 0x0022, 3, 5))
arr_char = t.add(0x1503, struct.pack('<II', 0x0070, 0x23) + num(0x9000) + cstr(''))  # LF_USHORT size
# unnamed union definition (renamed __unnamed_<idx>)
fl_u = t.add(0x1203, fieldlist([member(0x0074, 0, 'ui'), member(0x0040, 0, 'uf')]))
def_unnamed = t.add(0x1506, struct.pack('<HHI', 2, 0, fl_u) + num(4) + cstr('<unnamed-tag>'))
# union whose size needs LF_USHORT: python reads the raw u16 and the name from @10
fl_big = t.add(0x1203, fieldlist([member(0x0020, 0, 'c')]))
big_union = t.add(0x1506, struct.pack('<HHI', 1, 0, fl_big) + num(0x9041) + cstr('BigUnion'))
# enum with extended numeric leaves and a duplicate enumerator
fl_e = t.add(0x1203, fieldlist([enumerate_(0, 'A'), enumerate_(-1, 'NEG'), enumerate_(100000, 'L'),
                                 enumerate_(0xFFFFFFFF, 'UL'), enumerate_(-300, 'S'), enumerate_(0x9000, 'US'),
                                 enumerate_(5, 'A')]))
en = t.add(0x1507, struct.pack('<HHII', 7, 0, 0x0074, fl_e) + cstr('Colors'))
fwd_en = t.add(0x1507, struct.pack('<HHII', 0, FWD, 0x0074, 0) + cstr('Colors'))
# the main struct
fl_main = t.add(0x1203, fieldlist([
    member(0x0022, 0, 'a'),
    member(0x0603, 8, 'p64late'),           # pointer set to 4 later? (set below by ptr_b)
    member(arr_b, 16, 'arrB'),
    member(arr_mod_b, 88, 'arrConstB'),
    member(arr_arr, 136, 'arrArr'),
    member(bf, 280, 'bits'),
    member(ptr_b, 284, 'pB'),
    member(ptr_ptr, 288, 'ppB'),
    member(ptr_proc, 292, 'fn'),
    member(0x0403, 296, 'p32late'),
    member(0x0603, 300, 'p64late2'),
    member(fwd_unnamed, 308, 'u'),
    member(fwd_en, 312, 'color'),
    member(mod_b, 320, 'constB'),
    member(arr_char, 0x9000, 'bigarr'),     # LF_USHORT offset
    member(0x0022, -1, 'negoff'),           # LF_CHAR offset
    member(0x0074, 7, 'a'),                 # duplicate member: last wins
    member(0x0010, 9, 'st_member', st=True),  # LF_MEMBER_ST, pascal name
    member(0x0071, 10, 'caf\xe9 "q" \\ x'),  # latin-1 + escapes
]))
main = t.add(0x1505, struct.pack('<HHIII', 19, 0, fl_main, 0, 0) + num(0x9000 + 0x9000) + cstr('Main'))
# _ST structure (pascal name), VS19 class, a struct whose fields index is not a field list,
# an empty field list, a member typed by a raw (empty) field list
fl_st = t.add(0x1203, fieldlist([member(0x0021, 0, 'w')]))
st = t.add(0x1005, struct.pack('<HHIII', 1, 0, fl_st, 0, 0) + num(2) + pstr('OldStyle'))
vs19 = t.add(0x1608, struct.pack('<IIIIH', 0, fl_st, 0, 0, 1) + num(2) + cstr('Vs19Class'))
odd = t.add(0x1505, struct.pack('<HHIII', 0, 0, 0x1000, 0, 0) + num(4) + cstr('FieldsNotAList'))
fl_empty = t.add(0x1203, b'')
empty = t.add(0x1505, struct.pack('<HHIII', 0, 0, fl_empty, 0, 0) + num(1) + cstr('Empty'))
fl_rawlist = t.add(0x1203, fieldlist([member(fl_empty, 0, 'rawlist')]))
rawlist = t.add(0x1505, struct.pack('<HHIII', 1, 0, fl_rawlist, 0, 0) + num(4) + cstr('HasRawList'))
# redefinition of a name: last definition wins; anonymous tag
fl_dup = t.add(0x1203, fieldlist([member(0x0023, 0, 'second')]))
dup = t.add(0x1505, struct.pack('<HHIII', 1, 0, fl_dup, 0, 0) + num(8) + cstr('Early'))
fl_anon = t.add(0x1203, fieldlist([member(0x0068, 0, 'v')]))
anon = t.add(0x1505, struct.pack('<HHIII', 1, 0, fl_anon, 0, 0) + num(1) + cstr('__anonymous'))
latin = t.add(0x1505, struct.pack('<HHIII', 1, 0, fl_anon, 0, 0) + num(1) + cstr('\xe9t\xe9'))
lower = t.add(0x1505, struct.pack('<HHIII', 1, 0, fl_anon, 0, 0) + num(1) + cstr('alpha'))
if V == 'ptrmix':
    p8 = t.add(0x1002, struct.pack('<II', 0x0074, 0x0C | (8 << 13)))
    flm = t.add(0x1203, fieldlist([member(p8, 0, 'p8')]))
    t.add(0x1505, struct.pack('<HHIII', 1, 0, flm, 0, 0) + num(8) + cstr('Mixed'))
if V == 'unhandled':
    t.add(0x000A, struct.pack('<H', 0))
if V == 'quad_enum':
    flq = t.add(0x1203, fieldlist([struct.pack('<HHHQ', 0x1502, 3, 0x8009, 1 << 40) + cstr('Q')]))
    t.add(0x1507, struct.pack('<HHII', 1, 0, 0x0074, flq) + cstr('Quad'))
tpi = t.blob()

# --- IPI ---
ipi_t = Types()
ipi_t.add(0x1605, struct.pack('<I', 0) + cstr('C:\\x\\synth.pdb'))
ipi_t.add(0x1605, struct.pack('<I', 0) + cstr('cl.exe'))
ipi_t.add(0x1605, struct.pack('<I', 0) + cstr('D:\\y\\other.pdb'))
ipi_t.add(0x1605, struct.pack('<I', 0) + cstr('C:\\x\\synth.pdb'))
ipi_t.add(0x1603, struct.pack('<HIII', 3, 0x1000, 0x1001, 0x1002))
ipi_t.add(0x1606, struct.pack('<III', main, 0x1000, 42))
ipi_t.add(0x1607, struct.pack('<IIIH', main, 0x1000, 43, 1))
ipi_t.add(0x1601, struct.pack('<II', 0, proc) + cstr('func'))
ipi = ipi_t.blob()

# --- symbols ---
def pub(name, off, seg, leaf=0x110E, pascal=False):
    body = struct.pack('<HIIH', leaf, 0, off, seg) + (pstr(name) if pascal else cstr(name))
    body += b'\0' * ((-len(body) - 2) % 4)
    return struct.pack('<H', len(body)) + body

syms = b''.join([
    pub('_foo@12', 0x10, 1),
    pub('?bar@@YAXXZ', 0x20, 1),
    pub('\x7fIMPORT_DESCRIPTOR_x', 0x30, 2),
    pub('@fast@8', 0x40, 1),
    pub('_x', 0x50, 1),
    pub('__imp_Y', 0x60, 2),
    pub('_dup', 0x70, 1),
    pub('_dup', 0x80, 2),
    pub('_n@\xb2', 0x90, 1),
    pub('?q@12', 0x94, 1),
    pub('_a@b@c', 0x98, 1),
    pub('_tail@', 0x9c, 1),
    pub('pascal_sym', 0xa0, 1, leaf=0x1009, pascal=True),
    pub('lprocref', 0x10, 1, leaf=0x1127),
    pub('gdata_ignored', 0xb0, 1, leaf=0x110D),
    pub('seg0_last_section', 0x10, 0),
    pub('out_of_range_seg', 0x10, 3),
    pub('below_omap', 0x10, 0),
    pub('in_zero_region', 0x1100 - 0x1000, 2),
    pub('caf\xe9"\\', 0xc0, 1),
    pub('', 0xd0, 1),
] + ([pub('_@12', 0x10, 1)] if V == 'strip_idx' else [])
  + ([pub('too_high', 0x1800, 2)] if V == 'omap_high' else []) + [
])

def section(name, va):
    return name.ljust(8, b'\0') + struct.pack('<IIIIIIHHI', 0x1000, va, 0x1000, 0, 0, 0, 0, 0, 0)

sections = section(b'.text', 0x1000) + section(b'.data', 0x2000) + section(b'.junk', 0x0)
omap = b''.join(struct.pack('<II', s, d) for s, d in [(0x0, 0x7000), (0x1000, 0x11000), (0x1100, 0), (0x2000, 0x22000), (0x3000, 0x33000)])

info = struct.pack('<III', 20000404, 0x5A5A5A5A, 3) + bytes(range(0x10, 0x20)) + b'\0' * 8
dbg = struct.pack('<11h', -1, -1, -1, -1, 7, -1, -1, -1, -1, -1, 6)
dbi = struct.pack('<IIIHHHHHHIIIIIIIIHHI', 0xFFFFFFFF, 19990903, 3, 0xFFFF, 0, 0xFFFF, 0, 5, 0,
                  0, 0, 0, 0, 0, 0, len(dbg), 0, 0, 0x14C, 0) + dbg
streams = [b'', info, tpi, dbi, ipi, syms, sections, omap]

# --- MSF container ---
pages = [None, b'\0' * PS, b'\0' * PS]  # superblock + 2 FPM pages

def alloc(data):
    n = (len(data) + PS - 1) // PS
    first = len(pages)
    for i in range(n):
        pages.append(data[i * PS:(i + 1) * PS].ljust(PS, b'\0'))
    return list(range(first, first + n))

plists = [alloc(s) for s in streams]
directory = struct.pack('<I', len(streams)) + b''.join(struct.pack('<I', len(s)) for s in streams)
for pl in plists:
    directory += b''.join(struct.pack('<I', p) for p in pl)
dir_pages = alloc(directory)
block_map = alloc(b''.join(struct.pack('<I', p) for p in dir_pages))
pages[0] = (b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0' +
            struct.pack('<IIIII', PS, 1, len(pages), len(directory), 0) +
            struct.pack('<I', block_map[0])).ljust(PS, b'\0')
open(out, 'wb').write(b''.join(pages))
print(out, len(pages) * PS, 'bytes')
