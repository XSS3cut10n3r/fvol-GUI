#!/usr/bin/env python3
"""Reference Xpress encoders ([MS-XCA] Plain LZ77 and LZ77+Huffman), written independently of
the Rust decoders, used to generate the test vectors in this directory.

    python3 gen_xpress.py <outdir>

Originals are produced by gen_data() (mirrored in src/codecs/xpress.rs tests) so only the
compressed streams are stored.
"""
import heapq
import struct
import sys

M = (1 << 64) - 1
WORDS = [b"volatility", b"memory", b"kernel", b"\x00" * 8, b"process", b"handle",
         b"\\Device\\HarddiskVolume3\\Windows", b"ntoskrnl.exe", b"\xff\xff"]


def gen_data(seed, n):
    x = seed & M
    out = bytearray()

    def nxt():
        nonlocal x
        x ^= (x << 13) & M
        x ^= x >> 7
        x ^= (x << 17) & M
        return x

    while len(out) < n:
        r = nxt() % 100
        if r < 30:
            out += WORDS[nxt() % len(WORDS)]
        elif r < 40:
            out += b"\x00" * (nxt() % 700)
        elif r < 55 and out:
            start = nxt() % len(out)
            ln = nxt() % 300
            out += out[start:start + ln]
        else:
            k = 1 + nxt() % 16
            for _ in range(k):
                out.append(nxt() & 0xff)
    return bytes(out[:n])


def find_matches(data, max_off, min_len=3):
    """Greedy parse: yields ('L', byte) or ('M', offset, length)."""
    table = {}
    i = 0
    n = len(data)
    while i < n:
        best_len = 0
        best_off = 0
        if i + 3 <= n:
            key = data[i:i + 3]
            cands = table.get(key, [])
            for c in reversed(cands[-16:]):
                off = i - c
                if off > max_off:
                    break
                ln = 0
                while i + ln < n and data[c + ln] == data[i + ln] and ln < 70000:
                    ln += 1
                if ln > best_len:
                    best_len, best_off = ln, off
            table.setdefault(key, []).append(i)
        if best_len >= min_len:
            yield ('M', best_off, best_len)
            for k in range(i + 1, min(i + best_len, n - 2)):
                table.setdefault(data[k:k + 3], []).append(k)
            i += best_len
        else:
            yield ('L', data[i])
            i += 1


def lz77_compress(data):
    out = bytearray(b"\x00\x00\x00\x00")
    flags = 0
    flag_count = 0
    flag_pos = 0
    last_half = 0
    for el in find_matches(data, 8192):
        if el[0] == 'L':
            out.append(el[1])
            flags <<= 1
        else:
            _, off, ln = el
            ml = ln - 3
            mo = off - 1
            if ml < 7:
                out += struct.pack("<H", (mo << 3) | ml)
            else:
                out += struct.pack("<H", (mo << 3) | 7)
                ml -= 7
                if last_half == 0:
                    last_half = len(out)
                    out.append(min(ml, 15))
                else:
                    out[last_half] |= min(ml, 15) << 4
                    last_half = 0
                if ml >= 15:
                    ml -= 15
                    if ml < 255:
                        out.append(ml)
                    else:
                        out.append(255)
                        ml += 7 + 15
                        if ml < 65536:
                            out += struct.pack("<H", ml)
                        else:
                            out += struct.pack("<HI", 0, ml)
            flags = (flags << 1) | 1
        flag_count += 1
        if flag_count == 32:
            out[flag_pos:flag_pos + 4] = struct.pack("<I", flags & 0xffffffff)
            flag_count = 0
            flags = 0
            flag_pos = len(out)
            out += b"\x00\x00\x00\x00"
    flags <<= (32 - flag_count)
    flags |= (1 << (32 - flag_count)) - 1
    out[flag_pos:flag_pos + 4] = struct.pack("<I", flags & 0xffffffff)
    return bytes(out)


def huff_lengths(freqs, limit=15):
    syms = [s for s in range(512) if freqs[s]]
    if len(syms) == 1:
        freqs = list(freqs)
        freqs[0 if syms[0] != 0 else 1] = 1
        syms = [s for s in range(512) if freqs[s]]
    f = list(freqs)
    while True:
        heap = [(f[s], s, (s,)) for s in syms]
        heapq.heapify(heap)
        lengths = [0] * 512
        cnt = 1000
        while len(heap) > 1:
            a = heapq.heappop(heap)
            b = heapq.heappop(heap)
            for s in a[2] + b[2]:
                lengths[s] += 1
            heapq.heappush(heap, (a[0] + b[0], cnt, a[2] + b[2]))
            cnt += 1
        if max(lengths) <= limit:
            return lengths
        for s in syms:
            f[s] = (f[s] >> 1) + 1


class BitWriter:
    """Mirrors the decoder: two 16-bit words are prefetched; the decoder reads word k+2 once
    more than 16*(k+1) bits have been consumed (checked after each symbol and after each
    offset field). Length bytes are written at the current byte position."""

    def __init__(self, out):
        self.out = out
        self.slots = [len(out), len(out) + 2]
        self.reserved = 2
        out += b"\x00\x00\x00\x00"
        self.total = 0
        self.acc = []  # pending bits

    def bits(self, value, n):
        for k in range(n - 1, -1, -1):
            self.acc.append((value >> k) & 1)
        self.total += n
        # decoder refill points
        while self.total > 16 * (self.reserved - 1):
            self.slots.append(len(self.out))
            self.reserved += 1
            self.out += b"\x00\x00"
        self._emit_full_words()

    def _emit_full_words(self):
        while len(self.acc) >= 16:
            w = 0
            for b in self.acc[:16]:
                w = (w << 1) | b
            self.acc = self.acc[16:]
            pos = self.slots.pop(0)
            self.out[pos:pos + 2] = struct.pack("<H", w)

    def byte(self, b):
        self.out.append(b)

    def flush(self):
        if self.acc:
            self.acc += [0] * (16 - len(self.acc))
            self._emit_full_words()


def huffman_compress(data):
    elements = list(find_matches(data, 65535))
    out = bytearray()
    pos = 0
    ei = 0
    while ei < len(elements) or pos == 0:
        block_start = pos
        blk = []
        while ei < len(elements) and pos < block_start + 65536:
            el = elements[ei]
            blk.append(el)
            pos += 1 if el[0] == 'L' else el[2]
            ei += 1
        last = ei >= len(elements)
        syms = []
        for el in blk:
            if el[0] == 'L':
                syms.append((el[1], None))
            else:
                _, off, ln = el
                obits = off.bit_length() - 1
                ml = ln - 3
                syms.append((256 + (obits << 4) + min(ml, 15), (off, obits, ml)))
        if last:
            syms.append((256, (1, 0, 0)))  # end of stream marker
        freqs = [0] * 512
        for s, _ in syms:
            freqs[s] += 1
        lengths = huff_lengths(freqs)
        # canonical codes
        codes = [0] * 512
        code = 0
        for bl in range(1, 16):
            for s in range(512):
                if lengths[s] == bl:
                    codes[s] = code
                    code += 1
            code <<= 1
        for i in range(256):
            out.append(lengths[2 * i] | (lengths[2 * i + 1] << 4))
        bw = BitWriter(out)
        for s, m in syms:
            bw.bits(codes[s], lengths[s])
            if m is None:
                continue
            off, obits, ml = m
            if ml >= 15:
                ml -= 15
                if ml < 255:
                    bw.byte(ml)
                else:
                    bw.byte(255)
                    ml += 15
                    if ml < 65536:
                        for b in struct.pack("<H", ml):
                            bw.byte(b)
                    else:
                        for b in struct.pack("<HI", 0, ml):
                            bw.byte(b)
            bw.bits(off - (1 << obits), obits)
        bw.flush()
        # zero-fill any reserved slots the decoder will read
        if last:
            break
    return bytes(out)


VECTORS = [
    # (name, seed, length)
    ("small", 1, 3000),
    ("medium", 2, 40000),
    ("multiblock", 3, 200000),
    ("zeros_runs", 4, 70000),
]


def main():
    outdir = sys.argv[1]
    for name, seed, n in VECTORS:
        data = gen_data(seed, n)
        if name == "zeros_runs":
            data = b"\x00" * 30000 + data[:10000] + b"\x00" * 30000
        c1 = lz77_compress(data)
        c2 = huffman_compress(data)
        open(f"{outdir}/xpress_lz77_{name}.bin", "wb").write(c1)
        open(f"{outdir}/xpress_huff_{name}.bin", "wb").write(c2)
        print(name, len(data), len(c1), len(c2), hex(sum(data) & 0xffffffff))


if __name__ == "__main__":
    main()
