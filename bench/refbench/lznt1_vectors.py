#!/usr/bin/env python3
"""Generates the LZNT1 test vectors embedded in src/codecs/lznt1.rs.

    python3 bench/refbench/lznt1_vectors.py [--ruby-lib PATH] > vectors.rs.txt

Streams come from an independent LZNT1 compressor written here (greedy / randomized /
literal-only strategies, forced raw chunks, arbitrary chunk sizes) and from ruby_smb's
compressor; every vector is decoded by the straightforward python decoder below AND by
ruby_smb's decoder (metasploit bundle), and must round-trip, before it is printed as Rust
constants (hex strings; big outputs as length + CRC-32).
"""
import os
import subprocess
import sys
import tempfile
import zlib

RUBY_LZNT1 = "/opt/metasploit/vendor/bundle/ruby/3.4.0/gems/ruby_smb-3.3.21/lib/ruby_smb/compression/lznt1.rb"


class Rng:
    """xorshift64*"""

    def __init__(self, seed):
        self.s = seed & 0xFFFFFFFFFFFFFFFF or 1

    def next(self):
        s = self.s
        s ^= s >> 12
        s ^= (s << 25) & 0xFFFFFFFFFFFFFFFF
        s ^= s >> 27
        self.s = s
        return (s * 0x2545F4914F6CDD1D) & 0xFFFFFFFFFFFFFFFF

    def below(self, n):
        return self.next() % n


WORDS = (b"the of and process thread handle token kernel module driver pool tag object "
         b"offset virtual physical layer symbol table windows linux mac vad mft registry "
         b"hive key value service socket file image dump scan plugin volatility memory").split()


def gen_text(rng, n):
    out = bytearray()
    while len(out) < n:
        out += WORDS[rng.below(len(WORDS))]
        r = rng.below(10)
        out += b"\n" if r == 0 else b", " if r == 1 else b" "
    return bytes(out[:n])


def gen_binary(rng, n):
    """Structure-like binary: zero runs, repeated records, small integers, random bytes."""
    out = bytearray()
    while len(out) < n:
        r = rng.below(6)
        if r == 0:
            out += b"\0" * (1 + rng.below(40))
        elif r == 1 and len(out) > 16:
            d = 1 + rng.below(min(len(out), 300))
            for _ in range(3 + rng.below(30)):
                out.append(out[-d])
        elif r == 2:
            out += rng.below(1 << 16).to_bytes(4, "little")
        elif r == 3:
            b = rng.below(256)
            out += bytes([b]) * (1 + rng.below(12))
        else:
            out += bytes(rng.below(256) for _ in range(1 + rng.below(8)))
    return bytes(out[:n])


def gen_random(rng, n):
    return bytes(rng.below(256) for _ in range(n))


def offset_bits(pos):
    return max(4, (pos - 1).bit_length())


def compress_chunk(chunk, strategy, rng):
    """Compressed chunk body (flag bytes + items) for `chunk` (<= 4096 bytes)."""
    n = len(chunk)
    heads = {}
    out = bytearray()
    pos = 0

    def insert(p):
        if p + 3 <= n:
            heads.setdefault(chunk[p:p + 3], []).append(p)

    while pos < n:
        fi = len(out)
        out.append(0)
        flags = 0
        for i in range(8):
            if pos >= n:
                break
            best = None
            if strategy != "literal" and pos > 0 and pos + 3 <= n:
                bits = offset_bits(pos)
                max_len = min((0xFFFF >> bits) + 3, n - pos)
                cands = []
                for p in reversed(heads.get(chunk[pos:pos + 3], [])[-64:]):
                    off = pos - p
                    if off > (1 << bits):
                        break
                    ln = 0
                    while ln < max_len and chunk[p + ln] == chunk[pos + ln]:
                        ln += 1
                    if ln >= 3:
                        cands.append((off, ln))
                if cands:
                    if strategy == "random":
                        if rng.below(5) != 0:
                            off, ln = cands[rng.below(len(cands))]
                            best = (off, 3 + rng.below(ln - 2))
                    else:
                        best = max(cands, key=lambda c: (c[1], -c[0]))
            if best:
                off, ln = best
                bits = offset_bits(pos)
                tok = ((off - 1) << (16 - bits)) | (ln - 3)
                out += tok.to_bytes(2, "little")
                flags |= 1 << i
                for p in range(pos, pos + ln):
                    insert(p)
                pos += ln
            else:
                out.append(chunk[pos])
                insert(pos)
                pos += 1
        out[fi] = flags
    return bytes(out)


def compress(data, strategy="greedy", sizes=None, raw=(), force=(), seed=1):
    """LZNT1 stream. `sizes`: input bytes per chunk (default 4096); chunk indexes in `raw`
    are stored, in `force` compressed even when that does not save space."""
    rng = Rng(seed)
    out = bytearray()
    pos = 0
    k = 0
    while pos < len(data):
        size = sizes[k] if sizes and k < len(sizes) else 4096
        chunk = data[pos:pos + size]
        body = compress_chunk(chunk, strategy, rng)
        if k not in raw and len(body) <= 4096 and (len(body) < len(chunk) or k in force):
            out += (0xB000 | (len(body) - 1)).to_bytes(2, "little") + body
        else:
            out += (0x3000 | (len(chunk) - 1)).to_bytes(2, "little") + chunk
        pos += len(chunk)
        k += 1
    return bytes(out)


def decompress(data, pad=False):
    """Plain reference decoder (no padding unless `pad`: Windows layout)."""
    out = bytearray()
    ip = 0
    while len(data) - ip >= 2:
        h = int.from_bytes(data[ip:ip + 2], "little")
        if h == 0:
            break
        size = (h & 0xFFF) + 1
        chunk = data[ip + 2:ip + 2 + size]
        assert len(chunk) == size, "truncated"
        ip += 2 + size
        if pad and len(out) % 4096:
            out += b"\0" * (4096 - len(out) % 4096)
        if not h & 0x8000:
            out += chunk
            continue
        base = len(out)
        s = 0
        while s < size:
            flags = chunk[s]
            s += 1
            for _ in range(8):
                if s >= size:
                    break
                if flags & 1:
                    tok = int.from_bytes(chunk[s:s + 2], "little")
                    assert s + 2 <= size, "token cut"
                    s += 2
                    pos = len(out) - base
                    bits = offset_bits(pos)
                    off = (tok >> (16 - bits)) + 1
                    ln = (tok & (0xFFFF >> bits)) + 3
                    assert 1 <= off <= pos and pos + ln <= 4096
                    for _ in range(ln):
                        out.append(out[-off])
                else:
                    out.append(chunk[s])
                    s += 1
                flags >>= 1
        assert len(out) - base <= 4096
    return bytes(out)


def ruby(action, blobs, lib):
    """Runs ruby_smb's LZNT1 compress/decompress over `blobs`."""
    with tempfile.TemporaryDirectory() as d:
        paths = []
        for i, b in enumerate(blobs):
            p = os.path.join(d, f"{i}.in")
            with open(p, "wb") as f:
                f.write(b)
            paths.append(p)
        script = (f'load {lib!r}; ARGV.each {{ |f| d = RubySMB::Compression::LZNT1.{action}'
                  f'(File.binread(f).b); File.binwrite(f + ".out", d.b) }}')
        subprocess.run(["ruby", "-e", script] + paths, check=True)
        res = []
        for p in paths:
            with open(p + ".out", "rb") as f:
                res.append(f.read())
        return res


def hexlines(name, data):
    h = data.hex()
    lines = [h[i:i + 100] for i in range(0, len(h), 100)] or [""]
    body = "\\\n        ".join(lines)
    return f'    const {name}: &str = "\\\n        {body}";\n'


def main():
    lib = RUBY_LZNT1
    if len(sys.argv) > 2 and sys.argv[1] == "--ruby-lib":
        lib = sys.argv[2]
    rng = Rng(0x5EED)
    text700 = gen_text(rng, 700)
    text300 = gen_text(rng, 300)
    multi_in = gen_text(rng, 4096) + gen_random(rng, 64) + gen_binary(rng, 4096) + gen_text(rng, 700)
    rle_in = b"a" * 4096 + b"b" * 4096 + b"ab" * 20
    pad_in = gen_text(rng, 1000) + gen_binary(rng, 4096) + gen_text(rng, 50)

    vectors = [
        # (name, stream, expected, embed_expected)
        ("TEXT", compress(text700), text700, True),
        ("RANDOMIZED", compress(text700, "random", seed=7), text700, True),
        ("RUBY", ruby("compress", [text300], lib)[0], text300, True),
        ("MULTI", compress(multi_in, sizes=[4096, 64, 4096, 700], raw={1}, force={3}, seed=3),
         multi_in, False),
        ("RLE", compress(rle_in), rle_in, False),
        ("SHORT_FIRST", compress(pad_in, sizes=[1000, 4096, 50], seed=5), pad_in, False),
    ]
    binv = gen_binary(rng, 4096)
    vectors.append(("BINARY", compress(binv), binv, False))

    streams = [v[1] for v in vectors]
    for (name, stream, expected, _), rb in zip(vectors, ruby("decompress", streams, lib)):
        assert decompress(stream) == expected, name
        assert rb == expected, f"ruby disagrees on {name}"

    out = ["    // Generated by bench/refbench/lznt1_vectors.py (verified with ruby_smb's decoder).\n"]
    for name, stream, expected, embed in vectors:
        out.append(hexlines(f"V_{name}", stream))
        if embed:
            out.append(hexlines(f"V_{name}_OUT", expected))
        else:
            out.append(f"    const V_{name}_OUT: (usize, u32) = ({len(expected)}, {zlib.crc32(expected):#010x});\n")
    padded = decompress(vectors[5][1], pad=True)
    out.append(f"    const V_SHORT_FIRST_PADDED: (usize, u32) = ({len(padded)}, {zlib.crc32(padded):#010x});\n")
    sys.stdout.write("".join(out))
    sys.stderr.write("stream sizes: " + ", ".join(f"{v[0]}={len(v[1])}" for v in vectors) + "\n")


if __name__ == "__main__":
    main()
