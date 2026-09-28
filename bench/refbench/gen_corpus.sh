#!/bin/bash
# Generates the codec benchmark corpus.
#   bench/refbench/gen_corpus.sh [CORPUS_DIR]   (default: testdata/scratch/codecs/corpus, on disk: never tmpfs)
# Naming: BASE[.VARIANT].EXT, where BASE is the uncompressed reference file.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA=${FASTVOL_DATA:-$(dirname "$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$ROOT/.git")")}
CORPUS=${1:-$DATA/testdata/scratch/codecs/corpus}
mkdir -p "$CORPUS"
cd "$CORPUS"

ISF=${ISF:-$HOME/.cache/volatility3/symbols/windows/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B3-1.json.xz}
# two more real ISFs for big.json, no default (set one to "" to leave it out); the corpus the codec
# benchmarks ran on used linux-5.15.134.json (dwarf2json) and ntkrnlmp.pdb/2B2A15FA1FE2122BB1A39ED3572741D2-1.json.xz
: "${LINUX_ISF?set LINUX_ISF to a dwarf2json linux ISF (.json), or to \"\" to leave it out of big.json}"
: "${ISF2?set ISF2 to a second windows kernel ISF (.json.xz), or to \"\" to leave it out of big.json}"

# 1. The real ISF exactly as volatility ships/caches it (python lzma output).
cp "$ISF" isf.json.xz
xz -dc isf.json.xz > isf.json

# 2. ~50 MB of real ISF JSON (linux dwarf2json ISF + two windows kernel ISFs).
{
    if [ -f "$LINUX_ISF" ]; then cat "$LINUX_ISF"; fi
    cat isf.json
    if [ -f "$ISF2" ]; then xz -dc "$ISF2"; fi
} > big.json
while [ "$(stat -c %s big.json)" -lt 40000000 ]; do cat isf.json >> big.json; done

# 3. Incompressible, highly repetitive, and binary (executables/libraries) data.
head -c 33554432 /dev/urandom > random.bin
{ yes 'rsvol: highly repetitive line of text 0123456789 abcdefghijklmnopqrstuvwxyz' || true; } | head -c 67108864 > repeat.bin
: > binary.bin
for f in /usr/lib/libLLVM*.so* /usr/lib/libstdc++.so* /usr/lib/libc.so.6 /usr/bin/* ; do
    [ -f "$f" ] && [ ! -L "$f" ] && cat "$f" >> binary.bin
    [ "$(stat -c %s binary.bin)" -gt 48000000 ] && break
done
head -c 48000000 binary.bin > binary.tmp && mv binary.tmp binary.bin

# xz / lzma
xz -6 -T1 -c big.json > big.json.l6.xz
xz -9e -T1 -c big.json > big.json.l9e.xz
xz -1 -T1 -c big.json > big.json.l1.xz
xz -6 -T0 -c big.json > big.json.mt.xz
xz -6 -T1 -c random.bin > random.bin.xz
xz -6 -T1 -c repeat.bin > repeat.bin.xz
xz -6 -T1 -c binary.bin > binary.bin.xz
xz --x86 --lzma2=preset=6 -T1 -c binary.bin > binary.bin.x86.xz
xz --format=lzma -6 -c big.json > big.json.lzma
xz --format=lzma -6 -c isf.json > isf.json.lzma

# gzip / zlib
for l in 1 6 9; do gzip -$l -c big.json > big.json.l$l.gz; done
gzip -6 -c isf.json > isf.json.gz
gzip -6 -c random.bin > random.bin.gz
gzip -6 -c repeat.bin > repeat.bin.gz
gzip -6 -c binary.bin > binary.bin.gz
python3 -c 'import sys,zlib; sys.stdout.buffer.write(zlib.compress(open(sys.argv[1],"rb").read(), 6))' big.json > big.json.zz
python3 -c 'import sys,zlib; sys.stdout.buffer.write(zlib.compress(open(sys.argv[1],"rb").read(), 6))' binary.bin > binary.bin.zz

# bzip2
for l in 1 9; do bzip2 -$l -c big.json > big.json.l$l.bz2; done
bzip2 -9 -c isf.json > isf.json.bz2
bzip2 -9 -c random.bin > random.bin.bz2
bzip2 -9 -c repeat.bin > repeat.bin.bz2
bzip2 -9 -c binary.bin > binary.bin.bz2

ls -la "$CORPUS"
