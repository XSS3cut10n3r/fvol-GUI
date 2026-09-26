#!/usr/bin/env bash
# Codec throughput: reference C libraries vs rsvol (src/codecs), same inputs, in-process,
# best of N.
#   snappy       libsnappy (system, -lsnappy)
#   xpress_huff  wimlib 1.14.4 XPRESS decompressor (built from source into $WORK)
#   xpress_lz77  samba lib/compression/lzxpress.c (plain LZ77)
# Usage: bench/refbench/run.sh [RAW_IMAGE] [NCHUNKS] [REPS]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
RAW="${1:-/home/user/cbc2/task2/memory-dirty.raw}"
N="${2:-2048}"
REPS="${3:-7}"
export RSVOL_BENCH_CPU="${RSVOL_BENCH_CPU:-2}"   # pin both sides to one P-core
WORK="${WORK:-/tmp/rsvol-refbench}"
mkdir -p "$WORK"
cd "$WORK"

if [ ! -f wimlib-1.14.4/.libs/libwim.a ]; then
    curl -sSLO https://wimlib.net/downloads/wimlib-1.14.4.tar.gz
    tar xzf wimlib-1.14.4.tar.gz
    (cd wimlib-1.14.4 && ./configure --without-fuse --without-ntfs-3g --disable-shared --enable-static \
        CFLAGS="-O3 -march=native" >/dev/null && make -j"$(nproc)" libwim.la >/dev/null)
fi
if [ ! -f lzxpress.c ]; then
    curl -sSLO https://raw.githubusercontent.com/samba-team/samba/master/lib/compression/lzxpress.c
    curl -sSLO https://raw.githubusercontent.com/samba-team/samba/master/lib/compression/lzxpress.h
fi
gcc -O3 -march=native -o refbench "$HERE/refbench.c" lzxpress.c \
    -I. -I"$HERE/shim/inc" -Iwimlib-1.14.4/include \
    wimlib-1.14.4/.libs/libwim.a -lsnappy -lpthread
[ -f snappy.vec ] || ./refbench mkvec "$RAW" "$WORK" "$N"
./refbench bench "$WORK" "$REPS"
cd "$ROOT"
RSVOL_CODEC_BENCH="$WORK" RSVOL_BENCH_REPS="$REPS" cargo test --release codec_bench -- --ignored --nocapture 2>/dev/null \
    | grep -E "rsvol"
