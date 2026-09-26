#!/bin/bash
# LZNT1: rsvol vs reference C decoders (ntfs-3g, libfwnt, Wine), in-process decode throughput,
# same inputs, same machine, best of N, fresh output buffer per run.
#
#   bench/refbench/lznt1_ref.sh [WORK_DIR] [RUNS] [SOURCE_FILE...]
#
# There is no LZNT1 library to link against, so the reference decoders are built from source:
#  1. downloads (once) ntfs-3g libntfs-3g/compress.c, libyal libfwnt libfwnt_lznt1.[ch] and
#     Wine dlls/ntdll/rtl.c into WORK_DIR/src (GPL/LGPL: not vendored in this repo);
#  2. extracts their LZNT1 functions and builds WORK_DIR/lznt1_ref from lznt1_ref.c
#     (gcc -O3 -march=native);
#  3. makes the corpus: each SOURCE_FILE (default: binary.bin and big.json of the codecs corpus)
#     cut to a multiple of 4096 bytes, at most 32 MiB (so every chunk is full and all decoders,
#     padding or not, produce the same bytes) -> WORK_DIR/NAME, compressed with ntfs-3g's
#     compressor (lazy-matching, as NTFS) -> WORK_DIR/NAME.lznt1;
#  4. runs every decoder and rsvol's codecs_bench_file pinned to $CPU (default 12), $ROUNDS
#     interleaved rounds, best taken; both sides also report user-mode cycles.
# Keep WORK_DIR on disk (not the tmpfs /tmp).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
WORK=${1:-$ROOT/bench/out/lznt1}
RUNS=${2:-10}
shift $(($# < 2 ? $# : 2))
CORPUS=${CORPUS:-$ROOT/bench/out/corpus}
if [ $# -gt 0 ]; then SOURCES=("$@"); else SOURCES=("$CORPUS/binary.bin" "$CORPUS/big.json"); fi
CPU=${CPU:-12}
ROUNDS=${ROUNDS:-3}
LIMIT=${LIMIT:-/home/user/rs-vol/bench/scripts/limit.sh}

mkdir -p "$WORK/src" "$WORK/build/shim"
SRC=$WORK/src
BUILD=$WORK/build
fetch() { [ -s "$SRC/$1" ] || curl -sSfL --max-time 60 -o "$SRC/$1" "$2"; }
fetch compress.c https://raw.githubusercontent.com/tuxera/ntfs-3g/edge/libntfs-3g/compress.c
fetch libfwnt_lznt1.c https://raw.githubusercontent.com/libyal/libfwnt/main/libfwnt/libfwnt_lznt1.c
fetch libfwnt_lznt1.h https://raw.githubusercontent.com/libyal/libfwnt/main/libfwnt/libfwnt_lznt1.h
fetch rtl.c https://raw.githubusercontent.com/wine-mirror/wine/master/dlls/ntdll/rtl.c

# ntfs-3g: from the le16_to_cpup override through the end of ntfs_decompress().
awk '/^#undef le16_to_cpup/{p=1} p{print} p&&/^static int ntfs_decompress\(/{d=1} d&&/^}/{exit}' \
    "$SRC/compress.c" > "$BUILD/ntfs3g_lznt1.inc"
# Wine: lznt1_decompress_chunk() and lznt1_decompress().
awk '/^\/\* decompress a single LZNT1 chunk \*\//{p=1} p{print} p&&/^static NTSTATUS lznt1_decompress\(/{d=1} d&&/^}/{exit}' \
    "$SRC/rtl.c" > "$BUILD/wine_lznt1.inc"
# libfwnt: compiled as is against minimal libyal shims.
printf '#include <limits.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n#include <sys/types.h>\n' \
    > "$BUILD/shim/common.h"
: > "$BUILD/shim/types.h"
: > "$BUILD/shim/libfwnt_libcnotify.h"
echo '#define byte_stream_copy_to_uint16_little_endian(b, v) (v) = (uint16_t)((b)[0] | ((b)[1] << 8))' \
    > "$BUILD/shim/byte_stream.h"
echo '#define memory_copy(d, s, n) memcpy(d, s, n)' > "$BUILD/shim/memory.h"
echo '#define LIBFWNT_EXTERN extern' > "$BUILD/shim/libfwnt_extern.h"
printf 'typedef void libcerror_error_t;\n#define libcerror_error_set(...) ((void)0)\n' \
    > "$BUILD/shim/libfwnt_libcerror.h"
gcc -O3 -march=native -fno-strict-aliasing -w -I"$BUILD/shim" -I"$BUILD" -I"$SRC" \
    -o "$WORK/lznt1_ref" "$HERE/lznt1_ref.c" "$SRC/libfwnt_lznt1.c"

for s in "${SOURCES[@]}"; do
    name=$(basename "$s")
    [ -s "$WORK/$name.lznt1" ] && continue
    size=$(stat -c %s "$s")
    size=$((size > 33554432 ? 33554432 : size / 4096 * 4096))
    if [ "$(realpath "$s")" != "$(realpath -m "$WORK/$name")" ]; then
        head -c "$size" "$s" > "$WORK/$name"
    fi
    "$WORK/lznt1_ref" compress "$WORK/$name" "$WORK/$name.lznt1"
done

BIN=$(cd "$ROOT" && "$LIMIT" -m 6G cargo test --release --no-run 2>&1 | grep -oE 'Executable .*\((.*)\)' | sed -E 's/.*\((.*)\)/\1/' | head -1)
BIN="$ROOT/$BIN"
pin=("$LIMIT" -m 2G taskset -c "$CPU")
min() { awk -v a="$1" -v b="$2" 'BEGIN{print (b<a)?b:a}'; }

printf '%-14s %7s %9s %9s %9s %9s %8s %9s %9s\n' file out_MB ntfs3g libfwnt wine rsvol vs_best C_Mcyc rs_Mcyc
for s in "${SOURCES[@]}"; do
    f="$WORK/$(basename "$s").lznt1"
    declare -A ms=([ntfs3g]=1e18 [libfwnt]=1e18 [wine]=1e18 [rust]=1e18) cy=([ntfs3g]=1e18 [libfwnt]=1e18 [wine]=1e18 [rust]=1e18)
    out=0
    for ((r = 0; r < ROUNDS; r++)); do
        for d in ntfs3g libfwnt wine; do
            read -r _ _ _ out t _ c _ _ <<< "$("${pin[@]}" "$WORK/lznt1_ref" "$d" "$f" "$RUNS" "${f%.lznt1}")"
            ms[$d]=$(min "${ms[$d]}" "$t")
            [[ $c != 0 ]] && cy[$d]=$(min "${cy[$d]}" "$c")
        done
        read -r _ _ _ out t _ c _ _ <<< "$(CODECS_BENCH_FILE="$f" CODECS_BENCH_CODEC=lznt1 CODECS_RUNS="$RUNS" \
            "${pin[@]}" "$BIN" codecs_bench_file --ignored --nocapture --test-threads=1 | grep -oE 'rust [a-z0-9-]+ .*')"
        ms[rust]=$(min "${ms[rust]}" "$t")
        [[ $c != 0 ]] && cy[rust]=$(min "${cy[rust]}" "$c")
    done
    awk -v n="$(basename "$f")" -v out="$out" -v a="${ms[ntfs3g]}" -v b="${ms[libfwnt]}" -v c="${ms[wine]}" \
        -v r="${ms[rust]}" -v ca="${cy[ntfs3g]}" -v cb="${cy[libfwnt]}" -v cc="${cy[wine]}" -v cr="${cy[rust]}" 'BEGIN{
        best = a; if (b < best) best = b; if (c < best) best = c;
        bc = ca; if (cb < bc) bc = cb; if (cc < bc) bc = cc;
        printf "%-14s %7.1f %9.1f %9.1f %9.1f %9.1f %7.2fx %9.1f %9.1f\n", n, out / 1e6, out / a / 1e3,
            out / b / 1e3, out / c / 1e3, out / r / 1e3, best / r, (bc < 1e17) ? bc / 1e6 : 0, (cr < 1e17) ? cr / 1e6 : 0 }'
    unset ms cy
done
echo "(MB/s of output; vs_best = fastest C decoder time / rsvol time; Mcyc = user-mode cycles, best C vs rsvol)"
