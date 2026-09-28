#!/bin/bash
# Rust encoders vs reference C libraries (zlib / libbz2 / liblzma, libdeflate for context):
# in-process compression throughput, same inputs, same machine, best of N.
#
#   bench/refbench/codecs_enc_run.sh [-t THREADS] [-r RUNS] "CODEC:LEVEL[:REF...] ..." FILE...
#
#   e.g. codecs_enc_run.sh "zlib:6 zlib:9" big.json binary.bin
#   CODEC for the Rust side: deflate | zlib | gzip | bz2 | xz.
#   Reference codecs run per spec: zlib:L -> zlib L (+ libdeflate L when LIBDEFLATE=1),
#   gzip:L -> zlib L, bz2:L -> libbz2 L, xz:L -> liblzma L (+ xz-mt with -t N > 1).
#
# Single-thread runs (-t 1, default) are pinned to one P-core ($CPU, default 8) on both sides.
# With -t N > 1 the Rust side runs with FASTVOL_THREADS=N (unpinned); the reference libraries are
# single-threaded (except xz-mt). Inputs must be on disk (never tmpfs /tmp).
# Output columns: file codec level in_MB | C out ratio MB/s | rust out ratio MB/s | size% speedup
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
THREADS=1
RUNS=3
while getopts "t:r:" o; do
    case $o in
        t) THREADS=$OPTARG ;;
        r) RUNS=$OPTARG ;;
        *) exit 2 ;;
    esac
done
shift $((OPTIND - 1))
SPECS=$1
shift
CPU=${CPU:-8}
LIMIT=${LIMIT:-$ROOT/bench/scripts/limit.sh}
MEM=${MEM:-4G}

mkdir -p "$ROOT/target"
REF="$ROOT/target/codecs_enc_refbench"
gcc -O3 -march=native -o "$REF" "$HERE/codecs_enc_refbench.c" -llzma -lz -lbz2 -ldeflate -lpthread
BIN=$(cd "$ROOT" && "$ROOT/bench/scripts/cargo.sh" test --release --no-run 2>&1 | grep -oE 'Executable .*\((.*)\)' | sed -E 's/.*\((.*)\)/\1/' | head -1)
BIN="$ROOT/$BIN"

if [[ $THREADS == 1 ]]; then pin=("$LIMIT" -m "$MEM" taskset -c "$CPU"); else pin=("$LIMIT" -m "$MEM"); fi

printf '%-22s %-8s %-3s %8s | %-10s %10s %6s %8s | %10s %6s %8s | %7s %7s\n' \
    file codec lvl in_MB ref ref_out ratio MB/s rust_out ratio MB/s size% speedup
for f in "$@"; do
    name=$(basename "$f")
    for spec in $SPECS; do
        codec=${spec%%:*}
        level=${spec#*:}
        refs=()
        case $codec in
            zlib | deflate | gzip) refs=(zlib) ; [[ ${LIBDEFLATE:-0} == 1 ]] && refs+=(libdeflate) ;;
            bz2) refs=(bz2) ;;
            xz) refs=(xz); [[ $THREADS -gt 1 ]] && refs+=(xz-mt) ;;
        esac
        read -r _ _ _ _ n rout rms _ _ < <(FASTVOL_THREADS=$THREADS CODECS_ENC_FILE="$f" CODECS_ENC_CODEC="$codec" \
            CODECS_ENC_LEVEL="$level" CODECS_RUNS="$RUNS" "${pin[@]}" "$BIN" codecs_enc_bench_file --ignored \
            --nocapture --test-threads=1 | grep -oE 'rust [a-z0-9-]+ .*')
        for ref in "${refs[@]}"; do
            rc=$ref
            [[ $ref == zlib ]] && rc=$codec
            [[ $rc == deflate ]] && rc=deflate
            read -r _ _ _ _ _ cout cms _ < <("${pin[@]}" "$REF" "$rc" "$level" "$f" "$RUNS" "$THREADS")
            awk -v f="$name" -v c="$codec" -v l="$level" -v n="$n" -v ref="$ref" -v cout="$cout" -v cms="$cms" \
                -v rout="$rout" -v rms="$rms" 'BEGIN{
                printf "%-22s %-8s %-3s %8.1f | %-10s %10d %6.2f %8.1f | %10d %6.2f %8.1f | %6.1f%% %6.2fx\n",
                    f, c, l, n / 1e6, ref, cout, n / cout, n / cms / 1e3, rout, n / rout, n / rms / 1e3,
                    100 * rout / cout, cms / rms }'
        done
    done
done
