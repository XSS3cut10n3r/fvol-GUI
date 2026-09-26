#!/bin/bash
# Rust codecs vs reference C libraries (liblzma / zlib / libbz2): in-process decode
# throughput, same inputs, same machine, best of N, fresh output buffer per run.
#
#   bench/refbench/run.sh [CORPUS_DIR] [RUNS] [NAME_FILTER]
#
# Both sides run pinned to one CPU ($CPU, default 8) and are interleaved ($ROUNDS rounds,
# min taken) so background load affects them alike. Files named *.mt.xz are run unpinned
# (multi-threaded decoders on both sides: lzma_stream_decoder_mt vs rsvol's block-parallel
# decode).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
CORPUS=${1:-$ROOT/bench/out/corpus}
RUNS=${2:-10}
FILTER=${3:-}
CPU=${CPU:-8}
ROUNDS=${ROUNDS:-2}

gcc -O3 -march=native -o "$HERE/refbench" "$HERE/refbench.c" -llzma -lz -lbz2
BIN=$(cd "$ROOT" && cargo test --release --no-run 2>&1 | grep -oE 'Executable .*\((.*)\)' | sed -E 's/.*\((.*)\)/\1/' | head -1)
BIN="$ROOT/$BIN"

printf '%-26s %-7s %10s %10s %10s %8s\n' file codec out_MB c_MB/s rust_MB/s ratio
for f in "$CORPUS"/*; do
    name=$(basename "$f")
    [[ -n "$FILTER" && "$name" != *$FILTER* ]] && continue
    case "$name" in
        *.mt.xz) codec=xz-mt ;;
        *.xz) codec=xz ;;
        *.lzma) codec=lzma ;;
        *.gz) codec=gzip ;;
        *.zz) codec=zlib ;;
        *.bz2) codec=bz2 ;;
        *) continue ;;
    esac
    base=${f%.*}
    case "${base##*.}" in l[0-9]*|mt|x86|delta) base=${base%.*} ;; esac
    pin=(taskset -c "$CPU")
    [[ $codec == xz-mt ]] && pin=()
    cbest=0; rbest=0; out=0
    for ((r = 0; r < ROUNDS; r++)); do
        c=$("${pin[@]}" "$HERE/refbench" "$codec" "$f" "$RUNS" "$base")
        rs=$(CODECS_BENCH_FILE="$f" CODECS_BENCH_CODEC="$codec" CODECS_RUNS="$RUNS" \
            "${pin[@]}" "$BIN" codecs_bench_file --ignored --nocapture --test-threads=1 | grep -oE 'rust [a-z0-9-]+ .*')
        cm=$(echo "$c" | awk '{print $6}'); rm_=$(echo "$rs" | awk '{print $6}')
        out=$(echo "$c" | awk '{print $4}')
        cbest=$(awk -v a="$cbest" -v b="$cm" 'BEGIN{print (b>a)?b:a}')
        rbest=$(awk -v a="$rbest" -v b="$rm_" 'BEGIN{print (b>a)?b:a}')
    done
    printf '%-26s %-7s %10.1f %10.1f %10.1f %7.2fx\n' "$name" "$codec" \
        "$(awk -v n="$out" 'BEGIN{print n/1e6}')" "$cbest" "$rbest" \
        "$(awk -v a="$cbest" -v b="$rbest" 'BEGIN{print b/a}')"
done
