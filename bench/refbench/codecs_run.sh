#!/bin/bash
# Rust codecs vs reference C libraries (liblzma / zlib / libbz2): in-process decode
# throughput, same inputs, same machine, best of N, fresh output buffer per run.
#
#   bench/refbench/codecs_run.sh [CORPUS_DIR] [RUNS] [NAME_FILTER]
#
# CORPUS_DIR (default /home/user/fvol/testdata/scratch/codecs/corpus) is made by
# bench/refbench/gen_corpus.sh; keep it on disk, never on tmpfs /tmp.
# Both sides run pinned to one CPU ($CPU, default 8) and are interleaved ($ROUNDS rounds,
# best taken) so background load affects them alike. Besides wall-clock MB/s, both harnesses
# read user-mode CPU cycles with perf_event_open; the cycle ratio is insensitive to frequency
# changes and preemption (useful on a loaded machine). Files named *.mt.xz run unpinned
# (multi-threaded decoders on both sides: lzma_stream_decoder_mt vs block-parallel fastvol);
# their cycle columns are the calling thread only and not comparable.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
CORPUS=${1:-/home/user/fvol/testdata/scratch/codecs/corpus}
RUNS=${2:-10}
FILTER=${3:-}
CPU=${CPU:-8}
ROUNDS=${ROUNDS:-3}
# Memory-capped scopes (see DESIGN.md "Resource safety").
LIMIT=${LIMIT:-/home/user/fvol/bench/scripts/limit.sh}

mkdir -p "$ROOT/target"
REF="$ROOT/target/codecs_refbench"
gcc -O3 -march=native -o "$REF" "$HERE/codecs_refbench.c" -llzma -lz -lbz2
BIN=$(cd "$ROOT" && "$LIMIT" -m 6G cargo test --release --no-run 2>&1 | grep -oE 'Executable .*\((.*)\)' | sed -E 's/.*\((.*)\)/\1/' | head -1)
BIN="$ROOT/$BIN"

printf '%-24s %-7s %8s %9s %9s %7s %9s %9s %7s\n' file codec out_MB C_MB/s rust_MB/s speedup C_Mcyc rust_Mcyc cyc_x
for f in "$CORPUS"/*; do
    name=$(basename "$f")
    [[ -n "$FILTER" && "$name" != *$FILTER* ]] && continue
    case "$name" in
        *.mt.xz|*.mt[0-9]*.xz) codec=xz-mt ;;
        *.xz) codec=xz ;;
        *.lzma) codec=lzma ;;
        *.gz) codec=gzip ;;
        *.zz) codec=zlib ;;
        *.bz2) codec=bz2 ;;
        *.lznt1) codec=lznt1 ;;
        *) continue ;;
    esac
    base=${f%.*}
    case "${base##*.}" in l[0-9]*|mt|mt[0-9]*|x86|delta) base=${base%.*} ;; esac
    pin=("$LIMIT" -m 2G taskset -c "$CPU")
    [[ $codec == xz-mt ]] && pin=("$LIMIT" -m 2G)
    cms=1e18; rms=1e18; ccy=1e18; rcy=1e18; out=0
    for ((r = 0; r < ROUNDS; r++)); do
        if [[ $codec != lznt1 ]]; then
            read -r _ _ _ out ms _ cyc _ _ <<< "$("${pin[@]}" "$REF" "$codec" "$f" "$RUNS" "$base")"
            cms=$(awk -v a="$cms" -v b="$ms" 'BEGIN{print (b<a)?b:a}')
            [[ $cyc != 0 ]] && ccy=$(awk -v a="$ccy" -v b="$cyc" 'BEGIN{print (b<a)?b:a}')
        fi
        read -r _ _ _ out ms _ cyc _ _ <<< "$(CODECS_BENCH_FILE="$f" CODECS_BENCH_CODEC="$codec" CODECS_RUNS="$RUNS" \
            "${pin[@]}" "$BIN" codecs_bench_file --ignored --nocapture --test-threads=1 | grep -oE 'rust [a-z0-9-]+ .*')"
        rms=$(awk -v a="$rms" -v b="$ms" 'BEGIN{print (b<a)?b:a}')
        [[ $cyc != 0 ]] && rcy=$(awk -v a="$rcy" -v b="$cyc" 'BEGIN{print (b<a)?b:a}')
    done
    awk -v n="$name" -v c="$codec" -v out="$out" -v cms="$cms" -v rms="$rms" -v ccy="$ccy" -v rcy="$rcy" 'BEGIN{
        cmb = (cms < 1e17) ? out / cms / 1e3 : 0; rmb = out / rms / 1e3;
        printf "%-24s %-7s %8.1f %9.1f %9.1f %6.2fx %9.1f %9.1f %6.2fx\n", n, c, out / 1e6, cmb, rmb,
            (cmb > 0) ? rmb / cmb : 0, (ccy < 1e17) ? ccy / 1e6 : 0, (rcy < 1e17) ? rcy / 1e6 : 0,
            (ccy < 1e17 && rcy < 1e17) ? ccy / rcy : 0 }'
done
