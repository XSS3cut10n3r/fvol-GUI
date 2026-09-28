#!/bin/bash
# zlib_exact (Rust, bit-exact zlib 1.3.2 deflate) vs the system zlib 1.3.2 (C), and png_rgba_pillow
# vs Pillow's Image.save(PNG): in-process throughput, same inputs, best of N, pinned to one P-core.
#
#   bench/refbench/zlib_exact_run.sh [PNG_CORPUS_DIR] [RUNS]
#
# PNG_CORPUS_DIR (default testdata/png_corpus) is made by
#   bench/venv/bin/python bench/refbench/png_pillow_oracle.py DIR
# General-purpose inputs come from /home/user/fvol/testdata/scratch/codecs/corpus (gen_corpus.sh).
# The zlib part feeds Pillow's filtered scanline stream (decompressed IDAT) one (4W+1)-byte row
# per deflate(Z_NO_FLUSH) call with Pillow's parameters (6, 15, 9, Z_FILTERED), and the general
# files in one deflate(Z_FINISH) with python zlib.compress's parameters (L, 15, 8, default).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
PNGDIR=${1:-$ROOT/testdata/png_corpus}
RUNS=${2:-5}
CORPUS=${CORPUS:-/home/user/fvol/testdata/scratch/codecs/corpus}
CPU=${CPU:-8}
ROUNDS=${ROUNDS:-3}
PY=${PY:-/home/user/fvol/bench/venv/bin/python}
LIMIT=${LIMIT:-/home/user/fvol/bench/scripts/limit.sh}

mkdir -p "$ROOT/target"
REF="$ROOT/target/zlib_exact_ref"
gcc -O3 -march=native -o "$REF" "$HERE/zlib_exact_ref.c" -lz
BIN=$(cd "$ROOT" && /home/user/fvol/bench/scripts/cargo.sh test --release --no-run 2>&1 | grep -oE 'Executable .*\((.*)\)' | sed -E 's/.*\((.*)\)/\1/' | head -1)
BIN="$ROOT/$BIN"
"$PY" "$HERE/png_pillow_bench.py" extract "$PNGDIR"
pin=("$LIMIT" -m 2G taskset -c "$CPU")

min() { awk -v a="$1" -v b="$2" 'BEGIN{print (b<a)?b:a}'; }

echo "== deflate: zlib 1.3.2 (C) vs zlib_exact (Rust), identical output =="
printf '%-26s %-10s %6s %9s %9s %9s %9s %7s\n' input params rowlen in_MB out_MB C_MB/s rust_MB/s speedup
bench_one() { # file params rowlen
    local f=$1 params=$2 rowlen=$3 cms=1e18 rms=1e18 cout rout inb
    IFS=, read -r L W M S <<< "$params"
    for ((r = 0; r < ROUNDS; r++)); do
        read -r _ _ _ _ inb cout ms _ <<< "$("${pin[@]}" "$REF" bench "$L" "$W" "$M" "$S" "$f" "$RUNS" "$rowlen")"
        cms=$(min "$cms" "$ms")
        read -r _ _ _ _ _ rout ms _ <<< "$(ZX_FILE="$f" ZX_PARAMS="$params" ZX_ROWLEN="$rowlen" ZX_RUNS="$RUNS" \
            "${pin[@]}" "$BIN" zlib_exact_bench --ignored --nocapture --test-threads=1 | grep -oE 'rust zlib_exact .*')"
        rms=$(min "$rms" "$ms")
    done
    [[ $cout == "$rout" ]] || echo "SIZE MISMATCH $f: C $cout rust $rout"
    awk -v n="$(basename "$f")" -v p="$params" -v rl="$rowlen" -v inb="$inb" -v out="$cout" -v c="$cms" -v r="$rms" 'BEGIN{
        printf "%-26s %-10s %6s %9.2f %9.2f %9.1f %9.1f %6.2fx\n", n, p, rl, inb/1e6, out/1e6, inb/c/1e3, inb/r/1e3, c/r }'
}
for img in desktop_1920x1080 text_1920x1080 gradient_1920x1080 black_1920x1080 noise_1920x1080 desktop_1024x768 rgb565_1024x768; do
    f="$PNGDIR/$img.filtered"
    [[ -f $f ]] || continue
    w=${img##*_}; w=${w%x*}
    bench_one "$f" 6,15,9,1 $((4 * w + 1))
done
for f in "$CORPUS/isf.json" "$CORPUS/big.json" "$CORPUS/binary.bin" "$CORPUS/random.bin"; do
    [[ -f $f ]] || continue
    bench_one "$f" 6,15,8,0 0
done
if [[ -f $CORPUS/isf.json ]]; then
    for L in 1 3 4 9; do bench_one "$CORPUS/isf.json" $L,15,8,0 0; done
    bench_one "$CORPUS/isf.json" 6,15,9,1 0
fi

echo
echo "== PNG: Pillow 12.3.0 Image.save (C encoder) vs png_rgba_pillow (Rust), identical bytes =="
echo "   (Pillow is single-threaded; rust_1c pinned to one core, rust_2c = filter + deflate threads)"
printf '%-26s %10s %10s %10s %10s %8s %8s\n' image png_bytes pillow_ms rust_1c_ms rust_2c_ms x_1c x_2c
pin2=("$LIMIT" -m 2G taskset -c "$CPU,${CPU2:-$((CPU + 2))}")
for img in desktop_1920x1080 text_1920x1080 gradient_1920x1080 black_1920x1080 noise_1920x1080 desktop_1024x768; do
    f="$PNGDIR/$img.rgba"
    [[ -f $f ]] || continue
    pms=1e18; rms=1e18; r2ms=1e18
    for ((r = 0; r < ROUNDS; r++)); do
        read -r _ _ _ pn ms <<< "$("${pin[@]}" "$PY" "$HERE/png_pillow_bench.py" bench "$f" "$RUNS")"
        pms=$(min "$pms" "$ms")
        read -r _ _ _ rn ms <<< "$(PNG_BENCH="$f" PNG_RUNS="$RUNS" "${pin[@]}" "$BIN" png_bench --ignored --nocapture --test-threads=1 | grep -oE 'rust png .*')"
        rms=$(min "$rms" "$ms")
        read -r _ _ _ rn ms <<< "$(PNG_BENCH="$f" PNG_RUNS="$RUNS" "${pin2[@]}" "$BIN" png_bench --ignored --nocapture --test-threads=1 | grep -oE 'rust png .*')"
        r2ms=$(min "$r2ms" "$ms")
    done
    [[ $pn == "$rn" ]] || echo "SIZE MISMATCH $img: pillow $pn rust $rn"
    awk -v n="$img" -v b="$pn" -v p="$pms" -v r="$rms" -v r2="$r2ms" \
        'BEGIN{ printf "%-26s %10d %10.2f %10.2f %10.2f %7.2fx %7.2fx\n", n, b, p, r, r2, p/r, p/r2 }'
done
