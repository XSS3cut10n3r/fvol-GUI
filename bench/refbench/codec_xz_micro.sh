#!/usr/bin/env bash
# xz decode, rsvol vs liblzma, single-threaded and pinned: builds codec_xz_micro.rs with rustc
# (no crate build) and codecs_refbench.c with gcc, then runs both on every FILE, interleaved
# for $ROUNDS rounds of $RUNS decodes each, and prints best wall MB/s and best user-mode
# cycles per side.
#
#   bench/refbench/codec_xz_micro.sh [RUNS] FILE...
#   (no FILE: the codec corpus + the ISFs, see DEFAULT_FILES below)
#
# Env: CPU (default 8, a P-core), ROUNDS (3), WORK (build/scratch dir on disk),
#      OLD=1 also runs the lzma.rs/xz.rs copies in $WORK/old/ ("old" column, A/B runs),
#      RUSTFLAGS_EXTRA extra rustc flags.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-/home/user/rs-vol/testdata/scratch/xzperf}"
CPU="${CPU:-8}"
ROUNDS="${ROUNDS:-3}"
RUNS="${1:-10}"
shift || true
if [ $# -eq 0 ]; then
    C=/home/user/rs-vol/testdata/scratch/codecs/corpus
    set -- "$HOME/.cache/volatility3/symbols/windows/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B3-1.json.xz" \
        "/home/user/rs-vol/testdata/symbols/mac/Kernel_Debug_Kit_10.15.4_build_19E287.dmg.json.xz" \
        "$C/isf.json.xz" "$C/big.json.l1.xz" "$C/big.json.l6.xz" "$C/big.json.l9e.xz" \
        "$C/binary.bin.xz" "$C/binary.bin.x86.xz" "$C/random.bin.xz" "$C/repeat.bin.xz"
fi
mkdir -p "$WORK"
flags=(--edition 2024 -C opt-level=3 -C target-cpu=native -C codegen-units=1)
[ -n "${OLD:-}" ] && flags+=(--cfg old_lzma)
# shellcheck disable=SC2086
rustc "${flags[@]}" ${RUSTFLAGS_EXTRA:-} -o "$WORK/codec_xz_micro" "$HERE/codec_xz_micro.rs"
gcc -O3 -march=native -o "$WORK/codecs_refbench" "$HERE/codecs_refbench.c" -llzma -lz -lbz2

pin=(taskset -c "$CPU")
res="$WORK/micro.last"
: > "$res"
for ((r = 0; r < ROUNDS; r++)); do
    for f in "$@"; do
        "${pin[@]}" "$WORK/codecs_refbench" xz "$f" "$RUNS" >> "$res"
        "${pin[@]}" "$WORK/codec_xz_micro" bench "$RUNS" "$f" >> "$res"
    done
done
# columns: label file out ms MB/s cycles instructions branch-misses
awk -v files="$*" '
{
    if ($1 == "c") { for (i = 2; i < NF; i++) $i = $(i + 1); NF-- }  # "c xz FILE ..."
    k = $1 SUBSEP $2
    if (!(k in ms) || $4 < ms[k]) ms[k] = $4
    if (!(k in cy) || $6 < cy[k]) { cy[k] = $6; ins[k] = $7; bm[k] = $8 }
    out[$2] = $3; seen[$1] = 1
}
END {
    n = split(files, F, " ")
    printf "%-44s %7s %8s %8s %6s %8s %8s %6s %5s %5s", "file", "out_MB", "C_MB/s", "rs_MB/s", "wall_x", "C_Mcyc", "rs_Mcyc", "cyc_x", "C_IPC", "rsIPC"
    if ("old" in seen) printf " %8s %8s %6s", "old_MB/s", "old_Mcyc", "new/old"
    printf "\n"
    for (i = 1; i <= n; i++) {
        f = F[i]; c = "c" SUBSEP f; r = "rust" SUBSEP f; o = "old" SUBSEP f
        name = f; sub(/.*\//, "", name); if (length(name) > 44) name = substr(name, 1, 20) "~" substr(name, length(name) - 22)
        cmb = out[f] / ms[c] / 1e3; rmb = out[f] / ms[r] / 1e3
        printf "%-44s %7.1f %8.1f %8.1f %5.3fx %8.2f %8.2f %5.3fx %5.2f %5.2f", name, out[f] / 1e6, cmb, rmb, rmb / cmb, cy[c] / 1e6, cy[r] / 1e6, cy[c] / cy[r], ins[c] / cy[c], ins[r] / cy[r]
        if ("old" in seen) printf " %8.1f %8.2f %5.3fx", out[f] / ms[o] / 1e3, cy[o] / 1e6, cy[o] / cy[r]
        printf "\n"
    }
}' "$res"

