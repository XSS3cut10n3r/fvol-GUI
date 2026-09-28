#!/bin/bash
# libcapstone vs fastvol ARM / AArch64 decode+format throughput, interleaved runs (best of N),
# on random words and on real code blobs (raw .text, e.g. from llvm-objcopy -O binary).
#   bench/refbench/arm_bench.sh [ARM64_TEXT.bin] [ARM_TEXT.bin] [N]
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
BIN=${ARM_BENCH_BIN:-/home/user/fvol/testdata/scratch/disasm/arm/bin}
mkdir -p "$BIN"
gcc -O3 -march=native -o "$BIN/arm_bench" "$HERE/arm_bench.c" -lcapstone
(cd "$REPO" && cargo build -q --release --example disasm_diff_arm)
RS=$REPO/target/release/examples/disasm_diff_arm
T64=${1:-}
T32=${2:-}
N=${3:-10000000}
run() {  # label arch [file]
  local best_c=0 best_r=0
  for i in 1 2 3; do
    c=$("$BIN/arm_bench" "$2" "$N" $3 | sed -E 's/.* ([0-9.]+) M valid insn\/s.*/\1/')
    r=$("$RS" bench "$2" "$N" $3 | tail -1 | sed -E 's/.* ([0-9.]+) M valid insn\/s.*/\1/')
    best_c=$(echo "$c $best_c" | awk '{print ($1>$2)?$1:$2}')
    best_r=$(echo "$r $best_r" | awk '{print ($1>$2)?$1:$2}')
  done
  printf "%-22s capstone %6.2f M insn/s   fastvol %6.2f M insn/s   x%.1f\n" "$1" "$best_c" "$best_r" \
    "$(echo "$best_r $best_c" | awk '{print $1/$2}')"
}
run "arm64 random words" arm64
[ -n "$T64" ] && run "arm64 real code" arm64 "$T64"
run "arm random words" arm
[ -n "$T32" ] && run "arm real code" arm "$T32"
exit 0
