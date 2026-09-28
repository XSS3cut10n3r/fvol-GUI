#!/bin/bash
# Build and run the libcapstone reference benchmark (see capstone_bench.c) and, with --rust, the
# Rust side (examples/disasm_bench.rs, release build), under the memory-capped job wrapper.
#
# Usage: bench/refbench/capstone_bench.sh [--rust] [CORPUS_DIR] [PASSES] [WORKLOADS]
#   CORPUS_DIR  default /home/user/fvol/testdata/scratch/disasm/ref/bin (bench/scripts/disasm_bench_corpus.py output)
#   PASSES      best of N (default 5)
#   WORKLOADS   comma list of text,line,detail,cdetail,len (default all)
set -e
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
limit=/home/user/fvol/bench/scripts/limit.sh
rust=0
if [ "$1" = "--rust" ]; then rust=1; shift; fi
dir=${1:-/home/user/fvol/testdata/scratch/disasm/ref/bin}
passes=${2:-5}
work=${3:-text,line,detail,cdetail,len}
out=/home/user/fvol/testdata/scratch/disasm/perf/capstone_bench
mkdir -p "$(dirname "$out")"
gcc -O3 -march=native -o "$out" "$here/capstone_bench.c" -lcapstone
$limit -m 4G "$out" "$dir" "$passes" "$work"
if [ $rust = 1 ]; then
  (cd "$repo" && $limit -m 4G cargo build -q --release --example disasm_bench)
  $limit -m 4G "$repo/target/release/examples/disasm_bench" "$dir" "$passes" "$work"
fi
