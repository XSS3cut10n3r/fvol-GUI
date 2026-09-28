#!/bin/bash
# Time ours vs vol-rs per plugin (best of N runs, warm), output TSV: plugin ours_s volrs_s speedup
# Usage: bench_vs_volrs.sh [-b BIN] [-n N] [LIST]
#   -b BIN   our binary (default: $OURS, else target/release/fvol of the main checkout)
# Dumped files go to $SCRATCH (default testdata/scratch/bench_vs_volrs, on disk:
# a dumpfiles run writes 1.5-4.5 GB, too much for the RAM-backed /tmp); it is emptied per plugin.
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA=${FASTVOL_DATA:-$(dirname "$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$ROOT/.git")")}
N=3
OURS=${OURS:-$DATA/target/release/fvol}
while getopts b:n: o; do case $o in b) OURS=$OPTARG;; n) N=$OPTARG;; *) exit 2;; esac; done
shift $((OPTIND-1))
LIST=${1:-$ROOT/bench/win_noarg.txt}
IMG=${IMG:-$DATA/testdata/images/windows/memory-dirty.raw}
VOLRS=${VOLRS:-vol-rs}
T=${SCRATCH:-$DATA/testdata/scratch/bench_vs_volrs}
mkdir -p $T || exit 1
best() { # cmd...
  local b=999999
  for i in $(seq $N); do
    local s=$(date +%s%N); "$@" > /dev/null 2>&1; local e=$(date +%s%N)
    local ms=$(( (e-s)/1000000 )); [ $ms -lt $b ] && b=$ms
  done; echo $b
}
printf "plugin\tours_ms\tvolrs_ms\tspeedup\n"
while read p; do
  rm -rf $T/o $T/v; mkdir -p $T/o $T/v
  o=$(best $OURS -q -o $T/o -f $IMG $p)
  v=$(best $VOLRS -q -o $T/v -f $IMG $p)
  printf "%s\t%s\t%s\t%s\n" $p $o $v $(python3 -c "print(round($v/max($o,1),2))")
done < $LIST
rm -rf $T/o $T/v
