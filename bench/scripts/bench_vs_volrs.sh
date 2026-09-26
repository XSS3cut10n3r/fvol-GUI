#!/bin/bash
# Time ours vs vol-rs per plugin (best of N runs, warm), output TSV: plugin ours_s volrs_s speedup
# Usage: bench_vs_volrs.sh [-n N] [LIST]
N=3
if [ "$1" = "-n" ]; then N=$2; shift 2; fi
LIST=${1:-/home/user/rs-vol/bench/win_noarg.txt}
IMG=${IMG:-/home/user/cbc2/task2/memory-dirty.raw}
OURS=${OURS:-/home/user/rs-vol/target/release/vol}
VOLRS=/home/user/cbc2/vol-rs/target/release/vol-rs
T=$(mktemp -d)
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
rm -rf $T
