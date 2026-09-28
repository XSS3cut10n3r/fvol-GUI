#!/bin/bash
# Time ours vs vol-rs per plugin (best of N runs, warm), output TSV: plugin ours_s volrs_s speedup
# Usage: bench_vs_volrs.sh [-b BIN] [-n N] [LIST]
#   -b BIN   our binary (default: $OURS, else /home/user/fvol/target/release/fvol)
# Dumped files go to $SCRATCH (default /home/user/fvol/testdata/scratch/bench_vs_volrs, on disk:
# a dumpfiles run writes 1.5-4.5 GB, too much for the RAM-backed /tmp); it is emptied per plugin.
N=3
OURS=${OURS:-/home/user/fvol/target/release/fvol}
while getopts b:n: o; do case $o in b) OURS=$OPTARG;; n) N=$OPTARG;; *) exit 2;; esac; done
shift $((OPTIND-1))
LIST=${1:-/home/user/fvol/bench/win_noarg.txt}
IMG=${IMG:-/home/user/cbc2/task2/memory-dirty.raw}
VOLRS=/home/user/cbc2/vol-rs/target/release/vol-rs
T=${SCRATCH:-/home/user/fvol/testdata/scratch/bench_vs_volrs}
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
