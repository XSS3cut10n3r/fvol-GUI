#!/bin/bash
# Time vol-rs on each plugin (sequential, warm), saving outputs.
IMG=${IMG:-/home/user/cbc2/task2/memory-dirty.raw}
OUT=/home/user/fvol/bench/ref/volrs
LIST=${1:-/home/user/fvol/bench/win_noarg.txt}
: > $OUT/times.tsv
while read p; do
  d=$OUT/dump/$p; rm -rf $d; mkdir -p $d
  s=$(date +%s.%N)
  timeout 600 ~/cbc2/vol-rs/target/release/vol-rs -q -o $d -f $IMG $p > $OUT/$p.txt 2> $OUT/$p.err
  rc=$?
  e=$(date +%s.%N)
  echo -e "$p\t$rc\t$(python3 -c "print(round($e-$s,3))")" >> $OUT/times.tsv
done < $LIST
