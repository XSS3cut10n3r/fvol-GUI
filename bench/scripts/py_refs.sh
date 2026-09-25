#!/bin/bash
# Generate Python volatility3 reference outputs for each plugin (no args) on the Windows image.
IMG=${IMG:-/home/user/cbc2/task2/memory-dirty.raw}
OUT=/home/user/rs-vol/bench/ref/py
LIST=${1:-/home/user/rs-vol/bench/win_noarg.txt}
run() {
  p=$1
  [ -s "$OUT/$p.txt" ] && return
  d=$OUT/dump/$p; mkdir -p $d
  s=$(date +%s.%N)
  timeout 5400 nice -n 10 /home/user/rs-vol/bench/venv/bin/python /home/user/rs-vol/volatility3/vol.py -q -o $d -f $IMG $p > $OUT/$p.tmp 2> $OUT/$p.err
  rc=$?
  e=$(date +%s.%N)
  mv $OUT/$p.tmp $OUT/$p.txt
  echo -e "$p\t$rc\t$(python3 -c "print(round($e-$s,3))")" >> $OUT/times.tsv
}
export -f run; export IMG OUT
cat $LIST | xargs -P ${PAR:-6} -I{} bash -c 'run {}'
