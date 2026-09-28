#!/bin/bash
# Generate Python volatility3 reference outputs for each plugin (no args) on the Windows image.
# PAR python processes run at once (default 2; each takes 2-8 GB).
IMG=${IMG:-/home/user/cbc2/task2/memory-dirty.raw}
OUT=${OUT:-/home/user/fvol/bench/ref/py}
LIST=${1:-/home/user/fvol/bench/win_noarg.txt}
run() {
  p=$1
  [ -s "$OUT/$p.txt" ] && return
  d=$OUT/dump/$p; mkdir -p $d
  s=$(date +%s.%N)
  /home/user/fvol/bench/scripts/limit.sh -m 8G timeout 5400 nice -n 10 /home/user/fvol/bench/venv/bin/python /home/user/fvol/volatility3/vol.py -q -o $d -f $IMG $p > $OUT/$p.tmp 2> $OUT/$p.err
  rc=$?
  e=$(date +%s.%N)
  mv $OUT/$p.tmp $OUT/$p.txt
  echo -e "$p\t$rc\t$(python3 -c "print(round($e-$s,3))")" >> $OUT/times.tsv
}
export -f run; export IMG OUT
cat $LIST | xargs -P ${PAR:-2} -I{} bash -c 'run {}'
