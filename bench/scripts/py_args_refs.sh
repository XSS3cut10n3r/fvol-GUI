#!/bin/bash
# Generate python references for argument/renderer cases in bench/args_cases.txt (name<TAB>args)
# PAR python processes run at once (default 2; each takes 2-8 GB).
IMG=${IMG:-/home/user/cbc2/task2/memory-dirty.raw}
OUT=/home/user/fvol/bench/ref/pyargs
run() {
  name=$1; args=$2
  [ -s "$OUT/$name.txt" ] && return
  d=$OUT/dump/$name; mkdir -p $d
  s=$(date +%s%N)
  eval "COLUMNS=80 /home/user/fvol/bench/scripts/limit.sh -m 8G timeout 5400 nice -n 10 /home/user/fvol/bench/venv/bin/python /home/user/fvol/volatility3/vol.py -q -o $d -f $IMG $args" > $OUT/$name.tmp 2> $OUT/$name.err
  rc=$?; e=$(date +%s%N)
  mv $OUT/$name.tmp $OUT/$name.txt
  echo -e "$name\t$rc\t$(( (e-s)/1000000 ))ms\t$args" >> $OUT/times.tsv
}
export -f run; export IMG OUT
while IFS=$'\t' read name args; do printf '%s\0%s\0' "$name" "$args"; done < ${1:-/home/user/fvol/bench/args_cases.txt} | xargs -0 -n 2 -P ${PAR:-2} bash -c 'run "$0" "$1"'
