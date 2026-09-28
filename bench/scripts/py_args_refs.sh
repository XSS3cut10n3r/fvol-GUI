#!/bin/bash
# Generate python references for argument/renderer cases in bench/args_cases.txt (name<TAB>args)
# PAR python processes run at once (default 2; each takes 2-8 GB).
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA=${FASTVOL_DATA:-$(dirname "$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$ROOT/.git")")}
IMG=${IMG:-$DATA/testdata/images/windows/memory-dirty.raw}
OUT=$DATA/bench/ref/pyargs
run() {
  name=$1; args=$2
  [ -s "$OUT/$name.txt" ] && return
  d=$OUT/dump/$name; mkdir -p $d
  s=$(date +%s%N)
  eval "COLUMNS=80 $ROOT/bench/scripts/limit.sh -m 8G timeout 5400 nice -n 10 $DATA/bench/venv/bin/python $DATA/volatility3/vol.py -q -o $d -f $IMG $args" > $OUT/$name.tmp 2> $OUT/$name.err
  rc=$?; e=$(date +%s%N)
  mv $OUT/$name.tmp $OUT/$name.txt
  echo -e "$name\t$rc\t$(( (e-s)/1000000 ))ms\t$args" >> $OUT/times.tsv
}
export -f run; export IMG OUT ROOT DATA
while IFS=$'\t' read name args; do printf '%s\0%s\0' "$name" "$args"; done < ${1:-$ROOT/bench/args_cases.txt} | xargs -0 -n 2 -P ${PAR:-2} bash -c 'run "$0" "$1"'
