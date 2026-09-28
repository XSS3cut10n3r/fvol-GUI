#!/bin/bash
# Generate Python volatility3 reference outputs for each plugin (no args) on the Windows image.
# PAR python processes run at once (default 2; each takes 2-8 GB).
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA=${FASTVOL_DATA:-$(dirname "$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$ROOT/.git")")}
IMG=${IMG:-$DATA/testdata/images/windows/memory-dirty.raw}
OUT=${OUT:-$DATA/bench/ref/py}
LIST=${1:-$ROOT/bench/win_noarg.txt}
run() {
  p=$1
  [ -s "$OUT/$p.txt" ] && return
  d=$OUT/dump/$p; mkdir -p $d
  s=$(date +%s.%N)
  $ROOT/bench/scripts/limit.sh -m 8G timeout 5400 nice -n 10 $DATA/bench/venv/bin/python $DATA/volatility3/vol.py -q -o $d -f $IMG $p > $OUT/$p.tmp 2> $OUT/$p.err
  rc=$?
  e=$(date +%s.%N)
  mv $OUT/$p.tmp $OUT/$p.txt
  echo -e "$p\t$rc\t$(python3 -c "print(round($e-$s,3))")" >> $OUT/times.tsv
}
export -f run; export IMG OUT ROOT DATA
cat $LIST | xargs -P ${PAR:-2} -I{} bash -c 'run {}'
