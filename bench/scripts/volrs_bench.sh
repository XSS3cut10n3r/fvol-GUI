#!/bin/bash
# Time vol-rs on each plugin (sequential, warm), saving outputs.
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA=${FASTVOL_DATA:-$(dirname "$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$ROOT/.git")")}
IMG=${IMG:-$DATA/testdata/images/windows/memory-dirty.raw}
OUT=$DATA/bench/ref/volrs
LIST=${1:-$ROOT/bench/win_noarg.txt}
: > $OUT/times.tsv
while read p; do
  d=$OUT/dump/$p; rm -rf $d; mkdir -p $d
  s=$(date +%s.%N)
  timeout 600 ${VOLRS:-vol-rs} -q -o $d -f $IMG $p > $OUT/$p.txt 2> $OUT/$p.err
  rc=$?
  e=$(date +%s.%N)
  echo -e "$p\t$rc\t$(python3 -c "print(round($e-$s,3))")" >> $OUT/times.tsv
done < $LIST
