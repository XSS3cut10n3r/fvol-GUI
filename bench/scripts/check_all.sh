#!/bin/bash
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA=${FASTVOL_DATA:-$(dirname "$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$ROOT/.git")")}
# Each invocation writes to its own dir (concurrent runs used to clobber a shared bench/out).
export OUTDIR=${OUTDIR:-$DATA/testdata/scratch/gates/run-$$/main}; mkdir -p $OUTDIR; find $DATA/testdata/scratch/gates -maxdepth 1 -name "run-*" -mmin +360 -exec rm -rf {} + 2>/dev/null
# Run every plugin in a list against its python reference; summary of OK/DIFF/MISSING.
# Usage: check_all.sh [-b BIN] [LIST]   (default list: bench/win_noarg.txt)
BIN=$DATA/target/fast/fvol
if [ "$1" = "-b" ]; then BIN=$2; shift 2; fi
LIST=${1:-$ROOT/bench/win_noarg.txt}
ok=0; bad=0; miss=0
avail=$($BIN -h 2>/dev/null)
while read p; do
  if ! grep -q " $p " <<< "$avail" && ! grep -q "^ *$p\b" <<< "$avail"; then miss=$((miss+1)); echo "MISSING $p"; continue; fi
  r=$(DIFFLINES=${DIFFLINES:-4} $ROOT/bench/scripts/compare.sh -b $BIN $p)
  case "$r" in OK*) ok=$((ok+1));; *) bad=$((bad+1));; esac
  echo "$r"
done < $LIST
echo "== OK=$ok DIFF=$bad MISSING=$miss"
