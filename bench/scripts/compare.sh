#!/bin/bash
# Usage: bench/scripts/compare.sh [-b BIN] PLUGIN [extra args...]
# Runs our binary on the Windows test image and diffs stdout against the Python volatility3
# reference in bench/ref/py/PLUGIN.txt (first line - the version banner - is compared too).
# Prints "OK <plugin> <secs>" or "DIFF <plugin>" followed by the first diff lines.
BIN=/home/user/rs-vol/target/fast/vol
if [ "$1" = "-b" ]; then BIN=$2; shift 2; fi
P=$1; shift
IMG=${IMG:-/home/user/cbc2/task2/memory-dirty.raw}
REF=${REF:-/home/user/rs-vol/bench/ref/py/$P.txt}
OUTDIR=${OUTDIR:-/home/user/rs-vol/bench/out}
mkdir -p $OUTDIR/dump/$P
s=$(date +%s%N)
$BIN -q $GLOBAL_ARGS -o $OUTDIR/dump/$P -f $IMG $P "$@" > $OUTDIR/$P.txt 2> $OUTDIR/$P.err
rc=$?
e=$(date +%s%N)
secs=$(( (e - s) / 1000000 ))
if cmp -s $OUTDIR/$P.txt $REF; then
  echo "OK $P ${secs}ms"
elif grep -qx "$P" /home/user/rs-vol/bench/nondeterministic.txt && cmp -s <(sort $OUTDIR/$P.txt) <(sort $REF); then
  echo "OK~ $P ${secs}ms (order; python order is nondeterministic)"
else
  echo "DIFF $P rc=$rc ${secs}ms  (ours: $OUTDIR/$P.txt  ref: $REF)"
  diff $REF $OUTDIR/$P.txt | head -${DIFFLINES:-15}
fi
