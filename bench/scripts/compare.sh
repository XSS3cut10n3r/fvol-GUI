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
# isfinfo lists whatever symbol files are on disk right now (plus python's sqlite cache state), so a stored
# reference goes stale whenever symbol dirs change: compare it against a fresh python run instead.
if [ "$P" = "isfinfo.IsfInfo" ] && [ -z "$NO_LIVE_ISFINFO" ]; then
  mkdir -p $OUTDIR; LIVE=$OUTDIR/isfinfo.live.ref
  /home/user/rs-vol/bench/scripts/limit.sh -m 4G /home/user/rs-vol/bench/venv/bin/python /home/user/rs-vol/volatility3/vol.py -q $GLOBAL_ARGS -f $IMG isfinfo.IsfInfo > $LIVE 2>/dev/null
  REF=$LIVE
fi
rm -rf $OUTDIR/dump/$P; mkdir -p $OUTDIR/dump/$P
s=$(date +%s%N)
$BIN -q $GLOBAL_ARGS -o $OUTDIR/dump/$P -f $IMG $P "$@" > $OUTDIR/$P.txt 2> $OUTDIR/$P.err
rc=$?
e=$(date +%s%N)
secs=$(( (e - s) / 1000000 ))
if cmp -s $OUTDIR/$P.txt $REF; then
  echo "OK $P ${secs}ms"
elif grep -qx "$P" /home/user/rs-vol/bench/nondeterministic.txt && cmp -s <(sort $OUTDIR/$P.txt) <(sort $REF); then
  echo "OK~ $P ${secs}ms (order; python order is nondeterministic)"
elif [ "$P" = windows.info.Info ] && [ -z "$NO_LIVE_SYMBOLS" ] && cmp -s <(grep -v '^Symbols	' $OUTDIR/$P.txt) <(grep -v '^Symbols	' $REF) \
     && /home/user/rs-vol/bench/scripts/limit.sh -m 4G /home/user/rs-vol/bench/venv/bin/python /home/user/rs-vol/volatility3/vol.py -q $GLOBAL_ARGS -f $IMG $P > $OUTDIR/$P.live.ref 2>/dev/null \
     && cmp -s $OUTDIR/$P.txt $OUTDIR/$P.live.ref; then
  # the Symbols line names the kernel ISF python's identifier cache lists last: with the same ISF in several
  # symbol dirs it depends on the cache's history, which a stored reference cannot capture
  echo "OK~ $P ${secs}ms (Symbols line checked against a live python run: duplicate ISFs, python's identifier cache decides)"
else
  echo "DIFF $P rc=$rc ${secs}ms  (ours: $OUTDIR/$P.txt  ref: $REF)"
  diff $REF $OUTDIR/$P.txt | head -${DIFFLINES:-15}
fi
