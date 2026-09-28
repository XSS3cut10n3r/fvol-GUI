#!/bin/bash
# Generate Python volatility3 reference outputs for each no-arg linux plugin on a Linux image.
# Usage: IMG=<image> NAME=<imagename> [PAR=2] [LIST=linux_noarg.txt] py_refs_linux.sh
# Mirrors bench/scripts/py_refs.sh (the Windows equivalent) but for Linux images.
IMG=${IMG:?set IMG to the memory image path}
NAME=${NAME:?set NAME to the image short name}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA=${FASTVOL_DATA:-$(dirname "$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$ROOT/.git")")}
SYM=${SYM:-$DATA/testdata/symbols}
VOL=$DATA/volatility3/vol.py
PY=$DATA/bench/venv/bin/python
OUT=$DATA/bench/ref/linux/$NAME
LIST=${LIST:-$ROOT/bench/linux_noarg.txt}
mkdir -p "$OUT"
run() {
  p=$1
  [ -s "$OUT/$p.txt" ] && return
  d=$OUT/dump/$p; mkdir -p "$d"
  s=$(date +%s.%N)
  $ROOT/bench/scripts/limit.sh -m 8G timeout 3600 nice -n 10 "$PY" "$VOL" -q -s "$SYM" -o "$d" -f "$IMG" "$p" > "$OUT/$p.tmp" 2> "$OUT/$p.err"
  rc=$?
  e=$(date +%s.%N)
  mv "$OUT/$p.tmp" "$OUT/$p.txt"
  # prune empty dump dirs
  rmdir "$d" 2>/dev/null
  echo -e "$p\t$rc\t$(python3 -c "print(round($e-$s,3))")" >> "$OUT/times.tsv"
}
export -f run; export IMG NAME SYM OUT VOL PY ROOT
: > "$OUT/times.tsv"
cat "$LIST" | xargs -P ${PAR:-2} -I{} bash -c 'run {}'
echo "=== done: $NAME ==="
sort -t$'\t' -k3 -n "$OUT/times.tsv" | tail -8
awk -F'\t' '$2!=0{print "FAILED rc="$2": "$1}' "$OUT/times.tsv"
