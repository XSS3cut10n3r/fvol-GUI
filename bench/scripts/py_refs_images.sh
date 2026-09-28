#!/bin/bash
# Generate python volatility3 reference outputs for images listed in bench/images.tsv.
# Usage: py_refs_images.sh [-l LIST] NAME...     (NAME = first manifest column; "all" = every image)
#   plugin list: -l LIST, else the manifest's optional 6th column, else bench/{win,linux,mac}_noarg.txt
#   PAR=2       python processes at once (each capped at 8G by limit.sh)
#   TIMEOUT=3600 per-plugin timeout (seconds)
#   PYCACHE=testdata/scratch/pycache-refs  private python --cache-path (see below; PYCACHE=default = shared cache)
# Per image: <ref_dir>/<plugin>.txt (stdout), .err (stderr), dump/<plugin>/ (files written by -o;
# empty dirs pruned) and times.tsv (plugin, rc, seconds). Plugins whose .txt already exists are skipped.
# A warm-up run (windows.info / banners) goes first, alone, so the kernel ISF is downloaded and the
# identifier cache refreshed before parallel runs (concurrent PDB downloads can clobber each other).
# Private cache: python's identifier cache (~/.cache/volatility3/identifier.cache) is pruned by every python
# run to the ISFs under *its* -s dirs, so concurrent python jobs of other agents make plugins fail with
# "Unable to validate the plugin requirements" / re-download ISFs, and make timeliner silently drop the
# rows of sub-plugins that failed. References therefore run with their own --cache-path (downloads still
# land in the first -s dir; ~/.cache/volatility3/symbols stays on python's symbol path).
# Retry pass: rc!=0 runs whose .err shows such a symbol/cache failure are re-run (RETRIES times, default 2).
HERE=$(cd "$(dirname "$0")/../.." && pwd)
# the main checkout: the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is there,
# and linked worktrees find it through git; FASTVOL_DATA overrides
ROOT=${FASTVOL_DATA:-$(dirname "$(git -C "$HERE" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$HERE/.git")")}
MANIFEST=${MANIFEST:-$ROOT/bench/images.tsv}
LISTOVR=
if [ "$1" = "-l" ]; then LISTOVR=$2; shift 2; fi
[ $# -gt 0 ] || { echo "usage: $0 [-l LIST] NAME...|all" >&2; exit 2; }
export VOL=$ROOT/volatility3/vol.py PY=$ROOT/bench/venv/bin/python TIMEOUT=${TIMEOUT:-3600}
PYCACHE=${PYCACHE:-$ROOT/testdata/scratch/pycache-refs}
if [ "$PYCACHE" = default ]; then export CACHEARGS=; else mkdir -p "$PYCACHE"; export CACHEARGS="--cache-path $PYCACHE"; fi
run() { # plugin  (env: IMG OUT SYMARGS)
  p=$1
  [ -s "$OUT/$p.txt" ] && return
  d=$OUT/dump/$p; mkdir -p "$d"
  s=$(date +%s.%N)
  $ROOT/bench/scripts/limit.sh -m 8G timeout $TIMEOUT nice -n 10 "$PY" "$VOL" -q $CACHEARGS $SYMARGS -o "$d" -f "$IMG" "$p" > "$OUT/$p.tmp" 2> "$OUT/$p.err"
  rc=$?
  e=$(date +%s.%N)
  mv "$OUT/$p.tmp" "$OUT/$p.txt"
  rmdir "$d" 2>/dev/null
  echo -e "$p\t$rc\t$(python3 -c "print(round($e-$s,3))")" >> "$OUT/times.tsv"
}
export -f run; export ROOT
names=("$@")
[ "$1" = all ] && names=($(grep -v '^#' $MANIFEST | cut -f1))
for n in "${names[@]}"; do
  row=$(awk -F'\t' -v n="$n" '!/^#/ && $1==n' $MANIFEST)
  [ -n "$row" ] || { echo "unknown image $n" >&2; continue; }
  IFS=$'\t' read -r name os IMG SYMARGS OUT PLIST <<< "$row"
  [ "$SYMARGS" = "-" ] && SYMARGS=
  # relative manifest paths (image, -s dirs, ref dir) are relative to the data root
  [[ $IMG == /* ]] || IMG=$ROOT/$IMG; [[ $OUT == /* ]] || OUT=$ROOT/$OUT
  SYMARGS=$(sed -E "s#((^| )-s +|;)([^/; ])#\1$ROOT/\3#g" <<< "$SYMARGS")
  case $os in windows) LIST=$ROOT/bench/win_noarg.txt; warm=windows.info.Info;;
              linux) LIST=$ROOT/bench/linux_noarg.txt; warm=banners.Banners;;
              mac) LIST=$ROOT/bench/mac_noarg.txt; warm=banners.Banners;; esac
  [ -n "$PLIST" ] && LIST=$ROOT/bench/$PLIST
  [ -n "$LISTOVR" ] && LIST=$LISTOVR
  export IMG OUT SYMARGS
  mkdir -p "$OUT"; touch "$OUT/times.tsv"
  echo "=== $name ($os) $IMG -> $OUT"
  run $warm
  grep -vx "$warm" "$LIST" | xargs -P ${PAR:-2} -I{} bash -c 'run {}'
  for try in $(seq 1 ${RETRIES:-2}); do
    flaky=$(awk -F'\t' '$2!=0{print $1}' "$OUT/times.tsv" | while read -r p; do
      grep -qE "Unable to validate the plugin requirements|could not be downloaded from remote server" "$OUT/$p.err" && echo "$p"; done)
    [ -n "$flaky" ] || break
    echo "retry $try: $(echo $flaky)"
    for p in $flaky; do
      rm -f "$OUT/$p.txt"; awk -F'\t' -v p="$p" '$1!=p' "$OUT/times.tsv" > "$OUT/times.tsv.new"; mv "$OUT/times.tsv.new" "$OUT/times.tsv"
      run "$p"
    done
  done
  sort -t$'\t' -k3 -n "$OUT/times.tsv" | tail -5
  awk -F'\t' '$2!=0{print "FAILED rc="$2": "$1}' "$OUT/times.tsv"
done
