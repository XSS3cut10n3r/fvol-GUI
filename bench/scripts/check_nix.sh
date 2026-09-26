#!/bin/bash
# Check every linux/mac no-arg plugin on every linux/mac test image against the python references.
# Usage: check_nix.sh [-b BIN] [linux|mac|all]
BIN=/home/user/rs-vol/target/fast/vol
if [ "$1" = "-b" ]; then BIN=$2; shift 2; fi
WHICH=${1:-all}
R=/home/user/rs-vol/bench/ref; I=/home/user/rs-vol/testdata/images
avail=$($BIN -h 2>/dev/null)
tot_ok=0; tot_bad=0; tot_miss=0
run_set() { # os refdir image list
  local os=$1 refdir=$2 img=$3 list=$4 ok=0 bad=0 miss=0
  while read p; do
    [ -f "$refdir/$p.txt" ] || continue
    if ! grep -qE "^ *$p( |$)" <<< "$avail"; then miss=$((miss+1)); continue; fi
    r=$(IMG=$img REF=$refdir/$p.txt OUTDIR=/home/user/rs-vol/bench/out/$(basename $refdir) DIFFLINES=${DIFFLINES:-3} \
        GLOBAL_ARGS="-s /home/user/rs-vol/testdata/symbols" /home/user/rs-vol/bench/scripts/compare.sh -b $BIN $p 2>/dev/null)
    case "$r" in OK*) ok=$((ok+1));; *) bad=$((bad+1)); echo "[$(basename $refdir)] $r";; esac
  done < $list
  echo "== $(basename $refdir): OK=$ok DIFF=$bad MISSING=$miss"
  tot_ok=$((tot_ok+ok)); tot_bad=$((tot_bad+bad)); tot_miss=$((tot_miss+miss))
}
if [ "$WHICH" != mac ]; then
  for d in $R/linux/*/; do n=$(basename $d); base=${n%-*}; ext=${n##*-}
    run_set linux ${d%/} $I/linux/$base.$ext /home/user/rs-vol/bench/linux_noarg.txt; done
fi
if [ "$WHICH" != linux ]; then
  run_set mac $R/mac/rsvol-mac-mavericks-10.9.2 $I/mac/rsvol-mac-mavericks-10.9.2-13C64.dmp /home/user/rs-vol/bench/mac_noarg.txt
fi
echo "== TOTAL OK=$tot_ok DIFF=$tot_bad MISSING=$tot_miss"
