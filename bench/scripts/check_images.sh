#!/bin/bash
# Each invocation writes to its own dir (concurrent runs used to clobber a shared bench/out).
GATE_OUT=${GATE_OUT:-/home/user/fvol/testdata/scratch/gates/run-$$}; mkdir -p $GATE_OUT; find /home/user/fvol/testdata/scratch/gates -maxdepth 1 -name "run-*" -mmin +360 -exec rm -rf {} + 2>/dev/null
# Shared driver of check_nix.sh / check_win_images.sh: compare our binary against the python references of
# the images in bench/images.tsv (columns: name, os, image_path, symbol_args, ref_dir[, plugin_list]).
# Usage: check_images.sh -o OS[,OS...] [-b BIN] [NAME|PATTERN ...]
#   OS      windows | linux | mac (comma separated)
#   NAME    manifest names (bash globs allowed); default = every image of the selected OSes
# Each plugin of bench/{win,linux,mac}_noarg.txt that has <ref_dir>/<plugin>.txt is run via compare.sh
# (isfinfo.IsfInfo, which compare.sh checks against a live python run, only once per distinct symbol_args).
ROOT=/home/user/fvol
BIN=$ROOT/target/fast/fvol
OSES=
while [ $# -gt 0 ]; do
  case $1 in -b) BIN=$2; shift 2;; -o) OSES=$2; shift 2;; *) break;; esac
done
MANIFEST=${MANIFEST:-$ROOT/bench/images.tsv}
avail=$($BIN -h 2>/dev/null)
tot_ok=0; tot_bad=0; tot_miss=0; nimg=0
SEL=("$@")
selected() { # name -> 0 if it matches one of the NAME|PATTERN args
  local pat
  for pat in "${SEL[@]}"; do [[ $1 == $pat ]] && return 0; done
  return 1
}
declare -A isf_seen  # isfinfo output only depends on the symbol args: check it once per distinct value
while IFS=$'\t' read -r name os img symargs refdir plist; do
  [[ -z $name || $name == \#* ]] && continue
  [[ ",$OSES," == *",$os,"* ]] || continue
  if [ ${#SEL[@]} -gt 0 ]; then selected "$name" || continue; fi
  [ "$symargs" = "-" ] && symargs=
  case $os in windows) list=$ROOT/bench/win_noarg.txt;; linux) list=$ROOT/bench/linux_noarg.txt;;
              mac) list=$ROOT/bench/mac_noarg.txt;; *) continue;; esac
  if [ ! -r "$img" ]; then echo "== $name: image missing ($img)"; continue; fi
  ok=0; bad=0; miss=0; nimg=$((nimg+1))
  while read -r p; do
    [ -f "$refdir/$p.txt" ] || continue
    if [ "$p" = isfinfo.IsfInfo ]; then [ -n "${isf_seen[x$symargs]}" ] && continue; isf_seen[x$symargs]=1; fi
    if ! grep -qE "^ *$p( |$)" <<< "$avail"; then miss=$((miss+1)); continue; fi
    r=$(IMG=$img REF=$refdir/$p.txt OUTDIR=${OUTBASE:-$GATE_OUT}/$name DIFFLINES=${DIFFLINES:-3} \
        GLOBAL_ARGS="$symargs" $ROOT/bench/scripts/compare.sh -b $BIN $p 2>/dev/null < /dev/null)
    case "$r" in OK*) ok=$((ok+1));; *) bad=$((bad+1)); echo "[$name] $r";; esac
  done < $list
  echo "== $name: OK=$ok DIFF=$bad MISSING=$miss"
  tot_ok=$((tot_ok+ok)); tot_bad=$((tot_bad+bad)); tot_miss=$((tot_miss+miss))
done < $MANIFEST
echo "== TOTAL ($nimg images) OK=$tot_ok DIFF=$tot_bad MISSING=$tot_miss"
