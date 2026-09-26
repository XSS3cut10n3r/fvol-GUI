#!/bin/bash
# Run every plugin in a list against its python reference; summary of OK/DIFF/MISSING.
# Usage: check_all.sh [-b BIN] [LIST]   (default list: bench/win_noarg.txt)
BIN=/home/user/rs-vol/target/fast/vol
if [ "$1" = "-b" ]; then BIN=$2; shift 2; fi
LIST=${1:-/home/user/rs-vol/bench/win_noarg.txt}
ok=0; bad=0; miss=0
avail=$($BIN -h 2>/dev/null)
while read p; do
  if ! grep -q " $p " <<< "$avail" && ! grep -q "^ *$p\b" <<< "$avail"; then miss=$((miss+1)); echo "MISSING $p"; continue; fi
  r=$(DIFFLINES=${DIFFLINES:-4} /home/user/rs-vol/bench/scripts/compare.sh -b $BIN $p)
  case "$r" in OK*) ok=$((ok+1));; *) bad=$((bad+1));; esac
  echo "$r"
done < $LIST
echo "== OK=$ok DIFF=$bad MISSING=$miss"
