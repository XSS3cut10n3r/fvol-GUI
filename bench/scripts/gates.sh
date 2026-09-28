#!/bin/bash
# The pre-commit output gates with a private fastvol cache, each run cold (empty cache) then warm:
#   check_all.sh (Windows, 98 plugins) and check_nix.sh (Linux/Mac, 275 runs).
# Usage: bench/scripts/gates.sh BIN [SCRATCH_DIR]   (outputs and cache under SCRATCH_DIR)
BIN=${1:?binary}
S=${2:-$(cd "$(dirname "$0")/../.." && pwd)/testdata/scratch/gates}
mkdir -p "$S"
export FASTVOL_CACHE=$S/cache RSVOL_CACHE=$S/cache   # RSVOL_*: for a BIN from before the rename
for pass in cold warm; do
  [ $pass = cold ] && rm -rf "$FASTVOL_CACHE"
  OUTDIR=$S/out-win /home/user/fvol/bench/scripts/check_all.sh -b "$BIN" > "$S/win-$pass.txt" 2>&1
  echo "windows $pass: $(tail -1 "$S/win-$pass.txt")"
done
for pass in cold warm; do
  [ $pass = cold ] && rm -rf "$FASTVOL_CACHE"
  OUTBASE=$S/out-nix bash "$(dirname "$0")/check_nix.sh" -b "$BIN" > "$S/nix-$pass.txt" 2>&1
  echo "nix $pass: $(tail -1 "$S/nix-$pass.txt")"
done
grep -h "^DIFF\|^\[" "$S"/win-*.txt "$S"/nix-*.txt | head -20
