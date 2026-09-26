#!/bin/bash
# Side-by-side: python volatility3 vs rsvol on one image, per plugin.
# Prints wall time for each and the speedup.
#
# Usage: bench/scripts/vs_python.sh [-f IMAGE] [--cold] [PLUGIN ...]
#   -f IMAGE  memory image (default ~/cbc2/task2/memory-dirty.raw)
#   --cold    give rsvol an empty private cache for every run (first-ever-run timings)
#   PLUGIN    plugins to compare (default: a quick mixed set)
# Env: PY=<python interpreter> (default: the bench venv with capstone/yara, else python3)
IMG=$HOME/cbc2/task2/memory-dirty.raw
COLD=0
PLUGINS=()
while [ $# -gt 0 ]; do
  case "$1" in
    -f) IMG=$2; shift 2;;
    --cold) COLD=1; shift;;
    *) PLUGINS+=("$1"); shift;;
  esac
done
[ ${#PLUGINS[@]} -eq 0 ] && PLUGINS=(windows.info.Info windows.pslist.PsList windows.pstree.PsTree
  windows.psscan.PsScan windows.dlllist.DllList windows.cmdline.CmdLine windows.handles.Handles
  windows.filescan.FileScan windows.netscan.NetScan windows.registry.hivelist.HiveList
  windows.registry.printkey.PrintKey windows.malware.malfind.Malfind windows.vadinfo.VadInfo)
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
RS=$ROOT/target/release/vol
PY=${PY:-$ROOT/bench/venv/bin/python}; [ -x "$PY" ] || PY=python3
VOL=$ROOT/volatility3/vol.py
# a private dir per invocation (concurrent runs used to overwrite each other's outputs); kept for inspection
mkdir -p "$ROOT/testdata/scratch/vs_python"; OUT=$(mktemp -d "$ROOT/testdata/scratch/vs_python/run-XXXXXX")
echo "outputs: $OUT (py.txt / rs.txt of the last plugin)" >&2
now() { date +%s%N; }
printf "%-42s %10s %10s %9s\n" plugin python rsvol speedup
for p in "${PLUGINS[@]}"; do
  rm -rf "$OUT/py" "$OUT/rs"; mkdir -p "$OUT/py" "$OUT/rs"
  s=$(now); "$PY" "$VOL" -q -o "$OUT/py" -f "$IMG" "$p" > "$OUT/py.txt" 2>/dev/null; m=$(now)
  if [ $COLD = 1 ]; then rm -rf "$OUT/cache"; export RSVOL_CACHE="$OUT/cache"; fi
  "$RS" -q -o "$OUT/rs" -f "$IMG" "$p" > "$OUT/rs.txt" 2>/dev/null; e=$(now)
  awk -v p="$p" -v a=$s -v b=$m -v c=$e 'BEGIN {
    py=(b-a)/1e9; rs=(c-b)/1e9; printf "%-42s %9.2fs %9.3fs %8.0fx\n", p, py, rs, py/rs }'
done
