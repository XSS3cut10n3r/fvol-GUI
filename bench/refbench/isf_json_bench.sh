#!/bin/bash
# Build and run the reference JSON benchmarks (simdjson, yyjson, python json) on ISF files.
# Usage: bench/refbench/isf_json_bench.sh [FILE.json ...]
# simdjson is not packaged on this machine: its single-header amalgamation is fetched once into
# $WORK (disk scratch; override with WORK=...). Compare with rsvol:
#   RSVOL_BENCH_JSON=FILE.json bench/scripts/cargo.sh test --release isf_parse_bench -- --ignored --nocapture
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-$HERE/../../testdata/scratch/refbench-json}
mkdir -p "$WORK"
if [ ! -f "$WORK/simdjson.cpp" ]; then
  curl -sSL -o "$WORK/simdjson.h" https://raw.githubusercontent.com/simdjson/simdjson/master/singleheader/simdjson.h
  curl -sSL -o "$WORK/simdjson.cpp" https://raw.githubusercontent.com/simdjson/simdjson/master/singleheader/simdjson.cpp
fi
if [ ! -x "$WORK/isf_json_bench" ] || [ "$HERE/isf_json_bench.cc" -nt "$WORK/isf_json_bench" ]; then
  g++ -O3 -march=native -std=c++17 -I"$WORK" -o "$WORK/isf_json_bench" "$HERE/isf_json_bench.cc" "$WORK/simdjson.cpp" -lyyjson
fi
for f in "$@"; do
  "$WORK/isf_json_bench" "$f" 20
  python3 - "$f" <<'EOF'
import json, sys, time
d = open(sys.argv[1], 'rb').read()
best = min((lambda t: (json.loads(d), time.perf_counter() - t)[1])(time.perf_counter()) for _ in range(5))
print(f"  python json.loads (C):        {best*1e3:7.2f} ms  {len(d)/1e6/best:6.0f} MB/s")
EOF
done
