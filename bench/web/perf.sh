#!/bin/bash
# Performance numbers for `fvol serve` (see bench/web/perf.py). Uses target/release/fvol when built.
set -e
cd "$(dirname "$0")/../.."
export BIN=${BIN:-$PWD/target/release/fvol}
[ -x "$BIN" ] || BIN=$PWD/target/fast/fvol
bench/web/serve.sh start win 18765 /home/user/cbc2/task2/memory-dirty.raw --max-memory ${MAXMEM:-2G}
rc=0
timeout 900 bench/scripts/limit.sh -m 5G python3 bench/web/perf.py || rc=$?
bench/web/serve.sh stop win
exit $rc
