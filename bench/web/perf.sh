#!/bin/bash
# Performance numbers for `vol serve` (see bench/web/perf.py). Uses target/release/vol when built.
set -e
cd "$(dirname "$0")/../.."
export BIN=${BIN:-$PWD/target/release/vol}
[ -x "$BIN" ] || BIN=$PWD/target/fast/vol
bench/web/serve.sh start win 18765 /home/user/cbc2/task2/memory-dirty.raw --max-memory ${MAXMEM:-2G}
rc=0
timeout 900 bench/scripts/limit.sh -m 5G python3 bench/web/perf.py || rc=$?
bench/web/serve.sh stop win
exit $rc
