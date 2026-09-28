#!/bin/bash
# Performance numbers for `fvol serve` (see bench/web/perf.py). Uses target/release/fvol when built.
set -e
cd "$(dirname "$0")/../.."
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA=${FASTVOL_DATA:-$(dirname "$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$PWD/.git")")}
export BIN=${BIN:-$PWD/target/release/fvol}
[ -x "$BIN" ] || BIN=$PWD/target/fast/fvol
bench/web/serve.sh start win 18765 "$DATA/testdata/images/windows/memory-dirty.raw" --max-memory ${MAXMEM:-2G}
rc=0
timeout 900 bench/scripts/limit.sh -m 5G python3 bench/web/perf.py || rc=$?
bench/web/serve.sh stop win
exit $rc
