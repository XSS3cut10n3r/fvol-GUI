#!/bin/bash
# End-to-end tests of `fvol serve` (Windows + Linux images) against the CLI.
#   bench/web/e2e.sh            (uses target/fast/fvol; BIN=... to override)
set -e
cd "$(dirname "$0")/../.."
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA=${FASTVOL_DATA:-$(dirname "$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$PWD/.git")")}
export BIN=${BIN:-$PWD/target/fast/fvol}
bench/web/serve.sh start win 18765 "$DATA/testdata/images/windows/memory-dirty.raw"
bench/web/serve.sh start lnx 18766 "$DATA/testdata/images/linux/rsvol-noble-6.8.0-139.elf" -s "$DATA/testdata/symbols"
rc=0
timeout 600 bench/scripts/limit.sh -m 6G python3 bench/web/e2e.py || rc=$?
bench/web/serve.sh stop win
bench/web/serve.sh stop lnx
exit $rc
