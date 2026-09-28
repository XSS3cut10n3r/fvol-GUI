#!/bin/bash
# Rebuild (fast profile), restart the Windows test server and run UI screenshot steps.
#   bench/web/dev.sh [steps...]
set -e
cd "$(dirname "$0")/../.."
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA=${FASTVOL_DATA:-$(dirname "$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$PWD/.git")")}
bench/scripts/cargo.sh build --profile fast 2>&1 | grep -E "^(error|warning: unused)" -A6 || true
bench/web/serve.sh start win 18765 "$DATA/testdata/images/windows/memory-dirty.raw"
timeout 300 bench/scripts/limit.sh -m 4G python3 bench/web/shots.py "$@"
