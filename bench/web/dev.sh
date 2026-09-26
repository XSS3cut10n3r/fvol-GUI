#!/bin/bash
# Rebuild (fast profile), restart the Windows test server and run UI screenshot steps.
#   bench/web/dev.sh [steps...]
set -e
cd "$(dirname "$0")/../.."
bench/scripts/cargo.sh build --profile fast 2>&1 | grep -E "^(error|warning: unused)" -A6 || true
bench/web/serve.sh start win 18765 /home/user/cbc2/task2/memory-dirty.raw
timeout 300 bench/scripts/limit.sh -m 4G python3 bench/web/shots.py "$@"
