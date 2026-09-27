#!/bin/bash
# End-to-end tests of `fvol serve` (Windows + Linux images) against the CLI.
#   bench/web/e2e.sh            (uses target/fast/fvol; BIN=... to override)
set -e
cd "$(dirname "$0")/../.."
export BIN=${BIN:-$PWD/target/fast/fvol}
bench/web/serve.sh start win 18765 /home/user/cbc2/task2/memory-dirty.raw
bench/web/serve.sh start lnx 18766 /home/user/rs-vol/testdata/images/linux/rsvol-noble-6.8.0-139.elf -s /home/user/rs-vol/testdata/symbols
rc=0
timeout 600 bench/scripts/limit.sh -m 6G python3 bench/web/e2e.py || rc=$?
bench/web/serve.sh stop win
bench/web/serve.sh stop lnx
exit $rc
