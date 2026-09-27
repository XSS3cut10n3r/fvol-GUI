#!/bin/bash
# Run a heavy command in its own systemd --user scope with a hard memory cap, and at most SLOTS such
# jobs machine-wide (shared across all agents). Protects the interactive session from systemd-oomd,
# which otherwise kills the whole terminal scope when memory pressure builds up.
#
# Usage: bench/scripts/limit.sh [-m MEM] [-s SLOTS] [-p POOL] command [args...]
#   -m MEM    MemoryMax for the job (default 8G). Exceeding it OOM-kills only this job.
#   -s SLOTS  number of global slots competing for (default 4)
#   -p POOL   slot pool name (default "heavy"; cargo builds use the separate "cargo" pool)
# Use it for: python volatility runs, cargo --release builds, tests/benchmarks that touch the big
# memory images, anything that may use > 1-2 GB of RAM.
MEM=8G; SLOTS=4; POOL=heavy
while getopts m:s:p: o; do case $o in m) MEM=$OPTARG;; s) SLOTS=$OPTARG;; p) POOL=$OPTARG;; *) exit 2;; esac; done
shift $((OPTIND-1))
# Nested use (a gate script run under limit.sh that itself calls limit.sh for python runs) must not take a
# second slot from the same pool: with every slot held by outer wrappers that would deadlock. The inner job
# still gets its own memory-capped scope.
if [ -n "$RSVOL_LIMIT_HELD" ] && [[ ":$RSVOL_LIMIT_HELD:" == *":$POOL:"* ]]; then
  exec systemd-run --user --scope -q -p MemoryMax=$MEM -p MemorySwapMax=0 -- "$@"
fi
export RSVOL_LIMIT_HELD="${RSVOL_LIMIT_HELD:+$RSVOL_LIMIT_HELD:}$POOL"
dir=/tmp/rsvol-slots/$POOL; mkdir -p $dir
while true; do
  for i in $(seq 1 $SLOTS); do
    exec 9>>$dir/slot$i
    if flock -n 9; then
      systemd-run --user --scope -q -p MemoryMax=$MEM -p MemorySwapMax=0 -- "$@"
      exit $?
    fi
    exec 9>&-
  done
  sleep 0.5
done
