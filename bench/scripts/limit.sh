#!/bin/bash
# Run a heavy command in its own systemd --user scope with a hard memory cap, and at most SLOTS such
# jobs machine-wide (shared across all agents). Protects the interactive session from systemd-oomd,
# which otherwise kills the whole terminal scope when memory pressure builds up.
#
# Usage: bench/scripts/limit.sh [-m MEM] [-s SLOTS] command [args...]
#   -m MEM    MemoryMax for the job (default 8G). Exceeding it OOM-kills only this job.
#   -s SLOTS  number of global slots competing for (default 4)
# Use it for: python volatility runs, cargo --release builds, tests/benchmarks that touch the big
# memory images, anything that may use > 1-2 GB of RAM.
MEM=8G; SLOTS=4
while getopts m:s: o; do case $o in m) MEM=$OPTARG;; s) SLOTS=$OPTARG;; *) exit 2;; esac; done
shift $((OPTIND-1))
dir=/tmp/rsvol-slots; mkdir -p $dir
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
