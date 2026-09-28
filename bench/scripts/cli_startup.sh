#!/bin/bash
# Usage: bench/scripts/cli_startup.sh [BIN] [N]
# Average wall time of N invocations of the CLI paths that do no plugin work
# (help, an argument error, a bad -f), against /bin/true as the process-spawn floor.
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA=${FASTVOL_DATA:-$(dirname "$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$ROOT/.git")")}
BIN=${1:-$DATA/target/fast/fvol}
N=${2:-1000}
t() {
  local s e
  s=$(date +%s%N)
  for ((i = 0; i < N; i++)); do "$@" >/dev/null 2>&1; done
  e=$(date +%s%N)
  printf '%8d us  %s\n' $(((e - s) / N / 1000)) "$*"
}
t /bin/true
t "$BIN" -h
t "$BIN" -q -f /etc/hostname no.such.plugin
t "$BIN" -q -f /nonexistent windows
