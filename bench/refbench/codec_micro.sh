#!/usr/bin/env bash
# Quick codec iteration loop: build codec_micro.rs with rustc (no crate build) and run it
# against the refbench vectors, then the C reference on the same CPU, ROUNDS times.
#   WORK=<dir with *.vec and refbench> bench/refbench/codec_micro.sh [REPS] [FILTER]
# (run bench/refbench/run.sh once first to build the reference harness and the vectors)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA=${FASTVOL_DATA:-$(dirname "$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$ROOT/.git")")}
WORK="${WORK:-$DATA/testdata/scratch/refbench}"
REPS="${1:-9}"
FILTER="${2:-}"
export FASTVOL_BENCH_CPU="${FASTVOL_BENCH_CPU:-${RSVOL_BENCH_CPU:-2}}"
rustc --edition 2024 -C opt-level=3 -C target-cpu=native -C codegen-units=1 -C panic=abort \
    -o "$WORK/codec_micro" "$HERE/codec_micro.rs"
for _ in $(seq 1 "${ROUNDS:-1}"); do
    "$WORK/codec_micro" "$WORK" "$REPS" "$FILTER"
    if [ -z "${NOREF:-}" ]; then "$WORK/refbench" bench "$WORK" "$REPS"; fi
done
