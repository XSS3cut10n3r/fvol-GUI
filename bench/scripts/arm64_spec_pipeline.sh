#!/bin/bash
# Full AArch64 spec (re)build: learn from random words, explore class neighbourhoods, then
# emit src/disasm/arm64/spec_data.rs.  Needs the bench venv (python capstone 5).
#   bench/scripts/arm64_spec_pipeline.sh [WORKDIR] [--fresh] [--words FILE]
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=${1:-/home/user/rs-vol/testdata/scratch/disasm/arm}
shift || true
PY=/home/user/rs-vol/bench/venv/bin/python
SPEC=$WORK/s64.json
mkdir -p "$WORK"
EXTRA=()
while [ $# -gt 0 ]; do
  case $1 in
    --fresh) rm -f "$SPEC";;
    --words) EXTRA=(--words "$2"); shift;;
  esac
  shift
done
if [ ! -e "$SPEC" ]; then
  $PY "$HERE/gen_arm64_spec.py" learn "$SPEC" --rand 600000 --seed 3
fi
if [ ${#EXTRA[@]} -gt 0 ]; then
  $PY "$HERE/gen_arm64_spec.py" learn "$SPEC" "${EXTRA[@]}"
fi
$PY "$HERE/gen_arm64_spec.py" explore "$SPEC" --rounds 6
$PY "$HERE/gen_arm64_spec.py" emit "$SPEC" "$REPO/src/disasm/arm64/spec_data.rs"
