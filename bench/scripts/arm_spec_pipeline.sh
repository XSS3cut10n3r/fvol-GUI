#!/bin/bash
# (Re)build a learned ARM spec: learn from random words (fresh start) and/or seed words, explore
# class neighbourhoods, then emit the Rust text spec.  Needs the bench venv (python capstone 5).
#   bench/scripts/arm_spec_pipeline.sh arm64|arm [WORKDIR] [--fresh] [--rand N] [--words FILE]
# Then verify: bench/scripts/disasm_diff_arm.py exhaustive ARCH  (its mismatch words file,
# WORKDIR/ARCH.exh.words, is the --words input of the next iteration).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
ARCH=$1
shift
WORK=${1:-/home/user/rs-vol/testdata/scratch/disasm/arm}
shift || true
PY=/home/user/rs-vol/bench/venv/bin/python
case $ARCH in
  arm64) GEN=$HERE/gen_arm64_spec.py; SPEC=$WORK/s64.json; OUT=$REPO/src/disasm/arm64/spec_data.rs;;
  arm)   GEN=$HERE/gen_arm32_spec.py; SPEC=$WORK/s32.json; OUT=$REPO/src/disasm/arm/spec_data.rs;;
  *) echo "usage: $0 arm64|arm [WORKDIR] [--fresh] [--rand N] [--words FILE]"; exit 2;;
esac
mkdir -p "$WORK"
EXTRA=()
RAND=600000
while [ $# -gt 0 ]; do
  case $1 in
    --fresh) rm -f "$SPEC";;
    --rand) RAND=$2; shift;;
    --words) EXTRA=(--words "$2"); shift;;
  esac
  shift
done
if [ ! -e "$SPEC" ]; then
  $PY "$GEN" learn "$SPEC" --rand "$RAND" --seed 3
fi
if [ ${#EXTRA[@]} -gt 0 ]; then
  $PY "$GEN" learn "$SPEC" "${EXTRA[@]}"
fi
$PY "$GEN" explore "$SPEC" --rounds 6
if [ "$ARCH" = arm ]; then
  $PY "$GEN" prune "$SPEC"
fi
$PY "$GEN" emit "$SPEC" "$OUT"
