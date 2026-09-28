#!/usr/bin/env bash
# Byte-identity gate for the xz decoder: every .xz under the given files/directories (default:
# the codec corpus, testdata/symbols and the volatility3 symbol cache) is decoded by fastvol's
# decoder (codec_xz_micro, built with rustc) and compared with `xz -dc`.
#   bench/refbench/codec_xz_verify.sh [FILE|DIR]...
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA=${FASTVOL_DATA:-$(dirname "$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$ROOT/.git")")}
WORK="${WORK:-$DATA/testdata/scratch/xzperf}"
mkdir -p "$WORK"
rustc --edition 2024 -C opt-level=3 -C target-cpu=native -C codegen-units=1 \
    -o "$WORK/codec_xz_verify" "$HERE/codec_xz_micro.rs" || exit 1
[ $# -eq 0 ] && set -- "$DATA/testdata/scratch/codecs/corpus" "$DATA/testdata/symbols" \
    "$HOME/.cache/volatility3/symbols"
n=0
bad=0
while IFS= read -r -d '' f; do
    n=$((n + 1))
    if ! cmp -s <("$WORK/codec_xz_verify" cat "$f") <(xz -dc "$f"); then
        echo "MISMATCH $f"
        bad=$((bad + 1))
    fi
done < <(find "$@" -name '*.xz' -type f -print0)
echo "$n files, $bad mismatches"
[ "$bad" -eq 0 ]
