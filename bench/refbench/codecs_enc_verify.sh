#!/bin/bash
# Round-trips files through the Rust streaming encoders and checks the output with the
# system tools (gzip/bzip2/xz -dc | cmp) and python's gzip/bz2/lzma modules (+ tarfile for
# *.tar inputs). Streams file -> file with bounded memory (codecs_enc_stream_file).
#
#   bench/refbench/codecs_enc_verify.sh [-l LEVEL] FILE...      (LEVEL default: 9 gz/bz2, 6 xz)
#
# Outputs go to $OUT (default /home/user/rs-vol/testdata/scratch/codecs_enc_verify, on disk).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
LEVEL=
while getopts "l:" o; do
    case $o in
        l) LEVEL=$OPTARG ;;
        *) exit 2 ;;
    esac
done
shift $((OPTIND - 1))
OUT=${OUT:-/home/user/rs-vol/testdata/scratch/codecs_enc_verify}
PY=${PY:-/home/user/rs-vol/bench/venv/bin/python}
LIMIT=${LIMIT:-/home/user/rs-vol/bench/scripts/limit.sh}
mkdir -p "$OUT"
BIN=$(cd "$ROOT" && /home/user/rs-vol/bench/scripts/cargo.sh test --release --no-run 2>&1 | grep -oE 'Executable .*\((.*)\)' | sed -E 's/.*\((.*)\)/\1/' | head -1)
BIN="$ROOT/$BIN"
fail=0
for f in "$@"; do
    for codec in gzip bz2 xz; do
        case $codec in
            gzip) ext=gz; tool="gzip -dc"; mod=gzip; lv=${LEVEL:-9} ;;
            bz2) ext=bz2; tool="bzip2 -dc"; mod=bz2; lv=${LEVEL:-9} ;;
            xz) ext=xz; tool="xz -dc"; mod=lzma; lv=${LEVEL:-6} ;;
        esac
        o="$OUT/$(basename "$f").$ext"
        line=$(CODECS_ENC_FILE="$f" CODECS_ENC_OUT="$o" CODECS_ENC_CODEC=$codec CODECS_ENC_LEVEL=$lv \
            "$LIMIT" -m 4G "$BIN" codecs_enc_stream_file --ignored --nocapture --test-threads=1 2>&1 | grep -oE 'rust-stream.*')
        st=ok
        $tool "$o" | cmp -s - "$f" || st=TOOL_FAIL
        "$PY" - "$o" "$f" "$mod" <<'EOF' || st="$st PY_FAIL"
import sys, hashlib, importlib
c, o, mod = sys.argv[1], sys.argv[2], sys.argv[3]
m = importlib.import_module(mod)
h1 = hashlib.sha256(); h2 = hashlib.sha256()
with m.open(c, 'rb') as fh:
    for b in iter(lambda: fh.read(1 << 22), b''):
        h1.update(b)
with open(o, 'rb') as fh:
    for b in iter(lambda: fh.read(1 << 22), b''):
        h2.update(b)
sys.exit(0 if h1.digest() == h2.digest() else 1)
EOF
        if [[ "$f" == *.tar ]]; then
            "$PY" -c 'import tarfile,sys; t=tarfile.open(sys.argv[1], "r:"+sys.argv[2]); [m for m in t]' "$o" "$ext" || st="$st TARFILE_FAIL"
        fi
        [[ $st == ok ]] || fail=1
        echo "$st  $line"
    done
done
exit $fail
