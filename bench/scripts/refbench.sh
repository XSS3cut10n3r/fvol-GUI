#!/bin/bash
# Regex / YARA throughput: fastvol vs the reference libraries, same bytes, same machine.
#
# Builds the C/C++ harnesses of bench/refbench/ (gcc/g++ -O3 -march=native, outside the cargo
# build) and the rust drivers (src/yara/benchdrv.rs, ignored tests), runs every engine through
# limit.sh (memory-capped scopes, one job at a time so the timings do not disturb each other)
# over the SAME mmapped window of the memory image, and prints markdown tables:
#   case | python re | PCRE2-JIT | RE2 | libyara | rust | rust/best-ref   (MB/s, best of N)
#   plus compile times and a cross-check of the match counts reported by every engine.
#
# Engines: python re (bench/scripts/regex_bench.py, finditer over an mmap object), PCRE2-JIT
# (bench/refbench/regex_pcre2.c), RE2 (bench/refbench/regex_re2.cc), libyara
# (bench/refbench/yara_bench.c), fastvol (yara_regex_bench_driver / yara_rules_bench_driver).
# Regex cases: bench/refbench/regex_cases.tsv. YARA cases: bench/refbench/yara_cases/*.yar.
#
# usage: bench/scripts/refbench.sh [--fast|--release] [--reps N] [--yara-reps N] [--py-reps N]
#            [--off OFF] [--len LEN] [--py-len LEN] [--img IMG] [--no-python]
#            [--regex-only|--yara-only] [--only CASE[,CASE]] [--out DIR] [--rounds N] [--cpu CPUS]
#   --fast       rust built with --profile fast (iterating); default --release (final numbers)
#   --rounds N   run every engine N times, interleaved (pcre2, re2, rust, libyara, rust, ...), and keep
#                each engine's best throughput / compile time: on a shared, busy machine memory
#                bandwidth contention only ever slows a run down, so the best of interleaved rounds
#                is the fair comparison (python runs in the first round only)
#   --cpu CPUS   pin every engine to these CPUs (taskset -c), e.g. a P-core on hybrid Intel parts
#   --py-len     smaller window for python re (MB/s is comparable; its count is then not
#                cross-checked against the other engines)
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$(dirname "$HERE")")
# the untracked test data (testdata/, bench/ref/, bench/venv/, volatility3/) is in the main checkout,
# which linked worktrees find through git; FASTVOL_DATA overrides
DATA=${FASTVOL_DATA:-$(dirname "$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$ROOT/.git")")}
LIMIT=${LIMIT:-$DATA/bench/scripts/limit.sh}
[ -x "$LIMIT" ] || LIMIT=$ROOT/bench/scripts/limit.sh
PY=${PY:-$DATA/bench/venv/bin/python}
IMG=$DATA/testdata/images/windows/memory-dirty.raw
OFF=1G; LEN=1G; PYLEN=; REPS=5; YREPS=3; PYREPS=3
PROFILE=release; DO_REGEX=1; DO_YARA=1; DO_PY=1; ONLY=; ROUNDS=1; CPU=
OUT=$ROOT/target/refbench
while [ $# -gt 0 ]; do
  case $1 in
    --fast) PROFILE=fast;;
    --release) PROFILE=release;;
    --reps) REPS=$2; shift;;
    --yara-reps) YREPS=$2; shift;;
    --py-reps) PYREPS=$2; shift;;
    --off) OFF=$2; shift;;
    --len) LEN=$2; shift;;
    --py-len) PYLEN=$2; shift;;
    --img) IMG=$2; shift;;
    --no-python) DO_PY=0;;
    --regex-only) DO_YARA=0;;
    --yara-only) DO_REGEX=0;;
    --only) ONLY=$2; shift;;
    --out) OUT=$2; shift;;
    --rounds) ROUNDS=$2; shift;;
    --cpu) CPU=$2; shift;;
    -h|--help) sed -n '2,25p' "$0"; exit 0;;
    *) echo "unknown option $1" >&2; exit 2;;
  esac
  shift
done
PYLEN=${PYLEN:-$LEN}
mkdir -p "$OUT"
RES=$OUT/results.tsv
: > "$RES"
CASES=$ROOT/bench/refbench/regex_cases.tsv
YFILES=$(ls "$ROOT"/bench/refbench/yara_cases/*.yar | tr '\n' ',' | sed 's/,$//')
YLIST=$(echo "$YFILES" | tr ',' ' ')

echo "== building reference harnesses (gcc/g++ -O3 -march=native)" >&2
gcc -O3 -march=native -Wall -o "$OUT/regex_pcre2" "$ROOT/bench/refbench/regex_pcre2.c" -lpcre2-8 || exit 1
# shellcheck disable=SC2046
g++ -O3 -march=native -Wall -o "$OUT/regex_re2" "$ROOT/bench/refbench/regex_re2.cc" $(pkg-config --cflags --libs re2) || exit 1
gcc -O3 -march=native -Wall -o "$OUT/yara_bench" "$ROOT/bench/refbench/yara_bench.c" -lyara || exit 1

echo "== building rust drivers (cargo test --profile $PROFILE, through limit.sh)" >&2
(cd "$ROOT" && "$LIMIT" -m 8G cargo test --profile "$PROFILE" --bin fvol --no-run -q) >&2 || exit 1

run() { # engine-label cmd... : run through limit.sh, keep BENCH lines
  echo "== $1" >&2
  shift
  if [ -n "$CPU" ]; then set -- taskset -c "$CPU" "$@"; fi
  "$LIMIT" -m 4G "$@" 2>"$OUT/stderr.last" | grep --line-buffered -E '^(BENCH|PRIM)' | tee -a "$RES" >&2
}
rust() { # driver-name extra-env...
  local drv=$1; shift
  (cd "$ROOT" && run "rust $drv" env FASTVOL_BENCH_IMG="$IMG" FASTVOL_BENCH_OFF="$OFF" FASTVOL_BENCH_LEN="$LEN" \
    FASTVOL_BENCH_ONLY="$ONLY" "$@" cargo test --profile "$PROFILE" --bin fvol -q "$drv" -- --ignored --nocapture --test-threads=1)
}

for ROUND in $(seq 1 "$ROUNDS"); do
[ "$ROUNDS" -gt 1 ] && echo "== round $ROUND/$ROUNDS" >&2
if [ $DO_REGEX = 1 ]; then
  run "PCRE2-JIT" "$OUT/regex_pcre2" "$IMG" "$OFF" "$LEN" "$REPS" "$CASES" "$ONLY"
  run "RE2" "$OUT/regex_re2" "$IMG" "$OFF" "$LEN" "$REPS" "$CASES" "$ONLY"
  rust yara_regex_bench_driver FASTVOL_BENCH_REPS="$REPS" FASTVOL_BENCH_REGEX_CASES="$CASES"
  if [ $DO_PY = 1 ] && [ "$ROUND" = 1 ]; then
    run "python re (window $PYLEN, best of $PYREPS)" "$PY" "$ROOT/bench/scripts/regex_bench.py" --img "$IMG" \
      --off "$OFF" --len "$PYLEN" --reps "$PYREPS" --cases "$CASES" --only "$ONLY"
  fi
fi
if [ $DO_YARA = 1 ]; then
  if [ -n "$ONLY" ]; then
    YSEL=""; for c in ${ONLY//,/ }; do [ -f "$ROOT/bench/refbench/yara_cases/$c.yar" ] && YSEL="$YSEL $ROOT/bench/refbench/yara_cases/$c.yar"; done
  else
    YSEL=$YLIST
  fi
  if [ -n "$YSEL" ]; then
    # shellcheck disable=SC2086
    run "libyara" "$OUT/yara_bench" "$IMG" "$OFF" "$LEN" "$YREPS" $YSEL
    rust yara_rules_bench_driver FASTVOL_BENCH_REPS="$YREPS" FASTVOL_BENCH_YARA_CASES="$(echo $YSEL | tr ' ' ',')"
  fi
fi

done

# ---- report -------------------------------------------------------------------------
echo
echo "### fastvol regex / YARA throughput vs reference libraries"
echo
echo "machine: $(lscpu | sed -n 's/^Model name: *//p'), $(nproc) threads, kernel $(uname -r); gcc $(gcc -dumpfullversion);" \
  "pcre2 $(pkg-config --modversion libpcre2-8), re2 $(pkg-config --modversion re2), libyara $(pkg-config --modversion yara)," \
  "$("$PY" -c 'import sys; print("python", sys.version.split()[0])'), $(rustc --version | cut -d' ' -f1-2), rust profile $PROFILE"
echo "window: $IMG [$OFF, +$LEN) mmapped, warm page cache, single thread, best of $REPS (regex) / $YREPS (yara) / $PYREPS (python, window $PYLEN)" \
  "x $ROUNDS interleaved round(s)${CPU:+, pinned to CPU $CPU}"
echo
awk -F'\t' -v pylen="$PYLEN" -v len="$LEN" '
  $1 == "BENCH" {
    e = $2; c = $3
    if (!(c in seen)) { seen[c] = 1; order[++n] = c }
    # several rounds: keep the best throughput and the best compile time per engine
    if (!((c, e) in mbps) || mbps[c, e] == "-" || ($6 != "-" && $6 + 0 > mbps[c, e] + 0)) mbps[c, e] = $6
    if (!((c, e) in cus) || cus[c, e] == "-" || ($4 != "-" && $4 + 0 < cus[c, e] + 0)) cus[c, e] = $4
    cnt[c, e] = $7; note[c, e] = $8
  }
  function cell(c, e) {
    if (!((c, e) in mbps)) return "-"
    if (mbps[c, e] == "-") return (note[c, e] ~ /pending/ ? "pending" : "err")
    return sprintf("%.0f", mbps[c, e])
  }
  END {
    split("python-re pcre2-jit re2 libyara fastvol", E, " ")
    print "| case | python re | PCRE2-JIT | RE2 | libyara | rust | rust/best-ref | matches (cross-check) |"
    print "|---|---:|---:|---:|---:|---:|---:|---|"
    for (i = 1; i <= n; i++) {
      c = order[i]; best = 0; bestname = ""
      for (j = 1; j <= 4; j++) if ((c, E[j]) in mbps && mbps[c, E[j]] != "-" && mbps[c, E[j]] + 0 > best) { best = mbps[c, E[j]] + 0; bestname = E[j] }
      ratio = "-"
      if ((c, "fastvol") in mbps && mbps[c, "fastvol"] != "-" && best > 0) ratio = sprintf("%.2fx (vs %s)", mbps[c, "fastvol"] / best, bestname)
      else if ((c, "fastvol") in note && note[c, "fastvol"] ~ /pending/) ratio = "pending"
      # match count cross-check (python only when it scanned the same window)
      ref = ""; ok = 1; detail = ""
      for (j = 1; j <= 5; j++) {
        e = E[j]
        if (!((c, e) in cnt) || cnt[c, e] == "-") continue
        if (e == "python-re" && pylen != len) { detail = detail " py(" pylen ")=" cnt[c, e]; continue }
        if (ref == "") ref = cnt[c, e]; else if (cnt[c, e] != ref) ok = 0
        detail = detail " " e "=" cnt[c, e]
      }
      chk = (ref == "" ? "-" : (ok ? "ok " ref : "MISMATCH" detail))
      if (ok && detail ~ / py\(/) chk = chk " (python on smaller window:" substr(detail, index(detail, " py(")) ")"
      printf "| %s | %s | %s | %s | %s | %s | %s | %s |\n", c, cell(c, "python-re"), cell(c, "pcre2-jit"), cell(c, "re2"), cell(c, "libyara"), cell(c, "fastvol"), ratio, chk
    }
    print ""
    print "compile time (microseconds, best of 20 / 10 for yara):"
    print ""
    print "| case | python re | PCRE2-JIT | RE2 | libyara | rust | rust engine |"
    print "|---|---:|---:|---:|---:|---:|---|"
    for (i = 1; i <= n; i++) {
      c = order[i]; row = "| " c
      for (j = 1; j <= 5; j++) row = row " | " ((c, E[j]) in cus ? cus[c, E[j]] : "-")
      eng = ((c, "fastvol") in note ? note[c, "fastvol"] : "-"); sub(/.*engine=/, "", eng); if (eng ~ /window=/) eng = "-"
      print row " | " eng " |"
    }
  }' "$RES"
if grep -q '^PRIM' "$RES"; then
  echo
  echo "substring-search floor for the plain-literal cases (MB/s, same window; diagnostic, not a reference library):"
  echo
  echo "| case | glibc memmem | fastvol Memmem | fastvol regex |"
  echo "|---|---:|---:|---:|"
  awk -F'\t' '$1 == "PRIM" { if ($5 + 0 > p[$3, $2] + 0) p[$3, $2] = $5; if (!($3 in s)) { s[$3] = 1; o[++n] = $3 } }
    $1 == "BENCH" && $2 == "fastvol" { if ($6 + 0 > r[$3] + 0) r[$3] = $6 }
    END { for (i = 1; i <= n; i++) { c = o[i]; printf "| %s | %.0f | %.0f | %.0f |\n", c, p[c, "glibc-memmem"], p[c, "fastvol-memmem"], r[c] } }' "$RES"
fi
echo
echo "(yara matches = matching rules / string instances; raw lines: $RES)"
