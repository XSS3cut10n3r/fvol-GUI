#!/bin/bash
# Regenerate .cargo/symbol-order.txt, the hot-text ordering the release link uses (.cargo/linker.sh).
#
#   bench/scripts/gen-symbol-order.sh [SCRATCH_DIR]
#
# 1. builds an unstripped release binary (same codegen as the shipped one) into SCRATCH_DIR,
# 2. runs a set of typical warm runs under bench/scripts/hottrace.c (ptrace single-step, all
#    threads) with a private cache that was warmed first,
# 3. maps every executed instruction to its function and writes the functions, demangled (so the
#    list survives crate-hash changes) and ordered: functions every run executes first, in the
#    order they first ran, then those fewer runs need.
#
# Run it after large code changes (a stale list only costs speed: functions it no longer names
# are simply not moved, see .cargo/linker.sh), then rebuild the release binary. Takes a few minutes.
# Images: WIN_IMG, LINUX_IMG, MAC_IMG, SYMBOLS (defaults: the test images of this repo); cases
# whose image is missing are skipped. Extra cases: ORDER_CASES="args|args|..." (fvol arguments).
# Needs cc, python3, nm and readelf (binutils), and ptrace (Linux).
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
S=${1:-$ROOT/testdata/scratch/symorder}
mkdir -p "$S"
S=$(cd "$S" && pwd)
WIN_IMG=${WIN_IMG:-/home/user/cbc2/task2/memory-dirty.raw}
LINUX_IMG=${LINUX_IMG:-$ROOT/testdata/images/linux/rsvol-noble-6.8.0-139.elf}
MAC_IMG=${MAC_IMG:-$ROOT/testdata/images/mac/rsvol-mac-mavericks-10.9.2-13C64.dmp}
SYMBOLS=${SYMBOLS:-$ROOT/testdata/symbols}
[ -d "$SYMBOLS" ] || SYMBOLS=/home/user/fvol/testdata/symbols
[ -e "$LINUX_IMG" ] || LINUX_IMG=/home/user/fvol/testdata/images/linux/rsvol-noble-6.8.0-139.elf
[ -e "$MAC_IMG" ] || MAC_IMG=/home/user/fvol/testdata/images/mac/rsvol-mac-mavericks-10.9.2-13C64.dmp

# the cases (vol arguments; @W/@L/@M/@S = the Windows/Linux/mac image and the symbol dir)
CASES=(
  "-q -f @W windows.pslist.PsList"
  "-q -f @W windows.info.Info"
  "-q -s @S -f @L linux.pslist.PsList"
  "-q -s @S -f @M mac.pslist.PsList"
  "-q -r json -f @W windows.pslist.PsList"
  "-q -f @W windows.cmdline.CmdLine"
  "-q -s @S -f @L linux.lsmod.Lsmod"
  "-h"
  "-q -f @W windows.no_such_plugin"
)
IFS='|' read -r -a extra <<< "${ORDER_CASES:-}"
CASES+=("${extra[@]}")

# memory-capped systemd scopes where available (this repo's machine-sharing rules), else plain
if command -v systemd-run > /dev/null 2>&1; then
  limited() { "$ROOT/bench/scripts/limit.sh" -m 4G "$@"; }
  CARGO=$ROOT/bench/scripts/cargo.sh
else
  limited() { "$@"; }
  CARGO=cargo
fi

echo "== building an unstripped release binary in $S/target"
CARGO_PROFILE_RELEASE_STRIP=false FASTVOL_SYMBOL_ORDER=0 \
  "$CARGO" build --release --manifest-path "$ROOT/Cargo.toml" --target-dir "$S/target" 2>&1 | tail -2
BIN=$S/target/release/fvol
[ -x "$BIN" ] || { echo "build failed"; exit 1; }
cc -O2 -o "$S/hottrace" "$ROOT/bench/scripts/hottrace.c" || exit 1

export FASTVOL_CACHE=$S/cache
rm -f "$S"/trace.*.txt
n=0
for c in "${CASES[@]}"; do
  [ -n "$c" ] || continue
  a=${c//@W/$WIN_IMG}; a=${a//@L/$LINUX_IMG}; a=${a//@M/$MAC_IMG}; a=${a//@S/$SYMBOLS}
  case $c in *@W*) [ -e "$WIN_IMG" ] || { echo "skip (no image): $c"; continue; } ;; esac
  case $c in *@L*) [ -e "$LINUX_IMG" ] || { echo "skip (no image): $c"; continue; } ;; esac
  case $c in *@M*) [ -e "$MAC_IMG" ] || { echo "skip (no image): $c"; continue; } ;; esac
  read -r -a args <<< "$a"
  # twice untraced: the cache is warm and any background cache write is done
  "$BIN" "${args[@]}" > /dev/null 2>&1; "$BIN" "${args[@]}" > /dev/null 2>&1
  printf '%-50s ' "$c"
  limited "$S/hottrace" -o "$S/trace.$n.txt" -- "$BIN" "${args[@]}"
  n=$((n + 1))
done

OUT=$ROOT/.cargo/symbol-order.txt
python3 - "$BIN" "$OUT" "$S"/trace.*.txt <<'EOF'
import bisect, subprocess, sys, os
binary, out, traces = sys.argv[1], sys.argv[2], sorted(sys.argv[3:], key=lambda p: int(p.rsplit('.', 2)[1]))
segs = []
for l in subprocess.run(["readelf", "-lW", binary], capture_output=True, text=True, check=True).stdout.splitlines():
    p = l.split()
    if p and p[0] == "LOAD":
        segs.append((int(p[1], 16), int(p[2], 16), int(p[4], 16)))
def nm(*flags):
    r = subprocess.run(["nm", "-p", "--defined-only", "-S", *flags, binary], capture_output=True, text=True, check=True)
    return r.stdout.splitlines()
syms = []
for raw, dem in zip(nm(), nm("-C")):
    p = raw.split(" ", 3)
    q = dem.split(" ", 3)
    if len(p) == 4 and p[2] in "tTwWiI":       # addr size type name
        syms.append((int(p[0], 16), int(p[1], 16), q[3]))
    elif len(p) == 3 and p[1] in "tTwWiI":     # addr type name (no size)
        syms.append((int(p[0], 16), 0, dem.split(" ", 2)[2]))
syms.sort()
addrs = [s[0] for s in syms]
first = {}   # name -> (run index, first execution index)
runs = {}
for ri, t in enumerate(traces):
    seen = {}
    for l in open(t):
        off, seq, _ = l.split()
        off, seq = int(off, 16), int(seq)
        va = off
        for so, sv, sz in segs:
            if so <= off < so + sz:
                va = off - so + sv
        i = bisect.bisect_right(addrs, va) - 1
        if i < 0 or (syms[i][1] and va >= syms[i][0] + syms[i][1]):
            continue
        n = syms[i][2]
        if n not in seen or seq < seen[n]:
            seen[n] = seq
    for n, seq in seen.items():
        runs[n] = runs.get(n, 0) + 1
        if n not in first:
            first[n] = (ri, seq)
order = sorted(first, key=lambda n: (-runs[n], first[n]))
ver = subprocess.run(["rustc", "--version"], capture_output=True, text=True).stdout.strip()
with open(out + ".tmp", "w") as o:
    o.write("# Hot-text ordering for the release link (.cargo/linker.sh); generated by\n")
    o.write("# bench/scripts/gen-symbol-order.sh (%s, %d traced runs). Demangled function names,\n" % (ver, len(traces)))
    o.write("# most-used first. A stale list only costs speed; regenerate after large code changes.\n")
    for n in order:
        o.write(n + "\n")
os.replace(out + ".tmp", out)
size = sum(s[1] for s in syms if s[2] in first)
print("%d functions (%d KB of code) from %d runs -> %s" % (len(order), size // 1024, len(traces), out))
EOF
