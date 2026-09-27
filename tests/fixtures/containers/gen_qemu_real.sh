#!/usr/bin/env bash
# Produce REAL QEMU-written containers (savevm/migration stream "QEVM" and dump-guest-memory
# ELF cores) from diskless SeaBIOS VMs, using the rsvol-qemu docker image (QEMU 8.2), then
# record python volatility3's answers for them (gen_containers.py --expect-only).
#   gen_qemu_real.sh OUTDIR
# The files are large (RAM sized) and are not committed; check them with
#   FASTVOL_CONTAINER_FIXTURES=OUTDIR cargo test --release python_differential_large -- --ignored
set -euo pipefail
OUT="$(mkdir -p "$1" && cd "$1" && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${IMAGE:-rsvol-qemu}"
PY="${PY:-/home/user/rs-vol/bench/venv/bin/python}"

run_vm() { # name machine mem
    local name="$1" machine="$2" mem="$3"
    docker run --rm -v "$OUT":/out "$IMAGE" sh -c "
        (sleep 3; echo stop; echo 'migrate \"exec:cat > /out/$name.qemu\"'; sleep 15;
         echo 'dump-guest-memory /out/${name}_dump.elf'; sleep 15; echo quit) |
        qemu-system-x86_64 -machine $machine -m $mem -accel tcg -display none -nodefaults -monitor stdio >/dev/null 2>&1
        chmod a+r /out/$name.*"
}

run_vm q35_3g pc-q35-8.2 3072          # PCI hole: RAM above 2 GiB is remapped above 4 GiB
run_vm i440fx_small pc-i440fx-8.2 96    # small RAM: python turns the PCI hole off
run_vm ubuntu_noble pc-i440fx-noble-v2 128  # distro machine type (no hole regex match)
ls -la "$OUT"
cd "$OUT"
"$PY" "$HERE/gen_containers.py" --expect-only "$OUT"/*.qemu "$OUT"/*.elf
